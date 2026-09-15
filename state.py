"""State persistence for cross-run deduplication and candidate cooldown.

Two TTL classes share one JSON file:
  sent       — articles delivered in a digest. Suppressed for STATE_SENT_TTL_DAYS.
  candidate  — articles that reached the LLM but were not chosen. Cooled down
               for STATE_CANDIDATE_COOLDOWN_DAYS so near-misses do not recycle
               into the candidate pool every day.

URLs are canonicalized before storage so trivial variations (tracking params,
trailing slashes, default ports) don't bypass dedup.
"""

import json
import datetime
import os
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from config import (
    STATE_PATH, STATE_SENT_TTL_DAYS, STATE_CANDIDATE_COOLDOWN_DAYS,
)

# Tracking-style query parameters to strip during URL normalization.
_TRACKING_PARAMS = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "gclid", "fbclid", "mc_cid", "mc_eid", "ref", "ref_src",
    "_hsenc", "_hsmi", "ck_subscriber_id", "yclid", "msclkid",
})


def normalize_url(url: str) -> str:
    """Canonicalize a URL for dedup comparison.

    Lowercases scheme and host, strips fragment, removes tracking-style
    query parameters, removes default ports, and trims trailing slash from
    non-root paths.
    """
    if not url:
        return ""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return url.strip()

    scheme = (parts.scheme or "https").lower()
    netloc = parts.netloc.lower()

    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]

    path = parts.path
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    if not path and netloc:
        path = "/"  # https://ex.com and https://ex.com/ are one URL

    # Sorted so parameter order doesn't split one URL into two keys; blank
    # values kept so ?amp and ?print stay distinct from the bare URL.
    kept = sorted(
        (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if k.lower() not in _TRACKING_PARAMS
    )
    query = urlencode(kept)

    return urlunsplit((scheme, netloc, path, query, ""))


def _state_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), STATE_PATH)


# The digest day rolls over at 04:00 UTC, not midnight. The evening run
# (22:43 UTC) routinely fires hours late, past UTC midnight; with a midnight
# rollover its delivery counted as the next day's, and that morning's digest
# took itself for the emergency re-check. 04:00 sits in the overnight gap: the
# evening run would have to be 5h+ late to cross it, and the morning run
# (06:37 UTC) never fires early.
_DAY_ROLLOVER = datetime.timedelta(hours=4)


def digest_day() -> datetime.date:
    return (datetime.datetime.now(datetime.timezone.utc) - _DAY_ROLLOVER).date()


def _today() -> str:
    return digest_day().isoformat()


def _cutoff(days: int) -> str:
    """ISO date `days` ago; entries dated on or after it are in the window."""
    return (digest_day() - datetime.timedelta(days=days)).isoformat()


def load_state() -> dict:
    """Return state dict, pruning expired entries.

    Schema: {normalized_url: {"status": "sent"|"candidate", "date": "YYYY-MM-DD"}}
    """
    try:
        with open(_state_path()) as f:
            raw = json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        print(f"Warning: state file is corrupt ({exc}); starting with empty state.")
        return {}
    if not isinstance(raw, dict):
        print(f"Warning: state file holds {type(raw).__name__}, not an object; "
              f"starting with empty state.")
        return {}

    sent_cutoff = _cutoff(STATE_SENT_TTL_DAYS)
    cand_cutoff = _cutoff(STATE_CANDIDATE_COOLDOWN_DAYS)

    pruned: dict = {}
    for url, entry in raw.items():
        if not isinstance(entry, dict):
            continue
        status = entry.get("status")
        date = entry.get("date", "")
        if not (status == "sent" and date >= sent_cutoff
                or status == "candidate" and date >= cand_cutoff):
            continue
        # Re-key under the current normalize_url, so a rule change doesn't
        # orphan entries written under the old one. On a collision, sent wins.
        key = normalize_url(url)
        if pruned.get(key, {}).get("status") != "sent":
            pruned[key] = entry
    return pruned


def save_state(state: dict) -> None:
    """Atomically write state (write-then-rename), sorted for stable diffs."""
    path = _state_path()
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def is_excluded(url: str, state: dict, sent_only: bool = False) -> bool:
    """True if the URL is in either the sent-suppression set or candidate cooldown.

    sent_only=True checks the sent set alone. The emergency re-check path uses
    it: a story that was a near-miss this morning and has since escalated must
    be able to come back, but anything already delivered stays suppressed.
    """
    entry = state.get(normalize_url(url))
    if entry is None:
        return False
    return entry.get("status") == "sent" if sent_only else True


def record_candidates(state: dict, urls: list[str]) -> None:
    """Mark URLs as 'considered' in this run.

    Does NOT downgrade an existing 'sent' entry to 'candidate'.
    """
    today = _today()
    for url in urls:
        if not url:
            continue
        norm = normalize_url(url)
        if state.get(norm, {}).get("status") == "sent":
            continue
        state[norm] = {"status": "candidate", "date": today}


def record_sent(state: dict, urls: list[str], headline: str = "") -> None:
    """Mark URLs as delivered. Always overwrites prior status."""
    today = _today()
    for url in urls:
        if not url:
            continue
        norm = normalize_url(url)
        entry: dict = {"status": "sent", "date": today}
        if headline:
            entry["headline"] = headline
        state[norm] = entry


def sent_today(state: dict) -> bool:
    """True if an earlier run this digest day delivered (see _DAY_ROLLOVER)."""
    today = _today()
    return any(
        v.get("status") == "sent" and v.get("date") == today
        for v in state.values()
    )


def recent_sent_headlines(state: dict, days: int = 7) -> list[str]:
    """Return headlines from sent entries within the last N days, newest first."""
    cutoff = _cutoff(days)
    entries = [
        (v["date"], v.get("headline", ""))
        for v in state.values()
        if v.get("status") == "sent" and v.get("date", "") >= cutoff and v.get("headline")
    ]
    return [h for _, h in sorted(entries, reverse=True)]
