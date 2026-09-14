"""Article fetching: RSS feeds and Brave Search.

Two sources of candidates:
  - RSS feeds (config.FEEDS), round-robin merged so no single feed dominates
  - Brave Search results, driven by LLM-generated queries

All triage happens downstream in the LLM against a news-cycle "fire-tier" bar.
No deterministic vulnerability-catalog enrichment — scanners cover that, and
the whole point of the newsbot is to surface what the news cycle is reacting
to, not what a catalog flags.
"""

import re
import io
import html
import datetime
import ipaddress
import os
import socket
from urllib.parse import urlsplit, urljoin

import feedparser
import requests

from config import (
    FEEDS, MAX_RSS_ARTICLES, PER_FEED_CAP, SUMMARY_MAX_CHARS,
    BLOCKLIST_TITLE_TERMS, BLOCKLIST_DOMAINS, BLOCKLIST_URL_PATTERNS,
    BRAVE_SEARCH_URL, MAX_SEARCH_RESULTS, BRAVE_GOGGLES,
    FEED_FETCH_TIMEOUT_SEC, HTTP_USER_AGENT,
)
from state import normalize_url, is_excluded


# ---------------------------------------------------------------------------
# Summary sanitization
# ---------------------------------------------------------------------------
# RSS summary fields and Brave Search descriptions both routinely contain HTML
# (or HTML-entity-encoded text). The triage LLM gets cleaner signal — and the
# prompt-injection surface shrinks — if we drop tags and unescape entities
# before any of it reaches the model or the truncation step.

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def _strip_html(text: str) -> str:
    if not text:
        return ""
    # Unescape first so entity-encoded tags (&lt;script&gt;) become real tags,
    # THEN strip them. Reversing the order would let entity-encoded payloads
    # survive the tag pass and reanimate on unescape.
    unescaped = html.unescape(text)
    no_tags = _TAG_RE.sub(" ", unescaped)
    return _WS_RE.sub(" ", no_tags).strip()


# ---------------------------------------------------------------------------
# Block list
# ---------------------------------------------------------------------------

_BLOCKLIST_TITLE_PATTERNS = [
    re.compile(r"\b" + re.escape(term) + r"\b", re.IGNORECASE)
    for term in BLOCKLIST_TITLE_TERMS
]

_BLOCKLIST_URL_PATTERNS = [
    re.compile(pattern, re.IGNORECASE) for pattern in BLOCKLIST_URL_PATTERNS
]


def _is_blocked(article: dict) -> bool:
    title = article.get("title") or ""
    for pattern in _BLOCKLIST_TITLE_PATTERNS:
        if pattern.search(title):
            return True
    link_lower = (article.get("link") or "").lower()
    if link_lower:
        for pattern in _BLOCKLIST_URL_PATTERNS:
            if pattern.search(link_lower):
                return True
        try:
            host = urlsplit(link_lower).hostname or ""
        except ValueError:
            host = ""
        for domain in BLOCKLIST_DOMAINS:
            d = domain.lower()
            if host == d or host.endswith("." + d):
                return True
    return False


# ---------------------------------------------------------------------------
# RSS
# ---------------------------------------------------------------------------

def _fetch_feed_bytes(url: str) -> bytes | None:
    """HTTP-fetch a feed with explicit timeout (feedparser doesn't honor one)."""
    try:
        resp = requests.get(
            url,
            timeout=FEED_FETCH_TIMEOUT_SEC,
            headers={"User-Agent": HTTP_USER_AGENT},
        )
        if resp.status_code != 200:
            print(f"Warning: feed {url} returned HTTP {resp.status_code}")
            return None
        return resp.content
    except requests.RequestException as exc:
        print(f"Warning: feed {url} failed: {exc}")
        return None


def entry_published(entry) -> datetime.datetime | None:
    """UTC publish time from a feedparser entry, or None if unparseable."""
    for field in ("published_parsed", "updated_parsed"):
        parsed = getattr(entry, field, None)
        if not parsed:
            continue
        try:
            return datetime.datetime(*parsed[:6], tzinfo=datetime.timezone.utc)
        except (TypeError, ValueError):
            continue
    return None


def _parse_one_feed(url: str, cutoff: datetime.datetime) -> list[dict]:
    raw = _fetch_feed_bytes(url)
    if raw is None:
        return []
    feed = feedparser.parse(io.BytesIO(raw))
    out: list[dict] = []
    seen_titles_in_feed: set[str] = set()
    for entry in feed.entries:
        published = entry_published(entry)

        if published and published < cutoff:
            continue

        title = (getattr(entry, "title", "") or "").strip()
        if not title:
            continue

        # A linkless entry can only reach triage as an item the model has to
        # invent a URL for, so drop it here rather than spend a pool slot.
        link = (getattr(entry, "link", "") or "").strip()
        if not link:
            continue

        title_key = title.lower()
        if title_key in seen_titles_in_feed:
            continue
        seen_titles_in_feed.add(title_key)
        # Strip HTML before truncating so we don't slice through a tag.
        summary = _strip_html(getattr(entry, "summary", "") or "")[:SUMMARY_MAX_CHARS]

        out.append({
            "title": title,
            "link": link,
            "source": feed.feed.get("title", url),
            "published": published.isoformat() if published else "unknown",
            "summary": summary,
        })
    return out


def fetch_rss_articles(lookback_hours: int, state: dict,
                       sent_only: bool = False) -> tuple[list[dict], dict]:
    """Round-robin across feeds, with state/blocklist/cross-feed-title filtering.

    Each feed contributes at most PER_FEED_CAP items; total capped at
    MAX_RSS_ARTICLES. Round-robin order ensures one chatty feed can't crowd
    out quieter ones.

    Returns (articles, stats) where stats carries funnel counts for logging.
    """
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=lookback_hours)

    per_feed_raw: list[list[dict]] = []
    for url in FEEDS:
        per_feed_raw.append(_parse_one_feed(url, cutoff))

    total_fetched = sum(len(items) for items in per_feed_raw)
    per_feed = [items[:PER_FEED_CAP] for items in per_feed_raw]

    merged: list[dict] = []
    title_to_kept: dict[str, dict] = {}
    excl_state = 0
    excl_blocklist = 0
    total_popped = 0

    while any(per_feed) and len(merged) < MAX_RSS_ARTICLES:
        progressed = False
        for bucket in per_feed:
            if not bucket or len(merged) >= MAX_RSS_ARTICLES:
                continue
            article = bucket.pop(0)
            total_popped += 1
            progressed = True

            if is_excluded(article["link"], state, sent_only):
                excl_state += 1
                continue
            if _is_blocked(article):
                excl_blocklist += 1
                continue

            # Normalized title key for cross-feed dedup. Strip non-alphanumerics
            # so "Critical: Foo Bar" and "Critical Foo Bar!" collapse. When two
            # feeds carry the same story we keep the first and annotate it with
            # the second source — convergence is itself a fire-tier signal.
            title_key = re.sub(r"[^a-z0-9]", "", article["title"].lower())[:80]
            if title_key in title_to_kept:
                kept = title_to_kept[title_key]
                src = article.get("source", "")
                if src and src != kept.get("source") and src not in kept.get("also_sources", []):
                    kept.setdefault("also_sources", []).append(src)
                continue
            title_to_kept[title_key] = article

            merged.append(article)
        if not progressed:
            break

    stats = {
        "fetched": total_fetched,
        "after_state_dedup": total_popped - excl_state,
        "after_blocklist": total_popped - excl_state - excl_blocklist,
        "after_cross_feed_dedup": len(merged),
    }
    return merged, stats


# ---------------------------------------------------------------------------
# Brave Search
# ---------------------------------------------------------------------------

_STALE_AGE_TOKENS = {"week", "month", "year"}
_RELATIVE_DAYS_RE = re.compile(r"(\d+)\s*days?\s*ago", re.IGNORECASE)


def _is_stale_brave_age(age: str, cutoff: datetime.datetime | None = None) -> bool:
    """Return True if Brave's page_age indicates the item is older than cutoff.

    Brave returns `page_age` as ISO 8601 when available (most common) and may
    also return `age` as a relative phrase ("3 days ago", "2 weeks ago"). The
    original implementation only caught week/month/year tokens, so an ISO-format
    age or an "N days ago" phrase older than the lookback would slip through.

    Resolution order: ISO 8601 parse → "N days ago" relative parse → token
    fallback for week/month/year. The token fallback is preserved so the filter
    still works if a caller doesn't supply a cutoff.
    """
    if not age:
        return False

    if cutoff is not None:
        try:
            parsed = datetime.datetime.fromisoformat(age.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=datetime.timezone.utc)
            return parsed < cutoff
        except (ValueError, TypeError):
            pass

        m = _RELATIVE_DAYS_RE.search(age)
        if m:
            try:
                days = int(m.group(1))
                approx = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
                return approx < cutoff
            except (ValueError, OverflowError):
                pass

    age_lower = age.lower()
    return any(token in age_lower for token in _STALE_AGE_TOKENS)


def search_brave(query: str, lookback_hours: int,
                 count: int = MAX_SEARCH_RESULTS) -> list[dict]:
    api_key = os.environ.get("BRAVE_API_KEY", "")
    if not api_key:
        return []

    freshness = "pw" if lookback_hours >= 48 else "pd"
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=lookback_hours)

    # result_filter=web drops video/discussion/FAQ/infobox verticals from the
    # response — those types are pure backfill for security-news queries and
    # the parser below only reads web.results anyway.
    params = {"q": query, "count": count, "freshness": freshness,
              "result_filter": "web"}
    if BRAVE_GOGGLES:
        params["goggles"] = BRAVE_GOGGLES

    try:
        resp = requests.get(
            BRAVE_SEARCH_URL,
            headers={"X-Subscription-Token": api_key, "Accept": "application/json"},
            params=params,
            timeout=15,
        )
        if resp.status_code in (401, 403):
            raise RuntimeError(f"Brave Search auth failure: {resp.status_code}")
        if resp.status_code != 200:
            print(f"Warning: Brave Search returned {resp.status_code} for: {query}")
            return []
        results = []
        for item in resp.json().get("web", {}).get("results", []):
            url = item.get("url", "")
            title = _strip_html(item.get("title", "") or "")
            description = _strip_html(item.get("description", "") or "")[:SUMMARY_MAX_CHARS]
            age = item.get("page_age") or item.get("age") or "unknown"
            if _is_stale_brave_age(age, cutoff):
                continue
            if url and title:
                results.append({
                    "title": title,
                    "link": url,
                    "source": "[Web Search]",
                    "published": age,
                    "summary": description,
                })
        return results
    except requests.RequestException as exc:
        print(f"Warning: Brave Search failed for '{query}': {exc}")
        return []


def fetch_search_articles(query_specs: list[dict], lookback_hours: int,
                          state: dict, rss_articles: list[dict],
                          sent_only: bool = False) -> tuple[list[dict], dict]:
    """Run all queries, dedupe against RSS pool and prior state, apply blocklist.

    `query_specs` is a list of dicts: {"label": str, "query": str, "count": int}.
    Each surviving result is tagged with the `query_type` (label) and `query`
    that produced it — the first query to surface a URL owns the attribution —
    so the SKIP report can show which query pulled in each candidate.

    Returns (articles, stats) where stats carries funnel counts for logging.
    """
    rss_norm_urls = {normalize_url(a["link"]) for a in rss_articles if a["link"]}
    seen_in_search: set[str] = set()
    out: list[dict] = []
    total_brave = 0
    excl_invalid = 0
    excl_rss_dedup = 0
    excl_state = 0
    excl_blocklist = 0

    for spec in query_specs:
        label = spec.get("label", "")
        query = spec["query"]
        count = spec.get("count", MAX_SEARCH_RESULTS)
        try:
            results = search_brave(query, lookback_hours, count)
        except RuntimeError as exc:
            # Auth failure is global, not per-query: the remaining queries
            # would each burn a request on the same 401. Stop searching and
            # let the run continue on the RSS pool alone.
            print(f"Warning: {exc} — skipping the rest of the search stage.")
            break
        for r in results:
            total_brave += 1
            norm = normalize_url(r["link"])
            if not norm:
                excl_invalid += 1
                continue
            if norm in rss_norm_urls or norm in seen_in_search:
                excl_rss_dedup += 1
                continue
            if is_excluded(r["link"], state, sent_only):
                excl_state += 1
                continue
            if _is_blocked(r):
                excl_blocklist += 1
                continue
            seen_in_search.add(norm)
            r["query_type"] = label
            r["query"] = query
            out.append(r)

    stats = {
        "fetched": total_brave,
        "after_rss_dedup": total_brave - excl_invalid - excl_rss_dedup,
        "after_state_dedup": total_brave - excl_invalid - excl_rss_dedup - excl_state,
        "after_blocklist": len(out),
    }
    print(f"Search returned {len(out)} unique new articles.")
    return out, stats


# ---------------------------------------------------------------------------
# Article text (second-pass enrichment)
# ---------------------------------------------------------------------------
# Used after triage selects items: fetch the chosen article so the LLM can
# refine why/action with more than the 350-char summary it selected on.
# Best-effort by design — any failure returns "" and the caller keeps the
# triage-time fields.

_SCRIPT_STYLE_RE = re.compile(
    r"<(script|style|noscript|svg)\b[^>]*>.*?</\1>",
    re.IGNORECASE | re.DOTALL,
)
ARTICLE_TEXT_MAX_CHARS = 4000
_ARTICLE_FETCH_MAX_BYTES = 1_000_000  # don't slurp unbounded responses


_ARTICLE_FETCH_MAX_REDIRECTS = 5


def _is_public_host(host: str) -> bool:
    """True if every address the host resolves to is globally routable.

    SSRF guard: the article URL originates in LLM output (influenced by
    untrusted article content), and the fetch runs on infrastructure with a
    metadata endpoint (169.254.169.254). Rejecting private/loopback/link-local
    targets closes that off.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        return False
    if not infos:
        return False
    try:
        return all(ipaddress.ip_address(info[4][0]).is_global for info in infos)
    except ValueError:
        return False


def fetch_article_text(url: str, max_chars: int = ARTICLE_TEXT_MAX_CHARS) -> str:
    """Fetch a selected article and return plain text (best-effort).

    The URL comes from LLM triage output, which echoes candidate-pool URLs but
    is still model output — enforce http(s) and a public-address host before
    fetching. Redirects are followed manually so every hop gets the same
    checks (a public host could otherwise redirect to the metadata endpoint).
    Content is untrusted web data; the enrichment prompt's trust boundary
    handles that.
    """
    # ponytail: host check is resolve-then-fetch, so a DNS-rebinding server
    # could still slip through; pin the resolved IP at connect time if that
    # ever matters here.
    try:
        for _ in range(_ARTICLE_FETCH_MAX_REDIRECTS + 1):
            if not url or not url.lower().startswith(("http://", "https://")):
                return ""
            host = urlsplit(url).hostname
            if not host or not _is_public_host(host):
                print(f"Article fetch blocked (non-public host): {url}")
                return ""
            resp = requests.get(
                url,
                headers={"User-Agent": HTTP_USER_AGENT},
                timeout=FEED_FETCH_TIMEOUT_SEC,
                stream=True,
                allow_redirects=False,
            )
            if resp.is_redirect or resp.is_permanent_redirect:
                location = resp.headers.get("Location", "")
                if not location:
                    return ""
                url = urljoin(url, location)
                continue
            if resp.status_code != 200:
                return ""
            content_type = resp.headers.get("Content-Type", "")
            if "html" not in content_type and "text" not in content_type:
                return ""
            raw = resp.raw.read(_ARTICLE_FETCH_MAX_BYTES, decode_content=True)
            body = raw.decode(resp.encoding or "utf-8", errors="replace")
            body = _SCRIPT_STYLE_RE.sub(" ", body)
            return _strip_html(body)[:max_chars]
        return ""  # redirect loop exceeded
    except (requests.RequestException, ValueError) as exc:
        print(f"Article fetch failed for {url}: {exc}")
        return ""
