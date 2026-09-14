#!/usr/bin/env python3
"""Feed health check — run manually via workflow_dispatch (or weekly cron)
to verify all configured feeds are reachable and returning recent articles.
Does not call the LLM or send email.
"""

import datetime
import sys
import io
import feedparser
import requests

from config import FEEDS, FEED_FETCH_TIMEOUT_SEC, HTTP_USER_AGENT
from fetchers import entry_published

LOOKBACK_HOURS = 72


def check_feeds() -> bool:
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=LOOKBACK_HOURS)
    any_failed = False
    stale = 0

    # An empty list used to fall through to "All feeds reachable" and exit 0.
    if not FEEDS:
        print("⚠️  No feeds configured (feeds.md missing or has no links).")
        return False

    print(f"Feed health check — lookback {LOOKBACK_HOURS}h\n")
    print(f"{'STATUS':<14} {'RECENT':>6}  {'TOTAL':>5}  TITLE")
    print("-" * 72)

    for url in FEEDS:
        try:
            resp = requests.get(
                url,
                timeout=FEED_FETCH_TIMEOUT_SEC,
                headers={"User-Agent": HTTP_USER_AGENT},
            )
            http_status = resp.status_code
            feed = feedparser.parse(io.BytesIO(resp.content))
        except requests.RequestException as exc:
            print(f"{'DEAD(net)':<14} {'-':>6}  {'-':>5}  {url[:40]}")
            print(f"{'':14} {'':>6}  {'':>5}  → {exc}")
            any_failed = True
            continue

        total = len(feed.entries)
        recent = 0
        for entry in feed.entries:
            published = entry_published(entry)
            if published and published >= cutoff:
                recent += 1

        title = feed.feed.get("title", "")[:40] or url[:40]
        if http_status not in (200, 301, 302) or total == 0:
            status_str = f"DEAD({http_status})"
            any_failed = True
        elif recent == 0:
            status_str = "STALE"
            stale += 1
        else:
            status_str = "OK"

        print(f"{status_str:<14} {recent:>6}  {total:>5}  {title}")
        if status_str.startswith("DEAD"):
            print(f"{'':14} {'':>6}  {'':>5}  → {url}")

    print()
    if any_failed:
        print("⚠️  One or more feeds are unreachable. Check URLs above.")
        return False
    # One quiet blog is normal; every feed quiet at once points at our date
    # parsing or fetching, not at the feeds.
    if stale == len(FEEDS):
        print(f"⚠️  Every feed is STALE (nothing in {LOOKBACK_HOURS}h) — "
              f"likely a date-parsing or fetch problem.")
        return False
    print("✅  All feeds reachable.")
    return True


if __name__ == "__main__":
    sys.exit(0 if check_feeds() else 1)
