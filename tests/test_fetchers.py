"""Tests for fetchers.py — blocklist matching, HTML stripping, cross-feed merge.

No tests for CVE extraction or KEV/EPSS enrichment: those were removed.
News-cycle triage happens entirely in the LLM.
"""

import datetime
import re
from types import SimpleNamespace
from unittest import mock

import pytest

import fetchers


# --- HTML stripping (applied to RSS summary + Brave description/title) ---

@pytest.mark.parametrize("raw, expected", [
    ("<p>hello <b>world</b></p>", "hello world"),
    ("AT&amp;T &quot;urgent&quot;", 'AT&T "urgent"'),
    ("a\n\n  b\t\tc", "a b c"),
    ("", ""),
    (None, ""),
])
def test_strip_html(raw, expected):
    assert fetchers._strip_html(raw) == expected


def test_strip_html_does_not_reanimate_encoded_tags():
    """Tags inside encoded entities must stay inert after unescape.

    Without strip-then-unescape ordering, &lt;script&gt;... would become
    <script>... and slip through.
    """
    out = fetchers._strip_html("&lt;script&gt;alert(1)&lt;/script&gt;")
    assert "<script>" not in out
    assert "</script>" not in out


def test_strip_html_strips_attributes():
    out = fetchers._strip_html('<a href="evil:x" onclick="alert(1)">link text</a>')
    assert "evil:x" not in out
    assert "onclick" not in out
    assert "link text" in out


# --- Blocklist matching rules (patched lists) ---

def _patterns(*terms):
    return [re.compile(r"\b" + re.escape(t) + r"\b", re.IGNORECASE) for t in terms]


def _art(link, title=None):
    return {"title": title or "Some article title", "link": link}


@pytest.mark.parametrize("term, title, blocked", [
    ("weekly recap", "Security Weekly Recap — Apr 15", True),
    ("weekly recap", "SECURITY WEEKLY RECAP", True),  # case-insensitive
    ("RSA", "RSA Conference 2026 recap", True),       # standalone term
    ("RSA", "pseudoRSA encryption scheme", False),    # not at a word boundary
])
def test_title_blocklist(monkeypatch, term, title, blocked):
    monkeypatch.setattr(fetchers, "_BLOCKLIST_TITLE_PATTERNS", _patterns(term))
    assert fetchers._is_blocked(_art("https://example.com/x", title)) is blocked


@pytest.mark.parametrize("domain, link, blocked", [
    ("spam.example.com", "https://spam.example.com/article", True),
    ("bad.com", "https://sub.bad.com/article", True),     # subdomains too
    ("spam.example.com", "https://other.com/article", False),
    ("bad.com", "https://notbad.com/article", False),     # suffix, not subdomain
])
def test_domain_blocklist(monkeypatch, domain, link, blocked):
    monkeypatch.setattr(fetchers, "BLOCKLIST_DOMAINS", [domain])
    assert fetchers._is_blocked(_art(link, "x")) is blocked


@pytest.mark.parametrize("pattern, link, blocked", [
    (r"/price[s]?/", "https://exchange.com/en/price/somecoin", True),
    (r"aws\.amazon\.com/compliance/", "https://AWS.Amazon.com/Compliance/FedRAMP/", True),
    # A genuine article on a non-markets path must survive.
    (r"reuters\.com/markets/", "https://reuters.com/technology/cybersecurity/breach-x", False),
])
def test_url_pattern_blocklist(monkeypatch, pattern, link, blocked):
    monkeypatch.setattr(fetchers, "_BLOCKLIST_URL_PATTERNS", [re.compile(pattern, re.IGNORECASE)])
    assert fetchers._is_blocked(_art(link, "x")) is blocked


def test_empty_blocklists(monkeypatch):
    monkeypatch.setattr(fetchers, "_BLOCKLIST_TITLE_PATTERNS", [])
    monkeypatch.setattr(fetchers, "BLOCKLIST_DOMAINS", [])
    monkeypatch.setattr(fetchers, "_BLOCKLIST_URL_PATTERNS", [])
    assert not fetchers._is_blocked(_art("https://any.com/x", "Anything"))


# --- Shipped blocklist (real config) ---
# Real backfill URLs observed in SKIP reports (June 2026).

@pytest.mark.parametrize("link, title", [
    # Bare homepages
    ("https://aws.amazon.com/", None),
    ("https://trust.wiz.io/", None),
    ("https://aws.amazon.com", None),
    # Section index pages
    ("https://aws.amazon.com/blogs/", None),
    ("https://aws.amazon.com/blogs/security/", None),
    ("https://aws.amazon.com/new/", None),
    ("https://aws.amazon.com/resources/analyst-reports/?trk=16c76003", None),
    ("https://github.com/advisories", None),
    ("https://docs.cloud.google.com/release-notes", None),
    ("https://status.cloud.google.com/", None),
    # Newsroom indexes (the June 22 anthropic.com/news miss)
    ("https://www.anthropic.com/news", None),
    ("https://openai.com/blog/", None),
    ("https://example.com/press?utm=x", None),
    # Patch Tuesday / monthly-update titles, YouTube
    ("https://windowsforum.com/threads/whatever", "Windows 11 June 2026 Patch Tuesday (June 9)"),
    ("https://example.com/x", "Android June Monthly Security Update explained"),
    ("https://www.youtube.com/watch?v=vK9fen8u2IE", None),
])
def test_shipped_blocklist_blocks(link, title):
    assert fetchers._is_blocked(_art(link, title))


@pytest.mark.parametrize("link, title", [
    ("https://aws.amazon.com/blogs/security/building-secure-b2c-applications/", None),
    ("https://github.com/advisories/GHSA-xxxx-yyyy-zzzz", None),
    ("https://www.bleepingcomputer.com/news/security/some-zero-day-story/", None),
    ("https://www.anthropic.com/news/claude-fable-5-mythos-5", None),
    ("https://example.com/x", "Emergency patch for actively exploited zero-day"),
])
def test_shipped_blocklist_keeps_real_articles(link, title):
    assert not fetchers._is_blocked(_art(link, title))


# --- Brave age filter ---

def _ago(**delta) -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(**delta)


# Token-fallback path (no cutoff supplied): preserves legacy behavior.
@pytest.mark.parametrize("age, stale", [
    ("2 weeks ago", True),
    ("1 month ago", True),
    ("1 year ago", True),
    ("2 Weeks Ago", True),  # case-insensitive
    ("3 hours ago", False),
    ("unknown", False),
    ("", False),
    (None, False),
])
def test_brave_age_token_fallback(age, stale):
    assert fetchers._is_stale_brave_age(age) is stale


# Cutoff-aware paths. ISO 8601 page_age values older than the lookback used to
# slip through and reach the triage LLM with a visibly old publication date.
@pytest.mark.parametrize("age, cutoff_hours, stale", [
    (_ago(days=6).isoformat(), 24, True),
    (_ago(hours=6).isoformat(), 24, False),
    (_ago(days=10).strftime("%Y-%m-%dT%H:%M:%SZ"), 24, True),       # Z suffix
    (_ago(days=10).replace(tzinfo=None).isoformat(), 24, True),     # naive = UTC
    (_ago(days=2).isoformat(), 72, False),  # Monday 72h catch-up keeps 2-day-old
    # "N days ago" relative form
    ("6 days ago", 24, True),
    ("6 days ago", 168, False),
    ("2 days ago", 24, True),
    ("1 day ago", 48, False),
    # Token fallback still wins when a cutoff is supplied but parse fails
    ("2 weeks ago", 24, True),
    # Hours/minutes/articles used to fall through and survive any lookback
    ("30 hours ago", 24, True),
    ("3 hours ago", 24, False),
    ("an hour ago", 24, False),
    ("90 minutes ago", 1, True),
    ("yesterday", 12, True),
    ("yesterday", 48, False),
])
def test_brave_age_with_cutoff(age, cutoff_hours, stale):
    assert fetchers._is_stale_brave_age(age, _ago(hours=cutoff_hours)) is stale


_GOOD = {"url": "https://ex.com/a", "title": "t", "page_age": "unknown"}


@pytest.mark.parametrize("body, kept", [
    ({"web": {"results": [_GOOD]}}, 1),
    ({"web": None}, 0),
    ({"web": {"results": None}}, 0),
    ([], 0),
    ({"web": {"results": ["junk", 42, _GOOD]}}, 1),
    ({"web": {"results": [dict(_GOOD, page_age=12345)]}}, 1),
    ({"web": {"results": [dict(_GOOD, title=["t"])]}}, 0),
])
def test_search_brave_survives_malformed_response(monkeypatch, body, kept):
    """A 200 with an odd shape must degrade to fewer results, not abort the run."""
    monkeypatch.setenv("BRAVE_API_KEY", "k")
    resp = mock.MagicMock(status_code=200)
    resp.json.return_value = body
    monkeypatch.setattr(fetchers.requests, "get", lambda *a, **kw: resp)
    assert len(fetchers.search_brave("q", 24)) == kept


# --- Search query attribution ---

def test_search_tags_results_with_query_attribution(monkeypatch):
    """Each surviving search result carries the query_type + query that found it."""
    monkeypatch.setattr(fetchers, "_BLOCKLIST_URL_PATTERNS", [])

    def fake_brave(query, lookback_hours, count=5):
        return [{"title": f"r-{query}", "link": f"https://ex.com/{query}",
                 "source": "[Web Search]", "published": "now", "summary": ""}]

    monkeypatch.setattr(fetchers, "search_brave", fake_brave)
    specs = [
        {"label": "independent", "query": "q1", "count": 3},
        {"label": "ai-lab", "query": "q2", "count": 5},
    ]
    out, stats = fetchers.fetch_search_articles(specs, 24, {}, [])
    by_url = {a["link"]: a for a in out}
    assert by_url["https://ex.com/q1"]["query_type"] == "independent"
    assert by_url["https://ex.com/q1"]["query"] == "q1"
    assert by_url["https://ex.com/q2"]["query_type"] == "ai-lab"
    assert stats["after_blocklist"] == 2


def test_search_first_query_owns_duplicate(monkeypatch):
    """When two queries surface the same URL, the first query keeps attribution."""
    monkeypatch.setattr(fetchers, "_BLOCKLIST_URL_PATTERNS", [])

    def fake_brave(query, lookback_hours, count=5):
        return [{"title": "dup", "link": "https://ex.com/same",
                 "source": "[Web Search]", "published": "now", "summary": ""}]

    monkeypatch.setattr(fetchers, "search_brave", fake_brave)
    specs = [
        {"label": "independent", "query": "first", "count": 3},
        {"label": "ai-lab", "query": "second", "count": 5},
    ]
    out, _ = fetchers.fetch_search_articles(specs, 24, {}, [])
    assert len(out) == 1
    assert out[0]["query_type"] == "independent"
    assert out[0]["query"] == "first"


# --- Cross-feed convergence annotation ---

def _rss_setup(monkeypatch, feeds, fake_parse):
    monkeypatch.setattr(fetchers, "FEEDS", feeds)
    monkeypatch.setattr(fetchers, "MAX_RSS_ARTICLES", 10)
    monkeypatch.setattr(fetchers, "PER_FEED_CAP", 5)
    monkeypatch.setattr(fetchers, "_BLOCKLIST_TITLE_PATTERNS", [])
    monkeypatch.setattr(fetchers, "BLOCKLIST_DOMAINS", [])
    monkeypatch.setattr(fetchers, "_parse_one_feed", fake_parse)


def test_cross_feed_convergence_preserves_duplicate_source(monkeypatch):
    """When two feeds carry a story with the same normalized title, the kept
    article carries the duplicate's source as 'also_sources' so the triage LLM
    sees source convergence."""
    def fake_parse(url, cutoff):
        if url == "feed-a":
            return [{"title": "Critical: OpenSSL flaw exploited",
                     "link": "https://a.example.com/x", "source": "Feed A",
                     "published": "2026-04-14", "summary": ""}]
        return [{"title": "Critical OpenSSL flaw exploited!",
                 "link": "https://b.example.com/x", "source": "Feed B",
                 "published": "2026-04-14", "summary": ""}]

    _rss_setup(monkeypatch, ["feed-a", "feed-b"], fake_parse)
    articles, _ = fetchers.fetch_rss_articles(24, {})
    assert len(articles) == 1
    kept = articles[0]
    assert kept["source"] == "Feed A"
    assert "Feed B" in kept.get("also_sources", [])


def test_cross_feed_convergence_no_annotation_for_unique_titles(monkeypatch):
    def fake_parse(url, cutoff):
        if url == "feed-a":
            return [{"title": "Story A", "link": "https://a.example.com/x",
                     "source": "Feed A", "published": "p", "summary": ""}]
        return [{"title": "Story B", "link": "https://b.example.com/y",
                 "source": "Feed B", "published": "p", "summary": ""}]

    _rss_setup(monkeypatch, ["feed-a", "feed-b"], fake_parse)
    articles, _ = fetchers.fetch_rss_articles(24, {})
    assert len(articles) == 2
    for a in articles:
        assert "also_sources" not in a or a["also_sources"] == []


def test_per_feed_cap_counts_only_surviving_items(monkeypatch):
    """Excluded items must not use up a feed's cap and hide a fresh story."""
    def fake_parse(url, cutoff):
        return [{"title": f"Story {n}", "link": f"https://ex.com/{n}",
                 "source": "Feed", "published": "p", "summary": ""}
                for n in range(7)]

    _rss_setup(monkeypatch, ["feed"], fake_parse)  # PER_FEED_CAP = 5
    sent = {fetchers.normalize_url(f"https://ex.com/{n}"):
            {"status": "sent", "date": "2099-01-01"} for n in range(5)}
    articles, _ = fetchers.fetch_rss_articles(24, sent)
    assert [a["link"] for a in articles] == ["https://ex.com/5", "https://ex.com/6"]


@pytest.mark.parametrize("a, b, same", [
    ("Critical: OpenSSL flaw!", "critical openssl flaw", True),
    ("漏洞公告：某产品", "另一条完全不同的新闻", False),  # CJK no longer keys to ""
    ("🔥🔥", "🚨🚨", False),  # no word chars: keys on the title itself
])
def test_title_key(a, b, same):
    assert (fetchers._title_key(a) == fetchers._title_key(b)) is same


def test_cross_feed_convergence_three_way(monkeypatch):
    """Three feeds covering one story → kept article lists the other two as also_sources."""
    def fake_parse(url, cutoff):
        return [{"title": "Same story", "link": f"https://{url}.example.com/x",
                 "source": f"Source {url.upper()}", "published": "p", "summary": ""}]

    _rss_setup(monkeypatch, ["a", "b", "c"], fake_parse)
    articles, _ = fetchers.fetch_rss_articles(24, {})
    assert len(articles) == 1
    also = articles[0].get("also_sources", [])
    assert "Source B" in also
    assert "Source C" in also


# --- Brave auth failure must not abort the run (RSS path stays alive) ---

def test_search_auth_failure_returns_empty_and_stops(monkeypatch):
    """A bad/expired BRAVE_API_KEY used to propagate out of fetch_search_articles
    and kill the run before triage, discarding a healthy RSS pool. Auth is
    global, so the remaining queries must not each burn a request."""
    monkeypatch.setattr(fetchers, "_BLOCKLIST_URL_PATTERNS", [])
    calls = []

    def fake_brave(query, lookback_hours, count=5):
        calls.append(query)
        raise RuntimeError("Brave Search auth failure: 401")

    monkeypatch.setattr(fetchers, "search_brave", fake_brave)
    specs = [{"label": "independent", "query": f"q{i}", "count": 3} for i in range(5)]
    out, stats = fetchers.fetch_search_articles(specs, 24, {}, [])
    assert out == []
    assert stats["after_blocklist"] == 0
    assert calls == ["q0"]


# --- entry_published fallback ---

def test_entry_published_falls_back_when_published_is_malformed():
    """A malformed published_parsed used to `break` out of the loop, skipping
    the updated_parsed fallback entirely."""
    entry = SimpleNamespace(published_parsed=("not", "a", "time", "tuple", 0, 0),
                   updated_parsed=(2026, 4, 14, 9, 30, 0, 0, 0, 0))
    got = fetchers.entry_published(entry)
    assert got is not None
    assert (got.year, got.month, got.day) == (2026, 4, 14)


def test_entry_published_returns_none_when_both_malformed():
    entry = SimpleNamespace(published_parsed=("x",) * 6, updated_parsed=("y",) * 6)
    assert fetchers.entry_published(entry) is None


# --- linkless RSS entries ---

def test_parse_one_feed_drops_entries_without_a_link(monkeypatch):
    """A linkless entry can only reach triage as an item the model must invent
    a URL for, so it must not consume a pool slot."""
    xml = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>F</title>
      <item><title>Has a link</title><link>https://ex.com/a</link></item>
      <item><title>No link at all</title></item>
    </channel></rss>"""
    monkeypatch.setattr(fetchers, "_fetch_feed_bytes", lambda url: xml)
    out = fetchers._parse_one_feed("f", _ago(hours=24))
    assert [a["title"] for a in out] == ["Has a link"]


def test_parse_one_feed_resolves_links_and_dedups_title_variants(monkeypatch):
    xml = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>F</title>
      <item><title>Critical: Foo flaw</title><link>/posts/foo</link></item>
      <item><title>Critical Foo flaw!</title><link>/posts/foo-2</link></item>
    </channel></rss>"""
    monkeypatch.setattr(fetchers, "_fetch_feed_bytes", lambda url: xml)
    out = fetchers._parse_one_feed("https://blog.example.com/feed.xml", _ago(hours=24))
    assert [a["link"] for a in out] == ["https://blog.example.com/posts/foo"]
