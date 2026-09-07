"""Tests for fetchers.py — blocklist matching, HTML stripping, cross-feed merge.

No tests for CVE extraction or KEV/EPSS enrichment: those were removed.
News-cycle triage happens entirely in the LLM.
"""

import datetime
import re
import fetchers


# --- HTML stripping (applied to RSS summary + Brave description/title) ---

def test_strip_html_removes_simple_tags():
    assert fetchers._strip_html("<p>hello <b>world</b></p>") == "hello world"


def test_strip_html_unescapes_entities():
    assert fetchers._strip_html("AT&amp;T &quot;urgent&quot;") == 'AT&T "urgent"'


def test_strip_html_does_not_reanimate_encoded_tags():
    """Tags inside encoded entities must stay inert after unescape.

    Without strip-then-unescape ordering, &lt;script&gt;... would become
    <script>... and slip through.
    """
    out = fetchers._strip_html("&lt;script&gt;alert(1)&lt;/script&gt;")
    assert "<script>" not in out
    assert "</script>" not in out


def test_strip_html_collapses_whitespace():
    assert fetchers._strip_html("a\n\n  b\t\tc") == "a b c"


def test_strip_html_handles_empty_and_none():
    assert fetchers._strip_html("") == ""
    assert fetchers._strip_html(None) == ""


def test_strip_html_strips_attributes():
    out = fetchers._strip_html('<a href="evil:x" onclick="alert(1)">link text</a>')
    assert "evil:x" not in out
    assert "onclick" not in out
    assert "link text" in out


# --- Blocklist ---

def _patterns(*terms):
    return [re.compile(r"\b" + re.escape(t) + r"\b", re.IGNORECASE) for t in terms]


def test_blocked_by_title_substring(monkeypatch):
    monkeypatch.setattr(fetchers, "_BLOCKLIST_TITLE_PATTERNS", _patterns("weekly recap"))
    article = {"title": "Security Weekly Recap — Apr 15",
               "link": "https://example.com/x"}
    assert fetchers._is_blocked(article)


def test_blocked_title_is_case_insensitive(monkeypatch):
    monkeypatch.setattr(fetchers, "_BLOCKLIST_TITLE_PATTERNS", _patterns("weekly recap"))
    article = {"title": "SECURITY WEEKLY RECAP", "link": "https://example.com/x"}
    assert fetchers._is_blocked(article)


def test_word_boundary_matches_standalone_term(monkeypatch):
    monkeypatch.setattr(fetchers, "_BLOCKLIST_TITLE_PATTERNS", _patterns("RSA"))
    assert fetchers._is_blocked({"title": "RSA Conference 2026 recap", "link": "https://example.com/x"})


def test_word_boundary_does_not_match_embedded_term(monkeypatch):
    # "pseudoRSA" — RSA is not at a word boundary, so \bRSA\b should not match
    monkeypatch.setattr(fetchers, "_BLOCKLIST_TITLE_PATTERNS", _patterns("RSA"))
    assert not fetchers._is_blocked({"title": "pseudoRSA encryption scheme", "link": "https://example.com/x"})


def test_blocked_by_domain_exact(monkeypatch):
    monkeypatch.setattr(fetchers, "BLOCKLIST_DOMAINS", ["spam.example.com"])
    assert fetchers._is_blocked({
        "title": "x", "link": "https://spam.example.com/article",
    })


def test_blocked_by_domain_subdomain(monkeypatch):
    """Blocklist of 'bad.com' should also block 'sub.bad.com'."""
    monkeypatch.setattr(fetchers, "BLOCKLIST_DOMAINS", ["bad.com"])
    assert fetchers._is_blocked({
        "title": "x", "link": "https://sub.bad.com/article",
    })


def test_not_blocked_unrelated_domain(monkeypatch):
    monkeypatch.setattr(fetchers, "BLOCKLIST_DOMAINS", ["spam.example.com"])
    assert not fetchers._is_blocked({
        "title": "x", "link": "https://other.com/article",
    })


def test_not_blocked_similar_but_different(monkeypatch):
    """'bad.com' should NOT block 'notbad.com'."""
    monkeypatch.setattr(fetchers, "BLOCKLIST_DOMAINS", ["bad.com"])
    assert not fetchers._is_blocked({
        "title": "x", "link": "https://notbad.com/article",
    })


def test_empty_blocklists(monkeypatch):
    monkeypatch.setattr(fetchers, "_BLOCKLIST_TITLE_PATTERNS", [])
    monkeypatch.setattr(fetchers, "BLOCKLIST_DOMAINS", [])
    monkeypatch.setattr(fetchers, "_BLOCKLIST_URL_PATTERNS", [])
    assert not fetchers._is_blocked({
        "title": "Anything", "link": "https://any.com/x",
    })


# --- URL-pattern blocklist (evergreen index / price / marketing pages) ---

def test_blocked_by_url_pattern(monkeypatch):
    monkeypatch.setattr(fetchers, "_BLOCKLIST_URL_PATTERNS",
                        [re.compile(r"/price[s]?/", re.IGNORECASE)])
    assert fetchers._is_blocked({
        "title": "Some Coin Live Price", "link": "https://exchange.com/en/price/somecoin",
    })


def test_url_pattern_is_case_insensitive(monkeypatch):
    monkeypatch.setattr(fetchers, "_BLOCKLIST_URL_PATTERNS",
                        [re.compile(r"aws\.amazon\.com/compliance/", re.IGNORECASE)])
    assert fetchers._is_blocked({
        "title": "FedRAMP", "link": "https://AWS.Amazon.com/Compliance/FedRAMP/",
    })


def test_url_pattern_does_not_block_real_article(monkeypatch):
    monkeypatch.setattr(fetchers, "_BLOCKLIST_URL_PATTERNS",
                        [re.compile(r"reuters\.com/markets/", re.IGNORECASE)])
    # A genuine article on a non-markets path must survive.
    assert not fetchers._is_blocked({
        "title": "Breach report", "link": "https://reuters.com/technology/cybersecurity/breach-x",
    })


# --- Brave age filter ---

def _cutoff(hours: int) -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours)


# Token-fallback path (no cutoff supplied): preserves legacy behavior.

def test_stale_age_week():
    assert fetchers._is_stale_brave_age("2 weeks ago")


def test_stale_age_month():
    assert fetchers._is_stale_brave_age("1 month ago")


def test_stale_age_year():
    assert fetchers._is_stale_brave_age("1 year ago")


def test_stale_age_case_insensitive():
    assert fetchers._is_stale_brave_age("2 Weeks Ago")


def test_fresh_age_hours():
    assert not fetchers._is_stale_brave_age("3 hours ago")


def test_fresh_age_unknown():
    assert not fetchers._is_stale_brave_age("unknown")


def test_fresh_age_empty():
    assert not fetchers._is_stale_brave_age("")


def test_fresh_age_none():
    assert not fetchers._is_stale_brave_age(None)


# ISO 8601 page_age path (cutoff-aware): a date-format value older than the
# lookback should be filtered. Previously these slipped through and reached
# the triage LLM with a visibly old publication date.

def test_iso_age_older_than_cutoff_is_stale():
    old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=6)).isoformat()
    assert fetchers._is_stale_brave_age(old, _cutoff(24))


def test_iso_age_within_cutoff_is_fresh():
    recent = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=6)).isoformat()
    assert not fetchers._is_stale_brave_age(recent, _cutoff(24))


def test_iso_age_with_z_suffix():
    old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert fetchers._is_stale_brave_age(old, _cutoff(24))


def test_iso_age_naive_treated_as_utc():
    old_naive = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)).replace(tzinfo=None).isoformat()
    assert fetchers._is_stale_brave_age(old_naive, _cutoff(24))


def test_iso_age_72h_lookback_includes_2_day_old():
    """Monday catchup runs with 72h lookback; a 2-day-old item should be fresh."""
    two_days_ago = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=2)).isoformat()
    assert not fetchers._is_stale_brave_age(two_days_ago, _cutoff(72))


# "N days ago" relative path

def test_relative_days_older_than_cutoff_is_stale():
    assert fetchers._is_stale_brave_age("6 days ago", _cutoff(24))


def test_relative_days_within_cutoff_is_fresh():
    assert not fetchers._is_stale_brave_age("6 days ago", _cutoff(168))  # 7-day cutoff


def test_relative_single_day():
    assert fetchers._is_stale_brave_age("2 days ago", _cutoff(24))
    assert not fetchers._is_stale_brave_age("1 day ago", _cutoff(48))


# Token fallback still wins when cutoff is supplied but parse fails

def test_token_fallback_when_unparseable_with_cutoff():
    assert fetchers._is_stale_brave_age("2 weeks ago", _cutoff(24))


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

def test_cross_feed_convergence_preserves_duplicate_source(monkeypatch):
    """When two feeds carry a story with the same normalized title, the kept
    article carries the duplicate's source as 'also_sources' so the triage LLM
    sees source convergence."""
    monkeypatch.setattr(fetchers, "FEEDS", ["feed-a", "feed-b"])
    monkeypatch.setattr(fetchers, "MAX_RSS_ARTICLES", 10)
    monkeypatch.setattr(fetchers, "PER_FEED_CAP", 5)
    monkeypatch.setattr(fetchers, "_BLOCKLIST_TITLE_PATTERNS", [])
    monkeypatch.setattr(fetchers, "BLOCKLIST_DOMAINS", [])

    def fake_parse(url, cutoff):
        if url == "feed-a":
            return [{"title": "Critical: OpenSSL flaw exploited",
                     "link": "https://a.example.com/x", "source": "Feed A",
                     "published": "2026-04-14", "summary": ""}]
        return [{"title": "Critical OpenSSL flaw exploited!",
                 "link": "https://b.example.com/x", "source": "Feed B",
                 "published": "2026-04-14", "summary": ""}]

    monkeypatch.setattr(fetchers, "_parse_one_feed", fake_parse)
    articles, _ = fetchers.fetch_rss_articles(24, {})
    assert len(articles) == 1
    kept = articles[0]
    assert kept["source"] == "Feed A"
    assert "Feed B" in kept.get("also_sources", [])


def test_cross_feed_convergence_no_annotation_for_unique_titles(monkeypatch):
    monkeypatch.setattr(fetchers, "FEEDS", ["feed-a", "feed-b"])
    monkeypatch.setattr(fetchers, "MAX_RSS_ARTICLES", 10)
    monkeypatch.setattr(fetchers, "PER_FEED_CAP", 5)
    monkeypatch.setattr(fetchers, "_BLOCKLIST_TITLE_PATTERNS", [])
    monkeypatch.setattr(fetchers, "BLOCKLIST_DOMAINS", [])

    def fake_parse(url, cutoff):
        if url == "feed-a":
            return [{"title": "Story A", "link": "https://a.example.com/x",
                     "source": "Feed A", "published": "p", "summary": ""}]
        return [{"title": "Story B", "link": "https://b.example.com/y",
                 "source": "Feed B", "published": "p", "summary": ""}]

    monkeypatch.setattr(fetchers, "_parse_one_feed", fake_parse)
    articles, _ = fetchers.fetch_rss_articles(24, {})
    assert len(articles) == 2
    for a in articles:
        assert "also_sources" not in a or a["also_sources"] == []


def test_cross_feed_convergence_three_way(monkeypatch):
    """Three feeds covering one story → kept article lists the other two as also_sources."""
    monkeypatch.setattr(fetchers, "FEEDS", ["a", "b", "c"])
    monkeypatch.setattr(fetchers, "MAX_RSS_ARTICLES", 10)
    monkeypatch.setattr(fetchers, "PER_FEED_CAP", 5)
    monkeypatch.setattr(fetchers, "_BLOCKLIST_TITLE_PATTERNS", [])
    monkeypatch.setattr(fetchers, "BLOCKLIST_DOMAINS", [])

    def fake_parse(url, cutoff):
        return [{"title": "Same story", "link": f"https://{url}.example.com/x",
                 "source": f"Source {url.upper()}", "published": "p", "summary": ""}]

    monkeypatch.setattr(fetchers, "_parse_one_feed", fake_parse)
    articles, _ = fetchers.fetch_rss_articles(24, {})
    assert len(articles) == 1
    also = articles[0].get("also_sources", [])
    assert "Source B" in also
    assert "Source C" in also


# --- Blocklist additions from skip-report review (June 2026) ---
# Real backfill URLs observed in SKIP reports; all should be blocked.

def _art(link, title="Some article title"):
    return {"title": title, "link": link}


def test_blocklist_bare_homepages():
    assert fetchers._is_blocked(_art("https://aws.amazon.com/"))
    assert fetchers._is_blocked(_art("https://trust.wiz.io/"))
    assert fetchers._is_blocked(_art("https://aws.amazon.com"))


def test_blocklist_section_index_pages():
    assert fetchers._is_blocked(_art("https://aws.amazon.com/blogs/"))
    assert fetchers._is_blocked(_art("https://aws.amazon.com/blogs/security/"))
    assert fetchers._is_blocked(_art("https://aws.amazon.com/new/"))
    assert fetchers._is_blocked(_art(
        "https://aws.amazon.com/resources/analyst-reports/?trk=16c76003"))
    assert fetchers._is_blocked(_art("https://github.com/advisories"))
    assert fetchers._is_blocked(_art(
        "https://docs.cloud.google.com/release-notes"))
    assert fetchers._is_blocked(_art("https://status.cloud.google.com/"))
    # Newsroom indexes (the June 22 anthropic.com/news miss)
    assert fetchers._is_blocked(_art("https://www.anthropic.com/news"))
    assert fetchers._is_blocked(_art("https://openai.com/blog/"))
    assert fetchers._is_blocked(_art("https://example.com/press?utm=x"))


def test_blocklist_real_articles_not_blocked():
    assert not fetchers._is_blocked(_art(
        "https://aws.amazon.com/blogs/security/building-secure-b2c-applications/"))
    assert not fetchers._is_blocked(_art(
        "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"))
    assert not fetchers._is_blocked(_art(
        "https://www.bleepingcomputer.com/news/security/some-zero-day-story/"))
    assert not fetchers._is_blocked(_art(
        "https://www.anthropic.com/news/claude-fable-5-mythos-5"))


def test_blocklist_patch_tuesday_title_and_youtube():
    assert fetchers._is_blocked(_art(
        "https://windowsforum.com/threads/whatever", title="Windows 11 June 2026 Patch Tuesday (June 9)"))
    assert fetchers._is_blocked(_art(
        "https://example.com/x", title="Android June Monthly Security Update explained"))
    assert fetchers._is_blocked(_art("https://www.youtube.com/watch?v=vK9fen8u2IE"))
    assert not fetchers._is_blocked(_art(
        "https://example.com/x", title="Emergency patch for actively exploited zero-day"))


# --- Brave auth failure must not abort the run (RSS path stays alive) ---

def test_search_auth_failure_returns_empty_instead_of_raising(monkeypatch):
    """A bad/expired BRAVE_API_KEY used to propagate out of fetch_search_articles
    and kill the run before triage, discarding a healthy RSS pool."""
    monkeypatch.setattr(fetchers, "_BLOCKLIST_URL_PATTERNS", [])

    def fake_brave(query, lookback_hours, count=5):
        raise RuntimeError("Brave Search auth failure: 401")

    monkeypatch.setattr(fetchers, "search_brave", fake_brave)
    specs = [{"label": "independent", "query": "q1", "count": 3}]
    out, stats = fetchers.fetch_search_articles(specs, 24, {}, [])
    assert out == []
    assert stats["after_blocklist"] == 0


def test_search_auth_failure_stops_remaining_queries(monkeypatch):
    """Auth is global, so the remaining queries must not each burn a request."""
    monkeypatch.setattr(fetchers, "_BLOCKLIST_URL_PATTERNS", [])
    calls = []

    def fake_brave(query, lookback_hours, count=5):
        calls.append(query)
        raise RuntimeError("Brave Search auth failure: 403")

    monkeypatch.setattr(fetchers, "search_brave", fake_brave)
    specs = [{"label": "independent", "query": f"q{i}", "count": 3} for i in range(5)]
    fetchers.fetch_search_articles(specs, 24, {}, [])
    assert calls == ["q0"]


# --- entry_published fallback ---

class _Entry:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def test_entry_published_falls_back_when_published_is_malformed():
    """A malformed published_parsed used to `break` out of the loop, skipping
    the updated_parsed fallback entirely."""
    entry = _Entry(published_parsed=("not", "a", "time", "tuple", 0, 0),
                   updated_parsed=(2026, 4, 14, 9, 30, 0, 0, 0, 0))
    got = fetchers.entry_published(entry)
    assert got is not None
    assert (got.year, got.month, got.day) == (2026, 4, 14)


def test_entry_published_returns_none_when_both_malformed():
    entry = _Entry(published_parsed=("x",) * 6, updated_parsed=("y",) * 6)
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
    out = fetchers._parse_one_feed("f", _cutoff(24))
    assert [a["title"] for a in out] == ["Has a link"]
