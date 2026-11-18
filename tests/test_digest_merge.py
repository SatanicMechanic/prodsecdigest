"""Tests for digest._merge_triage_results and total-triage-failure handling."""

import pytest
from digest import _merge_triage_results, _fail_on_total_triage_failure


def _item(url, category="threat", headline=None):
    return {
        "headline": headline or f"headline for {url}",
        "category": category,
        "severity": "high",
        "why": "why",
        "action": "act",
        "url": url,
    }


# --- both-skip path ---

@pytest.mark.parametrize("a, b, urls", [
    (None, None, []),
    ([], [], []),
    (None, [_item("https://b.com", "tooling")], ["https://b.com"]),
    ([_item("https://a.com", "threat")], None, ["https://a.com"]),
])
def test_merge_skip_and_empty_inputs(a, b, urls):
    assert [r["url"] for r in _merge_triage_results(a, b)] == urls


# --- URL dedupe: A wins on tie ---

def test_url_dedupe_a_wins():
    shared_url = "https://shared.com"
    a = [_item(shared_url, "threat", "threat headline")]
    b = [_item(shared_url, "tooling", "tooling headline")]
    result = _merge_triage_results(a, b)
    assert len(result) == 1
    assert result[0]["category"] == "threat"
    assert result[0]["headline"] == "threat headline"


@pytest.mark.parametrize("a, b", [
    ([_item("https://Example.COM/path")], [_item("https://example.com/path", "tooling")]),
    # One URL-equality rule: tracking params and trailing slashes collapse here
    # instead of surviving as two items.
    ([_item("https://ex.com/x?utm_source=nl"), _item("https://ex.com/x")], []),
    ([_item("https://ex.com/x/")], [_item("https://ex.com/x")]),
])
def test_url_dedupe_variants(a, b):
    assert len(_merge_triage_results(a, b)) == 1


# --- tooling cap = 1 ---

def test_tooling_cap_is_one(monkeypatch):
    import digest
    monkeypatch.setattr(digest, "TRIAGE_TOOLING_CAP", 1)
    monkeypatch.setattr(digest, "TRIAGE_GLOBAL_CAP", 3)
    b = [_item("https://t1.com", "tooling"), _item("https://t2.com", "tooling")]
    result = _merge_triage_results([], b)
    assert len(result) == 1
    assert result[0]["url"] == "https://t1.com"


# --- global cap = 3 ---

def test_global_cap_is_three(monkeypatch):
    import digest
    monkeypatch.setattr(digest, "TRIAGE_TOOLING_CAP", 1)
    monkeypatch.setattr(digest, "TRIAGE_GLOBAL_CAP", 3)
    a = [
        _item("https://a1.com"), _item("https://a2.com"), _item("https://a3.com"),
    ]
    b = [_item("https://b1.com", "tooling")]
    result = _merge_triage_results(a, b)
    assert len(result) == 3
    assert all(r["url"] != "https://b1.com" for r in result)


# --- ordering: threat first, then tooling ---

def test_ordering_threat_before_tooling():
    a = [_item("https://threat.com", "threat")]
    b = [_item("https://tool.com", "tooling")]
    result = _merge_triage_results(a, b)
    assert result[0]["url"] == "https://threat.com"
    assert result[1]["url"] == "https://tool.com"


# --- items with missing or blank url are skipped in dedup ---

@pytest.mark.parametrize("url", ["", None])
def test_items_without_url_are_excluded(url):
    assert _merge_triage_results([_item(url)], None) == []


# --- _fail_on_total_triage_failure: both calls erroring must be loud ---

def test_fail_on_total_triage_failure_raises_with_errors():
    with pytest.raises(RuntimeError, match="Both triage calls failed"):
        _fail_on_total_triage_failure(ValueError("bad key"), TimeoutError("slow"))
    with pytest.raises(RuntimeError, match="bad key"):
        _fail_on_total_triage_failure(ValueError("bad key"), None)


# --- URL grounding (triage output must point at the pool we showed the model) ---

from digest import _ground_urls  # noqa: E402


@pytest.mark.parametrize("urls, pool, expected", [
    # An invented URL would be emailed to the reader and fetched by the
    # enrichment pass, so it must not survive triage.
    (["https://ex.com/real", "https://evil.example/invented"], {"https://ex.com/real"},
     ["https://ex.com/real"]),
    # A pool URL echoed back with tracking params or a trailing slash is real;
    # keep it, rewritten to the form state suppression and merge dedupe use.
    (["https://ex.com/story/?utm_source=newsletter"], {"https://ex.com/story"},
     ["https://ex.com/story"]),
    (["https://ex.com/a"], set(), []),
])
def test_ground_urls(urls, pool, expected):
    assert [i["url"] for i in _ground_urls([_item(u) for u in urls], pool)] == expected


def test_ground_urls_passes_skip_through():
    assert _ground_urls(None, {"https://ex.com/a"}) is None


# --- Emergency re-check bar ---

from digest import _emergency_filter, _no_digest_reason, _empty_pool_report  # noqa: E402


@pytest.mark.parametrize("category, severity, count, kept", [
    ("threat", "critical", 1, 1),
    # High is digest-worthy but not worth re-interrupting a reader who
    # already got today's digest.
    ("threat", "high", 1, 0),
    ("tooling", "critical", 1, 0),
    ("threat", "critical", 3, 1),  # capped at one
])
def test_emergency_filter(category, severity, count, kept):
    items = [dict(_item(f"https://ex.com/{n}", category), severity=severity)
             for n in range(count)]
    assert len(_emergency_filter(items)) == kept


def test_emergency_gate_runs_before_global_cap(monkeypatch):
    """A critical threat ranked past the cap must still reach the gate."""
    import digest
    monkeypatch.setattr(digest, "TRIAGE_GLOBAL_CAP", 3)
    threats = [_item(f"https://ex.com/{n}") for n in range(4)]
    threats[3]["severity"] = "critical"
    out = _merge_triage_results(threats, [], emergency=True)
    assert [i["url"] for i in out] == ["https://ex.com/3"]


# --- Degraded vs healthy skip ---

@pytest.mark.parametrize("degraded, emergency, present, absent", [
    (["threat triage returned unparseable JSON"], False, ["DEGRADED", "unparseable JSON"], []),
    (["threat triage call failed"], True, ["DEGRADED"], []),  # degraded wins
    ([], False, ["SKIP"], ["DEGRADED"]),
    ([], True, ["Emergency re-check clear"], ["DEGRADED"]),
])
def test_no_digest_reason(degraded, emergency, present, absent):
    msg = _no_digest_reason(degraded, emergency)
    assert all(s in msg for s in present)
    assert not any(s in msg for s in absent)


_NO_SEARCH = {"fetched": 0, "after_rss_dedup": 0, "after_state_dedup": 0, "after_blocklist": 0}


@pytest.mark.parametrize("rss, search, present", [
    # Nothing published: say so, rather than a bare "No articles found".
    ({"fetched": 0, "after_state_dedup": 0, "after_blocklist": 0}, _NO_SEARCH,
     ["no feed entries published in the last 72h", "Search: 0 returned"]),
    # Published but all already seen: the funnel shows where it went.
    ({"fetched": 5, "after_state_dedup": 0, "after_blocklist": 0},
     {"fetched": 4, "after_rss_dedup": 3, "after_state_dedup": 0, "after_blocklist": 0},
     ["RSS: 5 in window -> 0 after state dedup", "Search: 4 returned", "3 after RSS dedup"]),
])
def test_empty_pool_report(rss, search, present):
    msg = _empty_pool_report(72, rss, search)
    assert all(s in msg for s in present)


# --- Lookback window ---

from digest import get_lookback_hours  # noqa: E402


@pytest.mark.parametrize("now, hours", [
    ("2026-09-14T13:16", 72),  # Monday morning run
    # Monday's 22:43 UTC evening run firing late, past UTC midnight, is still
    # Monday's run and still covers the weekend.
    ("2026-09-15T00:54", 72),
    ("2026-09-15T12:03", 24),  # Tuesday morning
])
def test_lookback_follows_digest_day(freeze_utc, now, hours):
    freeze_utc(now)
    assert get_lookback_hours() == hours


# --- run(): a failed threat triage must not poison cooldown or exit green ---

from digest import _fail_on_threat_degraded  # noqa: E402


def test_fail_on_threat_degraded_only_for_threat_reasons():
    _fail_on_threat_degraded([])
    _fail_on_threat_degraded(["tooling triage call failed"])  # low-stakes: stays green
    with pytest.raises(RuntimeError, match="Threat triage degraded"):
        _fail_on_threat_degraded(["tooling triage call failed",
                                  "threat triage returned unparseable JSON"])


def _run_with(monkeypatch, tmp_path, threat_raw, tooling_raw):
    """Drive digest.run() with one RSS candidate and canned LLM answers
    (an Exception instance is raised instead of returned)."""
    import digest

    saved: list = []
    article = {"title": "t", "link": "https://ex.com/a", "source": "s",
               "published": "now", "summary": "x"}
    rss_stats = {"fetched": 1, "after_state_dedup": 1, "after_blocklist": 1,
                 "after_cross_feed_dedup": 1}

    def fake_llm(system, user, **kw):
        out = threat_raw if "prompt_threat" in system else tooling_raw
        if isinstance(out, Exception):
            raise out
        return out

    monkeypatch.setattr(digest, "__file__", str(tmp_path / "digest.py"))  # last_run.txt
    monkeypatch.setattr(digest, "_check_env", lambda: None)
    monkeypatch.setattr(digest, "load_state", lambda: {})
    monkeypatch.setattr(digest, "save_state", lambda st: saved.append(dict(st)))
    monkeypatch.setattr(digest, "fetch_rss_articles", lambda *a, **k: ([article], rss_stats))
    monkeypatch.setattr(digest, "generate_anchored_queries", lambda a: [])
    monkeypatch.setattr(digest, "QUERY_SLOTS", ())
    monkeypatch.setattr(digest, "_load_prompt", lambda f, *a: f)
    monkeypatch.setattr(digest, "call_llm", fake_llm)
    return digest, saved


def test_failed_threat_triage_leaves_no_cooldown_and_fails_the_run(monkeypatch, tmp_path):
    digest, saved = _run_with(monkeypatch, tmp_path,
                              RuntimeError("timeout"), '{"skip": true}')
    with pytest.raises(RuntimeError, match="Threat triage degraded"):
        digest.run()
    assert saved and all(not s for s in saved)  # state saved, nothing cooled down


def test_clean_skip_still_cools_down_candidates(monkeypatch, tmp_path):
    digest, saved = _run_with(monkeypatch, tmp_path, '{"skip": true}', '{"skip": true}')
    digest.run()  # no raise
    assert saved[-1]["https://ex.com/a"]["status"] == "candidate"


def test_triage_futures_carry_no_deadline_of_their_own(monkeypatch, tmp_path):
    # A future-level timeout cannot bound the run (the executor's `with` waits
    # for its threads anyway); it can only discard an answer that was about to
    # arrive. 2026-11-17/18: a 70s one failed two runs mid-retry.
    import concurrent.futures
    digest, _ = _run_with(monkeypatch, tmp_path, '{"skip": true}', '{"skip": true}')
    seen = []
    real = concurrent.futures.Future.result

    def spy(self, timeout=None):
        seen.append(timeout)
        return real(self, timeout)

    monkeypatch.setattr(concurrent.futures.Future, "result", spy)
    digest.run()
    assert seen and all(t is None for t in seen)


# --- last-clean-triage stamp: written only by a clean, full triage ---

def _stamp(saved):
    import state
    return state.last_clean_triage(saved[-1]) if saved else None


def test_a_clean_run_stamps_the_triage_time(monkeypatch, tmp_path):
    digest, saved = _run_with(monkeypatch, tmp_path, '{"skip": true}', '{"skip": true}')
    digest.run()
    assert _stamp(saved) is not None


def test_a_degraded_run_does_not_stamp(monkeypatch, tmp_path):
    digest, saved = _run_with(monkeypatch, tmp_path,
                              RuntimeError("timeout"), '{"skip": true}')
    with pytest.raises(RuntimeError, match="Threat triage degraded"):
        digest.run()
    assert saved and _stamp(saved) is None


def test_the_emergency_recheck_does_not_stamp(monkeypatch, tmp_path):
    # It triages threats at a higher bar and skips tooling, so it covers less
    # than a full run and must not shorten the next run's catch-up window.
    digest, saved = _run_with(monkeypatch, tmp_path, '{"skip": true}', '{"skip": true}')
    monkeypatch.setattr(digest, "sent_today", lambda st: True)
    digest.run()
    assert saved and _stamp(saved) is None


def test_run_looks_back_as_far_as_the_policy_says(monkeypatch, tmp_path):
    import state
    digest, _ = _run_with(monkeypatch, tmp_path, '{"skip": true}', '{"skip": true}')
    prior: dict = {}
    state.record_clean_triage(prior)
    monkeypatch.setattr(digest, "load_state", lambda: dict(prior))

    asked = {}

    def policy(base, last_clean, now):
        asked.update(base=base, last_clean=last_clean)
        return 55

    fetched = []
    real_fetch = digest.fetch_rss_articles
    monkeypatch.setattr(digest, "extended_lookback_hours", policy)
    monkeypatch.setattr(digest, "fetch_rss_articles",
                        lambda hours, *a, **k: (fetched.append(hours),
                                                real_fetch(hours, *a, **k))[1])
    digest.run()
    assert fetched == [55]
    assert asked["last_clean"] == state.last_clean_triage(prior)
    assert asked["base"] in (24, 72)
