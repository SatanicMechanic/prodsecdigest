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

def test_both_none_returns_empty():
    assert _merge_triage_results(None, None) == []


def test_both_empty_returns_empty():
    assert _merge_triage_results([], []) == []


def test_a_none_b_has_items():
    b = [_item("https://b.com", "tooling")]
    result = _merge_triage_results(None, b)
    assert len(result) == 1
    assert result[0]["url"] == "https://b.com"


def test_b_none_a_has_items():
    a = [_item("https://a.com", "threat")]
    result = _merge_triage_results(a, None)
    assert len(result) == 1
    assert result[0]["url"] == "https://a.com"


# --- URL dedupe: A wins on tie ---

def test_url_dedupe_a_wins():
    shared_url = "https://shared.com"
    a = [_item(shared_url, "threat", "threat headline")]
    b = [_item(shared_url, "tooling", "tooling headline")]
    result = _merge_triage_results(a, b)
    assert len(result) == 1
    assert result[0]["category"] == "threat"
    assert result[0]["headline"] == "threat headline"


def test_url_dedupe_case_insensitive():
    a = [_item("https://Example.COM/path", "threat")]
    b = [_item("https://example.com/path", "tooling")]
    result = _merge_triage_results(a, b)
    assert len(result) == 1


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

def test_items_with_no_url_are_excluded():
    a = [{"headline": "x", "category": "threat", "severity": "high",
          "why": "w", "action": "a", "url": ""}]
    result = _merge_triage_results(a, None)
    assert result == []


def test_items_with_none_url_are_excluded():
    a = [{"headline": "x", "category": "threat", "severity": "high",
          "why": "w", "action": "a", "url": None}]
    result = _merge_triage_results(a, None)
    assert result == []


# --- _fail_on_total_triage_failure: both calls erroring must be loud ---

def test_fail_on_total_triage_failure_raises_with_both_errors():
    with pytest.raises(RuntimeError, match="Both triage calls failed"):
        _fail_on_total_triage_failure(ValueError("bad key"), TimeoutError("slow"))


def test_fail_on_total_triage_failure_message_includes_both_exceptions():
    with pytest.raises(RuntimeError) as exc_info:
        _fail_on_total_triage_failure(ValueError("bad key"), None)
    assert "bad key" in str(exc_info.value)


# --- URL grounding (triage output must point at the pool we showed the model) ---

from digest import _ground_urls  # noqa: E402


def test_ground_urls_drops_url_not_in_pool():
    """An invented URL would be emailed to the reader and fetched by the
    enrichment pass, so it must not survive triage."""
    pool = {"https://ex.com/real"}
    items = [_item("https://ex.com/real"), _item("https://evil.example/invented")]
    kept = _ground_urls(items, pool)
    assert [i["url"] for i in kept] == ["https://ex.com/real"]


def test_ground_urls_canonicalizes_survivors():
    """A pool URL echoed back with tracking params or a trailing slash is a
    real candidate — keep it, but rewrite it to the form state suppression
    and the merge dedupe both use."""
    pool = {"https://ex.com/story"}
    kept = _ground_urls([_item("https://ex.com/story/?utm_source=newsletter")], pool)
    assert [i["url"] for i in kept] == ["https://ex.com/story"]


def test_ground_urls_passes_skip_through():
    assert _ground_urls(None, {"https://ex.com/a"}) is None


def test_ground_urls_empty_pool_drops_everything():
    assert _ground_urls([_item("https://ex.com/a")], set()) == []


def test_merge_dedupes_tracking_param_variants():
    """Same story, one copy with tracking params: one URL-equality rule means
    it collapses here instead of surviving as two items."""
    out = _merge_triage_results(
        [_item("https://ex.com/x?utm_source=nl"), _item("https://ex.com/x")], []
    )
    assert len(out) == 1


def test_merge_dedupes_trailing_slash_variants():
    out = _merge_triage_results([_item("https://ex.com/x/")], [_item("https://ex.com/x")])
    assert len(out) == 1


# --- Emergency re-check bar ---

from digest import _emergency_filter, _no_digest_reason  # noqa: E402


def test_emergency_filter_keeps_one_critical_threat():
    items = [_item("https://ex.com/a", headline="crit")]
    items[0]["severity"] = "critical"
    assert [i["url"] for i in _emergency_filter(items)] == ["https://ex.com/a"]


def test_emergency_filter_drops_non_critical():
    """A high-severity item is digest-worthy but not worth re-interrupting a
    reader who already got today's digest."""
    items = [_item("https://ex.com/a")]  # severity "high"
    assert _emergency_filter(items) == []


def test_emergency_filter_drops_non_threat_categories():
    item = _item("https://ex.com/a", category="tooling")
    item["severity"] = "critical"
    assert _emergency_filter([item]) == []


def test_emergency_filter_caps_at_one():
    items = []
    for n in range(3):
        it = _item(f"https://ex.com/{n}")
        it["severity"] = "critical"
        items.append(it)
    assert len(_emergency_filter(items)) == 1


# --- Degraded vs healthy skip ---

def test_no_digest_reason_degraded_is_not_a_skip():
    msg = _no_digest_reason(["threat triage returned unparseable JSON"], False)
    assert "DEGRADED" in msg
    assert "unparseable JSON" in msg


def test_no_digest_reason_degraded_wins_over_emergency():
    msg = _no_digest_reason(["threat triage call failed"], True)
    assert "DEGRADED" in msg


def test_no_digest_reason_healthy_skip():
    msg = _no_digest_reason([], False)
    assert "SKIP" in msg
    assert "DEGRADED" not in msg


def test_no_digest_reason_emergency_clear():
    msg = _no_digest_reason([], True)
    assert "Emergency re-check clear" in msg
    assert "DEGRADED" not in msg
