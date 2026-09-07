"""Tests for state.py — URL normalization and seen-URL persistence."""

import datetime
import json

import pytest

import state


# --- URL normalization ---

@pytest.mark.parametrize("inp,expected", [
    ("https://Example.COM/path", "https://example.com/path"),
    ("https://example.com/path/", "https://example.com/path"),
    ("https://example.com/", "https://example.com/"),
    ("https://example.com/path?utm_source=x&id=42", "https://example.com/path?id=42"),
    ("https://example.com/path?utm_campaign=x&utm_medium=y", "https://example.com/path"),
    ("https://example.com/path#fragment", "https://example.com/path"),
    ("https://example.com:443/path", "https://example.com/path"),
    ("http://example.com:80/path", "http://example.com/path"),
    ("HTTPS://example.com/Path?fbclid=abc", "https://example.com/Path"),
    ("", ""),
])
def test_normalize_url(inp, expected):
    assert state.normalize_url(inp) == expected


# --- State persistence and TTL ---

def test_load_returns_empty_when_no_file(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "_state_path", lambda: str(tmp_path / "state.json"))
    assert state.load_state() == {}


def test_record_and_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "_state_path", lambda: str(tmp_path / "state.json"))
    s: dict = {}
    state.record_candidates(s, ["https://Example.com/a/", "https://example.com/b"])
    state.save_state(s)

    loaded = state.load_state()
    assert "https://example.com/a" in loaded
    assert "https://example.com/b" in loaded


def test_sent_overrides_candidate(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "_state_path", lambda: str(tmp_path / "state.json"))
    s: dict = {}
    state.record_candidates(s, ["https://example.com/a"])
    assert s["https://example.com/a"]["status"] == "candidate"
    state.record_sent(s, ["https://example.com/a"])
    assert s["https://example.com/a"]["status"] == "sent"


def test_candidate_does_not_override_sent(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "_state_path", lambda: str(tmp_path / "state.json"))
    s: dict = {}
    state.record_sent(s, ["https://example.com/a"])
    state.record_candidates(s, ["https://example.com/a"])
    assert s["https://example.com/a"]["status"] == "sent"


def test_candidate_cooldown_expires(tmp_path, monkeypatch):
    """Entries past their TTL are pruned on load."""
    monkeypatch.setattr(state, "_state_path", lambda: str(tmp_path / "state.json"))
    monkeypatch.setattr(state, "STATE_CANDIDATE_COOLDOWN_DAYS", 5)
    monkeypatch.setattr(state, "STATE_SENT_TTL_DAYS", 30)

    today = datetime.date.today()
    old_date = (today - datetime.timedelta(days=10)).isoformat()
    fresh_date = today.isoformat()

    raw = {
        "https://example.com/old-candidate": {"status": "candidate", "date": old_date},
        "https://example.com/fresh-candidate": {"status": "candidate", "date": fresh_date},
        "https://example.com/old-sent": {"status": "sent", "date": old_date},
    }
    with open(tmp_path / "state.json", "w") as f:
        json.dump(raw, f)

    loaded = state.load_state()
    assert "https://example.com/old-candidate" not in loaded   # 10d > 5d cooldown
    assert "https://example.com/fresh-candidate" in loaded
    assert "https://example.com/old-sent" in loaded            # 10d < 30d sent TTL


def test_sent_ttl_expires(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "_state_path", lambda: str(tmp_path / "state.json"))
    monkeypatch.setattr(state, "STATE_SENT_TTL_DAYS", 30)

    very_old = (datetime.date.today() - datetime.timedelta(days=60)).isoformat()
    raw = {"https://example.com/ancient": {"status": "sent", "date": very_old}}
    with open(tmp_path / "state.json", "w") as f:
        json.dump(raw, f)

    loaded = state.load_state()
    assert "https://example.com/ancient" not in loaded


def test_is_excluded_normalizes(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "_state_path", lambda: str(tmp_path / "state.json"))
    s = {"https://example.com/a": {"status": "sent", "date": "2026-01-01"}}
    # All three are same canonical URL
    assert state.is_excluded("https://example.com/a/", s)
    assert state.is_excluded("https://EXAMPLE.com/a?utm_source=x", s)
    assert state.is_excluded("https://example.com/a#anchor", s)
    # Different URL
    assert not state.is_excluded("https://example.com/b", s)


def test_recent_sent_headlines_within_window(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "_state_path", lambda: str(tmp_path / "state.json"))
    today = datetime.date.today().isoformat()
    yesterday = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
    s = {
        "https://example.com/a": {"status": "sent", "date": today, "headline": "Alpha"},
        "https://example.com/b": {"status": "sent", "date": yesterday, "headline": "Beta"},
    }
    result = state.recent_sent_headlines(s, days=7)
    assert "Alpha" in result
    assert "Beta" in result


def test_recent_sent_headlines_excludes_old(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "_state_path", lambda: str(tmp_path / "state.json"))
    today = datetime.date.today().isoformat()
    old = (datetime.date.today() - datetime.timedelta(days=10)).isoformat()
    s = {
        "https://example.com/a": {"status": "sent", "date": today, "headline": "Fresh"},
        "https://example.com/b": {"status": "sent", "date": old, "headline": "Stale"},
    }
    result = state.recent_sent_headlines(s, days=7)
    assert "Fresh" in result
    assert "Stale" not in result


def test_recent_sent_headlines_excludes_candidates(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "_state_path", lambda: str(tmp_path / "state.json"))
    today = datetime.date.today().isoformat()
    s = {
        "https://example.com/a": {"status": "candidate", "date": today, "headline": "Should not appear"},
        "https://example.com/b": {"status": "sent", "date": today, "headline": "Should appear"},
    }
    result = state.recent_sent_headlines(s, days=7)
    assert "Should appear" in result
    assert "Should not appear" not in result


def test_recent_sent_headlines_sorted_newest_first(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "_state_path", lambda: str(tmp_path / "state.json"))
    today = datetime.date.today().isoformat()
    two_days_ago = (datetime.date.today() - datetime.timedelta(days=2)).isoformat()
    s = {
        "https://example.com/a": {"status": "sent", "date": two_days_ago, "headline": "Older"},
        "https://example.com/b": {"status": "sent", "date": today, "headline": "Newer"},
    }
    result = state.recent_sent_headlines(s, days=7)
    assert result.index("Newer") < result.index("Older")


def test_recent_sent_headlines_excludes_no_headline(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "_state_path", lambda: str(tmp_path / "state.json"))
    today = datetime.date.today().isoformat()
    s = {
        "https://example.com/a": {"status": "sent", "date": today},
        "https://example.com/b": {"status": "sent", "date": today, "headline": "Has headline"},
    }
    result = state.recent_sent_headlines(s, days=7)
    assert result == ["Has headline"]


def test_atomic_save_does_not_corrupt_on_error(tmp_path, monkeypatch):
    """save_state uses write-then-rename so a partial file never replaces a good one."""
    monkeypatch.setattr(state, "_state_path", lambda: str(tmp_path / "state.json"))
    s = {"https://example.com/a": {"status": "sent", "date": "2026-01-01"}}
    state.save_state(s)
    assert (tmp_path / "state.json").exists()
    assert not (tmp_path / "state.json.tmp").exists()


# --- sent_only suppression (emergency re-check) ---

def test_is_excluded_sent_only_ignores_candidate_cooldown():
    """A near-miss from the morning run must be able to come back in the
    afternoon emergency re-check if it has since escalated."""
    st = {}
    state.record_candidates(st, ["https://ex.com/near-miss"])
    assert state.is_excluded("https://ex.com/near-miss", st) is True
    assert state.is_excluded("https://ex.com/near-miss", st, sent_only=True) is False


def test_is_excluded_sent_only_still_suppresses_delivered():
    st = {}
    state.record_sent(st, ["https://ex.com/already-sent"], headline="h")
    assert state.is_excluded("https://ex.com/already-sent", st, sent_only=True) is True


def test_is_excluded_unknown_url_is_never_excluded():
    assert state.is_excluded("https://ex.com/new", {}) is False
    assert state.is_excluded("https://ex.com/new", {}, sent_only=True) is False
