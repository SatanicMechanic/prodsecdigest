"""Tests for the manual health-check scripts: a failure must exit nonzero."""

from unittest import mock

import pytest

import check_feeds
import llm_smoke

_OLD_FEED = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>F</title>
  <item><title>Old</title><link>https://ex.com/a</link>
  <pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate></item>
</channel></rss>"""


def test_check_feeds_fails_with_no_feeds(monkeypatch):
    monkeypatch.setattr(check_feeds, "FEEDS", [])
    assert check_feeds.check_feeds() is False


def test_check_feeds_fails_when_every_feed_is_stale(monkeypatch):
    monkeypatch.setattr(check_feeds, "FEEDS", ["https://a.example/f", "https://b.example/f"])
    resp = mock.MagicMock(status_code=200, content=_OLD_FEED)
    monkeypatch.setattr(check_feeds.requests, "get", lambda *a, **kw: resp)
    assert check_feeds.check_feeds() is False


@pytest.mark.parametrize("replies, code", [
    (["hi", '["a"]', '{"x": 1}'], 0),
    (["hi", "not json", '{"x": 1}'], 1),
    ([RuntimeError("boom"), '["a"]', '{"x": 1}'], 1),
])
def test_llm_smoke_exit_code(monkeypatch, replies, code):
    monkeypatch.setattr(llm_smoke, "load_dotenv", lambda: None)
    fake = mock.MagicMock(side_effect=replies)
    monkeypatch.setattr(llm_smoke.llm, "call_llm", fake)
    assert llm_smoke.main() == code
    assert fake.call_count == 3  # a failure doesn't skip the later checks
