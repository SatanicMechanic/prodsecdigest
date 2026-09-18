"""Tests for the second-pass enrichment: article fetch + why/action rewrite.

Enrichment is strictly best-effort — the invariants under test are:
  - fetch_article_text never raises and enforces http(s)
  - enrich_items only rewrites why/action when the LLM returns usable JSON
  - any failure (fetch, LLM, parse) leaves the triage-time item untouched
  - selection-identity fields (headline/category/severity/url) are never changed
"""

import json

import fetchers
import llm


# --- fetch_article_text ---

class _FakeRaw:
    def __init__(self, data: bytes):
        self._data = data

    def read(self, *_args, **_kwargs):
        return self._data


class _FakeResp:
    def __init__(self, body: str, status_code: int = 200,
                 content_type: str = "text/html; charset=utf-8",
                 location: str = ""):
        self.status_code = status_code
        self.headers = {"Content-Type": content_type}
        if location:
            self.headers["Location"] = location
        self.is_redirect = status_code in (302, 303, 307)
        self.is_permanent_redirect = status_code in (301, 308)
        self.encoding = "utf-8"
        self.raw = _FakeRaw(body.encode("utf-8"))


def _allow_all_hosts(monkeypatch):
    # fetch_article_text resolves hostnames for its SSRF guard; tests must not
    # depend on real DNS.
    monkeypatch.setattr(fetchers, "_is_public_host", lambda host: True)


def test_fetch_article_text_rejects_non_http_schemes():
    # No network call should even be attempted; URL is rejected up front.
    assert fetchers.fetch_article_text("file:///etc/passwd") == ""
    assert fetchers.fetch_article_text("javascript:alert(1)") == ""
    assert fetchers.fetch_article_text("") == ""


def test_fetch_article_text_strips_script_and_style(monkeypatch):
    _allow_all_hosts(monkeypatch)
    body = (
        "<html><head><style>body{color:red}</style>"
        "<script>steal()</script></head>"
        "<body><p>Real article text.</p><noscript>enable js</noscript></body></html>"
    )
    monkeypatch.setattr(fetchers.requests, "get",
                        lambda *a, **k: _FakeResp(body))
    out = fetchers.fetch_article_text("https://example.com/story")
    assert out == "Real article text."


def test_fetch_article_text_non_html_content_type_returns_empty(monkeypatch):
    _allow_all_hosts(monkeypatch)
    monkeypatch.setattr(
        fetchers.requests, "get",
        lambda *a, **k: _FakeResp("binary", content_type="application/pdf"))
    assert fetchers.fetch_article_text("https://example.com/x.pdf") == ""


def test_fetch_article_text_non_200_returns_empty(monkeypatch):
    _allow_all_hosts(monkeypatch)
    monkeypatch.setattr(fetchers.requests, "get",
                        lambda *a, **k: _FakeResp("nope", status_code=404))
    assert fetchers.fetch_article_text("https://example.com/gone") == ""


def test_fetch_article_text_respects_max_chars(monkeypatch):
    _allow_all_hosts(monkeypatch)
    monkeypatch.setattr(fetchers.requests, "get",
                        lambda *a, **k: _FakeResp("<p>" + "x" * 9000 + "</p>"))
    out = fetchers.fetch_article_text("https://example.com/long", max_chars=100)
    assert len(out) == 100


def test_fetch_article_text_blocks_non_public_host(monkeypatch):
    monkeypatch.setattr(fetchers, "_is_public_host", lambda host: False)
    monkeypatch.setattr(
        fetchers.requests, "get",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not fetch")))
    assert fetchers.fetch_article_text("https://169.254.169.254/metadata") == ""


def test_fetch_article_text_checks_host_on_every_redirect_hop(monkeypatch):
    # Public host redirecting to a non-public one must be blocked at the hop.
    monkeypatch.setattr(fetchers, "_is_public_host",
                        lambda host: host == "example.com")
    calls = []

    def fake_get(url, *a, **k):
        calls.append(url)
        return _FakeResp("", status_code=302,
                         location="http://169.254.169.254/metadata")

    monkeypatch.setattr(fetchers.requests, "get", fake_get)
    assert fetchers.fetch_article_text("https://example.com/story") == ""
    assert calls == ["https://example.com/story"]


def test_fetch_article_text_follows_public_redirect(monkeypatch):
    _allow_all_hosts(monkeypatch)
    resps = [
        _FakeResp("", status_code=301, location="https://example.com/final"),
        _FakeResp("<p>Landed.</p>"),
    ]
    monkeypatch.setattr(fetchers.requests, "get",
                        lambda *a, **k: resps.pop(0))
    assert fetchers.fetch_article_text("https://example.com/story") == "Landed."


def test_is_public_host_rejects_private_addresses():
    # Literal IPs resolve without DNS, so these run fine offline.
    assert fetchers._is_public_host("169.254.169.254") is False
    assert fetchers._is_public_host("127.0.0.1") is False
    assert fetchers._is_public_host("10.0.0.5") is False


# --- enrich_items ---

def _item():
    return {
        "headline": "Original headline",
        "category": "threat",
        "severity": "high",
        "why": "original why",
        "action": "original action",
        "url": "https://example.com/story",
    }


_LONG_TEXT = "word " * 100  # > 200-char usability floor


def test_enrich_items_rewrites_why_and_action(monkeypatch):
    monkeypatch.setattr(fetchers, "fetch_article_text", lambda url: _LONG_TEXT)
    monkeypatch.setattr(
        llm, "call_llm",
        lambda *a, **k: json.dumps({"why": "better why", "action": "better action"}))
    out = llm.enrich_items([_item()])
    assert out[0]["why"] == "better why"
    assert out[0]["action"] == "better action"
    # Selection-identity fields untouched.
    assert out[0]["headline"] == "Original headline"
    assert out[0]["severity"] == "high"
    assert out[0]["url"] == "https://example.com/story"


def test_enrich_items_keeps_originals_when_flagged_out_of_scope(monkeypatch):
    """Enrichment may disagree with the pick, but it may not ship that disagreement.

    2026-09-18: the enrichment pass rewrote why/action into "this item is out of
    scope / no action required" and the digest mailed it as a HIGH TOOLING
    UPDATE card that argued with its own headline.
    """
    monkeypatch.setattr(fetchers, "fetch_article_text", lambda url: _LONG_TEXT)
    monkeypatch.setattr(
        llm, "call_llm",
        lambda *a, **k: json.dumps({
            "why": "This is out of scope for our security digest.",
            "action": "No action required.",
            "in_scope": False,
        }))
    out = llm.enrich_items([_item()])
    assert out[0]["why"] == "original why"
    assert out[0]["action"] == "original action"
    # The item is still delivered: selection is triage's call, not enrichment's.
    assert len(out) == 1


def test_enrich_items_rewrites_when_in_scope_absent(monkeypatch):
    """Back-compat: a response without the flag is a normal refinement."""
    monkeypatch.setattr(fetchers, "fetch_article_text", lambda url: _LONG_TEXT)
    monkeypatch.setattr(
        llm, "call_llm",
        lambda *a, **k: json.dumps({"why": "better why", "action": "better action"}))
    assert llm.enrich_items([_item()])[0]["why"] == "better why"


def test_enrich_items_keeps_originals_when_article_unusable(monkeypatch):
    monkeypatch.setattr(fetchers, "fetch_article_text", lambda url: "short")
    monkeypatch.setattr(
        llm, "call_llm",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not be called")))
    out = llm.enrich_items([_item()])
    assert out[0]["why"] == "original why"
    assert out[0]["action"] == "original action"


def test_enrich_items_keeps_originals_on_bad_llm_json(monkeypatch):
    monkeypatch.setattr(fetchers, "fetch_article_text", lambda url: _LONG_TEXT)
    monkeypatch.setattr(llm, "call_llm", lambda *a, **k: "not json at all")
    out = llm.enrich_items([_item()])
    assert out[0]["why"] == "original why"
    assert out[0]["action"] == "original action"


def test_enrich_items_keeps_originals_on_missing_fields(monkeypatch):
    monkeypatch.setattr(fetchers, "fetch_article_text", lambda url: _LONG_TEXT)
    monkeypatch.setattr(llm, "call_llm",
                        lambda *a, **k: json.dumps({"why": "only why"}))
    out = llm.enrich_items([_item()])
    assert out[0]["why"] == "original why"
    assert out[0]["action"] == "original action"


def test_enrich_items_keeps_originals_when_llm_raises(monkeypatch):
    monkeypatch.setattr(fetchers, "fetch_article_text", lambda url: _LONG_TEXT)
    monkeypatch.setattr(
        llm, "call_llm",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("provider down")))
    out = llm.enrich_items([_item()])
    assert out[0]["why"] == "original why"
    assert out[0]["action"] == "original action"


def test_enrich_items_rejects_rewrite_with_placeholder_cve(monkeypatch):
    """Enrichment can hallucinate a fake CVE just as easily as triage can —
    the guardrail must apply to its rewrite too, not just the triage-time text."""
    monkeypatch.setattr(fetchers, "fetch_article_text", lambda url: _LONG_TEXT)
    monkeypatch.setattr(
        llm, "call_llm",
        lambda *a, **k: json.dumps({
            "why": "Exploiting CVE-2026-XXXX in the wild.",
            "action": "Patch now.",
        }))
    out = llm.enrich_items([_item()])
    assert out[0]["why"] == "original why"
    assert out[0]["action"] == "original action"


def test_enrich_items_caps_field_length(monkeypatch):
    monkeypatch.setattr(fetchers, "fetch_article_text", lambda url: _LONG_TEXT)
    monkeypatch.setattr(
        llm, "call_llm",
        lambda *a, **k: json.dumps({"why": "w" * 5000, "action": "a" * 5000}))
    out = llm.enrich_items([_item()])
    assert len(out[0]["why"]) == llm._ENRICH_FIELD_MAX_CHARS
    assert len(out[0]["action"]) == llm._ENRICH_FIELD_MAX_CHARS
