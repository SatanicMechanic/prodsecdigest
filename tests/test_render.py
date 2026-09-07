"""Tests for render.py — HTML escaping and URL validation."""

import json

import render
from render import render_html, render_slack, render_text, subject_line, _safe_url


def test_html_escapes_headline_script():
    items = [{
        "headline": "<script>alert('x')</script>",
        "category": "threat",
        "severity": "high",
        "why": "Dangerous & untrusted",
        "action": 'Patch "now"',
        "url": "https://example.com/x",
    }]
    out = render_html(items, "Apr 15, 2026")
    assert "<script>alert" not in out
    assert "&lt;script&gt;" in out
    assert "&amp;" in out
    assert "&quot;" in out or "&#x27;" in out


def test_html_escapes_url_in_href():
    items = [{
        "headline": "x", "category": "threat", "severity": "high",
        "why": "y", "action": "z",
        "url": "https://example.com/x?a=1&b=2",
    }]
    out = render_html(items, "Apr 15, 2026")
    # The raw & must be escaped in the href attribute
    assert 'href="https://example.com/x?a=1&amp;b=2"' in out


def test_safe_url_accepts_http_and_https():
    assert _safe_url("https://example.com/x") == "https://example.com/x"
    assert _safe_url("http://example.com/x") == "http://example.com/x"


def test_safe_url_rejects_dangerous_schemes():
    assert _safe_url("javascript:alert(1)") == "#"
    assert _safe_url("data:text/html,<script>") == "#"
    assert _safe_url("file:///etc/passwd") == "#"
    assert _safe_url("ftp://example.com/x") == "#"
    assert _safe_url("") == "#"
    assert _safe_url(None) == "#"


def test_javascript_url_does_not_leak_into_html():
    items = [{
        "headline": "x", "category": "threat", "severity": "high",
        "why": "y", "action": "z",
        "url": "javascript:alert(1)",
    }]
    out = render_html(items, "Apr 15, 2026")
    assert "javascript:" not in out
    # Rejected URL: no link is rendered at all.
    assert "href=" not in out
    assert "Read more" not in out


def test_render_text_basic():
    items = [{
        "headline": "CVE-2026-1234 in OpenSSL",
        "category": "threat", "severity": "critical",
        "why": "Affects appliance VMs.",
        "action": "Patch immediately.",
        "url": "https://example.com/x",
    }]
    txt = render_text(items, "Apr 15, 2026")
    assert "CRITICAL" in txt
    assert "CVE-2026-1234" in txt
    assert "https://example.com/x" in txt


def test_render_text_omits_dangerous_url():
    items = [{
        "headline": "x", "category": "threat", "severity": "high",
        "why": "y", "action": "z",
        "url": "javascript:alert(1)",
    }]
    txt = render_text(items, "Apr 15, 2026")
    assert "javascript:" not in txt


def _make_item(sev):
    return {"headline": "x", "category": "threat", "severity": sev,
            "why": "y", "action": "z", "url": "https://example.com"}


def test_subject_line_critical_prefix():
    assert "🔴" in subject_line([_make_item("critical")], "Apr 15, 2026")


def test_subject_line_high_prefix():
    out = subject_line([_make_item("high")], "Apr 15, 2026")
    assert "🟠" in out
    assert "🔴" not in out


def test_subject_line_medium_prefix():
    out = subject_line([_make_item("medium")], "Apr 15, 2026")
    assert "🟠" not in out
    assert "🔴" not in out


def test_subject_line_critical_wins_over_high():
    items = [_make_item("high"), _make_item("critical"), _make_item("medium")]
    assert "🔴" in subject_line(items, "Apr 15, 2026")


def test_slack_escapes_link_markup():
    items = [{
        "headline": "<https://evil.example|click me>",
        "category": "threat", "severity": "high",
        "why": "y & z", "action": "a",
        "url": "https://example.com/x",
    }]
    blob = json.dumps(render_slack(items, "Apr 15, 2026"))
    assert "<https://evil.example|" not in blob
    assert "&lt;https://evil.example" in blob


def test_slack_omits_dangerous_url():
    items = [{
        "headline": "x", "category": "threat", "severity": "high",
        "why": "y", "action": "z",
        "url": "javascript:alert(1)",
    }]
    blob = json.dumps(render_slack(items, "Apr 15, 2026"))
    assert "javascript:" not in blob


def test_slack_severity_drives_attachment_color():
    payload = render_slack([_make_item("critical")], "Apr 15, 2026")
    assert payload["attachments"][0]["color"] == "#ef4444"
    assert payload["blocks"][0]["text"]["text"].startswith("\U0001f6e1")


def test_subject_line_item_count():
    assert "(1 item)" in subject_line([_make_item("medium")], "Apr 15, 2026")
    assert "(3 items)" in subject_line([_make_item("medium")] * 3, "Apr 15, 2026")


# --- Card hierarchy: source domain, stack note, action-first ordering ---

def _full_item(**kw):
    item = {
        "headline": "Emergency advisory for the CI runner image",
        "category": "threat", "severity": "critical",
        "why": "why text", "action": "action text",
        "url": "https://www.github.blog/some-advisory",
        "stack_match": "GitHub Actions",
    }
    item.update(kw)
    return item


def test_source_domain_strips_www_and_scheme():
    assert render._source_domain("https://www.github.blog/x") == "github.blog"
    assert render._source_domain("http://example.com:8080/y") == "example.com:8080"


def test_source_domain_empty_for_unsafe_url():
    assert render._source_domain("javascript:alert(1)") == ""
    assert render._source_domain("") == ""


def test_html_shows_source_and_stack():
    out = render_html([_full_item()], "Apr 15, 2026")
    assert "Source: github.blog" in out
    assert "Stack: GitHub Actions" in out


def test_html_puts_action_before_why():
    out = render_html([_full_item()], "Apr 15, 2026")
    assert out.index("action text") < out.index("why text")


def test_html_omits_stack_line_when_absent():
    """Tooling and compliance items are exempt from stack grounding, so they
    carry no stack_match and must not render an empty label."""
    out = render_html([_full_item(category="tooling", stack_match="")], "Apr 15, 2026")
    assert "Stack:" not in out
    assert "Source: github.blog" in out


def test_text_puts_action_before_why_and_carries_source():
    out = render_text([_full_item()], "Apr 15, 2026")
    assert out.index("Do now: action text") < out.index("Why: why text")
    assert "Source: github.blog" in out
    assert "Stack: GitHub Actions" in out


def test_slack_puts_action_before_why_and_carries_source():
    payload = render_slack([_full_item()], "Apr 15, 2026")
    blob = json.dumps(payload)
    assert blob.index("Do now") < blob.index("Why it matters")
    assert "Source: github.blog" in blob
    assert "Stack: GitHub Actions" in blob


def test_slack_fallback_leads_with_headline():
    """Push notifications truncate, so the headline must come before the
    boilerplate subject line."""
    payload = render_slack([_full_item()], "Apr 15, 2026")
    assert "Emergency advisory for the CI runner image" in payload["text"]
    assert payload["text"].index("Emergency") < 8


def test_slack_fallback_counts_remaining_items():
    payload = render_slack([_full_item(), _full_item(), _full_item()], "Apr 15, 2026")
    assert "(+2 more)" in payload["text"]


def test_slack_fallback_escapes_headline():
    """The fallback is the one place a reader sees text before clicking, so a
    forged <url|label> in a headline must not survive into it."""
    payload = render_slack([_full_item(headline="<https://evil.example|GitHub>")],
                           "Apr 15, 2026")
    assert "<https://evil.example|" not in payload["text"]
    assert "&lt;" in payload["text"]


# --- Alert subject (emergency re-check) ---

def test_alert_subject_leads_with_headline():
    out = subject_line([_full_item()], "Apr 15, 2026", alert=True)
    assert "ALERT" in out
    assert "Emergency advisory for the CI runner image" in out
    assert "(1 item)" not in out


def test_alert_subject_strips_newlines_from_headline():
    """The subject is the one place LLM text reaches a mail header; a newline
    there is header injection."""
    out = subject_line([_full_item(headline="Real\r\nBcc: attacker@example.com")],
                       "Apr 15, 2026", alert=True)
    assert "\n" not in out and "\r" not in out


def test_alert_subject_falls_back_when_no_items():
    assert "Need to Know" in subject_line([], "Apr 15, 2026", alert=True)


# --- Header-bound LLM text is capped as well as flattened ---

def test_clip_leaves_short_text_alone():
    assert render._clip("short headline", 120) == "short headline"


def test_clip_collapses_all_whitespace():
    assert render._clip("a\r\nb\tc   d", 120) == "a b c d"


def test_clip_marks_truncation():
    out = render._clip("x" * 300, 120)
    assert len(out) == 120
    assert out.endswith("…")


def test_alert_subject_caps_headline_length():
    """An LLM headline has no length bound of its own; an uncapped one makes
    a broken mail subject."""
    out = subject_line([_full_item(headline="y" * 500)], "Apr 15, 2026", alert=True)
    assert len(out) < 140
    assert "…" in out


def test_slack_fallback_caps_headline_length():
    payload = render_slack([_full_item(headline="z" * 500)], "Apr 15, 2026")
    assert len(payload["text"]) < 170


def test_slack_fallback_clips_before_escaping():
    """Escaping expands & into &amp;; clipping after that could cut an entity
    in half and emit a broken fragment."""
    payload = render_slack([_full_item(headline="&" * 200)], "Apr 15, 2026")
    assert "&am" not in payload["text"].replace("&amp;", "")
    assert payload["text"].count("&amp;") > 0
