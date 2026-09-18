"""Tests for llm.py — output parsing and retry semantics."""

import json
from unittest import mock

import pytest

import llm


# --- parse_query_json ---

@pytest.mark.parametrize("raw, expected", [
    ('["query 1", "query 2", "query 3"]', ["query 1", "query 2", "query 3"]),
    ('```json\n["a", "b"]\n```', ["a", "b"]),
    ('```\n["a", "b"]\n```', ["a", "b"]),
    ('```["a","b"]```', ["a", "b"]),  # single-line fence must parse, not crash
    ('["", "a", null, "b"]', ["a", "b"]),  # empty values stripped
    ('["   ", " a "]', ["a"]),  # whitespace-only dropped after strip
    ('"foo"', []),  # a bare string is not a list of queries
    ("not json at all", []),
    ("{}", []),
    ("", []),
    # json_mode forces an object, so this is now the shape the prompts ask for.
    ('{"queries": ["a", "b"]}', ["a", "b"]),
    ('```json\n{"queries": ["a"]}\n```', ["a"]),
    ('{"queries": []}', []),  # "nothing worth asking today" is a real answer
    ('{"queries": "a"}', []),  # a bare string is not a list here either
    ('{"search_queries": ["a"]}', []),  # wrong key is a miss, not a silent pass
])
def test_parse_query_json(raw, expected):
    assert llm.parse_query_json(raw) == expected


@pytest.mark.parametrize("raw, expect_warning", [
    ('{"queries": []}', False),   # explicit empty list: the model answered
    ('{"queries": ["a"]}', False),
    ('{"search_queries": ["a"]}', True),   # output we could not use
    ("not json at all", True),
])
def test_parse_query_json_reports_lost_output(raw, expect_warning, capsys):
    """A slot that silently yields no queries costs a run its whole search pass.

    Before this, an unparseable response and a legitimate "nothing to ask"
    both returned [] without a word in the log (2026-09-17: the anchored slot
    produced zero queries on six consecutive runs, invisibly).
    """
    llm.parse_query_json(raw)
    assert ("Warning:" in capsys.readouterr().out) is expect_warning


@pytest.mark.parametrize("name", [
    "_ANCHORED_QUERY_SYSTEM", "_INDEPENDENT_QUERY_SYSTEM",
    "_TOOLING_SCAN_QUERY_SYSTEM", "_AI_LAB_QUERY_SYSTEM", "_SLOW_QUERY_SYSTEM",
    "_OWN_PRODUCT_QUERY_SYSTEM",
])
def test_query_prompts_share_quoting_and_year_rules(name):
    """Two prompts had drifted without the no-years rule, and the open-ended
    quoting rule produced 4-phrase queries that matched nothing (2026-09-14)."""
    prompt = getattr(llm, name)
    assert "Do NOT append dates or years" in prompt
    assert "Quote at most ONE multi-word phrase" in prompt
    # json_mode sends response_format=json_object, which cannot return a bare
    # array — a prompt still asking for one parses back as zero queries.
    assert "Return ONLY a JSON object" in prompt
    assert "Wrap multi-word exact concepts" not in prompt


def test_parse_triage_output_tolerates_fenced_json(monkeypatch):
    """Defense-in-depth: provider regressions to fenced output shouldn't blow up."""
    monkeypatch.setattr(llm, "STACK_SUMMARY", "CI/CD & SCM: GitHub")
    payload = '```json\n{"items": [{"headline":"x","category":"threat","severity":"high","why":"y","action":"z","url":"https://example.com","stack_match":"GitHub"}]}\n```'
    items = llm.parse_triage_output(payload)
    assert len(items) == 1
    assert items[0]["headline"] == "x"


# --- parse_triage_output ---

def test_parse_triage_output_skip_returns_none():
    assert llm.parse_triage_output('{"skip": true}') is None


def test_parse_triage_output_valid(monkeypatch):
    monkeypatch.setattr(llm, "STACK_SUMMARY", "CI/CD & SCM: GitHub")
    payload = {"items": [{
        "headline": "x", "category": "threat", "severity": "high",
        "why": "y", "action": "z", "url": "https://example.com",
        "stack_match": "GitHub",
    }]}
    items = llm.parse_triage_output(json.dumps(payload))
    assert len(items) == 1
    assert items[0]["headline"] == "x"


def test_parse_triage_output_drops_incomplete_items(monkeypatch):
    monkeypatch.setattr(llm, "STACK_SUMMARY", "CI/CD & SCM: GitHub")
    payload = {"items": [
        {"headline": "complete", "category": "threat", "severity": "high",
         "why": "w", "action": "a", "url": "https://example.com",
         "stack_match": "GitHub"},
        {"headline": "missing-url", "category": "threat", "severity": "high",
         "why": "w", "action": "a"},  # no url
        {"headline": "", "category": "threat", "severity": "high",
         "why": "w", "action": "a", "url": "https://example.com"},  # blank headline
    ]}
    items = llm.parse_triage_output(json.dumps(payload))
    assert len(items) == 1
    assert items[0]["headline"] == "complete"


@pytest.mark.parametrize("raw", ["{invalid json", "[1, 2, 3]"])
def test_parse_triage_output_malformed_raises(raw):
    with pytest.raises(RuntimeError):
        llm.parse_triage_output(raw)


# --- hallucination guardrails: fabricated CVEs, ungrounded stack claims ---

def _threat_item(**overrides):
    item = {
        "headline": "x", "category": "threat", "severity": "high",
        "why": "y", "action": "z", "url": "https://example.com",
        "stack_match": "GitHub",
    }
    item.update(overrides)
    return item


@pytest.mark.parametrize("overrides, kept", [
    ({"why": "Exploiting CVE-2026-XXXX in the wild."}, False),  # placeholder CVE
    ({"why": "Exploiting CVE-2026-41234 in the wild."}, True),
    ({"stack_match": ""}, False),
    # stack_match must be a real quote from stack.txt; a plausible out-of-stack
    # product is exactly the fabrication this check exists to catch.
    ({"stack_match": "GitLab", "why": "Affects our CI/CD pipeline."}, False),
    ({"category": "compliance", "stack_match": ""}, True),  # exempt from grounding
    # Truthy non-strings used to pass and crash downstream with TypeError.
    ({"url": 12345}, False),
    ({"headline": ["x"]}, False),
    ({"severity": "   "}, False),
    ({"stack_match": 42}, False),
    ({"why": "Exploiting CVE-XXXX in the wild."}, False),  # placeholder year
    ({"category": "Threat", "stack_match": ""}, False),  # case can't skip grounding
    ({"stack_match": "Hub"}, False),  # substring of GitHub, not a stack entry
])
def test_parse_triage_output_guardrails(monkeypatch, overrides, kept):
    monkeypatch.setattr(llm, "STACK_SUMMARY", "CI/CD & SCM: GitHub")
    payload = {"items": [_threat_item(**overrides)]}
    assert len(llm.parse_triage_output(json.dumps(payload))) == int(kept)


# --- build_triage_input ---

def test_build_triage_input_basic_format():
    articles = [{
        "title": "OpenSSL emergency patch", "source": "Krebs",
        "published": "2026-04-14", "link": "https://example.com",
        "summary": "urgent stuff",
    }]
    out = llm.build_triage_input(articles)
    assert "1. [Krebs] OpenSSL emergency patch" in out
    assert "https://example.com" in out
    assert "urgent stuff" in out


def test_build_triage_input_no_enrichment_tags():
    """No KEV/EPSS/CVE bracketed tags — triage reads article text only."""
    articles = [{
        "title": "CVE-2026-1234 exploited", "source": "src",
        "published": "date", "link": "u", "summary": "s",
    }]
    out = llm.build_triage_input(articles)
    assert "[KEV]" not in out
    assert "[EPSS" not in out
    # The CVE ID appears in the title (fine) but not as an injected tag
    assert "[CVE-2026-1234]" not in out  # no bracketed tag
    assert "CVE-2026-1234 exploited" in out  # still in title


def test_build_triage_input_multiple_items():
    articles = [
        {"title": "A", "source": "s1", "published": "p1", "link": "u1", "summary": "sum1"},
        {"title": "B", "source": "s2", "published": "p2", "link": "u2", "summary": "sum2"},
    ]
    out = llm.build_triage_input(articles)
    assert "1. [s1] A" in out
    assert "2. [s2] B" in out


def test_build_triage_input_surfaces_also_sources():
    """When cross-feed dedup collapsed a story, additional sources are visible to the LLM."""
    articles = [{
        "title": "Critical OpenSSL flaw exploited",
        "source": "GitHub Security Blog",
        "also_sources": ["AWS Security Blog", "Acme Security"],
        "published": "2026-04-14",
        "link": "https://example.com",
        "summary": "convergence detected",
    }]
    out = llm.build_triage_input(articles)
    assert "GitHub Security Blog" in out
    assert "also covered by:" in out
    assert "AWS Security Blog" in out
    assert "Acme Security" in out


def test_build_triage_input_no_also_sources_block_when_empty():
    articles = [{
        "title": "Routine post", "source": "Solo",
        "published": "p", "link": "u", "summary": "s",
    }]
    out = llm.build_triage_input(articles)
    assert "also covered by" not in out


# --- generate_slow_queries ---

def test_generate_slow_queries_parses_combined_response(monkeypatch):
    monkeypatch.setenv("GH_MODELS_TOKEN", "x")
    payload = '{"compliance": ["NVD operational change"], "pqc": ["NIST FIPS 203 rollout"]}'
    with mock.patch.object(llm, "call_llm", return_value=payload):
        comp, pqc = llm.generate_slow_queries(24)
    assert comp == ["NVD operational change"]
    assert pqc == ["NIST FIPS 203 rollout"]


@pytest.mark.parametrize("payload, expected", [
    ("not json", ([], [])),
    ('{"compliance": ["x"]}', (["x"], [])),  # missing key
    ('{"compliance": "foo", "pqc": ["   "]}', ([], [])),  # not split into chars
])
def test_generate_slow_queries_tolerates_bad_output(monkeypatch, payload, expected):
    monkeypatch.setenv("GH_MODELS_TOKEN", "x")
    with mock.patch.object(llm, "call_llm", return_value=payload):
        assert llm.generate_slow_queries(24) == expected


def test_generate_slow_queries_caps_to_configured_counts(monkeypatch):
    monkeypatch.setenv("GH_MODELS_TOKEN", "x")
    monkeypatch.setattr(llm, "COMPLIANCE_QUERIES", 1)
    monkeypatch.setattr(llm, "PQC_QUERIES", 1)
    payload = '{"compliance": ["a", "b", "c"], "pqc": ["x", "y"]}'
    with mock.patch.object(llm, "call_llm", return_value=payload):
        comp, pqc = llm.generate_slow_queries(24)
    assert len(comp) == 1
    assert len(pqc) == 1


# --- query slots ---

_SLOTS = {s.label: s for s in llm.QUERY_SLOTS}
_LABELS = list(_SLOTS)


def test_emergency_recheck_runs_only_threat_capable_slots():
    """The re-check is threats-only and pays per query, so it runs the two slots
    that can produce a threat: the urgency scan, and coverage of a vulnerability
    in what the reader themselves ships."""
    assert [s.label for s in llm.QUERY_SLOTS if s.in_emergency] == [
        "independent", "own-product"]


@pytest.mark.parametrize("label", _LABELS)
def test_generate_slot_queries_parses_array(monkeypatch, label):
    monkeypatch.setenv("GH_MODELS_TOKEN", "x")
    with mock.patch.object(llm, "call_llm", return_value='["a real query"]'):
        out = llm.generate_slot_queries(_SLOTS[label], 24)
    assert out == ["a real query"]


@pytest.mark.parametrize("label", _LABELS)
def test_generate_slot_queries_handles_garbage(monkeypatch, label):
    monkeypatch.setenv("GH_MODELS_TOKEN", "x")
    with mock.patch.object(llm, "call_llm", return_value="not json"):
        assert llm.generate_slot_queries(_SLOTS[label], 24) == []


@pytest.mark.parametrize("label", _LABELS)
def test_generate_slot_queries_survives_llm_failure(monkeypatch, label):
    """A transient provider error must not abort the run — the RSS pool is
    still worth triaging without this slot's queries."""
    monkeypatch.setenv("GH_MODELS_TOKEN", "x")
    with mock.patch.object(llm, "call_llm", side_effect=RuntimeError("503")):
        assert llm.generate_slot_queries(_SLOTS[label], 24) == []


@pytest.mark.parametrize("label", _LABELS)
def test_generate_slot_queries_caps_to_slot_count(monkeypatch, label):
    slot = _SLOTS[label]
    monkeypatch.setenv("GH_MODELS_TOKEN", "x")
    payload = json.dumps([f"q{i}" for i in range(slot.n_queries + 3)])
    with mock.patch.object(llm, "call_llm", return_value=payload):
        assert len(llm.generate_slot_queries(slot, 24)) == slot.n_queries


@pytest.mark.parametrize("label", _LABELS)
def test_generate_slot_queries_fills_prompt_placeholders(monkeypatch, label):
    """A slot whose prompt keeps a literal {n} or {lookback_hours} would ship
    the placeholder to the model, which is silent and hard to spot in output."""
    monkeypatch.setenv("GH_MODELS_TOKEN", "x")
    seen = {}

    def fake(system, user, **kw):
        seen["system"], seen["user"] = system, user
        return "[]"

    with mock.patch.object(llm, "call_llm", side_effect=fake):
        llm.generate_slot_queries(_SLOTS[label], 24)
    assert "{n}" not in seen["system"]
    assert "{lookback_hours}" not in seen["system"]
    assert _SLOTS[label].target in seen["user"]


def test_anchored_queries_survive_llm_failure(monkeypatch):
    monkeypatch.setenv("GH_MODELS_TOKEN", "x")
    articles = [{"title": "t", "source": "s"}]
    with mock.patch.object(llm, "call_llm", side_effect=RuntimeError("503")):
        assert llm.generate_anchored_queries(articles) == []


def test_slow_queries_survive_llm_failure(monkeypatch):
    monkeypatch.setenv("GH_MODELS_TOKEN", "x")
    with mock.patch.object(llm, "call_llm", side_effect=RuntimeError("503")):
        assert llm.generate_slow_queries(24) == ([], [])


# --- call_llm ---

def _make_mock_post(content="result"):
    mock_response = mock.MagicMock()
    mock_response.json.return_value = {
        "choices": [{"message": {"content": content}}]
    }
    return mock.MagicMock(return_value=mock_response)


def _post_payload(mock_post):
    _, kwargs = mock_post.call_args
    return kwargs["json"]


def test_call_llm_succeeds(monkeypatch):
    monkeypatch.setenv(llm.LLM_API_KEY_ENV, "tok")
    mock_post = _make_mock_post("result")
    with mock.patch.object(llm._SESSION, "post", mock_post):
        result = llm.call_llm("sys", "user")
    assert result == "result"
    mock_post.assert_called_once()


def test_call_llm_extracts_text_from_chunked_content(monkeypatch):
    monkeypatch.setenv(llm.LLM_API_KEY_ENV, "tok")
    chunks = [
        {"type": "thinking", "text": "reasoning..."},
        {"type": "text", "text": "result"},
    ]
    mock_post = _make_mock_post(chunks)
    with mock.patch.object(llm._SESSION, "post", mock_post):
        result = llm.call_llm("sys", "user")
    assert result == "result"


@pytest.mark.parametrize("extra, expected", [
    ('{"reasoning_effort": "low"}', "low"),
    ("{}", "<absent>"),
])
def test_call_llm_merges_llm_extra(monkeypatch, extra, expected):
    """LLM_EXTRA is provider-specific knobs (e.g. xAI's reasoning_effort)."""
    monkeypatch.setenv(llm.LLM_API_KEY_ENV, "tok")
    monkeypatch.setattr(llm, "LLM_EXTRA", extra)
    mock_post = _make_mock_post()
    with mock.patch.object(llm._SESSION, "post", mock_post):
        llm.call_llm("sys", "user")
    assert _post_payload(mock_post).get("reasoning_effort", "<absent>") == expected


def test_call_llm_sets_json_mode(monkeypatch):
    monkeypatch.setenv(llm.LLM_API_KEY_ENV, "tok")
    mock_post = _make_mock_post()
    with mock.patch.object(llm._SESSION, "post", mock_post):
        llm.call_llm("sys", "user", json_mode=True)
    assert _post_payload(mock_post).get("response_format") == {"type": "json_object"}


def test_call_llm_raises_http_error_on_bad_status(monkeypatch):
    monkeypatch.setenv(llm.LLM_API_KEY_ENV, "tok")
    monkeypatch.setenv("GH_MODELS_TOKEN", "tok")
    mock_response = mock.MagicMock()
    mock_response.raise_for_status.side_effect = Exception("HTTP 500")
    with mock.patch.object(llm._SESSION, "post", return_value=mock_response), \
         pytest.raises(Exception):
        llm.call_llm("sys", "user")


# --- parse_triage_output drop accounting ---
# An empty list from the guards looks identical to an editorial skip. The
# caller needs the counts to tell a broken run from a quiet one.

def _valid(headline="ok", **kw):
    item = {"headline": headline, "category": "threat", "severity": "high",
            "why": "w", "action": "a", "url": "https://example.com",
            "stack_match": "GitHub"}
    item.update(kw)
    return item


def test_stats_report_zero_drops_for_clean_output(monkeypatch):
    monkeypatch.setattr(llm, "STACK_SUMMARY", "CI/CD & SCM: GitHub")
    stats = {}
    llm.parse_triage_output(json.dumps({"items": [_valid()]}), stats)
    assert stats == {"returned": 1, "dropped": 0}


def test_stats_count_every_guard(monkeypatch):
    """Missing fields, placeholder CVE, failed stack-grounding, and a
    non-dict entry all count as drops."""
    monkeypatch.setattr(llm, "STACK_SUMMARY", "CI/CD & SCM: GitHub")
    payload = {"items": [
        _valid("kept"),
        {"headline": "no url", "category": "threat", "severity": "high",
         "why": "w", "action": "a"},
        _valid("fake cve", why="see CVE-2026-XXXX"),
        _valid("ungrounded", stack_match="Kubernetes"),
        "not even a dict",
    ]}
    stats = {}
    items = llm.parse_triage_output(json.dumps(payload), stats)
    assert [i["headline"] for i in items] == ["kept"]
    assert stats == {"returned": 5, "dropped": 4}


def test_stats_distinguish_all_dropped_from_empty_items(monkeypatch):
    """The case the caller acts on: the model sent items and the guards
    rejected every one. Both produce [], only one is degraded."""
    monkeypatch.setattr(llm, "STACK_SUMMARY", "CI/CD & SCM: GitHub")

    all_dropped = {}
    assert llm.parse_triage_output(
        json.dumps({"items": [_valid("bad", stack_match="Kubernetes")]}),
        all_dropped) == []
    assert all_dropped["returned"] > 0 and all_dropped["dropped"] > 0

    nothing_found = {}
    assert llm.parse_triage_output(json.dumps({"items": []}), nothing_found) == []
    assert nothing_found == {"returned": 0, "dropped": 0}


def test_stats_untouched_on_skip(monkeypatch):
    stats = {}
    assert llm.parse_triage_output('{"skip": true}', stats) is None
    assert stats == {}


def test_stats_argument_stays_optional(monkeypatch):
    monkeypatch.setattr(llm, "STACK_SUMMARY", "CI/CD & SCM: GitHub")
    assert len(llm.parse_triage_output(json.dumps({"items": [_valid()]}))) == 1


# --- transport retries ---

def test_chat_completion_retries_read_timeout(monkeypatch):
    """A single upstream read timeout must not kill the run."""
    import requests

    ok = mock.Mock(status_code=200)
    ok.json.return_value = {"choices": [{"message": {"content": "hi"}}]}
    post = mock.Mock(side_effect=[requests.exceptions.ReadTimeout("boom"), ok])
    # urllib3 does the real retrying inside the adapter; assert the policy is
    # mounted and that a retried call still returns, using Session.post as the
    # stand-in for the adapter's transport.
    monkeypatch.setattr(llm._SESSION, "post", post)

    retry = llm._SESSION.get_adapter("https://x/").max_retries
    assert "POST" in retry.allowed_methods
    assert retry.total == 2

    with pytest.raises(requests.exceptions.ReadTimeout):
        llm._chat_completion("https://x", "k", "m", "s", "u", 0.1, False)
    assert llm._chat_completion("https://x", "k", "m", "s", "u", 0.1, False) == "hi"
