"""Tests for digest._check_env delivery requirements."""

import pytest

import digest

_EMAIL = {"RESEND_API_KEY": "re_x", "DIGEST_TO_EMAIL": "a@b.c", "DIGEST_FROM_EMAIL": "d@b.c"}


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv(digest.LLM_API_KEY_ENV, "k")
    for name in (*_EMAIL, "SLACK_WEBHOOK_URL"):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_email_only_ok(env):
    for k, v in _EMAIL.items():
        env.setenv(k, v)
    digest._check_env()


def test_slack_only_ok(env):
    env.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/x")
    digest._check_env()


def test_no_delivery_fails(env):
    with pytest.raises(RuntimeError, match="No delivery"):
        digest._check_env()


@pytest.mark.parametrize("attr, value, match", [
    ("LLM_BASE_URL", "", "Unknown LLM_PROVIDER"),
    ("LLM_EXTRA", "{not json", "LLM_EXTRA is not valid JSON"),
    ("LLM_EXTRA", "[]", "LLM_EXTRA must be a JSON object"),
])
def test_llm_config_errors_fail_at_startup(env, attr, value, match):
    env.setattr(digest, attr, value)
    with pytest.raises(RuntimeError, match=match):
        digest._check_env()


@pytest.mark.parametrize("env_vars, base_url", [
    ({"LLM_PROVIDER": "nope"}, ""),  # used to SystemExit at import
    ({"LLM_BASE_URL": "https://llm.example/v1/"}, "https://llm.example/v1"),
])
def test_config_import_does_not_exit(monkeypatch, env_vars, base_url):
    """check_feeds imports config and never uses the LLM settings."""
    import importlib
    import config
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    for k, v in env_vars.items():
        monkeypatch.setenv(k, v)
    try:
        assert importlib.reload(config).LLM_BASE_URL == base_url
    finally:
        monkeypatch.undo()
        importlib.reload(config)


def test_partial_email_fails_even_with_slack(env):
    env.setenv("RESEND_API_KEY", "re_x")
    env.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/x")
    with pytest.raises(RuntimeError, match="DIGEST_TO_EMAIL"):
        digest._check_env()
