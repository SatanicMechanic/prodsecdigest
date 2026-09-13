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


def test_partial_email_fails_even_with_slack(env):
    env.setenv("RESEND_API_KEY", "re_x")
    env.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/x")
    with pytest.raises(RuntimeError, match="DIGEST_TO_EMAIL"):
        digest._check_env()
