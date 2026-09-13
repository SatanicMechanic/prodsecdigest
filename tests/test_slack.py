"""Tests for slack.py — optional webhook notification."""

from unittest import mock

import pytest

import slack


def test_send_slack_noop_when_unset(monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    with mock.patch.object(slack.requests, "post") as mock_post:
        slack.send_slack({"text": "x", "blocks": []})
    mock_post.assert_not_called()


def test_send_slack_posts_payload_when_set(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/x")
    payload = {"text": "fallback", "blocks": [{"type": "divider"}]}
    with mock.patch.object(slack.requests, "post") as mock_post:
        mock_post.return_value = mock.Mock(status_code=200)
        slack.send_slack(payload)
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert args[0] == "https://hooks.slack.com/services/x"
    assert kwargs["json"] == payload


def test_send_slack_noop_on_empty_payload(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/x")
    with mock.patch.object(slack.requests, "post") as mock_post:
        slack.send_slack({})
    mock_post.assert_not_called()


def test_send_slack_failure_is_non_fatal(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/x")
    with mock.patch.object(slack.requests, "post", side_effect=slack.requests.RequestException("down")):
        slack.send_slack({"text": "x"})  # must not raise


def test_send_slack_failure_raises_when_fatal(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/x")
    with mock.patch.object(slack.requests, "post", side_effect=slack.requests.RequestException("down")):
        with pytest.raises(slack.requests.RequestException):
            slack.send_slack({"text": "x"}, fatal=True)
