"""Tests for mailer.py — Resend payload and failure handling."""

from unittest import mock

import pytest

import mailer


@pytest.fixture
def session(monkeypatch):
    monkeypatch.setenv("RESEND_API_KEY", "re_x")
    monkeypatch.setenv("DIGEST_TO_EMAIL", "a@ex.com, ,b@ex.com")
    monkeypatch.setenv("DIGEST_FROM_EMAIL", "digest@ex.com")
    s = mock.MagicMock()
    monkeypatch.setattr(mailer.requests, "Session", lambda: s)
    return s


def test_send_email_posts_payload(session):
    mailer.send_email("<p>h</p>", "t", "subj")
    _, kwargs = session.post.call_args
    assert kwargs["json"]["to"] == ["a@ex.com", "b@ex.com"]
    assert kwargs["json"]["subject"] == "subj"
    assert kwargs["headers"]["Authorization"] == "Bearer re_x"


def test_send_email_failure_raises_without_leaking_key(session):
    """A failed send must fail the run, or the items get recorded as sent."""
    session.post.return_value.raise_for_status.side_effect = (
        mailer.requests.HTTPError("401"))
    with pytest.raises(RuntimeError) as exc_info:
        mailer.send_email("<p>h</p>", "t", "subj")
    assert "re_x" not in str(exc_info.value)


def test_send_email_failure_carries_status_and_body(session):
    resp = mock.MagicMock(status_code=422, text='{"message":"invalid from"}')
    session.post.return_value.raise_for_status.side_effect = (
        mailer.requests.HTTPError("422", response=resp))
    with pytest.raises(RuntimeError, match="HTTP 422.*invalid from"):
        mailer.send_email("<p>h</p>", "t", "subj")


def test_send_email_connection_error_has_no_response(session):
    session.post.side_effect = mailer.requests.ConnectionError("refused")
    with pytest.raises(RuntimeError, match="failed after retries$"):
        mailer.send_email("<p>h</p>", "t", "subj")
