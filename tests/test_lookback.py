"""Tests for digest.extended_lookback_hours — how far back a run must look
after earlier runs failed to triage.

The window is the gap since the last clean triage plus a margin, rounded up,
never below the base window and never past the cap. LOOKBACK_CAP_HOURS and
LOOKBACK_MARGIN_HOURS live in config.py, so tuning them does not break these.
"""

import datetime
import math

import config
from digest import extended_lookback_hours

NOW = datetime.datetime(2026, 11, 18, 12, 0, tzinfo=datetime.timezone.utc)


def _ago(hours: float) -> datetime.datetime:
    return NOW - datetime.timedelta(hours=hours)


def test_no_prior_clean_triage_keeps_the_base_window():
    assert extended_lookback_hours(24, None, NOW) == 24


def test_a_recent_clean_triage_keeps_the_base_window():
    assert extended_lookback_hours(24, _ago(12), NOW) == 24


def test_missed_runs_stretch_the_window_back_to_the_last_clean_triage():
    assert extended_lookback_hours(24, _ago(30), NOW) == math.ceil(
        30 + config.LOOKBACK_MARGIN_HOURS)


def test_a_fractional_gap_rounds_up_never_down():
    assert extended_lookback_hours(24, _ago(30.2), NOW) == math.ceil(
        30.2 + config.LOOKBACK_MARGIN_HOURS)


def test_the_window_never_exceeds_the_cap():
    assert extended_lookback_hours(24, _ago(1000), NOW) == config.LOOKBACK_CAP_HOURS


def test_the_base_window_wins_when_it_is_already_past_the_cap():
    base = config.LOOKBACK_CAP_HOURS + 24
    assert extended_lookback_hours(base, _ago(1000), NOW) == base


def test_a_stamp_in_the_future_is_clock_skew_not_a_reason_to_shrink():
    assert extended_lookback_hours(
        24, NOW + datetime.timedelta(hours=5), NOW) == 24
