"""Optional Slack notification via incoming webhook.

No-op unless SLACK_WEBHOOK_URL is set. Best-effort alongside email: a Slack
failure doesn't fail the run. When Slack is the only delivery, the caller
passes fatal=True so a failure isn't recorded as a sent digest.
"""

import os
import requests

_TIMEOUT_SEC = 10


def send_slack(payload: dict, fatal: bool = False) -> None:
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if not webhook_url or not payload:
        return
    try:
        resp = requests.post(webhook_url, json=payload, timeout=_TIMEOUT_SEC)
        resp.raise_for_status()
        print("Slack notification sent.")
    except requests.RequestException as exc:
        if fatal:
            raise
        print(f"Slack notification failed (non-fatal): {exc}")
