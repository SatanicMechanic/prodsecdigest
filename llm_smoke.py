"""Quick smoke test for the configured LLM provider.

Manual: hits the real APIs. Filename is intentionally not `test_*.py` so
pytest's auto-collection skips it; run it directly when you want to verify
provider connectivity.

Run with:  LLM_MODEL=<model> <PROVIDER_KEY>=<key> .venv/bin/python3 llm_smoke.py
"""

import json
import sys
import time
from dotenv import load_dotenv

import llm


def check(label, raw, elapsed, expect_type) -> bool:
    print(f"\n{'='*60}")
    print(f"[{label}]  {elapsed:.1f}s")
    print(f"Raw: {raw[:300]}{'...' if len(raw) > 300 else ''}")
    clean = llm._strip_fences(raw)
    try:
        parsed = json.loads(clean)
    except json.JSONDecodeError as e:
        print(f"  FAIL: invalid JSON — {e}")
        return False
    if not isinstance(parsed, expect_type):
        print(f"  FAIL: expected {expect_type.__name__}, got {type(parsed).__name__}")
        return False
    print(f"  OK: valid JSON {expect_type.__name__}")
    return True


def _call(label, system, user, **kwargs):
    """(raw, elapsed), or (None, 0.0) after printing the failure — one broken
    call must not hide the result of the checks after it."""
    t0 = time.monotonic()
    try:
        return llm.call_llm(system, user, **kwargs), time.monotonic() - t0
    except Exception as exc:
        print(f"\n[{label}]  FAIL: {type(exc).__name__}: {exc}")
        return None, 0.0


def main() -> int:
    load_dotenv()
    ok = True

    raw, elapsed = _call("plain", "You are a helpful assistant.", "Say hello.")
    if raw is None:
        ok = False
    else:
        print(f"\n[plain]  {elapsed:.1f}s  →  {raw!r}")

    raw, elapsed = _call(
        "JSON array",
        "Generate exactly 2 security search queries. Return ONLY a JSON array of strings. No preamble.",
        "Generate 2 queries targeting actively exploited vulnerabilities.",
        temperature=0.4,
    )
    ok &= raw is not None and check("JSON array", raw, elapsed, list)

    raw, elapsed = _call(
        "JSON object (json_mode)",
        'Return ONLY a JSON object: {"compliance": ["q1"], "pqc": ["q1"]}',
        "Generate 1 compliance query and 1 PQC query.",
        temperature=0.3, json_mode=True,
    )
    ok &= raw is not None and check("JSON object (json_mode)", raw, elapsed, dict)

    print(f"\n{'='*60}\n{'Done.' if ok else 'FAILED — see FAIL lines above.'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
