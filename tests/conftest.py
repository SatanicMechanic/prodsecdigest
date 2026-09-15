"""Make project root importable for tests."""
import datetime
import os
import sys
import pathlib
import types

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

# LLM_MODEL has no built-in default (digest._check_env enforces it at run
# start), so the suite supplies its own. setdefault, not a bare assignment, so
# running against a real model id from the environment still works.
os.environ.setdefault("LLM_MODEL", "test-model")


@pytest.fixture
def freeze_utc(monkeypatch):
    """Pin the digest-day clock (state.py) to a UTC instant:
    freeze_utc("2026-09-10T00:36")."""
    import state  # here, not at top: config must load after LLM_MODEL is set

    def _freeze(iso: str) -> None:
        frozen = datetime.datetime.fromisoformat(iso).replace(tzinfo=datetime.timezone.utc)

        class _Clock(datetime.datetime):
            @classmethod
            def now(cls, tz=None):
                return frozen

        monkeypatch.setattr(state, "datetime",
                            types.SimpleNamespace(**{**vars(datetime), "datetime": _Clock}))

    return _freeze
