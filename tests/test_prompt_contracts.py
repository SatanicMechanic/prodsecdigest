"""Tests for contracts the prompt files have to keep.

Prompt text is configuration the model acts on, so a rule silently edited out
of a prompt is a behavior change with no code diff to review. These pin the
ones that are not safe to lose.
"""

import os

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _prompt(name: str) -> str:
    with open(os.path.join(_ROOT, name)) as f:
        return f.read()


def test_threat_prompt_declares_the_stack_override_convention():
    """A fork's scope rules have to be able to beat the inclusion criteria.

    Without this, a stack summary line saying "this class is always in scope"
    argues against Category 1's "qualifies ONLY if..." and loses silently.
    """
    prompt = _prompt("prompt_threat.txt")
    assert "## Stack-summary overrides" in prompt
    assert "OVERRIDE:" in prompt
    # It has to reach the suppression rules too, not just the inclusion list.
    assert "trailing-coverage" in prompt
    assert "recent-coverage suppression" in prompt


def test_stack_override_marker_is_not_reachable_from_article_text():
    """The override marker is a prompt-injection vector if it is not fenced.

    Article titles and summaries are untrusted; an item that could talk its own
    way past the bar by claiming to carry the marker would be strictly worse
    than having no override at all.
    """
    prompt = _prompt("prompt_threat.txt")
    section = prompt.split("## Stack-summary overrides", 1)[1].split("## Inclusion", 1)[0]
    assert "only ever valid inside the stack summary" in section
    assert "untrusted" in section


@pytest.mark.parametrize("name", ["prompt_threat.txt", "prompt_tooling.txt"])
def test_prompts_keep_their_trust_boundary(name):
    assert "**Trust boundary:**" in _prompt(name)
