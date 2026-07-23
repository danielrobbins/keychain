# SPDX-License-Identifier: GPL-3.0-only
import re
from pathlib import Path

_WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def test_external_actions_are_pinned_to_commits():
    uses = re.findall(r"^\s*uses:\s+([^#\s]+)", "\n".join(path.read_text() for path in _WORKFLOWS.glob("*.yml")), re.M)

    assert uses
    for action in uses:
        assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", action), action


def test_release_build_is_read_only_and_publish_is_narrowly_privileged():
    workflow = (_WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    build, publish = workflow.split("\n  publish:", 1)

    assert "permissions:\n  contents: read" in build
    assert "contents: write" not in build
    assert "permissions:\n      contents: write" in publish
    assert "actions/checkout@" not in publish
    assert "actions/setup-python@" not in publish
