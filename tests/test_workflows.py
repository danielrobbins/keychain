# SPDX-License-Identifier: GPL-3.0-only
import os
import re
import subprocess
import textwrap
from pathlib import Path

import pytest

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


def test_full_sweep_and_merge_gate_require_the_same_events():
    workflow = (_WORKFLOWS / "python-ci.yml").read_text(encoding="utf-8")
    sweep = workflow.split("\n  test-full-sweep:\n", 1)[1]
    condition = sweep.split("    if: >-\n", 1)[1].split("    runs-on:", 1)[0]
    gate = workflow.split("      TEST_FULL_SWEEP_REQUIRED: >-\n", 1)[1].split("    steps:", 1)[0]
    expected = (
        "github.event_name == 'pull_request' || "
        "github.event_name == 'schedule' || "
        "github.event_name == 'workflow_dispatch' || "
        "(github.event_name == 'push' && github.ref == 'refs/heads/master') || "
        "(github.event_name == 'push' && startsWith(github.ref, 'refs/tags/'))"
    )

    assert " ".join(condition.split()) == expected
    assert " ".join(gate.replace("${{", "").replace("}}", "").split()) == expected


_ALWAYS_REQUIRED_RESULTS = (
    "STATIC_ANALYSIS_RESULT",
    "TEST_FAST_RESULT",
    "TEST_MSYS2_RESULT",
    "TEST_FREEBSD_RESULT",
    "TEST_OPENBSD_RESULT",
    "TEST_OMNIOS_RESULT",
    "TEST_ROCKY8_RESULT",
)


@pytest.mark.skipif(os.name != "posix", reason="The aggregate CI job runs in Bash on Linux")
@pytest.mark.parametrize(
    "required,changed,result,passes",
    [
        (required, "TEST_FULL_SWEEP_RESULT", result, result == "success" or (not required and result == "skipped"))
        for required in (True, False)
        for result in ("success", "failure", "cancelled", "skipped")
    ]
    + [
        (False, job, result, False)
        for job in _ALWAYS_REQUIRED_RESULTS
        for result in ("failure", "cancelled", "skipped")
    ],
)
def test_aggregate_ci_status(required, changed, result, passes):
    workflow = (_WORKFLOWS / "python-ci.yml").read_text(encoding="utf-8")
    gate = workflow.split("\n  ci-passing:\n", 1)[1]
    script = textwrap.dedent(gate.split("        run: |\n", 1)[1])
    env = dict(os.environ, **dict.fromkeys(_ALWAYS_REQUIRED_RESULTS, "success"))
    env.update(TEST_FULL_SWEEP_REQUIRED=str(required).lower(), TEST_FULL_SWEEP_RESULT="skipped")
    env[changed] = result

    completed = subprocess.run(["bash", "-e", "-c", script], env=env, capture_output=True, text=True)

    assert completed.returncode == (0 if passes else 1), completed.stdout + completed.stderr
