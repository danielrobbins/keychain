# SPDX-License-Identifier: GPL-3.0-only
"""The csh pidfile must survive csh history substitution and quoting rules."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from keychain.env import SshAgentRef
from keychain.paths import CshPidfile

_CSH = shutil.which("tcsh") or shutil.which("csh")

SOCKETS = [
    "/tmp/plain/agent.sock",
    "/tmp/a b/agent.sock",
    "/tmp/it's/agent.sock",
    "/tmp/a!b/agent.sock",
    "/tmp/a!!/agent.sock",
    "/tmp/a$HOME/agent.sock",
    "/tmp/a;b/agent.sock",
]


def _render(sock: str) -> str:
    return CshPidfile(Path("/unused"), "").render(SshAgentRef(sock, "1234"))


def test_bang_is_escaped_for_history_substitution():
    assert "\\!" in _render("/tmp/a!b/agent.sock")
    assert "!" not in _render("/tmp/a!b/agent.sock").replace("\\!", "")


@pytest.mark.skipif(_CSH is None, reason="tcsh/csh is not installed")
@pytest.mark.parametrize("sock", SOCKETS)
def test_csh_pidfile_sets_the_exact_socket_path(sock, tmp_path):
    pidfile = tmp_path / "pidfile.csh"
    pidfile.write_text(_render(sock), encoding="utf-8")
    result = subprocess.run(
        [_CSH, "-f"],
        input=f"source {pidfile}\nprintf '%s' \"$SSH_AUTH_SOCK\"\n",
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
    )
    assert result.stdout == sock, result.stderr
