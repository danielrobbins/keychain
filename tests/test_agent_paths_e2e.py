# SPDX-License-Identifier: GPL-3.0-only
"""Agent startup and reuse with shell-special characters in real socket paths."""

import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from keychain.env import SshAgentRef
from keychain.paths import KeychainPaths
from keychain.runtime import platform

pytestmark = pytest.mark.skipif(
    os.name == "nt" or not platform.detect().supported or shutil.which("ssh-agent") is None,
    reason="requires a supported POSIX host with ssh-agent",
)
ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("name", ["a;b", "a b", "a'b", 'a"b', "a!b", "a\\b", "a b;'\\"])
@pytest.mark.parametrize("socket_source", ["default", "cli", "env", "config"])
def test_keychain_reuses_agent_in_special_character_directory(name, socket_source):
    with tempfile.TemporaryDirectory(prefix="kc-path-", dir="/tmp") as temporary:
        home = Path(temporary) / name
        home.mkdir(mode=0o700)
        paths = KeychainPaths.build(str(home / ".keychain"), True, "test")
        env = os.environ.copy()
        env.update(HOME=str(home), PYTHONPATH=str(ROOT / "src"))
        for key in ("SSH_AUTH_SOCK", "SSH_AGENT_PID", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR",
                    "KEYCHAIN_CONFIG", "KEYCHAIN_SSH_AGENT_ARGS"):
            env.pop(key, None)
        expected_socket = str(paths.ssh_agent_socket_path)
        extra = []
        if socket_source != "default":
            expected_socket = str(home / "custom.sock")
            extra = ["--ssh-agent-socket", expected_socket]
        if socket_source in {"env", "config"}:
            extra = ["--ssh-agent-socket", str(home / "overridden.sock")]
            if socket_source == "env":
                env["KEYCHAIN_SSH_AGENT_ARGS"] = shlex.join(["-sa" + expected_socket])
                extra += ["--allow-env"]
            else:
                args = shlex.join(["-a", str(home / "first.sock"), "-a", expected_socket])
                (home / ".keychainrc").write_text(f"[agent.env]\nssh_args={args}\n", encoding="utf-8")
        pids = set()
        try:
            for _ in range(3):
                result = subprocess.run(
                    [sys.executable, "-m", "keychain", "add", "--noask", "--eval", "--no-inherit",
                     "--host", "test", "--dir", str(paths.keydir), "--absolute", *extra],
                    env=env, capture_output=True, text=True, timeout=30,
                )
                # Keep cleanup independent of the parser being tested.
                pidfile = paths.pidfile_path("sh")
                if pidfile.exists():
                    match = re.search(r"^SSH_AGENT_PID=(\d+);", pidfile.read_text(), re.M)
                    if match:
                        pids.add(int(match.group(1)))
                assert result.returncode == 0, result.stdout + result.stderr
                agent = SshAgentRef.from_text(result.stdout)
                assert agent.sock == expected_socket
                assert len(pids) == 1
                assert agent.pid_int in pids
        finally:
            for pid in pids:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
