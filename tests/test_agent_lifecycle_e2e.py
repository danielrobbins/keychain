# SPDX-License-Identifier: GPL-3.0-only
"""Real agent discovery, key retention, and shutdown on POSIX-shaped hosts."""

import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from keychain.env import SshAgentRef
from keychain.paths import KeychainPaths
from keychain.runtime import platform

pytestmark = pytest.mark.skipif(
    os.name == "nt" or not platform.detect().supported
    or any(shutil.which(tool) is None for tool in ("ssh-agent", "ssh-add", "ssh-keygen")),
    reason="requires a supported POSIX host and OpenSSH tools",
)
ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(sys.platform != "darwin", reason="Apple ps signed UID regression")
def test_macos_agent_lifecycle_with_nobody_process(monkeypatch):
    import pwd

    sudo = shutil.which("sudo")
    if not sudo or subprocess.run([sudo, "-n", "true"], capture_output=True, timeout=10).returncode:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            pytest.fail("macOS CI must provide passwordless sudo for the nobody regression")
        pytest.skip("requires passwordless sudo to start an unrelated nobody process")

    # A bounded sleeper supplies a real negative UID without running Keychain as root.
    started = subprocess.run(
        [sudo, "-n", "-u", "nobody", "/bin/sh", "-c",
         "/bin/sleep 120 </dev/null >/dev/null 2>&1 & echo $!"],
        capture_output=True, text=True, timeout=10,
    )
    assert started.returncode == 0, started.stderr
    pid = int(started.stdout.strip())
    assert pid > 0
    try:
        pattern = re.compile(r"(?:^|/)sleep$")
        deadline = time.monotonic() + 5
        while True:
            row = subprocess.run(
                ["ps", "-p", str(pid), "-o", "pid=", "-o", "uid=", "-o", "comm="],
                capture_output=True, text=True, check=True, timeout=10,
            ).stdout.split(None, 2)
            if len(row) == 3 and pattern.search(row[2].strip()):
                break
            assert time.monotonic() < deadline, f"nobody process did not exec sleep: {row}"
            time.sleep(0.05)
        assert row[:2] == [str(pid), "-2"], row
        platform.reset()
        assert pid in platform.detect().process_list(pattern, pwd.getpwnam("nobody").pw_uid)
        assert pid not in platform.detect().process_list(pattern, os.getuid())
        test_agent_reuse_preserves_loaded_key(monkeypatch, None)
    finally:
        subprocess.run([sudo, "-n", "kill", "-TERM", str(pid)], capture_output=True, timeout=10)


@pytest.mark.parametrize("columns", [None, "20", "80"])
def test_agent_reuse_preserves_loaded_key(monkeypatch, columns):
    monkeypatch.setattr(platform, "_cached", None)
    if columns is None:
        monkeypatch.delenv("COLUMNS", raising=False)
    else:
        monkeypatch.setenv("COLUMNS", columns)
    # Short paths also fit macOS sockaddr_un; spaces exercise real ps parsing.
    with tempfile.TemporaryDirectory(prefix="kc-life-", dir="/tmp") as temporary:
        home = Path(temporary) / "test home"
        home.mkdir(mode=0o700)
        paths = KeychainPaths.build(str(home / ".keychain"), True, "test")
        env = {key: value for key, value in os.environ.items() if not key.startswith("KEYCHAIN_")}
        env.update(HOME=str(home), PYTHONPATH=str(ROOT / "src"), SSH_ASKPASS_REQUIRE="never")
        for key in ("SSH_AUTH_SOCK", "SSH_AGENT_PID", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR"):
            env.pop(key, None)
        pids = set()

        def keychain(*args):
            try:
                return subprocess.run(
                    [sys.executable, "-m", "keychain", *args, "--host", "test",
                     "--dir", str(paths.keydir), "--absolute", "--nocolor"],
                    env=env, capture_output=True, text=True, timeout=30,
                )
            finally:
                # Cleanup must not depend on process discovery working correctly.
                pidfile = paths.pidfile_path("sh")
                if pidfile.exists():
                    match = re.search(r"^SSH_AGENT_PID=(\d+);", pidfile.read_text(), re.M)
                    if match:
                        pids.add(int(match.group(1)))

        def run(*args, agent=None):
            return subprocess.run(
                args, env={**env, **(agent.as_dict() if agent else {})},
                capture_output=True, text=True, timeout=30,
            )

        try:
            first = keychain("add", "--eval", "--noask", "--no-inherit")
            assert first.returncode == 0, first.stdout + first.stderr
            agent = SshAgentRef.from_text(first.stdout)
            assert agent.pid_int is not None
            assert agent.sock == str(paths.ssh_agent_socket_path)
            visible = platform.detect().process_list(re.compile(r"(?:^|/)ssh-agent$"), os.getuid())
            assert agent.pid_int in visible, {
                "agent": agent, "uid": os.getuid(), "COLUMNS": os.environ.get("COLUMNS"),
                "platform": repr(platform.detect()), "ps_path": shutil.which("ps"),
                "ps": run(*platform.detect().ps_command).stdout,
                "ssh-add": run("ssh-add", "-l", agent=agent),
            }
            assert agent.pid_int not in platform.detect().process_list(
                re.compile(r"(?:^|/)ssh-agent$"), os.getuid() + 1,
            )

            key = str(home / "test-key")
            generated = run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
            assert generated.returncode == 0, generated.stderr
            fingerprint = run("ssh-keygen", "-lf", key + ".pub")
            assert fingerprint.returncode == 0, fingerprint.stderr
            expected = fingerprint.stdout.split()[1]
            added = run("ssh-add", key, agent=agent)
            assert added.returncode == 0, added.stderr

            for _ in range(3):
                reused = keychain("add", "--eval", "--noask", "--no-inherit")
                assert reused.returncode == 0, reused.stdout + reused.stderr
                assert SshAgentRef.from_text(reused.stdout) == agent
                assert pids == {agent.pid_int}, "Keychain started another agent instead of reusing it"
                loaded = run("ssh-add", "-l", agent=agent)
                assert loaded.returncode == 0, loaded.stderr
                assert expected in loaded.stdout

            stopped = keychain("agent", "stop")
            assert stopped.returncode == 0, stopped.stdout + stopped.stderr
            assert not paths.pidfile_path("sh").exists()
            deadline = time.monotonic() + 5
            while run("ssh-add", "-l", agent=agent).returncode != 2:
                assert time.monotonic() < deadline, "agent still responds after Keychain stopped it"
                time.sleep(0.05)
        finally:
            for pid in pids:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
