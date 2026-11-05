from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from keychain.env import SshAgentRef
from keychain.runtime import platform

pytestmark = pytest.mark.skipif(
    os.name == "nt"
    or not platform.detect().supported
    or any(shutil.which(command) is None for command in ("ssh-add", "ssh-agent", "ssh-keygen")),
    reason="SSH confirmation e2e coverage requires a POSIX host with OpenSSH",
)

ROOT = Path(__file__).resolve().parents[1]


def _run(cmd: list[str], env: dict[str, str], *, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.DEVNULL,
        start_new_session=True,
        timeout=timeout,
        check=False,
    )


def _assert_ok(result: subprocess.CompletedProcess) -> None:
    assert result.returncode == 0, result.stdout + result.stderr


def _write_askpass(path: Path, log: Path, response: str = "yes") -> None:
    path.write_text(
        f"""#!/bin/sh
log={shlex.quote(str(log))}
printf '%s|%s\n' "${{SSH_ASKPASS_PROMPT-}}" "$1" >> "$log"
printf '%s\n' {shlex.quote(response)}
""",
        encoding="utf-8",
    )
    path.chmod(0o700)


def _require_force_askpass(env, key, log, agents):
    # Probe OpenSSH itself, not Keychain or a version number: vendors backport features.
    started = _run(["ssh-agent", "-s"], env)
    _assert_ok(started)
    agent = SshAgentRef.from_text(started.stdout)
    assert agent, started.stdout
    agents.append(agent)
    probe_env = agent.overlay(env)
    result = _run(["ssh-add", str(key)], probe_env)
    if result.returncode != 0 and not log.exists():
        # A working display-based helper distinguishes an unsupported force mode
        # from a broken helper, bad key, or other test setup failure.
        probe_env.pop("SSH_ASKPASS_REQUIRE", None)
        probe_env["DISPLAY"] = ":0"
        _assert_ok(_run(["ssh-add", str(key)], probe_env))
        assert log.exists(), "display-based askpass did not invoke the helper"
        pytest.skip("installed ssh-add does not support forced askpass without DISPLAY")
    _assert_ok(result)
    assert log.exists(), "forced askpass did not invoke the helper"
    log.unlink()


@pytest.mark.parametrize("case", ["supported", "unsupported", "broken-helper", "broken-fallback", "missing-log"])
def test_force_askpass_probe_only_skips_an_unsupported_capability(tmp_path, monkeypatch, case):
    log = tmp_path / "askpass.log"
    env = {"SSH_ASKPASS_REQUIRE": "force", "SSH_ASKPASS": str(tmp_path / "helper")}
    calls = []
    agents = []

    def run(cmd, child_env):
        calls.append((cmd, child_env.copy()))
        if cmd == ["ssh-agent", "-s"]:
            return subprocess.CompletedProcess(cmd, 0, "SSH_AUTH_SOCK=/test.sock; SSH_AGENT_PID=123;", "")
        if "DISPLAY" in child_env:
            assert "SSH_ASKPASS_REQUIRE" not in child_env
            if case == "unsupported":
                log.write_text("|passphrase\n")
                return subprocess.CompletedProcess(cmd, 0, "", "")
        elif case in ("supported", "broken-helper"):
            log.write_text("|passphrase\n")
        status = 0 if case in ("supported", "missing-log") else 1
        return subprocess.CompletedProcess(cmd, status, "", "probe diagnostic")

    monkeypatch.setattr(sys.modules[__name__], "_run", run)
    if case == "supported":
        _require_force_askpass(env, tmp_path / "key", log, agents)
        assert not log.exists(), "Keychain's later invocation must produce its own evidence"
    elif case == "unsupported":
        with pytest.raises(pytest.skip.Exception, match="without DISPLAY"):
            _require_force_askpass(env, tmp_path / "key", log, agents)
    else:
        with pytest.raises(AssertionError):
            _require_force_askpass(env, tmp_path / "key", log, agents)
    assert len(calls) == (3 if case in ("unsupported", "broken-fallback") else 2)
    assert agents == [SshAgentRef("/test.sock", "123")], "the fixture must clean up the probe agent"
    assert env == {"SSH_ASKPASS_REQUIRE": "force", "SSH_ASKPASS": str(tmp_path / "helper")}


@pytest.fixture
def ssh_confirm_home():
    root = Path(tempfile.mkdtemp(prefix="kc-ssh-", dir="/tmp" if sys.platform == "darwin" else None))
    home = root / "home"
    home.mkdir(mode=0o700)
    key = home / "id_confirm"
    log = root / "askpass.log"
    askpass = root / "askpass-test"
    _write_askpass(askpass, log)

    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "PYTHONPATH": str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", ""),
        }
    )
    for name in ("DISPLAY", "WAYLAND_DISPLAY", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "SSH_AUTH_SOCK", "SSH_AGENT_PID"):
        env.pop(name, None)

    _assert_ok(_run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], env))
    agents: list[SshAgentRef] = []
    yield env, key, askpass, log, agents

    for agent in agents:
        _run(["ssh-agent", "-k"], agent.overlay(env), timeout=10)
    shutil.rmtree(root, ignore_errors=True)


def _keychain_add_confirm(env: dict[str, str], key: Path) -> SshAgentRef:
    result = _run(
        [
            sys.executable,
            "-m",
            "keychain",
            "--no-color",
            "--quiet",
            "add",
            "--confirm",
            "--no-inherit",
            "--no-lock",
            "--eval",
            str(key),
        ],
        env,
    )
    _assert_ok(result)
    agent = SshAgentRef.from_text(result.stdout)
    assert agent, result.stdout + result.stderr
    return agent


def test_confirmed_key_invokes_askpass_when_agent_inherits_askpass(ssh_confirm_home) -> None:
    env, key, askpass, log, agents = ssh_confirm_home
    # The shell helper needs no X server; DISPLAY enables older OpenSSH's askpass path.
    env.update({"SSH_ASKPASS": str(askpass), "DISPLAY": ":0"})

    agent = _keychain_add_confirm(env, key)
    agents.append(agent)
    result = _run(["ssh-add", "-T", f"{key}.pub"], agent.overlay(env))

    _assert_ok(result)
    hint, prompt = log.read_text(encoding="utf-8").split("|", 1)
    assert hint in ("", "confirm")  # Older OpenSSH does not supply SSH_ASKPASS_PROMPT.
    assert prompt.strip()


@pytest.mark.parametrize("mode", ["display", "force"])
def test_askpass_loads_encrypted_key(ssh_confirm_home, mode) -> None:
    env, key, askpass, log, agents = ssh_confirm_home
    encrypted_key = key.with_name("id_encrypted")
    passphrase = "test passphrase"
    _assert_ok(_run(["ssh-keygen", "-q", "-t", "ed25519", "-N", passphrase, "-f", str(encrypted_key)], env))
    _write_askpass(askpass, log, passphrase)
    env["SSH_ASKPASS"] = str(askpass)
    if mode == "force":
        env["SSH_ASKPASS_REQUIRE"] = "force"
        _require_force_askpass(env, encrypted_key, log, agents)
    else:
        env["DISPLAY"] = ":0"

    agent = _keychain_add_confirm(env, encrypted_key)
    agents.append(agent)

    _assert_ok(_run(["ssh-add", "-l"], agent.overlay(env)))
    assert log.exists()


def test_confirmed_key_cannot_replace_askpass_after_agent_start(ssh_confirm_home) -> None:
    env, key, askpass, log, agents = ssh_confirm_home
    env.update({"SSH_ASKPASS": str(askpass.with_name("missing-askpass")), "DISPLAY": ":0"})
    agent = _keychain_add_confirm(env, key)
    agents.append(agent)
    client_env = agent.overlay(env)
    client_env["SSH_ASKPASS"] = str(askpass)

    result = _run(["ssh-add", "-T", f"{key}.pub"], client_env)

    assert result.returncode != 0
    assert not log.exists()
