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
    env.update({"SSH_ASKPASS": str(askpass), "SSH_ASKPASS_REQUIRE": "force"})

    agent = _keychain_add_confirm(env, key)
    agents.append(agent)
    result = _run(["ssh-add", "-T", f"{key}.pub"], agent.overlay(env))

    _assert_ok(result)
    assert log.read_text(encoding="utf-8").startswith("confirm|")


def test_force_askpass_loads_encrypted_key_without_display(ssh_confirm_home) -> None:
    env, key, askpass, log, agents = ssh_confirm_home
    encrypted_key = key.with_name("id_encrypted")
    passphrase = "test passphrase"
    _assert_ok(_run(["ssh-keygen", "-q", "-t", "ed25519", "-N", passphrase, "-f", str(encrypted_key)], env))
    _write_askpass(askpass, log, passphrase)
    env.update({"SSH_ASKPASS": str(askpass), "SSH_ASKPASS_REQUIRE": "force"})

    agent = _keychain_add_confirm(env, encrypted_key)
    agents.append(agent)

    _assert_ok(_run(["ssh-add", "-l"], agent.overlay(env)))
    assert log.exists()


def test_confirmed_key_cannot_replace_askpass_after_agent_start(ssh_confirm_home) -> None:
    env, key, askpass, log, agents = ssh_confirm_home
    env.update({"SSH_ASKPASS": str(askpass.with_name("missing-askpass")), "SSH_ASKPASS_REQUIRE": "force"})
    agent = _keychain_add_confirm(env, key)
    agents.append(agent)
    client_env = agent.overlay(env)
    client_env.update({"SSH_ASKPASS": str(askpass), "SSH_ASKPASS_REQUIRE": "force"})

    result = _run(["ssh-add", "-T", f"{key}.pub"], client_env)

    assert result.returncode != 0
    assert not log.exists()
