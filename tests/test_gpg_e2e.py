from __future__ import annotations

import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from keychain.runtime import platform

pytestmark = pytest.mark.skipif(
    os.name == "nt" or not platform.detect().supported or not shutil.which("gpg") or not shutil.which("gpgconf"),
    reason="GPG e2e coverage requires a POSIX host with gpg and gpgconf",
)


ROOT = Path(__file__).resolve().parents[1]


def _run(cmd: list[str], env: dict[str, str], *, input_: str | None = None, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        input=input_,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def _gpg(env: dict[str, str], *args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return _run(["gpg", *args], env, timeout=timeout)


def _assert_ok(result: subprocess.CompletedProcess) -> None:
    assert result.returncode == 0, result.stdout + result.stderr


def _write_fake_pinentry(path: Path, passfile: Path, log: Path) -> None:
    path.write_text(
        f"""#!/bin/sh
passfile={shlex.quote(str(passfile))}
log={shlex.quote(str(log))}
printf "OK fake pinentry\\n"
while IFS= read -r line; do
  printf "%s\\n" "$line" >> "$log"
  case "$line" in
    GETPIN*)
      if [ -r "$passfile" ]; then
        printf "D %s\\n" "$(cat "$passfile")"
        printf "OK\\n"
      else
        printf "ERR 83886179 Operation cancelled\\n"
      fi
      ;;
    BYE*) printf "OK\\n"; exit 0 ;;
    *) printf "OK\\n" ;;
  esac
done
""",
        encoding="utf-8",
    )
    path.chmod(0o700)


def _fingerprint(env: dict[str, str]) -> str:
    result = _gpg(env, "--batch", "--with-colons", "--list-secret-keys")
    _assert_ok(result)
    for line in result.stdout.splitlines():
        fields = line.split(":")
        if fields[0] == "fpr":
            return fields[9]
    raise AssertionError(f"no fingerprint in gpg output:\n{result.stdout}")


def _kill_keychain_ssh_agents(home: Path) -> None:
    for pidfile in (home / ".keychain").glob("*-sh"):
        match = re.search(r"SSH_AGENT_PID=([0-9]+)", pidfile.read_text(encoding="utf-8", errors="ignore"))
        if match:
            try:
                os.kill(int(match.group(1)), signal.SIGTERM)
            except OSError:
                pass


@pytest.fixture
def gpg_home(tmp_path: Path):
    home = tmp_path / "home"
    gnupg = home / ".gnupg"
    home.mkdir()
    gnupg.mkdir(mode=0o700)

    passfile = tmp_path / "passphrase"
    passfile.write_text("secret-pass", encoding="utf-8")
    pinentry_log = tmp_path / "pinentry.log"
    pinentry_log.write_text("", encoding="utf-8")
    pinentry = tmp_path / "pinentry-test"
    _write_fake_pinentry(pinentry, passfile, pinentry_log)
    (gnupg / "gpg-agent.conf").write_text(
        f"pinentry-program {pinentry}\n"
        "allow-loopback-pinentry\n"
        "default-cache-ttl 600\n"
        "max-cache-ttl 600\n",
        encoding="utf-8",
    )

    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "GNUPGHOME": str(gnupg),
            "GPG_TTY": "",
            "PYTHONPATH": str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", ""),
        }
    )
    env.pop("SSH_AUTH_SOCK", None)
    env.pop("SSH_AGENT_PID", None)

    yield env, home, passfile, pinentry_log

    _run(["gpgconf", "--kill", "gpg-agent"], env, timeout=10)
    _kill_keychain_ssh_agents(home)


def test_gpge_warms_encryption_subkey_for_decryption(gpg_home) -> None:
    env, home, passfile, _pinentry_log = gpg_home

    _assert_ok(
        _gpg(
            env,
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase-file",
            str(passfile),
            "--quick-generate-key",
            "Keychain Test <keychain@example.invalid>",
            "rsa2048",
            "sign",
            "0",
        )
    )
    fingerprint = _fingerprint(env)
    _assert_ok(
        _gpg(
            env,
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase-file",
            str(passfile),
            "--quick-add-key",
            fingerprint,
            "rsa2048",
            "encrypt",
            "0",
        )
    )

    plain = home / "plain.txt"
    cipher = home / "cipher.gpg"
    out = home / "out.txt"
    plain.write_text("plaintext\n", encoding="utf-8")
    _assert_ok(_gpg(env, "--batch", "--yes", "--trust-model", "always", "--encrypt", "-r", fingerprint, "-o", str(cipher), str(plain)))

    _run(["gpgconf", "--kill", "gpg-agent"], env, timeout=10)
    passfile.unlink()
    failed = _gpg(env, "--batch", "--yes", "--decrypt", "-o", str(out), str(cipher), timeout=15)
    assert failed.returncode != 0

    passfile.write_text("secret-pass", encoding="utf-8")
    _run(["gpgconf", "--kill", "gpg-agent"], env, timeout=10)
    keychain = _run(
        [sys.executable, "-m", "keychain", "--no-color", "--quiet", "add", f"gpge:{fingerprint}"],
        env,
        timeout=60,
    )
    _assert_ok(keychain)

    passfile.unlink()
    _assert_ok(_gpg(env, "--batch", "--yes", "--decrypt", "-o", str(out), str(cipher), timeout=15))
    assert out.read_text(encoding="utf-8") == "plaintext\n"
