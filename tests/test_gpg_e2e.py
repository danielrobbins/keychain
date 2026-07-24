from __future__ import annotations

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

from keychain.runtime import platform

pytestmark = pytest.mark.skipif(
    os.name == "nt" or not platform.detect().supported or not shutil.which("gpg") or not shutil.which("gpgconf"),
    reason="GPG e2e coverage requires a POSIX host with gpg and gpgconf",
)


ROOT = Path(__file__).resolve().parents[1]


def _run(
    cmd: list[str], env: dict[str, str], *, input_: str | None = None, timeout: int = 30
) -> subprocess.CompletedProcess:
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


def _write_gpg_wrapper(path: Path, passfile: Path) -> None:
    path.write_text(
        f"""#!/bin/sh
real_gpg={shlex.quote(shutil.which("gpg") or "gpg")}
passfile={shlex.quote(str(passfile))}
decrypt=0
for arg do
  [ "$arg" = "--decrypt" ] && decrypt=1
done
if [ "$decrypt" = 1 ] && [ -r "$passfile" ]; then
  exec "$real_gpg" --pinentry-mode loopback --passphrase-file "$passfile" "$@"
fi
exec "$real_gpg" "$@"
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
def gpg_home():
    # macOS has a short AF_UNIX socket path limit, and gpg-agent creates
    # sockets under GNUPGHOME. Pytest's default macOS tmp_path can be too long.
    root = Path(tempfile.mkdtemp(prefix="kc-gpg-", dir="/tmp" if sys.platform == "darwin" else None))
    home = root / "home"
    gnupg = home / ".gnupg"
    home.mkdir()
    gnupg.mkdir(mode=0o700)

    passfile = root / "passphrase"
    passfile.write_text("secret-pass", encoding="utf-8")
    wrapper_dir = root / "bin"
    wrapper_dir.mkdir()
    gpg_wrapper = wrapper_dir / "gpg"
    _write_gpg_wrapper(gpg_wrapper, passfile)
    (gnupg / "gpg-agent.conf").write_text(
        "allow-loopback-pinentry\n" "default-cache-ttl 600\n" "max-cache-ttl 600\n",
        encoding="utf-8",
    )

    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "GNUPGHOME": str(gnupg),
            "PATH": str(wrapper_dir) + os.pathsep + env.get("PATH", ""),
            "PYTHONPATH": str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", ""),
        }
    )
    env.pop("SSH_AUTH_SOCK", None)
    env.pop("SSH_AGENT_PID", None)

    yield env, home, passfile

    _run(["gpgconf", "--kill", "gpg-agent"], env, timeout=10)
    _kill_keychain_ssh_agents(home)
    shutil.rmtree(root, ignore_errors=True)


def test_gpge_warms_encryption_subkey_for_decryption(gpg_home) -> None:
    env, home, passfile = gpg_home

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
    _assert_ok(
        _gpg(
            env,
            "--batch",
            "--yes",
            "--trust-model",
            "always",
            "--encrypt",
            "-r",
            fingerprint,
            "-o",
            str(cipher),
            str(plain),
        )
    )

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


def test_gpga_rejects_signing_only_key_after_signing_is_warm(gpg_home) -> None:
    env, _home, passfile = gpg_home
    _assert_ok(
        _gpg(
            env,
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase-file",
            str(passfile),
            "--quick-generate-key",
            "Keychain Signing Test <keychain@example.invalid>",
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
            "--no-options",
            "--sign",
            "--local-user",
            fingerprint,
            "-o-",
        )
    )

    keychain = _run(
        [sys.executable, "-m", "keychain", "--no-color", "--quiet", "add", f"gpga:{fingerprint}"],
        env,
        timeout=60,
    )

    assert keychain.returncode != 0
    assert "Unable to add GPG encryption keys" in keychain.stderr


def test_failed_signing_warmup_has_clean_diagnostics(gpg_home) -> None:
    env, _home, passfile = gpg_home
    _assert_ok(
        _gpg(
            env,
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase-file",
            str(passfile),
            "--quick-generate-key",
            "Keychain Cancellation Test <keychain@example.invalid>",
            "rsa2048",
            "sign",
            "0",
        )
    )
    fingerprint = _fingerprint(env)
    _assert_ok(_gpg(env, "--batch", "--yes", "--delete-secret-keys", fingerprint))

    keychain = _run(
        [sys.executable, "-m", "keychain", "--no-color", "--quiet", "add", f"gpgs:{fingerprint}"],
        env,
        timeout=60,
    )

    assert keychain.returncode != 0
    assert "Unable to add GPG signing keys" in keychain.stderr
    assert "\ufffd" not in keychain.stderr
    assert "\x1b" not in keychain.stderr
    assert not any(ord(char) < 32 and char not in "\n\r\t" for char in keychain.stderr)
