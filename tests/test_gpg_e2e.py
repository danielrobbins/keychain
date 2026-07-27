from __future__ import annotations

import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
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


def _gpg_agent_reachable(env: dict[str, str]) -> bool:
    probe = _run(
        ["gpg-connect-agent", "--no-autostart"],
        env,
        input_="GETINFO socket_name\n",
        timeout=10,
    )
    return any(line.startswith("D ") for line in probe.stdout.splitlines())


def _kill_gpg_agent(env: dict[str, str]) -> None:
    _assert_ok(_run(["gpgconf", "--kill", "gpg-agent"], env, timeout=10))
    for _ in range(100):
        if not _gpg_agent_reachable(env):
            return
        time.sleep(0.05)
    raise AssertionError("gpg-agent remained reachable after gpgconf --kill")


def _sign_without_prompt(
    env: dict[str, str], fingerprint: str, source: Path, output: Path
) -> subprocess.CompletedProcess:
    return _gpg(
        env,
        "--batch",
        "--yes",
        "--pinentry-mode",
        "error",
        "--no-options",
        "--sign",
        "--local-user",
        fingerprint,
        "--output",
        str(output),
        str(source),
        timeout=15,
    )


def _write_gpg_wrapper(path: Path, passfile: Path) -> None:
    path.write_text(
        f"""#!/bin/sh
real_gpg={shlex.quote(shutil.which("gpg") or "gpg")}
passfile={shlex.quote(str(passfile))}
private_op=0
for arg do
  [ "$arg" = "--decrypt" ] && private_op=1
  [ "$arg" = "--sign" ] && private_op=1
done
if [ "$private_op" = 1 ] && [ -r "$passfile" ]; then
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
    # A non-default homedir gets its own socket instead of the user service's.
    gnupg = root / "gnupg"
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


def test_quick_skips_gpg_while_normal_resolution_uses_gnupg_autostart(gpg_home) -> None:
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
            "Keychain Quick Test <keychain@example.invalid>",
            "rsa2048",
            "sign",
            "0",
        )
    )
    fingerprint = _fingerprint(env)
    _kill_gpg_agent(env)

    keychain = _run(
        [sys.executable, "-m", "keychain", "--no-color", "--quiet", "add", "--quick", fingerprint],
        env,
        timeout=30,
    )
    _assert_ok(keychain)

    assert not _gpg_agent_reachable(env)

    noask = _run(
        [sys.executable, "-m", "keychain", "--no-color", "--quiet", "add", "--no-passphrase", fingerprint],
        env,
        timeout=30,
    )
    _assert_ok(noask)
    assert not _gpg_agent_reachable(env)

    normal = _run(
        [sys.executable, "-m", "keychain", "--no-color", "--quiet", "add", fingerprint],
        env,
        timeout=60,
    )
    _assert_ok(normal)

    assert _gpg_agent_reachable(env)


def test_gpg_wipe_is_a_noop_without_an_agent(gpg_home) -> None:
    env, _home, _passfile = gpg_home
    _kill_gpg_agent(env)

    keychain = _run(
        [sys.executable, "-m", "keychain", "--no-color", "wipe", "--gpg"],
        env,
        timeout=30,
    )

    _assert_ok(keychain)
    assert "No gpg-agent found running." in keychain.stderr


def test_gpg_wipe_confirms_a_live_agent(gpg_home) -> None:
    env, _home, _passfile = gpg_home
    _assert_ok(_run(["gpgconf", "--launch", "gpg-agent"], env, timeout=10))

    keychain = _run(
        [sys.executable, "-m", "keychain", "--no-color", "wipe", "--gpg"],
        env,
        timeout=30,
    )

    _assert_ok(keychain)
    assert "gpg-agent: Passphrase cache cleared." in keychain.stderr


def test_gpg_wipe_clears_a_warmed_passphrase(gpg_home) -> None:
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
            "Keychain Wipe Test <keychain@example.invalid>",
            "rsa2048",
            "sign",
            "0",
        )
    )
    fingerprint = _fingerprint(env)
    _kill_gpg_agent(env)

    keychain = _run(
        [sys.executable, "-m", "keychain", "--no-color", "--quiet", "add", f"gpgs:{fingerprint}"],
        env,
        timeout=60,
    )
    _assert_ok(keychain)

    passfile.unlink()
    source = home / "message.txt"
    source.write_text("signed by keychain\n", encoding="utf-8")
    _assert_ok(_sign_without_prompt(env, fingerprint, source, home / "before-wipe.gpg"))

    wipe = _run(
        [sys.executable, "-m", "keychain", "--no-color", "--quiet", "wipe", "--gpg"],
        env,
        timeout=30,
    )
    _assert_ok(wipe)

    after = _sign_without_prompt(env, fingerprint, source, home / "after-wipe.gpg")
    assert after.returncode != 0


def test_gpg_wipe_reports_connect_agent_failure(gpg_home) -> None:
    env, _home, _passfile = gpg_home
    path = Path(env["PATH"].split(os.pathsep, 1)[0]) / "gpg-connect-agent"
    path.write_text("#!/bin/sh\necho 'ERR simulated transport failure' >&2\nexit 42\n", encoding="utf-8")
    path.chmod(0o700)

    keychain = _run(
        [sys.executable, "-m", "keychain", "--no-color", "wipe", "--gpg"],
        env,
        timeout=30,
    )

    assert keychain.returncode != 0
    assert "Unable to clear GPG passphrase cache: ERR simulated transport failure" in keychain.stderr


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

    _kill_gpg_agent(env)
    passfile.unlink()
    failed = _gpg(env, "--batch", "--yes", "--decrypt", "-o", str(out), str(cipher), timeout=15)
    assert failed.returncode != 0

    passfile.write_text("secret-pass", encoding="utf-8")
    _kill_gpg_agent(env)
    keychain = _run(
        [sys.executable, "-m", "keychain", "--no-color", "--quiet", "add", f"gpge:{fingerprint}"],
        env,
        timeout=60,
    )
    _assert_ok(keychain)

    passfile.unlink()
    _assert_ok(_gpg(env, "--batch", "--yes", "--decrypt", "-o", str(out), str(cipher), timeout=15))
    assert out.read_text(encoding="utf-8") == "plaintext\n"


def test_gpgs_warms_signing_key(gpg_home) -> None:
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
            "Keychain Signing Test <keychain@example.invalid>",
            "rsa2048",
            "sign",
            "0",
        )
    )
    fingerprint = _fingerprint(env)
    _kill_gpg_agent(env)

    keychain = _run(
        [sys.executable, "-m", "keychain", "--no-color", "--quiet", "add", f"gpgs:{fingerprint}"],
        env,
        timeout=60,
    )
    _assert_ok(keychain)

    passfile.unlink()
    source = home / "message.txt"
    source.write_text("signed by keychain\n", encoding="utf-8")
    signed = home / "signed.gpg"
    _assert_ok(_sign_without_prompt(env, fingerprint, source, signed))
    assert signed.is_file()


def test_gpga_warms_signing_and_decryption(gpg_home) -> None:
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
            "Keychain All Capabilities Test <keychain@example.invalid>",
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
    source = home / "message.txt"
    cipher = home / "message.gpg"
    decrypted = home / "decrypted.txt"
    source.write_text("all capabilities\n", encoding="utf-8")
    _assert_ok(
        _gpg(
            env,
            "--batch",
            "--yes",
            "--trust-model",
            "always",
            "--encrypt",
            "--recipient",
            fingerprint,
            "--output",
            str(cipher),
            str(source),
        )
    )
    _kill_gpg_agent(env)

    keychain = _run(
        [sys.executable, "-m", "keychain", "--no-color", "--quiet", "add", f"gpga:{fingerprint}"],
        env,
        timeout=60,
    )
    _assert_ok(keychain)

    passfile.unlink()
    _assert_ok(_sign_without_prompt(env, fingerprint, source, home / "signed.gpg"))
    _assert_ok(
        _gpg(
            env,
            "--batch",
            "--yes",
            "--pinentry-mode",
            "error",
            "--decrypt",
            "--output",
            str(decrypted),
            str(cipher),
            timeout=15,
        )
    )
    assert decrypted.read_text(encoding="utf-8") == "all capabilities\n"


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
    assert f"Unable to prepare GPG decryption test for {fingerprint}" in keychain.stderr


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
    assert f"Unable to warm GPG signing key {fingerprint}" in keychain.stderr
    assert "\ufffd" not in keychain.stderr
    assert "\x1b" not in keychain.stderr
    assert not any(ord(char) < 32 and char not in "\n\r\t" for char in keychain.stderr)
