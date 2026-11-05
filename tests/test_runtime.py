# SPDX-License-Identifier: GPL-3.0-only
"""Tests for :mod:`keychain.runtime` platform detection."""

import io
import os
import re
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from keychain.runtime import platform
from keychain.util import KeychainError


@pytest.fixture(autouse=True)
def _reset_runtime():
    platform.reset()
    yield
    platform.reset()


@pytest.mark.parametrize("name", ["linux", "linux2", "darwin", "freebsd14", "openbsd7", "netbsd", "sunos5", "aix"])
def test_posix_platforms_supported(name):
    p = platform.detect(platform_override=name, has_ps=True)
    assert p.supported is True
    assert p.reason == ""


@pytest.mark.parametrize("name", ["cygwin", "msys", "msys2"])
def test_cygwin_msys_supported(name):
    p = platform.detect(platform_override=name, has_ps=True)
    assert p.supported is True


def test_native_windows_unsupported():
    p = platform.detect(platform_override="win32")
    assert p.supported is False
    assert p.name == "windows"
    assert "WSL" in p.reason or "Cygwin" in p.reason


def test_known_posix_ps_missing():
    # A known POSIX platform without ps in PATH is unsupported with a clear message.
    p = platform.detect(platform_override="linux", has_ps=False)
    assert p.supported is False
    assert "ps" in p.reason.lower()


def test_unknown_platform_with_ps():
    # An unrecognised platform string is accepted when ps is present.
    p = platform.detect(platform_override="plan9", has_ps=True)
    assert p.supported is True


def test_unknown_platform_without_ps():
    # An unrecognised platform without ps gets an "unrecognized" refusal.
    p = platform.detect(platform_override="plan9", has_ps=False)
    assert p.supported is False
    assert "unrecognized" in p.reason.lower()


def test_detection_is_cached():
    first = platform.detect(platform_override="linux", has_ps=True)
    second = platform.detect(platform_override="win32")  # ignored: cached
    assert first is second


def test_unsupported_process_list_raises():
    p = platform.detect(platform_override="win32")
    with pytest.raises(RuntimeError):
        p.process_list(re.compile("anything"))


def test_supported_process_list_returns_list():
    # Exercise the host's real discovery mechanism, not just a parser fixture.
    p = platform.detect()
    if not p.supported:
        pytest.skip("host platform unsupported")
    result = p.process_list(re.compile("definitely-not-a-real-command"))
    assert isinstance(result, list)


@pytest.mark.parametrize("state", ["R", "S", "D", "T", "t", "I", "Z", "X", "x"])
@pytest.mark.parametrize("comm", ["ssh-agent", "ssh ) agent ("])
def test_proc_discovery_checks_process_state(monkeypatch, state, comm):
    reads = []

    def read(path, **_kwargs):
        reads.append(path)
        return io.StringIO(
            {
                "/proc/123/comm": f"{comm}\n",
                "/proc/123/stat": f"123 ({comm}) {state} 1 123 123 0\n",
            }[path]
        )

    monkeypatch.setattr(platform.os.path, "isdir", lambda _path: True)
    monkeypatch.setattr(platform.os, "listdir", lambda _path: ["self", "123"])
    monkeypatch.setattr(platform.os, "stat", lambda _path: SimpleNamespace(st_uid=1000))
    monkeypatch.setattr(platform, "open", read, raising=False)
    monkeypatch.setattr(platform.subprocess, "Popen", lambda *_a, **_k: pytest.fail("must not run ps"))

    p = platform._PosixPlatform("linux")
    assert p.process_list(re.compile(re.escape(comm) + "$"), uid=1000) == ([] if state in ("Z", "X", "x") else [123])
    assert reads == ["/proc/123/comm", "/proc/123/stat"]
    reads.clear()
    assert p.process_list(re.compile("unrelated-command"), uid=1000) == []
    assert reads == ["/proc/123/comm"]
    reads.clear()
    assert p.process_list(re.compile(re.escape(comm) + "$"), uid=2000) == []
    assert reads == []


@pytest.mark.parametrize("error", [FileNotFoundError, PermissionError])
def test_proc_discovery_skips_unreadable_state(monkeypatch, error):
    def read(path, **_kwargs):
        if path.endswith("/comm"):
            return io.StringIO("ssh-agent\n")
        raise error(path)

    monkeypatch.setattr(platform.os.path, "isdir", lambda _path: True)
    monkeypatch.setattr(platform.os, "listdir", lambda _path: ["123"])
    monkeypatch.setattr(platform, "open", read, raising=False)
    assert platform._PosixPlatform("linux").process_list(re.compile("ssh-agent")) == []


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="requires Linux /proc and prctl")
def test_proc_discovery_excludes_real_zombie():
    # The child exits without being reaped, keeping its /proc entry available.
    code = """
import ctypes
import os
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(15, ctypes.c_char_p(b"ssh-agent"), 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "PR_SET_NAME")
os._exit(0)
"""
    with subprocess.Popen([sys.executable, "-c", code]) as child:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with open(f"/proc/{child.pid}/stat") as handle:
                if handle.read().rpartition(")")[2].split()[0] == "Z":
                    break
            time.sleep(0.01)
        else:
            child.kill()
            pytest.fail("child did not exit within 10 seconds")
        with open(f"/proc/{child.pid}/comm") as handle:
            assert handle.read().strip() == "ssh-agent"
        assert child.pid not in platform._PosixPlatform("linux").process_list(
            re.compile(r"^ssh-agent$"), uid=os.getuid()
        )


@pytest.mark.parametrize("uid, expected", [(1000, [123]), (2000, [456]), (None, [123, 456])])
def test_process_list_with_illumos_ps(monkeypatch, uid, expected):
    """illumos consumes the remainder of each -o argument as header text."""
    rows = [
        {"pid": "123", "uid": "1000", "comm": "/usr/bin/ssh-agent"},
        {"pid": "456", "uid": "2000", "comm": "ssh-agent"},
        {"pid": "789", "uid": "1000", "comm": "ssh-agent-helper"},
        {"pid": "987", "uid": "1000", "comm": "not-ssh-agent"},
    ]

    def fake_popen(cmd, **kwargs):
        assert cmd[:2] == ["ps", "-A"]
        fields = []
        headers = []
        for index in range(2, len(cmd), 2):
            assert cmd[index] == "-o"
            names, separator, header = cmd[index + 1].partition("=")
            fields.extend(names.split(","))
            headers.append(header if separator else names)
        lines = [" ".join(headers)] if any(headers) else []
        lines.extend(" ".join(row[field] for field in fields) for row in rows)
        stdout = ("\n".join(lines) + "\n").encode()
        return SimpleNamespace(returncode=0, communicate=lambda: (stdout, b""))

    monkeypatch.setattr(platform.subprocess, "Popen", fake_popen)
    p = platform.detect(platform_override="sunos5", has_ps=True)

    assert p.process_list(re.compile(r"(?:^|/)ssh-agent$"), uid=uid) == expected


@pytest.mark.parametrize("name", ["cygwin", "msys", "msys2"])
@pytest.mark.parametrize("uid, expected", [(1000, [123, 789]), (2000, [456]), (None, [123, 456, 789])])
@pytest.mark.parametrize("columns", [None, "20", "80"])
def test_process_list_with_cygwin_ps(monkeypatch, name, uid, expected, columns):
    if columns is None:
        monkeypatch.delenv("COLUMNS", raising=False)
    else:
        monkeypatch.setenv("COLUMNS", columns)
    parent_env = dict(os.environ)
    stdout = (
        b"      PID    PPID    PGID     WINPID   TTY         UID    STIME COMMAND\n"
        b"      123       1     123      52000     ?       1000 15:39:13 /usr/bin/ssh-agent\n"
        b"S     456       1     456      53000     ?       2000 15:39:13 /usr/bin/ssh-agent\n"
        b"I     789       1     789      54000     ?       1000 15:39:13 /path with spaces/ssh-agent\n"
        b"      987       1     987      55000     ?       1000 15:39:13 /usr/bin/ssh-agent-helper\n"
        b"      988       1     988      56000     ?       1000 15:39:13 /usr/bin/ssh-agent <defunct>\n"
        b"invalid row\n"
    )

    def fake_popen(cmd, **kwargs):
        assert cmd == ["ps", "-e", "-l"]
        assert kwargs["env"] == {key: value for key, value in parent_env.items() if key != "COLUMNS"}
        return SimpleNamespace(returncode=0, communicate=lambda: (stdout, b""))

    monkeypatch.setattr(platform.subprocess, "Popen", fake_popen)
    p = platform.detect(platform_override=name, has_ps=True)

    assert p.process_list(re.compile(r"(?:^|/)ssh-agent$"), uid=uid) == expected
    assert dict(os.environ) == parent_env


@pytest.mark.parametrize("name", ["cygwin", "msys", "msys2"])
@pytest.mark.parametrize("stime", ["15:39:13", "  Nov  1", "  Nov 12"])
def test_process_list_with_cygwin_stime(monkeypatch, name, stime):
    stdout = (
        "      PID    PPID    PGID     WINPID   TTY         UID    STIME COMMAND\n"
        f"      123       1     123      52000     ?       1000 {stime} /path with spaces/ssh-agent\n"
    ).encode()

    def fake_popen(cmd, **kwargs):
        assert cmd == ["ps", "-e", "-l"]
        return SimpleNamespace(returncode=0, communicate=lambda: (stdout, b""))

    monkeypatch.setattr(platform.subprocess, "Popen", fake_popen)
    p = platform.detect(platform_override=name, has_ps=True)

    assert p.process_list(re.compile(r"^/path with spaces/ssh-agent$"), uid=1000) == [123]


@pytest.mark.parametrize("name", ["sunos5", "darwin", "cygwin", "msys2"])
@pytest.mark.parametrize("status", [1, 2, -15])
@pytest.mark.parametrize("stderr", [b"ps: unsupported option\n", b"", b"invalid byte: \xff"])
def test_failed_ps_is_not_an_empty_process_list(monkeypatch, name, status, stderr):
    def fake_popen(_cmd, **kwargs):
        assert kwargs["stderr"] == platform.subprocess.PIPE
        return SimpleNamespace(returncode=status, communicate=lambda: (b"123 1000 ssh-agent\n", stderr))

    monkeypatch.setattr(platform.subprocess, "Popen", fake_popen)
    with pytest.raises(KeychainError, match=f"Process discovery failed: ps exited with status {status}") as exc:
        platform._PosixPlatform(name).process_list(re.compile("ssh-agent"))
    assert (stderr.decode(errors="replace").strip() or "no error output") in str(exc.value)


@pytest.mark.parametrize("error", [FileNotFoundError("ps missing"), PermissionError("ps not executable")])
def test_ps_launch_failure_is_fatal(monkeypatch, error):
    def fail(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(platform.subprocess, "Popen", fail)
    with pytest.raises(KeychainError, match="Process discovery failed: cannot run ps"):
        platform._PosixPlatform("cygwin").process_list(re.compile("ssh-agent"))


@pytest.mark.parametrize("stdout", [b"", b"123 1000 other-command\n"])
def test_successful_ps_without_matching_agents_is_valid(monkeypatch, stdout):
    monkeypatch.setattr(
        platform.subprocess, "Popen",
        lambda *_a, **_k: SimpleNamespace(returncode=0, communicate=lambda: (stdout, b"")),
    )
    assert platform._PosixPlatform("sunos5").process_list(re.compile("ssh-agent")) == []
