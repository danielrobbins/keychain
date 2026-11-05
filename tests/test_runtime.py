# SPDX-License-Identifier: GPL-3.0-only
"""Tests for :mod:`keychain.runtime` platform detection."""

import io
import os
import re
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from keychain.runtime import platform
from keychain.util import KeychainError
from tests.support import set_file_stat


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


def test_known_posix_ps_missing(monkeypatch):
    # A known POSIX platform without ps in PATH is unsupported with a clear message.
    monkeypatch.setattr(platform.os.path, "isdir", lambda _path: False)
    p = platform.detect(platform_override="linux", has_ps=False)
    assert p.supported is False
    assert "ps" in p.reason.lower()


@pytest.mark.parametrize("name", ["linux", "linux2", "android"])
def test_linux_proc_does_not_require_ps(monkeypatch, name):
    monkeypatch.setattr(platform.os.path, "isdir", lambda path: path == "/proc/self")
    monkeypatch.setattr(platform.shutil, "which", lambda *_a: pytest.fail("must not require ps"))
    assert platform.detect(platform_override=name).supported


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


def test_current_process_is_alive():
    assert platform.detect().pid_alive(os.getpid())


@pytest.mark.parametrize("name", ["linux", "darwin", "freebsd14", "sunos5", "cygwin", "win32"])
@pytest.mark.parametrize("pid", [0, -1])
def test_invalid_pids_never_probe_processes(name, pid, monkeypatch):
    monkeypatch.setattr(platform.os, "kill", lambda *_a: pytest.fail("must not signal a process group"))
    assert not platform._classify(name, has_ps=True).pid_alive(pid)


@pytest.mark.parametrize("name", ["linux", "android", "darwin", "freebsd14", "sunos5", "cygwin", "msys2"])
def test_posix_liveness_uses_signal_zero(name, monkeypatch):
    kill = Mock()
    monkeypatch.setattr(platform.os, "kill", kill)
    assert platform._classify(name, has_ps=True).pid_alive(123)
    kill.assert_called_once_with(123, 0)


@pytest.mark.parametrize("error", [ProcessLookupError(), PermissionError(), OverflowError()])
def test_liveness_failure_is_not_proof_of_a_live_process(error, monkeypatch):
    monkeypatch.setattr(platform.os, "kill", Mock(side_effect=error))
    assert not platform.Platform().pid_alive(123)


@pytest.mark.parametrize("opened,queried,exit_code,alive", [
    (True, True, 259, True), (True, True, 0, False),
    (True, False, 259, False), (False, False, 259, False),
])
def test_windows_liveness_closes_handles(opened, queried, exit_code, alive, monkeypatch):
    import ctypes

    def query(handle, code):
        assert handle == 1234
        code._obj.value = exit_code
        return queried

    kernel = SimpleNamespace(
        OpenProcess=Mock(return_value=1234 if opened else 0),
        GetExitCodeProcess=Mock(side_effect=query), CloseHandle=Mock(),
    )
    monkeypatch.setattr(ctypes, "windll", SimpleNamespace(kernel32=kernel), raising=False)
    p = platform._classify("win32")
    assert not p.supported
    assert p.pid_alive(123) is alive
    kernel.OpenProcess.assert_called_once_with(0x1000, False, 123)
    if opened:
        kernel.CloseHandle.assert_called_once_with(1234)
    else:
        kernel.GetExitCodeProcess.assert_not_called()
        kernel.CloseHandle.assert_not_called()


@pytest.mark.parametrize("name", ["linux", "freebsd14", "openbsd8", "sunos5", "cygwin", "msys2"])
def test_confirmation_environment_is_unchanged_outside_macos(name, tmp_path):
    p = platform._classify(name, has_ps=True)
    env = {"SSH_ASKPASS": "/custom/askpass", "SSH_ASKPASS_REQUIRE": "prefer"}
    p.configure_ssh_confirmation(env, tmp_path)
    assert not p.confirm_requires_own_agent
    assert env == {"SSH_ASKPASS": "/custom/askpass", "SSH_ASKPASS_REQUIRE": "prefer"}
    assert not list(tmp_path.iterdir())


def test_macos_confirmation_preserves_explicit_helper(tmp_path):
    p = platform._classify("darwin", has_ps=True)
    p.name = "freebsd14"  # Behavior belongs to the class, not the display label.
    env = {"SSH_ASKPASS": "/custom/askpass"}
    p.configure_ssh_confirmation(env, tmp_path)
    assert p.confirm_requires_own_agent
    assert env == {"SSH_ASKPASS": "/custom/askpass", "SSH_ASKPASS_REQUIRE": "force"}
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("condition", ["missing", "stale", "wrong-mode", "current"])
def test_macos_confirmation_helper_install_policy(condition, tmp_path, monkeypatch):
    p = platform._classify("darwin", has_ps=True)
    helper = tmp_path / "ssh-askpass-macos"
    if condition != "missing":
        helper.write_text("stale helper" if condition == "stale" else p._ASKPASS, encoding="utf-8")
        set_file_stat(monkeypatch, helper, mode=0o100755 if condition == "wrong-mode" else 0o100700)
    writer = Mock()
    monkeypatch.setattr(platform, "write_atomic", writer)
    env = {}
    p.configure_ssh_confirmation(env, tmp_path)
    if condition == "current":
        writer.assert_not_called()
    else:
        writer.assert_called_once_with(helper, p._ASKPASS, 0o700)
    assert env == {"SSH_ASKPASS": str(helper), "SSH_ASKPASS_REQUIRE": "force"}


@pytest.mark.skipif(
    os.name == "nt" or sys.platform.startswith(("cygwin", "msys")),
    reason="native POSIX permissions; MSYS2's filesystem may synthesize modes",
)
def test_macos_confirmation_repairs_helper_and_avoids_rewrites(tmp_path, monkeypatch):
    p = platform._classify("darwin", has_ps=True)
    helper = tmp_path / "ssh-askpass-macos"
    helper.write_text("stale helper")
    helper.chmod(0o755)
    env = {}
    p.configure_ssh_confirmation(env, tmp_path)
    assert helper.read_text() == p._ASKPASS
    assert helper.stat().st_mode & 0o777 == 0o700
    assert env == {"SSH_ASKPASS": str(helper), "SSH_ASKPASS_REQUIRE": "force"}
    monkeypatch.setattr(platform, "write_atomic", lambda *_a: pytest.fail("helper is already current"))
    p.configure_ssh_confirmation({}, tmp_path)


@pytest.mark.parametrize("name, implementation", [
    ("linux", platform._LinuxPlatform), ("android", platform._LinuxPlatform),
    ("darwin", platform._DarwinPlatform), ("freebsd14", platform._BSDPlatform),
    ("openbsd7", platform._BSDPlatform), ("netbsd10", platform._BSDPlatform),
    ("dragonfly6", platform._BSDPlatform), ("sunos5", platform._SolarisPlatform),
    ("cygwin", platform._CygwinPlatform), ("msys2", platform._CygwinPlatform),
    ("aix", platform._PsPlatform), ("unknown-posix", platform._PsPlatform),
])
def test_factory_selects_platform_implementation(name, implementation):
    p = platform._classify(name, has_ps=True)
    assert type(p) is implementation
    assert p.name == name


@pytest.mark.parametrize("name", ["linux", "android"])
def test_linux_ps_fallback_is_selected_once(monkeypatch, name):
    monkeypatch.setattr(platform.os.path, "isdir", lambda _path: False)
    p = platform._classify(name, has_ps=True)
    assert p.requires_ps
    monkeypatch.setattr(platform.os.path, "isdir", lambda _path: pytest.fail("must not redetect /proc"))

    def ps(command, **_kwargs):
        assert command == ["ps", "-A", "-o", "pid=", "-o", "uid=", "-o", "comm="]
        return SimpleNamespace(returncode=0, communicate=lambda: (b"123 1000 ssh-agent\n", b""))

    monkeypatch.setattr(platform.subprocess, "Popen", ps)
    assert p.process_list(re.compile("^ssh-agent$"), uid=1000) == [123]
    assert not p.process_details_unavailable(123)


@pytest.mark.parametrize("displayed, expected", [
    ("-2", 4294967294), ("-1", 4294967295), ("-2147483648", 2147483648),
    ("501", 501), ("4294967294", 4294967294),
])
def test_macos_normalizes_signed_uids(monkeypatch, displayed, expected):
    output = f"123 502 ssh-agent\n456 {displayed} ssh-agent\n789 {displayed} unrelated\n".encode()
    monkeypatch.setattr(platform.subprocess, "Popen", lambda *_a, **_kw: SimpleNamespace(
        returncode=0, communicate=lambda: (output, b""),
    ))
    p = platform._classify("darwin", has_ps=True)
    p.name = "freebsd14"  # The selected implementation, not the label, owns normalization.
    pattern = re.compile("^ssh-agent$")
    assert p.process_list(pattern, expected) == [456]
    assert p.process_list(pattern, 502) == [123]
    assert p.process_list(pattern) == [123, 456]


@pytest.mark.parametrize("record", [
    "-2 501 ssh-agent", "+123 501 ssh-agent", "123 -2147483649 ssh-agent",
    "123 --2 ssh-agent", "123 -2x ssh-agent", "123 +501 ssh-agent", "123 -2",
])
def test_macos_still_rejects_invalid_records(monkeypatch, record):
    monkeypatch.setattr(platform.subprocess, "Popen", lambda *_a, **_kw: SimpleNamespace(
        returncode=0, communicate=lambda: (f"456 501 ssh-agent\n{record}\n".encode(), b""),
    ))
    with pytest.raises(KeychainError, match="invalid record at line 2"):
        platform._classify("darwin", has_ps=True).process_list(re.compile("ssh-agent"), 501)


@pytest.mark.parametrize("name", ["freebsd14", "openbsd8", "netbsd10", "dragonfly6", "sunos5", "aix"])
def test_signed_uid_normalization_is_macos_only(monkeypatch, name):
    monkeypatch.setattr(platform.subprocess, "Popen", lambda *_a, **_kw: SimpleNamespace(
        returncode=0, communicate=lambda: (b"123 -2 ssh-agent\n", b""),
    ))
    with pytest.raises(KeychainError, match="invalid record"):
        platform._classify(name, has_ps=True).process_list(re.compile("ssh-agent"))


def test_ps_dialects_do_not_change_each_others_commands(monkeypatch):
    seen = []

    def ps(command, **_kwargs):
        seen.append(command)
        return SimpleNamespace(returncode=0, communicate=lambda: (b"123 1000 ssh-agent\n", b""))

    monkeypatch.setattr(platform.subprocess, "Popen", ps)
    for name in ("sunos5", "freebsd14", "aix", "sunos5"):
        p = platform._classify(name, has_ps=True)
        p.name = "msys2"  # Labels do not reroute a previously selected implementation.
        assert p.process_list(re.compile("^ssh-agent$")) == [123]
    assert seen == [
        list(platform._SolarisPlatform.ps_command), list(platform._BSDPlatform.ps_command),
        list(platform._PsPlatform.ps_command), list(platform._SolarisPlatform.ps_command),
    ]


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
@pytest.mark.parametrize("name", ["linux", "android"])
def test_proc_discovery_checks_process_state(monkeypatch, state, comm, name):
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

    p = platform._classify(name, has_ps=True)
    assert p.process_list(re.compile(re.escape(comm) + "$"), uid=1000) == ([] if state in ("Z", "X", "x") else [123])
    assert reads == ["/proc/123/comm", "/proc/123/stat"]
    reads.clear()
    assert p.process_list(re.compile("unrelated-command"), uid=1000) == []
    assert reads == ["/proc/123/comm"]
    reads.clear()
    assert p.process_list(re.compile(re.escape(comm) + "$"), uid=2000) == []
    assert reads == []


def test_proc_discovery_skips_task_with_empty_stat(monkeypatch):
    # A task that exits between the comm and stat reads can yield an empty stat.
    files = {"/proc/123/comm": "ssh-agent\n", "/proc/123/stat": "", "/proc/456/comm": "ssh-agent\n",
             "/proc/456/stat": "456 (ssh-agent) S 1 456 456 0\n"}
    monkeypatch.setattr(platform.os.path, "isdir", lambda _path: True)
    monkeypatch.setattr(platform.os, "listdir", lambda _path: ["123", "456"])
    monkeypatch.setattr(platform.os, "stat", lambda _path: SimpleNamespace(st_uid=1000))
    monkeypatch.setattr(platform, "open", lambda path, **_kw: io.StringIO(files[path]), raising=False)

    assert platform._LinuxPlatform("linux").process_list(re.compile("ssh-agent$"), uid=1000) == [456]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="requires Linux /proc")
@pytest.mark.parametrize("name", ["linux", "android"])
@pytest.mark.parametrize("ps_available", [False, True])
def test_real_agent_discovery_with_minimal_path(tmp_path, monkeypatch, name, ps_available):
    agent = shutil.which("ssh-agent")
    if not agent:
        pytest.skip("requires ssh-agent")
    if ps_available:
        busybox = shutil.which("busybox")
        if not busybox:
            pytest.skip("requires BusyBox")
        (tmp_path / "ps").symlink_to(busybox)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path))
    with subprocess.Popen([agent, "-D", "-a", "agent.sock"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as child:
        try:
            deadline = time.monotonic() + 5
            while not (tmp_path / "agent.sock").exists():
                assert child.poll() is None, child.stderr.read().decode()
                assert time.monotonic() < deadline, "agent did not create its socket"
                time.sleep(0.01)
            p = platform.detect(platform_override=name)
            assert p.supported
            assert child.pid in p.process_list(re.compile(r"^ssh-agent$"), uid=os.getuid())
        finally:
            child.terminate()
            child.wait(timeout=5)


@pytest.mark.parametrize("error", [FileNotFoundError, PermissionError])
def test_proc_discovery_skips_unreadable_state(monkeypatch, error):
    def read(path, **_kwargs):
        if path.endswith("/comm"):
            return io.StringIO("ssh-agent\n")
        raise error(path)

    monkeypatch.setattr(platform.os.path, "isdir", lambda _path: True)
    monkeypatch.setattr(platform.os, "listdir", lambda _path: ["123"])
    monkeypatch.setattr(platform, "open", read, raising=False)
    assert platform._LinuxPlatform("linux").process_list(re.compile("ssh-agent")) == []


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
        assert child.pid not in platform._LinuxPlatform("linux").process_list(
            re.compile(r"^ssh-agent$"), uid=os.getuid()
        )


@pytest.mark.parametrize("uid, expected", [(1000, [123]), (2000, [456]), (None, [123, 456])])
def test_process_list_with_illumos_ps(monkeypatch, uid, expected):
    """illumos consumes the remainder of each -o argument as header text."""
    rows = [
        {"pid": "123", "uid": "1000", "comm": "/path with spaces/" * 10 + "ssh-agent"},
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
        assert fields == ["pid", "uid", "fname"]
        assert headers == ["", "", "KEYCHAIN_COMMAND"]
        # Model illumos's pr_fname and its default eight-character display width.
        width = len(headers[-1]) or 8
        for row in rows:
            row["fname"] = row["comm"].rsplit("/", 1)[-1][:15][:width]
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
    )

    def fake_popen(cmd, **kwargs):
        assert cmd == ["ps", "-e", "-l"]
        assert kwargs["env"] == {**{key: value for key, value in parent_env.items() if key != "COLUMNS"}, "LC_ALL": "C"}
        return SimpleNamespace(returncode=0, communicate=lambda: (stdout, b""))

    monkeypatch.setattr(platform.subprocess, "Popen", fake_popen)
    p = platform.detect(platform_override=name, has_ps=True)

    assert p.process_list(re.compile(r"(?:^|/)ssh-agent$"), uid=uid) == expected
    assert dict(os.environ) == parent_env


@pytest.mark.parametrize("name", ["cygwin", "msys", "msys2"])
@pytest.mark.parametrize("stime", ["15:39:13", "  Nov  1", "  Nov 12"])
@pytest.mark.parametrize("status", [" ", "S", "I", "O"])
def test_process_list_with_cygwin_stime(monkeypatch, name, stime, status):
    stdout = (
        "      PID    PPID    PGID     WINPID   TTY         UID    STIME COMMAND\n"
        f"{status}     123       1     123      52000     ?       1000 {stime} /path with spaces/ssh-agent\n"
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
        platform._classify(name, has_ps=True).process_list(re.compile("ssh-agent"))
    assert (stderr.decode(errors="replace").strip() or "no error output") in str(exc.value)


@pytest.mark.parametrize("error", [FileNotFoundError("ps missing"), PermissionError("ps not executable")])
def test_ps_launch_failure_is_fatal(monkeypatch, error):
    def fail(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(platform.subprocess, "Popen", fail)
    with pytest.raises(KeychainError, match="Process discovery failed: cannot run ps"):
        platform._classify("cygwin", has_ps=True).process_list(re.compile("ssh-agent"))


@pytest.mark.parametrize("stdout", [b"123 1000 other-command\n", b"0 0 -\n", b"\n123 1000 other-command\n\n"])
def test_successful_ps_without_matching_agents_is_valid(monkeypatch, stdout):
    monkeypatch.setattr(
        platform.subprocess, "Popen",
        lambda *_a, **_k: SimpleNamespace(returncode=0, communicate=lambda: (stdout, b"")),
    )
    assert platform._classify("sunos5", has_ps=True).process_list(re.compile("ssh-agent")) == []


@pytest.mark.parametrize("name", ["sunos5", "darwin", "freebsd14", "openbsd7", "netbsd", "aix", "cygwin", "msys2"])
@pytest.mark.parametrize("stdout", [b"", b"\n", b"unsupported output\n", b"123 1000\n", b"123 uid ssh-agent\n"])
def test_successful_but_unusable_ps_output_is_fatal(monkeypatch, name, stdout):
    monkeypatch.setattr(
        platform.subprocess, "Popen",
        lambda *_a, **_k: SimpleNamespace(returncode=0, communicate=lambda: (stdout, b"")),
    )
    with pytest.raises(KeychainError, match="Process discovery failed: ps"):
        platform._classify(name, has_ps=True).process_list(re.compile("ssh-agent"))


@pytest.mark.parametrize("bad_row", ["garbage", "123 1000", "-1 1000 ssh-agent", "123 -1 ssh-agent", "+123 1000 ssh-agent"])
def test_ps_rejects_partial_results_before_uid_or_name_filtering(monkeypatch, bad_row):
    stdout = f"123 1000 ssh-agent\n{bad_row}\n456 2000 other-command\n".encode()
    monkeypatch.setattr(
        platform.subprocess, "Popen",
        lambda *_a, **_k: SimpleNamespace(returncode=0, communicate=lambda: (stdout, b"")),
    )
    with pytest.raises(KeychainError, match="Process discovery failed: ps.*line 2"):
        platform._classify("sunos5", has_ps=True).process_list(re.compile("ssh-agent"), uid=1000)


@pytest.mark.parametrize("name", ["cygwin", "msys2"])
@pytest.mark.parametrize("suffix", [b"", b"invalid row\n"])
def test_cygwin_header_is_not_a_process_record(monkeypatch, name, suffix):
    stdout = b"      PID    PPID    PGID     WINPID   TTY         UID    STIME COMMAND\n" + suffix
    monkeypatch.setattr(
        platform.subprocess, "Popen",
        lambda *_a, **_k: SimpleNamespace(returncode=0, communicate=lambda: (stdout, b"")),
    )
    with pytest.raises(KeychainError, match="Process discovery failed: ps"):
        platform._classify(name, has_ps=True).process_list(re.compile("ssh-agent"))


@pytest.mark.parametrize("prefix", ["1", "? ", "Z "])
def test_cygwin_ps_rejects_invalid_status_instead_of_truncating_pid(monkeypatch, prefix):
    stdout = f"{prefix}123 1 123 52000 ? 1000 15:39:13 /usr/bin/ssh-agent\n".encode()
    monkeypatch.setattr(
        platform.subprocess, "Popen",
        lambda *_a, **_k: SimpleNamespace(returncode=0, communicate=lambda: (stdout, b"")),
    )
    with pytest.raises(KeychainError, match="Process discovery failed: ps.*line 1"):
        platform._classify("cygwin", has_ps=True).process_list(re.compile("ssh-agent"))


@pytest.mark.parametrize("name", ["darwin", "freebsd14", "openbsd7", "netbsd", "dragonfly6"])
def test_bsd_ps_requests_unlimited_width(monkeypatch, name):
    monkeypatch.setenv("COLUMNS", "8")
    monkeypatch.setenv("LC_ALL", "fr_FR.UTF-8")
    parent_env = dict(os.environ)
    command_name = "/a very long installation directory/" * 8 + "ssh-agent"

    def fake_popen(cmd, **kwargs):
        assert cmd == ["ps", "-ww", "-A", "-o", "pid=", "-o", "uid=", "-o", "comm="]
        assert "COLUMNS" not in kwargs["env"]
        assert kwargs["env"]["LC_ALL"] == "C"
        stdout = f"123 1000 {command_name}\n456 1000 {command_name}-helper\n".encode()
        return SimpleNamespace(returncode=0, communicate=lambda: (stdout, b""))

    monkeypatch.setattr(platform.subprocess, "Popen", fake_popen)
    assert platform._classify(name, has_ps=True).process_list(re.compile(r"(?:^|/)ssh-agent$"), uid=1000) == [123]
    assert dict(os.environ) == parent_env


@pytest.mark.parametrize("command_name", ["ssh-agen", "ssh-agent-helper", "not-ssh-agent", "ssh-agent <defunct>"])
def test_ps_never_guesses_an_agent_from_a_partial_name(monkeypatch, command_name):
    stdout = f"123 1000 {command_name}\n".encode()
    monkeypatch.setattr(
        platform.subprocess, "Popen",
        lambda *_a, **_k: SimpleNamespace(returncode=0, communicate=lambda: (stdout, b"")),
    )
    assert platform._classify("darwin", has_ps=True).process_list(re.compile(r"(?:^|/)ssh-agent$"), uid=1000) == []


@pytest.mark.skipif(
    not sys.platform.startswith(("linux", "darwin", "freebsd", "openbsd", "netbsd", "dragonfly", "sunos")),
    reason="requires POSIX ps and symlinks",
)
def test_real_ps_discovers_agent_launched_from_long_path(tmp_path, monkeypatch):
    agent = shutil.which("ssh-agent")
    ps = shutil.which("ps")
    if not agent or not ps:
        pytest.skip("requires ssh-agent and ps")
    if os.path.basename(os.path.realpath(ps)).startswith("busybox"):
        pytest.skip("BusyBox is exercised through Linux /proc, not the generic ps format")
    directory = tmp_path / ("long installation path " * 5)
    directory.mkdir()
    executable = directory / "ssh-agent"
    executable.symlink_to(agent)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("COLUMNS", "1")
    # Force Linux's ps fallback too; normal Linux discovery already has a live test.
    p = platform._PsPlatform("linux") if sys.platform.startswith("linux") else platform.detect()
    with subprocess.Popen([str(executable), "-D", "-a", "agent.sock"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as child:
        try:
            deadline = time.monotonic() + 5
            while not (tmp_path / "agent.sock").exists():
                assert child.poll() is None, child.stderr.read().decode()
                assert time.monotonic() < deadline, "agent did not create its socket"
                time.sleep(0.01)
            assert child.pid in p.process_list(
                re.compile(r"(?:^|/)ssh-agent$"), uid=os.getuid()
            )
        finally:
            child.terminate()
            child.wait(timeout=5)
