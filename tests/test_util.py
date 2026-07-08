# SPDX-License-Identifier: GPL-3.0-only
"""Tests for keychain.util: Output and LockFile."""

import os
import socket

import pytest

from keychain.util import LockFile, Output, pid_alive

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _out(quiet=True, debug=False):
    return Output.build(quiet=quiet, debug=debug, eval_mode=False, color=False)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


class TestOutputBuild:
    def test_no_color_clears_all_escapes(self):
        out = _out()
        for name in ("BLUE", "CYAN", "CYANN", "GREEN", "RED", "PURP", "YEL", "OFF"):
            assert out.c(name) == ""

    def test_color_populates_escapes(self, monkeypatch):
        monkeypatch.setattr(os, "isatty", lambda fd: True)
        out = Output.build(quiet=False, debug=False, eval_mode=False, color=True)
        assert out.c("GREEN") != ""
        assert out.c("OFF") != ""

    def test_unknown_color_key_returns_empty(self):
        out = _out()
        assert out.c("NONEXISTENT") == ""

    def test_quiet_suppresses_mesg(self, capsys):
        _out(quiet=True).mesg("should not appear")
        assert capsys.readouterr().err == ""

    def test_not_quiet_emits_mesg(self, capsys):
        _out(quiet=False).mesg("hello world")
        assert "hello world" in capsys.readouterr().err

    def test_warn_always_emits_even_when_quiet(self, capsys):
        _out(quiet=True).warn("danger")
        assert "danger" in capsys.readouterr().err

    def test_note_suppressed_when_quiet(self, capsys):
        _out(quiet=True).note("just a note")
        assert capsys.readouterr().err == ""

    def test_debug_off_suppresses_message(self, capsys):
        _out(debug=False).debug("hidden")
        assert "hidden" not in capsys.readouterr().err

    def test_debug_on_emits_message(self, capsys):
        _out(debug=True).debug("visible")
        assert "visible" in capsys.readouterr().err


class TestOutputTheming:
    def test_default_theme_uses_modern_palette(self, monkeypatch):
        monkeypatch.setattr(os, "isatty", lambda fd: True)
        monkeypatch.delenv("KEYCHAIN_THEME", raising=False)
        out = Output.build(quiet=False, debug=False, eval_mode=False, color=True)
        # Modern (the new default) uses 256-color escapes: \033[38;5;NNNm
        assert "38;5;" in out.c("GREEN")
        assert out.theme == "modern"

    def test_modern_theme_uses_256_color_palette(self, monkeypatch):
        monkeypatch.setattr(os, "isatty", lambda fd: True)
        out = Output.build(quiet=False, debug=False, eval_mode=False, color=True, theme="modern")
        # Modern palette uses 256-color escapes: \033[38;5;NNNm
        assert "38;5;" in out.c("GREEN")
        assert out.theme == "modern"

    def test_legacy_theme_uses_8_color_palette(self, monkeypatch):
        monkeypatch.setattr(os, "isatty", lambda fd: True)
        out = Output.build(quiet=False, debug=False, eval_mode=False, color=True, theme="legacy")
        # Legacy palette uses bold 8-color green: \033[32;01m
        assert "32;01" in out.c("GREEN")
        assert out.theme == "legacy"

    def test_explicit_theme_flag(self, monkeypatch):
        monkeypatch.setattr(os, "isatty", lambda fd: True)
        out = Output.build(quiet=False, debug=False, eval_mode=False, color=True, theme="modern")
        assert "38;5;" in out.c("GREEN")

    def test_unknown_theme_falls_back_to_default(self, monkeypatch):
        monkeypatch.setattr(os, "isatty", lambda fd: True)
        out = Output.build(quiet=False, debug=False, eval_mode=False, color=True, theme="neon-burrito")
        # Falls back to the modern (default) palette without raising.
        assert "38;5;" in out.c("GREEN")

    def test_json_forces_quiet_and_no_color(self, monkeypatch):
        monkeypatch.setattr(os, "isatty", lambda fd: True)
        out = Output.build(quiet=False, debug=False, eval_mode=False, color=True, theme="modern", json=True)
        assert out.json is True
        assert out.quiet is True
        # color is suppressed so JSON consumers never see ANSI escapes.
        assert out.c("GREEN") == ""


# ---------------------------------------------------------------------------
# LockFile
# ---------------------------------------------------------------------------


@pytest.fixture
def silent_out():
    return _out()


class TestLockFile:
    def test_acquire_creates_lock_file(self, tmp_path, silent_out):
        lock = tmp_path / "test.lock"
        with LockFile(lock, no_lock=False, wait=1, out=silent_out) as lf:
            assert lf.acquired
            assert lock.exists()

    def test_release_removes_lock_file(self, tmp_path, silent_out):
        lock = tmp_path / "test.lock"
        with LockFile(lock, no_lock=False, wait=1, out=silent_out):
            pass
        assert not lock.exists()

    def test_nolock_is_noop_no_file_created(self, tmp_path, silent_out):
        lock = tmp_path / "test.lock"
        with LockFile(lock, no_lock=True, wait=1, out=silent_out) as lf:
            assert lf.acquired  # nolock always succeeds ...
            assert not lock.exists()  # ... but writes nothing to disk

    def test_lock_content_is_hostname_colon_pid(self, tmp_path, silent_out):
        lock = tmp_path / "test.lock"
        with LockFile(lock, no_lock=False, wait=1, out=silent_out) as lf:
            assert lf.acquired
            content = lock.read_text()
            hostname, _, pid_s = content.partition(":")
            assert hostname == socket.gethostname()
            assert int(pid_s) == os.getpid()

    def test_stale_local_lock_is_recovered(self, tmp_path, silent_out):
        lock = tmp_path / "test.lock"
        # PID 2**30 is far above the kernel max on any real system.
        lock.write_text(f"{socket.gethostname()}:{2**30}")
        with LockFile(lock, no_lock=False, wait=1, out=silent_out) as lf:
            assert lf.acquired

    def test_legacy_plain_pid_stale_lock_recovered(self, tmp_path, silent_out):
        lock = tmp_path / "test.lock"
        # Pre-NFS-fix format: just a PID with no hostname.
        lock.write_text(str(2**30))
        with LockFile(lock, no_lock=False, wait=1, out=silent_out) as lf:
            assert lf.acquired

    def test_live_local_lock_not_stolen(self, tmp_path, silent_out):
        lock = tmp_path / "test.lock"
        # Our own PID is guaranteed alive.
        lock.write_text(f"{socket.gethostname()}:{os.getpid()}")
        lf = LockFile(lock, no_lock=False, wait=0, out=silent_out)
        assert lf._acquire() is False

    def test_remote_host_lock_not_stolen(self, tmp_path, silent_out):
        lock = tmp_path / "test.lock"
        # A lock from a different host must be left alone (NFS safety).
        lock.write_text("remote-host-that-cannot-exist-xyz:12345")
        lf = LockFile(lock, no_lock=False, wait=0, out=silent_out)
        assert lf._acquire() is False

    def test_release_is_idempotent(self, tmp_path, silent_out):
        lock = tmp_path / "test.lock"
        lf = LockFile(lock, no_lock=False, wait=1, out=silent_out)
        lf.__enter__()
        lf.release()
        lf.release()  # second release must not raise
        assert not lf.acquired

    def test_lockwait_zero_force_acquires_live_lock(self, tmp_path, silent_out):
        """gap §3.6 / usage-patterns.md §3.6: with ``--lockwait 0`` the
        lockfile is forcibly taken over even when its owner is a live local
        process. The wait loop falls through immediately and the
        break-the-glass branch unlinks + reacquires.
        """
        lock = tmp_path / "test.lock"
        # Owner = ourselves (definitely alive). _acquire() would refuse
        # this lock; __enter__ with wait=0 must overrule and force-take it.
        lock.write_text(f"{socket.gethostname()}:{os.getpid()}")
        with LockFile(lock, no_lock=False, wait=0, out=silent_out) as lf:
            assert lf.acquired
            # New lock content should now be ours, not the seeded value.
            content = lock.read_text()
            hostname, _, pid_s = content.partition(":")
            assert hostname == socket.gethostname()
            assert int(pid_s) == os.getpid()
        assert not lock.exists()


class TestPidAlive:
    def test_current_process_is_reported_alive(self):
        assert pid_alive(os.getpid()) is True
        assert os.getpid() > 0
