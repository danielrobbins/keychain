# SPDX-License-Identifier: GPL-3.0-only
"""Tests for keychain.util: Output and LockFile."""

import multiprocessing
import os
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from keychain.util import KeychainError, LockFile, Output, pid_alive

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _out(quiet=True, debug=False):
    return Output.build(quiet=quiet, debug=debug, eval_mode=False, color=False)


def _acquire_lock_and_exit(path: str) -> None:
    lock = LockFile(path, no_lock=False, wait=0, out=_out())
    os._exit(0 if lock.try_acquire() else 1)


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

    def test_release_leaves_reusable_lock_file(self, tmp_path, silent_out):
        lock = tmp_path / "test.lock"
        with LockFile(lock, no_lock=False, wait=1, out=silent_out):
            pass
        with LockFile(lock, no_lock=False, wait=1, out=silent_out) as lf:
            assert lf.acquired

    def test_nolock_is_noop_no_file_created(self, tmp_path, silent_out):
        lock = tmp_path / "test.lock"
        with LockFile(lock, no_lock=True, wait=1, out=silent_out) as lf:
            assert lf.acquired  # nolock always succeeds ...
            assert not lock.exists()  # ... but writes nothing to disk

    def test_lock_content_is_hostname_colon_pid(self, tmp_path, silent_out):
        lock = tmp_path / "test.lock"
        with LockFile(lock, no_lock=False, wait=1, out=silent_out) as lf:
            assert lf.acquired
            if os.name != "nt":
                assert lock.stat().st_mode & 0o777 == 0o600

        content = lock.read_text()
        hostname, _, rest = content.partition(":")
        assert hostname == socket.gethostname()
        assert int(rest.split(":", 1)[0]) == os.getpid()

    def test_abandoned_lock_content_does_not_block_acquisition(self, tmp_path, silent_out):
        lock = tmp_path / "test.lock"
        lock.write_text(f"{socket.gethostname()}:{2**30}")
        with LockFile(lock, no_lock=False, wait=1, out=silent_out) as lf:
            assert lf.acquired

    def test_process_exit_releases_lock(self, tmp_path, silent_out):
        lock = tmp_path / "test.lock"
        process = multiprocessing.get_context("spawn").Process(target=_acquire_lock_and_exit, args=(str(lock),))
        process.start()
        process.join(10)

        assert process.exitcode == 0
        with LockFile(lock, no_lock=False, wait=0, out=silent_out) as lf:
            assert lf.acquired

    def test_live_local_lock_not_stolen(self, tmp_path, silent_out):
        lock = tmp_path / "test.lock"
        with LockFile(lock, no_lock=False, wait=1, out=silent_out):
            contender = LockFile(lock, no_lock=False, wait=0, out=silent_out)
            assert contender.try_acquire() is False

    def test_release_is_idempotent(self, tmp_path, silent_out):
        lock = tmp_path / "test.lock"
        lf = LockFile(lock, no_lock=False, wait=1, out=silent_out)
        lf.__enter__()
        lf.release()
        lf.release()  # second release must not raise
        assert not lf.acquired

    def test_lockwait_zero_rejects_live_lock(self, tmp_path, silent_out):
        lock = tmp_path / "test.lock"
        with LockFile(lock, no_lock=False, wait=1, out=silent_out):
            with pytest.raises(KeychainError, match="could not acquire lock"):
                LockFile(lock, no_lock=False, wait=0, out=silent_out).__enter__()

    @pytest.mark.skipif(sys.platform == "win32", reason="Windows does not unlink open files")
    def test_release_does_not_remove_replacement_lock(self, tmp_path, silent_out):
        lock = tmp_path / "test.lock"
        held = LockFile(lock, no_lock=False, wait=1, out=silent_out)
        held.__enter__()
        replacement = f"{socket.gethostname()}:{os.getpid()}:replacement"
        lock.unlink()
        lock.write_text(replacement)

        held.release()

        assert lock.read_text() == replacement

    def test_concurrent_contenders_elect_one_owner(self, tmp_path, silent_out):
        lock_path = tmp_path / "test.lock"
        count = 12
        start = threading.Barrier(count + 1)
        attempted = threading.Barrier(count + 1)
        release = threading.Event()

        def contend() -> bool:
            lock = LockFile(lock_path, no_lock=False, wait=0, out=silent_out)
            start.wait()
            acquired = lock.try_acquire()
            attempted.wait()
            if acquired:
                release.wait()
                lock.release()
            return acquired

        with ThreadPoolExecutor(max_workers=count) as pool:
            futures = [pool.submit(contend) for _ in range(count)]
            start.wait()
            attempted.wait()
            release.set()

        assert sum(future.result() for future in futures) == 1


class TestPidAlive:
    def test_current_process_is_reported_alive(self):
        assert pid_alive(os.getpid()) is True
        assert os.getpid() > 0
