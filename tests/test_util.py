# SPDX-License-Identifier: GPL-3.0-only
"""Tests for keychain.util locking and process helpers."""

import multiprocessing
import os
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from keychain.output.core import Output
from keychain.util import KeychainError, LockFile, pid_alive

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
