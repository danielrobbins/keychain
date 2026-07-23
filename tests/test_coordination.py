# SPDX-License-Identifier: GPL-3.0-only
"""Tests for the interactive activation coordination layer."""

from __future__ import annotations

import json
import os
import signal
import socket
import stat
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from keychain import main
from keychain.agents import SshAddPlan
from keychain.coordination import (
    ActivationCoordinator,
    ActivationInfo,
    ActivationLock,
    ActivationOwner,
    CoordinationState,
    WaiterEndpoint,
    WaiterInfo,
    WaitResult,
)
from keychain.env import SshAgentRef
from keychain.paths import KeychainPaths
from keychain.runtime.config import RuntimeConfig
from keychain.util import KeychainError, LockFile, Output, pid_alive


def _out():
    return Output.build(quiet=True, debug=False, eval_mode=False, color=False)


def _visible_out():
    return Output.build(quiet=False, debug=False, eval_mode=False, color=False)


class TestCoordinationState:
    def test_state_round_trip(self, tmp_path):
        path = tmp_path / "box.state.json"
        state = CoordinationState(
            generation=7,
            activation=ActivationInfo(
                in_progress=True,
                status="loading",
                requested_keys=["id_ed25519"],
            ),
            waiters=[
                WaiterInfo(
                    pid=456,
                    tty="/dev/pts/3",
                    fifo_path=str(tmp_path / "456.fifo"),
                    registered_at=15.0,
                    requested_keys=["id_ed25519"],
                )
            ],
        )

        state.save(path)
        loaded = CoordinationState.load(path)

        assert loaded.generation == 7
        assert loaded.activation.in_progress is True
        assert loaded.activation.requested_keys == ["id_ed25519"]
        assert len(loaded.waiters) == 1
        assert loaded.waiters[0].fifo_path.endswith("456.fifo")

    def test_invalid_state_file_is_treated_as_empty(self, tmp_path):
        path = tmp_path / "box.state.json"
        path.write_text("{not-json", encoding="utf-8")

        loaded = CoordinationState.load(path)

        assert loaded.generation == 0
        assert loaded.activation.in_progress is False
        assert loaded.waiters == []


class TestActivationPrompt:
    def test_inactive_prompt_is_compact_call_to_action(self, tmp_path, capsys):
        coord = ActivationCoordinator(KeychainPaths(keydir=tmp_path, host="box"), False, 1, _visible_out())

        coord._prompt(activation_active=False)

        err = capsys.readouterr().err
        assert "Press Enter to initialize keys" in err
        assert "wait for another terminal" not in err
        assert "Keys need initialization" not in err

    def test_active_prompt_offers_takeover_without_old_prose(self, tmp_path, capsys):
        coord = ActivationCoordinator(KeychainPaths(keydir=tmp_path, host="box"), False, 1, _visible_out())

        coord._prompt(activation_active=True)

        err = capsys.readouterr().err
        assert "Type 'takeover' to initialize keys in this terminal" in err
        assert "Enter to wait" in err
        assert "Another terminal is initializing keys." not in err


class TestActivationLock:
    def test_activation_lock_acquire_and_release(self, tmp_path):
        path = tmp_path / "box.activation.lock"

        with ActivationLock(path, no_lock=False, out=_out()) as lock:
            assert lock.acquired is True
            assert path.exists()

        raw = path.read_text(encoding="utf-8")
        assert raw.startswith(f"{socket.gethostname()}:{os.getpid()}:")
        with ActivationLock(path, no_lock=False, out=_out()) as lock:
            assert lock.acquired is True

    def test_activation_lock_does_not_steal_live_local_lock(self, tmp_path):
        path = tmp_path / "box.activation.lock"

        with ActivationLock(path, no_lock=False, out=_out()):
            with ActivationLock(path, no_lock=False, out=_out()) as contender:
                assert contender.acquired is False

    def test_activation_lock_ignores_abandoned_content(self, tmp_path):
        path = tmp_path / "box.activation.lock"
        path.write_text(f"{socket.gethostname()}:{2**30}:seed", encoding="utf-8")

        with ActivationLock(path, no_lock=False, out=_out()) as lock:
            assert lock.acquired is True
            assert path.exists()

    @pytest.mark.skipif(sys.platform == "win32", reason="Windows does not unlink open files")
    def test_activation_lock_does_not_remove_someone_elses_token(self, tmp_path):
        path = tmp_path / "box.activation.lock"
        lock = ActivationLock(path, no_lock=False, out=_out())
        assert lock.try_acquire() is True

        path.unlink()
        path.write_text(f"{socket.gethostname()}:999999:other", encoding="utf-8")
        lock.release()

        assert path.exists()
        assert path.read_text(encoding="utf-8").endswith(":other")


class TestWaiters:
    def test_waiter_endpoint_reads_one_json_message(self, tmp_path):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b'{"status": "success", "generation": 2}\n')
            endpoint = WaiterEndpoint(tmp_path / "missing.fifo", read_fd, -1)

            assert endpoint.read_message() == {"status": "success", "generation": 2}
        finally:
            os.close(write_fd)
            endpoint.cleanup()

    def test_handoff_timeout_reopens_inactive_activation(self, tmp_path):
        paths = KeychainPaths(keydir=tmp_path, host="box")
        coord = ActivationCoordinator(paths, no_lock=False, lockwait=1, out=_out())
        waiter = SimpleNamespace(wait_for_message=lambda timeout: {})

        assert coord.wait_for_handoff(waiter, timeout=0).action == "activate"

    def test_handoff_timeout_keeps_waiting_for_live_owner(self, tmp_path):
        paths = KeychainPaths(keydir=tmp_path, host="box")
        coord = ActivationCoordinator(paths, no_lock=False, lockwait=1, out=_out())
        coord.save_state(
            CoordinationState(
                activation=ActivationInfo(in_progress=True)
            )
        )
        waiter = SimpleNamespace(wait_for_message=lambda timeout: {})

        with coord.activation_lock() as owner:
            assert owner.acquired
            assert coord.wait_for_handoff(waiter, timeout=0).action == "handoff"

    def test_handoff_timeout_recovers_orphaned_activation(self, tmp_path):
        paths = KeychainPaths(keydir=tmp_path, host="box")
        coord = ActivationCoordinator(paths, no_lock=False, lockwait=1, out=_out())
        coord.save_state(
            CoordinationState(
                activation=ActivationInfo(in_progress=True)
            )
        )
        waiter = SimpleNamespace(wait_for_message=lambda timeout: {})

        assert coord.wait_for_handoff(waiter, timeout=0).action == "activate"
        assert coord.load_state().activation.status == "canceled"

    def test_waiter_endpoint_buffers_back_to_back_messages(self, tmp_path):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b'{"status": "canceled"}\n{"status": "success"}\n')
            endpoint = WaiterEndpoint(tmp_path / "missing.fifo", read_fd, -1)

            assert endpoint.read_message() == {"status": "canceled"}
            assert endpoint.read_message() == {"status": "success"}
        finally:
            os.close(write_fd)
            endpoint.cleanup()

    def test_register_waiter_is_idempotent_for_same_fifo(self, tmp_path):
        paths = KeychainPaths(keydir=tmp_path, host="box")
        coord = ActivationCoordinator(paths, no_lock=False, lockwait=1, out=_out())
        endpoint = WaiterEndpoint(tmp_path / "wait.fifo", -1, -1)
        state = CoordinationState()

        coord.register_waiter(state, endpoint, ["id1"])
        coord.register_waiter(state, endpoint, ["id2"])

        assert len(state.waiters) == 1
        assert state.waiters[0].requested_keys == ["id2"]

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO support required")
    def test_fifo_waiter_receives_notification_without_lost_wakeup(self, tmp_path):
        paths = KeychainPaths(keydir=tmp_path, host="box")
        coord = ActivationCoordinator(paths, no_lock=False, lockwait=1, out=_out())
        endpoint = coord.create_waiter()
        assert endpoint is not None
        try:
            assert stat.S_ISFIFO(endpoint.fifo_path.stat().st_mode)
            state = CoordinationState()
            coord.register_waiter(state, endpoint, ["id_ed25519"])

            coord.notify_waiters(state.waiters, status="success", generation=3)

            assert endpoint.wait_for_message(timeout=1.0)["status"] == "success"
        finally:
            endpoint.cleanup()

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO support required")
    def test_fifo_endpoint_receives_raw_writer_message(self, tmp_path):
        paths = KeychainPaths(keydir=tmp_path, host="box")
        coord = ActivationCoordinator(paths, no_lock=False, lockwait=1, out=_out())
        endpoint = coord.create_waiter()
        assert endpoint is not None
        try:
            fd = os.open(endpoint.fifo_path, os.O_WRONLY | getattr(os, "O_NONBLOCK", 0))
            try:
                os.write(fd, b'{"status": "canceled", "generation": 4}\n')
            finally:
                os.close(fd)

            assert endpoint.wait_for_message(timeout=1.0) == {"status": "canceled", "generation": 4}
        finally:
            endpoint.cleanup()

    def test_finish_activation_clears_waiters_and_advances_generation(self, tmp_path):
        paths = KeychainPaths(keydir=tmp_path, host="box")
        coord = ActivationCoordinator(paths, no_lock=False, lockwait=1, out=_out())
        state = CoordinationState(
            generation=1,
            activation=ActivationInfo(in_progress=True, status="loading"),
            waiters=[
                WaiterInfo(
                    pid=123,
                    tty="",
                    fifo_path=str(tmp_path / "gone.fifo"),
                    registered_at=1.0,
                    requested_keys=["id"],
                )
            ],
        )
        coord.save_state(state)

        waiters = coord.finish_activation("success")
        loaded = coord.load_state()

        assert [waiter.pid for waiter in waiters] == [123]
        assert loaded.generation == 2
        assert loaded.activation.in_progress is False
        assert loaded.activation.status == "success"
        assert loaded.waiters == []

    def test_state_lock_zero_wait_fails_without_user_visible_wait(self, tmp_path, capsys):
        paths = KeychainPaths(keydir=tmp_path, host="box")
        coord = ActivationCoordinator(paths, no_lock=False, lockwait=0, out=_visible_out())

        with LockFile(paths.state_lockf, no_lock=False, wait=1, out=_out()):
            with pytest.raises(KeychainError, match="could not acquire lock"):
                with coord.state_lock():
                    pytest.fail("live state lock must not be stolen")

        assert "Waiting" not in capsys.readouterr().err

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO support required")
    def test_request_takeover_sends_cancel_and_waits_for_notification(self, tmp_path):
        paths = KeychainPaths(keydir=tmp_path, host="box")
        coord = ActivationCoordinator(paths, no_lock=False, lockwait=1, out=_out())
        waiter = coord.create_waiter()
        cancel = coord.create_cancel_endpoint()
        assert waiter is not None
        assert cancel is not None
        try:
            state = CoordinationState(
                generation=1,
                activation=ActivationInfo(
                    in_progress=True,
                    cancel_endpoint=str(cancel.fifo_path),
                ),
            )
            coord.register_waiter(state, waiter, ["id_ed25519"])
            coord.save_state(state)

            def owner_side_cancel():
                ready, _, _ = select.select([cancel.read_fd], [], [], 1.0)
                assert ready
                assert cancel.read_command() == "cancel"
                coord.notify_waiters(state.waiters, "canceled", generation=2)

            import select

            thread = threading.Thread(target=owner_side_cancel)
            thread.start()
            with coord.activation_lock() as owner:
                assert owner.acquired
                msg = coord.request_takeover(waiter, timeout=1.0)
            thread.join(timeout=1.0)

            assert msg["status"] == "canceled"
        finally:
            waiter.cleanup()
            cancel.cleanup()

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO support required")
    def test_request_takeover_reconciles_state_when_notification_is_missed(self, tmp_path, monkeypatch):
        paths = KeychainPaths(keydir=tmp_path, host="box")
        coord = ActivationCoordinator(paths, no_lock=False, lockwait=1, out=_out())
        waiter = coord.create_waiter()
        cancel = coord.create_cancel_endpoint()
        assert waiter is not None
        assert cancel is not None
        try:
            state = CoordinationState(
                generation=1,
                activation=ActivationInfo(
                    in_progress=True,
                    cancel_endpoint=str(cancel.fifo_path),
                ),
            )
            coord.register_waiter(state, waiter, ["id_ed25519"])
            coord.save_state(state)

            def miss_notification(self, timeout=None):
                with coord.state_lock():
                    completed = coord.load_state()
                    completed.waiters = []
                    completed.activation = ActivationInfo(in_progress=False, status="canceled")
                    completed.generation += 1
                    coord.save_state(completed)
                return {}

            monkeypatch.setattr(WaiterEndpoint, "wait_for_message", miss_notification)

            with coord.activation_lock() as owner:
                assert owner.acquired
                msg = coord.request_takeover(waiter, timeout=1.0)

            assert msg["status"] == "canceled"
            assert msg["generation"] == 2
        finally:
            waiter.cleanup()
            cancel.cleanup()

    def test_activation_owner_records_minimal_activation_state(self, tmp_path):
        paths = KeychainPaths(keydir=tmp_path, host="box")
        coord = ActivationCoordinator(paths, no_lock=False, lockwait=1, out=_out())
        owner = ActivationOwner(coord, None, ["id_ed25519"], _out())

        status = owner.run_ssh_add([[sys.executable, "-c", ""]], os.environ.copy())

        state = coord.load_state()
        assert status == "success"
        assert state.activation.in_progress is True
        assert state.activation.requested_keys == ["id_ed25519"]
        assert set(state.activation.to_dict()) == {"in_progress", "cancel_endpoint", "status", "requested_keys"}

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO support required")
    def test_activation_owner_cancel_notifies_waiter_during_second_child(self, tmp_path, monkeypatch):
        paths = KeychainPaths(keydir=tmp_path, host="box")
        coord = ActivationCoordinator(paths, no_lock=False, lockwait=1, out=_out())
        waiter = coord.create_waiter()
        assert waiter is not None
        result: dict[str, str] = {}
        child_pid: list[int] = []
        marker = tmp_path / "second-child"
        owner = ActivationOwner(coord, None, ["id_ed25519"], _out())
        listener_starts = 0
        start_cancel_thread = owner._start_cancel_thread

        def count_listener_start():
            nonlocal listener_starts
            listener_starts += 1
            start_cancel_thread()

        monkeypatch.setattr(owner, "_start_cancel_thread", count_listener_start)

        def owner_side():
            with coord.activation_lock() as activation_lock:
                assert activation_lock.acquired
                status = owner.run_ssh_add(
                    [
                        [sys.executable, "-c", ""],
                        [
                            sys.executable,
                            "-c",
                            f"from pathlib import Path; Path({str(marker)!r}).touch(); "
                            "import time; time.sleep(30)",
                        ],
                    ],
                    os.environ.copy(),
                )
                result["status"] = status
                coord.finish_activation(status)

        try:
            thread = threading.Thread(target=owner_side)
            thread.start()

            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                state = coord.load_state()
                if state.activation.cancel_endpoint and marker.exists() and owner.proc is not None:
                    child_pid.append(owner.proc.pid)
                    with coord.state_lock():
                        state = coord.load_state()
                        coord.register_waiter(state, waiter, ["id_ed25519"])
                        coord.save_state(state)
                    break
                time.sleep(0.05)
            else:
                pytest.fail("activation owner did not publish cancel metadata")

            msg = coord.request_takeover(waiter, timeout=5.0)
            thread.join(timeout=5.0)

            assert msg["status"] == "canceled"
            assert result == {"status": "canceled"}
            assert not thread.is_alive()
            assert child_pid and not pid_alive(child_pid[0])
            assert listener_starts == 1
        finally:
            waiter.cleanup()


class TestKeychainAppCoordination:
    def test_signal_finalizes_state_before_releasing_activation_lock(self, tmp_path, monkeypatch):
        paths = KeychainPaths(keydir=tmp_path, host="box")
        coord = ActivationCoordinator(paths, no_lock=False, lockwait=1, out=_out())
        app = main.KeychainApp(RuntimeConfig.resolve(["add"]), _out())
        signals = tuple(sig for sig in (getattr(signal, "SIGHUP", None), signal.SIGINT, signal.SIGTERM) if sig is not None)
        originals = {sig: object() for sig in signals}
        installed = dict(originals)

        def fake_signal(sig, handler):
            previous = installed.get(sig, object())
            installed[sig] = handler
            return previous

        def interrupt(*_args):
            installed[signal.SIGTERM](signal.SIGTERM, None)

        lock_was_held: list[bool] = []
        finish_activation = coord.finish_activation

        def finish_while_locked(status):
            with ActivationLock(paths.activation_lockf, no_lock=False, out=_out()) as contender:
                lock_was_held.append(not contender.acquired)
            finish_activation(status)

        monkeypatch.setattr(main.signal, "signal", fake_signal)
        monkeypatch.setattr(app, "_wipe_before_activation", interrupt)
        monkeypatch.setattr(coord, "finish_activation", finish_while_locked)

        with pytest.raises(SystemExit):
            app._try_activation(coord, None, main._MissingKeys(), False)

        assert lock_was_held == [True]
        assert installed == originals
        with ActivationLock(paths.activation_lockf, no_lock=False, out=_out()) as contender:
            assert contender.acquired is True

    def test_direct_activation_uses_new_activation_lock_not_legacy_lock(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ActivationCoordinator, "create_waiter", lambda self: None)
        paths = KeychainPaths(keydir=tmp_path, host="box")
        loaded: list[tuple[list[list[str]], dict[str, str]]] = []

        class _Owner:
            def __init__(self, _coord, _waiter, requested_keys, _out):
                assert requested_keys == ["id_ed25519"]

            def run_ssh_add(self, cmd, env):
                loaded.append((list(cmd), dict(env)))
                return "success"

        monkeypatch.setattr(main, "ActivationOwner", _Owner)

        class _SSH:
            env = SshAgentRef(sock="/tmp/agent.sock", pid="123")

            def start(self, _ssh_spawn_gpg, _ssh_allow_gpg):
                return False

            def list_missing(self, ssh_keys, *, announce_known=True):
                return list(ssh_keys) if not loaded else []

            def prepare_load(self, missing, pkcs11=None, *, announce=True):
                assert pkcs11 == []
                assert announce is True
                return SshAddPlan([["ssh-add", *missing]], {"SSH_AUTH_SOCK": self.env.sock})

            def wipe(self):
                raise AssertionError("wipe should not run")

        class _GPG:
            def start(self, ssh_support):
                raise AssertionError("gpg should not start")

        kstate = SimpleNamespace(
            paths=paths,
            user="tester",
            ssh=_SSH(),
            gpg=_GPG(),
        )
        args = RuntimeConfig.resolve(["add", "--lockwait", "1", "id_ed25519"])
        out = _out()
        app = main.KeychainApp(args, out)
        app._kstate = kstate

        assert app._do_add(["id_ed25519"], [], [], [], [], [], False, False) == 0

        assert loaded == [([["ssh-add", "id_ed25519"]], {"SSH_AUTH_SOCK": "/tmp/agent.sock"})]
        assert not paths.lockf.exists()
        assert paths.activation_lockf.exists()
        assert paths.state_lockf.exists()
        state_data = json.loads(paths.state_file.read_text(encoding="utf-8"))
        assert state_data["generation"] == 1
        assert state_data["activation"]["status"] == "success"

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO support required")
    def test_canceled_owner_waits_for_takeover_completion(self, tmp_path, monkeypatch, capsys):
        paths = KeychainPaths(keydir=tmp_path, host="box")
        remote_done = False
        wait_modes: list[bool] = []
        owner_calls: list[list[list[str]]] = []

        monkeypatch.setattr(ActivationCoordinator, "can_prompt", lambda self: True)

        def fake_wait(self, _waiter, *, activation_active):
            wait_modes.append(activation_active)
            if len(wait_modes) > 1:
                pytest.fail("handoff should wait quietly for the takeover terminal")
            return WaitResult("activate")

        def fake_wait_for_message(self, timeout=None):
            nonlocal remote_done
            remote_done = True
            return {"status": "success"}

        monkeypatch.setattr(ActivationCoordinator, "wait_for_activation_signal", fake_wait)
        monkeypatch.setattr(WaiterEndpoint, "wait_for_message", fake_wait_for_message)

        class _Owner:
            def __init__(self, _coord, _waiter, _requested_keys, _out):
                return None

            def run_ssh_add(self, cmd, _env):
                owner_calls.append(list(cmd))
                return "canceled"

        monkeypatch.setattr(main, "ActivationOwner", _Owner)

        class _SSH:
            env = SshAgentRef(sock="/tmp/agent.sock", pid="123")

            def start(self, _ssh_spawn_gpg, _ssh_allow_gpg):
                return False

            def list_missing(self, ssh_keys, *, announce_known=True):
                return [] if remote_done else list(ssh_keys)

            def announce_load(self, _missing, _pkcs11=None):
                return None

            def prepare_load(self, missing, pkcs11=None, *, announce=True):
                assert pkcs11 == []
                assert announce is False
                return SshAddPlan([["ssh-add", *missing]], {"SSH_AUTH_SOCK": self.env.sock})

            def wipe(self):
                raise AssertionError("wipe should not run")

        kstate = SimpleNamespace(
            paths=paths,
            user="tester",
            ssh=_SSH(),
            gpg=SimpleNamespace(),
        )
        args = RuntimeConfig.resolve(["add", "--lockwait", "1", "id_ed25519"])
        app = main.KeychainApp(args, _visible_out())
        app._kstate = kstate

        assert app._do_add(["id_ed25519"], [], [], [], [], [], False, False) == 0

        assert owner_calls == [[["ssh-add", "id_ed25519"]]]
        assert wait_modes == [False]
        err = capsys.readouterr().err
        assert "Key initialization is still needed" not in err
        assert "Keys initialized by another terminal." in err

    def test_gpga_proves_decryption_even_when_signing_is_warm(self):
        calls: list[tuple[str, list[str]]] = []

        class _SSH:
            def list_missing(self, keys, *, announce_known=True):
                return list(keys)

            def list_missing_pkcs11(self, providers, *, announce_known=True):
                return list(providers)

        class _GPG:
            def list_missing(self, keys, *, mode="--sign", announce_known=True):
                return []

            def load(self, keys, mode="--sign"):
                calls.append((mode, list(keys)))
                return True

            def load_decryption(self, keys):
                calls.append(("decrypt", list(keys)))
                return True

        args = RuntimeConfig.resolve(["add"])
        app = main.KeychainApp(args, _out())
        app._kstate = SimpleNamespace(ssh=_SSH(), gpg=_GPG())

        missing = app._missing_keys([], [], [], [], ["GPGKEY"], [])
        app._load_gpg_missing_keys(missing)

        assert missing.gpg_a == ["GPGKEY"]
        assert calls == [("--sign", ["GPGKEY"]), ("decrypt", ["GPGKEY"])]
