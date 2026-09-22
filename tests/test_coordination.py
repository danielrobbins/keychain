# SPDX-License-Identifier: GPL-3.0-only
"""Coordination records, FIFO lifetime, locking, and application contracts."""

from __future__ import annotations

import json
import os
import select
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from keychain import agents, coordination, main
from keychain.coordination import ActivationCoordinator, ActivationLock, CoordinationState
from keychain.env import SshAgentRef
from keychain.output.core import Output
from keychain.paths import KeychainPaths
from keychain.runtime.config import RuntimeConfig
from keychain.util import KeychainError

ATTEMPT = "a" * 32
POSIX = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO support required")


def _out():
    return Output.build(quiet=True, debug=False, eval_mode=False, color=False)


@pytest.fixture
def coord(tmp_path, monkeypatch):
    monkeypatch.setattr(ActivationCoordinator, "can_prompt", lambda self: True)
    return ActivationCoordinator(KeychainPaths(keydir=tmp_path, host="box"), False, 1, _out())


class TestCoordinationState:
    def test_state_round_trip(self, tmp_path):
        path = tmp_path / "box.state.json"
        state = CoordinationState(ATTEMPT, "success")
        state.save(path)
        assert CoordinationState.load(path) == state
        assert json.loads(path.read_text()) == {"attempt": ATTEMPT, "status": "success"}
        if os.name != "nt":
            assert stat.S_IMODE(path.stat().st_mode) == 0o600

    @pytest.mark.parametrize("text", ["{", "[]", '"text"', "null"])
    def test_invalid_state_file_is_treated_as_empty(self, tmp_path, text):
        path = tmp_path / "box.state.json"
        path.write_text(text, encoding="utf-8")
        assert CoordinationState.load(path) == CoordinationState()

    @pytest.mark.parametrize(
        "data",
        [
            {"generation": "invalid"},
            {"activation": {"requested_keys": None}},
            {"waiters": [{"pid": 123, "fifo": "wait.fifo", "requested_keys": None}]},
            {"activation": {"in_progress": "false"}},
            {"attempt": None, "status": "loading"},
            {"attempt": "../../escape", "status": "loading"},
            {"attempt": ATTEMPT, "status": []},
        ],
    )
    def test_malformed_fields_do_not_raise_unhandled_exceptions(self, tmp_path, data):
        path = tmp_path / "box.state.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        assert CoordinationState.load(path) == CoordinationState()

    def test_unreadable_state_is_not_treated_as_empty(self, tmp_path, monkeypatch):
        def denied(*_args, **_kwargs):
            raise PermissionError("state file cannot be read")

        monkeypatch.setattr(Path, "open", denied)
        with pytest.raises(KeychainError, match="Cannot read coordination result"):
            CoordinationState.load(tmp_path / "box.state.json")

    def test_failed_save_preserves_previous_record(self, tmp_path, monkeypatch):
        path = tmp_path / "box.state.json"
        state = CoordinationState(ATTEMPT, "success")
        state.save(path)

        def failed_replace(*_args, **_kwargs):
            raise OSError("replacement failed")

        monkeypatch.setattr(Path, "replace", failed_replace)
        with pytest.raises(OSError, match="replacement failed"):
            CoordinationState("b" * 32, "loading").save(path)
        assert CoordinationState.load(path) == state
        assert list(tmp_path.glob(".box.state.json.*.tmp")) == []


class TestActivationLock:
    def test_activation_lock_acquire_and_release(self, tmp_path):
        path = tmp_path / "box.activation.lock"
        with ActivationLock(path, False, _out()) as lock:
            assert lock.acquired
        assert path.read_text().startswith(f"{socket.gethostname()}:{os.getpid()}:")
        with ActivationLock(path, False, _out()) as lock:
            assert lock.acquired

    def test_activation_lock_does_not_steal_live_local_lock(self, tmp_path):
        path = tmp_path / "box.activation.lock"
        with ActivationLock(path, False, _out()):
            with ActivationLock(path, False, _out()) as contender:
                assert not contender.acquired

    def test_activation_lock_ignores_abandoned_content(self, tmp_path):
        path = tmp_path / "box.activation.lock"
        path.write_text(f"{socket.gethostname()}:{2**30}:seed")
        with ActivationLock(path, False, _out()) as lock:
            assert lock.acquired

    @POSIX
    def test_activation_lock_does_not_remove_someone_elses_token(self, tmp_path):
        path = tmp_path / "box.activation.lock"
        with ActivationLock(path, False, _out()):
            path.unlink()
            path.write_text("replacement")
        assert path.read_text() == "replacement"

    def test_state_lock_zero_wait_fails_without_visible_wait(self, coord, capsys):
        coord.lockwait = 0
        with coord.state_lock():
            with pytest.raises(KeychainError):
                with coord.state_lock():
                    pytest.fail("must not acquire the live lock")
        assert capsys.readouterr().err == ""


@POSIX
class TestWaiters:
    def test_wait_returns_already_buffered_notification(self, coord):
        waiter = coord.create_waiter()
        try:
            messages = [{"attempt": ATTEMPT, "status": "canceled"}, {"attempt": "b" * 32, "status": "success"}]
            os.write(waiter.endpoint.keepalive_fd, "".join(json.dumps(m) + "\n" for m in messages).encode())
            assert waiter.wait(timeout=1).message == messages[0]
            assert waiter.endpoint.buffer
            assert waiter.wait(timeout=0).message == messages[1]
        finally:
            waiter.cleanup()

    def test_partial_and_malformed_messages_do_not_lose_following_message(self, coord):
        endpoint = coord.endpoint("test")
        try:
            os.write(endpoint.keepalive_fd, b'not json\n[]\n{"status":')
            assert endpoint.read_message() == {}
            os.write(endpoint.keepalive_fd, b'"success"}\n')
            assert endpoint.read_message() == {"status": "success"}
        finally:
            endpoint.cleanup()

    def test_notification_skips_stale_fifo_and_reaches_live_waiter(self, coord):
        waiter = coord.create_waiter()
        try:
            os.mkfifo(coord.paths.waiters_dir / "wait.stale.fifo", 0o600)
            coord.notify_waiters(ATTEMPT, "success")
            assert waiter.wait().message["status"] == "success"
        finally:
            waiter.cleanup()

    @pytest.mark.parametrize("symlink", [False, True])
    def test_notification_does_not_overwrite_regular_file(self, coord, symlink):
        coord.paths.waiters_dir.mkdir()
        destination = coord.paths.waiters_dir / "wait.replaced.fifo"
        target = coord.paths.keydir / "ordinary"
        target.write_text("untouched")
        if symlink:
            destination.symlink_to(target)
        else:
            destination.write_text("untouched")
        coord.notify_waiters(ATTEMPT, "success")
        assert destination.read_text() == target.read_text() == "untouched"

    def test_takeover_does_not_overwrite_regular_file(self, coord):
        waiter = coord.create_waiter()
        try:
            with coord.activation() as owner:
                with coord.state_lock():
                    waiter.attempt, waiter.life_fd = coord.observe()
                path = owner.cancel.fifo_path
                path.unlink()
                path.write_text("untouched")
                assert waiter.request_takeover().action == "unavailable"
                assert path.read_text() == "untouched"
        finally:
            waiter.cleanup()

    def test_registration_is_the_fifo_not_a_json_record(self, coord):
        waiter = coord.create_waiter()
        try:
            assert not coord.paths.state_file.exists()
            assert waiter.endpoint.fifo_path.is_fifo()
            coord.notify_waiters(ATTEMPT, "success")
            assert waiter.wait().message["status"] == "success"
        finally:
            waiter.cleanup()
        assert list(coord.paths.waiters_dir.glob("wait.*.fifo")) == []

    def test_completed_notification_survives_result_overwrite(self, coord):
        waiter = coord.create_waiter()
        try:
            with coord.activation() as owner:
                owner.status = "failed"
            CoordinationState("b" * 32, "success").save(coord.paths.state_file)
            assert waiter.wait().message == {"attempt": owner.attempt, "status": "failed"}
        finally:
            waiter.cleanup()

    @pytest.mark.parametrize("status", ["success", "failed", "canceled"])
    def test_lifetime_closure_recovers_missing_completion_message(self, coord, monkeypatch, status):
        waiter = coord.create_waiter()
        try:
            with coord.activation() as owner:
                with coord.state_lock():
                    waiter.attempt, waiter.life_fd = coord.observe()
                owner.status = status
                monkeypatch.setattr(coord, "notify_waiters", lambda *args: None)
            assert select.select([waiter.life_fd], [], [], 0)[0]
            assert waiter.wait().message["status"] == status
        finally:
            waiter.cleanup()

    def test_old_loading_record_cannot_make_new_invocation_wait(self, coord):
        CoordinationState(ATTEMPT, "loading").save(coord.paths.state_file)
        waiter = coord.create_waiter()
        try:
            assert waiter.wait(immediate=True).action == "activate"
        finally:
            waiter.cleanup()

    def test_every_observer_wakes_without_reading_lifetime_fifo(self, coord, monkeypatch):
        waiters = [coord.create_waiter() for _ in range(5)]
        read = os.read
        lifetime_inode = None

        def checked_read(fd, count):
            assert os.fstat(fd).st_ino != lifetime_inode, "reading EOF can clear other observers' macOS wakeup"
            return read(fd, count)

        monkeypatch.setattr(os, "read", checked_read)
        monkeypatch.setattr(coord, "notify_waiters", lambda *args: None)
        try:
            with coord.activation() as owner:
                lifetime_inode = os.fstat(owner.life.read_fd).st_ino
                for waiter in waiters:
                    with coord.state_lock():
                        waiter.attempt, waiter.life_fd = coord.observe()
                owner.status = "success"
            for waiter in waiters:
                assert select.select([waiter.life_fd], [], [], 0)[0]
                assert waiter.wait().message["status"] == "success"
        finally:
            for waiter in waiters:
                waiter.cleanup()

    def test_lifetime_path_without_activation_lock_cannot_authorize_waiting(self, coord):
        stale = coord.endpoint(f"life.{ATTEMPT}")
        try:
            with coord.state_lock():
                assert coord.observe() == ("", -1)
            assert not stale.fifo_path.exists()
        finally:
            stale.cleanup()

    def test_owner_death_during_discovery_cannot_leave_waiter_asleep(self, coord, monkeypatch):
        owner = coord.activation().__enter__()
        open_fifo = coordination._open_fifo

        def dying_loader(path, mode):
            # The initial lock probe saw a live operation, but it ends before discovery finishes.
            owner.lock.release()
            os.close(owner.life.keepalive_fd)
            owner.life.keepalive_fd = -1
            return open_fifo(path, mode)

        monkeypatch.setattr(coordination, "_open_fifo", dying_loader)
        try:
            with coord.state_lock():
                assert coord.observe() == ("", -1)
            assert not owner.life.fifo_path.exists()
        finally:
            owner._cleanup()

    def test_busy_lock_without_lifetime_channel_fails_clearly(self, coord):
        waiter = coord.create_waiter()
        try:
            with coord.activation_lock():
                with pytest.raises(KeychainError, match="lifetime notification is unavailable"):
                    waiter.wait(immediate=True)
        finally:
            waiter.cleanup()

    def test_handoff_timeout_reopens_inactive_activation(self, coord):
        waiter = coord.create_waiter()
        try:
            assert waiter.wait(handoff=True).action == "activate"
        finally:
            waiter.cleanup()

    def test_waiter_cleanup_does_not_require_readable_json(self, coord, monkeypatch):
        waiter = coord.create_waiter()
        monkeypatch.setattr(coord, "load_state", lambda: pytest.fail("cleanup must not read JSON"))
        waiter.cleanup()
        assert not waiter.endpoint.fifo_path.exists()


@POSIX
class TestOwner:
    def test_new_owner_removes_abandoned_channels_before_publication(self, coord):
        stale = coord.endpoint(f"life.{ATTEMPT}")
        cancel = coord.endpoint(f"cancel.{ATTEMPT}")
        try:
            with coord.activation() as owner:
                assert not stale.fifo_path.exists() and not cancel.fifo_path.exists()
                with coord.state_lock():
                    attempt, fd = coord.observe()
                try:
                    assert attempt == owner.attempt
                finally:
                    os.close(fd)
        finally:
            stale.cleanup()
            cancel.cleanup()

    def test_surviving_helper_preserves_lock_and_discoverable_lifetime(self, coord):
        helper = None
        fd = -1
        try:
            with coord.activation() as owner:
                life_path = owner.life.fifo_path
                helper = subprocess.Popen(
                    [sys.executable, "-c", "import sys; sys.stdin.read()"],
                    stdin=subprocess.PIPE,
                    pass_fds=owner.lock.pass_fds + (owner.life.keepalive_fd,),
                )
                owner.status = "success"
            assert life_path.exists()
            with coord.activation_lock() as lock:
                assert not lock.acquired
            with coord.state_lock():
                attempt, fd = coord.observe()
            assert attempt == owner.attempt and fd >= 0
            assert not select.select([fd], [], [], 0)[0]
            helper.communicate(timeout=5)
            assert select.select([fd], [], [], 1)[0]
            with coord.activation_lock() as lock:
                assert lock.acquired
            with coord.state_lock():
                assert coord.observe() == ("", -1)
            assert not life_path.exists()
        finally:
            if fd >= 0:
                os.close(fd)
            if helper is not None:
                if helper.poll() is None:
                    helper.kill()
                helper.communicate(timeout=5)

    def test_noninteractive_loading_still_publishes_lifetime(self, coord, monkeypatch):
        monkeypatch.setattr(coord, "can_prompt", lambda: False)
        assert coord.create_waiter() is None
        with coord.activation() as owner:
            with coord.state_lock():
                attempt, fd = coord.observe()
            assert attempt == owner.attempt
            os.close(fd)
            assert owner.run_ssh_add([[sys.executable, "-c", ""]], os.environ.copy()) == "success"
        assert coord.load_state().status == "success"

    def test_owner_records_only_attempt_and_outcome(self, coord):
        with coord.activation() as owner:
            assert owner.acquired
            assert coord.load_state() == CoordinationState(owner.attempt, "loading")
            assert owner.run_ssh_add([[sys.executable, "-c", ""]], os.environ.copy()) == "success"
        assert coord.load_state() == CoordinationState(owner.attempt, "success")
        assert list(coord.paths.waiters_dir.iterdir()) == []

    def test_failed_publication_releases_all_resources(self, coord, monkeypatch):
        def fail(*args):
            raise OSError("cannot save")

        monkeypatch.setattr(CoordinationState, "save", fail)
        with pytest.raises(OSError, match="cannot save"):
            with coord.activation():
                pytest.fail("must not begin loading")
        with coord.activation_lock() as lock:
            assert lock.acquired
        assert list(coord.paths.waiters_dir.iterdir()) == []

    def test_failed_final_save_still_closes_lifetime(self, coord, monkeypatch):
        waiter = coord.create_waiter()
        try:
            with pytest.raises(OSError, match="cannot save"):
                with coord.activation():
                    with coord.state_lock():
                        waiter.attempt, waiter.life_fd = coord.observe()

                    def fail(*args):
                        raise OSError("cannot save")

                    monkeypatch.setattr(CoordinationState, "save", fail)
            assert select.select([waiter.life_fd], [], [], 0)[0]
            assert waiter.wait().message["status"] == "abandoned"
        finally:
            waiter.cleanup()

    @pytest.mark.parametrize("ignore_sigterm", [False, True], ids=["cooperative-child", "sigterm-ignoring-child"])
    def test_cancel_during_second_child_reaps_child_before_release(self, coord, monkeypatch, ignore_sigterm):
        marker = coord.paths.keydir / "second-child"
        waiter = coord.create_waiter()
        started = threading.Event()
        errors = []
        holder = []
        cancel_child = coordination.ActivationOwner._cancel_child
        if ignore_sigterm:

            def delayed_cancel(owner):
                if threading.current_thread() is owner._thread:
                    # Model a small scheduling delay before the full child-termination grace period.
                    time.sleep(0.5)
                cancel_child(owner)

            monkeypatch.setattr(coordination.ActivationOwner, "_cancel_child", delayed_cancel)

        child_code = (
            "import signal, time; from pathlib import Path; "
            + ("signal.signal(signal.SIGTERM, signal.SIG_IGN); " if ignore_sigterm else "")
            + f"Path({str(marker)!r}).touch(); time.sleep(30)"
        )

        def run():
            try:
                with coord.activation() as owner:
                    holder.append(owner)
                    started.set()
                    owner.run_ssh_add(
                        [
                            [sys.executable, "-c", ""],
                            [sys.executable, "-c", child_code],
                        ],
                        os.environ.copy(),
                    )
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        try:
            assert started.wait(3)
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert marker.exists()
            with coord.state_lock():
                waiter.attempt, waiter.life_fd = coord.observe()
            result = waiter.request_takeover()
            thread.join(5)
            assert not thread.is_alive() and not errors
            assert holder[0].proc.poll() is not None
            assert coord.load_state().status == "canceled"
            assert result.action == "notified", "takeover timed out before child termination finished"
            assert result.message["status"] == "canceled"
        finally:
            if holder:
                cancel_child(holder[0])
            thread.join(5)
            waiter.cleanup()


class TestKeychainAppCoordination:
    @pytest.mark.parametrize("phase", ["key-list", "startup", "quick-startup"])
    def test_agent_queries_do_not_hold_state_lock(self, coord, monkeypatch, phase):
        args = RuntimeConfig.resolve(["add", "--noask", *(["--quick"] if phase == "quick-startup" else [])])
        state = main.state.KeychainState(args=args, paths=coord.paths, env={})
        state.out = _out()
        state.platform = SimpleNamespace(name="linux", supported=True)
        candidate = SshAgentRef(sock=str(coord.paths.keydir / "unused-test-agent.sock"), pid="123")
        coord.paths.write(candidate, _out())
        state.ssh.env = candidate
        monkeypatch.setattr(agents, "validate_ssh_socket", lambda sock: agents.SocketValidation(sock, True))
        monkeypatch.setattr(agents, "findpids", lambda _prog: [123])
        fingerprint = "SHA256:" + "A" * 43
        monkeypatch.setattr(state.ssh, "fingerprint", lambda _key: fingerprint)
        observations = []

        def query(cmd, **kwargs):
            assert cmd == ["ssh-add", "-l"]
            assert kwargs["env"]["SSH_AUTH_SOCK"] == candidate.sock
            lock = coord.state_lock()
            try:
                observations.append(lock.try_acquire())
            finally:
                lock.release()
            return subprocess.CompletedProcess(cmd, 0, stdout=f"256 {fingerprint} test (ED25519)\n")

        # Observe the real query call chain without allowing an unresponsive agent to hang pytest.
        monkeypatch.setattr(subprocess, "run", query)
        app = main.KeychainApp(args, _out())
        app._kstate = state
        if phase == "key-list":
            app._coordinate_ssh_keys(coord, main.keys.ResolvedKeys(ssh=["key-A"]))
        else:
            assert app._do_add(main.keys.ResolvedKeys()) == 0

        assert observations, "the requested key must be checked against the agent"
        assert all(observations), "an agent query must not prevent other terminals from acquiring the state lock"
        with coord.state_lock() as lock:
            assert lock.acquired

    @POSIX
    def test_wipe_ssh_cannot_clear_keys_while_another_terminal_loads_them(self, coord):
        args = RuntimeConfig.resolve(["wipe", "--ssh", "--lockwait", "0"])
        calls = []
        app = main.KeychainApp(args, _out())
        app._kstate = SimpleNamespace(
            args=args,
            paths=coord.paths,
            ssh=SimpleNamespace(wipe=lambda: calls.append("wipe")),
        )
        assert app._resolve_action() == "wipe"
        assert app._handle_wipe_action() == 0
        assert calls == ["wipe"], "an uncontended wipe must still work"
        calls.clear()

        with coord.activation() as owner:
            assert owner.acquired
            try:
                app._handle_wipe_action()
            except KeychainError as exc:
                assert "lock" in str(exc).lower()
        assert calls == [], "wipe must not clear keys while another terminal owns the activation lock"

    def test_signal_finalizes_state_before_releasing_lock(self, coord, monkeypatch):
        app = main.KeychainApp(RuntimeConfig.resolve(["add"]), _out())

        def interrupt(*args, **kwargs):
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)

        app._kstate = SimpleNamespace(
            ssh=SimpleNamespace(
                list_missing=lambda requested, **kwargs: list(requested),
                prepare_load=interrupt,
            )
        )
        saved = []
        original = CoordinationState.save

        def checked_save(state, path):
            with coord.activation_lock() as contender:
                saved.append((state.status, not contender.acquired))
            original(state, path)

        monkeypatch.setattr(CoordinationState, "save", checked_save)
        with pytest.raises(SystemExit):
            app._try_activation(coord, None, main.keys.ResolvedKeys(ssh=["key"]))
        if hasattr(os, "mkfifo"):
            assert saved == [("loading", True), ("failed", True)]
        with coord.activation_lock() as lock:
            assert lock.acquired

    def test_gpg_capabilities_are_warmed_once_with_cross_mode_deduplication(self):
        calls: list[tuple[str, list[str]]] = []

        class _GPG:
            def warm_signing(self, keys):
                calls.append(("sign", list(keys)))

            def warm_decryption(self, keys):
                calls.append(("decrypt", list(keys)))

        args = RuntimeConfig.resolve(["add"])
        app = main.KeychainApp(args, _out())
        app._kstate = SimpleNamespace(gpg=_GPG())

        requested = main.keys.ResolvedKeys(
            gpg=["A"],
            gpg_s=["A", "B"],
            gpg_e=["C", "D"],
            gpg_a=["B", "C"],
        )
        app._warm_gpg_keys(requested)

        assert calls == [("sign", ["A", "B", "C"]), ("decrypt", ["C", "D", "B"])]

    def test_bare_gpg_resolution_delegates_to_gnupg(self):
        calls: list[tuple[str, bool]] = []

        class _State:
            def resolve_requested_keys(self, _out, *, gpg_lookup=True):
                calls.append(("resolve", gpg_lookup))
                return main.keys.ResolvedKeys(gpg=["KEY"])

        app = main.KeychainApp(RuntimeConfig.resolve(["add", "KEY"]), _out())
        app._kstate = _State()

        resolved = app._resolve_add_keys()

        assert resolved.gpg == ["KEY"]
        assert calls == [("resolve", True)]

    def test_quick_bare_key_resolution_does_not_probe_gpg(self):
        class _State:
            def resolve_requested_keys(self, _out, *, gpg_lookup=True):
                assert gpg_lookup is False
                return main.keys.ResolvedKeys(missing=["KEY"])

        app = main.KeychainApp(RuntimeConfig.resolve(["add", "--quick", "KEY"]), _out())
        app._kstate = _State()

        assert app._resolve_add_keys().missing == ["KEY"]

    def test_explicit_ssh_key_uses_single_resolution_pass(self):
        class _State:
            def resolve_requested_keys(self, _out, *, gpg_lookup=True):
                assert gpg_lookup is True
                return main.keys.ResolvedKeys(missing=["ghost-key"])

        app = main.KeychainApp(RuntimeConfig.resolve(["add", "sshk:ghost-key"]), _out())
        app._kstate = _State()

        assert app._resolve_add_keys().missing == ["ghost-key"]

    def test_gpg_warmup_does_not_clear_cache(self):
        calls: list[str] = []

        class _GPG:
            def wipe(self):
                calls.append("wipe")

            def warm_signing(self, _keys):
                calls.append("sign")

            def warm_decryption(self, _keys):
                calls.append("decrypt")

        app = main.KeychainApp(RuntimeConfig.resolve(["add"]), _out())
        app._kstate = SimpleNamespace(gpg=_GPG())

        app._warm_gpg_keys(main.keys.ResolvedKeys(gpg_a=["KEY"]))

        assert calls == ["sign", "decrypt"]

    @pytest.mark.parametrize("quick_succeeded", [False, True])
    def test_quick_gpg_add_is_ssh_only(self, tmp_path, quick_succeeded):
        calls: list[str] = []

        class _SSH:
            env = SshAgentRef(sock="/tmp/agent.sock", pid="123")

            def start(self, state_lock):
                calls.append("ssh.start")
                return quick_succeeded

            def list_missing(self, ssh_keys, *, announce_known=True):
                assert ssh_keys == []
                return []

        app = main.KeychainApp(RuntimeConfig.resolve(["add", "--quick"]), _out())
        app._kstate = SimpleNamespace(
            paths=KeychainPaths(keydir=tmp_path, host="box"),
            ssh=_SSH(),
            gpg=object(),
        )

        assert app._do_add(main.keys.ResolvedKeys(gpg=["KEY"])) == 0
        assert calls == ["ssh.start"]

    def test_no_passphrase_starts_only_ssh_agent(self, tmp_path):
        calls: list[str] = []

        class _SSH:
            env = SshAgentRef(sock="/tmp/agent.sock", pid="123")

            def start(self, state_lock):
                calls.append("ssh.start")
                return False

        app = main.KeychainApp(RuntimeConfig.resolve(["add", "--no-passphrase"]), _out())
        app._kstate = SimpleNamespace(
            paths=KeychainPaths(keydir=tmp_path, host="box"),
            ssh=_SSH(),
            gpg=object(),
        )

        assert app._do_add(main.keys.ResolvedKeys(gpg=["KEY"])) == 0
        assert calls == ["ssh.start"]
