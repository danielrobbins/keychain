# SPDX-License-Identifier: GPL-3.0-only
"""Deterministic policy tests for --immediate activation."""

from __future__ import annotations

import contextlib
import os
import threading
import time
from types import SimpleNamespace

import pytest

from keychain import main
from keychain.agents import SshAddPlan
from keychain.coordination import ActivationCoordinator, WaitResult
from keychain.env import SshAgentRef
from keychain.output.core import Output
from keychain.paths import KeychainPaths
from keychain.runtime.config import RuntimeConfig
from keychain.util import KeychainError

pytestmark = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO support required")


def _out() -> Output:
    return Output.build(quiet=True, debug=False, eval_mode=False, color=False)


class _SharedSSH:
    env = SshAgentRef(sock="/tmp/agent.sock", pid="123")

    def __init__(self, loaded: threading.Event) -> None:
        self.loaded = loaded

    def list_missing(self, ssh_keys: list[str], *, announce_known: bool = True) -> list[str]:
        return [] if self.loaded.is_set() else list(ssh_keys)

    def announce_load(self, _missing: list[str], _pkcs11: list[str] | None = None) -> None:
        return None

    def prepare_load(
        self,
        missing: list[str],
        pkcs11: list[str] | None = None,
        *,
        announce: bool = True,
    ) -> SshAddPlan:
        return SshAddPlan([["ssh-add", *missing, *(pkcs11 or [])]], {"SSH_AUTH_SOCK": self.env.sock})

    def wipe(self) -> None:
        raise AssertionError("wipe should not run")


class _OwnerController:
    def __init__(self, loaded: threading.Event, statuses: list[str]) -> None:
        self.loaded = loaded
        self.statuses = statuses
        self.started = [threading.Event() for _ in statuses]
        self.release = [threading.Event() for _ in statuses]
        self.calls: list[list[str]] = []
        self._lock = threading.Lock()

    def factory(self, coord, waiter, requested_keys, _out):
        with self._lock:
            index = len(self.calls)
            if index >= len(self.statuses):
                raise AssertionError("unexpected additional activation attempt")
            self.calls.append(list(requested_keys))
        controller = self

        class _Owner:
            def run_ssh_add(self, _commands: list[list[str]], _env: dict[str, str]) -> str:
                with coord.state_lock():
                    state = coord.load_state()
                    coord.begin_activation(state, waiter, requested_keys)
                    coord.save_state(state)
                controller.started[index].set()
                if not controller.release[index].wait(timeout=5):
                    raise RuntimeError("test activation was not released")
                status = controller.statuses[index]
                if status == "success":
                    controller.loaded.set()
                return status

        return _Owner()


def _app(paths: KeychainPaths, ssh: _SharedSSH, *, immediate: bool) -> main.KeychainApp:
    args = RuntimeConfig.resolve(["add", "id_ed25519"])
    if immediate:
        args.rc_data = {"agent": {"immediate": "true"}}
    app = main.KeychainApp(args, _out())
    app._kstate = SimpleNamespace(paths=paths, user="tester", ssh=ssh, gpg=SimpleNamespace())
    return app


def _start(app: main.KeychainApp, coord: ActivationCoordinator):
    errors: list[BaseException] = []

    def run() -> None:
        try:
            app._coordinate_ssh_keys(coord, main.keys.ResolvedKeys(ssh=["id_ed25519"]), False)
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, errors


def _join(thread: threading.Thread) -> None:
    thread.join(timeout=7)
    assert not thread.is_alive()


def _install_owner(monkeypatch, controller: _OwnerController) -> None:
    monkeypatch.setattr(ActivationCoordinator, "can_prompt", lambda self: True)
    monkeypatch.setattr(main, "_activation_signals", contextlib.nullcontext)
    monkeypatch.setattr(main, "ActivationOwner", controller.factory)


def _mark_immediate_wait(monkeypatch) -> threading.Event:
    waiting = threading.Event()
    original = ActivationCoordinator.wait_for_notification

    def wait(self, waiter):
        waiting.set()
        return original(self, waiter)

    monkeypatch.setattr(ActivationCoordinator, "wait_for_notification", wait)
    return waiting


def test_immediate_skips_prompt_and_quiet_stays_silent(tmp_path, monkeypatch, capsys):
    paths = KeychainPaths(keydir=tmp_path, host="box")
    loaded = threading.Event()
    controller = _OwnerController(loaded, ["success"])
    controller.release[0].set()
    _install_owner(monkeypatch, controller)
    monkeypatch.setattr(
        ActivationCoordinator,
        "wait_for_activation_signal",
        lambda *_args, **_kwargs: pytest.fail("--immediate must not request terminal input"),
    )

    app = _app(paths, _SharedSSH(loaded), immediate=True)
    app._coordinate_ssh_keys(
        ActivationCoordinator(paths, False, 1, _out()),
        main.keys.ResolvedKeys(ssh=["id_ed25519"]),
        False,
    )

    assert controller.calls == [["id_ed25519"]]
    assert capsys.readouterr().err == ""


def test_activation_winner_rechecks_agent_before_loading(tmp_path, monkeypatch):
    paths = KeychainPaths(keydir=tmp_path, host="box")
    loaded = threading.Event()
    loaded.set()
    controller = _OwnerController(loaded, [])
    _install_owner(monkeypatch, controller)
    app = _app(paths, _SharedSSH(loaded), immediate=True)

    result = app._try_activation(
        ActivationCoordinator(paths, False, 1, _out()),
        None,
        main.keys.ResolvedKeys(ssh=["id_ed25519"]),
        False,
    )

    assert result == "success"
    assert controller.calls == []


def test_immediate_pair_runs_one_activation(tmp_path, monkeypatch):
    paths = KeychainPaths(keydir=tmp_path, host="box")
    loaded = threading.Event()
    controller = _OwnerController(loaded, ["success"])
    _install_owner(monkeypatch, controller)
    waiting = _mark_immediate_wait(monkeypatch)

    first = _app(paths, _SharedSSH(loaded), immediate=True)
    second = _app(paths, _SharedSSH(loaded), immediate=True)
    first_thread, first_errors = _start(first, ActivationCoordinator(paths, False, 1, _out()))
    assert controller.started[0].wait(timeout=2)
    second_thread, second_errors = _start(second, ActivationCoordinator(paths, False, 1, _out()))
    assert waiting.wait(timeout=2)

    controller.release[0].set()
    _join(first_thread)
    _join(second_thread)

    assert first_errors == []
    assert second_errors == []
    assert controller.calls == [["id_ed25519"]]


def test_immediate_owner_regular_waiter_uses_owner_result(tmp_path, monkeypatch):
    paths = KeychainPaths(keydir=tmp_path, host="box")
    loaded = threading.Event()
    controller = _OwnerController(loaded, ["success"])
    _install_owner(monkeypatch, controller)
    regular_waiting = threading.Event()

    def regular_wait(self, waiter, *, activation_active):
        if not activation_active:
            raise AssertionError("regular waiter should observe the immediate owner")
        regular_waiting.set()
        return self.wait_for_notification(waiter)

    monkeypatch.setattr(ActivationCoordinator, "wait_for_activation_signal", regular_wait)

    immediate = _app(paths, _SharedSSH(loaded), immediate=True)
    regular = _app(paths, _SharedSSH(loaded), immediate=False)
    owner_thread, owner_errors = _start(immediate, ActivationCoordinator(paths, False, 1, _out()))
    assert controller.started[0].wait(timeout=2)
    waiter_thread, waiter_errors = _start(regular, ActivationCoordinator(paths, False, 1, _out()))
    assert regular_waiting.wait(timeout=2)

    controller.release[0].set()
    _join(owner_thread)
    _join(waiter_thread)

    assert owner_errors == []
    assert waiter_errors == []
    assert controller.calls == [["id_ed25519"]]


def test_regular_owner_immediate_waiter_uses_owner_result(tmp_path, monkeypatch):
    paths = KeychainPaths(keydir=tmp_path, host="box")
    loaded = threading.Event()
    controller = _OwnerController(loaded, ["success"])
    _install_owner(monkeypatch, controller)
    immediate_waiting = _mark_immediate_wait(monkeypatch)

    def regular_activate(_self, _waiter, *, activation_active):
        if activation_active:
            raise AssertionError("regular owner should make the initial activation decision")
        return WaitResult("activate")

    monkeypatch.setattr(ActivationCoordinator, "wait_for_activation_signal", regular_activate)

    regular = _app(paths, _SharedSSH(loaded), immediate=False)
    immediate = _app(paths, _SharedSSH(loaded), immediate=True)
    owner_thread, owner_errors = _start(regular, ActivationCoordinator(paths, False, 1, _out()))
    assert controller.started[0].wait(timeout=2)
    waiter_thread, waiter_errors = _start(immediate, ActivationCoordinator(paths, False, 1, _out()))
    assert immediate_waiting.wait(timeout=2)

    controller.release[0].set()
    _join(owner_thread)
    _join(waiter_thread)

    assert owner_errors == []
    assert waiter_errors == []
    assert controller.calls == [["id_ed25519"]]


def test_immediate_failure_does_not_cascade_to_immediate_waiter(tmp_path, monkeypatch):
    paths = KeychainPaths(keydir=tmp_path, host="box")
    loaded = threading.Event()
    controller = _OwnerController(loaded, ["failed"])
    _install_owner(monkeypatch, controller)
    waiting = _mark_immediate_wait(monkeypatch)

    owner = _app(paths, _SharedSSH(loaded), immediate=True)
    waiter = _app(paths, _SharedSSH(loaded), immediate=True)
    owner_thread, owner_errors = _start(owner, ActivationCoordinator(paths, False, 1, _out()))
    assert controller.started[0].wait(timeout=2)
    waiter_thread, waiter_errors = _start(waiter, ActivationCoordinator(paths, False, 1, _out()))
    assert waiting.wait(timeout=2)

    controller.release[0].set()
    _join(owner_thread)
    _join(waiter_thread)

    assert len(owner_errors) == 1
    assert isinstance(owner_errors[0], KeychainError)
    assert len(waiter_errors) == 1
    assert isinstance(waiter_errors[0], KeychainError)
    assert controller.calls == [["id_ed25519"]]


def test_regular_waiter_can_retry_after_immediate_failure(tmp_path, monkeypatch):
    paths = KeychainPaths(keydir=tmp_path, host="box")
    loaded = threading.Event()
    controller = _OwnerController(loaded, ["failed", "success"])
    controller.release[1].set()
    _install_owner(monkeypatch, controller)
    regular_waiting = threading.Event()

    def regular_wait(self, waiter, *, activation_active):
        if activation_active:
            regular_waiting.set()
            return self.wait_for_notification(waiter)
        return WaitResult("activate")

    monkeypatch.setattr(ActivationCoordinator, "wait_for_activation_signal", regular_wait)

    immediate = _app(paths, _SharedSSH(loaded), immediate=True)
    regular = _app(paths, _SharedSSH(loaded), immediate=False)
    owner_thread, owner_errors = _start(immediate, ActivationCoordinator(paths, False, 1, _out()))
    assert controller.started[0].wait(timeout=2)
    waiter_thread, waiter_errors = _start(regular, ActivationCoordinator(paths, False, 1, _out()))
    assert regular_waiting.wait(timeout=2)

    controller.release[0].set()
    assert controller.started[1].wait(timeout=2)
    _join(owner_thread)
    _join(waiter_thread)

    assert len(owner_errors) == 1
    assert isinstance(owner_errors[0], KeychainError)
    assert waiter_errors == []
    assert controller.calls == [["id_ed25519"], ["id_ed25519"]]


def test_immediate_waiter_does_not_retry_after_regular_failure(tmp_path, monkeypatch):
    paths = KeychainPaths(keydir=tmp_path, host="box")
    loaded = threading.Event()
    controller = _OwnerController(loaded, ["failed"])
    _install_owner(monkeypatch, controller)
    immediate_waiting = _mark_immediate_wait(monkeypatch)
    monkeypatch.setattr(
        ActivationCoordinator,
        "wait_for_activation_signal",
        lambda _self, _waiter, *, activation_active: WaitResult("wait" if activation_active else "activate"),
    )

    regular = _app(paths, _SharedSSH(loaded), immediate=False)
    immediate = _app(paths, _SharedSSH(loaded), immediate=True)
    owner_thread, owner_errors = _start(regular, ActivationCoordinator(paths, False, 1, _out()))
    assert controller.started[0].wait(timeout=2)
    waiter_thread, waiter_errors = _start(immediate, ActivationCoordinator(paths, False, 1, _out()))
    assert immediate_waiting.wait(timeout=2)

    controller.release[0].set()
    _join(owner_thread)
    _join(waiter_thread)

    assert len(owner_errors) == 1
    assert isinstance(owner_errors[0], KeychainError)
    assert len(waiter_errors) == 1
    assert isinstance(waiter_errors[0], KeychainError)
    assert controller.calls == [["id_ed25519"]]


def test_regular_takeover_hands_immediate_owner_to_new_result(tmp_path, monkeypatch):
    paths = KeychainPaths(keydir=tmp_path, host="box")
    loaded = threading.Event()
    controller = _OwnerController(loaded, ["canceled", "success"])
    controller.release[1].set()
    _install_owner(monkeypatch, controller)
    takeover_started = threading.Event()
    busy_seen = threading.Event()
    release_owner_lock = threading.Event()

    def regular_takeover(_self, _waiter, *, activation_active):
        if not activation_active:
            raise AssertionError("regular process should observe the immediate owner")
        return WaitResult("takeover")

    def request_takeover(self, _waiter, timeout=5.0):
        takeover_started.set()
        controller.release[0].set()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            activation = self.load_state().activation
            if not activation.in_progress and activation.status == "canceled":
                return {"status": "canceled"}
            time.sleep(0.01)
        return {"status": "timeout"}

    monkeypatch.setattr(ActivationCoordinator, "wait_for_activation_signal", regular_takeover)
    monkeypatch.setattr(ActivationCoordinator, "request_takeover", request_takeover)

    immediate = _app(paths, _SharedSSH(loaded), immediate=True)
    regular = _app(paths, _SharedSSH(loaded), immediate=False)
    owner_coord = ActivationCoordinator(paths, False, 1, _out())
    regular_coord = ActivationCoordinator(paths, False, 1, _out())
    finish_activation = owner_coord.finish_activation
    activation_lock = regular_coord.activation_lock

    def finish_while_holding_lock(status):
        waiters = finish_activation(status)
        if status == "canceled" and not release_owner_lock.wait(timeout=2):
            raise RuntimeError("takeover did not encounter the held activation lock")
        return waiters

    @contextlib.contextmanager
    def observe_busy_lock():
        with activation_lock() as lock:
            if not lock.acquired:
                busy_seen.set()
                release_owner_lock.set()
            yield lock

    monkeypatch.setattr(owner_coord, "finish_activation", finish_while_holding_lock)
    monkeypatch.setattr(regular_coord, "activation_lock", observe_busy_lock)

    owner_thread, owner_errors = _start(immediate, owner_coord)
    assert controller.started[0].wait(timeout=2)
    takeover_thread, takeover_errors = _start(regular, regular_coord)
    assert takeover_started.wait(timeout=2)
    assert busy_seen.wait(timeout=2)
    assert controller.started[1].wait(timeout=2)

    _join(owner_thread)
    _join(takeover_thread)

    assert owner_errors == []
    assert takeover_errors == []
    assert controller.calls == [["id_ed25519"], ["id_ed25519"]]
