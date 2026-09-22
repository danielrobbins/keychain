# SPDX-License-Identifier: GPL-3.0-only
"""Prompt/immediate policy matrix using real coordination and controlled key loading."""

from __future__ import annotations

import builtins
import contextlib
import os
import select
import threading
import time
from types import SimpleNamespace

import pytest

from keychain import main
from keychain.agents import SshAddPlan
from keychain.coordination import ActivationCoordinator, ActivationOwner, ActivationWaiter, WaitResult
from keychain.output.core import Output
from keychain.paths import KeychainPaths
from keychain.runtime.config import RuntimeConfig
from keychain.util import KeychainError

pytestmark = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO support required")


class World:
    def __init__(self, paths, statuses):
        self.paths, self.statuses = paths, statuses
        self.loaded = set()
        self.started = [threading.Event() for _ in statuses]
        self.release = [threading.Event() for _ in statuses]
        self.calls = []
        self.loaders = []
        self.terminals = []
        self.local = threading.local()
        self.out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)

    def run_child(self, owner, command, env):
        index = len(self.calls)
        self.calls.append(command)
        self.loaders.append(self.local.terminal)
        assert index < len(self.statuses), "unexpected additional activation"
        self.started[index].set()
        deadline = time.monotonic() + 5
        while not self.release[index].wait(0.01):
            if owner._canceled.is_set():
                return "canceled"
            if time.monotonic() >= deadline:
                raise RuntimeError("test did not release the loading operation")
        status = self.statuses[index]
        if status == "success":
            self.loaded.update(command[1:])
        return status

    def app(self, immediate):
        args = RuntimeConfig.resolve(["add", "id_ed25519"])
        args.rc_data = {"agent": {"activation": "immediate" if immediate else "prompt"}}
        app = main.KeychainApp(args, self.out)
        app._kstate = SimpleNamespace(
            ssh=SimpleNamespace(
                list_missing=lambda requested, **kwargs: [key for key in requested if key not in self.loaded],
                announce_load=lambda *args: None,
                prepare_load=lambda missing, pkcs11=None, **kwargs: SshAddPlan([["ssh-add", *missing]], {}),
            )
        )
        return app

    def start(self, immediate, keys=("id_ed25519",)):
        reader, writer = os.pipe()
        terminal = SimpleNamespace(reader=reader, writer=writer, waiting=threading.Event(), errors=[])

        def run():
            self.local.terminal = terminal
            try:
                self.app(immediate)._coordinate_ssh_keys(
                    ActivationCoordinator(self.paths, False, 1, self.out),
                    main.keys.ResolvedKeys(ssh=list(keys)),
                )
            except BaseException as exc:
                terminal.errors.append(exc)

        terminal.thread = threading.Thread(target=run, daemon=True)
        self.terminals.append(terminal)
        terminal.thread.start()
        return terminal

    def finish(self, *terminals):
        for terminal in terminals:
            terminal.thread.join(5)
            assert not terminal.thread.is_alive(), "terminal was stranded"

    def press(self, terminal, text="\n"):
        terminal.waiting.clear()
        os.write(terminal.writer, text.encode())


@pytest.fixture
def world(tmp_path, monkeypatch):
    worlds = []

    def make(statuses):
        world = World(KeychainPaths(keydir=tmp_path, host="box"), statuses)
        worlds.append(world)
        real_open, real_select = builtins.open, select.select

        def open_tty(path, *args, **kwargs):
            if path == "/dev/tty":
                return os.fdopen(os.dup(world.local.terminal.reader), "r")
            return real_open(path, *args, **kwargs)

        def watch_select(readers, *args):
            terminal = getattr(world.local, "terminal", None)
            if terminal is not None and args[-1:] != (0,):
                terminal.waiting.set()
            return real_select(readers, *args)

        monkeypatch.setattr(builtins, "open", open_tty)
        monkeypatch.setattr(select, "select", watch_select)
        monkeypatch.setattr(ActivationCoordinator, "can_prompt", lambda self: True)
        monkeypatch.setattr(main, "_activation_signals", contextlib.nullcontext)
        monkeypatch.setattr(ActivationOwner, "_run_child", lambda owner, cmd, env: world.run_child(owner, cmd, env))
        return world

    yield make
    for world in worlds:
        for release in world.release:
            release.set()
        for terminal in world.terminals:
            os.close(terminal.writer)
        for terminal in world.terminals:
            terminal.thread.join(6)
            os.close(terminal.reader)


def test_immediate_skips_prompt_and_quiet_stays_silent(world, capsys):
    w = world(["success"])
    owner = w.start(True)
    assert w.started[0].wait(3)
    w.release[0].set()
    w.finish(owner)
    assert not owner.errors
    assert w.calls == [["ssh-add", "id_ed25519"]]
    assert capsys.readouterr().err == ""


def test_activation_winner_rechecks_agent_before_loading(world):
    w = world([])
    w.loaded.add("id_ed25519")
    coord = ActivationCoordinator(w.paths, False, 1, w.out)
    assert w.app(True)._try_activation(coord, None, main.keys.ResolvedKeys(ssh=["id_ed25519"])) == "success"
    assert w.calls == []


@pytest.mark.parametrize(
    "owner_immediate,waiter_immediate", [(True, True), (True, False), (False, True), (False, False)]
)
def test_owner_waiter_matrix_runs_one_activation(world, owner_immediate, waiter_immediate):
    w = world(["success"])
    owner = w.start(owner_immediate)
    if not owner_immediate:
        assert owner.waiting.wait(3)
        w.press(owner)
    assert w.started[0].wait(3)
    waiter = w.start(waiter_immediate)
    assert waiter.waiting.wait(3)
    w.release[0].set()
    w.finish(owner, waiter)
    assert not owner.errors and not waiter.errors
    assert len(w.calls) == 1


@pytest.mark.parametrize("owner_immediate", [True, False])
def test_immediate_waiter_loads_its_different_key_after_owner_succeeds(world, owner_immediate):
    w = world(["success", "success"])
    owner = w.start(owner_immediate, keys=["key-A"])
    if not owner_immediate:
        assert owner.waiting.wait(3)
        w.press(owner)
    assert w.started[0].wait(3)
    waiter = w.start(True, keys=["key-B"])
    assert waiter.waiting.wait(3)
    assert w.calls == [["ssh-add", "key-A"]], "the second load must wait for the first"

    w.release[1].set()
    w.release[0].set()
    w.finish(owner, waiter)

    assert not owner.errors
    assert not waiter.errors, "another terminal's success must not prevent loading a different requested key"
    assert w.calls == [["ssh-add", "key-A"], ["ssh-add", "key-B"]]
    assert w.loaded == {"key-A", "key-B"}


@pytest.mark.parametrize("owner_immediate", [True, False])
def test_failure_does_not_cascade_to_immediate_waiter(world, owner_immediate):
    w = world(["failed"])
    owner = w.start(owner_immediate)
    if not owner_immediate:
        assert owner.waiting.wait(3)
        w.press(owner)
    assert w.started[0].wait(3)
    waiter = w.start(True)
    assert waiter.waiting.wait(3)
    w.release[0].set()
    w.finish(owner, waiter)
    assert len(owner.errors) == len(waiter.errors) == 1
    assert isinstance(owner.errors[0], KeychainError)
    assert isinstance(waiter.errors[0], KeychainError)
    assert len(w.calls) == 1


def test_regular_waiter_can_retry_after_immediate_failure(world):
    w = world(["failed", "success"])
    owner = w.start(True)
    assert w.started[0].wait(3)
    waiter = w.start(False)
    assert waiter.waiting.wait(3)
    waiter.waiting.clear()
    w.release[0].set()
    w.finish(owner)
    assert waiter.waiting.wait(3)
    w.press(waiter)
    assert w.started[1].wait(3)
    w.release[1].set()
    w.finish(waiter)
    assert len(owner.errors) == 1 and not waiter.errors
    assert len(w.calls) == 2


def test_regular_takeover_hands_immediate_owner_to_new_result(world):
    w = world(["canceled", "success"])
    owner = w.start(True)
    assert w.started[0].wait(3)
    waiter = w.start(False)
    assert waiter.waiting.wait(3)
    w.press(waiter, "takeover\n")
    assert w.started[1].wait(3)
    w.release[1].set()
    w.finish(owner, waiter)
    assert not owner.errors and not waiter.errors
    assert len(w.calls) == 2


@pytest.mark.parametrize("owner_immediate", [True, False])
def test_late_cancellation_preserves_requesting_terminal_after_timeout(world, monkeypatch, owner_immediate):
    w = world(["canceled", "success"])
    canceled = threading.Event()
    notify = ActivationCoordinator.notify_waiters

    def notify_and_signal(coord, attempt, status):
        notify(coord, attempt, status)
        if status == "canceled":
            canceled.set()

    def response_times_out(waiter):
        # Leave the real completion message for the next wait, as happens after a slow cancellation.
        w.release[0].set()
        assert canceled.wait(3)
        return WaitResult("timeout")

    monkeypatch.setattr(ActivationCoordinator, "notify_waiters", notify_and_signal)
    monkeypatch.setattr(ActivationWaiter, "request_takeover", response_times_out)
    owner = w.start(owner_immediate)
    if not owner_immediate:
        assert owner.waiting.wait(3)
        w.press(owner)
    assert w.started[0].wait(3)
    waiter = w.start(False)
    assert waiter.waiting.wait(3)
    w.press(waiter, "takeover\n")
    assert w.started[1].wait(3), "the requesting terminal must not require a second Enter after a late cancellation"
    assert w.loaders[1] is waiter
    w.release[1].set()
    w.finish(owner, waiter)
    assert not owner.errors and not waiter.errors
