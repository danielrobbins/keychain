# SPDX-License-Identifier: GPL-3.0-only
"""Hidden processes are not dead processes, nor verified signal targets."""

import errno
import io
from unittest.mock import Mock

import pytest

from keychain import agents, state
from keychain.env import SshAgentRef
from keychain.output.core import Output
from keychain.paths import KeychainPaths
from keychain.runtime import platform


@pytest.mark.parametrize("name", ["linux", "linux2", "android"])
@pytest.mark.parametrize("error", [errno.ENOENT, errno.EACCES, errno.EPERM, errno.EIO, None])
@pytest.mark.parametrize("alive", [True, False])
def test_process_details_probe(monkeypatch, name, error, alive):
    def read(path, **_kwargs):
        assert path == "/proc/123/comm"
        if error:
            raise OSError(error, "test")
        return io.StringIO("python\n")

    def kill(pid, sig):
        assert (pid, sig) == (123, 0)
        if not alive:
            raise ProcessLookupError()

    monkeypatch.setattr(platform.os.path, "isdir", lambda _path: True)
    monkeypatch.setattr(platform, "open", read, raising=False)
    monkeypatch.setattr(platform.os, "kill", kill)
    assert platform._PosixPlatform(name).process_details_unavailable(123) is (
        alive and error in (errno.ENOENT, errno.EACCES, errno.EPERM)
    )


@pytest.mark.parametrize("name,proc", [("darwin", True), ("sunos5", True), ("linux", False), ("android", False)])
def test_no_visibility_inference_without_linux_proc(monkeypatch, name, proc):
    monkeypatch.setattr(platform.os.path, "isdir", lambda _path: proc)
    monkeypatch.setattr(platform, "open", lambda *_a, **_k: pytest.fail("must not read proc"), raising=False)
    assert not platform._PosixPlatform(name).process_details_unavailable(123)


@pytest.mark.parametrize("pid", [-1, 0, 2**64])
def test_invalid_pid_cannot_enable_fallback(monkeypatch, pid):
    def read(*_args, **_kwargs):
        raise FileNotFoundError()

    def kill(actual_pid, sig):
        assert actual_pid > 0 and sig == 0
        raise OverflowError()

    monkeypatch.setattr(platform.os.path, "isdir", lambda _path: True)
    monkeypatch.setattr(platform, "open", read, raising=False)
    monkeypatch.setattr(platform.os, "kill", kill)
    assert not platform._PosixPlatform("linux").process_details_unavailable(pid)


@pytest.fixture
def agent(tmp_path, monkeypatch):
    k = state.KeychainState(paths=KeychainPaths(keydir=tmp_path, host="test"), env={})
    k.platform = platform._PosixPlatform("linux")
    monkeypatch.setattr(agents, "findpids", lambda _name: [])
    monkeypatch.setattr(agents, "validate_ssh_socket", lambda sock: agents.SocketValidation(sock, True))
    monkeypatch.setattr(k.platform, "process_details_unavailable", lambda _pid: True)
    return agents.SshAgent(k, Output.build(quiet=False, debug=True, eval_mode=False, color=False))


@pytest.mark.parametrize("source", ["pidfile", "env", "selected"])
@pytest.mark.parametrize("status", [0, 1, 2])
def test_uninspectable_agent_requires_a_responding_socket(agent, monkeypatch, source, status):
    ref = SshAgentRef("/test.sock", "123")
    monkeypatch.setattr(agents, "ssh_l", lambda _env: ([], status))
    assert agent._validate_candidate(source, ref) == (ref if status != 2 else None)


@pytest.mark.parametrize("reason", ["foreign-owner", "symlink", "not-socket", "missing"])
def test_hidden_pid_does_not_bypass_socket_checks(agent, monkeypatch, reason):
    monkeypatch.setattr(agents, "validate_ssh_socket", lambda sock: agents.SocketValidation(sock, False, reason))
    monkeypatch.setattr(agents, "ssh_l", lambda _env: pytest.fail("must not contact rejected socket"))
    assert agent._validate_candidate("pidfile", SshAgentRef("/test.sock", "123")) is None


def test_visible_wrong_process_or_dead_pid_still_rejected(agent, monkeypatch):
    monkeypatch.setattr(agent.keychain_state.platform, "process_details_unavailable", lambda _pid: False)
    monkeypatch.setattr(agents, "ssh_l", lambda _env: pytest.fail("must reject PID first"))
    assert agent._validate_candidate("pidfile", SshAgentRef("/test.sock", "123")) is None


def test_verified_process_does_not_need_fallback_probe(agent, monkeypatch):
    monkeypatch.setattr(agents, "findpids", lambda _name: [123])
    monkeypatch.setattr(agent.keychain_state.platform, "process_details_unavailable", lambda _pid: pytest.fail("unneeded probe"))
    assert agent.keychain_state.ssh_pid_status(123) == "verified"


def test_process_status_is_rechecked_after_visibility_changes(agent, monkeypatch):
    pids = [123]
    monkeypatch.setattr(agents, "findpids", lambda _name: pids)
    assert agent.keychain_state.ssh_pid_status(123) == "verified"
    pids.clear()
    assert agent.keychain_state.ssh_pid_status(123) == "uninspectable"
    monkeypatch.setattr(agent.keychain_state.platform, "process_details_unavailable", lambda _pid: False)
    assert agent.keychain_state.ssh_pid_status(123) == "unverified"


@pytest.mark.parametrize("which", ["pidfile", "mine", "all", "others"])
@pytest.mark.parametrize("visible", [[], [456]])
def test_stop_never_signals_hidden_pid_and_keeps_its_reference(agent, monkeypatch, capsys, which, visible):
    ref = SshAgentRef("/test.sock", "123")
    monkeypatch.setattr(state.KeychainState, "pidfile_env", property(lambda _self: ref))
    monkeypatch.setattr(agents, "findpids", lambda _name: visible)
    clear = Mock()
    kill = Mock()
    monkeypatch.setattr(KeychainPaths, "clear", clear)
    monkeypatch.setattr(agents.os, "kill", kill)

    agent.stop(which)

    assert [call.args[0] for call in kill.call_args_list] == ([] if which == "pidfile" else visible)
    clear.assert_not_called()
    if which != "others":
        assert "pidfile kept" in capsys.readouterr().err
