import json
import os
import socket
import sys
from pathlib import Path

import pytest

from keychain import main
from keychain.paths import _PID_FACTORIES
from keychain.runtime import platform
from tests.support import set_home

POSIX_AGENT_ONLY = pytest.mark.skipif(
    not platform.detect().supported,
    reason="agent lifecycle e2e coverage requires a supported POSIX-shaped host",
)
LINUX_AGENT_ONLY = pytest.mark.skipif(
    not platform.detect().supported or not sys.platform.startswith("linux"),
    reason="real ssh-agent lifecycle e2e coverage is Linux-only in CI",
)


class PlaybookRunner:
    """An isolated E2E execution environment for keychain commands."""

    def __init__(self, home: Path, monkeypatch, capsys):
        self.home = home
        self.keydir = home / ".keychain"
        self.monkeypatch = monkeypatch
        self.capsys = capsys

        # Enforce sandbox
        set_home(self.monkeypatch, home)
        self.monkeypatch.setenv("USER", "testuser")
        self.monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
        self.monkeypatch.delenv("SSH_AGENT_PID", raising=False)
        self.monkeypatch.delenv("HOSTNAME", raising=False)

        # Ensure tests don't randomly kill background user agents by accident.
        # `agent stop` in the tests relies on isolated mock pidfiles and mocked PIDs!
        # But, subprocess to `ssh-agent -k` relies on SSH_AGENT_PID and `kill` PID.
        # Wait, if we run in-process, keychain uses subprocess to spawn `ssh-agent`.
        # `ssh-agent` will be spawned locally on the host. We SHOULD clean it up properly.
        # It's actually good if it spawns a real `ssh-agent` and sets up the socket!

    def set_host(self, name: str, export_env: bool = False):
        """Mock the system hostname."""
        self.monkeypatch.setattr(socket, "gethostname", lambda: name)
        if export_env:
            self.monkeypatch.setenv("HOSTNAME", name)
        else:
            self.monkeypatch.delenv("HOSTNAME", raising=False)

    def run(self, *args, expect_exit: int = 0):
        """Run a keychain CLI command in-process."""
        # Clear out existing output buffer
        self.capsys.readouterr()

        exit_code = 0
        try:
            main.main(list(args))
        except SystemExit as e:
            exit_code = e.code or 0

        out, err = self.capsys.readouterr()

        if expect_exit is not None:
            assert exit_code == expect_exit, (
                f"Command {' '.join(args)} exited with {exit_code}, " f"expected {expect_exit}\nErr: {err}\nOut: {out}"
            )

        # Return stdout and stderr separately so they can be validated. Preserve this contract:
        return out, err


def from_json(output: str):
    """Helper to extract JSON from a command output that may contain logging."""
    for line in output.strip().splitlines():
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                pass
    raise ValueError(f"Could not find valid JSON in output:\n{output}")


def pidfile_variants():
    """Helper to generate all pidfile variants for a given host. "sh", "csh", "fish", "envfile", etc."""
    return list(_PID_FACTORIES.keys())


@pytest.fixture
def playbook(tmp_path, monkeypatch, capsys):
    """Yields a PlaybookRunner configured with a sandboxed tmp_path HOME."""
    runner = PlaybookRunner(tmp_path, monkeypatch, capsys)
    yield runner
    # We should probably run `agent stop --mine` just in case to clean up spawned agents!
    runner.run("agent", "stop", "--mine", expect_exit=None)


@LINUX_AGENT_ONLY
def test_basic_agent_lifecycle(playbook: PlaybookRunner):
    """Test that an agent can be started and isolated cleanly."""
    playbook.set_host("testhost")

    # 1. Start the agent (doesn't produce JSON natively, we just run it)
    playbook.run("--quiet", "agent", "start")

    # Assertions
    assert playbook.keydir.exists(), "Keydir was not created in the mocked HOME"
    assert (playbook.keydir / "testhost-sh").exists(), "Pidfile missing"

    # 2. Inspect should reveal running agents
    out, err = playbook.run("inspect", "--json")
    state = from_json(out)

    assert state["pidfile"]["pid_alive"] is True
    assert state["pidfile"]["socket_valid"] is True

    # Export it to the environment dynamically so subsequent calls know it's there
    playbook.monkeypatch.setenv("SSH_AUTH_SOCK", state["pidfile"]["ssh_auth_sock"])
    playbook.monkeypatch.setenv("SSH_AGENT_PID", str(state["pidfile"]["ssh_agent_pid"]))

    # 3. Stop the agent specifically for this host
    playbook.run("--quiet", "agent", "stop", "--mine")

    # 4. Inspect should reveal NO running agents
    out_after, err_after = playbook.run("inspect", "--json")
    state_after = from_json(out_after)
    assert state_after["pidfile"]["pid_alive"] is False


@LINUX_AGENT_ONLY
def test_hostname_variable_priority(playbook: PlaybookRunner):
    """Verify that socket.gethostname() accurately beats out stale $HOSTNAME variables."""
    # Set the bash env to something stale
    playbook.monkeypatch.setenv("HOSTNAME", "stale-bash-host")
    # Set the real socket system hostname to the truth
    playbook.set_host("true-socket-host")

    playbook.run("--quiet", "agent", "start")

    # Did it generate files using the proper truth?
    assert (playbook.keydir / "true-socket-host-sh").exists(), "Priority was wrong"
    assert not (playbook.keydir / "stale-bash-host-sh").exists(), "Used stale env var"


@LINUX_AGENT_ONLY
def test_tilde_expansion_bug(playbook: PlaybookRunner):
    """Verify that --dir ~/mykeys expands to the absolute path and not literally CWD/~"""
    playbook.set_host("testhost")
    # Make sure we're in some known directory
    os.chdir(str(playbook.home))

    playbook.run("agent", "start", "--quiet", "--dir", "~/mykeys", "--absolute")

    expected_dir = playbook.home / "mykeys"
    assert (expected_dir / "testhost-sh").exists()

    # check that nothing called '~' was literally made
    assert not Path("~").exists()
    assert not (playbook.home / "~").exists()


@LINUX_AGENT_ONLY
def test_stale_pidfile_cleanup(playbook: PlaybookRunner):
    """Verify that obsolete shell-variant pidfiles are wiped to prevent drift."""
    playbook.set_host("testhost")
    playbook.keydir.mkdir(parents=True, exist_ok=True)

    variants = pidfile_variants()
    for ext in variants:
        (playbook.keydir / f"testhost-{ext}").write_text("stale data")

    playbook.run("agent", "start", "--quiet")
    playbook.run("agent", "stop", "--quiet", "--mine")

    for ext in variants:
        stale_file = playbook.keydir / f"testhost-{ext}"
        assert not stale_file.exists(), f"Stale file {stale_file.name} was left behind!"


@LINUX_AGENT_ONLY
def test_eval_shell_output(playbook: PlaybookRunner):
    """Verify that --eval correctly generates eval-ready assignments."""
    playbook.set_host("testhost")
    out, err = playbook.run("agent", "start", "--quiet", "--eval")

    assert "SSH_AUTH_SOCK" in out, "eval output failed to include SSH_AUTH_SOCK"
    assert "SSH_AGENT_PID" in out, "eval output failed to include SSH_AGENT_PID"
    assert "export SSH_AUTH_SOCK" in out, "eval missed POSIX export statements"


@POSIX_AGENT_ONLY
def test_list_without_running_agent_reports_friendly_message(playbook: PlaybookRunner):
    """Verify that `list` turns ssh-add's no-agent exit into a friendly warning instead of leaking raw socket errors."""
    playbook.set_host("testhost")
    playbook.monkeypatch.setenv("SSH_AUTH_SOCK", str(playbook.home / "missing-agent.sock"))
    playbook.monkeypatch.setenv("SSH_AGENT_PID", "999999")

    out, err = playbook.run("list", expect_exit=0)

    assert out == ""
    assert "No agent is currently running." in err
    assert "Error connecting to agent" not in err
    assert "No such file or directory" not in err


def test_man_commands(playbook: PlaybookRunner):
    """Verify that keychain man and keychain man --list succeed."""
    out_man, err = playbook.run("man", expect_exit=0)
    assert out_man or err, "Expected output from keychain man"

    out_list, err = playbook.run("man", "--list", expect_exit=0)
    assert out_list or err, "Expected output from keychain man --list"


def test_wipe_routes_ssh_and_gpg_targets(playbook: PlaybookRunner, monkeypatch):
    """Verify wipe target routing for GPG-backed SSH agents (issue #163)."""
    from keychain import agents

    calls: list[str] = []

    monkeypatch.setattr(platform, "detect", lambda *_args, **_kwargs: platform._classify("linux", has_ps=True))
    monkeypatch.setattr(agents.SshAgent, "wipe", lambda self: calls.append("ssh"))
    monkeypatch.setattr(agents.GpgAgent, "wipe", lambda self: calls.append("gpg"))

    playbook.set_host("testhost")

    playbook.run("wipe", "--ssh")
    assert calls == ["ssh"]

    calls.clear()
    playbook.run("wipe", "--gpg")
    assert calls == ["gpg"]

    calls.clear()
    playbook.run("wipe")
    assert calls == ["ssh", "gpg"]


@POSIX_AGENT_ONLY
def test_add_with_only_missing_keys_does_not_start_agent(playbook: PlaybookRunner):
    """Verify that a fully unresolved SSH key does not spawn an agent as a side effect."""
    playbook.set_host("testhost")

    out, err = playbook.run("sshk:ghost-key", expect_exit=1)

    assert "No requested keys could be resolved" in err
    assert "Starting ssh-agent" not in err
    assert not (playbook.keydir / "testhost-sh").exists()


@LINUX_AGENT_ONLY
def test_inspect_command(playbook: PlaybookRunner):
    """Verify that keychain inspect successfully outputs state."""
    playbook.set_host("testhost")

    # Run inspect with NO agents
    text_out_empty, err = playbook.run("inspect", expect_exit=0)
    assert (
        "No keychain" in text_out_empty
        or "0" in text_out_empty
        or "keydir" in text_out_empty
        or "No keychain" in err
        or "0" in err
        or "keydir" in err
    )

    # Start an agent
    playbook.run("agent", "start", "--quiet")

    # Test standard text inspect
    text_out, err = playbook.run("inspect", expect_exit=0)
    assert (
        "ssh-agent" in text_out.lower()
        or "pidfile" in text_out.lower()
        or "ssh-agent" in err.lower()
        or "pidfile" in err.lower()
    )

    # Test json inspect directly
    out, err = playbook.run("inspect", "--json", expect_exit=0)
    json_out = from_json(out)
    assert isinstance(json_out, dict), "inspect --json should return a parsed JSON dict in PlaybookRunner"
    assert "pidfile" in json_out, "JSON output should contain 'pidfile'"


def test_version_json_emits_expected_keys(playbook: PlaybookRunner):
    """Verify that keychain version --json outputs expected payload."""
    out, err = playbook.run("version", "--json", expect_exit=0)
    payload = from_json(out)
    assert payload["name"] == "keychain"
    assert payload["implementation"] == "python"
    assert "version" in payload
    assert "url" in payload


@LINUX_AGENT_ONLY
def test_agent_args_from_env_and_config(playbook: PlaybookRunner):
    """Verify that agent args flow from environment and config file into subprocess calls."""
    import keychain.agents

    original_run = keychain.agents.run
    intercepted_cmds = []

    def mock_run(cmd, *args, **kwargs):
        intercepted_cmds.append(cmd)
        return original_run(cmd, *args, **kwargs)

    playbook.monkeypatch.setattr(keychain.agents, "run", mock_run)

    # 1. Test via environment (requires -E to allow KEYCHAIN_* env vars)
    playbook.monkeypatch.setenv("KEYCHAIN_SSH_AGENT_ARGS", "-t 3601")
    playbook.set_host("testhost-env")
    playbook.run("agent", "start", "--quiet", "-E")

    ssh_cmd_1 = next((c for c in intercepted_cmds if "ssh-agent" in c[0]), [])
    assert "-t" in ssh_cmd_1 and "3601" in ssh_cmd_1, f"SSH_AGENT_ARGS missing from environment; cmd: {ssh_cmd_1}"

    intercepted_cmds.clear()
    playbook.set_host("testhost-env-ignored")
    playbook.run("agent", "start", "--quiet")

    ssh_cmd_ignored = next((c for c in intercepted_cmds if "ssh-agent" in c[0]), [])
    assert "3601" not in ssh_cmd_ignored, f"SSH_AGENT_ARGS should require -E; cmd: {ssh_cmd_ignored}"

    intercepted_cmds.clear()
    playbook.monkeypatch.delenv("KEYCHAIN_SSH_AGENT_ARGS", raising=False)

    # 2. Test via .keychainrc
    rc = playbook.home / ".keychainrc"
    rc.write_text("[agent.env]\nssh_args=-t 3602\n")

    playbook.set_host("testhost-config")
    playbook.run("agent", "start", "--quiet")

    ssh_cmd_2 = next((c for c in intercepted_cmds if "ssh-agent" in c[0]), [])
    assert "-t" in ssh_cmd_2 and "3602" in ssh_cmd_2, f"SSH_AGENT_ARGS missing from config file; cmd: {ssh_cmd_2}"
