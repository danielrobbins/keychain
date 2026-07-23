# SPDX-License-Identifier: GPL-3.0-only
"""Tests for the bare env-file output (issue #116) and config-driven env overrides."""

from __future__ import annotations

import json

from keychain.agents import SocketValidation
from keychain.env import SshAgentRef
from keychain.main import main
from keychain.output.core import Output
from keychain.paths import KeychainPaths

# ---------------------------------------------------------------------------
# Issue #116: paths.write() produces a bare KEY=value sidecar
# ---------------------------------------------------------------------------


class TestEnvFileWritten:
    def test_envfile_path(self, tmp_path):
        p = KeychainPaths(keydir=tmp_path, host="myhost")
        assert p.pidfile_path("envfile") == tmp_path / "myhost-envfile"

    def test_write_emits_bare_envfile(self, tmp_path):
        p = KeychainPaths(keydir=tmp_path, host="myhost")
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        p.write(SshAgentRef("/tmp/agent.sock", "4242"), out)
        content = p.pidfile_path("envfile").read_text()
        # Bare KEY=value: no quotes, no export, no semicolons -- so
        # systemd EnvironmentFile= and docker --env-file accept it as-is.
        assert content == "SSH_AUTH_SOCK=/tmp/agent.sock\nSSH_AGENT_PID=4242\n"

    def test_clear_removes_envfile(self, short_keydir):
        p = KeychainPaths(keydir=short_keydir, host="myhost")
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        p.write(SshAgentRef("/x"), out)
        assert p.pidfile_path("envfile").is_file()
        p.clear()
        assert not p.pidfile_path("envfile").exists()


# ---------------------------------------------------------------------------
# CLI: ``keychain env`` formats
# ---------------------------------------------------------------------------


class TestEnvAction:
    """End-to-end of the env action. We populate a pidfile manually so
    no real ssh-agent is required."""

    def _setup_pidfile(self, tmp_path, monkeypatch):
        keydir = tmp_path / ".keychain"
        keydir.mkdir(mode=0o700)
        # Create a fake socket file the validity probe will accept by also
        # patching ssh_socket_valid below.
        sock = tmp_path / "agent.sock"
        sock.write_bytes(b"")
        pidfile = keydir / "myhost-sh"
        pidfile.write_text(
            f'SSH_AUTH_SOCK="{sock}"; export SSH_AUTH_SOCK\nSSH_AGENT_PID=99999; export SSH_AGENT_PID;\n'
        )
        pidfile.chmod(0o600)
        monkeypatch.setattr("socket.gethostname", lambda: "myhost")
        monkeypatch.setattr("keychain.agents.validate_ssh_socket", lambda path: SocketValidation(path, True))
        # Skip ssh-add probing (no real agent).
        monkeypatch.setattr(
            "keychain.agents.SshAgent.list_loaded",
            lambda self: ([], 0),
        )
        return keydir, sock

    def test_env_default_bare(self, tmp_path, monkeypatch, capsys):
        _kd, sock = self._setup_pidfile(tmp_path, monkeypatch)
        try:
            main(["env", "--dir", str(tmp_path)])
        except SystemExit as e:
            assert e.code in (None, 0)
        captured = capsys.readouterr().out
        assert f"SSH_AUTH_SOCK={sock}" in captured
        assert "SSH_AGENT_PID=99999" in captured
        # Bare format -- no shell decoration.
        assert "export" not in captured
        assert ";" not in captured

    def test_env_json(self, tmp_path, monkeypatch, capsys):
        _kd, sock = self._setup_pidfile(tmp_path, monkeypatch)
        try:
            main(["env", "--dir", str(tmp_path), "--shell", "json"])
        except SystemExit as e:
            assert e.code in (None, 0)
        data = json.loads(capsys.readouterr().out)
        assert data == {"SSH_AUTH_SOCK": str(sock), "SSH_AGENT_PID": "99999"}

    def test_env_systemd(self, tmp_path, monkeypatch, capsys):
        """systemd format == bare KEY=value, suitable for EnvironmentFile=."""
        _kd, sock = self._setup_pidfile(tmp_path, monkeypatch)
        try:
            main(["env", "--dir", str(tmp_path), "--shell", "systemd"])
        except SystemExit as e:
            assert e.code in (None, 0)
        out = capsys.readouterr().out
        assert out == f"SSH_AUTH_SOCK={sock}\nSSH_AGENT_PID=99999\n"

    def test_env_action_silent_when_no_agent(self, tmp_path, monkeypatch, capsys):
        """No pidfile, no inherited env -> empty stdout (no banner, no warnings)."""
        keydir = tmp_path / ".keychain"
        keydir.mkdir(mode=0o700)
        monkeypatch.setenv("HOSTNAME", "myhost")
        monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
        monkeypatch.delenv("SSH_AGENT_PID", raising=False)
        try:
            main(["env", "--dir", str(tmp_path)])
        except SystemExit as e:
            assert e.code in (None, 0)
        out = capsys.readouterr().out
        assert out == ""  # no agent, nothing to print -- machines parse this
