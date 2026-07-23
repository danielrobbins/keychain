# SPDX-License-Identifier: GPL-3.0-only
"""Tests for keychain.paths: KeychainPaths construction, parse, write."""

import os
import shlex
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from keychain.env import SshAgentRef
from keychain.paths import KeychainPaths
from keychain.util import KeychainError, Output
from tests.support import set_home


def _out():
    return Output.build(quiet=True, debug=False, eval_mode=False, color=False)


# ---------------------------------------------------------------------------
# KeychainPaths construction
# ---------------------------------------------------------------------------


class TestKeychainPathsBuild:
    def test_default_dir_uses_home_dot_keychain(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
        kp = KeychainPaths.build(None, False, "myhost")
        assert kp.keydir == tmp_path / ".keychain"
        assert kp.host == "myhost"

    def test_explicit_dir_appends_dot_keychain(self, tmp_path):
        kp = KeychainPaths.build(str(tmp_path), False, "h")
        assert kp.keydir == tmp_path / ".keychain"

    def test_absolute_flag_uses_dir_verbatim(self, tmp_path):
        kp = KeychainPaths.build(str(tmp_path), True, "h")
        assert kp.keydir == tmp_path

    def test_dotted_path_does_not_append_keychain(self):
        kp = KeychainPaths.build("/home/user/.mykeys", False, "h")
        assert kp.keydir == Path("/home/user/.mykeys").absolute()

    def test_tilde_dotted_path_expands_home(self, tmp_path, monkeypatch):
        set_home(monkeypatch, tmp_path)
        kp = KeychainPaths.build("~/.keychain", False, "h")
        assert kp.keydir == tmp_path / ".keychain"

    def test_tilde_base_path_expands_then_appends_dot_keychain(self, tmp_path, monkeypatch):
        set_home(monkeypatch, tmp_path)
        kp = KeychainPaths.build("~", False, "h")
        assert kp.keydir == tmp_path / ".keychain"

    def test_relative_dir_produces_absolute_runtime_paths(self, monkeypatch):
        base = Path(__file__).resolve().parents[1]
        monkeypatch.chdir(base)

        kp = KeychainPaths.build("state", True, "h")

        assert kp.keydir == base / "state"
        assert kp.pidfile_path("sh").is_absolute()
        assert kp.ssh_agent_socket_path.is_absolute()


class TestKeychainPathsProperties:
    def test_pidfile_names_include_host(self):
        kp = KeychainPaths(keydir=Path("/tmp/.keychain"), host="box")
        assert kp.pidfile_path("sh").name == "box-sh"
        assert kp.pidfile_path("csh").name == "box-csh"
        assert kp.pidfile_path("fish").name == "box-fish"
        assert kp.ssh_agent_socket_path.name == "JvhWfyVp.s"
        assert kp.lockf.name == "box-lockf"
        assert kp.state_file.name == "box.state.json"
        assert kp.state_lockf.name == "box.state.lock"
        assert kp.activation_lockf.name == "box.activation.lock"
        assert kp.waiters_dir.name == "box-waiters"

    def test_pidfile_for_fish(self):
        kp = KeychainPaths(keydir=Path("/tmp/.keychain"), host="box")
        assert kp.pidfile_path("fish") == kp.pidfile_path("fish")

    def test_socket_name_is_bounded_stable_host_hash(self):
        host = "iad20-gt1023-4ef95436-3063-42d9-a2d7-2851f55c9919-4E95ECC65C1E.local"
        kp = KeychainPaths(keydir=Path("/tmp/kc-ssh-5rkj146h/home/.keychain"), host=host)

        assert kp.ssh_agent_socket_path.name == "eB_JExAO.s"
        assert len(os.fsencode(kp.ssh_agent_socket_path)) <= 103

    @pytest.mark.skipif(os.name == "nt", reason="Unix socket path limits do not apply on Windows")
    def test_socket_path_rejects_keydir_that_cannot_fit_bounded_name(self):
        kp = KeychainPaths(keydir=Path("/tmp") / ("x" * 90), host="host")

        with pytest.raises(KeychainError, match="directory is too long"):
            _ = kp.ssh_agent_socket_path

    @pytest.mark.skipif(os.name == "nt", reason="Unix socket path limits do not apply on Windows")
    def test_clear_removes_pidfile_when_socket_path_is_too_long(self, tmp_path):
        kp = KeychainPaths(keydir=tmp_path / ("x" * 90), host="host")
        kp.keydir.mkdir()
        kp.pidfile_path("sh").write_text("stale\n", encoding="utf-8")
        with pytest.raises(KeychainError, match="directory is too long"):
            _ = kp.ssh_agent_socket_path

        kp.clear()

        assert not kp.pidfile_path("sh").exists()


# ---------------------------------------------------------------------------
# KeychainPaths.parse
# ---------------------------------------------------------------------------

SH_CONTENT = (
    'SSH_AUTH_SOCK="/tmp/ssh-XXX/agent.1234"; export SSH_AUTH_SOCK\nSSH_AGENT_PID=5678; export SSH_AGENT_PID;\n'
)


class TestKeychainPathsParse:
    def _kp(self):
        return KeychainPaths(keydir=Path("/tmp/.keychain"), host="test")

    def test_parses_sock_and_pid(self):
        env = SshAgentRef.from_text(SH_CONTENT)
        assert env.sock == "/tmp/ssh-XXX/agent.1234"
        assert env.pid == "5678"

    def test_empty_content_returns_empty_dict(self):
        assert SshAgentRef.from_text("") == SshAgentRef()

    def test_unrelated_lines_ignored(self):
        env = SshAgentRef.from_text("echo Agent pid 5678;\n")
        assert env == SshAgentRef()

    def test_parse_is_tolerant_of_missing_quotes(self):
        content = "SSH_AUTH_SOCK=/tmp/agent.99; export SSH_AUTH_SOCK\n"
        env = SshAgentRef.from_text(content)
        assert env.sock == "/tmp/agent.99"


# ---------------------------------------------------------------------------
# KeychainPaths.write + read round-trip
# ---------------------------------------------------------------------------

AGENT_SH_OUTPUT = (
    "SSH_AUTH_SOCK=/tmp/ssh-YYY/agent.9999; export SSH_AUTH_SOCK;\n"
    "SSH_AGENT_PID=1111; export SSH_AGENT_PID;\n"
    "echo Agent pid 1111;\n"
)


class TestKeychainPathsWriteRead:
    def test_write_creates_all_three_pidfiles(self, tmp_path):
        kp = KeychainPaths.build(
            dir_opt=str(tmp_path), absolute=True, host="box", pid_formats="sh,csh,fish,envfile,json"
        )
        kp.write(SshAgentRef.from_text(AGENT_SH_OUTPUT), _out())
        assert kp.pidfile_path("sh").exists()
        assert kp.pidfile_path("csh").exists()
        assert kp.pidfile_path("fish").exists()
        assert kp.pidfile_path("envfile").exists()
        assert kp.pidfile_path("json").exists()

    def test_sh_pidfile_is_parseable(self, tmp_path):
        kp = KeychainPaths(keydir=tmp_path, host="box")
        kp.write(SshAgentRef.from_text(AGENT_SH_OUTPUT), _out())
        env = SshAgentRef.from_text(kp.pidfile_path("sh").read_text())
        assert env.sock == "/tmp/ssh-YYY/agent.9999"
        assert env.pid == "1111"

    def test_csh_pidfile_uses_setenv_syntax(self, tmp_path):
        kp = KeychainPaths(keydir=tmp_path, host="box")
        kp.write(SshAgentRef.from_text(AGENT_SH_OUTPUT), _out())
        csh = kp.pidfile_path("csh").read_text()
        assert "setenv SSH_AUTH_SOCK" in csh
        assert "setenv SSH_AGENT_PID" in csh

    def test_fish_pidfile_uses_set_syntax(self, tmp_path):
        kp = KeychainPaths(keydir=tmp_path, host="box")
        kp.write(SshAgentRef.from_text(AGENT_SH_OUTPUT), _out())
        fish = kp.pidfile_path("fish").read_text()
        assert "set -x -U SSH_AUTH_SOCK" in fish
        assert "set -x -U SSH_AGENT_PID" in fish

    def test_clear_removes_pidfiles(self, short_keydir):
        kp = KeychainPaths(keydir=short_keydir, host="box")
        kp.write(SshAgentRef.from_text(AGENT_SH_OUTPUT), _out())
        kp.ssh_agent_socket_path.write_text("stale", encoding="utf-8")
        kp.clear()
        assert not kp.pidfile_path("sh").exists()
        assert not kp.pidfile_path("csh").exists()
        assert not kp.pidfile_path("fish").exists()
        assert not kp.ssh_agent_socket_path.exists()

    def test_write_uses_mkstemp_in_target_dir(self, tmp_path):
        kp = KeychainPaths(keydir=tmp_path, host="box")
        calls = []
        real_mkstemp = tempfile.mkstemp

        def fake_mkstemp(*args, **kwargs):
            calls.append((kwargs["prefix"], kwargs["suffix"], kwargs["dir"]))
            return real_mkstemp(*args, **kwargs)

        with patch("keychain.paths.tempfile.mkstemp", side_effect=fake_mkstemp):
            kp.write(SshAgentRef.from_text(AGENT_SH_OUTPUT), _out())

        assert calls == [
            (".box-sh.", ".tmp", tmp_path),
            (".box-csh.", ".tmp", tmp_path),
            (".box-fish.", ".tmp", tmp_path),
            (".box-envfile.", ".tmp", tmp_path),
        ]
        assert kp.pidfile_path("sh").exists()
        assert not (tmp_path / "box-sh.tmp").exists()


class TestKeychainPathsRenderEnv:
    def test_sh_output_renders_passed_env_not_pidfile(self, tmp_path):
        kp = KeychainPaths(keydir=tmp_path, host="box")
        kp.write(SshAgentRef(sock="/tmp/stale.sock", pid="9999"), _out())

        rendered = kp.render_env(SshAgentRef(sock="/tmp/live.sock", pid="1111"), "sh")

        assert "SSH_AUTH_SOCK=/tmp/live.sock" in rendered
        assert "SSH_AGENT_PID=1111" in rendered
        assert "/tmp/stale.sock" not in rendered

    def test_csh_output_renders_passed_env_not_pidfile(self, tmp_path):
        kp = KeychainPaths(keydir=tmp_path, host="box")
        kp.write(SshAgentRef(sock="/tmp/stale.sock", pid="9999"), _out())

        rendered = kp.render_env(SshAgentRef(sock="/tmp/live.sock", pid="1111"), "csh")

        assert "setenv SSH_AUTH_SOCK /tmp/live.sock;" in rendered
        assert "setenv SSH_AGENT_PID 1111;" in rendered
        assert "/tmp/stale.sock" not in rendered

    def test_fish_output_renders_passed_env_not_pidfile(self, tmp_path):
        kp = KeychainPaths(keydir=tmp_path, host="box")
        kp.write(SshAgentRef(sock="/tmp/stale.sock", pid="9999"), _out())

        rendered = kp.render_env(SshAgentRef(sock="/tmp/live.sock", pid="1111"), "fish")

        assert "set -x -U SSH_AUTH_SOCK '/tmp/live.sock';" in rendered
        assert "set -x -U SSH_AGENT_PID '1111';" in rendered
        assert "/tmp/stale.sock" not in rendered

    def test_eval_output_uses_shell_but_renders_passed_env(self, tmp_path):
        kp = KeychainPaths(keydir=tmp_path, host="box")
        kp.write(SshAgentRef(sock="/tmp/stale.sock", pid="9999"), _out())

        rendered = kp.render_env(
            SshAgentRef(sock="/tmp/live.sock", pid="1111"),
            "eval",
            {"SHELL": "/usr/bin/fish"},
        )

        assert "set -x -U SSH_AUTH_SOCK '/tmp/live.sock';" in rendered
        assert "set -x -U SSH_AGENT_PID '1111';" in rendered
        assert "/tmp/stale.sock" not in rendered

    def test_shell_renderers_quote_hostile_values(self, tmp_path):
        value = "/tmp/$(touch /tmp/keychain-pwn)/agent'quoted"
        env = SshAgentRef(sock=value, pid="1111")
        kp = KeychainPaths(keydir=tmp_path, host="box")

        assert f"SSH_AUTH_SOCK={shlex.quote(value)};" in kp.render_env(env, "sh")
        assert f"setenv SSH_AUTH_SOCK {shlex.quote(value)};" in kp.render_env(env, "csh")
        assert "set -x -U SSH_AUTH_SOCK '/tmp/$(touch /tmp/keychain-pwn)/agent\\'quoted';" in kp.render_env(
            env, "fish"
        )

    @pytest.mark.skipif(os.name == "nt", reason="requires a Bourne shell")
    def test_sh_output_treats_hostile_socket_as_data(self, tmp_path):
        marker = tmp_path / "injected"
        value = f"/tmp/$(touch {marker})/agent'quoted"
        rendered = KeychainPaths(keydir=tmp_path, host="box").render_env(SshAgentRef(sock=value, pid="1111"), "sh")

        result = subprocess.run(
            ["sh", "-c", f'{rendered}\nprintf "%s" "$SSH_AUTH_SOCK"'],
            text=True,
            capture_output=True,
            check=True,
        )

        assert result.stdout == value
        assert not marker.exists()

    def test_sh_pidfile_round_trips_quoted_socket(self, tmp_path):
        value = "/tmp/$(not-a-command)/agent'quoted"
        kp = KeychainPaths(keydir=tmp_path, host="box")
        kp.write(SshAgentRef(sock=value, pid="1111"), _out())

        parsed = SshAgentRef.from_text(kp.pidfile_path("sh").read_text(encoding="utf-8"))

        assert parsed == SshAgentRef(sock=value, pid="1111")

    def test_renderers_reject_line_injection(self, tmp_path):
        kp = KeychainPaths(keydir=tmp_path, host="box")

        with pytest.raises(KeychainError, match="line breaks"):
            kp.render_env(SshAgentRef(sock="/tmp/agent\nEVIL=value"), "env")


# ---------------------------------------------------------------------------
# check_runtime_perms: hard-fail on unsafe runtime storage
# ---------------------------------------------------------------------------


class TestCheckRuntimePerms:
    def test_no_pidfiles_no_error(self, tmp_path):
        kp = KeychainPaths(keydir=tmp_path, host="h")
        tmp_path.mkdir(exist_ok=True)
        with patch("keychain.paths.get_owner", return_value="me"), patch(
            "keychain.paths.lax_perms", return_value=False
        ):
            kp.check_runtime_perms("me")

    def test_owned_by_us_passes(self, tmp_path):
        kp = KeychainPaths(keydir=tmp_path, host="h")
        kp.pidfile_path("sh").write_text("SSH_AUTH_SOCK=/tmp/foo\n")
        with (
            patch("keychain.paths.get_owner", return_value="me"),
            patch("keychain.paths.lax_perms", return_value=False),
        ):
            kp.check_runtime_perms("me")

    def test_foreign_owner_raises_keychain_error(self, tmp_path):
        kp = KeychainPaths(keydir=tmp_path, host="h")
        kp.pidfile_path("sh").write_text("SSH_AUTH_SOCK=/tmp/foo\n")
        with patch(
            "keychain.paths.get_owner",
            side_effect=lambda path: "attacker" if Path(path) == kp.pidfile_path("sh") else "me",
        ), patch("keychain.paths.lax_perms", return_value=False):
            with pytest.raises(KeychainError, match="owned by attacker"):
                kp.check_runtime_perms("me")

    def test_lax_perms_raise_keychain_error(self, tmp_path):
        kp = KeychainPaths(keydir=tmp_path, host="h")
        kp.pidfile_path("sh").write_text("SSH_AUTH_SOCK=/tmp/foo\n")
        with patch("keychain.paths.get_owner", return_value="me"), patch(
            "keychain.paths.lax_perms", side_effect=lambda path: Path(path) == kp.pidfile_path("sh")
        ):
            with pytest.raises(KeychainError, match="lax permissions"):
                kp.check_runtime_perms("me")

    def test_coordination_state_is_checked(self, tmp_path):
        kp = KeychainPaths(keydir=tmp_path, host="h")
        kp.state_file.write_text("{}\n", encoding="utf-8")
        with patch(
            "keychain.paths.get_owner",
            side_effect=lambda path: "attacker" if Path(path) == kp.state_file else "me",
        ), patch("keychain.paths.lax_perms", return_value=False):
            with pytest.raises(KeychainError, match="owned by attacker"):
                kp.check_runtime_perms("me")


class TestEnsureKeydir:
    def test_existing_lax_directory_is_rejected_by_runtime_audit(self, tmp_path):
        keydir = tmp_path / ".keychain"
        keydir.mkdir(mode=0o700)
        kp = KeychainPaths(keydir=keydir, host="h")

        with patch("keychain.paths.get_owner", return_value="me"), patch("keychain.paths.lax_perms", return_value=True):
            with pytest.raises(KeychainError, match="lax permissions"):
                kp.check_runtime_perms("me")

    def test_creates_missing_directory(self, tmp_path):
        kp = KeychainPaths(keydir=tmp_path / ".keychain", host="h")

        kp.ensure_keydir()

        assert kp.keydir.is_dir()
