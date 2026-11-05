# SPDX-License-Identifier: GPL-3.0-only
"""Tests for keychain.paths: KeychainPaths construction, parse, write."""

import os
import shlex
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from keychain import util
from keychain.env import SshAgentRef
from keychain.output.core import Output
from keychain.paths import KeychainPaths
from keychain.util import KeychainError
from tests.support import set_file_stat, set_home


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
        assert "set -x -g SSH_AUTH_SOCK" in fish
        assert "set -x -g SSH_AGENT_PID" in fish

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

        with patch("tempfile.mkstemp", side_effect=fake_mkstemp):
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
    @pytest.mark.parametrize(
        ("shell", "cleanup"),
        [("sh", "unset SSH_AGENT_PID;"), ("csh", "unsetenv SSH_AGENT_PID;"), ("fish", "set -x -g SSH_AGENT_PID '';")],
    )
    def test_socket_only_output_clears_stale_pid(self, tmp_path, shell, cleanup):
        paths = KeychainPaths(keydir=tmp_path, host="box")
        assert cleanup in paths.render_env(SshAgentRef(sock="/tmp/live.sock"), shell)
        assert paths.render_env(SshAgentRef(), shell) == ""

    @pytest.mark.skipif(os.name == "nt", reason="requires a Bourne shell")
    def test_socket_only_sh_output_removes_inherited_pid(self, tmp_path):
        rendered = KeychainPaths(keydir=tmp_path, host="box").render_env(SshAgentRef(sock="/tmp/live.sock"), "sh")
        result = subprocess.run(
            ["sh", "-c", rendered + 'test "$SSH_AUTH_SOCK" = /tmp/live.sock && test "${SSH_AGENT_PID+x}" != x'],
            env={**os.environ, "SSH_AUTH_SOCK": "/tmp/old.sock", "SSH_AGENT_PID": "9999"},
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr

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

        assert "set -x -g SSH_AUTH_SOCK '/tmp/live.sock';" in rendered
        assert "set -x -g SSH_AGENT_PID '1111';" in rendered
        assert "/tmp/stale.sock" not in rendered

    def test_eval_output_uses_shell_but_renders_passed_env(self, tmp_path):
        kp = KeychainPaths(keydir=tmp_path, host="box")
        kp.write(SshAgentRef(sock="/tmp/stale.sock", pid="9999"), _out())

        rendered = kp.render_env(
            SshAgentRef(sock="/tmp/live.sock", pid="1111"),
            "eval",
            {"SHELL": "/usr/bin/fish"},
        )

        assert "set -x -g SSH_AUTH_SOCK '/tmp/live.sock';" in rendered
        assert "set -x -g SSH_AGENT_PID '1111';" in rendered
        assert "/tmp/stale.sock" not in rendered

    def test_shell_renderers_quote_hostile_values(self, tmp_path):
        value = "/tmp/$(touch /tmp/keychain-pwn)/agent'quoted"
        env = SshAgentRef(sock=value, pid="1111")
        kp = KeychainPaths(keydir=tmp_path, host="box")

        assert f"SSH_AUTH_SOCK={shlex.quote(value)};" in kp.render_env(env, "sh")
        assert f"setenv SSH_AUTH_SOCK {shlex.quote(value)};" in kp.render_env(env, "csh")
        assert "set -x -g SSH_AUTH_SOCK '/tmp/$(touch /tmp/keychain-pwn)/agent\\'quoted';" in kp.render_env(env, "fish")

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


@pytest.fixture
def audited_paths(tmp_path, monkeypatch):
    monkeypatch.setattr("keychain.paths.current_uid", lambda: 1000)
    monkeypatch.setattr("keychain.paths.user_name", lambda uid: {1000: "me", 2000: "attacker"}.get(uid, str(uid)))
    set_file_stat(monkeypatch, tmp_path, mode=0o40700)
    return KeychainPaths(keydir=tmp_path, host="h")


class TestCheckRuntimePerms:
    def test_no_pidfiles_no_error(self, audited_paths):
        audited_paths.check_runtime_perms()
        assert [row.label for row in audited_paths.security_audit()] == ["keydir"]

    def test_owned_by_us_passes(self, audited_paths, monkeypatch):
        pidfile = audited_paths.pidfile_path("sh")
        pidfile.write_text("SSH_AUTH_SOCK=/tmp/foo\n")
        set_file_stat(monkeypatch, pidfile)
        audited_paths.check_runtime_perms()

    @pytest.mark.parametrize(
        "field", ["sh", "csh", "fish", "envfile", "state_file", "state_lockf", "activation_lockf", "waiters_dir"]
    )
    def test_foreign_runtime_owner_is_rejected(self, audited_paths, monkeypatch, field):
        path = (
            audited_paths.pidfile_path(field) if field in audited_paths.pid_formats else getattr(audited_paths, field)
        )
        path.touch()
        set_file_stat(monkeypatch, path, uid=2000)
        with pytest.raises(KeychainError, match="owned by attacker"):
            audited_paths.check_runtime_perms()

    def test_lax_perms_raise_keychain_error(self, audited_paths, monkeypatch):
        pidfile = audited_paths.pidfile_path("sh")
        pidfile.touch()
        set_file_stat(monkeypatch, pidfile, mode=0o100644)
        with pytest.raises(KeychainError, match="lax permissions"):
            audited_paths.check_runtime_perms()

    def test_each_path_is_statted_once(self, audited_paths, monkeypatch):
        original = Path.stat
        seen = []

        def record(path, *args, **kwargs):
            seen.append(path)
            return original(path, *args, **kwargs)

        monkeypatch.setattr(Path, "stat", record)
        audited_paths.check_runtime_perms()
        assert audited_paths.keydir in seen
        assert len(seen) == len(set(seen))


class TestEnsureKeydir:
    def test_existing_lax_directory_is_rejected_by_runtime_audit(self, audited_paths, monkeypatch):
        set_file_stat(monkeypatch, audited_paths.keydir, mode=0o40777)
        with pytest.raises(KeychainError, match="lax permissions"):
            audited_paths.check_runtime_perms()

    def test_creates_missing_directory(self, tmp_path):
        kp = KeychainPaths(keydir=tmp_path / ".keychain", host="h")

        kp.ensure_keydir()

        assert kp.keydir.is_dir()


class TestSecurityHardening:
    @pytest.mark.parametrize("lookup_error", [KeyError, OSError])
    @pytest.mark.parametrize(
        "owner_uid,mode,expected",
        [(1000, 0o40700, ""), (1000, 0o40777, "lax permissions"), (54321, 0o40700, "owned by")],
    )
    def test_missing_account_does_not_change_authorization(
        self, audited_paths, monkeypatch, lookup_error, owner_uid, mode, expected
    ):
        def missing(_uid):
            raise lookup_error("account lookup unavailable")

        monkeypatch.setattr(util, "_pwd", SimpleNamespace(getpwuid=missing))
        monkeypatch.setattr(util, "current_uid", lambda: 1000)
        monkeypatch.setattr("keychain.paths.user_name", util.user_name)
        set_file_stat(monkeypatch, audited_paths.keydir, uid=owner_uid, mode=mode)

        assert util.current_user() == "1000"
        row = audited_paths.security_audit()[0]
        assert row.owner == str(owner_uid)
        if expected:
            with pytest.raises(KeychainError, match=expected):
                audited_paths.check_runtime_perms()
        else:
            audited_paths.check_runtime_perms()

    def test_numeric_username_cannot_authorize_another_uid(self, audited_paths, monkeypatch):
        def lookup(uid):
            if uid == 1000:
                return SimpleNamespace(pw_name="54321")
            raise KeyError(uid)

        monkeypatch.setattr(util, "_pwd", SimpleNamespace(getpwuid=lookup))
        monkeypatch.setattr(util, "current_uid", lambda: 1000)
        monkeypatch.setattr("keychain.paths.user_name", util.user_name)
        set_file_stat(monkeypatch, audited_paths.keydir, uid=54321, mode=0o40700)

        assert util.current_user() == "54321"
        assert audited_paths.security_audit()[0].owner == "54321"
        with pytest.raises(KeychainError, match="not UID 1000"):
            audited_paths.check_runtime_perms()

    def test_unreadable_metadata_is_an_error(self, audited_paths, monkeypatch):
        original = Path.stat

        def unreadable(path, *args, **kwargs):
            if path == audited_paths.keydir:
                raise PermissionError("denied")
            return original(path, *args, **kwargs)

        monkeypatch.setattr(Path, "stat", unreadable)
        with pytest.raises(KeychainError, match="Cannot inspect"):
            audited_paths.check_runtime_perms()

    def test_socket_owner_is_checked_without_requiring_private_mode(self, audited_paths, monkeypatch):
        sock = audited_paths.keydir / "agent.sock"
        sock.touch()
        set_file_stat(monkeypatch, sock, mode=0o140777)
        assert audited_paths.security_audit(str(sock))[-1].severity == ""
        set_file_stat(monkeypatch, sock, uid=2000, mode=0o140777)
        assert audited_paths.security_audit(str(sock))[-1].severity == "err"

    def test_no_posix_uid_does_not_claim_owner_validation(self, audited_paths, monkeypatch):
        monkeypatch.setattr("keychain.paths.current_uid", lambda: None)
        set_file_stat(monkeypatch, audited_paths.keydir, mode=0o40777)
        row = audited_paths.security_audit()[0]
        assert row.owner == ""
        assert row.severity == ""

    @pytest.mark.parametrize("host", ["../evil", "a/b", "..", ".", "", "a\0b"])
    def test_host_cannot_leave_the_keydir(self, tmp_path, host):
        with pytest.raises(KeychainError, match="Invalid host name"):
            KeychainPaths.build(str(tmp_path), False, host)
