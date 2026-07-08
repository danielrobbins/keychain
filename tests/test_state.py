# SPDX-License-Identifier: GPL-3.0-only
"""Tests for :mod:`keychain.state`."""

import io
import sys
from contextlib import contextmanager
from unittest.mock import patch

import pytest

from keychain import agents, keys, state
from keychain.env import SshAgentRef
from keychain.output import inspect as inspect_view
from keychain.paths import KeychainPaths
from keychain.runtime import platform
from keychain.util import Output


@contextmanager
def _capture_stderr():
    buf = io.StringIO()
    old = sys.stderr
    sys.stderr = buf
    try:
        yield buf
    finally:
        sys.stderr = old


@pytest.fixture(autouse=True)
def _reset_runtime():
    platform.reset()
    yield
    platform.reset()


@pytest.fixture
def paths(tmp_path):
    keydir = tmp_path / ".keychain"
    keydir.mkdir(mode=0o700)
    return KeychainPaths(keydir=keydir, host="testhost")


@pytest.fixture
def out():
    return Output()


def test_cached_property_caches_underlying_call(paths):
    calls = {"n": 0}

    def fake_detect_ssh():
        calls["n"] += 1
        return True

    with patch.object(agents, "detect_ssh", fake_detect_ssh):
        st = state.KeychainState(paths=paths)
        assert st.openssh is True
        assert st.openssh is True
        assert calls["n"] == 1


def test_command_diagnostics_properties(paths):
    calls: list[tuple[str, ...]] = []

    class _R:
        def __init__(self, stdout: str = "", stderr: str = ""):
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(cmd, **_kwargs):
        calls.append(tuple(cmd))
        if cmd == ["ssh", "-V"]:
            return _R(stderr="OpenSSH_9.9p1, OpenSSL 1.1.1q  5 Jul 2022\n")
        if cmd == ["gpg", "--version"]:
            return _R(stdout="gpg (GnuPG) 2.4.7\nCopyright ...\n")
        raise AssertionError(f"unexpected command: {cmd!r}")

    with (
        patch.object(agents, "detect_ssh", return_value=True),
        patch("keychain.state.run", side_effect=fake_run),
        patch("keychain.state.shutil.which", side_effect=lambda cmd: f"/usr/bin/{cmd}"),
    ):
        st = state.KeychainState(paths=paths)
        assert st.ssh_implementation == "OpenSSH"
        assert st.ssh_version == "OpenSSH_9.9p1, OpenSSL 1.1.1q  5 Jul 2022"
        assert st.ssh_path == "/usr/bin/ssh"
        assert st.gpg_version == "gpg (GnuPG) 2.4.7"
        assert st.gpg_path == "/usr/bin/gpg"
        assert st.ssh_version == "OpenSSH_9.9p1, OpenSSL 1.1.1q  5 Jul 2022"
        assert st.gpg_version == "gpg (GnuPG) 2.4.7"
    assert calls == [("ssh", "-V"), ("gpg", "--version")]


def test_pidfile_section_with_dead_pid(paths):
    # No pidfile written -> all pidfile-related properties return falsy.
    st = state.KeychainState(paths=paths)
    assert st.pidfile_exists is False
    assert st.pidfile_content == ""
    assert st.pidfile_env == SshAgentRef()
    assert st.pidfile_socket == ""
    assert st.pidfile_pid == ""
    assert st.pidfile_socket_valid is False
    assert st.pidfile_pid_alive is False


def test_pidfile_section_with_invalid_socket(paths):
    paths.pidfile_path("sh").write_text(
        'SSH_AUTH_SOCK="/tmp/keychain-state-test-nonexistent/agent.42"; export SSH_AUTH_SOCK\n'
        "SSH_AGENT_PID=99999999; export SSH_AGENT_PID;\n"
    )
    st = state.KeychainState(paths=paths)
    assert st.pidfile_exists is True
    assert st.pidfile_socket.endswith("agent.42")
    assert st.pidfile_pid == "99999999"
    assert st.pidfile_socket_valid is False
    assert st.pidfile_socket_validation.reason == "missing"
    assert st.pidfile_pid_alive is False


def test_inherited_section_with_stale_socket(paths):
    env = {"SSH_AUTH_SOCK": "/tmp/keychain-state-test-stale/agent.0", "SSH_AGENT_PID": "99999999"}
    st = state.KeychainState(paths=paths, env=env)
    assert st.inherited_env == SshAgentRef.from_env(env)
    assert st.inherited_socket_valid is False
    assert st.inherited_socket_validation.reason == "missing"
    assert st.inherited_pid_alive is False


def test_inherited_env_empty_when_unset(paths):
    st = state.KeychainState(paths=paths, env={})
    assert st.inherited_env == SshAgentRef()
    assert st.inherited_socket == ""
    assert st.inherited_pid == ""


def test_keydir_introspection(paths):
    st = state.KeychainState(paths=paths)
    assert st.keydir_exists is True
    assert st.keydir_writable is True
    # On POSIX, mkdir(mode=0o700) yields tight perms; Windows ignores
    # POSIX bits (everything looks lax) so this assertion is POSIX-only.
    if sys.platform != "win32":
        assert st.keydir_lax_perms is False


def test_resolved_keys_classifies_real_and_missing(tmp_path, paths):
    real_key = tmp_path / "real_id"
    real_key.write_text("dummy")
    st = state.KeychainState(
        paths=paths,
        cmdline_keys=[str(real_key), "sshk:no-such-key-xyz"],
    )
    # Don't depend on whether `gpg` is installed in CI; both should resolve as
    # an SSH file and a missing key.
    assert any(p.endswith("real_id") for p in st.resolved_keys.ssh)
    assert "no-such-key-xyz" in st.resolved_keys.missing
    assert any(p.endswith("real_id") for p in st.ssh_keys)
    assert "no-such-key-xyz" in st.missing_keys


def test_resolved_keys_empty_when_no_args(paths):
    st = state.KeychainState(paths=paths)
    assert st.resolved_keys == keys.ResolvedKeys([], [], [], [], [], [], [])
    assert st.ssh_keys == []
    assert st.gpg_keys == []
    assert st.pkcs11_keys == []
    assert st.missing_keys == []


def test_render_inspect_emits_all_sections(paths, out):
    st = state.KeychainState(paths=paths)
    with _capture_stderr() as buf:
        inspect_view.render_inspect(st, out)
    text = buf.getvalue()
    # Section headings are now bare titles after the bar glyph (see
    # docs/output-design.md), no trailing colons or parens.
    for header in ("Platform", "Pidfile", "Loaded SSH keys", "Permissions"):
        assert header in text


def test_render_inspect_includes_resolved_keys_section_when_args(tmp_path, paths, out):
    real_key = tmp_path / "id_test"
    real_key.write_text("dummy")
    st = state.KeychainState(paths=paths, cmdline_keys=[str(real_key), "sshk:ghost"])
    with _capture_stderr() as buf:
        inspect_view.render_inspect(st, out)
    text = buf.getvalue()
    assert "Resolved keys" in text
    assert "id_test" in text
    assert "ghost" in text


def test_render_inspect_skips_resolved_keys_section_without_args(paths, out):
    st = state.KeychainState(paths=paths)
    with _capture_stderr() as buf:
        inspect_view.render_inspect(st, out)
    assert "Resolved keys" not in buf.getvalue()


def test_render_inspect_includes_socket_validation_reason(paths, out):
    paths.pidfile_path("sh").write_text(
        'SSH_AUTH_SOCK="/tmp/keychain-state-test-nonexistent/agent.42"; export SSH_AUTH_SOCK\n'
    )
    st = state.KeychainState(paths=paths)
    with _capture_stderr() as buf:
        inspect_view.render_inspect(st, out)
    assert "rejected socket (missing)" in buf.getvalue()


def test_render_inspect_json_emits_valid_object(paths, capsys):
    import json

    st = state.KeychainState(paths=paths)
    inspect_view.render_inspect_json(st)
    payload = json.loads(capsys.readouterr().out)
    # Spot-check the schema: a few sections must always be present.
    for key in ("platform", "ssh", "gpg", "pidfile", "inherited", "loaded_ssh_fingerprints", "permissions"):
        assert key in payload
    assert isinstance(payload["loaded_ssh_fingerprints"], list)
    assert payload["pidfile"]["exists"] is False
    assert payload["pidfile"]["socket_reason"] == "empty"
    assert payload["pidfile"]["socket_severity"] == ""
    assert "socket_reason" in payload["inherited"]
    assert "socket_severity" in payload["inherited"]
    assert "implementation" in payload["ssh"]
    assert "version" in payload["ssh"]
    assert "path" in payload["ssh"]
    assert "version" in payload["gpg"]
    assert "path" in payload["gpg"]
    # Permissions section has both the keydir facts and the audit rows.
    assert "keydir_path" in payload["permissions"]
    assert "audit" in payload["permissions"]


def test_render_inspect_json_includes_resolved_keys_when_args(tmp_path, paths, capsys):
    import json

    real_key = tmp_path / "id_test"
    real_key.write_text("dummy")
    st = state.KeychainState(paths=paths, cmdline_keys=[str(real_key), "sshk:ghost"])
    inspect_view.render_inspect_json(st)
    payload = json.loads(capsys.readouterr().out)
    assert "resolved_keys" in payload
    assert "ghost" in payload["resolved_keys"]["missing"]


# ---------------------------------------------------------------------------
# Foreign gpg-agent classification (issue #202)
# ---------------------------------------------------------------------------


class TestGpgPrimaryClassification:
    def test_primary_socket_under_homedir_is_ours(self, paths, tmp_path):
        gh = tmp_path / ".gnupg"
        gh.mkdir()
        sock = str(gh / "S.gpg-agent")
        with (
            patch.object(agents, "gpg_main_socket", return_value=sock),
            patch.object(agents, "gpg_user_homedirs", return_value=[gh.resolve()]),
        ):
            st = state.KeychainState(paths=paths)
            assert st.gpg_primary_socket_is_ours is True

    def test_foreign_socket_not_ours(self, paths, tmp_path):
        gh = tmp_path / ".gnupg"
        gh.mkdir()
        foreign = tmp_path / "zypp.XYZ"
        foreign.mkdir()
        sock = str(foreign / "S.gpg-agent")
        with (
            patch.object(agents, "gpg_main_socket", return_value=sock),
            patch.object(agents, "gpg_user_homedirs", return_value=[gh.resolve()]),
        ):
            st = state.KeychainState(paths=paths)
            assert st.gpg_primary_socket_is_ours is False

    def test_no_socket_is_not_ours(self, paths):
        with patch.object(agents, "gpg_main_socket", return_value=""):
            st = state.KeychainState(paths=paths)
            assert st.gpg_primary_socket_is_ours is False

    def test_foreign_agents_present_when_pids_but_no_primary(self, paths, tmp_path):
        # Simulates softmoth's #202: pids found, but socket not in our homedir.
        foreign = tmp_path / "zypp.XYZ"
        foreign.mkdir()
        sock = str(foreign / "S.gpg-agent")
        with (
            patch.object(agents, "gpg_main_socket", return_value=sock),
            patch.object(agents, "gpg_user_homedirs", return_value=[tmp_path / ".gnupg"]),
            patch.object(agents, "findpids", return_value=[4948]),
            patch.object(state.KeychainState, "process_listing_supported", True),
        ):
            st = state.KeychainState(paths=paths)
            assert st.gpg_foreign_agents_present is True

    def test_no_foreign_agents_when_socket_is_ours(self, paths, tmp_path):
        gh = tmp_path / ".gnupg"
        gh.mkdir()
        sock = str(gh / "S.gpg-agent")
        with (
            patch.object(agents, "gpg_main_socket", return_value=sock),
            patch.object(agents, "gpg_user_homedirs", return_value=[gh.resolve()]),
            patch.object(agents, "findpids", return_value=[3855]),
            patch.object(state.KeychainState, "process_listing_supported", True),
        ):
            st = state.KeychainState(paths=paths)
            assert st.gpg_foreign_agents_present is False

    def test_extras_alongside_ours_are_foreign(self, paths, tmp_path):
        # Primary socket is ours, but a second gpg-agent pid exists --
        # gpg-agent is single-instance per --homedir, so the extra
        # must belong to a different homedir (e.g. zypp).
        gh = tmp_path / ".gnupg"
        gh.mkdir()
        sock = str(gh / "S.gpg-agent")
        with (
            patch.object(agents, "gpg_main_socket", return_value=sock),
            patch.object(agents, "gpg_user_homedirs", return_value=[gh.resolve()]),
            patch.object(agents, "findpids", return_value=[3855, 4948]),
            patch.object(state.KeychainState, "process_listing_supported", True),
        ):
            st = state.KeychainState(paths=paths)
            assert st.gpg_foreign_agents_present is True

    def test_no_pids_means_no_foreign(self, paths):
        with (
            patch.object(agents, "gpg_main_socket", return_value=""),
            patch.object(agents, "findpids", return_value=[]),
            patch.object(state.KeychainState, "process_listing_supported", True),
        ):
            st = state.KeychainState(paths=paths)
            assert st.gpg_foreign_agents_present is False


# ---------------------------------------------------------------------------
# security_audit rows
# ---------------------------------------------------------------------------


class TestSecurityAudit:
    def test_keydir_owner_and_perms_rows_present(self, paths):
        with (
            patch("keychain.state.current_user", return_value="me"),
            patch("keychain.output.inspect.get_owner", return_value="me"),
            patch("keychain.output.inspect.os.stat") as st_mock,
        ):
            st_mock.return_value.st_mode = 0o40700  # dir, 0700
            ks = state.KeychainState(paths=paths)
            audit = ks.security_audit
            labels = [r[0] for r in audit]
            assert "keydir_owner" in labels
            assert "keydir_perms" in labels
            for label, value, hint, sev in audit:
                if label == "keydir_owner":
                    assert value == "me" and hint == "(you)" and sev == ""
                if label == "keydir_perms":
                    assert value == "0700" and hint == "" and sev == ""

    def test_keydir_lax_perms_emits_hint(self, paths):
        with (
            patch("keychain.state.current_user", return_value="me"),
            patch("keychain.output.inspect.get_owner", return_value="me"),
            patch("keychain.output.inspect.os.stat") as st_mock,
        ):
            st_mock.return_value.st_mode = 0o40777  # dir, 0777
            ks = state.KeychainState(paths=paths)
            row = next(r for r in ks.security_audit if r[0] == "keydir_perms")
            assert row[1] == "0777"
            assert "lax permissions" in row[2]
            assert row[3] == "warn"

    def test_foreign_keydir_owner_emits_hint(self, paths):
        with (
            patch("keychain.state.current_user", return_value="me"),
            patch("keychain.output.inspect.get_owner", return_value="attacker"),
            patch("keychain.output.inspect.os.stat") as st_mock,
        ):
            st_mock.return_value.st_mode = 0o40700
            ks = state.KeychainState(paths=paths)
            row = next(r for r in ks.security_audit if r[0] == "keydir_owner")
            assert row[1] == "attacker"
            assert "refusing to use" in row[2]
            assert row[3] == "warn"

    def test_foreign_gpg_socket_not_in_security_audit(self, paths, tmp_path):
        # GPG socket ownership is surfaced in the GPG panel (main socket hint),
        # not in security_audit. Verify audit has no gpg rows.
        foreign = tmp_path / "zypp.XYZ"
        foreign.mkdir()
        sock = str(foreign / "S.gpg-agent")
        with (
            patch.object(agents, "gpg_main_socket", return_value=sock),
            patch.object(agents, "gpg_user_homedirs", return_value=[tmp_path / ".gnupg"]),
        ):
            ks = state.KeychainState(paths=paths)
            labels = [r[0] for r in ks.security_audit]
            assert "gpg primary socket" not in labels
            assert "foreign gpg-agents" not in labels
