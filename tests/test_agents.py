# SPDX-License-Identifier: GPL-3.0-only
"""Tests for keychain.agents: fingerprint extraction, list dispatch and findpids."""

from __future__ import annotations

import os
import socket
import stat
from types import SimpleNamespace

import pytest

from keychain import agents
from keychain.agents import extract_fingerprints, findpids
from keychain.env import SshAgentRef
from keychain.runtime import platform
from keychain.util import Output


def _out(theme: str | None = None):
    return Output.build(quiet=True, debug=False, eval_mode=False, color=False, theme=theme)


# ---------------------------------------------------------------------------
# extract_fingerprints
# ---------------------------------------------------------------------------

# Representative ssh-add -l output (OpenSSH SHA256 format)
_SHA256_OUTPUT = """\
256 SHA256:abc123XYZdefGHI+jklMNO/pqr= /home/user/.ssh/id_rsa (RSA)
521 SHA256:uvwXYZ789+abc/def= /home/user/.ssh/id_ecdsa521 (ECDSA)
The agent has no identities.
"""

# Representative ssh-add -l output (legacy MD5 format)
_MD5_OUTPUT = """\
2048 aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99 /home/user/.ssh/id_rsa (RSA)
"""

# Some older implementations emit the bit-count in column 0 and MD5 in column 2
_MD5_COL2_OUTPUT = """\
RSA 1024 11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00 /path (RSA)
"""


class TestExtractFingerprints:
    def test_sha256_fingerprints_extracted(self):
        """Verify SHA256 fingerprints are parsed from standard ssh-add output because each key line exposes the fingerprint in column two."""
        fps = extract_fingerprints(_SHA256_OUTPUT)
        assert fps == [
            "SHA256:abc123XYZdefGHI+jklMNO/pqr=",
            "SHA256:uvwXYZ789+abc/def=",
        ]

    def test_md5_fingerprints_extracted(self):
        """Verify legacy MD5 fingerprints are preserved because older ssh-add formats still report identities with colon-delimited hashes."""
        fps = extract_fingerprints(_MD5_OUTPUT)
        assert len(fps) == 1
        assert fps[0] == "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"

    def test_md5_in_column_two_extracted(self):
        """Verify the parser accepts MD5 fingerprints from the alternate legacy column layout because some implementations print type, bits, then hash."""
        fps = extract_fingerprints(_MD5_COL2_OUTPUT)
        assert fps == ["11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00"]

    def test_empty_output_returns_empty_list(self):
        """Verify empty ssh-add output yields no fingerprints because there are no identity lines to parse."""
        assert extract_fingerprints("") == []

    def test_no_identities_line_returns_empty(self):
        """Verify the explicit no-identities banner produces an empty result because it is status text, not a key record."""
        assert extract_fingerprints("The agent has no identities.\n") == []

    def test_mixed_output_extracts_all(self):
        """Verify mixed SHA256 and MD5 listings are both collected because the extractor must handle both formats in one stream."""
        mixed = _SHA256_OUTPUT + _MD5_OUTPUT
        fps = extract_fingerprints(mixed)
        assert len(fps) == 3  # 2 SHA256 + 1 MD5

    def test_deduplication_not_performed(self):
        """Verify duplicate fingerprints are returned unchanged because de-duplication is the caller's responsibility, not the parser's."""
        # extract_fingerprints returns what it sees; dedup is the caller's job
        fps = extract_fingerprints(_SHA256_OUTPUT + _SHA256_OUTPUT)
        assert len(fps) == 4


class TestListSelection:
    def test_ssh_agent_defaults_to_find_active_agent_env(self):
        """Verify SshAgent starts from KeychainState.find_active_agent_env because that cached state is the single source of truth for live agent variables."""
        kstate = SimpleNamespace(find_active_agent_env=SshAgentRef(sock="/tmp/live.sock", pid="1111"))

        agent = agents.SshAgent(kstate, _out())

        assert agent.env == kstate.find_active_agent_env

    def test_render_list_table_uses_find_active_agent_env(self, monkeypatch, capsys):
        """Verify modern list rendering shells out with find_active_agent_env because stale pidfile values must not override the selected live agent."""
        seen = []

        def fake_run(cmd, env=None, **_kwargs):
            seen.append((cmd, env))
            return SimpleNamespace(returncode=0, stdout="256 SHA256:abc comment (ED25519)\n", stderr="")

        monkeypatch.setattr(agents, "run", fake_run)
        kstate = SimpleNamespace(
            find_active_agent_env=SshAgentRef(sock="/tmp/live.sock", pid="1111"),
            pidfile_env=SshAgentRef(sock="/tmp/stale.sock", pid="9999"),
            ssh=SimpleNamespace(passthrough=lambda _flag: 0),
        )

        assert agents.render_list_table(kstate, _out()) == 0
        assert len(seen) == 1
        assert seen[0][0] == ["ssh-add", "-l"]
        assert seen[0][1]["SSH_AUTH_SOCK"] == "/tmp/live.sock"
        assert seen[0][1]["SSH_AGENT_PID"] == "1111"
        assert "SHA256:abc" in capsys.readouterr().out


class TestSshAgentLoadOutput:
    def _agent(self, monkeypatch):
        def get_value(name):
            return {"no_gui": True, "confirm": False, "timeout": None}.get(name, False)

        kstate = SimpleNamespace(
            find_active_agent_env=SshAgentRef(sock="/tmp/agent.sock", pid="1111"),
            args=SimpleNamespace(get_value=get_value),
        )
        agent = agents.SshAgent(kstate, Output.build(quiet=False, debug=False, eval_mode=False, color=False))
        monkeypatch.setattr(agent, "envcheck", lambda *_args, **_kwargs: agent.env)
        monkeypatch.setattr(agents.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(returncode=0))
        return agent

    def test_multiple_loaded_keys_render_as_lists(self, monkeypatch, capsys):
        """Verify multi-key ssh-add output is readable instead of joining paths onto one long line."""
        assert self._agent(monkeypatch).load(["/home/user/.ssh/key1", "/home/user/.ssh/key2"]) is True

        err = capsys.readouterr().err
        assert "Need to add 2 ssh keys:" in err
        assert "   - /home/user/.ssh/key1" in err
        assert "   - /home/user/.ssh/key2" in err
        assert "Need to add 2 ssh keys: /home/user/.ssh/key1 /home/user/.ssh/key2" not in err
        assert "ssh-add: Identities added" not in err

    def test_single_loaded_key_uses_consistent_list_layout(self, monkeypatch, capsys):
        """Verify the common one-key path uses the same scannable layout as multi-key output."""
        assert self._agent(monkeypatch).load(["/home/user/.ssh/key1"]) is True

        err = capsys.readouterr().err
        assert "Need to add 1 ssh key:" in err
        assert "ssh-add: Identities added" not in err
        assert "   - /home/user/.ssh/key1" in err

    def test_prepare_load_keeps_force_askpass_without_display(self, monkeypatch):
        """Verify SSH_ASKPASS_REQUIRE=force survives because OpenSSH allows askpass without DISPLAY in that mode."""
        agent = self._agent(monkeypatch)
        agent.keychain_state.args.get_value = lambda name: {"no_gui": False, "confirm": True, "timeout": None}.get(
            name, False
        )
        monkeypatch.delenv("DISPLAY", raising=False)
        monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
        monkeypatch.setenv("SSH_ASKPASS", "/tmp/askpass")
        monkeypatch.setenv("SSH_ASKPASS_REQUIRE", "force")

        plan = agent.prepare_load(["/home/user/.ssh/key1"], announce=False)

        assert plan is not None
        assert plan.env["SSH_ASKPASS"] == "/tmp/askpass"
        assert plan.env["SSH_ASKPASS_REQUIRE"] == "force"

    def test_prepare_load_keeps_wayland_askpass(self, monkeypatch):
        """Verify WAYLAND_DISPLAY is treated like DISPLAY because OpenSSH accepts either as askpass-capable."""
        agent = self._agent(monkeypatch)
        agent.keychain_state.args.get_value = lambda name: {"no_gui": False, "confirm": True, "timeout": None}.get(
            name, False
        )
        monkeypatch.delenv("DISPLAY", raising=False)
        monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
        monkeypatch.setenv("SSH_ASKPASS", "/tmp/askpass")

        plan = agent.prepare_load(["/home/user/.ssh/key1"], announce=False)

        assert plan is not None
        assert plan.env["WAYLAND_DISPLAY"] == "wayland-0"
        assert plan.env["SSH_ASKPASS"] == "/tmp/askpass"

    def test_prepare_load_no_gui_blocks_askpass_force(self, monkeypatch):
        """Verify --no-gui removes askpass forcing because otherwise OpenSSH may still launch the fallback askpass."""
        agent = self._agent(monkeypatch)
        monkeypatch.setenv("DISPLAY", ":0")
        monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
        monkeypatch.setenv("SSH_ASKPASS", "/tmp/askpass")
        monkeypatch.setenv("SSH_ASKPASS_REQUIRE", "force")

        plan = agent.prepare_load(["/home/user/.ssh/key1"], announce=False)

        assert plan is not None
        for key in ("DISPLAY", "WAYLAND_DISPLAY", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE"):
            assert key not in plan.env

    def test_prepare_load_can_skip_announcement(self, monkeypatch, capsys):
        """Verify wait-driven activation can show the key list once before invoking ssh-add."""
        plan = self._agent(monkeypatch).prepare_load(["/home/user/.ssh/key1"], announce=False)

        assert plan is not None
        assert plan.commands == [["ssh-add", "/home/user/.ssh/key1"]]
        assert capsys.readouterr().err == ""

    def test_prepare_load_for_pkcs11_provider_uses_ssh_add_s(self, monkeypatch, capsys):
        plan = self._agent(monkeypatch).prepare_load([], ["/usr/lib/pkcs11/opensc-pkcs11.so"], announce=False)

        assert plan is not None
        assert plan.commands == [["ssh-add", "-s", "/usr/lib/pkcs11/opensc-pkcs11.so"]]
        assert capsys.readouterr().err == ""

    def test_prepare_load_combines_file_keys_and_pkcs11_provider(self, monkeypatch):
        plan = self._agent(monkeypatch).prepare_load(
            ["/home/user/.ssh/key1"], ["/usr/lib/pkcs11/opensc-pkcs11.so"], announce=False
        )

        assert plan is not None
        assert plan.commands == [
            ["ssh-add", "/home/user/.ssh/key1"],
            ["ssh-add", "-s", "/usr/lib/pkcs11/opensc-pkcs11.so"],
        ]

    def test_list_missing_pkcs11_skips_known_provider(self, monkeypatch):
        agent = self._agent(monkeypatch)
        monkeypatch.setattr(agent, "list_loaded", lambda: (["SHA256:known"], 0))
        monkeypatch.setattr(agents, "pkcs11_provider_fingerprints", lambda *_a, **_k: ["SHA256:known"])

        assert agent.list_missing_pkcs11(["/usr/lib/pkcs11/opensc-pkcs11.so"]) == []

    def test_list_missing_pkcs11_marks_unknown_provider_missing(self, monkeypatch):
        agent = self._agent(monkeypatch)
        monkeypatch.setattr(agent, "list_loaded", lambda: (["SHA256:known"], 0))
        monkeypatch.setattr(agents, "pkcs11_provider_fingerprints", lambda *_a, **_k: ["SHA256:other"])

        assert agent.list_missing_pkcs11(["/usr/lib/pkcs11/opensc-pkcs11.so"]) == ["/usr/lib/pkcs11/opensc-pkcs11.so"]


# ---------------------------------------------------------------------------
# gpg-agent wipe output
# ---------------------------------------------------------------------------


class TestGpgAgentEnvironment:
    def _agent(self, *, no_gui: bool):
        env = {
            "DISPLAY": ":0",
            "WAYLAND_DISPLAY": "wayland-0",
            "SSH_ASKPASS": "/tmp/askpass",
            "SSH_ASKPASS_REQUIRE": "force",
        }
        state = SimpleNamespace(env=env, args=SimpleNamespace(get_value=lambda name: no_gui if name == "no_gui" else None))
        return agents.GpgAgent(state, Output.silent())

    def test_no_gui_removes_x11_wayland_and_askpass(self):
        env = self._agent(no_gui=True)._gpg_env()

        for key in ("DISPLAY", "WAYLAND_DISPLAY", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE"):
            assert key not in env

    def test_gui_mode_preserves_wayland_environment(self):
        env = self._agent(no_gui=False)._gpg_env()

        assert env["DISPLAY"] == ":0"
        assert env["WAYLAND_DISPLAY"] == "wayland-0"


class TestGpgAgentWipe:
    def _agent(self, monkeypatch, returncode=1, stdout="", stderr="", debug=False):
        def fake_run(cmd, **kwargs):
            assert cmd == ["gpg-connect-agent", "--no-autostart"]
            assert kwargs["input_"] == "RELOADAGENT\n"
            assert kwargs["timeout"] == 5
            return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

        monkeypatch.setattr(agents, "run", fake_run)
        out = Output.build(quiet=False, debug=debug, eval_mode=False, color=False)
        return agents.GpgAgent(SimpleNamespace(), out)

    def test_blank_failure_is_quiet_by_default(self, monkeypatch, capsys):
        """Verify a no-agent/no-output gpg wipe failure does not render a janky empty output detail."""
        self._agent(monkeypatch, returncode=1).wipe()

        err = capsys.readouterr().err
        assert err == ""
        assert "output:" not in err

    def test_failure_details_are_debug_only(self, monkeypatch, capsys):
        """Verify non-empty gpg wipe diagnostics are available in debug mode without polluting normal startup output."""
        self._agent(monkeypatch, returncode=1, stderr="ERR 67108983 No agent running\n", debug=True).wipe()

        err = capsys.readouterr().err
        assert "gpg-agent could not remove identities" in err
        assert "No agent running" in err
        assert "output:" not in err

    def test_success_stays_visible(self, monkeypatch, capsys):
        """Verify a confirmed gpg-agent wipe still reports success to the user."""
        self._agent(monkeypatch, returncode=0, stdout="OK\n").wipe()

        assert "gpg-agent: All identities removed." in capsys.readouterr().err


# ---------------------------------------------------------------------------
# findpids
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not platform.detect().supported, reason="findpids requires a supported (POSIX-shaped) host")
class TestFindpids:
    def test_returns_list_of_ints(self):
        """Verify findpids returns integer process ids because callers use the result as numeric PIDs for follow-up probes."""
        result = findpids("ssh")
        assert isinstance(result, list)
        assert all(isinstance(p, int) for p in result)

    def test_current_python_process_not_in_ssh_agents(self):
        """Verify the pytest process is not reported as ssh-agent because process-name filtering should only match the requested daemon."""
        # The pytest runner should never appear as an ssh-agent.
        result = findpids("ssh")
        assert os.getpid() not in result

    def test_gpg_findpids_returns_list(self):
        """Verify gpg lookups also return integer PID lists because the helper supports both ssh-agent and gpg-agent discovery paths."""
        result = findpids("gpg")
        assert isinstance(result, list)
        assert all(isinstance(p, int) for p in result)

    def test_nonexistent_program_returns_empty(self):
        """Verify unknown program names produce no matches because the process scan should not fabricate PIDs for missing executables."""
        result = findpids("no-such-program-zzz")
        assert result == []


def test_findpids_matches_only_exact_agent_basename(monkeypatch):
    class FakePlatform:
        def process_list(self, pattern, uid):
            assert pattern.search("ssh-agent")
            assert pattern.search("/usr/bin/ssh-agent")
            assert not pattern.search("ssh-agent-helper")
            assert not pattern.search("not-ssh-agent")
            return [123]

    monkeypatch.setattr(platform, "detect", lambda: FakePlatform())

    assert findpids("ssh") == [123]


class TestSshAgentStop:
    def _agent(self, pid: str, cleared: list[bool]):
        state = SimpleNamespace(
            find_active_agent_env=SshAgentRef(sock="/tmp/agent.sock", pid=pid),
            pidfile_env=SshAgentRef(sock="/tmp/agent.sock", pid=pid),
            user="tester",
            paths=SimpleNamespace(clear=lambda: cleared.append(True)),
        )
        return agents.SshAgent(state, _out())

    def test_pidfile_stop_rejects_unverified_pid(self, monkeypatch):
        killed: list[int] = []
        cleared: list[bool] = []
        monkeypatch.setattr(agents, "findpids", lambda _prog: [123])
        monkeypatch.setattr(os, "kill", lambda pid, _sig: killed.append(pid))

        self._agent("999", cleared).stop("pidfile")

        assert killed == []
        assert cleared == [True]

    def test_pidfile_stop_terminates_verified_agent(self, monkeypatch):
        killed: list[int] = []
        cleared: list[bool] = []
        monkeypatch.setattr(agents, "findpids", lambda _prog: [123, 456])
        monkeypatch.setattr(os, "kill", lambda pid, _sig: killed.append(pid))

        self._agent("123", cleared).stop("pidfile")

        assert killed == [123]
        assert cleared == [True]


# ---------------------------------------------------------------------------
# ssh_socket_valid (owner check) and gpg_socket_is_primary
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX-only: socket owner check")
class TestSshSocketValid:
    def test_real_socket_owned_by_us_is_valid(self, tmp_path, monkeypatch):
        """Verify a real AF_UNIX socket owned by the current user is accepted because that is the expected shape of a usable SSH agent socket."""
        # macOS caps AF_UNIX paths at 104 bytes (Linux: 108); GitHub Actions
        # macos runners use long /private/var/folders/... TMPDIRs that
        # overflow this. Bind via a relative name from inside tmp_path so
        # the kernel only sees the short name.
        monkeypatch.chdir(tmp_path)
        sock_path = tmp_path / "agent.sock"
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind("agent.sock")
        try:
            assert agents.ssh_socket_valid(str(sock_path)) is True
            assert agents.validate_ssh_socket(str(sock_path)) == agents.SocketValidation(str(sock_path), True)
        finally:
            s.close()

    def test_regular_file_is_not_valid(self, tmp_path):
        """Verify regular files are rejected because only socket filesystem entries can back SSH_AUTH_SOCK."""
        f = tmp_path / "not_a_socket"
        f.write_text("x")
        assert agents.ssh_socket_valid(str(f)) is False
        assert agents.validate_ssh_socket(str(f)).reason == "not-socket"
        assert agents.validate_ssh_socket(str(f)).severity == "warn"

    def test_symlink_to_socket_is_not_valid(self, tmp_path, monkeypatch):
        """Verify symlinks are rejected because SSH_AUTH_SOCK should name the socket itself, not a redirected path."""
        monkeypatch.chdir(tmp_path)  # see note in test_real_socket_owned_by_us_is_valid
        sock_path = tmp_path / "agent.sock"
        link_path = tmp_path / "agent-link.sock"
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind("agent.sock")
        try:
            link_path.symlink_to(sock_path)
            assert agents.ssh_socket_valid(str(link_path)) is False
            assert agents.validate_ssh_socket(str(link_path)).reason == "symlink"
            assert agents.validate_ssh_socket(str(link_path)).severity == "err"
        finally:
            s.close()

    def test_missing_path_is_not_valid(self, tmp_path):
        """Verify missing paths are rejected because a nonexistent socket cannot connect to an agent."""
        assert agents.ssh_socket_valid(str(tmp_path / "nope")) is False
        assert agents.validate_ssh_socket(str(tmp_path / "nope")).reason == "missing"

    def test_empty_path_is_not_valid(self):
        """Verify the empty path is rejected because there is no socket location to validate."""
        assert agents.ssh_socket_valid("") is False
        assert agents.validate_ssh_socket("").reason == "empty"

    def test_foreign_owner_rejected(self, tmp_path, monkeypatch):
        """Verify sockets owned by another uid are rejected because keychain must not trust foreign agent endpoints."""
        monkeypatch.chdir(tmp_path)  # see note in test_real_socket_owned_by_us_is_valid
        sock_path = tmp_path / "agent.sock"
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind("agent.sock")
        try:
            # Pretend our uid is one we definitely don't match.
            real_uid = os.getuid()
            monkeypatch.setattr(os, "getuid", lambda: real_uid + 99999)
            assert agents.ssh_socket_valid(str(sock_path)) is False
            assert agents.validate_ssh_socket(str(sock_path)).reason == "foreign-owner"
            assert agents.validate_ssh_socket(str(sock_path)).severity == "err"
        finally:
            s.close()


class TestGpgSocketIsPrimary:
    def test_socket_under_gnupghome_is_primary(self, tmp_path):
        """Verify a socket inside GNUPGHOME is treated as primary because that directory explicitly defines the active GnuPG home."""
        gh = tmp_path / "gnupg"
        gh.mkdir()
        sock = gh / "S.gpg-agent"
        env = {"GNUPGHOME": str(gh), "HOME": str(tmp_path)}
        assert agents.gpg_socket_is_primary(str(sock), env=env, uid=1000)

    def test_socket_under_home_dot_gnupg_is_primary(self, tmp_path):
        """Verify a socket inside HOME/.gnupg is treated as primary because that is GnuPG's default home when GNUPGHOME is unset."""
        (tmp_path / ".gnupg").mkdir()
        sock = tmp_path / ".gnupg" / "S.gpg-agent"
        env = {"HOME": str(tmp_path)}
        assert agents.gpg_socket_is_primary(str(sock), env=env, uid=1000)

    def test_foreign_homedir_rejected(self, tmp_path):
        """Verify sockets under an unrelated homedir are rejected because package-manager scratch agents must not be mistaken for the user's primary agent."""
        # Simulates package-manager: gpg-agent --homedir /var/tmp/zypp.X
        foreign = tmp_path / "zypp.XXX"
        foreign.mkdir()
        sock = foreign / "S.gpg-agent"
        env = {"HOME": str(tmp_path / "home"), "GNUPGHOME": str(tmp_path / "home" / ".gnupg")}
        assert not agents.gpg_socket_is_primary(str(sock), env=env, uid=1000)

    def test_empty_socket_rejected(self):
        """Verify an empty socket path is rejected because there is no candidate GnuPG socket to classify as primary."""
        assert not agents.gpg_socket_is_primary("", env={"HOME": "/x"}, uid=1000)


# ---------------------------------------------------------------------------
# Issue #181: don't claim "forwarded socket" when source is unknown
# ---------------------------------------------------------------------------


class TestSshEnvcheckUnknownSource:
    """When SSH_AUTH_SOCK is valid but no SSH_AGENT_PID and not GnuPG,
    the message must be honest (path included, source called unknown)."""

    def test_unknown_source_message_includes_path_and_does_not_claim_forwarded(self, tmp_path, monkeypatch):
        """Verify envcheck names an otherwise valid socket as unknown source because without PID or GnuPG evidence it must not claim the socket was forwarded."""
        sock_path = tmp_path / "agent.sock"
        sock_path.write_text("")  # placeholder; validate_ssh_socket is mocked
        captured: list[str] = []

        class _Out:
            def debug(self, msg):
                captured.append(msg)

            def mesg(self, msg):
                captured.append(msg)

            def note(self, msg):
                captured.append(msg)

            def warn(self, msg):
                captured.append(msg)

            def c(self, _):
                return ""

        # Pretend the socket is valid and that GnuPG isn't supplying it,
        # so we hit the "unknown source" branch.
        monkeypatch.setattr(agents, "validate_ssh_socket", lambda sock: agents.SocketValidation(sock, True))
        monkeypatch.setattr(agents, "gpg_ssh_socket", lambda: None)

        env = SshAgentRef(str(sock_path))
        # Build a minimal SshAgent: envcheck reads self._allow_gpg and
        # self._allow_forwarded (latched by start()), self.out, and the host
        # probes validate_ssh_socket / gpg_ssh_socket which we mocked above.
        from keychain import state
        from keychain.paths import KeychainPaths

        kstate = state.KeychainState(paths=KeychainPaths(keydir=tmp_path, host="h"))
        agent = agents.SshAgent(kstate, _Out())
        ok = agent.envcheck("env", env, quick=False)
        assert ok is None
        joined = " ".join(captured)
        assert str(sock_path) in joined
        assert "forwarded" not in joined.lower()


class TestSshAgentStartupOutput:
    def _agent_with_args(self, keydir, *extra_args):
        from keychain import state
        from keychain.paths import KeychainPaths
        from keychain.runtime.config import RuntimeConfig

        args = RuntimeConfig.resolve(["add", "--no-inherit", *extra_args])
        paths = KeychainPaths(keydir=keydir, host="h")
        kstate = state.KeychainState(paths=paths, env={}, args=args)
        out = Output.build(quiet=False, debug=False, eval_mode=False, color=False)
        return agents.SshAgent(kstate, out), paths

    def _fake_spawn(self, monkeypatch):
        def fake_run(cmd, *_args, **_kwargs):
            assert cmd[0] == "ssh-agent"
            return SimpleNamespace(
                returncode=0,
                stdout='SSH_AUTH_SOCK="/tmp/keychain-test-agent.sock"; export SSH_AUTH_SOCK\n'
                "SSH_AGENT_PID=12345; export SSH_AGENT_PID;\n",
                stderr="",
            )

        monkeypatch.setattr(agents, "run", fake_run)

    def test_stale_pidfile_socket_missing_is_spawn_context(self, tmp_path, short_keydir, monkeypatch, capsys):
        """Verify common WSL-style stale pidfiles are folded into the spawn line instead of a standalone note."""
        agent, paths = self._agent_with_args(short_keydir)
        paths.write(SshAgentRef(sock=str(tmp_path / "missing-agent.sock"), pid="999999"), _out())
        self._fake_spawn(monkeypatch)

        agent.start(ssh_spawn_gpg=False, ssh_allow_gpg=False)

        err = capsys.readouterr().err
        assert "Starting ssh-agent (previous pidfile stale: socket missing)..." in err
        assert "SSH_AUTH_SOCK in pidfile points" not in err

    def test_suspicious_pidfile_socket_rejection_stays_visible(self, tmp_path, short_keydir, monkeypatch, capsys):
        """Verify non-stale-looking socket failures still warn because they may indicate bad state."""
        agent, paths = self._agent_with_args(short_keydir)
        bad_sock = tmp_path / "not-a-socket"
        bad_sock.write_text("not a socket", encoding="utf-8")
        paths.write(SshAgentRef(sock=str(bad_sock), pid="999999"), _out())
        self._fake_spawn(monkeypatch)

        agent.start(ssh_spawn_gpg=False, ssh_allow_gpg=False)

        err = capsys.readouterr().err
        assert "SSH_AUTH_SOCK in pidfile points" in err
        assert "rejected socket (not-socket)" in err
        assert "Starting ssh-agent..." in err
        assert "previous pidfile stale" not in err

    def test_spawned_agent_uses_returned_environment(self, short_keydir, monkeypatch):
        agent, _paths = self._agent_with_args(short_keydir)
        self._fake_spawn(monkeypatch)

        agent.start(ssh_spawn_gpg=False, ssh_allow_gpg=False)

        assert agent.env.sock == "/tmp/keychain-test-agent.sock"
        assert agent.env.pid == "12345"

    def test_spawn_failure_reports_ssh_agent_error(self, short_keydir, monkeypatch):
        agent, _paths = self._agent_with_args(short_keydir)
        monkeypatch.setattr(
            agents,
            "run",
            lambda *_args, **_kwargs: SimpleNamespace(
                returncode=1,
                stdout="",
                stderr="unix_listener: path too long for Unix domain socket\n",
            ),
        )

        with pytest.raises(agents.KeychainError, match="path too long for Unix domain socket"):
            agent.start(ssh_spawn_gpg=False, ssh_allow_gpg=False)

    def test_unparseable_spawn_output_is_rejected(self, short_keydir, monkeypatch):
        agent, _paths = self._agent_with_args(short_keydir)
        monkeypatch.setattr(
            agents,
            "run",
            lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="Agent pid 12345\n", stderr=""),
        )

        with pytest.raises(agents.KeychainError, match="did not return its socket information"):
            agent.start(ssh_spawn_gpg=False, ssh_allow_gpg=False)

    def test_confirm_and_no_gui_are_rejected(self, short_keydir):
        """Confirmation must fail closed instead of silently loading an unconstrained key."""
        agent, _paths = self._agent_with_args(short_keydir, "--confirm", "--no-gui")

        with pytest.raises(agents.KeychainError, match="requires graphical confirmation"):
            agent.start(ssh_spawn_gpg=False, ssh_allow_gpg=False)

    def test_macos_confirm_configures_new_agent_with_native_askpass(self, short_keydir, monkeypatch):
        """A managed macOS agent must inherit the helper needed for later signing prompts."""
        agent, paths = self._agent_with_args(short_keydir, "--confirm")
        monkeypatch.setattr(agent.keychain_state, "platform", SimpleNamespace(name="darwin"))
        captured_env = None

        def fake_run(cmd, *_args, **kwargs):
            nonlocal captured_env
            assert cmd[0] == "ssh-agent"
            captured_env = kwargs["env"]
            return SimpleNamespace(
                returncode=0,
                stdout='SSH_AUTH_SOCK="/tmp/keychain-test-agent.sock"; export SSH_AUTH_SOCK\n'
                "SSH_AGENT_PID=12345; export SSH_AGENT_PID;\n",
                stderr="",
            )

        monkeypatch.setattr(agents, "run", fake_run)

        agent.start(ssh_spawn_gpg=False, ssh_allow_gpg=False)

        helper = paths.keydir / "ssh-askpass-macos"
        assert captured_env is not None
        assert captured_env["SSH_ASKPASS"] == str(helper)
        assert captured_env["SSH_ASKPASS_REQUIRE"] == "force"
        if os.name != "nt":
            assert stat.S_IMODE(helper.stat().st_mode) == 0o700
        text = helper.read_text(encoding="utf-8")
        assert 'SSH_ASKPASS_PROMPT-}" = "confirm"' in text
        assert 'buttons {"Deny", "Allow"}' in text

    def test_macos_confirm_preserves_external_askpass(self, short_keydir, monkeypatch):
        """An explicitly configured helper takes precedence over Keychain's macOS helper."""
        agent, paths = self._agent_with_args(short_keydir, "--confirm")
        monkeypatch.setattr(agent.keychain_state, "platform", SimpleNamespace(name="darwin"))
        agent.keychain_state.env["SSH_ASKPASS"] = "/custom/askpass"
        captured_env = None

        def fake_run(cmd, *_args, **kwargs):
            nonlocal captured_env
            captured_env = kwargs["env"]
            return SimpleNamespace(
                returncode=0,
                stdout='SSH_AUTH_SOCK="/tmp/keychain-test-agent.sock"; export SSH_AUTH_SOCK\n'
                "SSH_AGENT_PID=12345; export SSH_AGENT_PID;\n",
                stderr="",
            )

        monkeypatch.setattr(agents, "run", fake_run)

        agent.start(ssh_spawn_gpg=False, ssh_allow_gpg=False)

        assert captured_env is not None
        assert captured_env["SSH_ASKPASS"] == "/custom/askpass"
        assert captured_env["SSH_ASKPASS_REQUIRE"] == "force"
        assert not (paths.keydir / "ssh-askpass-macos").exists()


# ---------------------------------------------------------------------------
# Issue #21: KEYCHAIN_{SSH,GPG}_AGENT_ARGS append flags to the spawn command
# ---------------------------------------------------------------------------


class TestAgentArgsPassthrough:
    """Verify env vars are spliced into the agent spawn command."""

    def _capture_run(self, monkeypatch):
        """Replace agents.run with a recorder; return the captured cmd list."""
        captured = []

        def fake_run(cmd, *_a, **_k):
            captured.append(list(cmd))
            stdout = (
                'SSH_AUTH_SOCK="/tmp/keychain-test-agent.sock"; export SSH_AUTH_SOCK\n'
                "SSH_AGENT_PID=12345; export SSH_AGENT_PID;\n"
                if cmd[0] == "ssh-agent"
                else ""
            )
            return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        monkeypatch.setattr(agents, "run", fake_run)
        return captured

    def _build_ssh_agent(self, keydir):
        """Construct a SshAgent with parsed args for the spawn path."""
        from keychain import state
        from keychain.paths import KeychainPaths
        from keychain.runtime.config import RuntimeConfig
        from keychain.util import Output

        args = RuntimeConfig.resolve(["add", "--no-inherit", "--no-gui"])

        kstate = state.KeychainState(
            paths=KeychainPaths(keydir=keydir, host="h"),
            args=args,
        )
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        return agents.SshAgent(kstate, out)

    def test_ssh_agent_args_appended(self, monkeypatch, short_keydir):
        """Verify KEYCHAIN_SSH_AGENT_ARGS tokens are appended to ssh-agent because the environment variable is the supported override for extra spawn flags."""
        cap = self._capture_run(monkeypatch)
        monkeypatch.setenv("KEYCHAIN_SSH_AGENT_ARGS", "-O no-restrict-websafe -t 7200")
        # Force a "spawn new agent" path: empty pidfile, no inherited env.
        monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
        monkeypatch.delenv("SSH_AGENT_PID", raising=False)
        self._build_ssh_agent(short_keydir).start(ssh_spawn_gpg=False, ssh_allow_gpg=False)
        # ssh-agent invocation is the last captured run.
        cmd = cap[-1]
        assert cmd[0] == "ssh-agent"
        assert "-O" in cmd and "no-restrict-websafe" in cmd
        assert "-t" in cmd and "7200" in cmd

    def test_gpg_agent_args_appended(self, monkeypatch, tmp_path):
        """Verify KEYCHAIN_GPG_AGENT_ARGS tokens are appended to gpg-agent because callers need a supported way to extend the spawned daemon command line."""
        from keychain import state
        from keychain.paths import KeychainPaths
        from keychain.runtime.config import RuntimeConfig
        from keychain.util import Output

        cap = self._capture_run(monkeypatch)
        monkeypatch.setenv("KEYCHAIN_GPG_AGENT_ARGS", "--allow-preset-passphrase --debug-level=basic")
        # Pretend no existing gpg-agent so we go down the spawn path.
        monkeypatch.setattr(agents, "gpg_main_socket", lambda *_args, **_kwargs: "")
        args = RuntimeConfig.resolve(["add", "--no-gui"])
        kstate = state.KeychainState(
            paths=KeychainPaths(keydir=tmp_path, host="h"),
            args=args,
        )
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        agents.GpgAgent(kstate, out).start(ssh_support=False)
        cmd = cap[-1]
        assert cmd[0] == "gpg-agent"
        assert "--allow-preset-passphrase" in cmd
        assert "--debug-level=basic" in cmd

    def test_no_args_when_env_unset(self, monkeypatch, short_keydir):
        """Verify no extra ssh-agent flags are added when the passthrough env var is unset because the default spawn command should stay minimal."""
        cap = self._capture_run(monkeypatch)
        monkeypatch.delenv("KEYCHAIN_SSH_AGENT_ARGS", raising=False)
        monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
        monkeypatch.delenv("SSH_AGENT_PID", raising=False)
        self._build_ssh_agent(short_keydir).start(ssh_spawn_gpg=False, ssh_allow_gpg=False)
        # Default invocation pins the socket under the keydir.
        assert cap[-1] == ["ssh-agent", "-s", "-a", str(short_keydir / "qqlAJmTx.s")]
