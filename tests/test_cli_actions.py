# SPDX-License-Identifier: GPL-3.0-only
"""CLI action-resolution and handler tests."""

import subprocess
from types import SimpleNamespace

import pytest

from keychain import keys, main
from keychain.main import KeychainApp
from keychain.output.core import Output
from keychain.paths import KeychainPaths
from keychain.runtime.config import RuntimeConfig
from keychain.util import KeychainError
from tests.support import set_home


class TestResolveAction:
    """Validation and dispatch tests for KeychainApp action resolution."""

    def test_start_returns_empty(self):
        args = RuntimeConfig.resolve([])
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        assert KeychainApp(args, out)._resolve_action() == "add"

    def test_agent_stop_action(self):
        """An explicit stop target should survive parse and resolve to the stop handler."""
        ns = RuntimeConfig.resolve(["agent", "stop", "--mine"])
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        assert KeychainApp(ns, out)._resolve_action() == "agent_stop"
        assert ns.get_value("target") == "mine"

    def test_agent_stop_defaults_to_pidfile_when_no_target_is_selected(self):
        """The stop handler applies its own runtime fallback when no target flag was parsed."""
        ns = RuntimeConfig.resolve(["agent", "stop"])
        seen: list[str] = []

        class _Paths:
            def ensure_keydir(self):
                return None

        class _SSH:
            def stop(self, target):
                seen.append(target)

        class _State:
            user = "tester"
            paths = _Paths()
            ssh = _SSH()

        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        app = KeychainApp(ns, out)
        app._kstate = _State()

        assert app._resolve_action() == "agent_stop"
        assert ns.get_value("target") is None
        assert app._handle_agent_stop_action() == 0
        assert seen == ["pidfile"]

    def test_agent_start_action(self):
        args = RuntimeConfig.resolve(["agent", "start"])
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        assert KeychainApp(args, out)._resolve_action() == "agent_start"

    @pytest.mark.parametrize(
        "argv,expected",
        [
            (["wipe", "--ssh"], "wipe"),
            (["wipe", "--gpg"], "wipe"),
            (["wipe"], "wipe"),
            (["wipe", "--ssh", "--gpg"], "wipe"),
        ],
    )
    def test_wipe_actions(self, argv, expected):
        args = RuntimeConfig.resolve(argv)
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        assert KeychainApp(args, out)._resolve_action() == expected

    @pytest.mark.parametrize(
        "sub,expected",
        [
            ("list", "list"),
            ("env", "env"),
            ("help", "help"),
            ("version", "version"),
        ],
    )
    def test_passthrough_actions(self, sub, expected):
        args = RuntimeConfig.resolve([sub])
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        assert KeychainApp(args, out)._resolve_action() == expected

    def test_ssh_rm_action(self):
        args = RuntimeConfig.resolve(["forget", "k"])
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        assert KeychainApp(args, out)._resolve_action() == "forget"

    def test_default_dir_resolves_tilde_to_home(self, tmp_path, monkeypatch):
        """Parser defaults should stay unexpanded until the path layer resolves them against HOME."""
        set_home(monkeypatch, tmp_path)
        ns = RuntimeConfig.resolve([])
        assert ns.get_value("dir") == "~/.keychain"
        assert (
            KeychainPaths.build(ns.get_value("dir"), bool(ns.get_value("absolute")), "host").keydir
            == tmp_path / ".keychain"
        )

    def test_forget_noop_without_keys(self):
        """Forget is a no-op unless the caller asked for keys or config-driven host expansion."""
        ns = RuntimeConfig.resolve(["forget"])
        removed: list[list[str]] = []

        class _Paths:
            def ensure_keydir(self):
                return None

        class _SSH:
            def remove(self, ssh_keys):
                removed.append(list(ssh_keys))

        class _State:
            user = "tester"
            paths = _Paths()
            ssh = _SSH()

            def resolve_requested_keys(self, _out, *, gpg_lookup=True):
                return keys.ResolvedKeys([], [], [], [], [], [], [])

        _State.args = ns
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        app = KeychainApp(ns, out)
        app._kstate = _State()
        assert app._handle_forget_action() == 0
        assert removed == []

    def test_forget_rejects_explicit_gpg_extkeys(self):
        """Forget intentionally stays SSH-only even when key lookup finds a GPG external key."""
        ns = RuntimeConfig.resolve(["forget", "gpgk:ABCD1234"])

        class _Paths:
            def ensure_keydir(self):
                return None

        class _SSH:
            def remove(self, _ssh_keys):
                raise AssertionError("ssh removal should not run for gpgk inputs")

        class _State:
            user = "tester"
            paths = _Paths()
            ssh = _SSH()

            def resolve_requested_keys(self, _out, *, gpg_lookup=True):
                return keys.ResolvedKeys([], ["ABCD1234"], [], [], [], [], [])

        _State.args = ns
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        app = KeychainApp(ns, out)
        app._kstate = _State()
        with pytest.raises(KeychainError, match="forget only supports SSH key files"):
            app._handle_forget_action()

    def test_systemd_set_env_warns_on_timeout(self, monkeypatch, capsys):
        def timeout_run(*_args, **_kwargs):
            raise subprocess.TimeoutExpired(["systemctl"], 5)

        monkeypatch.setattr(main.subprocess, "run", timeout_run)
        out = Output.build(quiet=False, debug=False, eval_mode=False, color=False)

        main._systemd_set_env(main.SshAgentRef("/tmp/user name/agent.sock", "123"), out)

        captured = capsys.readouterr()
        assert "Timed out while updating the systemd user environment" in captured.err

    def test_add_with_only_missing_keys_refuses_to_start_agent(self):
        ns = RuntimeConfig.resolve(["add", "ghost-key"])

        class _Paths:
            def ensure_keydir(self):
                return None

        class _State:
            user = "tester"
            paths = _Paths()

            def resolve_requested_keys(self, _out, *, gpg_lookup=True):
                return keys.ResolvedKeys([], [], [], [], [], [], ["ghost-key"])

        _State.args = ns
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        app = KeychainApp(ns, out)
        app._kstate = _State()
        app._agent_settings = lambda: (_ for _ in ()).throw(AssertionError("agent settings should not be read"))
        app._do_add = lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("agent should not start"))

        with pytest.raises(KeychainError, match="No requested keys could be resolved; refusing to start an agent"):
            app._handle_add_action()

    def test_add_with_pkcs11_request_does_not_trigger_missing_only_rejection(self):
        ns = RuntimeConfig.resolve(["add", "pkcs11:/usr/lib/pkcs11/opensc-pkcs11.so"])

        class _Paths:
            def ensure_keydir(self):
                return None

        class _State:
            user = "tester"
            paths = _Paths()

            def resolve_requested_keys(self, _out, *, gpg_lookup=True):
                return keys.ResolvedKeys([], [], [], [], [], ["/usr/lib/pkcs11/opensc-pkcs11.so"], [])

        _State.args = ns
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        app = KeychainApp(ns, out)
        app._kstate = _State()
        app._agent_settings = lambda: (False, False)
        app._do_add = lambda requested, *_rest: requested.pkcs11 == ["/usr/lib/pkcs11/opensc-pkcs11.so"]

        assert app._handle_add_action() is True

    def test_quick_and_clear_incompatible(self):
        ns = RuntimeConfig.resolve(["add", "--quick", "--clear"])
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        with pytest.raises(KeychainError):
            KeychainApp(ns, out)._resolve_action()

    def test_lockwait_negative_rejected(self):
        """Validation should reject negative lockwait once the parser has accepted the numeric value."""
        ns = RuntimeConfig.resolve(["add", "--lockwait=-1"])
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        with pytest.raises(KeychainError):
            KeychainApp(ns, out)._resolve_action()

    def test_timeout_zero_rejected(self):
        ns = RuntimeConfig.resolve(["add", "--timeout", "0"])
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        with pytest.raises(KeychainError):
            KeychainApp(ns, out)._resolve_action()

    def test_confhost_raises(self):
        ns = RuntimeConfig.resolve(["add", "--confhost", "remote"])
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        with pytest.raises(KeychainError):
            KeychainApp(ns, out)._resolve_action()

    def test_deprecated_agents_warns(self, capsys):
        ns = RuntimeConfig.resolve(["add", "--agents", "ssh"])
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        KeychainApp(ns, out)._resolve_action()
        assert "deprecated" in capsys.readouterr().err


class TestOutputFormatOptions:
    """Output-format and option-shape coverage for live actions."""

    def test_json_flag_defaults_false_on_list(self):
        """Action-local JSON flags should default to false when the option is omitted."""
        ns = RuntimeConfig.resolve(["list"])
        assert ns.get_value("json") is False

    def test_json_flag_after_action(self):
        ns = RuntimeConfig.resolve(["list", "--json"])
        assert ns.get_value("json") is True

    def test_json_flag_after_action_inspect(self):
        ns = RuntimeConfig.resolve(["inspect", "--json"])
        assert ns.get_value("json") is True

    def test_theme_flag_default_is_none(self, monkeypatch, tmp_path):
        monkeypatch.setenv("KEYCHAIN_CONFIG", str(tmp_path / "missing.conf"))
        ns = RuntimeConfig.resolve(["version"])
        assert ns.get_value("theme") is None

    def test_theme_flag_carries_value(self):
        ns = RuntimeConfig.resolve(["version", "--theme", "modern"])
        assert ns.get_value("theme") == "modern"

    def test_ssh_rm_with_no_keys_parses(self):
        ns = RuntimeConfig.resolve(["--ssh-rm"])
        assert ns.action == "forget"
        assert ns.get_value("keys") == []
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        assert KeychainApp(ns, out)._resolve_action() == "forget"

    def test_ssh_rm_with_multiple_keys(self):
        ns = RuntimeConfig.resolve(["--ssh-rm", "id_rsa", "id_ed25519"])
        assert ns.action == "forget"
        assert ns.get_value("keys") == ["id_rsa", "id_ed25519"]

    def test_eval_failure_prints_false_fallback(self, capsys):
        """Eval mode should emit the shell-friendly failure stub on runtime validation errors."""
        with pytest.raises(SystemExit):
            main.main(["--eval", "add", "--quick", "--clear"])
        captured = capsys.readouterr()
        assert "false;" in captured.out

    def test_non_eval_action_error_does_not_touch_missing_eval_attribute(self, monkeypatch, capsys):
        """Non-eval action failures should report the real KeychainError instead of crashing in the error handler."""
        monkeypatch.setattr(main.platform, "detect", lambda: SimpleNamespace(supported=True, name="linux", reason=""))
        with pytest.raises(SystemExit) as exc:
            main.main(["agent"])
        assert exc.value.code == 1
        captured = capsys.readouterr()
        assert "agent: missing subcommand (start|stop)" in captured.err
        assert "AttributeError" not in captured.err

    @pytest.mark.parametrize(
        "flag,value",
        [
            ("--inherit", "any"),
            ("--attempts", "3"),
        ],
    )
    def test_other_deprecated_flags_warn(self, flag, value, capsys):
        ns = RuntimeConfig.resolve(["add", flag, value])
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        KeychainApp(ns, out)._resolve_action()
        assert "deprecated" in capsys.readouterr().err

    @pytest.mark.parametrize(
        "opt,attr,value",
        [
            ("--dir", "dir", "/tmp/keychain"),
            ("--host", "host", "build-7"),
            ("--lockwait", "lockwait", 7),
            ("--timeout", "timeout", 30),
            ("--ssh-agent-socket", "ssh_agent_socket", "/tmp/agent.sock"),
        ],
    )
    def test_value_options_accept_equals_form(self, opt, attr, value):
        ns = RuntimeConfig.resolve(["add", f"{opt}={value}"])
        assert ns.get_value(attr) == value


class TestListFingerprints:
    """List-action handler behavior for table and JSON output."""

    def test_list_default_uses_short_form(self):
        ns = RuntimeConfig.resolve(["list"])
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        assert KeychainApp(ns, out)._resolve_action() == "list"

    def test_list_json_uses_find_active_agent_env(self, monkeypatch):
        seen = []

        monkeypatch.setattr(main.agents, "render_list_json", lambda env: seen.append(env))
        kstate = SimpleNamespace(
            pidfile_env=main.SshAgentRef(sock="/tmp/stale.sock", pid="9999"),
            find_active_agent_env=main.SshAgentRef(sock="/tmp/live.sock", pid="1111"),
        )
        out_json = Output.build(quiet=True, debug=False, eval_mode=False, color=False, json=True)

        app = KeychainApp(RuntimeConfig.resolve(["list", "--json"]), out_json)
        app._kstate = kstate
        assert app._handle_list_action() == 0
        assert seen == [kstate.find_active_agent_env]
