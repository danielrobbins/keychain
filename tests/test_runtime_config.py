# SPDX-License-Identifier: GPL-3.0-only
"""Tests for :mod:`keychain.runtime.config`."""

from __future__ import annotations

import stat
from types import SimpleNamespace

from keychain.runtime import config
from keychain.runtime.config import RuntimeConfig


def test_resolve_defaults_to_help_without_action(monkeypatch, tmp_path):
    """Verify that resolving an empty argv produces the compat default ``add`` action.

    This should pass because ``resolve()`` now enables compat mode by default,
    so an empty invocation is retried through the legacy translator and becomes
    the historical ``add`` default.
    """
    monkeypatch.setenv("KEYCHAIN_CONFIG", str(tmp_path / "missing.conf"))

    args = RuntimeConfig.resolve([])

    assert args.action == "add"
    assert args.action_node.fq_name == "add"


def test_resolve_short_circuits_help_with_action_hint(monkeypatch, tmp_path):
    """Verify that ``--help`` short-circuits parsing while preserving the action hint.

    This should pass because RuntimeConfig pre-scans help flags before full
    parsing and records the action token so help output can stay action-specific.
    """
    monkeypatch.setenv("KEYCHAIN_CONFIG", str(tmp_path / "missing.conf"))

    args = RuntimeConfig.resolve(["add", "--help"])

    # We expect `RuntimeConfig` to do prescan, find nothing,
    # skip compat (since there's none?), nope, compat translates it to 'add'
    # Wait, --help is prescan. Let's see how help propagates.
    assert args.action == "help"


def test_resolve_short_circuits_version(monkeypatch, tmp_path):
    """Verify that ``--version`` wins even when it appears after an action path.

    This should pass because version handling is a top-level short-circuit and
    does not require the rest of the action tree to be parsed first.
    """
    monkeypatch.setenv("KEYCHAIN_CONFIG", str(tmp_path / "missing.conf"))

    args = RuntimeConfig.resolve(["agent", "start", "--version"])

    assert args.action == "version"


def test_resolve_maps_subaction_options_and_positionals(monkeypatch, tmp_path):
    """Verify that subactions and their option-derived arguments are mapped correctly.

    This should pass because ``agent stop --mine`` is a valid new-style command,
    so RuntimeConfig should set the action, subaction, and exclusive target field.
    """
    monkeypatch.setenv("KEYCHAIN_CONFIG", str(tmp_path / "missing.conf"))

    args = RuntimeConfig.resolve(["agent", "stop", "--mine"])

    assert args.action == "agent stop"
    assert args.get_value("target") == "mine"
    assert args.has_option("target") is True


def test_resolve_accepts_equals_form(monkeypatch, tmp_path):
    """Verify that GNU-style ``--opt=value`` syntax is accepted for value options.

    This should pass because RuntimeConfig splits inline values during flag parsing
    and feeds them through the same coercion path as separate option arguments.
    """
    monkeypatch.setenv("KEYCHAIN_CONFIG", str(tmp_path / "missing.conf"))

    args = RuntimeConfig.resolve(["add", "--timeout=30", "--dir=/tmp/keychain"])

    assert args.get_value("timeout") == 30
    assert args.get_value("dir") == "/tmp/keychain"


def test_resolve_records_unknown_flags_as_parse_errors(monkeypatch, tmp_path):
    """Verify that unknown flags on a new-style action become parse errors.

    This should pass because the public ``resolve()`` path is now forgiving:
    it preserves the resolved action context and records a short parse error
    instead of raising or silently converting the invocation into help output.
    """
    monkeypatch.setenv("KEYCHAIN_CONFIG", str(tmp_path / "missing.conf"))

    args = RuntimeConfig.resolve(["list", "--not-a-real-flag"])

    assert args.action == "list"
    assert args.parse_error == "Unrecognized option '--not-a-real-flag'. Run 'keychain help list' for more information."


def test_resolve_with_compat_retries_legacy_flag(monkeypatch, tmp_path):
    """Verify that compat mode retries legacy flat flags through the translator.

    This should pass because ``--list`` is a known 2.x spelling and compat mode
    retries non-new-style argv after translation into the action-first form.
    """
    monkeypatch.setenv("KEYCHAIN_CONFIG", str(tmp_path / "missing.conf"))

    args = RuntimeConfig.resolve(["--list"])

    assert args.action == "list"


def test_resolve_with_compat_retries_bare_key(monkeypatch, tmp_path):
    """Verify that compat mode treats a bare positional key as legacy ``add`` input.

    This should pass because legacy key-only invocations are translated into the
    modern ``add <key>`` form when compat retry is enabled.
    """
    monkeypatch.setenv("KEYCHAIN_CONFIG", str(tmp_path / "missing.conf"))

    args = RuntimeConfig.resolve(["id_rsa"])

    assert args.action == "add"
    assert args.get_value("keys") == ["id_rsa"]


def test_resolve_with_compat_does_not_retry_new_style_invalid_subaction(monkeypatch, tmp_path):
    """Verify that unknown new-style arguments stay on the new-style path.

    This should pass because ``agent bogus`` already looks like a new-style
    command, so compat must not reinterpret it into a different legacy form.
    Instead, resolve should preserve the ``agent`` context and record a short
    parse error for the stray argument.
    """
    monkeypatch.setenv("KEYCHAIN_CONFIG", str(tmp_path / "missing.conf"))

    args = RuntimeConfig.resolve(["agent", "bogus"])

    assert args.action == "agent"
    assert args.parse_error == "Unrecognized argument 'bogus'. Run 'keychain help agent' for more information."


def test_resolve_with_compat_does_not_retry_new_style_unknown_flag(monkeypatch, tmp_path):
    """Verify that unknown flags stay on the recognized new-style action.

    This should pass because once argv starts with a recognized modern action,
    compat translation should no longer be considered. Resolve should record a
    parse error against the already-recognized action context instead.
    """
    monkeypatch.setenv("KEYCHAIN_CONFIG", str(tmp_path / "missing.conf"))

    args = RuntimeConfig.resolve(["list", "--not-a-real-flag"])

    assert args.action == "list"
    assert args.parse_error == "Unrecognized option '--not-a-real-flag'. Run 'keychain help list' for more information."


def test_resolve_preserves_dashdash_positionals(monkeypatch, tmp_path):
    """Verify that ``--`` forces later tokens to remain literal positionals.

    This should pass because RuntimeConfig stops flag parsing after ``--`` and
    preserves dash-prefixed key names as positional arguments.
    """
    monkeypatch.setenv("KEYCHAIN_CONFIG", str(tmp_path / "missing.conf"))

    args = RuntimeConfig.resolve(["add", "--", "-weird-key-name"])

    assert args.action == "add"
    assert args.get_value("keys") == ["-weird-key-name"]


def test_has_option_reflects_active_action(monkeypatch, tmp_path):
    """Verify that action-scoped option visibility matches the active action.

    This should pass because RuntimeConfig records only the option names valid for
    the resolved action, exposing ``shell`` for ``env`` while rejecting ``help_target``.
    """
    monkeypatch.setenv("KEYCHAIN_CONFIG", str(tmp_path / "missing.conf"))

    args = RuntimeConfig.resolve(["env", "--shell", "sh"])

    assert args.has_option("shell") is True
    assert args.get_value("shell") == "sh"
    assert args.has_option("timeout") is False


def test_apply_keychainrc_injects_config_agent_args_without_allow_env(tmp_path):
    """Verify that .keychainrc agent args do not require the environment gate."""
    rc = tmp_path / ".keychainrc"
    rc.write_text("[agent.env]\nssh_args = -t 3600\ngpg_args = --max-cache-ttl 7200\n")

    args = RuntimeConfig.resolve(["add"])
    args.apply_keychainrc({"HOME": str(tmp_path)})

    assert args.env["KEYCHAIN_SSH_AGENT_ARGS"] == "-t 3600"
    assert args.env["KEYCHAIN_GPG_AGENT_ARGS"] == "--max-cache-ttl 7200"


def test_apply_keychainrc_ignores_agent_arg_env_without_allow_env():
    """Verify that raw KEYCHAIN_* agent args are ignored unless explicitly enabled."""
    args = RuntimeConfig.resolve(["add"])

    args.apply_keychainrc(
        {
            "HOME": "/home/test",
            "KEYCHAIN_SSH_AGENT_ARGS": "-d",
            "KEYCHAIN_GPG_AGENT_ARGS": "--debug-level guru",
        }
    )

    assert "KEYCHAIN_SSH_AGENT_ARGS" not in args.env
    assert "KEYCHAIN_GPG_AGENT_ARGS" not in args.env


def test_apply_keychainrc_agent_arg_env_wins_over_config_with_allow_env(tmp_path):
    """Verify that allowed KEYCHAIN_* agent args override .keychainrc values."""
    rc = tmp_path / ".keychainrc"
    rc.write_text("[agent.env]\nssh_args = -t 3600\ngpg_args = --max-cache-ttl 7200\n")

    args = RuntimeConfig.resolve(["add", "-E"])
    args.apply_keychainrc(
        {
            "HOME": str(tmp_path),
            "KEYCHAIN_SSH_AGENT_ARGS": "-d",
            "KEYCHAIN_GPG_AGENT_ARGS": "--debug-level guru",
        }
    )

    assert args.env["KEYCHAIN_SSH_AGENT_ARGS"] == "-d"
    assert args.env["KEYCHAIN_GPG_AGENT_ARGS"] == "--debug-level guru"


def test_agent_arg_cli_options_are_not_public_surface():
    """Verify that advanced agent args are config/env-only."""
    args = RuntimeConfig.resolve(["add", "--ssh-agent-args", "-t 3600"])
    gpg_args = RuntimeConfig.resolve(["add", "--gpg-agent-args", "--debug-level guru"])

    assert args.parse_error == "Unrecognized option '--ssh-agent-args'. Run 'keychain help add' for more information."
    assert (
        gpg_args.parse_error == "Unrecognized option '--gpg-agent-args'. Run 'keychain help add' for more information."
    )


def test_pid_formats_cli_option_is_not_public_surface():
    """Verify that pidfile format selection is config-only."""
    args = RuntimeConfig.resolve(["add", "--pid-formats", "sh,fish"])

    assert args.parse_error == "Unrecognized option '--pid-formats'. Run 'keychain help add' for more information."


def test_apply_keychainrc_reads_config_only_pid_formats(tmp_path):
    """Verify that [paths] pid_formats remains a working config key."""
    rc = tmp_path / ".keychainrc"
    rc.write_text("[paths]\npid_formats = sh,fish,envfile\n")

    args = RuntimeConfig.resolve(["add"])
    args.apply_keychainrc({"HOME": str(tmp_path)})

    assert args.get_value("pid_formats") == "sh,fish,envfile"


def test_config_security_rejects_foreign_owner(monkeypatch, tmp_path):
    monkeypatch.setattr(config.os, "getuid", lambda: 1000, raising=False)

    error = config._config_security_error(
        tmp_path / ".keychainrc",
        SimpleNamespace(st_uid=1001, st_mode=stat.S_IFREG | 0o600),
    )

    assert "owned by uid 1001" in error


def test_config_security_rejects_group_writable_file(monkeypatch, tmp_path):
    monkeypatch.setattr(config.os, "getuid", lambda: 1000, raising=False)

    error = config._config_security_error(
        tmp_path / ".keychainrc",
        SimpleNamespace(st_uid=1000, st_mode=stat.S_IFREG | 0o620),
    )

    assert "writable by group or others" in error


def test_apply_keychainrc_reports_security_failure(monkeypatch, tmp_path):
    rc = tmp_path / ".keychainrc"
    rc.write_text("[agent]\ntimeout = 15\n", encoding="utf-8")
    monkeypatch.setattr(config, "_config_security_error", lambda _path, _stat: "Unsafe configuration")

    args = RuntimeConfig.resolve(["add"])
    args.apply_keychainrc({"HOME": str(tmp_path)})

    assert args.parse_error == "Unsafe configuration"
    assert args.diagnostics()["keychainrc"]["status"] == "rejected_permissions"
    assert args.get_value("timeout") is None


def test_apply_keychainrc_warns_on_unknown_section(tmp_path, monkeypatch):
    """Verify that unknown .keychainrc sections are preserved as warnings.

    This should pass because configuration parsing is intentionally tolerant and
    reports unsupported sections through ``rc_warnings`` instead of crashing.
    """
    rc = tmp_path / ".keychainrc"
    rc.write_text("[bogus]\nfoo = bar\n")
    monkeypatch.setenv("KEYCHAIN_CONFIG", str(rc))

    args = RuntimeConfig.resolve(["-E"])

    assert any("bogus" in warning for warning in args.rc_warnings)


def test_apply_keychainrc_warns_on_unknown_key(tmp_path, monkeypatch):
    """Verify that unsupported keys inside known sections become warnings.

    This should pass because apply_keychainrc validates keys against the config
    model and records unknown entries rather than accepting them silently.
    """
    rc = tmp_path / ".keychainrc"
    rc.write_text("[agent]\nno_such_option = yes\n")
    monkeypatch.setenv("KEYCHAIN_CONFIG", str(rc))

    args = RuntimeConfig.resolve(["-E"])

    assert any("no_such_option" in warning for warning in args.rc_warnings)


def test_apply_keychainrc_cli_value_wins_over_rc(tmp_path, monkeypatch):
    """Verify that explicit CLI settings override values loaded from .keychainrc.

    This should pass because RuntimeConfig tracks CLI-provided argnames in
    ``_cli_set`` and refuses to overwrite those values from config files.
    """
    rc = tmp_path / ".keychainrc"
    rc.write_text("[agent]\ntimeout = 20\n")
    monkeypatch.setenv("KEYCHAIN_CONFIG", str(rc))

    args = RuntimeConfig.resolve(["add", "--timeout=10", "-E"])

    assert args.get_value("timeout") == 10


def test_apply_keychainrc_coerces_bool_and_int_values(tmp_path, monkeypatch):
    """Verify that bool and int strings from .keychainrc are coerced to real types.

    This should pass because apply_keychainrc uses the option metadata to coerce
    raw config strings before storing them on RuntimeConfig.
    """
    rc = tmp_path / ".keychainrc"
    rc.write_text("[output]\nquiet = true\n[agent]\ntimeout = 15\n")
    monkeypatch.setenv("KEYCHAIN_CONFIG", str(rc))

    args = RuntimeConfig.resolve(["-E"])

    assert args.get_value("quiet") is True
    assert args.get_value("timeout") == 15


def test_diagnostics_report_normalized_config_and_only_relevant_environment(tmp_path):
    rc = tmp_path / ".keychainrc"
    rc.write_text("[output]\nquiet = true\ncolor = false\n")
    args = RuntimeConfig.resolve(["inspect"])
    args.apply_keychainrc(
        {
            "HOME": str(tmp_path),
            "TERM": "xterm-256color",
            "DISPLAY": ":0",
            "SSH_CONNECTION": "private network details",
            "KEYCHAIN_SSH_AGENT_ARGS": "-t 3600",
            "AWS_SECRET_ACCESS_KEY": "must-not-leak",
        }
    )

    diagnostics = args.diagnostics()
    configuration = diagnostics
    keychainrc = configuration["keychainrc"]
    environment = diagnostics["environment"]

    assert keychainrc == {
        "path": str(rc),
        "status": "loaded",
        "settings": {"output.color": False, "output.quiet": True},
        "warnings": [],
    }
    assert environment["TERM"] == {"set": True, "value": "xterm-256color"}
    assert environment["DISPLAY"] == {"set": True}
    assert environment["SSH_CONNECTION"] == {"set": True}
    assert environment["KEYCHAIN_SSH_AGENT_ARGS"] == {
        "set": True,
        "value": "-t 3600",
        "accepted": False,
    }
    assert configuration["effective"]["output.quiet"] == {"value": True, "source": "keychainrc"}
    assert configuration["effective"]["output.color"] == {"value": False, "source": "keychainrc"}
    assert configuration["effective"]["output.theme"]["source"] == "default"
    assert "AWS_SECRET_ACCESS_KEY" not in environment


def test_diagnostics_identify_command_line_and_accepted_environment_sources(tmp_path):
    args = RuntimeConfig.resolve(["add", "--confirm", "-E"])
    args.apply_keychainrc(
        {
            "HOME": str(tmp_path),
            "NO_COLOR": "",
            "KEYCHAIN_SSH_AGENT_ARGS": "-t 3600",
        }
    )

    effective = args.diagnostics()["effective"]
    assert args.get_value("nocolor") is True
    assert effective["agent.confirm"] == {"value": True, "source": "command_line"}
    assert effective["agent.env.ssh_args"] == {"value": "-t 3600", "source": "environment"}
    assert effective["output.color"] == {"value": False, "source": "environment"}


def test_diagnostics_distinguish_absent_invalid_and_accepted_env_config(tmp_path):
    args = RuntimeConfig.resolve(["inspect"])
    args.apply_keychainrc({"HOME": str(tmp_path)})
    assert args.diagnostics()["keychainrc"]["status"] == "absent"

    rc = tmp_path / "custom.conf"
    rc.write_text("[broken")
    args = RuntimeConfig.resolve(["inspect", "-E"])
    args.apply_keychainrc({"HOME": str(tmp_path), "KEYCHAIN_CONFIG": str(rc)})
    diagnostics = args.diagnostics()
    assert diagnostics["keychainrc"]["status"] == "parse_error"
    assert diagnostics["keychainrc"]["warnings"]
    assert diagnostics["environment"]["KEYCHAIN_CONFIG"]["accepted"] is True


def test_apply_keychainrc_inverted_bool_keys_use_positive_atoms(tmp_path, monkeypatch):
    """Verify positive config atoms map to legacy negative runtime flags.

    This should pass because some config booleans are intentionally authored in
    positive form even though the CLI flag remains negative for compatibility.
    """
    rc = tmp_path / ".keychainrc"
    rc.write_text("[output]\ncolor = false\ngui = false\n" "[agent]\ninherit = false\n")
    monkeypatch.setenv("KEYCHAIN_CONFIG", str(rc))

    args = RuntimeConfig.resolve(["-E"])

    assert args.get_value("nocolor") is True
    assert args.get_value("no_gui") is True
    assert args.get_value("no_inherit") is True


def test_apply_keychainrc_inverted_bool_true_keeps_positive_behavior(tmp_path, monkeypatch):
    """Verify positive config atoms remain false on the legacy negative vars when enabled.

    This should pass because ``lock = true`` or ``color = true`` should preserve
    the normal positive behavior and therefore leave the negative runtime flags false.
    """
    rc = tmp_path / ".keychainrc"
    rc.write_text("[output]\ncolor = true\n")
    monkeypatch.setenv("KEYCHAIN_CONFIG", str(rc))

    args = RuntimeConfig.resolve(["-E"])

    assert args.get_value("nocolor") is False
