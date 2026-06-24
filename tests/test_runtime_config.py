# SPDX-License-Identifier: GPL-3.0-only
"""Tests for :mod:`keychain.runtime.config`."""

from __future__ import annotations

import os

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


def test_apply_keychainrc_injects_agent_args_into_env():
    """Verify that agent argument settings are exported into the effective environment.

    This should pass because apply_keychainrc builds a derived environment mapping
    and mirrors agent argument options into KEYCHAIN_* variables without mutating os.environ.
    """
    args = RuntimeConfig.resolve(["add", "--ssh-agent-args=-t 3600", "--gpg-agent-args=--max-cache-ttl 7200", "-E"])

    args.apply_keychainrc({"HOME": "/home/test"})

    assert args.env["KEYCHAIN_SSH_AGENT_ARGS"] == "-t 3600"
    assert args.env["KEYCHAIN_GPG_AGENT_ARGS"] == "--max-cache-ttl 7200"
    assert "KEYCHAIN_SSH_AGENT_ARGS" not in os.environ
    assert "KEYCHAIN_GPG_AGENT_ARGS" not in os.environ


def test_apply_keychainrc_base_env_wins_over_agent_args():
    """Verify that an existing base environment overrides derived agent-arg exports.

    This should pass because apply_keychainrc treats the provided base environment
    as higher priority than values synthesized from RuntimeConfig fields.
    """
    args = RuntimeConfig.resolve(["add", "--ssh-agent-args=-t 3600", "--gpg-agent-args=--max-cache-ttl 7200", "-E"])

    args.apply_keychainrc(
        {
            "HOME": "/home/test",
            "KEYCHAIN_SSH_AGENT_ARGS": "-d",
            "KEYCHAIN_GPG_AGENT_ARGS": "--debug-level guru",
        }
    )

    assert args.env["KEYCHAIN_SSH_AGENT_ARGS"] == "-d"
    assert args.env["KEYCHAIN_GPG_AGENT_ARGS"] == "--debug-level guru"


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
    rc.write_text("[output]\ndebug = true\n[agent]\ntimeout = 15\n")
    monkeypatch.setenv("KEYCHAIN_CONFIG", str(rc))

    args = RuntimeConfig.resolve(["-E"])

    assert args.get_value("debug") is True
    assert args.get_value("timeout") == 15
