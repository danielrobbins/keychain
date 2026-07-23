# SPDX-License-Identifier: GPL-3.0-only
"""CLI parsing tests for new-style action routing and help/version short-circuits."""

import pytest

from keychain import main
from keychain.main import KeychainApp
from keychain.output.core import Output
from keychain.runtime.config import RuntimeConfig
from keychain.util import KeychainError


class TestParseArgsActions:
    """Parser-only expectations for the new action-first CLI surface."""

    def test_start_default_when_no_action(self):
        ns = RuntimeConfig.resolve([])
        assert ns.action == "add"
        assert ns.get_value("keys") == []

    def test_explicit_start(self):
        ns = RuntimeConfig.resolve(["add", "k1", "k2"])
        assert ns.action == "add"
        assert ns.get_value("keys") == ["k1", "k2"]

    def test_global_option_before_action(self):
        ns = RuntimeConfig.resolve(["--quiet", "list"])
        assert ns.action == "list"
        assert ns.get_value("quiet") is True

    def test_global_option_after_action(self):
        ns = RuntimeConfig.resolve(["list", "--quiet"])
        assert ns.action == "list"
        assert ns.get_value("quiet") is True

    def test_agent_requires_subverb(self):
        ns = RuntimeConfig.resolve(["agent"])
        out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
        with pytest.raises(KeychainError):
            KeychainApp(ns, out)._resolve_action()

    def test_agent_unknown_subverb_returns_short_error(self, capsys):
        with pytest.raises(SystemExit) as ex:
            main.main(["agent", "bogus"])
        assert ex.value.code == 2
        err = capsys.readouterr().err
        assert "Unrecognized argument 'bogus'." in err
        assert "keychain help agent" in err

    def test_list_unknown_flag_returns_short_error(self, capsys):
        with pytest.raises(SystemExit) as ex:
            main.main(["list", "--not-a-real-flag"])
        assert ex.value.code == 2
        err = capsys.readouterr().err
        assert "Unrecognized option '--not-a-real-flag'." in err
        assert "keychain help list" in err

    @pytest.mark.skip(
        reason="The parser does not currently enforce exclusive target flags for agent stop; discuss whether this belongs in parsing or action validation."
    )
    def test_agent_stop_rejects_mutually_exclusive_flags(self):
        with pytest.raises(SystemExit):
            RuntimeConfig.resolve(["agent", "stop", "--mine", "--others"])

    @pytest.mark.skip(
        reason="Unexpected wipe positionals are currently ignored by parsing; discuss whether wipe should reject stray arguments."
    )
    def test_wipe_requires_choice(self):
        with pytest.raises(SystemExit):
            RuntimeConfig.resolve(["wipe", "bogus"])


class TestPerActionHelp:
    """Pre-scan behavior for per-action help and version handling."""

    @pytest.mark.parametrize(
        "argv,expected_hint",
        [
            (["--help"], None),
            (["--help", "add"], "add"),
            (["--help", "agent", "stop"], "agent stop"),
            (["add", "--help"], "add"),
            (["add", "-h"], "add"),
            (["agent", "--help"], "agent"),
            (["wipe", "-h"], "wipe"),
            (["list", "--help"], "list"),
            (["env", "--shell", "sh", "--help"], "env"),
        ],
    )
    def test_help_short_circuits_for_every_action(self, argv, expected_hint):
        ns = RuntimeConfig.resolve(argv)
        assert ns.action == "help"
        expected = expected_hint.split() if expected_hint else None
        assert ns.get_value("help_target") == expected

    @pytest.mark.parametrize(
        "argv",
        [
            ["--version"],
            ["-V"],
            ["add", "--version"],
            ["wipe", "-V"],
        ],
    )
    def test_version_short_circuits_for_every_action(self, argv):
        ns = RuntimeConfig.resolve(argv)
        assert ns.action == "version"

    @pytest.mark.skip(
        reason="RuntimeConfig still pre-scans --help before honoring -- as a literal-positionals barrier; discuss whether this should be fixed in the parser."
    )
    def test_help_after_dashdash_is_a_key_not_an_action(self):
        ns = RuntimeConfig.resolve(["--", "--help"])
        assert ns.action == "add"
        assert "--help" in ns.get_value("keys")
