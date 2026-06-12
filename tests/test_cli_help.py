# SPDX-License-Identifier: GPL-3.0-only
"""CLI help and version rendering tests."""

import pytest

from keychain import main
from keychain.main import helpinfo
from keychain.runtime.config import RuntimeConfig
from keychain.util import Output


class TestHelpVersionOutput:
    def test_version_first_line_matches_banner_format(self, capsys):
        from keychain import __version__

        ns = RuntimeConfig.resolve(["version"])
        out = Output.build(quiet=False, debug=False, eval_mode=False, color=False)
        main.banner(out)
        main.versinfo(out)
        captured = capsys.readouterr().err
        assert __version__ in captured
        assert "keychain" in captured
        assert ns.action == "version"

    def test_help_lists_every_visible_action(self, capsys):
        helpinfo(None)
        captured = capsys.readouterr().out
        assert "Actions" in captured
        for sub in ("add", "agent", "list", "wipe", "forget", "env", "inspect", "version", "help", "man"):
            assert sub in captured, f"action {sub!r} missing from help"
        assert "list-fp" not in captured
        assert "--quiet" in captured
        assert "Global options" in captured

    @pytest.mark.parametrize(
        "sub",
        [
            "add",
            "agent",
            "list",
            "wipe",
            "forget",
            "env",
            "inspect",
        ],
    )
    def test_per_action_cheat_sheet_renders(self, sub, capsys):
        helpinfo(sub)
        captured = capsys.readouterr().out
        assert f"keychain {sub}" in captured

    def test_per_action_help_strips_markup_syntax(self, capsys):
        helpinfo("add")
        captured = capsys.readouterr().out
        assert "`" not in captured

    def test_cli_man_topic_dedupes_repeated_lines_and_strips_markup(self, capsys):
        with pytest.raises(SystemExit) as ex:
            main.main(["man", "topic:config"])
        assert ex.value.code == 0
        out = capsys.readouterr().out
        assert "See ``keychain config show``" not in out
        assert "[keys]        key-resolution:" not in out
        assert "[keys]         key-resolution:" not in out
        assert "Configuration reference:" in out
        assert "[ssh.askpass]" in out
        assert "program = VALUE" in out
        assert "Set the SSH_ASKPASS helper" in out
        assert "[agent.env]" in out
        assert "ssh_args = VALUE" in out
        assert "Same setting as the --ssh-agent-args command-line option." in out
        assert (
            "[keys]         key-resolution: ``confallhosts``,\n    [keys]         key-resolution: ``confallhosts``,"
            not in out
        )

    def test_cli_man_list_uses_authored_labels(self, capsys):
        with pytest.raises(SystemExit) as ex:
            main.main(["man", "--list"])
        assert ex.value.code == 0
        out = capsys.readouterr().out
        assert "keychain add" in out
        assert "topic:config" in out
        assert "keychain config" not in out
        assert "config:output.quiet" in out
        assert "config:agent.timeout" in out
        assert "config:paths.dir" in out
        assert "config:keys.ignore_missing" in out
        assert "config:ssh.askpass.program" in out
        assert "config:ssh.askpass.mode" in out
        assert "action:config" not in out
        assert "option:status-json" not in out
        assert "ACTIONS" not in out
        assert "--quiet" in out
        assert "keychain agent stop --mine" in out
        assert "keychain wipe --gpg" in out
        assert "keychain list --json" in out

    def test_cli_man_generated_config_key_renders(self, capsys):
        with pytest.raises(SystemExit) as ex:
            main.main(["man", "config:agent.timeout"])
        assert ex.value.code == 0
        out = capsys.readouterr().out
        assert "config:agent.timeout" in out
        assert "Config key: [agent] timeout" in out
        assert "Command-line option: --timeout" in out

    def test_cli_man_full_renders_section_markers(self, capsys):
        with pytest.raises(SystemExit) as ex:
            main.main(["man"])
        assert ex.value.code == 0
        out = capsys.readouterr().out
        assert "ACTIONS" in out
        assert "    keychain add\n        Add keys to the agent" in out
        assert "    keychain agent stop\n        terminate ssh-agents" in out
        assert "            --mine\n                terminate only this UID's agents" in out
        assert "    keychain list\n        List keys currently held by ssh-agent" in out
        assert "            --json\n                emit machine-readable JSON on stdout" in out
        assert "    keychain agent stop --mine\n        terminate only this UID's agents" not in out
        assert "keychain status" not in out
        assert "status payload" not in out

    def test_cli_man_action_entries_group_local_options(self, capsys):
        with pytest.raises(SystemExit) as ex:
            main.main(["man", "agent", "stop"])
        assert ex.value.code == 0
        out = capsys.readouterr().out
        assert out.startswith("    keychain agent stop")
        assert "        Syntax: keychain agent stop [--mine|--others|--all]" in out
        assert "        Options:" in out
        assert "            --mine\n                terminate only this UID's agents" in out
        assert "            --others\n                terminate agents owned by others" in out
        assert "            --all\n                terminate all matching agents" in out

    def test_cli_man_option_entries_use_tagged_paragraph_layout(self, capsys):
        with pytest.raises(SystemExit) as ex:
            main.main(["man", "option:mine", "option:list-json"])
        assert ex.value.code == 0
        out = capsys.readouterr().out
        assert "    keychain agent stop --mine\n        terminate only this UID's agents" in out
        assert "        Restrict the kill list" in out
        assert "    keychain list --json\n        emit machine-readable JSON on stdout" in out
        assert not out.startswith("keychain agent stop --mine")

    def test_removed_top_level_verb_helpinfo_errors(self, capsys):
        assert helpinfo("stop") == 2
        captured = capsys.readouterr()
        assert "help: unknown action: stop" in captured.err
        assert captured.out == ""

    def test_cli_help_removed_top_level_verb_errors(self, capsys):
        with pytest.raises(SystemExit) as ex:
            main.main(["help", "stop"])
        assert ex.value.code == 2
        err = capsys.readouterr().err
        assert "help: unknown action: stop" in err

    def test_cli_help_nested_action_target_renders(self, capsys):
        with pytest.raises(SystemExit) as ex:
            main.main(["help", "agent", "stop"])
        assert ex.value.code == 0
        out = capsys.readouterr().out
        assert "keychain agent stop" in out

    def test_cli_flag_help_nested_action_target_renders(self, capsys):
        with pytest.raises(SystemExit) as ex:
            main.main(["--help", "agent", "stop"])
        assert ex.value.code == 0
        out = capsys.readouterr().out
        assert "keychain agent stop" in out

    def test_cli_help_unknown_target_errors(self, capsys):
        with pytest.raises(SystemExit) as ex:
            main.main(["help", "nonsense-token"])
        assert ex.value.code == 2
        err = capsys.readouterr().err
        assert "help: unknown action: nonsense-token" in err

    def test_cli_flag_help_unknown_target_errors(self, capsys):
        with pytest.raises(SystemExit) as ex:
            main.main(["--help", "nonsense-token"])
        assert ex.value.code == 2
        err = capsys.readouterr().err
        assert "help: unknown action: nonsense-token" in err

    def test_cli_explain_noncompat_invocation_renders_action_and_option_panels(self, capsys):
        with pytest.raises(SystemExit) as ex:
            main.main(["add", "--quick", "--explain"])
        assert ex.value.code == 0
        out = capsys.readouterr().out
        assert "keychain add" in out
        assert "--quick" in out
        assert "╯\n\n ╭" not in out
        assert "``" not in out

    def test_cli_explain_compat_invocation_renders_legacy_panel(self, capsys):
        with pytest.raises(SystemExit) as ex:
            main.main(["--list", "--explain"])
        assert ex.value.code == 0
        out = capsys.readouterr().out
        assert "keychain list" in out
        assert "Legacy invocation" in out
        assert "No match for any new-style action; legacy keychain 2.x parsing invoked." in out

    def test_cli_explain_default_add_fallback_renders_legacy_warning(self, capsys):
        with pytest.raises(SystemExit) as ex:
            main.main(["start", "--explain"])
        assert ex.value.code == 0
        out = capsys.readouterr().out
        assert "Legacy invocation" in out
        assert "No match for any new-style action; legacy keychain 2.x parsing invoked." in out
        assert "keychain add" in out
        assert "Literal Agent Key: 'start'" in out
        assert "A literal SSH or GnuPG key specification to load into the agent." in out
