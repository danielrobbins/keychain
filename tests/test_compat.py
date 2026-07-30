# SPDX-License-Identifier: GPL-3.0-only
"""Tests for the legacy → action compatibility shim."""

import pytest

from keychain.runtime.actions import ROOT_ACTION
from keychain.runtime.compat import COMPAT

# Map module-level test functions to the built singleton
looks_new_style = COMPAT.looks_new_style
translate = COMPAT.translate

# ---------------------------------------------------------------------------
# looks_new_style
# ---------------------------------------------------------------------------


class TestLooksNewStyle:
    @pytest.mark.parametrize(
        "argv",
        [
            ["add"],
            ["agent", "stop"],
            ["agent", "start"],
            ["list"],
            ["wipe", "--ssh"],
            ["--quiet", "add", "key1"],
            ["--debug", "list"],
        ],
    )
    def test_recognised_actions(self, argv):
        assert looks_new_style(argv) is True

    @pytest.mark.parametrize(
        "argv",
        [
            [],
            ["--list"],
            ["--stop", "all"],
            ["mykey"],
            ["--quiet", "mykey"],
            ["--debug", "--wipe", "ssh"],
        ],
    )
    def test_legacy_invocations_rejected(self, argv):
        assert looks_new_style(argv) is False

    def test_double_dash_is_legacy(self):
        # ``--`` ends option processing; anything after it isn't an action.
        assert looks_new_style(["--", "add"]) is False


# ---------------------------------------------------------------------------
# translate
# ---------------------------------------------------------------------------


class TestTranslate:
    def test_empty_argv_becomes_start(self):
        assert translate([]) == ["add"]

    def test_bare_keys_become_start(self):
        assert translate(["k1", "k2"]) == ["add", "k1", "k2"]

    def test_list_flag(self):
        assert translate(["--list"]) == ["list"]
        assert translate(["-l"]) == ["list"]

    def test_list_fp_flag_maps_to_list(self):
        # ``--list-fp`` / ``-L`` shipped in keychain 2.x; they now map to
        # the unified ``list`` action (no separate list-fp anymore).
        assert translate(["--list-fp"]) == ["list"]
        assert translate(["-L"]) == ["list"]

    def test_query_flag(self):
        # keychain 2.x ``--query`` -> new-style ``env`` (default --shell env).
        assert translate(["--query"]) == ["env"]

    def test_help_and_version(self):
        assert translate(["--help"]) == ["help"]
        assert translate(["-h"]) == ["help"]
        assert translate(["--version"]) == ["version"]
        assert translate(["-V"]) == ["version"]

    def test_stop_with_value(self):
        # Legacy ``--stop X`` / ``-k X`` translates to the new ``agent stop``
        # domain form (with --mine/--others flags; bare = all).
        assert translate(["--stop", "all"]) == ["agent", "stop"]
        assert translate(["--stop", "mine"]) == ["agent", "stop", "--mine"]
        assert translate(["-k", "mine"]) == ["agent", "stop", "--mine"]
        assert translate(["-k", "others"]) == ["agent", "stop", "--others"]

    def test_stop_with_equals(self):
        assert translate(["--stop=others"]) == ["agent", "stop", "--others"]
        assert translate(["--stop=all"]) == ["agent", "stop"]

    def test_wipe_with_value(self):
        # ``--wipe ssh`` -> ``wipe --ssh``; ``--wipe gpg`` -> ``wipe --gpg``;
        # ``--wipe all`` keeps its legacy both-target behavior explicitly.
        assert translate(["--wipe", "ssh"]) == ["wipe", "--ssh"]
        assert translate(["--wipe", "gpg"]) == ["wipe", "--gpg"]
        assert translate(["--wipe", "all"]) == ["wipe", "--ssh", "--gpg"]

    def test_wipe_with_equals(self):
        assert translate(["--wipe=gpg"]) == ["wipe", "--gpg"]
        assert translate(["--wipe=ssh"]) == ["wipe", "--ssh"]
        assert translate(["--wipe=all"]) == ["wipe", "--ssh", "--gpg"]

    def test_ssh_rm_carries_keys(self):
        # keychain 2.x ``--ssh-rm`` / ``-r`` -> new-style ``forget``.
        assert translate(["--ssh-rm", "keyA", "keyB"]) == ["forget", "keyA", "keyB"]
        assert translate(["-r", "kk"]) == ["forget", "kk"]

    def test_pass_through_options_kept(self):
        # Global flags survive translation in their original positions.
        out = translate(["--quiet", "--debug", "--list"])
        assert out[0] == "list"
        assert "--quiet" in out
        assert "--debug" in out

    def test_start_keeps_keys_and_options(self):
        out = translate(["--quiet", "id_rsa", "id_ed25519"])
        assert out[0] == "add"
        assert "--quiet" in out
        assert out[-2:] == ["id_rsa", "id_ed25519"]

    def test_value_options_remain_paired(self):
        argv = ["--eval", "--timeout", "180", "--agents", "ssh,gpg", "id_rsa"]
        assert translate(argv) == ["add", *argv]

    def test_value_option_after_key_preserves_order(self):
        argv = ["id_rsa", "--timeout", "180"]
        assert translate(argv) == ["add", *argv]

    def test_global_value_option_after_key_preserves_order(self):
        argv = ["id_rsa", "--host", "work"]
        assert translate(argv) == ["add", *argv]

    def test_double_dash_passes_through(self):
        out = translate(["--", "--weird-key-name"])
        # Implicit ``add``; ``--`` and the literal arg are preserved.
        assert out[0] == "add"
        assert "--" in out
        assert "--weird-key-name" in out

    def test_combined_global_and_action_flags(self):
        out = translate(["--debug", "--stop", "all", "--quiet"])
        assert out[:2] == ["agent", "stop"]
        assert "--debug" in out
        assert "--quiet" in out

    def test_value_action_missing_value_passes_through(self):
        # Don't crash on partial argv; let the parser report it.
        out = translate(["--stop"])
        assert out == ["add", "--stop"]


# ---------------------------------------------------------------------------
# ACTIONS contract
# ---------------------------------------------------------------------------


def test_actions_tuple_complete():
    # Guards against accidental drift between the shim and the parser.
    expected = {
        "add",
        "agent",
        "list",
        "wipe",
        "forget",
        "inspect",
        "env",
        "version",
        "help",
        "man",
    }
    assert set(ROOT_ACTION.sub_actions.keys()) == expected


class TestTranslateEdgeCases:
    @pytest.mark.parametrize(
        "argv,expected_first",
        [
            # Action flag before / after / between global flags.
            (["--quiet", "--debug", "--stop", "all"], ["agent", "stop"]),
            (["--stop", "all", "--quiet", "--debug"], ["agent", "stop"]),
            (["--debug", "--stop", "all", "--quiet"], ["agent", "stop"]),
            # Wipe in the same positions.
            (["--quiet", "--wipe", "ssh"], ["wipe", "--ssh"]),
            (["--wipe", "ssh", "--quiet"], ["wipe", "--ssh"]),
        ],
    )
    def test_action_flag_position_matrix(self, argv, expected_first):
        out = translate(argv)
        assert out[:2] == expected_first
        # Every original global flag survives.
        for tok in argv:
            if tok.startswith("-") and tok not in ("--stop", "--wipe"):
                assert tok in out

    def test_repeated_action_flags_first_wins(self):
        # First action wins; the second is passed through so the parser
        # can complain about it (documented contract in compat.translate).
        out = translate(["--list", "--list-fp"])
        assert out[0] == "list"
        assert "--list-fp" in out

    def test_repeated_value_action_flags_first_wins(self):
        out = translate(["--stop", "all", "--stop", "mine"])
        assert out[:2] == ["agent", "stop"]
        # The second --stop and its argument come through verbatim.
        assert out.count("--stop") == 1  # only the second copy survives
        assert "mine" in out

    def test_dashdash_then_dash_prefixed_key_in_translate(self):
        out = translate(["--", "-foo"])
        assert out[0] == "add"
        assert "--" in out
        assert "-foo" in out

    def test_ssh_rm_with_no_keys(self):
        # Translate must not invent a key list; it just emits the action.
        assert translate(["--ssh-rm"]) == ["forget"]

    def test_ssh_rm_with_global_flag_interleaved(self):
        out = translate(["-r", "id_rsa", "--quiet"])
        assert out[0] == "forget"
        assert "id_rsa" in out
        assert "--quiet" in out


class TestEquivalentCommandQuoting:
    @pytest.mark.parametrize(
        "key",
        [
            "key with space",
            "key$with$dollar",
            "key;with;semicolon",
            "/c/Users/Foo Bar/.ssh/id_rsa",  # MSYS2-style path with a space
        ],
    )
    def test_quotes_shell_metacharacters(self, key):
        # shlex.quote will wrap any argument that needs escaping in single
        # quotes; the only exception is a bare alphanumeric/underscore token.
        # All of the above contain something shlex considers unsafe.
        rendered = COMPAT.equivalent_command(["add", key])
        assert "'" in rendered or '"' in rendered
        assert rendered.startswith("keychain add ")

    def test_quotes_specials(self):
        rendered = COMPAT.equivalent_command(["add", "key with space"])
        assert "'key with space'" in rendered


# ---------------------------------------------------------------------------
# Short-flag cluster expansion
# ---------------------------------------------------------------------------


class TestShortFlagClusters:
    def test_qL_expands_and_resolves_to_list(self):
        # ``-L`` was the keychain 2.x short for ``--list-fp``; it now
        # maps to the unified ``list`` action.
        out = translate(["-qL"])
        assert out[0] == "list"
        assert "-q" in out

    def test_qQ_passes_through_for_argparse_native_split(self):
        # -q and -Q are not action shorts, so the shim doesn't touch the
        # cluster -- argparse natively splits clusters of its own opts.
        out = translate(["-qQ", "id_rsa"])
        assert out[0] == "add"
        assert "-qQ" in out
        assert "id_rsa" in out

    def test_cluster_with_no_action_letter_passes_through(self):
        # No action letters in the cluster -- shim leaves it for argparse,
        # which natively splits short-option clusters of its own opts.
        out = translate(["-Dq"])
        assert out[0] == "add"
        # shim left the cluster alone; argparse picks it up downstream.
        assert "-Dq" in out

    def test_cluster_with_kr_expands_to_actions(self):
        # -r is the keychain 2.x short for --ssh-rm (now ``forget``).
        out = translate(["-qr", "id_rsa"])
        assert out[0] == "forget"
        assert "-q" in out
        assert "id_rsa" in out

    def test_cluster_after_dashdash_is_literal(self):
        # ``--`` ends option processing; clusters after it are literal keys.
        out = translate(["--", "-qL"])
        assert out[0] == "add"
        assert "-qL" in out
