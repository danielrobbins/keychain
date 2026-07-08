# SPDX-License-Identifier: GPL-3.0-only
"""Compatibility shim: translate keychain 2.x flat-flag argv into new-style actions.

The ``cli`` module exposes a single action-driven argparse tree (verbs like
``add``, ``stop``, ``wipe``). To preserve backwards compatibility with the
long-standing keychain 2.x flat-flag interface (``keychain --stop all``,
``keychain --wipe ssh``, ``keychain --list`` ...) we sniff incoming argv for
a recognized action token. When none is present we run the argv through
:func:`translate` -- which rewrites the *legacy action flags* into their
verb-equivalent positional form -- and re-invoke the parser on the translated
argv. The translation is otherwise a pass-through, so every non-action option
keeps working unchanged.

This keeps a single internal parser (no branching on "old vs new" further down)
and lets us surface a hint showing the equivalent new command.
"""

from __future__ import annotations

from .actions import ROOT_ACTION


class Compat:
    bool_actions = {
        "--list": "list",
        "-l": "list",
        "--list-fp": "list",
        "-L": "list",
        "--query": "env",
        "--ssh-rm": "forget",
        "-r": "forget",
        "--inspect": "inspect",
        "--help": "help",
        "-h": "help",
        "--version": "version",
        "-V": "version",
    }
    value_actions = ("--stop", "-k", "--wipe")
    incomplete_explain_actions = {
        "--wipe": (("wipe",), "--wipe expects one of: ssh, gpg, all."),
        "--stop": (("agent", "stop"), "--stop expects one of: all, mine, others."),
        "-k": (("agent", "stop"), "-k/--stop expects one of: all, mine, others."),
    }

    def __init__(self, actions: tuple[str, ...]) -> None:
        """Pass the tuple of known action verbs (e.g. ``('add', 'list', 'wipe', ...)``).
        Only tokens in this set are treated as action names during translation."""
        self.actions = actions
        self.short_actions = frozenset(flag[1:] for flag in self.bool_actions if len(flag) == 2)
        self.short_actions |= frozenset(flag[1:] for flag in self.value_actions if len(flag) == 2)

    @classmethod
    def build(cls) -> Compat:
        """Create a ``Compat`` instance pre-loaded with the actions defined in ``actions.py``.
        This is the normal entry point; use ``__init__`` directly only in tests."""
        return cls(tuple(ROOT_ACTION.sub_actions.keys()))

    def split_eq(self, token: str) -> tuple[str, str | None]:
        """Split ``--flag=value`` into ``("--flag", "value")``, or return ``(token, None)`` unchanged.
        Used internally by ``translate`` and ``explain`` to handle both ``--wipe=ssh`` and ``--wipe ssh`` forms."""
        if token.startswith("--") and "=" in token:
            key, _, value = token.partition("=")
            return key, value
        return token, None

    def split_short_cluster(self, token: str) -> list[str] | None:
        """Split a short-flag cluster like ``-qL`` into ``["-q", "-L"]``, but only when
        the cluster contains at least one legacy action letter (e.g. ``L``, ``k``).
        Returns ``None`` for clusters that contain no action letters, leaving them for argparse."""
        if not (len(token) > 2 and token.startswith("-") and not token.startswith("--")):
            return None
        letters = token[1:]
        if not letters.isalpha() or not any(letter in self.short_actions for letter in letters):
            return None
        return [f"-{letter}" for letter in letters]

    def _expand_argv(self, argv: list[str]) -> list[str]:
        """Expand only legacy action-bearing short clusters before analysis.

        This keeps the compatibility layer's view of argv consistent across
        translation and validation without teaching it about every ordinary
        short-option cluster that argparse already understands natively.
        """
        expanded: list[str] = []
        seen_dashdash = False
        for token in argv:
            if seen_dashdash:
                expanded.append(token)
                continue
            if token == "--":
                seen_dashdash = True
                expanded.append(token)
                continue
            split = self.split_short_cluster(token)
            if split is not None:
                expanded.extend(split)
            else:
                expanded.append(token)
        return expanded

    def legacy_parse_error(self, argv: list[str]) -> str | None:
        """Return a legacy-specific validation error for 2.x value-actions.

        This preserves the old parser's targeted diagnostics for a small number
        of flat action flags that historically validated their arguments before
        any deeper command dispatch occurred.
        """
        if self.looks_new_style(argv):
            return None

        expanded = self._expand_argv(argv)
        for i, token in enumerate(expanded):
            if token == "--":
                break
            key, eq_value = self.split_eq(token)
            if key not in self.value_actions:
                continue
            value = eq_value
            if value is None:
                if i + 1 >= len(expanded):
                    value = None
                else:
                    candidate = expanded[i + 1]
                    value = None if candidate == "--" or candidate.startswith("-") else candidate

            if key in ("--stop", "-k"):
                if value not in ("all", "mine", "others"):
                    return "Please specify 'all', 'mine' or 'others' for --stop"
            elif key == "--wipe":
                if value not in ("ssh", "gpg", "all"):
                    return "Please specify ssh, gpg or all for --wipe action"
        return None

    def looks_new_style(self, argv: list[str]) -> bool:
        """Return ``True`` if argv already starts with a known action verb (e.g. ``['add', ...]``)."""
        for token in argv:
            if token == "--":
                return False
            if token.startswith("-"):
                continue
            return token in self.actions
        return False

    def translate(self, argv: list[str]) -> list[str]:
        """Convert a legacy keychain 2.x argv into the new action-first form.

        Examples: ``['--list']`` -> ``['list']``,
        ``['--wipe', 'ssh']`` -> ``['wipe', '--ssh']``,
        ``['--stop', 'mine']`` -> ``['agent', 'stop', '--mine']``,
        ``['id_ed25519']`` -> ``['add', 'id_ed25519']``.
        Unrecognised tokens are passed through so argparse can reject them."""
        out_opts: list[str] = []
        out_keys: list[str] = []
        subcmd: str | None = None
        sub_args: list[str] = []
        expanded = self._expand_argv(argv)
        i = 0
        after_dashdash = False
        while i < len(expanded):
            token = expanded[i]
            if after_dashdash:
                out_keys.append(token)
                i += 1
                continue
            if token == "--":
                after_dashdash = True
                out_opts.append(token)
                i += 1
                continue
            key, eq_value = self.split_eq(token)
            if key in self.bool_actions and eq_value is None:
                if subcmd is None:
                    subcmd = self.bool_actions[key]
                else:
                    out_opts.append(token)
                i += 1
                continue
            if key in self.value_actions:
                value = eq_value
                if value is None:
                    if i + 1 >= len(expanded):
                        out_opts.append(token)
                        i += 1
                        continue
                    value = expanded[i + 1]
                    i += 2
                else:
                    i += 1
                if key in ("--stop", "-k"):
                    if subcmd is None:
                        subcmd = "agent"
                        if value == "all":
                            sub_args = ["stop"]
                        elif value in ("mine", "others"):
                            sub_args = ["stop", f"--{value}"]
                        else:
                            sub_args = ["stop", value]
                    else:
                        out_opts.append(token)
                        if eq_value is None:
                            out_opts.append(value)
                else:
                    if subcmd is None:
                        subcmd = "wipe"
                        if value == "all":
                            sub_args = []
                        elif value in ("ssh", "gpg"):
                            sub_args = [f"--{value}"]
                        else:
                            sub_args = [value]
                    else:
                        out_opts.append(token)
                        if eq_value is None:
                            out_opts.append(value)
                continue
            if token.startswith("-"):
                out_opts.append(token)
            else:
                out_keys.append(token)
            i += 1
        result = [subcmd or "add", *sub_args, *out_opts]
        if out_keys:
            result.extend(out_keys)
        return result

    def equivalent_command(self, translated_argv: list[str]) -> str:
        """Format a translated argv list as a shell-safe ``keychain <args>`` string.
        Used to show users the modern equivalent of the legacy command they ran."""
        import shlex

        return f"keychain {shlex.join(translated_argv)}"

    def explain(self, argv: list[str]) -> tuple[list[str], str | None, str | None] | None:
        """Translate legacy argv for ``--explain`` mode, returning ``(argv, display_cmd, note)``.

        Unlike ``translate``, a bare value-taking action (e.g. ``--wipe`` with no argument)
        is returned as-is with a note rather than consuming the next token as its value.
        Returns ``None`` when argv is already in new-style form."""
        if self.looks_new_style(argv):
            return None
        for i, token in enumerate(argv):
            if token == "--":
                break
            key, eq_value = self.split_eq(token)
            mapped = self.incomplete_explain_actions.get(key)
            if mapped is None or eq_value not in (None, ""):
                continue
            next_token = argv[i + 1] if eq_value is None and i + 1 < len(argv) else None
            if next_token is not None and next_token != "--" and not next_token.startswith("-"):
                continue
            replacement, note = mapped
            translated = argv[:i] + list(replacement) + argv[i + 1 :]
            return translated, self.equivalent_command(list(replacement)), note
        translated = self.translate(argv)
        if translated != ["add", *argv]:
            return translated, self.equivalent_command(translated), None
        return None

    def action_after_key_hint(self, argv: list[str]) -> tuple[str, str] | None:
        """Detect the keychain 2.x mistake of placing a legacy action flag after a key argument,
        e.g. ``keychain id_ed25519 --list``. Returns ``(legacy_flag, new_action_name)`` so the
        caller can show a targeted hint, or ``None`` if no such pattern is found."""
        seen_key = False
        for i, token in enumerate(argv):
            if token == "--":
                return None
            if token.startswith("-"):
                key, _eq_value = self.split_eq(token)
                if seen_key:
                    if key in self.bool_actions:
                        return key, self.bool_actions[key]
                    if key in self.value_actions:
                        translated = self.translate(argv[i:])
                        return key, " ".join(translated) if translated else key
                continue
            if token:
                seen_key = True
        return None


COMPAT = Compat.build()
