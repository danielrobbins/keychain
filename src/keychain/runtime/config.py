# SPDX-License-Identifier: GPL-3.0-only
# keychain argument parser — no argparse dependency.
# Owns CLI parsing, .keychainrc layering, and effective-environment assembly.

from __future__ import annotations

import configparser
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

from .actions import ROOT_ACTION, UNSET, Action, Option
from .compat import COMPAT

_AGENT_ARG_ENVS = {
    "ssh_args": "KEYCHAIN_SSH_AGENT_ARGS",
    "gpg_args": "KEYCHAIN_GPG_AGENT_ARGS",
}


class _CaseInsensitiveConfigParser(configparser.ConfigParser):
    """ConfigParser that normalizes section names and keys to lowercase.

    This prevents user confusion when .keychainrc uses mixed-case section
    or key names (e.g. ``[Agent]`` vs ``[agent]``) that the underlying
    option tree normalizes to lowercase.
    """

    def optionxform(self, optionstr: str) -> str:
        return optionstr.lower()


class ParserError(Exception):
    """Raised when strict parsing hits an invalid flag or missing argument."""

    pass


class OptionError(Exception):
    """Raised when declarative option policy rejects a supplied option value.

    ``ParserError`` covers command-shape failures such as unknown flags.
    ``OptionError`` is reserved for options whose authored policy says the
    command is recognized but still invalid, such as a rejected value or a
    deprecated option that now hard-fails.
    """

    pass


class RuntimeConfig:
    """
    Fully-resolved Keychain configuration, taking into account CLI args.
    (ENV and keychainrc layering to be bolted on in later phases).

    See docs/parser-design.md for architecture.
    """

    def __init__(self) -> None:
        self.action_node: Action | None = None
        self.action: str = "help"
        self.parse_error: str | None = None

        # State stores for lazy lookup by Options
        self.environ: dict[str, str] = {}
        self.rc_data: dict[str, dict[str, str]] = {}

        self.positionals: list[str] = []
        self._parsed_positionals: dict[str, Any] = {}
        self.rc_warnings: list[str] = []
        self.option_warnings: list[str] = []
        self._pending_option_errors: list[str] = []
        self.env: dict[str, str] = {}

    def apply_keychainrc(self, environ_overrides: dict[str, str] | None = None) -> None:
        """Read .keychainrc and build the effective env mapping."""
        base_environ = environ_overrides if environ_overrides is not None else dict(os.environ)
        self.environ = dict(base_environ)

        # SECURITY: KEYCHAIN_* env vars are gated by --allow-env / -E.
        # Direct access to os.environ for KEYCHAIN_* vars is prohibited —
        # all such access must flow through the actions API so the
        # --allow-env gate is enforced.
        allow_env = self.get_value("allow_env")

        # Locate configuration file (KEYCHAIN_CONFIG is gated)
        config_path = base_environ.get("KEYCHAIN_CONFIG") if allow_env else None
        if config_path:
            rc_path = Path(config_path)
        else:
            rc_path = Path(base_environ.get("HOME", "~")).expanduser() / ".keychainrc"

        if not allow_env:
            for key in list(self.environ):
                if key.startswith("KEYCHAIN_"):
                    del self.environ[key]
        self.env = dict(self.environ)

        # Validate sections layout using AST — keys stored lowercase for
        # case-insensitive matching against the parser output.
        all_options_by_section: dict[str, set[str]] = defaultdict(set)

        def _scan_sections(node: Action):
            for opt in node.options.values():
                if opt.config_section:
                    all_options_by_section[opt.config_section.lower()].add(opt.effective_config_key.lower())
            for child in node.sub_actions.values():
                _scan_sections(child)

        _scan_sections(ROOT_ACTION)

        # Parse .keychainrc with case-insensitive key/section matching
        parser = _CaseInsensitiveConfigParser()
        if rc_path.is_file():
            try:
                parser.read(rc_path)
                for section in parser.sections():
                    if section not in all_options_by_section:
                        self.rc_warnings.append(f"Ignoring unknown section [{section}] in .keychainrc")
                        continue

                    self.rc_data[section] = {}
                    for key, val in parser.items(section):
                        if key not in all_options_by_section[section]:
                            self.rc_warnings.append(f"Ignoring unknown key '{key}' in section [{section}]")
                            continue
                        self.rc_data[section][key] = val
            except configparser.Error as e:
                self.rc_warnings.append(f"Failed to parse {rc_path}: {e}")

        for varname, env_name in _AGENT_ARG_ENVS.items():
            value = self._agent_arg_value(varname, env_name, base_environ, allow_env)
            if value:
                self.env[env_name] = str(value)

    def _agent_arg_value(self, varname: str, env_name: str, base_environ: dict[str, str], allow_env: bool) -> Any:
        if allow_env and env_name in base_environ:
            return base_environ[env_name]
        return self.get_value(varname)

    def get_option(self, varname: str, action_node: Action | None = None) -> Option | None:
        """Return the authored option visible from an action context.

        Why this exists:
        multiple actions intentionally reuse varnames like ``json``. A pure
        global lookup is therefore ambiguous and was one of the reasons the old
        registry-based approach leaked the wrong option into callers.

        How it is used:
        value reads, explicit-option checks, and output-mode selection all call
        this helper instead of reaching into the tree ad hoc.

        How it resolves and why:
        lookup walks the action lineage from ``ROOT_ACTION`` to the terminal
        node. That yields exactly the options visible for the selected command:
        globals first, then ancestor nodes, then the terminal action. We do not
        search sibling branches because runtime semantics should come from the
        chosen action path, not from unrelated parts of the tree.
        """
        node = self.action_node if action_node is None else action_node
        visible = self._visible_options(node or ROOT_ACTION)
        return visible.get_by_varname(varname)

    def get_value(self, varname: str) -> Any:
        """Resolve a parsed value dynamically (CLI -> Env -> RC -> Default)."""
        # 1. Quick check if it's a positional argument mapped by name
        if varname in self._parsed_positionals:
            return self._parsed_positionals[varname]

        # 2. Check the active options mapped to this action
        if self.action_node:
            active_options = self._visible_options(self.action_node)
            opt = self.get_option(varname, self.action_node)
            if opt:
                return opt.resolve_value(self.rc_data, self.environ)

            # 2.1 Check for exclusive group projection (e.g. "target" -> "mine")
            for active_opt in active_options.values():
                if (
                    active_opt.exclusive_group == varname
                    and active_opt.resolve_value(self.rc_data, self.environ) is True
                ):
                    return active_opt.varname

        return None

    def _gather_options(self, node: Action):
        class ActiveOptions:
            def __init__(self, opts_by_flag, opts_by_varname):
                self.by_flag = opts_by_flag
                self.by_varname = opts_by_varname

            def get(self, flag: str) -> Option | None:
                return self.by_flag.get(flag)

            def get_by_varname(self, varname: str) -> Option | None:
                return self.by_varname.get(varname)

            def update(self, other):
                self.by_flag.update(other.by_flag)
                self.by_varname.update(other.by_varname)

            def values(self):
                return self.by_varname.values()

        opts_flag = {}
        opts_var = {}
        for opt in node.options.values():
            if opt.option:
                opts_flag[opt.option] = opt
            for alias in opt.cli_aliases:
                opts_flag[alias] = opt
            opts_var[opt.varname] = opt
        return ActiveOptions(opts_flag, opts_var)

    def _visible_options(self, node: Action):
        """Return the options visible along the authored path to *node*.

        Why this exists:
        runtime lookup should answer "which options are visible for this
        command?" rather than "where is the first matching option anywhere in
        the tree?". The visible set is therefore the union of option scopes
        encountered while descending from ``ROOT_ACTION`` to the terminal node.

        How it is used:
        ``get_option()``, ``get_value()``, and ``has_option()`` all build their
        semantics from this merged view.

        Why it resolves this way:
        later nodes on the lineage overwrite earlier ones, so an action-local
        option cleanly overrides a same-named ancestor option without opening a
        sibling-branch ambiguity.
        """
        lineage = node.lineage()
        visible = self._gather_options(lineage[0])
        for entry in lineage[1:]:
            visible.update(self._gather_options(entry))
        return visible

    def has_option(self, name: str) -> bool:
        """Check if an option was explicitly provided in the active context.

        The active action tree path wins over a same-named option elsewhere in
        the tree, and exclusive-group projections remain visible through their
        synthetic group name.
        """
        opt = self.get_option(name)
        if opt is not None and opt._cli_value is not UNSET:
            return True

        if self.action_node:
            active_options = self._visible_options(self.action_node)
            for active_opt in active_options.values():
                if active_opt.exclusive_group == name and active_opt._cli_value is not UNSET:
                    return True

        return False

    def apply_option_policies(self, out) -> None:
        """Emit recorded option warnings and raise the next recorded option error.

        Why this exists:
        option declarations decide what is deprecated or invalid, but human-
        facing output should still flow through the same coordinator and
        ``Output`` object as the rest of the application.

        How it is used:
        ``KeychainApp._resolve_action()`` calls this once after dispatch is
        known. Warnings are emitted in order and the first pending hard failure
        is raised as ``OptionError``.

        Why it resolves this way:
        parse-time policy collection keeps validation close to the parser while
        deferring presentation until runtime, which avoids printing from deep
        inside parsing code and prevents duplicate warnings on repeated reads.
        """
        while self.option_warnings:
            out.warn(self.option_warnings.pop(0))
        if self._pending_option_errors:
            raise OptionError(self._pending_option_errors.pop(0))

    def _record_option_policy(self, opt: Option, value: Any) -> None:
        """Convert declarative option metadata into pending warnings or errors.

        Validation and deprecation are both authored on ``Option`` objects.
        This helper is called when an option is explicitly supplied so that the
        parser records policy outcomes once and the runtime can later present
        them without re-implementing option-specific logic.
        """
        error = opt.validate_value(value)
        if error:
            self._pending_option_errors.append(error)
            return

        notice = opt.deprecation_notice(value)
        if not notice:
            return
        if opt.deprecation_error:
            self._pending_option_errors.append(notice)
            return
        if notice not in self.option_warnings:
            self.option_warnings.append(notice)

    def _adapt_action_argv(
        self, tokens: list[str], action_node: Action, consumed_sequence: list[str]
    ) -> list[str] | None:
        """Rewrite structural action flags into canonical action-first argv.

        Why this exists:
        flags like ``--help`` are user-facing aliases for real actions. Rather
        than short-circuiting parse state and manually injecting fields like
        ``help_target``, we rewrite argv into the same canonical shape that a
        user could have typed directly.

        How it is used:
        ``_canonicalize_argv()`` runs this before compat translation. If a root
        structural option matches, its ``Option.action_adapter`` returns the
        canonical argv that should be parsed normally.

        Why it resolves this way:
        keeping the rewrite at the argv level means the existing action tree,
        positional binding, and handler flow continue to do the real work. The
        parser only has one normal execution path after canonicalization.
        """
        root_options = self._gather_options(ROOT_ACTION)

        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok == "--":
                break
            if not tok.startswith("-"):
                i += 1
                continue

            opt = self._resolve_alias(tok, root_options)
            if opt is None:
                i += 1
                continue

            adapted = opt.adapt_argv(tokens, i, action_node, consumed_sequence)
            if adapted is not None:
                return adapted

            if opt.takes_value and "=" not in tok:
                i += 2
            else:
                i += 1

        return None

    def _canonicalize_argv(self, tokens: list[str]) -> list[str]:
        """Return the canonical argv to parse for this invocation.

        Why this exists:
        both structural action flags (``--help``) and legacy compat forms
        (``--list``, ``--stop mine``) are alternate spellings of the same
        internal action tree. Canonicalizing them first keeps the rest of the
        parser focused on one action-first grammar.

        How it is used:
        ``_parse_with_compat()`` calls this once, then prescans and strictly
        parses the returned argv as though the user had typed it directly.

        Why it resolves this way:
        structural action adapters get first claim because they are part of the
        current CLI surface. If none applies and no action path was found, the
        older compat translator gets a chance to rewrite legacy 2.x forms.
        """
        action_node, _active_options, consumed_sequence = self._prescan_actions(tokens)
        adapted = self._adapt_action_argv(tokens, action_node, consumed_sequence)
        if adapted is not None:
            return adapted
        if action_node == ROOT_ACTION:
            if legacy_error := COMPAT.legacy_parse_error(tokens):
                raise ParserError(legacy_error)
            return COMPAT.translate(tokens)
        return tokens

    @classmethod
    def resolve(cls, argv: list[str] | None = None) -> RuntimeConfig:
        if argv is None:
            import sys

            argv = sys.argv[1:]

        obj = cls()
        try:
            obj._parse_with_compat(argv)
        except ParserError as exc:
            obj.parse_error = obj._friendly_parse_error(str(exc))

        obj.apply_keychainrc()
        return obj

    def _friendly_parse_error(self, message: str) -> str:
        """Convert strict parser failures into short user-facing messages.

        The public ``resolve()`` path is intentionally forgiving: callers get a
        partially resolved config plus a parse-error string instead of an
        exception. That lets the CLI return an intuitive exit code and a short
        redirect to the relevant help page without dumping full help text.
        """
        action = self.action_node.fq_name if self.action_node is not None and self.action_node != ROOT_ACTION else "add"
        help_cmd = f"keychain help {action}"

        prefix = "Unrecognized flag '"
        if message.startswith(prefix) and "'" in message[len(prefix) :]:
            flag = message[len(prefix) :].split("'", 1)[0]
            return f"Unrecognized option '{flag}'. Run '{help_cmd}' for more information."

        prefix = "Unrecognized argument '"
        if message.startswith(prefix) and "'" in message[len(prefix) :]:
            arg = message[len(prefix) :].split("'", 1)[0]
            return f"Unrecognized argument '{arg}'. Run '{help_cmd}' for more information."

        if message.startswith("Please specify "):
            return message

        return f"{message} Run '{help_cmd}' for more information."

    def _parse_with_compat(self, tokens: list[str]) -> None:
        """
        Phase 1 & 2: Pre-scan for action verbs and trigger compat fallback if needed.

        Phase 1 runs `_prescan_actions` to attempt a new-style resolution.
        Phase 2 checks if ANY action verbs were found. If `ROOT_ACTION` was still the current
        node, it indicates legacy calls like `keychain ~/.ssh/id_rsa` or `keychain --eval`.
        This is safely translated using `COMPAT.translate(tokens)` and the pre-scan is retried.
        """
        self._reset_all_cli()

        tokens_to_parse = self._canonicalize_argv(tokens)
        action_node, active_options, consumed_sequence = self._prescan_actions(tokens_to_parse)

        self.action_node = action_node
        self.action = action_node.fq_name or "help"

        # Phase 3 & 4: Strict validation and positional binding
        self._strict_parse(tokens_to_parse, action_node, active_options, consumed_sequence)
        if self.action == "help" and self._parsed_positionals.get("help_target") == []:
            self._parsed_positionals.pop("help_target", None)

    def _reset_all_cli(self) -> None:
        def _reset(node: Action):
            for opt in node.options.values():
                opt.reset_cli()
            for child in node.sub_actions.values():
                _reset(child)

        _reset(ROOT_ACTION)

    def _prescan_actions(self, tokens: list[str]) -> tuple[Action, dict[str, Option], list[str]]:
        """
        Phase 1: The Action-Seeking Pre-Scan

        Scans CLI tokens from left to right to build an action sequence.
        Since the AST defines `takes_value` for every known option, it intelligently skips
        over flags and their arguments, enabling us to cleanly determine the terminal action.

        Returns:
            - The final Action node found
            - A dictionary mapping active option strings to Option objects
            - The sequence of action verbs consumed from tokens (for later removal).
        """
        current_node = ROOT_ACTION
        active_options = self._gather_options(current_node)
        consumed_sequence = []

        i = 0
        while i < len(tokens):
            tok = tokens[i]

            if tok == "--":
                break

            if tok.startswith("-"):
                opt = self._resolve_alias(tok, active_options)
                if opt and opt.takes_value:
                    if "=" in tok:
                        i += 1
                        continue
                    i += 2  # skip flag and its positional argument
                    continue
                i += 1
                continue

            # Non-flag positional, see if it maps to a sub-action in the current tree level
            if tok in current_node.sub_actions:
                current_node = current_node.sub_actions[tok]
                active_options.update(self._gather_options(current_node))
                consumed_sequence.append(tok)
                i += 1
            else:
                # End of the action verb chain
                break

        return current_node, active_options, consumed_sequence

    def _resolve_alias(self, flag: str, active_options) -> Option | None:
        if "=" in flag:
            flag = flag.split("=", 1)[0]
        return active_options.get(flag)

    def _strict_parse(
        self, tokens: list[str], action_node: Action, active_options, consumed_sequence: list[str]
    ) -> None:
        """
        Phase 3: Strict Option Validation
        Phase 4: Positional Binding

        Traverses all tokens against the resolved action context.
        It strictly validates flags against known active options and raises `ParserError`
        for any unrecognized flags or missing arguments.
        Consumed action verbs are discarded and any leftovers are collected into positionals.
        Finally, Phase 4 runs `_map_positionals` to bind to the action arguments.
        """
        positionals = []
        i = 0
        after_dashdash = False
        action_verb_queue = list(consumed_sequence)

        while i < len(tokens):
            tok = tokens[i]

            if after_dashdash:
                positionals.append(tok)
                i += 1
                continue

            if tok == "--":
                after_dashdash = True
                i += 1
                continue

            if tok.startswith("-"):
                flag, _, inline_val = tok.partition("=")
                opt = active_options.get(flag)

                if not opt:
                    # Temporary rescue for structural help/version flags if they aren't explicitly registered
                    if flag in ("-h", "--help"):
                        opt = active_options.get("--help")
                        if opt:
                            self._set_opt(opt, None)
                            i += 1
                            continue
                    raise ParserError(f"Unrecognized flag '{tok}'")

                if opt.takes_value:
                    if inline_val:
                        self._set_opt(opt, inline_val)
                    elif i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                        self._set_opt(opt, tokens[i + 1])
                        i += 1
                    else:
                        raise ParserError(f"Option '{flag}' requires an argument.")
                else:
                    if inline_val:
                        raise ParserError(f"Option '{flag}' does not take a value.")
                    self._set_opt(opt, None)
                i += 1
            else:
                # Is it one of the action verbs we matched in phase 1? Expand and skip.
                if action_verb_queue and tok == action_verb_queue[0]:
                    action_verb_queue.pop(0)
                    i += 1
                    continue

                positionals.append(tok)
                i += 1

        self.positionals = positionals
        self._map_positionals(positionals, action_node.arguments, action_node.fq_name)

    def _set_opt(self, opt: Option, val: str | None) -> None:
        if opt.argparse_action == "append":
            # Direct append against the _cli_value state layer
            from .actions import UNSET

            if opt._cli_value is UNSET:
                opt._cli_value = []
            opt._cli_value.append(val)
            self._record_option_policy(opt, val)
        elif val is not None:
            coerced = opt._coerce(val)
            if coerced is None and opt.type == "int":
                raise ParserError(f"Option '{opt.option}' expects an integer.")
            opt._cli_value = coerced
            self._record_option_policy(opt, coerced)
        elif opt.type == "bool":
            opt._cli_value = True
            self._record_option_policy(opt, True)
        else:
            opt._cli_value = val
            self._record_option_policy(opt, val)

    def _map_positionals(self, positionals: list[str], arguments: tuple[dict, ...], action_name: str) -> None:
        index = 0
        for arg in arguments:
            name = arg["name"]
            nargs = arg.get("nargs")
            if nargs in ("*", "+"):
                self._parsed_positionals[name] = positionals[index:]
                return
            else:
                self._parsed_positionals[name] = positionals[index] if index < len(positionals) else None
                index += 1

        if index < len(positionals):
            raise ParserError(f"Unrecognized argument '{positionals[index]}'")
