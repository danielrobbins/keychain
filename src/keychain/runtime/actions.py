# SPDX-License-Identifier: GPL-3.0-only
"""Authored embedded-doc records for keychain.

This is the single source of truth for every doc string keychain emits:
``--help`` cheat sheets, argparse ``help=`` strings, ``keychain man``,
``keychain --explain``, and the generated ``keychain.1`` man page.

**Formatting rules:**

To make keychain-specific principals stand out from the surrounding prose and
secondary commands, keychain documentation follows these formatting conventions:

* Keychain actions and options/arguments should be in double-backticks (``like this``).
* External commands directly related to keychain (e.g. ``ssh-agent``, ``ssh-add``, ``ssh``, ``scp``) should also be in double-backticks.
* Ancillary commands that users are expected to know but aren't the focus of the docs (e.g. ``eval``, ``systemctl``) should be in asterisks (e.g. *eval*, *systemctl*).
* Configuration files and directories exclusive to keychain should be in
  double-backticks (e.g. ``~/.keychain/``, ``~/.keychainrc``)
* More general files like ``~/.ssh/config`` should be emphasized with asterisks (e.g. *~/.ssh/config*, *~/.bash_profile*).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Optional

from keychain.output.core import Output

from ..doc_texts import DOC_TEXT

OUTPUT_ACTIONS = frozenset(("man", "version", "help"))
NO_BANNER_ACTIONS = frozenset(("inspect", "list", "env"))

UNSET = object()
ActionAdapter = Callable[[list[str], int, "Action", tuple[str, ...]], Optional[list[str]]]


def _help_action_adapter(
    tokens: list[str],
    index: int,
    _action_node: Action,
    consumed_sequence: tuple[str, ...],
) -> list[str]:
    """Rewrite ``--help`` forms into canonical ``help ...`` argv.

    Why this exists:
    ``--help`` is part of the public CLI surface, but internally ``help`` is a
    real action with a normal positional ``help_target`` argument. Rewriting the
    argv keeps that action as the single implementation path instead of teaching
    the parser a separate help-only side channel.

    How it resolves:
    if the user already selected an action path (for example ``add --help``),
    that path becomes the help target. Otherwise the adapter consumes the
    successive non-flag tokens after ``--help`` (for example ``--help agent
    stop``) and turns them into the help target.
    """
    if consumed_sequence:
        return ["help", *consumed_sequence]

    target: list[str] = []
    i = index + 1
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--" or tok.startswith("-"):
            break
        target.append(tok)
        i += 1
    return ["help", *target]


def _version_action_adapter(
    _tokens: list[str],
    _index: int,
    _action_node: Action,
    _consumed_sequence: tuple[str, ...],
) -> list[str]:
    """Rewrite version flags into canonical ``version`` argv.

    ``version`` does not take a positional target, so the canonical form is the
    bare action token.
    """
    return ["version"]


@dataclass(eq=False)
class Element:
    varname: str = ""  # variable name used to reference internal RuntimeConfig property
    doc_tag: str | None = None  # embedded-doc catalog key; derived from name if omitted
    see_also: tuple[str, ...] = ()  # related action names or topic keys

    @property
    def short_help(self) -> str:
        return DOC_TEXT.short_help(self.doc_tag or "")

    @property
    def doc_description(self) -> str:
        return DOC_TEXT.description(self.doc_tag or "")


@dataclass(eq=False)
class Option(Element):
    option: str | None = None  # the primary CLI flag spelling, e.g. "--eval"
    cli_aliases: tuple[str, ...] = ()  # additional flag spellings, e.g. ("-q",)
    actions: set[Action] = field(default_factory=set)  # action(s) this option belongs to
    type: str = "bool"  # value type: "bool" (store_true), "int", or "str"
    default: object = None  # default value injected into the args Namespace
    choices: tuple[str, ...] = ()  # restricts argparse to this set of values
    metavar: str | None = None  # display name for the value in usage output
    argparse_action: str | None = None  # explicit argparse action= override (e.g. "store_true", "append")
    exclusive_group: str | None = None  # bucket key for add_mutually_exclusive_group()
    env: str | None = None  # environment variable to set when option is specified
    hidden: bool = False  # skip this option in visible help output; used for deprecated options
    config_section: str | None = None  # INI section name for config file binding
    config_key: str | None = None  # INI key override; defaults to name if omitted
    examples: tuple[tuple[str, str], ...] = ()  # (description, command) pairs for docs
    action_adapter: ActionAdapter | None = None  # canonical argv rewriter for structural action-equivalent flags
    deprecated: bool = False  # deprecated options are auto-hidden and emit policy feedback when used
    deprecation_message: str | Callable[[Any], str] | None = None  # warning/error text for deprecated usage
    deprecation_error: bool = False  # deprecated options can hard-fail instead of warning
    validator: tuple[Callable[[Any], bool], str | Callable[[Any], str]] | None = None  # value rule + failure text

    @property
    def option_formats(self):
        out = self.option
        for a in self.cli_aliases:
            out += f", {a}"
        return out

    @property
    def argparse_flags(self) -> list[str]:
        flags = [self.option] if self.option else []
        flags.extend(self.cli_aliases)
        return flags

    @property
    def takes_value(self) -> bool:
        return self.type != "bool"

    @property
    def effective_config_key(self) -> str:
        return self.config_key or self.varname

    def __post_init__(self) -> None:
        if not self.varname and self.option:
            self.varname = self.option.lstrip("-").replace("-", "_")
        if not self.doc_tag:
            key = self.option.lstrip("-") if self.option else self.varname.replace("_", "-")
            self.doc_tag = f"option:{key}"
        if self.deprecated:
            self.hidden = True

        self._cli_value: Any = UNSET

        for act in self.actions:
            act.options[self.varname] = self

    def deprecation_notice(self, value: Any) -> str | None:
        """Return the message to emit when this deprecated option is used.

        Why this exists:
        the refactor goal is for options to own their own lifecycle policy.
        Callers should not need separate switch statements just to remember
        which legacy flags still exist and what guidance to print for them.

        How it is used:
        ``RuntimeConfig`` calls this after a CLI value is accepted. The returned
        text is either emitted as a warning or promoted to an error depending on
        ``deprecation_error``.

        Why it resolves this way:
        static strings cover common cases, while a callable allows a deprecated
        option to tailor its guidance to the supplied value.
        """
        if not self.deprecated:
            return None
        if callable(self.deprecation_message):
            return self.deprecation_message(value)
        if self.deprecation_message:
            return self.deprecation_message
        return f"{self.option or self.varname} is deprecated."

    def adapt_argv(
        self,
        tokens: list[str],
        index: int,
        action_node: Action,
        consumed_sequence: list[str],
    ) -> list[str] | None:
        """Rewrite raw argv into canonical action-first form when requested.

        Why this exists:
        some root flags are really alternate spellings of actions. Rewriting the
        full argv into canonical action-first form lets the normal parser bind
        action arguments and options without adding one-off parser state.

        How it is used:
        ``RuntimeConfig`` scans root options before compat translation and asks
        the matched structural option, if any, to return canonical argv.

        Why it resolves this way:
        the option owns the knowledge of how its flag maps into action syntax,
        so the parser only needs to apply the rewrite and then continue with one
        ordinary parse flow.
        """
        if self.action_adapter is None:
            return None
        return self.action_adapter(tokens, index, action_node, tuple(consumed_sequence))

    def validate_value(self, value: Any) -> str | None:
        """Return a validation error string when *value* violates option policy.

        Why this exists:
        rules like "positive integer" are part of an option's authored meaning
        and should live beside the option declaration, not inside unrelated
        runtime coordinator code.

        How it is used:
        ``RuntimeConfig`` calls this after coercing a CLI value. ``None`` means
        the value is acceptable; any returned string becomes the user-facing
        error for that option.

        Why it resolves this way:
        a predicate plus message keeps validation lightweight and declarative
        without inventing a larger schema or type system.
        """
        if self.validator is None:
            return None
        predicate, message = self.validator
        if predicate(value):
            return None
        if callable(message):
            return message(value)
        return message

    def _coerce(self, raw: str) -> Any:
        """Coerce raw strings to the appropriate Python type based on self.type."""
        if self.type == "bool":
            return raw.strip().lower() in ("true", "yes", "on", "1")
        if self.type == "int":
            try:
                return int(raw.strip())
            except ValueError:
                return None
        return raw.strip()

    def resolve_value(self, rc_data: dict[str, dict[str, str]], environ: dict[str, str]) -> Any:
        """O(1) Dynamic Lookup respecting the config hierarchy."""

        # 1. CLI (Highest Priority)
        if self._cli_value is not UNSET:
            return self._cli_value

        # 2. Environment Variables
        if self.env and self.env in environ:
            return self._coerce(environ[self.env])

        # 3. .keychainrc
        if self.config_section and rc_data:
            section = rc_data.get(self.config_section, {})
            effective_key = self.config_key or self.varname
            if effective_key in section:
                return self._coerce(section[effective_key])

        # 4. Fallback Default
        if self.default is not None:
            return self.default
        return False if self.type == "bool" else None

    def reset_cli(self) -> None:
        """Reset the CLI-provided value, usually invoked before a compat fallback parse."""
        self._cli_value = UNSET


@dataclass(eq=False)
class Action(Element):
    fq_name: str = ""
    arguments: tuple[dict, ...] = ()
    examples: tuple[tuple[str, str], ...] = ()
    parent: Action | None = None
    sub_actions: dict[str, Action] = field(default_factory=dict)
    options: dict[str, Option] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.fq_name:
            raise ValueError("Action requires a non-empty fq_name")
        if not self.varname:
            self.varname = self.fq_name.split()[-1]
        if not self.doc_tag:
            self.doc_tag = f"action:{self.fq_name}"

        if self.parent is not None:
            self.parent.sub_actions[self.varname] = self

    def add_action(self, **kwargs) -> Action:
        return Action(parent=self, **kwargs)

    def add_option(self, **kwargs) -> Option:
        return Option(actions={self}, **kwargs)

    def lineage(self) -> tuple[Action, ...]:
        """Return the authored action path from ``ROOT_ACTION`` to this node.

        Why this exists:
        runtime option semantics should come from the action tree itself, not
        from whole-tree searches that can accidentally pick up sibling options.
        The lineage is the exact structural context the user selected.

        How it is used:
        ``RuntimeConfig`` walks this chain to collect the options that are
        actually visible for the active command: global options first, then each
        ancestor node, then the terminal action.

        Why it resolves this way:
        the parent pointers already encode the unique path through the action
        tree. Reconstructing the path from parents avoids maintaining a second
        registry or cache for "visible option sets".
        """
        nodes: list[Action] = []
        node: Action | None = self
        while node is not None:
            nodes.append(node)
            node = node.parent
        nodes.reverse()
        return tuple(nodes)

    def find_action(self, target: str | list[str] | None) -> Action | None:
        """Resolve an authored action path by walking the tree from this node.

        Why this exists:
        the refactor is deliberately moving away from side registries such as
        ``ACTIONS`` and toward ``ROOT_ACTION`` as the single source of truth.
        Callers should not have to reconstruct lookup logic or keep a second
        mapping alive just to answer "what action does this token path name?".

        How it is used:
        ``main.helpinfo()`` and option-promotion code can pass either a joined
        path like ``"agent stop"`` or tokenized input like
        ``["agent", "stop"]`` and receive the terminal authored
        :class:`Action` node.

        How it resolves:
        the method normalizes the incoming representation into tokens, then
        walks ``sub_actions`` one token at a time. Returning ``None`` for an
        unknown hop keeps lookup failures explicit and avoids reintroducing the
        old global-registry fallback behavior.
        """
        if target is None:
            return self

        if isinstance(target, str):
            tokens = [token for token in target.split() if token]
        else:
            tokens = [token for token in target if token]

        node: Action = self
        for token in tokens:
            next_node = node.sub_actions.get(token)
            if next_node is None:
                return None
            node = next_node
        return node

    @property
    def dispatch_name(self) -> str:
        """Return the concrete handler suffix that ``KeychainApp`` should call.

        Why this exists:
        ``main.py`` still dispatches to methods with names like
        ``_handle_agent_start_action``. That method naming is an implementation
        detail, but the logic for translating an authored action node into that
        suffix belongs with the action tree itself, not in a separate block of
        string handling in the entrypoint.

        How it is used:
        ``KeychainApp._resolve_action()`` asks the resolved terminal
        :class:`Action` for its dispatch name and then looks up the matching
        handler method.

        Why it resolves this way:
        output-only top-level actions already have one-to-one handler names, so
        they keep their fq-name unchanged. Nested actions collapse whitespace to
        underscores because that matches the historical handler surface. The
        property raises for ``ROOT_ACTION`` and grouping nodes such as
        ``agent`` so callers cannot silently dispatch a non-terminal node.
        """
        if self.fq_name == "global":
            raise ValueError("ROOT_ACTION does not map to a concrete handler")
        if self.sub_actions and self.fq_name not in OUTPUT_ACTIONS:
            raise ValueError(f"{self.fq_name} is a grouping action and needs a subcommand")
        if self.fq_name in OUTPUT_ACTIONS:
            return self.fq_name
        return self.fq_name.replace(" ", "_")

    @property
    def command(self) -> str:
        if self.fq_name == "global":
            return "keychain"
        return f"keychain {self.fq_name}"

    def _option_rows(self) -> list[tuple[str, str]]:
        rows: list[tuple[str, str]] = []
        for opt in self.options.values():
            if opt.hidden:
                continue
            rows.append((opt.option_formats, opt.short_help))
        return rows

    def _print_option_section(self, title: str, out: Output) -> None:
        rows = self._option_rows()
        if not rows:
            return
        print()
        print(f"  {out.head(title)}")
        width = max((len(label) for label, _ in rows), default=0)
        for label, desc in rows:
            print(f"    {out.head(f'{label:<{width}}')}  {out.format_doc(desc)}")

    def _print_child_option_sections(self, out: Output) -> None:
        for child in self.sub_actions.values():
            child._print_option_section(f"Options for {child.varname}", out)
            child._print_child_option_sections(out)

    def help(self, out: Output) -> None:
        """Render the cheat-sheet view for this action.

        ``ROOT_ACTION`` keeps a dedicated top-level layout because users expect
        the command overview to lead with action names and global flags rather
        than the per-action command banner used by nested action help.
        """
        if self.fq_name == "global":
            print("Actions")
            width = max((len(child.varname) for child in self.sub_actions.values()), default=0)
            for child in self.sub_actions.values():
                print(f"  {out.head(f'{child.varname:<{width}}')}  {out.format_doc(child.short_help)}")

            rows = self._option_rows()
            if rows:
                print()
                print("Global options")
                width = max((len(label) for label, _ in rows), default=0)
                for label, desc in rows:
                    print(f"  {out.head(f'{label:<{width}}')}  {out.format_doc(desc)}")

            print()
            print(f"See {out.kbd('keychain man')} for full documentation, or")
            print(f"    {out.kbd('keychain man --list')} to list all available manual pages.")
            print()
            return

        print()
        print(f"  {out.head(self.command)}   {out.format_doc(self.short_help)}")

        if self.sub_actions:
            print()
            print(f"  {out.head('Sub-commands')}")
            width = max((len(child.varname) for child in self.sub_actions.values()), default=0)
            for child in self.sub_actions.values():
                print(f"    {out.head(f'{child.varname:<{width}}')}  {out.format_doc(child.short_help)}")

        self._print_option_section("Options", out)
        self._print_child_option_sections(out)

        print()
        print(
            f"  All global options also apply (e.g. {out.flag('--debug')}, "
            f"{out.flag('--dir')}, {out.flag('--host')})."
        )
        print(f"  Run {out.kbd('keychain <action> --help')} for action-specific flags.")
        print(f"  See {out.kbd('keychain man')} for full documentation, or")
        print(f"      {out.kbd('keychain man --list')} to list all available manual pages.")
        print()


# -------------------------------------------------------------------------------
# Global tree registry
# -------------------------------------------------------------------------------
ROOT_ACTION = Action(fq_name="global", varname="global")

ROOT_ACTION.add_option(
    option="--help",
    cli_aliases=("-h",),
    action_adapter=_help_action_adapter,
    doc_tag="action:help",
)
ROOT_ACTION.add_option(
    option="--version",
    cli_aliases=("-V",),
    action_adapter=_version_action_adapter,
    doc_tag="action:version",
)
ROOT_ACTION.add_option(option="--explain", see_also=("man",))

# Security gate: all KEYCHAIN_* env var ingestion is disabled by default.
# Set --allow-env (or -E) to permit KEYCHAIN_CONFIG, KEYCHAIN_THEME,
# KEYCHAIN_SSH_AGENT_ARGS, and KEYCHAIN_GPG_AGENT_ARGS to take effect.
ROOT_ACTION.add_option(option="--allow-env", cli_aliases=("-E",), type="bool", default=False)

ROOT_ACTION.add_option(option="--quiet", cli_aliases=("-q",), config_section="output")
ROOT_ACTION.add_option(option="--debug", cli_aliases=("-D",), config_section="output")
ROOT_ACTION.add_option(option="--nocolor", cli_aliases=("--no-color",), config_section="output")
ROOT_ACTION.add_option(option="--theme", type="str", hidden=True, config_section="output")
ROOT_ACTION.add_option(option="--no-gui", cli_aliases=("--nogui",), config_section="output", hidden=True)

# Deprecated NO-OPs
ROOT_ACTION.add_option(option="--gpg2", hidden=True, config_section="agent")
ROOT_ACTION.add_option(option="--absolute", hidden=True, config_section="paths")
ROOT_ACTION.add_option(option="--dir", type="str", default="~/.keychain", config_section="paths")
ROOT_ACTION.add_option(option="--host", type="str", config_section="paths")
ROOT_ACTION.add_option(option="--pid-formats", type="str", default="sh", config_section="paths")

cmd_add = ROOT_ACTION.add_action(
    fq_name="add",
    examples=(
        ("Add an SSH key (start agent if needed)", "keychain add ~/.ssh/id_ed25519"),
        ("Just spawn an agent and emit shell env", "eval `$(keychain add --eval)`"),
        ("Load a GPG key by ID", "keychain add gpgk:ABCDEF1234567890"),
    ),
    arguments=({"name": "keys", "nargs": "*"},),
    see_also=("ssh-add(1)", "topic:extkeys", "topic:agents"),
)

cmd_agent = ROOT_ACTION.add_action(fq_name="agent", see_also=("add", "topic:agents"))

agent_start = cmd_agent.add_action(
    fq_name="agent start",
    examples=(("Start agent and emit env in current shell", "eval `$(keychain agent start --eval)`"),),
    see_also=("add", "env", "topic:agents"),
)

agent_stop = cmd_agent.add_action(
    fq_name="agent stop",
    examples=(("Stop only my own agents", "keychain agent stop --mine"),),
    see_also=("topic:agents",),
)

cmd_list = ROOT_ACTION.add_action(fq_name="list")
cmd_wipe = ROOT_ACTION.add_action(fq_name="wipe")
cmd_forget = ROOT_ACTION.add_action(fq_name="forget", arguments=({"name": "keys", "nargs": "*"},))
cmd_env = ROOT_ACTION.add_action(fq_name="env")
cmd_inspect = ROOT_ACTION.add_action(fq_name="inspect", arguments=({"name": "keys", "nargs": "*"},))
cmd_help = ROOT_ACTION.add_action(fq_name="help", arguments=({"name": "help_target", "nargs": "*"},), see_also=("man",))
cmd_man = ROOT_ACTION.add_action(fq_name="man", arguments=({"name": "topics", "nargs": "*"},), see_also=("help",))
cmd_version = ROOT_ACTION.add_action(fq_name="version")

# Add shared options
Option(
    option="--eval", actions={cmd_add, agent_start}, config_section="output", config_key="eval", see_also=("--systemd",)
)
Option(option="--systemd", actions={cmd_add, agent_start}, config_section="agent", see_also=("--eval",))

cmd_add.add_option(option="--quick", cli_aliases=("-Q",), config_section="agent")
cmd_add.add_option(varname="noask", option="--no-passphrase", cli_aliases=("--noask",), config_section="agent")
cmd_add.add_option(option="--confirm", config_section="agent", doc_tag="option:confirm")
cmd_add.add_option(
    option="--timeout",
    type="int",
    config_section="agent",
    doc_tag="option:timeout",
    validator=(lambda value: value > 0, "--timeout requires a numeric argument greater than zero"),
)
cmd_add.add_option(varname="ignore_missing", option="--ignore-missing", config_section="keys")
cmd_add.add_option(option="--clear", hidden=True, config_section="agent", doc_tag="option:clear")
cmd_add.add_option(option="--extended", cli_aliases=("--ext", "-e"), hidden=True, config_section="keys")
cmd_add.add_option(option="--confallhosts", config_section="keys", doc_tag="option:confallhosts")

Option(option="--ssh-allow-gpg", actions={cmd_add, agent_start}, hidden=True, config_section="agent")
Option(option="--ssh-spawn-gpg", actions={cmd_add, agent_start}, hidden=True, config_section="agent")
Option(option="--ssh-allow-forwarded", actions={cmd_add, agent_start}, hidden=True, config_section="agent")
Option(
    varname="no_inherit",
    option="--no-inherit",
    cli_aliases=("--noinherit",),
    actions={cmd_add, agent_start},
    hidden=True,
    config_section="agent",
)
Option(option="--ssh-agent-socket", actions={cmd_add, agent_start}, type="str", hidden=True, config_section="agent")
Option(
    option="--ssh-agent-args",
    varname="ssh_args",
    type="str",
    config_section="agent.env",
    actions={cmd_add, agent_start},
    doc_tag="config:agent.env.ssh_args",
)
Option(
    option="--gpg-agent-args",
    varname="gpg_args",
    type="str",
    config_section="agent.env",
    actions={cmd_add, agent_start},
    doc_tag="config:agent.env.gpg_args",
)
Option(
    varname="ssh_askpass_program",
    type="str",
    config_section="ssh.askpass",
    config_key="program",
    actions={cmd_add, agent_start},
    hidden=True,
    doc_tag="config:ssh.askpass.program",
)
Option(
    varname="ssh_askpass_mode",
    type="str",
    default="auto",
    config_section="ssh.askpass",
    config_key="mode",
    actions={cmd_add, agent_start},
    hidden=True,
    doc_tag="config:ssh.askpass.mode",
    validator=(
        lambda value: value in ("auto", "prefer", "force", "never"),
        "[ssh.askpass] mode must be one of: auto, prefer, force, never",
    ),
)

# Add/Agent start misslabeled globals
Option(
    option="--lockwait",
    type="int",
    default=5,
    actions={cmd_add, agent_start},
    config_section="lock",
    doc_tag="option:lockwait",
    validator=(lambda value: value >= 0, "--lockwait requires an argument zero or greater."),
)
Option(
    option="--agents",
    type="str",
    argparse_action="append",
    actions={cmd_add, agent_start},
    deprecated=True,
    doc_tag="option:agents",
    deprecation_message="--agents is deprecated, ignoring.",
)
Option(
    option="--inherit",
    type="str",
    doc_tag="option:inherit",
    actions={cmd_add, agent_start},
    deprecated=True,
    deprecation_message="--inherit is deprecated, ignoring. Use --ssh-allow-forwarded, --noinherit as needed instead.",
)
Option(
    option="--confhost",
    type="str",
    doc_tag="option:confhost",
    actions={cmd_add, agent_start},
    deprecated=True,
    deprecation_error=True,
    deprecation_message=lambda value: f"--confhost is deprecated; use --extended host:{value} instead.",
)
Option(
    option="--attempts",
    type="str",
    doc_tag="option:attempts",
    actions={cmd_add, agent_start},
    deprecated=True,
    deprecation_message="--attempts is now deprecated.",
)
Option(
    option="--no-lock",
    cli_aliases=("--nolock",),
    actions={cmd_add, agent_start},
    config_section="lock",
    doc_tag="option:no-lock",
)

agent_stop.add_option(option="--mine", exclusive_group="target")
agent_stop.add_option(option="--others", exclusive_group="target")
agent_stop.add_option(option="--all", exclusive_group="target")

cmd_list.add_option(varname="json", option="--json", doc_tag="option:list-json")
cmd_wipe.add_option(varname="wipe_ssh", option="--ssh", doc_tag="option:wipe-ssh")
cmd_wipe.add_option(varname="wipe_gpg", option="--gpg", doc_tag="option:wipe-gpg")

cmd_env.add_option(
    option="--shell",
    type="str",
    default="env",
    cli_aliases=("--target",),
    doc_tag="option:env-shell",
    choices=("env", "sh", "csh", "fish", "systemd", "json", "eval"),
)
cmd_env.add_option(option="--json", doc_tag="option:env-json")

cmd_inspect.add_option(option="--json", doc_tag="option:inspect-json")
cmd_version.add_option(option="--json", doc_tag="option:version-json")

cmd_man.add_option(varname="list", option="--list", doc_tag="option:man-list")
cmd_man.add_option(varname="no_pager", option="--no-pager", doc_tag="option:man-no-pager")
cmd_man.add_option(varname="width", option="--width", type="int", doc_tag="option:man-width")
cmd_man.add_option(varname="man_groff", option="--groff", doc_tag="option:man-groff")
