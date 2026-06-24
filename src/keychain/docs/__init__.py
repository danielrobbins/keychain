# SPDX-License-Identifier: GPL-3.0-only
"""Embedded documentation runtime for ``keychain man`` and ``--explain``.

This module intentionally stays small: the authored documentation already lives
in ``_doc_texts.json`` and the action tree already knows the valid action names.
The runtime layer here just resolves targets and streams the pre-generated text
back out.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from functools import cache
from importlib.resources import files
from typing import Any

from ..output.tables import render_panel


@cache
def _payload() -> dict[str, Any]:
    blob = files("keychain").joinpath("docs").joinpath("_doc_texts.json").read_text(encoding="utf-8")
    return json.loads(blob)


def _entry(tag: str) -> dict[str, str]:
    section, _, key = tag.partition(":")
    if not section or not key:
        return {}
    return _payload().get(section, {}).get(key, {})


def _resolve_tags(topics: list[str]) -> list[str]:
    if not topics:
        return list(_payload().get("all", ()))

    from ..runtime.actions import ROOT_ACTION
    from ..util import KeychainError

    action = ROOT_ACTION.find_action(topics)
    if action is not None and action != ROOT_ACTION:
        return [f"action:{action.fq_name}"]

    tags: list[str] = []
    data = _payload()
    for token in topics:
        if ":" in token and _entry(token):
            tags.append(token)
            continue
        if token == "keychain":
            tags.append("tool:keychain")
            continue
        for section in ("topic", "option", "global", "action"):
            if token in data.get(section, {}):
                tags.append(f"{section}:{token}")
                break
        else:
            raise KeychainError(f"man: unknown topic: {token}")
    return tags


def _render_tags(tags: list[str]) -> str:
    parts = [entry.get("description", "") for tag in tags if (entry := _entry(tag))]
    return "\n\n".join(part for part in parts if part)


def _authored_label(tag: str) -> str:
    from ..runtime.actions import ROOT_ACTION

    if tag == "tool:keychain":
        return "keychain"
    if tag.startswith("section:"):
        return tag.split(":", 1)[1]
    if tag.startswith("topic:"):
        return tag
    if tag.startswith("global:"):
        key = tag.split(":", 1)[1]
        for opt in ROOT_ACTION.options.values():
            if opt.varname == key or opt.doc_tag == f"option:{key}":
                return opt.option_formats
        return f"--{key.replace('_', '-')}"

    def _walk(action) -> str | None:
        if action.doc_tag == tag:
            return action.command
        for opt in action.options.values():
            if opt.doc_tag == tag:
                return opt.option_formats
        for child in action.sub_actions.values():
            found = _walk(child)
            if found is not None:
                return found
        return None

    found = _walk(ROOT_ACTION)
    if found is not None:
        return found
    if tag.startswith("action:"):
        return f"keychain {tag.split(':', 1)[1]}"
    if tag.startswith("option:"):
        name = tag.split(":", 1)[1]
        if name.endswith("-json"):
            return "--json"
        return f"--{name}"
    return tag


def _render_manual_section(tag: str, width: int, out) -> str:
    entry = _entry(tag)
    if not entry:
        return ""

    heading = _authored_label(tag)
    lines: list[str] = [str(out.head(heading))]
    if tag.startswith("section:"):
        return "\n".join(lines).rstrip()
    short_help = entry.get("short_help", "")
    if short_help:
        lines.extend(out.wrap_doc(short_help, width) or [out.format_doc(short_help)])
    syntax = _syntax_for(tag)
    if syntax:
        lines.append("")
        lines.extend(out.wrap_doc(f"Syntax: {syntax}", width) or [out.format_doc(f"Syntax: {syntax}")])
    body = _render_manual_text(entry.get("description", ""), width, out)
    if body:
        lines.append("")
        lines.extend(body)
    return "\n".join(lines).rstrip()


def _render_manual_text(text: str, width: int, out) -> list[str]:
    source_lines = _dedupe_doc_source_lines(text)
    rendered: list[str] = []
    paragraph: list[str] = []

    def _flush_paragraph() -> None:
        nonlocal paragraph
        if not paragraph:
            return
        joined = " ".join(line.strip() for line in paragraph)
        if joined.startswith("* "):
            rendered.extend(out.wrap_doc(joined[2:], width - 2, prefix="* ", continuation="  ") or ["* "])
        else:
            rendered.extend(out.wrap_doc(joined, width) or [""])
        paragraph = []

    for line in source_lines:
        if line == "":
            _flush_paragraph()
            if rendered and rendered[-1] != "":
                rendered.append("")
            continue
        if line.startswith("    "):
            _flush_paragraph()
            rendered.append("    " + out.format_doc(line[4:]))
            continue
        paragraph.append(line)

    _flush_paragraph()
    while rendered and rendered[-1] == "":
        rendered.pop()
    return rendered


def _dedupe_doc_source_lines(text: str) -> list[str]:
    lines: list[str] = []
    previous: str | None = None
    for raw in text.splitlines():
        if raw.startswith("== @") or raw.startswith("@syntax "):
            continue
        line = raw.rstrip()
        if not line.strip():
            if lines and lines[-1] != "":
                lines.append("")
            previous = ""
            continue
        if line == previous:
            continue
        lines.append(line)
        previous = line
    while lines and lines[0] == "":
        lines.pop(0)
    while lines and lines[-1] == "":
        lines.pop()
    return lines


def _syntax_for(tag: str | None) -> str:
    if not tag:
        return ""
    entry = _entry(tag)
    syntax = entry.get("syntax", "").strip()
    if syntax:
        return syntax
    for line in entry.get("description", "").splitlines():
        if line.startswith("@syntax "):
            return line[len("@syntax ") :].strip()
    return ""


def _normalise_doc_lines(text: str) -> list[str]:
    lines: list[str] = []
    previous = None
    for raw in text.splitlines():
        stripped = raw.strip()
        if raw.startswith("== @") or raw.startswith("@syntax "):
            continue
        if not stripped:
            if lines and lines[-1] != "":
                lines.append("")
            previous = ""
            continue
        if stripped == previous:
            continue
        lines.append(stripped)
        previous = stripped
    while lines and lines[0] == "":
        lines.pop(0)
    while lines and lines[-1] == "":
        lines.pop()
    return lines


def _wrap_doc_text(text: str, width: int, out) -> list[str]:
    lines = _normalise_doc_lines(text)
    wrapped_lines: list[str] = []
    paragraph: list[str] = []
    out_obj = out

    def _flush() -> None:
        nonlocal paragraph
        if not paragraph:
            return
        joined = " ".join(paragraph)
        if joined.startswith("* "):
            wrapped_lines.extend(out_obj.wrap_doc(joined[2:], width - 2, prefix="* ", continuation="  ") or ["* "])
        else:
            wrapped_lines.extend(out_obj.wrap_doc(joined, width) or [""])
        paragraph = []

    for line in lines + [""]:
        if line == "":
            _flush()
            if wrapped_lines and wrapped_lines[-1] != "":
                wrapped_lines.append("")
            continue
        paragraph.append(line)

    while wrapped_lines and wrapped_lines[-1] == "":
        wrapped_lines.pop()
    return wrapped_lines


def _panel_body(short_help: str, description: str, syntax: str, width: int, out) -> list[str]:
    body: list[str] = []
    if short_help:
        body.extend(out.wrap_doc(short_help, width) or [out.format_doc(short_help)])
    if syntax:
        if body:
            body.append("")
        body.extend(out.wrap_doc(f"Syntax: {syntax}", width) or [out.format_doc(f"Syntax: {syntax}")])
    wrapped = _wrap_doc_text(description, width, out)
    if wrapped:
        if body:
            body.append("")
        body.extend(wrapped)
    return body or ["(no documentation record found)"]


def _classify_positional(action_name: str, value: str) -> tuple[str, str]:
    if action_name in ("add", "forget", "inspect"):
        if value.startswith("sshk:"):
            return f"Key: {value}", f"SSH key file: {value[5:]}"
        if value.startswith("gpgk:"):
            return f"Key: {value}", f"GPG key ID: {value[5:]}"
        if value.startswith("host:"):
            return f"Key: {value}", f"Every IdentityFile from ssh -G {value[5:]}"
        if action_name == "add":
            return (
                f"Literal Agent Key: '{value}'",
                "A literal SSH or GnuPG key specification to load into the agent.",
            )
        return f"Key: {value}", f"Key argument for the {action_name} action."
    if action_name == "help":
        return f"Help target: {value}", "Action or topic that the help action will render documentation for."
    if action_name == "man":
        return f"Doc target: {value}", "Manual-page target selected for the man action."
    return f"Argument: {value}", f"Positional argument for the {action_name} action."


def run_man(args, out) -> int:
    if bool(args.get_value("list")):
        rows = []
        for tag in _payload().get("all", ()):
            if tag.startswith("section:"):
                continue
            entry = _entry(tag)
            rows.append(f"{_authored_label(tag):<28}  {out.format_doc(entry.get('short_help', ''))}")
        out.write("\n".join(rows) + "\n")
        return 0

    topics = list(args.get_value("topics") or [])
    width = int(args.get_value("width") or shutil.get_terminal_size((96, 24)).columns)
    tags = _resolve_tags(topics) if topics else list(_payload().get("all", ()))
    sections = [_render_manual_section(tag, width, out) for tag in tags]
    out.write("\n\n".join(section for section in sections if section) + "\n")
    return 0


def run_explain(argv: list[str]) -> int:
    from ..runtime.actions import ROOT_ACTION
    from ..runtime.compat import COMPAT
    from ..runtime.config import RuntimeConfig
    from ..util import Output

    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    if "--nocolor" in argv or "--no-color" in argv:
        color = False

    filtered = [token for token in argv if token not in ("--explain", "--nocolor", "--no-color")]
    legacy_equivalent: str | None = None
    legacy_note: str | None = None
    compat_used = False

    probe = RuntimeConfig()
    probe._reset_all_cli()
    pre_action_node, _pre_active_options, pre_consumed_sequence = probe._prescan_actions(filtered)
    adapted = probe._adapt_action_argv(filtered, pre_action_node, pre_consumed_sequence)
    compat_used = adapted is None and pre_action_node == ROOT_ACTION

    if compat_used:
        compat_explain = COMPAT.explain(filtered)
        if compat_explain is not None:
            parse_argv, legacy_equivalent, legacy_note = compat_explain
        else:
            parse_argv = COMPAT.translate(filtered)
            legacy_equivalent = COMPAT.equivalent_command(parse_argv)
    else:
        parse_argv = probe._canonicalize_argv(filtered)

    parser = RuntimeConfig()
    parser._reset_all_cli()
    action_node, _active_options, consumed_sequence = parser._prescan_actions(parse_argv)
    if action_node == ROOT_ACTION:
        action_node = ROOT_ACTION.find_action("add") or ROOT_ACTION
    visible = parser._visible_options(action_node)

    out = Output.build(quiet=False, debug=False, eval_mode=False, color=color)
    title_style = out.style("heading")
    note_style = out.style("dim")
    box_inner = max(40, min(shutil.get_terminal_size((96, 24)).columns - 6, 80))

    panels: list[str] = []
    if compat_used:
        compat_body = _wrap_doc_text(
            "No match for any new-style action; legacy keychain 2.x parsing invoked.",
            box_inner,
            out,
        )
        if legacy_note:
            compat_body.extend([""] + _wrap_doc_text(legacy_note, box_inner, out))
        if legacy_equivalent:
            compat_body.extend(["", "Equivalent keychain 3 command:", legacy_equivalent])
        panels.append(
            render_panel(
                "Legacy invocation",
                compat_body,
                title_style=title_style,
                note="compat",
                note_style=note_style,
                min_width=box_inner,
            )
        )

    if action_node != ROOT_ACTION:
        action_body = _panel_body(
            action_node.short_help,
            action_node.doc_description,
            _syntax_for(action_node.doc_tag),
            box_inner,
            out,
        )
        panels.append(
            render_panel(
                f"keychain {action_node.fq_name}",
                action_body,
                title_style=title_style,
                note="action",
                note_style=note_style,
                min_width=box_inner,
            )
        )

    remaining_action_tokens = list(consumed_sequence)
    i = 0
    while i < len(parse_argv):
        tok = parse_argv[i]
        if tok == "--":
            i += 1
            continue

        if tok.startswith("-"):
            opt = parser._resolve_alias(tok, visible)
            value: str | None = None
            title = tok
            if opt is None:
                body = _wrap_doc_text(
                    "No documentation record matches this token. It would be rejected during normal parsing.",
                    box_inner,
                    out,
                )
                panels.append(render_panel(f"Unrecognised: {tok}", body, title_style=title_style, min_width=box_inner))
                i += 1
                continue

            if opt.takes_value:
                if "=" in tok:
                    title = tok
                    value = tok.split("=", 1)[1]
                elif i + 1 < len(parse_argv) and parse_argv[i + 1] != "--":
                    value = parse_argv[i + 1]
                    title = f"{tok} {value}"
                    i += 1

            body = _panel_body(opt.short_help, opt.doc_description, _syntax_for(opt.doc_tag), box_inner, out)
            details: list[str] = [f"Accepted spellings: {opt.option_formats}"]
            if value is not None:
                details.append(f"Value on this command line: {value}")
            if opt.config_section:
                details.append(f"Config key: [{opt.config_section}] {opt.effective_config_key}")
            if details:
                body = details + ([""] if body else []) + body

            label = "global option" if opt.actions == {ROOT_ACTION} else f"option for {action_node.fq_name}"
            panels.append(
                render_panel(
                    title,
                    body,
                    title_style=title_style,
                    note=label,
                    note_style=note_style,
                    min_width=box_inner,
                )
            )
            i += 1
            continue

        if remaining_action_tokens and tok == remaining_action_tokens[0]:
            remaining_action_tokens.pop(0)
            i += 1
            continue

        title, body_text = _classify_positional(action_node.fq_name if action_node != ROOT_ACTION else "add", tok)
        panels.append(
            render_panel(title, _wrap_doc_text(body_text, box_inner, out), title_style=title_style, min_width=box_inner)
        )
        i += 1

    sys.stdout.write("\n".join(panels) + ("\n" if panels else ""))
    return 0
