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
from collections import OrderedDict
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
    entry = _payload().get(section, {}).get(key, {})
    if entry:
        return entry
    if section == "config":
        return _generated_config_entries().get(key, {})
    return {}


@cache
def _generated_config_entries() -> dict[str, dict[str, str]]:
    """Return config-key docs generated from the option tree."""
    from ..runtime.actions import ROOT_ACTION

    entries: dict[str, dict[str, str]] = {}

    def _walk(action) -> None:
        for opt in action.options.values():
            if not opt.config_section:
                continue
            key = f"{opt.config_section}.{opt.effective_config_key}"
            if key in entries:
                continue
            cli_text = f"\n\nCommand-line option: ``{opt.option_formats}``." if opt.option else ""
            entries[key] = {
                "short_help": opt.short_help,
                "syntax": "",
                "description": (
                    f"Config key: ``[{opt.config_section}] {opt.effective_config_key}``."
                    f"{cli_text}"
                ),
                "section": opt.config_section,
                "key": opt.effective_config_key,
                "option_formats": opt.option_formats if opt.option else "",
            }
        for child in action.sub_actions.values():
            _walk(child)

    _walk(ROOT_ACTION)
    return entries


def _all_tags() -> list[str]:
    """Return authored tags plus generated config-key tags."""
    tags = list(_payload().get("all", ()))
    seen = set(tags)
    for key in _generated_config_entries():
        tag = f"config:{key}"
        if tag not in seen:
            tags.append(tag)
            seen.add(tag)
    return tags


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
        for section in ("topic", "option", "global", "action", "config"):
            if token in data.get(section, {}):
                tags.append(f"{section}:{token}")
                break
            if section == "config" and token in _generated_config_entries():
                tags.append(f"config:{token}")
                break
        else:
            raise KeychainError(f"man: unknown topic: {token}")
    return tags


def _full_manual_tags() -> list[str]:
    """Return top-level manual tags without duplicate option/config catalogs."""
    tags: list[str] = []
    for tag in _payload().get("all", ()):
        if tag.startswith(("option:", "config:")):
            continue
        tags.append(tag)
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
    if tag.startswith("config:"):
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
                if action == ROOT_ACTION:
                    return opt.option_formats
                return f"{action.command} {opt.option_formats}"
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

    if tag.startswith("action:") and tag != "action:global":
        return _render_action_section(tag, entry, width, out)

    if _is_tagged_paragraph(tag):
        return _render_tagged_paragraph(tag, entry, width, out)

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
    if tag == "topic:config":
        config_reference = _render_config_reference(out, width)
        if config_reference:
            lines.append("")
            lines.extend(config_reference)
    return "\n".join(lines).rstrip()


def _is_tagged_paragraph(tag: str) -> bool:
    return tag.startswith(("option:", "global:", "config:"))


def _action_for_tag(tag: str):
    from ..runtime.actions import ROOT_ACTION

    def _walk(action):
        if action.doc_tag == tag:
            return action
        for child in action.sub_actions.values():
            found = _walk(child)
            if found is not None:
                return found
        return None

    return _walk(ROOT_ACTION)


def _render_action_section(tag: str, entry: dict[str, str], width: int, out) -> str:
    """Render actions as man-page tagged paragraphs with local options below."""
    label_indent = "    "
    body_indent = "        "
    option_indent = "            "
    option_body_indent = "                "
    body_width = max(40, width - len(body_indent))
    option_width = max(40, width - len(option_body_indent))
    action = _action_for_tag(tag)
    label = action.command if action is not None else _authored_label(tag)
    lines: list[str] = [f"{label_indent}{out.head(label)}"]

    short_help = entry.get("short_help", "")
    if short_help:
        lines.extend(_indent_lines(out.wrap_doc(short_help, body_width) or [out.format_doc(short_help)], body_indent))

    syntax = _syntax_for(tag)
    if syntax:
        if len(lines) > 1:
            lines.append("")
        syntax_lines = out.wrap_doc(f"Syntax: {syntax}", body_width) or [out.format_doc(f"Syntax: {syntax}")]
        lines.extend(_indent_lines(syntax_lines, body_indent))

    body = _render_manual_text(entry.get("description", ""), body_width, out)
    if body:
        if len(lines) > 1:
            lines.append("")
        lines.extend(_indent_lines(body, body_indent))

    action_options = _visible_action_doc_options(action)
    if action_options:
        if len(lines) > 1:
            lines.append("")
        lines.append(f"{body_indent}{out.head('Options:')}")
        for opt in action_options:
            lines.append("")
            lines.extend(_render_action_option(opt, option_width, option_indent, option_body_indent, out))

    return "\n".join(lines).rstrip()


def _visible_action_doc_options(action) -> list[Any]:
    if action is None:
        return []
    seen: set[str] = set()
    options: list[Any] = []
    for opt in action.options.values():
        if not opt.option or not opt.doc_tag:
            continue
        dedupe_key = opt.doc_tag
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        options.append(opt)
    return options


def _render_action_option(opt, width: int, label_indent: str, body_indent: str, out) -> list[str]:
    entry = _entry(opt.doc_tag or "")
    lines: list[str] = [f"{label_indent}{out.head(opt.option_formats)}"]

    short_help = entry.get("short_help", "") or opt.short_help
    if short_help:
        lines.extend(_indent_lines(out.wrap_doc(short_help, width) or [out.format_doc(short_help)], body_indent))

    body = _render_manual_text(entry.get("description", "") or opt.doc_description, width, out)
    if opt.config_section:
        body = _strip_config_boilerplate(body)
        config_note = f"Config key: [{opt.config_section}] {opt.effective_config_key}."
        body = (out.wrap_doc(config_note, width) or [out.format_doc(config_note)]) + ([""] + body if body else [])
    if body:
        if len(lines) > 1:
            lines.append("")
        lines.extend(_indent_lines(body, body_indent))

    return lines


def _render_tagged_paragraph(tag: str, entry: dict[str, str], width: int, out) -> str:
    """Render option-like docs using traditional man-page indentation."""
    label_indent = "    "
    body_indent = "        "
    body_width = max(40, width - len(body_indent))
    lines: list[str] = [f"{label_indent}{out.head(_authored_label(tag))}"]

    short_help = entry.get("short_help", "")
    if short_help:
        lines.extend(_indent_lines(out.wrap_doc(short_help, body_width) or [out.format_doc(short_help)], body_indent))

    syntax = _syntax_for(tag)
    if syntax:
        if len(lines) > 1:
            lines.append("")
        syntax_lines = out.wrap_doc(f"Syntax: {syntax}", body_width) or [out.format_doc(f"Syntax: {syntax}")]
        lines.extend(_indent_lines(syntax_lines, body_indent))

    body = _render_manual_text(entry.get("description", ""), body_width, out)
    if body:
        if len(lines) > 1:
            lines.append("")
        lines.extend(_indent_lines(body, body_indent))

    return "\n".join(lines).rstrip()


def _render_config_reference(out, width: int) -> list[str]:
    """Render a generated .keychainrc key reference from parser metadata."""
    groups: OrderedDict[str, list[tuple[str, dict[str, str]]]] = OrderedDict()
    for full_key, generated in _generated_config_entries().items():
        section, _, key = full_key.rpartition(".")
        groups.setdefault(section, []).append((key, generated))

    lines = ["Configuration reference:", ""]
    for section in sorted(groups):
        rows = sorted(groups[section], key=lambda row: row[0])
        lines.append(f"    [{section}]")
        lines.append("")
        for key, generated in rows:
            tag = f"config:{section}.{key}"
            entry = _entry(tag) or generated
            option_formats = generated.get("option_formats", "")
            short_help = entry.get("short_help", "")
            canonical = f"{key} = VALUE"
            lines.append(f"      {canonical}")
            if short_help:
                lines.extend(
                    _indent_lines(
                        out.wrap_doc(short_help, max(40, width - 8)) or [out.format_doc(short_help)],
                        "        ",
                    )
                )
            if option_formats:
                text = f"Same setting as the ``{option_formats}`` command-line option."
                lines.extend(_indent_lines(out.wrap_doc(text, max(40, width - 8)) or [out.format_doc(text)], "        "))
            else:
                body = _render_manual_text(entry.get("description", ""), max(40, width - 8), out)
                body = _strip_config_boilerplate(body)
                if body:
                    lines.extend(_indent_lines(body, "        "))
            lines.append("")

    while lines and lines[-1] == "":
        lines.pop()
    return lines


def _indent_lines(lines: list[str], prefix: str) -> list[str]:
    return [prefix + line if line else "" for line in lines]


def _strip_config_boilerplate(lines: list[str]) -> list[str]:
    """Remove repeated boilerplate from config-only inline docs."""
    out: list[str] = []
    skip_fenced = False
    skip_next_blank = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("Config key:"):
            skip_next_blank = True
            continue
        if stripped.startswith("Configure it in"):
            skip_fenced = True
            skip_next_blank = True
            continue
        if skip_fenced:
            if stripped == "```":
                skip_fenced = False
            continue
        if stripped.startswith("See keychain man topic:password-managers"):
            skip_next_blank = True
            continue
        if skip_next_blank and not stripped:
            skip_next_blank = False
            continue
        skip_next_blank = False
        out.append(line)
    while out and not out[0].strip():
        out.pop(0)
    while out and not out[-1].strip():
        out.pop()
    return out


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
        for tag in _all_tags():
            if tag.startswith("section:"):
                continue
            entry = _entry(tag)
            rows.append(f"{_authored_label(tag):<28}  {out.format_doc(entry.get('short_help', ''))}")
        out.write("\n".join(rows) + "\n")
        return 0

    topics = list(args.get_value("topics") or [])
    width = int(args.get_value("width") or shutil.get_terminal_size((96, 24)).columns)
    tags = _resolve_tags(topics) if topics else _full_manual_tags()
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
