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
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from typing import Any

from ..output.tables import render_panel, visible_width


@cache
def _payload() -> dict[str, Any]:
    blob = files("keychain").joinpath("docs").joinpath("_doc_texts.json").read_text(encoding="utf-8")
    return json.loads(blob)


def _entry(tag: str) -> dict[str, str]:
    section, _, key = tag.partition(":")
    if not section or not key:
        return {}
    return _payload().get(section, {}).get(key, {})


@cache
def _config_items() -> tuple[dict[str, Any], ...]:
    from ..runtime.actions import ROOT_ACTION

    items: dict[tuple[str, str], dict[str, Any]] = {}

    def _walk(action) -> None:
        for opt in action.options.values():
            if not opt.config_section:
                continue
            config_key = opt.effective_config_key
            dedupe_key = (opt.config_section, config_key)
            if dedupe_key in items:
                continue
            items[dedupe_key] = {
                "section": opt.config_section,
                "key": config_key,
                "option": opt,
            }
        for child in action.sub_actions.values():
            _walk(child)

    _walk(ROOT_ACTION)
    return tuple(sorted(items.values(), key=lambda item: (item["section"], item["key"])))


def _visible_config_items() -> tuple[dict[str, Any], ...]:
    return tuple(item for item in _config_items() if not item["option"].hidden)


def _find_config_item(token: str) -> dict[str, Any] | None:
    normalized = token.strip()
    if normalized.startswith("config:"):
        normalized = normalized.split(":", 1)[1]
    if normalized.startswith("config."):
        normalized = normalized.split(".", 1)[1]

    for item in _config_items():
        full_name = f"{item['section']}.{item['key']}"
        dashed_name = full_name.replace("_", "-").replace(".", ".")
        if normalized in (full_name, dashed_name):
            return item
    return None


def _walk_actions() -> tuple[Any, ...]:
    from ..runtime.actions import ROOT_ACTION

    actions: list[Any] = []

    def _walk(action) -> None:
        for child in action.sub_actions.values():
            actions.append(child)
            _walk(child)

    _walk(ROOT_ACTION)
    return tuple(actions)


def _visible_actions() -> tuple[Any, ...]:
    return tuple(sorted(_walk_actions(), key=lambda action: action.fq_name))


def _row(kind: str, label: str, lookup: str, summary: str) -> tuple[str, str, str, str]:
    return (kind, label, lookup, summary)


def _style_list_label(kind: str, text: str, out) -> str:
    if kind == "action":
        return str(out.kbd(text))
    if kind == "option":
        return str(out.flag(text))
    if kind == "global":
        return str(out.flag(text))
    if kind == "topic":
        return str(out.id(text))
    if kind == "config":
        return str(out.id(text))
    return text


def _render_list_row(
    row: tuple[str, str, str, str], label_width: int, lookup_width: int, out, *, indent: int = 2
) -> str:
    kind, label, lookup, summary = row
    label_pad = label + " " * (label_width - visible_width(label))
    lookup_pad = lookup + " " * (lookup_width - visible_width(lookup))
    label_cell = _style_list_label(kind, label_pad, out)
    lookup_cell = str(out.dim(lookup_pad))
    summary_cell = out.format_doc(summary)
    return f"{' ' * indent}{label_cell}  {lookup_cell}  {summary_cell}".rstrip()


def _index_widths(rows: list[tuple[str, str, str, str]]) -> tuple[int, int]:
    if not rows:
        return (0, 0)
    return (
        max(visible_width(label) for _kind, label, _lookup, _summary in rows),
        max(visible_width(lookup) for _kind, _label, lookup, _summary in rows),
    )


def _render_list_section(
    title: str, rows: list[tuple[str, str, str, str]], label_width: int, lookup_width: int, out
) -> list[str]:
    if not rows:
        return []
    return [str(out.head(title)), *[_render_list_row(row, label_width, lookup_width, out) for row in rows]]


def _render_config_index(rows: list[tuple[str, str, str, str]], out, *, title: str | None = None) -> list[str]:
    if not rows:
        return []
    label_width, lookup_width = _index_widths(rows)
    lines: list[str] = []
    if title:
        lines.append(str(out.head(title)))
    lines.extend(_render_list_row(row, label_width, lookup_width, out) for row in rows)
    return lines


def _render_grouped_option_section(
    title: str,
    groups: list[tuple[str, list[tuple[str, str, str, str]]]],
    label_width: int,
    lookup_width: int,
    out,
) -> list[str]:
    if not groups:
        return []
    lines = [str(out.head(title))]
    for group_title, rows in groups:
        if not rows:
            continue
        if len(lines) > 1:
            lines.append("")
        lines.append(str(out.head(group_title)))
        lines.extend(_render_list_row(row, label_width, lookup_width, out) for row in rows)
    return lines


def _list_action_rows() -> list[tuple[str, str, str, str]]:
    return [
        _row("action", action.command, f"action:{action.fq_name}", action.short_help) for action in _visible_actions()
    ]


def _list_action_option_groups() -> list[tuple[str, list[tuple[str, str, str, str]]]]:
    groups: list[tuple[str, list[tuple[str, str, str, str]]]] = []
    for action in _visible_actions():
        rows: list[tuple[str, str, str, str]] = []
        seen: set[str] = set()
        for opt in action.options.values():
            if opt.hidden or not opt.option:
                continue
            lookup = opt.doc_tag or ""
            if not lookup or lookup in seen:
                continue
            seen.add(lookup)
            rows.append(_row("option", opt.option_formats, lookup, opt.short_help))
        if rows:
            rows.sort(key=lambda row: row[0])
            groups.append((action.command, rows))
    return groups


def _topic_metadata() -> dict[str, dict[str, str]]:
    """Extract topic metadata (category, priority) keyed by tag."""
    metadata = {}
    for key, entry in _payload().get("topic", {}).items():
        tag = f"topic:{key}"
        meta = entry.get("metadata", {})
        if meta:
            metadata[tag] = meta
    return metadata


def _list_topic_rows() -> list[tuple[str, str, str, str]]:
    """List topic rows sorted by category/priority."""
    data = _payload().get("topic", {})
    rows = []
    for key in data.keys():
        tag = f"topic:{key}"
        entry = data[key]
        rows.append(("topic", tag, tag, entry.get("short_help", "")))

    # Sort by category, then priority, then alphabetical
    metadata = _topic_metadata()

    def _sort_key(row):
        tag = row[1]
        meta = metadata.get(tag, {})
        category = meta.get("category", "zzz")
        priority = int(meta.get("priority", "99"))
        return (category, priority, tag)

    return sorted(rows, key=_sort_key)


def _list_global_rows() -> list[tuple[str, str, str, str]]:
    from ..runtime.actions import ROOT_ACTION

    rows: list[tuple[str, str, str, str]] = []
    for opt in ROOT_ACTION.options.values():
        if opt.hidden or not opt.option:
            continue
        rows.append(_row("global", opt.option_formats, f"global:{opt.varname.replace('_', '-')}", opt.short_help))
    return sorted(rows, key=lambda row: row[0])


def _list_config_rows() -> list[tuple[str, str, str, str]]:
    rows: list[tuple[str, str, str, str]] = []
    for item in _visible_config_items():
        section = item["section"]
        key = item["key"]
        opt = item["option"]
        summary = _entry(opt.config_doc_tag or "").get("short_help", "") or opt.short_help
        full_name = f"{section}.{key}"
        rows.append(_row("config", full_name, f"config:{full_name}", summary))
    return rows


def _has_authored_config_docs(item: dict[str, Any]) -> bool:
    opt = item["option"]
    if not opt.config_doc_tag:
        return False
    entry = _entry(opt.config_doc_tag)
    return bool(entry.get("short_help", "") or entry.get("description", "") or entry.get("syntax", ""))


def _build_labels() -> dict[str, str]:
    """Build a lookup table of tags to human-readable labels."""
    from ..runtime.actions import ROOT_ACTION

    labels: dict[str, str] = {"tool:keychain": "keychain"}

    # Topic labels
    for key in _payload().get("topic", {}).keys():
        tag = f"topic:{key}"
        labels[tag] = tag

    # Config labels
    for item in _config_items():
        full_name = f"{item['section']}.{item['key']}"
        labels[f"config:{full_name}"] = full_name

    # Global option labels
    for opt in ROOT_ACTION.options.values():
        if opt.option and not opt.hidden:
            key = opt.varname.replace("_", "-")
            labels[f"global:{key}"] = opt.option_formats

    # Action and option labels - walk tree once
    def _walk(action) -> None:
        if action.doc_tag:
            labels[action.doc_tag] = action.command
        for opt in action.options.values():
            if opt.option and not opt.hidden:
                if opt.doc_tag:
                    labels[opt.doc_tag] = opt.option_formats
        for child in action.sub_actions.values():
            _walk(child)

    _walk(ROOT_ACTION)

    return labels


@dataclass
class DocumentIndex:
    """Structured document index consumed by all renderers.

    Why this exists:
    The index is the central product of the docs system. It captures the
    structure once and allows multiple renderers (list, full man, markdown)
    to consume the same structure without re-computing it.

    How it is used:
    Build once via DocumentIndex.build(), then pass to renderers.
    """

    action_rows: list[tuple[str, str, str, str]]
    option_groups: list[tuple[str, list[tuple[str, str, str, str]]]]
    topic_rows: list[tuple[str, str, str, str]]
    topic_metadata: dict[str, dict[str, str]]  # tag -> {category, priority}
    global_rows: list[tuple[str, str, str, str]]
    config_rows: list[tuple[str, str, str, str]]
    labels: dict[str, str]  # tag -> human-readable label

    @classmethod
    def build(cls) -> DocumentIndex:
        """Build the document index from atoms and metadata."""
        return cls(
            action_rows=_list_action_rows(),
            option_groups=_list_action_option_groups(),
            topic_rows=_list_topic_rows(),
            topic_metadata=_topic_metadata(),
            global_rows=_list_global_rows(),
            config_rows=_list_config_rows(),
            labels=_build_labels(),
        )

    def all_rows(self) -> list[tuple[str, str, str, str]]:
        """All rows for width calculation."""
        return [
            *self.action_rows,
            *(row for _group_title, rows in self.option_groups for row in rows),
            *self.topic_rows,
            *self.global_rows,
            *self.config_rows,
        ]


@dataclass
class ExplainAnalysis:
    parse_argv: list[str]
    action_node: Any
    consumed_sequence: list[str]
    visible: Any
    compat_used: bool
    legacy_equivalent: str | None
    legacy_note: str | None


@dataclass
class ExplainPanelSpec:
    title: str
    body: list[str]
    note: str | None = None


def _render_list_from_index(index: DocumentIndex, out) -> str:
    """Render the document index in compact list format."""
    label_width, lookup_width = _index_widths(index.all_rows())
    sections: list[list[str]] = []

    for section in _document_sections(index):
        if section["kind"] == "grouped":
            sections.append(
                _render_grouped_option_section(section["title"], section["groups"], label_width, lookup_width, out)
            )
        else:
            sections.append(_render_list_section(section["title"], section["rows"], label_width, lookup_width, out))

    rendered_sections = ["\n".join(section) for section in sections if section]
    return "\n\n".join(rendered_sections)


def _group_topic_rows(index: DocumentIndex) -> list[tuple[str, list[tuple[str, str, str, str]]]]:
    topic_groups: dict[str, list[tuple[str, str, str, str]]] = {}
    for row in index.topic_rows:
        tag = row[1]
        meta = index.topic_metadata.get(tag, {})
        category = meta.get("category", "other")
        if category == "platform":
            category = "reference"
        topic_groups.setdefault(category, []).append(row)

    category_titles = {
        "intro": "Introduction",
        "reference": "Reference Topics",
        "appendix": "Appendix",
        "other": "Topics",
    }
    category_order = ("intro", "reference", "appendix", "other")
    groups: list[tuple[str, list[tuple[str, str, str, str]]]] = []
    for category in category_order:
        rows = topic_groups.get(category)
        if rows:
            groups.append((category_titles.get(category, category.title()), rows))
    for category in sorted(topic_groups.keys() - set(category_order)):
        groups.append((category_titles.get(category, category.title()), topic_groups[category]))
    return groups


def _ordered_unique_lookups(rows: list[tuple[str, str, str, str]]) -> list[str]:
    seen: set[str] = set()
    lookups: list[str] = []
    for _kind, _label, lookup, _summary in rows:
        if lookup in seen:
            continue
        seen.add(lookup)
        lookups.append(lookup)
    return lookups


def _document_sections(index: DocumentIndex) -> list[dict[str, Any]]:
    grouped_topics = dict(_group_topic_rows(index))
    config_reference_tag = "topic:config"
    option_rows = [row for _group_title, rows in index.option_groups for row in rows]
    sections: list[dict[str, Any]] = [
        {
            "title": "Introduction",
            "kind": "rows",
            "rows": grouped_topics.get("Introduction", []),
            "tags": [row[2] for row in grouped_topics.get("Introduction", [])],
        },
        {
            "title": "Global options",
            "kind": "rows",
            "rows": index.global_rows,
            "tags": _ordered_unique_lookups(index.global_rows),
        },
        {
            "title": "Actions",
            "kind": "rows",
            "rows": index.action_rows,
            "tags": _ordered_unique_lookups(index.action_rows),
        },
        {
            "title": "Action options",
            "kind": "grouped",
            "groups": index.option_groups,
            "tags": _ordered_unique_lookups(option_rows),
        },
        {
            "title": "Reference Topics",
            "kind": "rows",
            "rows": grouped_topics.get("Reference Topics", []),
            "tags": [row[2] for row in grouped_topics.get("Reference Topics", []) if row[2] != config_reference_tag],
        },
        {
            "title": "Config keys (~/.keychainrc)",
            "kind": "rows",
            "rows": index.config_rows,
            "tags": [config_reference_tag] if config_reference_tag in {row[2] for row in index.topic_rows} else [],
        },
        {
            "title": "Appendix",
            "kind": "rows",
            "rows": grouped_topics.get("Appendix", []),
            "tags": [row[2] for row in grouped_topics.get("Appendix", [])],
        },
    ]
    return [section for section in sections if section.get("rows") or section.get("groups") or section["tags"]]


def _manual_tags_from_index(index: DocumentIndex) -> list[str]:
    tags = ["tool:keychain"]
    for section in _document_sections(index):
        if section["tags"]:
            tags.extend([f"section:{section['title']}", *section["tags"]])
    return tags


def _resolve_tags_from_index(index: DocumentIndex, topics: list[str]) -> list[str]:
    """Resolve manual targets against the already-built document index."""
    if not topics:
        return _manual_tags_from_index(index)

    from ..runtime.actions import ROOT_ACTION
    from ..util import KeychainError

    action = ROOT_ACTION.find_action(topics)
    if action is not None and action != ROOT_ACTION:
        return [f"action:{action.fq_name}"]

    known_tags = {"tool:keychain", *index.labels.keys()}
    payload = _payload()
    tags: list[str] = []
    for token in topics:
        if config_item := _find_config_item(token):
            tags.append(f"config:{config_item['section']}.{config_item['key']}")
            continue
        if ":" in token and token in known_tags:
            tags.append(token)
            continue
        if token == "keychain":
            tags.append("tool:keychain")
            continue
        for section in ("topic", "option", "global", "action"):
            if token in payload.get(section, {}):
                tags.append(f"{section}:{token}")
                break
        else:
            raise KeychainError(f"man: unknown topic: {token}")
    return tags


def _config_doc_lines(item: dict[str, Any], width: int, out) -> list[str]:
    opt = item["option"]
    section = item["section"]
    key = item["key"]
    config_entry = _entry(opt.config_doc_tag or "") if opt.config_doc_tag else {}
    lines: list[str] = []
    # Grey for section brackets, cyan for key name
    lines.extend(
        out.wrap_doc(f"Config key: {str(out.dim(f'[{section}]'))} {key}", width)
        or [f"Config key: {str(out.dim(f'[{section}]'))} {key}"]
    )
    if opt.option:
        lines.extend([""])
        alias_text = f"Persistent equivalent of {opt.option_formats}. Set it in {str(out.dim('~/.keychainrc'))} to make that behavior the default."
        if opt.config_invert_bool and opt.type == "bool":
            alias_text = (
                f"Persistent inverse of {opt.option_formats}. Set `{str(out.dim(key))} = true` in {str(out.dim('~/.keychainrc'))} to enable the positive behavior, "
                f"or `{str(out.dim(key))} = false` to get the same effect as {opt.option_formats}."
            )
        lines.extend(out.wrap_doc(alias_text, width) or [alias_text])
        short_help = config_entry.get("short_help", "") or opt.short_help
        description = config_entry.get("description", "") or opt.doc_description
    else:
        short_help = config_entry.get("short_help", "")
        description = config_entry.get("description", "")

    if short_help:
        lines.extend([""])
        lines.extend(out.wrap_doc(short_help, width) or [out.format_doc(short_help)])
    if description:
        wrapped = _render_manual_text(description, width, out)
        if wrapped:
            lines.extend([""])
            lines.extend(wrapped)
    if not short_help and not description and opt.option:
        lines.extend([""])
        lines.extend(
            out.wrap_doc(f"See {opt.option_formats} for behavior details.", width)
            or ["See the equivalent CLI option for behavior details."]
        )
    return lines


def _render_config_index_block(width: int, out) -> list[str]:
    lines: list[str] = []
    config_rows = _list_config_rows()
    if config_rows:
        lines.extend(_render_config_index(config_rows, out, title="Config keys (~/.keychainrc)"))

    detailed_items = [item for item in _config_items() if _has_authored_config_docs(item)]
    if detailed_items:
        lines.append("")
        lines.append(str(out.head("Detailed config entries")))
        for item in detailed_items:
            full_name = f"{item['section']}.{item['key']}"
            lines.extend(["", str(out.head(full_name)), ""])
            lines.extend(_config_doc_lines(item, width, out))

    while lines and lines[-1] == "":
        lines.pop()
    return lines


_BLOCK_RENDERERS = {
    "config_index": _render_config_index_block,
}


def _render_block_directive(line: str, width: int, out) -> list[str] | None:
    if not line.startswith("@func:"):
        return None
    name = line.split(":", 1)[1].strip()
    renderer = _BLOCK_RENDERERS.get(name)
    if renderer is None:
        raise ValueError(f"unknown render block: {name}")
    return renderer(width, out)


def _authored_label(tag: str, labels: dict[str, str] | None = None) -> str:
    """Get human-readable label for a tag. Uses pre-built labels dict if provided."""
    if labels and tag in labels:
        return labels[tag]

    if tag.startswith("section:"):
        return tag.split(":", 1)[1]
    if tag.startswith("config:"):
        return tag.split(":", 1)[1]
    if tag.startswith("global:"):
        return f"--{tag.split(':', 1)[1].replace('_', '-')}"
    if tag.startswith("action:"):
        return f"keychain {tag.split(':', 1)[1]}"
    if tag.startswith("option:"):
        name = tag.split(":", 1)[1]
        if name.endswith("-json"):
            return "--json"
        return f"--{name}"
    return tag


def _render_manual_heading(tag: str, out, labels: dict[str, str] | None = None) -> str:
    entry = _entry(tag)
    if tag.startswith("section:"):
        name = tag.split(":", 1)[1].replace("_", " ").upper()
        # Section banners: bold cyan with bar prefix, no underline
        return f"{out.glyph('bar')} {str(out.underlined_heading(name))}"
    if tag.startswith("action:") or tag.startswith("option:") or tag.startswith("global:") or tag.startswith("config:"):
        return str(out.underlined_heading(_authored_label(tag, labels)))

    lookup = _authored_label(tag, labels)
    title = entry.get("short_help", "") or lookup
    if tag == "tool:keychain":
        return str(out.head(title))
    if title == lookup:
        return str(out.head(title))
    return f"{str(out.head(title))} {str(out.dim(f'({lookup})'))}"


def _render_manual_section(tag: str, width: int, out, labels: dict[str, str] | None = None) -> str:
    lines: list[str] = [_render_manual_heading(tag, out, labels)]
    if tag.startswith("section:"):
        return "\n".join(lines).rstrip()
    if tag.startswith("config:"):
        config_item = _find_config_item(tag)
        if not config_item:
            return ""
        lines.append("")
        lines.extend(_config_doc_lines(config_item, width, out))
        return "\n".join(lines).rstrip()

    entry = _entry(tag)
    if not entry:
        return ""
    syntax = _syntax_for(tag)
    if syntax:
        lines.append("")
        lines.append(f"{str(out.dim('Syntax:'))} {_format_syntax(syntax, out)}")
    body = _render_manual_text(entry.get("description", ""), width, out)
    if body:
        lines.append("")
        lines.extend(body)
    return "\n".join(lines).rstrip()


def _render_manual_text(text: str, width: int, out) -> list[str]:
    source_lines = _dedupe_doc_source_lines(text)
    rendered: list[str] = []
    paragraph: list[str] = []
    in_fence = False
    in_list = False
    list_item_lines: list[str] = []  # Accumulate lines for current list item

    def _flush_paragraph() -> None:
        nonlocal paragraph, in_list
        if not paragraph:
            return
        joined = " ".join(line.strip() for line in paragraph)

        # Check for bulleted list item
        if joined.startswith("* "):
            in_list = True
            rendered.extend(out.wrap_doc(joined[2:], width - 2, prefix="* ", continuation="  ") or ["* "])
        # Check for numbered list item (1. 2. 3. etc)
        elif _is_numbered_item(joined):
            num, rest = _extract_numbered_item(joined)
            in_list = True
            # Use the actual number from the source
            prefix = f"{num}. "
            rendered.extend(
                out.wrap_doc(rest, width - len(prefix), prefix=prefix, continuation=" " * (len(prefix))) or [prefix]
            )
        else:
            # End any active list when we hit non-list content
            if in_list:
                in_list = False
                if rendered and rendered[-1] != "":
                    rendered.append("")
            rendered.extend(out.wrap_doc(joined, width) or [""])
        paragraph = []

    def _flush_list_item() -> None:
        nonlocal list_item_lines, in_list
        if not list_item_lines:
            return
        # Join all accumulated lines for this list item
        first_line = list_item_lines[0]
        rest_lines = [line.strip() for line in list_item_lines[1:]]

        if first_line.startswith("* "):
            in_list = True
            content = first_line[2:] + " " + " ".join(rest_lines) if rest_lines else first_line[2:]
            rendered.extend(out.wrap_doc(content, width - 2, prefix="* ", continuation="  ") or ["* "])
        elif _is_numbered_item(first_line):
            num, rest = _extract_numbered_item(first_line)
            in_list = True
            content = rest + " " + " ".join(rest_lines) if rest_lines else rest
            prefix = f"{num}. "
            rendered.extend(
                out.wrap_doc(content, width - len(prefix), prefix=prefix, continuation=" " * (len(prefix))) or [prefix]
            )

        list_item_lines = []

    for line in source_lines:
        if line == "```":
            _flush_paragraph()
            _flush_list_item()
            in_fence = not in_fence
            continue
        directive = None if in_fence else _render_block_directive(line.strip(), width, out)
        if directive is not None:
            _flush_paragraph()
            _flush_list_item()
            if rendered and rendered[-1] != "":
                rendered.append("")
            rendered.extend(directive)
            if rendered and rendered[-1] != "":
                rendered.append("")
            continue
        if in_fence:
            if line == "":
                if rendered and rendered[-1] != "":
                    rendered.append("")
                continue
            code_color = out.colors.get("CYANN", "")
            reset = out.colors.get("OFF", "")
            rendered.append(f"    {code_color}{line}{reset}")
            continue
        if line == "":
            _flush_paragraph()
            _flush_list_item()
            if rendered and rendered[-1] != "":
                rendered.append("")
            continue
        if line.startswith("    "):
            _flush_paragraph()
            _flush_list_item()
            rendered.append("    " + out.format_doc(line[4:]))
            continue
        # Check if this is a list item
        if line.startswith("* ") or _is_numbered_item(line):
            _flush_paragraph()
            _flush_list_item()
            list_item_lines = [line]
            continue
        # Check if this is a continuation line for a list item (indented but not 4 spaces)
        if list_item_lines and (line.startswith("   ") or line.startswith("  ")):
            list_item_lines.append(line)
            continue
        # Regular paragraph line
        if list_item_lines:
            _flush_list_item()
        paragraph.append(line)

    _flush_paragraph()
    _flush_list_item()
    while rendered and rendered[-1] == "":
        rendered.pop()
    return rendered


def _is_numbered_item(text: str) -> bool:
    """Check if text starts with a numbered list marker like '1. ' or '2. '."""
    import re

    return bool(re.match(r"^\d+\.\s+", text))


def _extract_numbered_item(text: str) -> tuple[str, str]:
    """Extract the number and rest of text from a numbered list item."""
    import re

    match = re.match(r"^(\d+)\.\s+(.*)", text)
    if match:
        return match.group(1), match.group(2)
    return "", text


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


def _format_syntax(syntax: str, out) -> str:
    parts: list[str] = []
    for token in syntax.split():
        if token in ("|",):
            parts.append(str(out.dim(token)))
        elif token.startswith("[") and token.endswith("]"):
            parts.append(str(out.dim(token)))
        elif token.startswith("--"):
            parts.append(str(out.flag(token)))
        elif token == "keychain" or token.islower():
            parts.append(str(out.kbd(token)))
        elif token.isupper() or token.startswith("<") or token.endswith(">"):
            parts.append(str(out.value(token)))
        else:
            parts.append(out.format_doc(token))
    return " ".join(parts)


def _render_panel_body(short_help: str, description: str, syntax: str, width: int, out) -> list[str]:
    body: list[str] = []
    if short_help:
        body.extend(out.wrap_doc(short_help, width) or [out.format_doc(short_help)])
    if syntax:
        if body:
            body.append("")
        body.append(f"{str(out.dim('Syntax:'))} {_format_syntax(syntax, out)}")
    wrapped = _wrap_doc_text(description, width, out)
    if wrapped:
        if body:
            body.append("")
        body.extend(wrapped)
    return body or ["(no documentation record found)"]


def _render_option_panel_body(
    opt, value: str | None, box_inner: int, out, root_action, action_node
) -> tuple[list[str], str]:
    body = _render_panel_body(opt.short_help, opt.doc_description, _syntax_for(opt.doc_tag), box_inner, out)
    details: list[str] = [f"Accepted spellings: {opt.option_formats}"]
    if value is not None:
        details.append(f"Value on this command line: {value}")
    if opt.config_section:
        details.append(f"Config key: [{opt.config_section}] {opt.effective_config_key}")
    if details:
        body = details + ([""] if body else []) + body
    label = "global option" if opt.actions == {root_action} else f"option for {action_node.fq_name}"
    return body, label


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


def _analyze_explain_argv(argv: list[str]) -> ExplainAnalysis:
    from ..runtime.actions import ROOT_ACTION
    from ..runtime.compat import COMPAT
    from ..runtime.config import RuntimeConfig

    filtered = [token for token in argv if token not in ("--explain", "--nocolor", "--no-color")]
    legacy_equivalent: str | None = None
    legacy_note: str | None = None

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

    return ExplainAnalysis(
        parse_argv=parse_argv,
        action_node=action_node,
        consumed_sequence=list(consumed_sequence),
        visible=visible,
        compat_used=compat_used,
        legacy_equivalent=legacy_equivalent,
        legacy_note=legacy_note,
    )


def _compat_panel_spec(analysis: ExplainAnalysis, box_inner: int, out) -> ExplainPanelSpec | None:
    if not analysis.compat_used:
        return None

    body = _wrap_doc_text(
        "No match for any new-style action; legacy keychain 2.x parsing invoked.",
        box_inner,
        out,
    )
    if analysis.legacy_note:
        body.extend([""] + _wrap_doc_text(analysis.legacy_note, box_inner, out))
    if analysis.legacy_equivalent:
        body.extend(["", "Equivalent keychain 3 command:", analysis.legacy_equivalent])
    return ExplainPanelSpec("Legacy invocation", body, note="compat")


def _action_panel_spec(analysis: ExplainAnalysis, box_inner: int, out) -> ExplainPanelSpec | None:
    from ..runtime.actions import ROOT_ACTION

    if analysis.action_node == ROOT_ACTION:
        return None
    return ExplainPanelSpec(
        f"keychain {analysis.action_node.fq_name}",
        _render_panel_body(
            analysis.action_node.short_help,
            analysis.action_node.doc_description,
            _syntax_for(analysis.action_node.doc_tag),
            box_inner,
            out,
        ),
        note="action",
    )


def _option_panel_spec(
    parser, tok: str, parse_argv: list[str], index: int, visible, box_inner: int, out, action_node
) -> tuple[ExplainPanelSpec, int]:
    from ..runtime.actions import ROOT_ACTION

    opt = parser._resolve_alias(tok, visible)
    value: str | None = None
    title = tok
    consumed = 1
    if opt is None:
        body = _wrap_doc_text(
            "No documentation record matches this token. It would be rejected during normal parsing.",
            box_inner,
            out,
        )
        return ExplainPanelSpec(f"Unrecognised: {tok}", body), consumed

    if opt.takes_value:
        if "=" in tok:
            value = tok.split("=", 1)[1]
        elif index + 1 < len(parse_argv) and parse_argv[index + 1] != "--":
            value = parse_argv[index + 1]
            title = f"{tok} {value}"
            consumed += 1

    body, label = _render_option_panel_body(opt, value, box_inner, out, ROOT_ACTION, action_node)
    return ExplainPanelSpec(title, body, note=label), consumed


def _positional_panel_spec(action_name: str, value: str, box_inner: int, out) -> ExplainPanelSpec:
    title, body_text = _classify_positional(action_name, value)
    return ExplainPanelSpec(title, _wrap_doc_text(body_text, box_inner, out))


def _build_explain_panel_specs(analysis: ExplainAnalysis, parser, box_inner: int, out) -> list[ExplainPanelSpec]:
    from ..runtime.actions import ROOT_ACTION

    panels: list[ExplainPanelSpec] = []
    compat_panel = _compat_panel_spec(analysis, box_inner, out)
    if compat_panel is not None:
        panels.append(compat_panel)

    action_panel = _action_panel_spec(analysis, box_inner, out)
    if action_panel is not None:
        panels.append(action_panel)

    remaining_action_tokens = list(analysis.consumed_sequence)
    i = 0
    while i < len(analysis.parse_argv):
        tok = analysis.parse_argv[i]
        if tok == "--":
            i += 1
            continue

        if tok.startswith("-"):
            panel, consumed = _option_panel_spec(
                parser, tok, analysis.parse_argv, i, analysis.visible, box_inner, out, analysis.action_node
            )
            panels.append(panel)
            i += consumed
            continue

        if remaining_action_tokens and tok == remaining_action_tokens[0]:
            remaining_action_tokens.pop(0)
            i += 1
            continue

        action_name = analysis.action_node.fq_name if analysis.action_node != ROOT_ACTION else "add"
        panels.append(_positional_panel_spec(action_name, tok, box_inner, out))
        i += 1

    return panels


def _render_explain_panels(panels: list[ExplainPanelSpec], out, box_inner: int) -> str:
    title_style = out.style("heading")
    note_style = out.style("dim")
    return "\n".join(
        render_panel(
            panel.title,
            panel.body,
            title_style=title_style,
            note=panel.note or "",
            note_style=note_style,
            min_width=box_inner,
        )
        for panel in panels
    )


def _pager_command() -> str | None:
    """Return a pager command if stdout is a TTY and not piped.

    Checks ``$PAGER`` first, then falls back to ``less -R`` (ANSI passthrough),
    then ``more``.  Returns ``None`` when output is not a TTY so callers can
    skip the pager entirely.
    """
    if not sys.stdout.isatty():
        return None
    env_pager = os.environ.get("PAGER")
    if env_pager:
        return env_pager
    if shutil.which("less"):
        return "less -R"
    if shutil.which("more"):
        return "more"
    return None


def _run_pager(text: str) -> None:
    """Pipe *text* through the configured pager, or write directly."""
    pager = _pager_command()
    if pager is None:
        sys.stdout.write(text)
        return
    import subprocess

    proc = subprocess.Popen(pager.split(), stdin=subprocess.PIPE, stdout=sys.stdout.buffer, stderr=sys.stderr.buffer)
    proc.communicate(input=text.encode("utf-8"))


def run_man(args, out) -> int:
    # Build the document index once - consumed by both list and full renderers
    index = DocumentIndex.build()

    if bool(args.get_value("list")):
        out.write(_render_list_from_index(index, out) + "\n")
        return 0

    topics = list(args.get_value("topics") or [])
    # Default width cap: 80 cols is readable; terminal width is a fallback.
    width = int(args.get_value("width") or 80)
    tags = _resolve_tags_from_index(index, topics)
    sections = [_render_manual_section(tag, width, out, index.labels) for tag in tags]
    full_text = "\n\n".join(section for section in sections if section) + "\n"

    # Pipe through pager when on a TTY (unless --no-pager was given).
    if not bool(args.get_value("no_pager")):
        _run_pager(full_text)
    else:
        out.write(full_text)
    return 0


def run_explain(argv: list[str]) -> int:
    from ..runtime.config import RuntimeConfig
    from ..util import Output

    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    if "--nocolor" in argv or "--no-color" in argv:
        color = False

    out = Output.build(quiet=False, debug=False, eval_mode=False, color=color)
    box_inner = max(40, min(shutil.get_terminal_size((96, 24)).columns - 6, 80))

    analysis = _analyze_explain_argv(argv)
    parser = RuntimeConfig()
    parser._reset_all_cli()
    panels = _build_explain_panel_specs(analysis, parser, box_inner, out)
    rendered = _render_explain_panels(panels, out, box_inner)
    sys.stdout.write(rendered + ("\n" if rendered else ""))
    return 0
