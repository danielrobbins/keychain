# SPDX-License-Identifier: GPL-3.0-only
"""Render the embedded manual as roff man(7) source for ``keychain man --roff``."""

from __future__ import annotations

import datetime
import os
import re
from typing import Any

from ..output.core import split_doc_inline
from . import (
    DocumentIndex,
    _authored_label,
    _config_items,
    _dedupe_doc_source_lines,
    _entry,
    _extract_numbered_item,
    _has_authored_config_docs,
    _is_numbered_item,
    _list_config_rows,
    _manual_tags_from_index,
    _syntax_for,
)

_FONTS = {"code": "B", "emph": "I"}

_INDENT = 4
_LITERAL = "    "


def _escape(text: str) -> str:
    # "-" is a hyphen in roff; option names need the minus sign to stay searchable.
    return text.replace("\\", "\\e").replace("-", "\\-")


def _protect(text: str) -> str:
    """Keep text from being read as a roff request."""
    if text[:1] in (".", "'"):
        return "\\&" + text
    return text


def _inline(text: str) -> str:
    parts: list[str] = []
    for chunk, kind in split_doc_inline(text):
        if not chunk:
            continue
        font = _FONTS.get(kind)
        parts.append("\\f{}{}\\fP".format(font, _escape(chunk)) if font else _escape(chunk))
    return _protect("".join(parts))


def _section_heading(title: str) -> str:
    head, paren, tail = title.partition("(")
    return _escape(head.strip().upper() + (" (" + tail if paren else ""))


class _Writer:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def request(self, text: str) -> None:
        self.lines.append(text)

    def text(self, text: str) -> None:
        self.lines.append(_inline(text))

    def paragraph(self, text: str) -> None:
        self.request(".PP")
        self.text(text)

    def literal(self, lines: list[str]) -> None:
        if not lines:
            return
        self.request(".RS {}".format(_INDENT))
        self.request(".nf")
        for line in lines:
            self.lines.append(_protect(_escape(line)))
        self.request(".fi")
        self.request(".RE")

    def tagged(self, term: str, summary: str) -> None:
        self.request(".TP")
        self.request(".B {}".format(_escape(term)))
        self.text(summary or "")


def _render_body(text: str, writer: _Writer) -> None:
    """Translate one authored body, following the block grammar of ``_render_manual_text``."""
    paragraph: list[str] = []
    item: list[str] = []
    literal: list[str] = []
    in_fence = False

    def flush_paragraph() -> None:
        if paragraph:
            writer.paragraph(" ".join(line.strip() for line in paragraph))
            paragraph.clear()

    def flush_item() -> None:
        if not item:
            return
        first, rest = item[0], [line.strip() for line in item[1:]]
        if first.startswith("* "):
            marker, content = "\\(bu", first[2:]
        else:
            number, content = _extract_numbered_item(first)
            marker = '"{}."'.format(number)
        writer.request(".IP {} {}".format(marker, _INDENT))
        writer.text(" ".join([content, *rest]).strip())
        item.clear()

    def flush_literal() -> None:
        if literal:
            writer.literal(literal)
            literal.clear()

    for line in _dedupe_doc_source_lines(text):
        if line == "```":
            flush_paragraph()
            flush_item()
            if in_fence:
                flush_literal()
            in_fence = not in_fence
            continue

        if in_fence:
            literal.append(line)
            continue

        if line.strip().startswith("@func:"):
            flush_paragraph()
            flush_item()
            flush_literal()
            _render_directive(line.strip(), writer)
            continue

        if not line:
            flush_paragraph()
            flush_item()
            flush_literal()
            continue

        if line.startswith(_LITERAL):
            flush_paragraph()
            flush_item()
            literal.append(line[len(_LITERAL) :])
            continue

        flush_literal()

        if line.startswith("* ") or _is_numbered_item(line):
            flush_paragraph()
            flush_item()
            item.append(line)
            continue

        if item and line.startswith("  "):
            item.append(line)
            continue

        flush_item()
        paragraph.append(line)

    flush_paragraph()
    flush_item()
    flush_literal()


def _render_directive(line: str, writer: _Writer) -> None:
    name = line.split(":", 1)[1].strip()
    if name != "config_index":
        raise ValueError("unknown render block: {}".format(name))
    _render_config_index(writer)


def _render_config_index(writer: _Writer) -> None:
    for _kind, label, _lookup, summary in _list_config_rows():
        writer.tagged(label, summary)

    detailed = [item for item in _config_items() if _has_authored_config_docs(item)]
    if not detailed:
        return
    writer.request(".PP")
    writer.request(".B Detailed config entries")
    for item in detailed:
        writer.request(".PP")
        writer.request(".B {}".format(_escape("{}.{}".format(item["section"], item["key"]))))
        _render_config_entry(item, writer)


def _render_config_entry(item: dict[str, Any], writer: _Writer) -> None:
    opt = item["option"]
    key = item["key"]
    entry = _entry(opt.config_doc_tag or "") if opt.config_doc_tag else {}

    writer.paragraph("Config key: [{}] {}".format(item["section"], key))

    if opt.option:
        if opt.cli_const is not None:
            alias = "`{}` selects `{} = {}` for this invocation.".format(opt.option, key, opt.cli_const)
        elif opt.config_invert_bool and opt.type == "bool":
            alias = (
                "Persistent inverse of {}. Set `{} = true` in `~/.keychainrc` to enable the "
                "positive behavior, or `{} = false` to get the same effect as {}.".format(
                    opt.option_formats, key, key, opt.option_formats
                )
            )
        else:
            alias = "Persistent equivalent of {}. Set it in `~/.keychainrc` to make that behavior the default.".format(
                opt.option_formats
            )
        writer.paragraph(alias)
        short_help = entry.get("short_help", "") or opt.short_help
        description = entry.get("description", "") or opt.doc_description
    else:
        short_help = entry.get("short_help", "")
        description = entry.get("description", "")

    if short_help:
        writer.paragraph(short_help)
    if description:
        _render_body(description, writer)
    if not short_help and not description and opt.option:
        writer.paragraph("See {} for behavior details.".format(opt.option_formats))


def _render_tag(tag: str, labels: dict[str, str], writer: _Writer) -> None:
    entry = _entry(tag)
    if not entry:
        return

    lookup = _authored_label(tag, labels)
    title = entry.get("short_help", "") or lookup
    if tag.startswith(("action:", "option:", "global:", "config:")):
        heading = lookup
    elif title == lookup:
        heading = title
    else:
        heading = "{} ({})".format(title, lookup)
    writer.request(".SS {}".format(_escape(heading)))

    syntax = _syntax_for(tag)
    if syntax:
        writer.request(".PP")
        writer.request("Syntax: \\fB{}\\fP".format(_escape(syntax)))

    _render_body(entry.get("description", ""), writer)


def _page_date() -> str:
    stamp = os.environ.get("SOURCE_DATE_EPOCH")
    if stamp and stamp.isdigit():
        moment = datetime.datetime.fromtimestamp(int(stamp), tz=datetime.timezone.utc)
    else:
        moment = datetime.datetime.now(tz=datetime.timezone.utc)
    return moment.strftime("%Y-%m-%d")


def render_manual(index: DocumentIndex | None = None, *, version: str | None = None, date: str | None = None) -> str:
    """Return the complete manual as roff man(7) source."""
    if index is None:
        index = DocumentIndex.build()
    if version is None:
        from .. import __version__

        version = __version__

    tool = _entry("tool:keychain")
    summary = re.sub(r"\.\s*$", "", tool.get("short_help", "") or "manager for ssh-agent and private keys")

    writer = _Writer()
    writer.request('.TH KEYCHAIN 1 "{}" "keychain {}" "User Commands"'.format(date or _page_date(), version))
    writer.request(".SH NAME")
    writer.request("keychain \\- {}".format(_inline(summary)))
    writer.request(".SH SYNOPSIS")
    writer.request(".B keychain")
    writer.request(".RI [ global\\-options ]\\ [ action ]\\ [ action\\-options ]\\ [ keys .\\|.\\|.]")
    writer.request(".SH DESCRIPTION")
    _render_body(tool.get("description", ""), writer)

    for tag in _manual_tags_from_index(index):
        if tag == "tool:keychain":
            continue
        if tag.startswith("section:"):
            writer.request(".SH {}".format(_section_heading(tag.split(":", 1)[1])))
            continue
        _render_tag(tag, index.labels, writer)

    return "\n".join(writer.lines) + "\n"
