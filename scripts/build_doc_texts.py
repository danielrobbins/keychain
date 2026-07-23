# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
_SOURCE = _ROOT / "man" / "embedded-docs.txt"
_OUTPUT = _ROOT / "src" / "keychain" / "docs" / "_doc_texts.json"

_HEADING_RE = re.compile(r"^==\s+@([a-z][a-z0-9-]*)(?:\s+(.*\S))?\s*$")


@dataclass
class Section:
    lineno: int = 0
    kind: str = ""
    name: str = ""
    short_help: str = ""
    syntax: str = ""
    body: str = ""
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def tag(self) -> str:
        return f"{self.kind}:{self.name}"


def _split_heading(rest: str) -> tuple[str, str, dict[str, str]]:
    name, sep, short_help = rest.partition(":")
    # Extract metadata from short_help if present (format: "text [key=value, ...]")
    import re

    match = re.match(r"^(.*?)\s*\[(.*?)\]\s*$", short_help or "")
    if match:
        clean_short_help = match.group(1).strip()
        metadata_str = match.group(2)
        metadata = {}
        for item in metadata_str.split(","):
            if "=" in item:
                k, v = item.split("=", 1)
                metadata[k.strip()] = v.strip()
        return (name.rstrip(), clean_short_help, metadata)
    return (name.rstrip(), (short_help or "").strip(), {})


def get_heading(stripped: str, *, lineno: int) -> Section | None:
    """Return a Section if the current line starts a tagged block."""
    match = _HEADING_RE.match(stripped.rstrip("\r\n"))
    if match is None:
        return None
    kind, rest = match.groups()
    name, short_help, metadata = _split_heading(rest or "")
    return Section(lineno=lineno, kind=kind, name=name, short_help=short_help, metadata=metadata)


def parse_sections(text: str) -> list[Section]:
    """Parse tagged embedded-doc text into Section records."""
    docs: list[Section] = []
    cur_section: Section | None = None
    current_lines: list[str] = []

    def _finish(*, lineno: int) -> None:
        # Close out the current section when a new heading starts or at end of file.
        nonlocal cur_section, current_lines
        if cur_section is None:
            return
        cur_section.body = "".join(current_lines).rstrip("\r\n")
        if cur_section.kind != "section" and not cur_section.body.strip():
            raise ValueError(f"line {lineno}: empty doc body for {cur_section.tag}")
        docs.append(cur_section)
        cur_section = None
        current_lines = []

    for lineno, line in enumerate(text.splitlines(keepends=True), start=1):
        if line.lstrip().startswith("%% @"):
            raise ValueError(f"line {lineno}: pseudo-heading must use == @")
        new_section = get_heading(line, lineno=lineno)
        if new_section:
            # A heading always starts a new section, so flush any active one first.
            if cur_section:
                _finish(lineno=lineno)
            cur_section = new_section
            continue

        if cur_section is None:
            raise ValueError(f"line {lineno}: text outside a tagged block: {line!r}")

        stripped = line.strip()
        body_started = any(part.strip() for part in current_lines)
        if not body_started and stripped.startswith("@syntax"):
            key, _, value = stripped.partition(" ")
            if key != "@syntax" or not value:
                raise ValueError(f"line {lineno}: @syntax requires text")
            if cur_section.syntax:
                raise ValueError(f"line {lineno}: duplicate @syntax for {cur_section.tag}")
            cur_section.syntax = value.strip()
            continue
        if not body_started and stripped.startswith("@"):
            raise ValueError(f"line {lineno}: unknown metadata tag {stripped}")
        if not body_started and not stripped:
            continue
        current_lines.append(line.rstrip("\r\n") + "\n")

    _finish(lineno=len(text.splitlines()) or 1)
    return docs


def parse_tagged_text(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    out["all"] = []
    for section in parse_sections(text):
        tag = section.tag
        if tag in out["all"]:
            raise ValueError(f"duplicate doc tag {tag}")
        out["all"].append(tag)
        out.setdefault(section.kind, OrderedDict())
        entry: dict[str, Any] = {
            "short_help": section.short_help,
            "syntax": section.syntax,
            "description": section.body,
        }
        # Add metadata for topics (category, priority, etc.)
        if section.kind == "topic" and section.metadata:
            entry["metadata"] = section.metadata
        out[section.kind][section.name] = entry
    return out


def render_json(docs: dict[str, Any]) -> str:
    return json.dumps(docs, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the embedded docs JSON blob from tagged text.")
    parser.add_argument("--source", type=Path, default=_SOURCE)
    parser.add_argument("--output", type=Path, default=_OUTPUT)
    parser.add_argument("--check", action="store_true", help="fail if OUTPUT is out of date")
    args = parser.parse_args(argv)

    rendered = render_json(parse_tagged_text(args.source.read_text(encoding="utf-8")))
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
        if current != rendered:
            sys.stderr.write(f"{args.output} is out of date; run scripts/build_doc_texts.py\n")
            return 1
        return 0

    args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
