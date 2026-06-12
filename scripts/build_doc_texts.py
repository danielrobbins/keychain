# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import OrderedDict
from dataclasses import dataclass
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

    @property
    def tag(self) -> str:
        return f"{self.kind}:{self.name}"


def _split_heading(rest: str) -> tuple[str, str]:
    name, sep, short_help = rest.partition(":")
    return (name.rstrip(), short_help.strip() if sep else "")


def get_heading(stripped: str, *, lineno: int) -> Section | None:
    """Return a Section if the current line starts a tagged block."""
    match = _HEADING_RE.match(stripped.rstrip("\r\n"))
    if match is None:
        return None
    kind, rest = match.groups()
    name, short_help = _split_heading(rest or "")
    return Section(lineno=lineno, kind=kind, name=name, short_help=short_help)


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
        out[section.kind][section.name] = {
            "short_help": section.short_help,
            "syntax": section.syntax,
            "description": section.body,
        }
    return out


def render_json(docs: dict[str, Any]) -> str:
    return json.dumps(docs, indent=2, ensure_ascii=False) + "\n"


def _import_action_tree():
    src = str(_ROOT / "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    from keychain.runtime.actions import ROOT_ACTION

    return ROOT_ACTION


def _walk_actions(action):
    yield action
    for child in action.sub_actions.values():
        yield from _walk_actions(child)


def _authored_option_tag(action, opt) -> str:
    """Return the doc tag expected in embedded docs for *opt*."""
    tag = opt.doc_tag
    if action.fq_name == "global" and tag.startswith("option:"):
        return f"global:{tag.split(':', 1)[1]}"
    return tag


def validate_action_tree_docs(docs: dict[str, Any]) -> list[str]:
    """Return validation errors for action/option documentation drift."""
    root = _import_action_tree()
    authored_tags = set(docs.get("all", ()))
    expected_action_tags: set[str] = set()
    expected_option_tags: set[str] = set()

    for action in _walk_actions(root):
        if action is not root:
            expected_action_tags.add(action.doc_tag)
        for opt in action.options.values():
            expected_option_tags.add(_authored_option_tag(action, opt))

    authored_action_tags = {f"action:{name}" for name in docs.get("action", {})}
    authored_option_tags = {f"option:{name}" for name in docs.get("option", {})}
    authored_global_tags = {f"global:{name}" for name in docs.get("global", {})}
    authored_option_surface_tags = authored_option_tags | authored_global_tags

    errors: list[str] = []
    for tag in sorted(expected_action_tags - authored_tags):
        errors.append(f"missing action doc for live action: {tag}")
    for tag in sorted(expected_option_tags - authored_tags):
        errors.append(f"missing option doc for live option: {tag}")
    for tag in sorted(authored_action_tags - expected_action_tags):
        errors.append(f"stale action doc without live action: {tag}")
    for tag in sorted(authored_option_surface_tags - expected_option_tags):
        errors.append(f"stale option/global doc without live option: {tag}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the embedded docs JSON blob from tagged text.")
    parser.add_argument("--source", type=Path, default=_SOURCE)
    parser.add_argument("--output", type=Path, default=_OUTPUT)
    parser.add_argument("--check", action="store_true", help="fail if OUTPUT is out of date")
    args = parser.parse_args(argv)

    docs = parse_tagged_text(args.source.read_text(encoding="utf-8"))
    validation_errors = validate_action_tree_docs(docs)
    if validation_errors:
        for error in validation_errors:
            sys.stderr.write(f"{error}\n")
        return 1

    rendered = render_json(docs)
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
