# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

from pathlib import Path

from scripts import build_doc_texts


def test_parse_sections_keeps_heading_metadata_out_of_body():
    text = """== @action add: Add keys.

@syntax keychain add [KEYS...]

Load identities into the agent.
"""

    section = build_doc_texts.parse_sections(text)[0]

    assert section.tag == "action:add"
    assert section.short_help == "Add keys."
    assert section.syntax == "keychain add [KEYS...]"
    assert section.body == "Load identities into the agent."


def test_parse_tagged_text_preserves_each_body_line_once():
    text = """== @topic usage: Usage.

First line.
Second line.
"""

    docs = build_doc_texts.parse_tagged_text(text)

    assert docs["all"] == ["topic:usage"]
    assert docs["topic"]["usage"]["description"] == "First line.\nSecond line."


def test_parse_sections_allows_empty_section_markers():
    text = """== @topic usage: Usage.

Body.

== @section ACTIONS

== @action add: Add keys.

Body.
"""

    docs = build_doc_texts.parse_tagged_text(text)

    assert docs["all"] == ["topic:usage", "section:ACTIONS", "action:add"]
    assert docs["section"]["ACTIONS"]["description"] == ""


def test_embedded_docs_cover_live_action_tree():
    """Verify every live action/option has docs, and stale action/option docs fail."""
    source = Path(__file__).resolve().parents[1] / "man" / "embedded-docs.txt"
    docs = build_doc_texts.parse_tagged_text(source.read_text(encoding="utf-8"))

    assert build_doc_texts.validate_action_tree_docs(docs) == []
