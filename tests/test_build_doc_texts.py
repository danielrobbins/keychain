# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

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
    # Deprecated: @section markers are no longer used.
    # Sections are now generated from metadata (action tree, topic categories, etc.)
    # This test remains to ensure backward compatibility if old markers exist.
    text = """== @topic usage: Usage.

Body.

== @action add: Add keys.

Body.
"""

    docs = build_doc_texts.parse_tagged_text(text)

    assert docs["all"] == ["topic:usage", "action:add"]
    assert docs["topic"]["usage"]["description"] == "Body."


def test_parse_sections_rejects_pseudo_headings_in_body():
    text = """== @topic usage: Usage.

%% @config agent.env.ssh_args: Wrong marker.
"""

    try:
        build_doc_texts.parse_sections(text)
    except ValueError as exc:
        assert "pseudo-heading" in str(exc)
    else:
        raise AssertionError("expected pseudo-heading to fail")


def test_parse_tagged_text_accepts_config_sections():
    text = """== @config agent.env.ssh_args: SSH agent args.

Append extra arguments.
"""

    docs = build_doc_texts.parse_tagged_text(text)

    assert docs["all"] == ["config:agent.env.ssh_args"]
    assert docs["config"]["agent.env.ssh_args"]["short_help"] == "SSH agent args."
