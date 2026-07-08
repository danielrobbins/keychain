# SPDX-License-Identifier: GPL-3.0-only
"""Tests for keychain.tables."""

from keychain.output.tables import render_table, visible_width


def test_visible_width_strips_ansi():
    assert visible_width("\x1b[32;01mhi\x1b[0m") == 2
    assert visible_width("plain") == 5
    assert visible_width("") == 0


def test_render_table_empty_returns_empty_string():
    assert render_table([]) == ""


def test_render_table_with_headers_aligns_columns():
    text = render_table(
        [["a", "longer"], ["bbb", "x"]],
        headers=["L", "R"],
    )
    lines = text.splitlines()
    # Header + body cells are pad-aligned to the widest column entry.
    # Every body line must have identical length (tables are rectangular).
    body_lines = [ln for ln in lines if not set(ln.strip()) <= set("-+|─│┌┬┐├┼┤└┴┘")]
    widths = {len(ln) for ln in body_lines}
    assert len(widths) == 1, f"rows misaligned: {widths}"


def test_render_table_honours_ansi_for_alignment():
    plain = render_table([["abc"]])
    colored = render_table([["\x1b[32mabc\x1b[0m"]])
    # The colored cell occupies the same visible width as the plain one,
    # so the table outline is identical.
    assert plain.splitlines()[0] == colored.splitlines()[0]


def test_render_table_pads_short_rows():
    # Asymmetric rows must not raise; the short row gets blank cells.
    text = render_table([["a", "b"], ["c"]], headers=["x", "y"])
    assert "c" in text
