# SPDX-License-Identifier: GPL-3.0-only
"""Lightweight table renderer.

Single public function :func:`render_table`. Box-drawing characters when the
terminal is UTF-8 capable; ASCII fallback otherwise. ANSI color codes inside
cells are tolerated when computing column widths via :func:`visible_width`.

Kept dependency-free and small on purpose -- a third-party ``tabulate`` /
``rich`` would dwarf the rest of ``src/keychain/`` and bloat ``keychain.pyz``.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterable, Sequence

# Strip ANSI CSI sequences when measuring column widths so colored cells
# still align. We don't need a perfect parser -- ``\x1b[...m`` covers SGR.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# (top, mid, bottom, vertical, horizontal, junction-h, junction-v, cross)
_BOX_UNICODE = ("─", "│", "╭┬╮", "├┼┤", "╰┴╯")
_BOX_ASCII = ("-", "|", "+++", "+++", "+++")


def visible_width(text: str) -> int:
    """Length of *text* with ANSI SGR escapes removed."""
    return len(_ANSI_RE.sub("", text))


def _use_unicode() -> bool:
    enc = (getattr(sys.stderr, "encoding", "") or "").lower()
    return "utf" in enc


def render_table(
    rows: Sequence[Sequence[str]], headers: Sequence[str] | None = None, indent: int = 2, header_style: str = ""
) -> str:
    """Render *rows* (and optional *headers*) as an aligned text table.

    Returns the rendered string (no trailing newline). Empty input yields ``""``.
    Cells are coerced to ``str``; ANSI color codes inside cells are honoured
    and excluded from width calculations so colored tables still align.
    *header_style* is an ANSI escape applied to each header cell (cleared
    with ``\\x1b[0m``); pass ``""`` for plain headers.
    """
    body = [[str(c) for c in row] for row in rows]
    if not body and not headers:
        return ""
    head = [str(c).upper() for c in headers] if headers else None
    ncols = max((len(r) for r in body), default=0)
    if head is not None:
        ncols = max(ncols, len(head))
    # Pad short rows so zip-style logic works uniformly.
    for r in body:
        if len(r) < ncols:
            r.extend([""] * (ncols - len(r)))
    if head is not None and len(head) < ncols:
        head = head + [""] * (ncols - len(head))

    widths = [0] * ncols
    for r in ([head] if head else []) + body:
        for i, cell in enumerate(r):
            w = visible_width(cell)
            if w > widths[i]:
                widths[i] = w

    box = _BOX_UNICODE if _use_unicode() else _BOX_ASCII
    h, v, top, mid, bot = box
    pad = " " * indent

    def hline(left_mid_right: str) -> str:
        return pad + left_mid_right[0] + left_mid_right[1].join(h * (w + 2) for w in widths) + left_mid_right[2]

    def fmt_row(cells: Iterable[str]) -> str:
        parts: list[str] = []
        for cell, w in zip(cells, widths):
            extra = w - visible_width(cell)
            parts.append(" " + cell + " " * extra + " ")
        return pad + v + v.join(parts) + v

    lines: list[str] = [hline(top)]
    if head is not None:
        if header_style:
            styled = [f"{header_style}{c}\x1b[0m" for c in head]
            lines.append(fmt_row(styled))
        else:
            lines.append(fmt_row(head))
        lines.append(hline(mid))
    for r in body:
        lines.append(fmt_row(r))
    lines.append(hline(bot))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Panels (titled boxes) and column composition for control-panel layouts.
# Used by ``keychain inspect`` to render section blocks side-by-side when
# the terminal is wide enough; see ``docs/output-design.md``.
# ---------------------------------------------------------------------------


def render_panel(
    title: str,
    body_lines: Sequence[str],
    title_style: str = "",
    note: str = "",
    note_style: str = "",
    min_width: int = 0,
    indent: int = 1,
) -> str:
    """Render *body_lines* inside a rounded box with a titled top border.

    Output looks like::

        ╭─ Title ───────────╮
        │ row 1             │
        │ row 2             │
        ╰───────────────────╯

    ASCII fallback uses ``+``/``-``/``|`` like :func:`render_table`. ANSI
    color codes inside *body_lines* are honoured for width calculations.
    """
    box = _BOX_UNICODE if _use_unicode() else _BOX_ASCII
    h, v, top, _mid, bot = box
    pad = " " * indent

    title_text = f" {title_style}{title}\x1b[0m " if title_style else f" {title} "
    if note:
        note_text = f"({note})"
        if note_style:
            title_text += f"{note_style}{note_text}\x1b[0m "
        else:
            title_text += f"{note_text} "
    title_w = visible_width(title_text)
    body_w = max([visible_width(ln) for ln in body_lines] + [title_w + 2, min_width])

    fill = h * (body_w - title_w)
    top_line = pad + top[0] + h + h + title_text + fill + top[2]
    bot_line = pad + bot[0] + h * (body_w + 2) + bot[2]
    rows = [top_line]
    for ln in body_lines:
        rows.append(pad + v + " " + ln + " " * (body_w - visible_width(ln)) + " " + v)
    rows.append(bot_line)
    return "\n".join(rows)


def compose_columns(panels: Sequence[str], term_width: int, gap: int = 2) -> str:
    """Lay out pre-rendered *panels* into as many columns as fit *term_width*.

    Greedy first-fit: walks *panels* left to right, packing each into the
    current row until adding the next would overflow, then starts a new row.
    Within a row, panels are aligned at the top (shorter ones get blank
    padding underneath) so column boundaries stay clean.
    Returns a single string; rows are separated by a blank line.
    """
    if not panels:
        return ""
    panel_lines = [p.splitlines() for p in panels]
    widths = [max((visible_width(ln) for ln in pl), default=0) for pl in panel_lines]

    rows: list[list[int]] = []
    cur: list[int] = []
    cur_w = 0
    for i, w in enumerate(widths):
        added = w if not cur else cur_w + gap + w
        if cur and added > term_width:
            rows.append(cur)
            cur, cur_w = [i], w
        else:
            cur.append(i)
            cur_w = added
    if cur:
        rows.append(cur)

    gap_str = " " * gap
    out: list[str] = []
    for row in rows:
        row_panels = [panel_lines[i] for i in row]
        row_widths = [widths[i] for i in row]
        n = max(len(p) for p in row_panels)
        for line_idx in range(n):
            parts: list[str] = []
            for pl, w in zip(row_panels, row_widths):
                if line_idx < len(pl):
                    line = pl[line_idx]
                    parts.append(line + " " * (w - visible_width(line)))
                else:
                    parts.append(" " * w)
            out.append(gap_str.join(parts).rstrip())
        out.append("")
    return "\n".join(out).rstrip()
