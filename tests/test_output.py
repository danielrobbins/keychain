# SPDX-License-Identifier: GPL-3.0-only
"""Smoke tests for the role-based output API in ``keychain.output``.

The migration plan in ``docs/output-api.md`` lists a handful of acceptance
criteria for the new surface. This file covers:

* every theme resolves every role to a string (round-trip)
* ``Span`` interpolation respects the active theme
* ``Output.silent()`` swallows every emitter
* role helpers return :class:`Span` instances tagged with the right role
"""

import os

import pytest

from keychain import util
from keychain.output import core as output_core
from keychain.output.core import (
    DEFAULT_THEME,
    ROLES,
    THEMES,
    Output,
    Span,
)

# ---------------------------------------------------------------------------
# Theme integrity (acceptance criterion: every role resolves on every theme)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("theme_name", sorted(THEMES))
def test_every_role_resolves_on_every_theme(theme_name):
    theme = THEMES[theme_name]
    for role in ROLES:
        assert role in theme.roles
        assert isinstance(theme.roles[role], str)


def test_default_theme_is_known():
    assert DEFAULT_THEME in THEMES


def test_theme_render_passes_through_plain():
    # plain has no prefix, so render returns the text verbatim.
    for theme in THEMES.values():
        assert theme.render("plain", "hello") == "hello"


def test_theme_render_wraps_with_reset():
    theme = THEMES["modern"]
    rendered = theme.render("identifier", "x")
    # Wrapped sequence ends in the canonical reset.
    assert rendered.endswith(theme.reset)
    assert "x" in rendered


# ---------------------------------------------------------------------------
# Span interpolation against the active theme
# ---------------------------------------------------------------------------


def test_span_str_renders_against_active_theme(monkeypatch):
    monkeypatch.setattr(os, "isatty", lambda fd: True)
    out = Output.build(quiet=False, debug=False, eval_mode=False, color=True, theme="modern")
    s = out.id("hostname")
    rendered = str(s)
    assert "hostname" in rendered
    assert "\x1b[" in rendered  # an ANSI escape was emitted
    # Sanity: same Span re-rendered after switching to no-color drops escapes.
    Output.build(quiet=False, debug=False, eval_mode=False, color=False)
    plain = str(s)
    assert plain == "hostname"


def test_span_role_default_is_plain():
    assert Span("x").role == "plain"


# ---------------------------------------------------------------------------
# Role helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method,role",
    [
        ("id", "identifier"),
        ("path", "path"),
        ("value", "value"),
        ("flag", "flag"),
        ("warn_text", "warn"),
        ("err_text", "err"),
        ("dim", "dim"),
        ("head", "heading"),
        ("note_text", "note"),
        ("kbd", "kbd"),
    ],
)
def test_role_helper_returns_span_with_correct_role(method, role):
    out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
    span = getattr(out, method)("payload")
    assert isinstance(span, Span)
    assert span.role == role
    assert span.text == "payload"


def test_style_returns_concatenated_role_prefixes(monkeypatch):
    monkeypatch.setattr(os, "isatty", lambda fd: True)
    out = Output.build(quiet=False, debug=False, eval_mode=False, color=True, theme="modern")
    combined = out.style("heading", "dim")
    # Both role prefixes appear in the concatenated style string.
    assert combined.startswith("\x1b[")
    assert "\x1b[" in combined[1:]


def test_style_with_no_color_is_empty():
    out = Output.build(quiet=False, debug=False, eval_mode=False, color=False)
    assert out.style("heading", "dim") == ""


def test_doc_inline_code_uses_soft_amber_not_heading_cyan(monkeypatch):
    monkeypatch.setattr(os, "isatty", lambda fd: True)
    out = Output.build(quiet=False, debug=False, eval_mode=False, color=True, theme="modern")
    rendered = out.format_doc("Use `keychain man`.")

    assert THEMES["modern"].roles["doc_code"] in rendered
    assert THEMES["modern"].roles["heading"] not in rendered


def test_doc_text_is_quieter_than_emphasis(monkeypatch):
    monkeypatch.setattr(os, "isatty", lambda fd: True)
    out = Output.build(quiet=False, debug=False, eval_mode=False, color=True, theme="modern")
    rendered = out.format_doc("Normal *important* text.")

    assert THEMES["modern"].roles["doc_text"] in rendered
    assert THEMES["modern"].roles["doc_emph"] in rendered
    assert THEMES["modern"].roles["dim"] not in rendered


def test_note_glyph_uses_green_accent(monkeypatch):
    monkeypatch.setattr(os, "isatty", lambda fd: True)
    out = Output.build(quiet=False, debug=False, eval_mode=False, color=True, theme="modern")
    glyph = out.glyph("note")
    assert glyph.startswith(THEMES["modern"].palette["GREEN"])
    assert THEMES["modern"].glyphs["note"] in glyph


# ---------------------------------------------------------------------------
# Output.silent() (replaces the old _NullOut probe sink)
# ---------------------------------------------------------------------------


class TestOutputSilent:
    def test_silent_swallows_every_emitter(self, capsys):
        out = Output.silent()
        out.info("info")
        out.warn("warn")
        out.note("note")
        out.error("error")
        out.debug("debug")
        out.line("line")
        out.heading("heading")
        out.banner("banner")
        captured = capsys.readouterr()
        assert captured.err == ""
        assert captured.out == ""

    def test_silent_role_helpers_still_return_spans(self):
        # Role helpers don't emit; they just construct Spans for f-string
        # interpolation. They must keep working under silent() so probe
        # callers can still build error messages they choose to suppress.
        out = Output.silent()
        assert isinstance(out.id("x"), Span)
        assert out.id("x").role == "identifier"


# ---------------------------------------------------------------------------
# Emitters: write() bypasses suppression, line() respects quiet
# ---------------------------------------------------------------------------


def test_write_bypasses_quiet_and_json(capsys):
    # write() is for protocol output (shell-eval / env / JSON); it must
    # never be suppressed by quiet or json.
    out = Output.build(quiet=True, debug=False, eval_mode=False, color=False, json=True)
    out.write("MACHINE-READABLE\n")
    captured = capsys.readouterr()
    assert "MACHINE-READABLE" in captured.out


def test_line_suppressed_under_quiet(capsys):
    out = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
    out.line("nope")
    assert capsys.readouterr().err == ""


def test_ephemeral_line_uses_clearable_terminal_control(monkeypatch, capsys):
    monkeypatch.setattr(Output, "_terminal_control_enabled", lambda self: True)
    monkeypatch.setattr(output_core.shutil, "get_terminal_size", lambda fallback: os.terminal_size((120, 24)))
    monkeypatch.setenv("TERM", "xterm-256color")
    out = Output.build(quiet=False, debug=False, eval_mode=False, color=False)

    assert out.ephemeral_line("prompt") is True
    out.clear_ephemeral_line()

    assert capsys.readouterr().err == "\r\x1b[2Kprompt\r\x1b[2K"


def test_ephemeral_line_can_clear_after_input_echo(monkeypatch, capsys):
    monkeypatch.setattr(Output, "_terminal_control_enabled", lambda self: True)
    monkeypatch.setattr(output_core.shutil, "get_terminal_size", lambda fallback: os.terminal_size((120, 24)))
    monkeypatch.setenv("TERM", "xterm-256color")
    out = Output.build(quiet=False, debug=False, eval_mode=False, color=False)

    assert out.ephemeral_line("prompt") is True
    out.clear_ephemeral_line(after_input=True)

    assert capsys.readouterr().err == "\r\x1b[2Kprompt\x1b[1A\r\x1b[2K"


def test_ephemeral_line_falls_back_for_non_tty(monkeypatch, capsys):
    monkeypatch.setattr(os, "isatty", lambda fd: False)
    monkeypatch.setenv("TERM", "xterm-256color")
    out = Output.build(quiet=False, debug=False, eval_mode=False, color=False)

    assert out.ephemeral_line("prompt") is False

    assert capsys.readouterr().err == "prompt\n"


def test_info_suppressed_under_json(capsys):
    out = Output.build(quiet=False, debug=False, eval_mode=False, color=False, json=True)
    out.info("nope")
    assert capsys.readouterr().err == ""


def test_warn_suppressed_under_json(capsys):
    # New policy: warn/error are human-facing under --json too. The JSON
    # consumer sees only the JSON document on stdout.
    out = Output.build(quiet=False, debug=False, eval_mode=False, color=False, json=True)
    out.warn("noisy")
    assert capsys.readouterr().err == ""


def test_quiet_and_debug_emitter_policy(capsys):
    quiet = Output.build(quiet=True, debug=False, eval_mode=False, color=False)
    quiet.info("hidden")
    quiet.note("hidden")
    quiet.warn("visible")
    quiet.debug("hidden")

    captured = capsys.readouterr().err
    assert "visible" in captured
    assert "hidden" not in captured


def test_debug_emits_only_when_enabled(capsys):
    Output.build(quiet=False, debug=False, eval_mode=False, color=False).debug("hidden")
    Output.build(quiet=False, debug=True, eval_mode=False, color=False).debug("visible")

    captured = capsys.readouterr().err
    assert "visible" in captured
    assert "hidden" not in captured


def test_completed_migration_exposes_only_canonical_output_api():
    out = Output.silent()

    for old_name in ("c", "colors", "glyphs", "mesg", "qprint", "section", "banner_line"):
        assert not hasattr(out, old_name)
    assert not hasattr(util, "Output")
