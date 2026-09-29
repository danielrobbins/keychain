# SPDX-License-Identifier: GPL-3.0-only
"""User-facing output: themes, role-tagged spans, emitters.

Three layers, smallest first:

* :class:`Span` -- a typed colored fragment carrying a *role* name. Its
  ``__str__`` looks up the active :class:`Theme` from a thread-local set
  by :meth:`Output.build` and renders the wrapped text with that theme's
  ANSI prefix and reset.
* :class:`Theme` -- ``role -> ANSI prefix`` plus a glyph map and its
  internal palette.
* :class:`Output` -- emitters (``info``/``warn``/``note``/``error``/
  ``debug``/``line``/``heading``/``banner``/``write``) plus role
  helpers (``id``/``path``/``value``/``flag``/``warn_text``/
  ``err_text``/``dim``/``head``/``note_text``/``kbd``).

Targets Python 3.9+.
"""

from __future__ import annotations

import os
import re
import sys
import threading
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import TextIO, Union
from unicodedata import combining, east_asian_width

from .debug import DebugLog

# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------

# Canonical list of fragment roles. Adding a new role requires updating
# every theme's role map; ``_validate_themes`` enforces that at import time.
ROLES: tuple[str, ...] = (
    "plain",  # passthrough; no styling
    "identifier",  # hostnames, paths, key files, PIDs
    "path",  # filesystem paths (often == identifier)
    "value",  # newly-set or "good" values; loaded keys
    "flag",  # CLI flag tokens (--quick) in prose
    "warn",  # inline warning words
    "err",  # inline error words
    "note",  # inline emphasis (purple)
    "dim",  # parentheticals, "(none)", placeholder text
    "heading",  # section / panel titles
    "kbd",  # shell snippets in prose
    "doc_text",  # normal prose inside embedded docs
    "doc_code",  # inline `code` spans inside prose docs
    "doc_block",  # fenced code blocks inside prose docs
    "doc_emph",  # emphasized *text* inside prose docs
    "underlined_heading",  # bold cyan + underline for action/option/config/section headings
)

DEFAULT_THEME = "modern"


# ---------------------------------------------------------------------------
# Palettes
# ---------------------------------------------------------------------------

_LEGACY_PALETTE: dict[str, str] = {
    "BLUE": "\033[34;01m",
    "CYAN": "\033[36;01m",
    "CYANN": "\033[36m",
    "GREEN": "\033[32;01m",
    "RED": "\033[31;01m",
    "PURP": "\033[35;01m",
    "YEL": "\033[33;01m",
    "AMBER": "\033[33m",
    "DOC": "\033[37m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
    "OFF": "\033[0m",
}
_MODERN_PALETTE: dict[str, str] = {
    "BLUE": "\033[38;5;75m",  # cornflower blue
    "CYAN": "\033[38;5;87m",  # bright aqua
    "CYANN": "\033[38;5;81m",  # deep sky blue
    "GREEN": "\033[38;5;114m",  # soft sage
    "RED": "\033[38;5;203m",  # warm salmon
    "PURP": "\033[38;5;141m",  # muted mauve
    "YEL": "\033[38;5;221m",  # gold
    "AMBER": "\033[38;5;179m",  # softened amber for inline prose code
    "DOC": "\033[38;5;250m",  # readable but quieter than emphasis
    "BOLD": "\033[1m\033[38;5;255m",  # bright white emphasis
    "DIM": "\033[38;5;245m",  # neutral grey
    "OFF": "\033[0m",
}
_NO_ANSI: dict[str, str] = {k: "" for k in _LEGACY_PALETTE}

_DOC_INLINE_MARKUP_RE = re.compile(r"`([^`\n]+)`|(?<!\*)\*([^*\n]+)\*(?!\*)")
_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _roles_for(palette: Mapping[str, str]) -> dict[str, str]:
    """Map :data:`ROLES` onto a palette. Single source of truth for the
    role -> color binding (changing a role's color is a one-line edit)."""
    return {
        "plain": "",
        "identifier": palette["CYANN"],
        "path": palette["CYANN"],
        "value": palette["GREEN"],
        "flag": palette["CYANN"],
        "warn": palette["YEL"],
        "err": palette["RED"],
        "note": palette["PURP"],
        "dim": palette["DIM"],
        "heading": palette["CYANN"],
        "kbd": palette["CYANN"],
        "doc_text": palette["DOC"],
        "doc_code": palette["AMBER"],
        "doc_block": palette["CYANN"],
        "doc_emph": palette["BOLD"],
        "underlined_heading": f"\x1b[1m\x1b[4m{palette['CYANN']}",
    }


# ---------------------------------------------------------------------------
# Glyphs
# ---------------------------------------------------------------------------

_GLYPHS_MODERN: dict[str, str] = {
    "info": "\u25b8",  # ▸
    "ok": "\u25cf",  # ●
    "warn": "\u25b2",  # ▲
    "err": "\u2716",  # ✖
    "note": "\u203a",  # ›
    "debug": "\u22ef",  # ⋯
    "bar": "\u258c",  # ▌
    "arrow": "\u21b3",  # ↳
    "prompt": "\u25b8",  # ▸
}
_GLYPHS_ASCII: dict[str, str] = {
    "info": "*",
    "ok": "*",
    "warn": "!",
    "err": "x",
    "note": "-",
    "debug": ":",
    "bar": "|",
    "arrow": ">",
    "prompt": ">",
}
# Glyph -> palette color role (used to color the glyph itself).
_GLYPH_COLOR: dict[str, str] = {
    "info": "CYANN",
    "ok": "GREEN",
    "warn": "YEL",
    "err": "RED",
    "note": "GREEN",
    "debug": "DIM",
    "bar": "CYANN",
    "arrow": "DIM",
}


# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Theme:
    """A complete styling profile. Every role in :data:`ROLES` MUST resolve."""

    name: str
    palette: Mapping[str, str]
    roles: Mapping[str, str]
    glyphs: Mapping[str, str]
    reset: str = "\x1b[0m"

    def render(self, role: str, text: str) -> str:
        """Wrap *text* in the role's ANSI prefix + reset. No-op when prefix is empty."""
        prefix = self.roles.get(role, "")
        if not prefix:
            return text
        return f"{prefix}{text}{self.reset}"


THEMES: dict[str, Theme] = {
    "legacy": Theme(
        name="legacy",
        palette=_LEGACY_PALETTE,
        roles=_roles_for(_LEGACY_PALETTE),
        glyphs=_GLYPHS_ASCII,
    ),
    "modern": Theme(
        name="modern",
        palette=_MODERN_PALETTE,
        roles=_roles_for(_MODERN_PALETTE),
        glyphs=_GLYPHS_MODERN,
    ),
}

# A theme that renders nothing (every role -> empty prefix). Used for
# no-color output, JSON mode, and silent probes.
_NULL_THEME = Theme(
    name="none",
    palette=_NO_ANSI,
    roles=_roles_for(_NO_ANSI),
    glyphs=_GLYPHS_ASCII,
)


def _validate_themes() -> None:
    """Catch role/theme drift at import time (acceptance criterion)."""
    for theme in THEMES.values():
        for role in ROLES:
            if role not in theme.roles:
                raise RuntimeError(f"theme {theme.name!r} missing role {role!r}")


_validate_themes()


def resolve_theme_name(name: str | None) -> str:
    """Return a known theme name (case-insensitive); fall back to default."""
    if name:
        key = name.strip().lower()
        if key in THEMES:
            return key
    return DEFAULT_THEME


def stderr_supports_unicode() -> bool:
    """True when stderr's encoding can carry the modern glyphs."""
    enc = (getattr(sys.stderr, "encoding", "") or "").lower()
    return "utf" in enc


# ---------------------------------------------------------------------------
# Span
# ---------------------------------------------------------------------------

# One active theme per process, set by :meth:`Output.build`. Stored on a
# thread-local so :meth:`Span.__str__` can render without taking the
# ``Output`` instance as an argument -- which is what makes f-string
# interpolation (``f"hi {out.id(name)}"``) ergonomic.
_active = threading.local()


def _active_theme() -> Theme:
    return getattr(_active, "theme", _NULL_THEME)


@dataclass(frozen=True)
class Span:
    """A colored run of text tagged with a role.

    Renders against the *active* theme via :meth:`__str__`, so f-string
    interpolation works without leaking ANSI past the span:

        out.info(f"Known ssh key: {out.id(name)}")
    """

    text: str
    role: str = "plain"

    def __str__(self) -> str:
        return _active_theme().render(self.role, str(self.text))


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

# Type accepted by emitters: a plain string, or a Span, or a sequence of either.
Renderable = Union[str, Span, Iterable[Union[str, Span]]]


def _stringify(parts: Renderable) -> str:
    """Coerce a Renderable to a single string. Spans render via their
    ``__str__`` against the active theme."""
    if isinstance(parts, (str, Span)):
        return str(parts)
    return "".join(str(p) for p in parts)


def _split_doc_inline(text: str) -> list[tuple[str, str]]:
    parts: list[tuple[str, str]] = []
    pos = 0
    for match in _DOC_INLINE_MARKUP_RE.finditer(text):
        if match.start() > pos:
            parts.append((text[pos : match.start()], "text"))
        if match.group(1) is not None:
            parts.append((match.group(1), "code"))
        else:
            parts.append((match.group(2), "emph"))
        pos = match.end()
    if pos < len(text):
        parts.append((text[pos:], "text"))
    return parts or [("", "text")]


def _strip_doc_inline(text: str) -> str:
    return "".join(chunk for chunk, _kind in _split_doc_inline(text))


def _visible_width(text: str) -> int:
    # Prompt glyphs are individual characters; wide emoji occupy two cells.
    return sum(0 if combining(ch) else 2 if east_asian_width(ch) in ("W", "F") else 1 for ch in strip_ansi(text))


@dataclass(frozen=True)
class Output:
    """Console output and optional diagnostic log (one per process).

    ``Output.build()`` is the one true constructor for normal use; it
    parses theme/color/policy arguments and installs the active theme on
    the thread-local that :class:`Span` reads from. ``Output.silent()``
    returns a no-op sink for probes that must not emit anything.
    """

    quiet: bool = False
    debug_on: bool = False
    eval_mode: bool = False
    json: bool = False
    animate: bool = True
    theme: str = DEFAULT_THEME
    # Active Theme. Internal; call sites use role helpers / emitters.
    _theme: Theme = field(default=_NULL_THEME, repr=False)
    # When True, every emitter (including warn/error) is a no-op.
    # Used by :meth:`silent` for state probes; not user-tunable.
    _silent: bool = field(default=False, repr=False)
    _log: DebugLog | None = field(default=None, repr=False, compare=False)

    # ---- construction --------------------------------------------------

    @classmethod
    def build(
        cls,
        quiet: bool,
        debug: bool,
        eval_mode: bool,
        color: bool,
        theme: str | None = None,
        json: bool = False,
        color_stream: TextIO | None = None,
        debug_log: str | None = None,
        animate: bool = True,
    ) -> Output:
        # Theme is set exclusively via --theme CLI flag; no env var override.
        chosen = resolve_theme_name(theme)
        if color:
            try:
                stream = color_stream if color_stream is not None else sys.stderr
                color = bool(os.isatty(stream.fileno()))
            except (OSError, ValueError):
                color = False
        # JSON mode is silent on stderr -- the only useful output is the JSON
        # document on stdout. Force quiet so banners/notes don't pollute logs.
        if json:
            quiet = True
            color = False
        if color:
            active = THEMES[chosen]
            # Modern theme uses unicode glyphs; fall back to ASCII when stderr
            # can't render them so legacy/ascii consoles still align cleanly.
            if active.glyphs is _GLYPHS_MODERN and not stderr_supports_unicode():
                active = Theme(active.name, active.palette, active.roles, _GLYPHS_ASCII)
        else:
            active = _NULL_THEME
        # Install the active theme for Span.__str__ to read. There is one
        # active output per process (set at startup); the thread-local is
        # an implementation detail of role-helper interpolation.
        _active.theme = active
        return cls(
            quiet=quiet,
            debug_on=debug,
            eval_mode=eval_mode,
            json=json,
            animate=animate,
            theme=chosen,
            _theme=active,
            _log=DebugLog(debug_log) if debug_log else None,
        )

    @property
    def debug_enabled(self) -> bool:
        return self.debug_on or self._log is not None

    def close(self) -> None:
        if self._log is not None:
            self._log.close()

    def _record(self, level: str, msg: Renderable) -> None:
        if not self._silent and self._log is not None:
            self._log.write(level, _stringify(msg))

    @classmethod
    def silent(cls) -> Output:
        """Return a no-op :class:`Output`. Every emitter discards.

        Replaces the ``_NullOut(Output)`` smell from earlier revisions of
        :mod:`keychain.state`: state probes that need an ``Output``
        argument but mustn't print anything pass ``Output.silent()``.
        """
        return cls(
            quiet=True,
            json=False,
            theme=DEFAULT_THEME,
            _theme=_NULL_THEME,
            _silent=True,
        )

    # ---- glyph accessor ------------------------------------------------
    def glyph(self, role: str) -> str:
        """Return *role*'s glyph wrapped in its theme color (or bare)."""
        g = self._theme.glyphs.get(role, "*")
        col = _GLYPH_COLOR.get(role, "")
        if col and self._theme.palette.get(col):
            return f"{self._theme.palette[col]}{g}{self._theme.reset}"
        return g

    # ---- role helpers (Span constructors) -----------------------------
    def id(self, s: object) -> Span:
        """Identifier highlight: hostnames, key paths, user names, PIDs."""
        return Span(str(s), "identifier")

    def path(self, p: object) -> Span:
        """Filesystem path in prose."""
        return Span(str(p), "path")

    def value(self, s: object) -> Span:
        """Newly-set / 'good' value; loaded keys; sockets."""
        return Span(str(s), "value")

    def flag(self, s: object) -> Span:
        """CLI flag (e.g. ``--quick``) embedded in prose."""
        return Span(str(s), "flag")

    def warn_text(self, s: object) -> Span:
        """Inline warning word inside a sentence."""
        return Span(str(s), "warn")

    def err_text(self, s: object) -> Span:
        """Inline error word inside a sentence."""
        return Span(str(s), "err")

    def dim(self, s: object) -> Span:
        """Parenthetical aside, ``(none)``, placeholder text."""
        return Span(str(s), "dim")

    def head(self, s: object) -> Span:
        """Section / panel title fragment (use :meth:`heading` for full lines)."""
        return Span(str(s), "heading")

    def note_text(self, s: object) -> Span:
        """Inline emphasis (purple)."""
        return Span(str(s), "note")

    def kbd(self, s: object) -> Span:
        """Shell snippet in prose."""
        return Span(str(s), "kbd")

    def underlined_heading(self, s: object) -> Span:
        """Bold cyan + underline for action/option/config/section headings."""
        return Span(str(s), "underlined_heading")

    def style(self, *roles: str) -> str:
        """Return the concatenated ANSI prefix for one or more roles.

        Used by structural helpers (``tables.render_table``'s
        ``header_style``) that need a raw prefix string rather than a
        wrapped span. Reset is the renderer's job.
        """
        return "".join(self._theme.roles.get(r, "") for r in roles)

    def format_doc(self, text: str) -> str:
        """Render the minimal inline doc markup used by embedded help text.

        Supported today:
        - `code`
        - *emphasis*

        When color is disabled the markup is stripped but the text remains.
        """
        if not text:
            return ""
        if not self._theme.palette.get("OFF"):
            return _strip_doc_inline(text)

        text_on = self._theme.roles.get("doc_text", "")
        code_on = self._theme.roles.get("doc_code", "")
        emph_on = self._theme.roles.get("doc_emph", "")
        off = self._theme.reset
        out: list[str] = []
        for chunk, kind in _split_doc_inline(text):
            if kind == "code":
                out.append(f"{code_on}{chunk}{off}")
            elif kind == "emph":
                out.append(f"{emph_on}{chunk}{off}")
            else:
                out.append(f"{text_on}{chunk}{off}" if text_on else chunk)
        return "".join(out)

    def wrap_doc(self, text: str, width: int, *, prefix: str = "", continuation: str = "") -> list[str]:
        """Wrap minimal inline-markup text while preserving rendered styling.

        Width calculations are based on the plain-text form so wrapped output
        stays stable whether color is enabled or not.
        """
        lines: list[str] = []
        line = prefix
        line_len = len(prefix)
        line_has_text = bool(prefix)
        pending_space = ""

        for chunk, kind in _split_doc_inline(text):
            for token in re.findall(r"\s+|\S+", chunk):
                if token.isspace():
                    pending_space = " "
                    continue
                spacer = pending_space if line_has_text and pending_space else ""
                added_len = len(spacer) + len(token)
                if line_has_text and line_len + added_len > width:
                    lines.append(line.rstrip())
                    line = continuation
                    line_len = len(continuation)
                    line_has_text = bool(continuation)
                    spacer = ""
                if spacer:
                    line += spacer
                    line_len += len(spacer)
                if kind == "text":
                    line += token
                else:
                    line += (
                        self.format_doc(token if kind != "emph" else f"*{token}*")
                        if kind == "emph"
                        else self.format_doc(f"`{token}`")
                    )
                line_len += len(token)
                line_has_text = True
                pending_space = ""

        if line:
            lines.append(line.rstrip())
        return lines

    # ---- emitters ------------------------------------------------------

    def write(self, msg: str = "") -> None:
        """Stdout payload (machine-consumed: shell-eval, ``env``, JSON).

        Never suppressed by quiet/json -- this is protocol output.
        """
        try:
            sys.stdout.write(msg)
        except UnicodeEncodeError:
            # Fallback for terminals that can't encode unicode (e.g., Windows cp1252).
            # Replace unencodable characters with '?' to avoid crashing.
            sys.stdout.write(msg.encode(sys.stdout.encoding, errors="replace").decode(sys.stdout.encoding))

    def line(self, msg: Renderable = "") -> None:
        """Plain stderr line. Suppressed by quiet / json."""
        self._record("info", msg)
        if self._silent or self.quiet:
            return
        print(_stringify(msg), file=sys.stderr)

    def result(self, msg: Renderable = "") -> None:
        """Explicit command result on stderr. Never suppressed by quiet."""
        self._record("result", msg)
        if not self._silent:
            print(_stringify(msg), file=sys.stderr)

    def activation_prompt_frames(self, message: str, *, animate: bool) -> tuple[str, ...]:
        prefix = f" {self.glyph('prompt')} "
        lead = "Press Enter"
        body = f"{lead} {message}"
        final = f"{prefix}{self.warn_text(lead)} {message} "
        if not self.animate or not animate or not self._theme.roles["dim"] or not self._can_use_ephemeral_line(final):
            return (final,)
        frames = []
        for step in range(13):
            end = len(body) * step // 12
            yellow = str(self.warn_text(body[: min(end, len(lead))])) if end else ""
            plain = body[len(lead) : end]
            grey = str(self.dim(body[end:])) if end < len(body) else ""
            frames.append(f"{prefix}{yellow}{plain}{grey} ")
        return tuple(frames)

    def ephemeral_line(self, msg: Renderable, *, redraw: bool = False) -> bool:
        """Render a clearable stderr line for interactive prompts.

        Returns ``True`` when the line can be cleared without wrapping.
        Redraw replaces the previous frame without recording it again.
        When terminal control is unsafe, prints a static line and returns False.
        """
        if self._silent:
            return False
        text = _stringify(msg)
        if not self._can_use_ephemeral_line(text):
            self.result(text)
            return False
        if not redraw:
            self._record("prompt", text)
        # Recolor fixed-width text without erasing echoed input or moving its cursor.
        sys.stderr.write(f"\x1b7\r{text}\x1b8" if redraw else f"\r\x1b[2K{text}")
        sys.stderr.flush()
        return True

    def clear_ephemeral_line(self, *, after_input: bool = False) -> None:
        """Clear the last :meth:`ephemeral_line` prompt when terminal-safe."""
        if self._silent or not self._terminal_control_enabled():
            return
        prefix = "\x1b[1A" if after_input else ""
        sys.stderr.write(f"{prefix}\r\x1b[2K")
        sys.stderr.flush()

    def info(self, msg: Renderable) -> None:
        """Informational message (▸). Suppressed by quiet / json."""
        self._record("info", msg)
        if self._silent or self.quiet:
            return
        print(f" {self.glyph('info')} {_stringify(msg)}", file=sys.stderr)

    def warn(self, msg: Renderable) -> None:
        """Inline warning. Suppressed by json (and by silent())."""
        self._record("warning", msg)
        if self._silent or self.json:
            return
        prefix = self._theme.palette.get("YEL", "")
        off = self._theme.palette.get("OFF", "")
        print(f" {self.glyph('warn')} {prefix}Warning{off}: {_stringify(msg)}", file=sys.stderr)

    def note(self, msg: Renderable) -> None:
        """Notice (›). Suppressed by quiet / json."""
        self._record("note", msg)
        if self._silent or self.quiet:
            return
        prefix = self._theme.palette.get("PURP", "")
        off = self._theme.palette.get("OFF", "")
        print(f" {self.glyph('note')} {prefix}Note{off}: {_stringify(msg)}", file=sys.stderr)

    def error(self, msg: Renderable) -> None:
        """Inline error. Suppressed by json (and by silent())."""
        self._record("error", msg)
        if self._silent or self.json:
            return
        prefix = self._theme.palette.get("RED", "")
        off = self._theme.palette.get("OFF", "")
        print(f" {self.glyph('err')} {prefix}Error{off}: {_stringify(msg)}", file=sys.stderr)

    def debug(self, msg: Renderable) -> None:
        """Debug trace. Suppressed unless ``debug_on`` and not json."""
        self._record("debug", msg)
        if self._silent or self.json or not self.debug_on:
            return
        prefix = self._theme.palette.get("DIM", "")
        off = self._theme.palette.get("OFF", "")
        print(f" {self.glyph('debug')} {prefix}{_stringify(msg)}{off}", file=sys.stderr)

    def heading(self, title: Renderable) -> None:
        """Section heading: ``▌ Title`` (cyan bar + cyan label)."""
        if self._silent:
            return
        self.result()
        self.result(f" {self.glyph('bar')} {Span(_stringify(title), 'heading')}")

    def banner(self, body: Renderable) -> None:
        """Single ``▌ body`` line (used by the version banner)."""
        if self._silent or self.quiet:
            return
        self.line(f" {self.glyph('bar')} {_stringify(body)}")

    def _can_use_ephemeral_line(self, text: str) -> bool:
        if not self._terminal_control_enabled():
            return False
        columns = self.terminal_size().columns
        return _visible_width(text) < max(1, columns - 4)

    def terminal_size(self) -> os.terminal_size:
        try:
            return os.get_terminal_size(sys.stderr.fileno())
        except (OSError, ValueError):
            return os.terminal_size((0, 0))

    def _terminal_control_enabled(self) -> bool:
        if self.json:
            return False
        term = (os.environ.get("TERM") or "").lower()
        if not term or term == "dumb":
            return False
        try:
            import termios
        except ImportError:
            return False
        try:
            fd = sys.stderr.fileno()
            if not os.isatty(fd):
                return False
            flags = termios.tcgetattr(fd)[3]
            return flags & (termios.ICANON | termios.ECHO) == (termios.ICANON | termios.ECHO)
        except (termios.error, OSError, ValueError):
            return False


class ActivationPrompt:
    """One prompt display; timing and terminal redraws never drive coordination."""

    def __init__(self, out: Output, message: str, *, animate: bool):
        self.out = out
        self.frames = out.activation_prompt_frames(message, animate=animate)
        self.size = out.terminal_size()
        self.started = time.monotonic()
        self.frame = 0
        self.clearable = out.ephemeral_line(self.frames[0])

    def delay(self) -> float | None:
        if not self.clearable or self.frame == len(self.frames) - 1:
            return None
        return max(0.0, self.started + (self.frame + 1) * 0.04 - time.monotonic())

    def redraw(self) -> None:
        if self.out.terminal_size() != self.size:
            # A wrapped old prompt cannot be safely erased. Leave it in scrollback.
            if not self.out._silent:
                print(f"\n{self.frames[-1]}", file=sys.stderr, flush=True)
            self.clearable = False
            return
        self.frame = min(len(self.frames) - 1, int((time.monotonic() - self.started) / 0.04))
        self.clearable = self.out.ephemeral_line(self.frames[self.frame], redraw=True)

    def clear(self, *, after_input: bool = False) -> None:
        if self.clearable and self.out.terminal_size() == self.size:
            self.out.clear_ephemeral_line(after_input=after_input)
