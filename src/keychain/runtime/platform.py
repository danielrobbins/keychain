# SPDX-License-Identifier: GPL-3.0-only
"""Runtime environment detection.

Keychain manages POSIX agents (``ssh-agent``, ``gpg-agent``) and assumes a
POSIX-shaped userland (``ps``, ``kill``, UNIX-domain sockets, shell-style
environment files). Rather than scattering ``sys.platform`` checks across
process listing, signal installation and pidfile handling, we resolve the
host environment **once** at startup and let the rest of the codebase ask
a single :class:`Platform` for what it needs (or refuse to run).

The detected platform is cached for the life of the process; tests that
need to override it can call :func:`reset` and then :func:`detect` with a
``platform_override`` argument.
"""

from __future__ import annotations

import re
import shutil
import subprocess


class Platform:
    """Resolved host environment.

    A :class:`Platform` is the single point of truth for everything the
    rest of the codebase needs to know about the host: its short name,
    the reason it can't run keychain (empty when supported), and *how*
    to enumerate processes (:meth:`process_list`). Subclasses encapsulate
    the strategy; callers never branch on platform identifiers.
    """

    name = "unknown"
    reason = ""

    @property
    def supported(self) -> bool:
        """``True`` when keychain can manage agents on this host."""
        return not self.reason

    def process_list(self, pattern: re.Pattern, uid: int | None = None) -> list[int]:
        """Return PIDs whose command name matches *pattern*.

        When *uid* is given, only processes owned by that UID are
        returned. Unsupported platforms raise :class:`RuntimeError`;
        in practice the CLI aborts before any caller reaches this.
        """
        raise RuntimeError(
            "process listing not available on {}: {}".format(self.name, self.reason or "unsupported platform")
        )

    def __repr__(self):  # pragma: no cover - debugging aid
        return f"<Platform {self.name} supported={self.supported}>"


class _PosixPlatform(Platform):
    """POSIX-shaped userland: enumerate processes via ``ps``."""

    def __init__(self, name: str) -> None:
        self.name = name

    def process_list(self, pattern: re.Pattern, uid: int | None = None) -> list[int]:
        pids: list[int] = []
        try:
            proc = subprocess.Popen(
                # illumos/Solaris treats everything after '=' in one -o
                # argument as header text, including commas. Separate -o
                # options preserve all three columns across POSIX hosts.
                ["ps", "-A", "-o", "pid=", "-o", "uid=", "-o", "comm="],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            stdout, _ = proc.communicate()
        except OSError:
            return pids
        for line in stdout.decode(errors="replace").splitlines():
            parts = line.split(None, 2)
            if len(parts) < 3:
                continue
            try:
                pid, proc_uid = int(parts[0]), int(parts[1])
            except ValueError:
                continue
            if uid is not None and proc_uid != uid:
                continue
            if pattern.search(parts[2].strip()):
                pids.append(pid)
        return pids


class _UnsupportedPlatform(Platform):
    """Recognised platform on which keychain refuses to operate."""

    def __init__(self, name: str, reason: str) -> None:
        self.name = name
        self.reason = reason


_UNSUPPORTED_WINDOWS_REASON = (
    "Native Windows is not a supported keychain target: there is no "
    "ssh-agent process to manage in the POSIX sense, no UNIX-domain "
    "socket layer, and the shell-eval contract assumes a POSIX shell. "
    "Run keychain inside WSL, Cygwin or MSYS instead."
)


def _probe_ps() -> bool:
    """Return True if ``ps`` is findable in PATH."""
    return shutil.which("ps") is not None


def _classify(platform_name: str, has_ps: bool | None = None) -> Platform:
    """Classify *platform_name* into a concrete :class:`Platform`.

    *has_ps* controls whether ``ps`` is considered available; pass it
    explicitly in tests to avoid probing the host's actual PATH.
    When ``None`` (the default), :func:`_probe_ps` is called once.
    """
    if has_ps is None:
        has_ps = _probe_ps()

    p = platform_name.lower()

    # Native Windows is unsupported regardless of ps.
    if p == "win32":
        return _UnsupportedPlatform("windows", _UNSUPPORTED_WINDOWS_REASON)

    is_known_posix = (
        p.startswith(("linux", "darwin", "freebsd", "openbsd", "netbsd", "dragonfly", "sunos", "aix", "haiku", "gnu"))
        or p == "cygwin"
        or p.startswith("msys")
    )

    if is_known_posix:
        if has_ps:
            return _PosixPlatform(p)
        return _UnsupportedPlatform(
            p,
            "ps(1) was not found in PATH on this {} system. "
            "Ensure procps (Linux) or the system ps is installed "
            "and on PATH.".format(p),
        )

    # Unknown platform: use ps if available; refuse with a clear message otherwise.
    if has_ps:
        return _PosixPlatform(p)
    return _UnsupportedPlatform(
        p,
        "Unrecognized platform '{}' and ps(1) is not in PATH. "
        "Keychain requires a POSIX-compatible userland with ps(1).".format(p),
    )


_cached: Platform | None = None


def detect(platform_override: str | None = None, has_ps: bool | None = None) -> Platform:
    """Return the cached :class:`Platform` for this process.

    The first call performs detection (using ``sys.platform`` unless
    *platform_override* is given) and caches the result. Subsequent calls
    return the same instance. Tests can call :func:`reset` to clear the
    cache between runs.

    *has_ps* is forwarded to :func:`_classify`; pass it in tests to
    decouple detection from the host's actual PATH.
    """
    global _cached
    if _cached is None:
        import sys

        _cached = _classify(platform_override or sys.platform, has_ps)
    return _cached


def reset() -> None:
    """Clear the cached detection. Intended for tests."""
    global _cached
    _cached = None
