# SPDX-License-Identifier: GPL-3.0-only
"""Shared utilities: exceptions, output, locking, small POSIX helpers.

Targets Python 3.9+ (RHEL 8 users opt in via ``dnf module install python39``).
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
import os
import secrets
import socket
import stat
import subprocess
import sys
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Union, cast

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

try:
    import pwd as _pwd_impl  # POSIX
except ImportError:  # Windows / Git Bash on native Python
    _pwd: Any | None = None
else:
    _pwd = _pwd_impl


PathLike = Union[str, "os.PathLike[str]"]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class KeychainError(Exception):
    """Raised for user-visible fatal errors. Caught once in :func:`cli.main`."""


# ---------------------------------------------------------------------------
# Output / colors / themes -- moved to keychain.output. Re-exported here so
# ``from keychain.util import Output`` keeps working through the deprecation
# window. New code should import from ``keychain.output`` directly.
# ---------------------------------------------------------------------------

from .output.core import (  # noqa: E402,F401  (re-export for back-compat)
    DEFAULT_THEME,
    THEMES,
    Output,
    Span,
    stderr_supports_unicode,
)


# Back-compat: docs/render.py imports ``resolve_theme`` and uses the
# legacy-palette dict shape (``{'CYANN': '...', 'OFF': '...'}``). The new
# :class:`~keychain.output.Theme` exposes that as ``Theme.palette``.
def resolve_theme(name):  # type: ignore[no-untyped-def]
    """Return the legacy palette dict for *name*; fall back to default."""
    if name:
        key = name.strip().lower()
        if key in THEMES:
            return dict(THEMES[key].palette)
    return dict(THEMES[DEFAULT_THEME].palette)


# ---------------------------------------------------------------------------
# Subprocess wrapper
# ---------------------------------------------------------------------------


def run(
    cmd: list[str],
    env: dict[str, str] | None = None,
    input_: str | None = None,
    timeout: float | None = None,
    c_locale: bool = True,
) -> subprocess.CompletedProcess:
    """Run ``cmd``, capturing text output. Returns ``CompletedProcess``.

    ``c_locale=True`` forces ``LC_ALL=C`` for the child only, so the caller's
    locale is never mutated. Raises :class:`FileNotFoundError` if the binary
    is missing -- callers decide how to react.
    """
    run_env = {**os.environ, **(env or {})} | ({"LC_ALL": "C"} if c_locale else {})
    return subprocess.run(
        cmd,
        input=input_,
        env=run_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


# ---------------------------------------------------------------------------
# Lockfile
# ---------------------------------------------------------------------------


class LockFile:
    """OS-backed advisory file lock. Use as a context manager.

    ``no_lock=True`` makes the manager a no-op (still safe to use). The acquired
    state is exposed via :attr:`acquired` and the lock is released on exit.
    """

    __slots__ = ("path", "no_lock", "wait", "out", "acquired", "_fd", "_token")

    def __init__(self, path: PathLike, no_lock: bool, wait: int, out: Output) -> None:
        self.path = Path(path)
        self.no_lock = no_lock
        self.wait = max(0, int(wait))
        self.out = out
        self.acquired = False
        self._fd = -1
        self._token = f"{socket.gethostname()}:{os.getpid()}:{secrets.token_hex(8)}"

    # ---- context manager ----------------------------------------------
    def __enter__(self) -> LockFile:
        if self.try_acquire():
            return self
        if self.wait == 0:
            raise KeychainError(f"could not acquire lock {self.path}")
        self.out.info(f"Waiting {self.wait} seconds for lock...")
        deadline = time.monotonic() + self.wait
        while time.monotonic() < deadline:
            if self.try_acquire():
                return self
            time.sleep(0.1)
        if not self.try_acquire():
            raise KeychainError(f"could not acquire lock {self.path}")
        return self

    def __exit__(self, exc_type, exc, tb):
        self.release()
        return False

    # ---- internals -----------------------------------------------------
    def try_acquire(self) -> bool:
        if self.no_lock:
            self.acquired = True
            return True
        if self.acquired:
            return True
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(self.path), flags, 0o600)
        try:
            if not self._try_lock(fd):
                os.close(fd)
                return False
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            os.ftruncate(fd, 0)
            os.write(fd, self._token.encode())
        except Exception:
            os.close(fd)
            raise
        self._fd = fd
        self.acquired = True
        return True

    @staticmethod
    def _try_lock(fd: int) -> bool:
        try:
            if sys.platform == "win32":
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"\0")
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                return False
            raise
        return True

    def release(self) -> None:
        if not self.acquired:
            return
        if not self.no_lock:
            try:
                with contextlib.suppress(OSError):
                    if sys.platform == "win32":
                        os.lseek(self._fd, 0, os.SEEK_SET)
                        msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                with contextlib.suppress(OSError):
                    os.close(self._fd)
                self._fd = -1
        self.acquired = False


# ---------------------------------------------------------------------------
# Small POSIX helpers
# ---------------------------------------------------------------------------


def pid_alive(pid: int) -> bool:
    """Best-effort process liveness probe."""
    if pid <= 0:
        return False
    if os.name == "nt":
        kernel32 = cast(Any, ctypes).windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            exit_code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return False
            return exit_code.value == 259
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def get_owner(path: PathLike) -> str:
    """Return the username that owns *path*, or '' on error / non-POSIX."""
    if _pwd is None:
        return ""
    try:
        return _pwd.getpwuid(os.stat(path).st_uid).pw_name
    except (OSError, KeyError):
        return ""


def current_uid() -> int | None:
    """Numeric user ID for the current process, if available."""
    return os.getuid() if hasattr(os, "getuid") else None


def current_user() -> str:
    """Best-effort username for the current process."""
    uid = current_uid()
    if _pwd is not None and uid is not None:
        try:
            return _pwd.getpwuid(uid).pw_name
        except (KeyError, OSError):
            pass
    return os.environ.get("USER") or os.environ.get("LOGNAME") or os.environ.get("USERNAME") or ""


def get_tty() -> str:
    """Controlling tty device (POSIX only) or ''."""
    if not hasattr(os, "ttyname"):
        return ""
    try:
        return os.ttyname(sys.stdin.fileno())
    except OSError:
        return ""


def lax_perms(path: PathLike) -> bool:
    """True if *path* is group/world readable, writable or executable."""
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return False
    return bool(mode & (stat.S_IRWXG | stat.S_IRWXO))


def lax_perm_warning(keydir: PathLike) -> str:
    """Canonical warning text for a keychain dir / pidfile with lax perms.

    Single source of truth for both the runtime add-path warnings
    (:meth:`keychain.paths.KeychainPaths.ensure_keydir` /
    :meth:`check_runtime_perms`) and the ``inspect`` action's post-panel
    audit warnings, so the wording can't drift between code paths.
    """
    return f"Keychain dir has lax permissions. Use chmod -R go-rwx '{keydir}' to fix."


def unlink_quiet(*paths: PathLike) -> None:
    for p in paths:
        with contextlib.suppress(OSError):
            os.unlink(p)


def dedupe_sorted(items: Iterable[str]) -> list[str]:
    """Deterministic deduplication: insertion-order de-dup, then sorted."""
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        if it and it not in seen:
            seen.add(it)
            out.append(it)
    out.sort()
    return out
