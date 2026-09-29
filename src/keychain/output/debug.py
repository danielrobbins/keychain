# SPDX-License-Identifier: GPL-3.0-only
"""Private, append-only diagnostic records; never captures terminal input."""

from __future__ import annotations

import os
import re
import stat
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

from ..util import KeychainError, get_tty


class DebugLog:
    def __init__(self, path: str) -> None:
        self.path = Path(path).expanduser()
        self._lock = threading.Lock()
        self._fd = -1
        self._context = f"pid={os.getpid()} tty={get_tty() or 'none'}"
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            fd = os.open(self.path, flags, 0o600)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise OSError("must be a regular file with no hard links")
                if hasattr(os, "getuid") and info.st_uid != os.getuid():
                    raise OSError("must be owned by the current user")
                if hasattr(os, "fchmod"):
                    os.fchmod(fd, 0o600)
            except BaseException:
                os.close(fd)
                raise
            self._fd = fd
        except OSError as exc:
            raise KeychainError(f"Cannot open debug log {self.path}: {exc}") from exc

    def write(self, level: str, text: str) -> None:
        # Remove escape sequences, then escape remaining controls to keep each
        # event on one physical line without allowing forged record prefixes.
        text = re.sub(r"\x1b(?:\][^\x07\x1b]*(?:\x07|\x1b\\)|\[[0-?]*[ -/]*[@-~])", "", text)
        text = "".join(c if c.isprintable() else repr(c)[1:-1] for c in text)
        stamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        record = f"{stamp} {self._context} {level}: {text}\n".encode()
        with self._lock:
            if self._fd < 0:
                return
            try:
                if os.write(self._fd, record) != len(record):
                    raise OSError("incomplete write")
            except OSError as exc:
                os.close(self._fd)
                self._fd = -1
                print(f"Warning: Cannot write debug log {self.path}: {exc}", file=sys.stderr)

    def close(self) -> None:
        with self._lock:
            if self._fd >= 0:
                os.close(self._fd)
                self._fd = -1
