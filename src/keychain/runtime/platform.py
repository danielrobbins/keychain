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

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

from ..util import KeychainError, write_atomic


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
    confirm_requires_own_agent = False

    def configure_ssh_confirmation(self, env: dict[str, str], keydir: Path) -> None:
        """Prepare a new agent's confirmation environment; normally no changes."""

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

    def process_details_unavailable(self, pid: int) -> bool:
        """Whether a live PID's identity is inaccessible, not merely absent from a scan."""
        return False

    def __repr__(self):  # pragma: no cover - debugging aid
        return f"<Platform {self.name} supported={self.supported}>"


class _PsPlatform(Platform):
    """Shared ps execution and validation; subclasses own dialect differences."""

    # Separate -o arguments also work on Solaris, where text after '=' is a header.
    ps_command: tuple[str, ...] = ("ps", "-A", "-o", "pid=", "-o", "uid=", "-o", "comm=")
    ps_header: tuple[str, ...] = ()
    requires_ps = True

    def __init__(self, name: str) -> None:
        self.name = name

    def _parse_record(self, line: str) -> list[str]:
        return line.split(None, 2)

    def process_list(self, pattern: re.Pattern, uid: int | None = None) -> list[int]:
        pids: list[int] = []
        try:
            proc = subprocess.Popen(
                list(self.ps_command),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                # Cygwin/MSYS ps truncates command names to COLUMNS even in a pipe.
                env={**{key: value for key, value in os.environ.items() if key != "COLUMNS"}, "LC_ALL": "C"},
            )
            stdout, stderr = proc.communicate()
        except OSError as exc:
            raise KeychainError(f"Process discovery failed: cannot run ps: {exc}") from exc
        if proc.returncode:
            detail = stderr.decode(errors="replace").strip() or "no error output"
            raise KeychainError(f"Process discovery failed: ps exited with status {proc.returncode}: {detail}")
        records = 0
        for number, line in enumerate(stdout.decode(errors="replace").splitlines(), 1):
            if not line.strip():
                continue
            if number == 1 and self.ps_header and tuple(line.split()) == self.ps_header:
                continue
            parts = self._parse_record(line)
            if len(parts) != 3 or not all(re.fullmatch(r"[0-9]+", value) for value in parts[:2]):
                raise KeychainError(f"Process discovery failed: ps returned an invalid record at line {number}")
            pid, proc_uid = int(parts[0]), int(parts[1])
            records += 1
            if uid is not None and proc_uid != uid:
                continue
            if pattern.search(parts[2].strip()):
                pids.append(pid)
        if not records:
            raise KeychainError("Process discovery failed: ps returned no process records")
        return pids


class _BSDPlatform(_PsPlatform):
    # BSD ps supports unlimited width; System V ps does not share this option.
    ps_command = ("ps", "-ww", "-A", "-o", "pid=", "-o", "uid=", "-o", "comm=")


class _DarwinPlatform(_BSDPlatform):
    # A pre-existing inherited agent cannot acquire our askpass environment.
    confirm_requires_own_agent = True
    _ASKPASS = """\
#!/bin/sh
[ "${SSH_ASKPASS_PROMPT-}" = "confirm" ] || exit 1
exec /usr/bin/osascript - "$1" <<'APPLESCRIPT'
on run argv
    try
        set answer to display dialog (item 1 of argv) with title "Keychain SSH Confirmation" buttons {"Deny", "Allow"} default button "Deny" cancel button "Deny"
        if button returned of answer is "Allow" then return "yes"
    on error number -128
    end try
    error number 1
end run
APPLESCRIPT
"""

    def configure_ssh_confirmation(self, env: dict[str, str], keydir: Path) -> None:
        if not env.get("SSH_ASKPASS"):
            path = keydir / "ssh-askpass-macos"
            try:
                installed = path.read_text(encoding="utf-8") == self._ASKPASS and stat.S_IMODE(path.stat().st_mode) == 0o700
            except OSError:
                installed = False
            if not installed:
                write_atomic(path, self._ASKPASS, 0o700)
            env["SSH_ASKPASS"] = str(path)
        env["SSH_ASKPASS_REQUIRE"] = "force"


class _SolarisPlatform(_PsPlatform):
    # comm comes from bounded argv text. fname avoids path truncation;
    # a 16-character header widens its default eight-character field.
    ps_command = ("ps", "-A", "-o", "pid=", "-o", "uid=", "-o", "fname=KEYCHAIN_COMMAND")
    ps_header = ("KEYCHAIN_COMMAND",)


class _CygwinPlatform(_PsPlatform):
    """Cygwin and MSYS use their own fixed-column ps format."""

    ps_command = ("ps", "-e", "-l")
    ps_header = ("PID", "PPID", "PGID", "WINPID", "TTY", "UID", "STIME", "COMMAND")

    def _parse_record(self, line: str) -> list[str]:
        # The status prefix and eight-character STIME may contain spaces.
        match = re.match(r"^[ SIO] +([0-9]+)\s+[0-9]+\s+[0-9]+\s+[0-9]+\s+\S+\s+([0-9]+) .{8} (.+)$", line)
        return list(match.groups()) if match else []


class _LinuxPlatform(_PsPlatform):
    """Linux and Android prefer /proc, with ps as a fallback when unavailable."""

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.requires_ps = not os.path.isdir("/proc/self")

    def process_details_unavailable(self, pid: int) -> bool:
        if pid <= 0 or self.requires_ps:
            return False
        try:
            with open(f"/proc/{pid}/comm", encoding="utf-8", errors="replace") as handle:
                handle.read(1)
        except (FileNotFoundError, PermissionError):
            # hidepid can return ENOENT for a live, non-dumpable ssh-agent.
            # Check liveness after the read, so an exit during it is not "hidden".
            try:
                os.kill(pid, 0)
            except (OSError, OverflowError):
                return False
            return True
        except OSError:
            pass
        return False

    def process_list(self, pattern: re.Pattern, uid: int | None = None) -> list[int]:
        if self.requires_ps:
            return super().process_list(pattern, uid)
        pids: list[int] = []
        for entry in os.listdir("/proc"):
            try:
                if not entry.isdigit() or (uid is not None and os.stat(f"/proc/{entry}").st_uid != uid):
                    continue
                with open(f"/proc/{entry}/comm", encoding="utf-8", errors="replace") as handle:
                    if not pattern.search(handle.read().strip()):
                        continue
                with open(f"/proc/{entry}/stat", encoding="utf-8", errors="replace") as handle:
                    # Skip zombie/dead tasks; the parenthesized name can contain ')'.
                    # An empty read means the task vanished mid-scan.
                    fields = handle.read().rpartition(")")[2].split()
                    if fields and fields[0] not in ("Z", "X", "x"):
                        pids.append(int(entry))
            except OSError:
                continue  # exited mid-scan, or process details are restricted
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
    When ``None`` (the default), :func:`_probe_ps` is called once if /proc
    discovery is unavailable.
    """
    p = platform_name.lower()

    # Native Windows is unsupported regardless of ps.
    if p == "win32":
        return _UnsupportedPlatform("windows", _UNSUPPORTED_WINDOWS_REASON)

    implementation: type[_PsPlatform] = _PsPlatform
    for prefixes, candidate in (
        (("linux", "android"), _LinuxPlatform),
        (("darwin",), _DarwinPlatform),
        (("freebsd", "openbsd", "netbsd", "dragonfly"), _BSDPlatform),
        (("sunos",), _SolarisPlatform),
        (("cygwin", "msys"), _CygwinPlatform),
    ):
        if p.startswith(prefixes):
            implementation = candidate
            break
    platform = implementation(p)
    if not platform.requires_ps:
        return platform
    if has_ps is None:
        has_ps = _probe_ps()

    is_known_posix = implementation is not _PsPlatform or p.startswith(("aix", "haiku", "gnu"))

    if is_known_posix:
        if has_ps:
            return platform
        return _UnsupportedPlatform(
            p,
            "ps(1) was not found in PATH on this {} system. "
            "Ensure procps (Linux) or the system ps is installed "
            "and on PATH.".format(p),
        )

    # Unknown platform: use ps if available; refuse with a clear message otherwise.
    if has_ps:
        return platform
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
