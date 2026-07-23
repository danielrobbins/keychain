# SPDX-License-Identifier: GPL-3.0-only
"""Path & pidfile bundle for one (keydir, host) pair."""

from __future__ import annotations

import base64
import hashlib
import os
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from .env import SshAgentRef
from .util import (
    KeychainError,
    Output,
    get_owner,
    lax_perm_warning,
    lax_perms,
    unlink_quiet,
)

# macOS has the smallest common sockaddr_un.sun_path limit: 104 bytes,
# including the terminating null byte.
_MAX_UNIX_SOCKET_PATH_BYTES = 103


@dataclass(frozen=True)
class Pidfile:
    """A lightweight abstraction for a specific pidfile sequence."""

    suffix: ClassVar[str] = ""
    path: Path
    ext: str

    def render(self, env: SshAgentRef) -> str:
        """Subclasses override this."""
        return ""

    def write(self, env: SshAgentRef) -> None:
        """Write the pidfile atomically via temp file + rename."""
        fd, tmp_name = tempfile.mkstemp(prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent, text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(self.render(env))
            Path(tmp_name).replace(self.path)
        except Exception:
            unlink_quiet(tmp_name)
            raise


class ShPidfile(Pidfile):
    suffix = "-sh"

    def render(self, env: SshAgentRef) -> str:
        parts = []
        if env.sock:
            parts.append(f'SSH_AUTH_SOCK="{env.sock}"; export SSH_AUTH_SOCK')
        if env.pid:
            parts.append(f"SSH_AGENT_PID={env.pid}; export SSH_AGENT_PID;")
        return ("\n".join(parts) + "\n") if parts else ""


class CshPidfile(Pidfile):
    suffix = "-csh"

    def render(self, env: SshAgentRef) -> str:
        parts = []
        if env.sock:
            parts.append(f'setenv SSH_AUTH_SOCK "{env.sock}";')
        if env.pid:
            parts.append(f"setenv SSH_AGENT_PID {env.pid};")
        return ("\n".join(parts) + "\n") if parts else ""


class FishPidfile(Pidfile):
    suffix = "-fish"

    def render(self, env: SshAgentRef) -> str:
        parts = []
        if env.sock:
            parts.append(f'set -e SSH_AUTH_SOCK; set -x -U SSH_AUTH_SOCK "{env.sock}";')
        if env.pid:
            parts.append(f"set -e SSH_AGENT_PID; set -x -U SSH_AGENT_PID {env.pid};")
        return ("\n".join(parts) + "\n") if parts else ""


class EnvfilePidfile(Pidfile):
    suffix = "-envfile"

    def render(self, env: SshAgentRef) -> str:
        parts = []
        if env.sock:
            parts.append(f"SSH_AUTH_SOCK={env.sock}")
        if env.pid:
            parts.append(f"SSH_AGENT_PID={env.pid}")
        return ("\n".join(parts) + "\n") if parts else ""


class JsonPidfile(Pidfile):
    suffix = "-json"

    def render(self, env: SshAgentRef) -> str:
        import json

        return json.dumps({"SSH_AUTH_SOCK": env.sock, "SSH_AGENT_PID": env.pid}) + "\n"


_PID_FACTORIES = {
    "sh": ShPidfile,
    "csh": CshPidfile,
    "fish": FishPidfile,
    "envfile": EnvfilePidfile,
    "json": JsonPidfile,
}


def resolve_pidfile_class(shell_name: str) -> type[Pidfile]:
    """Resolve a fuzzy shell name to the correct Pidfile subclass."""
    pf = _PID_FACTORIES.get(shell_name)
    if pf:
        return pf
    if "fish" in shell_name:
        return FishPidfile
    if "csh" in shell_name:
        return CshPidfile
    if shell_name in ("env", "systemd"):
        return EnvfilePidfile
    return ShPidfile


@dataclass(frozen=True)
class KeychainPaths:
    """All on-disk artefacts for a single keychain (keydir, host) pair."""

    keydir: Path
    host: str
    pid_formats: tuple[str, ...] = ("sh", "csh", "fish", "envfile")

    # ---- construction --------------------------------------------------
    @classmethod
    def build(cls, dir_opt: str | None, absolute: bool, host: str, pid_formats: str | None = None) -> KeychainPaths:
        """Resolve the keychain directory from ``--dir`` / ``--absolute`` and *host*.

        The keydir is determined as follows:

        * No ``--dir``: use ``~/.keychain``.
        * ``--dir PATH`` with ``--absolute``, or where *PATH* contains ``/.``
        (e.g. ``/tmp/.keychain``): use *PATH* verbatim (after ``~``
        expansion) — the caller is overriding the conventional layout.
        * ``--dir PATH`` otherwise: append ``.keychain`` to the expanded
        path, preserving the 2.x convention that ``--dir /tmp`` stored
        files under ``/tmp/.keychain``.
        """
        if dir_opt:
            expanded = _expand_home(dir_opt)
            # Preserve historic behaviour: a path containing "/." is taken verbatim,
            # likewise --absolute. Otherwise we append ".keychain".
            if absolute or "/." in dir_opt or dir_opt.startswith("/."):
                base = expanded
            else:
                base = expanded / ".keychain"
        else:
            base = Path.home() / ".keychain"

        formats = tuple(fmt.strip() for fmt in (pid_formats or "sh,csh,fish,envfile").split(",") if fmt.strip())
        if "sh" not in formats:
            formats = ("sh",) + formats

        return cls(keydir=base, host=host, pid_formats=formats)

    # ---- pidfile paths -------------------------------------------------
    def pidfile_path(self, fmt: str) -> Path:
        """Construct the full path to a pidfile for a given format and host, AttributeError if no such pidfile"""
        pidf_cls = _PID_FACTORIES.get(fmt)
        if pidf_cls is None:
            raise AttributeError(f"unknown pidfile format: {fmt}")
        return self.keydir / f"{self.host}{pidf_cls.suffix}"

    @property
    def all_pidfiles(self) -> tuple[Path, ...]:
        """All supported process cache files for this host"""
        return tuple(self.keydir / f"{self.host}{pf_cls.suffix}" for pf_cls in _PID_FACTORIES.values())

    @property
    def lockf(self):
        return self.keydir / f"{self.host}-lockf"

    @property
    def state_file(self) -> Path:
        return self.keydir / f"{self.host}.state.json"

    @property
    def state_lockf(self) -> Path:
        return self.keydir / f"{self.host}.state.lock"

    @property
    def activation_lockf(self) -> Path:
        return self.keydir / f"{self.host}.activation.lock"

    @property
    def waiters_dir(self) -> Path:
        return self.keydir / f"{self.host}-waiters"

    @property
    def ssh_agent_socket_path(self) -> Path:
        host_digest = hashlib.sha256(os.fsencode(self.host)).digest()[:6]
        socket_name = base64.urlsafe_b64encode(host_digest).decode()
        path = self.keydir / f"{socket_name}.s"
        if os.name != "nt" and len(os.fsencode(path)) > _MAX_UNIX_SOCKET_PATH_BYTES:
            raise KeychainError(
                f"Keychain directory is too long for an ssh-agent socket: {self.keydir}"
            )
        return path

    def render_env(
        self, env: SshAgentRef | Mapping[str, str], shell: str = "env", shell_env: Mapping[str, str] | None = None
    ) -> str:
        """Render *env* in one of keychain's documented output formats."""
        agent_env = env if isinstance(env, SshAgentRef) else SshAgentRef.from_env(env)
        shell = shell or "env"
        if shell == "eval":
            shell = os.path.basename((shell_env or os.environ).get("SHELL", "sh")) or "sh"

        pidf_cls = resolve_pidfile_class(shell)
        return pidf_cls(Path(), shell).render(agent_env)

    def clear(self) -> None:
        """Remove all runtime files for this keychain."""
        unlink_quiet(*self.all_pidfiles, self.ssh_agent_socket_path)

    def write(self, agent_env: SshAgentRef, out: Output) -> None:
        """Write shell-specific pidfiles from the canonical agent env."""
        if not agent_env:
            out.debug("skipping creation of pidfiles!")
            return

        unlink_quiet(*self.all_pidfiles)

        for fmt in self.pid_formats:
            pidf_cls = _PID_FACTORIES.get(fmt)
            if pidf_cls:
                pidf_cls(self.keydir / f"{self.host}-{fmt}", fmt).write(agent_env)

    # ---- directory verification ---------------------------------------
    def verify_keydir(self, me: str, out: Output) -> None:
        if self.keydir.is_file():
            raise KeychainError(f"{self.keydir} is a file (it should be a directory)")
        if not self.keydir.is_dir():
            try:
                self.keydir.mkdir(mode=0o700, parents=True)
            except OSError as e:
                raise KeychainError(f"can't create {self.keydir}: {e}")

        owner = get_owner(self.keydir)
        if owner and owner != me:
            raise KeychainError(
                f"{self.keydir} is owned by {owner}, not {me}. " "Remove or chown the directory and re-run keychain."
            )
        if owner and lax_perms(self.keydir):
            raise KeychainError(lax_perm_warning(self.keydir))

        # Probe write permission inside keydir.
        probe = self.pidfile_path("sh").with_suffix(f"{self.pidfile_path('sh').suffix}.probe")
        try:
            probe.touch()
        except OSError:
            raise KeychainError(f"can't write inside {self.keydir}")
        unlink_quiet(probe)

    def check_pidfile_perms(self, me: str, out: Output) -> None:
        """Verify pidfile ownership and hard-fail on lax permissions.

        Pidfile contents are ``eval``'d by the user's shell (via
        ``keychain --eval``). A pidfile owned by another user is therefore
        an arbitrary-code-execution vector and is treated as a hard error.
        Group/world permissions on the pidfile or its directory make
        replacement attacks possible, so they are also treated as hard
        errors.
        """
        for p in self.all_pidfiles:
            if not p.is_file():
                continue
            owner = get_owner(p)
            if owner and owner != me:
                raise KeychainError(
                    "{} is owned by {}, not {}; refusing to use it. "
                    "Remove or chown the file and re-run keychain.".format(p, owner, me)
                )
            if owner and lax_perms(p):
                raise KeychainError(lax_perm_warning(self.keydir))


def _expand_home(path: str) -> Path:
    # Use standard Path.expanduser() which correctly parses ~ and ~user on all platforms.
    # It reads $HOME on POSIX if available before falling back to pwd.
    p = Path(path).expanduser()
    return p
