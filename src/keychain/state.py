# SPDX-License-Identifier: GPL-3.0-only
"""One-shot snapshot of every state probe keychain performs.

A :class:`KeychainState` is built once per process by :mod:`keychain.main`
(after :class:`keychain.paths.KeychainPaths` is constructed) and replaces
the scattered free-function calls that previously re-checked the same
state at each use site.

Every probe is wrapped behind a property that delegates to the existing
free function in :mod:`keychain.agents`, :mod:`keychain.paths`,
:mod:`keychain.runtime`, :mod:`keychain.util` or :mod:`keychain.keys`.
Results are memoised in ``self._cache`` so the runtime path and the
``keychain inspect`` action share work.
"""

from __future__ import annotations

import os
import platform as py_platform
import shutil
import socket
import sys
from collections.abc import Mapping
from functools import cached_property
from typing import Any

from . import agents, keys
from .env import SshAgentRef
from .output.core import Output
from .paths import KeychainPaths, SecurityCheck
from .runtime.platform import Platform
from .runtime.platform import detect as detect_platform
from .util import (
    KeychainError,
    current_user,
    pid_alive,
    run,
)

# Environment variables that influence (and are propagated by) ssh-agent.
_INHERITED_KEYS = ("SSH_AUTH_SOCK", "SSH_AGENT_PID")


def _resolve_host(args: Any, env: Mapping[str, str]) -> tuple[str, str]:
    """Return ``(hostname, source)`` honoring ``--host`` > ``socket.gethostname()`` > ``$HOSTNAME``.

    *source* is one of ``"--host"``, ``"socket.gethostname()"``, ``"$HOSTNAME"``,
    or ``"fallback"`` and is surfaced in ``keychain inspect``'s Host panel
    so users can see *why* they got the keydir they got (which surfaces
    bash's flaky $HOSTNAME export, container hostname inheritance, etc.).
    """
    h = args.get_value("host")
    if h:
        return h, "--host"
    try:
        n = socket.gethostname()
        if n:
            return n, "socket.gethostname()"
    except OSError:
        pass
    h = env.get("HOSTNAME") or ""
    if h:
        return h, "$HOSTNAME"
    return "unknown", "fallback"


def _command_first_line(cmd: list[str]) -> str:
    try:
        r = run(cmd)
    except (FileNotFoundError, OSError):
        return ""
    for line in (r.stdout + "\n" + r.stderr).splitlines():
        if line.strip():
            return line.strip()
    return ""


class KeychainState:
    """Lazy, memoised view of every probe keychain performs.

    Construction is cheap; nothing is probed until a property is read.
    Each cached property does the work exactly once.
    """

    def __init__(
        self,
        paths: KeychainPaths,
        env: Mapping[str, str] | None = None,
        cmdline_keys: list[str] | None = None,
        extended: bool = False,
        confallhosts: bool = False,
        hostname_source: str = "explicit",
        user: str | None = None,
        args: Any = None,
    ) -> None:
        self.paths = paths
        self.env = dict(os.environ if env is None else env)
        self.cmdline_keys = list(cmdline_keys or [])
        self.extended = extended
        self.confallhosts = confallhosts
        self.hostname_source = hostname_source
        self.user = user or current_user()
        # ``args`` is the fully-resolved ParsedArgs; the agent classes use
        # it to read run-flag options (timeout, confirm, nogui, ...) without
        # threading every flag through their constructors. Tests that build
        # KeychainState directly (without args) rely on agent methods only
        # via `getattr(args, X, default)` reads inside SshAgent / GpgAgent.
        self.args = args
        self.out: Output | None = None  # set by build(); needed by ssh/gpg

    # ---- one-call builder used by the CLI -----------------------------

    @classmethod
    def build(cls, args: Any, out: Output | None = None) -> KeychainState:
        """Resolve host + paths + perms in one call.

        Uses ``args.env`` (assembled by ``ParsedArgs.apply_config()``) as the
        effective process environment.  This is the single entry point used by
        the CLI; tests that exercise state probes directly should construct
        :class:`KeychainState` with an explicit ``env=`` instead.
        """
        env_map = dict(args.env)
        host, source = _resolve_host(args, env_map)
        paths = KeychainPaths.build(
            dir_opt=args.get_value("dir"),
            absolute=bool(args.get_value("absolute")),
            host=host,
            pid_formats=args.get_value("pid_formats"),
        )
        me = current_user()
        if not me:
            raise KeychainError("Who are you? Can't determine username.")
        k = cls(
            paths=paths,
            env=env_map,
            cmdline_keys=list(args.get_value("keys") or []),
            extended=bool(args.get_value("extended")),
            confallhosts=bool(args.get_value("confallhosts")),
            hostname_source=source,
            user=me,
            args=args,
        )
        k.out = out
        paths.check_runtime_perms(me)
        return k

    # ---- hostname (resolved by ``build``; reflected back for inspect) -

    @property
    def hostname(self) -> str:
        return self.paths.host

    @cached_property
    def runtime_info(self) -> dict[str, str]:
        from . import __version__

        return {
            "keychain_version": __version__,
            "keychain_executable": os.path.abspath(sys.argv[0]),
            "python_version": sys.version.split()[0],
            "python_executable": sys.executable,
            "system": py_platform.platform(),
            "machine": py_platform.machine(),
        }

    @property
    def config_diagnostics(self) -> dict[str, Any]:
        return self.args.diagnostics() if self.args is not None else {}

    # ---- agent façades (lazy; require out, which build() supplies) ----

    @cached_property
    def ssh(self) -> agents.SshAgent:
        if self.out is None:
            raise RuntimeError("KeychainState.ssh requires build() with out=")
        return agents.SshAgent(self, self.out)

    @cached_property
    def gpg(self) -> agents.GpgAgent:
        if self.out is None:
            raise RuntimeError("KeychainState.gpg requires build() with out=")
        return agents.GpgAgent(self, self.out)

    # ---- platform ------------------------------------------------------

    @cached_property
    def platform(self) -> Platform:
        return detect_platform()

    # ---- ssh / gpg implementation detection ---------------------------

    @cached_property
    def openssh(self) -> bool:
        return agents.detect_ssh()

    @property
    def ssh_implementation(self) -> str:
        if self.openssh:
            return "OpenSSH"
        return "(unknown)"

    @cached_property
    def ssh_version(self) -> str:
        return _command_first_line(["ssh", "-V"])

    @cached_property
    def ssh_path(self) -> str:
        return shutil.which("ssh") or ""

    @cached_property
    def gpg_has_ssh_support(self) -> bool:
        return agents.gpg_has_ssh_support()

    @cached_property
    def gpg_prog(self) -> str:
        return agents.choose_gpg_prog(bool(self.args.get_value("gpg2")) if self.args is not None else False)

    @cached_property
    def gpg_version(self) -> str:
        return _command_first_line([self.gpg_prog, "--version"])

    @cached_property
    def gpg_path(self) -> str:
        return shutil.which(self.gpg_prog) or ""

    @cached_property
    def gpg_ssh_socket(self) -> str:
        return agents.gpg_ssh_socket(self.env)

    @cached_property
    def gpg_main_socket(self) -> str:
        return agents.gpg_main_socket(self.env)

    # ---- running agent processes --------------------------------------

    @property
    def process_listing_supported(self) -> bool:
        return self.platform.supported

    @cached_property
    def ssh_agent_pids(self) -> list[int]:
        if not self.process_listing_supported:
            return []
        return agents.findpids("ssh")

    @cached_property
    def gpg_agent_pids(self) -> list[int]:
        if not self.process_listing_supported:
            return []
        return agents.findpids("gpg")

    @property
    def gpg_primary_socket_is_ours(self) -> bool:
        """True if the gpg-agent socket reported by ``GETINFO socket_name``
        lives under one of the user's gpg homedirs (``$GNUPGHOME``,
        ``$HOME/.gnupg`` or ``/run/user/<uid>/gnupg``). When False, any
        running gpg-agents owned by us were started by a third party
        (typically a package manager via ``--homedir /var/tmp/…``) and
        must not be adopted as a keychain agent.
        """
        sock = self.gpg_main_socket
        return bool(sock) and agents.gpg_socket_is_primary(sock, self.env)

    @property
    def gpg_foreign_agents_present(self) -> bool:
        """True when there is at least one gpg-agent we wouldn't adopt.

        Two scenarios trigger this:

        * The primary socket isn't ours -- every running gpg-agent is
          foreign (package-manager / sandbox).
        * The primary socket is ours, but there are *extra* gpg-agent
          pids besides the one backing it. gpg-agent is single-instance
          per homedir, so any extras necessarily live under a different
          ``--homedir`` and are foreign.
        """
        pids = self.gpg_agent_pids
        if not pids:
            return False
        if not self.gpg_primary_socket_is_ours:
            return True
        return len(pids) > 1

    # ---- pidfile ------------------------------------------------------
    # NOTE: These properties are specific to the "canonical" pidfile at
    # ~/.keychain/<host>-sh, which is used as the source of truth for the
    # running agent we adopt.

    @property
    def pidfile_path(self):
        return self.paths.pidfile_path("sh")

    @property
    def pidfile_exists(self) -> bool:
        return self.pidfile_path.is_file()

    @property
    def pidfile_content(self) -> str:
        try:
            return self.pidfile_path.read_text(encoding="utf-8")
        except OSError:
            return ""

    @property
    def pidfile_env(self) -> SshAgentRef:
        return SshAgentRef.from_text(self.pidfile_content)

    @property
    def pidfile_socket(self) -> str:
        return self.pidfile_env.sock

    @property
    def pidfile_pid(self) -> str:
        return self.pidfile_env.display_pid

    @property
    def pidfile_socket_valid(self) -> bool:
        return self.pidfile_socket_validation.valid

    @property
    def pidfile_socket_validation(self) -> agents.SocketValidation:
        return agents.validate_ssh_socket(self.pidfile_socket)

    @property
    def pidfile_pid_alive(self) -> bool:
        pid = self.pidfile_pid
        if not pid:
            return False
        pid_int = self.pidfile_env.pid_int
        return bool(pid_int and pid_alive(pid_int))

    # ---- inherited shell environment ----------------------------------

    @property
    def inherited_env(self) -> SshAgentRef:
        return SshAgentRef.from_env({k: self.env[k] for k in _INHERITED_KEYS if self.env.get(k)})

    @property
    def inherited_socket(self) -> str:
        return self.inherited_env.sock

    @property
    def inherited_pid(self) -> str:
        return self.inherited_env.display_pid

    @property
    def inherited_socket_valid(self) -> bool:
        return self.inherited_socket_validation.valid

    @property
    def inherited_socket_validation(self) -> agents.SocketValidation:
        return agents.validate_ssh_socket(self.inherited_socket)

    @property
    def inherited_pid_alive(self) -> bool:
        pid = self.inherited_pid
        if not pid:
            return False
        pid_int = self.inherited_env.pid_int
        return bool(pid_int and pid_alive(pid_int))

    # ---- agent contents (loaded keys) ---------------------------------

    @property
    def find_active_agent_env(self) -> SshAgentRef:
        """The single source of truth for which SSH agent keychain should talk to right now.

        It performs a prioritized fallback: it first uses the agent tracked in
        Keychain's own pidfile if alive (the managed agent), then falls back to
        an inherited agent from the invoking shell if valid (e.g. from X11 forwarding).
        If neither is reachable, it returns an empty environment to signal a new
        agent needs to be spawned.
        """
        if self.pidfile_socket_valid:
            return self.pidfile_env
        if self.inherited_socket_valid:
            return self.inherited_env
        return SshAgentRef()

    @property
    def has_reachable_agent(self) -> bool:
        """True if a live ssh-agent socket is reachable (pidfile or inherited)."""
        return bool(self.find_active_agent_env)

    @cached_property
    def loaded_ssh_fingerprints(self) -> list[str]:
        env = self.find_active_agent_env
        if not env:
            return []
        fps, _ = agents.ssh_l(env.as_dict())
        return fps

    # ---- keychain dir ------------------------------------------------

    @property
    def keydir_exists(self) -> bool:
        return self.paths.keydir.is_dir()

    @property
    def keydir_writable(self) -> bool:
        return self.keydir_exists and os.access(str(self.paths.keydir), os.W_OK)

    # ---- security audit ----------------------------------------------

    @property
    def security_audit(self) -> list[SecurityCheck]:
        socket_path = self.pidfile_socket if self.pidfile_socket_valid else ""
        return self.paths.security_audit(self.user, socket_path)

    # ---- key resolution (reflects user's --extended / cmdline) -------

    @cached_property
    def resolved_keys(self) -> keys.ResolvedKeys:
        """Resolved SSH/GPG/missing keys for the user's args."""
        if not (self.cmdline_keys or self.confallhosts):
            return keys.ResolvedKeys([], [], [], [], [], [], [])
        return self.resolve_requested_keys(Output.silent())

    def resolve_requested_keys(self, out: Output, *, gpg_lookup: bool = True) -> keys.ResolvedKeys:
        if not (self.cmdline_keys or self.confallhosts):
            return keys.ResolvedKeys([], [], [], [], [], [], [])
        gpg_prog = self.gpg_prog if gpg_lookup else "gpg"
        return keys.resolve_requested_keys(
            self.confallhosts, self.extended, self.cmdline_keys, gpg_prog, out, gpg_lookup=gpg_lookup
        )

    @property
    def ssh_keys(self) -> list[str]:
        return list(self.resolved_keys.ssh)

    @property
    def gpg_keys(self) -> list[str]:
        return list(self.resolved_keys.gpg)

    @property
    def pkcs11_keys(self) -> list[str]:
        return list(self.resolved_keys.pkcs11)

    @property
    def missing_keys(self) -> list[str]:
        return list(self.resolved_keys.missing)
