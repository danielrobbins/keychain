# SPDX-License-Identifier: GPL-3.0-only
"""Agent environment values.

:class:`SshAgentRef` is a small frozen record that captures the two environment
variables an *ssh-agent* process publishes when it starts::

    SSH_AUTH_SOCK=/run/user/1000/keychain/h/agent.sock
    SSH_AGENT_PID=12345

Keychain reads these from three sources, each handled by a separate factory:

* **pidfile** (``~/.keychain/<host>/<host>-sh``) — use :meth:`SshAgentRef.from_text`,
  which parses the sh-syntax lines.
* **inherited shell environment** — use :meth:`SshAgentRef.from_env`, which reads
  the two keys directly from an env dict (e.g. the process's ``os.environ``).
* **spawning a new agent** — the agent subprocess writes its own pidfile;
  the caller re-parses it with :meth:`SshAgentRef.from_text`.

Once constructed, :meth:`SshAgentRef.overlay` produces a copy of a base
environment with the agent variables set correctly, ready to pass to
subprocesses or to emit as shell eval output.
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Mapping
from dataclasses import dataclass

_ENV_KEYS = ("SSH_AUTH_SOCK", "SSH_AGENT_PID")


@dataclass(frozen=True)
class SshAgentRef:
    """Immutable snapshot of a running ssh-agent's identity.

    An agent is identified by the UNIX-domain socket it listens on
    (``SSH_AUTH_SOCK``) and, optionally, its PID (``SSH_AGENT_PID``).
    A forwarded agent (``SSH_AGENT_PID=forwarded``) has no usable PID;
    :attr:`forwarded` is set to ``True`` in that case and :attr:`pid` is
    stored as ``""``.

    An empty :class:`SshAgentRef` (all defaults) is falsy; any instance with
    a socket path is truthy.  This lets callers use it in a boolean context
    to test whether a reachable agent was found.
    """

    sock: str = ""
    pid: str = ""
    forwarded: bool = False

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> SshAgentRef:
        """Build an :class:`SshAgentRef` from a dict-like environment mapping.

        Typically called with the slice of ``os.environ`` that contains the
        two agent keys, or with the dict returned by :meth:`as_dict`.
        """
        pid = env.get("SSH_AGENT_PID", "")
        return cls(env.get("SSH_AUTH_SOCK", ""), "" if pid == "forwarded" else pid, pid == "forwarded")

    @classmethod
    def from_text(cls, text: str) -> SshAgentRef:
        """Parse the sh-syntax lines in a keychain pidfile.

        Handles the ``VAR=value; export VAR`` form. Quoted values are stripped.
        Lines starting with ``echo `` are skipped (keychain emits those for
        the ``--eval`` output path but they carry no new data).
        """
        values: dict[str, str] = {}
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("echo "):
                continue
            for part in line.split(";"):
                try:
                    words = shlex.split(part)
                except ValueError:
                    continue
                key, sep, value = (words[0] if len(words) == 1 else "").partition("=")
                if sep and key in _ENV_KEYS:
                    values[key] = value
        return cls.from_env(values)

    @property
    def display_pid(self) -> str:
        return "forwarded" if self.forwarded else self.pid

    @property
    def pid_int(self) -> int | None:
        if not self.pid:
            return None
        try:
            return int(self.pid)
        except ValueError:
            return None

    def with_sock(self, sock: str) -> SshAgentRef:
        return SshAgentRef(sock, self.pid, self.forwarded)

    def as_dict(self) -> dict[str, str]:
        """Return only the agent keys that are set, as a plain dict.

        Suitable for passing to :func:`subprocess.run` via ``env=`` after
        merging with the full process environment.
        """
        env: dict[str, str] = {}
        if self.sock:
            env["SSH_AUTH_SOCK"] = self.sock
        if self.pid:
            env["SSH_AGENT_PID"] = self.pid
        return env

    def overlay(self, base: Mapping[str, str] | None = None) -> dict[str, str]:
        """Return *base* with the agent variables replaced by this instance's values.

        Clears any pre-existing ``SSH_AUTH_SOCK`` / ``SSH_AGENT_PID`` from
        *base* before injecting, so stale inherited values can never
        accidentally survive.  Defaults to ``os.environ`` when *base* is
        ``None``.
        """
        env = dict(os.environ if base is None else base)
        for key in _ENV_KEYS:
            env.pop(key, None)
        env.update(self.as_dict())
        return env

    def __bool__(self) -> bool:
        return bool(self.sock)
