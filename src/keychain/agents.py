# SPDX-License-Identifier: GPL-3.0-only
"""ssh-agent and gpg-agent: detection, lifecycle, key listing and loading."""

from __future__ import annotations

import os
import re
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .env import SshAgentRef
from .util import KeychainError, Output, current_uid, get_tty, pid_alive, run, unlink_quiet

if TYPE_CHECKING:
    from .state import KeychainState


@dataclass(frozen=True)
class SshAddPlan:
    commands: list[list[str]]
    env: dict[str, str]


def _suppress_gui(env: dict[str, str]) -> None:
    for key in ("DISPLAY", "WAYLAND_DISPLAY", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE"):
        env.pop(key, None)


_MACOS_ASKPASS = """\
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


def ensure_macos_askpass(path: Path) -> Path:
    """Install Keychain's confirmation-only macOS askpass helper securely."""
    try:
        if path.read_text(encoding="utf-8") == _MACOS_ASKPASS and stat.S_IMODE(path.stat().st_mode) == 0o700:
            return path
    except OSError:
        pass

    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(_MACOS_ASKPASS)
        os.chmod(tmp_name, 0o700)
        Path(tmp_name).replace(path)
    except Exception:
        unlink_quiet(tmp_name)
        raise
    return path


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_RE_FP_SHA256 = re.compile(r"^[A-Z0-9]+:[A-Za-z0-9+/=]+$")
_RE_FP_MD5 = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2})+$")


@dataclass(frozen=True)
class SocketValidation:
    path: str
    valid: bool
    reason: str = ""
    severity: str = ""


# ---------------------------------------------------------------------------
# Implementation detection
# ---------------------------------------------------------------------------


def detect_ssh() -> bool:
    """Return True when ``ssh -V`` identifies OpenSSH."""
    try:
        r = run(["ssh", "-V"])
    except (FileNotFoundError, OSError):
        return False
    return "OpenSSH" in (r.stdout + r.stderr)


def gpg_has_ssh_support() -> bool:
    try:
        r = run(["gpg-agent", "--help"])
    except (FileNotFoundError, OSError):
        return False
    return "enable-ssh-support" in (r.stdout + r.stderr)


def choose_gpg_prog(force_gpg2: bool, env: Mapping[str, str] | None = None) -> str:
    """Decide which GnuPG binary to invoke."""
    env = os.environ if env is None else env
    bin_override = env.get("GPG_BIN")
    if bin_override:
        return bin_override
    return "gpg2" if force_gpg2 else "gpg"


# ---------------------------------------------------------------------------
# gpg-agent socket queries
# ---------------------------------------------------------------------------


def _gpg_query(name: str, env: Mapping[str, str] | None = None) -> str:
    try:
        r = run(
            ["gpg-connect-agent", "--no-autostart"],
            env=dict(env) if env is not None else None,
            input_=f"GETINFO {name}\n",
            timeout=5,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return ""
    for line in r.stdout.splitlines():
        if line.startswith("D "):
            return line[2:].strip()
    return ""


def gpg_ssh_socket(env: Mapping[str, str] | None = None) -> str:
    return _gpg_query("ssh_socket_name", env)


def gpg_main_socket(env: Mapping[str, str] | None = None) -> str:
    return _gpg_query("socket_name", env)


def gpg_user_homedirs(env: Mapping[str, str] | None = None, uid: int | None = None) -> list[Path]:
    """Directories whose ``S.gpg-agent`` we consider "ours".

    Includes ``$GNUPGHOME``, ``$HOME/.gnupg``, and the XDG-style
    ``/run/user/<uid>/gnupg`` (used by GnuPG 2.1+ on Linux). Anything
    outside this set -- e.g. a package-manager's ``--homedir /var/tmp/zypp.X``
    socket -- is treated as someone else's agent.
    """
    env = os.environ if env is None else env
    if uid is None:
        uid = current_uid()
    homes: list[Path] = []
    gh = env.get("GNUPGHOME")
    if gh:
        homes.append(Path(gh))
    home = env.get("HOME") or os.path.expanduser("~")
    if home:
        homes.append(Path(home) / ".gnupg")
    if uid is not None:
        homes.append(Path(f"/run/user/{uid}/gnupg"))
    # Resolve to absolute paths; ignore homedirs that don't currently exist
    # (Path.resolve(strict=False) is the default on 3.9+).
    return [h.resolve() for h in homes]


def gpg_socket_is_primary(sock: str, env: Mapping[str, str] | None = None, uid: int | None = None) -> bool:
    """True if *sock* lives under one of :func:`gpg_user_homedirs`.

    Used to refuse to adopt gpg-agents started by other tools (package
    managers, build sandboxes) that happen to be running as our uid.
    """
    if not sock:
        return False
    try:
        sock_dir = Path(sock).resolve().parent
    except (OSError, ValueError):
        return False
    return any(sock_dir == h for h in gpg_user_homedirs(env, uid))


def validate_ssh_socket(sock: str) -> SocketValidation:
    """Validate that *sock* is a UNIX socket owned by the current user.

    The owner check is the second line of defence after pidfile perms:
    if ``SSH_AUTH_SOCK`` was poisoned (compromised env, attacker-writable
    pidfile, ``/tmp`` race), we must not load keys into a foreign agent.
    On platforms without ``os.getuid`` (e.g. native Windows, where keychain
    refuses to operate anyway) the owner check is skipped.
    """
    if not sock:
        return SocketValidation(sock, False, "empty")
    try:
        if os.path.islink(sock):
            return SocketValidation(sock, False, "symlink", "err")
        st = os.stat(sock)
    except FileNotFoundError:
        return SocketValidation(sock, False, "missing")
    except OSError:
        return SocketValidation(sock, False, "stat-error", "warn")
    if not stat.S_ISSOCK(st.st_mode):
        return SocketValidation(sock, False, "not-socket", "warn")
    uid = current_uid()
    if uid is not None and st.st_uid != uid:
        return SocketValidation(sock, False, "foreign-owner", "err")
    return SocketValidation(sock, True)


def ssh_socket_valid(sock: str) -> bool:
    """True if *sock* is a UNIX socket owned by the current user."""
    return validate_ssh_socket(sock).valid


# ---------------------------------------------------------------------------
# Fingerprints
# ---------------------------------------------------------------------------


def extract_fingerprints(text: str) -> list[str]:
    fps: list[str] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and (_RE_FP_SHA256.match(parts[1]) or _RE_FP_MD5.match(parts[1])):
            fps.append(parts[1])
        elif len(parts) >= 3 and _RE_FP_MD5.match(parts[2]):
            fps.append(parts[2])
    return fps


def ssh_l(env: Mapping[str, str]) -> tuple[list[str], int]:
    """Run ``ssh-add -l``; return (fingerprints, retcode)."""
    try:
        r = run(["ssh-add", "-l"], env=dict(env))
    except (FileNotFoundError, OSError):
        return [], 2
    if r.returncode == 0:
        return extract_fingerprints(r.stdout.strip()), 0
    rc = 2 if (r.returncode == 1 and "open a connection" in r.stdout) else r.returncode
    return [], rc


def ssh_fingerprint(filename: str, out: Output) -> str | None:
    """Return the fingerprint of private key *filename*, or None on failure."""
    fp = Path(filename)
    resolved = fp.resolve() if fp.is_symlink() else fp
    pub = Path(f"{resolved!s}.pub")
    if not pub.is_file():
        alt = resolved.with_suffix(".pub")
        if alt.is_file():
            pub = alt
        else:
            out.note(f"Cannot find separate public key for {filename}.")
            pub = resolved
    try:
        r = run(["ssh-keygen", "-l", "-f", str(pub)])
    except (FileNotFoundError, OSError):
        return None
    if r.returncode != 0:
        return None
    fps = extract_fingerprints(r.stdout)
    return fps[0] if fps else None


def pkcs11_provider_fingerprints(provider: str, out: Output) -> list[str] | None:
    """Return SSH fingerprints exposed by a PKCS#11 provider, or None on failure."""
    try:
        r = run(["ssh-keygen", "-D", provider], c_locale=False)
    except (FileNotFoundError, OSError):
        return None
    if r.returncode != 0:
        return None

    public_keys = [line.strip() for line in r.stdout.splitlines() if line.strip()]
    if not public_keys:
        return []

    with tempfile.TemporaryDirectory(prefix="keychain-pkcs11-") as td:
        fps: list[str] = []
        for i, public_key in enumerate(public_keys):
            public_key_path = Path(td) / f"provider-{i}.pub"
            public_key_path.write_text(f"{public_key}\n", encoding="utf-8")
            fp = ssh_fingerprint(str(public_key_path), out)
            if fp:
                fps.append(fp)
    return fps


# ---------------------------------------------------------------------------
# Process scan (free function: heavily test-patched and platform-delegated)
# ---------------------------------------------------------------------------


def findpids(prog: str) -> list[int]:
    """PIDs of running ``prog``-agent processes owned by the current user.

    Process enumeration is delegated to the resolved
    :class:`keychain.runtime.Platform`, which knows how to list processes
    on the host (or refuses to do so on unsupported platforms — but the
    CLI aborts long before reaching this code path on those).
    """
    from .runtime import platform

    pattern = re.compile(rf"(?:^|[/\\]){re.escape(prog)}-agent$", re.IGNORECASE)
    uid = os.getuid() if hasattr(os, "getuid") else None
    return platform.detect().process_list(pattern, uid)


# ===========================================================================
# Agent classes -- the OOP face used by the CLI.
#
# Stateful agent operations live as methods that pull configuration
# (gpg_prog/paths/user/args) from the bound KeychainState. This eliminates
# the random ``(env, out)``-style argument tuples that used to thread through
# every helper.
#
# The free functions above remain free because they are *host-system*
# probes (not configuration-dependent): test suites mock them at the module
# boundary to simulate alternate hosts.
# ===========================================================================


class SshAgent:
    """ssh-agent operations bound to a :class:`~keychain.state.KeychainState`.

    ``self.env`` holds the live SSH_AUTH_SOCK / SSH_AGENT_PID pair that is
    read from the pidfile or inherited from the user's shell, mutated by
    :meth:`start`, and propagated to every child ``ssh-add`` invocation.
    """

    def __init__(self, state: KeychainState, out: Output) -> None:
        self.keychain_state = state
        self.out = out
        self.env: SshAgentRef = state.find_active_agent_env
        self._spawn_context = ""
        # Set by :meth:`start`; consumed by :meth:`envcheck` so per-call
        # plumbing of these flags is not needed.
        self._allow_gpg = False
        self._allow_forwarded = False

    # ---- list / fingerprint probes -----------------------------------

    def list_loaded(self) -> tuple[list[str], int]:
        """Run ``ssh-add -l``; return ``(fingerprints, retcode)``."""
        return ssh_l(self.env.as_dict())

    def fingerprint(self, filename: str) -> str | None:
        """Return the fingerprint of private key *filename*, or None on failure."""
        return ssh_fingerprint(filename, self.out)

    def list_missing(self, ssh_keys: list[str], *, announce_known: bool = True) -> list[str]:
        have_set = set(self.list_loaded()[0])
        missing: list[str] = []
        for k in filter(None, ssh_keys):
            fp = self.fingerprint(k)
            if fp is None:
                self.out.warn(f"Unable to extract fingerprint from keyfile {k}.pub, skipping")
                continue
            if fp in have_set:
                if announce_known:
                    self.out.info(f"Known ssh key: {self.out.id(k)}")
            else:
                missing.append(k)
        return missing

    def list_missing_pkcs11(self, providers: list[str], *, announce_known: bool = True) -> list[str]:
        have_set = set(self.list_loaded()[0])
        missing: list[str] = []
        for provider in filter(None, providers):
            fps = pkcs11_provider_fingerprints(provider, self.out)
            if fps and all(fp in have_set for fp in fps):
                if announce_known:
                    self.out.info(f"Known PKCS11 provider: {self.out.id(provider)}")
            else:
                missing.append(provider)
        return missing

    # ---- env validation ----------------------------------------------

    def envcheck(self, source: str, agent_env: SshAgentRef, quick: bool) -> SshAgentRef | None:
        """Validate ``SSH_AUTH_SOCK`` / ``SSH_AGENT_PID`` from *agent_env*."""
        out = self.out
        sock = agent_env.sock
        pid_str = agent_env.pid
        # When the source is an explicit pidfile or inherited shell environment the
        # user expects keychain to reuse that agent.  Silently falling through to
        # spawn a new one (because the socket has been rm'd or the process died)
        # is exactly the "why didn't keychain find my agent?" surprise we want to
        # avoid -- surface those rejections as notes.  Other sources (forwarded
        # sockets the user hasn't opted in to, gpg-agent's SSH socket) stay at
        # debug to avoid noise on every invocation.
        visible = source in ("pidfile", "env") and not quick

        sock_validation = validate_ssh_socket(sock)
        if not sock_validation.valid:
            if sock:
                msg = f"SSH_AUTH_SOCK in {source} points to {sock}; rejected socket ({sock_validation.reason})"
                if visible and sock_validation.severity:
                    out.warn(msg)
                else:
                    out.debug(msg)
                    if visible:
                        self._remember_spawn_context(source, sock_validation.reason)
            return None

        if pid_str:
            try:
                if not pid_alive(int(pid_str)):
                    raise ValueError
            except ValueError:
                msg = ("SSH_AGENT_PID in {} ({}) is not a live process; ignoring it").format(source, pid_str)
                out.debug(msg)
                if visible:
                    self._remember_spawn_context(source, "pid not running")
                pid_str = ""

        if not pid_str:
            # No PID -- might be gpg-agent's SSH socket or a forwarded socket.
            gsock = gpg_ssh_socket()
            if gsock and gsock == sock:
                if self._allow_gpg:
                    if not quick:
                        out.info(f"Using ssh-agent ({source}): {out.id(gsock)} (GnuPG)")
                    return SshAgentRef(sock)
                out.debug("Ignoring SSH_AUTH_SOCK -- this is the GnuPG-supplied socket")
                return None
            if self._allow_forwarded:
                if not quick:
                    out.info(f"Using {out.value('forwarded')} ssh-agent: {out.value(sock)}")
                return SshAgentRef(sock, forwarded=True)
            # No SSH_AGENT_PID, not GnuPG, and forwarding disallowed: could be a
            # forwarded socket, a stale socket from a dead session, or some other
            # unknown source. We can't tell which, so don't claim. (Issue #181.)
            out.debug(f"Ignoring SSH_AUTH_SOCK ({sock}) -- no SSH_AGENT_PID set, source unknown")
            return None

        if not quick:
            out.info(f"Existing ssh-agent ({source}): {out.id(pid_str)}")
        return SshAgentRef(sock, pid_str)

    def _remember_spawn_context(self, source: str, reason: str) -> None:
        display_reason = {"missing": "socket missing"}.get(reason, reason)
        if source == "pidfile":
            self._spawn_context = f"previous pidfile stale: {display_reason}"
        elif source == "env" and not self._spawn_context:
            self._spawn_context = f"inherited SSH_AUTH_SOCK stale: {display_reason}"

    # ---- lifecycle ---------------------------------------------------

    def _our_pid(self) -> int | None:
        return self.env.pid_int

    def start(self, ssh_spawn_gpg: bool, ssh_allow_gpg: bool) -> bool:
        """Find or spawn an ssh-agent.

        Returns True if a *quick* start succeeded (an existing agent was
        found already populated and no further key-loading is needed).
        Persists the resulting env to the pidfile when one was synthesised;
        updates ``self.env`` in place.
        """
        a = self.keychain_state.args
        self._spawn_context = ""
        # Latch run-flag flags so :meth:`envcheck` can pull them from self.
        self._allow_gpg = ssh_allow_gpg
        self._allow_forwarded = bool(a.get_value("ssh_allow_forwarded"))
        paths = self.keychain_state.paths

        if bool(a.get_value("confirm")) and bool(a.get_value("no_gui")):
            raise KeychainError("--confirm requires graphical confirmation and cannot be combined with --no-gui")

        # 1. Quick path: trust an existing pidfile if it is both valid AND
        # already has keys loaded -- saves a full key reload on repeat invocations.
        if bool(a.get_value("quick")):
            env = self.keychain_state.pidfile_env
            if env:
                test_env = self.envcheck("quick", env, quick=True)
                if test_env:
                    saved_env = self.env
                    self.env = test_env
                    fps, _ = self.list_loaded()
                    if fps:
                        self.out.info("Found existing populated ssh-agent (quick)")
                        return True
                    self.env = saved_env
                    self.out.note("Quick start unsuccessful -- no keys loaded...")
                else:
                    self.out.note("Quick start unsuccessful -- no agent found...")
            else:
                self.out.note("Quick start unsuccessful -- no agent found...")

        # 2. Normal path. Try existing pidfile.
        env = self.keychain_state.pidfile_env
        if env:
            test_env = self.envcheck("pidfile", env, quick=False)
            if test_env:
                self.out.debug("pidfile is valid")
                self.env = test_env
                return False

        # 3. Try inherited environment.
        if not bool(a.get_value("no_inherit")):
            inh = SshAgentRef.from_env(self.keychain_state.env)
            valid_inh = self.envcheck("env", inh, quick=False) if inh else None
            if valid_inh:
                self.env = valid_inh
                if not valid_inh.forwarded:
                    paths.write(valid_inh, self.out)
                    self.env = self.keychain_state.pidfile_env
                return False

        # 4. Spawn a new agent.
        paths.clear()
        spawned: SshAgentRef | None
        if ssh_spawn_gpg:
            spawned = self.keychain_state.gpg.start(ssh_support=True)
        else:
            context = f" ({self._spawn_context})" if self._spawn_context else ""
            self.out.info(f"Starting ssh-agent{context}...")
            cmd = ["ssh-agent", "-s"]
            timeout = a.get_value("timeout")
            if timeout is not None:
                cmd += ["-t", str(timeout * 60)]
            ssh_agent_socket = a.get_value("ssh_agent_socket")
            if ssh_agent_socket:
                cmd += ["-a", ssh_agent_socket]
            else:
                ssh_agent_socket = str(paths.ssh_agent_socket_path)
                unlink_quiet(ssh_agent_socket)
                cmd += ["-a", ssh_agent_socket]
            # User-supplied extra flags (issue #21).
            # SECURITY: KEYCHAIN_SSH_AGENT_ARGS is injected by config.py only
            # when --allow-env / -E is set. Direct env var access here is
            # safe because the gate is enforced at the config layer.
            cmd += shlex.split(self.keychain_state.env.get("KEYCHAIN_SSH_AGENT_ARGS", ""))
            spawn_env = dict(self.keychain_state.env)
            if bool(a.get_value("confirm")) and self.keychain_state.platform.name == "darwin":
                askpass = spawn_env.get("SSH_ASKPASS")
                if not askpass:
                    askpass = str(ensure_macos_askpass(paths.keydir / "ssh-askpass-macos"))
                    spawn_env["SSH_ASKPASS"] = askpass
                spawn_env["SSH_ASKPASS_REQUIRE"] = "force"
            try:
                r = run(cmd, env=spawn_env)
            except (FileNotFoundError, OSError) as exc:
                raise KeychainError(f"Unable to start ssh-agent: {exc}") from exc
            if r.returncode != 0:
                detail = (r.stderr or r.stdout).strip()
                if detail:
                    raise KeychainError(f"ssh-agent failed to start: {detail}")
                raise KeychainError(f"ssh-agent failed to start with exit status {r.returncode}")
            spawned = SshAgentRef.from_text(r.stdout)
            if not spawned:
                raise KeychainError("ssh-agent started but did not return its socket information")
        if spawned:
            paths.write(spawned, self.out)
            self.env = spawned
        return False

    def stop(self, which: str) -> None:
        out = self.out
        out.info("Stopping ssh-agent(s)...")
        if which != "all":
            pidf_env = self.keychain_state.pidfile_env
            if pidf_env:
                self.env = pidf_env
        pids = findpids("ssh")
        if not pids:
            out.info("No ssh-agent(s) found running")
        else:
            our = self._our_pid()
            ours = our if our in pids else None
            if which == "pidfile":
                targets = [ours] if ours else []
            elif which == "others":
                targets = [p for p in pids if p != ours]
            else:
                targets = pids
            killed: list[int] = []
            for pid in targets:
                try:
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    continue
                killed.append(pid)

            rendered = out.id(" ".join(map(str, killed)))
            if which == "all":
                out.info(f"All ssh-agents stopped: {rendered}")
            elif which == "mine":
                out.info(f"All {out.id(self.keychain_state.user)}'s ssh-agents stopped: {rendered}")
            elif which == "pidfile" and killed:
                out.info(f"Keychain ssh-agent stopped: {out.id(killed[0])}")
            elif which == "others":
                out.info(f"Other ssh-agents stopped: {rendered}")
            else:
                out.info("No keychain ssh-agent found running")
        if which != "others":
            self.keychain_state.paths.clear()

    # ---- key operations ----------------------------------------------

    def wipe(self) -> None:
        try:
            r = run(["ssh-add", "-D"], env=self.env.as_dict(), c_locale=False)
        except (FileNotFoundError, OSError):
            self.out.warn("ssh-add not found")
            return
        msg = (r.stdout + r.stderr).strip()
        (self.out.info if r.returncode == 0 else self.out.warn)(f"ssh-agent: {msg}")

    def remove(self, ssh_keys: list[str]) -> None:
        if not ssh_keys:
            raise KeychainError("No ssh keys specified to remove.")
        for k in ssh_keys:
            try:
                r = run(["ssh-add", "-d", k], env=self.env.as_dict(), c_locale=False)
            except (FileNotFoundError, OSError):
                raise KeychainError("ssh-add not found")
            if r.returncode == 0:
                self.out.info(f"ssh-agent key {k} removed.")
            else:
                raise KeychainError(f"keychain was unable to remove ssh-agent key {k}. output: {r.stderr}")

    def announce_load(self, missing: list[str], pkcs11: list[str] | None = None) -> None:
        pkcs11 = list(pkcs11 or [])
        if not missing and not pkcs11:
            return
        if missing:
            noun = "ssh key" if len(missing) == 1 else "ssh keys"
            self.out.info(f"Need to add {self.out.value(len(missing))} {noun}:")
            for key in missing:
                self.out.line(f"   - {self.out.value(key)}")
        if pkcs11:
            noun = "PKCS11 provider" if len(pkcs11) == 1 else "PKCS11 providers"
            self.out.info(f"Need to add {self.out.value(len(pkcs11))} {noun}:")
            for provider in pkcs11:
                self.out.line(f"   - {self.out.value(provider)}")

    def prepare_load(
        self, missing: list[str], pkcs11: list[str] | None = None, *, announce: bool = True
    ) -> SshAddPlan | None:
        pkcs11 = list(pkcs11 or [])
        if not missing and not pkcs11:
            return SshAddPlan([], {})
        a = self.keychain_state.args
        out = self.out
        # Re-validate the agent before loading keys to close the TOCTOU race
        # between start() validation and actual key loading.  If the agent
        # died or was replaced, refuse to load keys into a foreign agent.
        test = self.envcheck("pidfile", self.env, quick=True)
        if not test:
            out.warn("Agent disappeared; refusing to load keys")
            return None
        if announce:
            self.announce_load(missing, pkcs11)
        # ssh-add inherits stdio for passphrase prompts, so we cannot use util.run().
        run_env = self.env.overlay()
        askpass_allowed = bool(
            run_env.get("DISPLAY")
            or run_env.get("WAYLAND_DISPLAY")
            or run_env.get("SSH_ASKPASS_REQUIRE", "").lower() == "force"
        )
        if bool(a.get_value("no_gui")) or not askpass_allowed:
            _suppress_gui(run_env)
        base_cmd = ["ssh-add"]
        timeout = a.get_value("timeout")
        if timeout is not None:
            base_cmd += ["-t", str(timeout * 60)]
        if bool(a.get_value("confirm")):
            base_cmd.append("-c")
        commands: list[list[str]] = []
        if missing:
            commands.append([*base_cmd, *missing])
        for provider in pkcs11:
            commands.append([*base_cmd, "-s", provider])
        return SshAddPlan(commands, run_env)

    def load(self, missing: list[str]) -> bool:
        plan = self.prepare_load(missing)
        if plan is None:
            return False
        if not plan.commands:
            return True
        for cmd in plan.commands:
            try:
                rc = subprocess.run(cmd, env=plan.env, check=False).returncode
            except (FileNotFoundError, OSError):
                self.out.warn("ssh-add not found")
                return False
            if rc != 0:
                self.out.warn(f"ssh-add failed (return code: {rc})")
                return False
        return True

    def passthrough(self, arg: str) -> int:
        """Run ``ssh-add <arg>`` inheriting stdio (legacy theme `list` fallback)."""
        env = self.env.overlay()
        try:
            return subprocess.run(["ssh-add", arg], env=env, check=False).returncode
        except (FileNotFoundError, OSError):
            return 127


class GpgAgent:
    """gpg-agent operations bound to a :class:`~keychain.state.KeychainState`."""

    def __init__(self, k, out: Output) -> None:
        self.k = k
        self.out = out

    def _gpg_env(self, *, tty: bool = False) -> dict[str, str]:
        env = dict(self.k.env)
        if tty and (gpg_tty := get_tty()):
            env["GPG_TTY"] = gpg_tty
        if bool(self.k.args.get_value("no_gui")):
            _suppress_gui(env)
        return env

    def _run_gpg(
        self, args: list[str], *, env: dict[str, str] | None = None, input_: str = "", timeout: int | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.k.gpg_prog, *args],
            input=input_,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=self._gpg_env() if env is None else env,
            timeout=timeout,
            check=False,
        )

    # ---- lifecycle ---------------------------------------------------

    def start(self, ssh_support: bool) -> SshAgentRef | None:
        """Start (or adopt) gpg-agent. Returns its agent env, or None.

        Adoption is restricted to agents whose socket lives under one of the
        user's gpg homedirs (see :func:`gpg_socket_is_primary`). A foreign
        gpg-agent owned by the same uid -- e.g. one spawned by a package
        manager with ``--homedir /var/tmp/zypp.XXX`` -- is ignored.
        """
        out = self.out
        sock = gpg_main_socket(self.k.env)
        if sock and gpg_socket_is_primary(sock, self.k.env) and ssh_socket_valid(sock):
            if not ssh_support:
                out.info(f"Using existing gpg-agent: {out.id(sock)}")
                return SshAgentRef()
            ssh_sock = gpg_ssh_socket(self.k.env)
            if ssh_sock and ssh_socket_valid(ssh_sock):
                out.info(f"Using existing gpg-agent: {out.id(ssh_sock)} (SSH)")
                return SshAgentRef(ssh_sock)
        if sock and not gpg_socket_is_primary(sock, self.k.env):
            out.debug(f"ignoring non-primary gpg-agent socket: {sock}")
        opts = ["--daemon"]
        timeout = self.k.args.get_value("timeout")
        if timeout is not None:
            secs = timeout * 60
            opts += [f"--default-cache-ttl={secs}", f"--max-cache-ttl={secs}"]
        if ssh_support:
            opts.append("--enable-ssh-support")
        # User-supplied extra flags (issue #21). Last so they win on duplicates.
        opts += shlex.split(self.k.env.get("KEYCHAIN_GPG_AGENT_ARGS", ""))
        out.info("Starting gpg-agent...")
        try:
            r = run(["gpg-agent", "--sh"] + opts, env=self.k.env)
        except (FileNotFoundError, OSError):
            return None
        return SshAgentRef.from_text(r.stdout) if r.returncode == 0 else None

    # ---- key operations ----------------------------------------------

    def wipe(self) -> None:
        try:
            r = run(["gpg-connect-agent", "--no-autostart"], input_="RELOADAGENT\n", timeout=5)
        except FileNotFoundError:
            self.out.debug("gpg-agent wipe skipped: gpg-connect-agent not found")
            return
        except subprocess.TimeoutExpired:
            self.out.debug("gpg-agent wipe skipped: gpg-connect-agent timed out")
            return
        except OSError as exc:
            self.out.debug(f"gpg-agent wipe skipped: {exc}")
            return

        output = "\n".join(part.strip() for part in (r.stdout, r.stderr) if part.strip())
        if r.returncode == 0 and r.stdout.strip() == "OK":
            self.out.info("gpg-agent: All identities removed.")
        elif output:
            self.out.debug(f"gpg-agent could not remove identities: {output}")
        else:
            self.out.debug("gpg-agent wipe skipped: no agent response")

    def list_missing(self, gpg_keys: list[str], mode: str = "--sign", *, announce_known: bool = True) -> list[str]:
        out = self.out
        missing: list[str] = []
        tty = get_tty()
        extra_env = {"GPG_TTY": tty} if tty else {}
        for k in filter(None, gpg_keys):
            try:
                r = run(
                    [
                        self.k.gpg_prog,
                        "--no-autostart",
                        "--no-options",
                        "--use-agent",
                        "--no-tty",
                        mode,
                        "--local-user",
                        k,
                        "-o-",
                    ],
                    input_="",
                    env=extra_env,
                    timeout=10,
                )
                if r.returncode == 0:
                    if announce_known:
                        out.info(f"Known gpg key: {out.id(k)}")
                    continue
            except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
                pass
            missing.append(k)
        return missing

    def load(self, gpg_keys: list[str], mode: str = "--sign") -> bool:
        out = self.out
        run_env = self._gpg_env(tty=True)
        for k in filter(None, gpg_keys):
            out.info(f"Adding gpg key: {k}")
            try:
                r = self._run_gpg(
                    [
                        "--no-autostart",
                        "--no-options",
                        "--use-agent",
                        mode,
                        "--local-user",
                        k,
                        "-o-",
                    ],
                    env=run_env,
                )
            except (FileNotFoundError, OSError):
                out.warn(f"{self.k.gpg_prog} not found")
                return False
            if r.returncode != 0:
                err = (r.stdout + r.stderr).strip()
                out.warn(f"Error adding gpg key (error code: {r.returncode}; output: {err})")
                return False
        return True

    def load_decryption(self, gpg_keys: list[str]) -> bool:
        out = self.out
        run_env = self._gpg_env()
        with tempfile.TemporaryDirectory(prefix="keychain-gpg-") as td:
            plain = Path(td) / "plain"
            cipher = Path(td) / "cipher.gpg"
            decrypted = Path(td) / "decrypted"
            plain.write_text("keychain\n", encoding="utf-8")
            for k in filter(None, gpg_keys):
                out.info(f"Adding gpg encryption key: {k}")
                try:
                    enc = self._run_gpg(
                        [
                            "--batch",
                            "--yes",
                            "--no-options",
                            "--trust-model",
                            "always",
                            "--encrypt",
                            "--recipient",
                            k,
                            "--output",
                            str(cipher),
                            str(plain),
                        ],
                        env=run_env,
                        timeout=10,
                    )
                    dec = self._run_gpg(
                        [
                            "--yes",
                            "--no-autostart",
                            "--no-options",
                            "--use-agent",
                            "--decrypt",
                            "--output",
                            str(decrypted),
                            str(cipher),
                        ],
                        env=run_env,
                        timeout=30,
                    )
                except (FileNotFoundError, OSError):
                    out.warn(f"{self.k.gpg_prog} not found")
                    return False
                except subprocess.TimeoutExpired:
                    out.warn(f"Error adding gpg encryption key: {k} timed out")
                    return False
                if enc.returncode != 0 or dec.returncode != 0:
                    err = (enc.stdout + enc.stderr + dec.stdout + dec.stderr).strip()
                    out.warn(f"Error adding gpg encryption key (output: {err})")
                    return False
        return True


def render_list_table(kstate, out: Output) -> int:
    """Render ``ssh-add -l`` as a TYPE/BITS/FINGERPRINT/COMMENT table."""
    if out.theme != "modern":
        return kstate.ssh.passthrough("-l")

    from .output.tables import render_table

    try:
        result = run(["ssh-add", "-l"], env=kstate.find_active_agent_env.overlay())
    except (FileNotFoundError, OSError):
        out.error("ssh-add not found on PATH")
        return 127
    if result.returncode != 0:
        if result.returncode == 2:
            out.note("No agent is currently running.")
            return 0
        if result.stderr:
            sys.stderr.write(result.stderr)
        return result.returncode

    rows: list[list[str]] = []
    for line in result.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        bits, fingerprint = parts[0], parts[1]
        key_type = ""
        comment_parts = parts[2:]
        if comment_parts and comment_parts[-1].startswith("(") and comment_parts[-1].endswith(")"):
            key_type = comment_parts[-1][1:-1]
            comment_parts = comment_parts[:-1]
        rows.append([key_type, bits, fingerprint, " ".join(comment_parts)])
    if not rows:
        out.line("No keys loaded.")
        return 0

    header_style = out.style("heading", "dim")
    for line in render_table(
        rows, headers=["type", "bits", "fingerprint", "comment"], indent=2, header_style=header_style
    ).splitlines():
        print(line)
    return 0


def render_list_json(agent_env: SshAgentRef) -> None:
    """Emit ``ssh-add -L`` output as a JSON array of key objects."""
    import json

    try:
        result = run(["ssh-add", "-L"], env=agent_env.overlay())
        lines = result.stdout.splitlines() if result.returncode == 0 else []
    except (FileNotFoundError, OSError):
        lines = []

    keys = []
    for line in lines:
        parts = line.strip().split(None, 2)
        if len(parts) >= 2:
            keys.append(
                {
                    "type": parts[0],
                    "key": parts[1],
                    "comment": parts[2] if len(parts) > 2 else "",
                }
            )
    print(json.dumps(keys))
