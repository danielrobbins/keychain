# SPDX-License-Identifier: GPL-3.0-only
"""Command-line entry point: argument parsing + thin coordinator.

The user-visible interface is an action tree
(``keychain {add,agent,list,wipe,forget,inspect,status,env,version,help}``).
Legacy keychain 2.x flat-flag invocations (``keychain --stop all``,
``keychain --list``, plain ``keychain``) are translated to the new form
by :mod:`keychain.compat` before parsing, so a single internal parser
handles every entry point.

Targets Python 3.9+.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys

from . import __version__, agents, keys, state
from .env import SshAgentRef
from .runtime import platform
from .runtime.actions import NO_BANNER_ACTIONS, OUTPUT_ACTIONS, ROOT_ACTION
from .runtime.config import OptionError, RuntimeConfig
from .util import KeychainError, LockFile, Output


def _emit_eval_failure(enabled: bool) -> None:
    if enabled:
        sys.stdout.write("\nfalse;\n")


_HELP_PROJECT_URL = "https://kernel-seeds.org/projects/keychain/"


def banner(out: Output) -> None:
    """One-line visual identifier: ``▌ keychain VER · URL`` (see
    ``docs/output-design.md``). Replaces the historical multi-line ``* keychain``
    block; ``keychain version`` still prints the full GPL preamble.
    """
    out.line()
    # Mid-dot when stderr is utf-capable (matches the unicode bar glyph);
    # plain hyphen otherwise so legacy/ascii consoles still align cleanly.
    sep = "·" if out.theme == "modern" else "-"
    out.banner(f"{out.id('keychain')} {out.id(__version__)}  {sep}  {out.dim(_HELP_PROJECT_URL)}")


def versinfo(out: Output) -> None:
    out.line()
    out.line("   Copyright 2026 Daniel Robbins, BreezyOps")
    out.line()
    out.line(" Keychain is free software: you can redistribute it and/or modify")
    out.line(f" it under the terms of the {out.id('GNU General Public License version 3')} as")
    out.line(" published by the Free Software Foundation.")
    out.line()


def helpinfo(action: str | list[str] | None = None, out: Output | None = None) -> int:
    """Print top-level help when *action* is None, otherwise per-action help.

    *action* may be a single name or a list of tokens that are joined with
    spaces to form a full action name (so the caller can pass argparse's
    ``help_target`` list directly). Lookup is exact: unknown names emit
    ``help: unknown action: ...`` and return ``2``.
    """
    if out is None:
        out = Output.build(quiet=False, debug=False, eval_mode=False, color=False)
    if action is None:
        ROOT_ACTION.help(out)
    else:
        target = ROOT_ACTION.find_action(action)
        if target is None:
            label = " ".join(action) if isinstance(action, list) else str(action)
            sys.stderr.write(f"help: unknown action: {label}\n")
            return 2
        target.help(out)
    return 0


class KeychainApp:
    """Thin coordinator: owns ``args``, ``out``, and a lazy ``kstate``."""

    def __init__(self, args: RuntimeConfig, out: Output) -> None:
        self.args = args
        self.out = out
        self._kstate: state.KeychainState | None = None

    @property
    def kstate(self) -> state.KeychainState:
        if self._kstate is None:
            self._kstate = state.KeychainState.build(self.args, out=self.out)
        return self._kstate

    def run(self) -> int:
        action = self._resolve_action()
        if action not in OUTPUT_ACTIONS:
            os.umask(0o077)
            if action not in NO_BANNER_ACTIONS:
                banner(self.out)
        handler = getattr(self, f"_handle_{action}_action", None)
        if handler is None:  # pragma: no cover
            raise KeychainError(f"unknown action: {action}")
        return handler()

    def _resolve_action(self) -> str:
        """Validate run-time constraints and derive the concrete handler name.

        Why this exists:
        the parser now owns action discovery through ``ROOT_ACTION`` and
        ``RuntimeConfig.action_node``. The entrypoint should therefore stop
        reconstructing action identity from old registries or ad hoc
        ``subaction`` fields and instead consume the authored terminal node
        directly.

        How it is used:
        ``run()`` calls this exactly once before banner emission and handler
        lookup. The returned string is the suffix used to locate methods like
        ``_handle_add_action`` or ``_handle_agent_start_action``.

        How it resolves and why:
        we first ask the terminal action node for ``dispatch_name`` so the tree
        defines what is dispatchable. Only after a concrete node is established
        do we enforce cross-option rules such as ``--quick`` versus ``--clear``
        and validate runtime-only constraints such as timeout bounds. This keeps
        parse-time structure decisions in the parser and run-time policy checks
        in the coordinator.
        """
        action_node = self.args.action_node
        if action_node is None:
            raise KeychainError(f"unknown action: {self.args.action}")

        try:
            action = action_node.dispatch_name
        except ValueError as exc:
            if action_node.sub_actions:
                expected = "|".join(action_node.sub_actions.keys())
                raise KeychainError(f"{action_node.fq_name}: missing subcommand ({expected})") from exc
            raise KeychainError(str(exc)) from exc

        try:
            self.args.apply_option_policies(self.out)
        except OptionError as exc:
            raise KeychainError(str(exc)) from exc

        if bool(self.args.get_value("quick")) and bool(self.args.get_value("clear")):
            raise KeychainError("--quick and --clear are not compatible")

        return action

    # ---- Output-only Handlers (no KeychainState) ------------------------------------

    def _handle_man_action(self) -> int:
        # lazy-load to avoid loading all documentation-related code and data structures when not needed
        from . import docs

        return docs.run_man(self.args, self.out)

    def _handle_version_action(self) -> int:
        if self.out.json:
            import json

            print(
                json.dumps(
                    {
                        "name": "keychain",
                        "implementation": "python",
                        "version": __version__,
                        "url": _HELP_PROJECT_URL,
                    }
                )
            )
        else:
            banner(self.out)
            versinfo(self.out)
        return 0

    def _handle_help_action(self) -> int:
        help_target = self.args.get_value("help_target")
        if help_target is None:
            banner(self.out)
            versinfo(self.out)
        return helpinfo(help_target, self.out)

    # ---- state handlers -----------------------------------------------

    def _handle_list_action(self) -> int:
        if self.out.json:
            agents.render_list_json(self.kstate.find_active_agent_env)
            return 0
        return agents.render_list_table(self.kstate, self.out)

    def _handle_env_action(self) -> int:
        target = "json" if self.out.json else (self.kstate.args.get_value("shell") or "env")
        self.out.write(self.kstate.paths.render_env(self.kstate.find_active_agent_env, target, os.environ))
        return 0

    def _handle_inspect_action(self) -> int:
        from .output import inspect as inspect_view

        if self.out.json:
            inspect_view.render_inspect_json(self.kstate)
        else:
            inspect_view.render_inspect(self.kstate, self.out)
        return 1 if any(sev in ("warn", "err") for *_, sev in self.kstate.security_audit) else 0

    def _handle_agent_stop_action(self) -> int:
        self._verify_keydir()
        target = self.args.get_value("target") or "pidfile"
        self.kstate.ssh.stop(target)
        self.out.line()
        return 0

    def _handle_agent_start_action(self) -> int:
        self._verify_keydir()
        ssh_spawn_gpg, ssh_allow_gpg = self._agent_settings()
        return self._do_add([], [], [], [], [], ssh_spawn_gpg, ssh_allow_gpg)

    def _handle_wipe_action(self) -> int:
        self._verify_keydir()
        only_ssh = bool(self.args.get_value("wipe_ssh")) and not bool(self.args.get_value("wipe_gpg"))
        only_gpg = bool(self.args.get_value("wipe_gpg")) and not bool(self.args.get_value("wipe_ssh"))
        if not only_gpg:
            self.kstate.ssh.wipe()
        if not only_ssh:
            self.kstate.gpg.wipe()
        self.out.line()
        return 0

    def _handle_forget_action(self) -> int:
        self._verify_keydir()
        keys_arg = self.args.get_value("keys") or []
        conf_arg = bool(self.args.get_value("confallhosts"))
        if not keys_arg and not conf_arg:
            return 0
        resolved = self._resolve_requested_keys(gpg_lookup=False)
        if resolved.gpg:
            raise KeychainError("forget only supports SSH keys; use wipe --gpg to remove all gpg-agent identities.")
        self.kstate.ssh.remove(resolved.ssh)
        self.out.line()
        return 0

    def _handle_add_action(self) -> int:
        self._verify_keydir()
        resolved = self._resolve_requested_keys()
        requested_keys = list(self.args.get_value("keys") or [])
        if requested_keys and not resolved.ssh and not any((resolved.gpg, resolved.gpg_s, resolved.gpg_e, resolved.gpg_a)) and resolved.missing:
            raise KeychainError(
                "No requested keys could be resolved; refusing to start an agent. "
                "Run 'keychain help add' for more information."
            )
        ssh_spawn_gpg, ssh_allow_gpg = self._agent_settings()
        return self._do_add(
            resolved.ssh,
            resolved.gpg,
            resolved.gpg_s,
            resolved.gpg_e,
            resolved.gpg_a,
            ssh_spawn_gpg,
            ssh_allow_gpg,
        )

    # ---- Shared helpers -----------------------------------------------

    def _verify_keydir(self) -> None:
        self.kstate.paths.verify_keydir(self.kstate.user, self.out)

    def _agent_settings(self) -> tuple[bool, bool]:
        ssh_spawn_gpg = bool(self.args.get_value("ssh_spawn_gpg"))
        if ssh_spawn_gpg and not self.kstate.gpg_has_ssh_support:
            self.out.warn("gpg-agent ssh functionality not available; not using...")
            ssh_spawn_gpg = False
        ssh_allow_gpg = bool(self.args.get_value("ssh_allow_gpg"))
        return ssh_spawn_gpg, ssh_allow_gpg or ssh_spawn_gpg

    def _resolve_requested_keys(self, *, gpg_lookup: bool = True) -> keys.ResolvedKeys:
        resolved = self.kstate.resolve_requested_keys(self.out, gpg_lookup=gpg_lookup)
        if not bool(self.args.get_value("ignore_missing")):
            for missing in resolved.missing:
                self.out.warn(f'Can\'t find key "{self.out.value(missing)}"')
        return resolved

    def _do_add(
        self,
        ssh_keys: list[str],
        gpg_keys: list[str],
        gpg_s_keys: list[str],
        gpg_e_keys: list[str],
        gpg_a_keys: list[str],
        ssh_spawn_gpg: bool,
        ssh_allow_gpg: bool,
    ) -> int:
        """Lockfile-protected flow used for keychain 'add' and 'agent start' actions."""
        paths = self.kstate.paths

        lockwait = self.args.get_value("lockwait")
        if lockwait is None:
            lockwait = 5
        no_lock = bool(self.args.get_value("no_lock"))
        with LockFile(paths.lockf, no_lock, lockwait, self.out) as lock:
            wipe_pending = bool(self.args.get_value("clear"))
            if wipe_pending:
                signal.signal(signal.SIGINT, signal.SIG_IGN)  # disallow ^C until we've had a chance to --clear
                for sig in (getattr(signal, "SIGHUP", None), signal.SIGTERM):
                    _safe_signal(sig, lambda *_: _signal_exit(lock))  # drop the lock on signal
            else:
                for sig in (getattr(signal, "SIGHUP", None), signal.SIGINT, signal.SIGTERM):
                    _safe_signal(sig, lambda *_: _signal_exit(lock))  # drop the lock on signal

            quick_succeeded = self.kstate.ssh.start(ssh_spawn_gpg, ssh_allow_gpg)

            # gpg-agent is started separately when GPG keys are wanted and the
            # ssh-agent is *not* the gpg-agent itself (--ssh-spawn-gpg).
            if (gpg_keys or gpg_s_keys or gpg_e_keys or gpg_a_keys) and not ssh_spawn_gpg:
                gpg_env = self.kstate.gpg.start(ssh_support=False)
                if gpg_env and gpg_env.sock:
                    self.kstate.ssh.env = self.kstate.ssh.env.with_sock(gpg_env.sock)

            if bool(self.args.get_value("eval")):
                self.out.write(paths.render_env(self.kstate.ssh.env, "eval", os.environ))

            if bool(self.args.get_value("systemd")):
                _systemd_set_env(self.kstate.ssh.env, self.out)

            if bool(self.args.get_value("noask")) or quick_succeeded:
                self.out.line()
                return 0

            if wipe_pending:
                self.kstate.ssh.wipe()
                if gpg_keys or gpg_s_keys or gpg_e_keys or gpg_a_keys:
                    self.kstate.gpg.wipe()
                signal.signal(signal.SIGINT, lambda *_: _signal_exit(lock))  # done clearing, safe to ctrl-c

            missing_ssh = self.kstate.ssh.list_missing(ssh_keys)
            if not self.kstate.ssh.load(missing_ssh):
                raise KeychainError("Unable to add keys")

            if gpg_keys:
                missing_gpg = self.kstate.gpg.list_missing(gpg_keys)
                self.kstate.gpg.load(missing_gpg)
            if gpg_s_keys:
                missing_gpg = self.kstate.gpg.list_missing(gpg_s_keys, mode="--sign")
                self.kstate.gpg.load(missing_gpg, mode="--sign")
            if gpg_e_keys:
                self.kstate.gpg.load_decryption(gpg_e_keys)
            if gpg_a_keys:
                missing_gpg = self.kstate.gpg.list_missing(gpg_a_keys, mode="--sign")
                self.kstate.gpg.load(missing_gpg, mode="--sign")
                self.kstate.gpg.load_decryption(gpg_a_keys)

            self.out.line()
        return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    args = RuntimeConfig.resolve(argv)

    if bool(args.get_value("explain")):
        from . import docs

        sys.exit(docs.run_explain(argv))

    no_color_env = bool(os.environ.get("NO_COLOR"))
    out = Output.build(
        quiet=bool(args.get_value("quiet")) or args.action == "env",
        debug=bool(args.get_value("debug")),
        eval_mode=bool(args.get_value("eval")),
        color=not bool(args.get_value("no_color")) and not no_color_env,
        theme=(args.get_value("theme") or "modern"),
        json=bool(args.get_value("json")),
    )

    for warning in args.rc_warnings:
        out.warn(warning)

    if args.parse_error:
        out.error(args.parse_error)
        out.line()
        _emit_eval_failure(bool(args.get_value("eval")))
        sys.exit(2)

    plat = platform.detect()
    if not plat.supported and args.action not in ("help", "version", "inspect", "env", "man"):
        banner(out)
        out.error(f"Unsupported platform: {plat.name}")
        out.line(f" {plat.reason}")
        out.line()
        _emit_eval_failure(bool(args.get_value("eval")))
        sys.exit(2)

    try:
        sys.exit(KeychainApp(args, out).run())
    except KeychainError as e:
        msg = str(e)
        if msg:
            out.error(msg)
        out.line()
        _emit_eval_failure(bool(args.get_value("eval")))
        sys.exit(1)


# ---------------------------------------------------------------------------
# Signals & systemd
# ---------------------------------------------------------------------------


def _safe_signal(sig, handler):
    if sig is None:
        return
    try:
        signal.signal(sig, handler)
    except (ValueError, OSError, AttributeError):
        # SIGHUP doesn't exist on Windows; non-main threads can't install.
        pass


def _signal_exit(lock: LockFile) -> None:
    lock.release()
    sys.exit(1)


def _systemd_set_env(agent_env: SshAgentRef, out: Output) -> None:
    assignments = []
    if agent_env.sock:
        assignments.append(f"SSH_AUTH_SOCK={agent_env.sock}")
    if agent_env.pid:
        assignments.append(f"SSH_AGENT_PID={agent_env.pid}")
    if assignments:
        try:
            subprocess.run(
                ["systemctl", "--user", "set-environment", *assignments],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        except subprocess.TimeoutExpired:
            out.warn("Timed out while updating the systemd user environment")
        except (OSError, ValueError):
            pass


if __name__ == "__main__":  # pragma: no cover
    main()
