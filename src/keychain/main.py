# SPDX-License-Identifier: GPL-3.0-only
"""Command-line entry point: argument parsing + thin coordinator.

The user-visible interface is an action tree
(``keychain {add,agent,list,wipe,forget,inspect,env,version,help}``).
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
import time
from contextlib import contextmanager

from . import __version__, agents, keys, state
from .coordination import ActivationCoordinator, ActivationOwner, WaiterEndpoint, WaitResult
from .env import SshAgentRef
from .output.core import Output
from .runtime import platform
from .runtime.actions import NO_BANNER_ACTIONS, OUTPUT_ACTIONS, ROOT_ACTION
from .runtime.config import OptionError, RuntimeConfig
from .util import KeychainError


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
    project_url = out.format_doc(f"`{_HELP_PROJECT_URL}`")
    out.banner(f"{out.id('keychain')} {out.id(__version__)}  {sep}  {project_url}")


def versinfo(out: Output) -> None:
    out.line()
    out.line(" Copyright 2026 Daniel Robbins.")
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
            agents.render_list_json(self.kstate.selected_ssh_env)
            return 0
        return agents.render_list_table(self.kstate, self.out)

    def _handle_env_action(self) -> int:
        target = "json" if self.out.json else (self.kstate.args.get_value("shell") or "env")
        self.out.write(self.kstate.paths.render_env(self.kstate.selected_ssh_env, target, os.environ))
        return 0

    def _handle_inspect_action(self) -> int:
        from .output import inspect as inspect_view

        if self.out.json:
            inspect_view.render_inspect_json(self.kstate)
        else:
            inspect_view.render_inspect(self.kstate, self.out)
        return 1 if any(check.severity in ("warn", "err") for check in self.kstate.security_audit) else 0

    def _handle_agent_stop_action(self) -> int:
        self._ensure_keydir()
        target = self.args.get_value("target") or "pidfile"
        self.kstate.ssh.stop(target)
        self.out.line()
        return 0

    def _handle_agent_start_action(self) -> int:
        self._ensure_keydir()
        return self._do_add(keys.ResolvedKeys())

    def _handle_wipe_action(self) -> int:
        self._ensure_keydir()
        wipe_ssh = bool(self.args.get_value("wipe_ssh"))
        wipe_gpg = bool(self.args.get_value("wipe_gpg"))
        if wipe_ssh or not wipe_gpg:
            self.kstate.ssh.wipe()
        if wipe_gpg:
            self.kstate.gpg.wipe()
        self.out.line()
        return 0

    def _handle_forget_action(self) -> int:
        self._ensure_keydir()
        keys_arg = self.args.get_value("keys") or []
        conf_arg = bool(self.args.get_value("confallhosts"))
        if not keys_arg and not conf_arg:
            return 0
        resolved = self._resolve_requested_keys(gpg_lookup=False)
        if resolved.gpg or resolved.pkcs11:
            raise KeychainError(
                "forget only supports SSH key files; use wipe --gpg to clear gpg-agent's passphrase cache."
            )
        self.kstate.ssh.remove(resolved.ssh)
        self.out.line()
        return 0

    def _handle_add_action(self) -> int:
        self._ensure_keydir()
        if bool(self.args.get_value("noask")):
            return self._do_add(keys.ResolvedKeys())
        resolved = self._resolve_add_keys()
        requested_keys = list(self.args.get_value("keys") or [])
        if (
            requested_keys
            and not bool(self.args.get_value("quick"))
            and not resolved.ssh
            and not any((resolved.gpg, resolved.gpg_s, resolved.gpg_e, resolved.gpg_a, resolved.pkcs11))
            and resolved.missing
        ):
            raise KeychainError(
                "No requested keys could be resolved; refusing to start an agent. "
                "Run 'keychain help add' for more information."
            )
        return self._do_add(resolved)

    # ---- Shared helpers -----------------------------------------------

    def _resolve_add_keys(self) -> keys.ResolvedKeys:
        return self._resolve_requested_keys(gpg_lookup=not bool(self.args.get_value("quick")))

    def _ensure_keydir(self) -> None:
        self.kstate.paths.ensure_keydir()

    def _resolve_requested_keys(self, *, gpg_lookup: bool = True) -> keys.ResolvedKeys:
        resolved = self.kstate.resolve_requested_keys(self.out, gpg_lookup=gpg_lookup)
        if not bool(self.args.get_value("ignore_missing")):
            for missing in resolved.missing:
                self.out.warn(f'Can\'t find key "{self.out.value(missing)}"')
        return resolved

    def _do_add(self, requested: keys.ResolvedKeys) -> int:
        """Coordinated flow used for keychain 'add' and 'agent start' actions."""
        paths = self.kstate.paths

        lockwait = self.args.get_value("lockwait")
        if lockwait is None:
            lockwait = 5
        no_lock = bool(self.args.get_value("no_lock"))
        coord = ActivationCoordinator(paths, no_lock, lockwait, self.out)
        wipe_pending = bool(self.args.get_value("clear"))

        with coord.state_lock():
            quick_succeeded = self._prepare_agent_state()

        if bool(self.args.get_value("noask")):
            self.out.line()
            return 0

        if not quick_succeeded:
            self._coordinate_ssh_keys(coord, requested, wipe_pending)
        if not bool(self.args.get_value("quick")):
            self._warm_gpg_keys(requested, wipe_pending)
        self.out.line()
        return 0

    def _coordinate_ssh_keys(
        self,
        coord: ActivationCoordinator,
        requested: keys.ResolvedKeys,
        wipe_pending: bool,
    ) -> None:
        with coord.state_lock():
            missing = self._missing_ssh_keys(requested)

        if not missing.any:
            return

        waiter = coord.create_waiter() if coord.can_prompt() else None
        if waiter is None:
            self._activate_direct(coord, missing, wipe_pending)
            return

        try:
            with coord.state_lock():
                missing = self._missing_ssh_keys(requested)
                if not missing.any:
                    return
                state_snapshot = coord.load_state()
                coord.register_waiter(state_snapshot, waiter, missing.labels())
                coord.save_state(state_snapshot)
            self.kstate.ssh.announce_load(missing.ssh, missing.pkcs11)

            immediate = bool(self.args.get_value("immediate"))
            immediate_pending = immediate
            handoff_wait = False
            quiet_handoff_wait = False
            while True:
                if quiet_handoff_wait:
                    quiet_handoff_wait = False
                    wait_result = coord.wait_for_handoff(waiter)
                else:
                    state_snapshot = coord.load_state()
                    activation_active = state_snapshot.activation.in_progress or handoff_wait
                    if immediate_pending and not activation_active:
                        immediate_pending = False
                        wait_result = WaitResult("activate")
                    elif immediate:
                        immediate_pending = False
                        wait_result = coord.wait_for_notification(waiter)
                    else:
                        wait_result = coord.wait_for_activation_signal(
                            waiter,
                            activation_active=activation_active,
                        )
                if wait_result.action == "notified":
                    handoff_wait = False
                    status = str(wait_result.message.get("status", ""))
                    missing = self._missing_ssh_keys_after_notification(requested, status=status)
                    if not missing.any:
                        self.out.info("Keys initialized by another terminal.")
                        return
                    with coord.state_lock():
                        state_snapshot = coord.load_state()
                        coord.register_waiter(state_snapshot, waiter, missing.labels())
                        coord.save_state(state_snapshot)
                    if status == "canceled":
                        handoff_wait = True
                        quiet_handoff_wait = True
                    elif immediate:
                        raise KeychainError("Requested SSH keys remain unavailable after activation in another terminal")
                    elif status == "failed":
                        self.out.note("Key initialization failed in another terminal.")
                    else:
                        self.out.note("Key initialization is still needed.")
                    continue

                if wait_result.action == "wait":
                    continue

                if wait_result.action == "handoff":
                    quiet_handoff_wait = True
                    continue

                if wait_result.action == "takeover":
                    handoff_wait = True
                    takeover = coord.request_takeover(waiter)
                    if takeover.get("status") in ("canceled", "inactive"):
                        missing = self._missing_ssh_keys(requested)
                        if not missing.any:
                            self.out.info("Keys initialized by another terminal.")
                            return
                    else:
                        self.out.note("Activation owner did not cancel; still waiting.")
                        continue

                activation_result = self._try_activation(coord, waiter, missing, wipe_pending)
                if activation_result == "success":
                    return
                handoff_wait = activation_result == "canceled" or (
                    handoff_wait and activation_result == "busy"
                )
                quiet_handoff_wait = handoff_wait

                with coord.state_lock():
                    missing = self._missing_ssh_keys(requested)
                    if not missing.any:
                        self.out.info("Keys initialized by another terminal.")
                        return
                    state_snapshot = coord.load_state()
                    coord.register_waiter(state_snapshot, waiter, missing.labels())
                    coord.save_state(state_snapshot)
        finally:
            with coord.state_lock():
                state_snapshot = coord.load_state()
                coord.unregister_waiter(state_snapshot, waiter)
                coord.save_state(state_snapshot)
            waiter.cleanup()

    def _prepare_agent_state(self) -> bool:
        quick_succeeded = self.kstate.ssh.start()

        if bool(self.args.get_value("eval")):
            self.out.write(self.kstate.paths.render_env(self.kstate.ssh.env, "eval", os.environ))

        if bool(self.args.get_value("systemd")):
            _systemd_set_env(self.kstate.ssh.env, self.out)

        return quick_succeeded

    def _missing_ssh_keys(
        self,
        requested: keys.ResolvedKeys,
        *,
        announce_known: bool = True,
    ) -> keys.ResolvedKeys:
        return keys.ResolvedKeys(
            ssh=self.kstate.ssh.list_missing(requested.ssh, announce_known=announce_known),
            pkcs11=self.kstate.ssh.list_missing_pkcs11(requested.pkcs11, announce_known=announce_known)
            if requested.pkcs11
            else [],
        )

    def _missing_ssh_keys_after_notification(
        self,
        requested: keys.ResolvedKeys,
        *,
        status: str,
    ) -> keys.ResolvedKeys:
        attempts = 6 if status == "success" else 1
        for attempt in range(attempts):
            missing = self._missing_ssh_keys(requested, announce_known=False)
            if not missing.any or attempt == attempts - 1:
                return missing
            time.sleep(0.05)
        return missing

    def _activate_direct(self, coord: ActivationCoordinator, missing: keys.ResolvedKeys, wipe_pending: bool) -> None:
        deadline = time.monotonic() + coord.lockwait
        while True:
            if self._try_activation(coord, None, missing, wipe_pending) == "success":
                return
            if time.monotonic() >= deadline:
                raise KeychainError(f"could not acquire activation lock {coord.paths.activation_lockf}")
            time.sleep(0.1)

    def _try_activation(
        self,
        coord: ActivationCoordinator,
        waiter: WaiterEndpoint | None,
        missing: keys.ResolvedKeys,
        wipe_pending: bool,
    ) -> str:
        with coord.activation_lock() as activation:
            if not activation.acquired:
                self.out.info("Another terminal is initializing keys; waiting for completion.")
                return "busy"

            missing = self._missing_ssh_keys(missing, announce_known=False)
            if not missing.any:
                return "success"

            status = "failed"
            with _activation_signals():
                try:
                    if wipe_pending:
                        self.kstate.ssh.wipe()
                    plan = self.kstate.ssh.prepare_load(missing.ssh, missing.pkcs11, announce=waiter is None)
                    if plan is None:
                        raise KeychainError("Unable to add keys")
                    owner = ActivationOwner(coord, waiter, missing.labels(), self.out)
                    status = owner.run_ssh_add(plan.commands, plan.env)
                    if status == "canceled":
                        self.out.note("Another terminal took over key initialization; waiting for completion.")
                        return "canceled"
                    if status != "success":
                        raise KeychainError("Unable to add keys")
                    status = "success"
                finally:
                    coord.finish_activation(status)
            return "success"

    def _warm_gpg_keys(self, requested: keys.ResolvedKeys, wipe_pending: bool) -> None:
        signing = list(dict.fromkeys([*requested.gpg, *requested.gpg_s, *requested.gpg_a]))
        decryption = list(dict.fromkeys([*requested.gpg_e, *requested.gpg_a]))
        if not signing and not decryption:
            return
        if wipe_pending:
            self.kstate.gpg.wipe()
        if signing:
            self.kstate.gpg.warm_signing(signing)
        if decryption:
            self.kstate.gpg.warm_decryption(decryption)


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

    out = Output.build(
        quiet=bool(args.get_value("quiet")) or args.action == "env",
        debug=bool(args.get_value("debug")),
        eval_mode=bool(args.get_value("eval")),
        color=not bool(args.get_value("nocolor")),
        theme=args.get_value("theme"),
        json=bool(args.get_value("json")),
        color_stream=sys.stdout if args.action == "man" else None,
    )

    if out.debug_on:
        configuration = args.diagnostics()
        overrides = ", ".join(
            f"{key}={entry['value']!r} ({entry['source']})"
            for key, entry in configuration["effective"].items()
            if entry["source"] != "default"
        )
        if configuration["keychainrc"]["status"] == "loaded" or overrides:
            rc = configuration["keychainrc"]
            out.debug(
                f"Configuration ({rc['status']}: {rc['path'] or '(none)'})" + (f": {overrides}" if overrides else "")
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
    except KeyboardInterrupt:
        out.line()
        _emit_eval_failure(bool(args.get_value("eval")))
        sys.exit(130)
    except (KeychainError, OSError, subprocess.TimeoutExpired) as e:
        if isinstance(e, subprocess.TimeoutExpired):
            msg = f"External command timed out after {e.timeout} seconds"
        else:
            msg = str(e) or "Operating system operation failed"
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
        return None
    try:
        return signal.signal(sig, handler)
    except (ValueError, OSError, AttributeError):
        # SIGHUP doesn't exist on Windows; non-main threads can't install.
        return None


@contextmanager
def _activation_signals():
    previous = []
    for sig in (getattr(signal, "SIGHUP", None), signal.SIGINT, signal.SIGTERM):
        handler = _safe_signal(sig, lambda *_: sys.exit(1))
        if sig is not None and handler is not None:
            previous.append((sig, handler))
    try:
        yield
    finally:
        for sig, handler in previous:
            _safe_signal(sig, handler)


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
