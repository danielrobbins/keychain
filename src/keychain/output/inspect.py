# SPDX-License-Identifier: GPL-3.0-only
"""Inspect renderers and related presentation helpers."""

from __future__ import annotations

import json
import shutil
from typing import TYPE_CHECKING, Any

from .core import Output

if TYPE_CHECKING:
    from ..state import KeychainState


def _format_kv_rows(rows: list, out: Output) -> list[str]:
    """Return formatted kv lines (without indent) for *rows*.

    Each row is ``(label, value, hint)`` or ``(label, value, hint, severity)``.
    Severity is ``""`` (info), ``"warn"`` (yellow) or ``"err"`` (red); it
    colors the value and the hint together so security-relevant rows stand
    out without a separate badge column. Boolean values render as
    ``● yes`` / ``✖ no`` in the severity color (green/red by default).
    """
    if not rows:
        return []
    width = max(len(r[0]) for r in rows)
    lines: list[str] = []
    for row in rows:
        label, value, hint = row[0], row[1], row[2]
        sev = row[3] if len(row) > 3 else ""
        if isinstance(value, bool):
            text = "yes" if value else "no"
            if sev == "warn":
                disp = f"{out.glyph('warn')} {out.warn_text(text)}"
            elif sev == "err":
                disp = f"{out.glyph('err')} {out.err_text(text)}"
            else:
                disp = f"{out.glyph('ok')} {out.value('yes')}" if value else f"{out.glyph('err')} {out.err_text('no')}"
        else:
            if sev == "warn":
                disp = str(out.warn_text(value))
            elif sev == "err":
                disp = str(out.err_text(value))
            else:
                disp = str(out.id(value))
        lines.append(f"{label:<{width}}  {disp}")
        # Inline hints are for neutral annotations only (e.g. ``(you)``);
        # warn/err hints are surfaced as out.warn()/out.error() lines after
        # the panels render, matching the format used by other code paths.
        if hint and sev == "":
            lines[-1] += f" {out.dim(hint)}"
    return lines


def render_inspect(state: KeychainState, out: Output) -> None:
    """Print a structured snapshot of every probe in *state* to *out*."""
    from .tables import compose_columns, render_panel, render_table

    sections: list[tuple[str, list[tuple]]] = []

    runtime = state.runtime_info
    primary_hint = ""
    if state.gpg_main_socket and not state.gpg_primary_socket_is_ours:
        primary_hint = "socket is outside our gpg homedir; keychain will NOT adopt this agent"
    runtime_rows: list[tuple] = [
        ("hostname", state.hostname, f"- via {state.hostname_source}"),
        ("platform", f"{state.platform.name} / {runtime['machine']}", ""),
        ("supported", state.platform.supported, "" if state.platform.supported else state.platform.reason),
        ("keychain", runtime["keychain_version"], ""),
        ("keychain path", runtime["keychain_executable"], ""),
        ("python", runtime["python_version"], ""),
        ("python path", runtime["python_executable"], ""),
        ("ssh impl", state.ssh_implementation, ""),
        ("ssh version", state.ssh_version or "(unknown)", ""),
        ("ssh path", state.ssh_path or "(not found)", ""),
        ("gpg version", state.gpg_version or "(unknown)", ""),
        ("gpg path", state.gpg_path or "(not found)", ""),
        ("gpg ssh support", state.gpg_has_ssh_support, ""),
        ("gpg ssh socket", state.gpg_ssh_socket or "(none)", ""),
        ("gpg main socket", state.gpg_main_socket or "(none)", primary_hint),
    ]
    sections.append(("Runtime", runtime_rows))

    diagnostics = state.config_diagnostics
    if diagnostics:
        config = diagnostics
        keychainrc = config["keychainrc"]
        environment = config["environment"]
        status = keychainrc["status"]
        keychain_env = [name for name, item in environment.items() if name.startswith("KEYCHAIN_") and item["set"]]
        keychain_env_hint = (
            f"({len(keychain_env)} set{'' if config['allow_env'] else ', ignored'})" if keychain_env else ""
        )

        def env_value(name: str) -> str:
            item = environment[name]
            return item.get("value", "set") if item["set"] else "unset"

        def set_vars(*names: str) -> str:
            return ", ".join(name for name in names if environment[name]["set"]) or "(none)"

        config_rows: list[tuple] = [
            ("keychainrc", keychainrc["path"] or "(none)", ""),
            ("status", status, "", "warn" if status not in ("absent", "loaded") else ""),
            (
                "KEYCHAIN_* env",
                "enabled" if config["allow_env"] else "disabled",
                keychain_env_hint,
            ),
            ("shell", env_value("SHELL"), ""),
            ("terminal", env_value("TERM"), ""),
            ("display env", set_vars("DISPLAY", "WAYLAND_DISPLAY"), ""),
            ("askpass env", set_vars("SSH_ASKPASS", "SSH_ASKPASS_REQUIRE"), ""),
            ("agent env", set_vars("SSH_AUTH_SOCK", "SSH_AGENT_PID"), ""),
            ("gpg env", set_vars("GPG_TTY", "GNUPGHOME"), ""),
        ]
        config_rows.extend(
            (
                name,
                str(entry["value"]).lower() if isinstance(entry["value"], bool) else entry["value"],
                f"({entry['source'].replace('_', ' ')})",
            )
            for name, entry in config["effective"].items()
            if entry["source"] != "default"
        )
        sections.append(("Configuration", config_rows))

    state_rows: list[tuple] = [
        ("keydir path", str(state.paths.keydir), ""),
        ("keydir exists", state.keydir_exists, ""),
    ]
    if state.keydir_exists:
        state_rows.append(("keydir writable", state.keydir_writable, ""))
    for check in state.security_audit:
        state_rows.append((check.label.replace("_", " "), check.summary, check.message, check.severity))
    sections.append(("Keychain State", state_rows))

    pidf_rows: list[tuple] = [
        ("pidfile path", str(state.pidfile_path), ""),
        ("pidfile exists", state.pidfile_exists, ""),
    ]
    if state.pidfile_exists:
        pidf_rows.append(("SSH_AUTH_SOCK", state.pidfile_socket or "(unset)", ""))
        pidf_rows.append(("SSH_AGENT_PID", state.pidfile_pid or "(unset)", ""))
        socket_validation = state.pidfile_socket_validation
        sock_hint = "" if socket_validation.valid else f"rejected socket ({socket_validation.reason})"
        pidf_rows.append(("socket valid", socket_validation.valid, sock_hint, socket_validation.severity))
        pid_hint = "" if state.pidfile_pid_alive else ("process is not running" if state.pidfile_pid else "")
        pidf_rows.append(("pid alive", state.pidfile_pid_alive, pid_hint))
    if not state.process_listing_supported:
        pidf_rows.append(("processes", "listing not available on this platform", ""))
    else:
        pidf_rows.append(("ssh-agent pids", _fmt_pids(state.ssh_agent_pids), ""))
        gpg_hint = ""
        if state.gpg_foreign_agents_present:
            gpg_hint = "at least one is foreign (e.g. package-manager with --homedir); these are ignored by keychain"
        pidf_rows.append(("gpg-agent pids", _fmt_pids(state.gpg_agent_pids), gpg_hint))
    sections.append(("Agent State", pidf_rows))

    term_w = shutil.get_terminal_size((80, 24)).columns
    title_style = out.style("heading")
    panels = [render_panel(title, _format_kv_rows(rows, out), title_style=title_style) for title, rows in sections]
    panel_rows = (panels[:2], panels[2:])
    layout = "\n\n".join(compose_columns(row, max(term_w - 2, 40)) for row in panel_rows if row)
    out.result()
    for line in layout.splitlines():
        out.result(" " + line)

    out.heading("Loaded SSH keys (best available agent)")
    fps = state.loaded_ssh_fingerprints
    if fps:
        header_style = out.style("heading", "dim")
        table = render_table(
            [[str(i + 1), fp] for i, fp in enumerate(fps)],
            headers=["#", "fingerprint"],
            indent=2,
            header_style=header_style,
        )
        for line in table.splitlines():
            out.result(line)
    else:
        if state.has_reachable_agent:
            out.result(f"   {out.dim('(none loaded)')}")
        else:
            out.result(f"   {out.dim('(no agent reachable)')}")

    if state.cmdline_keys or state.confallhosts:
        cli_repr = " ".join(state.cmdline_keys) or "(--confallhosts)"
        miss = state.missing_keys
        body = _format_kv_rows(
            [
                ("ssh keys", ", ".join(state.ssh_keys) or "(none)", ""),
                ("gpg keys", ", ".join(state.gpg_keys) or "(none)", ""),
                ("pkcs11 providers", ", ".join(state.pkcs11_keys) or "(none)", ""),
                ("missing", ", ".join(miss) or "(none)", "these keys could not be located" if miss else ""),
            ],
            out,
        )
        out.result()
        for line in render_panel(f"Resolved keys ({cli_repr})", body, title_style=title_style).splitlines():
            out.result(" " + line)

    out.result()
    seen: set[tuple[str, str]] = set()
    for check in state.security_audit:
        if not check.message or (check.severity, check.message) in seen:
            continue
        seen.add((check.severity, check.message))
        if check.severity == "warn":
            out.warn(check.message)
        elif check.severity == "err":
            out.error(check.message)
    out.result()


def _fmt_pids(pids: Any) -> str:
    return ", ".join(str(p) for p in pids) if pids else "(none)"


def _agent_reference(
    socket_path: str,
    pid: str,
    socket_valid: bool,
    socket_reason: str,
    socket_severity: str,
    pid_alive: bool,
) -> dict[str, Any]:
    return {
        "socket": {
            "path": socket_path or None,
            "valid": socket_valid,
            "reason": socket_reason or None,
            "severity": socket_severity or None,
        },
        "process": {"pid": pid or None, "alive": pid_alive},
    }


def render_inspect_json(state: KeychainState) -> None:
    """JSON form of :func:`render_inspect`. Prints one object on stdout."""
    runtime = state.runtime_info
    resolved = None
    if state.cmdline_keys or state.confallhosts:
        resolved = {
            "ssh": list(state.ssh_keys),
            "gpg": list(state.gpg_keys),
            "pkcs11": list(state.pkcs11_keys),
            "missing": list(state.missing_keys),
        }
    payload: dict[str, Any] = {
        "schema_version": 1,
        "runtime": {
            "keychain": {"version": runtime["keychain_version"], "path": runtime["keychain_executable"]},
            "python": {"version": runtime["python_version"], "path": runtime["python_executable"]},
            "platform": {
                "name": state.platform.name,
                "description": runtime["system"],
                "machine": runtime["machine"],
                "supported": state.platform.supported,
                "reason": state.platform.reason or None,
                "hostname": state.hostname,
                "hostname_source": state.hostname_source,
            },
            "ssh": {
                "implementation": state.ssh_implementation,
                "version": state.ssh_version or None,
                "path": state.ssh_path or None,
            },
            "gpg": {
                "version": state.gpg_version or None,
                "path": state.gpg_path or None,
                "ssh_support": state.gpg_has_ssh_support,
                "ssh_socket": state.gpg_ssh_socket or None,
                "main_socket": state.gpg_main_socket or None,
                "primary_socket_is_ours": state.gpg_primary_socket_is_ours,
            },
        },
        "configuration": state.config_diagnostics,
        "keychain_state": {
            "current_user": state.user,
            "keydir": {
                "path": str(state.paths.keydir),
                "exists": state.keydir_exists,
                "writable": state.keydir_writable,
            },
            "security": {
                check.label: {
                    "path": str(check.path),
                    "owner": check.owner or None,
                    "mode": check.mode,
                    "status": check.status,
                    "message": check.message or None,
                }
                for check in state.security_audit
            },
        },
        "agent_state": {
            "pidfile": {
                "path": str(state.pidfile_path),
                "exists": state.pidfile_exists,
                **_agent_reference(
                    state.pidfile_socket,
                    state.pidfile_pid,
                    state.pidfile_socket_valid,
                    state.pidfile_socket_validation.reason,
                    state.pidfile_socket_validation.severity,
                    state.pidfile_pid_alive,
                ),
            },
            "inherited": _agent_reference(
                state.inherited_socket,
                state.inherited_pid,
                state.inherited_socket_valid,
                state.inherited_socket_validation.reason,
                state.inherited_socket_validation.severity,
                state.inherited_pid_alive,
            ),
            "processes": {
                "supported": state.process_listing_supported,
                "ssh_agent_pids": list(state.ssh_agent_pids),
                "gpg_agent_pids": list(state.gpg_agent_pids),
                "gpg_foreign_agents_present": state.gpg_foreign_agents_present,
            },
        },
        "keys": {
            "loaded_ssh_fingerprints": list(state.loaded_ssh_fingerprints),
            "resolved": resolved,
        },
    }
    print(json.dumps(payload, default=str))
