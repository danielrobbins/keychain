# SPDX-License-Identifier: GPL-3.0-only
"""Inspect renderers and related presentation helpers."""

from __future__ import annotations

import json
import os
import shutil
import stat
from typing import Any

from ..state import KeychainState
from ..util import Output, get_owner


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


def _owner_row(label: str, path: Any, me: str) -> tuple[str, str, str, str]:
    """Build a (label, value, hint, severity) row for a path's owner check."""
    owner = get_owner(path)
    if not owner:
        return (label, "(unknown)", "", "")
    if me and owner != me:
        return (label, owner, f"owned by {owner}, not you ({me}); refusing to use this file", "warn")
    return (label, owner, "(you)", "")


def _mode_row(label: str, path: Any, lax_hint: str) -> tuple[str, str, str, str]:
    """Build a (label, value, hint, severity) row for a path's permission bits."""
    try:
        mode = stat.S_IMODE(os.stat(str(path)).st_mode)
    except OSError:
        return (label, "(unreadable)", "", "")
    octal = f"0{mode:o}"
    hint = lax_hint if mode & (stat.S_IRWXG | stat.S_IRWXO) else ""
    return (label, octal, hint, "warn" if hint else "")


def render_inspect(state: KeychainState, out: Output) -> None:
    """Print a structured snapshot of every probe in *state* to *out*."""
    from .tables import compose_columns, render_panel, render_table

    sections: list[tuple[str, list[tuple]]] = []

    platform_rows: list[tuple] = [
        ("hostname", state.hostname, f"- via {state.hostname_source}"),
        ("platform", state.platform.name, ""),
        ("supported", state.platform.supported, "" if state.platform.supported else state.platform.reason),
    ]
    sections.append(("Platform", platform_rows))

    ssh_rows: list[tuple] = [
        ("ssh impl", state.ssh_implementation, ""),
        ("ssh version", state.ssh_version or "(unknown)", ""),
        ("ssh path", state.ssh_path or "(not found)", ""),
    ]
    sections.append(("SSH", ssh_rows))
    primary_hint = ""
    if state.gpg_main_socket and not state.gpg_primary_socket_is_ours:
        primary_hint = "socket is outside our gpg homedir; keychain will NOT adopt this agent"
    gpg_rows: list[tuple] = [
        ("gpg version", state.gpg_version or "(unknown)", ""),
        ("gpg path", state.gpg_path or "(not found)", ""),
        ("gpg ssh support", state.gpg_has_ssh_support, ""),
        ("gpg ssh socket", state.gpg_ssh_socket or "(none)", ""),
        ("gpg main socket", state.gpg_main_socket or "(none)", primary_hint),
    ]
    sections.append(("GPG", gpg_rows))

    keyd_rows: list[tuple] = [
        ("keydir path", str(state.paths.keydir), ""),
        ("keydir exists", state.keydir_exists, ""),
    ]
    if state.keydir_exists:
        keyd_rows.append(("keydir writable", state.keydir_writable, ""))
    sections.append(("Keychain Directory", keyd_rows))

    perms_rows: list[tuple] = []
    for lbl, val, hint, sev in state.security_audit:
        perms_rows.append((lbl.replace("_", " "), val, hint, sev))
    sections.append(("Permissions", perms_rows))

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
    sections.append(("Pidfile and Processes", pidf_rows))

    term_w = shutil.get_terminal_size((80, 24)).columns
    title_style = out.style("heading")
    panels = [render_panel(title, _format_kv_rows(rows, out), title_style=title_style) for title, rows in sections]
    out.line()
    for line in compose_columns(panels, max(term_w - 2, 40)).splitlines():
        out.line(" " + line)

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
            out.line(line)
    else:
        if state.has_reachable_agent:
            out.line(f"   {out.dim('(none loaded)')}")
        else:
            out.line(f"   {out.dim('(no agent reachable)')}")

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
        out.line()
        for line in render_panel(f"Resolved keys ({cli_repr})", body, title_style=title_style).splitlines():
            out.line(" " + line)

    out.line()
    seen: set[tuple[str, str]] = set()
    for _lbl, _val, hint, sev in state.security_audit:
        if not hint or (sev, hint) in seen:
            continue
        seen.add((sev, hint))
        if sev == "warn":
            out.warn(hint)
        elif sev == "err":
            out.error(hint)
    out.line()


def _fmt_pids(pids: Any) -> str:
    return ", ".join(str(p) for p in pids) if pids else "(none)"


def render_inspect_json(state: KeychainState) -> None:
    """JSON form of :func:`render_inspect`. Prints one object on stdout."""
    payload: dict[str, Any] = {
        "platform": {
            "name": state.platform.name,
            "supported": state.platform.supported,
            "reason": state.platform.reason if not state.platform.supported else "",
            "hostname": state.hostname,
            "hostname_source": state.hostname_source,
        },
        "ssh": {
            "openssh": state.openssh,
            "implementation": state.ssh_implementation,
            "version": state.ssh_version,
            "path": state.ssh_path,
        },
        "gpg": {
            "version": state.gpg_version,
            "path": state.gpg_path,
            "ssh_support": state.gpg_has_ssh_support,
            "ssh_socket": state.gpg_ssh_socket or "",
            "main_socket": state.gpg_main_socket or "",
            "primary_socket_is_ours": state.gpg_primary_socket_is_ours,
        },
        "pidfile": {
            "path": str(state.pidfile_path),
            "exists": state.pidfile_exists,
            "ssh_auth_sock": state.pidfile_socket or "",
            "ssh_agent_pid": state.pidfile_pid or "",
            "socket_valid": state.pidfile_socket_valid,
            "socket_reason": state.pidfile_socket_validation.reason,
            "socket_severity": state.pidfile_socket_validation.severity,
            "pid_alive": state.pidfile_pid_alive,
        },
        "inherited": {
            "ssh_auth_sock": state.inherited_socket or "",
            "ssh_agent_pid": state.inherited_pid or "",
            "socket_valid": state.inherited_socket_valid,
            "socket_reason": state.inherited_socket_validation.reason,
            "socket_severity": state.inherited_socket_validation.severity,
            "pid_alive": state.inherited_pid_alive,
        },
        "loaded_ssh_fingerprints": list(state.loaded_ssh_fingerprints),
        "permissions": {
            "keydir_path": str(state.paths.keydir),
            "keydir_exists": state.keydir_exists,
            "keydir_writable": state.keydir_writable if state.keydir_exists else False,
            "keydir_lax_perms": state.keydir_lax_perms if state.keydir_exists else False,
            "audit": [
                {"label": label, "value": value, "hint": hint} for label, value, hint, _sev in state.security_audit
            ],
        },
    }
    if state.process_listing_supported:
        payload["processes"] = {
            "ssh_agent_pids": list(state.ssh_agent_pids),
            "gpg_agent_pids": list(state.gpg_agent_pids),
            "gpg_foreign_agents_present": state.gpg_foreign_agents_present,
        }
    if state.cmdline_keys or state.confallhosts:
        payload["resolved_keys"] = {
            "ssh": list(state.ssh_keys),
            "gpg": list(state.gpg_keys),
            "pkcs11": list(state.pkcs11_keys),
            "missing": list(state.missing_keys),
        }
    print(json.dumps(payload, default=str))
