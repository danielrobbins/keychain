# SPDX-License-Identifier: GPL-3.0-only
"""Requested-key resolution (``sshk:``, ``gpgk:``, ``host:``)."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .output.core import Output
from .util import KeychainError, dedupe_sorted, run


@dataclass
class ResolvedKeys:
    ssh: list[str] = field(default_factory=list)
    gpg: list[str] = field(default_factory=list)
    gpg_s: list[str] = field(default_factory=list)
    gpg_e: list[str] = field(default_factory=list)
    gpg_a: list[str] = field(default_factory=list)
    pkcs11: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)

    @property
    def any(self) -> bool:
        return bool(self.ssh or self.gpg or self.gpg_s or self.gpg_e or self.gpg_a or self.pkcs11)

    def labels(self) -> list[str]:
        return [*self.ssh, *self.gpg, *self.gpg_s, *self.gpg_e, *self.gpg_a, *self.pkcs11]

    def extend(self, other: ResolvedKeys) -> None:
        self.ssh.extend(other.ssh)
        self.gpg.extend(other.gpg)
        self.gpg_s.extend(other.gpg_s)
        self.gpg_e.extend(other.gpg_e)
        self.gpg_a.extend(other.gpg_a)
        self.pkcs11.extend(other.pkcs11)
        self.missing.extend(other.missing)

    def deduped(self) -> ResolvedKeys:
        return ResolvedKeys(
            ssh=dedupe_sorted(self.ssh),
            gpg=dedupe_sorted(self.gpg),
            gpg_s=dedupe_sorted(self.gpg_s),
            gpg_e=dedupe_sorted(self.gpg_e),
            gpg_a=dedupe_sorted(self.gpg_a),
            pkcs11=dedupe_sorted(self.pkcs11),
            missing=dedupe_sorted(self.missing),
        )


def all_host_identities(out: Output) -> ResolvedKeys:
    """Return resolved IdentityFiles for every Host block in ``~/.ssh/config``.

    Per-host expansion is delegated to ``ssh -G`` (via :func:`expand_host`)
    so ``~``, ``${VAR}``, ``%d``/``%u``/``%h``, quoted args, ``Match``, and
    ``Include`` are handled exactly as OpenSSH does -- no parallel parser.
    """
    config = Path.home() / ".ssh" / "config"
    if not config.is_file():
        out.warn("No ~/.ssh/config -- can't extract host identities")
        return ResolvedKeys()
    hosts: set[str] = set()
    for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or not s.lower().startswith("host "):
            continue
        for pat in s.split()[1:]:
            # Skip negations and pure wildcards: ssh -G needs a concrete name.
            if not any(c in pat for c in "*?!"):
                hosts.add(pat)
    result = ResolvedKeys()
    for h in sorted(hosts):
        result.extend(expand_host(h))
    return result


def _resolve_bare_keys(keys: list[str], gpg_prog: str, gpg_lookup: bool) -> ResolvedKeys:
    """Resolve plain command-line key names."""
    result = ResolvedKeys()
    home_ssh = Path.home() / ".ssh"
    for k in filter(None, keys):
        if Path(k).is_file():
            result.ssh.append(k)
            continue
        ssh_path = home_ssh / k
        if ssh_path.is_file():
            result.ssh.append(str(ssh_path))
            continue
        if gpg_lookup:
            try:
                r = run([gpg_prog, "--list-secret-keys", k], timeout=5)
                if r.returncode == 0:
                    result.gpg.append(k)
                    continue
            except subprocess.TimeoutExpired as exc:
                raise KeychainError(f'{gpg_prog} timed out while resolving key "{k}"') from exc
            except (FileNotFoundError, OSError):
                pass
        result.missing.append(k)
    return result


def _add_ssh_key(result: ResolvedKeys, key: str) -> None:
    home_ssh = Path.home() / ".ssh"
    path = Path(key)
    if path.is_file():
        result.ssh.append(key)
    elif (home_ssh / key).is_file():
        result.ssh.append(str(home_ssh / key))
    else:
        result.missing.append(key)


def keyf_expand(paths: list[str]) -> ResolvedKeys:
    """Resolve plain SSH key paths."""
    result = ResolvedKeys()
    for path in paths:
        _add_ssh_key(result, path)
    return result


def expand_host(hostname: str) -> ResolvedKeys:
    """Expand a ``host:`` extkey into resolved SSH keys via ``ssh -nG``."""
    try:
        r = run(["ssh", "-nG", hostname], timeout=10)
    except subprocess.TimeoutExpired as exc:
        raise KeychainError(f'ssh timed out while expanding host "{hostname}"') from exc
    except (FileNotFoundError, OSError):
        return ResolvedKeys()
    paths: list[str] = []
    for line in r.stdout.splitlines():
        if line.startswith("identityfile "):
            paths.append(line.split(None, 1)[1])
    return keyf_expand(paths)


def extkey_expand(extkeys: list[str], out: Output) -> ResolvedKeys:
    """Expand public extended-key syntax; warn on unknown prefixes."""
    result = ResolvedKeys()
    for ek in filter(None, extkeys):
        if ek.startswith("host:"):
            result.extend(expand_host(ek.removeprefix("host:")))
        elif ek.startswith("sshk:"):
            _add_ssh_key(result, ek.removeprefix("sshk:"))
        elif ek.startswith("gpgk:"):
            result.gpg.append(ek.removeprefix("gpgk:"))
        elif ek.startswith("gpgs:"):
            result.gpg_s.append(ek.removeprefix("gpgs:"))
        elif ek.startswith("gpge:"):
            result.gpg_e.append(ek.removeprefix("gpge:"))
        elif ek.startswith("gpga:"):
            result.gpg_a.append(ek.removeprefix("gpga:"))
        elif ek.startswith("pkcs11:"):
            result.pkcs11.append(ek.removeprefix("pkcs11:"))
        else:
            out.warn(
                f'Unrecognized extended key "{ek}". Should have a sshk:, gpgk:, gpgs:, gpge:, gpga:, pkcs11: or host: prefix.'
            )
    return result


def _is_extkey(key: str) -> bool:
    return key.startswith(("sshk:", "gpgk:", "gpgs:", "gpge:", "gpga:", "pkcs11:", "host:"))


def resolve_requested_keys(
    confallhosts: bool,
    extended: bool,
    cmdline_keys: list[str],
    gpg_prog: str,
    out: Output,
    *,
    gpg_lookup: bool = True,
) -> ResolvedKeys:
    result = ResolvedKeys()
    if confallhosts:
        result.extend(all_host_identities(out))
    # ``--extended`` is a compatibility no-op. Prefixes are always accepted,
    # and bare keys keep their normal SSH/GPG lookup behaviour even when mixed.
    result.extend(extkey_expand([k for k in cmdline_keys if _is_extkey(k)], out))
    result.extend(_resolve_bare_keys([k for k in cmdline_keys if not _is_extkey(k)], gpg_prog, gpg_lookup))
    return result.deduped()
