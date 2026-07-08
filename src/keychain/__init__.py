# keychain - Manager for ssh-agent, gpg-agent and private keys
# Copyright 2026 Daniel Robbins
# SPDX-License-Identifier: GPL-3.0-only
"""Python-native keychain implementation.

The package exposes :func:`keychain.main.main` as its entry point. The
``keychain`` console-script (declared in ``pyproject.toml``) and ``python -m
keychain`` both invoke that single coordinator.
"""

from __future__ import annotations

import sys

# Hard floor: Python 3.9. Enforced before any other import so the message is
# the first thing the user sees regardless of which entry point they hit. The
# guard intentionally fires for runtimes BELOW the supported floor; ruff's
# UP036 wants this removed because the package metadata also enforces 3.9, but
# users running ``./keychain.pyz`` under an older system python never hit pip.
if sys.version_info < (3, 9):  # noqa: UP036
    sys.stderr.write(
        f"keychain requires Python 3.9 or newer "
        f"(you are running {sys.version.split()[0]}).\n"
        "  RHEL 8 / Rocky 8 :  dnf module install python39\n"
        "  Ubuntu 20.04     :  apt install python3.9 "
        "(or use the deadsnakes PPA)\n"
        "Then re-run keychain under the newer interpreter, e.g.:\n"
        "  python3.9 keychain.pyz ...\n"
    )
    sys.exit(2)

from importlib.metadata import PackageNotFoundError, version  # noqa: E402
from importlib.resources import files  # noqa: E402
from pathlib import Path  # noqa: E402

__all__ = ["__version__"]


def _resolve_version() -> str:
    # 1. Prefer a VERSION file co-located with the package.
    #
    # This is what gets bundled into ``keychain.pyz`` (see the Makefile),
    # so the zipapp always reports the version of the source tree it was
    # built from -- never a stale value from an unrelated ``keychain``
    # package that happens to be installed system-wide.
    try:
        text = files(__package__ or "keychain").joinpath("VERSION").read_text(encoding="utf-8").strip()
        if text:
            return text
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        pass
    # 2. Fall back to the VERSION file at the source-tree root (running
    # uninstalled from a checkout, e.g. ``python -m keychain``). This must
    # come before installed-package metadata so a development checkout is not
    # shadowed by an older ``keychain`` installed in the active environment.
    here = Path(__file__).resolve()
    for parent in (here.parent, *here.parents):
        candidate = parent / "VERSION"
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8").strip() or "0.0.0"
    # 3. Fall back to installed-package metadata (pip install ., wheels, ...).
    try:
        return version("keychain")
    except PackageNotFoundError:
        pass
    return "0.0.0"


__version__ = _resolve_version()
