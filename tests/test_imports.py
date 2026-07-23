# SPDX-License-Identifier: GPL-3.0-only
"""Verify that runtime modules do not depend on accidental import order."""

import pkgutil
import subprocess
import sys

import pytest

import keychain

_MODULES = sorted(module.name for module in pkgutil.walk_packages(keychain.__path__, f"{keychain.__name__}."))


@pytest.mark.parametrize("module", _MODULES)
def test_module_imports_in_fresh_interpreter(module):
    result = subprocess.run(
        [sys.executable, "-c", f"import {module}"],
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
