# SPDX-License-Identifier: GPL-3.0-only
"""Setuptools hook for defaults in the installed package."""

import os
import subprocess
import sys
from pathlib import Path

from setuptools.command.build_py import build_py


class BuildPy(build_py):
    def run(self) -> None:
        super().run()
        subprocess.run(
            [
                sys.executable,
                str(Path(__file__).with_name("build_defaults.py")),
                str(Path(self.build_lib) / "keychain" / "_build_defaults.py"),
                os.environ.get("KEYCHAIN_BUILD_ACTIVATION", "prompt"),
            ],
            check=True,
        )
