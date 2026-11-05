#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run the native POSIX acceptance suite as the VM's unprivileged test user."""

import os
import shutil
import subprocess
import sys

import pytest


class RequiredLiveTests:
    def __init__(self):
        self.passed = set()

    def pytest_runtest_logreport(self, report):
        if report.when == "call" and report.passed:
            self.passed.add(report.nodeid)


def main():
    if not sys.platform.startswith(sys.argv[1]) or os.getuid() == 0:
        raise RuntimeError(f"Expected unprivileged {sys.argv[1]}, got {sys.platform} uid={os.getuid()}")
    print(sys.version, sys.platform, os.uname(), flush=True)
    for tool in ("ps", "ssh-agent", "ssh-add", "ssh-keygen"):
        location = shutil.which(tool)
        if location is None:
            raise RuntimeError(f"Required test tool missing: {tool}")
        print(f"{tool}: {location}", flush=True)
    subprocess.run(["ssh", "-V"], check=True)
    live = RequiredLiveTests()
    result = pytest.main([
        "-v", "--tb=short", "-rs",
        "tests/test_runtime.py", "tests/test_agent_visibility.py",
        "tests/test_cli_startup.py", "tests/test_agent_lifecycle_e2e.py",
    ], plugins=[live])
    required = {
        "tests/test_runtime.py::test_supported_process_list_returns_list",
        "tests/test_runtime.py::test_real_ps_discovers_agent_launched_from_long_path",
        *{f"tests/test_agent_lifecycle_e2e.py::test_agent_reuse_preserves_loaded_key[{value}]"
          for value in ("None", "20", "80")},
    }
    missing = required - live.passed
    if missing:
        print(f"Required live tests did not pass: {sorted(missing)}", file=sys.stderr)
    return int(result) or int(bool(missing))


if __name__ == "__main__":
    sys.exit(main())
