# SPDX-License-Identifier: GPL-3.0-only
"""A green VM job must include the live tests, not just parser fixtures."""

from types import SimpleNamespace

import pytest
from scripts import test_posix_vm as runner


@pytest.fixture
def vm(monkeypatch):
    monkeypatch.setattr(runner.sys, "argv", ["test_posix_vm.py", "freebsd"])
    monkeypatch.setattr(runner.sys, "platform", "freebsd14")
    monkeypatch.setattr(runner.os, "getuid", lambda: 1000, raising=False)
    monkeypatch.setattr(runner.os, "uname", lambda: "test FreeBSD", raising=False)
    monkeypatch.setattr(runner.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(runner.subprocess, "run", lambda *_a, **_kw: None)
    return monkeypatch


@pytest.mark.parametrize("missing, result, expected", [(None, 0, 0), ("long_path", 0, 1), (None, 1, 1)])
def test_requires_live_tests_to_pass(vm, missing, result, expected):
    def run(args, plugins):
        assert "tests/test_agent_lifecycle_e2e.py" in args
        names = [
            "tests/test_runtime.py::test_supported_process_list_returns_list",
            "tests/test_runtime.py::test_real_ps_discovers_agent_launched_from_long_path",
            *[f"tests/test_agent_lifecycle_e2e.py::test_agent_reuse_preserves_loaded_key[{value}]"
              for value in ("None", "20", "80")],
        ]
        for name in names:
            plugins[0].pytest_runtest_logreport(SimpleNamespace(
                when="call", passed=missing is None or missing not in name, nodeid=name,
            ))
        return result

    vm.setattr(runner.pytest, "main", run)
    assert runner.main() == expected


@pytest.mark.parametrize("uid, name", [(0, "freebsd14"), (1000, "linux")])
def test_rejects_root_or_wrong_os(vm, uid, name):
    vm.setattr(runner.os, "getuid", lambda: uid)
    vm.setattr(runner.sys, "platform", name)
    with pytest.raises(RuntimeError, match="Expected unprivileged"):
        runner.main()


def test_missing_tools_are_errors_not_skips(vm):
    vm.setattr(runner.shutil, "which", lambda _name: None)
    with pytest.raises(RuntimeError, match="Required test tool missing"):
        runner.main()
