# SPDX-License-Identifier: GPL-3.0-only
import os
import subprocess
import sys

import pytest

from keychain import docs
from keychain.output.core import Output
from keychain.runtime.config import RuntimeConfig
from keychain.util import KeychainError


class PagerProcess:
    def __init__(self, returncode=0):
        self.returncode = returncode
        self.input = None

    def communicate(self, input):
        self.input = input


def test_pager_command_parses_quoted_executable(monkeypatch):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setenv("PAGER", '"/opt/My Pager/bin/pager" --raw')

    assert docs._pager_command() == ["/opt/My Pager/bin/pager", "--raw"]


def test_pager_command_rejects_malformed_quotes(monkeypatch):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setenv("PAGER", '"unterminated')

    with pytest.raises(KeychainError, match="invalid PAGER value"):
        docs._pager_command()


def test_pager_command_defaults_to_less_without_command_options(monkeypatch):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.delenv("PAGER", raising=False)
    monkeypatch.setattr(docs.shutil, "which", lambda command: "/usr/bin/less" if command == "less" else None)

    assert docs._pager_command() == ["less"]


def test_pager_recognizes_alias_of_less(monkeypatch):
    paths = {"more": "/usr/bin/more", "less": "/usr/bin/less"}
    monkeypatch.setattr(docs.shutil, "which", paths.get)
    monkeypatch.setattr(docs.os.path, "samefile", lambda left, right: {left, right} == set(paths.values()))

    assert docs._pager_is_less("more")


def test_pager_does_not_assume_more_is_less(monkeypatch):
    paths = {"more": "/bin/more", "less": "/usr/bin/less"}
    monkeypatch.setattr(docs.shutil, "which", paths.get)
    monkeypatch.setattr(docs.os.path, "samefile", lambda _left, _right: False)

    assert not docs._pager_is_less("more")


@pytest.mark.parametrize("less", [None, ""])
def test_run_pager_defaults_less_to_raw_ansi_in_child(monkeypatch, less):
    monkeypatch.setattr(docs, "_pager_command", lambda: ["/usr/bin/less"])
    monkeypatch.setattr(docs, "_pager_is_less", lambda _command: True)
    if less is None:
        monkeypatch.delenv("LESS", raising=False)
    else:
        monkeypatch.setenv("LESS", less)
    seen = {}

    def launch(command, **kwargs):
        seen["command"] = command
        seen["env"] = kwargs["env"]
        seen["process"] = PagerProcess()
        return seen["process"]

    monkeypatch.setattr(subprocess, "Popen", launch)

    assert docs._run_pager("\x1b[31mmanual text\x1b[0m\n") == 0
    assert seen["command"] == ["/usr/bin/less"]
    assert seen["env"]["LESS"] == "-R"
    assert seen["process"].input == b"\x1b[31mmanual text\x1b[0m\n"
    assert os.environ.get("LESS") == less


def test_run_pager_preserves_explicit_less_options(monkeypatch):
    monkeypatch.setattr(docs, "_pager_command", lambda: ["less"])
    monkeypatch.setattr(docs, "_pager_is_less", lambda _command: True)
    monkeypatch.setenv("LESS", "-FS")
    seen = {}

    def launch(_command, **kwargs):
        seen["env"] = kwargs["env"]
        return PagerProcess()

    monkeypatch.setattr(subprocess, "Popen", launch)

    assert docs._run_pager("manual text\n") == 0
    assert seen["env"] is None
    assert os.environ["LESS"] == "-FS"


def test_run_pager_strips_ansi_for_unverified_pager(monkeypatch):
    monkeypatch.setattr(docs, "_pager_command", lambda: ["more"])
    monkeypatch.setattr(docs, "_pager_is_less", lambda _command: False)
    process = PagerProcess()
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)

    assert docs._run_pager("\x1b[31mmanual text\x1b[0m\n") == 0
    assert process.input == b"manual text\n"


def test_run_pager_raises_when_launch_fails(monkeypatch):
    monkeypatch.setattr(docs, "_pager_command", lambda: ["missing-pager"])

    def fail_launch(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "Popen", fail_launch)

    with pytest.raises(KeychainError, match="cannot run pager 'missing-pager'"):
        docs._run_pager("manual text\n")


def test_run_pager_returns_pager_status(monkeypatch):
    monkeypatch.setattr(docs, "_pager_command", lambda: ["pager"])
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: PagerProcess(returncode=7))

    assert docs._run_pager("manual text\n") == 7


def test_run_man_propagates_pager_status(monkeypatch, capsys):
    monkeypatch.setattr(docs, "_run_pager", lambda _text: 7)
    args = RuntimeConfig.resolve(["man"])
    out = Output.build(quiet=False, debug=False, eval_mode=False, color=False)

    assert docs.run_man(args, out) == 7
    assert "Pager exited with status 7" in capsys.readouterr().err
