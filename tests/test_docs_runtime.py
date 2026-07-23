# SPDX-License-Identifier: GPL-3.0-only
import subprocess
import sys

from keychain import docs


def test_pager_command_parses_quoted_executable(monkeypatch):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setenv("PAGER", '"/opt/My Pager/bin/pager" --raw')

    assert docs._pager_command() == ["/opt/My Pager/bin/pager", "--raw"]


def test_pager_command_rejects_malformed_quotes(monkeypatch):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setenv("PAGER", '"unterminated')

    assert docs._pager_command() is None


def test_run_pager_writes_directly_when_launch_fails(monkeypatch, capsys):
    monkeypatch.setattr(docs, "_pager_command", lambda: ["missing-pager"])

    def fail_launch(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "Popen", fail_launch)

    docs._run_pager("manual text\n")

    assert capsys.readouterr().out == "manual text\n"
