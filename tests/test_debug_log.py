# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from keychain.main import main
from keychain.output.core import Output
from keychain.output.debug import DebugLog
from keychain.runtime.config import RuntimeConfig
from keychain.util import KeychainError


def test_log_keeps_console_and_protocol_output_unchanged(tmp_path, capsys):
    path = tmp_path / "debug.log"
    out = Output.build(quiet=True, debug=False, eval_mode=True, color=False, debug_log=str(path))
    try:
        out.debug("selected agent")
        out.info("ordinary message")
        out.warn("a warning")
        out.write("SSH_AUTH_SOCK=/some/socket; export SSH_AUTH_SOCK;\n")
    finally:
        out.close()
    captured = capsys.readouterr()
    assert captured.out == "SSH_AUTH_SOCK=/some/socket; export SSH_AUTH_SOCK;\n"
    assert "a warning" in captured.err
    assert "selected agent" not in captured.err
    assert "ordinary message" not in captured.err
    content = path.read_text()
    assert "selected agent" in content and "ordinary message" in content
    assert "a warning" in content
    assert "SSH_AUTH_SOCK" not in content
    assert re.search(r"\d{4}-\d\d-\d\dT.*\+00:00 pid=\d+ tty=\S+ debug:", content)


def test_plain_records_append_and_escape_controls(tmp_path):
    path = tmp_path / "debug.log"
    for _ in range(2):
        log = DebugLog(str(path))
        log.write("debug", "\x1b[31mred\x1b[0m\x1b]0;title\x07\nforged\r\t\x00")
        log.close()
    lines = path.read_text().splitlines()
    assert len(lines) == 2
    assert all(line.endswith(r"debug: red\nforged\r\t\x00") for line in lines)
    assert "\x1b" not in path.read_text()


@pytest.mark.skipif(os.name == "nt", reason="POSIX file permissions")
def test_log_restricts_permissions(tmp_path):
    path = tmp_path / "debug.log"
    log = DebugLog(str(path))
    log.close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    path.chmod(0o666)
    log = DebugLog(str(path))
    log.close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX special files")
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "directory"])
def test_log_rejects_unsafe_targets(tmp_path, kind):
    original = tmp_path / "original"
    original.write_text("untouched")
    path = tmp_path / "log"
    if kind == "symlink":
        path.symlink_to(original)
    elif kind == "hardlink":
        os.link(original, path)
    elif kind == "fifo":
        os.mkfifo(path)
    else:
        path.mkdir()
    with pytest.raises(KeychainError, match="Cannot open debug log"):
        DebugLog(str(path))
    assert original.read_text() == "untouched"


@pytest.mark.skipif(os.name == "nt", reason="POSIX atomic append semantics")
def test_concurrent_records_are_complete(tmp_path):
    path = tmp_path / "debug.log"
    code = (
        "from keychain.output.debug import DebugLog; import sys; "
        "log=DebugLog(sys.argv[1]); "
        "[log.write('debug', 'entry='+str(i)) for i in range(50)]; log.close()"
    )

    def writer(_):
        return subprocess.run([sys.executable, "-c", code, str(path)], capture_output=True, check=True)

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(writer, range(4)))
    lines = path.read_text().splitlines()
    assert len(lines) == 200
    assert len({re.search(r"pid=(\d+)", line).group(1) for line in lines}) == 4
    assert all(re.search(r" debug: entry=\d+$", line) for line in lines)


def test_json_stays_separate_and_log_is_closed(tmp_path, capsys):
    path = tmp_path / "debug.log"
    with pytest.raises(SystemExit) as exit_info:
        main(["version", "--json", "--debug-log", str(path)])
    assert exit_info.value.code == 0
    captured = capsys.readouterr()
    assert captured.out.startswith("{")
    assert captured.err == ""
    assert "action=version" in path.read_text()
    path.unlink()


def test_bad_log_path_has_clear_error_and_eval_failure(tmp_path, capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--eval", "--debug-log", str(tmp_path / "missing" / "log")])
    assert exit_info.value.code == 1
    captured = capsys.readouterr()
    assert "Cannot open debug log" in captured.err
    assert captured.out == "\nfalse;\n"
    assert "Traceback" not in captured.err


def test_debug_log_parses_without_enabling_console_debug():
    args = RuntimeConfig.resolve(["add", "--debug-log", "/tmp/keychain.log"])
    assert not args.parse_error
    assert args.get_value("debug_log") == "/tmp/keychain.log"
    assert not args.get_value("debug")


def test_write_failure_is_reported_once_without_breaking_coordination(tmp_path, monkeypatch, capsys):
    log = DebugLog(str(tmp_path / "debug.log"))

    def fail(*_):
        raise OSError("disk full")

    monkeypatch.setattr(os, "write", fail)
    log.write("debug", "first")
    log.write("debug", "second")
    log.close()
    assert capsys.readouterr().err.count("Cannot write debug log") == 1
