# SPDX-License-Identifier: GPL-3.0-only
"""CLI startup behavior tests."""

import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from keychain import agents, main
from keychain.paths import KeychainPaths
from keychain.util import KeychainError
from tests.support import set_file_stat, set_home


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX file ownership")
@pytest.mark.parametrize("action", [["add", "--noask", "--eval"], ["env"], ["agent", "stop"]])
@pytest.mark.parametrize("failure", ["exit", "launch", "malformed", "empty"])
def test_failed_discovery_preserves_agent_reference(tmp_path, monkeypatch, capsys, action, failure):
    set_home(monkeypatch, tmp_path, patch_path_home=True)
    monkeypatch.delenv("KEYCHAIN_CONFIG", raising=False)
    monkeypatch.delenv("KEYCHAIN_SSH_AGENT_ARGS", raising=False)
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    monkeypatch.delenv("SSH_AGENT_PID", raising=False)
    paths = KeychainPaths.build(str(tmp_path / ".keychain"), True, "test")
    paths.keydir.mkdir(mode=0o700)
    pidfile = paths.pidfile_path("sh")
    contents = "SSH_AUTH_SOCK=/test.sock; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=123; export SSH_AGENT_PID;\n"
    pidfile.write_text(contents)
    pidfile.chmod(0o600)
    monkeypatch.setattr(main.platform, "_cached", main.platform._classify("cygwin", has_ps=True))
    monkeypatch.setattr(agents, "validate_ssh_socket", lambda sock: agents.SocketValidation(sock, True))

    def fail_ps(cmd, **_kwargs):
        assert cmd == ["ps", "-e", "-l"], "must not launch a replacement agent"
        if failure == "launch":
            raise FileNotFoundError("test ps missing")
        if failure in ("malformed", "empty"):
            stdout = b"unsupported output\n" if failure == "malformed" else b""
            return SimpleNamespace(returncode=0, communicate=lambda: (stdout, b""))
        return SimpleNamespace(returncode=1, communicate=lambda: (b"", b"test ps failure"))

    monkeypatch.setattr(main.platform.subprocess, "Popen", fail_ps)
    monkeypatch.setattr(agents.os, "kill", lambda *_a: pytest.fail("must not signal an agent"))
    with pytest.raises(SystemExit) as exc:
        main.main([*action, "--nocolor", "--host", "test", "--dir", str(paths.keydir), "--absolute"])
    captured = capsys.readouterr()
    assert exc.value.code == 1
    assert "Process discovery failed" in captured.err
    if failure in ("exit", "launch"):
        assert "test ps" in captured.err
    assert "Traceback" not in captured.err
    assert captured.out.strip() == ("false;" if "--eval" in action else "")
    assert pidfile.read_text() == contents


def test_debug_reports_loaded_keychainrc_even_when_quiet(tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".keychainrc").write_text("[output]\nquiet = true\n")
    set_home(monkeypatch, home, patch_path_home=True)
    monkeypatch.setattr(
        main.platform,
        "detect",
        lambda: SimpleNamespace(supported=True, name="linux", reason=""),
    )
    monkeypatch.setattr(main.KeychainApp, "run", lambda _app: 0)

    with pytest.raises(SystemExit) as exc:
        main.main(["inspect", "--debug"])

    assert exc.value.code == 0
    assert f"Configuration (loaded: {home / '.keychainrc'}): output.quiet=True (keychainrc)" in capsys.readouterr().err


@pytest.mark.parametrize(("argv", "no_color_env"), [(["inspect", "--nocolor"], False), (["inspect"], True)])
def test_main_resolves_no_color_through_option_policy(monkeypatch, argv, no_color_env):
    if no_color_env:
        monkeypatch.setenv("NO_COLOR", "")
    seen = {}
    build = main.Output.build

    def capture_output(**kwargs):
        seen.update(kwargs)
        return build(**kwargs)

    monkeypatch.setattr(main.Output, "build", staticmethod(capture_output))
    monkeypatch.setattr(
        main.platform,
        "detect",
        lambda: SimpleNamespace(supported=True, name="linux", reason=""),
    )
    monkeypatch.setattr(main.KeychainApp, "run", lambda _app: 0)

    with pytest.raises(SystemExit):
        main.main(argv)

    assert seen["color"] is False


def test_main_uses_stdout_for_man_color_detection(monkeypatch):
    seen = {}
    build = main.Output.build

    def capture_output(**kwargs):
        seen.update(kwargs)
        return build(**kwargs)

    monkeypatch.setattr(main.Output, "build", staticmethod(capture_output))
    monkeypatch.setattr(
        main.platform,
        "detect",
        lambda: SimpleNamespace(supported=True, name="linux", reason=""),
    )
    monkeypatch.setattr(main.KeychainApp, "run", lambda _app: 0)

    with pytest.raises(SystemExit):
        main.main(["man"])

    assert seen["color_stream"] is sys.stdout


class TestKeychainErrorHandling:
    @pytest.mark.parametrize(
        ("error", "message"),
        [
            (
                KeychainError('gpg timed out while resolving key "ABCD1234"'),
                'gpg timed out while resolving key "ABCD1234"',
            ),
            (OSError(28, "No space left on device"), "No space left on device"),
            (subprocess.TimeoutExpired(["external-tool"], 3), "External command timed out after 3 seconds"),
        ],
    )
    def test_main_exits_1_without_traceback(self, monkeypatch, capsys, error, message):
        monkeypatch.setattr(
            main.platform,
            "detect",
            lambda: SimpleNamespace(supported=True, name="linux", reason=""),
        )

        def fail(_app):
            raise error

        monkeypatch.setattr(main.KeychainApp, "run", fail)

        with pytest.raises(SystemExit) as exc:
            main.main([])

        captured = capsys.readouterr()
        assert exc.value.code == 1
        assert message in captured.err
        assert "Traceback" not in captured.err


class TestKeyboardInterruptHandling:
    def test_main_exits_130_without_traceback(self, monkeypatch, capsys):
        monkeypatch.setattr(
            main.platform,
            "detect",
            lambda: SimpleNamespace(supported=True, name="linux", reason=""),
        )

        def interrupt(_app):
            raise KeyboardInterrupt

        monkeypatch.setattr(main.KeychainApp, "run", interrupt)

        with pytest.raises(SystemExit) as exc:
            main.main(["--eval"])

        captured = capsys.readouterr()
        assert exc.value.code == 130
        assert "Traceback" not in captured.err
        assert "KeyboardInterrupt" not in captured.err
        assert "false;" in captured.out


class TestDefaultStartupPermissions:
    def _patch_default_startup(self, monkeypatch):
        monkeypatch.setattr(
            main.platform,
            "detect",
            lambda: SimpleNamespace(supported=True, name="linux", reason=""),
        )
        monkeypatch.setattr("keychain.state.current_user", lambda: "me")
        monkeypatch.setattr("keychain.paths.current_uid", lambda: 1000)
        monkeypatch.setattr(
            main.KeychainApp,
            "_resolve_requested_keys",
            lambda *_a, **_k: main.keys.ResolvedKeys([], [], [], [], [], [], []),
        )
        monkeypatch.setattr(main.KeychainApp, "_do_add", lambda *_a, **_k: 0)

    def test_default_startup_no_lax_warning_when_home_keydir_is_tight(self, tmp_path, monkeypatch, capsys):
        self._patch_default_startup(monkeypatch)
        home = tmp_path / "home"
        keydir = home / ".keychain"
        keydir.mkdir(parents=True, mode=0o700)
        set_home(monkeypatch, home, patch_path_home=True)
        monkeypatch.setenv("HOSTNAME", "testhost")
        monkeypatch.chdir(tmp_path)
        set_file_stat(monkeypatch, keydir, mode=0o40700)

        with pytest.raises(SystemExit) as exc:
            main.main([])
        assert exc.value.code in (None, 0)
        assert "lax permissions" not in capsys.readouterr().err

    def test_default_startup_fails_when_resolved_home_keydir_is_lax(self, tmp_path, monkeypatch, capsys):
        self._patch_default_startup(monkeypatch)
        home = tmp_path / "home"
        keydir = home / ".keychain"
        keydir.mkdir(parents=True, mode=0o700)
        set_home(monkeypatch, home, patch_path_home=True)
        monkeypatch.setenv("HOSTNAME", "testhost")
        monkeypatch.chdir(tmp_path)
        set_file_stat(monkeypatch, keydir, mode=0o40777)

        with pytest.raises(SystemExit) as exc:
            main.main([])
        assert exc.value.code == 1
        assert "lax permissions" in capsys.readouterr().err
