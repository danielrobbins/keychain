# SPDX-License-Identifier: GPL-3.0-only
"""CLI startup behavior tests."""

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from keychain import main
from keychain.util import KeychainError
from tests.support import set_home


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
    assert (
        f"Configuration (loaded: {home / '.keychainrc'}): output.quiet=True (keychainrc)"
        in capsys.readouterr().err
    )


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


class TestKeychainErrorHandling:
    @pytest.mark.parametrize(
        ("error", "message"),
        [
            (KeychainError('gpg timed out while resolving key "ABCD1234"'), 'gpg timed out while resolving key "ABCD1234"'),
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
        monkeypatch.setattr(
            main.KeychainApp,
            "_resolve_requested_keys",
            lambda *_a, **_k: main.keys.ResolvedKeys([], [], [], [], [], [], []),
        )
        monkeypatch.setattr(main.KeychainApp, "_agent_settings", lambda *_a, **_k: (False, False))
        monkeypatch.setattr(main.KeychainApp, "_do_add", lambda *_a, **_k: 0)

    def test_default_startup_no_lax_warning_when_home_keydir_is_tight(self, tmp_path, monkeypatch, capsys):
        self._patch_default_startup(monkeypatch)
        home = tmp_path / "home"
        keydir = home / ".keychain"
        keydir.mkdir(parents=True, mode=0o700)
        seen: list[Path] = []

        def fake_lax_perms(path):
            seen.append(Path(path))
            return False

        set_home(monkeypatch, home, patch_path_home=True)
        monkeypatch.setenv("HOSTNAME", "testhost")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("keychain.paths.get_owner", lambda _path: "me")
        monkeypatch.setattr("keychain.paths.lax_perms", fake_lax_perms)

        with pytest.raises(SystemExit) as exc:
            main.main([])
        assert exc.value.code in (None, 0)
        assert seen == [keydir]
        assert "lax permissions" not in capsys.readouterr().err

    def test_default_startup_fails_when_resolved_home_keydir_is_lax(self, tmp_path, monkeypatch, capsys):
        self._patch_default_startup(monkeypatch)
        home = tmp_path / "home"
        keydir = home / ".keychain"
        keydir.mkdir(parents=True, mode=0o700)
        seen: list[Path] = []

        def fake_lax_perms(path):
            seen.append(Path(path))
            return Path(path) == keydir

        set_home(monkeypatch, home, patch_path_home=True)
        monkeypatch.setenv("HOSTNAME", "testhost")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("keychain.paths.get_owner", lambda _path: "me")
        monkeypatch.setattr("keychain.paths.lax_perms", fake_lax_perms)

        with pytest.raises(SystemExit) as exc:
            main.main([])
        assert exc.value.code == 1
        assert seen == [keydir]
        assert "lax permissions" in capsys.readouterr().err
