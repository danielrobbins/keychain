# SPDX-License-Identifier: GPL-3.0-only
"""CLI startup behavior tests."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from keychain import main
from tests.support import set_home


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
