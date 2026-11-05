from __future__ import annotations

import os
from pathlib import Path


def set_home(monkeypatch, home: Path, *, patch_path_home: bool = False) -> None:
    """Point test home resolution at *home* across POSIX and Windows code paths."""
    if patch_path_home:
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("HOME", str(home))
    if os.name == "nt":
        monkeypatch.setenv("USERPROFILE", str(home))
        monkeypatch.delenv("HOMEDRIVE", raising=False)
        monkeypatch.delenv("HOMEPATH", raising=False)


def set_file_stat(monkeypatch, path: Path, *, uid: int = 1000, mode: int = 0o100600) -> None:
    """Model POSIX ownership/mode for one test path, including on Windows."""
    original = Path.stat

    def stat_for_path(self, *args, **kwargs):
        info = original(self, *args, **kwargs)
        if self != path:
            return info
        fields = list(info)
        fields[0], fields[4] = mode, uid
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "stat", stat_for_path)
