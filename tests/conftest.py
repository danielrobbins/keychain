from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def pytest_configure() -> None:
    subprocess.run([sys.executable, str(ROOT / "scripts" / "build_doc_texts.py")], check=True)


@pytest.fixture
def short_keydir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Provide a private keydir whose socket name fits macOS sockaddr_un."""
    monkeypatch.chdir(tmp_path)
    keydir = Path("k")
    keydir.mkdir()
    return keydir
