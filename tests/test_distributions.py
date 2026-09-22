# SPDX-License-Identifier: GPL-3.0-only
"""Build and exercise distribution artifacts outside the source checkout."""

import os
import shutil
import subprocess
import sys
import tarfile
import venv
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def distribution_tree(tmp_path, monkeypatch):
    tree = tmp_path / "source"
    tree.mkdir()
    for name in ("src", "scripts", "man"):
        shutil.copytree(
            ROOT / name, tree / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", "*.egg-info")
        )
    for name in ("Makefile", "VERSION", "pyproject.toml", "MANIFEST.in", "README.md", "LICENSE"):
        shutil.copy2(ROOT / name, tree / name)
    home = tmp_path / "home"
    home.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    for name in ("PYTHONPATH", "PYTHONHOME", "KEYCHAIN_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_COLOR", "1")
    return tree


def run(argv, cwd):
    result = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout + result.stderr


@pytest.mark.skipif(os.name == "nt" or not shutil.which("make"), reason="zipapp Makefile requires POSIX tools")
def test_portable_zipapp_excludes_bytecode_and_runs(distribution_tree):
    tree = distribution_tree
    package = tree / "src" / "keychain"
    for name in ("stale.pyc", "stale.pyo", "__pycache__/stale.cpython-39.pyc"):
        path = package / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(b"stale bytecode")

    run(["make", "keychain.pyz"], tree)
    artifact = tree / "keychain.pyz"
    with zipfile.ZipFile(artifact) as archive:
        names = archive.namelist()
        assert not [name for name in names if name.endswith((".pyc", ".pyo")) or "__pycache__" in name.split("/")]
        assert "keychain/main.py" in names
        assert "keychain/docs/_doc_texts.json" in names
        assert archive.read("keychain/VERSION").decode().strip() == (tree / "VERSION").read_text().strip()

    version = (tree / "VERSION").read_text().strip()
    assert f"keychain {version}" in run([sys.executable, "-I", str(artifact), "version"], tree.parent)
    assert "--confirm" in run([sys.executable, "-I", str(artifact), "man", "--list"], tree.parent)


@pytest.mark.skipif(os.name == "nt" or not shutil.which("make"), reason="zipapp Makefile requires POSIX tools")
@pytest.mark.parametrize("override_shebang", [False, True])
def test_precompiled_zipapp_loads_bytecode(distribution_tree, override_shebang):
    tree = distribution_tree
    # A separate venv proves the build is using PYTHON, not python3 from PATH.
    builder = tree.parent / "builder"
    venv.EnvBuilder().create(builder)
    python = str(builder / "bin" / "python")
    options = [f"PYTHON={python}"]
    interpreter = sys.executable if override_shebang else python
    if override_shebang:
        options.append(f"PYZ_INTERPRETER={interpreter}")
    (tree / "src/keychain/docs/_doc_texts.json").unlink(missing_ok=True)
    run(["make", "precompiled-pyz", *options], tree)
    artifact = tree / "keychain-precompiled.pyz"
    assert artifact.read_bytes().splitlines()[0] == f"#!{interpreter}".encode()
    with zipfile.ZipFile(artifact) as archive:
        names = archive.namelist()
        sources = [name for name in names if name.endswith(".py")]
        assert "keychain/main.py" in sources
        assert all(f"{name}c" in names for name in sources)
        assert not any("__pycache__" in name for name in names)

    # Check every module, including the bootstrap, with the real ZIP importer.
    # Reject any attempt to compile source, even if the command still succeeds.
    probe = """
import sys, zipfile, zipimport
archive = sys.argv[1]
def reject_source_compilation(event, args):
    if event == 'compile' and str(args[1]).startswith(archive):
        raise RuntimeError('ZIP source compiled instead of loading bytecode: ' + str(args[1]))
sys.addaudithook(reject_source_compilation)
with zipfile.ZipFile(archive) as z:
    for name in z.namelist():
        if name.endswith('.py'):
            parent, _, leaf = name.rpartition('/')
            loader = zipimport.zipimporter(archive + '/' + parent)
            module = leaf[:-3]
            assert loader.get_filename(module).endswith('.pyc'), name
            assert loader.get_code(module) is not None, name
sys.path.insert(0, archive)
from keychain.main import main
main(['version'])
"""
    version = (tree / "VERSION").read_text().strip()
    assert f"keychain {version}" in run([python, "-I", "-c", probe, str(artifact)], tree.parent)
    assert f"keychain {version}" in run([str(artifact), "version"], tree.parent)
    assert "--confirm" in run([str(artifact), "man", "--list"], tree.parent)

    # Building the portable artifact afterwards must not inherit precompiled settings.
    run(["make", "keychain.pyz", f"PYTHON={python}"], tree)
    portable = tree / "keychain.pyz"
    assert portable.read_bytes().splitlines()[0] == b"#!/usr/bin/env python3"
    with zipfile.ZipFile(portable) as archive:
        assert not any(name.endswith(".pyc") for name in archive.namelist())


def test_standard_install_from_sdist(distribution_tree):
    tree = distribution_tree
    # The build frontend's default builds an sdist, then a wheel from that sdist.
    # Dependencies are installed with the dev extra; this test needs no network.
    run([sys.executable, "-m", "build", "--no-isolation"], tree)
    wheels = list((tree / "dist").glob("*.whl"))
    assert len(wheels) == 1
    sdists = list((tree / "dist").glob("*.tar.gz"))
    assert len(sdists) == 1
    with tarfile.open(sdists[0]) as archive:
        version_file = archive.extractfile(f"{sdists[0].name[:-7]}/VERSION")
        assert version_file is not None
        assert version_file.read() == (tree / "VERSION").read_bytes()
    with zipfile.ZipFile(wheels[0]) as archive:
        assert "keychain/docs/_doc_texts.json" in archive.namelist()

    installed = tree.parent / "installed"
    venv.EnvBuilder(with_pip=True).create(installed)
    bindir = installed / ("Scripts" if os.name == "nt" else "bin")
    python = bindir / ("python.exe" if os.name == "nt" else "python")
    command = bindir / ("keychain.exe" if os.name == "nt" else "keychain")
    run([str(python), "-m", "pip", "install", "--no-index", "--no-deps", str(wheels[0])], tree.parent)

    version = (tree / "VERSION").read_text().strip()
    assert f"keychain {version}" in run([str(command), "version"], tree.parent)
    assert f"keychain {version}" in run([str(python), "-I", "-m", "keychain", "version"], tree.parent)
    assert "--confirm" in run([str(command), "man", "--list"], tree.parent)
    assert "--confirm" in run([str(command), "add", "--help"], tree.parent)
