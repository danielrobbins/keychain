"""Run the published startup recipes without touching the user's SSH agent."""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FISH = shutil.which("fish")


@pytest.mark.skipif(FISH is None, reason="fish is required for shell startup tests")
@pytest.mark.parametrize("document", ["README.md", "man/embedded-docs.txt"])
@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        (["-i"], ["add", "--eval", "HOME/.ssh/id_ed25519", "HOME/.ssh/id_rsa"]),
        (["-i", "-l"], ["add", "--eval", "HOME/.ssh/id_ed25519", "HOME/.ssh/id_rsa"]),
        (["-l"], ["add", "--eval", "--noask"]),
        ([], []),
    ],
)
@pytest.mark.parametrize("extra_key", [False, True], ids=["default-key", "additional-key-with-spaces"])
def test_documented_fish_startup(document, flags, expected, extra_key, tmp_path):
    text = (ROOT / document).read_text(encoding="utf-8")
    recipes = re.findall(r"```(?:fish)?\n(set KEYCHAIN_KEYS .*?\nend)\n```", text, re.DOTALL)
    assert len(recipes) == 1
    # Source the actual recipe with fish's real interactive/login flags. A
    # shell function records the invocation and supplies harmless eval output.
    recipe = tmp_path / "config.fish"
    content = recipes[0]
    if extra_key:
        content = content.replace(
            "    ~/.ssh/id_rsa\n", '    ~/.ssh/id_rsa \\\n    "work key"\n'
        )
    recipe.write_text(content, encoding="utf-8")
    script = """
function keychain
    printf '%s\\n' $argv > $CALL_LOG
    printf '%s\\n' 'set -gx KEYCHAIN_TEST_EXPORTED yes'
end
source "$RECIPE"
printf 'exported=%s\\n' "$KEYCHAIN_TEST_EXPORTED"
"""
    log = tmp_path / "calls"
    env = {
        **os.environ,
        "HOME": str(tmp_path),
        "XDG_CONFIG_HOME": str(tmp_path / "config"),
        "XDG_DATA_HOME": str(tmp_path / "data"),
        "TERM": "dumb",
        "CALL_LOG": str(log),
        "RECIPE": str(recipe),
    }
    result = subprocess.run(
        [FISH, "--no-config", *flags, "-c", script],
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    calls = log.read_text().splitlines() if log.exists() else []
    wanted = [arg.replace("HOME", str(tmp_path)) for arg in expected]
    if extra_key and "-i" in flags:
        wanted.append("work key")
    assert calls == wanted
    assert result.stdout.strip() == ("exported=yes" if expected else "exported=")
