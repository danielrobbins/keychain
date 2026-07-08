# SPDX-License-Identifier: GPL-3.0-only
"""Tests for keychain.keys.all_host_identities (--confallhosts).

Issue #198: tilde / ${VAR} / %d / quoted args were not expanded. The fix
delegates per-host expansion to ``ssh -G`` (via ``expand_host``); these
tests verify the host-enumeration step pulls the right names out of the
config and that wildcard / negation patterns are skipped.
"""

from __future__ import annotations

import pytest

from keychain import keys


class _Out:
    def __init__(self):
        self.warnings: list[str] = []

    def warn(self, msg):
        self.warnings.append(msg)


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    (tmp_path / ".ssh").mkdir()
    return tmp_path


@pytest.fixture
def captured_hosts(monkeypatch):
    """Replace expand_host with a recorder that returns a marker key."""
    seen: list[str] = []

    def fake(h):
        seen.append(h)
        return keys.ResolvedKeys([f"/expanded/{h}"], [], [], [], [], [], [])

    monkeypatch.setattr(keys, "expand_host", fake)
    return seen


def test_no_config_warns(fake_home):
    out = _Out()
    assert keys.all_host_identities(out) == keys.ResolvedKeys([], [], [], [], [], [], [])
    assert any("No ~/.ssh/config" in w for w in out.warnings)


def test_concrete_hosts_enumerated(fake_home, captured_hosts):
    (fake_home / ".ssh" / "config").write_text(
        "Host alpha\n    IdentityFile ~/.ssh/id_alpha\nHost beta gamma\n    IdentityFile ~/.ssh/id_bg\n"
    )
    result = keys.all_host_identities(_Out())
    assert sorted(captured_hosts) == ["alpha", "beta", "gamma"]
    assert "/expanded/alpha" in result.ssh


def test_wildcards_and_negations_skipped(fake_home, captured_hosts):
    (fake_home / ".ssh" / "config").write_text(
        "Host *\n"
        "    IdentityFile ~/.ssh/id_default\n"
        "Host !badhost good.example\n"
        "    IdentityFile ~/.ssh/id_good\n"
        "Host srv?.example.com\n"
        "    IdentityFile ~/.ssh/id_srv\n"
    )
    keys.all_host_identities(_Out())
    # Only the concrete name from the mixed line should be enumerated.
    assert captured_hosts == ["good.example"]


def test_comments_and_blank_lines_ignored(fake_home, captured_hosts):
    (fake_home / ".ssh" / "config").write_text(
        "# this is a comment\n\n   # indented comment\nHost actual\n    IdentityFile ~/foo\n"
    )
    keys.all_host_identities(_Out())
    assert captured_hosts == ["actual"]


def test_case_insensitive_host_keyword(fake_home, captured_hosts):
    (fake_home / ".ssh" / "config").write_text("HOST upper\n")
    keys.all_host_identities(_Out())
    assert captured_hosts == ["upper"]


# ---------------------------------------------------------------------------
# Deterministic ordering of requested-key resolution (gap §3.5)
# ---------------------------------------------------------------------------


def test_resolve_requested_keys_is_deterministically_sorted(fake_home, monkeypatch):
    """Pidfile contents depend on key order; this test
    pins down that the result is sorted (not just deduplicated) so two
    runs against the same inputs produce byte-identical pidfiles."""

    # Stub gpg lookups to "key not found" so cmdline_keys end up missing.
    def fake_run(*a, **kw):
        class R:
            returncode = 1
            stdout = ""

        return R()

    monkeypatch.setattr(keys, "run", fake_run)

    inputs = ["zeta_key", "alpha_key", "mike_key", "bravo_key"]
    out1 = keys.resolve_requested_keys(False, False, inputs, "gpg", _Out())
    out2 = keys.resolve_requested_keys(False, False, list(reversed(inputs)), "gpg", _Out())
    assert out1 == out2
    assert out1.missing == sorted(inputs)
    # And no duplicates either.
    assert len(out1.missing) == len(set(out1.missing))


def test_resolve_requested_keys_dedupes_preserving_sort(fake_home, monkeypatch):
    def fake_run(*a, **kw):
        class R:
            returncode = 1
            stdout = ""

        return R()

    monkeypatch.setattr(keys, "run", fake_run)
    out = keys.resolve_requested_keys(False, False, ["a", "b", "a", "c", "b"], "gpg", _Out())
    assert out.missing == ["a", "b", "c"]


def test_resolve_requested_keys_skips_gpg_probe_when_disabled(fake_home, monkeypatch):
    def fail_run(*_a, **_kw):
        raise AssertionError("gpg lookup should be skipped")

    monkeypatch.setattr(keys, "run", fail_run)
    out = keys.resolve_requested_keys(False, False, ["barekey"], "gpg", _Out(), gpg_lookup=False)
    assert out == keys.ResolvedKeys([], [], [], [], [], [], ["barekey"])


def test_resolve_requested_keys_mixes_prefixed_and_bare(fake_home, monkeypatch):
    keyfile = fake_home / ".ssh" / "id_test"
    keyfile.write_text("dummy")

    def fake_run(*_a, **_kw):
        class R:
            returncode = 1
            stdout = ""

        return R()

    monkeypatch.setattr(keys, "run", fake_run)
    out = keys.resolve_requested_keys(False, False, ["sshk:id_test", "barekey", "gpgk:ABCD"], "gpg", _Out())
    assert out.ssh == [str(keyfile)]
    assert out.gpg == ["ABCD"]
    assert out.missing == ["barekey"]


def test_extended_flag_does_not_change_bare_key_resolution(fake_home, monkeypatch):
    keyfile = fake_home / ".ssh" / "id_test"
    keyfile.write_text("dummy")

    def fail_run(*_a, **_kw):
        raise AssertionError("existing SSH key should not need gpg lookup")

    monkeypatch.setattr(keys, "run", fail_run)
    out = keys.resolve_requested_keys(False, True, ["id_test"], "gpg", _Out())
    assert out == keys.ResolvedKeys([str(keyfile)], [], [], [], [], [], [])


# ---------------------------------------------------------------------------
# --extended prefix parsing (gap §3.4)
# ---------------------------------------------------------------------------


class TestExtendedPrefixParsing:
    """Direct unit tests for keys.extkey_expand. The prefixes ``sshk:``,
    ``gpgk:`` and ``host:`` are the public extended-key syntax; today only
    end-to-end coverage exists. These tests pin the per-prefix behaviour."""

    def test_sshk_prefix_resolves_path(self, fake_home):
        keyfile = fake_home / ".ssh" / "id_test"
        keyfile.write_text("dummy")
        out = _Out()
        assert keys.extkey_expand(["sshk:id_test"], out).ssh == [str(keyfile)]
        assert out.warnings == []

    def test_gpgk_prefix_kept_as_is(self):
        out = _Out()
        assert keys.extkey_expand(["gpgk:0123ABCD"], out).gpg == ["0123ABCD"]
        assert out.warnings == []

    def test_miss_prefix_warns(self):
        out = _Out()
        assert keys.extkey_expand(["miss:nope"], out) == keys.ResolvedKeys([], [], [], [], [], [], [])
        assert any("Unrecognized" in w for w in out.warnings)

    def test_host_prefix_calls_expand_host(self, monkeypatch):
        seen: list[str] = []

        def fake(h):
            seen.append(h)
            return keys.ResolvedKeys([f"/expanded/{h}"], [], [], [], [], [], [])

        monkeypatch.setattr(keys, "expand_host", fake)
        out = _Out()
        result = keys.extkey_expand(["host:bastion"], out)
        assert seen == ["bastion"]
        assert result.ssh == ["/expanded/bastion"]
        assert out.warnings == []

    def test_pkcs11_prefix_kept_as_is(self):
        out = _Out()
        assert keys.extkey_expand(["pkcs11:/usr/lib/pkcs11/opensc-pkcs11.so"], out).pkcs11 == [
            "/usr/lib/pkcs11/opensc-pkcs11.so"
        ]
        assert out.warnings == []

    def test_unknown_prefix_warns(self):
        out = _Out()
        result = keys.extkey_expand(["SSHK:capitals"], out)
        # Capitalised prefix is not the documented one and is rejected.
        assert result == keys.ResolvedKeys([], [], [], [], [], [], [])
        assert any("Unrecognized" in w for w in out.warnings)

    def test_unknown_prefix_with_no_colon_warns(self):
        out = _Out()
        result = keys.extkey_expand(["bareword"], out)
        assert result == keys.ResolvedKeys([], [], [], [], [], [], [])
        assert any("Unrecognized" in w for w in out.warnings)

    def test_empty_string_filtered_silently(self):
        out = _Out()
        assert keys.extkey_expand(["", "gpgk:x"], out).gpg == ["x"]
        assert out.warnings == []

    def test_host_with_no_identityfile_yields_nothing(self, monkeypatch):
        # ``ssh -G hostname`` returning no identityfile lines -> empty list.
        monkeypatch.setattr(keys, "expand_host", lambda h: keys.ResolvedKeys([], [], [], [], [], [], []))
        out = _Out()
        assert keys.extkey_expand(["host:no-keys.example"], out) == keys.ResolvedKeys([], [], [], [], [], [], [])
        assert out.warnings == []
