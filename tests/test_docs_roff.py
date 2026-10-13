# SPDX-License-Identifier: GPL-3.0-only
import re
import shutil
import subprocess
import sys

import pytest

from keychain.docs import roff

REQUESTS = frozenset({".TH", ".SH", ".SS", ".PP", ".TP", ".IP", ".RS", ".RE", ".RI", ".B", ".I", ".nf", ".fi"})

SECTION_TITLES = (
    "INTRODUCTION",
    "GLOBAL OPTIONS",
    "ACTIONS",
    "ACTION OPTIONS",
    "REFERENCE TOPICS",
    "APPENDIX",
)


@pytest.fixture(scope="module")
def page() -> str:
    return roff.render_manual(version="9.9.9", date="2026-01-01")


def test_page_opens_with_a_well_formed_header(page):
    first = page.splitlines()[0]

    assert first == '.TH KEYCHAIN 1 "2026-01-01" "keychain 9.9.9" "User Commands"'


def test_name_section_is_apropos_parseable(page):
    lines = page.splitlines()
    name_at = lines.index(".SH NAME")

    assert re.match(r"^keychain \\- \S.*", lines[name_at + 1])


def test_mandatory_sections_precede_the_manual_body(page):
    heads = [line for line in page.splitlines() if line.startswith(".SH ")]

    assert heads[:3] == [".SH NAME", ".SH SYNOPSIS", ".SH DESCRIPTION"]


def test_every_manual_section_becomes_a_heading(page):
    heads = {line[len(".SH ") :] for line in page.splitlines() if line.startswith(".SH ")}

    for title in SECTION_TITLES:
        assert title in heads
    assert "CONFIG KEYS (~/.keychainrc)" in heads


def test_option_names_use_the_minus_escape(page):
    assert "\\-\\-quiet" in page
    assert not re.search(r"(?<![\\])--quiet", page)


def test_inline_markup_survives_as_font_changes(page):
    assert page.count("\\fB") > 100
    assert page.count("\\fI") > 10


def test_each_list_item_is_its_own_paragraph(page):
    assert page.count(".IP \\(bu") > 5


def test_numbered_lists_keep_their_authored_numbering(page):
    markers = [int(num) for num in re.findall(r'^\.IP "(\d+)\." \d+$', page, flags=re.MULTILINE)]

    runs: list[list[int]] = []
    for marker in markers:
        if marker == 1:
            runs.append([])
        runs[-1].append(marker)

    assert runs, "the manual has numbered lists; none were rendered"
    for run in runs:
        assert run == list(range(1, len(run) + 1))


def test_literal_blocks_are_balanced(page):
    lines = page.splitlines()

    assert lines.count(".nf") == lines.count(".fi")
    assert lines.count(".RS 4") == lines.count(".RE")


def test_authored_text_never_starts_a_roff_request(page):
    for line in page.splitlines():
        if line.startswith((".", "'")):
            assert line.split()[0] in REQUESTS, line


def test_date_follows_source_date_epoch(monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")

    assert roff._page_date() == "2023-11-14"


def test_date_ignores_a_malformed_source_date_epoch(monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "not-a-number")

    assert re.match(r"^\d{4}-\d{2}-\d{2}$", roff._page_date())


def test_cli_emits_the_page_unpaged():
    result = subprocess.run(
        [sys.executable, "-m", "keychain", "man", "--roff"],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith(".TH KEYCHAIN 1 ")


@pytest.mark.skipif(shutil.which("groff") is None, reason="groff not installed")
def test_groff_reports_no_warnings(page, tmp_path):
    source = tmp_path / "keychain.1"
    source.write_text(page, encoding="utf-8")

    result = subprocess.run(
        ["groff", "-man", "-Tutf8", "-k", "-ww", "-z", str(source)],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0
    assert result.stderr == ""
