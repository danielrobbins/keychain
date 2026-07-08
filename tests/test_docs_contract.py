# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

from pathlib import Path

from scripts import build_doc_texts

from keychain.runtime.actions import ROOT_ACTION, Action, Option

DOC_SOURCE = Path(__file__).resolve().parents[1] / "man" / "embedded-docs.txt"


def _docs() -> dict:
    return build_doc_texts.parse_tagged_text(DOC_SOURCE.read_text(encoding="utf-8"))


def _walk_actions(action: Action = ROOT_ACTION):
    yield action
    for child in action.sub_actions.values():
        yield from _walk_actions(child)


def _options() -> list[Option]:
    seen: set[int] = set()
    out: list[Option] = []
    for action in _walk_actions():
        for opt in action.options.values():
            ident = id(opt)
            if ident in seen:
                continue
            seen.add(ident)
            out.append(opt)
    return out


def _has_doc(docs: dict, tag: str | None) -> bool:
    if not tag:
        return False
    section, _, key = tag.partition(":")
    if section == "option":
        entry = docs.get("option", {}).get(key) or docs.get("global", {}).get(key)
    else:
        entry = docs.get(section, {}).get(key)
    return bool(entry and (entry.get("short_help") or entry.get("description")))


def test_authored_action_docs_match_action_tree():
    docs = _docs()
    implemented = {action.doc_tag for action in _walk_actions() if action is not ROOT_ACTION}
    authored = {f"action:{name}" for name in docs.get("action", {})}

    assert authored == implemented


def test_authored_option_docs_match_option_metadata():
    docs = _docs()
    implemented = {opt.doc_tag.partition(":")[2] for opt in _options() if opt.doc_tag}
    authored = set(docs.get("option", {}))
    authored.update(docs.get("global", {}))

    assert authored <= implemented


def test_every_option_has_docs():
    docs = _docs()

    missing = [
        opt.option or opt.varname
        for opt in _options()
        if opt.has_docs
        if not (_has_doc(docs, opt.doc_tag) or _has_doc(docs, opt.config_doc_tag))
    ]

    assert missing == []


def test_authored_config_docs_match_config_metadata():
    docs = _docs()
    implemented = {f"{opt.config_section}.{opt.effective_config_key}" for opt in _options() if opt.config_section}
    authored = set(docs.get("config", {}))

    assert authored <= implemented


def test_every_config_key_has_docs():
    docs = _docs()

    missing = [
        f"{opt.config_section}.{opt.effective_config_key}"
        for opt in _options()
        if opt.config_section
        and opt.has_docs
        and not (_has_doc(docs, opt.doc_tag) or _has_doc(docs, opt.config_doc_tag))
    ]

    assert missing == []


def test_embedded_docs_do_not_use_pseudo_headings():
    text = DOC_SOURCE.read_text(encoding="utf-8")

    assert "\n%% @" not in text
