# keychain — Makefile for building keychain.pyz (single-file Python executable)
#
# Prerequisites: Python 3.9+ on the build host. No other dependencies needed.
#
# Targets:
#   make precompiled-pyz - build for the interpreter selected by PYTHON
#   make keychain.pyz   — build the zipapp
#   make clean          — remove build artifacts

V := $(shell cat VERSION)
PYTHON ?= python3
DEFAULT_ACTIVATION ?= prompt
PYZ_INTERPRETER ?= /usr/bin/env python3
PYZ_STAGE = build/$@-stage

.PHONY : all clean keychain.pyz keychain-precompiled.pyz precompiled-pyz release-artifacts

all : keychain.pyz

src/keychain/docs/_doc_texts.json : man/embedded-docs.txt scripts/build_doc_texts.py
	"$(PYTHON)" scripts/build_doc_texts.py

precompiled-pyz : keychain-precompiled.pyz

keychain-precompiled.pyz : PYZ_INTERPRETER = $(shell "$(PYTHON)" -c 'import sys; print(sys.executable)')
keychain-precompiled.pyz : PYZ_COMPILE = "$(PYTHON)" -m compileall -q -b -o 0 --invalidation-mode checked-hash -s "$(PYZ_STAGE)" "$(PYZ_STAGE)"

keychain.pyz keychain-precompiled.pyz : Makefile $(shell find src/keychain -name '*.py') src/keychain/docs/_doc_texts.json man/embedded-docs.txt scripts/build_doc_texts.py VERSION scripts/pyz_bootstrap.py scripts/build_defaults.py
	rm -rf "$(PYZ_STAGE)"
	mkdir -p "$(PYZ_STAGE)"
	cp -r src/keychain "$(PYZ_STAGE)/"
	cp VERSION "$(PYZ_STAGE)/keychain/VERSION"
	find "$(PYZ_STAGE)" -name __pycache__ -type d -prune -exec rm -rf {} +
	find "$(PYZ_STAGE)" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
	cp scripts/pyz_bootstrap.py "$(PYZ_STAGE)/__main__.py"
	"$(PYTHON)" scripts/build_defaults.py "$(PYZ_STAGE)/keychain/_build_defaults.py" "$(DEFAULT_ACTIVATION)"
	$(PYZ_COMPILE)
	"$(PYTHON)" -m zipapp "$(PYZ_STAGE)" -o "$@" -p '$(PYZ_INTERPRETER)' -c
	chmod +x "$@"

dist :
	mkdir -p dist

dist/keychain-$(V).pyz : keychain.pyz | dist
	cp keychain.pyz dist/keychain-$(V).pyz

dist/SHA256SUMS : dist/keychain-$(V).pyz
	cd dist && sha256sum keychain-$(V).pyz > SHA256SUMS

release-artifacts : dist/keychain-$(V).pyz dist/SHA256SUMS
	cd dist && sha256sum -c SHA256SUMS

clean :
	rm -rf dist build keychain.pyz keychain-precompiled.pyz src/keychain/docs/_doc_texts.json
	find src -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
