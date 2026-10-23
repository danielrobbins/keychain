# keychain — Makefile for building keychain.pyz (single-file Python executable)
#
# Prerequisites: Python 3.9+ on the build host. No other dependencies needed.
#
# Targets:
#   make precompiled-pyz - build for the interpreter selected by PYTHON
#   make keychain.pyz   — build the zipapp
#   make keychain.1     — build the man page from the embedded docs
#   make install-man   - install the man page (PREFIX, MANDIR, DESTDIR supported)
#   make clean          — remove build artifacts

V := $(shell cat VERSION)
PYTHON ?= python3
PREFIX ?= /usr/local
MANDIR ?= $(PREFIX)/share/man
INSTALL ?= install
DEFAULT_ACTIVATION ?= prompt
PYZ_INTERPRETER ?= /usr/bin/env python3
PYZ_STAGE = build/$@-stage

.PHONY : all clean install-man keychain.pyz keychain-precompiled.pyz precompiled-pyz release-artifacts

all : keychain.pyz keychain.1

src/keychain/docs/_doc_texts.json : man/embedded-docs.txt scripts/build_doc_texts.py
	"$(PYTHON)" scripts/build_doc_texts.py

keychain.1 : VERSION src/keychain/docs/_doc_texts.json $(shell find src/keychain -name '*.py')
	PYTHONPATH=src "$(PYTHON)" -m keychain man --roff > $@.tmp
	mv $@.tmp $@

install-man : keychain.1
	$(INSTALL) -d "$(DESTDIR)$(MANDIR)/man1"
	$(INSTALL) -m 644 keychain.1 "$(DESTDIR)$(MANDIR)/man1/keychain.1"

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

dist/keychain.1 : keychain.1 | dist
	cp keychain.1 dist/keychain.1

dist/SHA256SUMS : dist/keychain-$(V).pyz dist/keychain.1
	cd dist && sha256sum keychain-$(V).pyz keychain.1 > SHA256SUMS

release-artifacts : dist/keychain-$(V).pyz dist/keychain.1 dist/SHA256SUMS
	cd dist && sha256sum -c SHA256SUMS

clean :
	rm -rf dist build keychain.pyz keychain-precompiled.pyz keychain.1 keychain.1.tmp src/keychain/docs/_doc_texts.json
	find src -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
