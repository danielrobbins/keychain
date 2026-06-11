# Why Keychain 3 Uses Python

Keychain 3 is a ground-up rewrite in Python 3. For a project whose identity
for two decades was "one POSIX shell script you drop on any UNIX-like system,"
that was not a casual decision. It deserves a direct explanation.

## Why Move Off The Shell?

The 2.x series was a single, large POSIX Bourne shell script that had grown
steadily more sophisticated since the project began in 2002. It was portable
in the strictest sense: any sufficiently complete `/bin/sh` could run it. But
maintaining that portability had become a tax on every change.

Anything more expressive than the POSIX-era intersection of `sh`, `grep`,
`sed`, `awk`, `ps`, and `ls` was off-limits, even when modern GNU, BSD, macOS,
and Linux systems all supported something better. Quoting rules, the behavior
of `read`, the output format of `ps`, the flags accepted by `ls`, and the
handling of paths containing spaces all varied in subtle ways that could
surface as bug reports years after the code that triggered them was written.

Even with the help of modern tools like ShellCheck, the result was a codebase
that worked but was increasingly hostile to contribute to, hard to audit with
confidence, and effectively impossible to test in a meaningful automated way.
For a tool that handles SSH agent sockets and manages cached credentials in
users' login sessions, "hard to audit" and "hard to test" are not acceptable
long-term states.

## Why Python, And Why Now?

By 2026, Python 3 is effectively ubiquitous on the POSIX-shaped systems where
Keychain is deployed: modern Linux distributions, the BSDs, macOS, WSL, and the
homelab and infrastructure-class systems Keychain users tend to manage.

Compared to Bourne shell stitched together with POSIX command-line utilities,
Python 3 offers a dramatically more consistent, stable, and expressive
multi-platform API. Its standard library covers, with care and good defaults,
the areas where the old shell implementation had accumulated the most
platform-specific workarounds: process spawning and signaling, environment
manipulation, path and filename handling, structured text parsing, and TTY
interaction.

This rewrite is a deliberate choice by Daniel Robbins, Keychain's original
creator and current maintainer. The motivation is plain: ease ongoing
maintenance, improve auditability, enable real automated testing, and provide a
foundation solid enough to support future feature development without each new
option fighting the language it is written in.

Python makes it practical to apply software engineering practices that were
awkward or impossible in the shell version: unit and integration tests, static
type checking, linting, security scanning, and a clean separation of concerns
across a small package.

## Preserving The One-File Deployment Story

The single best property of the 2.x shell script was operational, not
technical: it was one file. You could copy it onto a system, mark it
executable, drop it in `/usr/local/bin`, and use it. No virtualenv, no `pip`,
no package-manager ceremony, and no entry-point shim.

Any rewrite that lost that property would have lost something real.

Keychain 3 preserves it by shipping as a Python zipapp: a single executable
`.pyz` file built from the `keychain` source tree and runnable on systems with
Python 3.9 or newer. The release artifact can be renamed to `keychain`, marked
executable, and dropped in `PATH` much like the historical shell script.

There is no `pip install` step for normal use. The zipapp has no third-party
runtime dependencies. The only requirement on the target system is a suitable
Python 3 interpreter.

For systems where `/usr/bin/env python3` is older than Python 3.9, the zipapp
bootstrap looks for a newer `python3.NN` on `PATH` and re-execs into it before
importing Keychain. This preserves the single-file deployment model while
still allowing Keychain 3 to use a modern Python floor.

## Why This Fits A Credential Helper

The combination of "interpreted Python" and "shipped as a zipapp" is unusually
well-aligned with what a credential helper should be.

**Inspectable on-box, with no extra tools.** A deployed `keychain` zipapp is a
zip file with a shebang. For example:

```console
unzip -p /usr/local/bin/keychain keychain/main.py
```

That shows the source for the program installed on the machine. A native
binary, by contrast, requires a different audit path before you can answer:
"what is this thing actually doing on my server right now?"

**Auditable in an emergency.** A sysadmin staring at a live incident can unpack
the `.pyz`, inspect the code, patch it locally if necessary, and keep going
without a compiler toolchain or release build environment. That is a real
operational property, and it is closely related to the property that made the
shell script trustworthy for two decades.

**A smaller trust gap between source and artifact.** A zipapp contains the
Python source that is shipped to users. There is no separate native compiler or
linker artifact between what you read in the repository and what runs on the
machine. For a tool that talks to your SSH agent, that is not just a packaging
detail; it is part of the security posture.

**Easy to wrangle.** The canonical `.pyz` file makes deployment easy for users
who need Keychain on several systems. Packagers and downstream maintainers can
still rebuild the artifact from source, carry small patches, or package the
Python project using their normal tooling.

## The Trade-Off

The trade-off is honest: starting Python costs more than starting `sh`.
Depending on the system, Keychain 3 may pay roughly an extra 80-200 ms of
interpreter startup time.

For a tool that runs at login, from shell startup, or from cron rather than in
a tight inner loop, that cost is worth what it buys in maintainability,
testability, auditability, and the ability to keep moving the project forward.
