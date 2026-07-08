# Keychain

Keychain manages SSH and GPG agent state for login shells, cron jobs, remote
sessions, and long-running user environments. It is a frontend to `ssh-agent`,
`ssh-add`, and `gpg-agent` that lets a user keep one useful agent per host
instead of spawning a new agent for every terminal session.

Keychain 3 is a Python rewrite of the original Bourne shell tool created by
Daniel Robbins. It preserves the single-file deployment model that made
Keychain useful for two decades, while moving the implementation to a runtime
that can be tested, audited, and extended with confidence.

For more on that decision, see
[Why Keychain 3 Uses Python](docs/python-rationale.md).

Official project page:

```text
https://kernel-seeds.org/projects/keychain/
```

Source repository:

```text
https://github.com/danielrobbins/keychain
```

## Install

Keychain 3 ships as a Python zipapp, `keychain.pyz`. The zipapp has no
third-party runtime dependencies and does not require `pip`; it only needs
Python 3.9 or newer. You can inspect the source code of the installed zipapp
by using the `unzip` command, so it is easily auditable.

Install it as `keychain` somewhere in `PATH`:

```console
sudo cp keychain.pyz /usr/local/bin/keychain
sudo chmod 755 /usr/local/bin/keychain
keychain version
```

On systems where `/usr/bin/env python3` is older than Python 3.9, the zipapp
bootstrap looks for a newer `python3.NN` on `PATH` and re-execs into it before
importing Keychain.

## Quick Start

For a Bourne-compatible shell, a typical login setup is:

```sh
eval "$(keychain add --eval ~/.ssh/id_ed25519)"
```

Keychain will start or reuse an agent, ensure the requested identity is loaded,
and write reusable environment files under `~/.keychain/` so later shells and
cron jobs can attach to the same agent.

You can also inspect the current state without changing it:

```console
keychain inspect
keychain inspect --json
```

## Command Map

Keychain 3 uses an action-oriented command surface:

```console
keychain add KEY...        start or reuse an agent and load keys
keychain env               print reusable agent environment
keychain list              list keys currently held by ssh-agent
keychain inspect           show how Keychain sees the current state
keychain agent start       start or reuse an agent
keychain agent stop        stop Keychain-managed agents
keychain wipe              remove loaded SSH/GPG keys
keychain forget KEY...     remove specific SSH keys from ssh-agent
keychain man               open the embedded manual
keychain man --list        list embedded documentation topics
```

The 2.x flat command style remains supported through an explicit compatibility
layer, so existing shell startup snippets can continue to work while users move
to the clearer 3.x commands.

## Configuration

Keychain 3 introduces `~/.keychainrc` for persistent preferences. This keeps
normal interactive configuration out of ambient shell environment variables.

Example:

```ini
[keychain]
quiet = true
lockwait = 5

[agent.ssh]
args = -t 3600

[agent.gpg]
args = --default-cache-ttl 3600
```

For the full configuration schema:

```console
keychain man topic:config
keychain man --list
```

## Explain Mode

Append `--explain` to an invocation to see how Keychain understands that
argument chain and which embedded documentation applies:

```console
keychain add --quick --eval ~/.ssh/id_ed25519 --explain
keychain --list --explain
keychain agent start --explain
```

This is useful when checking compatibility-mode invocations, new options, or
commands copied from older Keychain documentation.

## Documentation

Keychain 3 embeds its documentation:

```console
keychain help
keychain man
keychain man --list
keychain man add
keychain man topic:agents
```

Use the project page for release notes and broader project context:

```text
https://kernel-seeds.org/projects/keychain/
```

## Environment Variables

Keychain 3 ignores `KEYCHAIN_*` environment variables by default. To opt in to
legacy environment-driven behavior for a specific invocation, pass:

```console
keychain --allow-env ...
keychain -E ...
```

This gate allows `KEYCHAIN_CONFIG`, `KEYCHAIN_SSH_AGENT_ARGS`, and
`KEYCHAIN_GPG_AGENT_ARGS` to affect the run.
For normal use, prefer `~/.keychainrc`.

## Platform Notes

Keychain 3 targets POSIX-shaped systems with Python 3.9 or newer, including
Linux, macOS, BSDs, and WSL.

## License

Keychain 3.x is released under GPLv3; see `LICENSE`. Previous Keychain 2.x
releases remain under GPLv2.
