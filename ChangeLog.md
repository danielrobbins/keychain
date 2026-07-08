# ChangeLog

## 3.0.0_beta3

Third public beta of Keychain 3.x, collecting changes made after the
`3.0.0_beta2` tag.

This release focuses on feature additions and robustness. It makes Keychain
more dependable during shell startup, easier to configure,
supports smartcards or other PKCS#11-backed SSH tokens, closes
a known `.keychainrc` documentation gap, and significantly enhances
the integrated documentation and documentation rendering.

Highlights:

- **More reliable agent startup.** Keychain now keeps its managed `ssh-agent`
  socket in a stable location under `~/.keychain/` instead of depending on
  temporary `/tmp/ssh-*` paths. This helps avoid cases where the agent is
  still running but its socket directory has been cleaned up, a problem that
  showed up clearly under WSL but is not unique to it.

- **Better smartcard and hardware-token support.** You can now ask Keychain to
  load a PKCS#11 provider directly with `pkcs11:/path/to/provider.so`. This is
  useful for SSH keys stored on smartcards, security keys, and similar devices.
  This addresses issue #216.

- Improved Documentation Formatting. Significant improvements in the
  embedded documentation renderer used by `keychain man`. Pager support
  integrated. Supported .keychainrc config settings are now fully
  documented, streamlined and available. Addresses issue #217.

- **Improved 2.9.8 compatibility details.** A few legacy command-line edge
  cases with `--stop` and `--wipe` now print a more accurate error message.

- Copyright has been updated to reflect assignment/ownership by Daniel
  Robbins, the person, removing reference to BreezyOps / Funtoo Solutions,
  Inc.

## 3.0.0_beta2

Second public beta of Keychain 3.x, collecting all changes made after the
`3.0.0_beta1` tag.

This release transforms the multi-terminal experience and strengthens GPG key
handling. The headline feature is a coordinated unlock protocol that eliminates
the frustrating "could not acquire lock" errors when multiple shells start
simultaneously -- a common occurrence when Visual Studio Code reconnects to
WSL and restores several terminals at once.

Highlights:

- **Coordinated multi-terminal initialization (solves issue #214).** Keychain
  now uses an elegant coordination protocol instead of the classic lock-timeout
  race. When multiple terminals detect missing SSH keys:

  - All terminals display: `Press Enter to initialize keys`
  - Pressing Enter in *any* terminal runs `ssh-add` in that terminal
  - Other terminals wait automatically and are notified when initialization completes
  - Waiting terminals print `Keys initialized by another terminal.` and configure
    their environment without prompting

  This eliminates the `could not acquire lock` errors that plagued earlier
  versions. The technical implementation uses a short-lived state lock for
  metadata updates, a dedicated activation lock to elect the loader, and FIFO
  endpoints for instant kernel-level notification (no polling). A takeover
  mechanism allows any waiting terminal to cancel a stuck `ssh-add` by typing
  `takeover`, ensuring you're never blocked by a hidden or inaccessible prompt.
  Internal coordination is quiet -- no more `Waiting N seconds for lock...`
  messages during interactive key loading.

- **Improved startup and key-loading output.**
  - Multi-key `ssh-add` prompts render as compact lists instead of long inline
    messages
  - Common stale pidfile/socket cases (especially in WSL restart scenarios) are
    folded into the `Starting ssh-agent...` context instead of producing
    separate noisy notes
  - Empty `gpg-agent` wipe diagnostics no longer render awkward `(output: )`
    text; non-actionable no-agent details are debug output
  - Successful remote initialization is reported as `Keys initialized by another
    terminal.`

- **Reliable GPG warm-up with explicit verification.** The `gpge:KEYID` and
  `gpga:KEYID` extended key syntax now perform a complete encrypt-then-decrypt
  verification cycle instead of relying on signing warm-up side effects. A tiny
  temporary payload is encrypted to the requested key and immediately decrypted
  through `gpg-agent`. If this verification cannot be completed, `add` fails
  rather than reporting success. This is significantly more reliable across
  different GnuPG versions and key configurations, where signing warm-up may
  not populate the decryption passphrase cache. The legacy `gpgk:KEYID` alias
  remains equivalent to `gpgs:KEYID` (signing warm-up only).

- **Enhanced documentation.** The embedded man page now includes comprehensive
  coverage of the coordination model (`keychain man topic:coordination`),
  updated guidance for `--lockwait` and `--no-lock` options, and clearer
  explanations of GPG warm-up guarantees. New design documents and a formal
  UX acceptance checklist support manual multi-terminal testing.

- **Focused test coverage.** New tests validate the coordination state file,
  waiter FIFO registration, activation lock handoff, takeover/cancel mechanics,
  and GPG end-to-end warm-up for both signing and encryption/decryption paths.
  Test infrastructure improvements ensure the checkout's source code is tested
  rather than any installed version, and CI coverage now includes macOS GPG
  validation.

Beta notes:

- The coordinated unlock flow applies to SSH key loading only. GPG keys use
  explicit warm-up paths (`gpgs:`, `gpge:`, `gpga:`) and do not participate
  in multi-terminal coordination.
- Terminal prompt erasing is best-effort: used on ANSI-capable terminals,
  falling back to ordinary line output when stderr is redirected, `TERM=dumb`,
  or the prompt would wrap.

## 3.0.0_beta1

Initial public beta of Keychain 3.x.

Keychain 3 is a ground-up Python 3 rewrite of Daniel Robbins' long-running
SSH/GPG agent manager. The release preserves the traditional single-file
deployment model through `keychain.pyz`, while replacing the historical
Bourne shell implementation with a tested, auditable Python package.

Highlights:

- Ships as a standalone `keychain.pyz` with no third-party runtime
  dependencies.
- Requires Python 3.9 or newer at runtime; the zipapp bootstrap can re-exec
  into a newer `python3.NN` on systems where `/usr/bin/env python3` is below
  the floor.
- Adds an action-oriented command surface such as `keychain add`,
  `keychain agent start`, `keychain agent stop`, `keychain list`,
  `keychain env`, `keychain inspect`, `keychain help`, and `keychain man`.
- Keeps keychain 2.x-style invocations working through an explicit
  compatibility layer.
- Embeds documentation in the zipapp; use `keychain man` and
  `keychain man --list` to browse it.
- Uses a default-deny model for `KEYCHAIN_*` environment variables; pass
  `--allow-env` / `-E` when legacy environment-variable behavior is desired.
- Releases under GPLv3 for the 3.x series. Keychain 2.x remains GPLv2.

Known beta notes:

- WSL login-shell startup can run keychain in a noninteractive/no-TTY context
  when invoked by automation. This may fall through to `ssh_askpass`; stale
  WSL `/tmp/ssh-*` sockets and hostname-specific pidfiles are tracked for
  follow-up polish.
