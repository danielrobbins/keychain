# Keychain 3

Keychain is an agent orchestrator for `ssh-agent` and `gpg-agent`. It gives you one coordinated, long-running agent experience per user and host, so terminals, scripts, cron jobs, and login sessions can share encrypted keys without repeatedly prompting for passphrases.

Keychain 3 is the evolution of the original Bourne shell-based tool created by Daniel Robbins in 2001. It preserves the single-file deployment model that made Keychain useful for over two decades, while adding modern capabilities: coordinated multi-terminal initialization, stable agent sockets, seamless cron and script integration, PKCS#11 hardware key support, GPG agent consolidation, hardened security defaults, and a comprehensive test suite of 450+ unit and integration tests — now written in Python and distributed as a self-contained executable zipapp with no third-party Python dependencies.

For background on the decision to rewrite Keychain in Python, see [Why Keychain 3 Uses Python](https://kernel-seeds.org/projects/keychain/why-python/).

---

## Why Keychain Exists

Before diving into Keychain, it's worth understanding **why** we're doing this. The concepts come from Daniel's original IBM developerWorks articles on OpenSSH key management.

### From Passwords to SSH Keys

The simplest way to log in to a remote system is with a password: you type a secret, the encrypted SSH session carries it to the server, and the server checks it. SSH keys use a stronger model. Instead of proving your identity by presenting the same secret to the server each time, SSH uses **public-key cryptography** (also called asymmetric cryptography):

- You generate an SSH **key pair**: one public key, one private key.
- The **public key** can be shared freely — you put it on a remote system, in `~/.ssh/authorized_keys`, which grants you access.
- Your **private key** stays on your local machine, and never leaves.
- You can then access the remote system from your local machine, **without entering a password**.

This also means:
- **No passwords sent over the network** — authentication happens via cryptographic proof
- **Stronger security** — a 4096-bit RSA key is far harder to crack than any password
- **Automation-friendly** — scripts can authenticate without storing passwords

### Why Encrypt Your Private Key?

Your private key is stored in `~/.ssh/id_ed25519` (or similar). If someone steals this file, they can impersonate you on any server that has your public key.

**The Improvement:** You encrypt the private key on disk with a passphrase. Now even if stolen, it's useless without the passphrase. It's much safer, but comes with a catch.

**The new problem:** Now the server no longer needs your login password, but your local machine still needs the passphrase that decrypts your private key. Without an agent, that passphrase is needed every time the key is used. Open a new terminal? Enter it again. Run a cron job? It cannot prompt. You *could* remove the passphrase from the private key, but then anyone who steals the file can use it.

**Enter ssh-agent:** `ssh-agent` is distributed with OpenSSH. It's a background process that holds your decrypted private key in memory. You enter the passphrase only once; `ssh-agent` caches your private key, and OpenSSH asks `ssh-agent` for it each time, instead of having to prompt *you*.

**The next problem:** `ssh-agent` is just a process with a socket. You still need to start it at the right time, publish its environment to future shells, keep scripts and cron jobs pointed at it, and avoid races when several terminals initialize at once.

**Enter Keychain:** Keychain is an agent orchestrator for `ssh-agent` and `gpg-agent`. Keychain makes that agent experience reliable in real life by handling startup, reuse, stable sockets, shell exports, cron access, and coordinated initialization across terminals.

---

## 60-Second Quick Start

Here's the fastest way to get started. Add this line to your `~/.bash_profile`, `~/.zshrc`, or equivalent:

```bash
eval "$(keychain add --eval ~/.ssh/id_ed25519)"
```

**What just happened?**

1. Keychain checks if an `ssh-agent` is already running
2. If not, it starts one for you
3. It loads your private key (prompting for the passphrase once)
4. It writes the agent's connection info to `~/.keychain/`
5. Every new shell after that reconnects automatically — **no more prompts**

**Verify it worked:**

```bash
keychain list
```

You should see your key listed. Open a new terminal and run it again — still there, no passphrase needed. Use your SSH keypair to access a remote system. No passphrase is required.

> **Note:** No configuration file needed. Keychain works perfectly with zero setup. The optional `.keychainrc` file is for advanced customization only.

---

## The Agent Problem Keychain Solves

SSH is amazing, but entering your passphrase every time you open a terminal gets old fast. The standard `ssh-agent` helps, but it has limitations:

- **One agent per login session** — open a new terminal, get a new agent, enter your passphrase again
- **Cron jobs can't find your agent** — background processes run in a different session
- **No ssh-agent coordination** — individual ssh-agent processes are not aware of each other.

**Keychain fixes all of this:**

- **One agent per host** — all terminals share the same long-running agent
- **Persistent state** — cron jobs, remote sessions, and background tasks can all reconnect
- **Multi-terminal coordination** — when VS Code restores 5 login terminals at once, they cooperate instead of duplicating effort or competing

### The Keychain Difference

```
┌─────────────────────────────────────────────────────────────┐
│  Without Keychain:                                          │
│                                                             │
│  Terminal 1 → ssh-agent (prompt)                            │
│  Terminal 2 → ssh-agent (prompt again)                      │
│  Terminal 3 → ssh-agent (prompt again)                      │
│  Cron job → no agent (fails)                                │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  With Keychain:                                             │
│                                                             │
│  Terminal 1 ─┐                                              │
│  Terminal 2 ─┼→ single ssh-agent (prompt once)              │
│  Terminal 3 ─┤    ↓                                         │
│  Cron job ───┘    all terminals reconnect automatically     │
└─────────────────────────────────────────────────────────────┘
```

---

## Installation

Keychain 3 ships as a **Python zipapp** — a single executable file with no third-party Python dependencies. It needs Python 3.9 or newer and the standard OpenSSH tools (`ssh-agent` and `ssh-add`); GPG features also require GnuPG.

### Install System-Wide

```bash
# Download from https://github.com/danielrobbins/keychain/releases
chmod +x keychain-3.0.0.pyz
sudo cp keychain-3.0.0.pyz /usr/local/bin/keychain
sudo chmod 755 /usr/local/bin/keychain

# Verify installation
keychain version
```

### Verify It's Auditable

Want to inspect the source? The zipapp is just a zip file:

```bash
unzip -l /usr/local/bin/keychain
```

No hidden dependencies, no mystery code — everything is right there.

### Platform Support

Keychain 3 is designed for POSIX-like systems with Python 3.9+ and OpenSSH, and optionally GnuPG. That includes Linux, macOS, WSL, Git Bash, the BSDs, Solaris-derived systems, and similar UNIX-like environments. Native Windows is not a supported target yet, but Windows users can run Keychain through WSL or Git Bash.

---

## A Tool That Respects Your Intelligence ⭐

Most CLI tools ask you to trust them. Keychain 3 asks you to understand it. We believe you deserve:

- **Transparency:** See exactly how the tool interprets your commands before they run
- **Visibility:** Inspect internal state when troubleshooting, not just error messages
- **Cooperation:** Work with your actual multi-terminal workflows, not idealized single-shell scenarios
- **Self-documentation:** Complete reference always available, version-matched to your installation

### 1. Multi-Terminal Coordination

When multiple terminals start simultaneously (like when VS Code reconnects to WSL, or you log in via Linux desktop or terminal login), `ssh-agent` or an ad-hoc `ssh-agent` wrapper might start multiple `ssh-agent` processes, which all need to cache your private key and prompt you for your passphrase.

**Keychain 3 is different.** All terminals cooperate:

```
Terminal 1:  [ 🔑 Press Enter to initialize keys 🔑 ]
Terminal 2:  [ 🔑 Press Enter to initialize keys 🔑 ]
Terminal 3:  [ 🔑 Press Enter to initialize keys 🔑 ]
```

Press Enter in **any** terminal. That terminal runs `ssh-add` and prompts for your passphrase. The other terminals wait automatically and are notified when complete:

```
Terminal 2:  Keys initialized by another terminal.
Terminal 3:  Keys initialized by another terminal.
```

**Stuck prompt?** Type `takeover` in any waiting terminal to cancel the stuck process and take over.

### 2. Embedded Documentation

No more hunting for man pages or browsing outdated wikis. You deserve complete reference documentation that:

```bash
keychain man              # Full manual in your pager
keychain man --list       # Index of all topics and actions
keychain man add          # Documentation for 'add' action
keychain man topic:coordination  # Multi-terminal coordination docs
```

- Is always available, even offline
- Matches your exact version
- Covers every option, config key, and concept

### 3. --explain Mode

Not sure what a command will do? You deserve to see the tool's reasoning. Append `--explain` and Keychain shows you **exactly** how it interprets your command-line, which documentation applies, and what each option does:

```bash
keychain add --quick --eval ~/.ssh/id_ed25519 --explain
```

Output shows documentation boxes for the action and every recognized option, then exits without doing anything. This is transparency in action — the tool shows its work before acting.

### 4. keychain inspect

When things go wrong, you deserve better than "trust me, it's working." `keychain inspect` gives you a complete, structured snapshot of Keychain's internal state:

```bash
keychain inspect
```

Shows:
- Platform and host detection
- Keychain and Python runtime details
- Parsed preferences and their effective sources
- Keychain-relevant environment state
- SSH and GPG tool availability
- Agent status and socket locations
- Keychain directory and pidfile state
- Ownership and permission checks
- Loaded SSH keys from the best available agent

Add `--json` for machine-readable output suitable for bug reports or automation.

> **These four features reflect a simple belief:** Tools should serve you with transparency and cooperation, not demand that you adapt to their limitations.

---

## Common Workflows

### First-Time Setup

Add to your shell startup file (`~/.bash_profile`, `~/.zshrc`, etc.):

```bash
eval "$(keychain add --eval ~/.ssh/id_ed25519)"
```

Next login: you'll be prompted once, then all subsequent shells reconnect automatically.

### Adding Another Key

Already running Keychain and want to add a second key?

```bash
keychain add ~/.ssh/id_rsa_work
```

Keychain will load the new key into the existing agent.

### Checking What's Loaded

```bash
keychain list
```

For machine-readable output:

```bash
keychain list --json
```

### Clearing All Keys

Want to flush everything from memory (agent keeps running)?

```bash
keychain wipe
```

To wipe only SSH keys: `keychain wipe --ssh`
To wipe only GPG keys: `keychain wipe --gpg`

### Using with Cron

Cron jobs can't prompt for passphrases. Source the pidfile in your script:

```bash
#!/bin/bash
. ~/.keychain/$(hostname)-sh

# Now you can use ssh/scp/rsync without prompting
rsync -avz /path/to/data user@remote:/backup/
```

If a cron job invokes Keychain directly, use `--noask` so Keychain will not try to prompt in the cron context.



---

## Configuration (Optional)

**You don't need a config file.** Keychain works great with defaults.

But if you want to customize behavior, create `~/.keychainrc`:

```ini
# ~/.keychainrc — completely optional

[output]
quiet = true
theme = modern

[agent]
timeout = 480               # Auto-expire keys after 8 hours
confirm = true              # Ask before each SSH key use

[paths]
pid_formats = sh,envfile    # Write both shell and env-file formats
```

### Most Useful Settings

| Setting | What It Does |
|---------|--------------|
| `agent.timeout = 480` | Auto-expire keys after N minutes |
| `agent.confirm = true` | Require confirmation for each SSH key use |
| `paths.pid_formats = sh,envfile` | Write both shell and env-file formats |

### Full Configuration Reference

```bash
keychain man topic:config
```

Or browse all config keys:

```bash
keychain man --list
```

---

## Advanced Features

### GPG Agent Integration

Keychain can use `gpg-agent` as your SSH agent, consolidating to one process:

```bash
# In ~/.keychainrc
[agent]
ssh_spawn_gpg = true
```

Or on the command line:

```bash
keychain add --ssh-spawn-gpg ~/.ssh/id_ed25519
```

### Hardware-Backed SSH Keys (PKCS#11)

Using a YubiKey or other PKCS#11 token?

```bash
keychain add pkcs11:/path/to/provider.so
```

Keychain will enumerate the token's keys and load the provider via `ssh-add -s`.

### systemd Integration

Need your user services to access the SSH agent?

```bash
eval "$(keychain add --eval --systemd ~/.ssh/id_ed25519)"
```

This pushes the agent environment to `systemctl --user`, making it available to all your user services.

---

## Upgrading from Keychain 2.x

**Good news:** Your existing shell snippets still work.

Keychain 3 maintains full backward compatibility with the 2.x command-line interface. Your `~/.bash_profile` line:

```bash
eval `keychain --eval --quiet id_rsa`
```

continues to work exactly as before.

**What's new:**

- The action-driven interface (`keychain add`, `keychain agent start`) is now recommended
- Multi-terminal coordination eliminates lock errors
- Embedded documentation (`keychain man`) replaces the need for external man pages
- `.keychainrc` replaces environment variables for persistent preferences

**Migration tip:** When ready, update your shell snippet to the new syntax:

```bash
# Old (still works)
eval `keychain --eval id_rsa`

# New (recommended)
eval "$(keychain add --eval ~/.ssh/id_rsa)"
```

---

## Historical Notes

Keychain was created by **Daniel Robbins** in 2001 and introduced to the world through a trilogy of IBM developerWorks articles on OpenSSH key management. These articles became the definitive introduction to SSH agent management for a generation of system administrators.

**Development timeline:**

- **2001-2003**: Original creation and maintenance by Daniel Robbins
- **2003-2007**: Maintained by Gentoo Linux developers (Seth Chandler, Mike Frysinger, Robin H. Johnson, Aron Griffis)
- **2009-2017**: Daniel resumes maintenance via Funtoo Linux project
- **2017-2025**: Various maintainers, periods of limited activity
- **2025-present**: Daniel returns as maintainer, begins Python 3 rewrite

### The IBM developerWorks Articles

Daniel's original trilogy remains valuable reading for understanding SSH key management concepts:

- [**Part 1: Understanding RSA/DSA Authentication**](https://www.funtoo.org/OpenSSH_Key_Management,_Part_1) — The cryptography basics
- [**Part 2: Introducing ssh-agent and keychain**](https://www.funtoo.org/OpenSSH_Key_Management,_Part_2) — Agent management fundamentals
- [**Part 3: Agent forwarding and improvements**](https://www.funtoo.org/OpenSSH_Key_Management,_Part_3) — Advanced workflows

For background on the Keychain 3 rewrite decision, see [Why Keychain 3 Uses Python](https://kernel-seeds.org/projects/keychain/why-python/).

**Current project home:** [kernel-seeds.org/projects/keychain](https://kernel-seeds.org/projects/keychain/)

---

## Troubleshooting

### "Could not acquire lock" Errors

**This should not happen in Keychain 3.** If you see this, you may be running an older version. Upgrade to 3.0.0 or newer for multi-terminal coordination.

### Keys Not Persisting Across Reboots

This is expected behavior. Keychain caches keys in memory (via `ssh-agent`) for security. After a reboot, you'll need to enter your passphrase once again.

### Wrong Key Loaded

Check which keys are currently loaded:

```bash
keychain list
```

To clear and reload:

```bash
keychain wipe
keychain add ~/.ssh/id_correct_key
```

### Cron Jobs Failing

Ensure your cron script sources the pidfile:

```bash
. ~/.keychain/$(hostname)-sh
```

If the cron job invokes Keychain directly, include `--noask` so it cannot block waiting for a passphrase prompt.

---

## Getting Help

- **Embedded manual:** `keychain man` or `keychain man --list`
- **Explain mode:** Append `--explain` to any command
- **Project documentation:** https://kernel-seeds.org/projects/keychain/
- **Source & issues:** https://github.com/danielrobbins/keychain
- **Discussions:** https://github.com/danielrobbins/keychain/discussions

---

## License

Keychain 3.x is released under the **GPLv3** license.

Previous Keychain 2.x releases remain under **GPLv2**.

---

*Keychain 3 — Continuing a 25-year tradition of thoughtful Unix tool design.*
Created and maintained by Daniel Robbins.
