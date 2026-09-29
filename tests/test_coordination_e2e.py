# SPDX-License-Identifier: GPL-3.0-only
"""Real terminals, encrypted keys, and processes for activation recovery tests."""

from __future__ import annotations

import contextlib
import json
import os
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from keychain.coordination import ActivationLock
from keychain.env import SshAgentRef
from keychain.output.core import THEMES, Output
from keychain.paths import KeychainPaths
from keychain.runtime import platform
from keychain.util import LockFile

if os.name != "nt":
    import fcntl
    import pty
    import struct
    import termios

pytestmark = pytest.mark.skipif(
    os.name == "nt"
    or not platform.detect().supported
    or any(shutil.which(command) is None for command in ("ssh-add", "ssh-agent", "ssh-keygen")),
    reason="activation e2e coverage requires a POSIX host with OpenSSH and terminals",
)

ROOT = Path(__file__).resolve().parents[1]
PASSPHRASE = "keychain-coordination-test-only"
DEADLINE = 8
# Establish a controlling terminal in the child without preexec_fn or a Python fork.
TERMINAL_ENTRY = (
    "import faulthandler, fcntl, runpy, signal, termios; "
    "faulthandler.register(signal.SIGUSR1); "
    "fcntl.ioctl(0, termios.TIOCSCTTY, 0); "
    "runpy.run_module('keychain', run_name='__main__')"
)


class Terminal:
    def __init__(self, command: list[str], env: dict[str, str], peers: list[Terminal]):
        self.peers = peers
        self.fd, slave = pty.openpty()
        self.resize(int(env.get("COLUMNS", "100")))
        self.output = b""
        try:
            self.proc = subprocess.Popen(
                command, env=env, stdin=slave, stdout=slave, stderr=slave, start_new_session=True
            )
        except BaseException:
            os.close(self.fd)
            raise
        finally:
            os.close(slave)

    def resize(self, columns: int) -> None:
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, columns, 0, 0))

    def read(self, timeout: float = 0.05) -> None:
        # Real terminal windows drain output even while another window has focus.
        terminals = {terminal.fd: terminal for terminal in self.peers if terminal.fd >= 0}
        for fd in select.select(list(terminals), [], [], timeout)[0]:
            try:
                terminals[fd].output += os.read(fd, 65536)
            except OSError:
                pass

    def expect(self, text: str) -> None:
        expected = text.encode()
        deadline = time.monotonic() + DEADLINE
        while expected not in self.output and time.monotonic() < deadline:
            self.read()
            if self.proc.poll() is not None:
                self.read(0)
                break
        if expected not in self.output:
            self.diagnose()
            pytest.fail(f"Never received {text!r}:\n{self.output.decode(errors='replace')}")

    def diagnose(self) -> None:
        if self.proc.poll() is None:
            with contextlib.suppress(OSError):
                os.kill(self.proc.pid, signal.SIGUSR1)
            self.read(0.2)
        result = subprocess.run(
            ["ps", "-axo", "pid=,ppid=,pgid=,stat=,command="],
            capture_output=True,
            text=True,
            timeout=DEADLINE,
            check=False,
        )
        group = str(self.proc.pid)
        print("Test terminal process group:")
        print("\n".join(line for line in result.stdout.splitlines() if group in line.split()[:3]))
        print(self.output.decode(errors="replace"))

    def send(self, text: str) -> None:
        os.write(self.fd, text.encode())

    def wait(self) -> None:
        deadline = time.monotonic() + DEADLINE
        while self.proc.poll() is None and time.monotonic() < deadline:
            self.read()
        self.read(0)
        if self.proc.poll() is None:
            self.diagnose()
            pytest.fail(f"Process did not finish:\n{self.output.decode(errors='replace')}")

    def finish(self, *, success: bool = True) -> None:
        self.wait()
        assert (self.proc.returncode == 0) == success, self.output.decode(errors="replace")

    def interrupt(self, sig: int) -> None:
        os.killpg(self.proc.pid, sig)
        self.wait()

    def close(self) -> None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(self.proc.pid, signal.SIGKILL)
        self.wait()
        os.close(self.fd)
        self.fd = -1


class ActivationSession:
    def __init__(self, home: Path):
        self.home = home
        self.paths = KeychainPaths(keydir=home / ".keychain", host="testcoord")
        self.key = home / "id_ed25519"
        self.terminals: list[Terminal] = []
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("SSH_", "KEYCHAIN_"))}
        self.env.update(HOME=str(home), PYTHONPATH=str(ROOT / "src"), LC_ALL="C", TERM="xterm-256color")
        for name in ("DISPLAY", "WAYLAND_DISPLAY"):
            self.env.pop(name, None)
        self.options = ["--host", self.paths.host, "--noinherit", "--no-color"]
        self.agent = SshAgentRef()

    def run(self, command: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(command, env=self.env, capture_output=True, text=True, timeout=DEADLINE, check=False)

    def start(
        self,
        *,
        immediate: bool = True,
        quiet: bool = False,
        shell: bool = False,
        bootstrap: str = "",
        key: Path | None = None,
        extra_options: tuple[str, ...] = (),
    ) -> Terminal:
        options = [*self.options, *extra_options]
        if immediate:
            options.append("--immediate")
        if quiet:
            options.append("--quiet")
        entry = TERMINAL_ENTRY
        if bootstrap:
            entry = entry.replace("runpy.run_module", bootstrap + "; runpy.run_module")
        if shell:
            entry = (
                "import faulthandler, fcntl, signal, subprocess, sys, termios, time; "
                "faulthandler.register(signal.SIGUSR1); "
                "fcntl.ioctl(0, termios.TIOCSCTTY, 0); "
                "p = subprocess.Popen([sys.executable, '-m', 'keychain', *sys.argv[1:]]); "
                "print('KEYCHAIN_PID=' + str(p.pid), flush=True); "
                "p.wait(); print('KEYCHAIN_EXITED', flush=True); time.sleep(60)"
            )
        terminal = Terminal([sys.executable, "-c", entry, *options, str(key or self.key)], self.env, self.terminals)
        self.terminals.append(terminal)
        return terminal

    def state(self) -> dict:
        return json.loads(self.paths.state_file.read_text(encoding="utf-8"))

    def wait_until_registered(self, terminal: Terminal) -> None:
        deadline = time.monotonic() + DEADLINE
        while time.monotonic() < deadline:
            if list(self.paths.waiters_dir.glob(f"wait.{terminal.proc.pid}.*.fifo")):
                return
            terminal.read()
        pytest.fail(f"Waiter never registered:\n{terminal.output.decode(errors='replace')}")

    def assert_lock_available(self) -> None:
        with ActivationLock(self.paths.activation_lockf, False, Output.silent()) as lock:
            assert lock.acquired, "the terminated process still holds the activation lock"

    def unlock(self, terminal: Terminal) -> None:
        terminal.expect("Enter passphrase")
        terminal.send(PASSPHRASE + "\n")
        terminal.finish()
        result = self.run(["ssh-add", "-L"])
        public_key = self.key.with_suffix(".pub").read_text(encoding="utf-8").split()[1]
        assert result.returncode == 0 and public_key in result.stdout, result.stdout + result.stderr


@pytest.fixture
def activation_session():
    # Short paths are needed on macOS; /var/tmp also avoids WSL's boot-time /tmp cleanup.
    with tempfile.TemporaryDirectory(prefix="kc-coord-", dir="/var/tmp") as directory:
        session = ActivationSession(Path(directory))
        try:
            result = session.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", PASSPHRASE, "-f", str(session.key)])
            assert result.returncode == 0, result.stderr
            result = session.run([sys.executable, "-m", "keychain", *session.options, "agent", "start"])
            # Record any spawned agent before asserting, so setup failures also clean up.
            if session.paths.pidfile_path("sh").exists():
                session.agent = SshAgentRef.from_text(session.paths.pidfile_path("sh").read_text(encoding="utf-8"))
                session.env.update(session.agent.as_dict())
            assert result.returncode == 0 and session.agent, result.stdout + result.stderr
            yield session
        finally:
            for terminal in session.terminals:
                terminal.close()
            if not session.agent and session.paths.pidfile_path("sh").exists():
                session.agent = SshAgentRef.from_text(session.paths.pidfile_path("sh").read_text(encoding="utf-8"))
                session.env.update(session.agent.as_dict())
            if session.agent:
                session.run(["ssh-agent", "-k"])


@pytest.mark.parametrize("quiet", [False, True], ids=["normal", "quiet"])
def test_immediate_recovers_after_loading_process_is_killed(activation_session, quiet):
    """#260: a new invocation must not wait forever on an abandoned loading record."""
    session = activation_session
    owner = session.start(quiet=quiet)
    owner.expect("Enter passphrase")
    owner.interrupt(signal.SIGKILL)
    session.assert_lock_available()
    assert session.state()["status"] == "loading"

    restarted = session.start(quiet=quiet)
    session.unlock(restarted)


def test_debug_log_records_real_loading_without_recording_passphrase(activation_session):
    session = activation_session
    path = session.home / "debug.log"
    session.options.extend(["--debug-log", str(path)])
    terminal = session.start(quiet=True)
    session.unlock(terminal)
    content = path.read_text()
    assert f"pid={terminal.proc.pid} tty=/dev/" in content
    assert "ssh-add started:" in content
    assert "ssh-add exited:" in content
    assert "status=0" in content
    assert PASSPHRASE not in content
    assert "PRIVATE KEY" not in content
    assert "Enter passphrase" not in content
    assert "\x1b" not in content
    assert b"ssh-add started:" not in terminal.output


def test_waiting_terminal_recovers_when_loading_process_is_killed(activation_session):
    """The owner can also disappear after another terminal has begun waiting."""
    session = activation_session
    owner = session.start()
    owner.expect("Enter passphrase")
    waiter = session.start()
    session.wait_until_registered(waiter)
    owner.interrupt(signal.SIGKILL)

    # The successor may already hold the lock by the time the killed parent is reaped.
    session.unlock(waiter)
    session.assert_lock_available()


@pytest.mark.parametrize("immediate", [True, False], ids=["immediate", "prompt"])
def test_waiter_observes_successful_loading(activation_session, immediate):
    session = activation_session
    owner = session.start()
    owner.expect("Enter passphrase")
    waiter = session.start(immediate=immediate)
    waiter.expect("Enter passphrase" if immediate else "Press Enter to move")

    session.unlock(owner)
    waiter.finish()
    assert (b"Enter passphrase" in waiter.output) == immediate
    assert session.state()["status"] == "success"
    assert list(session.paths.waiters_dir.glob("wait.*.fifo")) == []


def test_suspended_agent_does_not_block_state_lock_or_get_replaced(activation_session):
    session = activation_session
    pid = session.agent.pid_int
    assert pid is not None
    os.kill(pid, signal.SIGSTOP)
    try:
        terminal = session.start(
            bootstrap="import keychain.agents as a; query = a.ssh_l; "
            "a.ssh_l = lambda env: (print('QUERY_STARTED', flush=True), query(env))[1]"
        )
        terminal.expect("QUERY_STARTED")
        assert terminal.proc.poll() is None
        with LockFile(session.paths.state_lockf, False, 0, Output.silent()) as lock:
            assert lock.acquired
    finally:
        os.kill(pid, signal.SIGCONT)
    session.unlock(terminal)
    assert SshAgentRef.from_text(session.paths.pidfile_path("sh").read_text()) == session.agent


def test_immediate_waiter_loads_a_different_real_key(activation_session):
    session = activation_session
    other_key = session.home / "other_ed25519"
    result = session.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(other_key)])
    assert result.returncode == 0, result.stderr
    owner = session.start()
    owner.expect("Enter passphrase")
    waiter = session.start(key=other_key)
    waiter.finish()
    assert owner.proc.poll() is None
    session.unlock(owner)
    result = session.run(["ssh-add", "-L"])
    assert result.returncode == 0, result.stderr
    loaded = {line.split()[1] for line in result.stdout.splitlines()}
    assert loaded == {key.with_suffix(".pub").read_text().split()[1] for key in (session.key, other_key)}


def test_wipe_waits_for_exclusive_access_to_real_agent(activation_session):
    session = activation_session
    owner = session.start()
    owner.expect("Enter passphrase")
    second = session.start()
    second.expect("Enter passphrase")
    command = [
        sys.executable,
        "-m",
        "keychain",
        "--host",
        session.paths.host,
        "--no-color",
        "wipe",
        "--ssh",
        "--lockwait",
        "0",
    ]
    result = session.run(command)
    assert result.returncode != 0 and "activation lock" in result.stderr, result.stdout + result.stderr
    session.unlock(owner)
    second.finish()
    result = session.run(command)
    assert result.returncode == 0, result.stdout + result.stderr
    result = session.run(["ssh-add", "-l"])
    assert result.returncode == 1 and "no identities" in result.stdout.lower()


@pytest.mark.parametrize("signame", ["SIGINT", "SIGTERM", "SIGHUP"])
def test_normal_interruption_notifies_waiters_and_allows_retry(activation_session, signame):
    session = activation_session
    owner = session.start(quiet=True)
    owner.expect("Enter passphrase")
    waiter = session.start(quiet=True)
    waiter.expect("Enter passphrase")
    owner.interrupt(getattr(signal, signame))
    session.unlock(waiter)
    session.assert_lock_available()
    assert session.state()["status"] == "success"

    session.start(quiet=True).finish()


def test_completed_state_does_not_replace_agent_key_query(activation_session):
    session = activation_session
    session.unlock(session.start())
    assert session.state()["status"] == "success"
    wiped = session.run(["ssh-add", "-D"])
    assert wiped.returncode == 0, wiped.stderr

    session.unlock(session.start())


@pytest.mark.parametrize("damage", ["remove", "truncate"])
def test_waiter_recovers_if_its_registration_is_lost(activation_session, damage):
    """Losing the JSON record must not strand a terminal after keys are loaded."""
    session = activation_session
    owner = session.start()
    owner.expect("Enter passphrase")
    waiter = session.start(immediate=False)
    # This prompt is emitted after registration and after reading the active owner.
    # Observing it avoids racing the file damage against the initial registration.
    waiter.expect("Press Enter to move")
    if damage == "remove":
        session.paths.state_file.unlink()
    else:
        session.paths.state_file.write_text("{", encoding="utf-8")

    session.unlock(owner)
    waiter.finish()


@pytest.mark.parametrize("immediate", [False, True])
def test_orphaned_ssh_add_keeps_lock_and_notifies_on_exit(activation_session, immediate):
    session = activation_session
    owner = session.start(shell=True)
    owner.expect("Enter passphrase")
    parent = int(owner.output.split(b"KEYCHAIN_PID=", 1)[1].splitlines()[0])
    os.kill(parent, signal.SIGKILL)
    owner.expect("KEYCHAIN_EXITED")

    with ActivationLock(session.paths.activation_lockf, False, Output.silent()) as lock:
        assert not lock.acquired, "surviving ssh-add must keep the activation lock"
    waiter = session.start(immediate=immediate)
    waiter.expect("Enter passphrase" if immediate else "Press Enter to move")
    owner.send(PASSPHRASE + "\n")
    waiter.finish()
    assert (b"Enter passphrase" in waiter.output) == immediate
    session.assert_lock_available()


@pytest.mark.parametrize("quiet", [False, True])
def test_prompt_remains_visible_and_waits_for_input(activation_session, quiet):
    session = activation_session
    terminal = session.start(immediate=False, quiet=quiet)
    terminal.expect(" > Press Enter to run ssh-add in this terminal ")
    assert b"Enter passphrase" not in terminal.output
    assert b"Keys need initialization" not in terminal.output
    terminal.send("\n")
    session.unlock(terminal)


@pytest.mark.parametrize("columns", [30, 100], ids=["narrow", "wide"])
@pytest.mark.parametrize("active", [False, True], ids=["initial", "takeover"])
def test_prompt_glyph_and_clearing(activation_session, columns, active):
    session = activation_session
    session.options.remove("--no-color")
    session.env.pop("NO_COLOR", None)
    session.env.update(PYTHONIOENCODING="utf-8", COLUMNS=str(columns), LINES="24")
    owner = session.start(quiet=True) if active else None
    if owner:
        owner.expect("Enter passphrase")
    terminal = session.start(immediate=False, quiet=True)
    glyph = "\u25b8"
    highlighted = THEMES["modern"].render("warn", "Press Enter")
    text = "to move the passphrase request to this terminal" if active else "to run ssh-add in this terminal"
    terminal.expect(f" {glyph} {highlighted} {text} ")
    if columns == 100 and not active:
        grey = THEMES["modern"].render("dim", f"Press Enter {text}")
        assert f" {glyph} {grey} ".encode() in terminal.output
        length = len(terminal.output)
        terminal.read(0.8)
        assert len(terminal.output) == length, "animation must finish rather than repeat"
    assert b"Enter passphrase" not in terminal.output
    terminal.send("\n")
    session.unlock(terminal)
    if owner:
        owner.finish()
    assert (b"\x1b[1A\r\x1b[2K" in terminal.output) == (columns == 100)
    assert b"\x1b[?25l" not in terminal.output


@pytest.mark.parametrize("event", ["enter", "typed", "eof", "resize", "cancel", "complete"])
def test_fade_remains_interruptible(activation_session, event):
    session = activation_session
    session.options.remove("--no-color")
    session.env.pop("NO_COLOR", None)
    session.env["PYTHONIOENCODING"] = "utf-8"
    log = session.home / "prompt.log"
    owner = session.start(quiet=True) if event == "complete" else None
    if owner:
        owner.expect("Enter passphrase")
    terminal = session.start(immediate=False, quiet=True, extra_options=("--debug-log", str(log)))
    message = "to move the passphrase request to this terminal" if owner else "to run ssh-add in this terminal"
    terminal.expect(THEMES["modern"].render("dim", f"Press Enter {message}"))
    if event == "eof":
        terminal.send("\x04")
        terminal.finish(success=False)
        assert b"\x1b[1A" not in terminal.output
        assert b"Terminal closed while waiting" in terminal.output
    elif event == "cancel":
        terminal.interrupt(signal.SIGINT)
        assert termios.tcgetattr(terminal.fd)[3] & termios.ECHO
    elif owner:
        session.unlock(owner)
        terminal.finish()
        assert b"Enter passphrase" not in terminal.output
    else:
        if event == "resize":
            terminal.resize(20)
            terminal.expect(THEMES["modern"].render("warn", "Press Enter"))
        elif event == "typed":
            terminal.send("testing")
            terminal.expect("testing")
            terminal.expect(THEMES["modern"].render("warn", "Press Enter") + " to run ssh-add in this terminal ")
        terminal.send("\n")
        session.unlock(terminal)
        if event == "resize":
            assert b"\x1b[1A" not in terminal.output
    assert log.read_text().count("Press Enter") == 1


@pytest.mark.parametrize("reason", ["config", "no-echo"])
def test_static_prompt_keeps_final_color_and_accepts_enter(activation_session, reason):
    session = activation_session
    session.options.remove("--no-color")
    session.env.pop("NO_COLOR", None)
    session.env["PYTHONIOENCODING"] = "utf-8"
    bootstrap = ""
    if reason == "config":
        (session.home / ".keychainrc").write_text("[output]\nanimate = false\n")
    else:
        bootstrap = "attrs = termios.tcgetattr(0); attrs[3] &= ~termios.ECHO; termios.tcsetattr(0, termios.TCSANOW, attrs)"
    terminal = session.start(immediate=False, quiet=True, bootstrap=bootstrap)
    terminal.expect(THEMES["modern"].render("warn", "Press Enter") + " to run ssh-add in this terminal ")
    assert THEMES["modern"].render("dim", "Press Enter").encode() not in terminal.output
    terminal.send("\n")
    session.unlock(terminal)
    assert b"\x1b7" not in terminal.output
    if reason == "no-echo":
        assert b"\x1b[1A" not in terminal.output


def test_prompt_fade_does_not_replay_after_coordination_changes(activation_session):
    session = activation_session
    session.options.remove("--no-color")
    session.env.pop("NO_COLOR", None)
    session.env["PYTHONIOENCODING"] = "utf-8"
    owner = session.start(quiet=True)
    owner.expect("Enter passphrase")
    waiter = session.start(immediate=False, quiet=True)
    grey = THEMES["modern"].render("dim", "Press Enter to move the passphrase request to this terminal")
    waiter.expect(grey)
    owner.interrupt(signal.SIGKILL)
    waiter.expect(THEMES["modern"].render("warn", "Press Enter") + " to run ssh-add in this terminal ")
    assert THEMES["modern"].render("dim", "Press Enter to run ssh-add in this terminal").encode() not in waiter.output
    waiter.send("\n")
    session.unlock(waiter)


def test_regular_waiter_returns_to_prompt_after_owner_is_killed(activation_session):
    session = activation_session
    owner = session.start()
    owner.expect("Enter passphrase")
    waiter = session.start(immediate=False)
    waiter.expect("Press Enter to move")
    owner.interrupt(signal.SIGKILL)
    waiter.expect("Press Enter to run ssh-add in this terminal")
    assert b"Enter passphrase" not in waiter.output
    waiter.send("\n")
    session.unlock(waiter)


def test_real_takeover_reaps_first_child_and_completes_both_terminals(activation_session):
    session = activation_session
    owner = session.start()
    owner.expect("Enter passphrase")
    waiter = session.start(immediate=False)
    waiter.expect("Press Enter to move")
    waiter.send("\n")
    session.unlock(waiter)
    owner.finish()
    assert owner.output.count(b"Enter passphrase") == 1
    assert b"Passphrase request moved here from another terminal" in waiter.output
    assert b"Passphrase request moved to another terminal" in owner.output
    assert termios.tcgetattr(owner.fd)[3] & termios.ECHO
    assert list(session.paths.waiters_dir.iterdir()) == []


def test_five_immediate_terminals_cancel_all_redundant_prompts(activation_session):
    session = activation_session
    terminals = [session.start(quiet=True) for _ in range(5)]
    for terminal in terminals:
        terminal.expect("Enter passphrase")
    session.unlock(terminals[-1])
    for terminal in terminals:
        terminal.finish()
        assert termios.tcgetattr(terminal.fd)[3] & termios.ECHO
    assert sum(terminal.output.count(b"Enter passphrase") for terminal in terminals) == 5
    assert all(b"canceled this passphrase request" in terminal.output for terminal in terminals[:-1])
    assert list(session.paths.waiters_dir.iterdir()) == []
    session.assert_lock_available()


@pytest.mark.parametrize("quiet", [False, True])
def test_visible_immediate_terminal_finishes_hidden_prompt(activation_session, quiet):
    """The WSL/Fedora case: never provide input to the first terminal."""
    session = activation_session
    hidden = session.start(quiet=quiet)
    hidden.expect("Enter passphrase")
    visible = session.start(quiet=quiet)
    session.unlock(visible)
    hidden.finish()
    assert hidden.output.count(b"Enter passphrase") == 1
    assert b"canceled this passphrase request" in hidden.output
    assert termios.tcgetattr(hidden.fd)[3] & termios.ECHO
    assert list(session.paths.waiters_dir.iterdir()) == []


def test_enter_moves_all_concurrent_prompts_to_one_terminal(activation_session):
    session = activation_session
    hidden = [session.start(quiet=True) for _ in range(3)]
    for terminal in hidden:
        terminal.expect("Enter passphrase")
    visible = session.start(immediate=False, quiet=True)
    visible.expect("Press Enter to move")
    visible.send("\n")
    session.unlock(visible)
    for terminal in hidden:
        terminal.finish()
        assert terminal.output.count(b"Enter passphrase") == 1
    assert b"Passphrase request moved here" in visible.output
    session.assert_lock_available()


def test_simultaneous_success_reports_each_invocations_settings(activation_session):
    session = activation_session
    first = session.start(extra_options=("--confirm", "--timeout", "10"))
    first.expect("Enter passphrase")
    second = session.start(extra_options=("--timeout", "20"))
    second.expect("Enter passphrase")
    # Pause the first parent, not its ssh-add, so both additions can complete
    # before either parent can cancel the other's redundant prompt.
    os.kill(first.proc.pid, signal.SIGSTOP)
    try:
        first.send(PASSPHRASE + "\n")
        first.expect("Identity added")
        session.unlock(second)
    finally:
        os.kill(first.proc.pid, signal.SIGCONT)
    first.finish()
    assert b"confirmation required; lifetime 10 minutes" in first.output
    assert b"confirmation not required; lifetime 20 minutes" in second.output
    result = session.run(["ssh-add", "-T", str(session.key.with_suffix(".pub"))])
    assert result.returncode == 0, result.stdout + result.stderr
    session.assert_lock_available()


def test_parent_only_termination_reaps_child_and_notifies_failure(activation_session):
    session = activation_session
    owner = session.start(shell=True)
    owner.expect("Enter passphrase")
    parent = int(owner.output.split(b"KEYCHAIN_PID=", 1)[1].splitlines()[0])
    waiter = session.start()
    waiter.expect("Enter passphrase")
    os.kill(parent, signal.SIGTERM)
    owner.expect("KEYCHAIN_EXITED")
    session.unlock(waiter)
    session.assert_lock_available()
    session.start().finish()


def test_old_json_loading_flag_cannot_block_new_activation(activation_session):
    session = activation_session
    session.paths.state_file.write_text(json.dumps({"activation": {"in_progress": True}, "generation": 999}))
    session.paths.state_file.chmod(0o600)
    session.unlock(session.start())


def test_death_between_result_save_and_notification_wakes_waiter(activation_session):
    session = activation_session
    bootstrap = (
        "from keychain.coordination import ActivationCoordinator as C; import os, signal; "
        "notify = C.notify_waiters; "
        "C.notify_waiters = lambda self, attempt, status: "
        "os.kill(os.getpid(), signal.SIGKILL) if status == 'success' else notify(self, attempt, status)"
    )
    owner = session.start(bootstrap=bootstrap)
    owner.expect("Enter passphrase")
    waiter = session.start(immediate=False)
    waiter.expect("Press Enter to move")
    owner.send(PASSPHRASE + "\n")
    owner.finish(success=False)
    assert session.state()["status"] == "success"
    waiter.finish()
    assert b"Enter passphrase" not in waiter.output


def test_successive_takeovers_keep_all_three_terminals_waiting(activation_session):
    session = activation_session
    first = session.start()
    first.expect("Enter passphrase")
    second = session.start(immediate=False)
    second.expect("Press Enter to move")
    second.send("\n")
    second.expect("Enter passphrase")
    third = session.start(immediate=False)
    third.expect("Press Enter to move")
    third.send("\n")
    session.unlock(third)
    first.finish()
    second.finish()
    assert first.output.count(b"Enter passphrase") == 1
    assert second.output.count(b"Enter passphrase") == 1
