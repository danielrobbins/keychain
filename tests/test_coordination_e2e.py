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
from keychain.output.core import Output
from keychain.paths import KeychainPaths
from keychain.runtime import platform
from keychain.util import LockFile

if os.name != "nt":
    import pty

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
    ) -> Terminal:
        options = [*self.options]
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
    session.wait_until_registered(waiter)

    session.unlock(owner)
    waiter.finish()
    assert b"Enter passphrase" not in waiter.output
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
    session.wait_until_registered(waiter)
    session.unlock(owner)
    waiter.finish()
    result = session.run(["ssh-add", "-L"])
    assert result.returncode == 0, result.stderr
    loaded = {line.split()[1] for line in result.stdout.splitlines()}
    assert loaded == {key.with_suffix(".pub").read_text().split()[1] for key in (session.key, other_key)}


def test_wipe_waits_for_exclusive_access_to_real_agent(activation_session):
    session = activation_session
    owner = session.start()
    owner.expect("Enter passphrase")
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
    session.wait_until_registered(waiter)
    owner.interrupt(getattr(signal, signame))
    waiter.finish(success=False)
    session.assert_lock_available()
    assert session.state()["status"] == "failed"

    session.unlock(session.start(quiet=True))


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
    waiter.expect("Type 'takeover'")
    if damage == "remove":
        session.paths.state_file.unlink()
    else:
        session.paths.state_file.write_text("{", encoding="utf-8")

    session.unlock(owner)
    waiter.finish()


def test_orphaned_ssh_add_keeps_lock_and_notifies_on_exit(activation_session):
    session = activation_session
    owner = session.start(shell=True)
    owner.expect("Enter passphrase")
    parent = int(owner.output.split(b"KEYCHAIN_PID=", 1)[1].splitlines()[0])
    os.kill(parent, signal.SIGKILL)
    owner.expect("KEYCHAIN_EXITED")

    with ActivationLock(session.paths.activation_lockf, False, Output.silent()) as lock:
        assert not lock.acquired, "surviving ssh-add must keep the activation lock"
    waiter = session.start()
    session.wait_until_registered(waiter)
    owner.send(PASSPHRASE + "\n")
    waiter.finish()
    assert b"Enter passphrase" not in waiter.output
    session.assert_lock_available()


@pytest.mark.parametrize("quiet", [False, True])
def test_prompt_remains_visible_and_waits_for_input(activation_session, quiet):
    session = activation_session
    terminal = session.start(immediate=False, quiet=quiet)
    terminal.expect("Press Enter to initialize keys")
    assert b"Enter passphrase" not in terminal.output
    assert b"Keys need initialization" not in terminal.output
    terminal.send("\n")
    session.unlock(terminal)


def test_regular_waiter_returns_to_prompt_after_owner_is_killed(activation_session):
    session = activation_session
    owner = session.start()
    owner.expect("Enter passphrase")
    waiter = session.start(immediate=False)
    waiter.expect("Type 'takeover'")
    owner.interrupt(signal.SIGKILL)
    waiter.expect("Press Enter to initialize keys")
    assert b"Enter passphrase" not in waiter.output
    waiter.send("\n")
    session.unlock(waiter)


def test_real_takeover_reaps_first_child_and_completes_both_terminals(activation_session):
    session = activation_session
    owner = session.start()
    owner.expect("Enter passphrase")
    waiter = session.start(immediate=False)
    waiter.expect("Type 'takeover'")
    waiter.send("takeover\n")
    session.unlock(waiter)
    owner.finish()
    assert owner.output.count(b"Enter passphrase") == 1
    assert list(session.paths.waiters_dir.iterdir()) == []


def test_five_simultaneous_immediate_terminals_run_one_ssh_add(activation_session):
    session = activation_session
    terminals = [session.start(quiet=True) for _ in range(5)]
    for terminal in terminals:
        session.wait_until_registered(terminal)
    deadline = time.monotonic() + DEADLINE
    owners = []
    while not owners and time.monotonic() < deadline:
        for terminal in terminals:
            terminal.read()
        owners = [terminal for terminal in terminals if b"Enter passphrase" in terminal.output]
    assert len(owners) == 1
    session.unlock(owners[0])
    for terminal in terminals:
        terminal.finish()
    assert sum(terminal.output.count(b"Enter passphrase") for terminal in terminals) == 1


def test_parent_only_termination_reaps_child_and_notifies_failure(activation_session):
    session = activation_session
    owner = session.start(shell=True)
    owner.expect("Enter passphrase")
    parent = int(owner.output.split(b"KEYCHAIN_PID=", 1)[1].splitlines()[0])
    waiter = session.start()
    session.wait_until_registered(waiter)
    os.kill(parent, signal.SIGTERM)
    owner.expect("KEYCHAIN_EXITED")
    waiter.finish(success=False)
    session.assert_lock_available()
    session.unlock(session.start())


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
    waiter.expect("Type 'takeover'")
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
    second.expect("Type 'takeover'")
    second.send("takeover\n")
    second.expect("Enter passphrase")
    third = session.start(immediate=False)
    third.expect("Type 'takeover'")
    third.send("takeover\n")
    session.unlock(third)
    first.finish()
    second.finish()
    assert first.output.count(b"Enter passphrase") == 1
    assert second.output.count(b"Enter passphrase") == 1
