# SPDX-License-Identifier: GPL-3.0-only
"""Event-driven key loading: per-attempt locks and FIFOs, with exclusive wiping."""

from __future__ import annotations

import contextlib
import errno
import json
import os
import secrets
import select
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .output.core import Output
from .paths import KeychainPaths
from .util import KeychainError, LockFile, unlink_quiet

_CHILD_TERMINATE_TIMEOUT = 5.0


@dataclass(frozen=True)
class CoordinationState:
    attempt: str = ""
    status: str = ""

    @classmethod
    def load(cls, path: Path) -> CoordinationState:
        try:
            with path.open(encoding="utf-8") as handle:
                data = json.load(handle)
        except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError):
            return cls()
        except OSError as exc:
            raise KeychainError(f"Cannot read coordination result {path}: {exc}") from exc
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Any) -> CoordinationState:
        if not isinstance(data, dict):
            return cls()
        attempt, status = data.get("attempt"), data.get("status")
        if not isinstance(attempt, str) or len(attempt) != 32 or any(c not in "0123456789abcdef" for c in attempt):
            return cls()
        if status not in ("loading", "success", "failed", "canceled"):
            return cls()
        return cls(attempt, status)

    def save(self, path: Path) -> None:
        fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"attempt": self.attempt, "status": self.status}, handle)
                handle.write("\n")
            Path(name).replace(path)
        finally:
            unlink_quiet(name)


def _open_fifo(path: Path, mode: int) -> int:
    fd = os.open(path, mode | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NOCTTY", 0))
    info = os.fstat(fd)
    if not stat.S_ISFIFO(info.st_mode) or info.st_uid != os.getuid():
        os.close(fd)
        raise OSError(errno.EINVAL, "Not an owned FIFO", str(path))
    return fd


@dataclass
class WaiterEndpoint:
    fifo_path: Path
    read_fd: int
    keepalive_fd: int
    buffer: bytes = b""

    @classmethod
    def create(cls, path: Path) -> WaiterEndpoint:
        os.mkfifo(path, mode=0o600)
        read_fd = -1
        try:
            read_fd = _open_fifo(path, os.O_RDONLY)
            return cls(path, read_fd, _open_fifo(path, os.O_WRONLY))
        except BaseException:
            if read_fd >= 0:
                os.close(read_fd)
            unlink_quiet(path)
            raise

    @staticmethod
    def send(path: Path, message: dict[str, str]) -> bool:
        try:
            fd = _open_fifo(path, os.O_WRONLY)
        except OSError as exc:
            if exc.errno == errno.ENXIO:
                with contextlib.suppress(OSError):
                    if stat.S_ISFIFO(path.lstat().st_mode):
                        unlink_quiet(path)
            return False
        try:
            # These small, fixed-field messages fit within POSIX PIPE_BUF.
            os.write(fd, (json.dumps(message) + "\n").encode())
            return True
        except OSError:
            return False
        finally:
            os.close(fd)

    def read_message(self) -> dict[str, Any]:
        while True:
            if b"\n" in self.buffer:
                raw, self.buffer = self.buffer.split(b"\n", 1)
                try:
                    value = json.loads(raw)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                if isinstance(value, dict):
                    return value
                continue
            try:
                chunk = os.read(self.read_fd, 65536)
            except BlockingIOError:
                return {}
            if not chunk:
                return {}
            self.buffer += chunk

    def cleanup(self, *, preserve_writers: bool = False) -> None:
        remove = True
        if preserve_writers and self.keepalive_fd >= 0:
            os.close(self.keepalive_fd)
            self.keepalive_fd = -1
            remove = bool(select.select([self.read_fd], [], [], 0)[0])
        for fd in (self.read_fd, self.keepalive_fd):
            with contextlib.suppress(OSError):
                os.close(fd)
        self.read_fd = self.keepalive_fd = -1
        if remove:
            unlink_quiet(self.fifo_path)


@dataclass(frozen=True)
class WaitResult:
    action: str
    message: dict[str, Any] = field(default_factory=dict)


class ActivationLock(LockFile):
    def __init__(self, path: Path, no_lock: bool, out: Output, *, shared: bool = False) -> None:
        super().__init__(path, no_lock, 0, out, shared=shared)

    def __enter__(self) -> ActivationLock:
        self.try_acquire()
        return self

    @property
    def pass_fds(self) -> tuple[int, ...]:
        return (self._fd,) if self._fd >= 0 and os.name != "nt" else ()


class ActivationCoordinator:
    def __init__(self, paths: KeychainPaths, no_lock: bool, lockwait: int, out: Output) -> None:
        self.paths, self.no_lock, self.lockwait, self.out = paths, no_lock, lockwait, out

    def state_lock(self) -> LockFile:
        return LockFile(self.paths.state_lockf, self.no_lock, self.lockwait, Output.silent())

    def activation_lock(self, *, shared: bool = False) -> ActivationLock:
        return ActivationLock(self.paths.activation_lockf, self.no_lock, self.out, shared=shared)

    def attempt_lock(self, attempt: str) -> ActivationLock:
        return ActivationLock(self.paths.waiters_dir / f"load.{attempt}.lock", self.no_lock, self.out)

    def load_state(self) -> CoordinationState:
        return CoordinationState.load(self.paths.state_file)

    def can_prompt(self) -> bool:
        if os.name == "nt":
            return False
        try:
            fd = os.open("/dev/tty", os.O_RDONLY)
        except OSError:
            return False
        os.close(fd)
        return True

    def endpoint(self, name: str) -> WaiterEndpoint:
        self.paths.waiters_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        return WaiterEndpoint.create(self.paths.waiters_dir / f"{name}.fifo")

    def create_waiter(self) -> ActivationWaiter | None:
        if self.no_lock or not hasattr(os, "mkfifo") or not self.can_prompt():
            return None
        with self.state_lock():
            return ActivationWaiter(self, self.endpoint(f"wait.{os.getpid()}.{secrets.token_hex(8)}"))

    def notify_waiters(self, attempt: str, status: str) -> None:
        for path in self.paths.waiters_dir.glob("wait.*.fifo"):
            WaiterEndpoint.send(path, {"attempt": attempt, "status": status})

    def activation(self, waiter: ActivationWaiter | None = None, *, exclusive: bool = False) -> ActivationOwner:
        return ActivationOwner(self, waiter, exclusive=exclusive)

    def observe(self, *, exclude: str = "") -> dict[str, int]:
        """Called under the state lock; each attempt's lock establishes liveness."""
        watches: dict[str, int] = {}
        attempts = {
            path.name.split(".")[1]
            for pattern in ("load.*.lock", "life.*.fifo", "cancel.*.fifo")
            for path in self.paths.waiters_dir.glob(pattern)
        }
        try:
            for attempt in sorted(attempts):
                if (
                    attempt == exclude
                    or not CoordinationState.from_dict({"attempt": attempt, "status": "loading"}).attempt
                ):
                    continue
                path = self.paths.waiters_dir / f"load.{attempt}.lock"
                with self.attempt_lock(attempt) as lock:
                    if lock.acquired:
                        unlink_quiet(
                            path,
                            self.paths.waiters_dir / f"life.{attempt}.fifo",
                            self.paths.waiters_dir / f"cancel.{attempt}.fifo",
                        )
                        continue
                watches[attempt] = _open_fifo(self.paths.waiters_dir / f"life.{attempt}.fifo", os.O_RDONLY)
                with self.attempt_lock(attempt) as lock:
                    if lock.acquired:
                        os.close(watches.pop(attempt))
                        unlink_quiet(
                            path,
                            self.paths.waiters_dir / f"life.{attempt}.fifo",
                            self.paths.waiters_dir / f"cancel.{attempt}.fifo",
                        )
        except BaseException as exc:
            for fd in watches.values():
                os.close(fd)
            if isinstance(exc, OSError):
                raise KeychainError("Key loading is locked but its lifetime notification is unavailable") from exc
            raise
        return watches


class ActivationWaiter:
    def __init__(self, coord: ActivationCoordinator, endpoint: WaiterEndpoint) -> None:
        self.coord, self.endpoint = coord, endpoint
        self.watches: dict[str, int] = {}
        self.ignore_attempt = ""
        self.pending_takeover: set[str] = set()
        self._seen: set[str] = set()

    def _close_watch(self) -> None:
        for fd in self.watches.values():
            os.close(fd)
        self.watches.clear()

    def watch(self) -> None:
        self._close_watch()
        self.watches = self.coord.observe(exclude=self.ignore_attempt)

    def cleanup(self) -> None:
        self._close_watch()
        self.endpoint.cleanup()

    def _completion(self, attempt: str) -> WaitResult:
        record = self.coord.load_state()
        status = record.status if record.attempt == attempt else "unknown"
        if status == "loading":
            status = "abandoned"
        fd = self.watches.pop(attempt, -1)
        if fd >= 0:
            os.close(fd)
        self._seen.discard(attempt)
        return WaitResult("notified", {"attempt": attempt, "status": status})

    def wait(
        self,
        *,
        immediate: bool = False,
        interactive: bool = False,
        handoff: bool = False,
        timeout: float | None = None,
        wake_fd: int | None = None,
    ) -> WaitResult:
        if handoff:
            timeout = 1.0
        deadline = None if timeout is None else time.monotonic() + timeout
        with contextlib.ExitStack() as stack:
            tty = stack.enter_context(open("/dev/tty", encoding="utf-8", errors="replace")) if interactive else None
            while True:
                with self.coord.state_lock():
                    while message := self.endpoint.read_message():
                        record = CoordinationState.from_dict(message)
                        attempt, status = record.attempt, record.status
                        if not attempt or attempt == self.ignore_attempt:
                            continue
                        if status in ("success", "failed", "canceled"):
                            self._seen.discard(attempt)
                            fd = self.watches.pop(attempt, -1)
                            if fd >= 0:
                                os.close(fd)
                            return WaitResult("notified", message)
                        self._seen.add(attempt)
                    for attempt, fd in list(self.watches.items()):
                        if select.select([fd], [], [], 0)[0]:
                            return self._completion(attempt)
                    self.watch()
                    missing = self._seen.difference(self.watches)
                    if missing:
                        return self._completion(next(iter(missing)))
                    self._seen.update(self.watches)
                    active = bool(self.watches)
                    if not active:
                        with self.coord.activation_lock(shared=True) as gate:
                            if not gate.acquired:
                                raise KeychainError(
                                    "Key loading is locked but its lifetime notification is unavailable"
                                )
                    if self.pending_takeover and not self.pending_takeover.intersection(self.watches):
                        self.pending_takeover.clear()
                        return WaitResult("activate", {"takeover": True})
                    if handoff and active:
                        # The successor is here: wait for its lifetime, not a timer.
                        deadline = None
                    if not handoff and (immediate or (not active and not interactive and timeout is None)):
                        with self.coord.activation_lock(shared=True) as gate:
                            if gate.acquired:
                                return WaitResult("activate")

                prompt = False
                if tty is not None and not handoff:
                    text = (
                        "Press Enter to move the passphrase request to this terminal"
                        if active
                        else "Press Enter to initialize keys"
                    )
                    prompt = self.coord.out.ephemeral_line(
                        self.coord.out.warn_text(
                            f"[ {self.coord.out.glyph('key')} {text} {self.coord.out.glyph('key')} ]"
                        )
                    )
                fds = [self.endpoint.read_fd, *self.watches.values()]
                if wake_fd is not None:
                    fds.append(wake_fd)
                if tty is not None and not handoff:
                    fds.append(tty.fileno())
                remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
                ready, _, _ = select.select(fds, [], [], remaining)
                if prompt:
                    self.coord.out.clear_ephemeral_line(after_input=tty.fileno() in ready if tty else False)
                if not ready:
                    return WaitResult("activate" if handoff and not active else "timeout")
                if wake_fd is not None and wake_fd in ready:
                    return WaitResult("cancel")
                if self.endpoint.read_fd in ready or any(fd in ready for fd in self.watches.values()):
                    continue
                if tty is not None:
                    line = tty.readline()
                    if not line:
                        raise KeychainError("Terminal closed while waiting to initialize keys")
                    if not active:
                        return WaitResult("activate")
                    if not line.strip():
                        return WaitResult("takeover")

    def request_takeover(self) -> WaitResult:
        with self.coord.state_lock():
            self.watch()
            if not self.watches:
                return WaitResult("activate")
            self.pending_takeover = set(self.watches)
            for attempt in self.watches:
                path = self.coord.paths.waiters_dir / f"cancel.{attempt}.fifo"
                if not WaiterEndpoint.send(path, {"status": "cancel"}):
                    self.pending_takeover.clear()
                    return WaitResult("unavailable")
        deadline = time.monotonic() + _CHILD_TERMINATE_TIMEOUT + 2.0
        while True:
            result = self.wait(timeout=max(0.0, deadline - time.monotonic()))
            if result.action != "notified":
                return result


class ActivationOwner:
    """The activation lock and lifetime writer both remain open in ssh-add."""

    def __init__(
        self, coord: ActivationCoordinator, waiter: ActivationWaiter | None, *, exclusive: bool = False
    ) -> None:
        self.coord, self.waiter = coord, waiter
        self.attempt = secrets.token_hex(16)
        self.gate = coord.activation_lock(shared=not exclusive)
        self.lock = coord.attempt_lock(self.attempt)
        self.status = "failed"
        self.life: WaiterEndpoint | None = None
        self.cancel: WaiterEndpoint | None = None
        self.proc: subprocess.Popen[bytes] | None = None
        self._stop = threading.Event()
        self._canceled = threading.Event()
        self._satisfied = threading.Event()
        self._keys_available: Callable[[], bool] | None = None
        self._thread: threading.Thread | None = None
        self._proc_lock = threading.Lock()

    @property
    def acquired(self) -> bool:
        return self.lock.acquired

    def __enter__(self) -> ActivationOwner:
        try:
            with self.coord.state_lock():
                if not self.gate.try_acquire():
                    return self
                self.coord.paths.waiters_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
                self.lock.try_acquire()
                if not self.coord.no_lock and hasattr(os, "mkfifo"):
                    for fd in self.coord.observe(exclude=self.attempt).values():
                        os.close(fd)
                    self.life = self.coord.endpoint(f"life.{self.attempt}")
                    self.cancel = self.coord.endpoint(f"cancel.{self.attempt}")
                    CoordinationState(self.attempt, "loading").save(self.coord.paths.state_file)
                    if self.waiter is not None:
                        self.waiter._close_watch()
                        self.waiter.ignore_attempt = self.attempt
                    # Every existing waiter is notified before a child can be started.
                    self.coord.notify_waiters(self.attempt, "loading")
            self.coord.out.debug(f"Activation started: attempt={self.attempt}")
            return self
        except BaseException:
            self._cleanup()
            raise

    def __exit__(self, exc_type, exc, tb) -> None:
        if not self.acquired:
            return
        if exc_type is not None:
            self.status = "failed"
        try:
            self._stop.set()
            self._cancel_child()
            if self._thread is not None:
                self._thread.join()
            with self.coord.state_lock():
                try:
                    if self.life is not None:
                        CoordinationState(self.attempt, self.status).save(self.coord.paths.state_file)
                        self.coord.notify_waiters(self.attempt, self.status)
                finally:
                    self._cleanup()
        finally:
            self._cleanup()

    def _cleanup(self) -> None:
        self.lock.release()
        self.gate.release()
        for endpoint in (self.life, self.cancel):
            if endpoint is not None:
                endpoint.cleanup(preserve_writers=endpoint is self.life)
        self.life = self.cancel = None
        if not (self.coord.paths.waiters_dir / f"life.{self.attempt}.fifo").exists():
            unlink_quiet(self.lock.path)

    @property
    def pass_fds(self) -> tuple[int, ...]:
        return self.lock.pass_fds + self.gate.pass_fds + ((self.life.keepalive_fd,) if self.life else ())

    def run_ssh_add(
        self, commands: list[list[str]], env: dict[str, str], *, keys_available: Callable[[], bool] | None = None
    ) -> str:
        self._keys_available = keys_available
        if self.cancel is not None:
            self._thread = threading.Thread(target=self._cancel_loop, name="keychain-cancel-listener", daemon=True)
            self._thread.start()
        for command in commands:
            self.status = self._run_child(command, env)
            if self.status != "success":
                break
        if self._satisfied.is_set() and self.status != "success":
            self.status = "success"
            return "satisfied"
        return self.status

    def _run_child(self, cmd: list[str], env: dict[str, str]) -> str:
        try:
            with contextlib.ExitStack() as stack:
                kwargs: dict[str, Any] = {"env": env, "close_fds": True}
                if os.name != "nt":
                    kwargs["pass_fds"] = self.pass_fds
                    try:
                        tty = stack.enter_context(open("/dev/tty", "rb+", buffering=0))
                    except OSError:
                        pass
                    else:
                        kwargs.update(stdin=tty, stdout=tty, stderr=tty)
                with self._proc_lock:
                    if self._canceled.is_set() or self._satisfied.is_set():
                        return "canceled"
                    self.proc = subprocess.Popen(cmd, **kwargs)
                self.coord.out.debug(f"ssh-add started: pid={self.proc.pid} attempt={self.attempt}")
                rc = self.proc.wait()
                self.coord.out.debug(f"ssh-add exited: pid={self.proc.pid} status={rc} attempt={self.attempt}")
        except OSError as exc:
            self.coord.out.warn(f"ssh-add failed to start: {exc}")
            return "failed"
        if rc == 0:
            return "success"
        if self._canceled.is_set() or self._satisfied.is_set():
            return "canceled"
        self.coord.out.warn(f"ssh-add failed (return code: {rc})")
        return "failed"

    def _cancel_loop(self) -> None:
        endpoint = self.cancel
        if endpoint is None:
            return
        monitor_peers = self.waiter
        while not self._stop.is_set():
            if monitor_peers is not None:
                try:
                    result = monitor_peers.wait(timeout=0.5, wake_fd=endpoint.read_fd)
                except (KeychainError, OSError) as exc:
                    self.coord.out.warn(
                        f"Cannot monitor other terminals; this passphrase request remains active: {exc}"
                    )
                    monitor_peers = None
                    continue
                if result.action == "notified" and self._keys_available is not None:
                    try:
                        available = self._keys_available()
                    except (KeychainError, OSError, subprocess.TimeoutExpired) as exc:
                        self.coord.out.debug(f"Cannot verify keys after peer completion: {exc}")
                        continue
                    if available:
                        self._satisfied.set()
                        self._cancel_child()
                        return
                if result.action != "cancel":
                    continue
            elif not select.select([endpoint.read_fd], [], [], 0.5)[0]:
                continue
            if endpoint.read_message().get("status") == "cancel":
                self.coord.out.debug(f"Activation cancellation requested: attempt={self.attempt}")
                self._canceled.set()
                self._cancel_child()
                return

    def _cancel_child(self) -> None:
        with self._proc_lock:
            proc = self.proc
        if proc is None or proc.poll() is not None:
            return
        with contextlib.suppress(OSError):
            proc.terminate()
        try:
            proc.wait(timeout=_CHILD_TERMINATE_TIMEOUT)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(OSError):
                proc.kill()
            proc.wait()
