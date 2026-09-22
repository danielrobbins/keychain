# SPDX-License-Identifier: GPL-3.0-only
"""Event-driven activation: OS locks exclude loaders; FIFO closure wakes waiters."""

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
    def __init__(self, path: Path, no_lock: bool, out: Output) -> None:
        super().__init__(path, no_lock, 0, out)

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

    def activation_lock(self) -> ActivationLock:
        return ActivationLock(self.paths.activation_lockf, self.no_lock, self.out)

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

    def activation(self, waiter: ActivationWaiter | None = None) -> ActivationOwner:
        return ActivationOwner(self, waiter)

    def discard_attempts(self) -> None:
        """Called with both locks held: no previous loader can still be running."""
        for kind in ("life", "cancel"):
            for path in self.paths.waiters_dir.glob(f"{kind}.*.fifo"):
                unlink_quiet(path)

    def observe(self) -> tuple[str, int]:
        """Called under the state lock; the activation lock establishes liveness."""
        with self.activation_lock() as lock:
            if lock.acquired:
                self.discard_attempts()
                return "", -1
        for path in self.paths.waiters_dir.glob("life.*.fifo"):
            attempt = path.name.split(".")[1]
            if not CoordinationState.from_dict({"attempt": attempt, "status": "loading"}).attempt:
                continue
            try:
                fd = _open_fifo(path, os.O_RDONLY)
            except OSError:
                continue
            # The loader could die between the first lock probe and opening this reader.
            with self.activation_lock() as lock:
                if lock.acquired:
                    os.close(fd)
                    self.discard_attempts()
                    return "", -1
            return attempt, fd
        raise KeychainError("Key loading is locked but its lifetime notification is unavailable")


class ActivationWaiter:
    def __init__(self, coord: ActivationCoordinator, endpoint: WaiterEndpoint) -> None:
        self.coord, self.endpoint = coord, endpoint
        self.attempt = ""
        self.life_fd = -1
        self.ignore_attempt = ""

    def _close_watch(self) -> None:
        if self.life_fd >= 0:
            os.close(self.life_fd)
            self.life_fd = -1

    def cleanup(self) -> None:
        self._close_watch()
        self.endpoint.cleanup()

    def _completion(self) -> WaitResult:
        record = self.coord.load_state()
        status = record.status if record.attempt == self.attempt else "unknown"
        if status == "loading":
            status = "abandoned"
        self._close_watch()
        self.ignore_attempt = self.attempt
        return WaitResult("notified", {"attempt": self.attempt, "status": status})

    def wait(
        self, *, immediate: bool = False, interactive: bool = False, handoff: bool = False, timeout: float | None = None
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
                            self._close_watch()
                            self.attempt = self.ignore_attempt = attempt
                            return WaitResult("notified", message)
                        if status == "loading" and self.life_fd < 0:
                            self.attempt = attempt
                    if self.life_fd >= 0 and select.select([self.life_fd], [], [], 0)[0]:
                        return self._completion()
                    if self.life_fd < 0:
                        attempt, fd = self.coord.observe()
                        if fd >= 0:
                            self.attempt, self.life_fd = attempt, fd
                        elif self.attempt and self.attempt != self.ignore_attempt:
                            return self._completion()
                    active = self.life_fd >= 0
                    if handoff and active:
                        # The successor is here: wait for its lifetime, not a timer.
                        handoff, deadline = False, None
                    if not active and not handoff and (immediate or (not interactive and timeout is None)):
                        return WaitResult("activate")

                prompt = False
                if tty is not None and not handoff:
                    text = (
                        "Type 'takeover' to initialize keys in this terminal; Enter to wait"
                        if active
                        else "Press Enter to initialize keys"
                    )
                    prompt = self.coord.out.ephemeral_line(
                        self.coord.out.warn_text(
                            f"[ {self.coord.out.glyph('key')} {text} {self.coord.out.glyph('key')} ]"
                        )
                    )
                fds = [self.endpoint.read_fd]
                if self.life_fd >= 0:
                    fds.append(self.life_fd)
                if tty is not None and not handoff:
                    fds.append(tty.fileno())
                remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
                ready, _, _ = select.select(fds, [], [], remaining)
                if prompt:
                    self.coord.out.clear_ephemeral_line(after_input=tty.fileno() in ready if tty else False)
                if not ready:
                    return WaitResult("activate" if handoff and not active else "timeout")
                if self.endpoint.read_fd in ready or self.life_fd in ready:
                    continue
                if tty is not None:
                    line = tty.readline()
                    if not line:
                        raise KeychainError("Terminal closed while waiting to initialize keys")
                    if not active:
                        return WaitResult("activate")
                    if line.strip().lower() == "takeover":
                        return WaitResult("takeover")

    def request_takeover(self) -> WaitResult:
        with self.coord.state_lock():
            if self.life_fd < 0:
                return WaitResult("activate")
            path = self.coord.paths.waiters_dir / f"cancel.{self.attempt}.fifo"
            if not WaiterEndpoint.send(path, {"status": "cancel"}):
                return WaitResult("unavailable")
        return self.wait(timeout=_CHILD_TERMINATE_TIMEOUT + 2.0)


class ActivationOwner:
    """The activation lock and lifetime writer both remain open in ssh-add."""

    def __init__(self, coord: ActivationCoordinator, waiter: ActivationWaiter | None) -> None:
        self.coord, self.waiter = coord, waiter
        self.lock = coord.activation_lock()
        self.attempt = secrets.token_hex(16)
        self.status = "failed"
        self.life: WaiterEndpoint | None = None
        self.cancel: WaiterEndpoint | None = None
        self.proc: subprocess.Popen[bytes] | None = None
        self._stop = threading.Event()
        self._canceled = threading.Event()
        self._thread: threading.Thread | None = None
        self._proc_lock = threading.Lock()

    @property
    def acquired(self) -> bool:
        return self.lock.acquired

    def __enter__(self) -> ActivationOwner:
        try:
            with self.coord.state_lock():
                if not self.lock.try_acquire():
                    return self
                if not self.coord.no_lock and hasattr(os, "mkfifo"):
                    self.coord.discard_attempts()
                    self.life = self.coord.endpoint(f"life.{self.attempt}")
                    self.cancel = self.coord.endpoint(f"cancel.{self.attempt}")
                    CoordinationState(self.attempt, "loading").save(self.coord.paths.state_file)
                    if self.waiter is not None:
                        self.waiter._close_watch()
                        self.waiter.attempt = self.waiter.ignore_attempt = self.attempt
                    # Every existing waiter is notified before a child can be started.
                    self.coord.notify_waiters(self.attempt, "loading")
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
        for endpoint in (self.life, self.cancel):
            if endpoint is not None:
                endpoint.cleanup(preserve_writers=endpoint is self.life)
        self.life = self.cancel = None

    def run_ssh_add(self, commands: list[list[str]], env: dict[str, str]) -> str:
        if self.cancel is not None:
            self._thread = threading.Thread(target=self._cancel_loop, name="keychain-cancel-listener", daemon=True)
            self._thread.start()
        for command in commands:
            self.status = self._run_child(command, env)
            if self.status != "success":
                break
        return self.status

    def _run_child(self, cmd: list[str], env: dict[str, str]) -> str:
        try:
            with contextlib.ExitStack() as stack:
                kwargs: dict[str, Any] = {"env": env, "close_fds": True}
                if os.name != "nt":
                    kwargs["pass_fds"] = self.lock.pass_fds + ((self.life.keepalive_fd,) if self.life else ())
                    try:
                        tty = stack.enter_context(open("/dev/tty", "rb+", buffering=0))
                    except OSError:
                        pass
                    else:
                        kwargs.update(stdin=tty, stdout=tty, stderr=tty)
                with self._proc_lock:
                    if self._canceled.is_set():
                        return "canceled"
                    self.proc = subprocess.Popen(cmd, **kwargs)
                rc = self.proc.wait()
        except OSError as exc:
            self.coord.out.warn(f"ssh-add failed to start: {exc}")
            return "failed"
        if self._canceled.is_set():
            return "canceled"
        if rc != 0:
            self.coord.out.warn(f"ssh-add failed (return code: {rc})")
            return "failed"
        return "success"

    def _cancel_loop(self) -> None:
        endpoint = self.cancel
        if endpoint is None:
            return
        while not self._stop.is_set():
            if not select.select([endpoint.read_fd], [], [], 0.5)[0]:
                continue
            if endpoint.read_message().get("status") == "cancel":
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
