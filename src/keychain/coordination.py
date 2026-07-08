# SPDX-License-Identifier: GPL-3.0-only
"""Coordination primitives for interactive key activation.

The add flow needs two very different kinds of synchronization:

* a short state lock for pidfile writes and waiter registration
* an activation lock for the one process that is allowed to prompt for keys

This module keeps those mechanics out of ``main.py``. The state file is
coordination metadata only; the agent itself remains the source of truth.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import select
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from .paths import KeychainPaths
from .util import LockFile, Output, current_uid, get_tty, pid_alive, unlink_quiet


def _json_load(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            loaded = json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _json_save(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, sort_keys=True)
            handle.write("\n")
        Path(tmp_name).replace(path)
    except Exception:
        unlink_quiet(tmp_name)
        raise


def _nonblock_flag() -> int:
    return getattr(os, "O_NONBLOCK", 0)


@dataclass
class ActivationInfo:
    in_progress: bool = False
    owner_pid: int | None = None
    owner_tty: str = ""
    owner_host: str = ""
    owner_uid: int | None = None
    started_at: float | None = None
    heartbeat_at: float | None = None
    ssh_add_pid: int | None = None
    cancel_endpoint: str = ""
    status: str = ""
    requested_keys: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ActivationInfo:
        if not isinstance(data, dict):
            return cls()
        return cls(
            in_progress=bool(data.get("in_progress")),
            owner_pid=_maybe_int(data.get("owner_pid")),
            owner_tty=str(data.get("owner_tty") or ""),
            owner_host=str(data.get("owner_host") or ""),
            owner_uid=_maybe_int(data.get("owner_uid")),
            started_at=_maybe_float(data.get("started_at")),
            heartbeat_at=_maybe_float(data.get("heartbeat_at")),
            ssh_add_pid=_maybe_int(data.get("ssh_add_pid")),
            cancel_endpoint=str(data.get("cancel_endpoint") or ""),
            status=str(data.get("status") or ""),
            requested_keys=[str(item) for item in data.get("requested_keys", []) if item],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "in_progress": self.in_progress,
            "owner_pid": self.owner_pid,
            "owner_tty": self.owner_tty,
            "owner_host": self.owner_host,
            "owner_uid": self.owner_uid,
            "started_at": self.started_at,
            "heartbeat_at": self.heartbeat_at,
            "ssh_add_pid": self.ssh_add_pid,
            "cancel_endpoint": self.cancel_endpoint,
            "status": self.status,
            "requested_keys": list(self.requested_keys),
        }


@dataclass
class WaiterInfo:
    pid: int
    tty: str
    fifo_path: str
    registered_at: float
    requested_keys: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WaiterInfo | None:
        if not isinstance(data, dict):
            return None
        pid = _maybe_int(data.get("pid"))
        fifo_path = str(data.get("fifo") or data.get("fifo_path") or "")
        if pid is None or not fifo_path:
            return None
        return cls(
            pid=pid,
            tty=str(data.get("tty") or ""),
            fifo_path=fifo_path,
            registered_at=_maybe_float(data.get("registered_at")) or time.time(),
            requested_keys=[str(item) for item in data.get("requested_keys", []) if item],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "tty": self.tty,
            "fifo": self.fifo_path,
            "registered_at": self.registered_at,
            "requested_keys": list(self.requested_keys),
        }


@dataclass
class CoordinationState:
    generation: int = 0
    activation: ActivationInfo = field(default_factory=ActivationInfo)
    waiters: list[WaiterInfo] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> CoordinationState:
        data = _json_load(path)
        raw_waiters = data.get("waiters", [])
        waiters: list[WaiterInfo] = []
        if isinstance(raw_waiters, list):
            for item in raw_waiters:
                waiter = WaiterInfo.from_dict(item)
                if waiter is not None:
                    waiters.append(waiter)
        return cls(
            generation=int(data.get("generation") or 0),
            activation=ActivationInfo.from_dict(data.get("activation", {})),
            waiters=waiters,
        )

    def save(self, path: Path) -> None:
        _json_save(path, self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "generation": self.generation,
            "activation": self.activation.to_dict(),
            "waiters": [waiter.to_dict() for waiter in self.waiters],
        }


@dataclass
class WaiterEndpoint:
    fifo_path: Path
    read_fd: int
    keepalive_fd: int
    buffer: bytes = b""

    def read_message(self) -> dict[str, Any]:
        data = self.buffer
        self.buffer = b""
        while b"\n" not in data:
            try:
                chunk = os.read(self.read_fd, 65536)
            except BlockingIOError:
                break
            if not chunk:
                break
            data += chunk
        if b"\n" in data:
            raw, self.buffer = data.split(b"\n", 1)
        else:
            raw = data
        raw = raw.strip()
        if not raw:
            return {}
        try:
            msg = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}
        return msg if isinstance(msg, dict) else {}

    def wait_for_message(self, timeout: float | None = None) -> dict[str, Any]:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            wait = None if deadline is None else max(0.0, deadline - time.monotonic())
            ready, _, _ = select.select([self.read_fd], [], [], wait)
            if not ready:
                return {}
            message = self.read_message()
            if message:
                return message
            if deadline is not None and time.monotonic() >= deadline:
                return {}

    def cleanup(self) -> None:
        for fd in (self.read_fd, self.keepalive_fd):
            with contextlib.suppress(OSError):
                os.close(fd)
        unlink_quiet(self.fifo_path)


@dataclass
class CancelEndpoint:
    fifo_path: Path
    read_fd: int
    keepalive_fd: int

    def read_command(self) -> str:
        try:
            data = os.read(self.read_fd, 4096)
        except BlockingIOError:
            return ""
        return data.decode("utf-8", errors="replace").strip().lower()

    def cleanup(self) -> None:
        for fd in (self.read_fd, self.keepalive_fd):
            with contextlib.suppress(OSError):
                os.close(fd)
        unlink_quiet(self.fifo_path)


@dataclass(frozen=True)
class WaitResult:
    action: str
    message: dict[str, Any] = field(default_factory=dict)


class ActivationLock:
    """A non-blocking hostname:pid lock for the activation owner.

    Unlike ``LockFile(..., wait=0)``, this never force-takes a live local
    lock. That keeps accidental double-prompts out of the normal path.
    """

    __slots__ = ("path", "no_lock", "out", "acquired", "_token")

    def __init__(self, path: Path, no_lock: bool, out: Output) -> None:
        self.path = path
        self.no_lock = no_lock
        self.out = out
        self.acquired = False
        self._token = f"{socket.gethostname()}:{os.getpid()}:{secrets.token_hex(8)}"

    def __enter__(self) -> ActivationLock:
        self.try_acquire()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.release()
        return False

    def try_acquire(self) -> bool:
        if self.no_lock:
            self.acquired = True
            return True
        try:
            fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if self._lock_is_live():
                return False
            with contextlib.suppress(OSError):
                self.path.unlink()
            try:
                fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except OSError:
                return False
        try:
            os.write(fd, self._token.encode("utf-8"))
        finally:
            os.close(fd)
        self.acquired = True
        return True

    def _lock_is_live(self) -> bool:
        try:
            raw = self.path.read_text(encoding="utf-8").strip()
        except OSError:
            return False
        hostname, sep, rest = raw.partition(":")
        if not sep:
            hostname, rest = socket.gethostname(), raw
        pid_s = rest.split(":", 1)[0]
        try:
            owner_pid = int(pid_s)
        except ValueError:
            return False
        if not owner_pid:
            return False
        if hostname != socket.gethostname():
            return True
        return pid_alive(owner_pid)

    def release(self) -> None:
        if not self.acquired:
            return
        if not self.no_lock:
            with contextlib.suppress(OSError):
                if self.path.read_text(encoding="utf-8").strip() == self._token:
                    self.path.unlink()
        self.acquired = False


class ActivationCoordinator:
    """Small façade around the state file, waiter FIFOs, and activation lock."""

    def __init__(self, paths: KeychainPaths, no_lock: bool, lockwait: int, out: Output) -> None:
        self.paths = paths
        self.no_lock = no_lock
        self.lockwait = lockwait
        self.out = out

    def state_lock(self) -> LockFile:
        return LockFile(self.paths.state_lockf, self.no_lock, self.lockwait, Output.silent())

    def load_state(self) -> CoordinationState:
        return CoordinationState.load(self.paths.state_file)

    def save_state(self, state: CoordinationState) -> None:
        state.save(self.paths.state_file)

    def create_waiter(self) -> WaiterEndpoint | None:
        if self.no_lock or not hasattr(os, "mkfifo"):
            return None
        self.paths.waiters_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        fifo_path = self.paths.waiters_dir / f"{os.getpid()}.{secrets.token_hex(8)}.fifo"
        read_fd = -1
        keepalive_fd = -1
        try:
            os.mkfifo(fifo_path, mode=0o600)
            read_fd = os.open(str(fifo_path), os.O_RDONLY | _nonblock_flag())
            keepalive_fd = os.open(str(fifo_path), os.O_WRONLY | _nonblock_flag())
        except OSError as exc:
            for fd in (read_fd, keepalive_fd):
                if fd >= 0:
                    with contextlib.suppress(OSError):
                        os.close(fd)
            unlink_quiet(fifo_path)
            self.out.debug(f"waiter FIFO unavailable ({exc}); falling back to direct activation")
            return None
        return WaiterEndpoint(fifo_path=fifo_path, read_fd=read_fd, keepalive_fd=keepalive_fd)

    def create_cancel_endpoint(self) -> CancelEndpoint | None:
        if self.no_lock or not hasattr(os, "mkfifo"):
            return None
        self.paths.waiters_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        fifo_path = self.paths.waiters_dir / f"cancel.{os.getpid()}.{secrets.token_hex(8)}.fifo"
        read_fd = -1
        keepalive_fd = -1
        try:
            os.mkfifo(fifo_path, mode=0o600)
            read_fd = os.open(str(fifo_path), os.O_RDONLY | _nonblock_flag())
            keepalive_fd = os.open(str(fifo_path), os.O_WRONLY | _nonblock_flag())
        except OSError as exc:
            for fd in (read_fd, keepalive_fd):
                if fd >= 0:
                    with contextlib.suppress(OSError):
                        os.close(fd)
            unlink_quiet(fifo_path)
            self.out.debug(f"cancel FIFO unavailable ({exc}); activation will not be cancelable")
            return None
        return CancelEndpoint(fifo_path=fifo_path, read_fd=read_fd, keepalive_fd=keepalive_fd)

    def can_prompt(self) -> bool:
        if os.name == "nt":
            return False
        try:
            fd = os.open("/dev/tty", os.O_RDONLY)
        except OSError:
            return False
        with contextlib.suppress(OSError):
            os.close(fd)
        return True

    def register_waiter(self, state: CoordinationState, waiter: WaiterEndpoint, requested_keys: list[str]) -> None:
        info = WaiterInfo(
            pid=os.getpid(),
            tty=get_tty(),
            fifo_path=str(waiter.fifo_path),
            registered_at=time.time(),
            requested_keys=list(requested_keys),
        )
        state.waiters = [existing for existing in state.waiters if existing.fifo_path != info.fifo_path]
        state.waiters.append(info)

    def unregister_waiter(self, state: CoordinationState, waiter: WaiterEndpoint) -> None:
        state.waiters = [existing for existing in state.waiters if existing.fifo_path != str(waiter.fifo_path)]

    def activation_lock(self) -> ActivationLock:
        return ActivationLock(self.paths.activation_lockf, self.no_lock, self.out)

    def begin_activation(
        self,
        state: CoordinationState,
        waiter: WaiterEndpoint | None,
        requested_keys: list[str],
        *,
        cancel_endpoint: str = "",
    ) -> None:
        if waiter is not None:
            self.unregister_waiter(state, waiter)
        now = time.time()
        state.activation = ActivationInfo(
            in_progress=True,
            owner_pid=os.getpid(),
            owner_tty=get_tty(),
            owner_host=socket.gethostname(),
            owner_uid=current_uid(),
            started_at=now,
            heartbeat_at=now,
            cancel_endpoint=cancel_endpoint,
            status="loading",
            requested_keys=list(requested_keys),
        )

    def mark_ssh_add_started(self, child_pid: int) -> None:
        with self.state_lock():
            state = self.load_state()
            state.activation.ssh_add_pid = child_pid
            state.activation.heartbeat_at = time.time()
            state.activation.status = "loading"
            self.save_state(state)

    def heartbeat(self) -> None:
        with self.state_lock():
            state = self.load_state()
            if state.activation.in_progress and state.activation.owner_pid == os.getpid():
                state.activation.heartbeat_at = time.time()
                self.save_state(state)

    def finish_activation(self, status: str) -> list[WaiterInfo]:
        with self.state_lock():
            state = self.load_state()
            waiters = list(state.waiters)
            state.waiters = []
            state.activation = ActivationInfo(in_progress=False, status=status)
            state.generation += 1
            self.save_state(state)
        self.notify_waiters(waiters, status=status, generation=state.generation)
        return waiters

    def request_takeover(self, waiter: WaiterEndpoint, timeout: float = 5.0) -> dict[str, Any]:
        with self.state_lock():
            state = self.load_state()
            activation = state.activation
            if not activation.in_progress:
                return {"status": "inactive"}
            if self._activation_owner_is_dead(activation):
                return self._recover_dead_activation(state)
            cancel_path = activation.cancel_endpoint

        if not cancel_path:
            return {"status": "unavailable"}

        try:
            fd = os.open(cancel_path, os.O_WRONLY | _nonblock_flag())
        except OSError:
            with self.state_lock():
                state = self.load_state()
                if self._activation_owner_is_dead(state.activation):
                    return self._recover_dead_activation(state)
            return {"status": "unavailable"}

        try:
            os.write(fd, b"cancel\n")
        finally:
            os.close(fd)
        return waiter.wait_for_message(timeout) or {"status": "timeout"}

    def _activation_owner_is_dead(self, activation: ActivationInfo) -> bool:
        if not activation.owner_pid:
            return False
        if activation.owner_host and activation.owner_host != socket.gethostname():
            return False
        uid = current_uid()
        if uid is not None and activation.owner_uid is not None and activation.owner_uid != uid:
            return False
        return not pid_alive(activation.owner_pid)

    def _recover_dead_activation(self, state: CoordinationState) -> dict[str, Any]:
        waiters = list(state.waiters)
        state.waiters = []
        state.activation = ActivationInfo(in_progress=False, status="canceled")
        state.generation += 1
        self.save_state(state)
        self.notify_waiters(waiters, status="canceled", generation=state.generation)
        return {"status": "canceled", "generation": state.generation}

    def notify_waiters(self, waiters: list[WaiterInfo], status: str, generation: int | None = None) -> None:
        message = {
            "status": status,
            "generation": generation,
            "loader_pid": os.getpid(),
            "timestamp": time.time(),
        }
        payload = (json.dumps(message, sort_keys=True) + "\n").encode("utf-8")
        for waiter in waiters:
            with contextlib.suppress(OSError):
                fd = os.open(waiter.fifo_path, os.O_WRONLY | _nonblock_flag())
                try:
                    os.write(fd, payload)
                finally:
                    os.close(fd)

    def wait_for_activation_signal(self, waiter: WaiterEndpoint, *, activation_active: bool) -> WaitResult:
        prompt_ephemeral = False
        try:
            with open("/dev/tty", encoding="utf-8", errors="replace") as tty:
                prompt_ephemeral = self._prompt(activation_active)
                ready, _, _ = select.select([tty.fileno(), waiter.read_fd], [], [])
                if waiter.read_fd in ready:
                    if prompt_ephemeral:
                        self.out.clear_ephemeral_line(after_input=tty.fileno() in ready)
                    return WaitResult("notified", waiter.read_message())
                line = tty.readline().strip().lower()
                if prompt_ephemeral:
                    self.out.clear_ephemeral_line(after_input=True)
        except OSError:
            if prompt_ephemeral:
                self.out.clear_ephemeral_line()
            return WaitResult("activate")

        if activation_active:
            return WaitResult("takeover" if line == "takeover" else "wait")
        return WaitResult("activate")

    def _prompt(self, activation_active: bool) -> bool:
        if activation_active:
            text = self.out.warn_text(
                f"[ {self.out.glyph('key')} Type 'takeover' to initialize keys in this terminal; "
                f"Enter to wait {self.out.glyph('key')} ]"
            )
        else:
            text = self.out.warn_text(
                f"[ {self.out.glyph('key')} Press Enter to initialize keys {self.out.glyph('key')} ]"
            )
        return self.out.ephemeral_line(text)


class ActivationOwner:
    """Own one cancelable ``ssh-add`` activation attempt."""

    def __init__(
        self,
        coord: ActivationCoordinator,
        waiter: WaiterEndpoint | None,
        requested_keys: list[str],
        out: Output,
        *,
        heartbeat_interval: float = 5.0,
    ) -> None:
        self.coord = coord
        self.waiter = waiter
        self.requested_keys = list(requested_keys)
        self.out = out
        self.heartbeat_interval = heartbeat_interval
        self.cancel_endpoint: CancelEndpoint | None = None
        self.proc: subprocess.Popen[bytes] | None = None
        self._stop = threading.Event()
        self._canceled = threading.Event()
        self._cancel_thread: threading.Thread | None = None
        self._heartbeat_thread: threading.Thread | None = None

    def run_ssh_add(self, cmd: list[str] | list[list[str]], env: dict[str, str]) -> str:
        self.cancel_endpoint = self.coord.create_cancel_endpoint()
        cancel_path = str(self.cancel_endpoint.fifo_path) if self.cancel_endpoint is not None else ""

        with self.coord.state_lock():
            state = self.coord.load_state()
            self.coord.begin_activation(state, self.waiter, self.requested_keys, cancel_endpoint=cancel_path)
            self.coord.save_state(state)

        try:
            if cmd and isinstance(cmd[0], list):
                commands = cast(list[list[str]], cmd)
            else:
                commands = [cast(list[str], cmd)]
            for child_cmd in commands:
                status = self._run_child(child_cmd, env)
                if status != "success":
                    return status
            return "success"
        finally:
            self._stop.set()
            self._join_threads()
            if self.cancel_endpoint is not None:
                self.cancel_endpoint.cleanup()

    def _run_child(self, cmd: list[str], env: dict[str, str]) -> str:
        try:
            with self._open_tty() as tty:
                kwargs: dict[str, Any] = {"env": env, "close_fds": True}
                if tty is not None:
                    kwargs.update({"stdin": tty, "stdout": tty, "stderr": tty})
                self.proc = subprocess.Popen(cmd, **kwargs)
                self.coord.mark_ssh_add_started(self.proc.pid)
                self._start_cancel_thread()
                self._start_heartbeat_thread()
                rc = self.proc.wait()
        except FileNotFoundError:
            self.out.warn("ssh-add not found")
            return "failed"
        except OSError as exc:
            self.out.warn(f"ssh-add failed to start: {exc}")
            return "failed"

        if self._canceled.is_set():
            self.out.debug("ssh-add canceled by another terminal.")
            return "canceled"
        if rc != 0:
            self.out.warn(f"ssh-add failed (return code: {rc})")
            return "failed"
        return "success"

    @contextlib.contextmanager
    def _open_tty(self):
        if os.name == "nt":
            yield None
            return
        try:
            with open("/dev/tty", "rb+", buffering=0) as tty:
                yield tty
        except OSError:
            yield None

    def _start_cancel_thread(self) -> None:
        if self.cancel_endpoint is None:
            return
        self._cancel_thread = threading.Thread(target=self._cancel_loop, name="keychain-cancel-listener", daemon=True)
        self._cancel_thread.start()

    def _start_heartbeat_thread(self) -> None:
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, name="keychain-activation-heartbeat", daemon=True
        )
        self._heartbeat_thread.start()

    def _join_threads(self) -> None:
        for thread in (self._cancel_thread, self._heartbeat_thread):
            if thread is not None:
                thread.join(timeout=1.0)

    def _cancel_loop(self) -> None:
        endpoint = self.cancel_endpoint
        if endpoint is None:
            return
        while not self._stop.is_set():
            ready, _, _ = select.select([endpoint.read_fd], [], [], 0.5)
            if not ready:
                continue
            if endpoint.read_command() == "cancel":
                self._cancel_child()
                return

    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(self.heartbeat_interval):
            self.coord.heartbeat()

    def _cancel_child(self) -> None:
        proc = self.proc
        if proc is None or proc.poll() is not None:
            return
        self._canceled.set()
        with contextlib.suppress(OSError):
            proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(OSError):
                proc.kill()


def _maybe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _maybe_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
