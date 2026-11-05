# SPDX-License-Identifier: GPL-3.0-only
"""Opt-in Linux reproduction of #270, with isolated mounts, PIDs, and keys.

Run as root with KEYCHAIN_TEST_HIDEPID=1. Root only creates the namespaces
and mount; agents and Keychain run as UID 65534 with disposable keys,
never the user's keys.
"""

import ctypes
import errno
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _namespace_probe(hidepid):
    # Only called inside unshare's new mount/PID namespaces, never on host /proc.
    if os.getpid() != 1 or os.geteuid() != 0:
        raise RuntimeError("The probe must be PID 1 under root's unshare --mount --pid --fork")
    subprocess.run(["mount", "-o", f"remount,hidepid={hidepid},gid=3009", "/proc"], check=True)
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    # Make this ordinary control process visible after dropping privileges.
    libc = ctypes.CDLL(None, use_errno=True)
    assert libc.prctl(4, 1, 0, 0, 0) == 0  # PR_SET_DUMPABLE
    sys.path.insert(0, str(ROOT / "src"))
    from keychain.env import SshAgentRef
    from keychain.output.core import Output
    from keychain.paths import KeychainPaths
    from keychain.runtime.platform import _LinuxPlatform

    report = {
        "hidepid": hidepid,
        "uid": os.getuid(),
        "control_visible": Path(f"/proc/{os.getpid()}/comm").exists(),
        "proc_mounts": [line for line in Path("/proc/self/mountinfo").read_text().splitlines() if " /proc " in line],
        "cases": {},
    }
    # Both platform names use Linux /proc; this does not emulate Android's SELinux policy.
    for backend in ("linux", "android"):
        with tempfile.TemporaryDirectory(prefix="kc-hidepid-") as temporary:
            home = Path(temporary)
            keydir = home / ".keychain"
            env = {"PATH": os.environ["PATH"], "HOME": str(home), "LC_ALL": "C", "PYTHONPATH": str(ROOT / "src")}
            program = (
                "import sys; from keychain.runtime import platform; "
                "platform.detect(platform_override=sys.argv.pop(1), has_ps=True); "
                "from keychain.main import main; sys.exit(main())"
            )
            command = [str(Path(sys.executable).resolve()), "-c", program, backend]
            options = ["--host", "visibility", "--dir", str(keydir), "--absolute", "--debug"]

            def invoke(*args, command=command, options=options, env=env):
                return subprocess.run([*command, *args, *options], env=env, capture_output=True, text=True, timeout=30)

            started = invoke("agent", "start")
            assert started.returncode == 0, started.stdout + started.stderr
            pidfile = keydir / "visibility-sh"
            original = SshAgentRef.from_text(pidfile.read_text())
            assert original.pid_int is not None
            empty_reused = invoke("agent", "start")
            empty_pid = SshAgentRef.from_text(pidfile.read_text()).pid_int
            agent_env = {**env, **original.as_dict()}
            key = home / "test-key"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], env=env, check=True)
            added = subprocess.run(["ssh-add", str(key)], env=agent_env, capture_output=True, text=True, timeout=10)
            assert added.returncode == 0, added.stderr
            listed = subprocess.run(["ssh-add", "-l"], env=agent_env, capture_output=True, text=True, timeout=10)
            assert listed.returncode == 0, listed.stderr
            os.kill(original.pid_int, 0)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(5)
                connection.connect(original.sock)
                peer_pid, peer_uid, peer_gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            try:
                owner = Path(f"/proc/{original.pid_int}").stat().st_uid
                proc_errno = 0
            except OSError as error:
                owner, proc_errno = None, error.errno
            try:
                Path(f"/proc/{original.pid_int}/comm").read_text()
                comm_errno = 0
            except OSError as error:
                comm_errno = error.errno
            pids = _LinuxPlatform(backend).process_list(re.compile(r"(?:^|/)ssh-agent$"), uid=os.getuid())
            inspected = invoke("inspect")
            inspected_json = invoke("inspect", "--json")
            assert inspected_json.returncode == 0, inspected_json.stderr
            reused = invoke("add", "--immediate", str(key))
            current = SshAgentRef.from_text(pidfile.read_text())
            # Exercise an actual load too, not only reuse of a populated agent.
            subprocess.run(["ssh-add", "-D"], env=agent_env, check=True, capture_output=True)
            loaded = invoke("add", "--immediate", str(key))
            loaded_keys = subprocess.run(["ssh-add", "-l"], env=agent_env, capture_output=True, text=True, timeout=10)
            paths = KeychainPaths(keydir=keydir, host="visibility")
            bad_references = {}
            with subprocess.Popen(["true"]) as dead:
                dead.wait()
            # A working socket must not excuse a visibly wrong or dead PID.
            for label, pid in (("visible-other-process", os.getpid()), ("dead-process", dead.pid)):
                paths.write(SshAgentRef(original.sock, str(pid)), Output.silent())
                rejected = invoke("inspect", "--json")
                assert rejected.returncode == 0, rejected.stderr
                bad_references[label] = json.loads(rejected.stdout)["agent_state"]
            paths.write(original, Output.silent())
            stopped = invoke("agent", "stop")
            after_stop = subprocess.run(["ssh-add", "-l"], env=agent_env, capture_output=True, text=True, timeout=10)
            report["cases"][backend] = {
                "pid_alive": True,
                "manual_ssh_add_status": listed.returncode,
                "proc_errno": proc_errno,
                "comm_errno": comm_errno,
                "proc_owner": owner,
                "listed": original.pid_int in pids,
                "peer_credentials": {"pid": peer_pid, "uid": peer_uid, "gid": peer_gid},
                "original_pid": original.pid_int,
                "subsequent_pid": current.pid_int,
                "add_status": reused.returncode,
                "add_output": reused.stdout + reused.stderr,
                "inspect_output": inspected.stdout + inspected.stderr,
                "inspect_lists_key": listed.stdout.split()[1] in inspected.stdout + inspected.stderr,
                "inspect_json": json.loads(inspected_json.stdout),
                "load_status": loaded.returncode,
                "load_output": loaded.stdout + loaded.stderr,
                "loaded_keys": loaded_keys.stdout,
                "stop_output": stopped.stdout + stopped.stderr,
                "pidfile_preserved": pidfile.exists(),
                "after_stop_status": after_stop.returncode,
                "empty_reuse_status": empty_reused.returncode,
                "empty_pid": empty_pid,
                "bad_references": bad_references,
            }
    # PID namespace teardown also removes any replacement/orphaned agents.
    print(json.dumps(report))


@pytest.fixture(scope="module", params=[0, 1, 2], ids=["normal-proc", "restricted-proc", "hidden-proc"])
def visibility_report(request):
    if os.environ.get("KEYCHAIN_TEST_HIDEPID") != "1":
        pytest.skip("set KEYCHAIN_TEST_HIDEPID=1 to run the isolated Linux mount test")
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        pytest.skip("requires Linux root to create private mount/PID namespaces, then drops to UID 65534")
    for tool in ("unshare", "mount", "ps", "ssh-agent", "ssh-keygen", "ssh-add"):
        if shutil.which(tool) is None:
            pytest.skip(f"requires {tool}")
    before = Path("/proc/self/mountinfo").read_text()
    result = subprocess.run([
        "unshare", "--mount", "--pid", "--fork", "--mount-proc", "--propagation", "private", "--kill-child",
        sys.executable, str(Path(__file__).resolve()), "--namespace-probe", str(request.param),
    ], capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
    assert Path("/proc/self/mountinfo").read_text() == before, "Host mount table changed"
    report = json.loads(result.stdout)
    summary = {**report, "cases": {
        name: {key: value for key, value in case.items() if not key.endswith(("_output", "_json", "_references"))}
        for name, case in report["cases"].items()
    }}
    print(json.dumps(summary, indent=2))
    return report


@pytest.mark.parametrize("backend", ["linux", "android"])
def test_real_agent_visibility(visibility_report, backend):
    report = visibility_report
    case = report["cases"][backend]
    assert report["uid"] == 65534
    assert report["control_visible"]
    if report["hidepid"]:
        assert any(re.search(r"hidepid=(?:1|2|noaccess|invisible)(?:,|$)", mount) for mount in report["proc_mounts"])
    assert case["pid_alive"] and case["manual_ssh_add_status"] == 0
    assert case["peer_credentials"]["uid"] == report["uid"]
    assert case["comm_errno"] in ((errno.ENOENT, errno.EACCES, errno.EPERM) if report["hidepid"] else (0,))
    assert case["listed"] is (report["hidepid"] == 0)


@pytest.mark.parametrize("backend", ["linux", "android"])
def test_keychain_reuses_working_agent(visibility_report, backend):
    report = visibility_report
    case = report["cases"][backend]
    assert case["add_status"] == 0, case["add_output"]
    assert case["subsequent_pid"] == case["original_pid"], case["add_output"]
    assert case["empty_reuse_status"] == 0
    assert case["empty_pid"] == case["original_pid"]


@pytest.mark.parametrize("backend", ["linux", "android"])
def test_inspect_reports_reachable_agent(visibility_report, backend):
    report = visibility_report
    case = report["cases"][backend]
    assert case["inspect_lists_key"], case["inspect_output"]
    data = case["inspect_json"]["agent_state"]
    assert data["pidfile"]["process"]["identity"] == ("uninspectable" if report["hidepid"] else "verified")
    assert data["selected"]["pid"] == str(case["original_pid"])
    assert "selected socket" in case["inspect_output"]
    if report["hidepid"]:
        assert "process details are inaccessible" in case["inspect_output"]
        assert "hidepid" in case["inspect_output"]


@pytest.mark.parametrize("backend", ["linux", "android"])
def test_keychain_loads_into_original_agent(visibility_report, backend):
    case = visibility_report["cases"][backend]
    assert case["load_status"] == 0, case["load_output"]
    assert "SHA256:" in case["loaded_keys"]


@pytest.mark.parametrize("backend", ["linux", "android"])
def test_responding_socket_does_not_excuse_wrong_pid(visibility_report, backend):
    for reference in visibility_report["cases"][backend]["bad_references"].values():
        assert reference["pidfile"]["process"]["identity"] == "unverified"
        assert reference["selected"]["socket"] is None


@pytest.mark.parametrize("backend", ["linux", "android"])
def test_stop_preserves_hidden_agent_without_signaling(visibility_report, backend):
    report = visibility_report
    case = report["cases"][backend]
    assert case["pidfile_preserved"] is bool(report["hidepid"])
    if report["hidepid"]:
        assert case["after_stop_status"] == 0
        assert "pidfile kept" in case["stop_output"]
    else:
        assert case["after_stop_status"] == 2


if __name__ == "__main__":
    assert sys.argv[1] == "--namespace-probe"
    _namespace_probe(int(sys.argv[2]))
