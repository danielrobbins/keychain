# SPDX-License-Identifier: GPL-3.0-only
"""Read pidfiles as shell syntax, but use the known socket address at startup."""

from pathlib import Path

import pytest

from keychain.env import SshAgentRef
from keychain.paths import ShPidfile

SOCKETS = [
    "/tmp/plain/agent.sock",
    "/tmp/a;b/agent.sock",
    "/tmp/a; export SSH_AUTH_SOCK=evil/agent.sock",
    "/tmp/it's;here/agent.sock",
    '/tmp/q"uote;/agent.sock',
    "/tmp/;/agent.sock",
    "/tmp/a b;c/agent.sock",
    "'quoted'/agent.sock",
    '"quoted"/agent.sock',
    "/tmp/back\\slash/#agent.sock",
    "/tmp/$(touch unwanted)/agent.sock",
    "/tmp/agent.sock ",
]


@pytest.mark.parametrize("sock", SOCKETS)
def test_sh_pidfile_round_trips_socket_paths(sock):
    ref = SshAgentRef(sock, "1234")
    text = ShPidfile(Path("/unused"), "").render(ref)
    assert SshAgentRef.from_text(text) == ref


def test_from_text_survives_an_unbalanced_quote_in_another_segment():
    text = "SSH_AUTH_SOCK=/tmp/x; export SSH_AUTH_SOCK; echo 'oops\nSSH_AGENT_PID=7; export SSH_AGENT_PID;\n"
    assert SshAgentRef.from_text(text) == SshAgentRef("/tmp/x", "7")


@pytest.mark.parametrize("sock", SOCKETS)
def test_raw_agent_output_preserves_path_characters(sock):
    text = f"SSH_AUTH_SOCK={sock}; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=4242; export SSH_AGENT_PID;\necho Agent pid 4242;\n"
    assert SshAgentRef.from_agent_output(text, sock) == SshAgentRef(sock, "4242")


@pytest.mark.parametrize("sock", SOCKETS)
def test_spawn_output_needs_only_the_pid(sock):
    text = "SSH_AGENT_PID=4242; export SSH_AGENT_PID;\necho Agent pid 4242;\n"
    assert SshAgentRef.from_agent_output(text, sock) == SshAgentRef(sock, "4242")


def test_pid_like_text_inside_socket_output_is_ignored():
    sock = "/tmp/path\nSSH_AGENT_PID=999; export SSH_AGENT_PID;\n/agent.sock"
    text = f"SSH_AUTH_SOCK={sock}; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=4242; export SSH_AGENT_PID;\n"
    assert SshAgentRef.from_agent_output(text, sock) == SshAgentRef(sock, "4242")


@pytest.mark.parametrize("pid_line", [
    "", "echo Agent pid 42;", "SSH_AGENT_PID=; export SSH_AGENT_PID;",
    "SSH_AGENT_PID=0; export SSH_AGENT_PID;", "SSH_AGENT_PID=-1; export SSH_AGENT_PID;",
    "SSH_AGENT_PID=abc; export SSH_AGENT_PID;", "OTHER=42; export OTHER;",
])
def test_spawn_output_requires_a_valid_pid(pid_line):
    text = "SSH_AUTH_SOCK=/tmp/ignored.sock; export SSH_AUTH_SOCK;\n" + pid_line + "\n"
    assert SshAgentRef.from_agent_output(text, "/tmp/requested.sock") == SshAgentRef()
