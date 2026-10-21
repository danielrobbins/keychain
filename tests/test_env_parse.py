# SPDX-License-Identifier: GPL-3.0-only
"""Round-trip of agent environment values through the sh pidfile."""

from __future__ import annotations

from pathlib import Path

import pytest

from keychain.env import SshAgentRef
from keychain.paths import ShPidfile


@pytest.mark.parametrize(
    "sock",
    [
        "/tmp/plain/agent.sock",
        "/tmp/a;b/agent.sock",
        "/tmp/a; export SSH_AUTH_SOCK=evil/agent.sock",
        "/tmp/it's;here/agent.sock",
        '/tmp/q"uote;/agent.sock',
        "/tmp/;/agent.sock",
    ],
)
def test_sh_pidfile_round_trips_socket_paths(sock):
    ref = SshAgentRef(sock, "1234")
    text = ShPidfile(Path("/unused"), "").render(ref)
    assert SshAgentRef.from_text(text) == ref


def test_from_text_survives_an_unbalanced_quote_in_another_segment():
    text = "SSH_AUTH_SOCK=/tmp/x; export SSH_AUTH_SOCK; echo 'oops\nSSH_AGENT_PID=7; export SSH_AGENT_PID;\n"
    ref = SshAgentRef.from_text(text)
    assert ref.sock == "/tmp/x"
    assert ref.pid == "7"


@pytest.mark.parametrize(
    "sock",
    ["/tmp/a;b/agent.123", "/tmp/a b;c/agent.123", "/tmp/;/agent.123", "/tmp/it's;x/agent.123"],
)
def test_from_text_accepts_unquoted_ssh_agent_output(sock):
    """``ssh-agent -s`` does not quote the socket path."""
    text = f"SSH_AUTH_SOCK={sock}; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=4242; export SSH_AGENT_PID;\necho Agent pid 4242;\n"
    assert SshAgentRef.from_text(text) == SshAgentRef(sock, "4242")
