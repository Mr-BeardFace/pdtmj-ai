"""local_exec runs a shell command on the local box and is in scope for the agents
that inspect downloaded files (enumeration + the foothold kit)."""
import sys

from core.registry import build_registry, load_all_agents
from core.tool_registry import expand_scope
from tools.local_exec import local_exec


def test_runs_local_command():
    r = local_exec("echo hello-local")
    assert r["exit_code"] == 0
    assert "hello-local" in r["stdout"]


def test_empty_command_errors():
    assert "error" in local_exec("")


def test_captures_nonzero_exit():
    r = local_exec("exit 3")
    assert r["exit_code"] == 3


def test_registered():
    assert "local_exec" in build_registry().list_tools()


def test_in_enumeration_and_foothold_scope():
    # foothold kit (used by the domain specialists + exploitation)
    assert "local_exec" in expand_scope(["@foothold"])
    # enumeration scope (the case that kept failing)
    enum = load_all_agents()["pentest/enumeration"]
    assert "local_exec" in expand_scope(enum.scope)
