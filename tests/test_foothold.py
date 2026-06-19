import socket
import time

from core.engagement_state import EngagementState
from core.orchestrator import Orchestrator, _auth_fields, _auth_result, _AUTH_TOOLS
from core.registry import build_registry
from core.shells import ShellManager, reverse_shell_payloads
from core.tool_registry import ToolRegistry


# ── ShellManager ──────────────────────────────────────────────────────────────

def test_payloads_have_both_os():
    p = reverse_shell_payloads("10.0.0.1", 4444)
    assert "10.0.0.1" in p["linux_bash"] and "4444" in p["linux_bash"]
    assert "windows_powershell" in p and "windows_nc" in p


def test_listener_accepts_and_registers_session():
    mgr = ShellManager()
    res = mgr.start_listener(46123, "127.0.0.1")
    assert res["listening"] and "linux_bash" in res["payloads"]
    try:
        c = socket.create_connection(("127.0.0.1", 46123), timeout=3)
        for _ in range(40):
            if mgr.poll_new_sessions():
                break
            time.sleep(0.05)
        assert len(mgr.sessions()) == 1
        c.close()
    finally:
        mgr.stop_all()


def test_shell_exec_missing_session():
    assert "error" in ShellManager().exec("nope", "id")


# ── orchestrator foothold handlers ────────────────────────────────────────────

def _orch(tmp_path, state, events=None):
    cb = (lambda e: events.append(e)) if events is not None else None
    return Orchestrator(object(), ToolRegistry(), tmp_path, quiet=True,
                        engagement_state=state, log_callback=cb)


def test_record_persistence_handler(tmp_path):
    events = []
    state = EngagementState(target="10.0.0.5")
    o = _orch(tmp_path, state, events)
    res = o._handle_foothold("record_persistence", {
        "kind": "authorized_key", "host": "10.0.0.5",
        "detail": "ed25519 key (svc@local)", "cleanup": "sed -i '/svc@local/d' ~/.ssh/authorized_keys",
        "os": "linux",
    }, "pentest/rce")
    assert res["recorded"] is True
    assert state.persistence[0].kind == "authorized_key"
    assert "sed" in state.persistence[0].cleanup
    assert any(e.get("type") == "persistence" for e in events)


def test_list_shells_handler(tmp_path):
    o = _orch(tmp_path, EngagementState(target="x"))
    assert o._handle_foothold("list_shells", {}, "a") == {"sessions": []}


# ── auth ledger ───────────────────────────────────────────────────────────────

def test_auth_field_mapping():
    assert _auth_fields("ssh_exec", {"host": "h", "username": "u", "password": "p"})[0] == "ssh"
    assert _auth_fields("netexec", {"target": "h", "protocol": "winrm", "username": "u", "password": "p"})[0] == "winrm"
    assert _auth_fields("nmap_scan", {}) is None


def test_auth_result_classification():
    assert _auth_result("ssh_exec", {"error": "Authentication failed for u@h"}) == "fail"
    assert _auth_result("ssh_exec", {"exit_code": 0, "output": "id"}) == "success"
    assert _auth_result("netexec", {"authenticated": False}) == "fail"
    assert _auth_result("netexec", {"authenticated": True}) == "success"


def test_auth_ledger_dedup_and_lookup():
    s = EngagementState(target="h")
    s.record_auth_attempt("ssh", "h", "nathan", "pw", "fail", 22, "a")
    s.record_auth_attempt("ssh", "h", "nathan", "pw", "fail", 22, "a")   # dup
    assert len(s.auth_attempts) == 1
    assert s.auth_attempted("ssh", "h", "nathan", "pw", 22) == "fail"
    assert s.auth_attempted("ssh", "h", "other", "pw", 22) is None


def test_auth_attempts_in_context_block():
    s = EngagementState(target="h")
    s.record_auth_attempt("ssh", "h", "nathan", "pw", "fail", 22, "a")
    block = s.build_context_block()
    assert "Auth already attempted" in block and "nathan" in block


# ── registry ──────────────────────────────────────────────────────────────────

def test_foothold_tools_registered():
    names = build_registry().list_tools()
    assert "ssh_keygen" in names and "web_exec" in names


def test_ssh_exec_in_auth_tools():
    assert "ssh_exec" in _AUTH_TOOLS and "netexec" in _AUTH_TOOLS
