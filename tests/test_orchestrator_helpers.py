from core.orchestrator import _redact_command, _safe_filename_part, _result_summary
from core.llm_client import LLMClient


# ── command redaction ─────────────────────────────────────────────────────────

def test_redact_space_form():
    assert _redact_command("nxc smb 10.0.0.1 -u admin -p hunter2") == \
        "nxc smb 10.0.0.1 -u admin -p ***"


def test_redact_equals_form():
    assert "hunter2" not in _redact_command("tool --password=hunter2 host")


def test_redact_hash_and_auth_cred():
    out = _redact_command("nxc smb x -H aad3b435b51404ee --auth-cred admin:pw")
    assert "aad3b435b51404ee" not in out
    assert "admin:pw" not in out


def test_redact_leaves_other_flags():
    cmd = "nmap -sV -sC --open 10.0.0.1"
    assert _redact_command(cmd) == cmd


def test_redact_script_args_password():
    # nmap --script-args ssh-run.password=… / ftp.password=… must be masked
    out = _redact_command("nmap --script ssh-run --script-args ssh-run.password=Buck3tH4TF0RM3! -p 22 host")
    assert "Buck3tH4TF0RM3!" not in out
    assert "password=***" in out


def test_redact_does_not_mangle_nmap_ports():
    # -p is a port spec for nmap, not a password — leave it intact
    out = _redact_command("nmap -sV -p 1-65535 10.0.0.1")
    assert "-p 1-65535" in out


def test_redact_still_masks_smbclient_password_p():
    out = _redact_command("smbclient //h/s -p hunter2pw -c ls")
    assert "hunter2pw" not in out


# ── safe filenames ────────────────────────────────────────────────────────────

def test_safe_filename_strips_url_chars():
    # ':' is invalid in Windows filenames — used to crash _save_run on URL targets
    out = _safe_filename_part("https://example.com:8443/app")
    assert ":" not in out and "/" not in out


# ── result summaries ──────────────────────────────────────────────────────────

def test_result_summary_error_passthrough():
    assert _result_summary("nmap_scan", {"error": "boom"}) == "error: boom"


def test_result_summary_unknown_tool():
    assert _result_summary("not_a_tool", {"x": 1}) == ""


def test_result_summary_never_raises():
    # Malformed result must not propagate an exception into the run loop
    assert _result_summary("nmap_scan", {"hosts": "not-a-list"}) == ""


# ── conversation prompt caching ───────────────────────────────────────────────

def test_cache_marker_on_last_tool_result():
    messages = [
        {"role": "user", "content": "start"},
        {"role": "assistant", "content": [{"type": "text", "text": "ok"}]},
        {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "1", "content": "{}"},
            {"type": "tool_result", "tool_use_id": "2", "content": "{}"},
        ]},
    ]
    out = LLMClient._with_conversation_cache(messages)
    assert out[-1]["content"][-1]["cache_control"] == {"type": "ephemeral"}
    # Original list untouched — stale markers must not accumulate across turns
    assert "cache_control" not in messages[-1]["content"][-1]
    assert "cache_control" not in out[-1]["content"][0]


def test_cache_marker_on_string_user_message():
    messages = [{"role": "user", "content": "begin assessment"}]
    out = LLMClient._with_conversation_cache(messages)
    blk = out[-1]["content"][-1]
    assert blk["text"] == "begin assessment"
    assert blk["cache_control"] == {"type": "ephemeral"}
    assert messages[-1]["content"] == "begin assessment"


def test_cache_marker_skips_assistant_tail():
    messages = [{"role": "assistant", "content": [{"type": "text", "text": "x"}]}]
    assert LLMClient._with_conversation_cache(messages) is messages
