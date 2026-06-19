"""Structured credential capture via the record_credential meta-tool.
(Replaces the old regex scrape of finding text, which produced IPv6 false positives.)
"""
from core.engagement_state import EngagementState
from core.orchestrator import Orchestrator, _INTERCEPTED
from core.tool_registry import ToolRegistry


def _orch(tmp_path, state, events=None):
    cb = (lambda e: events.append(e)) if events is not None else None
    return Orchestrator(object(), ToolRegistry(), tmp_path, quiet=True,
                        engagement_state=state, log_callback=cb)


def test_record_password_credential(tmp_path):
    events = []
    state = EngagementState(target="x")
    o = _orch(tmp_path, state, events)
    res = o._handle_record_credential({
        "type": "password", "username": "admin", "secret": "S3cret!99",
        "service": "smb", "location": "SMB 10.0.0.5", "verified": True,
    }, "pentest/exploitation")

    assert res["recorded"] is True
    c = state.credentials[0]
    assert c.cred_type == "password"
    assert c.username == "admin"
    assert c.secret == "S3cret!99"
    assert c.location == "SMB 10.0.0.5"
    assert c.verified is True
    # UI gets an immediate event with the real + masked value
    assert any(e["type"] == "credential" and e["secret"] == "S3cret!99" for e in events)


def test_record_hash_credential(tmp_path):
    state = EngagementState(target="x")
    o = _orch(tmp_path, state)
    o._handle_record_credential({
        "type": "hash", "username": "svc_sql",
        "secret": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        "secret_format": "NTLM", "location": "DC01",
    }, "agent")
    c = state.credentials[0]
    assert c.cred_type == "hash"
    assert c.secret_format == "NTLM"
    assert c.location == "DC01"


def test_record_api_key_no_username(tmp_path):
    state = EngagementState(target="x")
    o = _orch(tmp_path, state)
    o._handle_record_credential({
        "type": "api_key", "secret": "sk-live-abcdef123456", "location": "api.acme.com",
    }, "agent")
    c = state.credentials[0]
    assert c.cred_type == "api_key"
    assert c.username is None
    assert c.secret == "sk-live-abcdef123456"


def test_record_requires_secret(tmp_path):
    state = EngagementState(target="x")
    o = _orch(tmp_path, state)
    res = o._handle_record_credential({"type": "password", "username": "x"}, "agent")
    assert res["recorded"] is False
    assert state.credentials == []


def test_context_block_has_real_secret_and_format():
    state = EngagementState(target="x")
    state.add_credential(cred_type="hash", secret="31d6cfe0d16ae931b73c59d7e0c089c0",
                         username="svc", secret_format="NTLM", location="DC01", verified=True)
    block = state.build_context_block()
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" in block   # real value the agent can use
    assert "NTLM" in block
    assert "svc" in block
    # masked form is only for the operator UI, not this context
    assert state.credentials[0].secret_masked != "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_cold_start_seeded_creds_reach_the_agent():
    # A manually pre-loaded /cred add (or brief cred) lands in state.credentials
    # BEFORE any tool has run, so tool_log is empty. has_context() must still fire
    # so the first agent's prompt carries the seeded credential — the old gate
    # keyed on tool_log alone, so the agent started blind to manual creds.
    state = EngagementState(target="x")
    assert state.has_context() is False                    # truly empty
    state.add_credential(cred_type="password", username="root",
                         secret="toor123", service="ssh", source_agent="manual")
    assert not state.tool_log                              # nothing has run yet
    assert state.has_context() is True                    # but there IS intel to hand over
    assert "toor123" in state.build_context_block()       # real secret reaches the agent


def test_cold_start_operator_brief_reaches_the_agent():
    # Same gate: tech_context / focus_areas / out_of_scope seeded at intake must
    # surface on a cold start, not get swallowed until the first tool runs.
    state = EngagementState(target="x")
    state.tech_context = "Internal Flowise instance, customFunction RCE suspected."
    assert state.has_context() is True
    assert "Flowise" in state.build_context_block()


def test_record_credential_is_intercepted():
    assert "record_credential" in _INTERCEPTED


def test_regex_scrape_removed(tmp_path):
    state = EngagementState(target="x")
    o = _orch(tmp_path, state)
    assert not hasattr(o, "_extract_creds_from_finding")
