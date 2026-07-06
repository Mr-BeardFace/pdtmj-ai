from core.engagement_state import EngagementState
from core.models import Finding


def _state(target="10.10.10.5"):
    return EngagementState(target=target)


# ── scope ─────────────────────────────────────────────────────────────────────

def test_scope_seeded_with_target():
    s = _state()
    assert s.scope_targets == ["10.10.10.5"]
    assert s.in_scope("10.10.10.5")


def test_scope_host_port_collapses_to_host():
    s = _state()
    assert s.in_scope("10.10.10.5:445")


def test_scope_rejects_other_hosts():
    s = _state()
    assert not s.in_scope("10.10.10.6")
    assert not s.in_scope("evil.com")


def test_scope_cidr_entry_matches_contained_ips():
    s = _state(target="10.10.10.0/24")
    assert s.in_scope("10.10.10.99")
    assert not s.in_scope("10.10.11.1")


def test_scope_domain_entry_matches_subdomains():
    s = _state(target="example.com")
    assert s.in_scope("example.com")
    assert s.in_scope("api.example.com")
    assert s.in_scope("https://example.com:8443/admin")
    assert not s.in_scope("notexample.com")
    assert not s.in_scope("example.com.evil.net")


def test_add_scope_expands():
    s = _state()
    assert not s.in_scope("192.168.1.10")
    s.add_scope("192.168.1.10")
    assert s.in_scope("192.168.1.10")
    # No duplicate entries
    s.add_scope("192.168.1.10")
    assert s.scope_targets.count("192.168.1.10") == 1


# ── scan cache ────────────────────────────────────────────────────────────────

def test_cache_stores_full_result():
    s = _state()
    result = {"hosts": [{"ip": "10.10.10.5", "open_ports": [{"port": 80}]}], "host_count": 1}
    s.store_cache("nmap_scan", {"target": "10.10.10.5"}, result, "1 host(s)")
    cached = s.check_cache("nmap_scan", {"target": "10.10.10.5"})
    assert cached is not None
    assert cached["result"] == result
    assert cached["summary"] == "1 host(s)"


def test_cache_skips_noncacheable_tools():
    s = _state()
    s.store_cache("http_request", {"url": "http://x"}, {"status_code": 200}, "HTTP 200")
    assert s.check_cache("http_request", {"url": "http://x"}) is None


def test_cache_miss_on_different_inputs():
    s = _state()
    s.store_cache("nmap_scan", {"target": "a"}, {"host_count": 0}, "")
    assert s.check_cache("nmap_scan", {"target": "b"}) is None


# ── dedup / followups / ingest ────────────────────────────────────────────────

def _finding(title, target="10.10.10.5", **kw):
    return Finding(type="vuln", severity="high", title=title,
                   description="d", target=target, **kw)


def test_find_duplicate_exact_and_fuzzy():
    s = _state()
    existing = [_finding("SQL Injection in /login username parameter")]
    assert s.find_duplicate("SQL Injection in /login username parameter",
                            "10.10.10.5", existing) is existing[0]
    # High word overlap
    assert s.find_duplicate("SQL injection in /login username parameter!",
                            "10.10.10.5", existing) is existing[0]
    # Different target never matches
    assert s.find_duplicate("SQL Injection in /login username parameter",
                            "10.10.10.6", existing) is None


def test_followup_queue_dedupes():
    s = _state()
    assert s.request_followup("pentest/web", "10.10.10.5") is True
    assert s.request_followup("pentest/web", "10.10.10.5") is False
    items = s.drain_followup_queue()
    assert len(items) == 1
    assert s.followup_queue == []


def test_ingest_nmap_dedupes_ports():
    s = _state()
    result = {"hosts": [{"ip": "10.10.10.5",
                         "open_ports": [{"port": 80, "protocol": "tcp", "service": "http"}],
                         "os_matches": [{"name": "Linux 5.x"}]}]}
    s.ingest_tool_result("nmap_scan", result)
    s.ingest_tool_result("nmap_scan", result)
    assert len(s.recon.open_ports) == 1
    assert s.recon.os_info["10.10.10.5"] == "Linux 5.x"


def test_ingest_hydra_credentials_verified():
    s = _state()
    s.ingest_tool_result("hydra", {
        "found_credentials": [{"login": "admin", "password": "hunter2"}],
        "service": "ssh", "port": 22,
    }, source_agent="pentest/network")
    assert len(s.credentials) == 1
    c = s.credentials[0]
    assert c.username == "admin"
    assert c.verified is True
    assert "hunter2" not in c.secret_masked


def test_add_script_dedups_by_path():
    s = _state()
    s.add_script("brute the 4-digit PIN", "/tmp/poc1.py", "python")
    s.add_script("brute the 4-digit PIN (reworded)", "/tmp/poc1.py", "python")  # same path
    s.add_script("decode the token", "/tmp/poc2.py", "python")
    assert len(s.scripts) == 2                       # same path collapses to one entry
    assert s.scripts[0]["purpose"] == "brute the 4-digit PIN (reworded)"  # purpose refreshed
    assert {x["path"] for x in s.scripts} == {"/tmp/poc1.py", "/tmp/poc2.py"}
    s.add_script("ignored", "", "python")            # empty path is a no-op
    assert len(s.scripts) == 2


# ── agent handoff ─────────────────────────────────────────────────────────────

def test_add_handoff_records_and_truncates():
    s = _state()
    long_summary = "x" * 5000
    s.add_handoff("pentest/enumeration", long_summary)
    assert len(s.handoffs) == 1
    assert s.handoffs[0]["agent"] == "pentest/enumeration"
    # Capped well under the raw length, with an ellipsis appended.
    assert len(s.handoffs[0]["summary"]) <= EngagementState._HANDOFF_CAP + 4
    assert s.handoffs[0]["summary"].endswith("…")


def test_add_handoff_empty_is_noop():
    s = _state()
    s.add_handoff("pentest/web", "   ")
    s.add_handoff("pentest/web", "")
    assert s.handoffs == []


def test_add_handoff_keeps_only_recent():
    s = _state()
    for i in range(EngagementState._HANDOFF_KEEP + 3):
        s.add_handoff(f"agent-{i}", f"summary {i}")
    assert len(s.handoffs) == EngagementState._HANDOFF_KEEP
    # Oldest dropped, newest retained.
    assert s.handoffs[-1]["agent"] == f"agent-{EngagementState._HANDOFF_KEEP + 2}"
    assert s.handoffs[0]["agent"] == f"agent-3"


def test_context_block_labels_confirmed_vs_unconfirmed():
    # A version/banner CVE (verified=false) must read as a LEAD, not a confirmed
    # exploitable issue — the next agent was misreading the old subtle "?" marker.
    s = _state()
    findings = [
        Finding(type="vuln", severity="high", title="Anonymous FTP Access",
                description="d", target="t", verified=True),
        Finding(type="vuln", severity="critical", title="Next.js Authorization Bypass",
                description="inferred from version banner", target="t", verified=False),
    ]
    block = s.build_context_block(findings)
    assert "[CONFIRMED] Anonymous FTP Access" in block
    assert "[UNCONFIRMED] Next.js Authorization Bypass" in block
    assert "is a LEAD, not a fact" in block            # the clarifying rule is present


def test_context_block_sorts_confirmed_before_unconfirmed():
    # A proven fact must outrank an unconfirmed lead regardless of the agent's
    # severity label — so a guessed "critical" can't dominate the block over
    # something actually reproduced (the Overwatch false-GenericAll failure mode).
    s = _state()
    findings = [
        Finding(type="vuln", severity="medium", title="Proven SMB Cred",
                description="d", target="t", verified=True),
        Finding(type="vuln", severity="critical", title="Guessed DA Path",
                description="d", target="t", verified=False),
    ]
    block = s.build_context_block(findings)
    assert block.index("Proven SMB Cred") < block.index("Guessed DA Path")


def test_context_block_shows_recent_tool_output():
    # The most recent tool calls carry their ACTUAL output, not just the one-line
    # summary, so the next agent inherits the real command results.
    s = _state()
    s.log_tool(agent="pentest/rce", tool_name="run_script", command="wing rce",
               summary="exit 0",
               result={"stdout": "id\nuid=1000(wingftp) gid=1000(wingftp)\n", "exit_code": 0})
    block = s.build_context_block([])
    assert "uid=1000(wingftp)" in block          # real output threaded forward
    # and the stored snippet is the clean output, not the raw JSON envelope
    assert s.tool_log[-1].truncated_output.startswith("id\nuid=1000(wingftp)")


def test_context_block_includes_handoffs():
    s = _state()
    s.add_handoff("pentest/network", "Tested SMB null session — denied. Promising: anonymous LDAP on :389.")
    # Tool log is what triggers the block to be built with content; add one entry.
    s.ingest_tool_result("nmap_scan", {"_command": "nmap -Pn 10.10.10.5"}, source_agent="pentest/enumeration")
    block = s.build_context_block([])
    assert "Handoff from prior agents" in block
    assert "anonymous LDAP on :389" in block


def test_context_block_findings_carry_detail_for_top_items():
    s = _state()
    s.ingest_tool_result("nmap_scan", {"_command": "nmap -Pn 10.10.10.5"}, source_agent="x")
    f = Finding(
        type="vuln", severity="critical", title="Unauth RCE in Foo",
        description="The /upload endpoint accepts a serialized blob and deserializes it.",
        target="10.10.10.5", evidence={"endpoint": "/upload", "marker": "rO0AB"},
    )
    block = s.build_context_block([f])
    assert "Unauth RCE in Foo" in block
    assert "deserializes it" in block          # description surfaced for a top finding
    assert "endpoint=/upload" in block          # evidence snippet surfaced
