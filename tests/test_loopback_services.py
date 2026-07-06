"""Internal/loopback services. 127.0.0.1 is never a recorded host (it's ambiguous —
target loopback vs the pivot's local forward vs the Kali box); a loopback service is
recorded under the foothold's real IP with bind='loopback'. port_forward auto-records
the internal service it exposes + the channel to reach it."""
from core.engagement_state import EngagementState, _is_loopback_host
from core.models import EngagementRun
from core.orchestrator import Orchestrator
from core.tool_registry import ToolRegistry


def _orch(tmp_path, s):
    return Orchestrator(object(), ToolRegistry(), tmp_path, quiet=True, engagement_state=s)


def _scoped(t="10.0.0.1"):
    s = EngagementState(target=t); s.add_scope(t); return s


def test_is_loopback_host():
    for h in ("127.0.0.1", "localhost", "127.1.2.3", "::1",
              "http://127.0.0.1:8080/x", "localhost:5432"):
        assert _is_loopback_host(h), h
    for h in ("10.0.0.1", "0.0.0.0", "dc01.htb", "192.168.1.5", ""):
        assert not _is_loopback_host(h), h


# ── guard: loopback host rejected at every recording door ─────────────────────

def test_record_service_rejects_loopback(tmp_path):
    s = _scoped(); o = _orch(tmp_path, s)
    r = o._handle_record_service({"host": "127.0.0.1", "port": 8080}, "a")
    assert r["recorded"] is False and "bind='loopback'" in r["error"]
    assert not any(sv.get("host") == "127.0.0.1" for sv in s.services)


def test_annotate_finding_rejects_loopback_target(tmp_path):
    s = _scoped(); o = _orch(tmp_path, s)
    run = EngagementRun(agent="a", target="10.0.0.1")
    r = o._handle_annotation({"title": "X", "type": "vuln", "severity": "high",
                              "description": "d", "target": "127.0.0.1"}, run, "10.0.0.1")
    assert r["status"] == "error" and "bind='loopback'" in r["message"]
    assert run.findings == []


def test_register_surface_rejects_loopback(tmp_path):
    s = _scoped(); o = _orch(tmp_path, s)
    assert o._handle_register_surface({"host": "localhost", "port": 8080}, "a")["registered"] is False


def test_record_service_stores_bind(tmp_path):
    s = _scoped(); o = _orch(tmp_path, s)
    o._handle_record_service({"host": "10.0.0.1", "port": 8080, "service": "http",
                              "bind": "loopback"}, "a")
    assert next(sv for sv in s.services if sv["port"] == 8080)["bind"] == "loopback"


# ── capture: port_forward auto-records the internal service + channel ──────────

def test_port_forward_loopback_records_service_on_foothold_and_fact():
    s = _scoped("10.129.47.187")
    s.ingest_tool_result("port_forward", {
        "action": "start", "mode": "local", "local": "127.0.0.1:41080",
        "remote_host": "127.0.0.1", "remote_port": 8080, "foothold": "10.129.47.187",
        "spec": "127.0.0.1:41080 -> 127.0.0.1:8080 via user@10.129.47.187"}, source_agent="post")
    svc = next(sv for sv in s.services if sv["port"] == 8080)
    assert svc["host"] == "10.129.47.187" and svc["bind"] == "loopback"    # not 127.0.0.1
    assert any("reachable at 127.0.0.1:41080" in f.statement for f in s.operational_facts)


def test_port_forward_internal_ip_records_on_that_host():
    s = _scoped("10.10.0.1")
    s.ingest_tool_result("port_forward", {
        "action": "start", "mode": "local", "local": "127.0.0.1:1433",
        "remote_host": "10.10.5.5", "remote_port": 1433, "foothold": "10.10.0.1",
        "spec": "x"}, source_agent="post")
    svc = next(sv for sv in s.services if sv["host"] == "10.10.5.5")
    assert svc["port"] == 1433 and svc.get("bind") == ""                    # a real internal host


def test_port_forward_dynamic_records_only_channel_fact():
    s = _scoped("10.10.0.1")
    s.ingest_tool_result("port_forward", {
        "action": "start", "mode": "dynamic", "local": "127.0.0.1:1080",
        "foothold": "10.10.0.1", "spec": "SOCKS5 ..."}, source_agent="post")
    assert s.services == []                                                 # no single service
    assert any("SOCKS proxy" in f.statement for f in s.operational_facts)


def test_internal_service_from_forward_helper():
    from core.engagement_state import internal_service_from_forward
    loop = internal_service_from_forward({"action": "start", "mode": "local",
        "remote_host": "127.0.0.1", "remote_port": 8080, "foothold": "10.0.0.9"})
    assert loop == {"host": "10.0.0.9", "port": 8080, "bind": "loopback"}
    inter = internal_service_from_forward({"action": "start", "mode": "local",
        "remote_host": "10.1.1.5", "remote_port": 1433, "foothold": "10.0.0.9"})
    assert inter == {"host": "10.1.1.5", "port": 1433, "bind": ""}
    assert internal_service_from_forward({"action": "start", "mode": "dynamic"}) is None


# ── display: loopback service wraps its bind into the Port cell (127.0.0.1:8080) ──

def test_loopback_service_wraps_port_in_hosts_table():
    import asyncio
    from ui.app import PentestApp
    from textual.widgets import DataTable

    async def _run():
        app = PentestApp()
        async with app.run_test():
            app._host_name["10.129.47.187"] = "dc01.htb"
            app._add_host_row("10.129.47.187", {"port": 80, "protocol": "tcp",
                                                "service": "http", "version": "nginx"})
            app._add_host_row("10.129.47.187", {"port": 8080, "protocol": "tcp",
                "service": "http", "version": "Werkzeug", "bind": "loopback"},
                authoritative=True)
            dt = app.query_one("#hosts-table", DataTable)
            rows = {str(r.key.value): dt.get_row(r.key) for r in dt.ordered_rows}
            lb = rows["10.129.47.187:8080/tcp:"]
            # Port cell (index 4: IP,Hostname,Vhost,OS,Port,...) shows the loopback bind
            assert lb[4] == "127.0.0.1:8080"
            ext = rows["10.129.47.187:80/tcp:"]
            assert ext[4] == "80"                                    # external stays bare
            # copy source keeps the wrapped port too
            assert app._host_rowdata["10.129.47.187:8080/tcp:"][3] == "127.0.0.1:8080"

    asyncio.run(_run())
