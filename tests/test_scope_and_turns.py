"""vhost auto-scoping and the /turns command."""
import core.config as config
from core.engagement_state import EngagementState


# ── vhost / FQDN auto-scoping ──────────────────────────────────────────────────

def test_vhost_recorded_by_agent_is_in_scope():
    # The LLM reads a redirect out of tool output and records the vhost itself
    # (no Python regex) — via record_service(hostname=...).
    s = EngagementState(target="10.129.244.96")
    assert s.in_scope("facts.htb") is False          # not known yet
    s.annotate_service(host="10.129.244.96", port=80, service="http",
                       app="nginx", hostname="facts.htb")
    assert s.in_scope("facts.htb") is True
    assert s.in_scope("http://facts.htb/admin/login") is True
    assert "facts.htb" in s.scope_targets


def test_vhost_from_nmap_hostname_is_in_scope():
    s = EngagementState(target="10.10.10.5")
    s.ingest_tool_result("nmap_scan", {"hosts": [{"ip": "10.10.10.5", "hostnames": ["box.htb"],
        "open_ports": [{"port": 22, "protocol": "tcp", "service": "ssh"}]}]})
    assert s.in_scope("box.htb") is True


def test_unrelated_host_stays_out_of_scope():
    s = EngagementState(target="10.0.0.7")
    s.ingest_tool_result("nmap_scan", {"hosts": [{"ip": "10.0.0.7", "hostnames": ["box.htb"],
        "open_ports": [{"port": 80, "protocol": "tcp", "service": "http"}]}]})
    assert s.in_scope("evil.example.com") is False


def test_explicit_out_of_scope_still_wins():
    s = EngagementState(target="10.0.0.7")
    s.out_of_scope = ["bad.htb"]
    # even if recon ties bad.htb to the in-scope IP, the exclusion wins
    s.ingest_tool_result("nmap_scan", {"hosts": [{"ip": "10.0.0.7", "hostnames": ["bad.htb"],
        "open_ports": [{"port": 80, "protocol": "tcp", "service": "http"}]}]})
    assert s.in_scope("bad.htb") is False


# ── /turns command ─────────────────────────────────────────────────────────────

def test_turns_set_and_show(monkeypatch):
    store = {}
    monkeypatch.setattr(config, "set_value", lambda k, v: store.__setitem__(k, v))
    monkeypatch.setattr(config, "get", lambda k, d=None: store.get(k, d))
    from ui.commands import handle_turns
    _, ok = handle_turns(["60"])
    assert ok and store["max_turns_default"] == 60
    lines, ok = handle_turns([])
    assert ok and "60" in " ".join(lines)


def test_turns_off_is_unlimited(monkeypatch):
    store = {}
    monkeypatch.setattr(config, "set_value", lambda k, v: store.__setitem__(k, v))
    monkeypatch.setattr(config, "get", lambda k, d=None: store.get(k, d))
    from ui.commands import handle_turns
    _, ok = handle_turns(["off"])
    assert ok and store["max_turns_default"] == 0
    lines, _ = handle_turns([])
    assert "unlimited" in " ".join(lines).lower()


def test_turns_rejects_garbage(monkeypatch):
    monkeypatch.setattr(config, "set_value", lambda k, v: None)
    monkeypatch.setattr(config, "get", lambda k, d=None: d)
    from ui.commands import handle_turns
    _, ok = handle_turns(["abc"])
    assert ok is False


def test_default_turns_is_60():
    # The shipped default (a fresh _DEFAULTS, not a user's config.yaml)
    assert config._DEFAULTS["max_turns_default"] == 60


def test_dispatch_routes_turns():
    from ui.commands import dispatch
    out = dispatch("/turns")
    assert out is not None and out[1] is True
