from core.engagement_state import EngagementState
from core.models import EngagementBrief
from core.intake import brief_from_intent


def _state(target="10.0.0.5"):
    return EngagementState(target=target)


# ── surface registration ──────────────────────────────────────────────────────

def test_add_surface_and_dedup():
    s = _state()
    a = s.add_surface("10.0.0.5", service="http", port=80)
    b = s.add_surface("10.0.0.5", service="http", port=80)
    assert a is b                       # idempotent on key
    assert len(s.surfaces) == 1
    assert a.label.startswith("http://10.0.0.5:80")


def test_add_surface_rejects_out_of_scope():
    s = _state()
    s.out_of_scope = ["10.0.0.9"]
    assert s.add_surface("10.0.0.9", service="smb") is None
    assert s.surfaces == []


def test_derive_surfaces_from_recon():
    s = _state()
    s.ingest_tool_result("nmap_scan", {"hosts": [{
        "ip": "10.0.0.5",
        "open_ports": [
            {"port": 80, "protocol": "tcp", "service": "http"},
            {"port": 445, "protocol": "tcp", "service": "smb"},
        ],
    }]})
    added = s.derive_surfaces_from_recon()
    assert len(added) == 2
    # Idempotent — a second derive adds nothing
    assert s.derive_surfaces_from_recon() == []


def test_next_surface_skips_exhausted_and_caps():
    s = _state()
    s.add_surface("10.0.0.5", service="http", port=80)
    s.add_surface("10.0.0.5", service="smb", port=445)
    first = s.next_surface()
    first.status = "exhausted"
    second = s.next_surface()
    assert second is not first
    # Cap by cycles
    second.cycles = 4
    assert s.next_surface(max_cycles_per_surface=4) is None


# ── intel signature (exhaustion detector) ─────────────────────────────────────

def test_intel_signature_changes_with_new_intel():
    s = _state()
    sig0 = s.intel_signature()
    s.add_credential("plaintext", "secret", "agent", username="admin")
    assert s.intel_signature() != sig0


def test_intel_signature_counts_findings():
    s = _state()

    class F:
        def __init__(self, v): self.verified = v

    sig_none = s.intel_signature([])
    sig_one  = s.intel_signature([F(False)])
    sig_ver  = s.intel_signature([F(True)])
    assert sig_none != sig_one != sig_ver


# ── plans ─────────────────────────────────────────────────────────────────────

def test_record_and_get_plan():
    s = _state()
    surface = s.add_surface("10.0.0.5", service="http", port=80)
    plan = s.record_plan(surface.id, [
        {"action": "Test id param for IDOR", "rationale": "reflected", "technique": "IDOR"},
        {"action": "", "rationale": "skip"},   # empty action filtered out
    ], created_by="pentest/planning")
    assert len(plan.items) == 1
    assert s.get_plan_for(surface.id) is plan
    # Recording again replaces, not appends
    s.record_plan(surface.id, [{"action": "new"}])
    assert len([p for p in s.plans if p.surface_id == surface.id]) == 1


# ── out-of-scope on in_scope ──────────────────────────────────────────────────

def test_in_scope_respects_out_of_scope():
    s = EngagementState(target="acme.com")
    s.out_of_scope = ["billing.acme.com"]
    assert s.in_scope("api.acme.com")
    assert not s.in_scope("billing.acme.com")


# ── brief from regex intent ───────────────────────────────────────────────────

def test_brief_from_intent():
    intent = {
        "action": "pipeline", "target": "10.0.0.5",
        "objective": "scan it", "allowed_phases": ["discovery", "assessment", "reporting"],
        "entry": "pentest/enumeration",
    }
    brief = brief_from_intent(intent, "scan it")
    assert brief.primary_target == "10.0.0.5"
    # exploitation is on by default now (toggle with /exploit); brief reflects config
    assert brief.exploitation_allowed


def test_brief_exploitation_flag():
    b = EngagementBrief(targets=["x"], allowed_phases=["discovery", "exploitation"])
    assert b.exploitation_allowed
    assert b.primary_target == "x"
