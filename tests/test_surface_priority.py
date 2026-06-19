"""Surface prioritization, tool hints, and staged enumeration."""
from core.engagement_state import (
    EngagementState, surface_priority, service_weight,
)
from core.models import Surface, EngagementBrief
from core.pipeline import EngagementDriver, ENUM_AGENT


class _F:
    def __init__(self, severity, target="", title="", verified=False, evidence=None):
        self.severity = severity
        self.target = target
        self.title = title
        self.verified = verified
        self.evidence = evidence or {}


# ── service weighting ─────────────────────────────────────────────────────────

def test_high_value_services_outrank_ssh():
    assert service_weight("http") > service_weight("ssh")
    assert service_weight("minio") > service_weight("http")
    assert service_weight("smb") > service_weight("ssh")
    assert service_weight("mysql") > service_weight("telnet")
    # unknown service sits in the middle, still above ssh
    assert service_weight("ssh") < service_weight("totally-unknown") < service_weight("http")


def test_domain_controller_consolidates_and_outranks_web():
    """An AD DC's identity ports fold into one 'Domain Controller' surface that
    outranks the host's web ports; SMB stays its own surface."""
    s = EngagementState(target="10.0.0.5")
    s.recon.open_ports = [
        {"host": "10.0.0.5", "port": 80,   "service": "http"},
        {"host": "10.0.0.5", "port": 88,   "service": "kerberos"},
        {"host": "10.0.0.5", "port": 389,  "service": "ldap"},
        {"host": "10.0.0.5", "port": 445,  "service": "smb"},
        {"host": "10.0.0.5", "port": 636,  "service": "ldaps"},
        {"host": "10.0.0.5", "port": 8530, "service": "http"},
    ]
    s.derive_surfaces_from_recon()
    assert s.is_domain_controller("10.0.0.5")

    elig = {x.service: x for x in s.eligible_surfaces()}
    # one consolidated AD surface, the identity ports folded out of selection
    assert "active-directory" in elig
    assert elig["active-directory"].component == "Domain Controller"
    assert "ldap" not in elig and "kerberos" not in elig and "ldaps" not in elig
    # SMB stays selectable; web stays selectable
    assert "smb" in elig and "http" in elig
    # the DC surface is the top pick, above the web ports
    assert s.next_surface().service == "active-directory"
    assert surface_priority(elig["active-directory"]) > surface_priority(elig["http"])


def test_non_dc_host_is_not_consolidated():
    # A plain web+ssh host must NOT be turned into an AD surface.
    s = EngagementState(target="10.0.0.9")
    s.recon.open_ports = [
        {"host": "10.0.0.9", "port": 80, "service": "http"},
        {"host": "10.0.0.9", "port": 22, "service": "ssh"},
    ]
    s.derive_surfaces_from_recon()
    assert not s.is_domain_controller("10.0.0.9")
    assert all(x.service != "active-directory" for x in s.surfaces)


def test_next_surface_picks_high_value_over_ssh_regardless_of_order():
    # SSH discovered FIRST (port order) — must NOT be chosen over web/minio.
    s = EngagementState(target="10.0.0.5")
    s.add_surface("10.0.0.5", service="ssh", port=22)
    s.add_surface("10.0.0.5", service="http", port=80)
    s.add_surface("10.0.0.5", service="http", port=54321, fingerprint="MinIO")
    chosen = s.next_surface()
    assert chosen.service == "http"      # never the ssh surface first


def test_unexploited_lead_raises_priority():
    web = Surface(host="h", service="http", port=80)
    nolead = surface_priority(web, [])
    lead = surface_priority(web, [_F("critical", target="http://h:80/admin", title="rce")])
    assert lead > nolead


def test_cycles_penalty_decays_priority():
    fresh = Surface(host="h", service="http", port=80, cycles=0)
    worn = Surface(host="h", service="http", port=80, cycles=3)
    assert surface_priority(worn) < surface_priority(fresh)


def test_lead_attribution_is_port_scoped():
    # A finding tagged to :54321 must not boost the :22 surface on the same host.
    ssh = Surface(host="h", service="ssh", port=22)
    f = _F("critical", target="http://h:54321/bucket", title="exposed bucket")
    assert surface_priority(ssh, [f]) == surface_priority(ssh, [])


# ── tool hints ────────────────────────────────────────────────────────────────

def _driver():
    state = EngagementState(target="h")
    brief = EngagementBrief(targets=["h"], allowed_phases=["discovery"])
    return EngagementDriver(object(), {}, state, brief)


def test_minio_hint_points_to_awscli_not_http():
    d = _driver()
    hint = d._tool_hint_for(Surface(host="h", service="http", port=54321, fingerprint="MinIO"))
    assert "awscli" in hint.lower() and "sigv4" in hint.lower()


def test_redis_and_ldap_hints():
    d = _driver()
    assert "redis_query" in d._tool_hint_for(Surface(host="h", service="redis", port=6379))
    assert "ldapsearch_query" in d._tool_hint_for(Surface(host="h", service="ldap", port=389))


def test_no_hint_for_plain_http():
    d = _driver()
    assert d._tool_hint_for(Surface(host="h", service="http", port=80, fingerprint="nginx 1.26")) == ""


# ── staged enum objectives ────────────────────────────────────────────────────

def test_discovery_objective_is_ports_only():
    d = _driver()
    obj = d._discovery_objective("10.0.0.5")
    assert "DISCOVERY ONLY" in obj and "do not" in obj.lower()


def test_service_id_objective_mentions_versions_and_vhost():
    d = _driver()
    obj = d._service_id_objective("10.0.0.5")
    assert "version" in obj.lower() and "vhost" in obj.lower()


def test_exploit_objective_defers_bruteforce():
    d = _driver()
    obj = d._exploit_objective(Surface(host="h", service="ssh", port=22), None)
    low = obj.lower()
    assert "last resort" in low and "hydra" in low


# ── fingerprint capture from recon ─────────────────────────────────────────────

def test_fingerprint_captured_from_nmap_version():
    s = EngagementState(target="10.0.0.5")
    s.ingest_tool_result("nmap_scan", {"hosts": [{"ip": "10.0.0.5", "open_ports": [
        {"port": 54321, "protocol": "tcp", "service": "http", "product": "MinIO", "version": ""},
    ]}]})
    s.derive_surfaces_from_recon()
    surf = next(x for x in s.surfaces if x.port == 54321)
    assert "minio" in surf.fingerprint.lower()
