"""Ingest layer — evidence → Leads, and the run-outcome classifier."""
from core.models import Finding
from core.engagement_state import EngagementState
from core.leads import LeadStore, Lead, level_of
from core.ingest import (
    reach_for_finding, infer_cost, leads_from_findings, leads_from_recon,
    leads_from_credentials, reach_from_evidence, classify_outcome, ingest_all,
)


def _f(title, type="vuln", severity="high", verified=False, target="t"):
    return Finding(type=type, severity=severity, title=title, description="d",
                   target=target, verified=verified)


# ── reach mapping ─────────────────────────────────────────────────────────────

def test_reach_running_as_root_is_root():
    # The Silentium case: a verified misconfig that IS a path to root.
    f = _f("Second Flowise Instance Running as Root on Host", verified=True)
    assert reach_for_finding(f) == "root"


def test_reach_rce_is_exploited():
    assert reach_for_finding(_f("Remote Code Execution via Flowise")) == "exploited"


def test_reach_privesc_and_recon():
    assert reach_for_finding(_f("Sudo Misconfiguration Allows Privilege Escalation")) == "privesc"
    assert reach_for_finding(_f("Open Port 80", type="recon", severity="info")) == ""  # no lead


def test_infer_cost():
    assert infer_cost("password brute force with rockyou") == "expensive"
    assert infer_cost("anonymous FTP access") == "cheap"
    assert infer_cost("some generic check") == "medium"


# ── producers ─────────────────────────────────────────────────────────────────

def test_findings_become_leads_root_path_is_high_reach():
    leads = leads_from_findings([
        _f("Second Flowise Instance Running as Root on Host", verified=True),
        _f("Open Port 22", type="recon", severity="info"),   # → no lead
    ])
    assert len(leads) == 1
    lead = leads[0]
    assert lead.reach_level == "root" and lead.kind == "escalation"
    assert lead.prior > 0.7                       # verified + high severity


def test_recon_becomes_surface_leads_web_outranks_ssh():
    st = EngagementState(target="10.0.0.5")
    st.recon.open_ports = [
        {"host": "10.0.0.5", "port": 80, "service": "http", "version": "nginx"},
        {"host": "10.0.0.5", "port": 22, "service": "ssh", "version": "OpenSSH"},
    ]
    leads = leads_from_recon(st)
    by_port = {l.description: l for l in leads}
    web = next(l for l in leads if ":80" in l.description)
    ssh = next(l for l in leads if ":22" in l.description)
    assert all(l.kind == "surface" and l.reach_level == "service" for l in leads)
    assert web.prior > ssh.prior                  # service-weight prior: web ≫ ssh


def test_credentials_become_access_leads():
    st = EngagementState(target="t")
    st.add_credential(secret="hunter2", username="ben", service="smtp", verified=True)
    leads = leads_from_credentials(st)
    assert len(leads) == 1
    assert leads[0].kind == "cred" and leads[0].reach_level == "user"
    assert "ben" in leads[0].description and leads[0].prior >= 0.75   # verified


def test_ingest_all_dedups_and_counts_new():
    st = EngagementState(target="t")
    st.recon.open_ports = [{"host": "t", "port": 80, "service": "http"}]
    store = LeadStore()
    findings = [_f("SQL Injection in login")]
    n1 = ingest_all(store, st, findings)
    assert n1 == len(store.leads) and n1 >= 2          # surface + vuln lead
    n2 = ingest_all(store, st, findings)               # same evidence again
    assert n2 == 0                                     # nothing new (deduped)


# ── reach_from_evidence (conservative) ────────────────────────────────────────

def test_reach_from_evidence_root_flag_vs_catalogued_path():
    # A captured root flag reaches root...
    assert reach_from_evidence([{"location": "/root/root.txt"}], False, []) == level_of("root")
    # ...but a verified finding that merely DESCRIBES a root path does NOT — it
    # stays a lead until a flag/session proves it. This is the anti-"declare victory
    # on a catalogue" guard.
    finding = [{"title": "Service Running as Root on Host", "verified": True}]
    assert reach_from_evidence([], False, finding) < level_of("root")


def test_reach_from_evidence_user_flag_and_cred():
    assert reach_from_evidence([{"location": "/home/ben/user.txt"}], False, []) == level_of("user")
    assert reach_from_evidence([], True, []) == level_of("foothold")
    assert reach_from_evidence([], False,
        [{"title": "Remote Code Execution", "verified": True}]) == level_of("exploited")


# ── classify_outcome ──────────────────────────────────────────────────────────

def _lead(reach="exploited"):
    return Lead(kind="exploit", description="x", reach_level=reach, prior=0.6)


def test_classify_advanced_on_reach_and_conclude():
    status, reach = classify_outcome(_lead("exploited"), level_of("exploited"), 0,
                                     concluded=False, made_progress=True, spawned_leads=False)
    assert status == "advanced" and reach == "exploited"
    status, _ = classify_outcome(_lead("root"), 0, 0, concluded=True,
                                 made_progress=False, spawned_leads=False)
    assert status == "advanced"


def test_classify_partial_progress_still_advances_frontier():
    # didn't hit the lead's own goal (root) but moved the frontier (0→exploited)
    status, reach = classify_outcome(_lead("root"), level_of("exploited"), 0,
                                     concluded=False, made_progress=True, spawned_leads=True)
    assert status == "advanced" and reach == "exploited"


def test_classify_inconclusive_vs_refuted():
    # spawned a new lead but didn't confirm → re-queue
    s, _ = classify_outcome(_lead(), 0, 0, concluded=False,
                            made_progress=False, spawned_leads=True)
    assert s == "inconclusive"
    # nothing at all came back → dead end, release
    s, _ = classify_outcome(_lead(), 0, 0, concluded=False,
                            made_progress=False, spawned_leads=False)
    assert s == "refuted"
    # explicit refute signal wins
    s, _ = classify_outcome(_lead(), 0, 0, concluded=False, made_progress=True,
                            spawned_leads=True, refuted=True)
    assert s == "refuted"
