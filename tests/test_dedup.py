from core.utils import title_similarity, titles_match
from core.engagement_state import EngagementState
from core.models import Finding, EngagementRun
from reporting.formatter import merge_runs


def _f(title, ftype="vuln", target="10.0.0.5", verified=True):
    return Finding(type=ftype, severity="critical", title=title, description="d",
                   target=target, verified=verified)


# ── the real reworded-duplicate from the live report ──────────────────────────

def test_reworded_password_reset_dup_matches():
    a = "Authentication Bypass via Unauthenticated Password Reset"
    b = "Unauthenticated Password Reset Allows Account Takeover"
    assert titles_match(a, b)                       # >= 0.6 → same issue


def test_distinct_findings_do_not_match():
    # SSRF vs the RCE chain — share a couple words, clearly different
    a = "Server-Side Request Forgery via Custom Model Context Protocol Node Loader"
    b = "Unauthenticated Remote Code Execution via Chained Password Reset and Node Loader Injection"
    assert not titles_match(a, b)


def test_find_duplicate_merges_reworded_same_type():
    s = EngagementState(target="10.0.0.5")
    existing = [_f("Authentication Bypass via Unauthenticated Password Reset")]
    dup = s.find_duplicate("Unauthenticated Password Reset Allows Account Takeover",
                           "10.0.0.5", existing, new_type="vuln")
    assert dup is existing[0]


def test_find_duplicate_respects_type_gate():
    # SSH recon vs SSH config — overlapping words but different type → keep separate
    s = EngagementState(target="10.0.0.5")
    existing = [_f("Secure Shell Service Exposed", ftype="recon")]
    dup = s.find_duplicate("Secure Shell Service with Password Authentication Enabled",
                           "10.0.0.5", existing, new_type="config")
    assert dup is None


def test_find_duplicate_target_gate():
    s = EngagementState(target="10.0.0.5")
    existing = [_f("Unauthenticated Password Reset Allows Account Takeover")]
    assert s.find_duplicate("Authentication Bypass via Unauthenticated Password Reset",
                            "10.0.0.6", existing, new_type="vuln") is None


# ── report-time merge dedups reworded findings across runs ────────────────────

def test_merge_runs_collapses_reworded_dups():
    r1 = EngagementRun(agent="enum", target="10.0.0.5")
    r1.findings = [_f("Authentication Bypass via Unauthenticated Password Reset", verified=False)]
    r2 = EngagementRun(agent="exploit", target="10.0.0.5")
    r2.findings = [_f("Unauthenticated Password Reset Allows Account Takeover", verified=True)]
    merged = merge_runs([r1, r2], target="10.0.0.5")
    titles = [f.title for f in merged.findings]
    assert len(titles) == 1                         # the two reworded copies collapse
    assert merged.findings[0].verified is True      # verified copy kept
