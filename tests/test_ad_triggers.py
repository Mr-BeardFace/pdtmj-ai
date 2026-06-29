"""The active-directory playbook must trigger on domain-controller signals, not on
bare SMB/RPC — a Windows host with only 445/135/139 (no Kerberos/LDAP) is not a DC,
and AD attacks (Kerberos roasting, LDAP enum, BloodHound) have nothing to talk to."""
from core.registry import load_all_agents


def _trigger_keywords(agent) -> set[str]:
    kws: set[str] = set()
    for t in agent.metadata.get("triggers", []):
        for v in t.get("title_keywords", []):
            kws.add(str(v).lower())
    return kws


def test_ad_does_not_trigger_on_bare_smb():
    kws = _trigger_keywords(load_all_agents()["pentest/active-directory"])
    for generic in ("smb", "ntlm", "winrm"):
        assert generic not in kws, f"{generic!r} should not trigger active-directory"


def test_ad_still_triggers_on_dc_signals():
    kws = _trigger_keywords(load_all_agents()["pentest/active-directory"])
    assert {"kerberos", "ldap", "domain controller", "port 88", "port 389"} <= kws
