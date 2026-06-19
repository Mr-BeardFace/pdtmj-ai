"""Strategist — deterministic refresh always, LLM consult gated on material change."""
import json
from types import SimpleNamespace

from core.engagement_state import EngagementState
from core.leads import LeadStore, objective_for
from core.models import Finding
from core.strategist import Strategist


def _f(title, verified=True, severity="high"):
    return Finding(type="vuln", severity=severity, title=title, description="d",
                   target="t", verified=verified)


class _FakeLLM:
    """Returns a scripted JSON board-leads payload; records that it was called."""
    def __init__(self, payload):
        self._payload = payload
        self.calls = 0

    def run(self, **kwargs):
        self.calls += 1
        text = json.dumps(self._payload)
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)])


def _state_with_recon():
    st = EngagementState(target="10.0.0.5")
    st.recon.open_ports = [{"host": "10.0.0.5", "port": 80, "service": "http"}]
    return st


def test_refresh_is_deterministic_and_needs_no_llm():
    st = _state_with_recon()
    store = LeadStore()
    strat = Strategist(llm=None)
    added = strat.refresh(store, st, [_f("SQL Injection")])
    assert added == len(store.leads) >= 2          # surface + vuln, no LLM involved


def test_consult_gated_on_material_change():
    st = _state_with_recon()
    store = LeadStore()
    llm = _FakeLLM({"leads": [
        {"description": "Reuse SMTP password over SSH as ben", "reach_level": "user",
         "prior": 0.8, "technique": "credential-reuse"}],
        "focus": "ssh reuse"})
    strat = Strategist(llm=llm, model="m")
    obj = objective_for("pentest-ctf", "10.0.0.5")

    # First consider: board is new → LLM consulted, board lead added.
    assert strat.consider(store, st, obj, [_f("RCE via X")]) is True
    assert llm.calls == 1
    assert any("Reuse SMTP password" in l.description for l in store.leads)

    # Nothing changed → no second consult (the "only when something changed" rule).
    assert strat.consider(store, st, obj, [_f("RCE via X")]) is False
    assert llm.calls == 1

    # New verified finding → material change → consulted again.
    assert strat.consider(store, st, obj, [_f("RCE via X"), _f("New Cred Exposure")]) is True
    assert llm.calls == 2


def test_bad_llm_output_is_swallowed():
    st = _state_with_recon()
    store = LeadStore()
    bad = _FakeLLM("not json at all")
    bad.run = lambda **k: SimpleNamespace(content=[SimpleNamespace(type="text", text="garbage{")])
    strat = Strategist(llm=bad, model="m")
    # Deterministic leads still land; the broken LLM consult doesn't raise.
    before = len(store.leads)
    strat.consider(store, st, objective_for("pentest", "t"), [_f("SQLi")])
    assert len(store.leads) > before
