"""Leads panel formatting: live leads on top (active→advancing→open, higher rung first),
a divider, then the worked/ruled-out ones — with a tries count and per-status marker."""
from ui.app import _lead_rows, _fmt_lead


def _lead(**k):
    base = {"status": "open", "reach_level": "vuln", "description": "do a thing",
            "attempts": 1, "kind": "vuln", "target": "10.0.0.1"}
    base.update(k)
    return base


def test_live_first_then_divider_then_done():
    leads = [
        _lead(status="refuted", description="kerberoast"),
        _lead(status="open", description="esc1"),
        _lead(status="active", description="dll inject"),
    ]
    rows = _lead_rows(leads)
    kinds = [k for k, _ in rows]
    assert kinds == ["lead", "lead", "divider", "lead"]
    # active sorts above open in the live group
    assert rows[0][1]["description"] == "dll inject"
    assert rows[1][1]["description"] == "esc1"
    assert rows[3][1]["description"] == "kerberoast"      # the refuted one, below the divider


def test_no_divider_when_all_live_or_all_done():
    assert all(k == "lead" for k, _ in _lead_rows([_lead(status="open"), _lead(status="active")]))
    assert all(k == "lead" for k, _ in _lead_rows([_lead(status="refuted"), _lead(status="confirmed")]))


def test_live_sorted_by_rung_within_status():
    leads = [_lead(status="open", reach_level="vuln", description="low"),
             _lead(status="open", reach_level="root", description="high")]
    rows = _lead_rows(leads)
    assert rows[0][1]["description"] == "high"            # higher kill-chain rung first


def test_fmt_lead_marker_and_tries():
    assert _fmt_lead(_lead(status="active")).startswith("[bold cyan]●")
    assert "✗" in _fmt_lead(_lead(status="refuted"))
    # tries count only when >1
    assert "·3t" in _fmt_lead(_lead(status="open", attempts=3))
    assert "·1t" not in _fmt_lead(_lead(status="open", attempts=1))
    # rung + description present
    row = _fmt_lead(_lead(status="open", reach_level="privesc", description="esc1 on template"))
    assert "privesc" in row and "esc1 on template" in row
