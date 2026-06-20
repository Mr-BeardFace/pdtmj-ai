"""EngagementState.from_snapshot rebuilds a review-only state (inverse of
state_snapshot) — used to re-synthesise a report from a saved assessment. Secrets
are never recoverable; creds come back masked."""
from core.engagement_state import EngagementState


def test_from_snapshot_roundtrips_masked_state():
    s = EngagementState(target="10.0.0.5")
    s.scope_targets = ["10.0.0.5", "dc.htb"]
    s.add_credential(secret="Sup3rSecret!", username="admin", service="smb", verified=True)
    s.recon.host_names["10.0.0.5"] = "dc.htb"
    snap = s.state_snapshot()

    # the snapshot never carries cleartext
    assert all(c["secret"] == "" for c in snap["credentials"])

    r = EngagementState.from_snapshot(snap)
    assert r.target == "10.0.0.5"
    assert "dc.htb" in r.scope_targets
    assert r.recon.host_names.get("10.0.0.5") == "dc.htb"
    assert len(r.credentials) == 1
    c = r.credentials[0]
    assert c.username == "admin"
    assert c.secret != "Sup3rSecret!"            # never round-trips cleartext
    assert c.secret_masked == snap["credentials"][0]["secret_masked"]


def test_from_snapshot_tolerates_empty():
    r = EngagementState.from_snapshot({})
    assert r.target == ""
    assert r.scope_targets == []          # no target → no implicit scope
    assert r.credentials == []
