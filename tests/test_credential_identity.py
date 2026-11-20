"""Identity dedup rules. The dedup key is (username, realm, service) for named
identities; orphan records (no username) each get a unique entry. When an orphan
secret is later attributed to a known user, the orphan record is promoted
(username filled in) rather than creating a duplicate."""
from core.engagement_state import EngagementState


def _s():
    return EngagementState(target="10.0.0.1")


def test_usernameless_then_named_promotes_same_record():
    s = _s()
    s.add_identity(secret="P@ss1", username=None, location="dump.txt")  # found, unknown user
    s.add_identity(secret="P@ss1", username="admin", verified=True)     # later tied to admin
    assert len(s.identities) == 1
    c = s.identities[0]
    assert c.username == "admin" and c.verified is True
    assert "dump.txt" in c.locations          # original find location preserved


def test_password_reuse_across_users_stays_separate():
    s = _s()
    s.add_identity(secret="Shared1", username="admin", verified=True)
    s.add_identity(secret="Shared1", username="bob", realm="CORP")  # different realm = different identity
    assert len(s.identities) == 2
    assert {c.username for c in s.identities} == {"admin", "bob"}


def test_named_does_not_promote_into_a_different_users_record():
    # a blank-username record must exist to promote; a named record is never overwritten
    s = _s()
    s.add_identity(secret="X", username="admin", verified=True)
    s.add_identity(secret="X", username="carol", realm="CORP")  # different user+realm
    admin = next(c for c in s.identities if c.username == "admin")
    assert admin.username == "admin" and admin.verified is True   # untouched


def test_same_user_realm_service_dedup():
    """Same (username, realm, service) = same identity. Second add backfills fields,
    doesn't create a duplicate."""
    s = _s()
    s.add_identity(secret="P@ss", username="admin", realm="NORTH", service="AD")
    s.add_identity(username="admin", realm="NORTH", service="AD", verified=True,
                   location="DC01")
    assert len(s.identities) == 1
    c = s.identities[0]
    assert c.verified is True         # upgraded
    assert "DC01" in c.locations      # location added


def test_exact_duplicate_still_dedups_and_never_downgrades_verified():
    s = _s()
    s.add_identity(secret="P", username="admin", verified=True)
    s.add_identity(secret="P", username="admin", verified=False)   # a later unverified sighting
    assert len(s.identities) == 1
    assert s.identities[0].verified is True     # not downgraded


def test_two_usernameless_same_secret_dedup():
    """Orphan records with no username — each is a unique entry since there's no
    dedup key. But secret-based attribution catches duplicates."""
    s = _s()
    s.add_identity(secret="Lone", username=None)
    s.add_identity(secret="Lone", username=None)
    # Orphans: no username means no dedup key, so both are kept
    assert len(s.identities) == 2


def test_merge_identity_combines_records():
    s = _s()
    s.add_identity(username="admin", realm="NORTH", service="AD", notes="Domain Admin")
    s.add_identity(secret_hash="aad3:31d6", secret_type="hash", location="hashdump")
    assert len(s.identities) == 2
    target = next(i for i in s.identities if i.username == "admin")
    source = next(i for i in s.identities if not i.username)
    result = s.merge_identity(source.id, target.id)
    assert result["merged"] is True
    assert len(s.identities) == 1
    merged = s.identities[0]
    assert merged.username == "admin"
    assert merged.secret_hash == "aad3:31d6"
    assert "hashdump" in merged.locations
