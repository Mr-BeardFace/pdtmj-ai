"""Credential identity/dedup rules. A password found with an UNKNOWN user, later tied
to one, updates that single record (fills the blank username) — but password reuse
(same secret, different known users) and independent/old passwords must never collapse
or clobber a good record."""
from core.engagement_state import EngagementState


def _s():
    return EngagementState(target="10.0.0.1")


def test_usernameless_then_named_promotes_same_record():
    s = _s()
    s.add_credential(secret="P@ss1", username=None, location="dump.txt")  # found, unknown user
    s.add_credential(secret="P@ss1", username="admin", verified=True)     # later tied to admin
    assert len(s.credentials) == 1
    c = s.credentials[0]
    assert c.username == "admin" and c.verified is True
    assert c.location == "dump.txt"          # original find location preserved


def test_password_reuse_across_users_stays_separate():
    s = _s()
    s.add_credential(secret="Shared1", username="admin", verified=True)
    s.add_credential(secret="Shared1", username="bob")   # reuse — a DIFFERENT known user
    assert len(s.credentials) == 2
    assert {c.username for c in s.credentials} == {"admin", "bob"}


def test_named_does_not_promote_into_a_different_users_record():
    # a blank-username record must exist to promote; a named record is never overwritten
    s = _s()
    s.add_credential(secret="X", username="admin", verified=True)
    s.add_credential(secret="X", username="carol")
    admin = next(c for c in s.credentials if c.username == "admin")
    assert admin.username == "admin" and admin.verified is True   # untouched


def test_old_password_independent_from_new_one():
    s = _s()
    s.add_credential(secret="OldP@ss", username="admin", verified=True)   # known-good, later invalid
    s.add_credential(secret="NewP@ss", username="admin", verified=True)   # rotated
    assert len(s.credentials) == 2
    assert {c.secret for c in s.credentials} == {"OldP@ss", "NewP@ss"}


def test_exact_duplicate_still_dedups_and_never_downgrades_verified():
    s = _s()
    s.add_credential(secret="P", username="admin", verified=True)
    s.add_credential(secret="P", username="admin", verified=False)   # a later unverified sighting
    assert len(s.credentials) == 1
    assert s.credentials[0].verified is True     # not downgraded


def test_two_usernameless_same_secret_dedup():
    s = _s()
    s.add_credential(secret="Lone", username=None)
    s.add_credential(secret="Lone", username=None)
    assert len(s.credentials) == 1 and s.credentials[0].username is None
