"""Foothold-banking nudge (fix ①): once code execution is confirmed, the engine
nudges to annotate it if no verified finding is banked within a couple of turns.
The costly Helix miss was RCE proven (`uid=998(nifi)`) but never recorded."""
from core.engagement_state import EngagementState
from core.orchestrator import _result_shows_exec, _EXEC_SIG_RE


def _state() -> EngagementState:
    return EngagementState(target="10.10.10.10")


# ── state machine ─────────────────────────────────────────────────────────────

def test_nudge_fires_after_threshold_once():
    st = _state()
    st.note_exec_confirmed()
    # below threshold → no nudge yet
    assert st.foothold_bank_due(2) == 0
    # at threshold → fires, returning the turn count
    assert st.foothold_bank_due(2) == 2
    # and only once — subsequent ticks stay silent
    assert st.foothold_bank_due(2) == 0
    assert st.foothold_bank_due(2) == 0


def test_no_nudge_until_exec_confirmed():
    st = _state()
    for _ in range(5):
        assert st.foothold_bank_due(2) == 0   # nothing confirmed → never nudges


def test_banking_clears_the_nudge():
    st = _state()
    st.note_exec_confirmed()
    st.note_foothold_banked()                 # verified finding recorded
    for _ in range(5):
        assert st.foothold_bank_due(2) == 0   # banked → no nudge ever


def test_note_exec_confirmed_is_idempotent():
    st = _state()
    st.note_exec_confirmed()
    st.foothold_bank_due(3)                    # tick once
    st.note_exec_confirmed()                   # second call must not reset the clock
    assert st.foothold_bank_due(3) == 0        # still only 2 ticks in
    assert st.foothold_bank_due(3) == 3        # third tick fires


def test_threshold_zero_disables():
    st = _state()
    st.note_exec_confirmed()
    for _ in range(10):
        assert st.foothold_bank_due(0) == 0


def test_fork_carries_exec_state():
    st = _state()
    st.note_exec_confirmed()
    clone = st.fork()
    assert clone.exec_confirmed()
    # the clone keeps counting from where the parent was
    assert clone.foothold_bank_due(1) == 1


def test_merge_folds_worker_exec_confirmation():
    st = _state()
    marks = st.merge_marks()
    worker = st.fork()
    worker.note_exec_confirmed()               # a parallel worker proved exec
    st.merge_from(worker, marks)
    assert st.exec_confirmed()


# ── exec-signature detection (blind-channel readback) ─────────────────────────

def test_linux_id_output_detected():
    assert _result_shows_exec({"body": "uid=998(nifi) gid=998(nifi) groups=998(nifi)"})


def test_windows_whoami_priv_detected():
    assert _result_shows_exec(
        {"stdout": "PRIVILEGES INFORMATION\nSeImpersonatePrivilege  ...  Enabled"})


def test_windows_whoami_user_line_detected():
    assert _result_shows_exec({"output": "corp\\jsmith\n"})


def test_paths_and_enum_strings_not_detected():
    # No code ran — none of these should look like an exec readback.
    assert not _result_shows_exec({"output": "C:\\Windows\\System32\\cmd.exe"})
    assert not _result_shows_exec({"data": "HKLM\\SOFTWARE\\Microsoft\\Windows"})
    assert not _result_shows_exec({"ldap": "member: CORP\\svc_sql found in group"})
    assert not _result_shows_exec({"note": "uidNumber: 1001 in directory"})


def test_collect_scans_nested_values():
    assert _result_shows_exec({"bodies": ["nothing", {"x": "uid=0(root) gid=0(root)"}]})
