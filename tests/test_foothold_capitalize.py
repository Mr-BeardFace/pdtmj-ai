"""Capitalize-on-exec nudge: once exec is confirmed, nudge to EXTRACT VALUE with the
primitive in hand (flag/creds/privesc). Cleared by looted creds/flags or a stable
channel — NOT by annotating the RCE finding or by chasing a shell. The miss it guards:
a run that got RCE then burned the whole budget breaking a working exploit to plant an
SSH key, looting nothing."""
from core.engagement_state import EngagementState


def _state() -> EngagementState:
    return EngagementState(target="10.10.10.10")


def test_nudge_fires_after_threshold():
    st = _state()
    st.note_exec_confirmed()
    assert st.capitalize_due(3, 0) == 0
    assert st.capitalize_due(3, 0) == 0
    assert st.capitalize_due(3, 0) == 3


def test_no_nudge_until_exec_confirmed():
    st = _state()
    for _ in range(5):
        assert st.capitalize_due(2, 0) == 0


def test_shell_clears_it():
    st = _state()
    st.note_exec_confirmed()
    st.note_shell_confirmed()
    assert st.capitalized()
    for _ in range(8):
        assert st.capitalize_due(2, 2) == 0


def test_persistence_clears_it():
    st = _state()
    st.note_exec_confirmed()
    st.note_persistence_recorded()
    assert st.capitalized()
    for _ in range(8):
        assert st.capitalize_due(2, 2) == 0


def test_looted_credential_clears_it():
    st = _state()
    st.note_exec_confirmed()
    assert not st.capitalized()
    st.add_credential(secret="Sup3rSecret1", username="svc", verified=True)
    assert st.capitalized()                      # pulled value → satisfied
    for _ in range(8):
        assert st.capitalize_due(2, 2) == 0


def test_looted_flag_clears_it():
    st = _state()
    st.note_exec_confirmed()
    st.add_flag("HTB{rooted}", location="/root/root.txt")
    assert st.capitalized()


def test_annotating_the_rce_finding_alone_does_not_clear_it():
    # Banking the foothold finding satisfies the BANK nudge, not capitalization —
    # nothing has actually been looted yet.
    st = _state()
    st.note_exec_confirmed()
    st.note_foothold_banked()
    assert not st.capitalized()
    assert st.capitalize_due(1, 0) == 1


def test_refires_on_interval_until_extracted():
    st = _state()
    st.note_exec_confirmed()
    fired = [st.capitalize_due(2, 3) for _ in range(9)]
    assert [i for i, n in enumerate(fired, 1) if n] == [2, 5, 8]


def test_no_refire_when_repeat_disabled():
    st = _state()
    st.note_exec_confirmed()
    fired = [st.capitalize_due(2, 0) for _ in range(9)]
    assert [i for i, n in enumerate(fired, 1) if n] == [2]


def test_threshold_zero_disables():
    st = _state()
    st.note_exec_confirmed()
    for _ in range(10):
        assert st.capitalize_due(0, 5) == 0


def test_fork_carries_state():
    st = _state()
    st.note_exec_confirmed()
    st.note_shell_confirmed()
    clone = st.fork()
    assert clone.capitalized()
    for _ in range(5):
        assert clone.capitalize_due(1, 1) == 0


def test_merge_folds_worker_shell():
    st = _state()
    marks = st.merge_marks()
    worker = st.fork()
    worker.note_exec_confirmed()
    worker.note_shell_confirmed()
    st.merge_from(worker, marks)
    assert st._shell_confirmed
