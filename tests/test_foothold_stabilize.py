"""Foothold-stabilization nudge ("capitalize on exec"): once code execution is
confirmed, the engine nudges to convert one-shot exec into a STABLE channel
(a command driven through a live shell) and record_persistence — and keeps
nudging while unstabilized. Banking the finding does NOT clear it. The costly
miss was RCE at turn 8 that was re-driven for ~50 turns (shell_exec=0,
record_persistence=0) instead of being stabilized into a real foothold."""
from core.engagement_state import EngagementState


def _state() -> EngagementState:
    return EngagementState(target="10.10.10.10")


# ── state machine ─────────────────────────────────────────────────────────────

def test_nudge_fires_after_threshold():
    st = _state()
    st.note_exec_confirmed()
    assert st.stabilize_due(3, 0) == 0    # turn 1 — below threshold
    assert st.stabilize_due(3, 0) == 0    # turn 2
    assert st.stabilize_due(3, 0) == 3    # turn 3 — fires


def test_no_nudge_until_exec_confirmed():
    st = _state()
    for _ in range(5):
        assert st.stabilize_due(2, 0) == 0


def test_shell_exec_clears_the_nudge():
    st = _state()
    st.note_exec_confirmed()
    st.note_shell_confirmed()             # drove a command through a live shell
    assert st.stabilized()
    for _ in range(8):
        assert st.stabilize_due(2, 2) == 0


def test_persistence_clears_the_nudge():
    st = _state()
    st.note_exec_confirmed()
    st.note_persistence_recorded()        # planted + recorded a durable foothold
    assert st.stabilized()
    for _ in range(8):
        assert st.stabilize_due(2, 2) == 0


def test_banking_the_finding_does_not_clear_it():
    # Annotating the foothold satisfies the BANK nudge but not stabilization —
    # a recorded finding with no stable access still loses the foothold.
    st = _state()
    st.note_exec_confirmed()
    st.note_foothold_banked()
    assert not st.stabilized()
    assert st.stabilize_due(1, 0) == 1


def test_nudge_refires_on_interval_while_unstabilized():
    st = _state()
    st.note_exec_confirmed()
    fired = [st.stabilize_due(2, 3) for _ in range(9)]
    # threshold 2 → first fire at turn 2, then every 3 turns: turns 2, 5, 8
    assert [i for i, n in enumerate(fired, 1) if n] == [2, 5, 8]


def test_no_refire_when_repeat_disabled():
    st = _state()
    st.note_exec_confirmed()
    fired = [st.stabilize_due(2, 0) for _ in range(9)]
    assert [i for i, n in enumerate(fired, 1) if n] == [2]   # fires once only


def test_threshold_zero_disables():
    st = _state()
    st.note_exec_confirmed()
    for _ in range(10):
        assert st.stabilize_due(0, 5) == 0


def test_fork_carries_stabilization_state():
    st = _state()
    st.note_exec_confirmed()
    st.note_shell_confirmed()
    clone = st.fork()
    assert clone.stabilized()
    for _ in range(5):
        assert clone.stabilize_due(1, 1) == 0


def test_merge_folds_worker_stabilization():
    st = _state()
    marks = st.merge_marks()
    worker = st.fork()
    worker.note_exec_confirmed()
    worker.note_persistence_recorded()    # a parallel worker stabilized
    st.merge_from(worker, marks)
    assert st.stabilized()
