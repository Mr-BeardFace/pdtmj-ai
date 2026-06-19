"""read_artifact/grep_artifact return their slice directly and never re-offload it
to a NEW artifact — the loop that left the report agent spinning and never
synthesising (it read an artifact, the result got stored as a new artifact, it was
told to read that, …)."""
from core.engagement_state import EngagementState
from core.orchestrator import Orchestrator, _ARTIFACT_VIEW_CAP
from core.tool_registry import ToolRegistry


def _orch(tmp_path):
    return Orchestrator(object(), ToolRegistry(), tmp_path, quiet=True,
                        engagement_state=EngagementState(target="x"))


def test_read_artifact_does_not_spawn_a_new_artifact(tmp_path):
    o = _orch(tmp_path)
    # a big artifact whose 200-line slice exceeds the old 6000-char offload threshold
    big = "\n".join(f"line {i} " + "x" * 80 for i in range(400))
    art = o._artifacts.store(big, label="run_script")
    before = len(o._artifacts.list()) if hasattr(o._artifacts, "list") else None

    res = o._handle_artifact_query("read_artifact", {"artifact_id": art["artifact_id"], "limit": 200})
    view = o._cap_artifact_view(res)

    # the content comes back DIRECTLY — not a pointer to yet another artifact
    assert "content" in view and view["content"]
    assert "_artifact_id" not in view          # not re-offloaded
    # and reading did not create a new artifact
    if before is not None:
        assert len(o._artifacts.list()) == before


def test_pathologically_large_slice_is_truncated_in_place(tmp_path):
    o = _orch(tmp_path)
    huge_line = "z" * (_ARTIFACT_VIEW_CAP + 5000)
    art = o._artifacts.store(huge_line, label="run_script")
    view = o._cap_artifact_view(
        o._handle_artifact_query("read_artifact", {"artifact_id": art["artifact_id"]}))
    assert len(view["content"]) <= _ARTIFACT_VIEW_CAP
    assert "_truncated" in view
    assert "_artifact_id" not in view          # truncated, still not re-offloaded
