"""Re-read guard: pulling the identical artifact slice back into context is flagged
so the agent stops looping on the same bytes (observed 3x re-reads in a real run)."""
from core.orchestrator import Orchestrator
from core.artifacts import ArtifactStore
from core.tool_registry import ToolRegistry


class _NoLLM:
    def run(self, *a, **k):
        raise AssertionError("LLM should not be called in this test")


def _orch(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    return Orchestrator(_NoLLM(), ToolRegistry(), tmp_path, quiet=True,
                        save_individual_runs=False, artifact_store=store), store


def test_first_read_clean_repeat_flagged(tmp_path):
    orch, store = _orch(tmp_path)
    art = store.store("line one\nline two\nline three\n", label="nmap")
    aid = art["artifact_id"]

    first = orch._handle_artifact_query("read_artifact", {"artifact_id": aid})
    assert "_already_viewed" not in first

    again = orch._handle_artifact_query("read_artifact", {"artifact_id": aid})
    assert "_already_viewed" in again       # same slice → flagged


def test_different_window_not_flagged(tmp_path):
    orch, store = _orch(tmp_path)
    art = store.store("\n".join(f"line {i}" for i in range(50)), label="big")
    aid = art["artifact_id"]
    orch._handle_artifact_query("read_artifact", {"artifact_id": aid, "offset": 0, "limit": 10})
    other = orch._handle_artifact_query("read_artifact", {"artifact_id": aid, "offset": 10, "limit": 10})
    assert "_already_viewed" not in other   # a genuinely new window is fine
