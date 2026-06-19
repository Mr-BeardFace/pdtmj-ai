import json

import pytest

from core.artifacts import ArtifactStore
from core.orchestrator import Orchestrator, _FIELD_OFFLOAD_CHARS, _RESULT_OFFLOAD_CHARS
from core.tool_registry import ToolRegistry


# ── ArtifactStore ─────────────────────────────────────────────────────────────

def test_store_and_read(tmp_path):
    store = ArtifactStore(tmp_path)
    ref = store.store("line1\nline2\nline3", label="nmap")
    assert ref["lines"] == 3
    out = store.read(ref["artifact_id"])
    assert out["total_lines"] == 3
    assert "line2" in out["content"]


def test_read_window(tmp_path):
    store = ArtifactStore(tmp_path)
    ref = store.store("\n".join(f"row{i}" for i in range(100)))
    out = store.read(ref["artifact_id"], offset=10, limit=5)
    assert out["returned"] == 5
    assert out["content"].splitlines()[0] == "row10"


def test_grep_basic_and_linenumbers(tmp_path):
    store = ArtifactStore(tmp_path)
    ref = store.store("admin:secret\nuser:1234\nADMIN PANEL\n")
    out = store.grep(ref["artifact_id"], "admin")
    assert out["total_matches"] == 2          # case-insensitive
    assert "1: admin:secret" in out["content"]


def test_grep_context_and_invert(tmp_path):
    store = ArtifactStore(tmp_path)
    ref = store.store("a\nMATCH\nc\nd\n")
    ctx = store.grep(ref["artifact_id"], "MATCH", context=1)
    assert "1- a" in ctx["content"] and "2: MATCH" in ctx["content"] and "3- c" in ctx["content"]
    inv = store.grep(ref["artifact_id"], "MATCH", invert=True)
    assert inv["total_matches"] == 3          # all non-MATCH lines


def test_grep_truncates_and_reports(tmp_path):
    store = ArtifactStore(tmp_path)
    ref = store.store("\n".join("hit" for _ in range(500)))
    out = store.grep(ref["artifact_id"], "hit", max_matches=50)
    assert out["returned_matches"] == 50
    assert out["truncated"] is True
    assert out["total_matches"] == 500


def test_missing_artifact(tmp_path):
    store = ArtifactStore(tmp_path)
    assert "error" in store.read("deadbeef")
    assert "error" in store.grep("deadbeef", "x")


def test_invalid_regex(tmp_path):
    store = ArtifactStore(tmp_path)
    ref = store.store("x")
    assert "error" in store.grep(ref["artifact_id"], "(")


# ── Orchestrator offloading ───────────────────────────────────────────────────

class _LLM:
    pass


def _orch(tmp_path):
    return Orchestrator(
        _LLM(), ToolRegistry(), tmp_path, quiet=True,
        artifact_store=ArtifactStore(tmp_path / "artifacts"),
    )


def test_recent_index_newest_first(tmp_path):
    store = ArtifactStore(tmp_path)
    a = store.store("aaa", label="nmap")
    b = store.store("bbb\nccc", label="gobuster")
    rec = store.recent()
    assert [r["artifact_id"] for r in rec] == [b["artifact_id"], a["artifact_id"]]
    assert rec[0]["label"].startswith("gobuster") and rec[0]["lines"] == 2


def test_artifact_index_block(tmp_path):
    o = _orch(tmp_path)
    assert o._artifact_index_block() == ""            # nothing captured yet
    o._artifacts.store("PORT 8080 open", label="nmap_scan")
    block = o._artifact_index_block()
    assert "Captured artifacts" in block and "nmap_scan" in block
    assert "read_artifact" in block                   # tells the agent how to pull it


def test_small_result_unchanged(tmp_path):
    o = _orch(tmp_path)
    result = {"count": 3, "hosts": ["a", "b"]}
    assert o._offload_for_llm(result, "nmap_scan") == result


def test_large_string_field_offloaded(tmp_path):
    o = _orch(tmp_path)
    big = "x" * (_FIELD_OFFLOAD_CHARS + 500)
    view = o._offload_for_llm({"raw_output": big, "count": 1}, "ffuf")
    # field replaced by a preview + artifact pointer; full text retrievable
    assert "_raw_output_artifact_id" in view
    assert len(view["raw_output"]) < len(big)
    aid = view["_raw_output_artifact_id"]
    assert o._artifacts.read(aid)["content"].startswith("x")


def test_whole_result_offloaded(tmp_path):
    o = _orch(tmp_path)
    # many small fields, each under the field threshold but huge in aggregate
    result = {f"k{i}": "y" * 200 for i in range(60)}
    view = o._offload_for_llm(result, "nuclei_scan")
    assert "_artifact_id" in view
    assert "_note" in view
    assert len(json.dumps(view)) < _RESULT_OFFLOAD_CHARS


def test_non_dict_large_offloaded(tmp_path):
    o = _orch(tmp_path)
    view = o._offload_for_llm("z" * (_RESULT_OFFLOAD_CHARS + 100), "strings_extract")
    assert "_artifact_id" in view


def test_artifact_query_handlers(tmp_path):
    o = _orch(tmp_path)
    ref = o._artifacts.store("alpha\nbeta\ngamma")
    g = o._handle_artifact_query("grep_artifact", {"artifact_id": ref["artifact_id"], "pattern": "beta"})
    assert g["total_matches"] == 1
    r = o._handle_artifact_query("read_artifact", {"artifact_id": ref["artifact_id"], "limit": 2})
    assert r["returned"] == 2
