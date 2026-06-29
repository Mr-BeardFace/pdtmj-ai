"""run_script surfaces prior scripts in-band (the reuse fix) so the agent adapts
an existing script instead of re-authoring near-duplicates."""
import tempfile
from pathlib import Path

import pytest

import core.paths as paths
from tools.run_script import run_script, _load_index


@pytest.fixture
def assessment_scripts(monkeypatch):
    d = Path(tempfile.mkdtemp())
    monkeypatch.setattr(paths, "_current_assessment_dir", d)
    yield d
    monkeypatch.setattr(paths, "_current_assessment_dir", None)


def test_first_script_has_no_prior(assessment_scripts):
    r = run_script(language="python", script="print('hi')", purpose="first")
    assert r["scripts_written"] == 1
    assert "prior_scripts" not in r          # nothing written before it
    assert r["stdout"].strip() == "hi"       # header comment doesn't break execution


def test_prior_scripts_accumulate_in_result(assessment_scripts):
    run_script(language="python", script="print(1)", purpose="enumerate users")
    run_script(language="python", script="print(2)", purpose="spray passwords")
    r = run_script(language="python", script="print(3)", purpose="try log poisoning")
    assert r["scripts_written"] == 3
    assert r["prior_scripts"] == ["enumerate users", "spray passwords"]
    assert "reuse_hint" in r


def test_index_persists_purpose(assessment_scripts):
    run_script(language="python", script="print(1)", purpose="do a thing")
    idx = _load_index(paths.scripts_dir())
    assert idx and idx[0]["purpose"] == "do a thing"
    # purpose is also written as a header comment in the saved audit copy
    saved = next(paths.scripts_dir().glob("*.py"))
    assert "# purpose: do a thing" in saved.read_text(encoding="utf-8")
