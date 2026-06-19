"""Per-assessment folder consolidation (#4) + credential removal (#2)."""
import os
import tempfile

import pytest

from core import paths
from core.engagement_state import EngagementState

_TMP_VARS = ("TMPDIR", "TEMP", "TMP")


@pytest.fixture
def _restore_temp_env():
    """Snapshot/restore tempfile.tempdir + the TMP env vars set_assessment_dir
    rewrites, so a test pointing them at a tmp_path doesn't leak a deleted dir."""
    saved_tempdir = tempfile.tempdir
    saved_env = {k: os.environ.get(k) for k in _TMP_VARS}
    try:
        yield
    finally:
        tempfile.tempdir = saved_tempdir
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        paths._current_assessment_dir = None


# ── #4 one folder per assessment ──────────────────────────────────────────────

def test_set_assessment_dir_consolidates(tmp_path, monkeypatch, _restore_temp_env):
    monkeypatch.setattr(paths, "ASSESSMENTS_DIR", tmp_path / "assessments")
    monkeypatch.setattr(paths, "_current_assessment_dir", None)
    d = paths.set_assessment_dir("abc123", "10.0.0.5")
    assert d.exists()
    assert (d / "scripts").is_dir()
    assert (d / "artifacts").is_dir()
    assert (d / "scratch").is_dir()
    # scripts/artifacts now resolve INSIDE the assessment folder
    assert paths.scripts_dir() == d / "scripts"
    assert paths.artifacts_dir() == d / "artifacts"
    # transient tool tempfiles land in scratch/ — in-process AND spawned subprocesses
    assert tempfile.tempdir == str(d / "scratch")
    assert os.environ["TMPDIR"] == str(d / "scratch")
    assert os.environ["TEMP"] == str(d / "scratch") and os.environ["TMP"] == str(d / "scratch")
    assert "abc123" in d.name and "10.0.0.5" in d.name


def test_dirs_fall_back_without_active_assessment(monkeypatch):
    monkeypatch.setattr(paths, "_current_assessment_dir", None)
    assert paths.scripts_dir() == paths.RESULTS_DIR / "scripts"
    assert paths.artifacts_dir() == paths.ARTIFACTS_DIR


def test_scratch_env_points_tmp_vars_into_assessment(tmp_path, monkeypatch, _restore_temp_env):
    monkeypatch.setattr(paths, "ASSESSMENTS_DIR", tmp_path / "assessments")
    monkeypatch.setattr(paths, "_current_assessment_dir", None)
    d = paths.set_assessment_dir("envid", "t")
    # apt/pip get their temp + build + log dirs inside the assessment scratch, even
    # if the subprocess rebuilds its env or crosses a sudo boundary.
    env = paths.scratch_env({"DEBIAN_FRONTEND": "noninteractive"})
    scratch = str(d / "scratch")
    assert env["TMPDIR"] == scratch and env["TEMP"] == scratch and env["TMP"] == scratch
    assert env["DEBIAN_FRONTEND"] == "noninteractive"   # base entries preserved
    assert paths.scratch_dir() == d / "scratch"


def test_run_script_writes_into_assessment_dir(tmp_path, monkeypatch, _restore_temp_env):
    monkeypatch.setattr(paths, "ASSESSMENTS_DIR", tmp_path / "assessments")
    monkeypatch.setattr(paths, "_current_assessment_dir", None)
    d = paths.set_assessment_dir("run1", "t")
    from tools.run_script import run_script
    res = run_script(purpose="smoke", language="python", script="print('hi')")
    sf = res.get("script_file", "")
    assert sf and str(d / "scripts") in str(sf)   # audit copy lives in the folder


# ── #2 remove any credential ──────────────────────────────────────────────────

def test_remove_credential_pulls_any_cred():
    s = EngagementState(target="10.0.0.5")
    s.add_credential(secret="pw1", username="a", service="smb")
    s.add_credential(secret="pw2", username="b", service="ssh", verified=True)  # agent-found
    assert len(s.credentials) == 2

    removed = s.remove_credential(1)                  # pull the agent-discovered one
    assert removed is not None and removed.secret == "pw2"
    assert len(s.credentials) == 1 and s.credentials[0].secret == "pw1"

    assert s.remove_credential(9) is None             # out of range → no-op
    assert s.remove_credential(-1) is None
