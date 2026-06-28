"""Canonical filesystem paths for the PDTMJ-AI project.

Import from here instead of computing paths in main.py or ui/app.py.

Per-assessment layout (2.0): everything an assessment produces lives under ONE
folder — `assessments/assessment_<id>_<datetime>/` — instead of being scattered
across results/, logs/, artifacts/, and work/:

    assessments/assessment_<id>_<datetime>/
        assessment.json      engagement record (runs, findings, cost)
        state.json           masked panel snapshot (for /load)
        engagement.log       human-readable session log
        engagement.jsonl     full structured event log
        report_*.html/.md    generated report(s)
        scripts/             run_script audit copies
        artifacts/           offloaded large tool output
        scratch/             transient tool tempfiles (tempfile.tempdir)

Call `set_assessment_dir(id, target)` once when an assessment starts (and on
resume, with the same id) — it creates the tree, points `tempfile` at scratch/,
and makes `scripts_dir()`/`artifacts_dir()` resolve inside it. Until then (CLI
single runs, tests) those fall back to the legacy top-level dirs.
"""
import os
import re
import tempfile
from datetime import datetime
from pathlib import Path

BASE_DIR   = Path(__file__).parent.parent
AGENTS_DIR = BASE_DIR / "agents"
# Retrievable domain methodology — pulled on demand via the load_playbook tool,
# rather than dispatched to as a separate agent.
PLAYBOOKS_DIR = BASE_DIR / "playbooks"
RESULTS_DIR = BASE_DIR / "results"
LOGS_DIR = BASE_DIR / "logs"
ARTIFACTS_DIR = BASE_DIR / "artifacts"
# One folder per assessment lives here (see module docstring).
ASSESSMENTS_DIR = BASE_DIR / "assessments"
# Legacy per-assessment scratch root (kept for back-compat / older callers).
WORK_DIR = BASE_DIR / "work"

# The active assessment's root dir, set by set_assessment_dir(). None → not in an
# assessment (CLI single run / tests) → writers fall back to the top-level dirs.
_current_assessment_dir: Path | None = None

_SAFE_RE = re.compile(r'[^A-Za-z0-9_.-]')


def _point_scratch_at(scratch: Path) -> None:
    """Route ALL transient files at `scratch`, not /tmp — both Python's in-process
    tempfile calls AND the spawned CLI tools. Setting tempfile.tempdir only covers
    the former; subprocess tools (sqlmap, nuclei, ffuf, sslscan, …) create their own
    temp files from $TMPDIR / $TEMP / $TMP, so those are set too (TMPDIR for Linux/
    Kali, TEMP/TMP for Windows)."""
    scratch.mkdir(parents=True, exist_ok=True)
    tempfile.tempdir = str(scratch)
    for var in ("TMPDIR", "TEMP", "TMP"):
        os.environ[var] = str(scratch)


def _safe(part: str) -> str:
    return _SAFE_RE.sub("_", part or "")[:40]


def _existing_assessment_dir(assessment_id: str) -> Path | None:
    """An already-created folder for this id, if any — so resume/idempotent calls
    reuse the same folder (and don't mint a new timestamp). Matches both the new
    `assessment_<id>_<datetime>` layout and older `assessment_<id>[_<target>]` ones;
    the trailing `_` after the id keeps a short id from matching a longer one."""
    if not ASSESSMENTS_DIR.exists():
        return None
    safe_id = _safe(assessment_id)
    for d in sorted(ASSESSMENTS_DIR.glob(f"assessment_{safe_id}_*")):
        if d.is_dir():
            return d
    legacy = ASSESSMENTS_DIR / f"assessment_{safe_id}"   # no-suffix legacy folder
    return legacy if legacy.is_dir() else None


def assessment_dirname(assessment_id: str, target: str = "") -> str:
    """Folder name for an assessment: `assessment_<id>_<YYYY-MM-DD_HHMM>`. The start
    time is stamped once, on first creation; a later call for the same id reuses the
    existing folder's name (resume-safe). `target` is accepted for call-site
    compatibility but no longer part of the name. Colon-free → Windows-safe."""
    existing = _existing_assessment_dir(assessment_id)
    if existing is not None:
        return existing.name
    ts = datetime.now().strftime("%Y-%m-%d_%H%M")
    return f"assessment_{_safe(assessment_id)}_{ts}"


def set_assessment_dir(assessment_id: str, target: str = "") -> Path:
    """Create (or reuse) the single per-assessment folder, make it the active one,
    and point transient tool tempfiles at its scratch/ subdir. Idempotent — safe to
    call again on resume with the same id."""
    global _current_assessment_dir
    d = ASSESSMENTS_DIR / assessment_dirname(assessment_id, target)
    for sub in ("scripts", "artifacts", "scratch", "keys", "downloads", "analysis"):
        (d / sub).mkdir(parents=True, exist_ok=True)
    _current_assessment_dir = d
    _point_scratch_at(d / "scratch")          # in-process + subprocess temp → here
    return d


def assessment_root() -> Path | None:
    """The active per-assessment folder, or None when not in an assessment."""
    return _current_assessment_dir


def scripts_dir() -> Path:
    """Where run_script saves audit copies — per-assessment when one is active."""
    if _current_assessment_dir is not None:
        return _current_assessment_dir / "scripts"
    return RESULTS_DIR / "scripts"


def artifacts_dir() -> Path:
    """Where large tool output is offloaded — per-assessment when one is active."""
    if _current_assessment_dir is not None:
        return _current_assessment_dir / "artifacts"
    return ARTIFACTS_DIR


def scratch_dir() -> Path:
    """The active transient/scratch dir — the assessment's scratch/ when one is
    active, else the system temp dir."""
    if _current_assessment_dir is not None:
        return _current_assessment_dir / "scratch"
    return Path(tempfile.gettempdir())


def keys_dir() -> Path:
    """Where generated keypairs (ssh_keygen) are written — inside the assessment
    folder when one is active, else the legacy results/keys."""
    if _current_assessment_dir is not None:
        return _current_assessment_dir / "keys"
    return RESULTS_DIR / "keys"


def downloads_dir() -> Path:
    """Files actually downloaded off targets (smbclient get, ftp, curl -O)."""
    d = (_current_assessment_dir / "downloads" if _current_assessment_dir is not None
         else RESULTS_DIR / "downloads")
    d.mkdir(parents=True, exist_ok=True)
    return d


def analysis_dir() -> Path:
    """Working area for inspecting pulled files (unzip/extract/strings) — the /tmp
    replacement; transient, not kept. run_script runs here."""
    d = (_current_assessment_dir / "analysis" if _current_assessment_dir is not None
         else RESULTS_DIR / "analysis")
    d.mkdir(parents=True, exist_ok=True)
    return d


def scratch_env(base: dict | None = None) -> dict:
    """A copy of `base` (default os.environ) with TMPDIR/TEMP/TMP pointed at the
    scratch dir. Pass this as a subprocess's `env` for tools that rebuild their
    environment or run under sudo (which strips TMPDIR) — e.g. apt/pip, whose build
    and log temp files otherwise land in /tmp regardless of the process-wide env."""
    env = dict(base if base is not None else os.environ)
    sd = str(scratch_dir())
    for var in ("TMPDIR", "TEMP", "TMP"):
        env[var] = sd
    return env


def use_assessment_scratch(assessment_id: str) -> Path:
    """Legacy: point tempfile at work/assessment_<id>. Superseded by
    set_assessment_dir (which also consolidates scripts/artifacts/reports). Kept so
    older callers and existing tests keep working."""
    scratch = WORK_DIR / f"assessment_{assessment_id}"
    _point_scratch_at(scratch)
    return scratch
