"""Execute an ad-hoc script (Python or Bash) when no existing tool fits.

The agent writes a short script and this tool runs it, returning stdout, stderr,
and the exit code. Use it for bespoke exploit code, custom protocol clients,
payload encoders, output parsers, or any one-off automation that would require
contorting existing tools. Scripts run on the operator's machine — pair with
ssh_exec, web_exec, or nc to deliver output to the target.

Scripts are saved to results/scripts/ for audit and reproducibility. Add
background=true (handled by the orchestrator) for slow operations.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from core.timeutil import now_local

from core import paths
from core import proc as runner

_SUPPORTED = {"python", "bash"}

# Append-only index of scripts written this engagement, so every run_script result
# can show what's already been written WITHOUT the agent having to call list_scripts.
# This is the in-band reuse signal — a passive "call list_scripts" nudge loses to
# momentum; showing prior scripts in the result the agent is already reading does not.
_INDEX_NAME = "_scripts_index.jsonl"
_PRIOR_SHOWN = 8          # how many recent prior purposes to surface in the result


def _index_path(scripts_dir: Path) -> Path:
    return scripts_dir / _INDEX_NAME


def _load_index(scripts_dir: Path) -> list[dict]:
    p = _index_path(scripts_dir)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def _append_index(scripts_dir: Path, entry: dict) -> None:
    try:
        with open(_index_path(scripts_dir), "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

# Resolve interpreters across platforms: Linux/Kali ships python3; Windows
# typically only has `python`. Bash is python's WSL/Git-Bash equivalent.
_INTERPRETERS = {
    "python": ("python3", "python"),
    "bash":   ("bash",),
}

OUTPUT_CAP = 20_000


def _resolve_interpreter(lang: str) -> str | None:
    # Python must be THIS interpreter (the venv's), so a script can import whatever
    # pip_install put in the venv. Resolving "python3" off PATH would, after the
    # startup venv-scrub, land on the system Python without those packages.
    if lang == "python":
        return sys.executable or shutil.which("python3") or shutil.which("python")
    for cand in _INTERPRETERS[lang]:
        if shutil.which(cand):
            return cand
    return None


def run_script(
    language: str,
    script: str,
    purpose: str = "",
    args: list[str] | None = None,
    timeout: int = 30,
) -> dict:
    lang = language.strip().lower()
    if lang not in _SUPPORTED:
        return {"error": f"unsupported language '{language}' — use python or bash"}
    if not script or not script.strip():
        return {"error": "script is empty"}
    if not purpose or not purpose.strip():
        return {"error": "purpose is required — one line describing what this script does and why"}

    interpreter = _resolve_interpreter(lang)
    if interpreter is None:
        return {"error": f"no interpreter for {lang} found in PATH "
                         f"(looked for: {', '.join(_INTERPRETERS[lang])})"}

    scripts_dir = paths.scripts_dir()      # per-assessment when one is active
    scripts_dir.mkdir(parents=True, exist_ok=True)

    # Scripts already written this engagement (BEFORE recording the current one) —
    # surfaced in the result so the agent reuses/adapts instead of re-authoring.
    prior = _load_index(scripts_dir)

    ts = now_local().strftime("%Y%m%d_%H%M%S_%f")
    ext = "py" if lang == "python" else "sh"
    script_path = scripts_dir / f"{ts}_{lang}.{ext}"
    # Persist the purpose as a header comment so the audit copy is self-describing.
    header = f"# purpose: {purpose.strip()}\n"
    script_path.write_text(header + textwrap.dedent(script), encoding="utf-8")
    if lang == "bash":
        script_path.chmod(0o700)
    _append_index(scripts_dir, {"file": script_path.name, "lang": lang,
                                "purpose": purpose.strip()})

    extra_args = list(args) if args else []
    cmd = [interpreter, str(script_path)] + extra_args
    # command_str leads with the purpose so the operator sees what the script is
    # for in the activity log, not just an opaque "python3 <file>.py".
    run_part = f"{interpreter} {script_path.name}" + (f" {' '.join(extra_args)}" if extra_args else "")
    cmd_str = f"{purpose.strip()}  ({run_part})"

    try:
        proc = runner.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return {
            "error": f"script timed out after {timeout}s — use background=true for slow operations",
            "script_file": str(script_path),
            "_command": cmd_str,
        }
    except FileNotFoundError:
        return {"error": f"{interpreter} not found in PATH", "_command": cmd_str}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e), "_command": cmd_str}

    stdout = proc.stdout[:OUTPUT_CAP]
    stderr = proc.stderr[:OUTPUT_CAP]
    result = {
        "purpose": purpose.strip(),
        "exit_code": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "truncated": len(proc.stdout) > OUTPUT_CAP or len(proc.stderr) > OUTPUT_CAP,
        "script_file": str(script_path),
        "_command": cmd_str,
    }
    result.update(_reuse_block(prior))
    return result


def _reuse_block(prior: list[dict]) -> dict:
    """In-band reuse signal: the count of scripts written this engagement and the
    recent ones' purposes, so the agent adapts an existing script instead of
    re-authoring a near-duplicate (the run_script grind)."""
    block: dict = {"scripts_written": len(prior) + 1}
    if prior:
        block["prior_scripts"] = [e.get("purpose", "") for e in prior][-_PRIOR_SHOWN:]
        block["reuse_hint"] = (
            "You have already written the scripts listed in prior_scripts this "
            "engagement. If one is close to what you need, adapt or fix THAT script "
            "(list_scripts shows the source) instead of writing another near-duplicate."
        )
    return block


TOOL_DEFINITION = {
    "name": "run_script",
    "description": (
        "LAST-RESORT escape hatch: write and run an ad-hoc Python or Bash script when NO existing "
        "tool fits the task. Reach for the dedicated tools first — sqlmap_scan, ffuf, nuclei_scan, "
        "netexec, web_exec, http_request, the impacket_* tools, etc. Only write a script when the "
        "task genuinely has no tool: a bespoke exploit, a custom protocol client, a specific "
        "encoder/decoder, a padding-oracle, a one-off parser. Do NOT use it to re-implement what a "
        "tool already does. "
        "The script runs LOCALLY — pair it with ssh_exec, web_exec, nc, or shell_exec to reach the "
        "target. You MUST set `purpose` to one plain-language line describing what the script does "
        "and why, so the operator can follow along. Scripts are saved to results/scripts/ for audit. "
        "Before writing a new script, call `list_scripts` to see what you have already written this "
        "engagement and reuse or adapt one rather than re-writing a near-duplicate. "
        "For long-running scripts, add background=true to avoid blocking the engagement."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "purpose": {
                "type": "string",
                "description": "One plain-language line: what this script does and why (shown to the operator). e.g. 'brute-force the 4-digit PIN on the /reset endpoint'.",
            },
            "language": {
                "type": "string",
                "enum": ["python", "bash"],
                "description": "Script language: 'python' (python3) or 'bash'.",
            },
            "script": {
                "type": "string",
                "description": "Complete, self-contained script source code. Do not truncate.",
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional command-line arguments passed to the script.",
            },
            "timeout": {
                "type": "integer",
                "description": "Execution timeout seconds (default 30). Use background=true for slow jobs instead.",
            },
            "background": {
                "type": "boolean",
                "description": "Run as a background job — result delivered automatically when done. Use for slow operations.",
            },
        },
        "required": ["purpose", "language", "script"],
    },
}
