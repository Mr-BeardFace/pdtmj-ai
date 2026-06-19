import json
import shlex
import shutil
import subprocess
from core import proc as runner
import tempfile
from typing import Optional


def gitleaks(path: str, source_type: str = "detect",
             flags: Optional[str] = None) -> dict:
    if not shutil.which("gitleaks"):
        return {"error": "gitleaks not found in PATH. Install from: github.com/gitleaks/gitleaks"}

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        report_file = f.name

    cmd = ["gitleaks", source_type, "--source", path,
           "--report-format", "json", "--report-path", report_file,
           "--exit-code", "0"]

    if flags:
        cmd += shlex.split(flags)

    try:
        runner.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return {"error": "gitleaks timed out"}

    result = _parse_report(report_file, path)
    result["_command"] = " ".join(cmd)

    import os
    try:
        os.unlink(report_file)
    except Exception:
        pass

    return result


def _parse_report(report_file: str, path: str) -> dict:
    import os
    findings: list = []

    if not os.path.exists(report_file):
        return {"path": path, "findings": [], "count": 0}

    try:
        with open(report_file) as f:
            data = json.load(f)
    except (json.JSONDecodeError, ValueError):
        return {"path": path, "findings": [], "count": 0}

    if not data:
        return {"path": path, "findings": [], "count": 0}

    for item in data:
        findings.append({
            "rule_id":      item.get("RuleID", ""),
            "description":  item.get("Description", ""),
            "secret":       item.get("Secret", "")[:100] + ("..." if len(item.get("Secret", "")) > 100 else ""),
            "match":        item.get("Match", "")[:200],
            "file":         item.get("File", ""),
            "line":         item.get("StartLine"),
            "commit":       item.get("Commit", ""),
            "author":       item.get("Author", ""),
            "date":         item.get("Date", ""),
            "tags":         item.get("Tags", []),
        })

    return {"path": path, "findings": findings, "count": len(findings)}


TOOL_DEFINITION = {
    "name": "gitleaks",
    "description": (
        "Git secrets detection via gitleaks. Scans git history and working directories for "
        "API keys, tokens, passwords, and other sensitive data patterns. "
        "source_type: 'detect' for local repo/directory, 'git' for git history specifically. "
        "Complements TruffleHog — run both for complete coverage. "
        "Reports include file path, line number, commit hash, and author."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "path":        {"type": "string", "description": "Path to git repository or directory to scan"},
            "source_type": {"type": "string", "description": "'detect' or 'git'. Default: detect"},
            "flags":       {"type": "string", "description": "Additional gitleaks flags, e.g. '--no-git'"},
        },
        "required": ["path"],
    },
}
