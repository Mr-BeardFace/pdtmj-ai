import json
import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def bandit(path: str, severity: str = "LOW", confidence: str = "LOW",
           flags: Optional[str] = None) -> dict:
    if not shutil.which("bandit"):
        return {"error": "bandit not found in PATH. Install: pip install bandit"}

    cmd = [
        "bandit", "-r", path,
        "-f", "json",
        "-l",  # show line ranges
        "-lll",  # all severity levels (override with actual flags if needed)
    ]

    # Remove the placeholder and apply real severity/confidence
    cmd = ["bandit", "-r", path, "-f", "json",
           "--severity-level", severity.lower(),
           "--confidence-level", confidence.lower()]

    if flags:
        cmd += shlex.split(flags)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": "bandit timed out"}

    result = _parse_output(proc.stdout, proc.stderr, path)
    result["_command"] = " ".join(cmd)
    return result


def _parse_output(stdout: str, stderr: str, path: str) -> dict:
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return {"path": path, "findings": [], "count": 0, "errors": stderr[:1000]}

    findings: list = []
    for r in data.get("results", []):
        findings.append({
            "test_id":    r.get("test_id", ""),
            "test_name":  r.get("test_name", ""),
            "severity":   r.get("issue_severity", "").lower(),
            "confidence": r.get("issue_confidence", "").lower(),
            "message":    r.get("issue_text", ""),
            "file":       r.get("filename", ""),
            "line":       r.get("line_number"),
            "code":       r.get("code", "")[:500],
            "cwe":        r.get("issue_cwe", {}).get("id") if r.get("issue_cwe") else None,
        })

    metrics = data.get("metrics", {})
    return {
        "path":     path,
        "findings": findings,
        "count":    len(findings),
        "metrics":  metrics,
    }


TOOL_DEFINITION = {
    "name": "bandit",
    "description": (
        "Python-specific security scanner via Bandit. "
        "Finds: SQL injection, shell injection, hardcoded passwords, use of weak crypto, "
        "pickle deserialization, YAML load vulnerabilities, assert statements in auth code, "
        "and 40+ other Python security issues. "
        "severity: LOW/MEDIUM/HIGH — minimum severity to report. "
        "confidence: LOW/MEDIUM/HIGH — minimum confidence to report."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "path":       {"type": "string", "description": "Python file or directory to scan"},
            "severity":   {"type": "string", "description": "Minimum severity: LOW, MEDIUM, HIGH. Default: LOW"},
            "confidence": {"type": "string", "description": "Minimum confidence: LOW, MEDIUM, HIGH. Default: LOW"},
            "flags":      {"type": "string", "description": "Additional bandit flags, e.g. '--skip B101 --exclude tests'"},
        },
        "required": ["path"],
    },
}
