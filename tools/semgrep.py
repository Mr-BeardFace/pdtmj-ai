import json
import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def semgrep(path: str, config: str = "auto", flags: Optional[str] = None) -> dict:
    if not shutil.which("semgrep"):
        return {"error": "semgrep not found in PATH. Install: pip install semgrep"}

    cmd = ["semgrep", "--config", config, "--json", "--no-rewrite-rule-ids"]
    if flags:
        cmd += shlex.split(flags)
    cmd.append(path)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return {"error": "semgrep timed out"}

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
            "rule_id":   r.get("check_id", ""),
            "severity":  r.get("extra", {}).get("severity", "").lower() or "info",
            "message":   r.get("extra", {}).get("message", ""),
            "file":      r.get("path", ""),
            "line_start": r.get("start", {}).get("line"),
            "line_end":   r.get("end", {}).get("line"),
            "code":       r.get("extra", {}).get("lines", "")[:500],
            "cwe":        r.get("extra", {}).get("metadata", {}).get("cwe", []),
            "owasp":      r.get("extra", {}).get("metadata", {}).get("owasp", []),
        })

    errors = [e.get("message", "") for e in data.get("errors", [])]

    return {
        "path":     path,
        "findings": findings,
        "count":    len(findings),
        "errors":   errors[:10],
    }


TOOL_DEFINITION = {
    "name": "semgrep",
    "description": (
        "Static Application Security Testing (SAST) via Semgrep. "
        "Detects code-level vulnerabilities: injection flaws, insecure deserialization, "
        "hardcoded secrets, dangerous function calls, weak crypto, SSRF, and more. "
        "Supports Python, JS/TS, Java, Go, Ruby, PHP, C/C++, and more. "
        "config='auto' downloads community rules automatically. "
        "Specific configs: 'p/owasp-top-ten', 'p/javascript', 'p/python', 'p/secrets', 'p/jwt'."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "path":   {"type": "string", "description": "File or directory path to scan"},
            "config": {"type": "string", "description": "Semgrep config: 'auto', 'p/owasp-top-ten', 'p/python', etc. Default: auto"},
            "flags":  {"type": "string", "description": "Additional semgrep flags, e.g. '--severity ERROR --exclude tests/'"},
        },
        "required": ["path"],
    },
}
