import json
import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def safety_check(path: Optional[str] = None, requirements_file: Optional[str] = None,
                 flags: Optional[str] = None) -> dict:
    if not shutil.which("safety"):
        return {"error": "safety not found in PATH. Install: pip install safety"}

    cmd = ["safety", "check", "--json"]

    if requirements_file:
        cmd += ["-r", requirements_file]
    elif path:
        # Try to find requirements files in the path
        import os
        req_files = []
        for root, _, files in os.walk(path):
            for fname in files:
                if fname in ("requirements.txt", "requirements.in", "Pipfile", "pyproject.toml"):
                    req_files.append(os.path.join(root, fname))
        if req_files:
            for rf in req_files[:3]:  # Limit to first 3
                cmd += ["-r", rf]
        else:
            # Scan installed packages
            pass
    else:
        # Scan currently installed packages
        pass

    if flags:
        cmd += shlex.split(flags)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return {"error": "safety timed out"}

    result = _parse_output(proc.stdout, proc.stderr)
    result["_command"] = " ".join(cmd)
    return result


def _parse_output(stdout: str, stderr: str) -> dict:
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        # safety v3 outputs differently
        return {"vulnerabilities": [], "count": 0, "raw": (stdout + stderr)[:4000]}

    vulnerabilities: list = []

    # Handle both safety v2 (list) and v3 (dict) output formats
    items = data if isinstance(data, list) else data.get("vulnerabilities", [])

    for item in items:
        if isinstance(item, list):
            # v2 format: [package, version, "<version", advisory, vuln_id]
            vulnerabilities.append({
                "package":     item[0] if len(item) > 0 else "",
                "version":     item[1] if len(item) > 1 else "",
                "affected":    item[2] if len(item) > 2 else "",
                "advisory":    (item[3] if len(item) > 3 else "")[:500],
                "vuln_id":     item[4] if len(item) > 4 else "",
                "severity":    "unknown",
            })
        elif isinstance(item, dict):
            # v3 format
            vulnerabilities.append({
                "package":     item.get("package_name", ""),
                "version":     item.get("analyzed_version", ""),
                "affected":    item.get("vulnerable_spec", ""),
                "advisory":    (item.get("advisory", "") or "")[:500],
                "vuln_id":     item.get("vulnerability_id", ""),
                "severity":    item.get("severity", "unknown").lower(),
                "cvss_score":  item.get("cvss_v3", {}).get("base_score") if item.get("cvss_v3") else None,
            })

    return {"vulnerabilities": vulnerabilities, "count": len(vulnerabilities)}


TOOL_DEFINITION = {
    "name": "safety_check",
    "description": (
        "Python dependency vulnerability scanner via safety. "
        "Checks installed packages or requirements files against PyPI Safety DB and CVE databases. "
        "Provide path to a directory (auto-discovers requirements.txt/pyproject.toml) "
        "or a specific requirements_file path. "
        "If neither given, scans currently installed packages."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "path":              {"type": "string", "description": "Directory to scan for requirements files"},
            "requirements_file": {"type": "string", "description": "Direct path to requirements.txt or Pipfile"},
            "flags":             {"type": "string", "description": "Additional safety flags"},
        },
        "required": [],
    },
}
