import json
import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def trufflehog(path: str, source_type: str = "filesystem",
               flags: Optional[str] = None) -> dict:
    if not shutil.which("trufflehog"):
        return {"error": "trufflehog not found in PATH. Install from: github.com/trufflesecurity/trufflehog"}

    cmd = ["trufflehog", source_type, path, "--json", "--no-update"]
    if flags:
        cmd += shlex.split(flags)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return {"error": "trufflehog timed out"}

    result = _parse_output(proc.stdout, path)
    result["_command"] = " ".join(cmd)
    return result


def _parse_output(stdout: str, path: str) -> dict:
    findings: list = []
    verified_count = 0

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        verified = obj.get("Verified", False)
        if verified:
            verified_count += 1

        findings.append({
            "detector":    obj.get("DetectorName", ""),
            "verified":    verified,
            "raw":         obj.get("Raw", "")[:200],
            "source_name": obj.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "")
                           or obj.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("file", ""),
            "line":        obj.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line"),
            "commit":      obj.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("commit", ""),
            "extra_data":  obj.get("ExtraData", {}),
        })

    return {
        "path":           path,
        "findings":       findings,
        "count":          len(findings),
        "verified_count": verified_count,
    }


TOOL_DEFINITION = {
    "name": "trufflehog",
    "description": (
        "Secrets detection via TruffleHog. Scans for live, verified credentials and sensitive data: "
        "AWS keys, GitHub tokens, Stripe keys, Slack tokens, Google API keys, private keys, passwords, and 700+ detectors. "
        "source_type options: 'filesystem' (scan directory), 'git' (scan git repo history including all commits), "
        "'github' (scan GitHub repo). "
        "Verified=true means TruffleHog confirmed the secret is active against its API."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "path":        {"type": "string", "description": "Path to scan — directory, git repo, or GitHub URL"},
            "source_type": {"type": "string", "description": "'filesystem', 'git', or 'github'. Default: filesystem"},
            "flags":       {"type": "string", "description": "Additional flags, e.g. '--only-verified' to show only live creds"},
        },
        "required": ["path"],
    },
}
