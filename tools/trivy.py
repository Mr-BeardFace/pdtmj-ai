import json
import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def trivy(target: str, scan_type: str = "image", severity: str = "MEDIUM,HIGH,CRITICAL",
          flags: Optional[str] = None) -> dict:
    if not shutil.which("trivy"):
        return {"error": "trivy not found in PATH. Install from: github.com/aquasecurity/trivy"}

    cmd = ["trivy", scan_type, "--format", "json",
           "--severity", severity, "--no-progress", target]

    if flags:
        cmd += shlex.split(flags)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return {"error": "trivy timed out"}

    result = _parse_output(proc.stdout, proc.stderr, target, scan_type)
    result["_command"] = " ".join(cmd)
    return result


def _parse_output(stdout: str, stderr: str, target: str, scan_type: str) -> dict:
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return {"target": target, "vulnerabilities": [], "count": 0, "error": stderr[:1000]}

    vulns: list = []
    misconfigs: list = []
    secrets: list = []

    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities") or []:
            vulns.append({
                "vuln_id":         v.get("VulnerabilityID", ""),
                "package":         v.get("PkgName", ""),
                "installed_ver":   v.get("InstalledVersion", ""),
                "fixed_version":   v.get("FixedVersion", ""),
                "severity":        v.get("Severity", "").lower(),
                "title":           v.get("Title", ""),
                "description":     (v.get("Description", "") or "")[:300],
                "cvss_score":      (v.get("CVSS", {}) or {}).get("nvd", {}).get("V3Score"),
                "references":      (v.get("References") or [])[:3],
            })

        for m in result.get("Misconfigurations") or []:
            misconfigs.append({
                "id":       m.get("ID", ""),
                "type":     m.get("Type", ""),
                "title":    m.get("Title", ""),
                "severity": m.get("Severity", "").lower(),
                "message":  m.get("Message", ""),
            })

        for s in result.get("Secrets") or []:
            secrets.append({
                "rule_id":     s.get("RuleID", ""),
                "category":    s.get("Category", ""),
                "severity":    s.get("Severity", "").lower(),
                "title":       s.get("Title", ""),
                "match":       (s.get("Match", "") or "")[:100],
            })

    sev_counts: dict = {}
    for v in vulns:
        sev_counts[v["severity"]] = sev_counts.get(v["severity"], 0) + 1

    return {
        "target":          target,
        "scan_type":       scan_type,
        "vulnerabilities": vulns,
        "misconfigurations": misconfigs,
        "secrets":         secrets,
        "severity_counts": sev_counts,
        "count":           len(vulns),
    }


TOOL_DEFINITION = {
    "name": "trivy",
    "description": (
        "Vulnerability and misconfiguration scanner via Trivy. "
        "scan_type options:\n"
        "- 'image': scan a Docker image for OS and library CVEs\n"
        "- 'fs': scan a local directory/filesystem for CVEs and misconfigs\n"
        "- 'repo': scan a git repository\n"
        "- 'config': scan IaC files (Dockerfile, K8s, Terraform, CloudFormation) for misconfigurations\n"
        "Reports CVEs with CVSS scores, installed/fixed versions, and fix availability."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target":    {"type": "string", "description": "Image name, directory path, or repo URL"},
            "scan_type": {"type": "string", "description": "'image', 'fs', 'repo', 'config'. Default: image"},
            "severity":  {"type": "string", "description": "Comma-separated severity filter: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL. Default: MEDIUM,HIGH,CRITICAL"},
            "flags":     {"type": "string", "description": "Additional trivy flags, e.g. '--ignore-unfixed'"},
        },
        "required": ["target"],
    },
}
