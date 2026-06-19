"""
Google Cloud Platform enumeration and assessment via the gcloud CLI.
"""
import json
import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def gcloud(service: str, command: str, project: Optional[str] = None,
           format: str = "json", flags: Optional[str] = None) -> dict:
    if not shutil.which("gcloud"):
        return {"error": "gcloud not found. Install Google Cloud SDK: https://cloud.google.com/sdk/install"}

    # Build command: gcloud <service> <subcommands...>
    cmd = ["gcloud"] + service.split() + shlex.split(command)

    if project:
        cmd += ["--project", project]

    cmd += ["--format", format]

    if flags:
        cmd += shlex.split(flags)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return {"error": "gcloud timed out"}

    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()

    parsed = None
    if format == "json" and stdout:
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError:
            pass

    return {
        "service":  service,
        "command":  command,
        "project":  project,
        "success":  proc.returncode == 0,
        "data":     parsed if parsed else stdout[:16000],
        "error":    stderr[:500] if proc.returncode != 0 else None,
        "_command": " ".join(cmd),
    }


TOOL_DEFINITION = {
    "name": "gcloud",
    "description": (
        "Google Cloud Platform enumeration and security testing via gcloud CLI. "
        "Requires active gcloud authentication (gcloud auth login or service account key).\n\n"
        "Common security enumeration commands:\n"
        "service='auth' command='list' — show current authenticated accounts\n"
        "service='projects' command='list' — enumerate accessible GCP projects\n"
        "service='storage buckets' command='list' — list GCS buckets\n"
        "service='storage objects' command='list --bucket=BUCKET' — list bucket contents\n"
        "service='compute instances' command='list' — enumerate VM instances\n"
        "service='compute firewall-rules' command='list' — check firewall rules for 0.0.0.0/0\n"
        "service='iam service-accounts' command='list' — list service accounts\n"
        "service='iam' command='list-grantable-roles //cloudresourcemanager.googleapis.com/projects/PROJECT' — enumerate roles\n"
        "service='sql instances' command='list' — enumerate Cloud SQL instances\n"
        "service='functions' command='list' — list Cloud Functions\n"
        "service='secrets versions' command='list --secret=SECRETNAME' — list secret versions\n"
        "service='container clusters' command='list' — list GKE clusters\n\n"
        "For public bucket checks: no credentials needed — try 'storage buckets list' without auth."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "service":  {"type": "string", "description": "gcloud service and resource, e.g. 'compute instances', 'storage buckets', 'iam service-accounts', 'projects'"},
            "command":  {"type": "string", "description": "Command and arguments, e.g. 'list' or 'describe INSTANCE --zone us-central1-a'"},
            "project":  {"type": "string", "description": "GCP project ID. Omit to use active project."},
            "format":   {"type": "string", "description": "Output format: json (default), yaml, text, table"},
            "flags":    {"type": "string", "description": "Additional gcloud flags"},
        },
        "required": ["service", "command"],
    },
}
