import os
import shlex
import shutil
import subprocess
from core import proc as runner
import tempfile
from typing import Optional


def bloodhound_python(domain: str, dc: str, username: str, password: Optional[str] = None,
                      hash: Optional[str] = None, collection_method: str = "All",
                      flags: Optional[str] = None) -> dict:
    binary = shutil.which("bloodhound-python") or shutil.which("bloodhound_python")
    if not binary:
        return {"error": "bloodhound-python not found. Install: pip install bloodhound"}

    with tempfile.TemporaryDirectory() as tmpdir:
        cmd = [
            binary,
            "-d", domain,
            "-u", username,
            "-dc", dc,
            "-c", collection_method,
            "--zip",
            "--outputdir", tmpdir,
        ]

        if password:
            cmd += ["-p", password]
        elif hash:
            cmd += ["--hashes", hash]
        else:
            return {"error": "password or hash required for authentication"}

        if flags:
            cmd += shlex.split(flags)

        try:
            proc = runner.run(cmd, capture_output=True, text=True, timeout=600, cwd=tmpdir)
        except subprocess.TimeoutExpired:
            return {"error": "bloodhound-python timed out"}

        output = proc.stdout + proc.stderr

        # Find generated zip
        zip_files = [f for f in os.listdir(tmpdir) if f.endswith(".zip")]
        json_files = [f for f in os.listdir(tmpdir) if f.endswith(".json")]

        return {
            "domain":            domain,
            "collection_method": collection_method,
            "success":           proc.returncode == 0 and bool(zip_files or json_files),
            "output_zip":        zip_files[0] if zip_files else None,
            "json_files":        json_files,
            "output_dir":        tmpdir,
            "notes":             "Data collected. Import the zip file into BloodHound for analysis.",
            "raw":               output[:8000],
            "_command":          " ".join(cmd),
        }


TOOL_DEFINITION = {
    "name": "bloodhound_python",
    "description": (
        "Collect Active Directory attack path data using bloodhound-python (SharpHound Python port). "
        "Collects users, groups, computers, sessions, ACLs, and domain trusts for BloodHound graph analysis. "
        "Collection methods: 'All', 'DCOnly', 'Group', 'LocalAdmin', 'Session', 'Trusts', 'ACL', 'Container'. "
        "'DCOnly' is stealthier; 'All' is most complete but noisier. "
        "Output should be imported into BloodHound for path analysis."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "domain":            {"type": "string", "description": "Active Directory domain, e.g. 'lab.local'"},
            "dc":                {"type": "string", "description": "Domain controller IP or hostname"},
            "username":          {"type": "string", "description": "Domain username"},
            "password":          {"type": "string", "description": "Domain password"},
            "hash":              {"type": "string", "description": "NTLM hash for pass-the-hash"},
            "collection_method": {"type": "string", "description": "Collection method: All, DCOnly, Group, LocalAdmin, Session, ACL. Default: All"},
            "flags":             {"type": "string", "description": "Additional bloodhound-python flags"},
        },
        "required": ["domain", "dc", "username"],
    },
}
