import os
import re
import shlex
import shutil
import subprocess
from core import paths
from core import proc as runner
from typing import Optional

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _normalize_hash(h: str) -> str:
    """bloodhound --hashes wants LMHASH:NTHASH; a bare NT hash gets an empty LM."""
    h = h.strip()
    return h if ":" in h else f"aad3b435b51404eeaad3b435b51404ee:{h}"


def bloodhound_python(domain: str, dc: str, username: str, password: Optional[str] = None,
                      hash: Optional[str] = None, nameserver: Optional[str] = None,
                      collection_method: str = "All", flags: Optional[str] = None) -> dict:
    binary = shutil.which("bloodhound-python") or shutil.which("bloodhound_python")
    if not binary:
        return {"error": "bloodhound-python not found. Install: pip install bloodhound"}

    dc = (dc or "").strip()
    dc_is_ip = bool(_IP_RE.match(dc))
    # DNS is the usual failure: bloodhound resolves the domain + every computer via
    # DNS the local resolver doesn't know — point it at the DC. Default the nameserver
    # to the DC IP; a hostname DC with no nameserver can't be resolved.
    ns = (nameserver or "").strip() or (dc if dc_is_ip else "")
    if not ns:
        return {"error": "bloodhound needs the DC's IP for DNS — pass nameserver=<DC IP> "
                         "(or give dc as the DC IP)."}

    # Output lands in cwd (this bloodhound-python build has no --outputdir flag);
    # cwd is the assessment downloads dir, so the zip is kept as loot.
    outdir = str(paths.downloads_dir())
    cmd = [
        binary,
        "-d", domain,
        "-u", username,
        "-ns", ns,
        "--dns-tcp",                          # UDP/53 is often filtered; TCP is reliable
        "-c", collection_method,
        "--zip",
    ]
    # -dc wants the DC *hostname*; only pass it when we have one (an IP there breaks
    # name resolution). With just the IP, -ns lets bloodhound find the DC.
    if dc and not dc_is_ip:
        cmd += ["-dc", dc]

    if password:
        cmd += ["-p", password]
    elif hash:
        cmd += ["--hashes", _normalize_hash(hash)]
    else:
        return {"error": "password or hash required for authentication"}

    if flags:
        cmd += shlex.split(flags)

    before = set(os.listdir(outdir))
    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=600, cwd=outdir)
    except subprocess.TimeoutExpired:
        return {"error": "bloodhound-python timed out", "_command": " ".join(cmd)}

    output = proc.stdout + proc.stderr
    new = [f for f in os.listdir(outdir) if f not in before]
    zip_files = [f for f in new if f.endswith(".zip")]
    json_files = [f for f in new if f.endswith(".json")]
    ok = proc.returncode == 0 and bool(zip_files or json_files)

    result = {
        "domain":            domain,
        "collection_method": collection_method,
        "success":           ok,
        "output_zip":        os.path.join(outdir, zip_files[0]) if zip_files else None,
        "json_files":        json_files,
        "output_dir":        outdir,
        "raw":               output[:8000],
        "_command":          " ".join(cmd),
    }
    if ok:
        result["notes"] = "Data collected. Import the zip into BloodHound for analysis."
    else:
        result["error"] = (output[-1500:].strip()
                           or f"bloodhound-python exited {proc.returncode} with no data")
        result["hint"] = ("Common causes: wrong domain FQDN, DNS not pointed at the DC, "
                          "clock skew >5min (sync time for Kerberos), or bad credentials.")
    return result


TOOL_DEFINITION = {
    "name": "bloodhound_python",
    "description": (
        "Collect Active Directory attack path data using bloodhound-python (SharpHound Python port). "
        "Collects users, groups, computers, sessions, ACLs, and domain trusts for BloodHound graph analysis. "
        "Collection methods: 'All', 'DCOnly', 'Group', 'LocalAdmin', 'Session', 'Trusts', 'ACL', 'Container'. "
        "'DCOnly' is stealthier; 'All' is most complete but noisier. "
        "DNS must point at the DC — pass the DC IP as 'dc' (or set 'nameserver' to it), or "
        "collection fails to resolve the domain. Output zip is imported into BloodHound."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "domain":            {"type": "string", "description": "AD domain FQDN, e.g. 'lab.local' (lowercase)"},
            "dc":                {"type": "string", "description": "Domain controller IP (preferred) or hostname"},
            "username":          {"type": "string", "description": "Domain username"},
            "password":          {"type": "string", "description": "Domain password"},
            "hash":              {"type": "string", "description": "NTLM hash (NT or LM:NT) for pass-the-hash"},
            "nameserver":        {"type": "string", "description": "DNS server IP for resolving the domain — the DC IP. Defaults to 'dc' when that is an IP."},
            "collection_method": {"type": "string", "description": "Collection method: All, DCOnly, Group, LocalAdmin, Session, ACL. Default: All"},
            "flags":             {"type": "string", "description": "Additional bloodhound-python flags"},
        },
        "required": ["domain", "dc", "username"],
    },
}
