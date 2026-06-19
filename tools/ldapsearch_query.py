import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def ldapsearch_query(target: str, base_dn: str, filter: str = "(objectClass=*)",
                     attributes: Optional[str] = None, port: int = 389,
                     username: Optional[str] = None, password: Optional[str] = None,
                     tls: bool = False, flags: Optional[str] = None) -> dict:
    if not shutil.which("ldapsearch"):
        return {"error": "ldapsearch not found in PATH"}

    proto = "ldaps" if tls else "ldap"
    url = f"{proto}://{target}:{port}"

    cmd = ["ldapsearch", "-x", "-H", url, "-b", base_dn, "-LLL"]

    if username:
        cmd += ["-D", username]
        if password:
            cmd += ["-w", password]
    else:
        # Anonymous bind
        pass

    if flags:
        cmd += shlex.split(flags)

    cmd.append(filter)

    if attributes:
        cmd += attributes.split()

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return {"error": "ldapsearch timed out"}

    result = _parse_ldif(proc.stdout, target, base_dn)
    result["_command"] = " ".join(cmd)
    return result


def _parse_ldif(ldif: str, target: str, base_dn: str) -> dict:
    entries: list = []
    current: dict = {}

    for line in ldif.splitlines():
        line = line.rstrip()
        if not line:
            if current:
                entries.append(current)
                current = {}
            continue
        if line.startswith("#"):
            continue
        # Handle continuation lines (start with space)
        if line.startswith(" ") and current:
            last_key = list(current.keys())[-1] if current else None
            if last_key:
                val = current[last_key]
                if isinstance(val, list) and val:
                    val[-1] = val[-1] + line[1:]
            continue

        if ": " in line:
            k, _, v = line.partition(": ")
            k = k.rstrip(":")
            if k in current:
                if not isinstance(current[k], list):
                    current[k] = [current[k]]
                current[k].append(v)
            else:
                current[k] = v

    if current:
        entries.append(current)

    # Extract useful summary fields
    users  = [e for e in entries if "sAMAccountName" in e]
    groups = [e for e in entries if "groupType" in e or e.get("objectClass", "") == "group"]

    return {
        "target":   target,
        "base_dn":  base_dn,
        "entries":  entries[:500],
        "total":    len(entries),
        "users":    [{"name": u.get("sAMAccountName", ""), "dn": u.get("dn", "")} for u in users[:200]],
        "groups":   [{"name": g.get("cn", ""), "dn": g.get("dn", "")} for g in groups[:200]],
    }


TOOL_DEFINITION = {
    "name": "ldapsearch_query",
    "description": (
        "Query an LDAP/Active Directory server using ldapsearch. "
        "Supports anonymous and authenticated binds. "
        "Use for: domain user/group enumeration, domain policy, computer accounts, "
        "SPN lookup, AdminSDHolder, ACL analysis. "
        "Common base DNs: 'DC=lab,DC=local'. "
        "Useful filters: '(objectClass=user)', '(objectClass=group)', "
        "'(servicePrincipalName=*)', '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' (no pre-auth)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target":     {"type": "string", "description": "LDAP server IP or hostname"},
            "base_dn":    {"type": "string", "description": "Search base DN, e.g. 'DC=lab,DC=local'"},
            "filter":     {"type": "string", "description": "LDAP filter, e.g. '(objectClass=user)'. Default: (objectClass=*)"},
            "attributes": {"type": "string", "description": "Space-separated attribute names to return, e.g. 'cn sAMAccountName memberOf'"},
            "port":       {"type": "integer", "description": "LDAP port. Default 389; use 636 for LDAPS"},
            "username":   {"type": "string", "description": "Bind DN or UPN for authenticated query, e.g. 'administrator@lab.local'"},
            "password":   {"type": "string", "description": "Password for authenticated bind"},
            "tls":        {"type": "boolean", "description": "Use LDAPS (TLS). Default false"},
            "flags":      {"type": "string", "description": "Additional ldapsearch flags"},
        },
        "required": ["target", "base_dn"],
    },
}
