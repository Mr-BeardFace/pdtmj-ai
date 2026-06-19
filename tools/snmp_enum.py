import re
import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def snmp_enum(target: str, community: str = "public", mode: str = "walk",
              oid: str = "1.3.6.1.2.1", version: str = "2c", port: int = 161,
              flags: Optional[str] = None) -> dict:
    """
    SNMP enumeration.
    mode='walk': snmpwalk (recursive OID traversal)
    mode='check': snmp-check (comprehensive system info report)
    mode='get': snmpget on specific OID
    mode='brute': try common community strings
    """
    mode = mode.lower()

    if mode == "check":
        return _snmp_check(target, community, version, port, flags)
    elif mode == "brute":
        return _community_brute(target, version, port)
    elif mode == "get":
        return _snmpget(target, community, oid, version, port, flags)
    else:
        return _snmpwalk(target, community, oid, version, port, flags)


def _snmpwalk(target, community, oid, version, port, flags):
    if not shutil.which("snmpwalk"):
        return {"error": "snmpwalk not found. Install: apt install snmp"}

    cmd = ["snmpwalk", "-v", version, "-c", community, "-On"]
    if flags:
        cmd += shlex.split(flags)
    cmd += [f"{target}:{port}", oid]

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return {"error": "snmpwalk timed out"}

    output = proc.stdout + proc.stderr
    result = _parse_walk(output, target, community)
    result.update({"mode": "walk", "oid": oid, "_command": " ".join(cmd)})
    return result


def _snmpget(target, community, oid, version, port, flags):
    if not shutil.which("snmpget"):
        return {"error": "snmpget not found. Install: apt install snmp"}

    cmd = ["snmpget", "-v", version, "-c", community, f"{target}:{port}", oid]
    if flags:
        cmd += shlex.split(flags)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        return {"error": "snmpget timed out"}

    return {
        "mode":     "get",
        "oid":      oid,
        "output":   proc.stdout.strip(),
        "error":    proc.stderr.strip() if proc.returncode != 0 else None,
        "_command": " ".join(cmd),
    }


def _snmp_check(target, community, version, port, flags):
    binary = shutil.which("snmp-check")
    if not binary:
        # Fall back to snmpwalk with system info OIDs
        return _snmpwalk(target, community, "1.3.6.1.2.1.1", version, port, flags)

    cmd = [binary, target, "-c", community, "-v", version[0], "-p", str(port)]
    if flags:
        cmd += shlex.split(flags)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": "snmp-check timed out"}

    output = proc.stdout + proc.stderr
    return {
        "mode":      "check",
        "target":    target,
        "community": community,
        "output":    output[:16000],
        "_command":  " ".join(cmd),
    }


def _community_brute(target, version, port):
    if not shutil.which("onesixtyone") and not shutil.which("snmpwalk"):
        return {"error": "onesixtyone or snmpwalk required for brute mode"}

    communities = ["public", "private", "community", "manager", "snmpd",
                   "cisco", "admin", "monitor", "0", "internal", "secret"]
    found: list = []

    if shutil.which("onesixtyone"):
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(communities))
            comm_file = f.name
        try:
            cmd = ["onesixtyone", "-c", comm_file, target]
            proc = runner.run(cmd, capture_output=True, text=True, timeout=30)
            for line in proc.stdout.splitlines():
                m = re.search(r"\[(\S+)\]", line)
                if m:
                    found.append(m.group(1))
        finally:
            os.unlink(comm_file)
    else:
        # Fallback: try each with snmpwalk
        for comm in communities:
            cmd = ["snmpwalk", "-v", version, "-c", comm, f"{target}:{port}",
                   "1.3.6.1.2.1.1.1.0"]
            try:
                proc = runner.run(cmd, capture_output=True, text=True, timeout=5)
                if proc.returncode == 0 and proc.stdout.strip():
                    found.append(comm)
            except Exception:
                pass

    return {
        "mode":               "brute",
        "target":             target,
        "valid_communities":  found,
        "count":              len(found),
        "_command":           f"community brute against {target}",
    }


def _parse_walk(output: str, target: str, community: str) -> dict:
    entries: list = []
    system_info: dict = {}

    sysname_oid  = "1.3.6.1.2.1.1.5"
    sysdesc_oid  = "1.3.6.1.2.1.1.1"
    sysuptime    = "1.3.6.1.2.1.1.3"
    syscontact   = "1.3.6.1.2.1.1.4"
    syslocation  = "1.3.6.1.2.1.1.6"

    for line in output.splitlines():
        if " = " in line:
            parts = line.split(" = ", 1)
            oid_part = parts[0].strip()
            val_part = parts[1].strip() if len(parts) > 1 else ""

            # Strip type annotation: STRING: "value" → "value"
            val_clean = re.sub(r"^\w+:\s*", "", val_part).strip('"')
            entries.append({"oid": oid_part, "value": val_clean[:200]})

            if sysdesc_oid in oid_part:
                system_info["description"] = val_clean
            elif sysname_oid in oid_part:
                system_info["hostname"] = val_clean
            elif syscontact in oid_part:
                system_info["contact"] = val_clean
            elif syslocation in oid_part:
                system_info["location"] = val_clean
            elif sysuptime in oid_part:
                system_info["uptime"] = val_clean

    accessible = bool(entries)
    return {
        "target":      target,
        "community":   community,
        "accessible":  accessible,
        "system_info": system_info,
        "entries":     entries[:500],
        "count":       len(entries),
    }


TOOL_DEFINITION = {
    "name": "snmp_enum",
    "description": (
        "SNMP enumeration via snmpwalk and snmp-check.\n"
        "modes:\n"
        "- 'walk' (default): snmpwalk — traverse OID tree from specified root. Use oid='1.3.6.1.2.1' for all MIB-II\n"
        "- 'check': snmp-check — comprehensive system report (system info, processes, interfaces, users, software)\n"
        "- 'get': snmpget — retrieve a specific OID value\n"
        "- 'brute': try common community strings (public, private, community, etc.)\n\n"
        "Common OIDs:\n"
        "- 1.3.6.1.2.1.1 — system info (sysDescr, sysName, sysContact)\n"
        "- 1.3.6.1.2.1.2 — interfaces\n"
        "- 1.3.6.1.2.1.4.20 — IP addresses\n"
        "- 1.3.6.1.2.1.6.13 — TCP connections\n"
        "- 1.3.6.1.4.1.77 — Windows LAN Manager (users, shares)\n"
        "- 1.3.6.1.2.1.25.4.2 — running processes\n\n"
        "If community 'public' is accessible: annotate as high — SNMP v1/v2c with default community is a misconfiguration."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target":    {"type": "string", "description": "Target IP or hostname"},
            "community": {"type": "string", "description": "SNMP community string. Default: public"},
            "mode":      {"type": "string", "description": "'walk', 'check', 'get', 'brute'. Default: walk"},
            "oid":       {"type": "string", "description": "OID to query/walk. Default: 1.3.6.1.2.1 (MIB-II root)"},
            "version":   {"type": "string", "description": "SNMP version: '1', '2c', '3'. Default: 2c"},
            "port":      {"type": "integer", "description": "SNMP port. Default: 161"},
            "flags":     {"type": "string", "description": "Additional snmpwalk/snmp-check flags"},
        },
        "required": ["target"],
    },
}
