import re
import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def rpcclient(target: str, command: str = "enumdomusers",
              username: Optional[str] = None, password: Optional[str] = None,
              domain: Optional[str] = None, flags: Optional[str] = None) -> dict:
    if not shutil.which("rpcclient"):
        return {"error": "rpcclient not found in PATH. Install: apt install samba-common-bin"}

    if username:
        auth = f"{domain}\\{username}" if domain else username
        auth_str = f"{auth}%{password}" if password else f"{auth}%"
    else:
        auth_str = "%"  # anonymous / null session

    cmd = ["rpcclient", "-U", auth_str, "-c", command]

    if flags:
        cmd += shlex.split(flags)

    cmd.append(target)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return {"error": "rpcclient timed out"}

    output = proc.stdout + proc.stderr
    result = _parse_output(output, command, target)
    result["_command"] = " ".join(cmd)
    return result


def _parse_output(output: str, command: str, target: str) -> dict:
    users: list = []
    groups: list = []
    shares: list = []
    generic: list = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # enumdomusers: user:[username] rid:[0xRID]
        user_m = re.search(r"user:\[(.+?)\]\s+rid:\[(0x[0-9a-f]+)\]", line, re.IGNORECASE)
        if user_m:
            users.append({
                "username": user_m.group(1),
                "rid":      int(user_m.group(2), 16),
            })
            continue

        # enumdomgroups: group:[name] rid:[0xRID]
        group_m = re.search(r"group:\[(.+?)\]\s+rid:\[(0x[0-9a-f]+)\]", line, re.IGNORECASE)
        if group_m:
            groups.append({
                "name": group_m.group(1),
                "rid":  int(group_m.group(2), 16),
            })
            continue

        # netshareenum: sharename type comment
        share_m = re.match(r"^(\S+)\s+(\d+)\s+(.*)", line)
        if share_m and command in ("netshareenum", "netshareenumall"):
            shares.append({
                "name":    share_m.group(1),
                "type":    share_m.group(2),
                "comment": share_m.group(3),
            })
            continue

        generic.append(line[:200])

    connected = "NT_STATUS_ACCESS_DENIED" not in output and "NT_STATUS_LOGON_FAILURE" not in output

    return {
        "target":    target,
        "command":   command,
        "connected": connected,
        "users":     users,
        "groups":    groups,
        "shares":    shares,
        "output":    generic[:200],
        "raw":       output[:8000],
    }


TOOL_DEFINITION = {
    "name": "rpcclient",
    "description": (
        "Windows RPC enumeration via rpcclient. "
        "Useful for null-session enumeration and authenticated domain reconnaissance.\n"
        "Common commands:\n"
        "- 'enumdomusers' — list all domain users (with RIDs)\n"
        "- 'enumdomgroups' — list domain groups\n"
        "- 'querydominfo' — domain info (password policy, account count)\n"
        "- 'getdompwinfo' — password policy\n"
        "- 'netshareenum' — enumerate network shares\n"
        "- 'queryuser 0x1f4' — query user by RID (500 decimal = 0x1f4 = Administrator)\n"
        "- 'querygroupmem 0x200' — list members of group by RID\n"
        "- 'lookupnames administrator' — resolve username to SID\n"
        "- 'lookupsids S-1-5-21-...' — resolve SID to name\n"
        "- 'srvinfo' — server info\n"
        "For null/anonymous session: omit username and password."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target":   {"type": "string", "description": "Target IP or hostname"},
            "command":  {"type": "string", "description": "RPC command to run. Default: enumdomusers"},
            "username": {"type": "string", "description": "Username (omit for null session)"},
            "password": {"type": "string", "description": "Password"},
            "domain":   {"type": "string", "description": "Windows domain"},
            "flags":    {"type": "string", "description": "Additional rpcclient flags"},
        },
        "required": ["target"],
    },
}
