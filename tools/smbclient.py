import re
import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


# Placeholder usernames that really mean "unauthenticated" — mapped to a null
# session (-N) when no password is supplied, so anonymous enumeration is the exact
# `smbclient -L <target> -N`, not a named login.
_ANON_USERS = {"", "anonymous", "guest", "null", "anonymous logon"}


def smbclient(target: str, share: Optional[str] = None, command: str = "ls",
              username: Optional[str] = None, password: Optional[str] = None,
              domain: Optional[str] = None, port: int = 445,
              flags: Optional[str] = None) -> dict:
    if not shutil.which("smbclient"):
        return {"error": "smbclient not found in PATH. Install: apt install smbclient"}

    def _auth(cmd: list[str]) -> None:
        user = (username or "").strip()
        # Anonymous / null session: no real user AND no password → `-N` with no -U
        # (smbclient -L <target> -N). Agents often pass a placeholder username
        # ("anonymous"/"guest"/"null") for what is really an unauthenticated probe;
        # treat those as anonymous so the command is the correct null session, not a
        # bogus `-U anonymous` that auths as a named account (or prompts and hangs).
        if not password and user.lower() in _ANON_USERS:
            cmd += ["-N"]
            return
        if user:
            auth = user if not domain else f"{domain}\\{user}"
            # Always pin the password (real or empty) so smbclient never drops to an
            # interactive password prompt and blocks the turn. Empty = `-U user%`.
            cmd += ["-U", f"{auth}%{password or ''}"]
        else:
            cmd += ["-N"]  # No password / anonymous

    # No share given → enumerate the share list first (smbclient -L). This is the
    # right first move: discover what shares exist, then connect to each. Without
    # it the agent can only guess at share names and falls back to IPC$.
    if not share:
        cmd = ["smbclient", "-L", target, "-p", str(port)]
        _auth(cmd)
        if flags:
            cmd += shlex.split(flags)
        try:
            proc = runner.run(cmd, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            return {"error": "smbclient timed out", "target": target}
        output = proc.stdout + proc.stderr
        result = _parse_shares(output, target)
        result["_command"] = " ".join(cmd)
        return result

    unc = f"//{target}/{share}"
    cmd = ["smbclient", unc, "-p", str(port)]
    _auth(cmd)
    if flags:
        cmd += shlex.split(flags)
    cmd += ["-c", command]

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return {"error": "smbclient timed out"}

    output = proc.stdout + proc.stderr
    result = _parse_output(output, target, share, command)
    result["_command"] = " ".join(cmd)
    return result


# Shares we never want the agent to fixate on as "the" target — administrative /
# special shares that exist on virtually every host and are rarely the foothold.
_ADMIN_SHARES = {"ADMIN$", "IPC$", "PRINT$"}


def _parse_shares(output: str, target: str) -> dict:
    """Parse `smbclient -L` output into a list of shares. The table looks like:
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        data            Disk
        IPC$            IPC       Remote IPC
    """
    shares: list = []
    errors: list = []
    for line in output.splitlines():
        m = re.match(r"^\s+(\S.*?)\s+(Disk|IPC|Printer)\s*(.*)$", line)
        if m and m.group(1).strip().lower() != "sharename":
            name = m.group(1).strip()
            shares.append({
                "name":    name,
                "type":    m.group(2).strip(),
                "comment": m.group(3).strip(),
                "admin":   name.upper() in _ADMIN_SHARES,
            })
        if any(err in line for err in ["NT_STATUS_", "Error", "DENIED", "failed"]) \
                and "NT_STATUS_OK" not in line:
            errors.append(line.strip())

    listable = [s["name"] for s in shares if not s["admin"]]
    return {
        "target":    target,
        "mode":      "list_shares",
        "connected": bool(shares) and not (errors and not shares),
        "shares":    shares,
        # Non-administrative shares worth connecting to next, in priority order.
        "next_shares": listable,
        "errors":    errors[:10],
        "raw":       output[:8000],
    }


def _parse_output(output: str, target: str, share: str, command: str) -> dict:
    files: list = []
    errors: list = []

    for line in output.splitlines():
        # File listing: drwxr-xr-x or -rwxr-xr-x style, or Windows SMB ls format
        # smbclient ls output: "  filename  D  0  Mon Jan 1 00:00:00 2024"
        file_m = re.match(r"^\s+(.+?)\s+(D|A|N|H|S|R)\s+(\d+)\s+", line)
        if file_m:
            files.append({
                "name":  file_m.group(1).strip(),
                "type":  "directory" if file_m.group(2) == "D" else "file",
                "size":  int(file_m.group(3)),
            })

        if any(err in line for err in ["NT_STATUS_", "Error", "DENIED", "failed"]):
            errors.append(line.strip())

    connected = "NT_STATUS_" not in output or "NT_STATUS_OK" in output
    if errors and not files:
        connected = False

    return {
        "target":    target,
        "share":     share,
        "command":   command,
        "connected": connected,
        "files":     files[:500],
        "errors":    errors[:10],
        "raw":       output[:8000],
    }


TOOL_DEFINITION = {
    "name": "smbclient",
    "description": (
        "Interact with SMB shares via smbclient.\n"
        "ALWAYS enumerate shares first: call with NO 'share' to run `smbclient -L` and get the "
        "share list (returns 'shares' and 'next_shares' — the non-administrative shares worth "
        "exploring). THEN call again with each share name to list/read its contents. Do not jump "
        "straight to IPC$ or guess a share name; list first, then walk the shares that come back.\n"
        "Once a share is given, 'command' runs inside it:\n"
        "- 'ls' — list files in share root\n"
        "- 'ls subdir/' — list subdirectory\n"
        "- 'get filename' — download a file (writes to current dir)\n"
        "- 'put localfile remotefile' — upload a file\n"
        "- 'recurse; ls' — recursive listing\n"
        "- 'dir' — alias for ls\n"
        "For anonymous access: omit username/password (uses -N flag)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target":   {"type": "string", "description": "Target IP or hostname"},
            "share":    {"type": "string", "description": "Share name to connect to (e.g. a name returned by the share-list call). OMIT to enumerate the available shares first (smbclient -L)."},
            "command":  {"type": "string", "description": "smbclient command to run inside the share. Default: ls. Ignored when listing shares."},
            "username": {"type": "string", "description": "Username (omit for anonymous)"},
            "password": {"type": "string", "description": "Password"},
            "domain":   {"type": "string", "description": "Windows domain"},
            "port":     {"type": "integer", "description": "SMB port. Default: 445"},
            "flags":    {"type": "string", "description": "Additional smbclient flags"},
        },
        "required": ["target"],
    },
}
