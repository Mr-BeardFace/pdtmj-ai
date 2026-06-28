import os
import re
import shlex
import shutil
import subprocess
from core import paths
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

    def _auth_variants() -> list[tuple[str, list[str]]]:
        """Ordered (mode, smbclient-auth-args) to try until one connects.

        With real credentials: a single attempt, password always pinned (empty as
        `user%`) so smbclient never drops to an interactive prompt and blocks the
        turn. Unauthenticated (no creds, or a placeholder user like
        anonymous/guest/null with no password): try a pure null session (`-N`)
        FIRST, then an explicit anonymous user (`-U anonymous%`) — some servers
        reject a bare null session but accept anonymous with no password."""
        user = (username or "").strip()
        if user and not (user.lower() in _ANON_USERS and not password):
            auth = user if not domain else f"{domain}\\{user}"
            return [("credentialed", ["-U", f"{auth}%{password or ''}"])]
        return [("null", ["-N"]), ("anonymous", ["-U", "anonymous%"])]

    extra = shlex.split(flags) if flags else []

    # No share given → enumerate the share list first (smbclient -L). This is the
    # right first move: discover what shares exist, then connect to each. Without
    # it the agent can only guess at share names and falls back to IPC$.
    if not share:
        last: dict = {}
        for mode, auth_args in _auth_variants():
            cmd = ["smbclient", "-L", target, "-p", str(port)] + auth_args + extra
            try:
                proc = runner.run(cmd, capture_output=True, text=True, timeout=30)
            except subprocess.TimeoutExpired:
                last = {"error": "smbclient timed out", "target": target,
                        "_command": " ".join(cmd), "_auth_mode": mode}
                continue
            result = _parse_shares(proc.stdout + proc.stderr, target)
            result["_command"] = " ".join(cmd)
            result["_auth_mode"] = mode
            if result.get("connected") and result.get("shares"):
                return result            # this auth form worked — done
            last = result
        return last                      # nothing connected — return the last attempt

    unc = f"//{target}/{share}"
    last = {}
    for mode, auth_args in _auth_variants():
        cmd = ["smbclient", unc, "-p", str(port)] + auth_args + extra + ["-c", command]
        try:
            proc = runner.run(cmd, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            last = {"error": "smbclient timed out", "_command": " ".join(cmd),
                    "_auth_mode": mode}
            continue
        result = _parse_output(proc.stdout + proc.stderr, target, share, command)
        result["_command"] = " ".join(cmd)
        result["_auth_mode"] = mode
        if result.get("connected"):
            _annotate_download(result, command)
            return result
        last = result
    return last


def _annotate_download(result: dict, command: str) -> None:
    """For a `get`, report the local path of the downloaded file."""
    try:
        toks = shlex.split(command)
    except ValueError:
        toks = command.split()
    if not toks or toks[0].lower() != "get":
        return
    local = toks[2] if len(toks) >= 3 else os.path.basename(toks[1].replace("\\", "/"))
    dest = os.path.join(str(paths.downloads_dir()), os.path.basename(local))
    if os.path.exists(dest):
        result["saved_to"] = dest


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
        "- 'get filename' — download a file to the local downloads dir; result 'saved_to' is "
        "the local path. Analyze it with run_script (bash: unzip/strings/cat/grep), NOT remote-exec/listener tools.\n"
        "- 'put localfile remotefile' — upload a file\n"
        "- 'recurse; ls' — recursive listing\n"
        "- 'dir' — alias for ls\n"
        "For anonymous access: omit username/password — it tries a null session (-N) "
        "first, then falls back to an explicit anonymous user automatically. 'connected' "
        "and '_auth_mode' (null/anonymous/credentialed) report which form worked."
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
