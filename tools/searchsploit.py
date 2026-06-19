import json
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def searchsploit(query: str, flags: Optional[str] = None) -> dict:
    if not shutil.which("searchsploit"):
        return {"error": "searchsploit not found in PATH. Install exploitdb package."}

    cmd = ["searchsploit", "--json"]
    if flags:
        import shlex
        cmd += shlex.split(flags)
    cmd += query.split()

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return {"error": "searchsploit timed out"}

    result = _parse_output(proc.stdout, query)
    result["_command"] = " ".join(cmd)
    return result


def _parse_output(stdout: str, query: str) -> dict:
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return {"query": query, "exploits": [], "shellcodes": [], "count": 0}

    exploits = []
    for item in data.get("RESULTS_EXPLOIT", []):
        exploits.append({
            "title":       item.get("Title", ""),
            "edb_id":      item.get("EDB-ID", ""),
            "date":        item.get("Date", ""),
            "author":      item.get("Author", ""),
            "type":        item.get("Type", ""),
            "platform":    item.get("Platform", ""),
            "path":        item.get("Path", ""),
            "codes":       item.get("Codes", ""),
            "verified":    item.get("Verified", False),
        })

    shellcodes = []
    for item in data.get("RESULTS_SHELLCODE", []):
        shellcodes.append({
            "title":    item.get("Title", ""),
            "edb_id":   item.get("EDB-ID", ""),
            "platform": item.get("Platform", ""),
            "path":     item.get("Path", ""),
        })

    return {
        "query":      query,
        "exploits":   exploits,
        "shellcodes": shellcodes,
        "count":      len(exploits) + len(shellcodes),
    }


TOOL_DEFINITION = {
    "name": "searchsploit",
    "description": (
        "Search Exploit-DB for public exploits and shellcodes matching a software name and version. "
        "Returns EDB-IDs, titles, types (local/remote/webapps/dos), platforms, and file paths. "
        "Use when a service version is identified — search the product name + version: "
        "'Apache 2.4.49', 'ProFTPD 1.3.5', 'vBulletin 5.6.9'."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Search terms, e.g. 'Apache 2.4.49' or 'ProFTPD 1.3.5 RCE'",
            },
            "flags": {
                "type": "string",
                "description": "Additional searchsploit flags, e.g. '--www' to include Offensive Security URL",
            },
        },
        "required": ["query"],
    },
}
