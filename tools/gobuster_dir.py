import re
import shlex
import shutil
import subprocess
from typing import Optional

from core import proc as runner

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


def gobuster_dir(
    url: str,
    wordlist: Optional[str] = None,
    extensions: Optional[str] = None,
    status_codes: Optional[str] = None,
    extra_args: Optional[str] = None,
) -> dict:
    if not shutil.which("gobuster"):
        return {"error": "gobuster not found in PATH"}

    wl = wordlist or DEFAULT_WORDLIST

    cmd = [
        "gobuster", "dir",
        "-u", url,
        "-w", wl,
        "--no-color",
        "-q",
        "-k",               # skip TLS verification
    ]
    if extensions:
        cmd += ["-x", extensions]
    if status_codes:
        cmd += ["-s", status_codes]
    # Free-form passthrough — threads, cookies, user-agent, proxy, etc.
    if extra_args:
        cmd += shlex.split(extra_args)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return {"error": "gobuster dir timed out", "url": url}

    # Output format: /path   (Status: 200) [Size: 1234] [--> /redirect/]
    pattern = re.compile(
        r"^(\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\](?:\s+\[-->\s*(.+?)\])?"
    )

    results = []
    for line in proc.stdout.splitlines():
        m = pattern.match(line.strip())
        if m:
            results.append({
                "path":     m.group(1),
                "status":   int(m.group(2)),
                "size":     int(m.group(3)),
                "redirect": m.group(4) or None,
            })

    return {"url": url, "wordlist": wl, "results": results, "count": len(results),
            "_command": " ".join(cmd)}


TOOL_DEFINITION = {
    "name": "gobuster_dir",
    "description": (
        "Directory and file brute-force against a web root using gobuster. "
        "Returns discovered paths with HTTP status codes and sizes. "
        "Use `extensions` to include file extensions (e.g. 'php,html,txt,bak'). "
        "Defaults to /usr/share/wordlists/dirb/common.txt."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Base URL to enumerate (e.g. https://example.com)",
            },
            "wordlist": {
                "type": "string",
                "description": "Absolute path to wordlist. Defaults to dirb/common.txt.",
            },
            "extensions": {
                "type": "string",
                "description": "Comma-separated file extensions to append (e.g. 'php,html,txt,bak,zip')",
            },
            "status_codes": {
                "type": "string",
                "description": "Comma-separated status codes to include (default: gobuster default — 200,204,301,302,307,401,403)",
            },
            "extra_args": {
                "type": "string",
                "description": "Any additional raw gobuster flags as a single string, e.g. '-t 50 -a <ua> -c <cookies> --proxy http://127.0.0.1:8080'. Passed through verbatim.",
            },
            "background": {
                "type": "boolean",
                "description": "Run as a background job and keep working; results are delivered automatically when it finishes. Use for large wordlists so it doesn't block.",
            },
        },
        "required": ["url"],
    },
}
