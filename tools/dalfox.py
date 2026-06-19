import shlex
import shutil
import subprocess
import re
from typing import Optional, Dict

from core import proc as runner


def dalfox(
    url: str,
    data: Optional[str] = None,
    cookies: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    method: str = "GET",
    extra_args: Optional[str] = None,
) -> dict:
    if not shutil.which("dalfox"):
        return {"error": "dalfox not found in PATH"}

    cmd = ["dalfox", "url", url, "--silence", "--no-color"]

    if method.upper() == "POST" and data:
        cmd += ["--data", data]
    if cookies:
        cmd += ["--cookie", cookies]
    if headers:
        for k, v in headers.items():
            cmd += ["--add-header", f"{k}: {v}"]
    # Free-form passthrough — custom payloads, blind XSS, params, worker count, etc.
    if extra_args:
        cmd += shlex.split(extra_args)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": "dalfox timed out", "url": url}

    findings = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # POC lines: [POC][G][...][Reflected] payload
        # or:        [POC][G][Reflected] payload
        if line.startswith("[POC]"):
            inject_type = ""

            # Extract inject type
            type_match = re.search(r"\[(inHTML[^\]]*|inJS[^\]]*|inATTR[^\]]*)\]", line)
            if type_match:
                inject_type = type_match.group(1)

            # Extract parameter
            param_match = re.search(r"PARAM:([^\s\]]+)", line)
            param = param_match.group(1) if param_match else ""

            # Reflected vs stored
            reflected = "Reflected" in line
            stored    = "Stored" in line

            # Extract the PoC URL/payload (last bracketed section or trailing text)
            poc_match = re.search(r"\[(?:Reflected|Stored)\]\s+(.+)$", line)
            poc = poc_match.group(1).strip() if poc_match else line

            findings.append({
                "inject_type": inject_type,
                "parameter":   param,
                "reflected":   reflected,
                "stored":      stored,
                "poc":         poc,
                "raw":         line,
            })

    return {
        "url":        url,
        "vulnerable": len(findings) > 0,
        "findings":   findings,
        "count":      len(findings),
        "_command":   " ".join(cmd),
    }


TOOL_DEFINITION = {
    "name": "dalfox",
    "description": (
        "XSS scanner. Tests URL parameters, form fields, and headers for reflected and stored "
        "cross-site scripting. Returns confirmed injection points with working PoC payloads. "
        "Supports GET and POST. Provide cookies for authenticated scanning."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Target URL to scan for XSS",
            },
            "data": {
                "type": "string",
                "description": "POST body for POST-based scanning",
            },
            "cookies": {
                "type": "string",
                "description": "Session cookies for authenticated scanning",
            },
            "headers": {
                "type": "object",
                "description": "Additional request headers",
                "additionalProperties": {"type": "string"},
            },
            "method": {
                "type": "string",
                "description": "HTTP method: GET (default) or POST",
            },
            "extra_args": {
                "type": "string",
                "description": "Any additional raw dalfox flags as a single string, e.g. '--custom-payload file.txt -b yourcollab.net -p id --worker 50'. Passed through verbatim.",
            },
        },
        "required": ["url"],
    },
}
