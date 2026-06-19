import shlex
import shutil
import subprocess
import tempfile
import os
import re
from typing import Optional, Dict

from core import proc as runner


def sqlmap_scan(
    url: str,
    data: Optional[str] = None,
    cookies: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    param: Optional[str] = None,
    depth: str = "enumerate",
    table: Optional[str] = None,
    database: Optional[str] = None,
    flags: Optional[str] = None,
) -> dict:
    if not shutil.which("sqlmap"):
        return {"error": "sqlmap not found in PATH"}

    fd, out_path = tempfile.mkstemp(prefix="pentest_sqlmap_", suffix=".json")
    os.close(fd)

    try:
        cmd = [
            "sqlmap",
            "-u", url,
            "--batch",
            "--level=2",
            "--risk=1",
            "--output-dir", tempfile.gettempdir(),
            "--no-cast",
            "--answers=quit=N",
        ]

        if data:
            cmd += ["--data", data]
        if cookies:
            cmd += ["--cookie", cookies]
        if headers:
            for k, v in headers.items():
                cmd += ["-H", f"{k}: {v}"]
        if param:
            cmd += ["-p", param]

        # Depth controls how far sqlmap goes
        if depth == "probe":
            # Confirm injection exists only — no enumeration
            pass
        elif depth == "enumerate":
            # Get DB name, current user, list databases — proof without dumping
            cmd += ["--current-db", "--current-user", "--dbs"]
        elif depth == "dump":
            # Dump a specific table — only when explicitly requested
            if table:
                cmd += ["--dump", "-T", table]
                if database:
                    cmd += ["-D", database]
            else:
                return {"error": "depth='dump' requires a table name"}

        if flags:
            cmd += shlex.split(flags)

        try:
            proc = runner.run(
                cmd, capture_output=True, text=True, timeout=300
            )
        except subprocess.TimeoutExpired:
            return {"error": "sqlmap timed out", "url": url}

        output = proc.stdout + proc.stderr
        result = _parse_output(output, url, depth)
        result["_command"] = " ".join(cmd)
        return result

    finally:
        try:
            os.unlink(out_path)
        except Exception:
            pass


def _parse_output(output: str, url: str, depth: str) -> dict:
    result = {
        "url":        url,
        "depth":      depth,
        "injectable": False,
        "parameters": [],
        "dbms":       "",
        "current_db": "",
        "current_user": "",
        "databases":  [],
        "tables":     [],
        "data":       [],
        "raw":        output[-3000:],
    }

    if "is vulnerable" in output or "Parameter:" in output and "is vulnerable" in output:
        result["injectable"] = True
    if "[INFO] the back-end DBMS is" in output:
        m = re.search(r"the back-end DBMS is (.+)", output)
        if m:
            result["dbms"] = m.group(1).strip()
    if "current database:" in output.lower():
        m = re.search(r"current database:\s+'?([^'\n]+)'?", output, re.IGNORECASE)
        if m:
            result["current_db"] = m.group(1).strip()
    if "current user:" in output.lower():
        m = re.search(r"current user:\s+'?([^'\n]+)'?", output, re.IGNORECASE)
        if m:
            result["current_user"] = m.group(1).strip()

    # Extract database list
    db_section = re.search(r"available databases.*?:\n(.*?)(?:\n\n|\Z)", output, re.DOTALL)
    if db_section:
        result["databases"] = [
            line.strip().strip("*[]").strip()
            for line in db_section.group(1).splitlines()
            if line.strip() and not line.strip().startswith("[")
        ]

    # Vulnerable parameters
    for m in re.finditer(r"Parameter: (\S+) \((.+?)\)", output):
        result["parameters"].append({"name": m.group(1), "type": m.group(2)})

    return result


TOOL_DEFINITION = {
    "name": "sqlmap_scan",
    "description": (
        "SQL injection detection and exploitation via sqlmap. "
        "depth='probe': confirm injection exists. "
        "depth='enumerate' (default): get DBMS version, current DB, current user, list databases — sufficient proof for report. "
        "depth='dump': dump a specific table (requires table parameter). "
        "Supports GET/POST injection, cookie injection, and custom headers."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Target URL (e.g. http://target/page?id=1)",
            },
            "data": {
                "type": "string",
                "description": "POST body (e.g. 'username=admin&password=test')",
            },
            "cookies": {
                "type": "string",
                "description": "Cookie string (e.g. 'session=abc123')",
            },
            "headers": {
                "type": "object",
                "description": "Additional HTTP headers",
                "additionalProperties": {"type": "string"},
            },
            "param": {
                "type": "string",
                "description": "Specific parameter to test. Omit to test all.",
            },
            "depth": {
                "type": "string",
                "enum": ["probe", "enumerate", "dump"],
                "description": "probe=confirm only, enumerate=get DB/user/schema (default), dump=extract table data",
            },
            "table": {
                "type": "string",
                "description": "Table name to dump (required for depth='dump')",
            },
            "database": {
                "type": "string",
                "description": "Database name for dump (optional, narrows scope)",
            },
            "flags": {
                "type": "string",
                "description": "Additional sqlmap flags (e.g. '--technique=B --dbms=mysql')",
            },
            "background": {
                "type": "boolean",
                "description": "Run as a background job and keep working; results are delivered automatically when it finishes. Use for deep enumeration/dumps so it doesn't block.",
            },
        },
        "required": ["url"],
    },
}
