"""
IIS Short Name (8.3) vulnerability scanner.
Exploits a feature of IIS that reveals 8.3 file/directory names via HTTP tilde (~) requests.
This allows enumeration of file and directory names that would otherwise be hidden.
"""
import re
import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def iis_shortname(target: str, path: str = "/", method: str = "GET",
                  threads: int = 20, flags: Optional[str] = None) -> dict:
    # Try dedicated tools first
    binary = (shutil.which("iis-shortname-scanner")
              or shutil.which("shortname_scanner")
              or shutil.which("iis_shortname_scanner.py"))

    if binary:
        return _run_tool(binary, target, path, flags)
    else:
        return _http_probe(target, path, method)


def _run_tool(binary: str, target: str, path: str, flags: Optional[str]) -> dict:
    cmd = [binary, target + path]
    if flags:
        cmd += shlex.split(flags)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": "IIS shortname scanner timed out"}

    output = proc.stdout + proc.stderr
    found = _parse_tool_output(output)
    return {
        "target":       target,
        "vulnerable":   bool(found),
        "found":        found,
        "count":        len(found),
        "raw":          output[:8000],
        "_command":     " ".join(cmd),
    }


def _http_probe(target: str, path: str, method: str) -> dict:
    """
    Manual HTTP-based detection via tilde (~) requests.
    A 404 vs 400 status difference indicates vulnerability.
    """
    # Ensure target has scheme
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    base_url = target.rstrip("/") + path.rstrip("/") + "/"

    # Canary check: valid tilde URL vs invalid
    test_exist   = base_url + "~1/*"
    test_noexist = base_url + "~zzzzzz/*"

    status_exist   = _get_status(test_exist, method)
    status_noexist = _get_status(test_noexist, method)

    vulnerable = (
        status_exist is not None
        and status_noexist is not None
        and status_exist != status_noexist
        and status_exist in (200, 301, 302, 403)
        and status_noexist == 404
    )

    # If vulnerable, brute-force first characters of 8.3 names
    found: list = []
    if vulnerable:
        found = _brute_shortnames(base_url, method)

    return {
        "target":       target,
        "vulnerable":   vulnerable,
        "probe_status": {"valid_tilde": status_exist, "invalid_tilde": status_noexist},
        "found":        found,
        "count":        len(found),
        "note":         (
            "Vulnerable! IIS 8.3 short name disclosure confirmed. "
            "Use full tool (iis-shortname-scanner) for complete enumeration."
            if vulnerable else
            "Not detected as vulnerable, or requires HTTPS/auth."
        ),
        "_command":     f"HTTP probe: {base_url}~1/*",
    }


def _get_status(url: str, method: str) -> Optional[int]:
    import urllib.error
    from core.utils import DEFAULT_UA
    try:
        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", DEFAULT_UA)
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def _brute_shortnames(base_url: str, method: str) -> list:
    """Brute-force single character to find valid short name prefixes."""
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    found_prefixes: list = []

    for c in chars:
        test_url = f"{base_url}{c}~1*"
        status = _get_status(test_url, method)
        if status and status in (200, 301, 302, 403):
            found_prefixes.append({
                "prefix": c.upper(),
                "url":    test_url,
                "status": status,
                "note":   f"File/dir starting with '{c.upper()}' exists",
            })

    return found_prefixes


def _parse_tool_output(output: str) -> list:
    found: list = []
    for line in output.splitlines():
        # Most scanners output discovered names like: [+] Found: SHORTNA~1.EXT
        m = re.search(r"\[(?:\+|FOUND|VULN)\].*?([A-Z0-9_-]{1,8}~\d+(?:\.[A-Z0-9]{0,3})?)", line, re.IGNORECASE)
        if m:
            found.append(m.group(1).upper())
        elif "VULNERABLE" in line.upper() or "FOUND" in line.upper():
            found.append(line.strip()[:100])
    return list(dict.fromkeys(found))  # deduplicate


TOOL_DEFINITION = {
    "name": "iis_shortname",
    "description": (
        "Detect and enumerate the IIS 8.3 short name (tilde) vulnerability on Microsoft IIS servers. "
        "When vulnerable, IIS leaks the first 6 characters of file and directory names via HTTP ~1 requests. "
        "This can reveal hidden backup files, config files, admin directories, and sensitive paths "
        "that are not in robots.txt or directory listings.\n"
        "Detection: sends HTTP requests with tilde notation and compares response codes.\n"
        "If a dedicated scanner tool is found (iis-shortname-scanner), uses it for full enumeration. "
        "Otherwise performs HTTP-based probe and single-character prefix brute-force.\n"
        "Affected: IIS 6, 7.0, 7.5, 8.0 (varies by config). Fixed in IIS 8.5+ by default."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Target URL or IP, e.g. 'http://example.com' or '10.10.10.5'"},
            "path":   {"type": "string", "description": "Base path to test. Default: /"},
            "method": {"type": "string", "description": "HTTP method: GET or OPTIONS. Default: GET"},
            "flags":  {"type": "string", "description": "Additional scanner flags (if dedicated tool present)"},
        },
        "required": ["target"],
    },
}
