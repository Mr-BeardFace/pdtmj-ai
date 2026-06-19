import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def strings_extract(path: str, min_length: int = 8, encoding: str = "both",
                    flags: Optional[str] = None) -> dict:
    if not shutil.which("strings"):
        return {"error": "strings not found in PATH"}

    cmd = ["strings", f"-n{min_length}"]

    if encoding in ("little-endian", "unicode", "wide", "16"):
        cmd += ["-el"]
    elif encoding in ("big-endian", "16be"):
        cmd += ["-eb"]
    elif encoding == "both":
        # Run twice: ASCII and little-endian Unicode
        pass

    if flags:
        cmd += shlex.split(flags)

    cmd.append(path)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return {"error": "strings timed out"}

    all_strings = proc.stdout.splitlines()

    # If both encodings requested, also run unicode
    if encoding == "both":
        cmd_u = ["strings", f"-n{min_length}", "-el"]
        if flags:
            cmd_u += shlex.split(flags)
        cmd_u.append(path)
        try:
            proc_u = runner.run(cmd_u, capture_output=True, text=True, timeout=60)
            all_strings += proc_u.stdout.splitlines()
        except subprocess.TimeoutExpired:
            pass

    result = _categorize(all_strings, path)
    result["_command"] = " ".join(cmd)
    return result


def _categorize(strings_list: list, path: str) -> dict:
    import re

    urls      = [s for s in strings_list if re.search(r'https?://', s, re.IGNORECASE)]
    ips       = [s for s in strings_list if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', s)]
    emails    = [s for s in strings_list if re.search(r'[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}', s)]
    paths     = [s for s in strings_list if re.search(r'^[/\\][\w/\\.-]{4,}$', s)]
    # Strings that look like credentials or secrets
    secrets   = [s for s in strings_list if re.search(
        r'(password|passwd|secret|token|api[_-]?key|access[_-]?key|auth[_-]?key|private[_-]?key)',
        s, re.IGNORECASE
    )]

    return {
        "path":         path,
        "total_strings": len(strings_list),
        "urls":         urls[:50],
        "ip_addresses": list(set(ips))[:30],
        "emails":       list(set(emails))[:30],
        "file_paths":   paths[:50],
        "potential_secrets": secrets[:30],
        "all_strings":  strings_list[:2000],
    }


TOOL_DEFINITION = {
    "name": "strings_extract",
    "description": (
        "Extract printable strings from a binary file. "
        "Identifies embedded URLs, IP addresses, file paths, credentials, keys, and other indicators. "
        "min_length: minimum string length to include (default 8, lower = more noise). "
        "encoding: 'ascii' (default), 'unicode' (UTF-16 LE), or 'both' (runs both and deduplicates). "
        "Use as first step in binary/malware RE — quickly maps embedded indicators and code paths."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "path":       {"type": "string", "description": "Path to binary file"},
            "min_length": {"type": "integer", "description": "Minimum string length. Default: 8"},
            "encoding":   {"type": "string", "description": "'ascii', 'unicode', or 'both'. Default: both"},
            "flags":      {"type": "string", "description": "Additional strings flags"},
        },
        "required": ["path"],
    },
}
