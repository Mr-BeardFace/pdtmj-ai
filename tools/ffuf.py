import json
import os
import shlex
import shutil
import subprocess
import tempfile
from typing import Optional, Dict

from core import proc as runner

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


def ffuf(
    url: str,
    wordlist: Optional[str] = None,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[str] = None,
    match_codes: Optional[str] = None,
    filter_size: Optional[str] = None,
    extra_args: Optional[str] = None,
) -> dict:
    if not shutil.which("ffuf"):
        return {"error": "ffuf not found in PATH"}

    # Inject FUZZ keyword if not present
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"

    wl = wordlist or DEFAULT_WORDLIST

    fd, out_path = tempfile.mkstemp(suffix=".json", prefix="pentest_ffuf_")
    os.close(fd)

    try:
        cmd = [
            "ffuf",
            "-u", url,
            "-w", wl,
            "-X", method.upper(),
            "-o", out_path,
            "-of", "json",
            "-s",           # silent — suppress progress bar
            "-k",           # skip TLS verification
        ]

        if headers:
            for k, v in headers.items():
                cmd += ["-H", f"{k}: {v}"]
        if data:
            cmd += ["-d", data]

        cmd += ["-mc", match_codes or "200,201,204,301,302,307,401,403,405"]

        if filter_size:
            cmd += ["-fs", filter_size]

        # Free-form passthrough — any additional ffuf flag (matchers, filters,
        # recursion, rate, threads, extensions, etc.).
        if extra_args:
            cmd += shlex.split(extra_args)

        try:
            runner.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            return {"error": "ffuf timed out", "url": url}

        try:
            with open(out_path, encoding="utf-8") as f:
                raw = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {"error": "ffuf produced no parseable output", "url": url}

        results = []
        for r in raw.get("results", []):
            results.append({
                "url":          r.get("url", ""),
                "input":        r.get("input", {}).get("FUZZ", ""),
                "status":       r.get("status", 0),
                "length":       r.get("length", 0),
                "words":        r.get("words", 0),
                "lines":        r.get("lines", 0),
                "content_type": r.get("content-type", ""),
                "redirect":     r.get("redirectlocation", ""),
            })

        return {"url": url, "wordlist": wl, "results": results, "count": len(results),
                "_command": " ".join(cmd)}

    finally:
        try:
            os.unlink(out_path)
        except Exception:
            pass


TOOL_DEFINITION = {
    "name": "ffuf",
    "description": (
        "Fast web fuzzer. Use for directory/file discovery, parameter fuzzing, vhost discovery, "
        "or any wordlist-based brute-force. Place FUZZ keyword in the URL (or it will be appended). "
        "Supports custom methods, headers, and POST body for parameter fuzzing."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Target URL. Include FUZZ where substitution should occur (e.g. https://example.com/FUZZ or https://example.com/?id=FUZZ)",
            },
            "wordlist": {
                "type": "string",
                "description": "Absolute path to wordlist. Defaults to dirb/common.txt.",
            },
            "method": {
                "type": "string",
                "description": "HTTP method (GET, POST, PUT, etc.). Default: GET",
            },
            "headers": {
                "type": "object",
                "description": "Request headers as key-value pairs",
                "additionalProperties": {"type": "string"},
            },
            "data": {
                "type": "string",
                "description": "Request body for POST/PUT. Use FUZZ keyword for parameter fuzzing.",
            },
            "match_codes": {
                "type": "string",
                "description": "Comma-separated HTTP status codes to include in results (default: 200,201,204,301,302,307,401,403,405)",
            },
            "filter_size": {
                "type": "string",
                "description": "Filter out responses of this size (bytes). Useful to remove false positives.",
            },
            "extra_args": {
                "type": "string",
                "description": "Any additional raw ffuf flags as a single string, e.g. '-recursion -recursion-depth 2 -e .php,.bak -t 100 -mr regex'. Passed through verbatim.",
            },
            "background": {
                "type": "boolean",
                "description": "Run as a background job and keep working; results are delivered automatically when it finishes. Use for large wordlists / long fuzzing so it doesn't block.",
            },
        },
        "required": ["url"],
    },
}
