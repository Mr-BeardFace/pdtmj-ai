import json
import shlex
import shutil
import subprocess
from typing import Optional

from core import proc as runner

DEFAULT_TAGS = "cves,exposed-panels,misconfigs,default-logins,exposures"


def nuclei_scan(url: str, tags: Optional[str] = None, templates: Optional[str] = None,
                extra_args: Optional[str] = None) -> dict:
    if not shutil.which("nuclei"):
        return {"error": "nuclei not found in PATH"}

    cmd = ["nuclei", "-u", url, "-json", "-silent", "-no-color"]

    if templates:
        cmd += ["-t", templates]
    else:
        cmd += ["-tags", tags or DEFAULT_TAGS]

    # Free-form passthrough — severity filters, rate limits, headers, -itags, etc.
    if extra_args:
        cmd += shlex.split(extra_args)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return {"error": "nuclei timed out", "url": url}

    findings = []
    for line in proc.stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = obj.get("info", {})
        findings.append({
            "template_id":       obj.get("template-id", ""),
            "name":              info.get("name", ""),
            "severity":          info.get("severity", ""),
            "tags":              info.get("tags", []),
            "description":       info.get("description", ""),
            "matched_at":        obj.get("matched-at", ""),
            "extracted_results": obj.get("extracted-results", []),
            "curl_command":      obj.get("curl-command", ""),
        })

    return {
        "url":       url,
        "tags_used": tags or DEFAULT_TAGS,
        "findings":  findings,
        "count":     len(findings),
        "_command":  " ".join(cmd),
    }


TOOL_DEFINITION = {
    "name": "nuclei_scan",
    "description": (
        "Template-based vulnerability scanner. Runs curated checks from the nuclei-templates library "
        "against a target URL. Default tags: cves, exposed-panels, misconfigs, default-logins, exposures. "
        "Each finding includes a curl command for manual verification. "
        "Use `templates` to specify a path to a single template or directory for targeted testing."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Target URL to scan (e.g. https://example.com)",
            },
            "tags": {
                "type": "string",
                "description": f"Comma-separated template tags to run. Default: {DEFAULT_TAGS}",
            },
            "templates": {
                "type": "string",
                "description": "Path to a specific template file or directory (overrides tags)",
            },
            "extra_args": {
                "type": "string",
                "description": "Any additional raw nuclei flags as a single string, e.g. '-severity critical,high -rl 50 -H \"Authorization: Bearer x\" -itags rce'. Passed through verbatim.",
            },
            "background": {
                "type": "boolean",
                "description": "Run as a background job and keep working; results are delivered automatically when it finishes. Use for broad template runs so it doesn't block.",
            },
        },
        "required": ["url"],
    },
}
