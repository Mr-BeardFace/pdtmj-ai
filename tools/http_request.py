import os
import re
import shutil
import subprocess
from core import proc as runner
import tempfile
from typing import Dict, Optional

from core.utils import DEFAULT_UA

BODY_CAP = 51200  # 50 KB

# Persistent cookie jars for named sessions — let the agent keep a login across
# multiple http_request calls without manually re-passing cookies each time.
# Resolved lazily so it follows the per-assessment scratch dir (tempfile.tempdir),
# not the system /tmp it was bound to at import time.
_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]")


def _session_jar(name: str) -> str:
    session_dir = os.path.join(tempfile.gettempdir(), "pentest_sessions")
    os.makedirs(session_dir, exist_ok=True)
    return os.path.join(session_dir, _SAFE_NAME.sub("_", name) + ".jar")


def _jar_cookie_names(jar_path: str) -> list:
    """Cookie names currently stored in a Netscape-format jar (for visibility)."""
    names: list = []
    try:
        with open(jar_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line or (line.startswith("#") and not line.startswith("#HttpOnly_")):
                    continue
                fields = line.split("\t")
                if len(fields) >= 7 and fields[5]:
                    names.append(fields[5])
    except FileNotFoundError:
        pass
    return names


def http_request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    follow_redirects: bool = True,
    verify_ssl: bool = False,
    timeout: int = 30,
    cookies: Optional[str] = None,
    session: Optional[str] = None,
) -> dict:
    if not shutil.which("curl"):
        return {"error": "curl not found in PATH"}

    hdr_fd, hdr_path = tempfile.mkstemp(prefix="pentest_hdr_")
    bdy_fd, bdy_path = tempfile.mkstemp(prefix="pentest_bdy_")
    os.close(hdr_fd)
    os.close(bdy_fd)

    # Cookie jar. A named session uses a persistent jar so login state carries
    # across calls; otherwise a throwaway jar still turns curl's cookie engine ON
    # so cookies set mid-redirect are sent to the later hops of THIS request.
    if session:
        jar_path = _session_jar(session)
        ephemeral_jar = False
    else:
        jfd, jar_path = tempfile.mkstemp(prefix="pentest_jar_")
        os.close(jfd)
        ephemeral_jar = True

    try:
        # Use a legitimate browser UA unless the caller already specified one
        caller_ua = next(
            (v for k, v in (headers or {}).items() if k.lower() == "user-agent"), None
        )
        effective_ua = caller_ua or DEFAULT_UA

        cmd = [
            "curl", "-s",
            "-X", method.upper(),
            "-A", effective_ua,
            "-D", hdr_path,         # dump response headers to file
            "-o", bdy_path,         # dump body to file
            "-c", jar_path,         # write/update the jar → enables the cookie engine
            "--max-time", str(timeout),
            "--connect-timeout", "10",
            # write-out metrics to stdout (not mixed with body)
            "-w", "%{http_code}|%{url_effective}|%{time_total}|%{size_download}",
        ]

        # Send cookies stored from earlier calls in this session.
        if os.path.exists(jar_path) and os.path.getsize(jar_path) > 0:
            cmd += ["-b", jar_path]

        if not verify_ssl:
            cmd.append("-k")
        if follow_redirects:
            cmd += ["-L", "--max-redirs", "10"]

        if headers:
            for k, v in headers.items():
                if k.lower() == "user-agent":
                    continue  # already set via -A above
                cmd += ["-H", f"{k}: {v}"]
        # Explicit cookie string (merged with any session jar cookies by curl).
        if cookies:
            cmd += ["-b", cookies]
        if body:
            cmd += ["--data-raw", body]

        cmd.append(url)

        try:
            proc = runner.run(cmd, capture_output=True, text=True, timeout=timeout + 15)
        except subprocess.TimeoutExpired:
            return {"error": "curl timed out", "url": url, "method": method.upper()}

        # Parse -w output (stdout when body goes to file)
        parts = proc.stdout.strip().split("|")
        status_code   = int(parts[0])  if len(parts) > 0 and parts[0].isdigit() else 0
        final_url     = parts[1]       if len(parts) > 1 else url
        time_total    = float(parts[2]) if len(parts) > 2 else 0.0
        size_download = int(parts[3])  if len(parts) > 3 and parts[3].isdigit() else 0

        # Parse headers — curl writes one block per hop when following redirects.
        # Parse every block so Set-Cookie from intermediate 302s is never lost.
        with open(hdr_path, encoding="utf-8", errors="replace") as f:
            raw_headers = f.read()

        blocks = [b.strip() for b in re.split(r"(?=HTTP/)", raw_headers.strip()) if b.strip()]

        def _parse_block(block: str) -> tuple[dict, list]:
            """Return (headers_dict, set_cookie_list) for one response block.
            Tolerant of both CRLF and LF line endings."""
            hdrs: Dict[str, str] = {}
            set_cookies: list = []
            for line in block.replace("\r\n", "\n").split("\n")[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    if k.strip().lower() == "set-cookie":
                        set_cookies.append(v.strip())
                    else:
                        hdrs[k.strip().lower()] = v.strip()
            return hdrs, set_cookies

        # Collect redirect chain summary + all Set-Cookie values across every hop
        redirect_chain = []
        all_set_cookies: list = []
        for block in blocks[:-1]:
            hdrs, set_cookies = _parse_block(block)
            all_set_cookies.extend(set_cookies)
            status_line = block.replace("\r\n", "\n").split("\n")[0]
            redirect_chain.append({
                "status":   status_line.split()[1] if len(status_line.split()) > 1 else "",
                "location": hdrs.get("location", ""),
            })

        # Final response headers — Set-Cookie is always a list, never collapsed
        response_headers, final_cookies = _parse_block(blocks[-1] if blocks else "")
        all_set_cookies.extend(final_cookies)
        if all_set_cookies:
            response_headers["set-cookie"] = all_set_cookies

        with open(bdy_path, encoding="utf-8", errors="replace") as f:
            body_content = f.read(BODY_CAP)

        # Build a clean display command (omit temp file paths)
        display_cmd = f'curl -s -X {method.upper()} -A "{effective_ua}"'
        if not verify_ssl:
            display_cmd += " -k"
        if session:
            display_cmd += f" [session: {session}]"
        if headers:
            for k, v in headers.items():
                if k.lower() != "user-agent":
                    display_cmd += f' -H "{k}: {v}"'
        if cookies:
            display_cmd += f' -b "{cookies}"'
        if body:
            snippet = body[:60] + "..." if len(body) > 60 else body
            display_cmd += f" --data-raw '{snippet}'"
        display_cmd += f" {url}"

        result = {
            "status_code":    status_code,
            "method":         method.upper(),
            "url":            url,
            "final_url":      final_url,
            "headers":        response_headers,
            "body":           body_content,
            "body_truncated": size_download > BODY_CAP,
            "size_bytes":     size_download,
            "time_seconds":   round(time_total, 3),
            "_command":       display_cmd,
        }
        if redirect_chain:
            result["redirect_chain"] = redirect_chain
        # Surface the live session cookie jar so the agent can see it's authenticated.
        if session:
            result["session"] = session
            result["session_cookies"] = _jar_cookie_names(jar_path)
        elif all_set_cookies:
            # This response set cookies but no named session was used — the state is
            # lost on the next call. Nudge, in-band, to carry it. Re-deriving a login
            # every request (the observed grind) is what this prevents.
            result["_session_hint"] = (
                "This response set cookies (likely a login/session). Pass "
                "session='<name>' on this and subsequent http_request calls to carry "
                "the login automatically instead of re-authenticating each time."
            )
        return result

    finally:
        cleanup = [hdr_path, bdy_path]
        if ephemeral_jar:
            cleanup.append(jar_path)        # keep named-session jars between calls
        for p in cleanup:
            try:
                os.unlink(p)
            except Exception:
                pass


TOOL_DEFINITION = {
    "name": "http_request",
    "description": (
        "Send an arbitrary HTTP request (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD) "
        "and return the full response: status code, all response headers, and body. "
        "response['headers']['set-cookie'] is always a list — never collapsed — and "
        "includes Set-Cookie values from every redirect hop, so session cookies are never lost. "
        "response['redirect_chain'] gives the status and Location of each intermediate hop. "
        "\n\n"
        "COOKIES & SESSIONS: cookies set during a redirect chain are carried to the later hops "
        "automatically. For a STATEFUL session across multiple calls (log in once, then act as the "
        "logged-in user), pass the same `session` name on every request — cookies are stored in a "
        "jar and re-sent automatically, so you do NOT have to copy Set-Cookie forward by hand. The "
        "response then includes `session_cookies` (the cookie names currently held). Use `cookies` "
        "for a one-off explicit cookie string (it merges with the session jar). "
        "\n\n"
        "Use for enumeration (redirect chains, probing endpoints, checking auth), exploitation "
        "(injecting payloads, testing SSRF/IDOR/SQLi, interacting with APIs), and verification. "
        "SSL verification is off by default. Body is capped at 50KB; headers are always complete."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "method": {
                "type": "string",
                "description": "HTTP method: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD",
            },
            "url": {
                "type": "string",
                "description": "Full URL to request",
            },
            "headers": {
                "type": "object",
                "description": "Request headers as key-value pairs (e.g. Authorization, Content-Type)",
                "additionalProperties": {"type": "string"},
            },
            "body": {
                "type": "string",
                "description": "Request body for POST/PUT/PATCH. Can be JSON, form data, or raw payload.",
            },
            "follow_redirects": {
                "type": "boolean",
                "description": "Follow HTTP redirects (default: true)",
            },
            "verify_ssl": {
                "type": "boolean",
                "description": "Verify SSL certificate (default: false)",
            },
            "timeout": {
                "type": "integer",
                "description": "Request timeout in seconds (default: 30)",
            },
            "cookies": {
                "type": "string",
                "description": "One-off explicit cookie string (e.g. 'session=abc123; token=xyz'). Merges with the session jar if a session is also set.",
            },
            "session": {
                "type": "string",
                "description": "Name a persistent session (any label, e.g. 'admin-login'). Cookies received are stored under it and re-sent on every later request with the same name — keep an authenticated session across calls without re-pasting cookies. Returns `session_cookies` (names currently held).",
            },
        },
        "required": ["method", "url"],
    },
}
