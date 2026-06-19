"""Fetch a public web page and return it as readable text.

The companion to `web_search`: once the agent finds a promising result (a CVE
writeup, a PoC, a vendor doc), this pulls the page and strips it to plain text so
the agent can actually read the exploitation steps / payload / default creds.

GUARDRAIL (OPSEC): this is for PUBLIC documentation only. It refuses to fetch
private/internal hosts (RFC1918, localhost, link-local) and internal TLDs, and the
orchestrator additionally refuses any URL that names a target host — interacting
with the target is what http_request / web_exec are for, not this.
"""
from __future__ import annotations

import html
import ipaddress
import re
from urllib.parse import urlparse

import httpx

from core.utils import DEFAULT_UA

TEXT_CAP = 12000

_SCRIPT_STYLE = re.compile(r"<(script|style|noscript)\b.*?</\1>", re.S | re.I)
_TITLE        = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
_BLOCK_BREAK  = re.compile(r"</(p|div|li|h[1-6]|tr|br|section|article)>", re.I)
_TAG          = re.compile(r"<[^>]+>")
_MULTINL      = re.compile(r"\n{3,}")
_INLINE_WS    = re.compile(r"[ \t\r\f\v]+")
_INTERNAL_TLD = re.compile(r"\.(?:htb|local|internal|corp|lan|intra|home|test)$", re.I)


def _is_public_host(host: str) -> bool:
    host = (host or "").strip().strip("[]").lower()
    if not host or host in ("localhost",):
        return False
    if _INTERNAL_TLD.search(host):
        return False
    try:
        ip = ipaddress.ip_address(host)
        # Any literal IP that isn't globally routable is off-limits (and a public
        # IP literal is almost certainly the target — use http_request for that).
        return ip.is_global
    except ValueError:
        return True   # a hostname (resolved later); domain checks above handled internal


def _html_to_text(body: str) -> str:
    body = _SCRIPT_STYLE.sub(" ", body)
    body = _BLOCK_BREAK.sub("\n", body)
    body = _TAG.sub("", body)
    body = html.unescape(body)
    lines = [_INLINE_WS.sub(" ", ln).strip() for ln in body.splitlines()]
    return _MULTINL.sub("\n\n", "\n".join(ln for ln in lines if ln)).strip()


def fetch_url(url: str, max_chars: int = TEXT_CAP) -> dict:
    url = (url or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {"error": "url must be http(s)://"}
    if not _is_public_host(parsed.hostname or ""):
        return {"error": "Refusing to fetch a private/internal/target host. fetch_url is for "
                         "PUBLIC documentation only — use http_request/web_exec to interact "
                         "with the target."}
    try:
        resp = httpx.get(url, headers={"User-Agent": DEFAULT_UA}, timeout=20.0,
                        follow_redirects=True)
    except Exception as e:  # noqa: BLE001
        return {"error": f"fetch failed: {e}", "_command": f"GET {url}"}

    ctype = resp.headers.get("content-type", "")
    if "html" not in ctype and "text" not in ctype and "json" not in ctype:
        return {"url": str(resp.url), "status_code": resp.status_code,
                "note": f"non-text content ({ctype or 'unknown'}); not rendered", "text": ""}

    tm = _TITLE.search(resp.text)
    title = _INLINE_WS.sub(" ", html.unescape(_TAG.sub("", tm.group(1)))).strip() if tm else ""
    text = _html_to_text(resp.text)
    cap = max(500, int(max_chars or TEXT_CAP))
    return {
        "url": str(resp.url),
        "status_code": resp.status_code,
        "title": title,
        "text": text[:cap],
        "truncated": len(text) > cap,
        "_command": f"GET {url}",
    }


TOOL_DEFINITION = {
    "name": "fetch_url",
    "description": (
        "Fetch a PUBLIC web page (a CVE writeup, PoC, vendor doc you found via web_search) and "
        "return it as readable text, so you can read the actual exploitation steps / payload / "
        "default credentials. For public documentation ONLY — it refuses private, internal, and "
        "target hosts. To interact with the engagement target, use http_request / web_exec, not "
        "this."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Public http(s) URL to fetch and read."},
            "max_chars": {"type": "integer",
                          "description": f"Max characters of text to return (default {TEXT_CAP})."},
        },
        "required": ["url"],
    },
}
