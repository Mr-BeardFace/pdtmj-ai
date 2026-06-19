"""Web search (DuckDuckGo) for product / technology / CVE research.

Lets an agent look up the things its training may be stale on — a CVE's exact
exploitation steps, a product's default credentials, a known-misconfig writeup, a
public PoC, a protocol quirk. Pair it with `fetch_url` to read a promising result.

No API key and no extra dependency: it queries DuckDuckGo's HTML endpoint over
httpx (already a project dependency).

GUARDRAIL (OPSEC): this leaves the engagement environment, so it is for GENERAL
technology/application/service information ONLY — never target IPs, hostnames,
internal paths, usernames, passwords, or captured data. The orchestrator also
scrubs each query against the live engagement state (scope hosts + credentials)
and refuses anything that would leak target specifics to a third party.
"""
from __future__ import annotations

import html
import re
from urllib.parse import parse_qs, unquote, urlparse

import httpx

from core.utils import DEFAULT_UA

_ENDPOINT = "https://html.duckduckgo.com/html/"

_ANCHOR = re.compile(r"<a\b([^>]*)>(.*?)</a>", re.S | re.I)
_HREF   = re.compile(r'href="([^"]+)"', re.I)
_TAG    = re.compile(r"<[^>]+>")
_WS     = re.compile(r"[ \t\r\f\v]+")

# Defence-in-depth (the orchestrator does the context-aware scrub): refuse a query
# that obviously names a host rather than a technology.
_IPV4    = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_IPV6    = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f]{1,4}\b")
_INTERNAL_TLD = re.compile(r"\.(?:htb|local|internal|corp|lan|intra|home|test)\b", re.I)


def _strip(text: str) -> str:
    return _WS.sub(" ", html.unescape(_TAG.sub("", text or ""))).strip()


def _decode_href(href: str) -> str:
    """DuckDuckGo wraps result links as //duckduckgo.com/l/?uddg=<encoded>. Unwrap it."""
    if href.startswith("//"):
        href = "https:" + href
    parsed = urlparse(href)
    if "duckduckgo.com" in parsed.netloc and parsed.path.startswith("/l/"):
        uddg = parse_qs(parsed.query).get("uddg")
        if uddg:
            return unquote(uddg[0])
    return href


def web_search(query: str, max_results: int = 6) -> dict:
    query = (query or "").strip()
    if not query:
        return {"error": "query is required"}

    # In-tool OPSEC guard (the orchestrator's scrub is the context-aware one).
    if _IPV4.search(query) or _IPV6.search(query) or _INTERNAL_TLD.search(query):
        return {"error": "Refusing to web-search target-specific identifiers (an IP or "
                         "internal hostname). Search only general product/technology/CVE "
                         "terms — e.g. 'Wing FTP 7.4.3 CVE-2025-47812 exploit'."}

    try:
        resp = httpx.post(_ENDPOINT, data={"q": query, "kl": "us-en"},
                          headers={"User-Agent": DEFAULT_UA}, timeout=20.0,
                          follow_redirects=True)
    except Exception as e:  # noqa: BLE001
        return {"error": f"search request failed: {e}", "_command": f"ddg: {query}"}

    results: list[dict] = []
    snippets: list[str] = []
    for attrs, inner in _ANCHOR.findall(resp.text):
        cls = ("result__a" in attrs, "result__snippet" in attrs)
        if cls[0]:
            m = _HREF.search(attrs)
            if m:
                results.append({"title": _strip(inner), "url": _decode_href(m.group(1))})
        elif cls[1]:
            snippets.append(_strip(inner))

    for i, r in enumerate(results):
        r["snippet"] = snippets[i] if i < len(snippets) else ""
    results = results[: max(1, int(max_results or 6))]

    return {
        "query": query,
        "count": len(results),
        "results": results,
        "note": "Use fetch_url on a promising result to read the page (exploit steps, "
                "default creds, PoC). Keep follow-up queries to general tech terms.",
        "_command": f"ddg: {query}",
    }


TOOL_DEFINITION = {
    "name": "web_search",
    "description": (
        "Search the web (DuckDuckGo) for TECHNOLOGY / APPLICATION / SERVICE information the "
        "engagement needs — a CVE's exploitation details, a product's default credentials, a "
        "known-misconfiguration writeup, a public proof-of-concept, a protocol quirk, a tool's "
        "usage. Returns ranked title/url/snippet results; follow up with `fetch_url` to read the "
        "full page. "
        "STRICT OPSEC RULE: search for GENERAL product/version/CVE/technique terms ONLY (e.g. "
        "'Apache Tomcat 9 default manager credentials', 'CVE-2023-22515 Confluence exploit'). NEVER "
        "put a target's IP address, hostname, internal path, username, password, or any captured "
        "engagement data into a query — that would leak the engagement to a third party and is "
        "refused. Use the local `searchsploit` for the offline Exploit-DB; use this for current, "
        "detailed material that isn't in your training."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "General technology/product/CVE search terms. No target IPs, "
                               "hostnames, credentials, or captured data.",
            },
            "max_results": {
                "type": "integer",
                "description": "Number of results to return (default 6).",
            },
        },
        "required": ["query"],
    },
}
