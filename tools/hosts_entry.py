"""Manage `/etc/hosts` entries for discovered vhosts on the local attack host.

HTB-style and vhost-routed targets routinely require the hostname in the local
resolver before the web app will answer (name-based virtual hosting, redirects
to a `.htb` name, TLS SNI). This adds/removes those mappings idempotently so the
agent never has to hand-author a `sudo tee` incantation and accidentally clobber
the file.

Scope note: this edits the LOCAL Kali host's resolver only — it does NOT touch
the target and is not a target-side change. Managed lines are tagged with a
marker so they can be listed and cleanly removed at the end of the engagement.
"""
from __future__ import annotations

import re

from core import proc as runner

HOSTS_PATH = "/etc/hosts"
_MARKER = "# PDTMJ-AI"


def _read_hosts() -> str:
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return ""
    except PermissionError:
        p = runner.run(["sudo", "-n", "cat", HOSTS_PATH],
                       capture_output=True, text=True, timeout=15)
        return p.stdout or ""


def _existing_pairs(text: str) -> set[tuple[str, str]]:
    """(ip, hostname) mappings already present, so `add` stays idempotent."""
    pairs: set[tuple[str, str]] = set()
    for line in text.splitlines():
        body = line.split("#", 1)[0].strip()
        if not body:
            continue
        parts = body.split()
        ip = parts[0]
        for hn in parts[1:]:
            pairs.add((ip, hn.lower()))
    return pairs


def _split_hostnames(hostnames) -> list[str]:
    if isinstance(hostnames, str):
        hostnames = re.split(r"[\s,]+", hostnames)
    return [h.strip().lower() for h in (hostnames or []) if h and h.strip()]


def hosts_entry(action: str = "add", ip: str = "", hostnames=None) -> dict:
    action = (action or "add").strip().lower()
    names = _split_hostnames(hostnames)
    current = _read_hosts()

    if action == "list":
        ours = [ln for ln in current.splitlines() if _MARKER in ln]
        return {"action": "list", "entries": ours, "count": len(ours)}

    if action == "add":
        if not ip or not names:
            return {"error": "add requires 'ip' and at least one hostname"}
        have = _existing_pairs(current)
        new = [hn for hn in names if (ip, hn) not in have]
        if not new:
            return {"action": "add", "ip": ip, "added": [], "note": "already present"}
        line = f"{ip}\t{' '.join(new)}\t{_MARKER}\n"
        p = runner.run(["sudo", "-n", "tee", "-a", HOSTS_PATH],
                       capture_output=True, text=True, input=line, timeout=15)
        if p.returncode != 0:
            return {"error": f"failed to write {HOSTS_PATH}: {(p.stderr or '').strip()}",
                    "hint": "passwordless sudo may not be configured for tee"}
        return {"action": "add", "ip": ip, "added": new,
                "_command": f"echo '{line.strip()}' | sudo tee -a {HOSTS_PATH}"}

    if action in ("remove", "delete"):
        kept, removed = [], []
        for ln in current.splitlines():
            if _MARKER in ln and (not names or any(h in ln.lower() for h in names)):
                removed.append(ln)
            else:
                kept.append(ln)
        if not removed:
            return {"action": "remove", "removed": [], "note": "no managed entries matched"}
        body = ("\n".join(kept)).rstrip("\n") + "\n"
        p = runner.run(["sudo", "-n", "tee", HOSTS_PATH],
                       capture_output=True, text=True, input=body, timeout=15)
        if p.returncode != 0:
            return {"error": f"failed to rewrite {HOSTS_PATH}: {(p.stderr or '').strip()}"}
        return {"action": "remove", "removed": removed,
                "_command": f"# pruned {len(removed)} managed line(s) from {HOSTS_PATH}"}

    return {"error": f"unknown action {action!r} — use add | remove | list"}


TOOL_DEFINITION = {
    "name": "hosts_entry",
    "description": (
        "Add, remove, or list `/etc/hosts` entries on the LOCAL attack host so a discovered "
        "vhost/hostname resolves before you hit it (required for name-based virtual hosting, "
        "`.htb` redirects, and TLS SNI). Use action='add' with the target IP and one or more "
        "hostnames the moment enumeration reveals a hostname (redirect, cert CN/SAN, vhost fuzz "
        "hit). Idempotent — re-adding an existing mapping is a no-op. Managed entries are tagged "
        "and can be cleaned up with action='remove'. Edits the local resolver only; it does not "
        "modify the target."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["add", "remove", "list"],
                "description": "add a mapping (default), remove managed mapping(s), or list managed entries.",
            },
            "ip": {
                "type": "string",
                "description": "Target IP the hostname(s) should resolve to (required for add).",
            },
            "hostnames": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Hostname(s) to map, e.g. ['app.htb','www.app.htb']. May also be a "
                               "comma/space-separated string.",
            },
        },
        "required": ["action"],
    },
}
