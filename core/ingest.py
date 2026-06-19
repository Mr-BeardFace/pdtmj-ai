"""Ingest layer — turn engagement evidence into Leads.

The frontier controller works a `LeadStore`; this module is what fills it. It is
the structural fix for Silentium's "catalogued the path to root but never walked
it": a verified-but-unexecuted critical finding (e.g. "second Flowise running as
root on the host") becomes a high-`reach` escalation **lead** automatically, so it
rises to the top of the board and gets *worked* instead of filed.

Three deterministic, side-effect-free producers (recon → surfaces, findings →
vuln/escalation leads, credentials → access leads) plus two classification helpers
the live driver uses to turn an agent run into a `WorkResult` (`reach_from_evidence`,
`classify_outcome`). Everything here is pure over plain data / state reads — no LLM,
no agent calls — so it is cheap to run after every step and independently testable.

Relevance is left to the controller: every actionable finding becomes a lead, and
EV-against-the-frontier + dedup decide what actually gets picked. An already-walked
path scores low (no forward gain) and a fresh root path scores high — without this
module having to know which is which.
"""
from __future__ import annotations

from typing import Iterable

from core.leads import Lead, LeadStore, level_of

# Technique/title keywords → kill-chain reach. Checked most-advanced first, so a
# title that mentions both "RCE" and "root" lands on root. Mirrors the ladder in
# core.leads (recon<service<vuln<exploited<foothold<user<privesc<root).
_ROOT_HINTS = ("as root", "running as root", "root shell", "root access", "uid=0",
               "domain admin", "domain administrator", "nt authority\\system",
               "system shell", "root flag", "root.txt", "administrator access")
_PRIVESC_HINTS = ("privilege escalation", "privesc", "escalat", "sudo", "suid",
                  "setuid", "capabilities", "writable cron", "cron job", "writable path",
                  "ld_preload", "ld_library", "polkit", "pkexec", "dirty", "gtfobins",
                  "weak service permission", "unquoted service path", "dll hijack",
                  "token impersonation", "kernel exploit")
_USER_HINTS = ("user flag", "user.txt", "local user", "shell as", "logged in as",
               "authenticated shell", "interactive shell")
_EXEC_HINTS = ("remote code execution", "rce", "command injection", "command exec",
               "code execution", "code injection", "arbitrary code", "deserial",
               "ssti", "template injection", "file upload", "arbitrary file upload",
               "web shell", "webshell", "reverse shell", "sql injection to",
               "xxe to", "ssrf to rce", "exec primitive", "foothold")

# Cost inference (shared shape with parallel_driver's hints).
_EXPENSIVE_HINTS = ("brute", "bruteforce", "brute-force", "spray", "crack", "hashcat",
                    "john", "decrypt", "fuzz", "wordlist", "rockyou", "exhaustive",
                    "enumerate all", "every")
_CHEAP_HINTS = ("default", "anonymous", "unauth", "null session", "null-session",
                "idor", "misconfig", "exposed", "reuse", "cred-reuse", "sudo -l",
                "suid", "known cve", "public exploit", "guest", "directory listing",
                "as root", "running as root")

# Severity → prior nudge. A critical/high finding is a likelier real lead than an
# info one; this rides on top of the verified/unverified base prior.
_SEV_PRIOR = {"critical": 0.30, "high": 0.22, "medium": 0.12, "low": 0.05, "info": 0.0}


def _blob(*parts: str) -> str:
    return " ".join(p for p in parts if p).lower().replace("-", " ").replace("_", " ")


def infer_cost(*parts: str) -> str:
    b = _blob(*parts)
    if any(k in b for k in _EXPENSIVE_HINTS):
        return "expensive"
    if any(k in b for k in _CHEAP_HINTS):
        return "cheap"
    return "medium"


def reach_for_finding(finding) -> str:
    """The kill-chain rung a finding's lead would reach if walked to ground.

    A verified RCE is an exec primitive (`exploited`); a "running as root"
    misconfiguration is a path to `root`; a privesc note is `privesc`; a generic
    vuln is `vuln`. Pure recon/info entries have no rung and yield no lead.
    """
    title = getattr(finding, "title", "") or ""
    ftype = (getattr(finding, "type", "") or "").lower()
    b = _blob(title, ftype)
    if any(k in b for k in _ROOT_HINTS):
        return "root"
    if any(k in b for k in _PRIVESC_HINTS):
        return "privesc"
    if any(k in b for k in _USER_HINTS):
        return "user"
    if any(k in b for k in _EXEC_HINTS):
        return "exploited"
    if ftype == "recon":
        return ""                 # recon findings are surfaces, not action leads
    return "vuln"


def _kind_for_reach(reach: str) -> str:
    if reach in ("root", "privesc"):
        return "escalation"
    if reach in ("exploited", "foothold"):
        return "exploit"
    if reach == "user":
        return "cred"
    return "vuln"


# ── producers ────────────────────────────────────────────────────────────────

def leads_from_findings(findings: Iterable, *, created_by: str = "ingest") -> list[Lead]:
    """One actionable lead per finding worth chasing. The Silentium fix lives here:
    a verified finding describing an un-walked path to root becomes a root-reach
    escalation lead, not a filed artifact."""
    out: list[Lead] = []
    for f in findings or []:
        reach = reach_for_finding(f)
        if not reach:
            continue
        title = getattr(f, "title", "") or ""
        verified = bool(getattr(f, "verified", False))
        sev = (getattr(f, "severity", "info") or "info").lower()
        # A verified finding is a more reliable lead than a hunch; severity sharpens it.
        prior = min(0.95, (0.55 if verified else 0.4) + _SEV_PRIOR.get(sev, 0.0))
        verb = "Exploit" if reach in ("exploited", "vuln") else "Walk to ground"
        out.append(Lead(
            kind=_kind_for_reach(reach),
            description=f"{verb}: {title}",
            technique=getattr(f, "type", "") or "",
            target=getattr(f, "target", "") or "",
            reach_level=reach,
            prior=prior,
            cost=infer_cost(title, getattr(f, "type", "")),
            origin_id=getattr(f, "id", "") or "",
            created_by=created_by,
            notes=(getattr(f, "description", "") or "")[:200],
        ))
    return out


def leads_from_recon(state, *, created_by: str = "ingest") -> list[Lead]:
    """One enumeration lead per open port — the cheap breadth the controller falls
    back to when the frontier is cold. Reach is `service` (fingerprint it / find a
    vuln); a richer service (web/db/object store) gets a higher prior."""
    from core.engagement_state import service_weight
    out: list[Lead] = []
    for p in getattr(state, "recon", None).open_ports if getattr(state, "recon", None) else []:
        host = p.get("host", "")
        port = p.get("port")
        if not host:
            continue
        service = p.get("service", "") or ""
        # service weight (15..78) → prior 0.25..0.7, so a web/db surface outranks SSH.
        prior = max(0.2, min(0.7, service_weight(service) / 110.0))
        label = f"{service or 'service'} on {host}:{port}".strip()
        out.append(Lead(
            kind="surface",
            description=f"Enumerate {label}",
            technique="enumeration",
            target=host,
            reach_level="service",
            prior=prior,
            cost="cheap",
            created_by=created_by,
            notes=(p.get("version", "") or ""),
        ))
    return out


def leads_from_credentials(state, *, creds=None, created_by: str = "ingest") -> list[Lead]:
    """An access lead per credential not yet proven to grant a session — 'use this
    against applicable services'. Reach is `user` (a login is local access). A
    verified cred is a near-certain lead; an unverified one is worth a try.

    `creds` overrides the source list (used to build leads from only the NEW
    credentials a step produced); otherwise every credential in state is used."""
    out: list[Lead] = []
    for c in (creds if creds is not None else (getattr(state, "credentials", []) or [])):
        user = c.username or "(unknown user)"
        loc = c.location or c.service or ""
        verified = bool(c.verified)
        out.append(Lead(
            kind="cred",
            description=f"Authenticate as {user} against reachable services"
                        + (f" (from {loc})" if loc else ""),
            technique="credential-reuse",
            target=getattr(state, "target", "") or "",
            reach_level="user",
            prior=0.8 if verified else 0.55,
            cost="cheap",
            created_by=created_by,
            notes=f"used@ {', '.join(c.used_at)}" if c.used_at else "",
        ))
    return out


def ingest_all(store: LeadStore, state, findings: Iterable, *,
               include_recon: bool = True, created_by: str = "ingest") -> int:
    """Fold every deterministic lead source into the store (deduped). Returns the
    number of genuinely new leads added — the driver uses that as a cheap
    'material change' signal. Safe to call after every step."""
    before = len(store.leads)
    for lead in leads_from_findings(findings, created_by=created_by):
        store.add(lead)
    for lead in leads_from_credentials(state, created_by=created_by):
        store.add(lead)
    if include_recon:
        for lead in leads_from_recon(state, created_by=created_by):
            store.add(lead)
    return len(store.leads) - before


# ── classification (agent run → WorkResult facts) ────────────────────────────

def reach_from_evidence(flags: Iterable, creds_verified: bool,
                        findings: Iterable) -> int:
    """The highest kill-chain rung actually REACHED by evidence banked this step —
    conservative on purpose. A captured root flag / root shell is root; a user flag
    is user; a verified credential that authenticated is a foothold; a verified
    exec-class finding is `exploited`. A finding that merely *describes* a path to
    root (not yet walked) does NOT count as reaching root — it stays a high-EV lead
    until a flag/session proves it. This is what stops the engine declaring victory
    on a catalogued path."""
    best = 0
    for f in flags or []:
        loc = (f.get("location", "") if isinstance(f, dict)
               else getattr(f, "location", "")).lower()
        if "root.txt" in loc or "/root" in loc:
            best = max(best, level_of("root"))
        elif "user.txt" in loc or "/home/" in loc:
            best = max(best, level_of("user"))
        else:
            best = max(best, level_of("user"))      # an unplaced flag is still access
    if creds_verified:
        best = max(best, level_of("foothold"))
    for f in findings or []:
        if not (f.get("verified") if isinstance(f, dict) else getattr(f, "verified", False)):
            continue
        title = (f.get("title", "") if isinstance(f, dict) else getattr(f, "title", "")) or ""
        if any(k in title.lower() for k in _EXEC_HINTS):
            best = max(best, level_of("exploited"))
    return best


def classify_outcome(lead: Lead, achieved_level: int, frontier_before: int, *,
                     concluded: bool, made_progress: bool, spawned_leads: bool,
                     refuted: bool = False) -> tuple[str, str]:
    """Turn an agent run into a (status, reach_level) verdict for the controller.

      advanced     — reached the lead's rung, pushed the frontier forward, or the
                     engagement concluded. The frontier moves; lower work is preempted.
      refuted      — an explicit dead-end signal (e.g. an LLM judge), OR nothing at
                     all came back: no progress, no new leads. Release it.
      inconclusive — something happened (new leads / partial progress) but the lead
                     itself isn't proven. Re-queue until the attempt cap.

    The reach returned on 'advanced' is the rung actually reached, falling back to
    the lead's own reach when conclusion outran the evidence read.
    """
    target_level = level_of(lead.reach_level)
    if concluded:
        reached = max(achieved_level, target_level)
        return "advanced", _name_for_level(reached)
    if achieved_level >= target_level and achieved_level > 0:
        return "advanced", _name_for_level(achieved_level)
    if achieved_level > frontier_before:
        # partial: didn't hit the lead's goal but moved the frontier anyway
        return "advanced", _name_for_level(achieved_level)
    if refuted:
        return "refuted", lead.reach_level
    if made_progress or spawned_leads:
        return "inconclusive", lead.reach_level
    return "refuted", lead.reach_level


def _name_for_level(level: int) -> str:
    from core.leads import FRONTIER_LEVELS
    return next((n for n, v in FRONTIER_LEVELS.items() if v == level), "vuln")
