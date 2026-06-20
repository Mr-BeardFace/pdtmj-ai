from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime
from core.timeutil import now_local
from urllib.parse import urlparse

from typing import ClassVar, Optional

from pydantic import BaseModel, Field, PrivateAttr

from core.models import Surface, TestPlan
from core.utils import mask_secret

# Tools whose results should not be cached (side effects or stateful)
_NO_CACHE = {
    "http_request", "oob_listener", "impacket_ntlmrelay", "petitpotam",
    "coercer", "ssh_exec", "queue_followup", "annotate_finding",
}

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Service-class weights for surface prioritization — higher is worked first.
# The lesson from real engagements: SSH/telnet are credential *destinations*,
# not discovery surfaces, so they sit at the bottom; rich, frequently
# misconfigured services (web apps, object storage, databases) sit at the top.
_SERVICE_WEIGHT = {
    # object storage / web — rich, often anonymous, the usual entry point
    "minio": 78, "s3": 78,
    "http": 70, "https": 70, "http-alt": 70, "https-alt": 70, "http-proxy": 70,
    "www": 70, "ssl/http": 70, "http-rpc-epmap": 60,
    # data stores — high value, frequently exposed/misconfigured
    "mysql": 66, "ms-sql-s": 66, "mssql": 66, "postgresql": 66, "postgres": 66,
    "mongodb": 66, "mongod": 66, "redis": 66, "oracle": 66, "elasticsearch": 66,
    "couchdb": 66, "memcached": 64,
    # a domain controller, recognised as one consolidated surface — on a DC, AD is
    # THE attack surface, above the web ports that would otherwise outrank it.
    "active-directory": 75,
    # windows / active directory
    "smb": 60, "microsoft-ds": 60, "netbios-ssn": 58, "netbios": 58,
    "ldap": 58, "ldaps": 58, "kerberos": 54, "kerberos-sec": 54,
    # other network services worth a look before resorting to creds
    "ftp": 50, "ftps": 50, "nfs": 50, "rsync": 50, "snmp": 48, "smtp": 44,
    "rpcbind": 40, "rpc": 40,
    # interactive services — usually need credentials first, so lower
    "rdp": 32, "ms-wbt-server": 32, "vnc": 30, "telnet": 24,
    # credential destinations — almost never the way *in*; work last
    "ssh": 15,
}
_DEFAULT_SERVICE_WEIGHT = 36   # unknown/unfingerprinted service — middle of the pack

# Active Directory identity services — the ones that fold into a single "Domain
# Controller" surface. SMB is deliberately NOT here: shares/RID-cycling are a
# distinct vector worth their own cycle.
_AD_IDENTITY_SERVICES = {
    "kerberos", "kerberos-sec", "kpasswd",
    "ldap", "ldaps", "ldapssl", "globalcatldap", "globalcatldapssl",
}
_SMB_SERVICES = {"smb", "microsoft-ds", "netbios-ssn", "netbios"}


def _is_dc(services: set) -> bool:
    """A host is treated as a domain controller when it exposes Kerberos (88 is
    essentially DC-only) or LDAP alongside SMB."""
    svcs = {(s or "").lower() for s in services}
    has_krb  = bool(svcs & {"kerberos", "kerberos-sec"})
    has_ldap = bool(svcs & {"ldap", "ldaps", "ldapssl", "globalcatldap"})
    has_smb  = bool(svcs & _SMB_SERVICES)
    return has_krb or (has_ldap and has_smb)

# Severity → bonus for an unexploited lead sitting on a surface. Unverified
# findings weigh slightly more than verified ones because they are open threads.
_SEV_LEAD_BONUS = {"critical": 40, "high": 30, "medium": 16, "low": 5, "info": 0}


def service_weight(service: str) -> int:
    return _SERVICE_WEIGHT.get((service or "").strip().lower(), _DEFAULT_SERVICE_WEIGHT)


def _finding_on_surface(finding, surface) -> bool:
    """Best-effort attribution of a finding to a surface. Conservative: requires
    a port or service-name match so a host-wide finding does not wrongly boost
    every port on a multi-service host (e.g. an SSH surface gaining a MinIO lead)."""
    tgt = (getattr(finding, "target", "") or "").lower()
    title = (getattr(finding, "title", "") or "").lower()
    blob = f"{tgt} {title} {json.dumps(getattr(finding, 'evidence', {}) or {})[:400].lower()}"
    if surface.port and str(surface.port) in blob:
        return True
    svc = (surface.service or "").strip().lower()
    if svc and svc not in ("http", "https", "tcp", "") and svc in blob:
        return True
    if surface.component and surface.component.lower() in blob:
        return True
    return False


def surface_priority(surface, findings: list | None = None) -> int:
    """Numeric work-priority for a surface. Higher is worked first.

    score = service-class weight
          + best unexploited-lead bonus from findings attributable to the surface
          - a revisit penalty so a heavily-cycled surface drifts down
    """
    score = service_weight(surface.service)
    if findings:
        best = 0
        for f in findings:
            if _finding_on_surface(f, surface):
                bonus = _SEV_LEAD_BONUS.get(getattr(f, "severity", "info"), 0)
                # an open (unverified) lead is worth slightly more attention
                if not getattr(f, "verified", False):
                    bonus = int(bonus * 1.15)
                best = max(best, bonus)
        score += best
    score -= surface.cycles * 12
    return score


def _extract_host(target: str) -> str:
    """Reduce a target string (URL, host:port, bare host/IP/CIDR) to its host part."""
    t = target.strip().lower()
    if "://" in t:
        t = urlparse(t).hostname or t
    # host:port (but not IPv6 or CIDR)
    if ":" in t and t.count(":") == 1:
        host, _, port = t.rpartition(":")
        if port.isdigit():
            t = host
    return t.strip("[]")


# Result fields that hold the human-meaningful output of a tool call, in priority
# order — used to keep a clean snippet (not the raw JSON envelope) so the next agent
# sees actual command output, not "exit 0  out: 1450b".
_TOOL_OUTPUT_KEYS = ("stdout", "output", "decoded", "exfil", "body", "response",
                     "result", "note", "summary", "stderr")


def _clean_output_snippet(result, cap: int = 1200) -> str:
    """A readable snippet of a tool result's actual output (preferred fields first;
    falls back to a compact JSON of non-internal keys), capped."""
    if not isinstance(result, dict):
        text = "" if result is None else str(result)
    else:
        chunks = [result[k].strip() for k in _TOOL_OUTPUT_KEYS
                  if isinstance(result.get(k), str) and result[k].strip()]
        if chunks:
            text = "\n".join(chunks)
        else:
            try:
                text = json.dumps({k: v for k, v in result.items()
                                   if not str(k).startswith("_")}, default=str)
            except Exception:
                text = str(result)
    text = text.strip()
    return (text[:cap] + "…") if len(text) > cap else text


class ToolLogEntry(BaseModel):
    agent: str
    tool_name: str
    command: Optional[str] = None
    summary: str = ""
    truncated_output: str = ""
    timestamp: datetime = Field(default_factory=lambda: now_local())


class Credential(BaseModel):
    cred_type: str = "password"     # password | hash | api_key | token | key
    username: Optional[str] = None
    secret: str                     # the value: password, hash, key, or token
    secret_masked: str = ""         # operator-facing display form
    secret_format: str = ""         # for hash/key/token: NTLM, NetNTLMv2, Kerberos-AS-REP, JWT, rsa, …
    location: str = ""              # where the credential was FOUND
    used_at: list[str] = []         # other locations where it was confirmed to WORK
    service: str = ""               # protocol (smb, ssh, http, …)
    port: Optional[int] = None
    source_agent: str = ""
    verified: bool = False
    timestamp: datetime = Field(default_factory=lambda: now_local())


class Flag(BaseModel):
    value: str                      # the captured flag string
    location: str = ""             # where it was found (challenge/host/path)
    source_agent: str = ""
    verified: bool = False
    timestamp: datetime = Field(default_factory=lambda: now_local())


class AuthAttempt(BaseModel):
    service: str                    # ssh, smb, ftp, winrm, mssql, …
    host: str
    port: Optional[int] = None
    username: Optional[str] = None
    secret_masked: str = ""
    result: str = "unknown"        # success | fail | error
    source_agent: str = ""
    timestamp: datetime = Field(default_factory=lambda: now_local())


class PersistenceItem(BaseModel):
    """A change the engagement made to a target — planted OR modified — tracked as
    an IOC so the report lists what changed, where, when, and the exact revert
    steps. Don't leave anything altered or undocumented."""
    kind: str                       # authorized_key | user | reverse_shell | cron | scheduled_task | rdp | service | webshell | password_change | permission_change | template_change | config_change | file_edit | other
    host: str
    detail: str = ""               # what was planted/changed (key fingerprint, username, object + new value…)
    before: str = ""               # original state before the change, for restoration
    cleanup: str = ""              # exact command/steps to revert/remove and restore the original
    os: str = ""                   # linux | windows
    source_agent: str = ""
    timestamp: datetime = Field(default_factory=lambda: now_local())


class ReconData(BaseModel):
    open_ports: list[dict] = []     # {host, port, protocol, service, version}
    os_info: dict[str, str] = {}    # ip → best OS guess
    host_names: dict[str, str] = {} # ip → resolved/PTR/vhost hostname
    users: list[str] = []
    groups: list[str] = []
    shares: list[dict] = []         # {name, comment, access}


class EngagementState(BaseModel):
    target: str
    tool_log: list[ToolLogEntry] = []
    scan_cache: dict[str, dict] = {}    # cache_key → {summary, result}
    credentials: list[Credential] = []
    flags: list[Flag] = []          # CTF flags captured during the engagement
    auth_attempts: list[AuthAttempt] = []   # who/what was tried against which service
    persistence: list[PersistenceItem] = [] # footholds planted (for cleanup/report)
    services: list[dict] = []        # agent-annotated service detail: {host,port,service,app,version,tech,os}
    scripts: list[dict] = []         # ad-hoc run_script library: {purpose,path,language,timestamp}
    handoffs: list[dict] = []        # per-agent close-out notes for the next agent: {agent,summary}
    recon: ReconData = Field(default_factory=ReconData)
    followup_queue: list[dict] = []     # {agent_name, target, context}
    # Operator-approved scope. Seeded with the engagement target; expanded
    # via /scope add. Followups to targets outside this list are rejected.
    scope_targets: list[str] = []
    # Explicit exclusions from the engagement brief — rejected even if they
    # would otherwise match an in-scope CIDR/domain.
    out_of_scope: list[str] = []

    # Operator brief — injected verbatim into every agent's context block.
    tech_context: str = ""
    focus_areas: list[str] = []

    # Set (to a reason) when an agent declares the objective achieved (root, RCE,
    # the root flag, …). The loop stops opening new work and proceeds to reporting.
    concluded: Optional[str] = None

    # Attack surfaces the Enum→Plan→Exploit→Validate loop cycles on.
    surfaces: list[Surface] = []
    # Planner output, keyed by surface id.
    plans: list[TestPlan] = []

    # O(1) duplicate check for surfaces — private, not serialised.
    _surface_keys: dict = PrivateAttr(default_factory=dict)  # key → Surface

    # O(1) duplicate check for open_ports — private, not serialised.
    _port_keys: set[str] = PrivateAttr(default_factory=set)
    # auth-attempt dedup: key → last result. Private (key embeds raw secret).
    _auth_keys: dict = PrivateAttr(default_factory=dict)
    # Per-finding normalized title cache for find_duplicate — private, not serialised.
    _norm_cache: dict = PrivateAttr(default_factory=dict)  # id → (norm_str, frozenset)

    # ── cross-agent progress tracking (pivot / reuse / grind nudges) ──────────
    # These persist across agent runs (private, not serialised) so thrash spread
    # over several runs — e.g. 100+ no-progress decrypt scripts over five rce runs —
    # is caught, where a per-run counter resets each agent and misses it.
    _scripts_since_progress: int = PrivateAttr(default=0)   # run_scripts since last banked result
    _grind_nudged_at: int = PrivateAttr(default=0)          # script count at last grind nudge
    _eng_script_calls: int = PrivateAttr(default=0)         # cumulative run_script calls
    _eng_listscripts_used: bool = PrivateAttr(default=False)
    _eng_reuse_nudged: bool = PrivateAttr(default=False)

    def note_script_call(self) -> None:
        """A run_script ran — counts toward reuse and no-progress (grind) tracking."""
        self._eng_script_calls += 1
        self._scripts_since_progress += 1

    def note_listscripts(self) -> None:
        self._eng_listscripts_used = True

    def note_progress(self) -> None:
        """A finding/credential/flag was banked — reset the no-progress streak."""
        self._scripts_since_progress = 0
        self._grind_nudged_at = 0

    def grind_nudge_due(self, threshold: int) -> int:
        """No-progress 'grind' check: many scripts run without banking any result.
        Returns the running no-progress count when a nudge is due (re-arming the
        next one), else 0."""
        if threshold and self._scripts_since_progress >= self._grind_nudged_at + threshold:
            self._grind_nudged_at = self._scripts_since_progress
            return self._scripts_since_progress
        return 0

    def reuse_nudge_due(self, threshold: int) -> int:
        """Heavy run_script use without ever consulting list_scripts. Fires once."""
        if (threshold and not self._eng_reuse_nudged
                and self._eng_script_calls >= threshold and not self._eng_listscripts_used):
            self._eng_reuse_nudged = True
            return self._eng_script_calls
        return 0

    # ── foothold-banking nudge ────────────────────────────────────────────────
    # Code execution proven but never recorded is the costliest miss: the foothold
    # is the headline finding and everything builds on it, yet a run can burn the
    # whole turn budget exploring without ever calling annotate_finding for it.
    _exec_confirmed: bool = PrivateAttr(default=False)   # exec observed this engagement
    _foothold_banked: bool = PrivateAttr(default=False)  # a verified finding banked since
    _turns_since_exec: int = PrivateAttr(default=0)
    _foothold_nudged: bool = PrivateAttr(default=False)

    def exec_confirmed(self) -> bool:
        return self._exec_confirmed

    def note_exec_confirmed(self) -> None:
        """Code execution on a target was observed (an `id`/`whoami` readback, a
        caught shell, a successful shell_exec). Idempotent — only the first matters;
        the foothold-banking nudge keys off it until a verified finding is banked."""
        if not self._exec_confirmed:
            self._exec_confirmed = True
            self._foothold_banked = False
            self._turns_since_exec = 0

    def note_foothold_banked(self) -> None:
        """A verified finding was annotated after exec was confirmed — the foothold
        is on the record. Clears the banking nudge."""
        if self._exec_confirmed:
            self._foothold_banked = True

    def foothold_bank_due(self, threshold: int) -> int:
        """Tick once per turn. Returns turns-since-exec when a nudge is due (exec
        confirmed, no verified finding banked since, threshold reached), else 0.
        Fires once — banking the foothold is a single specific action, not a streak."""
        if not (threshold and self._exec_confirmed and not self._foothold_banked):
            return 0
        self._turns_since_exec += 1
        if self._turns_since_exec >= threshold and not self._foothold_nudged:
            self._foothold_nudged = True
            return self._turns_since_exec
        return 0

    def model_post_init(self, __context) -> None:
        if not self.scope_targets:
            self.scope_targets = [self.target]
        # Rebuild the private surface index (e.g. after load from disk)
        for s in self.surfaces:
            self._surface_keys[s.key()] = s
        # Rebuild auth-attempt dedup keys (raw secret not stored, so keep masked key)
        for a in self.auth_attempts:
            self._auth_keys[self._auth_key(a.service, a.host, a.port, a.username,
                                           a.secret_masked)] = a.result

    # ── parallel fork / merge (snapshot + serial merge) ─────────────────────────

    @staticmethod
    def _port_key(p: dict) -> str:
        return f"{p.get('host', '')}:{p.get('port')}/{p.get('protocol', 'tcp')}"

    def fork(self) -> "EngagementState":
        """An isolated deep copy a parallel worker can mutate freely without locks.

        Each worker reads/writes its own fork; the driver folds the deltas back
        with merge_from() on a single thread after the workers join — the same
        snapshot-read / serial-merge discipline as the JobManager. model_copy does
        NOT run model_post_init, so the derived private indexes are rebuilt here,
        and the engagement-level nudge counters are carried across so progress
        tracking survives the fork.
        """
        clone = self.model_copy(deep=True)
        clone._surface_keys = {s.key(): s for s in clone.surfaces}
        clone._port_keys = {self._port_key(p) for p in clone.recon.open_ports}
        clone._auth_keys = {
            self._auth_key(a.service, a.host, a.port, a.username, a.secret_masked): a.result
            for a in clone.auth_attempts
        }
        clone._norm_cache = {}
        clone._scripts_since_progress = self._scripts_since_progress
        clone._grind_nudged_at = self._grind_nudged_at
        clone._eng_script_calls = self._eng_script_calls
        clone._eng_listscripts_used = self._eng_listscripts_used
        clone._eng_reuse_nudged = self._eng_reuse_nudged
        clone._exec_confirmed = self._exec_confirmed
        clone._foothold_banked = self._foothold_banked
        clone._turns_since_exec = self._turns_since_exec
        clone._foothold_nudged = self._foothold_nudged
        return clone

    def merge_marks(self) -> dict:
        """Lengths/counters captured at fork time so merge_from can tell a worker's
        additions to append-only collections apart from the snapshot it started with."""
        return {
            "tool_log": len(self.tool_log),
            "persistence": len(self.persistence),
            "handoffs": len(self.handoffs),
            "_eng_script_calls": self._eng_script_calls,
            "_scripts_since_progress": self._scripts_since_progress,
        }

    def merge_from(self, other: "EngagementState", marks: dict,
                   owned_surface_ids=None) -> None:
        """Fold a worker fork's additions back into this (canonical) state.

        Content-deduped collections are replayed through the existing add_*
        methods, so re-applying the snapshot portion is an idempotent no-op and
        only genuinely new items land. Append-only collections (tool_log,
        persistence, handoffs) are extended past their fork-time length. Surface
        *progress* (cycles/status) is synced only for the surfaces this worker
        OWNED — so a worker that forked the whole board can't roll back a sibling's
        progress on a surface it never touched. First worker to conclude wins.
        """
        owned = set(owned_surface_ids or [])

        # recon
        for p in other.recon.open_ports:
            k = self._port_key(p)
            if k not in self._port_keys:
                self._port_keys.add(k)
                self.recon.open_ports.append(dict(p))
        for u in other.recon.users:
            if u not in self.recon.users:
                self.recon.users.append(u)
        for g in other.recon.groups:
            if g not in self.recon.groups:
                self.recon.groups.append(g)
        for sh in other.recon.shares:
            if sh not in self.recon.shares:
                self.recon.shares.append(sh)
        for ip, v in other.recon.os_info.items():
            self.recon.os_info.setdefault(ip, v)
        for ip, v in other.recon.host_names.items():
            self.recon.host_names.setdefault(ip, v)

        # services (upsert by host/port)
        for svc in other.services:
            self.annotate_service(
                host=svc.get("host", ""), port=svc.get("port"),
                service=svc.get("service", ""), app=svc.get("app", ""),
                version=svc.get("version", ""), tech=svc.get("tech", ""),
                os=svc.get("os", ""), source_agent=svc.get("source_agent", ""))

        # credentials / flags (content-deduped)
        for c in other.credentials:
            merged = self.add_credential(
                cred_type=c.cred_type, secret=c.secret, username=c.username,
                service=c.service, port=c.port, secret_format=c.secret_format,
                location=c.location, source_agent=c.source_agent, verified=c.verified)
            if merged is not None:
                for loc in c.used_at:
                    if loc and loc not in merged.used_at:
                        merged.used_at.append(loc)
        for f in other.flags:
            self.add_flag(f.value, location=f.location,
                          source_agent=f.source_agent, verified=f.verified)

        # auth ledger (masked-key deduped — raw secret isn't carried on the model)
        for a in other.auth_attempts:
            k = self._auth_key(a.service, a.host, a.port, a.username, a.secret_masked)
            if k not in self._auth_keys:
                self.auth_attempts.append(a.model_copy(deep=True))
            self._auth_keys[k] = a.result

        # ad-hoc script library + scan cache
        for sc in other.scripts:
            self.add_script(sc.get("purpose", ""), sc.get("path", ""), sc.get("language", ""))
        for k, v in other.scan_cache.items():
            self.scan_cache.setdefault(k, v)

        # legacy followup queue (queue_followup) — dedup-carried for the driver to
        # absorb into surfaces after the batch
        for fu in other.followup_queue:
            self.request_followup(fu.get("agent_name", ""), fu.get("target", ""),
                                  fu.get("context", ""))

        # surfaces: always add newly-discovered ones; sync progress only for owned
        for s in other.surfaces:
            existing = self._surface_keys.get(s.key())
            if existing is None:
                self._surface_keys[s.key()] = s
                self.surfaces.append(s)
            elif s.id in owned:
                existing.status = s.status
                existing.cycles = s.cycles
                if s.fingerprint and not existing.fingerprint:
                    existing.fingerprint = s.fingerprint
                if s.notes:
                    existing.notes = s.notes

        # plans (replace per surface)
        for p in other.plans:
            self.plans = [pp for pp in self.plans if pp.surface_id != p.surface_id]
            self.plans.append(p)

        # append-only collections — extend past the fork-time length
        self.tool_log.extend(other.tool_log[marks.get("tool_log", 0):])
        self.persistence.extend(other.persistence[marks.get("persistence", 0):])
        self.handoffs.extend(other.handoffs[marks.get("handoffs", 0):])
        if len(self.handoffs) > self._HANDOFF_KEEP:
            self.handoffs = self.handoffs[-self._HANDOFF_KEEP:]

        # nudge counters — fold in this worker's deltas
        self._eng_script_calls += max(0, other._eng_script_calls - marks.get("_eng_script_calls", 0))
        delta_sp = other._scripts_since_progress - marks.get("_scripts_since_progress", 0)
        if delta_sp > 0:
            self._scripts_since_progress += delta_sp
        if other._eng_listscripts_used:
            self._eng_listscripts_used = True
        # exec confirmation is sticky across workers; banking clears the nudge
        if other._exec_confirmed:
            self.note_exec_confirmed()
        if other._foothold_banked:
            self._foothold_banked = True

        # objective — first worker to conclude wins
        if other.concluded and not self.concluded:
            self.concluded = other.concluded

    # ── scope ─────────────────────────────────────────────────────────────────

    def add_scope(self, target: str) -> None:
        t = target.strip()
        if t and t not in self.scope_targets:
            self.scope_targets.append(t)
        # If it was previously excluded, lifting it back in clears the exclusion.
        self.out_of_scope = [o for o in self.out_of_scope if o.strip() != t]

    def remove_scope(self, target: str) -> bool:
        """Take a host/IP/CIDR out of scope. Drops it from scope_targets AND adds
        it to out_of_scope — the latter is what actually excludes it, since the
        target might still match an in-scope CIDR or be a vhost tied to an
        in-scope IP. out_of_scope always wins in in_scope(). Returns True if the
        target was in scope before this call."""
        t = target.strip()
        if not t:
            return False
        was_in = self.in_scope(t)
        self.scope_targets = [s for s in self.scope_targets if s.strip() != t]
        # Drop any auto-tied vhost mapping so it can't re-enter scope via the IP.
        self.recon.host_names = {
            ip: name for ip, name in self.recon.host_names.items()
            if ip != t and name != t
        }
        if t not in self.out_of_scope:
            self.out_of_scope.append(t)
        return was_in

    def annotate_service(self, host: str, port=None, service: str = "", app: str = "",
                         version: str = "", tech: str = "", os: str = "",
                         hostname: str = "", source_agent: str = "") -> dict:
        """Record/refine the agent's structured understanding of a service. Upgrades
        the existing entry for the same (host, port) — only non-empty fields
        overwrite, so successive calls sharpen the picture without wiping it."""
        host = (host or "").strip()
        # OS is host-level — also feed os_info so it shows on every row for the host.
        if os and host and host not in self.recon.os_info:
            self.recon.os_info[host] = os
        # A vhost the agent identified for this IP — tie it on and auto-scope it
        # (the target's vhosts are in scope). This is the LLM's call, made from
        # the tool output, not a Python regex guessing at redirect text.
        if hostname and host:
            self._register_vhost(host, hostname)
        existing = next((s for s in self.services
                         if s.get("host") == host and s.get("port") == port), None)
        if existing is None:
            existing = {"host": host, "port": port, "service": "", "app": "",
                        "version": "", "tech": "", "os": "", "source_agent": source_agent}
            self.services.append(existing)
        for k, v in (("service", service), ("app", app), ("version", version),
                     ("tech", tech), ("os", os)):
            if v:
                existing[k] = v
        return existing

    def _register_vhost(self, ip: str, hostname: str) -> None:
        """Tie a discovered hostname to an IP (PTR, resolved name, or HTTP
        redirect target). If the IP is in scope, the hostname is the target's
        vhost and is auto-added to scope — a vhost of your target IS your target.
        Explicit out-of-scope entries still win (checked in in_scope)."""
        host = _extract_host(hostname or "")
        ip = (ip or "").strip()
        if not host or not ip or host == ip:
            return
        try:
            ipaddress.ip_address(host)
            return                       # a bare IP is not a vhost
        except ValueError:
            pass
        self.recon.host_names.setdefault(ip, host)
        if self.in_scope(ip) and not self._matches_any(host, None, self.out_of_scope):
            self.add_scope(host)

    def _matches_any(self, host: str, host_ip, entries: list[str]) -> bool:
        for entry in entries:
            scope_host = _extract_host(entry)
            if host == scope_host:
                return True
            if host_ip is not None and "/" in scope_host:
                try:
                    if host_ip in ipaddress.ip_network(scope_host, strict=False):
                        return True
                except ValueError:
                    pass
            if host_ip is None and "/" not in scope_host and host.endswith("." + scope_host):
                return True
        return False

    def in_scope(self, target: str) -> bool:
        """True if target is within approved scope and not explicitly excluded.

        A scope entry matches when the target host is identical, is a
        subdomain of a domain entry, or is an IP inside a CIDR entry.
        Comparison is on the host part only — URLs and host:port collapse
        to their hostname. Explicit out-of-scope entries always win.
        """
        host = _extract_host(target)
        if not host:
            return False

        try:
            host_ip = ipaddress.ip_address(host)
        except ValueError:
            host_ip = None

        if self.out_of_scope and self._matches_any(host, host_ip, self.out_of_scope):
            return False

        if self._matches_any(host, host_ip, self.scope_targets):
            return True

        # A hostname recon has tied to an in-scope IP (vhost / resolved name /
        # redirect target) is in scope — the target's vhosts are the target.
        if host_ip is None:
            for ip, name in self.recon.host_names.items():
                if (name or "").lower() == host:
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                    except ValueError:
                        ip_obj = None
                    if self._matches_any(ip.lower(), ip_obj, self.scope_targets):
                        return True
        return False

    # ── surfaces & exhaustion ──────────────────────────────────────────────────

    def add_surface(self, host: str, service: str = "", port=None,
                    component: str = "", origin: str = "initial",
                    notes: str = "", fingerprint: str = "") -> Surface | None:
        """Register an attack surface. Returns the Surface, or None if the host
        is out of scope. Idempotent on (host, port, service, component)."""
        if not self.in_scope(host):
            return None
        s = Surface(host=host, service=service, port=port, component=component,
                    origin=origin, notes=notes, fingerprint=fingerprint,
                    label=self._surface_label(host, service, port, component))
        existing = self._surface_keys.get(s.key())
        if existing:
            # Backfill a fingerprint discovered on a later (service-id) pass.
            if fingerprint and not existing.fingerprint:
                existing.fingerprint = fingerprint
            return existing
        self._surface_keys[s.key()] = s
        self.surfaces.append(s)
        return s

    @staticmethod
    def _surface_label(host: str, service: str, port, component: str) -> str:
        base = host
        if service in ("http", "https") and port:
            base = f"{service}://{host}:{port}"
        elif port:
            base = f"{host}:{port}"
        if service and service not in base:
            base += f" ({service})"
        if component:
            base += f" {component}"
        return base

    def derive_surfaces_from_recon(self, origin: str = "initial") -> list[Surface]:
        """Create one surface per discovered open port, then fold a domain
        controller's identity ports into a single consolidated AD surface.
        Returns newly added surfaces."""
        added: list[Surface] = []
        for p in self.recon.open_ports:
            host = p.get("host", "")
            if not host:
                continue
            before = len(self._surface_keys)
            s = self.add_surface(host, service=p.get("service", ""),
                                 port=p.get("port"), origin=origin,
                                 fingerprint=(p.get("version") or "").strip())
            if s is not None and len(self._surface_keys) > before:
                added.append(s)
        added += self._consolidate_dc_surfaces(origin)
        return added

    def is_domain_controller(self, host: str) -> bool:
        svcs = {(p.get("service") or "").lower()
                for p in self.recon.open_ports if p.get("host") == host}
        return _is_dc(svcs)

    def _consolidate_dc_surfaces(self, origin: str = "initial") -> list[Surface]:
        """On a DC, fold the AD identity-port surfaces (Kerberos/LDAP/GC) into one
        'Domain Controller' surface owned by the active-directory agent, so AD
        competes as a single high-value target instead of several buried ports.
        SMB keeps its own surface. Idempotent — safe to call on every re-derive."""
        added: list[Surface] = []
        host_svcs: dict[str, set] = {}
        for p in self.recon.open_ports:
            h = p.get("host", "")
            if h:
                host_svcs.setdefault(h, set()).add((p.get("service") or "").lower())
        for host, svcs in host_svcs.items():
            if not _is_dc(svcs):
                continue
            # Fold only un-worked identity surfaces, so a mid-engagement re-derive
            # never yanks a surface that is already being cycled.
            for s in self.surfaces:
                if (s.host == host and (s.service or "").lower() in _AD_IDENTITY_SERVICES
                        and s.status == "pending" and s.cycles == 0):
                    s.status = "folded"
            before = len(self._surface_keys)
            cs = self.add_surface(host, service="active-directory",
                                  component="Domain Controller", origin=origin)
            if cs is not None and len(self._surface_keys) > before:
                added.append(cs)
        return added

    def eligible_surfaces(self, max_cycles_per_surface: int | None = None) -> list[Surface]:
        """Surfaces still open for work — not exhausted and under the per-surface
        cycle cap (over-cap ones are marked exhausted here). The cap is a hard rail
        applied regardless of who picks among the survivors."""
        out: list[Surface] = []
        for s in self.surfaces:
            if s.status in ("exhausted", "folded"):   # folded = represented by the consolidated AD surface
                continue
            if max_cycles_per_surface and s.cycles >= max_cycles_per_surface:
                s.status = "exhausted"
                continue
            out.append(s)
        return out

    def next_surface(self, max_cycles_per_surface: int | None = None,
                     findings: list | None = None) -> Surface | None:
        """Heuristic pick (the fallback): highest `surface_priority` among the
        eligible surfaces, or None if all are exhausted. Value-ordered, not the
        port order surfaces were discovered in."""
        candidates = self.eligible_surfaces(max_cycles_per_surface)
        if not candidates:
            return None
        # Highest priority first; ties broken by original discovery order (stable).
        return max(candidates, key=lambda s: surface_priority(s, findings))

    def get_plan_for(self, surface_id: str) -> TestPlan | None:
        return next((p for p in self.plans if p.surface_id == surface_id), None)

    def record_plan(self, surface_id: str, items: list[dict],
                    created_by: str = "", notes: str = "") -> TestPlan:
        """Store (or replace) the test plan for a surface."""
        from core.models import TestPlan, TestPlanItem
        surface = next((s for s in self.surfaces if s.id == surface_id), None)
        plan = TestPlan(
            surface_id=surface_id,
            surface_label=surface.label if surface else "",
            created_by=created_by,
            notes=notes,
            items=[TestPlanItem(
                action=i.get("action", ""),
                rationale=i.get("rationale", ""),
                technique=i.get("technique", ""),
            ) for i in items if i.get("action")],
        )
        # Replace any existing plan for this surface
        self.plans = [p for p in self.plans if p.surface_id != surface_id]
        self.plans.append(plan)
        return plan

    def intel_signature(self, findings: list | None = None) -> tuple:
        """A coarse fingerprint of accumulated intel. If this is unchanged after a
        full cycle, the surface produced nothing new and is exhausted.

        Pass the running findings list so newly annotated or newly verified
        findings also count as progress.
        """
        f_total = len(findings) if findings else 0
        f_verified = sum(1 for f in findings if getattr(f, "verified", False)) if findings else 0
        return (
            len(self.recon.open_ports),
            len(self.recon.users),
            len(self.recon.groups),
            len(self.recon.shares),
            len(self.services),
            len(self.credentials),
            sum(1 for c in self.credentials if c.verified),
            len(self.surfaces),
            f_total,
            f_verified,
        )

    # ── cache ─────────────────────────────────────────────────────────────────

    def is_cacheable(self, tool_name: str) -> bool:
        return tool_name not in _NO_CACHE

    def cache_key(self, tool_name: str, inputs: dict) -> str:
        raw = f"{tool_name}:{json.dumps(inputs, sort_keys=True)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def check_cache(self, tool_name: str, inputs: dict) -> dict | None:
        if not self.is_cacheable(tool_name):
            return None
        return self.scan_cache.get(self.cache_key(tool_name, inputs))

    def store_cache(self, tool_name: str, inputs: dict, result: dict, summary: str):
        if not self.is_cacheable(tool_name):
            return
        key = self.cache_key(tool_name, inputs)
        # Store the full result — later agents hitting the cache get the same
        # detail the original caller received, not an 800-char stub.
        self.scan_cache[key] = {
            "summary": summary,
            "result": result,
        }

    # ── tool log ──────────────────────────────────────────────────────────────

    def log_tool(self, agent: str, tool_name: str, command: str | None,
                 summary: str, result: dict):
        self.tool_log.append(ToolLogEntry(
            agent=agent,
            tool_name=tool_name,
            command=command,
            summary=summary,
            truncated_output=_clean_output_snippet(result) if result else "",
        ))

    # ── credentials ───────────────────────────────────────────────────────────

    def add_credential(self, cred_type: str = "password", secret: str = "",
                       source_agent: str = "", username: str | None = None,
                       service: str = "", port: int | None = None,
                       secret_format: str = "", location: str = "",
                       verified: bool = False):
        if not secret:
            return None
        for existing in self.credentials:
            if (existing.secret == secret and existing.username == username
                    and existing.cred_type == cred_type):
                if verified:
                    existing.verified = True
                if location and not existing.location:
                    existing.location = location
                elif (verified and location and location != existing.location
                        and location not in existing.used_at):
                    # Same credential confirmed working at a new location → track
                    # where it is USED, distinct from where it was FOUND.
                    existing.used_at.append(location)
                if secret_format and not existing.secret_format:
                    existing.secret_format = secret_format
                return existing
        cred = Credential(
            cred_type=cred_type, username=username, secret=secret,
            secret_masked=mask_secret(secret), secret_format=secret_format,
            location=location or service, service=service, port=port,
            source_agent=source_agent, verified=verified,
        )
        self.credentials.append(cred)
        return cred

    def remove_credential(self, index: int) -> "Credential | None":
        """Remove the credential at a 0-based index — ANY credential, operator-loaded
        OR agent-discovered. Returns the removed credential, or None if out of range.
        The operator is the authority on the board: a wrong/expired cred the agent
        recorded can be pulled so it stops being reused in the context block."""
        if 0 <= index < len(self.credentials):
            return self.credentials.pop(index)
        return None

    # ── CTF flags ───────────────────────────────────────────────────────────────

    def add_flag(self, value: str, location: str = "", source_agent: str = "",
                 verified: bool = False) -> "Flag | None":
        value = (value or "").strip()
        if not value:
            return None
        for existing in self.flags:
            if existing.value == value:
                if verified:
                    existing.verified = True
                if location and not existing.location:
                    existing.location = location
                return existing
        flag = Flag(value=value, location=location,
                    source_agent=source_agent, verified=verified)
        self.flags.append(flag)
        return flag

    # ── auth attempts (avoid re-trying the same creds) ──────────────────────────

    @staticmethod
    def _auth_key(service: str, host: str, port, username, secret: str) -> str:
        return f"{(service or '').lower()}|{host}|{port or ''}|{username or ''}|{secret or ''}"

    def record_auth_attempt(self, service: str, host: str, username, secret: str,
                            result: str, port=None, source_agent: str = "") -> None:
        if not host:
            return
        key = self._auth_key(service, host, port, username, secret)
        if key in self._auth_keys:
            self._auth_keys[key] = result
            for a in self.auth_attempts:
                if self._auth_key(a.service, a.host, a.port, a.username, secret) == key:
                    a.result = result
                    return
        self._auth_keys[key] = result
        self.auth_attempts.append(AuthAttempt(
            service=service, host=host, port=port, username=username,
            secret_masked=mask_secret(secret) if secret else "",
            result=result, source_agent=source_agent,
        ))

    def auth_attempted(self, service: str, host: str, username, secret: str,
                       port=None) -> "str | None":
        """Return the prior result for an identical attempt, else None."""
        return self._auth_keys.get(self._auth_key(service, host, port, username, secret))

    # ── persistence (planted footholds → cleanup) ───────────────────────────────

    def add_persistence(self, kind: str, host: str, detail: str = "", cleanup: str = "",
                        os: str = "", source_agent: str = "", before: str = "") -> "PersistenceItem":
        item = PersistenceItem(kind=kind, host=host, detail=detail, before=before,
                               cleanup=cleanup, os=os, source_agent=source_agent)
        self.persistence.append(item)
        return item

    # ── ad-hoc script library (run_script reuse) ────────────────────────────────

    def add_script(self, purpose: str, path: str, language: str = "") -> None:
        """Record an ad-hoc script written via run_script so the agent can list and
        reuse it later instead of re-writing a near-duplicate. Idempotent on path."""
        path = (path or "").strip()
        if not path:
            return
        for s in self.scripts:
            if s.get("path") == path:
                if purpose:
                    s["purpose"] = purpose
                return
        self.scripts.append({
            "purpose": purpose or "", "path": path, "language": language or "",
            "timestamp": now_local().isoformat(),
        })

    # Cap a single handoff so one verbose agent cannot blow up the (uncached,
    # per-turn) context block for everyone after it. ClassVar so Pydantic treats
    # these as constants, not model fields/private attrs.
    _HANDOFF_CAP: ClassVar[int] = 2000
    _HANDOFF_KEEP: ClassVar[int] = 6

    def add_handoff(self, agent: str, summary: str) -> None:
        """Record an agent's close-out note — what it tested, what worked/didn't, and
        the most promising unexplored leads — so the next agent inherits a real picture
        instead of re-deriving it. Kept bounded (last few, each truncated) because this
        rides in the per-turn context block, which is not cache-friendly."""
        summary = (summary or "").strip()
        if not summary:
            return
        if len(summary) > self._HANDOFF_CAP:
            summary = summary[: self._HANDOFF_CAP].rstrip() + " …"
        self.handoffs.append({
            "agent": agent or "",
            "summary": summary,
            "timestamp": now_local().isoformat(),
        })
        # Keep only the most recent few — older context is already reflected in the
        # tool log, findings, and creds.
        if len(self.handoffs) > self._HANDOFF_KEEP:
            self.handoffs = self.handoffs[-self._HANDOFF_KEEP:]

    # ── UI snapshot (for saving/reloading an assessment in the TUI) ─────────────

    @classmethod
    def from_snapshot(cls, snap: dict) -> "EngagementState":
        """Rebuild a review-only state from a state_snapshot() dict — the inverse of
        state_snapshot(). Secrets are NOT recoverable (creds come back masked); this
        is for reporting/review, never re-authentication. Findings and the tool log
        are not in the snapshot and are supplied separately (e.g. from the runs)."""
        s = cls(target=snap.get("target", "") or "")
        s.scope_targets = list(snap.get("scope_targets") or ([s.target] if s.target else []))
        s.out_of_scope  = list(snap.get("out_of_scope") or [])
        for c in snap.get("credentials", []) or []:
            cred = s.add_credential(
                cred_type=c.get("cred_type", "password"), username=c.get("username"),
                secret=c.get("secret_masked") or "(masked)", service=c.get("service", ""),
                location=c.get("location", "") or c.get("service", ""),
                source_agent=c.get("source_agent", "loaded"), verified=bool(c.get("verified")))
            if cred is not None and c.get("secret_masked"):
                cred.secret_masked = c["secret_masked"]      # keep the original masked form
        recon = snap.get("recon", {}) or {}
        s.recon.host_names.update(recon.get("host_names", {}) or {})
        s.recon.os_info.update(recon.get("os_info", {}) or {})
        for svc in snap.get("services", []) or []:
            try:
                s.services.append(dict(svc))
            except Exception:
                pass
        return s

    def state_snapshot(self) -> dict:
        """A masked, panel-focused dump of the live state for persisting alongside
        an assessment so the TUI can reload its Hosts/Creds/Flags/change-ledger
        panels later. Secrets are NEVER written in cleartext — only the masked
        form is kept (a reloaded assessment is for review, not re-authentication)."""
        creds = []
        for c in self.credentials:
            d = c.model_dump(mode="json")
            d["secret"] = ""                                    # never persist cleartext
            d["secret_masked"] = c.secret_masked or mask_secret(c.secret)
            creds.append(d)
        return {
            "target":        self.target,
            "services":      [dict(s) for s in self.services],
            "credentials":   creds,
            "flags":         [f.model_dump(mode="json") for f in self.flags],
            "persistence":   [p.model_dump(mode="json") for p in self.persistence],
            "recon":         {"os_info":    dict(self.recon.os_info),
                              "host_names": dict(self.recon.host_names)},
            "scope_targets": list(self.scope_targets),
            "out_of_scope":  list(self.out_of_scope),
        }

    # ── finding deduplication ─────────────────────────────────────────────────

    def find_duplicate(self, title: str, target: str, existing_findings,
                       new_type: str | None = None) -> object | None:
        """Match a same-issue finding by target + fuzzy title. To avoid merging
        genuinely different findings that share words, a fuzzy (non-exact) match
        also requires the same finding type."""
        from core.utils import title_similarity
        norm = (title or "").strip().lower()
        for f in existing_findings:
            if f.target != target:
                continue
            if f.title.strip().lower() == norm:
                return f
            sim = title_similarity(title, f.title)
            if sim >= 0.6 and (new_type is None or f.type == new_type):
                return f
        return None

    # ── followup queue ────────────────────────────────────────────────────────

    def request_followup(self, agent_name: str, target: str, context: str = "") -> bool:
        for existing in self.followup_queue:
            if existing["agent_name"] == agent_name and existing["target"] == target:
                return False
        self.followup_queue.append({
            "agent_name": agent_name,
            "target": target,
            "context": context,
        })
        return True

    def drain_followup_queue(self) -> list[dict]:
        items = list(self.followup_queue)
        self.followup_queue.clear()
        return items

    # ── recon extraction ──────────────────────────────────────────────────────

    def ingest_tool_result(self, tool_name: str, result: dict, source_agent: str = ""):
        if not isinstance(result, dict) or "error" in result:
            return

        if tool_name == "nmap_scan":
            for host in result.get("hosts", []):
                ip = host.get("ip", "")
                for p in host.get("open_ports", []):
                    product = p.get("product", "")
                    version = p.get("version", "")
                    extra   = p.get("extra_info", "")
                    # Fingerprint banner: product + version + extra (e.g.
                    # "nginx 1.26.3 (Ubuntu)", "OpenSSH 9.9p1 Ubuntu", "MinIO").
                    banner = " ".join(x for x in (product, version) if x).strip()
                    if extra:
                        banner = f"{banner} ({extra})".strip() if banner else extra
                    port_key = f"{ip}:{p.get('port')}/{p.get('protocol', 'tcp')}"
                    if port_key not in self._port_keys:
                        self._port_keys.add(port_key)
                        self.recon.open_ports.append({
                            "host":     ip,
                            "port":     p.get("port"),
                            "protocol": p.get("protocol", "tcp"),
                            "service":  p.get("service", ""),
                            "version":  banner,
                        })
                os_matches = host.get("os_matches", [])
                if ip and os_matches and ip not in self.recon.os_info:
                    self.recon.os_info[ip] = os_matches[0].get("name", "")
                # nmap-resolved hostnames are structured tool output — keep them.
                # A vhost the agent reads out of a redirect/cert/page is its own
                # call: it records that via record_service(hostname=...).
                for hn in host.get("hostnames", []):
                    if hn:
                        self._register_vhost(ip, hn)

        elif tool_name == "masscan":
            host = result.get("target", "")
            for p in result.get("ports", []):
                port_key = f"{host}:{p.get('port')}/{p.get('proto', 'tcp')}"
                if port_key not in self._port_keys:
                    self._port_keys.add(port_key)
                    self.recon.open_ports.append({
                        "host":     host,
                        "port":     p.get("port"),
                        "protocol": p.get("proto", "tcp"),
                        "service":  "",
                        "version":  "",
                    })

        elif tool_name in ("enum4linux_ng", "rpcclient", "ldapsearch_query"):
            for u in result.get("users", []):
                name = u if isinstance(u, str) else u.get("username", "")
                if name and name not in self.recon.users:
                    self.recon.users.append(name)
            for g in result.get("groups", []):
                name = g if isinstance(g, str) else g.get("name", "")
                if name and name not in self.recon.groups:
                    self.recon.groups.append(name)
            for s in result.get("shares", []):
                if s not in self.recon.shares:
                    self.recon.shares.append(s)

        elif tool_name == "hydra":
            # hydra.py returns found_credentials with "login" key (hydra's native field name)
            svc  = result.get("service", "")
            host = result.get("host") or result.get("target") or ""
            for cred in result.get("found_credentials", []):
                self.add_credential(
                    cred_type="password",
                    username=cred.get("login") or cred.get("username"),
                    secret=cred.get("password", ""),
                    service=svc,
                    port=result.get("port"),
                    location=f"{svc} {host}".strip(),
                    source_agent=source_agent,
                    verified=True,
                )

        elif tool_name == "netexec":
            if result.get("authenticated") and result.get("password"):
                proto = result.get("protocol", "smb")
                host  = result.get("host") or result.get("target") or ""
                self.add_credential(
                    cred_type="password",
                    username=result.get("username"),
                    secret=result.get("password", ""),
                    service=proto,
                    location=f"{proto} {host}".strip(),
                    source_agent=source_agent,
                    verified=True,
                )
            for s in result.get("shares", []):
                if s not in self.recon.shares:
                    self.recon.shares.append(s)

        elif tool_name == "hashcat_crack":
            # A cracked hash becomes a verified plaintext credential.
            for c in result.get("cracked", []):
                if c.get("plaintext"):
                    self.add_credential(
                        cred_type="password",
                        secret=c["plaintext"],
                        username=c.get("username") or None,
                        location=c.get("location") or "cracked hash",
                        source_agent=source_agent,
                        verified=True,
                    )

    # ── context block ─────────────────────────────────────────────────────────

    def has_context(self) -> bool:
        """True when there is anything worth handing to an agent — accumulated
        work OR operator-seeded intel. Gates whether build_context_block is
        injected into the prompt. Must fire on a COLD start that carries seeded
        credentials or an operator brief, not just once tool_log is non-empty —
        otherwise pre-loaded /cred entries never reach the first agent."""
        return bool(
            self.tool_log or self.credentials or self.flags
            or self.handoffs or self.persistence
            or self.recon.open_ports or self.recon.host_names
            or self.tech_context or self.focus_areas or self.out_of_scope
        )

    def build_context_block(self, all_findings=None) -> str:
        lines = ["=== Engagement State ===", ""]

        # Operator brief — background the operator provided at intake
        if self.tech_context or self.focus_areas or self.out_of_scope:
            lines.append("**Operator brief:**")
            if self.tech_context:
                lines.append(f"  Background: {self.tech_context}")
            if self.focus_areas:
                lines.append(f"  Focus: {', '.join(self.focus_areas)}")
            if self.out_of_scope:
                lines.append(f"  OUT OF SCOPE (never touch): {', '.join(self.out_of_scope)}")
            lines.append("")

        # Handoff from prior agents — their own close-out: what they tested, what
        # worked/didn't, and the leads they judged most promising. This is the
        # narrative the tool log and findings can't carry on their own; read it
        # first so you build on prior work instead of re-deriving it.
        if self.handoffs:
            lines.append("**Handoff from prior agents** (build on this — do not start from scratch):")
            for h in self.handoffs:
                who = h.get("agent", "") or "agent"
                lines.append(f"  ── {who} ──")
                for para in (h.get("summary", "") or "").splitlines():
                    if para.strip():
                        lines.append(f"  {para.strip()}")
            lines.append("")

        # Tool log — last 30 entries. The most recent few also carry their actual
        # output snippet (not just the one-line summary) so the next agent inherits
        # the real command results, not "exit 0 out:1450b". Older entries stay terse;
        # full raw output for any of them is in the captured artifacts (below).
        if self.tool_log:
            lines.append("**Work already completed** (do not repeat these):")
            recent = self.tool_log[-30:]
            detail_from = len(recent) - 6        # show output for the last 6 only
            for i, entry in enumerate(recent):
                cmd = entry.command or entry.tool_name
                lines.append(f"  [{entry.agent}] {cmd}")
                if entry.summary:
                    lines.append(f"    → {entry.summary}")
                if i >= detail_from and entry.truncated_output:
                    out = entry.truncated_output.strip()
                    out = out if len(out) <= 600 else out[:600] + "…"
                    for ln in out.splitlines()[:12]:
                        lines.append(f"      {ln}")
            lines.append("")

        # Credentials
        if self.credentials:
            lines.append("**Credentials found** (use these verbatim against applicable services):")
            for c in self.credentials:
                # The agent needs the real secret to authenticate — passed in full.
                # The operator-facing UI masks it separately; this is the model's
                # working copy, not a display.
                bits = [f"type={c.cred_type}"]
                if c.username:
                    bits.append(f"user={c.username}")
                bits.append(f"secret={c.secret}")
                if c.secret_format:
                    bits.append(f"format={c.secret_format}")
                loc = c.location or c.service
                if loc:
                    bits.append(f"found@ {loc}")
                if c.used_at:
                    bits.append(f"works@ {', '.join(c.used_at)}")
                if c.verified:
                    bits.append("✓verified")
                lines.append("  " + "  ".join(bits))
            lines.append("")

        # Auth attempts already made — do not repeat these
        if self.auth_attempts:
            lines.append("**Auth already attempted** (do NOT re-try the same combination):")
            for a in self.auth_attempts[-20:]:
                u = f"{a.username}:" if a.username else ""
                lines.append(f"  [{a.result.upper()}] {u}{a.secret_masked} → "
                             f"{a.service}@{a.host}{(':' + str(a.port)) if a.port else ''}")
            lines.append("")

        # Recon summary
        if self.recon.open_ports:
            lines.append("**Open ports:**")
            for p in self.recon.open_ports[:25]:
                svc = f"{p.get('service', '')} {p.get('version', '')}".strip()
                lines.append(
                    f"  {p.get('host', '')}:{p.get('port', '')}/"
                    f"{p.get('protocol', 'tcp')}"
                    + (f"  — {svc}" if svc else "")
                )
            lines.append("")

        if self.recon.users:
            lines.append(f"**Users:** {', '.join(self.recon.users[:30])}")
        if self.recon.groups:
            lines.append(f"**Groups:** {', '.join(self.recon.groups[:15])}")
        if self.recon.shares:
            names = [s.get("name", str(s)) for s in self.recon.shares[:15]]
            lines.append(f"**Shares:** {', '.join(names)}")
        # Services the agent has identified (app/tech) — its own annotations.
        svc_bits = []
        for s in self.services[:15]:
            label = f"{s.get('host', '')}" + (f":{s['port']}" if s.get("port") else "")
            detail = " ".join(x for x in (s.get("app"), s.get("version"), s.get("tech")) if x)
            if detail:
                svc_bits.append(f"{label} {detail}".strip())
        if svc_bits:
            lines.append(f"**Identified services:** {'; '.join(svc_bits)}")

        # Findings summary
        if all_findings:
            sev_sort = sorted(
                all_findings,
                key=lambda f: SEV_ORDER.get(f.severity, 0),
                reverse=True,
            )
            lines.append(
                f"\n**Findings so far ({len(sev_sort)} total)** — [CONFIRMED] = reproduced/"
                "exploited with evidence; [UNCONFIRMED] = a LEAD still to be proven (e.g. a CVE "
                "inferred from a version/banner), NOT an established fact:")
            # The most significant handful carry a one-line description + a key
            # evidence snippet so the next agent inherits a real lead, not just a
            # title; the long tail stays title-only to keep the block bounded.
            DETAIL_N = 6
            for i, f in enumerate(sev_sort[:20]):
                status = "CONFIRMED" if f.verified else "UNCONFIRMED"
                lines.append(f"  [{f.severity.upper()}] [{status}] {f.title}  (id={f.id})")
                if i < DETAIL_N:
                    desc = " ".join((f.description or "").split())
                    if desc:
                        lines.append(f"      {desc[:240]}" + ("…" if len(desc) > 240 else ""))
                    bits = []
                    for k, v in list((f.evidence or {}).items())[:3]:
                        vs = " ".join(str(v).split())
                        bits.append(f"{k}={vs[:80] + ('…' if len(vs) > 80 else '')}")
                    if bits:
                        lines.append(f"      evidence: {'; '.join(bits)}")
            if len(sev_sort) > 20:
                lines.append(f"  ... and {len(sev_sort) - 20} more")
            lines.append("")

        lines += [
            "**Rules:**",
            "- Do NOT re-run tools already in the work log with the same target/parameters.",
            "- A finding marked [UNCONFIRMED] is a LEAD, not a fact — a CVE/vulnerability inferred "
            "from a version or banner is NOT confirmed exploitable until you actually reproduce it. "
            "Treat it as something to prove (and only then annotate it verified=true); do not report "
            "or build on it as if it were already exploited.",
            "- Use found credentials against all applicable services (SSH, SMB, WinRM, FTP, etc.).",
            "- If you discover a new host or network segment, call queue_followup to schedule enumeration.",
            "",
        ]

        return "\n".join(lines)
