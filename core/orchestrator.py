import json
import queue
import re
from core.timeutil import now_local
from pathlib import Path
from typing import Callable, Optional

from rich.console import Console
from rich.panel import Panel

from core.models import EngagementRun, Finding, ToolCall, CvssScores
from core.agent_loader import AgentDefinition
from core.tool_registry import ToolRegistry
from core.llm_client import LLMClient, APIAuthError, APIAccountLimitError
from core.pricing import estimate_cost
from core.engagement_state import EngagementState
from core.artifacts import ArtifactStore
from core.jobs import JobManager, Job
from core.proc import ProcessRegistry, bind as proc_bind
from core.paths import ARTIFACTS_DIR
from core.utils import mask_secret
from tools.annotate_finding import TOOL_DEFINITION as ANNOTATE_DEF
from tools.queue_followup import TOOL_DEFINITION as FOLLOWUP_DEF
from tools.record_plan import TOOL_DEFINITION as RECORD_PLAN_DEF
from tools.register_surface import TOOL_DEFINITION as REGISTER_SURFACE_DEF
from tools.record_credential import TOOL_DEFINITION as RECORD_CRED_DEF
from tools.record_service import TOOL_DEFINITION as RECORD_SERVICE_DEF
from tools.grep_artifact import TOOL_DEFINITION as GREP_ARTIFACT_DEF
from tools.read_artifact import TOOL_DEFINITION as READ_ARTIFACT_DEF
from tools.check_jobs import TOOL_DEFINITION as CHECK_JOBS_DEF
from tools.wait import TOOL_DEFINITION as WAIT_DEF, wait as _wait_fn
from tools.record_flag import TOOL_DEFINITION as RECORD_FLAG_DEF
from tools.conclude_engagement import TOOL_DEFINITION as CONCLUDE_DEF
from tools.start_listener import TOOL_DEFINITION as START_LISTENER_DEF
from tools.shell_exec import TOOL_DEFINITION as SHELL_EXEC_DEF
from tools.list_shells import TOOL_DEFINITION as LIST_SHELLS_DEF
from tools.list_scripts import TOOL_DEFINITION as LIST_SCRIPTS_DEF
from tools.record_persistence import TOOL_DEFINITION as RECORD_PERSIST_DEF
from tools.load_playbook import TOOL_DEFINITION as LOAD_PLAYBOOK_DEF, load_playbook as _load_playbook_fn
from core.shells import ShellManager

console = Console()

SEV_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "blue",
    "info":     "dim",
}

# These tools are intercepted before reaching the registry
_INTERCEPTED = {"annotate_finding", "queue_followup", "record_plan", "register_surface",
                "record_credential", "record_service", "record_flag", "conclude_engagement",
                "grep_artifact", "read_artifact", "check_jobs", "list_scripts",
                "start_listener", "shell_exec", "list_shells", "record_persistence", "wait",
                "load_playbook"}

# Tools whose call represents a credential auth attempt (for the auth ledger).
_AUTH_TOOLS = {"ssh_exec", "netexec", "ftp", "smbclient"}

# Tools that reach a third-party service (web search / page fetch) and therefore must
# never carry engagement specifics off the box. Scrubbed against live state below.
_WEB_TOOLS = {"web_search", "fetch_url"}

# Active scanning / enumeration / exploitation tools that take an explicit target
# host and therefore must respect the authorized scope — they are HARD-BLOCKED
# against any target not in scope (a DC's DNS often points at extra IPs/interfaces;
# that does not authorize them). Deliberately excludes web-research tools (external
# targets), and channel/foothold tools (oob_listener, nc, ssh_exec, web_exec,
# port_forward, http_request) which legitimately reference the attacker host.
_SCOPE_GATED_TOOLS = {
    "nmap_scan", "masscan", "netexec", "smbclient", "rpcclient",
    "ldapsearch_query", "snmp_enum", "enum4linux_ng", "kerbrute",
    "nuclei_scan", "gobuster_dir", "ffuf", "dalfox", "sqlmap_scan",
    "iis_shortname", "tls_inspect", "redis_query", "mongosh_query",
    "bloodhound_python", "certipy_ad", "impacket_kerberos",
    "impacket_mssql", "hydra", "ftp", "telnet",
}
# Input keys a gated tool's target may arrive under (first match wins).
_TARGET_KEYS = ("target", "host", "rhost", "ip", "url")

# Usernames generic enough to be normal search terms ("tomcat default creds admin")
# — not treated as a leak. A discovered, non-generic account name still is.
_GENERIC_USERS = {"admin", "administrator", "root", "user", "guest", "test", "sa",
                  "postgres", "mysql", "oracle", "tomcat", "manager", "service",
                  "operator", "anonymous", "ftp", "www-data", "nobody", "system"}

_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f]{1,4}\b")
_INTERNAL_TLD_RE = re.compile(r"\b[\w.-]+\.(?:htb|local|internal|corp|lan|intra|home|test)\b", re.I)

# Signature of confirmed code execution in a tool RESULT — the readback from a
# blind-RCE channel where there is no live shell object to key off. This is only ever
# scanned for output of the command-execution channels below (`_EXEC_CHANNEL_TOOLS`),
# NOT enum tools — so a `host\user` line here is genuinely whoami output, not an
# LDAP/SMB service-account string. A miss only costs a nudge; a false positive would
# nag wrongly, so each alternative is anchored to be near-unmistakable:
#   • Linux `id`:            uid=998(nifi) gid=998(nifi)
#   • Windows whoami /priv:  SeImpersonatePrivilege, SeChangeNotifyPrivilege, …
#   • Windows plain whoami:  a standalone `host\user` line (no drive letter / UNC / spaces)
_EXEC_SIG_RE = re.compile(
    r"uid=\d+\([^)]*\)\s+gid=\d+\(|"               # Linux id(1)
    r"\bSe[A-Z][A-Za-z]+Privilege\b|"             # whoami /priv token
    r"(?im:^[a-z0-9][\w.-]*\\[a-z0-9][\w.$ -]*?[ \t]*$)")  # whoami: host\user line
# Tools that run a command ON the target — the only results worth sniffing for an
# exec signature. Enum/auth tools are excluded so their output can't false-trip it.
_EXEC_CHANNEL_TOOLS = {"web_exec", "oob_listener", "http_request", "ssh_exec",
                       "nc", "telnet", "run_script"}


def _collect_strings(obj, out: list, budget: list) -> None:
    """Gather raw string values from a tool result (recursively) into `out` until the
    char budget runs out. Used for exec-signature matching — scanning RAW values, not
    a JSON dump, so real backslashes/newlines survive (whoami `host\\user`, line anchors)."""
    if budget[0] <= 0:
        return
    if isinstance(obj, str):
        out.append(obj[:budget[0]])
        budget[0] -= len(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_strings(v, out, budget)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _collect_strings(v, out, budget)


def _result_shows_exec(result: dict) -> bool:
    """True if a command-channel result contains an unmistakable exec readback."""
    parts: list = []
    _collect_strings(result, parts, [20000])
    return bool(_EXEC_SIG_RE.search("\n".join(parts)))

# Tools that always run as a background job (too long to block a turn, and the
# agent otherwise tends to narrate them as "done" the moment the subprocess is
# launched). Their results are delivered automatically when the job finishes.
_ALWAYS_BACKGROUND = {
    "hashcat_crack",
    "gobuster_dir",
    "ffuf",
    "nuclei_scan",
    "sqlmap_scan",
    "masscan",
}

# Tool output handling. A single string field longer than this is offloaded to a
# text artifact (newlines preserved, so grep_artifact works well). If the whole
# serialized result still exceeds the result threshold, the result itself is
# offloaded. Full output is always kept in the session log, cache, and state —
# only what is handed back to the LLM is trimmed.
_FIELD_OFFLOAD_CHARS  = 3000
_RESULT_OFFLOAD_CHARS = 6000
# read_artifact/grep_artifact slices are returned directly (already line-bounded) and
# only TRUNCATED if pathologically large — never re-offloaded to a new artifact, which
# would loop (the agent asked to read this very slice).
_ARTIFACT_VIEW_CAP    = 16000

FINDINGS_SCHEMA_INSTRUCTIONS = """

## Annotation

Call `annotate_finding` immediately when you observe something worth tracking — do not wait until the end.

**`verified` means PROVEN, not plausible.** Set `verified=false` for anything you have only *inferred* — most importantly a CVE or vulnerability identified from a **version or banner** (e.g. "Next.js 14.1 → CVE-2025-XXXXX"). A version match is a LEAD, not a confirmed exploitable issue: it says the target *might* be vulnerable, not that it *is*. Keep it `verified=false`, and make the description say so explicitly ("identified by version banner; not yet reproduced"). Only call again with `verified=true` once you have actually reproduced/exploited it with concrete evidence in this engagement. Never mark a version-based or theoretical finding verified — the next agent reads `verified=true` as "confirmed exploitable" and will build on it as fact.
The agent instructions above define what to annotate and when.

**Title rules — keep titles generalized:**
- Name the vulnerability *class*, spelled out — "Insecure Direct Object Reference", not "IDOR"; "Cross-Site Scripting", not "XSS". Expand every acronym.
- Do NOT put specific paths, parameter names, IDs, ports, or file names in the title. "Insecure Direct Object Reference" — not "IDOR on /data/{id} — Unauthenticated PCAP Access". Put those specifics in `description`/`evidence`.
- NEVER put a credential, password, hash, token, or other secret in the title or anywhere in the finding. Record secrets with `record_credential`. In the finding, describe only *what was exposed* ("cleartext FTP credentials recovered from a captured PCAP"), never the value or `user:pass` pair.
- A good title reads as a finding-class heading: "Cleartext Credentials Exposed in Network Capture", "Anonymous FTP Access", "Unauthenticated Database Access".

## Final response

End your final response with this JSON block. Its purpose is to:
1. Write the `technical_overview` attacker narrative for this run
2. Enrich already-annotated findings with CVSS scores, impact, and remediation
3. Add any findings not yet annotated mid-run

**Voice:** Never first person. Passive voice throughout.
**`description`:** Paragraph form — overview first, then root cause, exploitability, technical detail.
**`impact`:** Paragraph form — what breaks, what an attacker achieves, likelihood.
**`remediation`:** Bullet list, max 5 items.
**`technical_overview`:** Attacker narrative, flowing paragraphs, no bullets. Mark each evidence point with `[IMAGE: <the specific command run and a distinctive line of its output>]` — the engine fills these in with the ACTUAL tool command and captured output (its own "screenshot"), so name the concrete result (e.g. `[IMAGE: dir.html RCE output showing uid=1000(wingftp)]`, not `[IMAGE: proof of access]`). Put one wherever a command's output proves a step.

**CVSS 3.1:** Score every finding except pure `type: recon` entries. Use X for undefined environmental metrics.
Temporal defaults: E:P, RL:O, RC:C — adjust based on evidence in this run.

```json
{
  "technical_overview": "Attacker narrative. Flowing paragraphs. [IMAGE: command + distinctive output line] markers at each evidence point — the engine fills them with the real captured command/output.",
  "findings": [
    {
      "title": "Exactly match an annotated finding title to enrich it, or a new title to add a new finding",
      "type": "recon|vuln|config|exposure",
      "severity": "info|low|medium|high|critical",
      "description": "Paragraph 1 — overview. Paragraph 2+ — root cause, exploitability.",
      "impact": "What breaks and how likely is exploitation.",
      "cvss": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
        "base_score": 9.8,
        "temporal_score": 8.6,
        "environmental_score": 9.8
      },
      "evidence": {},
      "remediation": ["Bullet 1", "Bullet 2"]
    }
  ]
}
```
"""

_BASE_INSTRUCTIONS_PATH = Path(__file__).parent.parent / "agents" / "base-instructions.md"


# Credential-bearing flags in reconstructed CLI strings must be redacted before
# being stored in tool logs, emitted as events, or written to disk.
# Covers both "--flag value" and "--flag=value" forms.
_REDACT_CRED_RE = re.compile(
    r'(?<=\s)(-p|-H|--password|--hash|--pass|--auth-cred|--secret|--token)(\s+|=)(\S+)'
)
# key=value secret patterns — e.g. nmap --script-args 'ssh-run.password=…',
# 'ftp.password=…', connection strings. The key may be dotted (ssh-run.password).
_REDACT_KV_RE = re.compile(
    r'\b(password|passwd|pwd|pass|secret|token)=([^\s,;]+)', re.IGNORECASE
)
_PORTSPEC_RE = re.compile(r'^[\d,\-:]+$')


def _redact_command(cmd_str: str) -> str:
    def _flag_sub(m: re.Match) -> str:
        flag, sep, val = m.group(1), m.group(2), m.group(3)
        # nmap's -p is a port spec, not a password — don't redact a port range.
        if flag == "-p" and _PORTSPEC_RE.match(val):
            return m.group(0)
        return f"{flag}{sep}***"
    cmd_str = _REDACT_CRED_RE.sub(_flag_sub, cmd_str)
    cmd_str = _REDACT_KV_RE.sub(r"\1=***", cmd_str)
    return cmd_str


def _auth_fields(tool_name: str, inputs: dict):
    """(service, host, port, username, secret) for an auth-bearing tool call, or None."""
    if tool_name == "ssh_exec":
        return ("ssh", inputs.get("host", ""), inputs.get("port", 22),
                inputs.get("username"), inputs.get("password") or inputs.get("key_file") or "")
    if tool_name == "netexec":
        return (inputs.get("protocol", "smb"), inputs.get("target", ""), inputs.get("port"),
                inputs.get("username"), inputs.get("password") or inputs.get("hash") or "")
    if tool_name == "ftp":
        return ("ftp", inputs.get("host", ""), inputs.get("port", 21),
                inputs.get("username"), inputs.get("password") or "")
    if tool_name == "smbclient":
        return ("smb", inputs.get("target", ""), inputs.get("port"),
                inputs.get("username"), inputs.get("password") or "")
    return None


def _auth_result(tool_name: str, result: dict) -> str | None:
    """Classify a tool result as success | fail | error for the auth ledger."""
    if not isinstance(result, dict):
        return None
    err = (result.get("error") or "")
    if tool_name == "ssh_exec":
        if "authentication failed" in err.lower():
            return "fail"
        if "exit_code" in result:
            return "success"
        return None                     # connection error etc. — not an auth verdict
    if tool_name == "netexec":
        if result.get("authenticated") is True:
            return "success"
        if result.get("authenticated") is False:
            return "fail"
        return None
    if tool_name in ("ftp", "smbclient"):
        if result.get("connected") is True:
            return "success"
        if "login" in err.lower() or "auth" in err.lower():
            return "fail"
        return None
    return None


def _call_sig(tool_name: str, inputs: dict) -> str:
    """Stable signature for a tool call (name + args) used to detect an agent
    repeating the identical call. The orchestrator-only `background` control flag
    is ignored so a backgrounded repeat still counts as the same call."""
    try:
        scrub = {k: v for k, v in (inputs or {}).items() if k != "background"}
        return f"{tool_name}:{json.dumps(scrub, sort_keys=True, default=str)}"
    except Exception:
        return f"{tool_name}:{inputs!r}"


_PERSIST_STR_CAP = 4000   # max chars per string field kept in the saved run record


def _cap_for_persist(obj, _depth: int = 0):
    """Trim oversized string values before a tool result is stored on the run
    record. Huge tool outputs (e.g. base64 OOB exfil dumps) otherwise bloat the
    assessment JSON many-fold without adding audit value — the report draws on
    findings/evidence, not raw tool output. Truncation is marked so it's visible."""
    if isinstance(obj, str):
        if len(obj) > _PERSIST_STR_CAP:
            return obj[:_PERSIST_STR_CAP] + f"…[+{len(obj) - _PERSIST_STR_CAP} chars truncated]"
        return obj
    if _depth > 6:
        return obj
    if isinstance(obj, dict):
        return {k: _cap_for_persist(v, _depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        capped = [_cap_for_persist(v, _depth + 1) for v in obj[:500]]
        if len(obj) > 500:
            capped.append(f"…[+{len(obj) - 500} more items truncated]")
        return capped
    return obj


def _is_unproductive(name: str, result, error: Optional[str]) -> bool:
    """Did this tool call fail to make progress? Used for the pivot nudge — a run
    of these in a row is the signal an agent is stuck retrying a dead end (the
    near-identical retries the exact-match loop nudge cannot see)."""
    if error:
        return True
    if not isinstance(result, dict):
        return False
    if result.get("error"):
        return True
    ec = result.get("exit_code")
    if ec is not None and ec != 0:
        return True
    return False


_SAFE_FILENAME_RE = re.compile(r'[^A-Za-z0-9_-]')

def _safe_filename_part(s: str) -> str:
    """Sanitise a target/agent string for use in a filename (Windows-safe)."""
    return _SAFE_FILENAME_RE.sub("_", s)


# Per-tool result summary formatters — module-level so lambdas are not
# reinstantiated on every call.
_RESULT_SUMMARY_FNS: dict = {
        "nmap_scan":    lambda r: f"{r.get('host_count', 0)} host(s), "
                                  f"{sum(len(h.get('open_ports', [])) for h in r.get('hosts', []))} open port(s)",
        "masscan":      lambda r: f"{r.get('count', 0)} open port(s) found",
        "gobuster_dir": lambda r: f"{r.get('count', 0)} path(s) found",
        "ffuf":         lambda r: f"{r.get('count', 0)} result(s)",
        "nuclei_scan":  lambda r: f"{r.get('count', 0)} finding(s)",
        "http_request": lambda r: f"HTTP {r.get('status_code', '?')} — {r.get('size_bytes', 0):,} bytes",
        "sqlmap_scan":  lambda r: f"injectable: {'YES' if r.get('injectable') else 'no'}"
                                  + (f"  dbms: {r['dbms']}" if r.get("dbms") else ""),
        "dalfox":       lambda r: f"xss: {'FOUND' if r.get('vulnerable') else 'clean'} ({r.get('count', 0)} poc)",
        "tls_inspect":  lambda r: f"TLS {r.get('protocol_version', '?')} — {len(r.get('issues', []))} issue(s)",
        "oob_listener": lambda r: (f"callback RECEIVED ({r.get('count', 0)})"
                                   if r.get("callback_fired") else r.get("status", "")),
        "ssh_exec":     lambda r: (f"✓ {r.get('output', '')[:80]}"
                                   if r.get("success") else f"✗ auth failed / {r.get('error', '')[:60]}"),
        "netexec":         lambda r: f"authed: {'YES' if r.get('authenticated') else 'no'}"
                                     + (" PWNED" if r.get('pwned') else "")
                                     + f"  shares: {len(r.get('shares', []))}",
        "hydra":           lambda r: f"creds found: {r.get('count', 0)}",
        "enum4linux_ng":   lambda r: f"users: {len(r.get('users', []))}  shares: {len(r.get('shares', []))}  null: {r.get('null_session', False)}",
        "searchsploit":    lambda r: f"{r.get('count', 0)} exploit(s) found",
        "ldapsearch_query":   lambda r: f"{r.get('total', 0)} entries  users: {len(r.get('users', []))}",
        "kerbrute":           lambda r: f"valid: {r.get('count', 0)}",
        "impacket_kerberos":  lambda r: f"{r.get('attack', '?')}: {r.get('count', 0)} hash(es)",
        "bloodhound_python":  lambda r: f"collected: {'yes' if r.get('success') else 'failed'}",
        "certipy_ad":         lambda r: f"{r.get('action', '?')}: {r.get('count', r.get('success', '?'))} template(s)/result",
        "impacket_ntlmrelay": lambda r: f"captures: {r.get('count', 0)}  relay_events: {len(r.get('relay_events', []))}",
        "petitpotam":         lambda r: f"coerced: {'YES' if r.get('coerced') else 'no'}",
        "coercer":            lambda r: f"triggered: {'YES' if r.get('coercion_triggered') else 'no'}  protocols: {len(r.get('protocols_tested', []))}",
        "rpcclient":          lambda r: f"users: {len(r.get('users', []))}  groups: {len(r.get('groups', []))}",
        "smbclient":          lambda r: f"files: {len(r.get('files', []))}  connected: {r.get('connected', False)}",
        "snmp_enum":          lambda r: f"accessible: {r.get('accessible', r.get('count', 0) > 0)}  entries: {r.get('count', 0)}",
        "impacket_mssql":  lambda r: f"success: {r.get('success', False)}",
        "mongosh_query":   lambda r: f"success: {r.get('success', False)}",
        "redis_query":     lambda r: f"success: {r.get('success', False)}",
        "iis_shortname":  lambda r: f"vulnerable: {'YES' if r.get('vulnerable') else 'no'}  found: {r.get('count', 0)}",
        "awscli":         lambda r: f"success: {r.get('success', False)}",
        "gcloud":         lambda r: f"success: {r.get('success', False)}",
        "git_ops":        lambda r: f"action: {r.get('action', '?')}  count: {r.get('count', r.get('total', '?'))}",
        "semgrep":        lambda r: f"{r.get('count', 0)} finding(s)",
        "bandit":         lambda r: f"{r.get('count', 0)} finding(s)",
        "trufflehog":     lambda r: f"{r.get('count', 0)} secret(s)  verified: {r.get('verified_count', 0)}",
        "gitleaks":       lambda r: f"{r.get('count', 0)} secret(s)",
        "trivy":          lambda r: f"{r.get('count', 0)} CVE(s)  "
                                    + "  ".join(f"{k}: {v}" for k, v in (r.get('severity_counts') or {}).items()),
        "safety_check":   lambda r: f"{r.get('count', 0)} vulnerable dep(s)",
        "file_identify":    lambda r: r.get("file_type", "")[:60] or r.get("file_class", ""),
        "strings_extract":  lambda r: f"{r.get('total_strings', 0)} strings  urls: {len(r.get('urls', []))}  potential secrets: {len(r.get('potential_secrets', []))}",
        "readelf_analyze":  lambda r: f"arch: {r.get('elf_header', {}).get('Machine', '?')}  sections: {len(r.get('sections', []))}  libs: {len(r.get('shared_libs', []))}",
        "binwalk_scan":     lambda r: f"{r.get('count', 0)} signature(s) found",
        "yara_scan":        lambda r: f"{r.get('count', 0)} rule match(es)",
        "strace_run":       lambda r: f"{r.get('total_syscalls', 0)} syscalls  network: {len(r.get('network_calls', []))}  suspicious: {len(r.get('suspicious', []))}",
        "ltrace_run":       lambda r: f"{r.get('total_calls', 0)} lib calls  auth: {len(r.get('auth_related', []))}  crypto: {len(r.get('crypto_calls', []))}",
        "run_script":       lambda r: f"exit {r.get('exit_code', '?')}  "
                                      f"out: {len(r.get('stdout', ''))}b  err: {len(r.get('stderr', ''))}b",
}


def _result_summary(tool_name: str, result: dict) -> str:
    if not isinstance(result, dict):
        return ""
    if "error" in result:
        return f"error: {result['error']}"
    fn = _RESULT_SUMMARY_FNS.get(tool_name)
    try:
        return fn(result) if fn else ""
    except Exception:
        return ""


class Orchestrator:
    def __init__(
        self,
        llm_client: LLMClient,
        tool_registry: ToolRegistry,
        results_dir: Path,
        log_callback: Optional[Callable] = None,
        quiet: bool = False,
        engagement_state: Optional[EngagementState] = None,
        interrupt_queue: Optional[queue.Queue] = None,
        active_persona: str = "",
        save_individual_runs: bool = True,
        session_logger=None,
        artifact_store: Optional[ArtifactStore] = None,
        job_manager: Optional[JobManager] = None,
        control_queue: Optional[queue.Queue] = None,
    ):
        self.llm = llm_client
        self.tools = tool_registry
        self.results_dir = results_dir
        self.results_dir.mkdir(exist_ok=True)
        self._log_callback = log_callback
        self._quiet = quiet
        # Mid-agent control channel: "abort" parks the agent (after the operator
        # kills its processes); "resume"/"skip" release it. See _check_control.
        self.control_queue: queue.Queue = control_queue or queue.Queue()
        self.state = engagement_state
        self.interrupt_queue: queue.Queue = interrupt_queue or queue.Queue()
        self._save_individual_runs = save_individual_runs
        self._session_logger = session_logger
        self._artifacts = artifact_store or ArtifactStore(ARTIFACTS_DIR)
        # Live child-process registry — lets the operator kill a single job
        # (/job kill) or every in-flight process (/abort). Tools register via
        # core.proc.run; foreground calls and jobs bind to it below.
        self._procs = ProcessRegistry()
        self._jobs = job_manager or JobManager(self._procs)
        self._shells = ShellManager()
        # Secret values seen this session (recorded creds + secrets passed into
        # tool calls). Redaction draws on this so a secret is masked from its
        # FIRST appearance — not only after record_credential adds it to state.
        self._secret_values: set[str] = set()
        # Last UI-state fingerprint — state_update is only emitted when the panels
        # would actually change, so a run of tool calls that adds no new intel does
        # not flood the TUI with redundant full-state re-posts.
        self._last_ui_state_sig: tuple | None = None
        # Worker label (parallel mode) — set on a clone so its activity is
        # attributable in the interleaved stream. Empty for the canonical orch.
        self._label: str = ""
        # Count of successful commands driven on a reverse/bind shell. Feeds the
        # sliding turn budget so actively working a foothold counts as progress (the
        # agent isn't killed mid local-enum just because it hasn't annotated yet).
        self._shell_exec_ok = 0
        # Count of background jobs (scans/cracks) delivered with a real result. A
        # delivered result is genuinely new information, so it feeds the sliding
        # turn budget — backgrounding a long scan must not starve the budget while
        # the agent does other work waiting for it.
        self._jobs_progress = 0

        if _BASE_INSTRUCTIONS_PATH.exists():
            self._base_instructions = _BASE_INSTRUCTIONS_PATH.read_text(encoding="utf-8") + "\n\n---\n\n"
        else:
            self._base_instructions = ""

        self._active_persona = active_persona
        self._persona_instructions = ""
        if active_persona:
            agents_base = Path(__file__).parent.parent / "agents"
            persona_path = (agents_base / active_persona / "persona.md").resolve()
            # Guard against path traversal in the persona name
            if str(persona_path).startswith(str(agents_base.resolve())) and persona_path.exists():
                body = persona_path.read_text(encoding="utf-8")
                # Strip the YAML frontmatter (name/description/agents allowlist) — it's
                # metadata for loading/routing, not instructions for the model.
                body = re.sub(r"^---\n.*?\n---\n", "", body, count=1, flags=re.DOTALL)
                self._persona_instructions = body.strip() + "\n\n---\n\n"

    def clone_for_worker(self, state: EngagementState, label: str = "") -> "Orchestrator":
        """A sibling Orchestrator for a parallel worker — its OWN forked `state` and
        control/interrupt queues, but the SAME live singletons as this one.

        Sharing the process registry, job manager, shell manager, and secret set is
        deliberate: the operator's /abort (which kills this orch's `_procs`) must
        reach a worker's child processes too; reverse shells and background jobs are
        engagement-wide; and a secret seen by ANY worker must be masked everywhere.
        State is the only thing isolated — workers mutate their fork, and the driver
        folds the deltas back with `merge_from` after they join.
        """
        w = Orchestrator(
            self.llm, self.tools, self.results_dir,
            log_callback=self._log_callback, quiet=self._quiet,
            engagement_state=state,
            interrupt_queue=queue.Queue(),       # per-worker — operator interrupts don't fan out
            active_persona=self._active_persona,
            save_individual_runs=self._save_individual_runs,
            session_logger=self._session_logger,
            artifact_store=self._artifacts,
            job_manager=self._jobs,              # shared → bound to the shared _procs
            control_queue=queue.Queue(),
        )
        w._procs = self._procs
        w._shells = self._shells
        w._secret_values = self._secret_values
        w._label = label
        return w

    def _emit(self, event_type: str, **data) -> None:
        # Mask known credential secrets in everything sent to logs/UI — except the
        # dedicated cred events, which the UI needs in full for click-to-reveal.
        if (((self.state and self.state.credentials) or self._secret_values)
                and event_type not in ("state_update", "credential")):
            data = self._redact_obj(data)
        if self._session_logger:
            try:
                self._session_logger.log(event_type, data)
            except Exception:
                pass
        if self._log_callback:
            try:
                self._log_callback({"type": event_type, **data})
            except Exception:
                pass

    # ── sliding turn budget (progress detection) ────────────────────────────────

    def _progress_fingerprint(self, run) -> tuple:
        """A monotonic snapshot of everything that counts as real progress in a run:
        banked findings (and verified ones), credentials, flags, planted changes,
        discovered surfaces/services, live shell sessions, and commands driven on a
        shell. A change in ANY component between turns means the agent advanced — the
        signal the sliding turn budget uses to refuse to kill a working exploit."""
        st = self.state
        creds   = len(st.credentials) if st else 0
        vcreds  = sum(1 for c in st.credentials if c.verified) if st else 0
        flags   = len(st.flags) if st else 0
        persist = len(st.persistence) if st else 0
        surf    = len(st.surfaces) if st else 0
        svc     = len(st.services) if st else 0
        try:
            shells = len(self._shells.sessions()) if self._shells else 0
        except Exception:
            shells = 0
        findings = len(run.findings)
        vfind    = sum(1 for f in run.findings if getattr(f, "verified", False))
        return (findings, vfind, creds, vcreds, flags, persist, surf, svc,
                shells, self._shell_exec_ok, self._jobs_progress)

    @staticmethod
    def _forward_progress(fp: tuple, last: tuple) -> bool:
        """True if any progress counter went UP since the last turn (a session
        dropping while a finding lands still reads as progress)."""
        return any(a > b for a, b in zip(fp, last))

    # Pollers/meta tools that aren't substantive "actions" worth carrying forward.
    _HANDOFF_SKIP_TOOLS = frozenset({
        "check_jobs", "list_shells", "wait", "read_artifact", "grep_artifact",
        "list_scripts", "safety_check",
    })

    def _synthesize_handoff(self, run, last_text: str) -> str:
        """Build a substantive handoff when a run ends without a clean text close-out
        (cap-stop, conclude, error). The old behaviour handed off only `last_text`,
        which on a tool-busy cap-stop is often a scrap or empty — so the next agent
        inherited nothing of what was actually accomplished. This combines the last
        reasoning with the run's real work: findings recorded, the most recent
        meaningful tool actions, and any live shell sessions. Secrets are masked by
        the caller (_redact_secrets) before it is stored/handed off.
        """
        parts: list[str] = []
        if last_text and last_text.strip():
            parts.append(last_text.strip())

        # Live foothold sessions — the single most important thing to carry forward.
        try:
            shells = self._shells.sessions() if self._shells else []
        except Exception:
            shells = []
        if shells:
            parts.append(
                f"{len(shells)} live shell session(s) are OPEN — drive them with "
                "shell_exec; do NOT re-exploit to re-establish access.")

        # Findings annotated during this run.
        titles = [getattr(f, "title", "") for f in (run.findings or []) if getattr(f, "title", "")]
        if titles:
            parts.append("Findings recorded this run: " + "; ".join(titles[:6]))

        # The most recent substantive tool actions, oldest→newest, so the next agent
        # sees the exact thread that was in flight when the budget ran out.
        actions: list[str] = []
        for tc in reversed(run.tool_calls or []):
            name = getattr(tc, "tool_name", "")
            if not name or name in self._HANDOFF_SKIP_TOOLS:
                continue
            cmd = (getattr(tc, "command_str", None) or "").strip()
            actions.append(f"{name}: {cmd[:140]}" if cmd else name)
            if len(actions) >= 6:
                break
        if actions:
            parts.append("Most recent actions (in flight at stop):\n- "
                         + "\n- ".join(reversed(actions)))

        return "\n\n".join(parts).strip()

    def _live_shells_block(self) -> str:
        """An opening-context section listing live foothold sessions this engagement
        already holds, so an agent taking over knows it can drive them with shell_exec
        instead of re-exploiting from scratch. Empty when there are none."""
        if not self._shells:
            return ""
        try:
            live = [s for s in self._shells.sessions() if s.get("alive")]
        except Exception:
            return ""
        if not live:
            return ""
        lines = ["**Active shell sessions you ALREADY HOLD** "
                 "(a prior step caught these — USE them, do not re-exploit to get a shell):"]
        for s in live:
            os_hint = f", {s['os_hint']}" if s.get("os_hint") else ""
            lines.append(f"  • session {s['id']} — from {s.get('from', '?')}{os_hint}. "
                         f"Drive it with shell_exec(session_id='{s['id']}', command=...).")
        lines.append("Pick up from this foothold: enumerate locally, escalate privileges, "
                     "and pursue the objective through the session you have.")
        return "\n".join(lines)

    def _artifact_index_block(self) -> str:
        """An index of full raw tool outputs captured this engagement, so any agent
        can pull the exact bytes of an earlier command (read_artifact / grep_artifact)
        instead of re-running it. The context block carries summaries + recent output
        snippets; this is the escape hatch to the complete record."""
        store = getattr(self, "_artifacts", None)
        if store is None:
            return ""
        try:
            items = store.recent(12)
        except Exception:
            return ""
        if not items:
            return ""
        lines = ["**Captured artifacts** (full raw output from earlier tool runs — "
                 "read with read_artifact(artifact_id=...) or grep_artifact to get the "
                 "complete bytes, don't re-run the command):"]
        for a in items:
            lines.append(f"  • {a.get('artifact_id')} — {a.get('label', 'output')} "
                         f"({a.get('lines', '?')} lines)")
        return "\n".join(lines)

    def _scope_block(self, tool_name: str, inputs) -> Optional[str]:
        """Hard-block reason if a scanning/enum tool is aimed at a target outside the
        authorized scope, else None. Scope is a contract boundary: the agent is told
        to stay in scope, but this ENFORCES it at the tool boundary so a discovered
        IP (e.g. a DC's second DNS A record, or a PTR-leaked host) cannot be scanned
        just because the model decided to pivot."""
        if not self.state or tool_name not in _SCOPE_GATED_TOOLS or not isinstance(inputs, dict):
            return None
        target = next((str(inputs[k]).strip() for k in _TARGET_KEYS
                       if isinstance(inputs.get(k), str) and inputs[k].strip()), None)
        if not target or self.state.in_scope(target):
            return None
        scope = ", ".join(self.state.scope_targets) or "(the authorized target only)"
        return (f"{target!r} is OUTSIDE the engagement scope — {tool_name} was NOT run "
                f"(hard-blocked). Authorized scope: {scope}. A domain controller's DNS "
                f"often points at extra IPs/interfaces; that does not put them in scope. "
                f"Do not scan or probe this target. If it genuinely belongs in scope, "
                f"annotate it as a recon finding so the operator can add it with /scope add.")

    def _web_research_block(self, inputs) -> Optional[str]:
        """Reason string if a web_search/fetch_url call would leak engagement specifics
        to a third party (or web research is disabled), else None. This is the context-
        aware OPSEC guard — it knows the actual scope hosts and discovered credentials,
        which the standalone tool cannot."""
        from core.config import get as _get
        if not _get("allow_web_search", True):
            return "web research is disabled (allow_web_search=false)"
        if not isinstance(inputs, dict):
            return None
        blob = " ".join(str(v) for v in inputs.values() if isinstance(v, (str, int, float)))
        low = blob.lower()
        if _IPV4_RE.search(blob) or _IPV6_RE.search(blob):
            return "it contains an IP address"
        m = _INTERNAL_TLD_RE.search(blob)
        if m:
            return f"it contains an internal hostname ('{m.group(0)}')"
        if self.state:
            from core.engagement_state import _extract_host
            hosts = set(self.state.scope_targets or []) | set(self.state.out_of_scope or [])
            hosts |= set(self.state.recon.host_names.keys()) | set(self.state.recon.host_names.values())
            for h in hosts:
                host = _extract_host(h)
                if host and len(host) >= 4 and host.lower() in low:
                    return f"it names the engagement target ('{host}')"
            for c in self.state.credentials:
                if c.secret and len(c.secret) >= 4 and c.secret.lower() in low:
                    return "it contains a discovered credential value"
                u = (c.username or "").strip()
                if u and len(u) >= 4 and u.lower() not in _GENERIC_USERS and u.lower() in low:
                    return f"it contains a discovered username ('{u}')"
            for s in self._secret_values:
                if s and len(s) >= 6 and s.lower() in low:
                    return "it contains a captured secret"
        return None

    # ── foothold / reverse-shell meta-tools ─────────────────────────────────────

    def _handle_foothold(self, name: str, inputs: dict, source_agent: str) -> dict:
        if name == "list_shells":
            return {"sessions": self._shells.sessions()}

        if name == "shell_exec":
            sid = inputs.get("session_id", "")
            cmd = inputs.get("command", "")
            if not sid or not cmd:
                return {"error": "session_id and command are required"}
            res = self._shells.exec(sid, cmd, timeout=inputs.get("timeout", 15))
            if "output" in res and not res.get("error"):
                self._shell_exec_ok += 1          # active foothold work → budget progress
                if self.state:                    # driving a shell = confirmed exec
                    self.state.note_exec_confirmed()
            self._emit("shell_exec", session_id=sid, command=cmd,
                       summary=(res.get("output", "")[:120] if "output" in res else res.get("error", "")))
            return res

        if name == "start_listener":
            from core.utils import get_interface_ip
            ip = get_interface_ip(inputs.get("interface", "tun0"))
            res = self._shells.start_listener(inputs.get("port", 4444), attacker_ip=ip)
            if res.get("listening"):
                self._print(f"  [magenta][listener][/magenta] {ip}:{res.get('port')}")
                self._emit("listener_started", ip=ip, port=res.get("port"))
            return res

        if name == "record_persistence":
            if not self.state:
                return {"recorded": False, "error": "no engagement state"}
            host = inputs.get("host", "")
            kind = inputs.get("kind", "other")
            if not host:
                return {"recorded": False, "error": "host is required"}
            item = self.state.add_persistence(
                kind=kind, host=host, detail=inputs.get("detail", ""),
                before=inputs.get("before", ""),
                cleanup=inputs.get("cleanup", ""), os=inputs.get("os", ""),
                source_agent=source_agent,
            )
            self._print(f"  [bold yellow][change][/bold yellow] {kind} @ {host}")
            self._emit("persistence", kind=kind, host=host, detail=item.detail,
                       before=item.before, cleanup=item.cleanup, os=item.os)
            return {"recorded": True, "kind": kind, "host": host}

        return {"error": f"unknown foothold tool {name!r}"}

    # ── secret redaction (logs / UI / findings) ─────────────────────────────────

    # Tool-input keys whose values are secrets, and flag tokens that precede a
    # secret on a command line — used to mask a secret on its FIRST appearance.
    _SECRET_KEYS = {"password", "passwd", "pass", "secret", "hash", "ntlm",
                    "nthash", "token", "api_key", "apikey"}
    _SECRET_FLAGS = ("-p", "--password", "-H", "--hash", "-W", "--smb-pass")

    def _register_input_secrets(self, inputs: dict, tool_name: str = "") -> None:
        """Harvest secret-bearing values from a tool call's inputs into the
        redaction set, so they are masked from the very first emit/log line."""
        if not isinstance(inputs, dict):
            return
        for k, v in inputs.items():
            if isinstance(v, str) and v and k.lower() in self._SECRET_KEYS:
                self._secret_values.add(v)
            # Parse "-p <pass>" / "--password=<pass>" out of flag/command strings.
            elif isinstance(v, str) and v and k.lower() in ("flags", "command", "args", "extra"):
                toks = v.split()
                for i, t in enumerate(toks):
                    # space-separated form: "-p secret"
                    if t in self._SECRET_FLAGS and i + 1 < len(toks):
                        self._secret_values.add(toks[i + 1])
                    # equals form: "-p=secret" / "--password=secret"
                    for fl in self._SECRET_FLAGS:
                        if t.startswith(fl + "=") and len(t) > len(fl) + 1:
                            self._secret_values.add(t[len(fl) + 1:])

    def _redact_secrets(self, text: str) -> str:
        if not isinstance(text, str):
            return text
        creds = self.state.credentials if self.state else []
        for c in creds:
            s = c.secret
            if s and len(s) >= 5 and s in text:
                text = text.replace(s, c.secret_masked or mask_secret(s))
        for s in self._secret_values:
            if len(s) >= 5 and s in text:
                text = text.replace(s, mask_secret(s))
        return text

    def _redact_obj(self, obj):
        if isinstance(obj, str):
            return self._redact_secrets(obj)
        if isinstance(obj, dict):
            return {k: self._redact_obj(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._redact_obj(v) for v in obj]
        return obj

    def _print(self, *args, **kwargs) -> None:
        if not self._quiet:
            console.print(*args, **kwargs)

    # ── interrupt queue ───────────────────────────────────────────────────────

    def _drain_interrupts(self) -> list[str]:
        messages = []
        while True:
            try:
                messages.append(self.interrupt_queue.get_nowait())
            except queue.Empty:
                break
        return messages

    def _clear_control(self) -> None:
        """Drop any stale control signals so they don't leak across agents."""
        while True:
            try:
                self.control_queue.get_nowait()
            except queue.Empty:
                return

    def _handle_control(self, run) -> bool:
        """Operator mid-agent control. On a pending 'abort' (the UI already killed
        this agent's processes), park the agent and block until the operator
        releases it: 'resume' continues THIS agent (the guidance they typed is
        injected on the next turn), 'skip' stops it so the pipeline advances.
        Returns True only when the run should stop (skip)."""
        aborting = False
        while True:
            try:
                sig = self.control_queue.get_nowait()
            except queue.Empty:
                break
            if sig == "abort":
                aborting = True
                break   # stop draining — leave any release signal for the wait below
            # stray 'resume'/'skip' without a pending abort are stale — ignore
        if not aborting:
            return False

        self._print("[yellow]⏸ Agent held by operator — type guidance, then "
                    "/continue (resume) or /skip (next agent).[/yellow]")
        self._emit("agent_held", agent=run.agent)
        while True:
            sig = self.control_queue.get()      # blocks until the operator decides
            if sig == "resume":
                self._print("[green]▶ Resuming with operator guidance.[/green]")
                self._emit("agent_resumed", agent=run.agent)
                return False
            if sig == "skip":
                self._print("[yellow]⏭ Skipping agent — advancing to next.[/yellow]")
                self._emit("agent_skipped", agent=run.agent)
                run.status = "aborted"
                if not run.summary:
                    run.summary = "[Operator aborted this agent and skipped to the next.]"
                return True
            # ignore extra 'abort' signals while already held

    # ── main run loop ─────────────────────────────────────────────────────────

    def run(
        self,
        agent: AgentDefinition,
        target: str,
        objective: Optional[str] = None,
        max_turns: int = 20,
        all_findings: Optional[list] = None,
    ) -> EngagementRun:
        run = EngagementRun(agent=agent.name, target=target)
        self._clear_control()   # no stale abort/resume/skip carried from a prior agent

        self._print(Panel(
            f"[bold green]Engagement started[/bold green]\n"
            f"Agent:  {agent.name}\n"
            f"Target: {target}\n"
            f"Run ID: {run.id}"
        ))
        self._emit("agent_start", agent=agent.name, target=target, run_id=run.id)

        from core.config import (get_model_for_agent, get_global_model,
                                  get_temperature_for_agent, get as _config_get)
        # Full-transcript debug capture (off unless /debug on). Re-read per agent so a
        # mid-engagement toggle takes effect on the next agent; appended to one file.
        from core import debug_capture
        debug_capture.configure(self.results_dir / "llm_debug.log",
                                bool(_config_get("debug_capture", False)))
        effective_model = get_model_for_agent(agent.name) or get_global_model() or agent.model
        # Per-agent sampling temperature (None → provider default). Resolved once per run.
        effective_temperature = get_temperature_for_agent(agent.name)

        available_tools = self.tools.get_by_scope(agent.scope)
        phase = agent.metadata.get("phase", "assessment")
        # Meta-tools available everywhere; plan/surface gated by phase.
        meta_defs = [ANNOTATE_DEF, FOLLOWUP_DEF, GREP_ARTIFACT_DEF, READ_ARTIFACT_DEF]
        # Retrievable domain methodology — available to any agent that works a target,
        # so the generalist can pull a playbook instead of routing to a specialist.
        if phase not in ("planning", "reporting"):
            meta_defs.append(LOAD_PLAYBOOK_DEF)
        if "record_plan" in agent.scope or phase == "planning":
            meta_defs.append(RECORD_PLAN_DEF)
        # Any agent that actively touches a target may discover a new surface;
        # only the tool-less planning/reporting phases are excluded.
        if "register_surface" in agent.scope or phase not in ("planning", "reporting"):
            meta_defs.append(REGISTER_SURFACE_DEF)
        # Any active phase can discover credentials and run background jobs.
        if phase not in ("planning", "reporting"):
            meta_defs.append(RECORD_CRED_DEF)
            meta_defs.append(RECORD_SERVICE_DEF)
            meta_defs.append(CHECK_JOBS_DEF)
            meta_defs.append(WAIT_DEF)      # let the agent actually wait for a reset/reboot
            meta_defs.append(CONCLUDE_DEF)
            # Script library — only for agents that can write scripts.
            if any(s in agent.scope for s in ("run_script", "*")):
                meta_defs.append(LIST_SCRIPTS_DEF)
            # Foothold / blind-RCE meta-tools
            meta_defs += [START_LISTENER_DEF, SHELL_EXEC_DEF, LIST_SHELLS_DEF, RECORD_PERSIST_DEF]
            # CTF flag capture — only when running the CTF persona.
            if self._active_persona == "pentest-ctf":
                meta_defs.append(RECORD_FLAG_DEF)
        tool_schemas = [t.to_api_format() for t in available_tools] + meta_defs

        # Planning does not annotate findings — it only records a plan.
        schema_instructions = "" if phase == "planning" else FINDINGS_SCHEMA_INSTRUCTIONS
        system = self._persona_instructions + self._base_instructions + agent.system_prompt + schema_instructions

        # Build initial message with engagement state context
        base_objective = objective or f"Begin assessment on target: {target}"
        if self.state and (self.state.has_context() or all_findings):
            context_block = self.state.build_context_block(all_findings or [])
            user_message = f"{context_block}\n\n{base_objective}"
        else:
            user_message = base_objective

        # Live footholds + captured artifacts are held on the orchestrator, not the
        # engagement state, so build_context_block can't see them — inject them here.
        # The shells block stops an agent re-exploiting a session it already holds; the
        # artifact index lets it pull the FULL raw output of any earlier command on
        # demand (read_artifact/grep_artifact) rather than re-running it. Prepended so
        # the most up-to-date, actionable context sits at the top of the brief.
        prefix = [b for b in (self._live_shells_block(), self._artifact_index_block()) if b]
        if prefix:
            user_message = "\n\n".join(prefix) + "\n\n" + user_message

        messages = [{"role": "user", "content": user_message}]

        # Turn budget. max_turns <= 0 means unlimited — the agent runs until it stops
        # on its own. Otherwise the budget is a SLIDING "turns since last progress"
        # window, not a hard total: every turn that banks something real (a finding,
        # credential, flag, a reverse shell connecting, or a successful command on a
        # held shell) resets the no-progress counter. This is what stops a hard cap
        # from killing an agent in the MIDDLE of a working exploit (e.g. local enum
        # right after catching a shell). An absolute ceiling still bounds a runaway.
        import itertools
        from core.config import get as _cfg_get
        unlimited = max_turns <= 0
        extend_on_progress = bool(_cfg_get("extend_turns_on_progress", True)) and not unlimited
        progress_factor = max(1, int(_cfg_get("max_turns_progress_factor", 5) or 5))
        hard_ceiling = 0 if unlimited else max_turns * progress_factor
        no_progress_turns = 0
        last_progress_fp = self._progress_fingerprint(run)
        turn_iter = itertools.count() if (unlimited or extend_on_progress) else range(max_turns)

        # Loop-nudge state: count identical tool calls and nudge (redirect) the
        # agent off a rut instead of letting it spin until the hard turn cap.
        nudge_threshold = int(_cfg_get("repeat_nudge_threshold", 3) or 0)
        # Tools that are legitimately called repeatedly with identical args
        # (polling an OOB listener, background jobs, or for a reverse shell) — a
        # repeat is normal operation for these, so they are excluded from nudging.
        nudge_exempt = set(_cfg_get("nudge_exempt_tools", ()) or ())
        call_counts: dict[str, int] = {}
        nudged: set[str] = set()
        # Pivot nudge (per-run): consecutive hard failures within this agent run.
        pivot_after = int(_cfg_get("pivot_nudge_after_failures", 4) or 0)
        fail_streak = 0          # consecutive unproductive tool results
        # Reuse + grind nudges are ENGAGEMENT-level (counters live on self.state) so
        # they survive the agent cycling — thrash spread over many runs still trips.
        reuse_threshold = int(_cfg_get("run_script_volume_nudge", 10) or 0)
        grind_threshold = int(_cfg_get("grind_nudge_after_scripts", 12) or 0)
        # Foothold-banking: turns after exec is confirmed to allow before nudging to
        # annotate it. Small — confirm exec, then bank within a turn or two.
        foothold_bank_after = int(_cfg_get("foothold_bank_nudge_after_turns", 2) or 0)
        # Last substantive agent text — becomes the handoff to the next agent if the
        # run ends without a clean text-only close-out (e.g. hits the turn cap).
        last_text = ""

        try:
            for _turn in turn_iter:
                # Sliding turn budget: stop only after `max_turns` turns in a row
                # WITHOUT progress (each banked finding/cred/flag/shell/command reset
                # the counter below), with an absolute ceiling as a runaway backstop.
                # When extend-on-progress is off this is dead (range() bounds it).
                if extend_on_progress and (
                        no_progress_turns >= max_turns
                        or (hard_ceiling and _turn >= hard_ceiling)):
                    why = ("no progress for the turn budget" if no_progress_turns >= max_turns
                           else "absolute turn ceiling")
                    self._print(f"[yellow]Max turns reached ({why}) — stopping.[/yellow]")
                    run.status = "max_turns"
                    self._emit("agent_done", agent=run.agent, status=run.status,
                               findings_count=len(run.findings), cost=run.estimated_cost_usd,
                               max_turns=max_turns)
                    return run
                # Mid-agent operator control: /abort parks the agent here (its
                # processes are already killed) until /continue (resume THIS agent
                # with the guidance just typed) or /skip (advance to next agent).
                if self._handle_control(run):
                    break
                # Check interrupt queue before each API call
                interrupts = self._drain_interrupts()
                if interrupts:
                    for msg in interrupts:
                        self._print(f"\n[bold magenta]⚡ Operator:[/bold magenta] {msg}")
                        self._emit("operator_interrupt", message=msg)
                    # Inject interrupts into the last user turn or as a new content block
                    if messages and messages[-1]["role"] == "user":
                        last = messages[-1]["content"]
                        interrupt_text = "\n".join(f"[Operator]: {m}" for m in interrupts)
                        if isinstance(last, list):
                            last.append({"type": "text", "text": interrupt_text})
                        else:
                            messages[-1]["content"] = last + "\n\n" + interrupt_text
                    else:
                        messages.append({"role": "user", "content":
                                         "\n".join(f"[Operator]: {m}" for m in interrupts)})

                # Deliver any background jobs that finished — their results are
                # injected into context so the agent does not have to poll.
                completed_jobs = self._jobs.poll_completed()
                if completed_jobs:
                    job_texts = [self._ingest_job(j, agent.name, run) for j in completed_jobs]
                    self._inject_user_text(messages, "\n\n".join(job_texts))
                    # A delivered scan/crack result is real new information — count
                    # it so backgrounding a long job doesn't starve the turn budget.
                    self._jobs_progress += sum(1 for j in completed_jobs if j.status == "done")

                # Announce any reverse shells that just connected back.
                new_shells = self._shells.poll_new_sessions()
                if new_shells:
                    notice = "\n".join(
                        f"[Reverse shell connected — session {s.id} from {s.addr[0]}:{s.addr[1]}. "
                        f"Drive it with shell_exec(session_id='{s.id}', command=...).]"
                        for s in new_shells)
                    self._print(f"\n[bold green]⚡ {len(new_shells)} reverse shell(s) connected[/bold green]")
                    for s in new_shells:
                        self._emit("shell_connected", session_id=s.id, addr=f"{s.addr[0]}:{s.addr[1]}")
                    self._inject_user_text(messages, notice)
                    if self.state:                # a caught shell is confirmed exec
                        self.state.note_exec_confirmed()

                # Objective declared achieved — stop this agent's loop. EXCEPT the
                # reporting agent: it runs AFTER the engagement is concluded, to write
                # the deliverable. A concluded state must not short-circuit it, or the
                # report agent returns instantly with no LLM call and the report falls
                # back to the un-synthesized DRAFT (no executive summary, missing detail).
                if self.state and self.state.concluded and phase != "reporting":
                    self._print(f"[green]■ Stopping — {self.state.concluded}[/green]")
                    run.status = "concluded"
                    break

                debug_capture.log_request(agent.name, _turn, effective_model,
                                          system, messages, tool_schemas)
                response = self.llm.run(
                    model=effective_model,
                    system=system,
                    messages=messages,
                    tools=tool_schemas,
                    temperature=effective_temperature,
                )
                debug_capture.log_response(agent.name, _turn, response)

                usage = response.usage
                run.token_usage.input_tokens       += usage.input_tokens
                run.token_usage.output_tokens      += usage.output_tokens
                run.token_usage.cache_read_tokens  += getattr(usage, "cache_read_input_tokens", 0)
                run.token_usage.cache_write_tokens += getattr(usage, "cache_creation_input_tokens", 0)
                run.estimated_cost_usd = estimate_cost(
                    effective_model,
                    run.token_usage.input_tokens,
                    run.token_usage.output_tokens,
                    run.token_usage.cache_read_tokens,
                    run.token_usage.cache_write_tokens,
                )
                self._emit(
                    "token_update",
                    run_id=run.id,
                    input=run.token_usage.input_tokens,
                    output=run.token_usage.output_tokens,
                    cache_read=run.token_usage.cache_read_tokens,
                    cost=run.estimated_cost_usd,
                )

                messages.append({"role": "assistant", "content": response.content})

                tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
                text_blocks     = [b for b in response.content if b.type == "text"]

                if not tool_use_blocks:
                    for block in text_blocks:
                        self._extract_and_enrich(block.text, run, target)
                    # The agent's final, tool-free message is its real close-out —
                    # keep the whole thing (joined) as the handoff, not just block 1.
                    final_text = "\n".join(b.text for b in text_blocks if b.text.strip())
                    if final_text:
                        run.summary = final_text
                        last_text = final_text
                    break

                # Text blocks alongside tool_use are chain-of-thought reasoning
                for block in text_blocks:
                    if block.text.strip():
                        self._emit("agent_reasoning", text=block.text)
                        last_text = block.text

                tool_results = []
                nudges: list[str] = []
                for tb in tool_use_blocks:
                    # Loop nudge — flag identical repeated calls (same tool + args).
                    # Polling-style tools (OOB listener, job/shell checks) are exempt.
                    if nudge_threshold and tb.name not in nudge_exempt:
                        sig = _call_sig(tb.name, tb.input)
                        call_counts[sig] = call_counts.get(sig, 0) + 1
                        if call_counts[sig] >= nudge_threshold and sig not in nudged:
                            nudged.add(sig)
                            nudges.append(f"{tb.name} (x{call_counts[sig]})")

                    # Register any secret carried in this call's inputs BEFORE any
                    # emit/log in this iteration, so it is masked from first sight.
                    self._register_input_secrets(tb.input, tb.name)
                    debug_capture.log_command(agent.name, _turn, tb.name, tb.input)

                    # ── intercepted tools ──────────────────────────────────────
                    if tb.name == "annotate_finding":
                        result = self._handle_annotation(tb.input, run, target, all_findings)
                        self._save_run(run)
                        if self.state:
                            self.state.note_progress()   # banked a result → reset grind streak
                            if tb.input.get("verified"):
                                # a verified finding lands the foothold on the record
                                self.state.note_foothold_banked()
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": tb.id,
                            "content":     json.dumps(result),
                        })
                        continue

                    if tb.name == "queue_followup":
                        result = self._handle_followup(tb.input, agent.name)
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": tb.id,
                            "content":     json.dumps(result),
                        })
                        continue

                    if tb.name == "record_plan":
                        result = self._handle_record_plan(tb.input, agent.name)
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": tb.id,
                            "content":     json.dumps(result),
                        })
                        continue

                    if tb.name == "register_surface":
                        result = self._handle_register_surface(tb.input, agent.name)
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": tb.id,
                            "content":     json.dumps(result),
                        })
                        continue

                    if tb.name == "record_credential":
                        result = self._handle_record_credential(tb.input, agent.name)
                        if self.state:
                            self.state.note_progress()
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": tb.id,
                            "content":     json.dumps(result),
                        })
                        continue

                    if tb.name == "record_service":
                        result = self._handle_record_service(tb.input, agent.name)
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": tb.id,
                            "content":     json.dumps(result),
                        })
                        continue

                    if tb.name == "record_flag":
                        result = self._handle_record_flag(tb.input, agent.name)
                        if self.state:
                            self.state.note_progress()
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": tb.id,
                            "content":     json.dumps(result),
                        })
                        continue

                    if tb.name == "conclude_engagement":
                        reason = (tb.input.get("reason") or "objective achieved").strip()
                        if self.state:
                            self.state.concluded = reason
                        self._print(f"\n[bold green]■ Engagement concluded:[/bold green] {reason}")
                        self._emit("engagement_concluded", reason=reason)
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": tb.id,
                            "content":     json.dumps({"concluded": True, "reason": reason}),
                        })
                        continue

                    if tb.name in ("grep_artifact", "read_artifact"):
                        result = self._handle_artifact_query(tb.name, tb.input)
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": tb.id,
                            "content":     json.dumps(self._cap_artifact_view(result)),
                        })
                        continue

                    if tb.name in ("start_listener", "shell_exec", "list_shells", "record_persistence"):
                        result = self._handle_foothold(tb.name, tb.input, agent.name)
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": tb.id,
                            "content":     json.dumps(self._offload_for_llm(result, tb.name)),
                        })
                        continue

                    # ── web-research OPSEC scrub: never leak target specifics off-box ──
                    if tb.name in _WEB_TOOLS:
                        blocked = self._web_research_block(tb.input)
                        if blocked:
                            self._print(f"  [yellow]⛔ {tb.name} blocked — {blocked}[/yellow]")
                            self._emit("web_blocked", name=tb.name, reason=blocked)
                            tool_results.append({
                                "type": "tool_result", "tool_use_id": tb.id,
                                "content": json.dumps({
                                    "error": f"Refused: {blocked}. {tb.name} is for GENERAL "
                                             "product/technology/CVE research only — never send a "
                                             "target IP, hostname, credential, or captured data to "
                                             "a third-party search. Rephrase with generic tech terms.",
                                }),
                            })
                            continue

                    # ── auth short-circuit: don't retry creds already known to fail ──
                    if self.state and tb.name in _AUTH_TOOLS:
                        af = _auth_fields(tb.name, tb.input)
                        if af and self.state.auth_attempted(af[0], af[1], af[3], af[4], af[2]) == "fail":
                            self._print(f"  [dim]↩ {tb.name} skipped — these creds already failed[/dim]")
                            tool_results.append({
                                "type": "tool_result", "tool_use_id": tb.id,
                                "content": json.dumps({
                                    "skipped": True,
                                    "note": f"{af[3] or ''}:*** already failed against {af[0]}@{af[1]} — not retried. Use different credentials.",
                                }),
                            })
                            continue

                    if tb.name == "check_jobs":
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": tb.id,
                            "content":     json.dumps({"jobs": self._jobs.snapshot()}),
                        })
                        continue

                    if tb.name == "wait":
                        result = _wait_fn(**tb.input)
                        self._print(f"  [dim]⏳ {result.get('note', 'waited')}[/dim]")
                        self._emit("tool_done", name="wait", command_str=None,
                                   summary=result.get("note", ""), inputs=tb.input, output=result)
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": tb.id,
                            "content":     json.dumps(result),
                        })
                        continue

                    if tb.name == "list_scripts":
                        if self.state:
                            self.state.note_listscripts()
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": tb.id,
                            "content":     json.dumps(self._handle_list_scripts(tb.input)),
                        })
                        continue

                    if tb.name == "load_playbook":
                        result = _load_playbook_fn(tb.input.get("names", []))
                        names = ", ".join(result.get("loaded", [])) or "—"
                        self._print(f"  [magenta]▣ playbook loaded:[/magenta] {names}")
                        self._emit("playbook_loaded", names=result.get("loaded", []))
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": tb.id,
                            "content":     json.dumps(result),   # whole — not offloaded
                        })
                        continue

                    # `background` is an orchestrator-level control flag, not a tool
                    # argument — strip it before the tool ever sees it.
                    inputs = dict(tb.input)
                    want_bg = bool(inputs.pop("background", False)) or tb.name in _ALWAYS_BACKGROUND

                    # ── scope gate (hard-block out-of-scope targets) ───────────
                    scope_reason = self._scope_block(tb.name, inputs)
                    if scope_reason:
                        self._print(f"\n[red]⛔ {tb.name}[/red]  blocked — out of scope")
                        self._emit("tool_blocked", name=tb.name, reason=scope_reason)
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": tb.id,
                            "content":     json.dumps({"error": scope_reason, "blocked": True}),
                            "is_error":    True,
                        })
                        continue

                    # ── scan cache check ───────────────────────────────────────
                    if self.state:
                        cached = self.state.check_cache(tb.name, inputs)
                        if cached:
                            summary = cached.get("summary", "cached")
                            self._print(f"\n[dim]↩ {tb.name}[/dim]  [dim]cache hit — {summary}[/dim]")
                            self._emit("tool_cached", name=tb.name, summary=summary)
                            # Return the full cached result so later agents are not
                            # starved of detail the original caller received.
                            cached_result = {"_cached": True, "summary": summary,
                                             "result": cached.get("result",
                                                                  cached.get("truncated_output", ""))}
                            tool_results.append({
                                "type":        "tool_result",
                                "tool_use_id": tb.id,
                                "content":     json.dumps(self._offload_for_llm(cached_result, tb.name)),
                            })
                            continue

                    # ── background job ─────────────────────────────────────────
                    if want_bg:
                        try:
                            tool = self.tools.get(tb.name)
                        except KeyError as e:
                            tool_results.append({"type": "tool_result", "tool_use_id": tb.id,
                                                 "content": f"Error: {e}", "is_error": True})
                            continue
                        job = self._jobs.start(
                            tb.name, inputs,
                            lambda t=tool, i=inputs: t.execute(**i),
                        )
                        self._print(f"\n[magenta]⏗ {tb.name}[/magenta]  started in background (job {job.id})")
                        self._emit("job_started", name=tb.name, job_id=job.id, inputs=self._redact_obj(inputs))
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": tb.id,
                            "content":     json.dumps({
                                "_job_id": job.id, "status": "running",
                                "note": (f"{tb.name} started in the background (job {job.id}). Its result "
                                         "will be delivered to you automatically when it finishes — keep "
                                         "working on other things. You can call check_jobs to see status."),
                            }),
                        })
                        continue

                    # ── normal tool dispatch ───────────────────────────────────
                    safe_inputs = self._redact_obj(inputs)
                    inputs_preview = json.dumps(safe_inputs)[:120]
                    self._print(f"\n[cyan]→ {tb.name}[/cyan]  {inputs_preview}")
                    self._emit("tool_start", name=tb.name, inputs=safe_inputs)

                    tc = ToolCall(id=tb.id, tool_name=tb.name, inputs=inputs)

                    try:
                        tool   = self.tools.get(tb.name)
                        # Bind so any process this tool spawns registers as a
                        # foreground process (job_id=None) and /abort can kill it.
                        with proc_bind(self._procs, None, tb.name):
                            result = tool.execute(**inputs)
                        # Full `result` is used below (state, cache, LLM view); the
                        # copy persisted on the run record is capped to bound JSON size.
                        tc.output = _cap_for_persist(result)

                        if isinstance(result, dict) and "_command" in result:
                            tc.command_str = _redact_command(result["_command"])

                        summary = _result_summary(tb.name, result)
                        self._print(f"[green]  ✓[/green] {summary}")
                        self._emit("tool_done", name=tb.name,
                                   command_str=tc.command_str, summary=summary,
                                   inputs=inputs, output=result)

                        # Auth ledger — record success/fail so the same credential
                        # is not tried again (works even when the tool "errored").
                        if self.state and tb.name in _AUTH_TOOLS:
                            af = _auth_fields(tb.name, inputs)
                            res = _auth_result(tb.name, result)
                            if af and res:
                                self.state.record_auth_attempt(af[0], af[1], af[3], af[4],
                                                               res, af[2], agent.name)

                        # Update engagement state
                        if self.state and isinstance(result, dict) and "error" not in result:
                            self.state.log_tool(
                                agent=agent.name,
                                tool_name=tb.name,
                                command=tc.command_str,
                                summary=summary,
                                result=result,
                            )
                            self.state.store_cache(tb.name, inputs, result, summary)
                            self.state.ingest_tool_result(tb.name, result, source_agent=agent.name)
                            # Record ad-hoc scripts so list_scripts can offer them for reuse.
                            if tb.name == "run_script" and result.get("script_file"):
                                self.state.add_script(result.get("purpose", ""),
                                                      result["script_file"],
                                                      inputs.get("language", ""))
                            self._emit_state_update()

                        # Confirmed code execution via a blind channel (no live shell
                        # object to key off) — arm the foothold-banking nudge. Cheap:
                        # only until exec is first confirmed, only for command-execution
                        # channels, on a capped serialization.
                        if (self.state and not self.state.exec_confirmed()
                                and tb.name in _EXEC_CHANNEL_TOOLS
                                and isinstance(result, dict) and _result_shows_exec(result)):
                            self.state.note_exec_confirmed()

                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": tb.id,
                            "content":     json.dumps(self._offload_for_llm(result, tb.name)),
                        })
                    except Exception as e:
                        tc.error = str(e)
                        self._print(f"[red]  ✗ {e}[/red]")
                        self._emit("tool_error", name=tb.name, error=str(e))
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": tb.id,
                            "content":     f"Error: {e}",
                            "is_error":    True,
                        })

                    run.tool_calls.append(tc)

                    # Progress tracking for the pivot (per-run) and grind/reuse
                    # (engagement-level) nudges. list_scripts and the record_* tools
                    # are intercepted earlier, so they update state in their handlers.
                    if tb.name == "run_script" and self.state:
                        self.state.note_script_call()
                    if _is_unproductive(tb.name, tc.output, tc.error):
                        fail_streak += 1
                    else:
                        fail_streak = 0

                # Inject any operator interrupts that arrived during tool execution
                interrupts = self._drain_interrupts()
                if interrupts:
                    for msg in interrupts:
                        self._print(f"\n[bold magenta]⚡ Operator:[/bold magenta] {msg}")
                        self._emit("operator_interrupt", message=msg)
                    tool_results.append({
                        "type": "text",
                        "text": "\n".join(f"[Operator]: {m}" for m in interrupts),
                    })

                # Loop nudge — a soft redirect, not a kill. The agent keeps control;
                # it's just told it's repeating itself and should change approach.
                if nudges:
                    detail = ", ".join(nudges)
                    self._print(f"  [yellow]↻ nudge — repeated call(s): {detail}[/yellow]")
                    self._emit("loop_nudge", detail=detail)
                    tool_results.append({
                        "type": "text",
                        "text": (
                            f"[Engine notice: you've repeated identical tool call(s) — {detail} — "
                            "without new results. Don't run the same call again. Change the tool, "
                            "arguments, target, or approach; or if this line is a dead end, move on "
                            "or conclude it.]"
                        ),
                    })

                # Pivot nudge — a run of failed/empty results means a dead end. This
                # is the semantic loop the exact-match nudge can't see (each retry is
                # a slightly different script/payload). Fires at the threshold and
                # again each time it's crossed anew while the streak persists.
                if pivot_after and fail_streak and fail_streak % pivot_after == 0:
                    self._print(f"  [yellow]⇄ pivot nudge — {fail_streak} failures in a row[/yellow]")
                    self._emit("pivot_nudge", failures=fail_streak)
                    tool_results.append({
                        "type": "text",
                        "text": (
                            f"[Engine notice: {fail_streak} tool calls in a row have failed or "
                            "returned nothing useful. Re-running variations of the same approach is "
                            "not progress — you are likely on a dead end. STOP and step back: bank "
                            "what you have already confirmed now (annotate_finding / record_credential "
                            "/ record_flag), then either try a fundamentally different approach or "
                            "move on. Do not keep tweaking the same payload/script.]"
                        ),
                    })

                # Grind nudge (engagement-level) — many scripts run across the whole
                # engagement with NO new banked result is a no-progress dead end (the
                # 100+ decrypt-loop pattern), even when each script exits cleanly.
                if self.state:
                    grind_n = self.state.grind_nudge_due(grind_threshold)
                    if grind_n:
                        self._print(f"  [yellow]⌀ grind nudge — {grind_n} scripts, nothing banked[/yellow]")
                        self._emit("grind_nudge", scripts=grind_n)
                        tool_results.append({
                            "type": "text",
                            "text": (
                                f"[Engine notice: {grind_n} scripts have run across this engagement "
                                "without banking a single new finding, credential, or flag. That is a "
                                "no-progress grind — you are almost certainly repeating a dead end (e.g. "
                                "retrying the same decryption or exploit with small tweaks). STOP: bank "
                                "anything already proven (annotate_finding / record_credential / "
                                "record_flag), then switch to a fundamentally different approach or move "
                                "on. Tweaking the same thing again is not progress.]"
                            ),
                        })

                    # Reuse nudge (engagement-level) — heavy run_script use, list_scripts
                    # never consulted → near-duplicates piling up.
                    reuse_n = self.state.reuse_nudge_due(reuse_threshold)
                    if reuse_n:
                        self._print(f"  [yellow]♻ reuse nudge — {reuse_n} scripts, list_scripts unused[/yellow]")
                        self._emit("reuse_nudge", scripts=reuse_n)
                        tool_results.append({
                            "type": "text",
                            "text": (
                                f"[Engine notice: {reuse_n} scripts have been written this engagement and "
                                "list_scripts has never been called. You are very likely rewriting "
                                "near-duplicates. Call list_scripts to reuse or adapt one, and fix a "
                                "working script rather than re-authoring it.]"
                            ),
                        })

                    # Foothold-banking nudge (engagement-level) — code execution has
                    # been proven but no verified finding has been banked since. The
                    # foothold is the headline finding; an unrecorded one means a run
                    # can end mid-privesc with $0 of evidence to show for the exec.
                    bank_n = self.state.foothold_bank_due(foothold_bank_after)
                    if bank_n:
                        self._print("  [yellow]🏴 foothold nudge — exec confirmed, nothing banked[/yellow]")
                        self._emit("foothold_nudge", turns=bank_n)
                        tool_results.append({
                            "type": "text",
                            "text": (
                                "[Engine notice: code execution on the target has been CONFIRMED but you "
                                "have not banked it. The foothold is the headline finding — everything "
                                "after builds on it, and this run can hit its turn cap mid-privesc with "
                                "nothing recorded. Call annotate_finding for the code-execution/access NOW "
                                "— verified=true, with the command and its output as evidence — before "
                                "continuing. Put any credentials in record_credential, not the finding.]"
                            ),
                        })

                messages.append({"role": "user", "content": tool_results})

                # Progress accounting for the sliding budget: did this turn bank
                # anything real? If so, reset the no-progress counter so a working
                # exploit chain keeps its budget; otherwise spend one turn of it.
                fp = self._progress_fingerprint(run)
                if self._forward_progress(fp, last_progress_fp):
                    no_progress_turns = 0
                else:
                    no_progress_turns += 1
                last_progress_fp = fp

            else:
                # Reached only when extend-on-progress is OFF (range-bounded loop).
                self._print("[yellow]Max turns reached — stopping.[/yellow]")
                run.status = "max_turns"
                self._emit("agent_done", agent=run.agent, status=run.status,
                           findings_count=len(run.findings), cost=run.estimated_cost_usd,
                           max_turns=max_turns)
                return run

            if run.status not in ("concluded", "aborted"):
                run.status = "complete"

        except APIAccountLimitError:
            run.status = "account_limit"
            raise  # let the pipeline handle messaging + resume

        except APIAuthError:
            run.status = "auth_failed"
            raise  # let the pipeline handle messaging

        except Exception as e:
            run.status = "failed"
            self._print(f"[red]Engagement failed: {e}[/red]")
            raise

        finally:
            run.end_time = now_local()
            # When the run never produced a tool-free close-out (turn cap, conclude,
            # error), don't hand off a bare scrap of reasoning — synthesize a real
            # handoff from what the run actually DID (findings, recent meaningful
            # actions, live shells) so the next agent inherits the thread instead of
            # a stub. A clean text close-out (run.summary already set) is kept as-is.
            if not run.summary:
                run.summary = self._synthesize_handoff(run, last_text)
            if run.summary:
                # Mask any recorded secret the agent slipped into prose — the next
                # agent reads real creds from the Credentials section, and this keeps
                # the operator-facing saved run clean.
                run.summary = self._redact_secrets(run.summary)
            if self.state and run.summary:
                self.state.add_handoff(agent.name, run.summary)
            self._save_run(run)

        self._print_summary(run)
        return run

    # ── intercepted tool handlers ─────────────────────────────────────────────

    _DEDUP_NOTE = (
        "current_findings lists every finding recorded so far this engagement. Before you "
        "annotate a NEW finding, check it: if this issue is already there — even worded "
        "differently — do NOT create a second one; call annotate_finding again with that "
        "finding's finding_id to refine/verify it instead. One issue = one finding."
    )

    def _findings_digest(self, run: EngagementRun,
                         all_findings: Optional[list] = None) -> list[dict]:
        """Compact list of all findings so far (id/title/severity/verified). Returned
        from every annotate_finding call so the agent can self-dedup — the start-of-run
        context block is not refreshed mid-run, so this is its live view."""
        seen: dict = {}
        for f in list(run.findings) + list(all_findings or []):
            if f.id not in seen:
                seen[f.id] = {"id": f.id, "title": f.title,
                              "severity": f.severity, "verified": f.verified}
        return list(seen.values())

    def _handle_annotation(self, inputs: dict, run: EngagementRun, target: str,
                           all_findings: Optional[list] = None) -> dict:
        finding_id = inputs.get("finding_id")

        # Update existing finding — search this run first, then prior runs
        if finding_id:
            existing = next((f for f in run.findings if f.id == finding_id), None)
            if not existing and all_findings:
                existing = next((f for f in all_findings if f.id == finding_id), None)
            if not existing:
                return {"status": "error", "message": f"finding_id {finding_id!r} not found"}
            if inputs.get("verified") is not None:
                existing.verified = inputs["verified"]
            if inputs.get("severity"):
                existing.severity = inputs["severity"]
            if inputs.get("description"):
                existing.description = self._redact_secrets(inputs["description"])
            if inputs.get("evidence"):
                existing.evidence.update(self._redact_obj(inputs["evidence"]))
            status = "confirmed" if existing.verified else "updated"
            color  = SEV_COLOR.get(existing.severity, "white")
            tag    = "[CONFIRMED]" if existing.verified else "[updated]"
            self._print(f"  [{color}]{tag}[/{color}] [{existing.severity.upper()}] {existing.title}")
            self._emit_annotation(existing)
            return {"status": status, "finding_id": existing.id}

        # Deduplication — check against current run AND cross-agent findings
        # from prior runs in this pipeline (all_findings).
        all_existing = list(run.findings)
        if all_findings:
            seen_ids = {f.id for f in all_existing}
            all_existing += [f for f in all_findings if f.id not in seen_ids]
        title = self._redact_secrets(inputs.get("title", "Untitled"))
        ann_target = inputs.get("target", target)

        if self.state:
            duplicate = self.state.find_duplicate(
                title, ann_target, all_existing, new_type=inputs.get("type"))
        else:
            duplicate = None

        if duplicate:
            # Update the existing one instead of creating a new one
            if inputs.get("verified") and not duplicate.verified:
                duplicate.verified = True
            if inputs.get("evidence"):
                duplicate.evidence.update(self._redact_obj(inputs["evidence"]))
            self._print(f"  [dim][dedup][/dim] [{duplicate.severity.upper()}] {duplicate.title}")
            self._emit_annotation(duplicate)
            return {"status": "deduplicated", "finding_id": duplicate.id,
                    "note": f"Merged into existing finding {duplicate.id!r} ({duplicate.title!r}) — it was the same issue.",
                    "current_findings": self._findings_digest(run, all_findings)}

        finding = Finding(
            type=inputs.get("type", "recon"),
            severity=inputs.get("severity", "info"),
            title=title,
            description=self._redact_secrets(inputs.get("description", "")),
            target=ann_target,
            evidence=self._redact_obj(inputs.get("evidence", {})),
            verified=inputs.get("verified", False),
        )
        run.findings.append(finding)

        color = SEV_COLOR.get(finding.severity, "white")
        tag   = "[potential]" if not finding.verified else "[CONFIRMED]"
        self._print(f"  [{color}]{tag}[/{color}] [{finding.severity.upper()}] {finding.title}")
        self._emit_annotation(finding)
        return {"status": "annotated", "finding_id": finding.id,
                "current_findings": self._findings_digest(run, all_findings),
                "note": self._DEDUP_NOTE}

    def _emit_annotation(self, finding: Finding) -> None:
        """Emit a full annotation event so the UI can show live finding detail."""
        self._emit("annotation",
                   severity=finding.severity, title=finding.title,
                   verified=finding.verified, finding_id=finding.id,
                   ftype=finding.type, description=finding.description,
                   target=finding.target, evidence=finding.evidence)

    def _handle_followup(self, inputs: dict, source_agent: str) -> dict:
        agent_name = inputs.get("agent_name", "")
        target     = inputs.get("target", "")
        context    = inputs.get("context", "")

        if not agent_name or not target:
            return {"queued": False, "error": "agent_name and target are required"}

        if self.state:
            if not self.state.in_scope(target):
                self._print(f"  [yellow][followup][/yellow] {target} rejected — out of scope")
                self._emit("followup_rejected", agent_name=agent_name, target=target)
                return {
                    "queued": False,
                    "error": (
                        f"Target {target!r} is outside the engagement scope. "
                        "Do not pivot to it. If you believe it is in scope, annotate it "
                        "as a recon finding so the operator can expand scope (/scope add)."
                    ),
                }
            queued = self.state.request_followup(agent_name, target, context)
            msg = f"Queued {agent_name} on {target}" if queued else "Already queued"
            self._print(f"  [magenta][followup][/magenta] {msg}")
            self._emit("followup_queued", agent_name=agent_name, target=target, queued=queued)
            return {"queued": queued, "agent_name": agent_name, "target": target}

        return {"queued": False, "error": "No engagement state attached to orchestrator"}

    def _handle_record_plan(self, inputs: dict, source_agent: str) -> dict:
        if not self.state:
            return {"recorded": False, "error": "No engagement state attached"}
        surface_id = inputs.get("surface_id", "")
        items      = inputs.get("items", []) or []
        if not surface_id:
            return {"recorded": False, "error": "surface_id is required"}
        plan = self.state.record_plan(
            surface_id, items, created_by=source_agent, notes=inputs.get("notes", ""),
        )
        self._print(f"  [magenta][plan][/magenta] {len(plan.items)} item(s) for {plan.surface_label or surface_id}")
        self._emit("plan_recorded", surface_id=surface_id,
                   surface_label=plan.surface_label, item_count=len(plan.items),
                   items=[i.model_dump() for i in plan.items])
        return {"recorded": True, "item_count": len(plan.items)}

    def _handle_register_surface(self, inputs: dict, source_agent: str) -> dict:
        if not self.state:
            return {"registered": False, "error": "No engagement state attached"}
        host = inputs.get("host", "")
        if not host:
            return {"registered": False, "error": "host is required"}
        surface = self.state.add_surface(
            host=host, service=inputs.get("service", ""), port=inputs.get("port"),
            component=inputs.get("component", ""), origin=inputs.get("origin", "deeper"),
            notes=inputs.get("notes", ""),
        )
        if surface is None:
            self._print(f"  [yellow][surface][/yellow] {host} rejected — out of scope")
            self._emit("surface_rejected", host=host)
            return {
                "registered": False,
                "error": f"{host!r} is out of scope. Annotate it as recon if it should be in scope.",
            }
        self._print(f"  [magenta][surface][/magenta] {surface.label}  ({surface.origin})")
        self._emit("surface_registered", surface_id=surface.id,
                   label=surface.label, origin=surface.origin)
        return {"registered": True, "surface_id": surface.id, "label": surface.label}

    # ── large-output offloading ────────────────────────────────────────────────

    # ── background jobs ─────────────────────────────────────────────────────────

    @staticmethod
    def _inject_user_text(messages: list, text: str) -> None:
        """Append text to the last user message (or add one) — same pattern as
        operator interrupts, so role alternation stays valid."""
        if messages and messages[-1]["role"] == "user":
            last = messages[-1]["content"]
            if isinstance(last, list):
                last.append({"type": "text", "text": text})
            else:
                messages[-1]["content"] = last + "\n\n" + text
        else:
            messages.append({"role": "user", "content": text})

    def _ingest_job(self, job: Job, agent_name: str, run: Optional[EngagementRun]) -> str:
        """Handle a completed background job on the main thread: update state,
        cache, events, and return a summary string to inject into the agent."""
        name   = job.label
        result = job.result if isinstance(job.result, dict) else {}

        if job.status == "failed":
            self._print(f"\n[red]⏗ {name} job failed:[/red] {job.error}")
            self._emit("job_done", name=name, job_id=job.id, status="failed", error=job.error)
            return f"[Background job '{name}' (id {job.id}) FAILED: {job.error}]"

        summary = _result_summary(name, result)
        cmd = _redact_command(result["_command"]) if result.get("_command") else None
        self._print(f"\n[magenta]⏗ {name}[/magenta]  done ({job.runtime_s:.0f}s) — {summary}")
        self._emit("job_done", name=name, job_id=job.id, status="done",
                   summary=summary, command_str=cmd, runtime=round(job.runtime_s, 1))

        if self.state and "error" not in result:
            self.state.log_tool(agent=agent_name, tool_name=name, command=cmd,
                                summary=summary, result=result)
            self.state.store_cache(name, job.inputs, result, summary)
            self.state.ingest_tool_result(name, result, source_agent=agent_name)
            self._emit_state_update()
            # hashcat recovered plaintext(s) → surface as credential event(s)
            if name == "hashcat_crack":
                for c in result.get("cracked", []):
                    pw = c.get("plaintext")
                    if pw:
                        self._emit("credential", cred_type="password",
                                   username=c.get("username") or "", secret=pw,
                                   secret_masked=mask_secret(pw), secret_format="",
                                   location=c.get("location") or "cracked hash", verified=True)

        if run is not None:
            tc = ToolCall(id=f"job-{job.id}", tool_name=name, inputs=job.inputs)
            tc.output = _cap_for_persist(result)
            tc.command_str = cmd
            run.tool_calls.append(tc)

        llm_view = self._offload_for_llm(result, name)
        return (f"[Background job '{name}' (id {job.id}) finished — {summary}]\n"
                + json.dumps(llm_view)[:1500])

    def flush_jobs(self) -> None:
        """Wait for all outstanding background jobs and fold their results into
        state. Called before the reporting phase so nothing is left running."""
        if not (self._jobs.has_pending() or self._jobs.poll_completed()):
            # nothing running and nothing uncollected
            pass
        running = self._jobs.running()
        if running:
            self._print(f"[dim]Waiting on {len(running)} background job(s) before finishing…[/dim]")
            self._emit("jobs_flushing", count=len(running))
        self._jobs.wait_all()
        for job in self._jobs.poll_completed():
            self._ingest_job(job, "background", None)

    def _ui_state_sig(self) -> tuple:
        """A cheap fingerprint of everything the TUI panels render from a
        state_update (ports, surfaces, OS/hostnames, creds). Computed without
        pydantic serialization so the common 'nothing changed' case is fast."""
        st = self.state
        def g(o, k):
            return o.get(k) if isinstance(o, dict) else getattr(o, k, None)
        ports = tuple((g(p, "host"), g(p, "port"), g(p, "service"),
                       g(p, "product"), g(p, "version"), g(p, "hostname"))
                      for p in st.recon.open_ports)
        surfs = tuple((g(s, "host"), g(s, "port"), g(s, "service")) for s in st.surfaces)
        os_i  = tuple(sorted(st.recon.os_info.items()))
        hns   = tuple(sorted(st.recon.host_names.items()))
        creds = tuple((c.cred_type, c.username, c.location or c.service,
                       c.secret_masked, tuple(c.used_at), c.verified)
                      for c in st.credentials)
        return (ports, surfs, os_i, hns, creds)

    def _emit_state_update(self) -> None:
        if not self.state:
            return
        # Skip when nothing the UI cares about changed — avoids re-serializing and
        # re-posting the whole state after every tool call (the TUI-freeze cause).
        sig = self._ui_state_sig()
        if sig == self._last_ui_state_sig:
            return
        self._last_ui_state_sig = sig
        self._emit("state_update",
                   recon=self.state.recon.model_dump(),
                   credentials=[c.model_dump() for c in self.state.credentials],
                   surfaces=[s.model_dump() for s in self.state.surfaces])

    def _handle_list_scripts(self, inputs: dict) -> dict:
        if not self.state or not self.state.scripts:
            return {"scripts": [], "count": 0,
                    "note": "No scripts written yet this engagement."}
        try:
            limit = int(inputs.get("limit", 20) or 20)
        except (TypeError, ValueError):
            limit = 20
        out = []
        for s in reversed(self.state.scripts[-limit:]):   # newest first
            entry = {"purpose": s.get("purpose", ""), "language": s.get("language", ""),
                     "path": s.get("path", "")}
            try:
                txt = Path(s["path"]).read_text(encoding="utf-8", errors="replace")
                entry["preview"] = txt[:1500]
                if len(txt) > 1500:
                    entry["preview_truncated"] = True
            except Exception:
                entry["preview"] = "(script file no longer available)"
            out.append(entry)
        return {"scripts": out, "count": len(self.state.scripts),
                "note": "Reuse or adapt one of these instead of writing a near-duplicate."}

    def _handle_artifact_query(self, name: str, inputs: dict) -> dict:
        aid = inputs.get("artifact_id", "")
        if name == "grep_artifact":
            return self._artifacts.grep(
                aid, inputs.get("pattern", ""),
                ignore_case=inputs.get("ignore_case", True),
                context=inputs.get("context", 0),
                max_matches=inputs.get("max_matches", 200),
                invert=inputs.get("invert", False),
            )
        return self._artifacts.read(
            aid, offset=inputs.get("offset", 0), limit=inputs.get("limit", 200),
        )

    def _cap_artifact_view(self, result):
        """Bound a read_artifact/grep_artifact result for the prompt by truncating its
        content IN PLACE — never re-offloading it to a new artifact. The agent
        explicitly asked to read this slice; storing it again and pointing back at it
        creates an infinite read→offload→read loop (this is what left the report agent
        spinning on artifacts and never synthesising)."""
        if not isinstance(result, dict):
            return result
        content = result.get("content")
        if isinstance(content, str) and len(content) > _ARTIFACT_VIEW_CAP:
            out = dict(result)
            out["content"] = content[:_ARTIFACT_VIEW_CAP]
            out["_truncated"] = (f"content truncated to {_ARTIFACT_VIEW_CAP} chars — read "
                                 "a smaller window with offset/limit, or use grep_artifact.")
            return out
        return result

    def _offload_for_llm(self, result, tool_name: str):
        """Return a context-safe view of a tool result.

        Oversized string fields are written to text artifacts (newlines intact,
        so grep_artifact works), and if the whole result is still too large it is
        offloaded wholesale. The original `result` object is never mutated — the
        full version continues to flow to the log, cache, and engagement state.
        """
        if not isinstance(result, dict):
            text = result if isinstance(result, str) else str(result)
            if len(text) <= _RESULT_OFFLOAD_CHARS:
                return result
            art = self._artifacts.store(text, label=tool_name)
            self._emit("artifact_stored", tool=tool_name, artifact_id=art["artifact_id"],
                       lines=art["lines"], bytes=art["bytes"])
            return {"_artifact_id": art["artifact_id"], "_artifact_lines": art["lines"],
                    "_note": "Output too large; stored as artifact. Use grep_artifact/read_artifact.",
                    "preview": text[:1200]}

        view = dict(result)
        for key, val in list(view.items()):
            if isinstance(val, str) and len(val) > _FIELD_OFFLOAD_CHARS:
                art = self._artifacts.store(val, label=f"{tool_name}_{key}")
                self._emit("artifact_stored", tool=tool_name, field=key,
                           artifact_id=art["artifact_id"], lines=art["lines"], bytes=art["bytes"])
                view[key] = (val[:1000] +
                             f"\n…[{art['lines']} lines total — artifact {art['artifact_id']}; "
                             f"grep_artifact/read_artifact to read the rest]")
                view[f"_{key}_artifact_id"] = art["artifact_id"]

        if len(json.dumps(view, default=str)) <= _RESULT_OFFLOAD_CHARS:
            return view

        # Whole result still too big — offload the JSON and return a compact stub.
        art = self._artifacts.store(json.dumps(result, indent=2, default=str),
                                    label=f"{tool_name}_result", ext="json")
        self._emit("artifact_stored", tool=tool_name, artifact_id=art["artifact_id"],
                   lines=art["lines"], bytes=art["bytes"])
        stub = {"_artifact_id": art["artifact_id"], "_artifact_lines": art["lines"],
                "_note": "Result too large; full JSON stored as artifact. "
                         "Use grep_artifact/read_artifact.",
                "summary": _result_summary(tool_name, result)}
        for k, v in result.items():
            if isinstance(v, (int, float, bool)) or (isinstance(v, str) and len(v) < 120):
                stub[k] = v
        return stub

    def _handle_record_credential(self, inputs: dict, source_agent: str) -> dict:
        if not self.state:
            return {"recorded": False, "error": "No engagement state attached"}
        secret = (inputs.get("secret") or "").strip()
        if not secret:
            return {"recorded": False, "error": "secret is required (the credential value)"}

        cred = self.state.add_credential(
            cred_type=inputs.get("type", "password") or "password",
            secret=secret,
            username=inputs.get("username") or None,
            secret_format=inputs.get("secret_format", "") or "",
            location=inputs.get("location", "") or "",
            service=inputs.get("service", "") or "",
            port=inputs.get("port"),
            source_agent=source_agent,
            verified=bool(inputs.get("verified", False)),
        )
        if cred is None:
            return {"recorded": False, "error": "no credential value"}

        label = f"{cred.username + ':' if cred.username else ''}{cred.secret_masked}"
        self._print(f"  [magenta][cred][/magenta] [{cred.cred_type}] {label}"
                    + (f"  @ {cred.location}" if cred.location else ""))
        self._emit("credential",
                   cred_type=cred.cred_type, username=cred.username or "",
                   secret=cred.secret, secret_masked=cred.secret_masked,
                   secret_format=cred.secret_format, location=cred.location,
                   used_at=list(cred.used_at), verified=cred.verified)
        return {"recorded": True, "cred_type": cred.cred_type, "username": cred.username}

    def _handle_record_service(self, inputs: dict, source_agent: str) -> dict:
        if not self.state:
            return {"recorded": False, "error": "No engagement state attached"}
        host = (inputs.get("host") or "").strip()
        if not host:
            return {"recorded": False, "error": "host is required (the target IP)"}
        item = self.state.annotate_service(
            host=host, port=inputs.get("port"),
            service=inputs.get("service", "") or "",
            app=inputs.get("app", "") or "",
            version=inputs.get("version", "") or "",
            tech=inputs.get("tech", "") or "",
            os=inputs.get("os", "") or "",
            hostname=inputs.get("hostname", "") or "",
            source_agent=source_agent,
        )
        fp = (f"{item['app']} {item['version']}".strip()) if item.get("app") else ""
        label = f"{host}{':' + str(item['port']) if item.get('port') else ''}"
        detail = " ".join(x for x in (item.get("service"), fp, item.get("tech"), item.get("os")) if x)
        self._print(f"  [cyan][service][/cyan] {label}  {detail}")
        self._emit("service", host=host, port=item.get("port"),
                   service=item.get("service", ""), app=item.get("app", ""),
                   version=item.get("version", ""), tech=item.get("tech", ""),
                   os=item.get("os", ""), hostname=inputs.get("hostname", "") or "")
        return {"recorded": True, "host": host, "port": item.get("port")}

    def _handle_record_flag(self, inputs: dict, source_agent: str) -> dict:
        if not self.state:
            return {"recorded": False, "error": "No engagement state attached"}
        value = (inputs.get("value") or "").strip()
        if not value:
            return {"recorded": False, "error": "value is required (the flag string)"}
        flag = self.state.add_flag(
            value=value, location=inputs.get("location", "") or "",
            source_agent=source_agent, verified=bool(inputs.get("verified", False)),
        )
        if flag is None:
            return {"recorded": False, "error": "empty flag"}
        tag = "✓" if flag.verified else "?"
        self._print(f"  [bold green][FLAG {tag}][/bold green] {flag.value}"
                    + (f"  @ {flag.location}" if flag.location else ""))
        self._emit("flag", value=flag.value, location=flag.location, verified=flag.verified)
        return {"recorded": True, "value": flag.value}

    # ── final-response enrichment ─────────────────────────────────────────────

    def _extract_and_enrich(self, text: str, run: EngagementRun, target: str):
        match = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
        if not match:
            return
        try:
            data = json.loads(match.group(1))
        except json.JSONDecodeError:
            return

        if not run.technical_overview and data.get("technical_overview"):
            run.technical_overview = self._redact_secrets(data["technical_overview"])
        if not run.executive_summary and data.get("executive_summary"):
            run.executive_summary = self._redact_secrets(data["executive_summary"])

        for f in data.get("findings", []):
            remediation = f.get("remediation", [])
            if isinstance(remediation, str):
                remediation = [remediation]

            # Strip any credential secrets the model may have written into the finding.
            f["title"]       = self._redact_secrets(f.get("title", ""))
            f["description"] = self._redact_secrets(f.get("description", ""))
            f["impact"]      = self._redact_secrets(f.get("impact", ""))
            if f.get("evidence"):
                f["evidence"] = self._redact_obj(f["evidence"])

            cvss = None
            if f.get("cvss"):
                c = f["cvss"]
                # Robust against the model emitting nulls or non-numeric scores: a
                # JSON `null` makes .get(key, default) return None (the key exists), so
                # float(None) would raise "float ... NoneType". Coerce safely.
                def _num(v):
                    try:
                        return float(v)
                    except (TypeError, ValueError):
                        return 0.0
                cvss = CvssScores(
                    vector=c.get("vector") or "",
                    base_score=_num(c.get("base_score")),
                    temporal_score=_num(c.get("temporal_score")),
                    environmental_score=_num(c.get("environmental_score")),
                )

            title = f.get("title", "")
            ftype = f.get("type")
            existing = next(
                (e for e in run.findings if e.title.lower() == title.lower()), None
            )
            if existing is None:
                # fuzzy match so a reworded title enriches, not duplicates
                from core.utils import title_similarity
                existing = next(
                    (e for e in run.findings
                     if (ftype is None or e.type == ftype)
                     and title_similarity(title, e.title) >= 0.6), None
                )

            if existing:
                if cvss:
                    existing.cvss = cvss
                if f.get("impact"):
                    existing.impact = f["impact"]
                if remediation:
                    existing.remediation = remediation
                final_desc = f.get("description", "")
                if len(final_desc) > len(existing.description):
                    existing.description = final_desc
                if f.get("severity"):
                    existing.severity = f["severity"]
            else:
                finding = Finding(
                    type=f.get("type", "recon"),
                    severity=f.get("severity", "info"),
                    title=title,
                    description=f.get("description", ""),
                    impact=f.get("impact", ""),
                    target=target,
                    evidence=f.get("evidence", {}),
                    cvss=cvss,
                    remediation=remediation,
                )
                run.findings.append(finding)
                color = SEV_COLOR.get(finding.severity, "white")
                self._print(
                    f"  [bold {color}][{finding.severity.upper()}][/bold {color}] {finding.title}"
                )
                self._emit_annotation(finding)

    # ── utilities ─────────────────────────────────────────────────────────────

    def _print_summary(self, run: EngagementRun):
        counts: dict = {}
        for f in run.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        confirmed   = sum(1 for f in run.findings if f.verified)
        unconfirmed = len(run.findings) - confirmed

        lines = [
            f"Status: {run.status}  |  Findings: {len(run.findings)}  "
            f"(confirmed: {confirmed}  potential: {unconfirmed})"
        ]
        for sev in ["critical", "high", "medium", "low", "info"]:
            if counts.get(sev):
                lines.append(f"  {sev.upper()}: {counts[sev]}")

        self._print(Panel("\n".join(lines), title=f"Run {run.id} complete"))
        self._emit("agent_done", agent=run.agent, status=run.status,
                   findings_count=len(run.findings), cost=run.estimated_cost_usd)

    def _save_run(self, run: EngagementRun):
        if not self._save_individual_runs:
            return
        safe_target = _safe_filename_part(run.target)
        safe_agent  = _safe_filename_part(run.agent)
        path = self.results_dir / f"{run.id}_{safe_agent}_{safe_target}.json"
        path.write_text(run.model_dump_json(indent=2), encoding="utf-8")
