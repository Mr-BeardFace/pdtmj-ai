# Technical Deep Dive

## Orchestration pipeline

The autonomous engine is built around the **FrontierDriver**, which subclasses `ParallelDriver` for its plumbing (agent invocation, exploit-approval gate, concurrency, run bookkeeping) but replaces the control loop. Instead of coverage-first, it always pushes the single highest-value lead toward the objective.

### Phase 0 — staged discovery (no LLM)

Discovery is deterministic and hardcoded — no LLM deliberation. Two nmap stages:

1. **Stage 1** — top-1000 TCP with `-sV` (version detection). Synchronous, returns in seconds. Results are ingested into state immediately via `state.ingest_tool_result("nmap_scan", result)`, seeding the board with hosts, ports, and version banners. The UI is refreshed with `_refresh_ui()` so the Hosts pane shows discovered ports before any agent runs.
2. **Stage 2** — deep TCP (top-45000) + UDP (top-250) discovery, then `-sV -sC` on every open port found. Kicked off as a single background job via `JobManager`. Results fold into recon automatically when the job finishes (the orchestrator drains completed jobs at each turn boundary and before the report).

After the sweep, the LLM enumeration agent runs for service *identification* only — fingerprinting discovered ports, not re-running nmap.

### Surfaces and the board

`state.derive_surfaces_from_recon(origin="initial")` turns discovered host:port:service tuples into `Surface` objects. Each surface is a (host, service, port) unit that the orchestrator can route to a specialist agent. No surfaces from discovery = one default surface added from the primary target.

### Lead seeding and the strategist

Two tiers of lead generation, by cost:

- **Deterministic ingest** (`core/ingest.py`) — runs after every step, free. Pure data transforms: findings become vuln/escalation leads, credentials become access leads. A verified-but-unexecuted critical finding (e.g. "Flowise running as root") becomes a high-reach escalation lead automatically, rising to the top of the board. Keywords in the finding title/technique map to kill-chain rungs: root hints → `root`, privesc hints → `privesc`, RCE hints → `exploited`. Severity influences the prior probability (critical: +0.30, high: +0.22, medium: +0.12).
- **LLM strategist consult** (`core/strategist.py`) — expensive, fires only on material change (new leads landed, or frontier advanced). Asks a fast model, given the full board and objective, for inferred/chained leads the keyword ingest would miss (e.g. "you have an SMTP password; the SSH user reuses it"). Strictly additive — no LLM, error, or junk output leaves the deterministic board untouched.

### The FrontierController loop

`core/frontier.py` — the control loop, decoupled from LLM/orchestrator. Takes a `work_lead` callable and drives the board:

```
while budget remains and leads exist:
    if external stop (operator /pause, /end): break
    if objective complete and persona halts (ctf): break
    lead = store.pick_top()          # highest EV toward objective
    if none: frontier cold → breadth_fallback() → stop
    result = work_lead(lead)         # spawns agent run(s)
    fold new leads + evidence into state
    if advanced: confirm lead, frontier moves, preempt lower work
    if refuted: release lead, loop pops next-best
    if inconclusive: re-queue until attempts_cap (default 3)
```

Key parameters: `max_actions` (global lead budget), `attempts_cap` (times one lead is re-worked before exhaustion). Non-halting personas (pentest) keep working remaining leads after the objective is met.

### _work_lead — agent dispatch

The `FrontierDriver._work_lead(lead)` callback:

1. **Exploit gate check** — exploit-class leads (anything past enumeration) need approval. CTF auto-approves. Pentest resolves lazily at the moment exploitation actually starts.
2. **_plan_lead** — routes the lead to an agent with a budget:
   - `kind=cred` → exploitation agent, spray-the-known-secret objective, full foothold budget
   - `kind=surface/service` or low reach → enumeration agent (or specialist), enum turn budget
   - `kind=escalation` or high reach (foothold+) → post-exploitation agent if a foothold exists, else exploitation agent, full kill-chain budget
   - AD domain techniques → AD specialist regardless of surface service tag
   - Generic vuln → exploitation agent
3. **Agent run** — `_run_agent(agent, target, objective, max_turns=budget)`
4. **Result classification** — compares findings/credentials/flags before vs after:
   - `reach_from_evidence()` — checks flags, verified credentials, verified findings against the kill-chain
   - `classify_outcome()` → `advanced` / `refuted` / `inconclusive`
   - Refuted = no progress AND no new leads spawned (the bounded agent budget makes "nothing came back" a real signal)
5. **New leads** — `leads_from_findings()` + `leads_from_credentials()` → returned to the controller for re-ranking
6. **Strategist** — `_maybe_strategize()` fires the LLM consult if material change detected

### The orchestrator per-turn

Each agent turn, the orchestrator (`core/orchestrator.py`):

- Builds the system prompt: persona instructions + base instructions + agent system prompt + schema instructions
- Gates tools by persona and agent role (CTF gets `record_flag`; pentest/redteam get `record_ioc`; `load_playbook` available to non-planning/non-reporting agents)
- Intercepts tool calls before they hit the registry — `annotate_finding`, `record_credential`, `shell_exec`, etc. are processed by the orchestrator for state management, not passed to external tools
- High-impact tools (`hydra`, `sqlmap_scan`, `coercer`, `run_script`, etc.) pause for operator confirmation when `tool_gate=gated`
- Web tools (`web_search`, `fetch_url`) are scrubbed against live engagement state to prevent leaking target-specific information

---

## Analyst pipeline

The analyst is a background daemon that watches your terminal and maintains a tactical picture in the engagement DB. It runs in `pentest` and `redteam` only.

### Stage 1 — TTY capture

Shell hooks (`shell/pdtmj-hooks.zsh`) wrap your session in `script(1)` when an op is active. Every byte of terminal I/O — prompts, commands, output, escape sequences — is captured to a `.raw` file in the op's `logs/` directory. SSH and evil-winrm wrappers ensure remote sessions are captured too. A `preexec` hook also writes each command to a separate `.cmd.log` with timestamps.

### Stage 2 — log processor

`shell/log_processor.py` tails `.raw` files and writes clean `.log` files:

- **CursorRenderer** — interprets raw TTY escape sequences (cursor movement, line erasure, character insertion) to reconstruct what actually appeared on screen, line by line
- **Alt-screen filtering** — a state machine tracks `\x1b[?1049h` (enter alt-screen) and `\x1b[?1049l` (leave alt-screen) transitions. Everything between is suppressed — this filters out TUI, vim, less, and other full-screen applications so the analyst only sees command-line output
- Output: clean text lines with prompts rendered inline (e.g. `user@host:~$ nmap target`)

### Stage 3 — LogWatcher

`core/log_watcher.py` polls the log directory at a configurable interval (default 10s, tunable via `analyst_interval`):

- Tracks per-file byte cursors — on each poll, reads only new bytes since the last cursor position
- Cursors are persisted to the engagement DB via `store.set_log_cursor()` and restored on daemon restart via `store.load_log_cursors()` — so the analyst resumes where it left off
- Skips files named `sidesaddle`, `debug`, `pdtmj` (internal tool output, not operator activity)
- New bytes are passed directly to `analyst.feed(path, raw_bytes)` — no buffering, no prompt boundary detection

### Stage 4 — debounce and batching

`LogAnalyst.feed()` receives raw bytes, runs them through `parse_chunks()` to extract structured command/output pairs, and adds them to a pending queue:

- **Quiet debounce** — waits `analyst_debounce` seconds (default 15s) after the last chunk before firing analysis. This batches rapid output (e.g. a fast nmap scan producing many lines) into one analysis call.
- **Max wait** — regardless of debounce, fires after 60s from the first pending chunk. Prevents indefinite buffering during long-running commands.
- The drain loop checks every 5s: `if age < debounce AND waiting < 60s: continue`. Otherwise, the batch is flushed to `_analyse()`.

### Stage 5 — micro-model extraction

Before the main analysis, chunks tagged as `raw` or `remote-raw` (garbled TTY data from webshells, netcat pipes, etc.) are cleaned up by a cheap micro-model (default: Haiku):

- The micro-model receives the raw command + output and calls an `extract_log` tool to return structured extractions: cleaned command, cleaned output, remote user/host/privilege indicators
- Well-parsed chunks (from clean terminal sessions) pass through untouched
- A single raw chunk may produce multiple cleaned chunks (e.g. a pasted multi-command sequence)

### Stage 6 — LLM analysis

The main analysis call sends:

- **System prompt** — the full analyst persona: rules for tagging commands (op/local/unknown), credential extraction, finding criteria, lead quality rules, failure diagnosis, protocol fallback knowledge, and a phase hint based on the current frontier position
- **User message** — the current engagement state summary (all known hosts, creds, findings, open leads, recent advisories) + the new log content wrapped in `<TARGET_OUTPUT>` tags (treated as untrusted data)
- **Tool** — a single `update_engagement_state` tool call that returns structured arrays: beacons, hosts, surfaces, credentials, findings, leads, auth_attempts, facts, lead_updates, version_lookups, persistence, and activities

The LLM tags each command as `op` (engagement-related), `local` (setup noise), or `unknown`. Only `op`-tagged commands with output generate findings, leads, and surfaces. Credentials are extracted from ALL commands regardless of tag (a `cat` on a local file might reveal a target password).

### Stage 7 — DB write and TUI refresh

The tool call response is parsed and written to the engagement DB in one transaction: new hosts, credentials (deduped by username+secret), findings (deduped by title+target), leads (deduped by intent slug), lead status updates, surfaces, facts (upserted by topic), auth attempts, persistence records, activities, and version lookups (which trigger background searchsploit/CVE lookups between cycles).

The TUI polls the DB every 2s using `PRAGMA data_version` — a single integer comparison. When the version increments (meaning any write occurred), it does a full refresh of all panes: activity log, hosts, credentials, findings, and leads.
