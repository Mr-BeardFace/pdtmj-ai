# Configuration Reference

All settings are runtime-tunable via `/config <key> <value>` in the TUI or `saddle config <key> <value>` from the shell. Settings are grouped by function and filtered by the active persona — you only see what applies.

## Engagement

| Setting | Type | Personas | Description |
|---------|------|----------|-------------|
| `exploitation` | bool | pentest-ctf, pentest | Enable the plan → exploit → validate phase. Off = assessment-only (enumerate + report). |
| `confirm_exploit` | bool | pentest-ctf, pentest | Pause and ask the operator before each exploit action. CTF defaults to off (auto-approved). |
| `tool_gate` | str | pentest | `autonomous` = run freely. `gated` = pause for confirmation before each high-impact tool call (brute-force, active exploitation, coercion/relay, arbitrary code execution on target). |
| `enum_turns` | int | pentest-ctf, pentest | Turn budget for each staged enumeration pass. Enumeration gathers intel without banking findings, so the progress-extension window never fires — this is the hard cap. |
| `agent_turns` | int | pentest-ctf, pentest | Per-agent turn budget. 0 = unlimited. |
| `sliding_turns` | bool | pentest-ctf, pentest | Treat the turn budget as a sliding window that resets on progress (new finding, new credential, new lead). |
| `turn_ceiling_factor` | int | pentest-ctf, pentest | Absolute turn ceiling = max_turns × this factor. Prevents runaway sliding windows. |
| `time_limit` | str | pentest-ctf, pentest | Wall-clock limit for autonomous runs (e.g. `30m`, `1h30m`, `2h`). Null = no limit. |
| `validation` | bool | pentest | Dedicated agent independently reproduces each finding before the report. |
| `package_install` | bool | pentest | Let agents pip/apt-install missing tooling on the fly. |
| `reporting` | bool | pentest-ctf | Run the report-writer agent automatically at pipeline end. |
| `web_search` | bool | pentest-ctf | Allow the `web_search` + `fetch_url` tools (for researching CVEs, techniques, etc.). |
| `temp` | float | all | Sampling temperature baseline (0.0–2.0). Null = provider default. Per-agent overrides via `/agent set temp`. |

## Parallelism

> Parallelism settings apply to `pentest-ctf` and `pentest` only.

| Setting | Type | Description |
|---------|------|-------------|
| `parallel` | bool | Work independent surfaces + hypotheses concurrently. |
| `parallel_agents` | int | Global cap on concurrent agent loops. |
| `surface_fanout` | int | Surfaces worked at once (1 = serial). |
| `hypothesis_fanout` | int | Hypotheses proved/refuted at once per surface (1 = serial). |
| `hypothesis_turns` | int | Per-worker turn budget for one prove/refute hypothesis. |

## Loop backstops

Safety limits to prevent infinite loops and runaway token spend.

| Setting | Type | Description |
|---------|------|-------------|
| `cycles_per_surface` | int | Cap on enum→exploit cycles for one surface. Null = off. |
| `dry_cycles_per_surface` | int | Stop a surface after N cycles with no new finding. 0 = off. |
| `total_cycles` | int | Global cycle backstop across all surfaces. Null = unlimited. |
| `surfaces` | int | Cap on surfaces investigated. Null = unlimited. |
| `frontier_actions` | int | Max leads worked before stopping. Null = use total_cycles. |
| `frontier_attempts` | int | Times a single lead is re-worked before it's marked exhausted. |

## Nudges

Automatic interventions when the engine shows signs of getting stuck.

| Setting | Type | Description |
|---------|------|-------------|
| `repeat_nudge` | int | Flag a tool call repeated N times as a loop. 0 = off. |
| `pivot_nudge` | int | Nudge the agent to pivot after N consecutive failures. 0 = off. |
| `reuse_nudge` | int | Remind to reuse existing scripts after N writes without `list_scripts`. 0 = off. |
| `grind_nudge` | int | Flag a grind after N scripts with no banked finding. 0 = off. |

## Analyst

| Setting | Type | Personas | Description |
|---------|------|----------|-------------|
| `analyst_interval` | int | pentest, redteam | Seconds between log-file polls (how often the LogWatcher checks for new .log content). |
| `analyst_debounce` | int | pentest, redteam | Quiet seconds after the last log chunk before the LLM analysis fires. Batches rapid output; max wait is 60s regardless. |
| `analyst_model` | str | pentest, redteam | Model for the background log analyst. Null = fast_model. |
| `micro_model` | str | pentest, redteam | Cheapest model for TTY log extraction (cleaning garbled raw chunks). Null = provider default (e.g. Haiku). |

## Models & routing

| Setting | Type | Description |
|---------|------|-------------|
| `fast_model` | str | Model for all support LLM calls (strategist, routing, compaction). Null = provider default. All personas. |
| `llm_routing` | bool | Pick specialist agents with an LLM vs keyword heuristics. pentest-ctf, pentest. |
| `router_model` | str | Model for routing calls. Null = fast_model. pentest-ctf, pentest. |

## Context compaction

| Setting | Type | Description |
|---------|------|-------------|
| `compact_threshold` | int | Summarize conversation when estimated tokens exceed this % of the context window (30–70). |
| `compact_keep_recent` | int | Turn pairs always kept verbatim (short-term memory, minimum 2). |
| `compact_model` | str | Model for the summarizer call. Null = fast_model. |

## Cracking

| Setting | Type | Description |
|---------|------|-------------|
| `hashcat_wordlist` | str | Wordlist path for hashcat jobs. |
| `hashcat_rules` | str | Rules file for hashcat jobs. |
| `hashcat_binary` | str | Hashcat executable name or path. |

## Diagnostics

| Setting | Type | Description |
|---------|------|-------------|
| `debug` | bool | Capture full LLM request/response/command transcript to `llm_debug.log`. All personas. |
