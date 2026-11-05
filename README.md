# Please Don't Take My Job, AI

**PDTMJ-AI** — an AI-powered penetration testing and red team operations platform

![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue) ![Kali Linux](https://img.shields.io/badge/Platform-Kali_Linux-557C94) ![Textual TUI](https://img.shields.io/badge/Interface-Textual_TUI-green)

An AI-powered offensive security platform with two operational modes: **autonomous penetration testing** (`pentest-ctf` and `pentest` personas) driven by a frontier-based agent engine, and a **passive real-time analyst** (`pentest` and `redteam` personas) that watches your terminal, extracts hosts, credentials, and findings, and suggests what to try next — with OPSEC awareness baked in.

> This started as a learning project — built to understand how LLMs interact with agents and to see what it takes to put a red teamer's way of thinking into a form an LLM can reason about. It's under active development and the internals change often.

## Demo

![PDTMJ-AI demo](assets/demo.gif)

*([full-quality video](assets/demo.mp4))*

## What it does

### Autonomous testing

Point it at a target with an objective. The engine enumerates, identifies attack surfaces, exploits what it can confirm, turns code execution into a stable foothold, loots and cracks credentials, escalates privileges, and writes up findings. A frontier-driven driver always works the single highest-value lead. Available in `pentest-ctf` (fast, flag-focused) and `pentest` (methodical, full specialist routing).

The orchestration pipeline:

```
staged port sweep → service ID → seed leads → strategist → score & pick lead → route agent → orchestrator → ingest results ↻
```

### Passive analyst

The operator runs every command. The AI watches your terminal session in real time — parsing nmap scans, credential dumps, enumeration output — and maintains a tactical picture: discovered hosts, credentials, findings, and suggested next steps with detection-risk ratings. It thinks like an adversary and advises like a senior operator, without ever touching the keyboard. Available in `pentest` and `redteam` personas.

The analyst pipeline:

```
shell hooks → TTY capture → log processor → LogWatcher → LLM analyst → DB → TUI
```

## Personas

| Persona | Mode | Description |
|---------|------|-------------|
| **pentest-ctf** | Autonomous | CTF-tuned — flag-focused, aggressive. Six core agents (planning, enumeration, exploitation, post-exploitation, validation, report) with no specialist routing. Domain depth via on-demand playbook retrieval. Built for boxes. |
| **pentest** | Hybrid | Full agent engine — all agents available, specialist routing (web, AD, database, network, cloud), methodical coverage. Ranges from fully autonomous to fully operator-driven. *In development.* |
| **redteam** | Operator-driven | Fully passive — never executes commands. You run the op, the AI reads your logs, extracts intel, maintains the tactical picture, and suggests next moves with OPSEC/detection-risk ratings. Framed around finding SOC detection gaps. |

## How it works

### pentest-ctf — fast, flag-driven

Six agents — planning, enumeration, exploitation, post-exploitation, validation, report — share an engagement state (SQLite, WAL mode). The **FrontierDriver** always works the single highest-value lead, scored by kill-chain position:

```
recon → service → vuln → exploited → foothold → user → privesc → root
```

Phase 0 runs a staged port sweep then service identification. Each subsequent pass: pick the top lead, hand it to the right agent, the agent works it and writes back findings/credentials/new leads, re-score, repeat. No specialist routing — agents pull domain methodology via `load_playbook` on demand. Exploitation is auto-approved (no operator confirmation). A `record_flag` tool captures CTF flags.

### pentest — methodical, full coverage

Same FrontierDriver loop, but with the full agent pool: all six core agents plus domain specialists (web, AD, database, network, cloud). The orchestrator routes to the specialist whose domain matches the lead. Supports the full spectrum from autonomous operation to operator-driven with AI guidance. The passive analyst also runs in this persona — terminal capture feeds the same DB the agents read from.

> The pentest persona is in active development. Agent routing, stop conditions, and the operator interaction model are evolving.

### redteam — passive observation

No agent engine. No command execution. Shell hooks (`pdtmj-hooks.zsh`) auto-capture your terminal session via `script(1)`. A log processor renders raw TTY output into clean text, filtering out TUI/vim alt-screen noise. The LogWatcher daemon polls for new log content and feeds it to an LLM analyst that extracts structured data — hosts, open ports, credentials, findings, leads — and writes it to the engagement DB. Every suggestion carries an OPSEC/detection-risk rating. A `record_ioc` tool captures indicators of compromise. Framed around SOC detection gaps: finding what defenders would miss is the primary objective.

### Shared infrastructure

- **Engagement DB** — per-op SQLite with WAL mode, shared across agents, analyst, TUI, and CLI

### Analyst infrastructure

Runs in `pentest` and `redteam` only — not in `pentest-ctf`.

- **Analyst pipeline** — shell hooks → TTY capture → log processor → LogWatcher → LLM analyst → DB
- **C2 integration** — NightHawk C2 backend polls beacon activity and feeds it through the analyst pipeline
- **TUI polls DB** via `PRAGMA data_version` — cheap integer check every 2s, full refresh only when data changes

## The TUI

A Textual-based terminal interface showing:

- **Activity log** — real-time analyst output, advisories, OPSEC warnings
- **Hosts** — discovered hosts, ports, services, OS
- **Credentials** — extracted creds (secrets masked in UI)
- **Findings** — vulnerabilities, misconfigurations, detection gaps
- **Suggested Commands** — prioritized leads ranked by expected value, with OPSEC risk
- **Chat** — direct conversation with the AI about the engagement

## saddle CLI

Shell-native CLI for managing ops without opening the TUI. Use it to query op state from a separate terminal without leaving your workflow.

```bash
$ saddle start --op Enigma --persona redteam
$ saddle op status
$ saddle op hosts
$ saddle op creds
$ saddle op findings
$ saddle op leads
$ saddle op advisory
$ saddle ai "what should I try next on the SMTP service?"
$ saddle stop
```

## Setup

### Requirements

- **Kali Linux** (built and tested on Kali) with standard offensive tooling on `PATH`
- **Python 3.11+**
- **Passwordless sudo** for the running user — many tools need root
- **An API key** for at least one provider (Anthropic, OpenRouter, or NVIDIA)

### Install

```bash
$ python -m venv venv
$ source venv/bin/activate
$ ./install.sh
$ cp config.yaml.example config.yaml
```

## Getting started

### 1. Set up a provider

You need an API key for at least one LLM provider. Supported: **Anthropic**, **OpenRouter**, **NVIDIA**, **Bedrock**, and any **OpenAI-compatible** endpoint (Ollama, LM Studio, vLLM, etc.).

Keys resolve in order: explicit override (`/key set`) → environment variable (e.g. `ANTHROPIC_API_KEY`) → OS keyring.

```bash
$ python main.py

# Inside the TUI — set your key and provider:
/key set sk-ant-...
/provider set anthropic

# Or for local models:
/provider set local http://localhost:11434/v1
```

### 2. Source the shell hooks

For the analyst pipeline (`pentest` and `redteam` personas), your terminal needs to be captured. Source the hooks in the shell where you'll run commands:

```bash
$ source shell/pdtmj-hooks.zsh

# Or add to ~/.zshrc to load automatically:
$ echo 'source /path/to/pdtmj-ai/shell/pdtmj-hooks.zsh' >> ~/.zshrc
```

The hooks enable: TTY capture via `script(1)` (auto-starts when an op is active), SSH/evil-winrm session wrappers (so remote sessions are captured too), command logging via `preexec`, and an RPROMPT badge showing the active op name.

> Not needed for `pentest-ctf` — the autonomous engine doesn't use the analyst pipeline, so no terminal capture is required.

### 3. Start your first op

```bash
# In the TUI:
/op start Enigma pentest-ctf    # autonomous CTF — engine runs immediately
/op start CorpNet redteam        # passive analyst — daemon starts, you run commands

# Or from the shell:
$ saddle start --op Enigma --persona pentest-ctf
```

What happens on `/op start`:

- Op directory created at `ops/<name>/` with an engagement DB (SQLite, WAL mode)
- **pentest / redteam:** a background daemon spawns — starts the LogWatcher, LogAnalyst, and C2 backends (if configured). Writes a `.daemon_pid` and `.badge` file.
- **pentest-ctf / pentest:** the autonomous engine starts — sets a target and objective, then the FrontierDriver takes over.

## Configuration reference

40+ runtime-tunable settings covering engagement rules, parallelism, loop backstops, nudges, analyst behavior, model routing, context compaction, and cracking. All configurable via `/config <key> <value>` in the TUI or `saddle config <key> <value>` from the shell. Settings are filtered by the active persona — you only see what applies.

See **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)** for the full reference with every setting, type, persona filter, and description.

## Technical deep dive

Detailed internals of both the autonomous orchestration pipeline (FrontierDriver, Phase 0 discovery, lead seeding, strategist, agent dispatch, result classification) and the analyst pipeline (7-stage flow from shell hooks through TTY capture, log processing, debounce, micro-model extraction, LLM analysis, and DB write).

See **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** for the full deep dive with pseudocode, data flows, and per-stage breakdowns.

## Benchmarks

`pentest-ctf` is regularly tested against Hack The Box machines across difficulty tiers and across providers. Updated benchmarks with the latest engine version are in progress.

Metrics tracked per run:

- **Result** — user flag, root flag, or partial progress
- **Time to root** — wall-clock from `/op start` to flag capture
- **Token spend** — input tokens, output tokens, cache hits, and estimated cost (USD)
- **Model & provider** — which model was used, enabling cross-provider comparison
- **Human nudges** — whether operator intervention was needed (and where the engine got stuck)
- **Engine version** — tracking improvement across releases

> Coming soon — full results table with per-box breakdowns across Easy / Medium / Hard tiers and multiple providers. Previous testing showed strong results on Easy and Medium boxes with common failure modes around privilege escalation and lateral movement on harder targets.

## Status

- **pentest-ctf** is the most exercised persona — regularly tested against HTB/CTF targets.
- **pentest** is in active development — specialist routing, operator interaction, and stop conditions are evolving.
- **redteam** analyst pipeline is functional and improving.
- The internals change often. This is a learning project that became a real tool — expect rough edges.

## Resources & inspiration

**AI offensive-security projects**

- [PentAGI](https://github.com/vxcontrol/pentagi) — autonomous AI penetration-testing agents
- [CAI](https://github.com/aliasrobotics/cai) — Cybersecurity AI framework (Alias Robotics)
- [CyberStrike](https://github.com/CyberStrikeus/CyberStrike) — AI-powered multi-agent autonomous pentesting

**Methodology references**

- [ired.team](https://www.ired.team/) — Active Directory & offensive-security techniques
- [Hackviser](https://hackviser.com/tactics/pentesting) — service-by-service enumeration and exploitation
- [thewhiteh4t](https://thewhiteh4t.github.io/blog/mssql-pentesting-cheatsheet/) — MSSQL pentesting cheatsheet

---

## Authorized use only

This is a dual-use offensive security tool intended for authorized penetration testing, CTF practice, and security research **only**. Use it solely against systems you own or have explicit written permission to test. The engine is constrained to non-destructive, reversible actions, but you remain responsible for operating within scope and the law.

Provided as-is, with no warranty, for educational purposes.
