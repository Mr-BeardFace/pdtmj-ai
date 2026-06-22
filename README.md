# Please Don't Take My Job, AI!

### PDTMJ-AI

An autonomous, agentic penetration-testing assistant with a Textual TUI. A
frontier-driven engine works the single highest-value lead toward the objective,
dispatching agents (enumeration, web, Active Directory, database, network,
exploitation/foothold, post-exploitation, reporting) over a shared engagement
state, with credentials masked and every change to a target tracked and
reversible.

## Demo

![PDTMJ-AI demo](assets/demo.gif)

*([full-quality video](assets/demo.mp4))*

## Why this exists

I'm not a developer. This was vibe-coded — built with an LLM doing the heavy
lifting because writing it by hand would have taken me far too long.

The real point wasn't the tool. It was to **learn how LLMs interact with agents** —
the orchestration, the workflow, the handoffs — and to see what it takes to put a
**red teamer's / pentester's way of thinking** into a form an LLM can actually
reason about and act on. If something genuinely useful falls out of that, great,
but that was always a bonus, not the goal.

So treat this as a learning project and a sandbox for ideas, not a polished
product. It's under active, continuous testing and the internals change often.

## What it does

Point it at a target with an objective; the engine enumerates, identifies attack
surfaces, exploits what it can confirm, turns code execution into a stable
foothold, escalates, and writes up findings. It runs as an interactive TUI so you
can watch each step, interrupt, feed it credentials, and steer.

Personas tune behavior: `pentest` (full, methodical) and `pentest-ctf`
(flag-focused, fast, pinned to a generalist agent so it solves a box without
specialist routing).

## How it works — agents, state, and routing

The engine runs one agent at a time against a shared **engagement state**. Agents
don't call each other — they read from that state and write back to it, and the
driver decides who runs next.

### Shared state

An agent is a system prompt plus a set of tools. Most tools shell out (nmap,
netexec, etc.), but a few write straight into the engagement state:

- `annotate_finding` records a finding (with a `verified` flag for proven vs.
  suspected).
- `record_credential` records a credential. The real secret is kept and handed to
  the agent so it can authenticate; the operator UI and saved snapshots only ever
  show a masked version.
- `register_surface` records a `(host, service)` attack surface — the unit the
  driver cycles on.
- `record_persistence` logs any change made to a target, with the original value
  and the exact command to revert it.
- `queue_followup` hands a lead to another agent.

Everything else an agent runs is appended to a tool log, and each agent finishes
with a short handoff note. Before the next agent starts, the engine assembles a
**context block** from all of this — recent tool output, known credentials, open
surfaces, prior handoffs, and the findings so far — and puts it at the top of that
agent's prompt. That context block is the only way work passes between agents.

### The agents

Each agent is a Markdown file (system prompt + methodology + tool scope). Shared
methodology — like turning code execution into a stable foothold — lives in
`_shared/` partials that multiple agents pull in.

| Agent | Phase | Role |
|---|---|---|
| `planning` | planning | Reasons over the enumerated surface and produces an ordered, vetted list of what to test next and why. |
| `enumeration` | discovery | Broad, **observe-only** fingerprinting + cheap safe checks (anonymous/null/default access). Flags what responds; never exploits. |
| `web` | assessment | Web app assessment — auth, business logic, injection, APIs, client-side. |
| `database` | assessment | DB services — MySQL, PostgreSQL, MSSQL, MongoDB, Redis, Elasticsearch. |
| `network` | assessment | Non-web/non-AD protocols — SMB, SSH, FTP, SMTP, SNMP, RDP, etc. |
| `active-directory` | assessment | Windows domain — user enum, Kerberos, LDAP, lateral movement. |
| `cloud` | assessment | AWS/GCP misconfig, exposed buckets, IAM privesc. |
| `exploitation` | exploitation | Generalist — turns confirmed vulns into code execution and a stable foothold. Has every tool and the foothold methodology. |
| `post-exploitation` | exploitation | Local enumeration + privilege escalation through an existing shell. |
| `validation` | validation | Independently reproduces exploited findings and kills false positives / hallucinations. |
| `report` | reporting | Consolidates findings and writes the final deliverable. Always runs last. |

### The driver loop

The driver is **frontier-driven**: it works the single most valuable *lead* at a
time. A lead is anything actionable — a surface, a vuln, a credential, a foothold, a
new internal host — tagged with the kill-chain rung it would reach if it pans out:

```
recon → service → vuln → exploited → foothold → user → privesc → root
```

The engine tracks how far up that ladder it has gotten, and scores each open lead by
how much further it would push the frontier (with a nudge for higher-severity,
still-open threads). So the next turn always goes to the lead that advances the
engagement the most — not to whatever service happens to look the busiest.

Each pass:

1. Pick the top-scored lead and hand it to the right agent.
2. The agent works it and writes back — findings, credentials, a foothold — and any
   new findings/credentials become **new leads** (a cracked password to reuse, a new
   host to enumerate).
3. Re-score the leads and repeat, until the objective is met, the leads dry up, or
   the turn budget runs out.

`validation` then re-checks the exploited findings to drop false positives, and
`report` runs last.

### How an agent gets picked

A lead's kind and rung decide the broad move (enumerate it, exploit it, escalate
from it), and for a specific service there's a default specialist — `http → web`,
`smb`/`ldap`/`kerberos → active-directory`, `mysql`/`mssql`/`redis → database`,
`ssh`/`ftp`/`smtp` → network, `aws`/`gcp` → cloud.

Selection is **reasoning-first with that map as a floor**: when a specialist is
available, a small LLM router decides between it and the generalist `exploitation`
agent based on the actual surface; the map is only the fallback when routing is off
or no specialist fits. (Routing can be disabled in config, which pins everything to
the map.)

Finally, the **persona controls which agents are even in play**. `pentest` exposes
all of them — full specialist routing, surfaces worked in parallel. `pentest-ctf`
loads only a generalist spine (enumeration, exploitation, post-exploitation,
validation, report), so on a single box exploitation always lands on the generalist
with no routing decision to get wrong.

### Two ways to deliver domain depth: route, or retrieve

There are two ways the same domain methodology reaches an agent, and the project is
mid-transition between them:

- **Route to a specialist (the `pentest` persona).** A web/AD/DB surface is dispatched
  to the `web` / `active-directory` / `database` agent — a separate run with that
  domain's methodology as its system prompt.
- **Retrieve a playbook (the `pentest-ctf` persona).** There are no specialists in the
  pool; the generalist recognizes the domain from what it enumerated and calls the
  `load_playbook` tool to pull that methodology **into its own context** — same
  knowledge, no routing, no handoff. The `playbooks/` directory holds one document per
  domain (`web`, `active-directory`, `database`, `network`, `cloud`); the specialist
  agents and the playbooks are the same methodology in two delivery forms.

The retrieval model is deliberate: routing reliability stops gating domain depth, one
agent holds the whole picture, and you only pay for the playbooks a box actually needs.
The direction is to move the `pentest` persona onto retrieval too — a generalist that
retrieves, run in parallel one-per-host for larger scopes.

Shared *foothold* methodology (turning code execution into a stable session) is handled
a third way — a partial spliced into every exploitation-capable agent at load time — so
the generalist and the specialists work a foothold identically.

## Status

Active development. Interfaces, agent layout, and workflow are still changing —
see [Known limitations](#known-limitations).

## Requirements

- **A Kali-style Linux host** (this is built and tested on Kali) with the usual
  offensive tooling on `PATH` — `nmap`, `netexec`, `impacket`, `hashcat`, etc.
  See `install.sh`.
- **Passwordless `sudo` for the user that runs the tool.** Many tools shell out
  to commands that need root (raw-socket scans, `/etc/hosts` edits, etc.), and
  the engine does not stop to prompt for a password mid-run. Configure the
  running user with `NOPASSWD` sudo.

  > Yes, this is a security trade-off. It's deliberate: this runs as root in a
  > disposable lab VM (a Kali attack box), not on anything you care about.

- **Python 3.11+**, run inside a virtual environment (see Setup).
- **An API key** for at least one provider (Anthropic, OpenRouter, or NVIDIA).

## Setup

Run everything inside a Python virtual environment:

```bash
python -m venv venv
source venv/bin/activate
./install.sh

python main.py
```

Once inside the app, store a provider key (auto-detected by prefix) and select it:

```
/key set sk-ant-...
/provider set anthropic
```

### Local models

Any OpenAI-compatible runtime works — Ollama, LM Studio, llama.cpp's server, vLLM.
Point the `local` provider at its base URL and pick a model:

```
/provider set local http://localhost:11434/v1   # Ollama (LM Studio: :1234/v1)
/agent set model global llama3.1:8b
/models list local
```

No API key is needed for a typical local server; if yours requires one, set it with
`/key set local <api-key>`. The base URL persists to `config.yaml` (`local_base_url`).

Configuration lives in `config.yaml` (copy `config.yaml.example`); API keys are
read from the OS keyring or the env vars in `.env.example`. Neither `config.yaml`
nor `.env` is tracked — see `.gitignore`.

## Known limitations

Things I already know don't work the way I want yet — calling them out so nobody
is surprised:

- **Limited LLM providers.** Anthropic, OpenRouter, NVIDIA, and any
  OpenAI-compatible local server (Ollama, LM Studio, …). More to come.
- **Reporting is rough.** Report generation and regeneration are inconsistent and
  still being reworked.
- **Copying text is flaky.** Pulling text out of the TUI panes doesn't always
  behave.
- **Logic and workflow are a work in progress.** Agent routing, lead handling,
  and stop conditions are under continuous testing and tuning — expect rough
  edges and behavior changes.
- **Credential storage needs work.** Secrets are masked in the UI and snapshots,
  but the underlying handling (keyring/state, on-disk artifacts) deserves a more
  secure approach — on the list to improve.
- General polish: this is a personal learning project, so plenty is half-built or
  in flux at any given time.

If something is broken in a way that isn't listed here, that's expected too — it's
that kind of project.

## Authorized use only

This is a dual-use offensive security tool intended for authorized penetration
testing, CTF practice, and security research **only**. Use it solely against
systems you own or have explicit written permission to test. The engine is
constrained to non-destructive, reversible actions, but you remain responsible
for operating within scope and the law.

Provided as-is, with no warranty, for educational purposes.
