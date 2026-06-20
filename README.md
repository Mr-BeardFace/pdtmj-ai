# Please Don't Take My Job, AI!

### PDTMJ-AI

An autonomous, agentic penetration-testing assistant with a Textual TUI. A
frontier-driven engine works the single highest-value lead toward the objective,
dispatching agents (enumeration, web, Active Directory, database, network,
exploitation/foothold, post-exploitation, reporting) over a shared engagement
state, with credentials masked and every change to a target tracked and
reversible.

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

The system is a set of focused **agents** coordinated by a **driver**, all sharing
one **engagement state**. This is the part the project was really built to explore,
so here's how the pieces fit.

### Information flows through shared state, not direct messages

Agents never talk to each other directly. They read from and write to a single
shared `EngagementState`, and the driver decides who runs next. The state holds:

- **Findings** — written with `annotate_finding` (verified vs. potential).
- **Credentials** — written with `record_credential`. Masked in the operator UI
  and in saved snapshots, but the *real* value is handed to the agent so it can
  actually authenticate.
- **Surfaces** — `(host, service)` attack surfaces registered with
  `register_surface`; these are the units the engine cycles on.
- **Tool log + handoffs** — what's already been run, and each agent's close-out
  note to the next one.
- **An IOC change-ledger** — every change made to a target (`record_persistence`)
  with the original state and an exact revert command, so nothing is left behind.

Before an agent runs, the engine builds it a **context block** from this state —
prior work, credentials, open surfaces, and the previous agents' handoffs — so each
agent inherits the picture instead of starting from scratch. When an agent finds
something another should chase, it calls `queue_followup` to hand off a lead.

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

### How an engagement flows

The driver is **frontier-driven and lead-based**. The unit of work is a *lead*
(a surface, a vuln, a credential, a foothold, a misconfig…), and each lead is
ranked by **expected progress toward the objective**, not by generic service
weight. Progress is measured on a kill-chain ladder:

```
recon → service → vuln → exploited → foothold → user → privesc → root
```

The loop, roughly:

1. **Enumerate** the target into surfaces and findings.
2. **Rank** the open leads by expected value — how much closer a lead, if it pans
   out, moves the engagement up the ladder.
3. **Dispatch** the best agent for the single highest-value lead.
4. That agent works it, banks findings/credentials/a foothold, and often spawns
   **new** leads (a cracked password to reuse, a new internal host to enumerate).
5. Repeat on the new frontier until the objective is met or leads run dry.
6. **Validate** exploited findings, then **report**.

### How an agent gets picked

Routing is **reasoning-first with a deterministic floor**:

- A lead's *kind* and *reach* decide the broad role (enumerate it, exploit it,
  escalate from it, …).
- For a specific surface, a service→specialist map is the floor — e.g. `http →
  web`, `smb/ldap/kerberos → active-directory`, `mysql/mssql/redis → database`,
  `ssh/ftp/smtp → network`. When a specialist is loaded, an LLM router chooses
  between it and the generalist `exploitation` agent; the map is the safety net,
  never a hard switch.
- The **persona pins the candidate pool.** `pentest` exposes every agent (full
  specialist routing + parallelism). `pentest-ctf` declares only the generalist
  spine, so the specialists aren't in the pool at all — exploitation
  deterministically uses the generalist, and there's no per-surface routing
  decision to get wrong on a single box.

The guiding idea: **methodology is the value; the agents are just how it's
delivered.** A specialist and a "playbook the generalist could read" are the same
knowledge — which is why the architecture is slowly moving toward a generalist that
*retrieves* domain depth on demand, with the persona deciding how many run at once.

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
  > disposable lab VM (a Kali attack box), not on anything you care about. Run it
  > the same way — in a throwaway VM, never on a host with anything to lose.

- **Python 3.11+**, run inside a virtual environment (see Setup).
- **An API key** for at least one provider (Anthropic, OpenRouter, or NVIDIA).

## Setup

Run everything inside a Python virtual environment:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

python main.py
```

Once inside the app, store a provider key (auto-detected by prefix) and select it:

```
/key set sk-ant-...
/provider set anthropic
```

Configuration lives in `config.yaml` (copy `config.yaml.example`); API keys are
read from the OS keyring or the env vars in `.env.example`. Neither `config.yaml`
nor `.env` is tracked — see `.gitignore`.

## Known limitations

Things I already know don't work the way I want yet — calling them out so nobody
is surprised:

- **Limited LLM providers.** Only a few sources are wired in (Anthropic,
  OpenRouter, NVIDIA). More to come.
- **Reporting is rough.** Report generation and regeneration are inconsistent and
  still being reworked.
- **Copying text is flaky.** Pulling text out of the TUI panes doesn't always
  behave.
- **Logic and workflow are a work in progress.** Agent routing, lead handling,
  and stop conditions are under continuous testing and tuning — expect rough
  edges and behavior changes.
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
