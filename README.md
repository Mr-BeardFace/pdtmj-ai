# PDTMJ-AI

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
