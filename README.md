# PDTMJ-AI

An autonomous, agentic penetration-testing assistant with a Textual TUI. A
frontier-driven engine works the single highest-value lead toward the objective,
dispatching specialist agents (enumeration, web, Active Directory, database,
network, RCE/foothold, post-exploitation, reporting) over a shared engagement
state, with all changes tracked and reversible.

## Status

Active development. Interfaces and agent layout are still changing.

## Requirements

- Python 3.11+
- A Kali-style Linux host with the usual offensive tooling on `PATH`
  (`nmap`, `netexec`, `impacket`, `hashcat`, etc.) — see `install.sh`.
- An API key for at least one provider (Anthropic, OpenRouter, or NVIDIA).

## Setup

```bash
pip install -r requirements.txt
# store a key (auto-detected by prefix) once inside the app:
#   /key set sk-ant-...      then   /provider set anthropic
python main.py
```

Configuration lives in `config.yaml` (copy `config.yaml.example`); API keys are
read from the OS keyring or the env vars in `.env.example`. Neither file is
tracked — see `.gitignore`.

## Authorized use only

This is a dual-use offensive security tool intended for authorized penetration
testing, CTF practice, and security research **only**. Use it solely against
systems you own or have explicit written permission to test. The engine is
constrained to non-destructive, reversible actions, but you remain responsible
for operating within scope and the law.
