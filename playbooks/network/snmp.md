---
name: snmp
services: [snmp]
summary: SNMP — community-string guessing, system/credential disclosure, RW-string abuse
---

# SNMP playbook

SNMP (161/UDP) leaks a surprising amount once a community string is found — process
command lines (with creds), software, users, network config. Use `snmp_enum`. The commands
below are **examples** — compose your own from what you find.

## Community strings
- Example: `snmp_enum(target)` (tries common strings: `public`, `private`, `community`)

look for: a working string (v1/v2c) and whether it is read-write (`private`).

## Harvest
A read string dumps a lot — walk the system, process, software, user, and network OIDs.
- Example: enumerate processes (credentials often sit in command-line args), installed
  software (→ CVEs), and network/routing config via `snmp_enum`

look for: credentials in process arguments, internal hostnames/topology, device configs.

## RW string → modify
A read-write string can change device config (router/switch/printer) — read/prove only,
never disrupt.

## Record
A working string = finding; `record_credential` for credentials found in process args or configs.
