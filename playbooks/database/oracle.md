---
name: oracle
services: [oracle, oracle-tns]
summary: Oracle TNS — SID discovery, default creds, ODAT file R/W and code execution
---

# Oracle playbook

Oracle (1521 TNS) needs a valid SID and a login before the database opens up; default
credentials are common, and `odat` automates most of the post-auth abuse. Drive it with
`local_exec`. The commands below are **examples** — compose your own from what you find.

## Find the SID
The listener won't talk usefully without the right SID/service name.
- Example: `local_exec("odat sidguesser -s <host> -p 1521")` or an nmap `oracle-sid-brute`

look for: a valid SID/service name to target.

## Default & weak credentials
Oracle ships many well-known default accounts.
- Example: `local_exec("odat passwordguesser -s <host> -p 1521 -d <SID>")`
- common pairs: `scott/tiger`, `system/manager`, `sys/change_on_install`, `dbsnmp/dbsnmp`

look for: any working login, and whether it holds the `DBA` role (unlocks the abuse below).

## File read/write and code execution (ODAT)
With a login (DBA makes it trivial), Oracle exposes file and OS-command primitives:
- Example (file R/W): `odat utlfile -s <host> -d <SID> -U <u> -P <p> --getFile ...`
- Example (command exec): `odat externaltable` / `dbmsscheduler` / `java` modules → run OS commands

look for: a writable path the system acts on (→ foothold methodology), or direct command exec
(critical, benign proof).

## Record
`record_credential` for every login (default creds are still a finding), and feed any
recovered Oracle password hashes to `hashcat_crack`. Code-exec or file R/W = critical.
