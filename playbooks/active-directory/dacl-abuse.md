---
name: dacl-abuse
services: [dacl, acl]
summary: DACL/ACE abuse — convert a BloodHound write edge into control of the target object
---

# DACL abuse playbook

BloodHound edges (GenericAll, GenericWrite, WriteDACL, WriteOwner, Owns) each have a specific
abuse. Confirm the edge against the **actual object** before acting. Use `bloodyAD` and impacket
`dacledit`/`owneredit` via `local_exec`. The commands below are **examples** — compose your own.

## Map the abuse to the edge
- **GenericAll / GenericWrite on a USER** → Shadow Credential (`load_playbook(["shadow-credentials"])`),
  a targeted Kerberoast (set an SPN, roast, clear it), or force a password change.
  - Example (force pw): `bloodyAD -u <u> -p <p> -d <domain> --host <dc> set password <target> <newpw>`
- **GenericAll / GenericWrite on a COMPUTER** → RBCD (`load_playbook(["rbcd"])`) or Shadow Credentials.
- **GenericAll on a GROUP** → add yourself as a member.
  - Example: `bloodyAD -u <u> -p <p> -d <domain> --host <dc> add groupMember '<group>' <you>`
- **WriteDACL** → grant yourself GenericAll, then abuse as above.
  - Example: `impacket-dacledit -action write -rights FullControl -principal <you> -target '<obj>' <domain>/<u>:<p>`
- **WriteOwner / Owns** → take ownership, then WriteDACL → GenericAll.
  - Example: `impacket-owneredit -action write -owner <you> -target '<obj>' <domain>/<u>:<p>`

look for: the exact edge type on the exact object (from BloodHound) — pick the matching abuse. A
denied write means the edge wasn't what it looked like, **not** that the path is dead — re-check it.

## Record
`record_persistence` every change (group add, DACL/owner edit, SPN, key) with the exact revert.
A confirmed path to DA = critical.
