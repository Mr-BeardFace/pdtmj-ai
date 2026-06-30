---
name: smtp
services: [smtp, smtps, submission]
summary: SMTP — username enumeration (VRFY/EXPN/RCPT), open relay, info disclosure
---

# SMTP playbook

A mail server can confirm valid local users (a username oracle for spraying elsewhere) and
may relay mail. Use `local_exec`. The commands below are **examples** — compose your own.

## User enumeration
- Example: `local_exec("smtp-user-enum -M VRFY -U users.txt -t <host>")` (also `EXPN`, `RCPT TO`)

look for: `VRFY`/`EXPN` enabled; valid usernames — feed them to spraying against AD/SSH/etc.
(within the lockout discipline).

## Open relay
- Example: `local_exec("swaks --to ext@evil.com --from x@<domain> --server <host>")` — accepted = relay

look for: the server relays mail for arbitrary external recipients.

## Banner / info
The banner often leaks the hostname, mail software + version (→ CVEs), and internal names.

## Record
Valid usernames and an open relay are findings; the usernames feed enumeration/spraying elsewhere.
