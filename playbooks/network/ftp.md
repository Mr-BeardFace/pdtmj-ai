---
name: ftp
services: [ftp, ftps]
summary: FTP — anonymous access, writable upload to webshell, cleartext credential reuse
---

# FTP playbook

FTP is cleartext and frequently allows anonymous access; the wins are exposed files, a
writable directory, and credential reuse. Use `netexec ftp` or `local_exec`. The commands
below are **examples** — compose your own from what you find.

## Anonymous & default access
- Example: `local_exec("curl -s ftp://anonymous:anonymous@<host>/")`
- Example: `netexec ftp <host> -u anonymous -p ''`

look for: anonymous login allowed; readable configs/backups/keys; which directory it lands in.

## Writable → webshell / exec
If you can upload **and** the FTP root is served by a web server (common on shared hosting),
upload a webshell and request its URL. Otherwise convert per the foothold methodology.
- Example: upload a `.php`/`.aspx` (try a benign marker first), then request its URL

look for: write access (test with a benign file) and whether the path is web-served.

## Cleartext creds / reuse
Any credential found here reuses widely — replay every discovered credential against
other services.

## Record
Anonymous or writable access = finding; `record_credential` for any creds and reuse them.
