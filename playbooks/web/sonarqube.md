---
name: sonarqube
services: [sonarqube]
summary: SonarQube — default creds, source/token theft, version-specific RCE
---

# SonarQube playbook

SonarQube holds source code and CI/SCM tokens, so the prize is often credentials and code
rather than RCE. Use `http_request`. The commands below are **examples** — compose your own.

## Access
- Example: `http_request(GET, http://<host>:9000/api/system/status)`

look for: default `admin/admin`; the version (→ CVEs).

## Loot — source & tokens
- Example: pull project source and extract stored tokens via the API (`/api/...`)

look for: SCM/CI tokens (GitHub/GitLab, deploy keys) → pivot to repos and pipelines.

## RCE
Version-specific CVEs; with admin, plugin/webhook abuse.

## Record
`record_credential` stored tokens and reuse them against the linked SCM/CI; RCE = critical.
