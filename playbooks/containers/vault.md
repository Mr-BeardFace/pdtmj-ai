---
name: vault
services: [vault]
summary: HashiCorp Vault — unsealed/weak-auth access, secret extraction, token abuse
---

# Vault playbook

Vault (8200) stores secrets; the prize is an unsealed instance with weak auth or a leaked
token. Use `http_request`. The commands below are **examples** — compose your own.

## Status & access
- Example: `http_request(GET, http://<host>:8200/v1/sys/health)` (sealed? initialized?)

look for: unsealed + a usable token/role — a leaked root token, dev mode, or a weak auth method.

## Read secrets
- Example: `http_request(GET, http://<host>:8200/v1/secret/data/<path>)` with header `X-Vault-Token`
- enumerate mounts (`/v1/sys/mounts`), list (`LIST /v1/secret/metadata`)

look for: DB creds, cloud keys, SSH/PKI signing material — high-value pivots.

## Record
`record_credential` every secret pulled and reuse it against the systems it unlocks.
