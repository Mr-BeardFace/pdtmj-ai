---
name: consul
services: [consul]
summary: Consul — unauthenticated HTTP API, KV secret read, service-check script RCE
---

# Consul playbook

Consul (8500) exposes a service catalog and KV store, and service/health checks can run
scripts → RCE. Use `http_request`. The commands below are **examples** — compose your own.

## Reach & read
- Example: `http_request(GET, http://<host>:8500/v1/kv/?recurse)` (KV store)
- Example: `http_request(GET, http://<host>:8500/v1/agent/services)`

look for: unauthenticated API; secrets in KV; ACLs disabled.

## RCE via a script check
Register a service/health check whose body is a command (if script checks are enabled).
- Example: `PUT` a check with a script to `/v1/agent/check/register` → runs on the agent host

look for: `enable-script-checks` on → RCE on the agent.

## Record
`record_credential` KV secrets; RCE = critical (benign proof).
