---
name: memcached
services: [memcached]
summary: Memcached — unauthenticated access, cached session/credential extraction
---

# Memcached playbook

Memcached (11211) has no real auth and caches whatever the application stores —
sessions, tokens, query results — so it's a credential- and session-exposure target.
Drive it with `local_exec` (nc) or `run_script`. The commands below are **examples**.

## Connecting & stats
- Example: `local_exec("echo -e 'stats\\r\\nquit' | nc <host> 11211")`

look for: it answers with no auth (unauthenticated = critical); the item count from `stats`.

## Dump cached keys → values
Enumerate slabs, list keys, then read each value — sessions and tokens are the prize.
- Example: `stats items` → `stats cachedump <slab_id> <limit>` (list keys) → `get <key>` (read value)

look for: session IDs, auth tokens, password/credential values, API responses with secrets.

## Record
`record_credential` for any session token or credential recovered, then reuse it
(a stolen session can be replayed straight against the app). Unauthenticated access = critical.
