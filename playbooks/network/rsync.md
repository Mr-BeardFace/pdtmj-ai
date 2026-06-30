---
name: rsync
services: [rsync]
summary: rsync daemon — anonymous module listing, file read and write
---

# rsync playbook

An rsync daemon (873) often exports modules with no auth — readable data and, where a
module is writable, a write primitive. Use `local_exec`. The commands below are **examples**.

## List modules
- Example: `local_exec("rsync rsync://<host>/")` (lists exported modules)

look for: modules accessible without authentication.

## Read / write
- Example (read): `local_exec("rsync -av rsync://<host>/<module>/ ./loot/")`
- Example (write): `local_exec("rsync -av ./payload rsync://<host>/<module>/")` — if it
  succeeds, convert per the foothold methodology (SSH key / cron / webshell, depending on
  where the module maps)

look for: world-readable data; a writable module mapping to a home, web, or cron path.

## Record
Anonymous read or write = finding; `record_persistence` anything planted in a writable module.
