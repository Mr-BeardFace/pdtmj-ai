---
name: nfs
services: [nfs, rpcbind]
summary: NFS — export enumeration, no_root_squash privesc, writable-export write-to-exec
---

# NFS playbook

NFS exports often trust the client's UID blindly, so a writable export — especially one
with `no_root_squash` — is a direct privilege-escalation primitive. Drive it with
`local_exec`. The commands below are **examples** — compose your own from what you find.

## Enumerate exports
- Example: `local_exec("showmount -e <host>")` (list exports)
- Example (mount): `local_exec("mkdir -p /mnt/x; mount -t nfs <host>:/export /mnt/x -o nolock")`

look for: world-readable/writable exports; sensitive files (keys, configs, backups);
the export options.

## no_root_squash → root (the gold)
When an export is `no_root_squash`, a file you create **as root on the client** is
root-owned on the server. Drop a root-owned SUID shell and run it from a normal account.
- Example: as root locally, copy a shell binary into the mount, `chown root`, `chmod +s`,
  then execute it on the target for an instant root shell

look for: `no_root_squash` in the export options and the ability to write as uid 0.

## Writable export → exec
A writable export mapping into a home or web directory → SSH key / cron / webshell per
the foothold methodology.

look for: write access landing in `~/.ssh`, a web root, or `/etc/cron.d`.

## UID matching
Files owned by a specific UID → create a local user with that UID to read/write them.

## Record
`record_persistence` anything planted (SUID binary, key, cron). Privesc to root = critical.
