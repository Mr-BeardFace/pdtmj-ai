---
name: webdav
services: [webdav]
summary: WebDAV — unauthenticated/writable upload to webshell (RCE)
---

# WebDAV playbook

WebDAV adds file upload over HTTP; if you can `PUT` an executable extension into a
web-executed directory, it's direct RCE. Use `http_request` / `local_exec`. The commands
below are **examples** — compose your own from what you find.

## Probe methods & writability
- Example: `local_exec("davtest -url http://<host>/dav/")` — reports which extensions both
  upload AND execute
- Example (manual): `http_request(PUT, http://<host>/dav/shell.<ext>, body=<webshell>)`

look for: `PUT` allowed, and which extensions are both uploadable and server-executed
(davtest tells you directly).

## Upload → shell
Upload a webshell in an executable extension the server runs, then request its URL. If the
executable extension is blocked, upload then `MOVE` to a runnable name, or fall back to the
foothold methodology.

## Record
Writable WebDAV / achieved RCE = critical (prove with a benign payload); `record_persistence`
the uploaded file with its cleanup.
