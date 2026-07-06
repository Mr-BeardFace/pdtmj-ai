---
name: minio-s3
services: [minio, s3]
summary: MinIO / S3 — anonymous buckets, exposed objects, write-to-served-path
---

# MinIO / S3 playbook

Object stores leak via public/misconfigured buckets and weak/default keys. Use `local_exec`
(`aws`/`mc`). The commands below are **examples** — compose your own from what you find.

## Enumerate buckets & objects
- Example (anon): `local_exec("aws --endpoint-url http://<host>:9000 s3 ls --no-sign-request")`
- Example: `aws --endpoint-url http://<host>:9000 s3 ls s3://<bucket> --no-sign-request`

look for: public buckets; creds/backups/source in objects; MinIO default `minioadmin/minioadmin`.

## Write → impact
A writable bucket that backs a website or is consumed by an app → upload a payload (a webshell
if it's web-served) per the foothold methodology.

## MinIO console / admin
Default creds → admin console; older MinIO has info-disclosure CVEs leaking keys.

## Record
`record_credential` keys/secrets in objects; a public or writable bucket = finding (critical if it holds creds).
