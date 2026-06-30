---
name: kibana
services: [kibana]
summary: Kibana — version-specific RCE (CVE-2019-7609 Timelion), Elasticsearch pivot
---

# Kibana playbook

Kibana fronts Elasticsearch and has version-specific RCE in older builds. Use `http_request`.
The commands below are **examples** — compose your own from what you find.

## Version & access
- Example: `http_request(GET, http://<host>:5601/api/status)` (version)

look for: the version (decides the CVE); unauthenticated access.

## RCE — version-specific
- **CVE-2019-7609** (Timelion, < 6.6.1) — prototype pollution → Node.js RCE
- **CVE-2018-17246** (Console LFI → RCE)

look for: a vulnerable version → run the matching exploit for a reverse shell as the kibana user.

## Data — pivot to Elasticsearch
Kibana sits in front of Elasticsearch — pivot to the ES indices (`load_playbook(["elasticsearch"])`).

## Record
RCE = critical; note the linked Elasticsearch surface and queue it.
