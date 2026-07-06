---
name: elasticsearch
services: [elasticsearch]
summary: Elasticsearch — unauthenticated HTTP API, data exposure, version-specific RCE CVEs
---

# Elasticsearch playbook

Elasticsearch exposes an HTTP API on 9200 that is often unauthenticated — primarily a
data-exposure target, with version-specific RCE in older builds. Use `http_request`.
The calls below are **examples** — compose your own from what you find.

## Connecting — is it open?
- Example: `http_request(GET, http://<host>:9200/)` — version/build, cluster name

look for: the API answers with no auth (unauthenticated = critical) and the `version.number`
(decides the RCE options below).

## Enumerate (data is the prize)
- Example: `GET /_cat/indices?v` (list indices), `GET /<index>/_search?size=10` (sample docs),
  `GET /_cluster/health`

look for: indices holding logs, app data, credentials, PII; an index named for secrets/users.

## RCE — version-specific (older builds)
Old Elasticsearch shipped a Groovy/MVEL scripting sandbox escape:
- Example (concept): a `_search` with a script payload (CVE-2014-3120 / CVE-2015-1427) on
  vulnerable 1.x versions → OS command execution

look for: a 1.x version → pursue the matching CVE; modern versions → focus on data + auth.

## Record
Unauthenticated access = critical. `record_credential` for any secrets in documents.
Note related services on the same host (Kibana → its own surface).
