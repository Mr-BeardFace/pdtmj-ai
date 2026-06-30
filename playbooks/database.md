---
name: database
services: [mysql, postgresql, postgres, mongodb, mongod, redis, oracle, elasticsearch]
summary: Database services — unauth/default access, privilege, data exposure, code-exec primitives
---

# Database playbook

Retrieved methodology for database services — high-value targets. Order for every
engine: **unauthenticated / default-credential access first**, then assess privilege
and data exposure, then note any code-execution primitive. Brute is the last rung,
never the opener.

## Guardrails (database-specific)
- **Read-only, always.** Demonstrate access by reading structure (db/collection/index
  names, schema, a few sample rows) — never modify, delete, drop, or corrupt. A
  code-exec primitive (`xp_cmdshell`, Postgres `COPY … PROGRAM`, Redis `CONFIG SET dir`)
  is recorded as a finding with the technique described and proven only with a benign
  `whoami` — do not perform the destructive config write against a live service.
- **Don't exfiltrate.** Capture field names and sample *structure*; truncate real values.

Use the protocol's real client (`impacket_mssql`, `mongosh_query`, `redis_query`,
`http_request` for HTTP-API stores). Unauthenticated DB access is always `critical`.

## Per-engine — load the dedicated playbook where one exists
Several engines have their own focused playbook; load it for the worked technique set:
- **MSSQL** → `load_playbook(["mssql"])` — auth, privilege, code-exec, linked servers, NTLM coercion
- **Redis** → `load_playbook(["redis"])` — unauth, config file-write → RCE, modules, replication
- **PostgreSQL** → `load_playbook(["postgresql"])` — COPY…PROGRAM RCE, file read/write
- **MySQL/MariaDB** → `load_playbook(["mysql"])` — FILE-priv file read/write → webshell, UDF RCE

Engines without a dedicated playbook yet — same shape (unauth/default first, assess
privilege and data exposure, record any code-exec primitive):
- **MongoDB (27017):** unauthenticated access (critical); enumerate collections, sample
  document structure; creds/PII/secrets in documents (`mongosh_query`).
- **Elasticsearch (9200) / CouchDB (5984):** probe the HTTP API for unauth access, list
  indices/databases, sample data; CouchDB "admin party" (no admin password).
- **Oracle, Cassandra, Neo4j, Memcached:** unauth/default first, assess privilege + data
  exposure, record any code-exec primitive.

Record every credential with `record_credential`; crackable hashes → `hashcat_crack`.
If you obtain code execution, move to the foothold methodology.
