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

## Per-engine focus
- **MySQL (3306):** blank/weak root, anonymous; accessible DBs/users, privilege; file
  read / code-exec (`LOAD DATA INFILE`, UDF injection).
- **PostgreSQL (5432):** weak creds, superuser status, `COPY … TO/FROM PROGRAM` exec (9.3+).
- **MSSQL (ms-sql-s):** has its own playbook — `load_playbook(["mssql"])` for auth,
  privilege, code-exec, linked servers, and NTLM coercion.
- **MongoDB (27017):** unauthenticated access (critical); enumerate collections, sample
  document structure; creds/PII/secrets in documents.
- **Redis (6379):** check whether auth is required; if open, read config + keyspace.
  RCE primitives (`CONFIG SET dir` → cron / `authorized_keys`) recorded as a finding,
  not performed.
- **Elasticsearch (9200) / CouchDB (5984):** probe the HTTP API for unauth access, list
  indices/databases, sample data; CouchDB "admin party" (no admin password).
- **Other** (Oracle, Cassandra, Neo4j, Memcached): same shape — unauth/default first,
  assess privilege + data exposure, record any code-exec primitive.

Record every credential with `record_credential`; crackable hashes → `hashcat_crack`.
If you obtain code execution, move to the foothold methodology.
