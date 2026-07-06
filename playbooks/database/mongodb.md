---
name: mongodb
services: [mongodb, mongod]
summary: MongoDB — unauthenticated access, data/credential exposure, server-side JS
---

# MongoDB playbook

MongoDB is frequently exposed with no authentication, making it primarily a data- and
credential-exposure target. Use `mongosh_query`. The commands below are **examples** —
compose your own from what you find.

## Connecting — is it open?
A no-auth instance answers immediately; `--auth` off is the common misconfiguration.
- Example: `mongosh_query(target, query="db.adminCommand('listDatabases')")`

look for: commands succeed with no credentials (unauthenticated = critical).

## Enumerate (data is the prize)
Walk databases → collections → sample documents; application user tables and config
collections routinely hold password hashes, API keys, and session tokens.
- Example: `show dbs`, `use <db>`, `show collections`, `db.<coll>.findOne()`, `db.users.find().limit(5)`

look for: a `users`/`accounts`/`credentials` collection, secrets in config docs, PII.
Sample structure and a few rows — don't dump a large collection.

## Server-side JavaScript (older / misconfigured)
If JS execution is enabled, `db.eval()` / `$where` / mapReduce can run JS server-side
(removed/restricted in modern versions — version-dependent).

## Record
`record_credential` for every hash/secret in documents (crackable → `hashcat_crack`),
then reuse against other services. Unauthenticated access = critical finding.
