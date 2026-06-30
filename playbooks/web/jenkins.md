---
name: jenkins
services: [jenkins]
summary: Jenkins — Groovy script console RCE, build-step abuse, stored-credential theft
---

# Jenkins playbook

Jenkins runs Groovy; the script console is direct RCE, and stored credentials are a prize.
Use `http_request`. The commands below are **examples** — compose your own from what you find.

## Access
- Example: `http_request(GET, http://<host>:8080/)` then check `/script` and job config reachability

look for: anonymous read/build, `/script` reachable (older/misconfigured), signup enabled, or
default/weak creds (`admin/admin`).

## Script console → RCE
- Example: POST Groovy to `/script` — `println "id".execute().text` → OS command exec as the Jenkins user

look for: `/script` reachable → RCE (benign proof).

## Without the script console
- A job you can configure/build → add a shell build step.
- Older versions: CLI/remoting deserialization CVEs.

## Credentials
Jenkins stores credentials (`credentials.xml`, job env, secrets) — decrypt with the master
key or via the script console, then reuse.

## Record
RCE = critical; harvest and `record_credential` stored creds and reuse them.
