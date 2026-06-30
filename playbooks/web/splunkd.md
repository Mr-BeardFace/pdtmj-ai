---
name: splunkd
services: [splunkd, splunk]
summary: Splunk — default creds, custom-app scripted-input RCE, credential extraction
---

# Splunk playbook

Splunk runs scripted inputs as the splunkd account (often root/SYSTEM), so admin access to
deploy an app is direct, high-privilege RCE. Use `http_request`. The commands below are
**examples** — compose your own from what you find.

## Access
- Example: `http_request(GET, https://<host>:8089/services/server/info)` (mgmt port 8089)

look for: default `admin/changeme`; the version; the web UI on 8000.

## RCE via a custom app
With admin, upload an app bundle containing a scripted input (a script splunkd runs) → RCE
as the Splunk user.
- Example: upload a malicious app via the API/UI, enable its scripted input → callback

look for: admin access to deploy an app.

## Loot
Splunk stores credentials (`passwords.conf`, forwarder keys) — extract and reuse.

## Record
RCE = critical (benign proof); `record_credential` extracted creds and reuse them.
