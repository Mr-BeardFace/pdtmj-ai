---
name: tomcat
services: [tomcat]
summary: Apache Tomcat — manager default creds → WAR deploy RCE, Ghostcat file read
---

# Tomcat playbook

Tomcat's Manager app deploys WARs, so default/weak creds on `/manager` are direct RCE. Use
`http_request`. The commands below are **examples** — compose your own from what you find.

## Find the manager & creds
- Example: `http_request(GET, http://<host>:8080/manager/html)` (401 = present)
- common defaults: `tomcat/tomcat`, `admin/admin`, `tomcat/s3cret`, `role1/role1`

look for: `/manager/html` or `/host-manager` reachable; default creds accepted.

## WAR deploy → RCE
With manager access, deploy a WAR containing a JSP webshell, then request it.
- Example: build a `.war` with a JSP shell → POST to `/manager/text/deploy?path=/x` → `GET /x/shell.jsp`

look for: deploy succeeds → RCE (prove with a benign command).

## Other vectors
- `/manager/text` scripting API; CVE-2017-12617 (`PUT` a JSP); **Ghostcat** (AJP 8009,
  CVE-2020-1938) arbitrary file read of `WEB-INF`.

## Record
RCE = critical; `record_credential` for manager creds; `record_persistence` the deployed app.
