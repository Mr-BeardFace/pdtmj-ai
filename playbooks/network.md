---
name: network
services: [ssh, ftp, ftps, smtp, snmp, telnet, rdp, ms-wbt-server, vnc, nfs, winrm]
summary: Non-web / non-DB / non-AD services — SMB, SSH, FTP, SMTP, SNMP, RDP, NFS, WinRM
---

# Network services playbook

Retrieved methodology for non-web, non-database, non-AD services. Technique ordering
for every service, cheapest-and-quietest first:

1. anonymous / unauthenticated access (null session, anon FTP, public SNMP strings)
2. a *single* check of well-known product defaults
3. credentials already discovered this engagement, replayed where they apply
4. known CVEs and misconfigurations
5. only then, targeted brute with a short engagement-derived list — never the opener

Do nothing disruptive: read, enumerate, prove — confirm any write capability with a
benign marker, don't damage data.

## Per-service focus
- **SMB (139/445):** enumerate the full share list, then read every non-admin share
  recursively — the foothold is almost always a file in a share, not `IPC$`. `netexec`/
  `smbclient` (no share = list mode); `rpcclient` for null-session user/RID. Catch:
  null/guest reads, writable shares, secrets in files, SMB CVEs (MS17-010).
- **SSH (22):** the realistic way in is reused credentials — replay every discovered
  cred first. Catch: password auth where key-only is expected, exposed keys. Brute is
  almost never the path.
- **FTP (21):** anonymous access and what it exposes; readable files, writable dirs, traversal.
- **RDP (3389):** assess exposure/patch without logging in — NLA disabled, weak crypto,
  BlueKeep-class CVEs.
- **SNMP (161/UDP):** try common community strings; if one works, pull system info,
  processes, software, routing. Catch: working strings, v1/v2c, infra disclosure.
- **Telnet (23):** identify the service/banner; flag the cleartext protocol itself.
- **SMTP (25/587/465):** open relay, VRFY/EXPN user enum, missing STARTTLS.
- **WinRM (5985/5986):** reachability and, with any creds, whether they grant command
  execution (`netexec winrm`).
- **VNC (5900):** desktop reachable without / with trivial auth.
- **NFS (2049):** list exports; world-readable/writable exports, sensitive files, and
  `no_root_squash` (a direct privilege-escalation primitive).
- **Other:** same shape — anon/unauth → defaults → reused creds → CVEs; reach for the
  protocol's real client, not a brute tool, to open it.

Annotate findings (`verified=false` until confirmed); record creds with
`record_credential`; a new host/subnet → `queue_followup`. On code execution or a
caught session, switch to the foothold methodology.
