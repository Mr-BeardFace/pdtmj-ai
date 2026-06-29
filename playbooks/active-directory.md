---
name: active-directory
services: [smb, microsoft-ds, netbios-ssn, ldap, ldaps, kerberos, kerberos-sec, globalcatldap, winrm]
summary: Windows domain / Active Directory — enumeration, Kerberos attacks, BloodHound paths, lateral movement
---

# Active Directory playbook

Retrieved methodology for a Windows domain. AD environments have rich attack
surfaces — start broad, enumerate users and services, then map privilege-escalation
paths. Two guardrails are sharpened for AD.

## Guardrails (AD-specific)

- **Never trigger account lockouts.** Review the password policy and lockout
  threshold *before* any spray; then one password per spray, staying at least two
  attempts under the threshold, with a gap between rounds. Lockout-free username
  enumeration (`kerbrute userenum`, AS-REP queries) is fine; online guessing against
  the threshold is not.
- **Don't alter the domain.** No modifying ACLs, group memberships, GPOs, or objects.
  No golden/silver-ticket forging without explicit exploitation authorization. Prefer
  BloodHound DCOnly collection unless full collection is authorized.

## Attack progression — objectives, not command strings

Compose the actual queries, Kerberos requests, and hashcat modes yourself from what
each step returns. The named tools are the capability to reach for.

1. **Domain reachability.** `netexec smb <dc>` → hostname, domain, SMB-signing, OS.
   Note the domain/realm from LDAP/Kerberos responses.
2. **Unauthenticated enumeration.** Valid usernames without lockout risk
   (`kerbrute userenum`), anonymous LDAP bind (`ldapsearch_query` — users, groups,
   computers, no-preauth accounts), null-session enum (`enum4linux_ng`, `rpcclient`).
   Catch: anonymous LDAP reads, a user list, the lockout policy, AS-REP-roastable accounts.
3. **AS-REP roasting (no creds).** For any no-preauth account, retrieve the AS-REP
   hash with `impacket_kerberos` → `hashcat_crack`.
4. **With credentials.** Validate + check admin (`netexec`), authenticated directory
   enum (`ldapsearch_query`), Kerberoast SPN accounts (`impacket_kerberos` →
   `hashcat_crack`), collect the graph (`bloodhound_python` / `netexec ldap --bloodhound`),
   pull shares and the password policy.
5. **Privilege-escalation paths.** From BloodHound: DCSync rights
   (DS-Replication-Get-Changes), GenericAll/GenericWrite/WriteDACL on high-value
   objects, AdminTo edges, unconstrained/constrained delegation, readable LAPS,
   GPO-abuse. Document each as source → target → edge type → impact.
6. **Password spraying — last resort.** Only after the policy is understood and within
   the lockout discipline above; one password at a time.

Net-NTLMv2 capture via a discovered NTLM-authenticating web service is in play;
LLMNR/NBNS poisoning is out of scope here (needs a network-position tool).

## What to record

- `record_credential` for every credential/hash the moment it's obtained; crackable
  hashes go straight to `hashcat_crack` (it backgrounds and records the result).
- `annotate_finding`: anonymous LDAP / null sessions (config, high); Kerberoastable /
  no-preauth accounts (config, high); retrieved ticket/AS-REP hashes (vuln, high);
  confirmed path to Domain Admin / DCSync / credentials obtained (vuln, critical).
- A new host or subnet → `queue_followup("pentest/enumeration", "<ip>")`.
