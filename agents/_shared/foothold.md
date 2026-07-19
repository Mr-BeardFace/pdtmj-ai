## Turning code execution into a foothold

When your work lands a **command-execution primitive** — any way to run a command on the target — the next job is to turn it into a **stable session plus a reliable output channel**, then loot, escalate, and hand off. What follows is methodology, not a script: work out the specific commands, payloads, and encodings yourself for the actual target, OS, and filters in front of you. Stay in scope, keep it non-destructive (a foothold is never a reason to damage data or disrupt a service), and record everything you plant.

### From a file-write primitive to execution
Several services give you the ability to **write a file**, not run a command — a
writable NFS/SMB share, a Redis/Postgres/MySQL file-write, an FTP/WebDAV upload, a
writable web root. Convert write → exec by writing where the target will *act on* the
file; pick by **where** you can write, **as whom**, and **what the host will run it with**
— the selector is which *mechanism/service is actually present*, not the OS label:
- **Web root → webshell.** A write under a directory the web server executes → drop a
  minimal shell in the stack's language (`.php`/`.aspx`/`.jsp`) and request its URL
  (`.aspx` on IIS, etc.). look for: the document root from config or a known app path.
- **`authorized_keys` → log in — where an SSH service is reachable.** If sshd is exposed
  and you can write the target account's `authorized_keys`, append a key you generated
  (`ssh_keygen`) and connect with `ssh_exec` — the most stable outcome, a connect-in not a
  held channel. **This is gated on the SSH *service*, not the OS**: Windows OpenSSH counts
  (admin keys live in `C:\ProgramData\ssh\administrators_authorized_keys`). Skip it only
  when no SSH is reachable — then nothing authenticates the key.
- **cron → scheduled exec (Unix mechanism).** A writable `/etc/cron.d/`, `/etc/crontab`, or
  a user's crontab runs your command as that user (root for system cron). Mind the format —
  cron is strict about the user field and a trailing newline.
- **SUID root binary — only when writing AS root (Unix mechanism).** Writing as uid 0 (e.g.
  `no_root_squash` NFS) → drop a root-owned binary, set the SUID bit, run it from a normal
  shell for an instant root shell.
- **Windows-native locations.** A writable Startup folder (`.bat`/`.lnk` runs at logon), a
  service or scheduled-task binary/script path, or a DLL-search-order directory a program
  side-loads from → plant there and the OS runs it as that user/SYSTEM.

`record_persistence` whatever you plant with the exact cleanup, and remove it when done.
Once one lands you have execution — continue below.

### The primitive may be blind
Often you can run a command but not see its output (web command injection, SSTI, deserialization). Step zero is a feedback channel, in priority order:

1. **HTTP exfil (most reliable):** start an `oob_listener`, then run a command that encodes its own output (e.g. `… | base64 -w0`) and sends it back over an outbound HTTP (or DNS) callback; drive each command through `web_exec` or `http_request`. `check` returns the **raw** capture — it never guesses an encoding. If what comes back looks encoded (base64/hex/gzip), call `check` again with `decode=` set to the codec you recognize. Garbled-looking output is almost always still-encoded exfil, **not** a broken shell — decode it before concluding the channel failed.
2. **Reverse shell (framed):** if arbitrary outbound is allowed, `start_listener` (it returns ready-to-fire payloads), trigger one through the primitive, and drive the caught session with `shell_exec` — the manager frames per-command output for you, and new sessions are announced automatically (`list_shells` recovers a session id). Keep commands non-interactive. A plain `nc` listener is the crude fallback if you need it.
3. **Write to a readable location** the target already serves, then retrieve it.

Confirm the primitive actually executes (a single callback ping) before building on it.

**If the primitive executes a binary directly rather than through a shell** (common with command-injection and SSTI sinks), shell metacharacters and redirections are NOT interpreted — a redirection-based reverse-shell one-liner is passed as literal arguments and never connects. Either wrap the whole payload as a single argument to an explicitly-invoked shell, or stage it to a file and execute that file. This is also why a reverse shell can silently fail while OOB exfil works — don't conclude outbound is blocked until you've tried invoking a shell explicitly.

**A connect-*in* method survives egress filtering where a reverse shell won't** — an SSH key + `ssh_exec` wherever sshd is reachable, `netexec winrm`/RDP with creds you hold, or plain OOB HTTP exfil — all need no outbound shell. Reach for whichever remote-access service the target actually exposes when outbound looks blocked, and treat each as a single attempt.

**When the primitive needs custom code no tool can produce** — a non-trivial deserialization payload, a binary handshake, a specific filter-evasion encoder — write it with `run_script` (Python preferred) as a last resort and drive the target through your channel. Try dedicated tools first.

### Bank the foothold the instant exec is confirmed
The moment code execution is proven, call `annotate_finding` for it — **verified, with the evidence (the command and its output)** — before anything else. The foothold is the headline finding; everything after builds on it, and your run can stop at the turn cap mid-privesc. Confirm exec → annotate → continue. Fingerprint the OS and current user immediately; everything forks on that.

### Pin the operational facts so the next turn acts, not re-derives
As you establish HOW this target is exploited and HOW your access behaves, `record_fact` the durable ones — this is act-on-this scaffolding, kept apart from findings so a later turn (or the next agent) builds on it instead of re-reading artifacts to reconstruct it, or worse, contradicting it. Two kinds, each proven with the command that established it:

- **target** — a property that dictates the exploit. *Example:* you `file` a binary you'll inject into and it's a .NET AnyCPU/PE32 assembly → the LoadLibrary target runs 64-bit, so `record_fact(kind='target', 'native DLL must be x64', evidence='file UpdateMonitor.exe → PE32 Mono/.Net assembly')`. Check the property before you build against it — the fact is what stops you from rebuilding the wrong-arch payload three runs in a row.
- **channel** — an access/exec channel you established and how it behaves. *Example:* a scheduled-task DLL gives exec but the reverse shell returns empty → `record_fact(kind='channel', 'DLL exec works but the shell is BLIND — stdout not piped; exfil over the OOB listener', evidence='whoami via shell → empty; same via OOB POST → logging\\jaylee')`. Also pin the working command channel itself (e.g. WinRM as which principal, via password or hash).

If a later result corrects a fact you pinned, `record_fact` the correction with `supersedes=<old id>` so the wrong one is retired, not left to mislead the next turn.

### Loot with the primitive you have — before chasing a better channel
The exec you already have is enough to read files. The moment it's confirmed, use it to grab the immediate wins — `id`/`sudo -l`, the user flag, readable creds/config, SUID/cron/writable-path privesc vectors — and record them (`record_credential`/`record_flag`/`annotate_finding`). A one-shot or blind primitive is fine for this; you do not need a full shell to read files. Invest in a stable channel only when sustained interactive work needs one (see below), and never abandon a working exploit to chase a prettier shell.

**Exec channels are finicky with formatting.** Once a command runs (e.g. a one-token `id`), FREEZE that exact request/encoding and change ONLY the command string — don't refactor the transport (string↔bytes, re-encoding), it silently breaks. If a command with spaces or quotes fails where `id` worked, the channel mangled it — a form parser turning `+` into spaces, URL-encoding `"`→`%22`, the sink's own quoting. Avoid spaces/quotes: use `${IFS}`, base64-decode (`echo <b64>|base64 -d|sh`), or stage a script to disk and run it. Don't hammer a rate/session-limited exploit — you already proved access; reuse it sparingly.

### Upgrade the channel — but don't get stuck chasing a shell
A clean, framed session is *nicer* to work through, so make a brief, time-boxed attempt to upgrade — but it is a means, not the goal. There's a preference order, but **the real selector is stability: try them roughly in this order and keep whichever holds up most reliably for *this* target, not whichever is highest on the list.**

1. **Connect-in over a real service — most stable.** A login you initiate beats a session you're holding open: it survives egress filtering, process death, and session timeouts. Use whichever remote-access service the target actually exposes: where **sshd is reachable** (Linux, or Windows OpenSSH) inject a generated key (`ssh_keygen`) into that account's authorized_keys and connect back with `ssh_exec`; otherwise reuse/created credentials via `netexec winrm` or RDP (typical on Windows), or enable a remote-management service. This is the "SSH implant / identified creds" tier — prefer it when it's available.
2. **Reverse shell (framed).** If a connect-in isn't available but arbitrary outbound is allowed, hold a `start_listener` session and drive it with `shell_exec`. Stable enough to work through, but dies with the process and won't survive egress filtering.
3. **The initial access vector itself.** The primitive you already have — blind OOB exfil, web command injection, the exploit sink — is always available because it's how you got in. Least convenient, but a guaranteed fallback: it's enough to enumerate, read files, harvest credentials, check privesc, and reach the objective.

So: attempt 1, fall to 2, and if neither holds, **stop stabilising and just work through 3** — at most a couple of focused tries before you pivot. Don't burn the run chasing a prettier shell when the access vector already lets you operate. Recognise when a tier *can't* work and skip it: an SSH key where no SSH service is reachable (a Windows host with no OpenSSH, or sshd firewalled off — nothing authenticates the key) or the target account has no interactive login, filtered egress (a reverse shell never connects — OOB exfil often still works), or app-enforced session limits that make any held channel flaky. Need a tool on the target? Host it with `oob_listener(action='host', …)` and pull it down.

### If the remote path can't reach, run the tool on the host
Remote tooling (Impacket, certipy, netexec from Kali) needs no upload, so it's the natural
first reach — but it authenticates the identity over the network, so it only works while you
*hold* that identity's password or hash. When what you have instead is code-execution **as**
a principal you can't replay remotely — a blind privesc as a user whose secret you never
recovered — the same abuse usually runs fine **locally, in that token's context**: stage a
tool that fits the host and the technique with `oob_listener(action='host', …)`, pull it down
through the exec primitive you already have, and run it there. On Windows the on-host family
covers what the remote path can't — Rubeus for Kerberos tickets/roasting, Certify for ADCS
templates, a potato for SeImpersonate. It's a normal fallback, not a last resort: if a remote
attack keeps bouncing off a credential you don't have, that missing credential is the cue to
switch to on-host rather than keep retrying the same remote call.

### Always record what you change
`record_persistence` is the engagement's IOC ledger — call it the moment you change the target, for anything *planted* (an authorized key, a new account, an enabled service, a dropped payload, a scheduled task) **and** anything *modified* (a changed password, an edited config, a flipped registry value). Give the exact `cleanup`/revert command, and for a modification put the original value in `before`. Keep every change reversible and non-destructive; an undocumented or unrevertable change is unacceptable.

### Loot and crack credentials — usually the real escalation path
A foothold's biggest prize is **other people's passwords**. As soon as exec works, harvest and crack:
- **Harvest** credential stores: app config and DB connection strings, the app's own user/hash table, the system password/shadow store (if readable), private keys, shell history, cloud/CI tokens, vaults, and Windows credential stores. An app's **config is also its credential recipe** — it defines how the stored passwords are protected (algorithm, salt, iteration count, any pepper). Whenever you pull a user/hash table, pull the app's config too: you need that scheme to crack those hashes, and configs routinely leak DB/service secrets besides.
- **When a harvested value is encoded or reversibly encrypted, try to recover the plaintext right then** — don't bank it as opaque and move on. Many app secrets aren't real hashes: they're base64, hex, a known-key scheme (NiFi `enc{…}`, GPP `cpassword`, Jenkins/Tomcat/web.config secrets, Django/Rails/Flask signing material), or otherwise deterministically reversible. If you recognize the scheme, decode/decrypt it immediately with the matching deterministic step (`run_script` for a known algorithm, the right codec, or the tool that owns that format). It won't always be reversible — plenty are genuine one-way hashes that belong in `hashcat_crack` — but an *encoded* secret you walked past is an unfinished lead, not a finding. Record the recovered plaintext with `record_credential` and reuse it.
- **Crack with the `hashcat_crack` tool — not a hand-written `run_script`.** It runs in the background, escalates passes (your `custom_words` first, then wordlist, then wordlist+rules), and auto-records the recovered password. Pass the hash, its format/mode, and the username/location; build `custom_words` from engagement intel (app name, hostnames, found passwords, usernames). This is offline cracking of hashes you already hold — normal looting, not the online "brute-force last resort."
- **Salted hash? You need the salt, and it lives apart from the hash.** The salt (with the algorithm and iteration count) comes from the app's config or DB schema, not the hash table — an app that stores `algo(salt+password)` keeps only the digest per user. hashcat's salted modes take the input as `hash:salt`, so a bare hash — or a saltless mode (`sha256` where the scheme is `sha256($pass.$salt)`) — never lands, whatever the wordlist. Identify the full scheme, retrieve the salt, and build the input in that mode's format. **A salted hash that won't crack is a construction problem first — wrong mode, missing or mis-ordered salt — not a wordlist problem: go back to the config for the salt/algorithm before grinding.**
- **Password-protected/encrypted file?** (a downloaded zip/7z/rar, a KeePass `.kdbx`, an encrypted SSH key, an Office doc, a PDF) — run `hash_extract` on it to pull the crackable hash, then crack it with `hashcat_crack` (use its suggested mode) or `john` (auto-detects the format; use it for file formats hashcat lacks a mode for). Both background and auto-record the plaintext.
- **Reuse aggressively.** Password reuse is the norm: a cracked app/service-account password is very often a local user's too. The moment you recover a plaintext, try it against every matching local account and every other reachable service.
- **A known password reveals the scheme, not just the string.** When a captured password fails elsewhere but is clearly patterned — a season+year (`Summer2024`), a base word plus digits/symbol (`Company1!`), a keyboard walk (`Qwerty123`, `Zxcvbn!`), or an incrementing counter — that pattern is the target's password *policy*. Derive close variations and try them: roll the season/year forward (`Autumn2025`), bump the trailing number/symbol (`Company2!`, `Company1@`), flip case, extend the walk; and feed the same mutations into `hashcat_crack` `custom_words` (its rules pass expands them) when cracking. Against a domain, stay within the lockout discipline — one candidate at a time, policy understood first.

### Then escalate and hand off
Enumerate for privilege escalation (sudo rights, SUID/SGID, capabilities, scheduled jobs, writable root-owned paths on Linux; service, registry, token, and path issues on Windows), escalate where a clear path exists, and read any objective. **Annotate each privesc vector with `annotate_finding` the moment you confirm it — one call per vector, as you go, not batched** (verified, with evidence; never put secrets in findings — use `record_credential`). Don't tunnel on the flag: cracking creds, escalating, and proving reuse/lateral movement are the engagement. When the objective is met, `conclude_engagement`.

**When the foothold fronts a subnet or loopback service the attack box can't reach**, that's a pivot, not a dead end — `load_playbook(["pivoting"])`: the `port_forward` tool where SSH is reachable, a dropped ligolo-ng/chisel agent from a Windows/RCE host. Re-enumerate the newly reachable hosts and `queue_followup` the subnet.
