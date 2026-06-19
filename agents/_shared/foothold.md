## Turning code execution into a foothold

When your work lands a **command-execution primitive** — any way to run a command on the target — the next job is to turn it into a **stable session plus a reliable output channel**, then loot, escalate, and hand off. What follows is methodology, not a script: work out the specific commands, payloads, and encodings yourself for the actual target, OS, and filters in front of you. Stay in scope, keep it non-destructive (a foothold is never a reason to damage data or disrupt a service), and record everything you plant.

### The primitive may be blind
Often you can run a command but not see its output (web command injection, SSTI, deserialization). Step zero is a feedback channel, in priority order:

1. **HTTP exfil (most reliable):** start an `oob_listener`, then run a command that encodes its own output and sends it back over an outbound HTTP (or DNS) callback; read the decoded result from the listener. Drive each command through `web_exec` or `http_request`.
2. **Reverse shell:** if arbitrary outbound is allowed, `start_listener`, trigger a reverse-shell payload, and drive the caught session with `shell_exec` (it frames output for you). New shells are announced automatically.
3. **Write to a readable location** the target already serves, then retrieve it.

Confirm the primitive actually executes (a single callback ping) before building on it.

**If the primitive executes a binary directly rather than through a shell** (common with command-injection and SSTI sinks), shell metacharacters and redirections are NOT interpreted — a redirection-based reverse-shell one-liner is passed as literal arguments and never connects. Either wrap the whole payload as a single argument to an explicitly-invoked shell, or stage it to a file and execute that file. This is also why a reverse shell can silently fail while OOB exfil works — don't conclude outbound is blocked until you've tried invoking a shell explicitly.

**A connect-*in* method survives egress filtering where a reverse shell won't** — injecting a key and connecting back with `ssh_exec`, or plain OOB HTTP exfil, needs no outbound shell. Reach for those first when outbound looks blocked, but treat each as a single attempt.

**When the primitive needs custom code no tool can produce** — a non-trivial deserialization payload, a binary handshake, a specific filter-evasion encoder — write it with `run_script` (Python preferred) as a last resort and drive the target through your channel. Try dedicated tools first.

### Bank the foothold the instant exec is confirmed
The moment code execution is proven, call `annotate_finding` for it — **verified, with the evidence (the command and its output)** — before anything else. The foothold is the headline finding; everything after builds on it, and your run can stop at the turn cap mid-privesc. Confirm exec → annotate → continue. Fingerprint the OS and current user immediately; everything forks on that.

### Upgrade the channel — but don't get stuck chasing a shell
A clean, framed session is *nicer* to work through, so make a brief, time-boxed attempt to upgrade — but it is a means, not the goal. At most a couple of focused tries:
- **Linux:** inject a generated key (`ssh_keygen`) into the user's authorized_keys and connect back with `ssh_exec`; or add an account; or hold a reverse shell.
- **Windows:** create an admin account with a generated password (`record_credential` it) and drive it with `netexec winrm`; or enable a remote-management service.

If a durable channel doesn't come up in a couple of tries, **stop stabilising and use the primitive you already have.** A working primitive — even simple OOB HTTP exfil that returns output — is enough to enumerate, read files, harvest credentials, check privesc, and reach the objective. Recognise when stabilisation can't work and pivot to enumerating *through* the primitive instead of retrying: a service/daemon account with no interactive login (an injected key is pointless), filtered egress (a reverse shell never connects — OOB exfil often still works), or app-enforced session limits that make any held channel flaky. Need a tool on the target? Host it with `oob_listener(action='host', …)` and pull it down.

### Always record what you change
`record_persistence` is the engagement's IOC ledger — call it the moment you change the target, for anything *planted* (an authorized key, a new account, an enabled service, a dropped payload, a scheduled task) **and** anything *modified* (a changed password, an edited config, a flipped registry value). Give the exact `cleanup`/revert command, and for a modification put the original value in `before`. Keep every change reversible and non-destructive; an undocumented or unrevertable change is unacceptable.

### Loot and crack credentials — usually the real escalation path
A foothold's biggest prize is **other people's passwords**. As soon as exec works, harvest and crack:
- **Harvest** credential stores: app config and DB connection strings, the app's own user/hash table, the system password/shadow store (if readable), private keys, shell history, cloud/CI tokens, vaults, and Windows credential stores.
- **Crack with the `hashcat_crack` tool — not a hand-written `run_script`.** It runs in the background, escalates passes (your `custom_words` first, then wordlist, then wordlist+rules), and auto-records the recovered password. Pass the hash, its format/mode, and the username/location; build `custom_words` from engagement intel (app name, hostnames, found passwords, usernames). This is offline cracking of hashes you already hold — normal looting, not the online "brute-force last resort."
- **Reuse aggressively.** Password reuse is the norm: a cracked app/service-account password is very often a local user's too. The moment you recover a plaintext, try it against every matching local account and every other reachable service.

### Then escalate and hand off
Enumerate for privilege escalation (sudo rights, SUID/SGID, capabilities, scheduled jobs, writable root-owned paths on Linux; service, registry, token, and path issues on Windows), escalate where a clear path exists, and read any objective. **Annotate each privesc vector with `annotate_finding` the moment you confirm it — one call per vector, as you go, not batched** (verified, with evidence; never put secrets in findings — use `record_credential`). Don't tunnel on the flag: cracking creds, escalating, and proving reuse/lateral movement are the engagement. When the objective is met, `conclude_engagement`.
