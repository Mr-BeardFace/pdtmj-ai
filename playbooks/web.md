---
name: web
services: [http, https, http-alt, https-alt, http-proxy, www, ssl/http]
summary: Web application — content discovery, injection, auth/authz, APIs, client-side
---

# Web playbook

Retrieved methodology for a web application. **Map the whole application before
committing to any one thing** — enumerate every directory, endpoint, and parameter
first, then choose targets with the full map in hand. The endpoint that matters is
often not the first one found. Non-disruptive: probe to confirm what something *is*;
never drop tables or DoS to prove a point.

## 1. Fingerprint the stack
- `tls_inspect` on HTTPS ports — extract SANs as additional scope/vhosts.
- `nmap -sV -sC` / `nuclei_scan` tech-detection → server, framework, CMS, version.
- `http_request` `/robots.txt`, `/sitemap.xml`; mine HTML/JS for linked paths.

## 2. Exhaustive content discovery (the core)
- `nuclei_scan` for CVEs, exposed panels, default creds, security headers.
- `gobuster_dir` with stack-appropriate extensions (PHP: `php,bak,zip,sql,inc`;
  ASP.NET: `aspx,asp,config,bak`; Java: `jsp,do,action,war`; generic: `html,txt,bak,zip,conf,log,xml,json`).
- **Recurse** into every directory found and discover again until nothing new appears.
- Each discovered vhost (e.g. `app.target.htb`) gets its own full pass.
- `ffuf` for parameter/value fuzzing on endpoints that take input.

## 3. Catalogue + attack each endpoint
- **Reflected input** → `<test>` then XSS payloads (`dalfox` to confirm/PoC).
- **URL/param** → `'`, `"`, `{{7*7}}`, `; id`, `../../../etc/passwd`, `%0a`.
- **SQLi** → `admin'--`, `' OR '1'='1`, `' UNION SELECT NULL--`; `sqlmap_scan` to confirm/extract (read-only).
- **SSTI** → `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`. **LFI** → traversal + PHP filter wrappers.
- **Auth** → default/vendor creds; SQLi in login (`admin'--`, `admin' OR '1'='1'--`).
  For authenticated flows pass a named `session` to `http_request` (e.g. `session="admin"`):
  log in once and every later call with that name stays authenticated, cookies carried —
  check `session_cookies` in the response to confirm. Use it for post-login enumeration,
  CSRF-token flows, and IDOR/authz tests as a real user.
  **An image CAPTCHA is not a dead end** — load the form with a named `session` (sets the
  captcha cookie + gives the captcha id/image URL), call `captcha_solve` with that same
  session and the image URL (`charset='digits'` for Gogs-style, else `'alnum'`), then submit
  in the SAME session with the decoded value + captcha id. If rejected, the captcha rotates
  per request — reload the form and solve the fresh one. (Behavioral/JS challenges —
  reCAPTCHA, hCaptcha, Turnstile — are not OCR-solvable; find another way in.)
  Check JWTs (`alg:none`, weak secret), lockout, username enum, auth bypass (verb
  tampering, `X-Forwarded-For: 127.0.0.1`).
- **Authz** → IDOR (increment IDs), horizontal/vertical privilege escalation, mass
  assignment (`role=admin`).
- **API** → GraphQL introspection, undocumented methods (PUT/DELETE), old API versions.
- **Headers/client** → CORS reflection (`Origin: https://evil.com`), missing CSP/HSTS.
- **Blind** → `oob_listener` for blind SSRF/RCE/XXE.

## 4. Confirm
A finding is verified only with concrete proof: SQLi = extracted data; XSS = executing
PoC; LFI = `/etc/passwd` contents; RCE = command output (`id`/`whoami`). When you land
code execution, switch to the foothold methodology (turn it into a stable channel).

Record credentials with `record_credential`; annotate each issue with `annotate_finding`
(`verified=false` until proven). A new host/subnet → `queue_followup`.
