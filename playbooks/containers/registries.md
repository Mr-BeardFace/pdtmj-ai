---
name: registries
services: [docker-registry, registry]
summary: Container registries — unauth catalog, image pull for secrets, push to poison
---

# Container registry playbook

A registry (5000) often allows unauthenticated pull; image layers carry secrets, and push
access lets you poison images. Use `http_request` / `local_exec`. The commands below are
**examples** — compose your own from what you find.

## Enumerate
- Example: `http_request(GET, http://<host>:5000/v2/_catalog)` (list repos)
- Example: `http_request(GET, http://<host>:5000/v2/<repo>/tags/list)`

look for: an unauthenticated catalog; interesting images (app, ci, base).

## Pull & loot
Pull an image and inspect its layers/history for secrets.
- Example: `docker pull <host>:5000/<repo>:<tag>` → `docker history --no-trunc` → explore the layers

look for: hardcoded creds, tokens, private keys baked into layers.

## Push → poison (if writable)
Push access → replace an image with a backdoored one (supply-chain). Non-destructive: prove
write capability with a benign tag — don't replace a production image.

## Record
`record_credential` secrets from layers and reuse them.
