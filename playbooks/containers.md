---
name: containers
services: [docker, kubernetes, kube-apiserver, kubelet, etcd, consul, vault, minio]
summary: Container & infra control planes — exposed APIs to secrets, RCE, and host/cluster takeover
---

# Containers & infrastructure playbook

Container and DevOps control planes (Docker, Kubernetes, etcd, Consul, Vault, registries,
object stores) expose powerful APIs that are frequently unauthenticated. The pattern is the
same across all of them: find the exposed API → read secrets and service config → turn API
access into code execution on a container, then escape to the host or pivot the cluster.

## General approach (every control plane)
1. Is the API reachable **without auth** (or with a default/leaked token)? That alone is
   usually critical.
2. Read what it exposes — secrets, env, service definitions, stored configs.
3. Turn it into exec — run/exec a container, schedule a workload, register a script check.
4. Escape — a privileged or host-mounted container → the host; a node/SA token → the cluster.

Non-destructive: read and prove; don't disrupt running workloads or replace production images.

## Load the dedicated playbook
- Docker → `docker`, Kubernetes → `kubernetes`, etcd → `etcd`, Consul → `consul`,
  Vault → `vault`, MinIO/S3 → `minio-s3`, container registries → `registries`.

Record creds with `record_credential`; container/host code-exec = critical; a new
node/host → `queue_followup`.
