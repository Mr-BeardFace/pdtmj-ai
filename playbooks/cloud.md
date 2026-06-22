---
name: cloud
services: [aws, gcp]
summary: Cloud infrastructure — IAM, storage exposure, compute/networking, secrets, metadata
---

# Cloud playbook

Retrieved methodology for AWS / GCP. Identify misconfigurations, excessive
permissions, exposed data, and attack paths. Use the cloud-native clients (`awscli`,
`gcloud`) — storage and IAM/compute APIs need signed requests, not raw HTTP.

## Guardrails (cloud-specific)
- **Read-only, no exfiltration.** Enumerate and assess; never modify IAM, bucket
  policies, security groups, or any resource, and never delete or write. Note that
  sensitive data *exists* and its structure — don't download it.
- Credential material found in the cloud is annotated and left there — do not pivot
  with it unless that pivot is explicitly in scope.

## What to assess
- **Identity first.** Establish your identity and permission level
  (`awscli sts get-caller-identity`, `gcloud auth list`) — limited user vs. admin
  changes the whole surface.
- **Storage (S3/GCS).** Enumerate buckets; check each for public / `allUsers` /
  `allAuthenticatedUsers` access via ACL and policy; test unauthenticated read. Public
  read = high, public write = critical, sensitive data in a public bucket = critical.
- **IAM.** Enumerate users, roles, attached policies; hunt over-permission — wildcard
  (`*`) permissions, overpermissive role trust, stale accounts with active keys,
  default service accounts with editor/owner, external-identity bindings.
- **Compute & networking.** List instances/VMs and their firewall/security-group
  exposure — `0.0.0.0/0` inbound, public-IP instances with overpermissive groups or
  sensitive attached roles.
- **Secrets & config.** Secret/parameter stores and function/VM env vars for readable
  credentials.
- **Instance metadata (only from a compromised/SSRF context).** `169.254.169.254` (AWS)
  / `metadata.google.internal` (GCP) is plain HTTP and may hand out instance
  credentials.

Annotate public buckets / overpermissive IAM / exposed secrets as high/critical the
moment found; record credentials with `record_credential`.
