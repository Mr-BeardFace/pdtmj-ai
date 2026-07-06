---
name: java-rmi
services: [java-rmi, rmi, jmx, jdwp]
summary: Java RMI/JMX/JDWP — deserialization and MBean code execution
---

# Java RMI / JMX / JDWP playbook

Exposed Java remoting endpoints commonly yield RCE via deserialization or MBean abuse. Use
the `ysoserial` tool (or `local_exec`). The commands below are **examples** — compose your own.

## RMI registry (1099) — deserialization
- Example: enumerate the registry, then deliver a `ysoserial` gadget at the sink
  (`ysoserial CommonsCollections6 '<cmd>'`) matched to a gadget on the target's classpath

look for: a registry that accepts a bound object and a known-vulnerable gadget available.

## JMX (1099 / 9999) — MBean RCE
Unauth or default-cred JMX → load an MLet MBean that pulls and runs code you host.
- Example: point the target's MLet at a jar you serve (`oob_listener` host) → RCE

look for: JMX reachable with no auth or default creds.

## JDWP (debug port) — direct RCE
An exposed Java Debug Wire Protocol port is arbitrary code execution by design.
- Example: `jdwp-shellifier` against the port → command exec

look for: the JDWP handshake succeeds (debugging left enabled).

## Record
RCE = critical (benign proof); `record_persistence` anything planted.
