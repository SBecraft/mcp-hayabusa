---
title: Pass-the-Hash Lateral Movement Response Playbook
techniques:
  - T1550.002
alert_names:
  - Pass-the-Hash via Suspicious NTLM Network Logon
severity: high
summary: Response steps for Pass-the-Hash lateral movement using stolen NTLM hashes over network logons.
---

# Pass-the-Hash Lateral Movement Response Playbook

## Overview

Covers direct Pass-the-Hash activity: an attacker authenticates to a remote host over the network (Logon Type 3) using a stolen NTLM hash instead of a plaintext password, typically via tooling like Mimikatz's `sekurlsa::pth` or Impacket's `wmiexec`/`psexec`.

**ATT&CK technique:** T1550.002 (Use Alternate Authentication Material: Pass the Hash)

**Triggering alert:**
- Pass-the-Hash via Suspicious NTLM Network Logon

## Triage

1. Identify the target account (`TargetUserName`) and source host/IP of the logon.
2. Confirm the logon used NTLM authentication and Logon Type 3 (network), and check the associated process on the target for known lateral-movement tooling (Mimikatz, Impacket components, PsExec).
3. Determine whether the source host has independent evidence of compromise — Pass-the-Hash almost always indicates the source host's credential store (or the source of the hash) was already compromised.
4. Enumerate other hosts the same account has recently authenticated to, to scope lateral spread.

## Containment

1. Isolate both the source and target hosts from the network.
2. Disable the compromised account or force an immediate password reset, then reset again after the hash itself is confirmed rotated (a single reset can leave the old hash valid in some caching scenarios).
3. Revoke active sessions for the account across the environment, not just the alerting host.

## Eradication & Recovery

1. Identify and remediate the original credential-theft source (this alert is a *consequence* of an earlier compromise, not the initial access point — trace backward to find it, likely an LSASS access or similar credential dump).
2. Remove attacker tooling from all touched hosts.
3. Rotate credentials for every account that authenticated from or to the affected hosts during the suspected compromise window.

## Escalation Criteria

Escalate immediately if the target account has administrative rights on multiple hosts, or if lateral movement to three or more distinct hosts is confirmed within the incident window.

## References

- https://attack.mitre.org/techniques/T1550/002/
- `custom_rules/pass_the_hash_ntlm_logon.yml`
