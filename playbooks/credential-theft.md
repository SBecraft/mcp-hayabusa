---
title: Credential Theft Response Playbook
techniques:
  - T1003.001
  - T1003.006
alert_names:
  - Suspicious Process Access to LSASS Memory
  - LSASS Memory Dump via comsvcs.dll MiniDump
  - DCSync - Directory Replication Services Used to Dump Credentials
severity: high
summary: Response steps for LSASS memory access, comsvcs.dll LSASS dumping, and DCSync-based credential theft.
---

# Credential Theft Response Playbook

## Overview

Covers two related but distinct credential-dumping paths against a Windows environment: direct memory access to `lsass.exe` (including the comsvcs.dll MiniDump living-off-the-land technique), and DCSync abuse of the Directory Replication Service to pull password hashes without touching a domain controller's disk.

**ATT&CK techniques:** T1003.001 (OS Credential Dumping: LSASS Memory), T1003.006 (OS Credential Dumping: DCSync)

**Triggering alerts:**
- Suspicious Process Access to LSASS Memory
- LSASS Memory Dump via comsvcs.dll MiniDump
- DCSync - Directory Replication Services Used to Dump Credentials

## Triage

1. Identify the source process and account for the alert (`SourceImage`/`SubjectUserName` in the underlying event).
2. For LSASS access/dump alerts: confirm the source process isn't a known EDR/AV/backup agent (check against the process's on-disk hash and signing certificate, not just its name — attackers rename binaries).
3. For DCSync alerts: confirm `SubjectUserName` is not a legitimate domain controller computer account (`$`-suffixed) or an authorized directory-sync service account (e.g. Azure AD Connect).
4. Check whether the host is a domain controller. A DCSync request *originating* from a DC is expected; one *targeting* a DC from a workstation or member server is not.
5. Pull recent process creation and network logon history for the source account to look for precursor activity (e.g. `Rubeus`, `Mimikatz`, `secretsdump.py`, `wmiexec.py`).

## Containment

1. Isolate the source host from the network if the activity is confirmed malicious.
2. Disable or force-expire credentials for the account(s) whose secrets may have been exposed — for DCSync, this can mean every account in the domain, prioritize privileged and service accounts first.
3. If `krbtgt` hash exposure is suspected (common DCSync objective), plan a `krbtgt` password reset (twice, per Microsoft guidance, to invalidate all outstanding Kerberos tickets).
4. Revoke active sessions/tokens for affected accounts.

## Eradication & Recovery

1. Remove any dropped credential-dumping tooling and persistence mechanisms found on the source host.
2. Rotate credentials for every account confirmed or suspected compromised.
3. Rebuild the source host from a known-good image if attacker tooling had SYSTEM-level access.

## Escalation Criteria

Escalate to incident commander immediately if: the source account has Domain Admin/Enterprise Admin rights, the DCSync request succeeded (not just attempted), or `krbtgt` was among the accounts targeted.

## References

- https://attack.mitre.org/techniques/T1003/001/
- https://attack.mitre.org/techniques/T1003/006/
- `custom_rules/lsass_memory_access_process.yml`, `custom_rules/lsass_dump_via_comsvcs.yml`, `custom_rules/dcsync_replication_rights.yml`
