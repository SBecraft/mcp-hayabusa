---
title: Kerberos Ticket Abuse Response Playbook
techniques:
  - T1558.003
  - T1550.002
alert_names:
  - Potential Kerberoasting via RC4 Service Ticket Request
  - Overpass-the-Hash - Kerberos TGT Request Following NTLM Hash Use
severity: medium
summary: Response steps for Kerberoasting (RC4 service ticket requests) and Overpass-the-Hash (NTLM-to-Kerberos ticket requests).
---

# Kerberos Ticket Abuse Response Playbook

## Overview

Covers two Kerberos-abuse techniques that let an attacker obtain usable credentials/tickets without ever touching LSASS directly: Kerberoasting (requesting a weakly-encrypted RC4 service ticket for offline cracking) and Overpass-the-Hash (using a stolen NTLM hash to request a legitimate Kerberos TGT, bypassing NTLM-specific detections).

**ATT&CK techniques:** T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting), T1550.002 (Use Alternate Authentication Material: Pass the Hash — the Overpass-the-Hash variant)

**Triggering alerts:**
- Potential Kerberoasting via RC4 Service Ticket Request
- Overpass-the-Hash - Kerberos TGT Request Following NTLM Hash Use

## Triage

1. Identify the requesting account (`TargetUserName`/`SubjectUserName`) and source host/IP for the ticket request.
2. For Kerberoasting alerts: check request volume and diversity — a single account requesting RC4 tickets for many distinct SPNs in a short window is a strong indicator versus one-off legacy-application traffic.
3. For Overpass-the-Hash alerts: confirm whether the account normally authenticates via Kerberos with AES, and whether this is the first RC4-based TGT request seen for that account recently.
4. Cross-reference the requesting host against known asset inventory — an unmanaged or unexpected host requesting either pattern is higher-priority.
5. Check for follow-on activity: successful service logons using a cracked/obtained ticket, lateral movement, or access to resources the account doesn't normally use.

## Containment

1. If Kerberoasting is confirmed: disable or reset the password of the targeted service account(s), prioritizing any with weak/old passwords.
2. If Overpass-the-Hash is confirmed: treat it as equivalent to a stolen credential — reset the source account's password and invalidate its active Kerberos tickets.
3. Isolate the requesting host if attacker tooling (e.g. Rubeus, PowerView) is confirmed present.

## Eradication & Recovery

1. Rotate credentials/passwords for every service account with a known-weak (non-AES, easily guessable) configuration to reduce future Kerberoasting exposure.
2. Enforce AES-only Kerberos encryption where legacy compatibility allows, to remove the RC4 downgrade path both techniques rely on.
3. Remove any credential-dumping or ticket-manipulation tooling found on the source host.

## Escalation Criteria

Escalate if the targeted/compromised service account has elevated privileges (Domain Admin service accounts, accounts with access to sensitive systems), or if cracked credentials are confirmed used elsewhere in the environment.

## References

- https://attack.mitre.org/techniques/T1558/003/
- https://attack.mitre.org/techniques/T1550/002/
- `custom_rules/kerberoasting_rc4_service_ticket.yml`, `custom_rules/overpass_the_hash_ticket_request.yml`
