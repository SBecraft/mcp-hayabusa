# Severity Guide

`level:` must be exactly one of `low`, `medium`, `high`, `critical` — these are the
only values `_filter_records`/`min_severity` in `server.py` understand. Every rule
must also carry a `# Severity:` comment above `detection:` that states *why* that
specific level was chosen (see `../SKILL.md` and `validate-rule.py`'s
`severity_justified` check). "Detects X" is not a justification; "detects X, which has
no legitimate business explanation and directly indicates credential theft" is.

Pick the level by asking two questions about the *specific pattern this rule matches*,
not the technique in the abstract:

1. **How deterministic is the match?** Could a normal admin, a common piece of
   software, or routine infrastructure produce this exact log pattern?
2. **How bad is it if the match is a true positive?** Does firing mean "credential
   theft in progress" or "mildly unusual, worth a second look"?

## critical

High-confidence, high-impact technique with few or no legitimate explanations. A
critical alert should be actionable on its own, without needing to be corroborated by
other detections.

- The behavior is inherently attacker tradecraft (e.g. a domain replication request
  from a non-domain-controller principal — DCSync), or
- The only realistic way to produce the log pattern is a dedicated
  credential-dumping/exploitation tool, or a LOLBin invoked in a way that has no
  routine administrative use (e.g. `rundll32 comsvcs.dll,MiniDump` against `lsass.exe`).

Ask: "If I paged someone at 3am for this alone, would they thank me or tell me to
tune it?" — critical should survive that bar.

## high

Strong indicator of malicious activity, but with a plausible, narrow false-positive
path — usually a specific class of legitimate tool (security/EDR software, backup
agents, diagnostic utilities) that happens to trigger the same signature.

- Process access to LSASS with credential-dump-typical `GrantedAccess` masks, where
  AV/EDR agents are a known, filterable source of noise.
- Use of an API or Win32 call trace (e.g. `MiniDumpWriteDump` via `dbghelp.dll`) that
  legitimate diagnostic tools (Task Manager, WerFault) also invoke, but rarely against
  this specific target process.

If you can name the 1-2 legitimate tools that would trigger this and filter them out
in the rule itself, `high` is usually right — the residual signal after filtering is
still strong.

## medium

A suspicious pattern that also occurs in legitimate or legacy use, where the
false-positive rate is high enough that the alert needs a human to triage rather than
being actionable by itself.

- RC4 Kerberos service tickets (`etype 0x17`), which are downgrade/Kerberoasting
  indicators but also appear from legacy service accounts or older application
  compatibility settings.
- A configuration or protocol choice that is *risky by design* (e.g. ROPC OAuth flows
  exposing raw user credentials to an application) but has known, common legitimate
  callers (legacy line-of-business apps, automated test harnesses).

If your `falsepositives:` list has more than one or two *common* (not edge-case)
entries, you're probably at `medium`, not `high`.

## low

A weak or noisy signal that is only useful as corroboration alongside other
detections — never something to alert on by itself.

- Broad telemetry events that are logged constantly and only become interesting in
  combination with another `medium`+ detection (e.g. a process-creation event for a
  dual-use admin tool with no suspicious arguments).
- Reconnaissance-adjacent activity that is extremely common in normal operations
  (e.g. routine LDAP queries, DNS lookups for internal hostnames).

## Worked comparison

| Pattern | Level | Why |
|---|---|---|
| DCSync from a non-DC principal | `critical` | No legitimate account outside domain controllers/AD Connect issues this request; deterministic and severe. |
| `rundll32 comsvcs.dll,#24` against `lsass.exe` | `critical` | No routine administrative reason to invoke this specific LOLBin export; near-zero legitimate use. |
| LSASS process access with dump-typical `GrantedAccess` | `high` | Strong signal, but EDR/AV agents are a known, nameable, filterable false-positive source. |
| RC4 Kerberos service ticket request | `medium` | Kerberoasting indicator, but legacy service accounts produce the same pattern routinely. |
| ROPC authentication flow used by an app | `medium` | Bypasses MFA/conditional access, but legacy apps and test harnesses are common, legitimate callers. |
| Generic process-creation telemetry for a LOLBin with benign arguments | `low` | Only meaningful paired with another detection; alone it's noise. |

## Anti-patterns to reject in review

- **Severity inflation**: marking something `critical` because the *technique* sounds
  scary (e.g. "credential access") even though the specific log pattern this rule
  matches has a wide legitimate-use footprint.
- **Severity deflation**: marking something `low` to avoid alert fatigue instead of
  fixing the rule's specificity (tighten the selection or add a filter, don't just
  lower the number).
- **No justification, or a justification that restates the title**: `# Severity: high
  — this is high severity because it's suspicious` fails the same bar as no comment
  at all.
