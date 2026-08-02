# False Positive Patterns

Every rule needs a non-empty `falsepositives:` list where each entry names a
*concrete, plausible legitimate cause* of the detection firing — not a hedge like
"unknown" or "none observed" used as a placeholder (`validate-rule.py`'s
`false_positives` check rejects a fixed set of these placeholder strings outright).
If you genuinely believe there are no false positives, say so explicitly and explain
why — that's a testable claim a reviewer can push back on, unlike "none".

Bad: `falsepositives: ["Unknown"]`
Good: `falsepositives: ["Legitimate domain controllers and Azure AD Connect /
directory-sync service accounts"]`

The categories below are the recurring *sources* of false positives across this
project's rules. When writing a new rule, check whether one of these applies to your
detection surface, and if so, name the specific tool/account/process — not the
category name itself.

## 1. Security and EDR tooling

Antivirus, EDR agents, and vulnerability scanners routinely perform the same actions
attackers do (reading process memory, enumerating credentials, making privileged API
calls) because that's how they detect those same attacks.

- Example: `MsMpEng.exe` (Windows Defender) and other AV engines opening LSASS with
  broad `GrantedAccess` for their own credential-theft scanning.
- How to document it: name the specific product/process, not "security software" —
  `SourceImage|endswith: '\MsMpEng.exe'` in a `filter_*` selection, and the matching
  `falsepositives` entry naming Defender specifically.

## 2. Built-in Windows diagnostic and admin tools

Task Manager, Windows Error Reporting, and Sysinternals tools invoke the same
underlying APIs (e.g. `MiniDumpWriteDump` via `dbghelp.dll`/`dbgcore.dll`) that
credential-dumping tools use, for legitimate crash/diagnostic dumps.

- Example: `Taskmgr.exe`'s "Create dump file" feature or `WerFault.exe` generating a
  crash dump if a monitored process (even `lsass.exe`) crashes.
- How to document it: filter the specific known-legitimate `SourceImage`, and note in
  `falsepositives` that a renamed/relocated copy of the tool would evade the filter —
  that's the honest residual risk, not a reason to skip the filter.

## 3. Legacy protocols and backward-compatibility settings

Older authentication protocols, cipher suites, or application flows that are
insecure-by-current-standards but still intentionally enabled for compatibility with
legacy systems or applications that haven't been migrated.

- Example: RC4-encrypted Kerberos service tickets (Kerberoasting indicator) also
  produced by legacy service accounts or apps pinned to older `msDS-SupportedEncryptionTypes`.
- Example: ROPC (resource owner password credential) OAuth flows, which bypass MFA
  and conditional access but are sometimes the only flow a legacy line-of-business
  app supports.
- How to document it: name the legacy use case specifically (which account types, which
  app category), and consider whether `medium` rather than `high`/`critical` severity
  is more honest given how common the legitimate path is (see `severity-guide.md`).

## 4. Domain infrastructure and service accounts

Some actions look like attacker tradecraft from a regular workstation but are routine
from the infrastructure that's actually supposed to perform them.

- Example: DS-Replication-Get-Changes requests (DCSync pattern) are illegitimate from
  a normal user account, but every domain controller and Azure AD Connect's
  directory-sync service account performs them constantly as normal operation.
- How to document it: filter on the structural property that distinguishes
  infrastructure from attacker use (e.g. `SubjectUserName|endswith: '$'` for computer
  accounts) rather than an allowlist of specific hostnames, which goes stale.

## 5. Automated testing and CI/CD pipelines

Test harnesses and CI pipelines often exercise the exact code paths or authentication
flows a rule is designed to catch, because they're testing that functionality or
using it as a shortcut for non-interactive auth.

- Example: an app using ROPC in a test environment because it's the simplest flow to
  automate against, not because it's compromised.
- How to document it: name "automated testing" or "CI/CD service principals"
  explicitly rather than leaving it implicit — this is one of the more common causes
  reviewers forget to write down.

## 6. Scheduled maintenance and backup tooling

Backup agents, crash-dump collection, and scheduled maintenance jobs can request
unusually broad process access rights or touch sensitive processes as part of their
normal, infrequent operation — which makes them easy to miss during rule design
because they don't show up in day-to-day testing.

- Example: enterprise backup software granted broad `PROCESS_ALL_ACCESS`-class rights
  system-wide, incidentally covering `lsass.exe`.
- How to document it: if the tooling is known and fixed in your environment, filter
  it explicitly; if it varies (e.g. differs by customer/deployment), document it in
  `falsepositives` as a category to be tuned per environment rather than silently
  under-detecting or over-filtering.

## Writing the entry once you've identified the pattern

A good `falsepositives` entry answers three questions in one sentence: *who* triggers
it legitimately, *why* they need to, and *how it differs* (if at all) from the
malicious case the rule is trying to catch. If you can't answer the third question,
that's a sign the rule's selection logic needs to be tightened rather than the
false-positive documented and shipped as-is.
