---
name: detection-engineering
description: Enforce detection rule standards when writing or reviewing Sigma rules, discussing detection coverage, or working with YAML detection files in custom_rules/. Triggers on writing/creating Sigma rules, reviewing detection rules, discussing detection coverage, and working with YAML detection files.
---

# Detection Engineering Standards

Apply these standards to every Sigma rule in `custom_rules/` — when authoring a new
rule, editing an existing one, or reviewing one. If a rule under review violates a
standard, flag it and propose the fix rather than silently accepting it.

## 1. ATT&CK technique mapping is mandatory

Every rule must carry at least one `attack.tXXXX` or `attack.tXXXX.YYY` tag in its
`tags:` list (lowercase, matching the convention `_extract_technique_ids` /
`_rules_for_technique` in `server.py` look for). A rule with no technique tag is
invisible to `analyze_coverage`, `detection://rules/by-technique/{technique_id}`, and
`detection://attack/techniques/{technique_id}` — it exists but contributes nothing to
coverage.

- Prefer the most specific sub-technique that applies (e.g. `attack.t1003.001` over
  bare `attack.t1003`) — coverage assessment matches exact-or-prefix, so specificity
  only adds precision, never loses a match.
- Also include the tactic tag (e.g. `attack.credential-access`) alongside the
  technique tag — every existing rule in `custom_rules/` follows this pattern.
- A rule may map to more than one technique (e.g.
  `lsass_dump_via_comsvcs.yml` carries both `attack.t1003.001` and
  `attack.t1218.011` for the LOLBin angle) — tag every technique the behavior
  genuinely maps to, not just the primary one.

Reject a rule with no `attack.t*` tag, or with a tag that doesn't correspond to a real
ATT&CK technique ID.

## 2. Severity (`level`) must be justified

`level` must be exactly one of: `low`, `medium`, `high`, `critical` (these are the
only values `_filter_records`/`min_severity` in `server.py` understand — anything else
silently fails to filter correctly). Alongside the `level` field, the rule's
`description` must state *why* that severity was chosen — tie it to attacker impact
and how deterministic the detection is, not just "this seems bad":

- `critical` — high-confidence, high-impact technique with few/no legitimate
  explanations (e.g. DCSync from a non-DC principal).
- `high` — strong indicator of malicious activity but with a plausible, narrow
  false-positive path.
- `medium` — suspicious pattern that also occurs in legitimate/legacy use
  (e.g. RC4 Kerberos tickets from old service accounts).
- `low` — weak/noisy signal, useful mainly as corroboration with other detections.

Reject a rule where `level` is set but the description gives no rationale for that
specific level — "detects X" is not a justification, "detects X, which has no
legitimate business justification and directly indicates credential theft" is.

See `references/severity-guide.md` for a fuller decision framework and worked examples
per level.

## 3. False positive conditions must be documented

Every rule requires a non-empty `falsepositives:` list. Each entry must name a
concrete, plausible legitimate cause of the detection firing — not a hedge like
"unknown" or "none observed" used as a placeholder. If a rule's authors genuinely
believe there are no false positives, the entry should say so explicitly and explain
why (e.g. "None — this API/protocol combination has no legitimate caller"), because
that's a testable claim a reviewer can push back on.

Bad: `falsepositives: ["Unknown"]`
Good: `falsepositives: ["Legitimate domain controllers and Azure AD Connect /
directory-sync service accounts"]`

See `references/false-positive-patterns.md` for the recurring categories of
legitimate-cause false positives across this project's rules (security/EDR tooling,
built-in diagnostics, legacy protocols, domain infrastructure, test/CI automation,
backup tooling) and how to document each.

## 4. At least one test case is required

Sigma's schema has no native test-case field, so document it in the rule file itself
as a YAML comment block directly above `detection:`, in this form:

```yaml
# test_case:
#   sample: tests/samples/<file>.evtx   # or: a synthesized log line / command line
#   expect: match                        # match | no_match
#   notes: <what in the sample triggers/avoids each selection>
detection:
    ...
```

At minimum, document one case that should match (a true positive) and, where a
`filter_*` selection exists, one case that should be excluded (to prove the filter
isn't accidentally over-broad). If `tests/samples/` doesn't have a fitting EVTX file,
describe the synthetic event fields that would trigger the rule instead of leaving the
test case unwritten — an untestable rule is a rule nobody can validate before or after
edits.

Reject a rule with a `detection:` block and no adjacent `test_case:` comment.

## 5. Rule naming: lowercase with underscores

The filename (minus `.yml`) and the file itself must use `lower_snake_case`, e.g.
`dcsync_replication_rights.yml`, `lsass_memory_access_process.yml`. No hyphens, no
CamelCase, no spaces. The `title:` field inside the YAML is prose and stays
human-readable (e.g. `title: DCSync - Directory Replication Services Used to Dump
Credentials`) — only the filename must follow the lowercase_with_underscores rule.

Reject a filename like `DCSync-Rule.yml` or `lsassMemoryAccess.yml`; rename it to
match convention before accepting.

## Review checklist

When reviewing a rule (new or existing), check in this order and report every
violation found, not just the first:

1. `tags:` contains at least one valid `attack.tXXXX[.YYY]` entry.
2. `level:` is one of `low`/`medium`/`high`/`critical`, and `description:` justifies
   that specific level.
3. `falsepositives:` is present, non-empty, and each entry is a concrete scenario.
4. A `# test_case:` comment block precedes `detection:`, covering at least one
   matching case (and an excluded case if the rule has a `filter_*` selection).
5. The filename is `lower_snake_case.yml`.

When a rule fails one or more checks, state which checks failed and fix them directly
rather than describing the fix in prose — these are mechanical, low-risk edits to a
YAML file.

## Automated validation

Run `scripts/validate-rule.py <path-to-rule.yml>` to check a rule mechanically instead
of eyeballing it. It prints JSON (`valid`, per-check `checks`, `issues`, `warnings`) and
exits `0` if all required checks pass, `1` if any fail, `2` on a usage/file error.

It checks 12 things: `attack_tags`, `tactic_tags` (warning only — doesn't fail
validation), `valid_level`, `severity_justified` (a `# Severity:` comment),
`false_positives` (non-empty, no placeholder entries like "unknown"/"TBD"),
`test_cases` (a `# test_case(s):` comment block), `positive_test` / `negative_test`
(documented "should trigger" / "should NOT trigger" cases), `valid_uuid`,
`valid_filename` (`lower_snake_case.yml`), `has_references` (an `attack.mitre.org` URL),
and `no_todo_placeholders` (no `TODO`/`FIXME`/`XXX` inside `detection:`).

Treat the script as the source of truth for what "passes" means — run it on any new or
edited rule before considering the work done.

## References

When writing rules, consult:
- `references/example-rules/` - Well-formatted examples to follow
- `references/severity-guide.md` - Severity level guidance
- `references/false-positive-patterns.md` - Common FP documentation
