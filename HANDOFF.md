# HANDOFF

## What we built

An MCP (Model Context Protocol) server, `server.py`, that wraps the [Hayabusa](https://github.com/Yamato-Security/hayabusa) Windows event log analysis CLI so an LLM client can scan EVTX files and browse Hayabusa's detection rules, and doubles as a small detection engineering knowledge base (curated Sigma rules mapped to ATT&CK techniques, with coverage assessment). It exposes three tools and four resources.

### Tools

### `scan_evtx`
Runs Hayabusa against one EVTX file and returns structured JSON findings.

| Param | Type | Default | Notes |
|---|---|---|---|
| `evtx_path` | string, required | — | path to the `.evtx` file |
| `min_severity` | enum | `medium` | `informational` / `low` / `medium` / `high` / `critical` |
| `rule_filter` | string, optional | — | case-insensitive substring match against rule title (e.g. `"mimikatz"`) |
| `output_format` | enum | `summary` | `summary` = condensed fields; `full` = every field Hayabusa emits |
| `max_results` | int, optional | — | truncates the result list |

Response includes `total_detections`, `filtered_detections`, `returned_detections`, and `findings`.

### `get_hayabusa_rules`
Lists the ~4,961 bundled Sigma detection rules, optionally filtered by keyword. **Note:** as of the ruleset switch documented below, `scan_evtx` no longer scans this bundled set — it scans `custom_rules/` instead. So this tool is useful for browsing what Hayabusa itself ships, but a `rule_filter` string found here won't necessarily match anything `scan_evtx` returns. `get_hayabusa_rules` is now the only tool/resource in the server that still reads the bundled `hayabusa/rules/` catalog.

| Param | Type | Default | Notes |
|---|---|---|---|
| `keyword` | string, optional | — | substring match against title, description, and tags |
| `max_results` | int, optional | `100` | rules are pre-sorted critical → informational, then title |

Response includes `total_rules`, `matched_rules`, `returned_rules`, and `rules` (each with `id`, `title`, `level`, `status`, `description`, `tags`, `logsource`, `path`).

### `analyze_coverage`
Given an ATT&CK `technique_id` (e.g. `"T1003"` or `"T1003.001"`) or a `tactic` name/shortname (e.g. `"Credential Access"` / `"credential-access"`) — exactly one required — reports which techniques our **curated `custom_rules/` set** covers, partially covers, or leaves as gaps. A bare technique ID expands to itself plus all sub-techniques; a tactic expands to every technique tagged with it. Internally it's a batch runner over `_rules_for_technique()` / `_assess_coverage()`, the same coverage logic that backs the `detection://attack/techniques/{technique_id}` resource — no separate coverage logic to keep in sync. **This now checks `custom_rules/`, reversing an earlier switch to the bundled ruleset** — see Decisions below; with only 8 curated rules across 6 techniques, most techniques will show as gaps, which is expected given the small curated set.

| Param | Type | Default | Notes |
|---|---|---|---|
| `technique_id` | string, optional | — | exactly one of `technique_id`/`tactic` required |
| `tactic` | string, optional | — | matched case/spacing-insensitively against ATT&CK tactic names and shortnames |

Response includes `query`, `techniques_assessed`, `summary` (`covered`/`partial`/`gap` counts), `gap_techniques` (id + name list), and `details` (per-technique id, name, coverage, `rule_count`). `rule_count` stays a count rather than a rule-name list for consistency with `analyze_coverage`'s original (bundled-ruleset) design, where a single technique could match 100+ rules; against the current curated `custom_rules/` set counts are small (0-3 per technique), but the response shape wasn't changed back.

### Resources (detection engineering knowledge base)

All under the `detection://` URI scheme. `detection://rules*` and `detection://attack/techniques/{technique_id}` are now both backed by `custom_rules/` (our own hand-authored Sigma rules, distinct from the ~5000 Hayabusa bundles); the latter also combines in `attack_data/enterprise-attack.json` (MITRE's ATT&CK Enterprise STIX bundle) for technique name/description:

| Resource URI | Returns |
|---|---|
| `detection://rules` | JSON index of every rule in `custom_rules/` (`name`, `uri`, `id`, `title`, `level`, `status`, `tags`, `path`) |
| `detection://rules/{rule_name}` | One rule's raw Sigma YAML, by file stem (e.g. `dcsync_replication_rights`) |
| `detection://rules/by-technique/{technique_id}` | **Curated** (`custom_rules/`) rules tagged with a given ATT&CK ID (e.g. `T1003.001`); a parent ID like `T1003` also matches its sub-techniques |
| `detection://attack/techniques/{technique_id}` | `{technique_id, name, description, rule_count, detecting_rules, coverage}` — ATT&CK's own name/description plus which **curated `custom_rules/`** rules (`{title, level, path}` each) detect it and a `covered`/`partial`/`gap` verdict |

`detection://rules/by-technique/{id}` and `detection://attack/techniques/{id}`/`analyze_coverage` now share one rule source (`custom_rules/`, via `_rules_for_technique()`) and answer the same underlying question: "what have we hand-authored for this technique." They used to assess against two different rule sources (curated vs. bundled) — see Decisions below for why that changed.

`custom_rules/` currently has 8 sample rules covering T1003.001 (LSASS memory access, x3: process-access GrantedAccess check, comsvcs.dll MiniDump LOLBin, and a direct MiniDumpWriteDump/CallTrace check), T1003.006 (DCSync), T1218.011 (LOLBin angle, the comsvcs.dll rule's second tag), T1558.003 (Kerberoasting), T1550.002 (Pass-the-Hash / overpass-the-hash, x2), and T1078 (Valid Accounts, via a ROPC authentication-flow rule). As of the switches documented below, these are no longer *just* browsable content — they're also what `scan_evtx` actually scans, and what `analyze_coverage`/`detection://attack/techniques/{technique_id}` assess coverage against. `hayabusa/rules/` (the bundled catalog) is now used only by `get_hayabusa_rules`.

## How to use it

```bash
# one-time setup
python scripts/download_hayabusa.py     # fetches the Hayabusa binary + rules into ./hayabusa/
python scripts/download_attack_data.py  # fetches MITRE's ATT&CK STIX bundle into ./attack_data/
pip install -r requirements.txt         # mcp, pydantic, pyyaml

# manual smoke test (calls server.call_tool() directly, no MCP transport)
python tests/test_scan_evtx.py

# run the server standalone (normally launched by an MCP client per .mcp.json)
python server.py
```

`.mcp.json` already registers this server for local Claude Code use (`venv/bin/python server.py`). Once connected, a client can call:

```json
{"tool": "get_hayabusa_rules", "arguments": {"keyword": "dcsync"}}
{"tool": "scan_evtx", "arguments": {"evtx_path": "tests/samples/CA_DCSync_4662.evtx", "rule_filter": "mimikatz", "output_format": "full"}}
```

or read a resource:

```json
{"resource": "detection://attack/techniques/T1003.001"}
{"resource": "detection://rules/by-technique/T1550.002"}
```

**Gotcha hit during development:** the MCP client caches the tool list from server startup. Any time `server.py`'s `list_tools()` changes (new tool, new params), the client needs to reconnect / restart for the change to show up — mid-session edits aren't picked up automatically. We worked around this a few times by invoking `server.call_tool(...)` directly via `python -c "..."` to test changes before a reconnect.

**Gotcha hit post-development (2026-07-25):** the repo moved from `$HOME/mcp-hayabusa` to `$HOME/ai-defense-labs/mcp-hayabusa`, but `.mcp.json`'s `command`/`cwd` fields still pointed at the old absolute path (`$HOME/mcp-hayabusa/venv/bin/python`, `cwd: $HOME/mcp-hayabusa`). Claude Code couldn't launch the server from a path that no longer existed, so the hayabusa connector just vanished from the server list — no error surfaced, it looked identical to the connector never having been registered. Fixed by updating both fields to the current path and reconnecting. If this repo is ever moved again, `.mcp.json` needs the same update.

## What's left to do

- **Three new content directories exist but aren't wired into `server.py` yet**: `playbooks/` (3 Markdown files with YAML frontmatter — incident response playbooks for credential theft, Kerberos ticket abuse, and pass-the-hash lateral movement), `environment/` (3 YAML files — `hosts.yml`, `services.yml`, `baselines.yml`, describing a fictional `insecurebank.local` environment), and `investigations/` (3 Markdown case write-ups with YAML frontmatter, case IDs `INC-2024-014`/`021`/`033`). All three are cross-referenced against each other and against `custom_rules/`'s existing techniques/alert titles, but none of them have `detection://` resource endpoints yet — planned shapes are `detection://playbooks`, `detection://playbooks/{playbook_name}`, `detection://playbooks/by-alert/{alert_name}`; `detection://environment/hosts`, `detection://environment/services`, `detection://environment/baselines`; and `detection://investigations`, `detection://investigations/{case_id}`, `detection://investigations/by-technique/{tid}`. Wiring these up means adding loader functions (mirroring `_load_kb_rules()`), resource registration in `list_resources()`/`list_resource_templates()`, and dispatch branches in `read_resource()` — same pattern as `custom_rules/`.
- **Test coverage**: `tests/test_scan_evtx.py` is a single manual smoke test against one sample file with default params. It doesn't exercise `rule_filter`, `output_format`, `max_results`, error paths, `get_hayabusa_rules`, `analyze_coverage`, or any of the four resources at all. No automated test runner (pytest, etc.) is wired up.
- **No lint/format tooling** configured (no ruff/black/mypy).
- **No CI.**
- **`_rules_cache`, `_kb_rules_cache`, `_attack_techniques_cache`, and `_attack_tactics_cache` have no invalidation path.** Each assumes its source directory/file never changes during the process's life. Fine today, but would need addressing if a "refresh rules" tool, hot-reload, or in-session editing of `custom_rules/` is ever added.
- **Single-file scanning only.** `scan_evtx` takes one `evtx_path`; Hayabusa itself supports `-d` (directory) and `-l` (live local system) modes that aren't exposed.
- **No pagination beyond `max_results`** — a caller can't page past the first N results of a large rule/finding set (no offset/cursor). `analyze_coverage` has no cap at all — a broad tactic (e.g. Credential Access: 67 techniques) returns every technique in `details`; a technique subtree could theoretically be large too, though in practice ATT&CK sub-technique counts stay small.
- **Repo isn't under version control yet** — no `.git` here. Worth `git init` + an initial commit before this goes further.
- More sample EVTX files would help — `tests/samples/` currently has just the one DCSync sample.
- **`custom_rules/` is back to feeding coverage assessment directly** (see Decisions — coverage was switched to the bundled ruleset mid-development, then switched back). With only 8 rules across 6 techniques, most techniques in any tactic sweep show as gaps — e.g. Credential Access still reports 62 of 67 as gaps (verified against the live `analyze_coverage` tool; the two rules added since — both under T1003.001, already `covered` via an existing high-severity rule — didn't move that number). This is an accurate reflection of the curated set's size, not a bug, but it does mean `analyze_coverage` currently answers "what have we hand-documented" rather than "what can Hayabusa actually detect" — the latter question would require pointing back at the bundled ruleset, which `get_hayabusa_rules` still exposes for manual browsing even though no coverage tool reads it anymore.
- **A Claude Code skill and validator were added to enforce authoring standards on `custom_rules/`, separate from `server.py`.** `.claude/skills/detection-engineering/SKILL.md` documents the standards (mandatory ATT&CK tag, a justified `level` via a `# Severity:` comment, concrete `falsepositives` entries, a `# test_case:` block with a matching and an excluded case, `lower_snake_case.yml` naming); `.claude/skills/detection-engineering/scripts/validate-rule.py` checks 12 things mechanically and prints JSON (`valid`, per-check `checks`, `issues`, `warnings`); `.claude/skills/detection-engineering/references/` holds a fully-passing example rule plus `severity-guide.md` and `false-positive-patterns.md`. **The original 6 `custom_rules/*.yml` files predate this and don't fully pass `validate-rule.py`** (missing the `# Severity:` comment and `# test_case:` block) — only the 2 rules added since (`lsass_minidump_write_dump.yml`, `ropc_authentication_flow.yml`) pass all 12 checks. Retrofitting the original 6 is still open.
- **Coverage heuristic is simplistic.** `covered` just means "at least one high/critical rule exists for this technique" — it doesn't account for data-source availability, detection logic quality, or whether the technique has multiple sub-behaviors only some of which are covered. With the pool at 8 curated rules, this heuristic is easy to reason about (any given "covered" verdict traces to one or two specific, readable rules), but the sparse curated set also means it's easy for a technique to look like a "gap" even if a bundled Hayabusa rule would actually catch it — `analyze_coverage` no longer reflects Hayabusa's real detection capability, only the curated documentation.
- **Curated-ruleset coverage is narrow by design**, not just Windows-skewed. E.g. within T1003 (OS Credential Dumping), only T1003.001 (LSASS Memory) and T1003.006 (DCSync) are covered/partial; the other 6 sub-techniques (Security Account Manager, NTDS, LSA Secrets, Cached Domain Credentials, Proc Filesystem, /etc/passwd and /etc/shadow) are gaps simply because no curated rule targets them yet, not because they're inherently hard to detect.
- **No way to look up an ATT&CK technique by name/keyword**, only by exact ID or tactic — `analyze_coverage`'s `tactic` param covers the "browse a whole category" case, but a caller still can't e.g. search for "the technique about golden tickets" without already knowing it's `T1558.001`.
- **`attack_data/enterprise-attack.json` has no staleness check.** MITRE updates ATT&CK periodically; nothing here flags when the cached bundle is out of date.

## Decisions made and why

- **`min_severity` and `rule_filter` are applied post-hoc in Python, not passed to Hayabusa's CLI.** Hayabusa's `--min-level` filters which *rules load*, not which *detections* are returned, and there's no native free-text rule-title filter (only `--include-tag`/`--include-category`). Post-hoc filtering was the only way to support `rule_filter` and to report `total_detections` vs `filtered_detections` separately.
- **`-L` (JSONL output), not `-o` alone.** `-o` alone emits concatenated pretty-printed JSON objects, which isn't valid parseable JSON as a whole.
- **`output_format` defaults to `"summary"`.** Full Hayabusa output per finding (`Details`, `ExtraFieldInfo`, etc.) is verbose; most callers just need Timestamp/Rule/Level/Computer/EventID/RecordID to decide what to look at next. `"full"` is there when the raw fields are needed.
- **Errors are returned as structured `{"error": ...}` JSON rather than raised exceptions**, for every validation and runtime failure path. This keeps failures visible to the MCP client as normal tool output instead of transport-level errors.
- **The Hayabusa binary is never committed.** It's OS/arch-specific and large, so it's fetched per-machine by `scripts/download_hayabusa.py` and gitignored along with `venv/` and `__pycache__/`.
- **`pyyaml` prefers the `CSafeLoader` (libyaml) binding over the pure-Python loader**, with a fallback if unavailable — parsing all ~5,000 rule files takes ~0.6s with libyaml vs ~6s pure-Python, and `get_hayabusa_rules` would otherwise feel sluggish on every cold call.
- **Parsed rules are cached in-process (`_rules_cache`)** rather than re-parsed per call, since the rules directory is populated once at setup and doesn't change while the server runs.
- **Rules are sorted critical → informational, then by title**, so that when `max_results` truncates a broad keyword match, the most severe/relevant rules survive the cut rather than an arbitrary filesystem-order slice.
- **Two separate tools instead of one** for scanning vs. rule discovery, so a caller (especially an LLM) can discover what detections exist and find the right `rule_filter` substring via `get_hayabusa_rules` before running `scan_evtx`, rather than guessing rule names blind.
- **(Superseded — see the entry below.) `scan_evtx` originally explicitly passed `-r hayabusa/rules` to Hayabusa**, guaranteeing `custom_rules/` was never scanned. This has since been reversed: `scan_evtx` now passes `-r custom_rules` instead, per an explicit instruction that EVTX scanning should exercise the curated sample ruleset built in the "Get Sample Rules" step. Kept here for history; the current behavior is `-r custom_rules`.
- **`analyze_coverage` was added as a new tool rather than folding technique/tactic lookup into the resources.** Resources (`detection://attack/techniques/{technique_id}`) are single-item reads by design (MCP resource URIs address one thing); `analyze_coverage` needed to expand one query into many techniques (a whole sub-tree or tactic) and aggregate the results, which is a tool-shaped operation (arbitrary input, computed batch output), not a resource-shaped one (browsable, single-item). It deliberately reuses the same coverage-computation helper as the resource, so the two can never disagree about what "covered" means.
- **(Superseded — see the entry below.) Coverage assessment (`analyze_coverage` and `detection://attack/techniques/{technique_id}`) was at one point switched from `custom_rules/` to the bundled `hayabusa/rules/` ruleset**, because curated-only coverage made "gap" counts misleading (e.g. Credential Access reported 62 of 67 techniques as gaps against a 6-rule curated set, when Hayabusa's bundled ruleset already covered most of them). `_rules_for_technique()` (curated) stayed in place for `detection://rules/by-technique/{id}` browsing; a parallel `_bundled_rules_for_technique()` was added for coverage. Kept here for history — this has since been reversed again, see below.
- **Coverage assessment was switched back to `custom_rules/`, and `_bundled_rules_for_technique()` was deleted as dead code.** This reverses the previous entry. Trigger: an explicit assignment requirement that `analyze_coverage` "reads our detection rules (from resources)" — i.e. from `custom_rules/`/`detection://rules*`, not the bundled catalog. Both `analyze_coverage`'s `_build_coverage_report()` and `detection://attack/techniques/{technique_id}`'s `_read_attack_technique()` now call `_rules_for_technique()` against `_load_kb_rules()`, the same function `detection://rules/by-technique/{technique_id}` already used — so there is now exactly one coverage rule source in the server, not two. Net effect: `get_hayabusa_rules` is the only remaining consumer of the bundled `hayabusa/rules/` catalog; coverage numbers are correspondingly sparse (6 rules, 4 techniques) rather than the near-full coverage the bundled ruleset gave. This makes two out of three "which ruleset does X use" decisions in this file's history flip-flops — worth treating as settled unless another explicit instruction says otherwise, since a third reversal would suggest the requirement itself needs clarifying rather than the code.
- **`custom_rules/` is a separate, committed directory from `hayabusa/rules/`**, not a subfolder of it. `hayabusa/rules/` is gitignored and fully replaced every time `download_hayabusa.py` runs, so anything hand-authored there would be at risk of being wiped. `custom_rules/` is small and curated by design — the goal is a hand-picked, ATT&CK-mapped set, not another copy of Hayabusa's ~5000 rules.
- **ATT&CK data is fetched into `attack_data/` and cached in-process (`_attack_techniques_cache`)** rather than queried live from MITRE's GitHub on every resource read — same rationale as caching Hayabusa's rules: the source file is ~53MB and doesn't change during a server's lifetime, so re-parsing per call would be wasted work.
- **Technique-to-rule mapping is derived purely from Sigma `tags`** (`attack.tXXXX[.YYY]`), not a separate mapping file. Sigma already has a de facto standard for this, so a second hand-maintained mapping would just be a second thing to keep in sync.
- **`by-technique` and coverage lookups match parent IDs to sub-techniques** (e.g. `T1003` matches rules tagged `T1003.001`, `T1003.006`, ...) via prefix matching on the tag, so a caller doesn't need to know exactly which sub-technique a rule targets to find it.
- **Resources raise exceptions on bad input (unknown rule/technique, empty ID) rather than returning `{"error": ...}` JSON**, unlike the tools. This follows the MCP resource convention where a failed read is a protocol-level error, whereas tool calls in this server were deliberately designed to keep failures visible as normal tool output.
