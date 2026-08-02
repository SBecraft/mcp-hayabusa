# Hayabusa Bundled Rules — Breakdown

Generated from `hayabusa/rules/` via `server.py`'s `_load_rules()` loader (same data `get_hayabusa_rules` sees).

**Total rules: 4,961**

## By source

| Source | Count | Notes |
|---|---|---|
| SigmaHQ (`rules/sigma/`) | 4,768 | Community Sigma rules ported into Hayabusa's ruleset |
| Hayabusa (`rules/hayabusa/`) | 193 | Author-written, Hayabusa-specific rules |

## By severity

| Level | Count |
|---|---|
| critical | 234 |
| high | 2,352 |
| medium | 1,906 |
| low | 350 |
| informational | 119 |

## By source x severity

| Level | SigmaHQ | Hayabusa |
|---|---|---|
| critical | 233 | 1 |
| high | 2,333 | 19 |
| medium | 1,859 | 47 |
| low | 325 | 25 |
| informational | 18 | 101 |

SigmaHQ rules skew heavily toward high/critical detections; Hayabusa's own rules skew toward informational, consistent with SigmaHQ covering attacker techniques and Hayabusa's author-written rules covering more general telemetry/logging events.

Note: this count excludes the 6 hand-curated rules in the project's top-level `custom_rules/` directory (distinct from `hayabusa/rules/` above), which is a separate knowledge-base ruleset and is not currently included when `scan_evtx` runs.
