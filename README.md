# mcp-hayabusa

An MCP (Model Context Protocol) server that wraps
[Hayabusa](https://github.com/Yamato-Security/hayabusa) — a Windows event log
fast-forensics timeline generator — for EVTX analysis, and doubles as a small
detection engineering knowledge base.

Built for Modules 3 & 4 of **AI Cyber Defense Ops**, a Just Hacking Training
(JHT) course offered by Women in CyberSecurity (WiCyS) and taught by Anton
Ovrutsky. All modules are in the
[ai-defense-labs](https://github.com/SBecraft/ai-defense-labs) repo.

## What it exposes

**Three tools:**

- `scan_evtx` — runs Hayabusa against an EVTX file and returns structured JSON
  findings, filterable by severity and rule title. Scans the curated
  `custom_rules/` set.
- `get_hayabusa_rules` — lists the ~5000 Sigma rules Hayabusa ships with,
  optionally filtered by keyword.
- `analyze_coverage` — given an ATT&CK technique ID or tactic name, reports
  which techniques the curated rules cover, partially cover, or leave as gaps.

**Four resources**, under the `detection://` URI scheme:

- `detection://rules` — index of the curated Sigma rules
- `detection://rules/{rule_name}` — a rule's raw YAML
- `detection://rules/by-technique/{technique_id}` — rules tagged with an ATT&CK technique
- `detection://attack/techniques/{technique_id}` — technique detail plus a coverage verdict

## Stack

- Python 3, the `mcp` library (stdio transport), `pydantic`, `pyyaml`
- Hayabusa CLI, downloaded as a prebuilt binary and invoked as a subprocess

## Running

```bash
python scripts/download_hayabusa.py      # fetch the Hayabusa binary
python scripts/download_attack_data.py   # fetch the MITRE ATT&CK STIX bundle
pip install -r requirements.txt
python tests/test_scan_evtx.py           # manual smoke test
```

The server is normally launched by an MCP client via `.mcp.json` rather than
run directly. The Hayabusa binary and ATT&CK data are fetched per-machine and
gitignored; `custom_rules/` is authored content and checked in.

## A Note on Placeholders

This is public coursework, so anything that pointed at my local machine or
personal accounts has been replaced with generic placeholders:

| Placeholder | Stands for |
|---|---|
| `$HOME` | the home directory this repo was developed in |
| `C:\Users\<username>` | the Windows user profile (Claude Desktop config lives here) |
| `<repo-path>` / `<old-repo-path>` | this repo's absolute path on disk |

Commits are authored under a GitHub noreply address rather than a personal
email. If you clone this, substitute your own paths — the placeholder paths are
documentation, not working config, and nothing is meant to run against them as
written.

The hostnames, IPs, domains, accounts, and incident write-ups here are
**synthetic lab data**. The `insecurebank.local` domain in `environment/`, the
`INC-2024-*` case files in `investigations/`, and the scenarios in `playbooks/`
describe a fictional environment built for the coursework — they do not
correspond to any real network, organization, or incident. Sample EVTX files in
`tests/samples/` come from the public
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) repo.
