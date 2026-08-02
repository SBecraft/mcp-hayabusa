from mcp.server import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.types import Resource, ResourceTemplate, Tool, TextContent
import asyncio
import json
import platform
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import Iterable

import yaml

try:
    from yaml import CSafeLoader as YamlLoader  # libyaml binding: ~10x faster over ~5000 rule files
except ImportError:
    from yaml import SafeLoader as YamlLoader

server = Server("hayabusa-mcp")

SEVERITY_LEVELS = ["informational", "low", "medium", "high", "critical"]
OUTPUT_FORMATS = ["summary", "full"]
SUMMARY_FIELDS = ["Timestamp", "RuleTitle", "Level", "Computer", "EventID", "RecordID"]

HAYABUSA_PATH = Path(
    "./hayabusa/hayabusa.exe" if platform.system() == "Windows" else "./hayabusa/hayabusa"
)
RULES_DIR = Path("./hayabusa/rules")
DEFAULT_RULES_MAX_RESULTS = 100

# Detection engineering knowledge base: our own curated Sigma rules (distinct
# from the ~5000 rules Hayabusa ships under hayabusa/rules), exposed as MCP
# resources under the detection://rules URI scheme.
KB_RULES_DIR = Path("./custom_rules")
RESOURCE_URI_PREFIX = "detection://rules"

# MITRE ATT&CK Enterprise STIX bundle, fetched by scripts/download_attack_data.py.
ATTACK_DATA_PATH = Path("./attack_data/enterprise-attack.json")
ATTACK_URI_PREFIX = "detection://attack/techniques"

_rules_cache: list[dict] | None = None
_kb_rules_cache: dict[str, dict] | None = None
_attack_techniques_cache: dict[str, dict] | None = None
_attack_tactics_cache: dict[str, str] | None = None


@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="scan_evtx",
            description=(
                "Scan an EVTX file with Hayabusa to detect suspicious activity, using the "
                "bundled Hayabusa/SigmaHQ catalog (hayabusa/rules/, ~4,961 rules) so findings "
                "aren't limited to our own rules. Note analyze_coverage assesses custom_rules/ "
                "instead, so its coverage verdicts describe a different, much smaller ruleset."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "evtx_path": {
                        "type": "string",
                        "description": "Path to the EVTX file to scan"
                    },
                    "min_severity": {
                        "type": "string",
                        "enum": ["informational", "low", "medium", "high", "critical"],
                        "description": "Minimum severity level to include",
                        "default": "medium"
                    },
                    "rule_filter": {
                        "type": "string",
                        "description": "Only include detections whose rule title contains this string, case-insensitive (e.g., \"lateral\" or \"mimikatz\")"
                    },
                    "output_format": {
                        "type": "string",
                        "enum": ["summary", "full"],
                        "description": "\"summary\" returns condensed fields per finding; \"full\" includes all Details/ExtraFieldInfo",
                        "default": "summary"
                    },
                    "max_results": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Limit the number of findings returned"
                    }
                },
                "required": ["evtx_path"]
            }
        ),
        Tool(
            name="get_hayabusa_rules",
            description=(
                "List available Hayabusa detection rules, optionally filtered by keyword "
                "(matched against rule title, description, and tags). Useful for seeing what "
                "detections exist before scanning, or for finding the exact rule_filter string "
                "to pass to scan_evtx."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "Case-insensitive substring to filter rules by, matched against title, description, and tags (e.g. \"lateral\" or \"mimikatz\")"
                    },
                    "max_results": {
                        "type": "integer",
                        "minimum": 1,
                        "default": DEFAULT_RULES_MAX_RESULTS,
                        "description": f"Limit the number of rules returned (default {DEFAULT_RULES_MAX_RESULTS})"
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="analyze_coverage",
            description=(
                "Assess detection coverage for an ATT&CK technique or tactic, using our own "
                "curated ruleset (custom_rules/) — NOT the bundled catalog that scan_evtx runs "
                "against, so most techniques will report as gaps. Given a technique_id (e.g. \"T1003\" or "
                "\"T1003.001\") or a tactic (e.g. \"credential-access\" or \"Credential Access\"), "
                "returns which techniques are covered, partially covered, or gaps, and how many "
                "matching rules exist for each. Provide exactly one of technique_id or tactic."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "technique_id": {
                        "type": "string",
                        "description": "An ATT&CK technique ID. A parent ID (e.g. \"T1003\") also covers its sub-techniques."
                    },
                    "tactic": {
                        "type": "string",
                        "description": "An ATT&CK tactic name or shortname (e.g. \"Credential Access\" or \"credential-access\")"
                    }
                },
                "required": []
            }
        )
    ]


@server.list_resources()
async def list_resources() -> list[Resource]:
    resources = [
        Resource(
            uri=RESOURCE_URI_PREFIX,
            name="rules",
            title="All detection rules",
            description="Index of every Sigma rule in the detection engineering knowledge base (custom_rules/)",
            mimeType="application/json",
        )
    ]
    kb_rules = _load_kb_rules()
    for name, rule in kb_rules.items():
        doc = rule["doc"]
        resources.append(
            Resource(
                uri=f"{RESOURCE_URI_PREFIX}/{name}",
                name=name,
                title=doc.get("title"),
                description=doc.get("description"),
                mimeType="application/yaml",
            )
        )

    for technique_id in _extract_technique_ids(kb_rules):
        resources.append(
            Resource(
                uri=f"{ATTACK_URI_PREFIX}/{technique_id}",
                name=technique_id,
                title=f"ATT&CK {technique_id}",
                description="Technique info, detecting rules, and coverage assessment",
                mimeType="application/json",
            )
        )
    return resources


@server.list_resource_templates()
async def list_resource_templates() -> list[ResourceTemplate]:
    return [
        ResourceTemplate(
            uriTemplate=f"{RESOURCE_URI_PREFIX}/{{rule_name}}",
            name="rule",
            description="Get a specific Sigma rule's raw YAML content by file name (without extension)",
            mimeType="application/yaml",
        ),
        ResourceTemplate(
            uriTemplate=f"{RESOURCE_URI_PREFIX}/by-technique/{{technique_id}}",
            name="rules_by_technique",
            description="List rules tagged with a given ATT&CK technique ID, e.g. T1003.001",
            mimeType="application/json",
        ),
        ResourceTemplate(
            uriTemplate=f"{ATTACK_URI_PREFIX}/{{technique_id}}",
            name="attack_technique",
            description=(
                "Get an ATT&CK technique's name and description, which of our curated "
                "custom_rules/ detect it, and a coverage assessment (covered/partial/gap)"
            ),
            mimeType="application/json",
        ),
    ]


@server.read_resource()
async def read_resource(uri) -> Iterable[ReadResourceContents]:
    uri_str = str(uri)

    if uri_str.startswith(f"{ATTACK_URI_PREFIX}/"):
        technique_id = uri_str[len(ATTACK_URI_PREFIX):].lstrip("/")
        if not technique_id:
            raise ValueError("technique_id must not be empty")
        content = _read_attack_technique(technique_id)
        return [ReadResourceContents(content=json.dumps(content, indent=2), mime_type="application/json")]

    if not uri_str.startswith(RESOURCE_URI_PREFIX):
        raise ValueError(f"Unknown resource URI: {uri_str}")

    remainder = uri_str[len(RESOURCE_URI_PREFIX):].lstrip("/")
    rules = _load_kb_rules()

    if remainder == "":
        summaries = [_summarize_kb_rule(name, rule) for name, rule in rules.items()]
        return [ReadResourceContents(content=json.dumps(summaries, indent=2), mime_type="application/json")]

    if remainder.startswith("by-technique/"):
        technique_id = remainder[len("by-technique/"):]
        if not technique_id:
            raise ValueError("technique_id must not be empty")
        matched = _rules_for_technique(rules, technique_id)
        return [ReadResourceContents(content=json.dumps(matched, indent=2), mime_type="application/json")]

    rule = rules.get(remainder)
    if rule is None:
        raise ValueError(f"Unknown rule: {remainder}")
    return [ReadResourceContents(content=rule["raw"], mime_type="application/yaml")]


def _error(message: str) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps({"error": message}, indent=2))]


def _filter_records(records: list[dict], min_severity: str, rule_filter: str | None) -> list[dict]:
    min_index = SEVERITY_LEVELS.index(min_severity)
    rule_filter_lower = rule_filter.lower() if rule_filter else None
    filtered = []
    for record in records:
        level = str(record.get("Level", "")).lower()
        if level not in SEVERITY_LEVELS or SEVERITY_LEVELS.index(level) < min_index:
            continue
        if rule_filter_lower and rule_filter_lower not in str(record.get("RuleTitle", "")).lower():
            continue
        filtered.append(record)
    return filtered


def _summarize(record: dict) -> dict:
    return {field: record.get(field) for field in SUMMARY_FIELDS}


def _load_rules() -> list[dict]:
    """Parse every Sigma rule under RULES_DIR into a summary dict, caching the
    result for the life of the process — the rules directory is populated once
    by scripts/download_hayabusa.py and doesn't change while the server runs."""
    global _rules_cache
    if _rules_cache is not None:
        return _rules_cache

    rules = []
    for path in sorted(RULES_DIR.rglob("*.yml")):
        if ".git" in path.parts:
            continue
        try:
            with path.open(encoding="utf-8") as fh:
                doc = next(yaml.load_all(fh, Loader=YamlLoader), None)
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict) or "title" not in doc:
            continue

        logsource = doc.get("logsource") or {}
        rules.append({
            "id": doc.get("id"),
            "title": doc.get("title"),
            "level": doc.get("level"),
            "status": doc.get("status"),
            "description": doc.get("description"),
            "tags": doc.get("tags") or [],
            "logsource": {
                "product": logsource.get("product"),
                "category": logsource.get("category"),
                "service": logsource.get("service"),
            },
            "path": str(path.relative_to(RULES_DIR)),
        })

    def _sort_key(rule: dict) -> tuple:
        level = str(rule.get("level") or "").lower()
        level_rank = SEVERITY_LEVELS.index(level) if level in SEVERITY_LEVELS else -1
        return (-level_rank, str(rule.get("title") or "").lower())

    rules.sort(key=_sort_key)
    _rules_cache = rules
    return rules


def _filter_rules(rules: list[dict], keyword: str | None) -> list[dict]:
    if not keyword:
        return rules
    keyword_lower = keyword.lower()
    matched = []
    for rule in rules:
        haystack = " ".join([
            rule.get("title") or "",
            rule.get("description") or "",
            " ".join(rule.get("tags") or []),
        ]).lower()
        if keyword_lower in haystack:
            matched.append(rule)
    return matched


def _load_kb_rules() -> dict[str, dict]:
    """Parse every Sigma rule under KB_RULES_DIR, keyed by file stem, caching
    for the process lifetime (same rationale as _load_rules: this directory
    is curated ahead of time, not written to while the server runs)."""
    global _kb_rules_cache
    if _kb_rules_cache is not None:
        return _kb_rules_cache

    rules: dict[str, dict] = {}
    if KB_RULES_DIR.is_dir():
        paths = sorted(set(KB_RULES_DIR.rglob("*.yml")) | set(KB_RULES_DIR.rglob("*.yaml")))
        for path in paths:
            if ".git" in path.parts:
                continue
            raw = path.read_text(encoding="utf-8")
            try:
                doc = next(yaml.load_all(raw, Loader=YamlLoader), None)
            except yaml.YAMLError:
                continue
            if not isinstance(doc, dict) or "title" not in doc:
                continue
            rules[path.stem] = {
                "path": str(path.relative_to(KB_RULES_DIR)),
                "raw": raw,
                "doc": doc,
            }

    _kb_rules_cache = rules
    return rules


def _summarize_kb_rule(name: str, rule: dict) -> dict:
    doc = rule["doc"]
    return {
        "name": name,
        "uri": f"{RESOURCE_URI_PREFIX}/{name}",
        "id": doc.get("id"),
        "title": doc.get("title"),
        "level": doc.get("level"),
        "status": doc.get("status"),
        "tags": doc.get("tags") or [],
        "path": rule["path"],
    }


def _normalize_technique_tag(technique_id: str) -> str:
    tid = technique_id.strip().lower()
    if not tid.startswith("t"):
        tid = f"t{tid}"
    return f"attack.{tid}"


def _technique_tag_matches(tags: list, technique_id: str) -> bool:
    tag = _normalize_technique_tag(technique_id)
    tags_lower = [str(t).lower() for t in (tags or [])]
    return any(t == tag or t.startswith(f"{tag}.") for t in tags_lower)


def _rules_for_technique(rules: dict[str, dict], technique_id: str) -> list[dict]:
    """Curated custom_rules/ rules tagged with technique_id (or a sub-technique of it).
    Used for both browsing (detection://rules/by-technique/{id}) and coverage
    assessment (_read_attack_technique, analyze_coverage) — one rule source,
    one matching function, for both."""
    matched = []
    for name, rule in rules.items():
        if _technique_tag_matches(rule["doc"].get("tags"), technique_id):
            matched.append(_summarize_kb_rule(name, rule))
    return matched


def _extract_technique_ids(rules: dict[str, dict]) -> list[str]:
    """Pull every distinct ATT&CK technique ID (e.g. "T1003.001") referenced
    by attack.tXXXX tags across our curated Sigma rules."""
    ids = set()
    for rule in rules.values():
        for tag in rule["doc"].get("tags") or []:
            tag_str = str(tag).lower()
            if tag_str.startswith("attack.t") and tag_str[8:9].isdigit():
                ids.add(tag_str[len("attack."):].upper())
    return sorted(ids)


def _load_attack_techniques() -> dict[str, dict]:
    """Parse the ATT&CK STIX bundle into technique_id -> {id, name, description},
    caching for the process lifetime (same rationale as _load_rules: the file
    is fetched once by scripts/download_attack_data.py and doesn't change
    while the server runs)."""
    global _attack_techniques_cache
    if _attack_techniques_cache is not None:
        return _attack_techniques_cache

    techniques: dict[str, dict] = {}
    if ATTACK_DATA_PATH.is_file():
        with ATTACK_DATA_PATH.open(encoding="utf-8") as fh:
            bundle = json.load(fh)
        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            technique_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break
            if not technique_id:
                continue
            tactics = [
                phase.get("phase_name")
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ]
            techniques[technique_id] = {
                "id": technique_id,
                "name": obj.get("name"),
                "description": obj.get("description"),
                "tactics": tactics,
            }

    _attack_techniques_cache = techniques
    return techniques


def _load_attack_tactics() -> dict[str, str]:
    """Parse ATT&CK tactic objects (x-mitre-tactic) into shortname -> display
    name (e.g. "credential-access" -> "Credential Access"), caching for the
    process lifetime like _load_attack_techniques."""
    global _attack_tactics_cache
    if _attack_tactics_cache is not None:
        return _attack_tactics_cache

    tactics: dict[str, str] = {}
    if ATTACK_DATA_PATH.is_file():
        with ATTACK_DATA_PATH.open(encoding="utf-8") as fh:
            bundle = json.load(fh)
        for obj in bundle.get("objects", []):
            if obj.get("type") != "x-mitre-tactic":
                continue
            shortname = obj.get("x_mitre_shortname")
            if shortname:
                tactics[shortname] = obj.get("name")

    _attack_tactics_cache = tactics
    return tactics


def _normalize_tactic(tactic_input: str) -> str | None:
    """Resolve a user-supplied tactic name or shortname (case/spacing-insensitive)
    to its canonical shortname, e.g. "Credential Access" -> "credential-access"."""
    normalized_input = tactic_input.strip().lower().replace(" ", "-")
    tactics = _load_attack_tactics()
    if normalized_input in tactics:
        return normalized_input
    for shortname, name in tactics.items():
        if name.lower() == tactic_input.strip().lower():
            return shortname
    return None


def _resolve_techniques(technique_id: str | None, tactic: str | None) -> tuple[list[dict], str]:
    """Expand a technique_id or tactic query into the list of ATT&CK technique
    dicts it covers, plus a human-readable label for the report. A parent
    technique_id (no dot) also pulls in its sub-techniques."""
    techniques = _load_attack_techniques()

    if technique_id:
        tid = technique_id.strip().upper()
        matches = [t for t in techniques.values() if t["id"] == tid or t["id"].startswith(f"{tid}.")]
        if not matches:
            raise ValueError(f"Unknown ATT&CK technique: {technique_id}")
        return sorted(matches, key=lambda t: t["id"]), f"technique {tid}"

    shortname = _normalize_tactic(tactic)
    if shortname is None:
        valid = ", ".join(sorted(_load_attack_tactics().values()))
        raise ValueError(f"Unknown ATT&CK tactic: {tactic}. Valid tactics: {valid}")
    matches = [t for t in techniques.values() if shortname in t.get("tactics", [])]
    tactic_name = _load_attack_tactics()[shortname]
    return sorted(matches, key=lambda t: t["id"]), f"tactic {tactic_name}"


def _build_coverage_report(technique_id: str | None, tactic: str | None) -> dict:
    matched_techniques, query_label = _resolve_techniques(technique_id, tactic)

    kb_rules = _load_kb_rules()
    details = []
    for technique in matched_techniques:
        detecting_rules = _rules_for_technique(kb_rules, technique["id"])
        details.append({
            "technique_id": technique["id"],
            "name": technique["name"],
            "coverage": _assess_coverage(detecting_rules),
            "rule_count": len(detecting_rules),
        })

    tally = Counter(d["coverage"] for d in details)
    gaps = [f"{d['technique_id']} - {d['name']}" for d in details if d["coverage"] == "gap"]

    return {
        "query": query_label,
        "techniques_assessed": len(details),
        "summary": {
            "covered": tally.get("covered", 0),
            "partial": tally.get("partial", 0),
            "gap": tally.get("gap", 0),
        },
        "gap_techniques": gaps,
        "details": details,
    }


def _assess_coverage(matched_rules: list[dict]) -> str:
    if not matched_rules:
        return "gap"
    if any(str(rule.get("level", "")).lower() in ("high", "critical") for rule in matched_rules):
        return "covered"
    return "partial"


def _read_attack_technique(technique_id: str) -> dict:
    if not ATTACK_DATA_PATH.is_file():
        raise ValueError(
            f"ATT&CK data not found at {ATTACK_DATA_PATH}. "
            "Run scripts/download_attack_data.py to install it."
        )

    techniques = _load_attack_techniques()
    technique = techniques.get(technique_id.strip().upper())
    if technique is None:
        raise ValueError(f"Unknown ATT&CK technique: {technique_id}")

    matched_rules = _rules_for_technique(_load_kb_rules(), technique_id)
    return {
        "technique_id": technique["id"],
        "name": technique["name"],
        "description": technique["description"],
        "rule_count": len(matched_rules),
        "detecting_rules": [
            {"title": rule["title"], "level": rule["level"], "path": rule["path"]}
            for rule in matched_rules
        ],
        "coverage": _assess_coverage(matched_rules),
    }


def _run_hayabusa(evtx_path: Path, output_path: Path, rules_dir: Path) -> subprocess.CompletedProcess:
    cmd = [
        str(HAYABUSA_PATH),
        "json-timeline",
        "-f", str(evtx_path),
        "-r", str(rules_dir),
        "-L",  # JSONL output: -o alone emits concatenated pretty-printed objects, not valid JSON
        "-o", str(output_path),
        "-w",  # no-wizard: don't prompt interactively
        "-q",  # quiet: skip launch banner
        "-Q",  # quiet-errors: don't write error log files
        "-K",  # no-color
        "-b",  # disable-abbreviations: keep Level as "critical", not "crit"
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=300)


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "scan_evtx":
        return await _scan_evtx(arguments)
    if name == "get_hayabusa_rules":
        return await _get_hayabusa_rules(arguments)
    if name == "analyze_coverage":
        return await _analyze_coverage(arguments)
    raise ValueError(f"Unknown tool: {name}")


async def _scan_evtx(arguments: dict) -> list[TextContent]:
    evtx_path_arg = arguments.get("evtx_path")
    min_severity = arguments.get("min_severity", "medium")
    rule_filter = arguments.get("rule_filter")
    output_format = arguments.get("output_format", "summary")
    max_results = arguments.get("max_results")

    if not evtx_path_arg:
        return _error("evtx_path is required")

    min_severity = str(min_severity).lower()
    if min_severity not in SEVERITY_LEVELS:
        return _error(
            f"Invalid min_severity '{min_severity}'. Must be one of: {', '.join(SEVERITY_LEVELS)}"
        )

    output_format = str(output_format).lower()
    if output_format not in OUTPUT_FORMATS:
        return _error(
            f"Invalid output_format '{output_format}'. Must be one of: {', '.join(OUTPUT_FORMATS)}"
        )

    if rule_filter is not None and not str(rule_filter).strip():
        return _error("rule_filter must not be empty")

    if max_results is not None:
        if not isinstance(max_results, int) or isinstance(max_results, bool) or max_results < 1:
            return _error("max_results must be a positive integer")

    evtx_path = Path(evtx_path_arg)
    if not evtx_path.is_file():
        return _error(f"EVTX file not found: {evtx_path_arg}")

    if not HAYABUSA_PATH.is_file():
        return _error(
            f"Hayabusa executable not found at {HAYABUSA_PATH}. "
            "Run scripts/download_hayabusa.py to install it."
        )

    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = Path(tmp_dir) / "results.jsonl"

        try:
            # RULES_DIR (the bundled ~5000-rule catalog), deliberately NOT
            # KB_RULES_DIR: scanning maximizes what's found in an EVTX, while
            # analyze_coverage and the detection:// resources assess custom_rules/
            # instead. The two report on different rulesets on purpose — "what did
            # the full catalog find here" vs "what do our own rules cover".
            result = _run_hayabusa(evtx_path, output_path, RULES_DIR)
        except FileNotFoundError:
            return _error(f"Hayabusa executable not found or not executable at {HAYABUSA_PATH}")
        except subprocess.TimeoutExpired:
            return _error(f"Hayabusa scan of {evtx_path_arg} timed out")
        except OSError as exc:
            return _error(f"Failed to run Hayabusa: {exc}")

        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            return _error(f"Hayabusa scan failed (exit code {result.returncode}). {detail}")

        if not output_path.exists():
            detail = result.stderr.strip() or result.stdout.strip()
            return _error(f"Hayabusa did not produce output. {detail}")

        raw_text = output_path.read_text()

    try:
        records = [json.loads(line) for line in raw_text.splitlines() if line.strip()]
    except json.JSONDecodeError as exc:
        return _error(f"Failed to parse Hayabusa output as JSON: {exc}")

    findings = _filter_records(records, min_severity, rule_filter)
    filtered_count = len(findings)

    if max_results is not None:
        findings = findings[:max_results]

    if output_format == "summary":
        findings = [_summarize(record) for record in findings]

    response = {
        "evtx_path": str(evtx_path),
        "min_severity": min_severity,
        "rule_filter": rule_filter,
        "output_format": output_format,
        "total_detections": len(records),
        "filtered_detections": filtered_count,
        "returned_detections": len(findings),
        "findings": findings,
    }
    return [TextContent(type="text", text=json.dumps(response, indent=2))]


async def _get_hayabusa_rules(arguments: dict) -> list[TextContent]:
    keyword = arguments.get("keyword")
    max_results = arguments.get("max_results", DEFAULT_RULES_MAX_RESULTS)

    if keyword is not None and not str(keyword).strip():
        return _error("keyword must not be empty")

    if not isinstance(max_results, int) or isinstance(max_results, bool) or max_results < 1:
        return _error("max_results must be a positive integer")

    if not RULES_DIR.is_dir():
        return _error(
            f"Rules directory not found at {RULES_DIR}. "
            "Run scripts/download_hayabusa.py to install it."
        )

    all_rules = _load_rules()
    matched = _filter_rules(all_rules, keyword)
    returned = matched[:max_results]

    response = {
        "keyword": keyword,
        "total_rules": len(all_rules),
        "matched_rules": len(matched),
        "returned_rules": len(returned),
        "rules": returned,
    }
    return [TextContent(type="text", text=json.dumps(response, indent=2))]


async def _analyze_coverage(arguments: dict) -> list[TextContent]:
    technique_id = arguments.get("technique_id")
    tactic = arguments.get("tactic")

    if technique_id is not None and not str(technique_id).strip():
        return _error("technique_id must not be empty")
    if tactic is not None and not str(tactic).strip():
        return _error("tactic must not be empty")

    if bool(technique_id) == bool(tactic):
        return _error("Provide exactly one of technique_id or tactic")

    if not ATTACK_DATA_PATH.is_file():
        return _error(
            f"ATT&CK data not found at {ATTACK_DATA_PATH}. "
            "Run scripts/download_attack_data.py to install it."
        )

    try:
        report = _build_coverage_report(technique_id, tactic)
    except ValueError as exc:
        return _error(str(exc))

    return [TextContent(type="text", text=json.dumps(report, indent=2))]


async def main():
    from mcp.server.stdio import stdio_server
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
