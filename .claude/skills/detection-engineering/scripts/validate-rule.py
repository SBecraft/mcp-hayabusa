#!/usr/bin/env python3
"""Validate a Sigma rule against the detection-engineering skill's standards.

Usage: validate-rule.py <path-to-sigma-rule.yml>
"""

import json
import re
import sys
import uuid
from pathlib import Path

import yaml

ATTACK_TAG_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$", re.IGNORECASE)
VALID_LEVELS = {"low", "medium", "high", "critical"}
VALID_TACTICS = {
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
}
PLACEHOLDER_FALSEPOSITIVES = {"unknown", "none", "n/a", "na", "tbd", "todo", "none observed", "none known"}

SEVERITY_COMMENT_RE = re.compile(r"^\s*#\s*Severity:", re.IGNORECASE | re.MULTILINE)
TEST_CASES_RE = re.compile(r"^\s*#\s*test[\s_]*cases?:", re.IGNORECASE | re.MULTILINE)
POSITIVE_TEST_RE = re.compile(r"should\s+trigger|expect:\s*match\b", re.IGNORECASE)
NEGATIVE_TEST_RE = re.compile(r"should\s+not\s+trigger|expect:\s*no_match", re.IGNORECASE)
TODO_RE = re.compile(r"\b(TODO|FIXME|XXX)\b", re.IGNORECASE)
FILENAME_RE = re.compile(r"^[a-z0-9]+(_[a-z0-9]+)*\.ya?ml$")


def _detection_block(raw: str) -> str:
    match = re.search(r"^detection:\n(.*?)(?=^\S|\Z)", raw, re.MULTILINE | re.DOTALL)
    return match.group(1) if match else raw


def validate(path: Path) -> dict:
    raw = path.read_text(encoding="utf-8")

    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        return {"file": str(path), "valid": False, "checks": {}, "issues": [f"Failed to parse YAML: {exc}"], "warnings": []}

    if not isinstance(doc, dict):
        return {"file": str(path), "valid": False, "checks": {}, "issues": ["Rule does not parse to a YAML mapping"], "warnings": []}

    issues = []
    warnings = []
    tags = [t for t in (doc.get("tags") or []) if isinstance(t, str)]

    # 1. attack_tags
    attack_tags = [t for t in tags if ATTACK_TAG_RE.match(t)]
    attack_tags_ok = len(attack_tags) > 0
    if not attack_tags_ok:
        issues.append("No ATT&CK technique tag found (expected attack.tXXXX or attack.tXXXX.YYY in tags)")

    # 2. tactic_tags (warning only)
    tactic_tags = [t for t in tags if t.lower().startswith("attack.") and t[7:].lower() in VALID_TACTICS]
    tactic_tags_ok = len(tactic_tags) > 0
    if not tactic_tags_ok:
        warnings.append("No ATT&CK tactic tag found (e.g. attack.credential-access) alongside the technique tag")

    # 3. valid_level
    level = doc.get("level")
    level_ok = isinstance(level, str) and level.lower() in VALID_LEVELS
    if not level_ok:
        issues.append(f"Invalid or missing 'level': {level!r}. Must be one of {sorted(VALID_LEVELS)}")

    # 4. severity_justified
    severity_justified_ok = bool(SEVERITY_COMMENT_RE.search(raw))
    if not severity_justified_ok:
        issues.append("No '# Severity:' comment found justifying the chosen level")

    # 5. false_positives
    falsepositives = doc.get("falsepositives")
    fp_list_ok = isinstance(falsepositives, list) and len(falsepositives) > 0
    placeholder_entries = []
    if fp_list_ok:
        placeholder_entries = [
            fp for fp in falsepositives
            if isinstance(fp, str) and fp.strip().lower() in PLACEHOLDER_FALSEPOSITIVES
        ]
    false_positives_ok = fp_list_ok and not placeholder_entries
    if not fp_list_ok:
        issues.append("Missing or empty 'falsepositives' list")
    elif placeholder_entries:
        issues.append(f"'falsepositives' contains placeholder entries instead of concrete scenarios: {placeholder_entries}")

    # 6. test_cases
    test_cases_ok = bool(TEST_CASES_RE.search(raw))
    if not test_cases_ok:
        issues.append("No '# test_case(s):' comment block found above detection:")

    # 7. positive_test
    positive_test_ok = bool(POSITIVE_TEST_RE.search(raw))
    if not positive_test_ok:
        issues.append("No documented 'should trigger' / 'expect: match' test case")

    # 8. negative_test
    negative_test_ok = bool(NEGATIVE_TEST_RE.search(raw))
    if not negative_test_ok:
        issues.append("No documented 'should NOT trigger' / 'expect: no_match' test case")

    # 9. valid_uuid
    rule_id = doc.get("id")
    valid_uuid_ok = False
    if isinstance(rule_id, str):
        try:
            uuid.UUID(rule_id)
            valid_uuid_ok = True
        except ValueError:
            pass
    if not valid_uuid_ok:
        issues.append(f"'id' is not a valid UUID: {rule_id!r}")

    # 10. valid_filename
    valid_filename_ok = bool(FILENAME_RE.match(path.name))
    if not valid_filename_ok:
        issues.append(f"Filename '{path.name}' does not match lower_snake_case.yml convention")

    # 11. has_references
    references = doc.get("references") or []
    has_references_ok = isinstance(references, list) and any(
        isinstance(r, str) and "attack.mitre.org" in r for r in references
    )
    if not has_references_ok:
        issues.append("No ATT&CK URL (attack.mitre.org) found in 'references'")

    # 12. no_todo_placeholders
    todo_matches = sorted(set(TODO_RE.findall(_detection_block(raw))))
    no_todo_ok = len(todo_matches) == 0
    if not no_todo_ok:
        issues.append(f"TODO-style placeholder(s) found in detection logic: {todo_matches}")

    checks = {
        "attack_tags": {"passed": attack_tags_ok, "found": attack_tags},
        "tactic_tags": {"passed": tactic_tags_ok, "found": tactic_tags, "warning_only": True},
        "valid_level": {"passed": level_ok, "value": level},
        "severity_justified": {"passed": severity_justified_ok},
        "false_positives": {"passed": false_positives_ok, "count": len(falsepositives) if fp_list_ok else 0},
        "test_cases": {"passed": test_cases_ok},
        "positive_test": {"passed": positive_test_ok},
        "negative_test": {"passed": negative_test_ok},
        "valid_uuid": {"passed": valid_uuid_ok, "value": rule_id},
        "valid_filename": {"passed": valid_filename_ok, "value": path.name},
        "has_references": {"passed": has_references_ok},
        "no_todo_placeholders": {"passed": no_todo_ok},
    }

    required_passed = all(check["passed"] for name, check in checks.items() if not check.get("warning_only"))

    return {
        "file": str(path),
        "valid": required_passed,
        "checks": checks,
        "issues": issues,
        "warnings": warnings,
    }


def main() -> None:
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: validate-rule.py <path-to-sigma-rule.yml>"}, indent=2))
        sys.exit(2)

    path = Path(sys.argv[1])
    if not path.is_file():
        print(json.dumps({"error": f"File not found: {path}"}, indent=2))
        sys.exit(2)

    result = validate(path)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
