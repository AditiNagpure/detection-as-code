"""Validate every Microsoft Sentinel analytics rule in rules/sentinel/ before it can be deployed.

Checks the fields Sentinel needs, allowed values, query timing limits, ATT&CK technique format,
duplicate rule IDs, and that every entity-mapping column actually exists in the KQL query.
"""
import re
import uuid
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES = sorted((ROOT / "rules" / "sentinel").glob("*.yaml"))

REQUIRED = [
    "id", "name", "description", "severity", "requiredDataConnectors", "queryFrequency",
    "queryPeriod", "triggerOperator", "triggerThreshold", "tactics", "relevantTechniques",
    "query", "entityMappings", "version", "kind",
]
SEVERITIES = {"Informational", "Low", "Medium", "High"}
OPERATORS = {"gt", "lt", "eq"}
TACTICS = {
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence",
    "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Discovery", "LateralMovement",
    "Collection", "Exfiltration", "CommandAndControl", "Impact",
}
DURATION = re.compile(r"^(\d+)([mhd])$")
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
VERSION = re.compile(r"^\d+\.\d+\.\d+$")


def minutes(value):
    m = DURATION.match(str(value))
    assert m, f"Bad duration '{value}': use a number plus m, h or d (e.g. 5m, 1h, 1d)"
    return int(m.group(1)) * {"m": 1, "h": 60, "d": 1440}[m.group(2)]


def load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_rule_ids_are_unique():
    ids = [str(load(p).get("id")) for p in RULES]
    dupes = {i for i in ids if ids.count(i) > 1}
    assert not dupes, f"Duplicate rule IDs: {dupes}"


@pytest.mark.parametrize("rule_path", RULES, ids=[r.stem for r in RULES])
def test_sentinel_rule(rule_path):
    rule = load(rule_path)

    missing = [k for k in REQUIRED if k not in rule]
    assert not missing, f"Missing required fields: {missing}"

    uuid.UUID(str(rule["id"]))  # raises if the ID is not a valid GUID
    assert rule["kind"] == "Scheduled", "Only Scheduled rules are supported"
    assert rule["severity"] in SEVERITIES, f"severity must be one of {SEVERITIES}"
    assert rule["triggerOperator"] in OPERATORS, f"triggerOperator must be one of {OPERATORS}"
    assert isinstance(rule["triggerThreshold"], int) and rule["triggerThreshold"] >= 0
    assert VERSION.match(str(rule["version"])), "version must look like 1.0.0"

    freq, period = minutes(rule["queryFrequency"]), minutes(rule["queryPeriod"])
    assert 5 <= freq <= 14 * 1440, "queryFrequency must be between 5m and 14d"
    assert period <= 14 * 1440, "queryPeriod cannot exceed 14d"
    assert freq <= period, "queryFrequency cannot be longer than queryPeriod (events would be skipped)"

    bad_tactics = [t for t in rule["tactics"] if t not in TACTICS]
    assert not bad_tactics, f"Unknown tactics: {bad_tactics}"
    bad_tech = [t for t in rule["relevantTechniques"] if not TECHNIQUE.match(str(t))]
    assert not bad_tech, f"Bad technique IDs: {bad_tech}"

    query = rule["query"]
    assert query and query.strip(), "query is empty"
    for connector in rule["requiredDataConnectors"]:
        for table in connector["dataTypes"]:
            assert re.search(rf"\b{re.escape(table)}\b", query), f"Query never uses declared table {table}"

    for entity in rule["entityMappings"]:
        for fm in entity["fieldMappings"]:
            col = fm["columnName"]
            assert re.search(rf"\b{re.escape(col)}\b", query), (
                f"Entity mapping column '{col}' ({entity['entityType']}) does not appear in the query"
            )