"""Prove every Sigma rule fires on its malicious samples and stays quiet on benign ones.

For each rule in rules/sigma/, a matching test file in tests/sigma/ (same name, .json)
holds "should_match" and "should_not_match" events. The rule is converted to SQL with
pySigma's SQLite backend and run against those events in an in-memory database.
"""
import json
import sqlite3
from pathlib import Path

import pytest
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

ROOT = Path(__file__).resolve().parent.parent
RULES = sorted((ROOT / "rules" / "sigma").glob("*.yml"))
TESTS = ROOT / "tests" / "sigma"


def run_rule(rule_path, events):
    """Return the indexes of events that the rule matches."""
    queries = sqliteBackend().convert(SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8")))
    fields = sorted({k for e in events for k in e if k != "description"})
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    cols = ", ".join(f'"{f}" TEXT' for f in fields)
    db.execute(f'CREATE TABLE logs ("_idx" INTEGER, {cols})')
    for i, e in enumerate(events):
        names = ", ".join(['"_idx"'] + [f'"{f}"' for f in fields])
        marks = ", ".join("?" * (len(fields) + 1))
        db.execute(f"INSERT INTO logs ({names}) VALUES ({marks})", [i] + [e.get(f) for f in fields])
    hits = set()
    for q in queries:
        hits |= {row["_idx"] for row in db.execute(q)}
    return hits


@pytest.mark.parametrize("rule_path", RULES, ids=[r.stem for r in RULES])
def test_sigma_rule(rule_path):
    test_file = TESTS / f"{rule_path.stem}.json"
    assert test_file.exists(), f"Missing test file: tests/sigma/{test_file.name}"
    data = json.loads(test_file.read_text(encoding="utf-8"))
    good, bad = data["should_match"], data["should_not_match"]
    assert good and bad, "Need at least one should_match and one should_not_match event"

    hits = run_rule(rule_path, good + bad)
    missed = [good[i]["description"] for i in range(len(good)) if i not in hits]
    false_pos = [bad[i]["description"] for i in range(len(bad)) if i + len(good) in hits]
    assert not missed, f"Rule did NOT fire on: {missed}"
    assert not false_pos, f"Rule fired on benign events: {false_pos}"