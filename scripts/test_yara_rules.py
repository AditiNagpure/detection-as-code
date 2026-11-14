"""Prove every YARA rule compiles, matches its malicious samples and ignores benign ones.

Layout for a rule rules/yara/<name>.yar:
    tests/yara/<name>/match/     files the rule MUST match
    tests/yara/<name>/nomatch/   files the rule must NOT match
"""
from pathlib import Path

import pytest
import yara

ROOT = Path(__file__).resolve().parent.parent
RULES = sorted((ROOT / "rules" / "yara").glob("*.yar"))
TESTS = ROOT / "tests" / "yara"


@pytest.mark.parametrize("rule_path", RULES, ids=[r.stem for r in RULES])
def test_yara_rule(rule_path):
    rules = yara.compile(filepath=str(rule_path))  # fails the test on any syntax error

    match_dir = TESTS / rule_path.stem / "match"
    nomatch_dir = TESTS / rule_path.stem / "nomatch"
    good = sorted(p for p in match_dir.glob("*") if p.is_file())
    bad = sorted(p for p in nomatch_dir.glob("*") if p.is_file())
    assert good, f"No malicious samples in tests/yara/{rule_path.stem}/match/"
    assert bad, f"No benign samples in tests/yara/{rule_path.stem}/nomatch/"

    missed = [p.name for p in good if not rules.match(data=p.read_bytes())]
    false_pos = [p.name for p in bad if rules.match(data=p.read_bytes())]
    assert not missed, f"Rule did NOT fire on: {missed}"
    assert not false_pos, f"Rule fired on benign files: {false_pos}"