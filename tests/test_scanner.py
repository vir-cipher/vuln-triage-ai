"""Scanner tests -- Phase 2, step-007.

step-007: src/run_scanner.py wraps Semgrep with a locally-pinned ruleset
(src/rules/security_rules.yml) so scans are reproducible forever, and
produces deterministic alert JSON for the Django vulnerable snapshot.

Network/gh-api calls are NOT exercised here (CI has no gh auth token for
arbitrary repo content) -- these tests validate (a) the committed alert
artifact's structure and sort order, and (b) that normalize_alerts() is a
pure, deterministic function, using synthetic Semgrep-shaped input.
"""

import json
import re
from pathlib import Path

from src.run_scanner import normalize_alerts

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "src" / "rules" / "security_rules.yml"
DJANGO_ALERTS = ROOT / "data" / "alerts" / "django.json"


def test_ruleset_file_exists_and_has_rules():
    assert RULES.exists(), "src/rules/security_rules.yml missing"
    text = RULES.read_text(encoding="utf-8")
    rule_ids = re.findall(r"^\s*-\s+id:\s+(\S+)", text, re.MULTILINE)
    assert len(rule_ids) >= 5, f"Expected >=5 rules, got {len(rule_ids)}"
    assert len(rule_ids) == len(set(rule_ids)), "Duplicate rule ids"


def test_django_alerts_file_exists():
    assert DJANGO_ALERTS.exists(), "data/alerts/django.json missing"


def test_django_alerts_structure():
    with open(DJANGO_ALERTS) as f:
        data = json.load(f)
    for key in ("snapshot_dir", "ruleset", "total_alerts", "alerts"):
        assert key in data, f"django.json missing key: {key}"
    assert data["total_alerts"] == len(data["alerts"])
    assert data["total_alerts"] > 0, "expected at least one alert"
    required = {"check_id", "file", "start_line", "end_line",
                "message", "severity"}
    for a in data["alerts"]:
        assert required.issubset(a.keys()), f"alert missing fields: {a}"


def test_django_alerts_are_sorted_deterministically():
    with open(DJANGO_ALERTS) as f:
        data = json.load(f)
    alerts = data["alerts"]
    keys = [(a["file"], a["start_line"], a["check_id"]) for a in alerts]
    assert keys == sorted(keys), (
        "alerts must be sorted by (file, start_line, check_id) so "
        "re-running the scan yields byte-identical output"
    )


def _fake_result(path, line, check_id, msg="x", sev="WARNING"):
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line},
        "end": {"line": line},
        "extra": {"message": msg, "severity": sev},
    }


def test_normalize_alerts_is_deterministic_across_calls():
    snap = Path("/tmp/snap")
    raw = [
        _fake_result("/tmp/snap/b.py", 10, "rule-b"),
        _fake_result("/tmp/snap/a.py", 5, "rule-a"),
        _fake_result("/tmp/snap/a.py", 1, "rule-c"),
    ]
    out1 = normalize_alerts(list(raw), snap)
    out2 = normalize_alerts(list(reversed(raw)), snap)
    assert out1 == out2, "same findings in a different input order must " \
        "normalize to the identical, sorted output"


def test_normalize_alerts_sort_order():
    snap = Path("/tmp/snap")
    raw = [
        _fake_result("/tmp/snap/b.py", 1, "z-rule"),
        _fake_result("/tmp/snap/a.py", 2, "a-rule"),
        _fake_result("/tmp/snap/a.py", 1, "b-rule"),
    ]
    out = normalize_alerts(raw, snap)
    files_lines = [(a["file"], a["start_line"]) for a in out]
    assert files_lines == [("a.py", 1), ("a.py", 2), ("b.py", 1)]


def test_run_scanner_cli_importable():
    from src.run_scanner import fetch_snapshot, run_semgrep, main
    assert callable(fetch_snapshot)
    assert callable(run_semgrep)
    assert callable(main)
