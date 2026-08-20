"""Phase 1 gate: verify answer-key totals meet plan thresholds.

Gate criteria (from plan.json step-006):
  - >=30 vulnerable spots across all 5 projects
  - >=3 distinct vuln types (CWE IDs)
  - spot-check 3 entries (done manually via gh api on 2026-08-20)
"""
import json
import glob
import os
import pytest

ANSWER_KEY_DIR = os.path.join(
    os.path.dirname(__file__), '..', 'data', 'answer_key'
)

# Files that are NOT per-project answer keys
_EXCLUDE = {'phase1_summary.json'}


def _load_all_answer_keys():
    """Load all per-project answer-key JSON files (exclude seeds + summary)."""
    pattern = os.path.join(ANSWER_KEY_DIR, '*.json')
    files = sorted(
        f for f in glob.glob(pattern)
        if 'seeds' not in os.path.basename(f)
        and os.path.basename(f) not in _EXCLUDE
    )
    keys = []
    for f in files:
        with open(f) as fh:
            keys.append(json.load(fh))
    return keys


class TestPhase1Gate:
    """Phase 1 completion gate tests."""

    def test_five_projects_present(self):
        keys = _load_all_answer_keys()
        projects = {k['project'] for k in keys}
        assert len(projects) >= 5, f"Need 5 projects, got {len(projects)}: {projects}"

    def test_minimum_30_spots(self):
        keys = _load_all_answer_keys()
        total = sum(k.get('total_spots', 0) for k in keys)
        assert total >= 30, f"Need >=30 spots, got {total}"

    def test_minimum_3_vuln_types(self):
        keys = _load_all_answer_keys()
        cwes = set()
        for k in keys:
            for e in k.get('entries', []):
                cw = e.get('cwe_id', '')
                if cw:
                    cwes.add(cw)
        assert len(cwes) >= 3, f"Need >=3 CWE types, got {len(cwes)}"

    def test_each_project_has_10_plus_spots(self):
        """Each individual project must have >=10 spots."""
        keys = _load_all_answer_keys()
        for k in keys:
            spots = k.get('total_spots', 0)
            name = k.get('project', '?')
            assert spots >= 10, f"{name} has only {spots} spots (need >=10)"

    def test_entries_have_required_fields(self):
        """Every entry must have cve_id, fix_commit_sha, vulnerable_files."""
        keys = _load_all_answer_keys()
        for k in keys:
            name = k.get('project', '?')
            for i, e in enumerate(k.get('entries', [])):
                assert e.get('cve_id'), f"{name} entry {i} missing cve_id"
                assert e.get('fix_commit_sha'), f"{name} entry {i} missing fix_sha"
                assert e.get('vulnerable_files'), f"{name} entry {i} missing vuln_files"

    def test_spot_check_log_exists(self):
        """Verify the spot-check results file was written."""
        path = os.path.join(ANSWER_KEY_DIR, 'phase1_summary.json')
        assert os.path.exists(path), "phase1_summary.json not found"
        with open(path) as f:
            summary = json.load(f)
        assert summary.get('spot_checks_passed') == 3
        assert summary.get('spot_checks_total') == 3
