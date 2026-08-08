"""Answer-key tests — Phase 1 (steps 001–006).

Step-001: targets.md lists 5 projects with language, fix-commit density,
and rationale for each.

Step-002: django.json has >=10 pre-fix vulnerable spots across >=5 CVEs
with >=3 CWE types, mined via git archaeology from real fix commits.
"""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ROOT / "data" / "answer_key" / "targets.md"
DJANGO_AK = ROOT / "data" / "answer_key" / "django.json"
DJANGO_SEEDS = ROOT / "data" / "answer_key" / "django_seeds.json"

# The five project names we selected (order matters for the heading check).
EXPECTED_PROJECTS = ["Django", "curl", "OpenSSL", "Pillow", "Node.js"]


# --- Step-001 tests (targets.md) ---

def test_targets_file_exists():
    assert TARGETS.exists(), "data/answer_key/targets.md missing"


def test_targets_lists_five_projects():
    text = TARGETS.read_text(encoding="utf-8")
    # Each project has a "### N. Name" heading
    headings = re.findall(r"^### \d+\.\s+(.+)$", text, re.MULTILINE)
    assert len(headings) == 5, f"Expected 5 project headings, got {headings}"
    for name in EXPECTED_PROJECTS:
        assert name in headings, f"Missing project heading: {name}"

def test_each_project_has_language():
    text = TARGETS.read_text(encoding="utf-8")
    for name in EXPECTED_PROJECTS:
        pattern = rf"### \d+\.\s+{re.escape(name)}.*?(?=### \d+\.|---|\Z)"
        match = re.search(pattern, text, re.DOTALL)
        assert match, f"Could not find section for {name}"
        section = match.group()
        assert re.search(
            r"\*\*Language:\*\*", section
        ), f"{name} section missing **Language:**"


def test_each_project_has_fix_commit_density():
    text = TARGETS.read_text(encoding="utf-8")
    for name in EXPECTED_PROJECTS:
        pattern = rf"### \d+\.\s+{re.escape(name)}.*?(?=### \d+\.|---|\Z)"
        match = re.search(pattern, text, re.DOTALL)
        assert match, f"Could not find section for {name}"
        section = match.group()
        assert re.search(
            r"\*\*Fix-commit density:\*\*", section
        ), f"{name} section missing **Fix-commit density:**"


def test_each_project_has_rationale():
    text = TARGETS.read_text(encoding="utf-8")
    for name in EXPECTED_PROJECTS:
        pattern = rf"### \d+\.\s+{re.escape(name)}.*?(?=### \d+\.|---|\Z)"
        match = re.search(pattern, text, re.DOTALL)
        assert match, f"Could not find section for {name}"
        section = match.group()
        assert re.search(
            r"\*\*Rationale:\*\*", section
        ), f"{name} section missing **Rationale:**"


# --- Step-002 tests (django.json answer key) ---

def test_django_answer_key_exists():
    assert DJANGO_AK.exists(), "data/answer_key/django.json missing"


def test_django_seeds_exists():
    assert DJANGO_SEEDS.exists(), "data/answer_key/django_seeds.json missing"


def test_django_ak_has_at_least_10_spots():
    ak = json.loads(DJANGO_AK.read_text(encoding="utf-8"))
    assert ak["total_spots"] >= 10, (
        f"Need >=10 vulnerable spots, got {ak['total_spots']}"
    )


def test_django_ak_has_at_least_5_cves():
    ak = json.loads(DJANGO_AK.read_text(encoding="utf-8"))
    assert ak["total_cves"] >= 5, (
        f"Need >=5 CVEs, got {ak['total_cves']}"
    )


def test_django_ak_has_at_least_3_cwe_types():
    ak = json.loads(DJANGO_AK.read_text(encoding="utf-8"))
    types = {e["cwe_id"] for e in ak["entries"]}
    assert len(types) >= 3, (
        f"Need >=3 distinct CWE types, got {len(types)}: {types}"
    )


def test_django_ak_entries_have_required_fields():
    ak = json.loads(DJANGO_AK.read_text(encoding="utf-8"))
    required = ["cve_id", "fix_commit_sha", "parent_commit_sha",
                "vulnerable_files", "vuln_type", "cwe_id"]
    for entry in ak["entries"]:
        for field in required:
            assert entry.get(field), (
                f'{entry.get("cve_id", "?")}: missing or empty field "{field}"'
            )


def test_django_ak_every_entry_has_vuln_files():
    ak = json.loads(DJANGO_AK.read_text(encoding="utf-8"))
    for entry in ak["entries"]:
        assert len(entry["vulnerable_files"]) >= 1, (
            f'{entry["cve_id"]}: no vulnerable files recorded'
        )


def test_django_ak_vuln_files_are_source_not_docs():
    """Vulnerable files should be source code, not docs or test files."""
    ak = json.loads(DJANGO_AK.read_text(encoding="utf-8"))
    for entry in ak["entries"]:
        for vf in entry["vulnerable_files"]:
            f = vf["file"]
            assert not f.startswith("docs/"), (
                f'{entry["cve_id"]}: {f} is a docs file, not source'
            )
            assert not f.startswith("tests/"), (
                f'{entry["cve_id"]}: {f} is a test file, not source'
            )


def test_django_ak_fix_shas_are_40_hex():
    """Fix commit SHAs should be full 40-char hex."""
    ak = json.loads(DJANGO_AK.read_text(encoding="utf-8"))
    for entry in ak["entries"]:
        sha = entry["fix_commit_sha"]
        assert len(sha) == 40 and all(c in "0123456789abcdef" for c in sha), (
            f'{entry["cve_id"]}: fix_commit_sha "{sha}" is not 40-char hex'
        )


def test_django_ak_parent_shas_are_40_hex():
    """Parent commit SHAs should be full 40-char hex."""
    ak = json.loads(DJANGO_AK.read_text(encoding="utf-8"))
    for entry in ak["entries"]:
        sha = entry["parent_commit_sha"]
        assert len(sha) == 40 and all(c in "0123456789abcdef" for c in sha), (
            f'{entry["cve_id"]}: parent_commit_sha "{sha}" is not 40-char hex'
        )
