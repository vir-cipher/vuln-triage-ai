"""Answer-key tests — Phase 1 (steps 001–006).

Step-001: targets.md lists 5 projects with language, fix-commit density,
and rationale for each.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ROOT / "data" / "answer_key" / "targets.md"

# The five project names we selected (order matters for the heading check).
EXPECTED_PROJECTS = ["Django", "curl", "OpenSSL", "Pillow", "Node.js"]


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
        # Find the section for this project (from its heading to the next ### or ---)
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