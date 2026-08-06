"""Scaffold integrity tests — step-000.

Every later step builds on the guarantees checked here: the plan is frozen,
the metadata parses, the docs meet their word floors, and no secret-shaped
string is committed.
"""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _words(rel: str) -> int:
    return len(re.findall(r"\S+", (ROOT / rel).read_text(encoding="utf-8")))


def test_readme_is_substantial():
    assert _words("README.md") >= 200


def test_walkthrough_is_substantial():
    assert _words("docs/WALKTHROUGH.md") >= 300


def test_plan_is_frozen_and_ordered():
    plan = json.loads((ROOT / ".project-meta/plan.json").read_text(encoding="utf-8"))
    assert plan["immutable"] is True
    ids = [s["id"] for s in plan["steps"]]
    assert ids == [f"step-{i:03d}" for i in range(len(ids))]
    assert len(ids) >= 21
    phases = [s["phase"] for s in plan["steps"]]
    assert phases == sorted(phases)

def test_ledger_parses_and_knows_step_000():
    ledger = json.loads((ROOT / ".project-meta/ledger.json").read_text(encoding="utf-8"))
    steps = {s["id"]: s for s in ledger["steps"]["p1_cyber"]}
    assert steps["step-000"]["status"] == "done"


def test_src_package_imports():
    import src

    assert src.__version__


def test_meta_loader_reads_frozen_plan():
    from src.meta import current_step, load_ledger, load_plan

    assert load_plan()["project"] == "p1_cyber"
    assert load_ledger()["github"] == "vir-cipher"
    # current_step() returns the NEXT step to execute (step_pointer indexes plan)
    step = current_step()
    pointer = load_ledger()["projects"]["p1_cyber"]["step_pointer"]
    assert step["id"] == f"step-{pointer:03d}"


def test_ci_workflow_runs_pytest():
    text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "actions/checkout" in text
    assert "pytest" in text


SECRET = re.compile(
    r"(?i)(anthropic_api_key|password|secret|token)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{8,}[\"']"
)


def test_no_secret_shaped_strings_committed():
    for pattern in ("**/*.py", "**/*.yml", "**/*.json", "**/*.md", "**/*.txt", "**/*.log"):
        for f in ROOT.glob(pattern):
            if ".git" in f.parts:
                continue
            text = f.read_text(encoding="utf-8", errors="ignore")
            assert not SECRET.search(text), f"secret-shaped string in {f}"