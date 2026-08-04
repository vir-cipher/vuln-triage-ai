"""Helpers to read the project's frozen metadata (.project-meta/).

The daily engine and the test suite both go through these functions, so the
frozen plan and the ledger are parsed in exactly one place.
"""

import json
from pathlib import Path

META_DIR = Path(__file__).resolve().parents[1] / ".project-meta"


def load_plan() -> dict:
    """Return the frozen, immutable step plan (Rule 1)."""
    return json.loads((META_DIR / "plan.json").read_text(encoding="utf-8"))


def load_ledger() -> dict:
    """Return the canonical ledger. Status is derived from git, never asserted."""
    return json.loads((META_DIR / "ledger.json").read_text(encoding="utf-8"))


def current_step() -> dict:
    """The next step the engine will execute (pointer indexes the frozen plan)."""
    pointer = load_ledger()["projects"]["p1_cyber"]["step_pointer"]
    return load_plan()["steps"][pointer]
