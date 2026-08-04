# Walkthrough — vuln-triage-ai

A guided tour written for a reader two weeks into a CS degree. Every jargon term is defined the first time it appears. This document grows with the project; sections marked *coming* are not written yet, and nothing below claims a result that has not been measured.

## 1. The problem in one minute

- A **scanner** (also called SAST — static application security testing) is a program that reads source code and flags lines that look dangerous, without running the program.
- Scanners are noisy. On real codebases, most alerts are **false positives**: the scanner says "danger" but the code is fine.
- Engineers must **triage** the pile — decide, alert by alert, real or false alarm. That is slow, boring, and error-prone.
- An **LLM** (large language model — AI that reads and reasons over text and code) can help with triage. Published work shows big noise reductions.
- Open question: when you ask an LLM "is this alert real?", **how much surrounding code should you paste in?** The function alone? The whole file? The whole repo? Nobody has measured where the sweet spot is. That measurement is this project.

## 2. What exists at this commit

- Project skeleton: `src/`, `tests/`, `data/`, `results/`, `docs/`.
- `.project-meta/` — the project's self-description: `spec.md` (the frozen brief), `plan.json` (the frozen, ordered list of 21 steps), `ledger.json` (machine-readable progress, always reconciled against `git log`), `decisions.log` (dated decisions).
- `src/meta.py` — small helpers that read the frozen plan and ledger; the daily engine and the tests both use them.
- `tests/test_scaffold.py` — checks the plan is frozen and ordered, the docs meet their word floors, the metadata parses, and no secret-shaped string is committed.
- **CI** (continuous integration — a robot that reruns the tests on every push) via GitHub Actions: `.github/workflows/ci.yml`.

## 3. The experiment we will run

- **Phase 1 — answer key.** Find five open-source projects with a rich history of security fixes. Each fix commit tells us where a real vulnerability used to live. Collecting those locations gives **ground truth** (the known-correct answers we score against).
- **Phase 2 — scanner baseline.** Run Semgrep on the pre-fix (still vulnerable) snapshots. Score its alerts against the answer key: **precision** (of all alerts, how many were real?) and **recall** (of all real bugs, how many were caught?).
- **Phase 3 — the context curve.** For each alert, ask the LLM for a verdict five times, each time with a different, fixed amount of surrounding code: L0 flagged function only · L1 + direct callers · L2 + tests and docs that touch it · L3 whole module · L4 repo-wide. Plot accuracy against level.
- **Phase 4 — scoring + failure taxonomy.** Precision/recall/F1 per level, plus a labelled catalogue of the ways the LLM got it wrong.
- **Phase 5–6 — write-up and publish.**

## 4. The answer key *(coming — Phase 1)*

## 5. Scanner baseline *(coming — Phase 2)*

## 6. LLM triage and the context curve *(coming — Phase 3)*

## 7. Scoring and failure analysis *(coming — Phase 4)*

## 8. How to reproduce (at this commit)

```bash
# copy the project to your machine
git clone https://github.com/vir-cipher/vuln-triage-ai
cd vuln-triage-ai
# install the one test dependency
pip install -r requirements.txt
# run the checks — expect all green
python -m pytest -q
```

## 9. Glossary

- **SAST / scanner** — reads code, flags danger, never runs the program.
- **Semgrep** — the free, open-source scanner used here.
- **False positive / false negative** — false alarm / missed real bug.
- **Triage** — sorting alerts into real vs noise.
- **LLM** — AI model that reads and reasons over text and code.
- **Ground truth / answer key** — the known-correct answers, mined here from maintainers' own fix commits.
- **Precision / recall** — alert quality / bug coverage, defined in §3.
- **CI** — auto-running tests on every change.
- **Context level** — the fixed amount of surrounding code shown to the LLM (L0–L4, defined in §3).
