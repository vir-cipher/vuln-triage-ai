# spec.md — vuln-triage-ai · FROZEN 2026-08-04 (Rule 1: read-only for every daily run)

## Research question
For LLM triage of static-analysis security alerts, how does verdict accuracy change with the amount of surrounding code context shown to the model — and does accuracy invert past an optimum context size?

## Hypothesis
Accuracy versus context follows a rise → peak → invert curve: too little context forces guessing; too much drowns the signal. The inversion point ("context-optimality") has not been measured in prior work.

## Prior art (primary sources, verified 2026-08-04)
- "Sifting the Noise: A Comparative Study of LLM Agents in Vulnerability False Positive Filtering" — arXiv:2601.22952, submitted 30-Jan-2026. Evaluates Aider, OpenHands, SWE-agent on OWASP Benchmark + real-world Java projects; reports false-positive rate reduced from >92% to as low as 6%.
- Semgrep Assistant — semgrep.dev/products/semgrep-assistant (2025). Commercial LLM triage; ~95% user agreement, ~20% noise reduction reported by vendor.

## Differentiation (what nobody has measured)
1. The context-optimality curve itself — accuracy as a controlled function of context size.
2. Cross-language targets (Python/C/JavaScript) vs Java-only prior work.
3. Direct prompting with fixed context windows (isolates the context variable) vs agent frameworks (which choose their own context, confounding it).
4. A failure taxonomy: LONG_FUNCTION / CROSS_FILE / UNFAMILIAR_LANG / SUBTLE_FLOW / MISSING_CALLER / OTHER.

## Method (phases and gates)
- **P0 scaffold** — repo, README ≥200w, WALKTHROUGH ≥300w, CI, frozen spec+plan. Gate: tests green, no speculation.
- **P1 answer key** — 5 OSS projects with rich security-fix history; git archaeology recovers pre-fix vulnerable locations into `data/answer_key/*.json`. Gate: ≥30 spots total, ≥10/project, ≥3 vuln types, 3 entries spot-checked via GitHub API.
- **P2 scanner baseline** — Semgrep on the pre-fix snapshots; precision/recall vs answer key with ±5-line location matching. Gate: matching rule documented; expectation (not requirement): precision <50%.
- **P3 context-curve triage** — fixed context levels: **L0** flagged function only · **L1** + direct callers/callees · **L2** + tests and docs touching it · **L3** whole module · **L4** repo-wide retrieval. LLM verdict per alert per level. Gate: ≥3 projects triaged, verdicts not uniform, spend <$5.
- **P4 scoring + failure taxonomy** — precision/recall/F1 per level; ≥5 classified failures. Gate: scores reproducible, nothing fabricated.
- **P5 write-up** — WALKTHROUGH >2000w (9 sections, all jargon defined); README <500w with quick-start + key finding + credits "B.Cyber at IIT Kanpur (WSAIS)".
- **P6 publish** — evidence sync to portal + Ground Truth §7.

## Guardrails (non-negotiable)
- ≤10 LLM API calls per daily run; total project spend <$5.
- `ANTHROPIC_API_KEY` from environment only — never in code, config, or commits. Missing key = human gate, not a workaround.
- Public repositories and published benchmark data only; never a live system.
- Defensive scope: output helps maintainers rank real bugs. No exploit generation.
- Any real, unreported finding → private maintainer disclosure before anything public.

## Out of scope
Agent frameworks, exploit tooling, live targets, private code, model fine-tuning.
