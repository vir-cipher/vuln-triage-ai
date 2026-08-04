# vuln-triage-ai

**Context-Curve Experiment: when does more code context start hurting an LLM's vulnerability triage?**

Security scanners (SAST tools such as Semgrep) read source code and raise alerts on lines that look dangerous. On real projects most alerts are false positives — false alarms — and humans burn hours separating real bugs from noise. Recent research shows large language models (LLMs) can filter much of that noise: "Sifting the Noise" (arXiv:2601.22952, Jan 2026) reports LLM agent frameworks cutting a >92% false-positive rate on the OWASP Benchmark to as low as 6%.

One variable stays unmeasured in that line of work: **how much surrounding code the model should see**. Show too little and it guesses; show too much and the signal drowns. This project measures triage accuracy at five fixed context levels — from the flagged function alone up to repo-wide context — and plots the resulting **context-optimality curve**. The hypothesis under test: accuracy rises, peaks, then inverts beyond some context size.

## How this differs from prior art

- Cross-language targets (Python/C/JavaScript), not Java-only.
- Direct prompting with controlled context windows, not agent frameworks — so the context variable is isolated.
- A failure taxonomy of *where* and *why* triage goes wrong.

## Method (six phases)

Answer key mined from real fix-commit history → scanner baseline → LLM triage at each context level → scoring + failure analysis → write-up → publish. The frozen step list lives in `.project-meta/plan.json`; progress is derived from `git log`, never asserted from memory.

## Status

building — Phase 0 done (scaffold, CI, frozen spec + plan). Numbers appear in `results/` only once measured; this README makes no result claims yet.

## Reproduce today

```bash
git clone https://github.com/vir-cipher/vuln-triage-ai
cd vuln-triage-ai
pip install -r requirements.txt
python -m pytest -q
```

## Ethics

Public repositories and published benchmark data only. The purpose is defensive — helping maintainers rank real bugs faster. No live-system scanning, no exploit tooling.

## Credits

Built by **Ansh Vir Bhargav** — B.Cyber at IIT Kanpur (WSAIS), 2026–2030. Extends an earlier OWASP Juice Shop admin-auth-bypass write-up.
