"""Semgrep scanner wrapper — Phase 2 (steps 007-009).

Fetches the pre-fix (vulnerable) snapshot of source files named in an
answer-key JSON, scans them with a locally-pinned Semgrep ruleset
(src/rules/security_rules.yml) so results are fully reproducible -- no
dependency on the Semgrep registry, which can change its rules over time
and would silently break determinism.

Usage:
  python src/run_scanner.py --answer-key data/answer_key/django.json \
                             --snapshot-dir data/snapshots/django \
                             --out data/alerts/django.json

  # Re-score an existing snapshot without re-fetching from GitHub:
  python src/run_scanner.py --answer-key data/answer_key/django.json \
                             --snapshot-dir data/snapshots/django \
                             --out data/alerts/django.json --skip-fetch
"""

import argparse
import base64
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "src" / "rules" / "security_rules.yml"
SEMGREP_BIN = "semgrep"


def _gh_api(endpoint: str) -> dict:
    """Call GitHub API via `gh api`. Self-contained (no cross-module import
    from answer_key_miner) so this file works both as a script and when
    imported as src.run_scanner in tests."""
    result = subprocess.run(
        ["gh", "api", endpoint],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"gh api failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def fetch_snapshot(answer_key_path: Path, out_dir: Path) -> list[Path]:
    """Fetch every vulnerable file at its pre-fix parent SHA into out_dir.

    Layout: out_dir/<parent_sha[:8]>/<original/path>
    Dedupes identical (parent_sha, file) pairs across CVE entries.
    """
    with open(answer_key_path) as f:
        ak = json.load(f)
    repo = ak["repo"]

    fetched = []
    seen = set()
    for entry in ak["entries"]:
        sha = entry["parent_commit_sha"]
        for vf in entry["vulnerable_files"]:
            path = vf["file"]
            key = (sha, path)
            if key in seen:
                continue
            seen.add(key)
            dest = out_dir / sha[:8] / path
            if _fetch_file(repo, path, sha, dest):
                fetched.append(dest)
    return fetched


def _fetch_file(repo: str, path: str, sha: str, dest: Path) -> bool:
    """Fetch one file's content at `sha` via `gh api`, write bytes to dest."""
    try:
        data = _gh_api(f"repos/{repo}/contents/{path}?ref={sha}")
    except RuntimeError as e:
        print(f"  SKIP {path}@{sha[:8]}: {e}")
        return False
    if data.get("encoding") != "base64":
        print(f"  SKIP {path}@{sha[:8]}: unexpected encoding "
              f"{data.get('encoding')}")
        return False
    content = base64.b64decode(data["content"])
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(content)
    return True


def normalize_alerts(results: list[dict], snapshot_dir: Path) -> list[dict]:
    """Strip run-specific noise; return alerts sorted for determinism.

    Sort key: (relative file path, start line, check_id) so re-running the
    scan on an unchanged snapshot always yields byte-identical output,
    regardless of the order Semgrep happened to emit results in.
    """
    alerts = []
    for r in results:
        rel_path = Path(r["path"])
        try:
            rel_path = rel_path.resolve().relative_to(snapshot_dir.resolve())
        except ValueError:
            pass
        alerts.append({
            "check_id": r["check_id"],
            "file": str(rel_path).replace("\\", "/"),
            "start_line": r["start"]["line"],
            "end_line": r["end"]["line"],
            "message": r["extra"]["message"].strip(),
            "severity": r["extra"]["severity"],
        })
    alerts.sort(key=lambda a: (a["file"], a["start_line"], a["check_id"]))
    return alerts


def run_semgrep(snapshot_dir: Path, out_json: Path,
                 semgrep_bin: str = SEMGREP_BIN) -> dict:
    """Run the pinned local ruleset against snapshot_dir; write
    deterministic JSON to out_json. Returns the parsed output dict."""
    snapshot_dir = snapshot_dir.resolve()
    result = subprocess.run(
        [semgrep_bin, "--config", str(RULES_PATH), "--json", "--quiet",
         "--no-git-ignore", str(snapshot_dir)],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode not in (0, 1):  # 1 = findings present, still ok
        raise RuntimeError(
            f"semgrep failed (rc={result.returncode}): "
            f"{result.stderr.strip()}"
        )

    raw = json.loads(result.stdout)
    alerts = normalize_alerts(raw.get("results", []), snapshot_dir)

    out = {
        "snapshot_dir": str(snapshot_dir.relative_to(ROOT)).replace("\\", "/"),
        "ruleset": str(RULES_PATH.relative_to(ROOT)).replace("\\", "/"),
        "total_alerts": len(alerts),
        "alerts": alerts,
    }
    out_json.parent.mkdir(parents=True, exist_ok=True)
    with open(out_json, "w") as f:
        json.dump(out, f, indent=2)
    return out


def main():
    parser = argparse.ArgumentParser(description="Semgrep scanner wrapper")
    parser.add_argument("--answer-key", type=Path, required=True)
    parser.add_argument("--snapshot-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--skip-fetch", action="store_true",
                         help="Reuse an existing snapshot dir; skip gh api")
    parser.add_argument("--semgrep-bin", type=str, default=SEMGREP_BIN)
    args = parser.parse_args()

    if not args.skip_fetch:
        print(f"Fetching vulnerable snapshot -> {args.snapshot_dir}")
        fetched = fetch_snapshot(args.answer_key, args.snapshot_dir)
        print(f"  {len(fetched)} file(s) fetched")

    print(f"Scanning {args.snapshot_dir} with {RULES_PATH.name}...")
    out = run_semgrep(args.snapshot_dir, args.out, args.semgrep_bin)
    print(f"  {out['total_alerts']} alert(s) -> {args.out}")


if __name__ == "__main__":
    main()
