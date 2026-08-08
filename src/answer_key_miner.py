"""Answer-key miner: git archaeology via GitHub API.

Given a seeds file listing CVEs and fix commits, fetches diffs from
GitHub and produces a structured answer-key JSON recording:
  - the pre-fix (vulnerable) file paths
  - vulnerability type (CWE category)
  - fix commit + parent commit SHAs

Usage:
  python src/answer_key_miner.py --seeds data/answer_key/django_seeds.json \
                                 --output data/answer_key/django.json \
                                 --repo django/django

  python src/answer_key_miner.py --verify data/answer_key/django.json
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path


def gh_api(endpoint: str) -> dict:
    """Call GitHub API via `gh api`. Returns parsed JSON."""
    result = subprocess.run(
        ["gh", "api", endpoint],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"gh api failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def extract_vuln_files(commit_data: dict) -> list[dict]:
    """Extract source-code files changed by a fix commit (skip docs/tests)."""
    spots = []
    for f in commit_data.get("files", []):
        name = f["filename"]
        # Skip docs, release notes, test files, and non-source files
        if (name.startswith("docs/") or name.startswith("tests/")
                or name.endswith(".txt") or name.endswith(".rst")):
            continue
        spots.append({
            "file": name,
            "additions": f.get("additions", 0),
            "deletions": f.get("deletions", 0),
        })
    return spots


def mine_single(seed: dict, repo: str) -> dict:
    """Mine a single CVE entry from its seed data."""
    fix_sha = seed["fix_commit_sha"]

    # Fetch commit details from GitHub API
    commit_data = gh_api(f"repos/{repo}/commits/{fix_sha}")

    # Get parent (the vulnerable snapshot)
    parents = commit_data.get("parents", [])
    parent_sha = parents[0]["sha"] if parents else None

    # Extract vulnerable source files
    vuln_files = extract_vuln_files(commit_data)

    return {
        "cve_id": seed["cve_id"],
        "description": seed["description"],
        "vuln_type": seed["vuln_type"],
        "cwe_id": seed["cwe_id"],
        "severity": seed.get("severity", "moderate"),
        "fix_commit_sha": fix_sha,
        "parent_commit_sha": parent_sha,
        "repo": repo,
        "vulnerable_files": vuln_files,
        "primary_source": seed.get("primary_source", ""),
    }


def mine_all(seeds_path: Path, output_path: Path, repo: str) -> None:
    """Mine all CVE entries from a seeds file."""
    with open(seeds_path) as f:
        seeds = json.load(f)

    entries = []
    for i, seed in enumerate(seeds):
        print(f'  [{i+1}/{len(seeds)}] Mining {seed["cve_id"]}...', end=" ")
        try:
            entry = mine_single(seed, repo)
            entries.append(entry)
            n = len(entry["vulnerable_files"])
            print(f"{n} vulnerable file(s)")
        except Exception as e:
            print(f"FAILED: {e}")

    answer_key = {
        "project": repo.split("/")[-1],
        "repo": repo,
        "total_spots": sum(len(e["vulnerable_files"]) for e in entries),
        "total_cves": len(entries),
        "entries": entries,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(answer_key, f, indent=2)

    print(f'\nWrote {answer_key["total_cves"]} CVEs, '
          f'{answer_key["total_spots"]} vulnerable spots '
          f'to {output_path}')


def verify(answer_key_path: Path) -> bool:
    """Verify an answer key meets quality gates."""
    with open(answer_key_path) as f:
        ak = json.load(f)

    issues = []
    if ak["total_spots"] < 10:
        issues.append(f'Need >=10 spots, got {ak["total_spots"]}')
    if ak["total_cves"] < 5:
        issues.append(f'Need >=5 CVEs, got {ak["total_cves"]}')

    # Check vuln type diversity
    types = {e["cwe_id"] for e in ak["entries"]}
    if len(types) < 3:
        issues.append(f"Need >=3 CWE types, got {len(types)}")

    # Check each entry has required fields
    required = ["cve_id", "fix_commit_sha", "parent_commit_sha",
                "vulnerable_files", "vuln_type", "cwe_id"]
    for e in ak["entries"]:
        for field in required:
            if not e.get(field):
                issues.append(f'{e.get("cve_id", "?")}: missing {field}')

    if issues:
        print("VERIFY FAILED:")
        for issue in issues:
            print(f"  - {issue}")
        return False

    print(f'VERIFY OK: {ak["total_cves"]} CVEs, {ak["total_spots"]} spots, '
          f"{len(types)} CWE types")
    return True


def main():
    parser = argparse.ArgumentParser(description="Answer-key miner")
    parser.add_argument("--seeds", type=Path, help="Path to seeds JSON")
    parser.add_argument("--output", type=Path, help="Path for output JSON")
    parser.add_argument("--repo", type=str, help="GitHub repo (owner/name)")
    parser.add_argument("--verify", type=Path, help="Verify an answer key")
    args = parser.parse_args()

    if args.verify:
        ok = verify(args.verify)
        sys.exit(0 if ok else 1)
    elif args.seeds and args.output and args.repo:
        mine_all(args.seeds, args.output, args.repo)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
