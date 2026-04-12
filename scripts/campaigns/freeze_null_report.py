#!/usr/bin/env python3
"""
Freeze a campaign result into an immutable null report artifact.

PURPOSE
-------
The two-layer campaign writes its run output to a single overwritable file
(results/f_two_layer_stego_cipher_v1.json). That's fine for iteration, but
when a run produces a result worth citing — like the full-cartesian null
over the entire constrained two-layer hypothesis class — that result needs
to become a stable project artifact, not "just another run log."

This script reads the most recent campaign output, captures the exact
provenance of the run (git commit, working tree state, code hashes, kernel
constant hashes, generator counts, sampling mode, seed, worker count), and
writes a frozen, timestamped, commit-tagged report to:

    results/null_reports/two_layer_<mode>_<date>_<commit>.{json,md}

The frozen report is the audit-grade artifact. The original results file
keeps moving with the next run; the frozen report does not.

USAGE
-----
    PYTHONPATH=src python3 scripts/campaigns/freeze_null_report.py
    PYTHONPATH=src python3 scripts/campaigns/freeze_null_report.py --input results/f_two_layer_stego_cipher_v1.json
    PYTHONPATH=src python3 scripts/campaigns/freeze_null_report.py --note "Run after stratified sampling fix"

The script never modifies the source results. It only reads.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ── Repo discovery ────────────────────────────────────────────────────

def _find_repo_root(start: Path) -> Path:
    """Walk up from `start` to find the repo root (the dir containing .git)."""
    p = start.resolve()
    while p != p.parent:
        if (p / ".git").exists():
            return p
        p = p.parent
    raise RuntimeError(f"Could not find repo root from {start}")


REPO_ROOT = _find_repo_root(Path(__file__))
DEFAULT_INPUT = REPO_ROOT / "results" / "f_two_layer_stego_cipher_v1.json"
NULL_REPORTS_DIR = REPO_ROOT / "results" / "null_reports"


# ── Git provenance ────────────────────────────────────────────────────

def _git(*args: str) -> str:
    """Run a git command at the repo root and return stdout (or empty on fail)."""
    try:
        out = subprocess.run(
            ["git", *args],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return out.stdout.strip()
    except Exception:
        return ""


def capture_git_state() -> dict:
    """Capture the exact git state at freeze time."""
    return {
        "commit": _git("rev-parse", "HEAD"),
        "commit_short": _git("rev-parse", "--short", "HEAD"),
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "commit_subject": _git("log", "-1", "--pretty=%s"),
        "commit_date": _git("log", "-1", "--pretty=%cI"),
        "working_tree_clean": _git("status", "--porcelain") == "",
        "dirty_files": _git("status", "--porcelain").split("\n") if _git("status", "--porcelain") else [],
        "tracked_files_in_campaign": _git("ls-files", "src/kryptos/campaigns/", "scripts/campaigns/f_two_layer_stego_cipher_v1.py").split("\n"),
    }


# ── Code hashing ──────────────────────────────────────────────────────

def _sha256_file(path: Path) -> str:
    """SHA-256 of a file's bytes; empty string if missing."""
    if not path.exists():
        return ""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def capture_code_hashes() -> dict:
    """SHA-256 hashes of every file involved in producing the result.

    Includes both the standalone campaign script and the campaign module.
    A change to any of these between this freeze and a future re-run would
    invalidate replay reproducibility, so the hashes are part of the artifact.
    """
    files_to_hash = [
        "scripts/campaigns/f_two_layer_stego_cipher_v1.py",
        "src/kryptos/campaigns/__init__.py",
        "src/kryptos/campaigns/two_layer/__init__.py",
        "src/kryptos/campaigns/two_layer/families.py",
        "src/kryptos/campaigns/two_layer/outer_layers.py",
        "src/kryptos/campaigns/two_layer/inner_layers.py",
        "src/kryptos/campaigns/two_layer/evaluation.py",
        "src/kryptos/campaigns/two_layer/multiplicity.py",
        "src/kryptos/campaigns/two_layer/provenance.py",
        "src/kryptos/campaigns/two_layer/sampling.py",
        "src/kryptos/campaigns/two_layer/coverage.py",
        "src/kryptos/campaigns/two_layer/parallel.py",
        "src/kryptos/campaigns/two_layer/checkpoint.py",
    ]
    result = {}
    for rel in files_to_hash:
        p = REPO_ROOT / rel
        result[rel] = _sha256_file(p)
    return result


def capture_kernel_constants_hash() -> dict:
    """Hash the canonical input data so we can detect transcription drift.

    If CT or cribs change between this freeze and a future replay, the
    null no longer applies to the same input. Capturing the hash makes
    that detectable.
    """
    try:
        sys.path.insert(0, str(REPO_ROOT / "src"))
        from kryptos.kernel.constants import (
            CT, CT_LEN, CRIB_DICT, BEAN_EQ, BEAN_INEQ, BEAN_LINEAR,
        )
        ct_hash = hashlib.sha256(CT.encode()).hexdigest()
        crib_str = "|".join(f"{k}:{v}" for k, v in sorted(CRIB_DICT.items()))
        crib_hash = hashlib.sha256(crib_str.encode()).hexdigest()
        bean_eq_str = "|".join(f"{a},{b}" for a, b in sorted(BEAN_EQ))
        bean_eq_hash = hashlib.sha256(bean_eq_str.encode()).hexdigest()
        bean_ineq_str = "|".join(f"{a},{b}" for a, b in sorted(BEAN_INEQ))
        bean_ineq_hash = hashlib.sha256(bean_ineq_str.encode()).hexdigest()
        bean_linear_str = "|".join(",".join(map(str, t)) for t in sorted(BEAN_LINEAR))
        bean_linear_hash = hashlib.sha256(bean_linear_str.encode()).hexdigest()
        return {
            "ct_length": CT_LEN,
            "ct_sha256": ct_hash,
            "crib_count": len(CRIB_DICT),
            "crib_dict_sha256": crib_hash,
            "bean_eq_count": len(BEAN_EQ),
            "bean_eq_sha256": bean_eq_hash,
            "bean_ineq_count": len(BEAN_INEQ),
            "bean_ineq_sha256": bean_ineq_hash,
            "bean_linear_count": len(BEAN_LINEAR),
            "bean_linear_sha256": bean_linear_hash,
        }
    except Exception as exc:
        return {"error": f"Could not import kernel constants: {exc}"}


# ── Canonical claim wording ───────────────────────────────────────────

def render_canonical_claim(run: dict) -> str:
    """Render the canonical, citation-grade wording for the result.

    The wording is mode-specific. A FULL-CARTESIAN null gets the strongest
    language; an EXPLORATORY result gets explicitly weak language. The text
    here is the version that should be quoted in any future writeup,
    paper, or external claim. Do not change it casually.
    """
    mode = run.get("sampling_mode", "unknown")
    n = run.get("total_profiles_tested", 0)
    n_outer = run.get("outer_families_count", 0)
    n_inner = run.get("inner_families_count", 0)
    cov = run.get("coverage_report", {})
    successes = run.get("joint_anomaly_successes", [])

    if successes:
        return (
            f"NOT A NULL — the run produced {len(successes)} candidate(s) "
            f"meeting the joint anomaly success criterion. This freeze does "
            f"not apply; the result requires investigation, not preservation."
        )

    if mode == "full_cartesian" and run.get("plan_is_complete_for_mode"):
        return (
            f"FULL-CARTESIAN NULL. The complete constrained two-layer "
            f"hypothesis class — every one of {n_outer} outer parameterized "
            f"instances composed with every one of {n_inner} inner "
            f"parameterized instances, totalling {n:,} (outer × inner) profiles "
            f"— was enumerated under blind evaluation. Zero candidates met the "
            f"joint anomaly success criterion (crib_score >= 18, Bean compatible "
            f"or H1 legitimately disabled, width-21 z >= 3 with no cherry-pick, "
            f"Stehle local pattern present, weak identity preservation >= 0.4, "
            f"English likeness above noise floor, zero overfit flags). Within "
            f"the constrained low-complexity two-layer hypothesis space the "
            f"campaign expresses, the architecture has produced no positive "
            f"signal. This is the strongest negative result the project has "
            f"published for this hypothesis class."
        )

    if mode == "stratified_family_cover" and run.get("plan_is_complete_for_mode"):
        n_outers_in_run = cov.get("distinct_outer_instances", n_outer)
        return (
            f"FAMILY-COVER NULL. Every one of {n_outers_in_run} eligible outer "
            f"parameterized instances was paired with at least one representative "
            f"from every inner family class ({n:,} total evaluations under blind "
            f"evaluation). Zero candidates met the joint anomaly success criterion. "
            f"Every constrained outer instance × every inner family class has "
            f"been tested under the project's strict joint-success bar with no "
            f"positive signal."
        )

    if mode == "stratified_low_complexity_bias":
        low = cov.get("low_complexity_eval_count", 0)
        return (
            f"LOW-COMPLEXITY-EMPHASIZED NULL. {n:,} profiles evaluated under "
            f"blind evaluation, with {low:,} of them in the low-complexity "
            f"band (oversampled relative to medium and high). The simplest, "
            f"most epistemically informative end of the constrained two-layer "
            f"search space was probed deeply with no joint anomaly success."
        )

    if mode == "exploratory_stride":
        return (
            f"EXPLORATORY null over {n:,} stride-sampled profiles. Coverage is "
            f"approximate; this is NOT a definitive negative result for the "
            f"two-layer hypothesis class. Use only as a first-look indicator."
        )

    return (
        f"PARTIAL null over {n:,} profiles in mode {mode}. Coverage shape "
        f"did not meet a strong-claim invariant; treat as exploratory."
    )


# ── Naming ────────────────────────────────────────────────────────────

def build_artifact_name(run: dict, git_state: dict, freeze_time: datetime) -> str:
    """Build a stable, descriptive filename for the frozen artifact.

    Format: two_layer_<mode>_<YYYYMMDD>_<short_commit>[_dirty]
    """
    mode = run.get("sampling_mode", "unknown")
    date = freeze_time.strftime("%Y%m%d")
    commit = git_state.get("commit_short", "nocommit") or "nocommit"
    dirty_suffix = "" if git_state.get("working_tree_clean") else "_dirty"
    return f"two_layer_{mode}_{date}_{commit}{dirty_suffix}"


# ── Markdown report ───────────────────────────────────────────────────

def render_markdown(frozen: dict) -> str:
    """Render the frozen artifact as a human-readable markdown report."""
    lines = []
    lines.append(f"# {frozen['artifact_name']}")
    lines.append("")
    lines.append("**FROZEN NULL REPORT — IMMUTABLE PROJECT ARTIFACT**")
    lines.append("")
    lines.append(f"- Frozen at: {frozen['frozen_at']}")
    lines.append(f"- Frozen by: {frozen['frozen_by']}")
    if frozen.get("note"):
        lines.append(f"- Note: {frozen['note']}")
    lines.append("")
    lines.append("## Canonical Claim")
    lines.append("")
    lines.append("> " + frozen["canonical_claim"].replace("\n", "\n> "))
    lines.append("")
    lines.append("## Run Provenance")
    lines.append("")
    run = frozen["run"]
    lines.append(f"- Campaign: `{run.get('campaign', 'unknown')}`")
    lines.append(f"- Sampling mode: `{run.get('sampling_mode', 'unknown')}`")
    lines.append(f"- Sampling seed: `{run.get('sampling_seed', 0)}`")
    lines.append(f"- Target evaluations: `{run.get('target_evals', '-')}`")
    lines.append(f"- Pairs evaluated: `{run.get('total_profiles_tested', 0):,}`")
    lines.append(f"- Plan complete for mode: `{run.get('plan_is_complete_for_mode', False)}`")
    lines.append(f"- Workers: `{run.get('workers', '-')}`")
    lines.append(f"- Started: `{run.get('started_at', '-')}`")
    lines.append(f"- Completed: `{run.get('completed_at', '-')}`")
    lines.append("")
    lines.append("## Generator Counts")
    lines.append("")
    lines.append(f"- Outer parameterized instances: `{run.get('outer_families_count', 0)}`")
    lines.append(f"- Inner parameterized instances: `{run.get('inner_families_count', 0)}`")
    cartesian = run.get('outer_families_count', 0) * run.get('inner_families_count', 0)
    lines.append(f"- Full cartesian: `{cartesian:,}`")
    lines.append("")
    lines.append("## Coverage Report")
    lines.append("")
    cov = run.get("coverage_report", {})
    if cov:
        lines.append(f"- Distinct outer instances touched: `{cov.get('distinct_outer_instances', 0)}/{cov.get('total_outer_instances', 0)}`")
        lines.append(f"- Distinct inner instances touched: `{cov.get('distinct_inner_instances', 0)}/{cov.get('total_inner_instances', 0)}`")
        lines.append(f"- Cross-pair coverage: `{cov.get('cross_pair_coverage_count', 0)}/{cov.get('cross_pair_coverage_total', 0)}`")
        lines.append(f"- Outers seeing all inner families: `{cov.get('outers_seeing_all_inner_families', 0)}`")
        lines.append(f"- Median inner families per outer: `{cov.get('median_inner_families_per_outer', 0)}`")
        lines.append(f"- Low complexity evals: `{cov.get('low_complexity_eval_count', 0)}`")
        lines.append(f"- Medium complexity evals: `{cov.get('medium_complexity_eval_count', 0)}`")
        lines.append(f"- High complexity evals: `{cov.get('high_complexity_eval_count', 0)}`")
        lines.append(f"- Qualifies as family-cover-complete: `{cov.get('qualifies_as_family_cover_complete', False)}`")
        lines.append(f"- Qualifies as low-complexity-emphasized: `{cov.get('qualifies_as_low_complexity_emphasized', False)}`")
        lines.append(f"- Qualifies as full-cartesian-complete: `{cov.get('qualifies_as_full_cartesian_complete', False)}`")
    lines.append("")
    lines.append("## Joint Anomaly Successes")
    lines.append("")
    successes = run.get("joint_anomaly_successes", [])
    if successes:
        lines.append(f"**{len(successes)} candidate(s) met the joint success criterion.**")
        lines.append("")
        lines.append("This freeze should not be cited as a null result. Investigate each candidate.")
    else:
        lines.append("**Zero candidates** met the joint anomaly success criterion.")
    lines.append("")
    lines.append("## Git Provenance")
    lines.append("")
    git_state = frozen["git"]
    lines.append(f"- Commit: `{git_state.get('commit', 'unknown')}`")
    lines.append(f"- Branch: `{git_state.get('branch', 'unknown')}`")
    lines.append(f"- Subject: {git_state.get('commit_subject', '')}")
    lines.append(f"- Commit date: `{git_state.get('commit_date', '')}`")
    lines.append(f"- Working tree clean: `{git_state.get('working_tree_clean', False)}`")
    if not git_state.get("working_tree_clean"):
        lines.append(f"- Dirty files: `{len(git_state.get('dirty_files', []))}`")
        lines.append("  ```")
        for df in git_state.get("dirty_files", [])[:30]:
            lines.append(f"  {df}")
        lines.append("  ```")
    lines.append("")
    lines.append("## Kernel Constants")
    lines.append("")
    kc = frozen["kernel_constants"]
    if "error" in kc:
        lines.append(f"- ERROR: {kc['error']}")
    else:
        lines.append(f"- CT length: `{kc.get('ct_length', 0)}`")
        lines.append(f"- CT SHA-256: `{kc.get('ct_sha256', '')}`")
        lines.append(f"- Crib count: `{kc.get('crib_count', 0)}`")
        lines.append(f"- Crib dict SHA-256: `{kc.get('crib_dict_sha256', '')}`")
        lines.append(f"- Bean equality SHA-256: `{kc.get('bean_eq_sha256', '')}`")
        lines.append(f"- Bean inequality count: `{kc.get('bean_ineq_count', 0)}`")
        lines.append(f"- Bean inequality SHA-256: `{kc.get('bean_ineq_sha256', '')}`")
        lines.append(f"- Bean linear constraint count: `{kc.get('bean_linear_count', 0)}`")
        lines.append(f"- Bean linear SHA-256: `{kc.get('bean_linear_sha256', '')}`")
    lines.append("")
    lines.append("## Code SHA-256 Hashes")
    lines.append("")
    lines.append("These hashes pin the exact code that produced the result. A future")
    lines.append("re-run with different hashes is not a replay; it is a new run.")
    lines.append("")
    lines.append("```")
    for f, h in frozen["code_hashes"].items():
        lines.append(f"{h[:16]}  {f}")
    lines.append("```")
    lines.append("")
    lines.append("## Replay Instructions")
    lines.append("")
    lines.append("To attempt to reproduce this exact result:")
    lines.append("")
    lines.append("```bash")
    lines.append(f"git checkout {git_state.get('commit', 'HEAD')}")
    lines.append("PYTHONPATH=src python3 scripts/campaigns/f_two_layer_stego_cipher_v1.py \\")
    lines.append(f"    --sampling-mode {run.get('sampling_mode', 'unknown')} \\")
    lines.append(f"    --seed {run.get('sampling_seed', 0)} \\")
    lines.append(f"    --target-evals {run.get('target_evals', 2000)} \\")
    lines.append(f"    --workers {run.get('workers', 0)}")
    lines.append("```")
    lines.append("")
    lines.append("If kernel constants or code hashes have changed, the replay is")
    lines.append("not the same experiment.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("*This file is a frozen project artifact. Do not edit.*")
    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Freeze a campaign result into an immutable null report."
    )
    parser.add_argument(
        "--input", type=Path, default=DEFAULT_INPUT,
        help="Path to the campaign results JSON to freeze.",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=NULL_REPORTS_DIR,
        help="Directory to write the frozen artifact into.",
    )
    parser.add_argument(
        "--note", type=str, default="",
        help="Optional human-readable note to attach to the frozen artifact.",
    )
    args = parser.parse_args()

    if not args.input.exists():
        print(f"ERROR: input results file not found: {args.input}", file=sys.stderr)
        return 1

    print(f"[freeze] reading {args.input}")
    run = json.loads(args.input.read_text())

    print(f"[freeze] capturing git state")
    git_state = capture_git_state()

    print(f"[freeze] hashing campaign code ({len(capture_code_hashes())} files)")
    code_hashes = capture_code_hashes()

    print(f"[freeze] hashing kernel constants")
    kernel_constants = capture_kernel_constants_hash()

    print(f"[freeze] rendering canonical claim")
    canonical_claim = render_canonical_claim(run)

    freeze_time = datetime.now(timezone.utc)
    artifact_name = build_artifact_name(run, git_state, freeze_time)

    frozen = {
        "schema": "frozen_null_report.v1",
        "artifact_name": artifact_name,
        "frozen_at": freeze_time.isoformat(),
        "frozen_by": os.environ.get("USER", "unknown"),
        "note": args.note,
        "canonical_claim": canonical_claim,
        "run": run,
        "git": git_state,
        "kernel_constants": kernel_constants,
        "code_hashes": code_hashes,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)

    json_path = args.output_dir / f"{artifact_name}.json"
    md_path = args.output_dir / f"{artifact_name}.md"

    if json_path.exists():
        # Frozen artifacts are immutable. Refuse to overwrite.
        print(f"ERROR: frozen artifact already exists: {json_path}", file=sys.stderr)
        print(f"       Frozen artifacts are immutable. To force a re-freeze,", file=sys.stderr)
        print(f"       delete the existing file or use a different commit.", file=sys.stderr)
        return 2

    json_path.write_text(json.dumps(frozen, indent=2))
    md_path.write_text(render_markdown(frozen))

    print()
    print("=" * 70)
    print(f"FROZEN: {artifact_name}")
    print("=" * 70)
    print(f"  JSON: {json_path}")
    print(f"  MD:   {md_path}")
    print()
    print("Canonical claim:")
    print()
    # Wrap claim text for terminal
    claim = canonical_claim
    width = 70
    while claim:
        print(f"  {claim[:width]}")
        claim = claim[width:]
    print()
    if not git_state.get("working_tree_clean"):
        print("WARNING: working tree was DIRTY at freeze time.")
        print("         The artifact name carries a _dirty suffix.")
        print("         For a clean replay, re-run on a clean commit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
