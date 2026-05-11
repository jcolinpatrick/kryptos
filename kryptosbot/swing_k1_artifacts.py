"""Swing K-1 artifact emitters and verdict.md writer."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

MANIFEST_SCHEMA_VERSION = "swing_k1.manifest.v1"


def write_manifest(
    out_path: Path,
    universe_hash: str,
    kernel_commit: str,
    prereg_thresholds: Dict[str, Any],
    mask_catalog_path: str,
    corpus_manifest_path: str,
    total_config_count: int,
) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "universe_hash": universe_hash,
        "kernel_commit": kernel_commit,
        "prereg_thresholds": prereg_thresholds,
        "mask_catalog_path": mask_catalog_path,
        "corpus_manifest_path": corpus_manifest_path,
        "total_config_count": total_config_count,
        "non_claim_banner": (
            "This artifact records a hypothesis-testing campaign. "
            "No K4 plaintext or solve is claimed. A null verdict "
            "is the most likely outcome by base rate. "
            "K4 is NOT proven impossible by this artifact."
        ),
    }
    out_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def read_manifest(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def append_config_row(out_path: Path, row: Dict[str, Any]) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, sort_keys=True))
        f.write("\n")


def write_verdict_md(
    out_path: Path,
    classification: str,
    universe_hash: str,
    total_configs: int,
    admitted_count: int,
    promotions_count: int,
    tier_b_hits_count: int,
) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    body = f"""# Swing K-1 Verdict

**Classification:** {classification}

**Universe hash:** `{universe_hash}`

**Counts:**
- Total configs evaluated: {total_configs}
- Bean-admitted: {admitted_count}
- Promotion-eligible: {promotions_count}
- Tier B exploratory hits: {tier_b_hits_count}

**Non-claim banner:** This verdict records the outcome of a
hypothesis-testing campaign over a preregistered, hashed universe.
No K4 plaintext or solve is claimed. K4 is NOT proven impossible by
this verdict; a null result rejects the specific universe at the
preregistered threshold and nothing more.
"""
    out_path.write_text(body, encoding="utf-8")


def split_artifacts(run_dir: Path) -> Dict[str, int]:
    """Read configs.jsonl and emit filtered views: admitted, promotions, tier_b hits.

    Spec section 8.1 defines admitted_keystreams.jsonl, promotions.jsonl, tier_b_hits.jsonl
    as separate emitted files. They are derivable from configs.jsonl, so this helper
    runs after the main sweep completes.
    """
    cfg_path = run_dir / "configs.jsonl"
    admitted_path = run_dir / "admitted_keystreams.jsonl"
    promotions_path = run_dir / "promotions.jsonl"
    tier_b_path = run_dir / "tier_b_hits.jsonl"
    counts = {"admitted": 0, "promotions": 0, "tier_b_hits": 0}
    # Truncate split files.
    for p in (admitted_path, promotions_path, tier_b_path):
        if p.exists():
            p.unlink()
    if not cfg_path.exists():
        return counts
    with open(cfg_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("bean_passed"):
                append_config_row(admitted_path, row)
                counts["admitted"] += 1
            if row.get("promote_eligible"):
                append_config_row(promotions_path, row)
                counts["promotions"] += 1
            if row.get("s1_tier_b_match"):
                append_config_row(tier_b_path, row)
                counts["tier_b_hits"] += 1
    return counts


def write_null_calibration(
    out_path: Path,
    method: str,
    n_trials: int,
    sampled_config_count: int,
    baseline_max_joint_event_count: int,
    candidate_p_values: Dict[str, float],
) -> None:
    """Emit null_calibration.json. Spec section 7.3.

    method: "empirical_shuffled_ct" (baseline) or "analytical_binomial" / "monte_carlo_1m" (escalation).
    candidate_p_values: per-spec-hash p-value for any promotion-eligible candidate (empty when none).
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "swing_k1.null_calibration.v1",
        "method": method,
        "n_trials": n_trials,
        "sampled_config_count": sampled_config_count,
        "baseline_max_joint_event_count": baseline_max_joint_event_count,
        "candidate_p_values": candidate_p_values,
    }
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
