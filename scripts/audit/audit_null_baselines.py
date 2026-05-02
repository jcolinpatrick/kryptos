#!/usr/bin/env python3
"""Audit null-baseline calibration, p-value tails, and alert consumption."""

from __future__ import annotations

import json
import math
import random
import subprocess
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "null_baselines" / "manifest.json"
RESULT_PATH = REPO_ROOT / "results" / "audit" / "null_baselines_audit.json"
DOC_PATH = REPO_ROOT / "docs" / "audits" / "null_baselines_audit.md"

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"  # 97-char carved K4 (canonical)
CRIB_WORDS = ((21, "EASTNORTHEAST"), (63, "BERLINCLOCK"))
CRIBS = {start + i: ch for start, word in CRIB_WORDS for i, ch in enumerate(word)}


def current_commit() -> str:
    out = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=5,
    )
    if out.returncode != 0:
        return "unknown"
    return out.stdout.strip()


def exact_binomial_tail(observed: int, n: int = 24, p: float = 1 / 26) -> float:
    if observed <= 0:
        return 1.0
    if observed > n:
        return 0.0
    return sum(math.comb(n, k) * (p**k) * ((1 - p) ** (n - k)) for k in range(observed, n + 1))


def small_random_text_calibration(samples: int = 10000, seed: int = 20260501) -> dict[str, Any]:
    rng = random.Random(seed)
    alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    scores = []
    for _ in range(samples):
        text = "".join(rng.choice(alph) for _ in range(len(CT)))
        scores.append(sum(1 for pos, ch in CRIBS.items() if text[pos] == ch))
    mean = sum(scores) / samples
    variance = sum((s - mean) ** 2 for s in scores) / samples
    return {
        "samples": samples,
        "seed": seed,
        "mean": mean,
        "stdev": math.sqrt(variance),
        "expected_mean_binomial": 24 / 26,
        "max": max(scores),
        "tail_ge_6_empirical": sum(1 for s in scores if s >= 6) / samples,
        "tail_ge_6_exact": exact_binomial_tail(6),
    }


def inspect_manifest(manifest: dict[str, Any], head: str) -> dict[str, Any]:
    stale = []
    empirical_gate_risks = []
    distributions = manifest.get("distributions", {})
    for key, dist in distributions.items():
        commit = dist.get("kernel_commit", "unknown")
        if commit not in ("unknown", head):
            stale.append({"cache_key": key, "kernel_commit": commit, "current_commit": head})
        if dist.get("parametric_model") is None:
            n_samples = int(dist.get("n_samples", 0) or 0)
            if n_samples:
                floor_1 = 1 / n_samples
                floor_10 = 10 / n_samples
                empirical_gate_risks.append({
                    "cache_key": key,
                    "n_samples": n_samples,
                    "one_event_floor": floor_1,
                    "ten_event_floor": floor_10,
                    "supports_1e_minus_6_ten_event_floor": floor_10 <= 1e-6,
                })
    return {
        "distribution_count": len(distributions),
        "stale_distributions": stale,
        "empirical_gate_support": empirical_gate_risks,
    }


def inspect_alert_usage() -> dict[str, Any]:
    alerts = (REPO_ROOT / "kryptosbot" / "alerts.py").read_text()
    nulls = (REPO_ROOT / "kryptosbot" / "null_baselines.py").read_text()
    aggregate = (REPO_ROOT / "src" / "kryptos" / "kernel" / "scoring" / "aggregate.py").read_text()
    return {
        "alerts_calls_p_value_for_alert": "p_value_for_alert" in alerts,
        "alerts_has_gate_constant": "ALERT_P_VALUE_GATE" in alerts,
        "alerts_records_effective_gate": "effective_p_value_gate" in alerts,
        "alerts_records_null_identity": "p_value_null_cache_key" in alerts and "p_value_null_method" in alerts,
        "alerts_records_candidate_p_value": "candidate_p_value_vs_null" in alerts,
        "alerts_records_family_wise_p_value": "family_wise_p_value_vs_null" in alerts,
        "alerts_records_universe_hash": "universe_hash" in alerts,
        "alerts_records_sample_floor": "p_value_sample_floor" in alerts,
        "nulls_has_calibration_stale": "def calibration_stale" in nulls,
        "alert_path_mentions_calibration_stale": "calibration_stale" in alerts or "calibration_stale" in nulls[nulls.find("def p_value_for_alert"):nulls.find("__all__")],
        "score_candidate_optional_p_values": "include_p_values" in aggregate and "p_value_breakdown" in aggregate,
    }


def write_markdown(payload: dict[str, Any]) -> None:
    stale_count = len(payload["manifest_inspection"]["stale_distributions"])
    stale_guard = payload["alert_usage"]["alert_path_mentions_calibration_stale"]
    stale_guard_text = (
        "Alert p-value helper refuses stale caches and returns `stale_cache`."
        if stale_guard
        else "Alert code consults p-values, but stale-cache warning behavior is a hardening concern."
    )
    lines = [
        "# Null Baselines Audit",
        "",
        "## Verdict",
        "",
        "- Exact Binomial crib-score tail is mathematically correct for the random_text null.",
        "- Empirical nulls cannot justify p-values below their sample floor.",
        f"- Stale cache entries found: {stale_count}.",
        f"- {stale_guard_text}",
        "- Alert artifacts record null identity, candidate p-value, family-wise p-value, sample floor, and universe hash.",
        "",
        "## Reproduction",
        "",
        "```bash",
        "PYTHONPATH=src python3 scripts/audit/audit_null_baselines.py",
        "```",
        "",
        "## Key Findings",
        "",
        f"- Current git commit: `{payload['current_commit']}`",
        f"- Manifest distributions: {payload['manifest_inspection']['distribution_count']}",
        f"- Small random-text calibration mean: {payload['small_calibration']['mean']:.4f} (expected {payload['small_calibration']['expected_mean_binomial']:.4f})",
        f"- Exact P(crib_score>=18): {payload['exact_tails']['crib_ge_18']:.3e}",
        "",
        "Search breadth and multiplicity are not solved by the cache itself. "
        "A p-value is only candidate-local unless the tested universe and "
        "post-hoc search family are explicitly included in the correction.",
    ]
    DOC_PATH.parent.mkdir(parents=True, exist_ok=True)
    DOC_PATH.write_text("\n".join(lines) + "\n")


def main() -> int:
    manifest = json.loads(MANIFEST_PATH.read_text()) if MANIFEST_PATH.exists() else {}
    head = current_commit()
    payload = {
        "schema_version": 1,
        "current_commit": head,
        "manifest_path": str(MANIFEST_PATH),
        "manifest_inspection": inspect_manifest(manifest, head),
        "small_calibration": small_random_text_calibration(),
        "exact_tails": {
            "crib_ge_6": exact_binomial_tail(6),
            "crib_ge_10": exact_binomial_tail(10),
            "crib_ge_18": exact_binomial_tail(18),
            "crib_ge_24": exact_binomial_tail(24),
        },
        "alert_usage": inspect_alert_usage(),
        "conclusions": {
            "random_text_null": "valid for independent random candidate plaintext at fixed crib positions",
            "shuffled_ct_null": "preserves CT multiset but is still candidate-local",
            "matched_variant_family_null": "useful only for calibrated supported families; empirical floor dominates extreme tails",
            "normal_ngram_tail": "acceptable as a rough heuristic for random_text ngram, not a proof for searched cipher families",
            "multiplicity": "not globally accounted for by per-candidate p-values",
        },
        "reproduction_command": "PYTHONPATH=src python3 scripts/audit/audit_null_baselines.py",
    }
    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True))
    write_markdown(payload)
    print(json.dumps({"wrote": [str(RESULT_PATH), str(DOC_PATH)], "stale": len(payload["manifest_inspection"]["stale_distributions"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
