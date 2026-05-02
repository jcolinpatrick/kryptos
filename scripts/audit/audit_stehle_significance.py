#!/usr/bin/env python3
"""Independent audit of the Stehle delta-5 lag-4 anomaly."""

from __future__ import annotations

import argparse
import json
import math
import random
from collections import Counter
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
RESULT_PATH = REPO_ROOT / "results" / "audit" / "stehle_significance_audit.json"
DOC_PATH = REPO_ROOT / "docs" / "audits" / "stehle_significance_audit.md"

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"  # 97-char carved K4 (canonical)
ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
IDX = {ch: i for i, ch in enumerate(ALPH)}


def delta(a: str, b: str) -> int:
    return (IDX[b] - IDX[a]) % 26


def lag_deltas(text: str, start: int, lag: int, pairs: int) -> list[int]:
    return [delta(text[start + i], text[start + i + lag]) for i in range(pairs)]


def max_equal_delta_run(text: str, max_lag: int) -> dict[str, Any]:
    best = {"run": 0, "start": None, "lag": None, "delta": None}
    n = len(text)
    for lag in range(1, max_lag + 1):
        diffs = [delta(text[i], text[i + lag]) for i in range(n - lag)]
        cur_run = 1
        cur_start = 0
        for i in range(1, len(diffs)):
            if diffs[i] == diffs[i - 1]:
                cur_run += 1
            else:
                cur_run = 1
                cur_start = i
            if cur_run > best["run"]:
                best = {
                    "run": cur_run,
                    "start": cur_start,
                    "lag": lag,
                    "delta": diffs[i],
                }
    return best


def any_constant_five_pair_hit(text: str, lags: range) -> bool:
    n = len(text)
    for lag in lags:
        max_start = n - lag - 5
        for start in range(max_start + 1):
            ds = lag_deltas(text, start, lag, 5)
            if len(set(ds)) == 1:
                return True
    return False


def permutation_mc(samples: int, seed: int, max_lag: int) -> dict[str, Any]:
    rng = random.Random(seed)
    chars = list(CT)
    observed_best = max_equal_delta_run(CT, max_lag)
    fixed_hits = 0
    lag4_hits = 0
    lag1_8_hits = 0
    broad_hits = 0
    max_run_hist: Counter[int] = Counter()
    for _ in range(samples):
        shuffled = chars[:]
        rng.shuffle(shuffled)
        text = "".join(shuffled)
        if len(set(lag_deltas(text, 55, 4, 5))) == 1:
            fixed_hits += 1
        if any_constant_five_pair_hit(text, range(4, 5)):
            lag4_hits += 1
        if any_constant_five_pair_hit(text, range(1, 9)):
            lag1_8_hits += 1
        best = max_equal_delta_run(text, max_lag)
        max_run_hist[int(best["run"])] += 1
        if int(best["run"]) >= int(observed_best["run"]):
            broad_hits += 1
    return {
        "samples": samples,
        "seed": seed,
        "max_lag": max_lag,
        "observed_best": observed_best,
        "fixed_start_lag4_any_delta_p": (fixed_hits + 1) / (samples + 1),
        "any_start_lag4_any_delta_p": (lag4_hits + 1) / (samples + 1),
        "any_start_lag1_to_8_any_delta_p": (lag1_8_hits + 1) / (samples + 1),
        "broad_max_run_ge_observed_p": (broad_hits + 1) / (samples + 1),
        "max_run_histogram": dict(sorted(max_run_hist.items())),
    }


def write_markdown(payload: dict[str, Any]) -> None:
    conclusion = payload["conclusion"]
    lines = [
        "# Stehle Significance Audit",
        "",
        "## Verdict",
        "",
        f"- Existence: {conclusion['existence']}.",
        f"- Bean p~1/642: {conclusion['p_value_reproduction']}.",
        f"- Cryptographic role: {conclusion['cryptographic_role']}.",
        f"- Recommended use: {conclusion['recommended_use']}.",
        "",
        "## Observed Pattern",
        "",
        f"- 0-indexed positions: {payload['observed']['zero_indexed_positions']}",
        f"- 1-indexed positions: {payload['observed']['one_indexed_positions']}",
        f"- Substring: `{payload['observed']['substring']}`",
        f"- Lag-4 deltas: {payload['observed']['lag4_deltas']}",
        "",
        "## Statistics",
        "",
        f"- Fixed start, lag, and specified delta=5: {payload['iid_uniform']['fixed_start_lag4_delta5_probability']:.6g}",
        f"- Fixed start and lag, any constant delta: {payload['iid_uniform']['fixed_start_lag4_any_delta_probability']:.6g}",
        f"- Bonferroni factor 712 applied to any-delta raw probability: {payload['iid_uniform']['bonferroni_712_any_delta_probability']:.6g}",
        "",
        "The p~1/642 figure is reproduced only as a Bonferroni calculation "
        "using raw probability 1/26^4 and a 712-test family. That is a "
        "post-hoc descriptive significance calculation, not a cipher predicate.",
        "",
        "## Reproduction",
        "",
        "```bash",
        "PYTHONPATH=src python3 scripts/audit/audit_stehle_significance.py",
        "```",
    ]
    DOC_PATH.parent.mkdir(parents=True, exist_ok=True)
    DOC_PATH.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=20000)
    parser.add_argument("--seed", type=int, default=20260501)
    parser.add_argument("--max-lag", type=int, default=20)
    args = parser.parse_args()

    start = 55
    lag = 4
    pairs = 5
    substring = CT[start : start + lag + pairs]
    observed_deltas = lag_deltas(CT, start, lag, pairs)
    exact_any_delta = 1.0 / (26 ** (pairs - 1))
    exact_delta5 = 1.0 / (26 ** pairs)
    bonf_712 = min(1.0, 712 * exact_any_delta)
    observed_best = max_equal_delta_run(CT, args.max_lag)
    mc = permutation_mc(args.samples, args.seed, args.max_lag)

    payload = {
        "schema_version": 1,
        "claim": "Stehle delta-5 lag-4 local regularity",
        "classification": (
            "PROJECT_REVERIFIED_STATISTICAL_ANOMALY for existence and the limited "
            "712-test Bonferroni p-value; cryptographic role remains unproven"
        ),
        "observed": {
            "zero_indexed_positions": [start, start + lag + pairs - 1],
            "one_indexed_positions": [start + 1, start + lag + pairs],
            "substring": substring,
            "lag": lag,
            "lag4_pairs_zero_indexed": [[start + i, start + i + lag] for i in range(pairs)],
            "lag4_deltas": observed_deltas,
            "all_five_equal_5": observed_deltas == [5, 5, 5, 5, 5],
            "broad_scan_observed_best": observed_best,
        },
        "iid_uniform": {
            "null": "iid uniform letters A-Z",
            "fixed_start_lag4_delta5_probability": exact_delta5,
            "fixed_start_lag4_any_delta_probability": exact_any_delta,
            "bonferroni_712_any_delta_probability": bonf_712,
            "bonferroni_712_as_inverse": 1.0 / bonf_712 if bonf_712 else None,
            "note": "p~1/642 is reproduced by 712 * 1/26^4, not by specified delta=5 (1/26^5).",
        },
        "permutation_null": mc,
        "exploitability": {
            "additive_relations": {
                "vigenere": "C[i+4]-C[i]=5 implies (P[i+4]-P[i]) + (K[i+4]-K[i]) = 5 mod 26.",
                "beaufort": "C[i+4]-C[i]=5 implies (K[i+4]-K[i]) - (P[i+4]-P[i]) = 5 mod 26.",
                "variant_beaufort": "C[i+4]-C[i]=5 implies (P[i+4]-P[i]) - (K[i+4]-K[i]) = 5 mod 26.",
            },
            "crib_overlap": "Only position 63 overlaps a known crib; this is insufficient to constrain the other local plaintext or keystream values.",
            "hard_constraint_status": "not justified",
            "ranking_feature_status": "weak prompt context or soft ranking only",
        },
        "conclusion": {
            "existence": "verified",
            "p_value_reproduction": (
                "reproduced under the 712-test Bonferroni family; not reproduced "
                "as a pre-registered cryptanalytic test"
            ),
            "cryptographic_role": "not proven",
            "recommended_use": "local anomaly with no current exploit; not a hard constraint",
        },
        "reproduction_command": "PYTHONPATH=src python3 scripts/audit/audit_stehle_significance.py",
    }
    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True))
    write_markdown(payload)
    print(json.dumps({"wrote": [str(RESULT_PATH), str(DOC_PATH)], "all_five_equal_5": observed_deltas == [5] * 5}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
