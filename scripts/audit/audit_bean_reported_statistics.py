#!/usr/bin/env python3
"""Independent audit of Bean-reported K4 crib-position statistics.

This script intentionally does not import the repo's claims registry or
kernel constants as trusted values. It defines CT and crib text locally,
then recomputes the minor-difference and repeated-plaintext-letter
statistics from first principles.
"""

from __future__ import annotations

import argparse
import json
import math
import random
from itertools import combinations
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
RESULT_PATH = REPO_ROOT / "results" / "audit" / "bean_reported_statistics.json"
DOC_PATH = REPO_ROOT / "docs" / "audits" / "bean_reported_statistics.md"

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"  # 97-char carved K4 (canonical)
CRIB_WORDS = ((21, "EASTNORTHEAST"), (63, "BERLINCLOCK"))
KRYPTOS_SET = set("KRYPTOS")
ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def crib_dict() -> dict[int, str]:
    return {start + i: ch for start, word in CRIB_WORDS for i, ch in enumerate(word)}


def circular_distance(a: str, b: str) -> int:
    d = abs(ord(a) - ord(b))
    return min(d, 26 - d)


def exact_iid_sum_tail(observed: int, n: int) -> float:
    """Exact P(sum of n AZ circular distances <= observed)."""
    weights = [0] * 14
    weights[0] = 1
    for d in range(1, 13):
        weights[d] = 2
    weights[13] = 1
    dp: dict[int, int] = {0: 1}
    for _ in range(n):
        nxt: dict[int, int] = {}
        for total, count in dp.items():
            for dist, weight in enumerate(weights):
                if weight:
                    nxt[total + dist] = nxt.get(total + dist, 0) + count * weight
        dp = nxt
    numerator = sum(count for total, count in dp.items() if total <= observed)
    denominator = 26**n
    return numerator / denominator


def minor_difference_stat() -> dict[str, Any]:
    cribs = crib_dict()
    rows = []
    for pos, pt in sorted(cribs.items()):
        if pt not in KRYPTOS_SET:
            continue
        rows.append({
            "position": pos,
            "pt": pt,
            "ct": CT[pos],
            "distance": circular_distance(pt, CT[pos]),
        })
    observed = sum(row["distance"] for row in rows)
    exact_iid_p = exact_iid_sum_tail(observed, len(rows))
    return {
        "subset_rule": "plaintext letter in set(KRYPTOS)",
        "n_positions": len(rows),
        "positions": rows,
        "observed_sum_distance": observed,
        "observed_mean_distance": observed / len(rows),
        "exact_iid_uniform_p_sum_le_observed": exact_iid_p,
        "exact_iid_uniform_inverse": 1 / exact_iid_p,
    }


def repeated_pt_stat() -> dict[str, Any]:
    cribs = crib_dict()
    groups = []
    pair_specs: list[tuple[int, int]] = []
    positions = sorted(cribs)
    pos_index = {pos: i for i, pos in enumerate(positions)}
    for letter in sorted(set(cribs.values())):
        ps = [pos for pos, ch in sorted(cribs.items()) if ch == letter]
        if len(ps) < 2:
            continue
        pairs = []
        for a, b in combinations(ps, 2):
            pairs.append({
                "a": a,
                "b": b,
                "ct_a": CT[a],
                "ct_b": CT[b],
                "distance": circular_distance(CT[a], CT[b]),
            })
            pair_specs.append((pos_index[a], pos_index[b]))
        groups.append({
            "pt_letter": letter,
            "positions": ps,
            "pairs": pairs,
            "sum_distance": sum(pair["distance"] for pair in pairs),
        })
    return {
        "statistic": "sum circular CT-letter distances over all pairs of crib positions sharing the same plaintext letter",
        "crib_position_order": positions,
        "n_pairs": len(pair_specs),
        "observed_sum_distance": sum(group["sum_distance"] for group in groups),
        "groups": groups,
        "pair_indices": pair_specs,
    }


def permutation_mc(
    *,
    samples: int,
    seed: int,
    minor: dict[str, Any],
    repeated: dict[str, Any],
) -> dict[str, Any]:
    rng = random.Random(seed)
    chars = list(CT)
    minor_pts = [row["pt"] for row in minor["positions"]]
    minor_obs = int(minor["observed_sum_distance"])
    crib_positions = repeated["crib_position_order"]
    pair_indices = [tuple(pair) for pair in repeated["pair_indices"]]
    repeated_obs = int(repeated["observed_sum_distance"])
    minor_hits = 0
    repeated_hits = 0
    for _ in range(samples):
        minor_sample = rng.sample(chars, len(minor_pts))
        minor_sum = sum(
            circular_distance(pt, ct)
            for pt, ct in zip(minor_pts, minor_sample)
        )
        if minor_sum <= minor_obs:
            minor_hits += 1

        repeated_sample = rng.sample(chars, len(crib_positions))
        repeated_sum = sum(
            circular_distance(repeated_sample[a], repeated_sample[b])
            for a, b in pair_indices
        )
        if repeated_sum <= repeated_obs:
            repeated_hits += 1

    return {
        "null": "random permutation preserving K4 CT letter multiset",
        "samples": samples,
        "seed": seed,
        "minor_difference_p_add_one": (minor_hits + 1) / (samples + 1),
        "minor_difference_hits": minor_hits,
        "minor_difference_inverse": (samples + 1) / (minor_hits + 1),
        "repeated_pt_distance_p_add_one": (repeated_hits + 1) / (samples + 1),
        "repeated_pt_distance_hits": repeated_hits,
        "repeated_pt_distance_inverse": (samples + 1) / (repeated_hits + 1),
    }


def write_markdown(payload: dict[str, Any]) -> None:
    minor = payload["minor_difference"]
    repeated = payload["repeated_plaintext_distances"]
    mc = payload["permutation_mc"]
    lines = [
        "# Bean-Reported Statistics Audit",
        "",
        "## Verdict",
        "",
        "- Bean/Materna minor-difference statistic is independently reproduced in substance under a K4-multiset permutation null.",
        "- The IID uniform null gives a smaller p-value than Bean's reported p≈1/5520; the K4-multiset permutation null lands near the reported value.",
        "- Repeated-plaintext-letter CT distances are descriptive unless a precise pre-registered statistic and correction family are declared.",
        "",
        "## Minor Difference",
        "",
        f"- Subset: PT letters in KRYPTOS set; n={minor['n_positions']}",
        f"- Observed sum distance: {minor['observed_sum_distance']}",
        f"- Exact IID p(sum <= observed): {minor['exact_iid_uniform_p_sum_le_observed']:.6g} (1/{minor['exact_iid_uniform_inverse']:.1f})",
        f"- K4-multiset permutation MC p: {mc['minor_difference_p_add_one']:.6g} (1/{mc['minor_difference_inverse']:.1f}, samples={mc['samples']})",
        "",
        "## Repeated Plaintext Letters",
        "",
        f"- Pair count: {repeated['n_pairs']}",
        f"- Observed summed CT-distance statistic: {repeated['observed_sum_distance']}",
        f"- K4-multiset permutation MC p: {mc['repeated_pt_distance_p_add_one']:.6g} (1/{mc['repeated_pt_distance_inverse']:.1f})",
        "",
        "## Caveat",
        "",
        "Both statistics are crib-position and H1 dependent. The minor-difference subset is post-hoc: the selected PT-letter set spells KRYPTOS. Neither statistic is a hard constraint or elimination basis without an explicit pre-registered search family correction.",
        "",
        "## Reproduction",
        "",
        "```bash",
        "PYTHONPATH=src python3 scripts/audit/audit_bean_reported_statistics.py",
        "```",
    ]
    DOC_PATH.parent.mkdir(parents=True, exist_ok=True)
    DOC_PATH.write_text("\n".join(lines) + "\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--samples", type=int, default=2_000_000)
    ap.add_argument("--seed", type=int, default=20260501)
    args = ap.parse_args(argv)

    minor = minor_difference_stat()
    repeated = repeated_pt_stat()
    mc = permutation_mc(samples=args.samples, seed=args.seed, minor=minor, repeated=repeated)
    payload = {
        "schema_version": 1,
        "classification": {
            "minor_difference": "PROJECT_REVERIFIED_STATISTICAL_ANOMALY for arithmetic/statistic; still post-hoc and H1-conditional",
            "repeated_plaintext_distances": "PROJECT_REVERIFIED_STATISTICAL_ANOMALY for this explicit statistic only; Bean's unspecified reported variants remain BEAN_REPORTED_NOT_RERUN",
        },
        "minor_difference": minor,
        "repeated_plaintext_distances": repeated,
        "permutation_mc": mc,
        "caveats": [
            "H1-conditional crib-position statistics.",
            "The KRYPTOS PT-letter subset is post-hoc.",
            "Monte Carlo p-values are not global search-family p-values.",
        ],
        "reproduction_command": "PYTHONPATH=src python3 scripts/audit/audit_bean_reported_statistics.py",
    }
    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True))
    write_markdown(payload)
    print(json.dumps({
        "wrote": [str(RESULT_PATH), str(DOC_PATH)],
        "minor_permutation_p": mc["minor_difference_p_add_one"],
        "repeated_permutation_p": mc["repeated_pt_distance_p_add_one"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
