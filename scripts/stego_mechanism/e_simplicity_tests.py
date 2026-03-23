#!/usr/bin/env python3
"""
Phase B1: Simplicity Tests — Can a simpler system generate the 7×5 table?

Tests whether SEVEN alone, a single shift, or a 2-letter cycling key
achieves 23/23 pure-cell classification WITH a structured partition
(threshold, modular rule, or Polybius region).

If any simpler system works, CHART is unnecessary.

Output: results/stego_mechanism/simplicity_tests.json
"""
import sys, os, json
from collections import defaultdict
from datetime import datetime, timezone
from itertools import product

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
)

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
KRYPTOS_WORD = "KRYPTOS"

# ── Build target table ──────────────────────────────────────────────
PALETTE_POSITIONS = sorted(p for p in range(CT_LEN) if CT[p] in NULL_PALETTE)

cell_data = defaultdict(list)
for p in PALETTE_POSITIONS:
    cell_data[(p % 7, p % 5)].append((p, p in CONSENSUS_NULL_POSITIONS))

target = {}
for r in range(7):
    for c in range(5):
        entries = cell_data.get((r, c), [])
        if not entries:
            target[(r, c)] = None
        else:
            nulls = [e for e in entries if e[1]]
            reals = [e for e in entries if not e[1]]
            if nulls and not reals:
                target[(r, c)] = True
            elif reals and not nulls:
                target[(r, c)] = False
            else:
                target[(r, c)] = "mixed"

occupied_pure = {(r, c): v for (r, c), v in target.items() if v in (True, False)}
N_PURE = len(occupied_pure)  # 23

# ── Cipher functions ────────────────────────────────────────────────
CIPHER_FNS = {
    "beaufort_az": lambda a, b: (ALPH_IDX[a] - ALPH_IDX[b]) % MOD,
    "vigenere_az": lambda a, b: (ALPH_IDX[a] + ALPH_IDX[b]) % MOD,
    "beaufort_ka": lambda a, b: (KA_IDX[a] - KA_IDX[b]) % MOD,
    "vigenere_ka": lambda a, b: (KA_IDX[a] + KA_IDX[b]) % MOD,
}


def score_word(col_key, cipher_fn):
    """Compute cell outputs and find best data-fit partition score on 23 pure cells."""
    cell_outputs = {}
    for r in range(7):
        for c in range(5):
            cell_outputs[(r, c)] = cipher_fn(KRYPTOS_WORD[r], col_key[c % len(col_key)])

    # Induce null-value set from pure-null cells
    null_values = set()
    for (r, c), is_null in occupied_pure.items():
        if is_null:
            null_values.add(cell_outputs[(r, c)])

    # Score: how many pure cells are correctly classified?
    correct = 0
    for (r, c), is_null in occupied_pure.items():
        predicted_null = cell_outputs[(r, c)] in null_values
        if predicted_null == is_null:
            correct += 1

    return correct, null_values, cell_outputs


def test_structured_partitions(cell_outputs):
    """Test threshold and modular partition rules. Return best structured score."""
    best = {"type": None, "score": 0, "params": {}}

    # Threshold rules: null iff output < T
    for t in range(1, MOD):
        correct = 0
        for (r, c), is_null in occupied_pure.items():
            predicted = cell_outputs[(r, c)] < t
            if predicted == is_null:
                correct += 1
        if correct > best["score"]:
            best = {"type": "threshold", "score": correct, "params": {"T": t}}

    # Modular rules: null iff output % M in S, for M=2..6
    for m in range(2, 7):
        residues = set(range(m))
        # Try all non-empty subsets of residues
        for r_size in range(1, m):
            for subset in _combinations(list(residues), r_size):
                s = set(subset)
                correct = 0
                for (r, c), is_null in occupied_pure.items():
                    predicted = (cell_outputs[(r, c)] % m) in s
                    if predicted == is_null:
                        correct += 1
                if correct > best["score"]:
                    best = {"type": f"mod_{m}", "score": correct,
                            "params": {"M": m, "S": sorted(s)}}

    return best


def _combinations(lst, r):
    """Simple combinations generator (avoid importing itertools.combinations twice)."""
    from itertools import combinations
    return combinations(lst, r)


def run_b1():
    results = {
        "experiment": "e_simplicity_tests",
        "date": datetime.now(timezone.utc).isoformat(),
        "spec": "docs/superpowers/specs/2026-03-23-stego-mechanism-formalization-design.md",
    }

    print("=" * 80)
    print("PHASE B1: SIMPLICITY TESTS")
    print("=" * 80)

    # ── B1.1: SEVEN direct ──────────────────────────────────────────
    print("\n── B1.1: SEVEN as column keyword ──")
    b1_1 = {}
    for cname, cfn in CIPHER_FNS.items():
        score, null_vals, cell_outs = score_word("SEVEN", cfn)
        structured = test_structured_partitions(cell_outs)
        b1_1[cname] = {
            "data_fit_score": score,
            "null_values": sorted(null_vals),
            "null_letters": sorted(ALPH[v] for v in null_vals),
            "best_structured": structured,
        }
        print(f"  {cname}: data-fit={score}/{N_PURE}, "
              f"best structured={structured['score']}/{N_PURE} ({structured['type']})")

    results["B1_1_seven"] = b1_1
    seven_kills = any(v["best_structured"]["score"] == N_PURE for v in b1_1.values())
    results["B1_1_kills_chart"] = seven_kills
    print(f"  → SEVEN kills CHART? {seven_kills}")

    # ── B1.2: Single shift ──────────────────────────────────────────
    print("\n── B1.2: Single constant shift (0-25) ──")
    b1_2 = {"best_per_variant": {}}
    for cname, cfn in CIPHER_FNS.items():
        best_shift = {"shift": -1, "data_fit": 0, "structured": 0}
        for s in range(MOD):
            # Use ALPH[s] as the constant column "letter"
            col_letter = ALPH[s]
            cell_outputs = {}
            for r in range(7):
                for c in range(5):
                    cell_outputs[(r, c)] = cfn(KRYPTOS_WORD[r], col_letter)

            # Induce partition
            null_values = set()
            for (rc), is_null in occupied_pure.items():
                if is_null:
                    null_values.add(cell_outputs[rc])
            correct = sum(
                1 for rc, is_null in occupied_pure.items()
                if (cell_outputs[rc] in null_values) == is_null
            )
            if correct > best_shift["data_fit"]:
                best_shift = {"shift": s, "letter": col_letter,
                              "data_fit": correct, "structured": 0}

        # Test structured partitions for the best shift
        col_letter = ALPH[best_shift["shift"]]
        cell_outputs = {}
        for r in range(7):
            for c in range(5):
                cell_outputs[(r, c)] = cfn(KRYPTOS_WORD[r], col_letter)
        structured = test_structured_partitions(cell_outputs)
        best_shift["structured"] = structured["score"]
        best_shift["structured_type"] = structured["type"]

        b1_2["best_per_variant"][cname] = best_shift
        print(f"  {cname}: best shift={best_shift['shift']} ({best_shift['letter']}), "
              f"data-fit={best_shift['data_fit']}/{N_PURE}, "
              f"structured={best_shift['structured']}/{N_PURE}")

    results["B1_2_single_shift"] = b1_2
    shift_kills = any(
        v["data_fit"] == N_PURE
        for v in b1_2["best_per_variant"].values()
    )
    results["B1_2_kills_chart"] = shift_kills
    print(f"  → Single shift kills CHART? {shift_kills}")

    # ── B1.3: 2-letter cycling key ─────────────────────────────────
    print("\n── B1.3: 2-letter cycling keys (676 × 4 variants) ──")
    b1_3 = {"best_per_variant": {}, "perfect_keys": []}
    for cname, cfn in CIPHER_FNS.items():
        best_key = {"key": "", "data_fit": 0}
        for a in range(MOD):
            for b in range(MOD):
                key_str = ALPH[a] + ALPH[b]
                score, null_vals, _ = score_word(key_str, cfn)
                if score > best_key["data_fit"]:
                    best_key = {"key": key_str, "data_fit": score,
                                "null_values": sorted(null_vals)}
                if score == N_PURE:
                    b1_3["perfect_keys"].append({
                        "key": key_str, "cipher": cname, "score": score
                    })

        b1_3["best_per_variant"][cname] = best_key
        print(f"  {cname}: best key={best_key['key']}, "
              f"data-fit={best_key['data_fit']}/{N_PURE}")

    results["B1_3_two_letter"] = b1_3
    two_letter_kills = len(b1_3["perfect_keys"]) > 0
    results["B1_3_kills_chart"] = two_letter_kills
    print(f"  → 2-letter key kills CHART? {two_letter_kills} "
          f"({len(b1_3['perfect_keys'])} perfect keys)")

    # ── Summary ─────────────────────────────────────────────────────
    any_kill = seven_kills or shift_kills or two_letter_kills
    results["any_simplicity_kill"] = any_kill
    results["verdict"] = "CHART_UNNECESSARY" if any_kill else "CHART_SURVIVES"

    print(f"\n{'=' * 80}")
    print(f"VERDICT: {results['verdict']}")
    print(f"{'=' * 80}")

    # Write results
    os.makedirs(os.path.join(_ROOT, "results", "stego_mechanism"), exist_ok=True)
    out_path = os.path.join(_ROOT, "results", "stego_mechanism", "simplicity_tests.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults written to {out_path}")

    return results


if __name__ == "__main__":
    run_b1()
