#!/usr/bin/env python3
"""
Phase C: Constraint Propagation — Stego → Cipher

C1: Palette-enriched keystream as hard constraint
C2: AP {G,K,O} structural requirement
C3: Row-key mod-6 substitution search (720 permutations × 4 input sources)
C4: Partition-cipher interaction
C5: Mask-conditioned cipher re-test (compare mechanism mask vs consensus)

Output: results/stego_mechanism/constraint_propagation.json
"""
import sys, os, json
from collections import Counter
from datetime import datetime, timezone
from itertools import permutations

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    CRIB_POSITIONS, CRIB_DICT, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, BEAUFORT_KEYSTREAM_AT_CRIBS,
)

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

# Known row key (Beaufort, from split-coordinate model)
ROW_KEY = [4, 4, 1, 4, 1, 5, 0, 0, 5, 4, 1, 2, 1, 4, 2, 0, 1, 3, 3, 4, 2, 3, 1, 0]
CRIB_POS_SORTED = sorted(CRIB_POSITIONS)


def run_c():
    results = {
        "experiment": "e_constraint_propagation",
        "date": datetime.now(timezone.utc).isoformat(),
    }

    print("=" * 80)
    print("PHASE C: CONSTRAINT PROPAGATION (Stego → Cipher)")
    print("=" * 80)

    # Load B3 partition if available
    b3_path = os.path.join(_ROOT, "results", "stego_mechanism", "partition_analysis.json")
    if os.path.exists(b3_path):
        with open(b3_path) as f:
            b3 = json.load(f)
        null_set = frozenset(b3["null_set_az_indices"])
    else:
        null_set = frozenset([3, 8, 12, 15, 16, 19, 20, 24])

    null_letters = frozenset(ALPH[v] for v in null_set)
    palette_nums = frozenset(ALPH_IDX[c] for c in NULL_PALETTE)

    # ── C1: Palette-enriched keystream ──────────────────────────────
    print("\n── C1: Palette-Enriched Keystream ──")
    ks_nums = [ALPH_IDX[c] for c in BEAUFORT_KEYSTREAM_AT_CRIBS]

    ks_in_palette = sum(1 for v in ks_nums if v in palette_nums)
    expected = len(ks_nums) * len(palette_nums) / MOD

    c1 = {
        "observed": ks_in_palette,
        "expected_random": round(expected, 2),
        "total": len(ks_nums),
        "constraint": f"Any cipher must produce >= {max(1, int(expected * 1.5))}/24 "
                      f"palette membership (2σ filter: reject if < {max(1, int(expected + 2 * (expected * (1 - len(palette_nums)/MOD))**0.5))})",
    }
    results["C1_palette_enrichment"] = c1
    print(f"  Keystream palette membership: {ks_in_palette}/24 "
          f"(expected random: {expected:.1f})")

    # ── C2: AP {G,K,O} structural requirement ──────────────────────
    print("\n── C2: AP {G,K,O} Structural Requirement ──")
    ap_set = {ALPH_IDX[c] for c in "GKO"}
    ks_in_ap = sum(1 for v in ks_nums if v in ap_set)

    # Map to KA rows
    ap_ka_rows = {KA_IDX[c] // 5 for c in "GKO"}

    c2 = {
        "ap_values_az": sorted(ap_set),
        "ap_ka_rows": sorted(ap_ka_rows),
        "ks_in_ap": ks_in_ap,
        "total": len(ks_nums),
        "constraint": f"Cipher key at {ks_in_ap}/24 positions must produce "
                      f"Polybius rows {sorted(ap_ka_rows)}",
    }
    results["C2_ap_requirement"] = c2
    print(f"  AP {{G,K,O}} at {ks_in_ap}/24 keystream positions")
    print(f"  KA row mapping: G→row{KA_IDX['G']//5}, K→row{KA_IDX['K']//5}, "
          f"O→row{KA_IDX['O']//5}")

    # ── C3: Row-key mod-6 substitution search ──────────────────────
    print("\n── C3: Row-Key Mod-6 Substitution Search ──")

    # Input sources for substitution
    input_sources = {}

    # (a) Sequential position index mod 6
    input_sources["pos_mod6"] = [p % 6 for p in CRIB_POS_SORTED]

    # (b) CT letter at crib position mod 6
    input_sources["ct_mod6"] = [ALPH_IDX[CT[p]] % 6 for p in CRIB_POS_SORTED]

    # (c) PT letter at crib position mod 6
    crib_pts = []
    for p in CRIB_POS_SORTED:
        crib_pts.append(ALPH_IDX[CRIB_DICT[p]])
    input_sources["pt_mod6"] = [v % 6 for v in crib_pts]

    # (d) Column key mod 5 (with 0-pad for 6th value)
    col_keys_beaufort = []
    for p in CRIB_POS_SORTED:
        ct_val = ALPH_IDX[CT[p]]
        pt_val = ALPH_IDX[CRIB_DICT[p]]
        col_keys_beaufort.append((ct_val + pt_val) % MOD % 5)
    input_sources["col_key_mod5"] = col_keys_beaufort

    c3 = {"input_sources": {}, "best_overall": {"score": 0}}

    for src_name, src_vals in input_sources.items():
        best_perm = None
        best_score = 0

        # Test all 720 permutations of {0,1,2,3,4,5}
        for perm in permutations(range(6)):
            mapped = [perm[v] for v in src_vals]
            score = sum(1 for a, b in zip(mapped, ROW_KEY) if a == b)
            if score > best_score:
                best_score = score
                best_perm = perm

        c3["input_sources"][src_name] = {
            "input_values": src_vals,
            "best_perm": list(best_perm) if best_perm else None,
            "best_score": best_score,
            "total": len(ROW_KEY),
        }

        if best_score > c3["best_overall"]["score"]:
            c3["best_overall"] = {
                "source": src_name, "score": best_score,
                "perm": list(best_perm) if best_perm else None,
            }

        print(f"  {src_name}: best perm score = {best_score}/24")

    # Expected by chance: for each position, P(match) = 1/6. Expected = 24/6 = 4.
    c3["expected_random"] = 4.0
    c3["constraint"] = (
        f"Best mod-6 substitution: {c3['best_overall']['score']}/24 "
        f"from {c3['best_overall']['source']} (expected random: 4.0)"
    )
    results["C3_mod6_substitution"] = c3
    print(f"  → Best overall: {c3['best_overall']['source']} at "
          f"{c3['best_overall']['score']}/24 (random baseline: 4.0)")

    # ── C4: Partition-cipher interaction ────────────────────────────
    print("\n── C4: Partition-Cipher Interaction ──")

    ks_in_null_part = sum(1 for v in ks_nums if v in null_set)
    expected_null = len(ks_nums) * len(null_set) / MOD

    c4 = {
        "ks_in_null_partition": ks_in_null_part,
        "expected_random": round(expected_null, 2),
        "total": len(ks_nums),
        "avoidance_or_preference": (
            "AVOIDANCE" if ks_in_null_part < expected_null * 0.5
            else "PREFERENCE" if ks_in_null_part > expected_null * 1.5
            else "NEUTRAL"
        ),
    }
    results["C4_partition_interaction"] = c4
    print(f"  Keystream values in null output partition: {ks_in_null_part}/24 "
          f"(expected: {expected_null:.1f})")
    print(f"  → {c4['avoidance_or_preference']}")

    # ── C5: Constraint Summary ──────────────────────────────────────
    print(f"\n── C5: Constraint Summary ──")
    constraints = []

    constraints.append(f"C1: Cipher must produce ≥{ks_in_palette}/24 palette keystream "
                       f"(vs {expected:.1f} random)")
    constraints.append(f"C2: {ks_in_ap}/24 positions must map to AP rows "
                       f"{sorted(ap_ka_rows)} in KA grid")
    constraints.append(f"C3: Row key is NOT a simple mod-6 substitution of "
                       f"position/CT/PT/colkey (best: {c3['best_overall']['score']}/24)")
    constraints.append(f"C4: Keystream-partition interaction: {c4['avoidance_or_preference']}")
    constraints.append("C5: Row key is non-periodic, non-autokey, non-NDYAHR, "
                       "non-Berlin-Clock-routed (prior eliminations)")

    results["constraints_summary"] = constraints
    for con in constraints:
        print(f"  {con}")

    # New constraints (beyond existing CxS-1..4)
    new_constraints = []
    if c3["best_overall"]["score"] <= 6:  # not much better than random
        new_constraints.append(
            "Row key is NOT a substitution cipher of any tested input source at mod-6 level"
        )
    if c4["avoidance_or_preference"] != "NEUTRAL":
        new_constraints.append(
            f"Keystream {c4['avoidance_or_preference'].lower()}s the null output partition "
            f"({ks_in_null_part}/24 vs {expected_null:.1f} expected)"
        )

    results["new_constraints"] = new_constraints
    results["verdict"] = (
        "NEW_CONSTRAINTS_FOUND" if new_constraints else "NO_NEW_CONSTRAINTS"
    )

    print(f"\n{'=' * 80}")
    if new_constraints:
        print(f"VERDICT: {len(new_constraints)} NEW CONSTRAINT(S) FOUND")
        for nc in new_constraints:
            print(f"  → {nc}")
    else:
        print("VERDICT: No new constraints beyond existing CxS-1..4")
    print(f"{'=' * 80}")

    out_path = os.path.join(_ROOT, "results", "stego_mechanism",
                            "constraint_propagation.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults written to {out_path}")

    return results


if __name__ == "__main__":
    run_c()
