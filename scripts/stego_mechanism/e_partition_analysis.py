#!/usr/bin/env python3
"""
Phase B3: Partition Rule Analysis — CRITICAL GATE

Determines whether the null-value set has algebraic structure
(Polybius region, keyword complement, threshold, modular rule).

Reads the canonical partition from B2 results. If B2 hasn't run,
uses CHART:vigenere_az partition {3,8,12,15,16,19,20,24}.

Output: results/stego_mechanism/partition_analysis.json
"""
import sys, os, json
from collections import Counter
from datetime import datetime, timezone
from itertools import combinations

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    NULL_PALETTE, BEAUFORT_KEYSTREAM_AT_CRIBS,
)

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

# ── Load canonical partition from B2, or use default ────────────────
B2_PATH = os.path.join(_ROOT, "results", "stego_mechanism", "exhaustive_word_sweep.json")
DEFAULT_NULL_SET = frozenset([3, 8, 12, 15, 16, 19, 20, 24])  # CHART:vigenere_az
DEFAULT_VARIANT = "vigenere_az"

if os.path.exists(B2_PATH):
    with open(B2_PATH) as f:
        b2 = json.load(f)
    # Use the vigenere_az canonical partition (or whichever has fewest distinct partitions)
    vig_data = b2["variants"].get("vigenere_az", {})
    if vig_data.get("distinct_partitions", 0) == 1:
        # Unique partition — extract it
        part_str = list(vig_data.get("partition_sizes", {}).keys())[0]
        null_set = frozenset(json.loads(part_str))
        print(f"Loaded UNIQUE partition from B2 vigenere_az: {sorted(null_set)}")
    else:
        null_set = DEFAULT_NULL_SET
        print(f"B2 has multiple partitions; using CHART default: {sorted(null_set)}")
else:
    null_set = DEFAULT_NULL_SET
    print(f"No B2 results; using CHART default: {sorted(null_set)}")

null_letters = frozenset(ALPH[v] for v in null_set)
real_set = frozenset(range(MOD)) - null_set
real_letters = frozenset(ALPH[v] for v in real_set)


def run_b3():
    results = {
        "experiment": "e_partition_analysis",
        "date": datetime.now(timezone.utc).isoformat(),
        "null_set_az_indices": sorted(null_set),
        "null_set_letters": sorted(null_letters),
        "null_set_size": len(null_set),
        "real_set_letters": sorted(real_letters),
    }

    print("=" * 80)
    print("PHASE B3: PARTITION RULE ANALYSIS — CRITICAL GATE")
    print(f"Null set ({len(null_set)} letters): {sorted(null_letters)}")
    print(f"Real set ({len(real_set)} letters): {sorted(real_letters)}")
    print("=" * 80)

    # ── B3.1: Polybius Grid Mapping ─────────────────────────────────
    print("\n── B3.1: Polybius Grid Mapping ──")

    # AZ grid (5-wide)
    az_positions = {}
    for v in null_set:
        r, c = divmod(v, 5)
        az_positions[ALPH[v]] = (r, c)
    results["B3_1_az_grid"] = {letter: list(pos) for letter, pos in az_positions.items()}

    print("  AZ 5-wide positions of null-set letters:")
    for letter, (r, c) in sorted(az_positions.items()):
        print(f"    {letter} (AZ={ALPH_IDX[letter]:2d}) → row={r}, col={c}")

    az_rows = Counter(pos[0] for pos in az_positions.values())
    az_cols = Counter(pos[1] for pos in az_positions.values())
    print(f"  AZ row distribution: {dict(az_rows)}")
    print(f"  AZ col distribution: {dict(az_cols)}")

    # KA grid (5-wide)
    ka_positions = {}
    for letter in null_letters:
        ki = KA_IDX[letter]
        r, c = divmod(ki, 5)
        ka_positions[letter] = (r, c)
    results["B3_1_ka_grid"] = {letter: list(pos) for letter, pos in ka_positions.items()}

    print("\n  KA 5-wide positions of null-set letters:")
    for letter, (r, c) in sorted(ka_positions.items()):
        print(f"    {letter} (KA={KA_IDX[letter]:2d}) → row={r}, col={c}")

    ka_rows = Counter(pos[0] for pos in ka_positions.values())
    ka_cols = Counter(pos[1] for pos in ka_positions.values())
    print(f"  KA row distribution: {dict(ka_rows)}")
    print(f"  KA col distribution: {dict(ka_cols)}")

    # Check for contiguous regions
    results["B3_1_az_row_set"] = sorted(az_rows.keys())
    results["B3_1_ka_row_set"] = sorted(ka_rows.keys())
    results["B3_1_az_col_set"] = sorted(az_cols.keys())
    results["B3_1_ka_col_set"] = sorted(ka_cols.keys())

    # ── B3.2: Set-Theoretic Relationships ───────────────────────────
    print("\n── B3.2: Set-Theoretic Relationships ──")

    palette_set = frozenset(NULL_PALETTE)
    kryptos_set = frozenset("KRYPTOS")
    seven_set = frozenset("SEVEN")
    chart_set = frozenset("CHART")

    intersections = {
        "palette": sorted(null_letters & palette_set),
        "kryptos": sorted(null_letters & kryptos_set),
        "seven": sorted(null_letters & seven_set),
        "chart": sorted(null_letters & chart_set),
    }
    results["B3_2_intersections"] = intersections

    for name, inter in intersections.items():
        print(f"  Null set ∩ {name:>8s} = {inter} ({len(inter)} letters)")

    # Complement analysis
    print(f"\n  Complement (real set, 18 letters): {sorted(real_letters)}")
    # Check if complement contains recognizable words
    # (Just report — manual review needed)

    # ── B3.3: Numerical Structure ───────────────────────────────────
    print("\n── B3.3: Numerical Structure ──")
    null_list = sorted(null_set)
    diffs = [null_list[i+1] - null_list[i] for i in range(len(null_list)-1)]
    total_sum = sum(null_list)

    print(f"  Values (AZ): {null_list}")
    print(f"  Consecutive diffs: {diffs}")
    print(f"  Sum: {total_sum} = {_factorize(total_sum)}")

    numerical = {"values": null_list, "diffs": diffs, "sum": total_sum}

    for m in range(2, 14):
        residues = sorted(set(v % m for v in null_list))
        coverage = len(residues) / m
        numerical[f"mod_{m}_residues"] = residues
        if coverage < 0.6:  # concentrated in fewer than 60% of residue classes
            print(f"  mod-{m}: residues {residues} ({len(residues)}/{m} = {coverage:.0%}) ← CONCENTRATED")
        else:
            print(f"  mod-{m}: residues {residues} ({len(residues)}/{m} = {coverage:.0%})")

    results["B3_3_numerical"] = numerical

    # Bit pattern analysis
    print(f"\n  5-bit patterns:")
    for v in null_list:
        print(f"    {ALPH[v]} = {v:2d} = {v:05b}")
    # Check if any single bit position selects the null set
    for bit in range(5):
        selected = {v for v in range(MOD) if (v >> bit) & 1}
        overlap = null_set & selected
        print(f"  Bit {bit} set → {len(overlap)}/{len(null_set)} null members "
              f"({len(selected)}/26 total)")

    # KA indexing
    null_ka_indices = sorted(KA_IDX[ALPH[v]] for v in null_set)
    print(f"\n  Values (KA): {null_ka_indices}")
    ka_diffs = [null_ka_indices[i+1] - null_ka_indices[i]
                for i in range(len(null_ka_indices)-1)]
    print(f"  KA consecutive diffs: {ka_diffs}")

    results["B3_3_ka_indices"] = null_ka_indices

    # ── B3.4: Generative Tests ──────────────────────────────────────
    print("\n── B3.4: Generative Tests ──")

    # NOTE: A single-key Beaufort/Vigenere is a bijection on Z/26, so
    # EVERY key maps SOME 8-element input set onto the null set.
    # That is trivially true and not a structural finding.
    #
    # The real test: does the null set have a RECOGNIZABLE preimage
    # under a specific cipher+key? I.e., does Beaufort(key=K) map
    # a meaningful word/set onto the null set?
    generative = {}
    test_keys = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

    for key_letter in test_keys:
        ki = ALPH_IDX[key_letter]
        # Beaufort AZ: preimage of null_set under key K
        preimage_beau = frozenset((ki - v) % MOD for v in null_set)
        preimage_vig = frozenset((v - ki) % MOD for v in null_set)

        preimage_beau_letters = "".join(sorted(ALPH[v] for v in preimage_beau))
        preimage_vig_letters = "".join(sorted(ALPH[v] for v in preimage_vig))

        # Check if preimage contains a recognizable word (5+ letter substring)
        for label, letters in [("beaufort", preimage_beau_letters),
                                ("vigenere", preimage_vig_letters)]:
            # Check against known keywords
            for word in ["KRYPTOS", "SEVEN", "CHART", "CLOCK", "NORTH",
                         "BERLIN", "TOWER", "LAYER", "SHADE", "LIGHT"]:
                if all(c in letters for c in set(word)):
                    gen_key = f"{label}_key_{key_letter}_contains_{word}"
                    generative[gen_key] = {
                        "preimage_letters": letters,
                        "keyword_found": word,
                        "keyword_coverage": f"{len(set(word))}/{len(letters)}",
                    }

    results["B3_4_generative"] = generative
    if generative:
        print(f"  Found {len(generative)} preimage-keyword matches:")
        for name, data in sorted(generative.items()):
            print(f"    {name}: preimage={data['preimage_letters']}, "
                  f"keyword={data['keyword_found']}")
    else:
        print("  No recognizable keyword found in any preimage.")

    # ── B3.5: Cross-Layer Test ──────────────────────────────────────
    print("\n── B3.5: Cross-Layer Test ──")
    ks_nums = [ALPH_IDX[c] for c in BEAUFORT_KEYSTREAM_AT_CRIBS]

    ks_in_null = [v for v in ks_nums if v in null_set]
    ks_in_real = [v for v in ks_nums if v in real_set]

    cross_layer = {
        "keystream_values": ks_nums,
        "ks_in_null_set": len(ks_in_null),
        "ks_in_real_set": len(ks_in_real),
        "ks_null_fraction": len(ks_in_null) / len(ks_nums),
        "expected_null_fraction": len(null_set) / MOD,
    }

    # Additive inverses
    null_inverses = frozenset((MOD - v) % MOD for v in null_set)
    ks_set = frozenset(ks_nums)
    cross_layer["inverse_overlap_with_ks"] = len(null_inverses & ks_set)

    results["B3_5_cross_layer"] = cross_layer
    print(f"  Keystream values in null set: {len(ks_in_null)}/24 "
          f"(expected: {len(null_set)/MOD*24:.1f})")
    print(f"  Keystream values in real set: {len(ks_in_real)}/24")
    print(f"  Null set additive inverses ∩ keystream: "
          f"{cross_layer['inverse_overlap_with_ks']}")

    # ── Verdict ─────────────────────────────────────────────────────
    print(f"\n{'=' * 80}")

    structured_signals = []
    # Check for row/col concentration in either grid
    for grid_name, rows, cols in [("AZ", az_rows, az_cols), ("KA", ka_rows, ka_cols)]:
        if len(rows) <= 3:
            structured_signals.append(f"{grid_name} grid: null set in {len(rows)} rows")
        if len(cols) <= 2:
            structured_signals.append(f"{grid_name} grid: null set in {len(cols)} columns")
    # Check for modular concentration
    for m in range(2, 8):
        residues = set(v % m for v in null_list)
        if len(residues) <= m // 2:
            structured_signals.append(f"mod-{m}: only {len(residues)}/{m} residues")
    # Check for meaningful preimage-keyword matches (not trivially true)
    if generative:
        structured_signals.append(
            f"Preimage contains recognizable keyword(s): "
            f"{', '.join(set(v['keyword_found'] for v in generative.values()))}"
        )

    results["structured_signals"] = structured_signals

    if structured_signals:
        results["verdict"] = "STRUCTURED"
        print("VERDICT: STRUCTURED — partition has algebraic structure")
        for sig in structured_signals:
            print(f"  + {sig}")
    else:
        results["verdict"] = "ARBITRARY"
        print("VERDICT: ARBITRARY — no structural interpretation found")
        print("  → CRITICAL GATE FAILED. Classification is descriptive, not generative.")
        print("  → Phase C still runs on weaker (existing) constraints.")

    print(f"{'=' * 80}")

    out_path = os.path.join(_ROOT, "results", "stego_mechanism", "partition_analysis.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults written to {out_path}")

    return results


def _factorize(n):
    """Simple factorization for display."""
    if n <= 1:
        return str(n)
    factors = []
    d = 2
    temp = n
    while d * d <= temp:
        while temp % d == 0:
            factors.append(d)
            temp //= d
        d += 1
    if temp > 1:
        factors.append(temp)
    return " × ".join(str(f) for f in factors) if len(factors) > 1 else str(n)


if __name__ == "__main__":
    run_b3()
