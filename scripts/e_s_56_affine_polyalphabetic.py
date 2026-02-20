#!/usr/bin/env python3
"""E-S-56: Affine Polyalphabetic Cipher — Algebraic Analysis.

What if K4's substitution is affine (CT[i] = a[i]*PT[i] + b[i] mod 26) rather
than additive (Vigenère: a=1, Beaufort: a=-1)? This would be a genuine
"change in methodology" from K3's Vigenère.

For a periodic affine cipher with period p:
  CT[i] = a[i%p] * PT[i] + b[i%p] mod 26
  where gcd(a[i%p], 26) = 1 (12 valid values: 1,3,5,7,9,11,15,17,19,21,23,25)

At each crib position i where PT[i] is known:
  a[i%p] * PT[i] + b[i%p] ≡ CT[i] mod 26

For each residue class r with 2+ crib positions (i,j):
  a[r] * (PT[i] - PT[j]) ≡ (CT[i] - CT[j]) mod 26

If (PT[i] - PT[j]) is coprime to 26, this UNIQUELY determines a[r].
Then b[r] = (CT[i] - a[r]*PT[i]) mod 26.

This experiment:
1. Direct correspondence (no transposition): test periods 2-14
2. With keyword columnar transpositions: test top keywords + periods 2-14
3. Determines algebraically if any (transposition, period, affine key) is consistent

This extends ALL prior polyalphabetic tests from {a=1, a=25} to {all 12 coprime values}.
"""

import json
import math
import time
import sys
from collections import defaultdict

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, myszkowski_perm, keyword_to_order,
    invert_perm, validate_perm,
)

CT_IDX = [ALPH_IDX[c] for c in CT]
PT_IDX = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

# Valid multiplicative constants (coprime to 26)
VALID_A = [a for a in range(1, MOD) if math.gcd(a, MOD) == 1]
# = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]

# Precompute modular inverses
MOD_INV = {}
for a in range(MOD):
    for b in range(MOD):
        if (a * b) % MOD == 1:
            MOD_INV[a] = b


def solve_affine_residue(positions_in_class, ct_idx_list, pt_idx_list):
    """Given crib positions in a residue class, solve for (a, b) mod 26.

    Returns:
      (a, b, n_consistent) if a unique (a,b) is found
      (None, None, 0) if no consistent solution exists
      ('underdetermined', None, n) if only 1 position (can't determine a)

    positions_in_class: list of positions
    ct_idx_list: CT index for each position
    pt_idx_list: PT index for each position (from cribs)
    """
    n = len(positions_in_class)
    if n == 0:
        return ('empty', None, 0)
    if n == 1:
        return ('underdetermined', None, 1)

    # Try all 12 valid values of a and check consistency
    best_a = None
    best_b = None
    best_consistent = 0

    for a in VALID_A:
        # For this a, compute b from first position
        b = (ct_idx_list[0] - a * pt_idx_list[0]) % MOD
        # Check all positions
        consistent = 0
        for i in range(n):
            predicted_ct = (a * pt_idx_list[i] + b) % MOD
            if predicted_ct == ct_idx_list[i]:
                consistent += 1
        if consistent > best_consistent:
            best_consistent = consistent
            best_a = a
            best_b = b

    return (best_a, best_b, best_consistent)


def test_affine_direct(period):
    """Test affine polyalphabetic at given period with direct correspondence."""
    # Group crib positions by residue mod period
    residue_groups = defaultdict(list)
    for pos in sorted(CRIB_POSITIONS):
        residue_groups[pos % period].append(pos)

    total_consistent = 0
    affine_params = {}
    residue_details = {}

    for r in range(period):
        positions = residue_groups.get(r, [])
        if len(positions) == 0:
            continue
        ct_vals = [CT_IDX[p] for p in positions]
        pt_vals = [PT_IDX[p] for p in positions]
        a, b, n_con = solve_affine_residue(positions, ct_vals, pt_vals)
        total_consistent += n_con
        affine_params[r] = (a, b)
        residue_details[r] = {
            "positions": positions, "n_total": len(positions),
            "n_consistent": n_con, "a": a, "b": b,
        }

    return total_consistent, affine_params, residue_details


def test_affine_transposed(perm, period, direction=1):
    """Test affine polyalphabetic with transposition perm at given period.

    Direction 1: Sub then Trans
      CT[i] = Transpose(AffineSub(PT))[i]
      AffineSub(PT)[j] = a[j%p]*PT[j] + b[j%p]
      CT[inv_perm[j]] = a[j%p]*PT[j] + b[j%p]  (for crib pos j)

    Direction 2: Trans then Sub
      CT[i] = AffineSub(Transpose(PT))[i]
      CT[i] = a[i%p]*PT[perm[i]] + b[i%p]
    """
    inv_perm = invert_perm(perm)

    # Map crib positions through transposition
    residue_groups = defaultdict(list)  # residue -> list of (mapped_ct_val, pt_val)

    if direction == 1:
        for pos in sorted(CRIB_POSITIONS):
            ct_pos = inv_perm[pos]  # Where in CT does this plaintext position land?
            ct_val = CT_IDX[ct_pos]
            pt_val = PT_IDX[pos]
            residue_groups[pos % period].append((ct_val, pt_val, pos))
    else:
        for i in range(CT_LEN):
            pt_pos = perm[i]  # Which PT position maps to CT position i?
            if pt_pos in PT_IDX:
                ct_val = CT_IDX[i]
                pt_val = PT_IDX[pt_pos]
                residue_groups[i % period].append((ct_val, pt_val, i))

    total_consistent = 0
    for r in range(period):
        group = residue_groups.get(r, [])
        if len(group) == 0:
            continue
        ct_vals = [g[0] for g in group]
        pt_vals = [g[1] for g in group]
        positions = [g[2] for g in group]
        a, b, n_con = solve_affine_residue(positions, ct_vals, pt_vals)
        total_consistent += n_con

    return total_consistent


# ── Keywords for transposition ──────────────────────────────────────
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "FORCES",
    "INVISIBLE", "BERLIN", "CLOCK", "BERLINCLOCK", "SCHEIDT",
    "SANBORN", "CARTER", "TUTANKHAMUN", "EGYPT", "CAIRO",
    "CIA", "LANGLEY", "SECRET", "ENIGMA", "COMPASS",
    "POINT", "WHATSTHEPOINT", "MESSAGE", "DELIVERING",
    "KEY", "CODE", "SPY", "EAST", "NORTH", "NORTHEAST",
    "CHECKPOINT", "CHARLIE", "QUARTZ", "LODESTONE",
    "PHARAOH", "TOMB", "VALLEY", "KINGS",
    "SOUTHEASTERN", "NORTHWESTERN", "CRYPTANALYSIS",
]

# Deduplicate
seen = set()
UNIQUE_KEYWORDS = []
for kw in KEYWORDS:
    kw_upper = kw.upper()
    if kw_upper not in seen and len(kw_upper) >= 3:
        seen.add(kw_upper)
        UNIQUE_KEYWORDS.append(kw_upper)


def main():
    print("=" * 70)
    print("E-S-56: Affine Polyalphabetic Cipher — Algebraic Analysis")
    print("=" * 70)
    print(f"Valid a values: {VALID_A} ({len(VALID_A)} values)")
    print(f"Note: a=1 is Vigenère, a=25 is Variant Beaufort")
    print()

    t0 = time.time()
    results = []
    configs = 0

    # ── Phase 1: Direct correspondence ──────────────────────────────
    print("=" * 50)
    print("Phase 1: Direct Correspondence (no transposition)")
    print("=" * 50)
    for period in range(2, 25):
        n_con, params, details = test_affine_direct(period)
        configs += 1

        # Count positions in residue classes
        total_testable = sum(d["n_total"] for d in details.values())
        n_classes = sum(1 for d in details.values() if d["n_total"] >= 2)

        if n_con >= STORE_THRESHOLD or period <= 14:
            a_vals = [str(d["a"]) for r, d in sorted(details.items()) if d["a"] not in (None, 'empty', 'underdetermined')]
            print(f"  p={period:2d}: {n_con}/24 consistent ({n_classes} classes with 2+ pos) "
                  f"a=[{','.join(a_vals[:7])}{'...' if len(a_vals)>7 else ''}]")

            if n_con >= STORE_THRESHOLD:
                results.append({
                    "type": "direct", "period": period,
                    "score": n_con, "details": details,
                })

    # Reference: what does Vigenère give?
    print(f"\n  Vigenère reference (a=1 only):")
    for period in [5, 7, 13, 14]:
        # Count Vigenère consistency
        residue_groups = defaultdict(list)
        for pos in sorted(CRIB_POSITIONS):
            residue_groups[pos % period].append(pos)
        vig_con = 0
        for r, positions in residue_groups.items():
            if len(positions) == 0:
                continue
            key_vals = [(CT_IDX[p] - PT_IDX[p]) % MOD for p in positions]
            first = key_vals[0]
            vig_con += 1  # first always counts
            vig_con += sum(1 for k in key_vals[1:] if k == first)
        print(f"    Vig p={period}: {vig_con}/24")

    # ── Phase 2: With keyword transpositions ────────────────────────
    print()
    print("=" * 50)
    print("Phase 2: Keyword Transpositions + Affine")
    print("=" * 50)
    print(f"Keywords: {len(UNIQUE_KEYWORDS)}")

    best_score = 0
    best_config = None

    for ki, kw in enumerate(UNIQUE_KEYWORDS):
        width = len(kw)
        order = keyword_to_order(kw, width)
        if order is None:
            continue
        perm = columnar_perm(width, order, CT_LEN)
        if not validate_perm(perm, CT_LEN):
            continue

        for direction in [1, 2]:
            for period in range(2, 15):
                n_con = test_affine_transposed(perm, period, direction)
                configs += 1

                if n_con > best_score:
                    best_score = n_con
                    best_config = {
                        "keyword": kw, "direction": direction,
                        "period": period, "score": n_con,
                    }

                if n_con >= STORE_THRESHOLD:
                    results.append({
                        "type": "keyword_columnar",
                        "keyword": kw, "direction": direction,
                        "period": period, "score": n_con,
                    })

        if (ki + 1) % 10 == 0:
            print(f"  Keyword {ki+1}/{len(UNIQUE_KEYWORDS)}: configs={configs} "
                  f"best={best_score}/24 hits(≥{STORE_THRESHOLD})={len(results)} [{time.time()-t0:.1f}s]")

    elapsed = time.time() - t0

    # ── Phase 3: Compare affine vs Vigenère ─────────────────────────
    print()
    print("=" * 50)
    print("Phase 3: Affine vs Vigenère Comparison")
    print("=" * 50)
    # For direct correspondence at each period, compare:
    # - Vigenère (a=1): number of consistent positions
    # - Best affine: number of consistent positions
    print(f"  Period | Vig | Best Affine | Gain | Best a-values")
    print(f"  -------|-----|-------------|------|---------------")
    for period in range(2, 15):
        # Vigenère
        residue_groups = defaultdict(list)
        for pos in sorted(CRIB_POSITIONS):
            residue_groups[pos % period].append(pos)
        vig_con = 0
        for r, positions in residue_groups.items():
            key_vals = [(CT_IDX[p] - PT_IDX[p]) % MOD for p in positions]
            if len(key_vals) > 0:
                first = key_vals[0]
                vig_con += 1 + sum(1 for k in key_vals[1:] if k == first)

        # Best affine
        aff_con, params, details = test_affine_direct(period)
        a_vals = [d["a"] for r, d in sorted(details.items()) if isinstance(d["a"], int)]
        gain = aff_con - vig_con
        print(f"  {period:7d} | {vig_con:3d} | {aff_con:11d} | {gain:+4d} | {a_vals[:5]}")

    # ── Summary ─────────────────────────────────────────────────────
    results.sort(key=lambda r: -r["score"])

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Total configs: {configs}")
    print(f"  Hits ≥{STORE_THRESHOLD}: {len(results)}")
    print(f"  Time: {elapsed:.1f}s")
    print(f"  Best score: {best_score}/24")

    if results:
        print(f"\n  Top 10:")
        for r in results[:10]:
            if r["type"] == "direct":
                print(f"    {r['score']}/24 p={r['period']} DIRECT")
            else:
                print(f"    {r['score']}/24 p={r['period']} d={r['direction']} kw={r['keyword']}")

    # Key question: does ANY a-value (other than 1 and 25) appear consistently?
    print(f"\n  Key question: do non-Vigenère a-values help?")
    for period in [5, 7]:
        aff_con, params, details = test_affine_direct(period)
        vig_con = 0
        residue_groups = defaultdict(list)
        for pos in sorted(CRIB_POSITIONS):
            residue_groups[pos % period].append(pos)
        for r, positions in residue_groups.items():
            key_vals = [(CT_IDX[p] - PT_IDX[p]) % MOD for p in positions]
            if key_vals:
                first = key_vals[0]
                vig_con += 1 + sum(1 for k in key_vals[1:] if k == first)

        if aff_con > vig_con:
            print(f"    Period {period}: Affine ({aff_con}) BEATS Vigenère ({vig_con}) by {aff_con - vig_con}")
            for r, d in sorted(details.items()):
                if isinstance(d["a"], int) and d["a"] not in (1, 25) and d["n_consistent"] >= 2:
                    print(f"      Residue {r}: a={d['a']} b={d['b']} "
                          f"({d['n_consistent']}/{d['n_total']} consistent)")
        else:
            print(f"    Period {period}: No improvement (Vig={vig_con}, Affine={aff_con})")

    if best_score <= NOISE_FLOOR:
        verdict = "ELIMINATED — no improvement over Vigenère"
    elif best_score <= 14:
        verdict = f"WEAK — best {best_score}/24"
    else:
        verdict = f"INVESTIGATE — best {best_score}/24"

    print(f"\n  Verdict: {verdict}")

    artifact = {
        "experiment": "E-S-56",
        "total_configs": configs,
        "n_hits": len(results),
        "best_score": best_score,
        "best_config": best_config,
        "verdict": verdict,
        "elapsed_seconds": elapsed,
        "top_20": [
            {k: v for k, v in r.items() if k != "details"}
            for r in results[:20]
        ],
    }

    with open("results/e_s_56_affine_polyalphabetic.json", "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"\n  Artifact: results/e_s_56_affine_polyalphabetic.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_56_affine_polyalphabetic.py")


if __name__ == "__main__":
    main()
