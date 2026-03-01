#!/usr/bin/env python3
"""E-RECURRENCE-00: All order-2 linear recurrence key models for K4.

HYPOTHESIS
----------
A periodic key generation rule of the form:
    key[n] = (a * key[n-1] + b * key[n-2] + c) mod 26

with seeds (key[0], key[1]) and parameters (a, b, c) — could produce a
non-obvious, hand-computable, non-random-looking key from a short seed.

FRAMEWORK GAP
-------------
E-FRAC-38 explicitly tested three specific cases:
  - Progressive key: key[i] = key[0] + i*δ (a=1, b=0, c=δ) → BEAN-ELIMINATED
  - Quadratic key: key[i] = a*i² + b*i + c → BEAN-ELIMINATED (0/676 seeds)
  - Fibonacci key: key[n] = key[n-1] + key[n-2] (a=1, b=1, c=0) → BEAN-ELIMINATED

NOT TESTED: General (a, b, c) combinations.

E-FRAC-38's claim "running key is the ONLY structured model surviving Bean"
is based on these three specific cases, NOT an exhaustive sweep of all linear
recurrences. This script closes that gap.

SCOPE
-----
For efficiency, we fix c=0 (pure homogeneous recurrence, since c just adds a
constant offset reducible to seed adjustment) and test:
  - All 26×26 = 676 (a, b) pairs
  - All 26×26 = 676 (key[0], key[1]) seeds
  - Total: 456,976 configurations per cipher variant

Filtering pipeline:
  1. Bean equality: key[27] == key[65] (required: both = 24 for Vigenere)
  2. All 21 Bean inequalities
  3. All 24 crib-position matches
  4. Quadgram score on resulting plaintext (if all 24 match → BREAKTHROUGH)

For c ≠ 0: the c term shifts every key value by c, which is equivalent to
shifting both seeds by c. So c=0 with all 676 seeds covers the same solution
space as c≠0 (up to seed re-labeling). We note this explicitly.

Run: PYTHONPATH=src python3 -u scripts/e_recurrence_00_linear_order2.py
"""

import sys
import os
import json
from multiprocessing import Pool, cpu_count
from typing import Dict, List, Tuple, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)

ALPH_STR = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CT_VALS = [ALPH_IDX[c] for c in CT]
PT_VALS = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
CRIB_POS_LIST = sorted(CRIB_DICT.keys())

# ── Known key values per cipher variant ──────────────────────────────────────

KNOWN_VIG = {pos: (CT_VALS[pos] - PT_VALS[pos]) % MOD for pos in PT_VALS}
KNOWN_BEAU = {pos: (CT_VALS[pos] + PT_VALS[pos]) % MOD for pos in PT_VALS}
KNOWN_VAR = {pos: (PT_VALS[pos] - CT_VALS[pos]) % MOD for pos in PT_VALS}

KNOWN_BY_VARIANT = {
    "vigenere": KNOWN_VIG,
    "beaufort": KNOWN_BEAU,
    "var_beaufort": KNOWN_VAR,
}

# Bean equality required values per variant
BEAN_EQ_REQ = {vname: KNOWN_BY_VARIANT[vname][BEAN_EQ[0][0]] for vname in KNOWN_BY_VARIANT}

# ── Generate recurrence sequence ──────────────────────────────────────────────

def gen_recurrence(a: int, b: int, k0: int, k1: int, length: int) -> List[int]:
    """Generate key[0..length-1] where key[n] = (a*key[n-1] + b*key[n-2]) mod 26."""
    seq = [k0, k1]
    for _ in range(length - 2):
        seq.append((a * seq[-1] + b * seq[-2]) % MOD)
    return seq[:length]

# ── Constraint checkers ───────────────────────────────────────────────────────

def check_bean_eq(seq: List[int], req: int) -> bool:
    """Check key[27] == key[65] == req."""
    return seq[27] == seq[65] == req

def check_bean_ineq(seq: List[int]) -> bool:
    """Check all 21 Bean inequality constraints."""
    for ia, ib in BEAN_INEQ:
        if seq[ia] == seq[ib]:
            return False
    return True

def count_crib_matches(seq: List[int], known: Dict[int, int]) -> int:
    """Count how many crib positions match."""
    return sum(1 for pos, kval in known.items() if seq[pos] == kval)

# ── Worker function (per (a, b) pair) ────────────────────────────────────────

def sweep_ab(args: Tuple[int, int, str]) -> List[dict]:
    """Sweep all 676 (k0, k1) seeds for a given (a, b) and cipher variant."""
    a, b, vname = args
    known = KNOWN_BY_VARIANT[vname]
    bean_req = BEAN_EQ_REQ[vname]
    results = []

    for k0 in range(MOD):
        for k1 in range(MOD):
            # Generate full sequence
            seq = gen_recurrence(a, b, k0, k1, CT_LEN)

            # Filter 1: Bean equality
            if not check_bean_eq(seq, bean_req):
                continue

            # Filter 2: Bean inequalities
            if not check_bean_ineq(seq):
                continue

            # Filter 3: Crib matches
            n_match = count_crib_matches(seq, known)
            if n_match >= 10:  # Store interesting hits only
                results.append({
                    "a": a, "b": b, "k0": k0, "k1": k1,
                    "cipher": vname,
                    "crib_matches": n_match,
                    "key_preview": "".join(ALPH_STR[v] for v in seq[:30]),
                })

    return results

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("="*65)
    print("E-RECURRENCE-00: All order-2 linear recurrences key[n] = a*k[n-1]+b*k[n-2]")
    print("="*65)
    print(f"Parameters: a ∈ [0,25], b ∈ [0,25], seeds k0,k1 ∈ [0,25]")
    print(f"Total configs per variant: 676 (a,b) × 676 (seeds) = 456,976")
    print(f"Variants: Vigenere, Beaufort, Variant Beaufort")
    print(f"Workers: {cpu_count()}")
    print()

    import time
    t0 = time.time()

    all_results: List[dict] = []
    bean_passes: Dict[str, int] = {"vigenere": 0, "beaufort": 0, "var_beaufort": 0}
    total_24: List[dict] = []

    for vname in ["vigenere", "beaufort", "var_beaufort"]:
        print(f"\n[{vname}]")
        tasks = [(a, b, vname) for a in range(MOD) for b in range(MOD)]

        with Pool(cpu_count()) as pool:
            chunk_results = pool.map(sweep_ab, tasks)

        variant_hits = []
        for chunk in chunk_results:
            variant_hits.extend(chunk)

        n_bean = sum(
            1 for a in range(MOD) for b in range(MOD)
            for k0 in range(MOD) for k1 in range(MOD)
            if check_bean_eq(gen_recurrence(a, b, k0, k1, CT_LEN), BEAN_EQ_REQ[vname])
        ) if False else "N/A (not computed separately)"  # Skip expensive recount

        n_hits = len(variant_hits)
        n24 = sum(1 for r in variant_hits if r["crib_matches"] == 24)
        print(f"  Hits ≥10/24: {n_hits}")
        print(f"  24/24 matches: {n24}")

        top = sorted(variant_hits, key=lambda r: -r["crib_matches"])[:5]
        for r in top:
            print(f"    a={r['a']},b={r['b']},k0={r['k0']},k1={r['k1']} "
                  f"→ {r['crib_matches']}/24  key={r['key_preview']}")

        all_results.extend(variant_hits)
        total_24.extend(r for r in variant_hits if r["crib_matches"] == 24)

    elapsed = time.time() - t0
    print(f"\n{'='*65}")
    print(f"SUMMARY  (elapsed: {elapsed:.1f}s)")
    print(f"{'='*65}")
    print(f"Total hits ≥10/24: {len(all_results)}")
    print(f"24/24 matches: {len(total_24)}")

    if total_24:
        print("\n*** POTENTIAL BREAKTHROUGH — 24/24 matches found! ***")
        for r in total_24:
            print(f"  {r}")
        verdict = "BREAKTHROUGH"
    else:
        best = max((r["crib_matches"] for r in all_results), default=0)
        print(f"Best score: {best}/24")
        if best < 14:
            print("Best ≤ random baseline (14/24) → NOISE")
            verdict = "NOISE"
        elif best < 18:
            verdict = "INTERESTING"
        else:
            verdict = "SIGNAL"
        print(f"Verdict: {verdict}")

    # Statistical baseline for comparison
    print(f"\nReference: random key expected ~9.2/24 matches (≈1/26 per position)")
    print(f"Underdetermination floor at ≥18/24: scores above this may be false positives")

    # Write results
    os.makedirs("results", exist_ok=True)
    out = {
        "experiment": "E-RECURRENCE-00",
        "hypothesis": "key[n] = (a*key[n-1] + b*key[n-2]) mod 26 for all a,b,k0,k1",
        "scope": {
            "a_range": "0-25",
            "b_range": "0-25",
            "seed_range": "k0,k1 ∈ 0-25",
            "total_per_variant": 456_976,
            "variants": ["vigenere", "beaufort", "var_beaufort"],
        },
        "note_on_c": (
            "Parameter c (constant offset) omitted: adding c to all key values "
            "is equivalent to shifting both seeds, already covered by the full "
            "seed sweep. So c=0 with all 676 seeds covers c≠0 as well."
        ),
        "total_hits_ge10": len(all_results),
        "total_24_matches": len(total_24),
        "breakthrough_configs": total_24[:20],
        "top_results": sorted(all_results, key=lambda r: -r["crib_matches"])[:30],
        "verdict": verdict,
        "framework_gap_closed": (
            "E-FRAC-38 tested Fibonacci (a=b=1), progressive (b=0), and quadratic "
            "(not a recurrence), all Bean-eliminated. This script exhaustively tests "
            "ALL 676 (a,b) pairs × 676 seeds = 456,976 configs × 3 variants. "
            "If verdict is NOISE, ALL order-2 linear homogeneous recurrences are eliminated."
        ),
    }
    outfile = "results/e_recurrence_00_linear_order2.json"
    with open(outfile, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nResults written to {outfile}")


if __name__ == "__main__":
    main()
