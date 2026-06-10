"""Phase 3 experiment: independent baseline statistics on K4.

Run on:
- frequency distribution
- index of coincidence
- repeated trigrams + Kasiski gap GCDs
- autocorrelation (suggests period if any)
- the required keystream at the 24 crib positions under
  (AZ, KA) x (vig, beau, vbeau)
- independent re-derivation of Bean equality / inequality counts

Outputs to results/baseline_stats.json for the final report.
"""

import json
import os
import sys
from itertools import combinations
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.dirname(ROOT))

from independent_solve_2026_05_19.src.alphabets import AZ, KA
from independent_solve_2026_05_19.src.stats import (
    frequency,
    index_of_coincidence,
    repeated_ngrams,
    kasiski_gaps,
    autocorrelation,
    keystream_deltas_at_crib,
)
from independent_solve_2026_05_19.src.constraints import (
    CRIB_MAP, keystream_letter, bean_equality_check, bean_inequality_check,
)


CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
EAST = "EASTNORTHEAST"
BERLINCLOCK = "BERLINCLOCK"


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def main():
    report = {}

    # Frequency
    f = frequency(CT)
    report["frequency"] = dict(sorted(f.items()))
    report["alphabet_coverage"] = {ch: f.get(ch, 0) for ch in AZ}

    # IC
    report["index_of_coincidence"] = round(index_of_coincidence(CT), 6)
    report["ic_random_expected"] = round(1.0 / 26, 6)  # 0.03846
    report["ic_english_expected"] = 0.0667
    report["ic_interpretation"] = (
        "K4 IC ~ random; n=97 too short for IC alone to discriminate; "
        "matches kernel-side IC_K4 = 0.0361."
    )

    # Repeated trigrams + Kasiski-style gap analysis
    repeats = repeated_ngrams(CT, n=3)
    report["repeated_trigrams"] = {g: positions for g, positions in repeats.items()}
    gaps = kasiski_gaps(CT, n=3)
    if gaps:
        # GCDs of all gap sizes
        all_gaps = [g for _, g in gaps]
        gap_factors = defaultdict(int)
        for g in all_gaps:
            for d in range(2, min(g + 1, 30)):
                if g % d == 0:
                    gap_factors[d] += 1
        report["kasiski_gap_factor_counts_2_to_29"] = dict(sorted(gap_factors.items()))
    else:
        report["kasiski_gap_factor_counts_2_to_29"] = {}

    # Autocorrelation
    ac = autocorrelation(CT, max_shift=30)
    report["autocorrelation_top_shifts"] = sorted(ac, key=lambda x: x[1], reverse=True)[:10]

    # Keystream at cribs under each variant x alphabet
    deltas = {}
    for op in ("vig", "beau", "vbeau"):
        for alpha_name, alpha in (("AZ", AZ), ("KA", KA)):
            entries_east = keystream_deltas_at_crib(CT, 21, EAST, alpha, op)
            entries_bcl = keystream_deltas_at_crib(CT, 63, BERLINCLOCK, alpha, op)
            ks_letters = "".join(e[3] for e in entries_east) + "|" + "".join(e[3] for e in entries_bcl)
            deltas[f"{op}_{alpha_name}"] = {
                "east_keystream": "".join(e[3] for e in entries_east),
                "bcl_keystream": "".join(e[3] for e in entries_bcl),
                "joined": ks_letters,
            }
    report["crib_position_keystreams"] = deltas

    # Independent Bean check
    bean = {}
    for op in ("vig", "beau", "vbeau"):
        eq = bean_equality_check(op)
        ineq = bean_inequality_check(op)
        bean[op] = {
            "equality_pairs_count": len(eq),
            "inequality_pairs_count": len(ineq),
            "equality_pairs": [list(p) for p in eq],
        }
        assert len(eq) + len(ineq) == 24 * 23 // 2 == 276
    report["bean_independent_rederivation"] = bean

    # Compare against the union across variants (kernel reports 1 eq, 242 ineq union)
    # Reconstruct the variant-independent equality count.
    union_eq = set()
    for op in ("vig", "beau", "vbeau"):
        for p in bean_equality_check(op):
            union_eq.add(p)
    # The set of pairs that are equal under ANY variant.
    # The kernel's BEAN_EQ is variant-independent. Verify:
    invariant_eq = set()
    for i, j in combinations(sorted(CRIB_MAP), 2):
        ci, pi = CRIB_MAP[i]
        cj, pj = CRIB_MAP[j]
        # k[i]=k[j] under all 3 ops iff (ci-pi)=(cj-pj) AND (ci+pi)=(cj+pj) AND (pi-ci)=(pj-cj),
        # which reduces to ci=cj AND pi=pj.
        if ci == cj and pi == pj:
            invariant_eq.add((i, j))
    report["bean_variant_invariant_equality_pairs"] = sorted(list(invariant_eq))
    report["bean_variant_invariant_equality_count"] = len(invariant_eq)

    # K1/K2-context keystream pattern look: does any 7-char or 14-char
    # window of the EAST/BERLIN keystreams look like a known Kryptos word?
    interesting = []
    candidates = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK",
                  "BERLINCLOCK", "EAST", "NORTHEAST", "EASTNORTHEAST",
                  "WORLD", "LANGLEY", "WEBSTER", "CARTER", "TUTANKHAMUN",
                  "LAYERTWO", "INVISIBLE", "SHADOW", "FORCES", "ATBASH"]
    for k, v in deltas.items():
        full = v["east_keystream"] + v["bcl_keystream"]
        for cand in candidates:
            if cand in full:
                interesting.append({"variant": k, "keyword": cand, "context": full})
    report["keystream_keyword_substring_matches"] = interesting

    # Write report
    out_path = os.path.join(ROOT, "results", "baseline_stats.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    # Summary to stdout
    print(f"baseline_stats: wrote {out_path}")
    print(f"  IC                 : {report['index_of_coincidence']}")
    print(f"  repeated trigrams  : {len(repeats)}")
    print(f"  top autocorr shifts: {report['autocorrelation_top_shifts'][:3]}")
    print(f"  Bean variant-invariant equality pairs: {report['bean_variant_invariant_equality_count']}")
    print(f"    -> {report['bean_variant_invariant_equality_pairs']}")
    print(f"  Per-variant equality pair counts:")
    for op, b in bean.items():
        print(f"    {op}: eq={b['equality_pairs_count']} ineq={b['inequality_pairs_count']}")
    print(f"  Keystream keyword substring matches: {len(interesting)}")
    for m in interesting:
        print(f"    {m['variant']:>10s}  contains  {m['keyword']!r}")
    print("\n  Crib-position keystreams (the required keystream at the 24 known plaintext positions):")
    for k, v in deltas.items():
        print(f"    {k:>10s}  EAST={v['east_keystream']}  BCL={v['bcl_keystream']}")


if __name__ == "__main__":
    main()
