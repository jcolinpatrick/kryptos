#!/usr/bin/env python3 -u
"""
=================================================================
ARGENTI NULL RULE SEARCH v1
=================================================================
Cipher:     Stego layer (null position determination)
Family:     campaigns
Status:     active
Keyspace:   ~500K simple predicate rules

Can we find a SIMPLE rule f(CT[p], p) → {null, real} that predicts
ALL 24 null positions from the ciphertext alone?

The (pos%7,pos%5) table gets 35/35 on palette positions but:
  - Has 0 degrees of freedom (post-hoc fit)
  - Only classifies palette characters, not the 7 varying non-palette nulls
  - The N/R cell assignments have no known generating rule

This script searches for a UNIFIED rule covering BOTH palette and
non-palette null positions, tested against:
  - 17 consensus nulls (MUST predict null)
  - 24 crib positions (MUST predict real)
  - Predict exactly 24 nulls total (7 remaining TBD)
=================================================================

QUARANTINE 2026-04-17
---------------------
This script depends on the retired palette / consensus-null construct and is
retained only as a historical artifact. Execution requires
`--allow-retired-construct`.
"""

import sys
import os
import json
import time
from itertools import combinations

if "--allow-retired-construct" not in sys.argv:
    print(
        "Refusing to run: this campaign depends on the retired palette / "
        "consensus-null construct and is quarantined as a historical "
        "artifact. Re-run only with --allow-retired-construct for "
        "explicit reproducibility work.",
        file=sys.stderr,
    )
    raise SystemExit(2)

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT

# ── Constants ──────────────────────────────────────────────────────────

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}

CT_AZ = [ALPH_IDX[c] for c in CT]  # AZ indices
CT_KA = [KA_IDX[c] for c in CT]    # KA indices

CONSENSUS_NULLS = {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}
CRIB_POS = set(CRIB_DICT.keys())
PALETTE = set("BGIKOWZ")

# Known status
KNOWN_NULL = CONSENSUS_NULLS  # 17 positions, MUST be null
KNOWN_REAL = CRIB_POS         # 24 positions, MUST be real
UNKNOWN = set(range(97)) - KNOWN_NULL - KNOWN_REAL  # 56 positions

print(f"Known null: {len(KNOWN_NULL)}, Known real: {len(KNOWN_REAL)}, Unknown: {len(UNKNOWN)}")
print(f"Need to find: 7 more nulls among {len(UNKNOWN)} unknown positions")

# Varying ranges (from SA convergence)
VARY_A = set(range(38, 46))   # pick 3
VARY_B = {55, 56}             # pick 1
VARY_C = {87, 88}             # pick 1
VARY_D = {93, 94, 95, 96}     # pick 2

# ── Rule testing engine ───────────────────────────────────────────────

def test_rule(null_set):
    """Test if a predicted null set is consistent with known constraints.
    Returns (passes, n_null, n_correct_consensus, n_wrong_real)."""
    # Must include all consensus nulls
    consensus_correct = len(null_set & KNOWN_NULL)
    # Must NOT include any crib positions
    crib_wrong = len(null_set & KNOWN_REAL)
    # Must have exactly 24 nulls
    passes = (consensus_correct == 17 and crib_wrong == 0 and len(null_set) == 24)
    return passes, len(null_set), consensus_correct, crib_wrong


def evaluate_rule(rule_func, desc):
    """Apply rule to all 97 positions, check constraints."""
    null_set = set()
    for p in range(97):
        if rule_func(p):
            null_set.add(p)
    passes, n_null, n_cons, n_wrong = test_rule(null_set)
    if passes:
        varying = null_set - KNOWN_NULL
        return {
            "desc": desc,
            "n_null": n_null,
            "varying_nulls": sorted(varying),
            "varying_chars": "".join(CT[p] for p in sorted(varying)),
            "in_clusters": all(
                p in VARY_A | VARY_B | VARY_C | VARY_D | {20, 36, 48, 58, 74}
                for p in varying
            ),
        }
    return None


# ── Rule families ──────────────────────────────────────────────────────

def search_modular_rules():
    """Rules of form: (a * char_idx + b * pos + c) mod M < threshold."""
    print("\n  Family 1: (a*CT_val + b*pos + c) mod M < T", flush=True)
    hits = []
    count = 0

    for use_ka in [False, True]:
        ct_vals = CT_KA if use_ka else CT_AZ
        alph_name = "KA" if use_ka else "AZ"

        for M in range(2, 40):
            for a in range(M):
                for b in range(M):
                    for c in range(M):
                        for T in range(1, M):
                            count += 1
                            def rule(p, _a=a, _b=b, _c=c, _M=M, _T=T, _v=ct_vals):
                                return (_a * _v[p] + _b * p + _c) % _M < _T
                            result = evaluate_rule(rule, f"{alph_name}:({a}*v+{b}*p+{c})%{M}<{T}")
                            if result:
                                hits.append(result)

    print(f"    Tested {count:,} rules, found {len(hits)} valid", flush=True)
    return hits


def search_modular_equality():
    """Rules of form: (a * char_idx + b * pos) mod M == target."""
    print("\n  Family 2: (a*CT_val + b*pos) mod M == target", flush=True)
    hits = []
    count = 0

    for use_ka in [False, True]:
        ct_vals = CT_KA if use_ka else CT_AZ
        alph_name = "KA" if use_ka else "AZ"

        for M in range(2, 40):
            for a in range(M):
                for b in range(M):
                    for target in range(M):
                        count += 1
                        def rule(p, _a=a, _b=b, _M=M, _t=target, _v=ct_vals):
                            return (_a * _v[p] + _b * p) % _M == _t
                        result = evaluate_rule(rule, f"{alph_name}:({a}*v+{b}*p)%{M}=={target}")
                        if result:
                            hits.append(result)

    print(f"    Tested {count:,} rules, found {len(hits)} valid", flush=True)
    return hits


def search_sum_mod():
    """Rules of form: (CT_val + pos) mod M in target_set."""
    print("\n  Family 3: (CT_val + pos) mod M in target_set (up to 3 targets)", flush=True)
    hits = []
    count = 0

    for use_ka in [False, True]:
        ct_vals = CT_KA if use_ka else CT_AZ
        alph_name = "KA" if use_ka else "AZ"

        for M in range(2, 30):
            # Compute (CT_val + pos) mod M for all positions
            vals = [(ct_vals[p] + p) % M for p in range(97)]

            # What values do the 17 consensus nulls have?
            null_vals = set(vals[p] for p in KNOWN_NULL)
            # What values do the 24 crib positions have?
            real_vals = set(vals[p] for p in KNOWN_REAL)

            # Target set must include all null_vals and exclude all real_vals
            # (for the rule to get consensus right and not hit cribs)
            candidate_targets = null_vals - real_vals
            if not candidate_targets or null_vals & real_vals:
                # Some null value is also a real value — can't separate
                continue

            # The null set would be: all positions where (v+p)%M in null_vals
            null_set = {p for p in range(97) if vals[p] in null_vals}
            count += 1
            result_data = test_rule(null_set)
            if result_data[0]:
                varying = null_set - KNOWN_NULL
                hits.append({
                    "desc": f"{alph_name}:(v+p)%{M} in {sorted(null_vals)}",
                    "n_null": len(null_set),
                    "varying_nulls": sorted(varying),
                    "varying_chars": "".join(CT[p] for p in sorted(varying)),
                    "in_clusters": all(p in VARY_A | VARY_B | VARY_C | VARY_D | {20,36,48,58,74} for p in varying),
                })

            # Also try (CT_val * pos) mod M
            vals2 = [(ct_vals[p] * (p + 1)) % M for p in range(97)]
            null_vals2 = set(vals2[p] for p in KNOWN_NULL)
            real_vals2 = set(vals2[p] for p in KNOWN_REAL)
            if null_vals2 and not (null_vals2 & real_vals2):
                null_set2 = {p for p in range(97) if vals2[p] in null_vals2}
                count += 1
                r2 = test_rule(null_set2)
                if r2[0]:
                    varying2 = null_set2 - KNOWN_NULL
                    hits.append({
                        "desc": f"{alph_name}:(v*(p+1))%{M} in {sorted(null_vals2)}",
                        "n_null": len(null_set2),
                        "varying_nulls": sorted(varying2),
                        "varying_chars": "".join(CT[p] for p in sorted(varying2)),
                        "in_clusters": all(p in VARY_A | VARY_B | VARY_C | VARY_D | {20,36,48,58,74} for p in varying2),
                    })

    print(f"    Tested {count:,} rules, found {len(hits)} valid", flush=True)
    return hits


def search_xor_rules():
    """Rules of form: CT_val XOR pos satisfies condition."""
    print("\n  Family 4: bitwise (CT_val XOR pos) mod M == target", flush=True)
    hits = []
    count = 0

    for use_ka in [False, True]:
        ct_vals = CT_KA if use_ka else CT_AZ
        alph_name = "KA" if use_ka else "AZ"

        for M in range(2, 30):
            vals = [(ct_vals[p] ^ p) % M for p in range(97)]
            null_vals = set(vals[p] for p in KNOWN_NULL)
            real_vals = set(vals[p] for p in KNOWN_REAL)

            if null_vals and not (null_vals & real_vals):
                null_set = {p for p in range(97) if vals[p] in null_vals}
                count += 1
                r = test_rule(null_set)
                if r[0]:
                    varying = null_set - KNOWN_NULL
                    hits.append({
                        "desc": f"{alph_name}:(v^p)%{M} in {sorted(null_vals)}",
                        "n_null": len(null_set),
                        "varying_nulls": sorted(varying),
                        "varying_chars": "".join(CT[p] for p in sorted(varying)),
                        "in_clusters": all(p in VARY_A | VARY_B | VARY_C | VARY_D | {20,36,48,58,74} for p in varying),
                    })

    print(f"    Tested {count:,} rules, found {len(hits)} valid", flush=True)
    return hits


def search_compound_rules():
    """Compound: palette rule + secondary rule for non-palette positions."""
    print("\n  Family 5: Palette + secondary rule for non-palette nulls", flush=True)
    hits = []

    # Palette nulls: positions where CT[p] in palette AND (pos%7,pos%5) = N-cell
    # These give us 17 consensus nulls. We need 7 more from non-palette positions.
    # The 7 must come from the varying ranges.

    # For the secondary rule: test simple predicates on non-palette positions
    non_palette_unknown = [p for p in UNKNOWN if CT[p] not in PALETTE]

    # Which of these are in the varying ranges?
    in_vary = [p for p in non_palette_unknown
               if p in VARY_A | VARY_B | VARY_C | VARY_D]

    print(f"    Non-palette unknown positions: {len(non_palette_unknown)}")
    print(f"    In varying ranges: {len(in_vary)} = {sorted(in_vary)}")

    # Characters at these positions
    for p in in_vary:
        print(f"      pos {p:>2}: CT={CT[p]} AZ={CT_AZ[p]:>2} KA={CT_KA[p]:>2} "
              f"p%7={p%7} p%5={p%5} p%35={p%35}")

    # Test: for each way to pick 7 from in_vary that gives 24 total nulls
    # (17 consensus + 7 new), check if any simple arithmetic rule selects them

    # Since we need exactly 7, and they should distribute as 3+1+1+2 in clusters,
    # enumerate cluster-constrained selections and check for simple rules
    count = 0
    for a_picks in combinations([p for p in in_vary if p in VARY_A], 3):
        for b_pick in [p for p in in_vary if p in VARY_B]:
            for c_pick in [p for p in in_vary if p in VARY_C]:
                for d_picks in combinations([p for p in in_vary if p in VARY_D], 2):
                    seven = set(a_picks) | {b_pick, c_pick} | set(d_picks)
                    if len(seven) != 7:
                        continue
                    full_nulls = KNOWN_NULL | seven
                    if len(full_nulls) != 24:
                        continue
                    # Check no crib overlap
                    if full_nulls & KNOWN_REAL:
                        continue
                    count += 1

                    # Test simple rules on this specific 24-null set
                    for M in range(2, 40):
                        for use_ka in [False, True]:
                            ct_vals = CT_KA if use_ka else CT_AZ
                            vals = [(ct_vals[p] + p) % M for p in range(97)]
                            null_target_vals = set(vals[p] for p in full_nulls)
                            real_check_vals = set(vals[p] for p in KNOWN_REAL)
                            if not (null_target_vals & real_check_vals):
                                predicted = {p for p in range(97) if vals[p] in null_target_vals}
                                if predicted == full_nulls:
                                    alph = "KA" if use_ka else "AZ"
                                    hits.append({
                                        "desc": f"EXACT {alph}:(v+p)%{M} in {sorted(null_target_vals)}",
                                        "n_null": 24,
                                        "varying_nulls": sorted(seven),
                                        "varying_chars": "".join(CT[p] for p in sorted(seven)),
                                        "in_clusters": True,
                                        "exact_match": True,
                                    })

    print(f"    Tested {count:,} cluster-constrained masks × modular rules", flush=True)
    print(f"    Found {len(hits)} exact rule matches", flush=True)
    return hits


# ── Main ───────────────────────────────────────────────────────────────

def main():
    t_start = time.time()
    print("=" * 70)
    print("ARGENTI NULL RULE SEARCH v1")
    print("=" * 70)

    all_hits = []

    # Family 3 and 4 are fast — do them first
    all_hits.extend(search_sum_mod())
    all_hits.extend(search_xor_rules())

    # Family 5: compound rules (cluster-constrained)
    all_hits.extend(search_compound_rules())

    # Family 2: modular equality (medium — ~100K rules)
    all_hits.extend(search_modular_equality())

    # Family 1: modular threshold (large — ~500K rules, skip if M kept small)
    # Only test small M to keep runtime reasonable
    print("\n  Family 1: threshold rules (M ≤ 10 only for speed)", flush=True)
    hits1 = []
    count1 = 0
    for use_ka in [False, True]:
        ct_vals = CT_KA if use_ka else CT_AZ
        alph_name = "KA" if use_ka else "AZ"
        for M in range(2, 11):
            for a in range(M):
                for b in range(M):
                    for c in range(M):
                        for T in range(1, M):
                            count1 += 1
                            null_set = {p for p in range(97)
                                        if (a * ct_vals[p] + b * p + c) % M < T}
                            passes, n_null, n_cons, n_wrong = test_rule(null_set)
                            if passes:
                                varying = null_set - KNOWN_NULL
                                hits1.append({
                                    "desc": f"{alph_name}:({a}*v+{b}*p+{c})%{M}<{T}",
                                    "n_null": n_null,
                                    "varying_nulls": sorted(varying),
                                    "varying_chars": "".join(CT[p] for p in sorted(varying)),
                                    "in_clusters": all(
                                        p in VARY_A | VARY_B | VARY_C | VARY_D | {20,36,48,58,74}
                                        for p in varying
                                    ),
                                })
    print(f"    Tested {count1:,} rules, found {len(hits1)} valid", flush=True)
    all_hits.extend(hits1)

    # Report
    elapsed = time.time() - t_start
    print(f"\n{'='*70}")
    print(f"RESULTS ({elapsed:.1f}s)")
    print(f"{'='*70}")
    print(f"  Total valid rules (predict 17 consensus + 7 more = 24, no crib overlap): {len(all_hits)}")

    if all_hits:
        # Group by varying nulls prediction
        by_prediction = {}
        for h in all_hits:
            key = tuple(h["varying_nulls"])
            if key not in by_prediction:
                by_prediction[key] = []
            by_prediction[key].append(h)

        print(f"\n  Distinct 7-position predictions: {len(by_prediction)}")
        print(f"\n  {'Varying nulls':<35} {'#Rules':>6} {'InClust':>8} {'Chars':>10} Example rule")
        print(f"  {'─'*35} {'─'*6} {'─'*8} {'─'*10} {'─'*40}")

        for pred, rules in sorted(by_prediction.items(), key=lambda x: -len(x[1])):
            example = rules[0]
            print(f"  {str(list(pred)):<35} {len(rules):>6} "
                  f"{'YES' if example['in_clusters'] else 'no':>8} "
                  f"{example['varying_chars']:>10} {example['desc'][:40]}")

        # Highlight exact matches from compound search
        exact = [h for h in all_hits if h.get("exact_match")]
        if exact:
            print(f"\n  *** EXACT RULE MATCHES (predict EXACTLY the right 24 positions): ***")
            for h in exact:
                print(f"    {h['desc']}")
                print(f"    Varying: {h['varying_nulls']} = {h['varying_chars']}")
    else:
        print(f"\n  NO simple rule found that predicts all 24 null positions.")
        print(f"  The null insertion rule is either:")
        print(f"    (a) more complex than tested (needs 2+ conditions)")
        print(f"    (b) depends on the key (not derivable from CT alone)")
        print(f"    (c) is a lookup table with no compact formula")

    # Save
    output_path = os.path.join(_ROOT, "results", "f_argenti_null_rule_v1.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({
            "experiment": "argenti_null_rule_v1",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "elapsed": elapsed,
            "total_hits": len(all_hits),
            "hits": all_hits[:100],
        }, f, indent=2)
    print(f"\n  Results: {output_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()
