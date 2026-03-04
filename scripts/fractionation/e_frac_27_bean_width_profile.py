#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-27: Bean-Compatible Width Profiling.

Systematic structural profiling of widths 5-15 for Bean constraint compatibility.
E-FRAC-26 found: width-7 has ZERO Bean-passing configs while width-9 has 67,320.
This experiment maps out ALL widths to identify which are structurally compatible
with the Bean constraint and which are not.

For each width:
1. Exhaustive (if w! <= 500K) or sampled (otherwise) orderings
2. Decompose Bean check: equality vs full (equality + 21 inequalities)
3. Compute quadgram scores for Bean-passing configs
4. Identify the structural reason WHY certain widths fail Bean

Key insight from E-FRAC-26: Bean equality requires CT[inv(27)] = CT[inv(65)]
regardless of cipher variant. Since PT[27] = PT[65] = 'R', the constraint reduces
to matching CT letters at the two positions that map to PT positions 27 and 65.
"""
import itertools
import json
import math
import os
import random
import time
from collections import Counter, defaultdict

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def load_quadgrams(path="data/english_quadgrams.json"):
    with open(path) as f:
        qgrams = json.load(f)
    floor = min(qgrams.values()) - 1.0
    return qgrams, floor


QGRAMS, QFLOOR = load_quadgrams()


def quadgram_score(text):
    if len(text) < 4:
        return QFLOOR
    total = 0.0
    n = 0
    for i in range(len(text) - 3):
        qg = text[i:i + 4]
        total += QGRAMS.get(qg, QFLOOR)
        n += 1
    return total / n if n > 0 else QFLOOR


def build_col_heights(width, length):
    n_rows = length // width
    remainder = length % width
    return [n_rows + 1 if j < remainder else n_rows for j in range(width)]


def build_columnar_inv_perm(order, width, col_heights):
    """Build inverse permutation: inv_perm[pt_pos] = ct_pos."""
    enc_perm = []
    for c in order:
        height = col_heights[c]
        for row in range(height):
            enc_perm.append(row * width + c)
    inv_perm = [0] * len(enc_perm)
    for k, pt_pos in enumerate(enc_perm):
        inv_perm[pt_pos] = k
    return inv_perm


def check_bean_equality(inv_perm):
    """Check ONLY Bean equality (k[27] = k[65]).

    Since PT[27] = PT[65] = 'R', this reduces to CT[inv(27)] = CT[inv(65)].
    """
    for eq_a, eq_b in BEAN_EQ:
        ct_pos_a = inv_perm[eq_a]
        ct_pos_b = inv_perm[eq_b]
        if CT_NUM[ct_pos_a] != CT_NUM[ct_pos_b]:
            return False
    return True


def check_bean_inequality(inv_perm, variant):
    """Check Bean inequality constraints (21 pairs that must differ)."""
    for ineq_a, ineq_b in BEAN_INEQ:
        ct_a = CT_NUM[inv_perm[ineq_a]]
        pt_a = CRIB_PT_NUM[ineq_a]
        ct_b = CT_NUM[inv_perm[ineq_b]]
        pt_b = CRIB_PT_NUM[ineq_b]

        if variant == "vigenere":
            k_a = (ct_a - pt_a) % MOD
            k_b = (ct_b - pt_b) % MOD
        elif variant == "beaufort":
            k_a = (ct_a + pt_a) % MOD
            k_b = (ct_b + pt_b) % MOD
        else:
            k_a = (pt_a - ct_a) % MOD
            k_b = (pt_b - ct_b) % MOD

        if k_a == k_b:
            return False
    return True


def derive_and_decrypt(inv_perm, variant, period):
    """Derive majority-vote key and decrypt. Returns (crib_score, pt_text)."""
    residue_keys = defaultdict(list)
    for pt_pos in CRIB_POS:
        ct_pos = inv_perm[pt_pos]
        ct_val = CT_NUM[ct_pos]
        pt_val = CRIB_PT_NUM[pt_pos]
        if variant == "vigenere":
            k = (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            k = (ct_val + pt_val) % MOD
        else:
            k = (pt_val - ct_val) % MOD
        residue_keys[pt_pos % period].append(k)

    key = [0] * period
    crib_score = 0
    for r in range(period):
        keys = residue_keys.get(r, [])
        if not keys:
            continue
        counts = Counter(keys)
        best_val, best_count = counts.most_common(1)[0]
        key[r] = best_val
        crib_score += best_count

    pt_nums = [0] * CT_LEN
    for j in range(CT_LEN):
        ct_pos = inv_perm[j]
        ct_val = CT_NUM[ct_pos]
        k = key[j % period]
        if variant == "vigenere":
            pt_nums[j] = (ct_val - k) % MOD
        elif variant == "beaufort":
            pt_nums[j] = (k - ct_val) % MOD
        else:
            pt_nums[j] = (ct_val + k) % MOD

    return crib_score, "".join(ALPH[v] for v in pt_nums)


def analyze_bean_positions(width):
    """Analyze which CT position pairs are reachable for Bean equality positions."""
    col_heights = build_col_heights(width, CT_LEN)

    # PT position 27: row = 27 // width, col = 27 % width
    # PT position 65: row = 65 // width, col = 65 % width
    row_27 = 27 // width
    col_27 = 27 % width
    row_65 = 65 // width
    col_65 = 65 % width

    # Check if both positions exist in the grid
    if row_27 >= col_heights[col_27] or row_65 >= col_heights[col_65]:
        return {"valid": False, "reason": "positions out of grid bounds"}

    # For each ordering, the CT position depends on column placement
    # CT[inv(27)] depends on where col_27 appears in the order
    # CT[inv(65)] depends on where col_65 appears in the order
    # Bean equality: CT_NUM[inv(27)] == CT_NUM[inv(65)]

    # Enumerate all possible (ct_pos_27, ct_pos_65) pairs
    pair_counts = Counter()
    n_match = 0
    n_total = 0

    # If same column, they always have the same column offset
    if col_27 == col_65:
        # Both in same column — the difference in their CT positions is always
        # (row_65 - row_27), regardless of ordering
        # So only one pair is possible per ordering
        for order in itertools.permutations(range(width)):
            inv_perm = build_columnar_inv_perm(order, width, col_heights)
            ct_a = inv_perm[27]
            ct_b = inv_perm[65]
            pair_counts[(ct_a, ct_b)] += 1
            if CT_NUM[ct_a] == CT_NUM[ct_b]:
                n_match += 1
            n_total += 1
            if n_total >= 100000:
                break
    else:
        # Different columns — CT positions depend on relative order
        for order in itertools.permutations(range(width)):
            inv_perm = build_columnar_inv_perm(order, width, col_heights)
            ct_a = inv_perm[27]
            ct_b = inv_perm[65]
            pair_counts[(ct_a, ct_b)] += 1
            if CT_NUM[ct_a] == CT_NUM[ct_b]:
                n_match += 1
            n_total += 1
            if n_total >= 100000:
                break

    # What CT letters are at the reachable positions?
    positions_27 = set()
    positions_65 = set()
    for (a, b), count in pair_counts.items():
        positions_27.add(a)
        positions_65.add(b)

    letters_27 = {CT[p] for p in positions_27}
    letters_65 = {CT[p] for p in positions_65}
    common_letters = letters_27 & letters_65

    return {
        "valid": True,
        "row_27": row_27, "col_27": col_27,
        "row_65": row_65, "col_65": col_65,
        "same_column": col_27 == col_65,
        "n_unique_pairs": len(pair_counts),
        "n_match": n_match,
        "n_total": n_total,
        "match_rate": n_match / n_total if n_total > 0 else 0,
        "reachable_ct_27": sorted(positions_27),
        "reachable_ct_65": sorted(positions_65),
        "letters_27": sorted(letters_27),
        "letters_65": sorted(letters_65),
        "common_letters": sorted(common_letters),
    }


def profile_width(width, max_orderings=500000):
    """Profile a single width for Bean compatibility + quadgram scoring."""
    col_heights = build_col_heights(width, CT_LEN)
    n_perms = math.factorial(width)
    exhaustive = n_perms <= max_orderings

    variants = ["vigenere", "beaufort", "variant_beaufort"]
    periods = [3, 4, 5, 6, 7]

    if exhaustive:
        orderings = itertools.permutations(range(width))
        n_total = n_perms
    else:
        rng = random.Random(42 + width)
        orderings = []
        for _ in range(max_orderings):
            order = list(range(width))
            rng.shuffle(order)
            orderings.append(tuple(order))
        n_total = max_orderings

    n_tested = 0
    n_eq_pass = 0  # Bean equality only
    n_full_pass = {v: 0 for v in variants}  # Full Bean (eq + ineq)
    best_quadgram_any = -999.0
    best_quadgram_bean = {v: -999.0 for v in variants}
    best_result_any = None
    best_result_bean = {v: None for v in variants}

    t0 = time.time()
    last_report = t0

    for order in orderings:
        order = tuple(order)
        inv_perm = build_columnar_inv_perm(order, width, col_heights)
        n_tested += 1

        eq_pass = check_bean_equality(inv_perm)
        if eq_pass:
            n_eq_pass += 1

        for variant in variants:
            if eq_pass:
                ineq_pass = check_bean_inequality(inv_perm, variant)
                full_pass = ineq_pass
            else:
                full_pass = False

            if full_pass:
                n_full_pass[variant] += 1

            # Score with quadgrams for best overall and best Bean-passing
            for period in periods:
                crib_score, pt_text = derive_and_decrypt(inv_perm, variant, period)
                q = quadgram_score(pt_text)

                if q > best_quadgram_any:
                    best_quadgram_any = q
                    best_result_any = {
                        "order": list(order), "variant": variant,
                        "period": period, "crib_score": crib_score,
                        "quadgram": round(q, 4),
                        "bean_eq": eq_pass, "bean_full": full_pass,
                        "plaintext": pt_text[:50],
                    }

                if full_pass and q > best_quadgram_bean[variant]:
                    best_quadgram_bean[variant] = q
                    best_result_bean[variant] = {
                        "order": list(order), "variant": variant,
                        "period": period, "crib_score": crib_score,
                        "quadgram": round(q, 4),
                        "plaintext": pt_text[:50],
                    }

        now = time.time()
        if now - last_report > 30:
            pct = 100 * n_tested / n_total
            print(f"    w={width} [{pct:5.1f}%] tested={n_tested:,}/{n_total:,}, "
                  f"eq_pass={n_eq_pass:,}")
            last_report = now

    elapsed = time.time() - t0

    # Best Bean quadgram across all variants
    best_bean_q_overall = max(best_quadgram_bean.values())
    best_bean_result = None
    for v in variants:
        if best_quadgram_bean[v] == best_bean_q_overall and best_result_bean[v]:
            best_bean_result = best_result_bean[v]
            break

    return {
        "width": width,
        "n_total": n_total,
        "exhaustive": exhaustive,
        "n_tested": n_tested,
        "n_eq_pass": n_eq_pass,
        "eq_pass_rate": round(n_eq_pass / n_tested, 6),
        "n_full_pass": {v: n_full_pass[v] for v in variants},
        "total_full_pass": sum(n_full_pass.values()),
        "full_pass_rate": round(sum(n_full_pass.values()) / (n_tested * len(variants)), 6),
        "best_quadgram_any": round(best_quadgram_any, 4),
        "best_quadgram_bean": round(best_bean_q_overall, 4) if best_bean_q_overall > -900 else None,
        "best_result_any": best_result_any,
        "best_result_bean": best_bean_result,
        "elapsed_seconds": round(elapsed, 1),
    }


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-FRAC-27: Bean-Compatible Width Profiling (Widths 5-15)")
    print("=" * 70)
    print()
    print("E-FRAC-26 found: width-7 has ZERO Bean-passing configs,")
    print("width-9 has 67,320 (1.24%). This profiles ALL widths.")
    print()

    widths = list(range(5, 16))  # 5 through 15
    results = {}

    # ── Part 1: Structural analysis of Bean positions per width ──
    print("Part 1: Bean Equality Position Analysis")
    print("-" * 60)
    print(f"  Bean requires CT[inv(27)] = CT[inv(65)]")
    print(f"  PT[27] = PT[65] = 'R' → constraint is variant-independent")
    print()

    bean_analysis = {}
    for width in widths:
        info = analyze_bean_positions(width)
        bean_analysis[width] = info
        if info["valid"]:
            print(f"  w={width:2d}: pos27 at (row={info['row_27']}, col={info['col_27']}), "
                  f"pos65 at (row={info['row_65']}, col={info['col_65']}), "
                  f"same_col={info['same_column']}, "
                  f"eq_matches={info['n_match']}/{info['n_total']} "
                  f"({100*info['match_rate']:.1f}%)")
            print(f"         letters_27={info['letters_27']}, "
                  f"letters_65={info['letters_65']}, "
                  f"common={info['common_letters']}")
        else:
            print(f"  w={width:2d}: {info['reason']}")

    # ── Part 2: Width profiling ─────────────────────────────────
    print()
    print("Part 2: Width Profiling (Bean + Quadgram)")
    print("-" * 60)

    for width in widths:
        n_perms = math.factorial(width)
        if n_perms <= 500000:
            print(f"\n  Width {width}: exhaustive ({n_perms:,} orderings)")
        else:
            print(f"\n  Width {width}: sampled (50,000 of {n_perms:,} orderings)")

        profile = profile_width(width, max_orderings=50000)
        results[width] = profile

        print(f"    Tested: {profile['n_tested']:,} orderings")
        print(f"    Bean eq pass: {profile['n_eq_pass']:,} ({100*profile['eq_pass_rate']:.2f}%)")
        print(f"    Bean full pass: {profile['total_full_pass']:,} "
              f"({100*profile['full_pass_rate']:.2f}%)")
        print(f"    Best quadgram (any): {profile['best_quadgram_any']:.4f}")
        bq = profile['best_quadgram_bean']
        print(f"    Best quadgram (Bean): {bq if bq is not None else 'N/A'}")
        print(f"    Time: {profile['elapsed_seconds']}s")

    # ── Part 3: Summary table ─────────────────────────────────
    print()
    print("Part 3: Summary Table")
    print("=" * 90)
    print(f"  {'Width':>5s}  {'Tested':>8s}  {'Exh?':>4s}  "
          f"{'EqPass':>8s}  {'EqRate':>8s}  "
          f"{'FullPass':>8s}  {'FullRate':>8s}  "
          f"{'BestQ(any)':>10s}  {'BestQ(Bean)':>11s}")
    print(f"  {'-'*5}  {'-'*8}  {'-'*4}  "
          f"{'-'*8}  {'-'*8}  "
          f"{'-'*8}  {'-'*8}  "
          f"{'-'*10}  {'-'*11}")

    for width in widths:
        r = results[width]
        exh = "Y" if r["exhaustive"] else "N"
        bq = f"{r['best_quadgram_bean']:.4f}" if r['best_quadgram_bean'] is not None else "N/A"
        print(f"  {width:5d}  {r['n_tested']:8,}  {exh:>4s}  "
              f"{r['n_eq_pass']:8,}  {100*r['eq_pass_rate']:7.2f}%  "
              f"{r['total_full_pass']:8,}  {100*r['full_pass_rate']:7.2f}%  "
              f"{r['best_quadgram_any']:10.4f}  {bq:>11s}")

    # ── Part 4: Bean-zero widths vs Bean-nonzero ──────────────
    print()
    print("Part 4: Bean Compatibility Classification")
    print("-" * 60)

    bean_zero = [w for w in widths if results[w]['total_full_pass'] == 0]
    bean_nonzero = [w for w in widths if results[w]['total_full_pass'] > 0]

    print(f"\n  Bean-INCOMPATIBLE widths (zero full passes): {bean_zero}")
    print(f"  Bean-COMPATIBLE widths (nonzero full passes): {bean_nonzero}")

    if bean_nonzero:
        print(f"\n  Best Bean-passing quadgrams by width:")
        for w in sorted(bean_nonzero):
            r = results[w]
            bq = r['best_quadgram_bean']
            br = r.get('best_result_bean')
            if br:
                print(f"    w={w:2d}: q={bq:.4f} {br['variant'][:4]} p={br['period']} "
                      f"crib={br['crib_score']}/24")
                print(f"          PT: {br['plaintext']}")

    # ── Part 5: Structural explanation ─────────────────────────
    print()
    print("Part 5: Structural Explanation")
    print("-" * 60)
    print()

    for width in bean_zero:
        info = bean_analysis.get(width)
        if info and info["valid"]:
            if info["n_match"] == 0:
                print(f"  w={width}: Bean equality ALWAYS fails.")
                print(f"    pos27 col={info['col_27']}, pos65 col={info['col_65']}")
                print(f"    Reachable CT letters for pos27: {info['letters_27']}")
                print(f"    Reachable CT letters for pos65: {info['letters_65']}")
                print(f"    Common letters: {info['common_letters']}")
                if not info['common_letters']:
                    print(f"    → NO COMMON LETTERS. Width-{width} is STRUCTURALLY IMPOSSIBLE.")
                else:
                    print(f"    → Common letters exist but no ordering maps both to matching CT positions.")
            else:
                print(f"  w={width}: Bean equality passes for {info['n_match']} orderings, "
                      f"but ALL fail inequalities.")

    # ── Verdict ───────────────────────────────────────────────
    print()
    print("=" * 70)
    print("VERDICT")
    print("=" * 70)

    if bean_nonzero:
        best_width = max(bean_nonzero,
                        key=lambda w: results[w]['best_quadgram_bean'] or -999)
        best_q = results[best_width]['best_quadgram_bean']
        print(f"\n  Bean-compatible widths: {bean_nonzero}")
        print(f"  Bean-incompatible widths: {bean_zero}")
        print(f"  Best Bean-passing quadgram: w={best_width}, q={best_q:.4f}")
    else:
        print(f"\n  ALL widths 5-15 are Bean-INCOMPATIBLE.")

    elapsed = time.time() - t0
    print(f"\nTotal time: {elapsed:.1f}s")

    # ── Save artifacts ────────────────────────────────────────
    os.makedirs("results/frac", exist_ok=True)
    artifact = {
        "experiment": "E-FRAC-27",
        "description": "Bean-compatible width profiling, widths 5-15",
        "bean_analysis": {
            str(w): {k: v for k, v in info.items()
                    if k not in ("reachable_ct_27", "reachable_ct_65")}
            for w, info in bean_analysis.items()
        },
        "width_profiles": {
            str(w): {k: v for k, v in r.items()
                    if k not in ("best_result_any", "best_result_bean")}
            for w, r in results.items()
        },
        "bean_zero_widths": bean_zero,
        "bean_nonzero_widths": bean_nonzero,
        "best_results": {
            str(w): {
                "any": results[w].get("best_result_any"),
                "bean": results[w].get("best_result_bean"),
            }
            for w in widths
        },
        "elapsed_seconds": round(elapsed, 1),
    }
    path = "results/frac/e_frac_27_bean_width_profile.json"
    with open(path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\nSaved to {path}")


if __name__ == "__main__":
    main()
