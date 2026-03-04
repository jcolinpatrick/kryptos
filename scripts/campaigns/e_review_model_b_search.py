"""
Cipher: multi-vector campaign
Family: campaigns
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-REVIEW-MODEL-B: Search for Model B (trans-then-sub) at periods 14-26.

Model B: PT -> Trans(PT) -> Sub(Trans(PT), key_by_CT_pos) -> CT
  CT[i] = Enc(PT[sigma_inv(i)], key[i % p])

For crib position j (PT pos), key at CT position sigma(j):
  k[sigma(j)] = Recover(CT[sigma(j)], PT[j])

For periodic key with period p: k[sigma(j)] depends on sigma(j) % p.
Two crib positions j1, j2 can share residue class sigma(j1) ≡ sigma(j2) (mod p)
only if their derived key values are equal:
  CT[sigma(j1)] - PT[j1] ≡ CT[sigma(j2)] - PT[j2] (mod 26) [Vigenère]

Also tests Beaufort at periods 12-26 (lower chromatic number).

Search: structured transposition families (columnar, rail fence, serpentine, spiral)
+ random permutation sampling at large scale.
"""

import itertools
import json
import math
import os
import random
import sys
import time
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, CRIB_ENTRIES, N_CRIBS, MOD, ALPH, ALPH_IDX,
    BEAN_EQ, BEAN_INEQ, NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, invert_perm, apply_perm, validate_perm,
    rail_fence_perm, serpentine_perm, spiral_perm, myszkowski_perm,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, vig_recover_key, beau_recover_key, varbeau_recover_key,
    vig_decrypt, beau_decrypt, varbeau_decrypt,
)
from kryptos.kernel.scoring.ic import ic

# ── Constants ──────────────────────────────────────────────────────────────

CRIB_POS = sorted(CRIB_DICT.keys())
CT_NUMS = [ord(c) - 65 for c in CT]
PT_NUMS = {pos: ord(ch) - 65 for pos, ch in CRIB_DICT.items()}

RECOVER_FN = {
    CipherVariant.VIGENERE: vig_recover_key,
    CipherVariant.BEAUFORT: beau_recover_key,
    CipherVariant.VAR_BEAUFORT: varbeau_recover_key,
}

DECRYPT_FN = {
    CipherVariant.VIGENERE: vig_decrypt,
    CipherVariant.BEAUFORT: beau_decrypt,
    CipherVariant.VAR_BEAUFORT: varbeau_decrypt,
}

# Periods to test per variant (based on chromatic number analysis)
PERIODS_VIG = list(range(14, 27))    # 14-26 (chromatic number 14)
PERIODS_BEAU = list(range(12, 27))   # 12-26 (chromatic number 12)
PERIODS_VB = list(range(14, 27))     # 14-26 (chromatic number 14)

VARIANT_PERIODS = {
    CipherVariant.VIGENERE: PERIODS_VIG,
    CipherVariant.BEAUFORT: PERIODS_BEAU,
    CipherVariant.VAR_BEAUFORT: PERIODS_VB,
}


# ── Model B scoring ───────────────────────────────────────────────────────

def model_b_crib_score(perm: List[int], period: int, variant: CipherVariant) -> int:
    """Score a permutation under Model B.

    Under Model B: CT[i] = Enc(PT[perm_inv[i]], key[i % p])
    So for crib position j (PT pos): the CT position is perm[j].
    key[perm[j] % p] = Recover(CT[perm[j]], PT[j])

    For two crib positions j1, j2 with perm[j1] % p == perm[j2] % p:
    the key values must be equal.
    """
    recover = RECOVER_FN[variant]

    # Compute key values at each crib position (mapped through perm)
    key_at_crib = {}  # {crib_pt_pos: (ct_pos, key_value)}
    for j in CRIB_POS:
        ct_pos = perm[j]  # Where PT position j maps to in CT
        k = recover(CT_NUMS[ct_pos], PT_NUMS[j])
        key_at_crib[j] = (ct_pos, k)

    # Group by residue class (ct_pos % period)
    groups = defaultdict(list)  # {residue: [(pt_pos, key_val)]}
    for j in CRIB_POS:
        ct_pos, k = key_at_crib[j]
        groups[ct_pos % period].append((j, k))

    # Count consistent positions
    consistent = 0
    for residue, members in groups.items():
        if len(members) == 1:
            consistent += 1  # Single member, trivially consistent
        else:
            # All members must have same key value
            vals = set(v for _, v in members)
            if len(vals) == 1:
                consistent += len(members)
            else:
                # Count the majority
                from collections import Counter
                val_counts = Counter(v for _, v in members)
                consistent += val_counts.most_common(1)[0][1]

    return consistent


def model_b_full_check(perm: List[int], period: int, variant: CipherVariant) -> Optional[dict]:
    """Full Model B check: if 24/24 consistent, decrypt and evaluate."""
    recover = RECOVER_FN[variant]
    decrypt = DECRYPT_FN[variant]

    # Compute key values at crib positions
    key_at_residue = {}  # {residue: key_value}
    for j in CRIB_POS:
        ct_pos = perm[j]
        k = recover(CT_NUMS[ct_pos], PT_NUMS[j])
        r = ct_pos % period
        if r in key_at_residue:
            if key_at_residue[r] != k:
                return None  # Contradiction
        else:
            key_at_residue[r] = k

    # All 24 cribs consistent! Check Bean constraints
    # Under Model B, Bean applies to effective key at PT positions
    # k_eff[j] = key[perm[j] % period]
    eff_key = [key_at_residue.get(perm[j] % period) for j in range(CT_LEN)]

    # Bean EQ
    for a, b in BEAN_EQ:
        ka = key_at_residue.get(perm[a] % period)
        kb = key_at_residue.get(perm[b] % period)
        if ka is not None and kb is not None and ka != kb:
            return None

    # Bean INEQ
    bean_ineq_pass = True
    for a, b in BEAN_INEQ:
        ka = key_at_residue.get(perm[a] % period)
        kb = key_at_residue.get(perm[b] % period)
        if ka is not None and kb is not None and ka == kb:
            bean_ineq_pass = False
            break

    # Decrypt full text under Model B
    # First, we need key values for ALL residue classes
    # Classes without crib data: unknown, fill with 0 for evaluation
    full_key = [key_at_residue.get(i % period, 0) for i in range(CT_LEN)]

    # Under Model B: CT[i] = Enc(PT[perm_inv[i]], key[i])
    # So: PT[perm_inv[i]] = Dec(CT[i], key[i])
    # intermediate[i] = Dec(CT[i], full_key[i])
    # PT[j] = intermediate[perm[j]]

    intermediate = [decrypt(CT_NUMS[i], full_key[i]) for i in range(CT_LEN)]
    inv_perm = invert_perm(perm)
    pt_nums = [intermediate[perm[j]] for j in range(CT_LEN)]
    # Actually: intermediate[i] = PT[inv_perm[i]], so PT[j] = intermediate[perm[j]]
    plaintext = ''.join(chr(intermediate[perm[j]] + 65) for j in range(CT_LEN))

    # Verify cribs appear
    crib_match = sum(1 for pos, ch in CRIB_DICT.items() if pos < len(plaintext) and plaintext[pos] == ch)

    ic_val = ic(plaintext)

    # Count known residue classes vs total
    known_residues = len(key_at_residue)
    total_residues = period

    return {
        'crib_score': crib_match,
        'bean_ineq_pass': bean_ineq_pass,
        'ic': ic_val,
        'plaintext': plaintext,
        'period': period,
        'variant': variant.value,
        'known_residues': known_residues,
        'total_residues': total_residues,
        'key_fragment': {r: v for r, v in sorted(key_at_residue.items())},
    }


# ── Permutation generators ────────────────────────────────────────────────

def gen_columnar_perms(widths=range(6, 16)):
    """Generate columnar permutations at various widths."""
    for w in widths:
        n_orders = math.factorial(w)
        if n_orders <= 100000:
            # Exhaustive
            for order in itertools.permutations(range(w)):
                yield columnar_perm(w, list(order)), f"col_w{w}"
        else:
            # Sample 50K
            for _ in range(50000):
                order = list(range(w))
                random.shuffle(order)
                yield columnar_perm(w, order), f"col_w{w}_sampled"


def gen_rail_fence_perms():
    """Generate rail fence permutations."""
    for depth in range(2, 50):
        p = rail_fence_perm(CT_LEN, depth)
        if validate_perm(p, CT_LEN):
            yield p, f"rail_d{depth}"


def gen_serpentine_perms():
    """Generate serpentine permutations."""
    for rows in range(2, 50):
        for cols in range(2, 50):
            if rows * cols >= CT_LEN:
                for vert in [False, True]:
                    p = serpentine_perm(rows, cols, CT_LEN, vert)
                    if len(p) == CT_LEN and validate_perm(p, CT_LEN):
                        yield p, f"serp_{rows}x{cols}_{'v' if vert else 'h'}"
                break  # Only first valid cols per rows


def gen_spiral_perms():
    """Generate spiral permutations."""
    for rows in range(2, 50):
        for cols in range(2, 50):
            if rows * cols >= CT_LEN:
                for cw in [True, False]:
                    p = spiral_perm(rows, cols, CT_LEN, cw)
                    if len(p) == CT_LEN and validate_perm(p, CT_LEN):
                        yield p, f"spiral_{rows}x{cols}_{'cw' if cw else 'ccw'}"
                break


def gen_random_perms(n=200000):
    """Generate random permutations."""
    for i in range(n):
        p = list(range(CT_LEN))
        random.shuffle(p)
        yield p, f"random_{i}"


# ── Main search ───────────────────────────────────────────────────────────

def main():
    random.seed(42)

    print("=" * 70)
    print("E-REVIEW-MODEL-B: Trans-then-Sub search at periods 14-26")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"Cribs: {len(CRIB_POS)} positions")
    print(f"Variants: Vigenere (p14-26), Beaufort (p12-26), VarBeau (p14-26)")
    print()

    best_scores = {}  # {(variant, period): (score, perm_name)}
    hits_18plus = []
    hits_24 = []

    total_configs = 0
    start_time = time.time()

    # Phase 1: Structured transpositions
    generators = [
        ("Columnar w6-15", gen_columnar_perms(range(6, 16))),
        ("Rail fence", gen_rail_fence_perms()),
        ("Serpentine", gen_serpentine_perms()),
        ("Spiral", gen_spiral_perms()),
    ]

    for gen_name, gen in generators:
        phase_start = time.time()
        phase_count = 0
        phase_best = 0

        for perm, perm_name in gen:
            if not validate_perm(perm, CT_LEN):
                continue

            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
                for period in VARIANT_PERIODS[variant]:
                    score = model_b_crib_score(perm, period, variant)
                    total_configs += 1

                    key = (variant.value, period)
                    if key not in best_scores or score > best_scores[key][0]:
                        best_scores[key] = (score, perm_name)

                    if score > phase_best:
                        phase_best = score

                    if score >= 24:
                        result = model_b_full_check(perm, period, variant)
                        if result:
                            hits_24.append((perm_name, result))
                            print(f"  *** 24/24 HIT: {perm_name} {variant.value} p{period} "
                                  f"Bean={'PASS' if result['bean_ineq_pass'] else 'FAIL'} "
                                  f"IC={result['ic']:.4f} "
                                  f"known={result['known_residues']}/{result['total_residues']} "
                                  f"PT={result['plaintext'][:30]}...")
                    elif score >= 18:
                        hits_18plus.append((score, perm_name, variant.value, period))

            phase_count += 1
            if phase_count % 10000 == 0:
                elapsed = time.time() - phase_start
                print(f"  {gen_name}: {phase_count} perms, {total_configs} configs, "
                      f"best={phase_best}/24, {elapsed:.1f}s", flush=True)

        elapsed = time.time() - phase_start
        print(f"  {gen_name}: DONE. {phase_count} perms, best={phase_best}/24, {elapsed:.1f}s")

    # Phase 2: Random permutations (200K)
    print("\nPhase 2: Random permutations (200K)")
    phase_start = time.time()
    phase_best = 0
    phase_count = 0

    for perm, perm_name in gen_random_perms(200000):
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
            for period in VARIANT_PERIODS[variant]:
                score = model_b_crib_score(perm, period, variant)
                total_configs += 1

                key = (variant.value, period)
                if key not in best_scores or score > best_scores[key][0]:
                    best_scores[key] = (score, perm_name)

                if score > phase_best:
                    phase_best = score

                if score >= 24:
                    result = model_b_full_check(perm, period, variant)
                    if result:
                        hits_24.append((perm_name, result))
                        print(f"  *** 24/24 HIT: {perm_name} {variant.value} p{period} "
                              f"Bean={'PASS' if result['bean_ineq_pass'] else 'FAIL'} "
                              f"IC={result['ic']:.4f} "
                              f"known={result['known_residues']}/{result['total_residues']} "
                              f"PT={result['plaintext'][:30]}...")
                elif score >= 18:
                    hits_18plus.append((score, perm_name, variant.value, period))

        phase_count += 1
        if phase_count % 50000 == 0:
            elapsed = time.time() - phase_start
            print(f"  Random: {phase_count} perms, {total_configs} configs, "
                  f"best={phase_best}/24, {elapsed:.1f}s", flush=True)

    elapsed_total = time.time() - start_time

    # ── Results ────────────────────────────────────────────────────────────

    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)
    print(f"Total configs tested: {total_configs:,}")
    print(f"Total time: {elapsed_total:.1f}s")
    print(f"24/24 hits: {len(hits_24)}")
    print(f"18+/24 hits: {len(hits_18plus)}")

    print("\n--- Best scores by variant and period ---")
    for variant_name in ['vigenere', 'beaufort', 'var_beaufort']:
        print(f"\n{variant_name}:")
        periods = PERIODS_BEAU if variant_name == 'beaufort' else PERIODS_VIG
        for p in periods:
            key = (variant_name, p)
            if key in best_scores:
                score, name = best_scores[key]
                marker = " ***" if score >= 18 else ""
                print(f"  p{p:2d}: {score:2d}/24 ({name}){marker}")

    if hits_24:
        print("\n--- 24/24 Hits Detail ---")
        for i, (name, result) in enumerate(hits_24[:20]):
            print(f"\nHit {i+1}: {name}")
            print(f"  Variant: {result['variant']}, Period: {result['period']}")
            print(f"  Bean INEQ: {'PASS' if result['bean_ineq_pass'] else 'FAIL'}")
            print(f"  IC: {result['ic']:.4f}")
            print(f"  Known residues: {result['known_residues']}/{result['total_residues']}")
            print(f"  Key fragment: {result['key_fragment']}")
            print(f"  PT: {result['plaintext']}")

    if hits_18plus:
        print(f"\n--- 18+/24 Hits (top 20) ---")
        hits_18plus.sort(reverse=True)
        for score, name, var, period in hits_18plus[:20]:
            print(f"  {score}/24: {name} {var} p{period}")

    # Compute expected random scores for context
    print("\n--- Expected random scores (underdetermination context) ---")
    for p in [14, 16, 19, 20, 24, 26]:
        # At period p, each residue class has ~24/p crib positions
        # Expected consistent = sum over classes of max_count
        # For random: P(match in class of size k) ≈ k * (1/26)^(k-1)
        # Simpler: just report what we observed
        for vn in ['vigenere', 'beaufort']:
            key = (vn, p)
            if key in best_scores:
                print(f"  p{p:2d} {vn}: best {best_scores[key][0]}/24")

    print(f"\n{'='*70}")
    print("VERDICT: ", end="")
    if any(r['bean_ineq_pass'] and r['ic'] > 0.05 for _, r in hits_24):
        print("SIGNAL DETECTED — investigate 24/24 + Bean PASS + high IC hits")
    elif hits_24:
        print(f"{len(hits_24)} hits at 24/24 — check for underdetermination artifacts")
    else:
        print("NO 24/24 hits found. Model B at tested periods: NOISE")


if __name__ == "__main__":
    main()
