#!/usr/bin/env python3
"""
# Cipher: autokey_beaufort+vigenere
# Family: campaigns
# Status: active
# Keyspace: ~200 SA restarts * 120K steps + 720 col orderings + width sweep
# Last run: never
# Best score: 0

Col6 DEFECTOR palette test.

MOTIVATION: Width-6 column IC anomaly on CT73 (IC=0.106/0.121 on columns 1
and 5) is the strongest untested cipher-layer signal. Lag-7 autocorrelation
that motivated col7 was proven to be a STEGO ARTIFACT. Real cipher-layer
autocorrelation signals are lag-1 (z=3.36) and lag-6 (z=2.95).

Phase 1: DEFECTOR:AZ_beau + col6 + SA mask optimization (200 restarts)
Phase 2: All keywords x col6 (DEFECTOR, KRYPTOS, ABSCISSA, KOMPASS,
         PALIMPSEST, DEFECT) with SA mask
Phase 3: Exhaustive 720 column orderings for best mask
Phase 4: Width sweep (5, 6, 9, 11) comparison
Phase 5: DEFECT as col6 transposition keyword

Consensus nulls (17): {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85}
Palette-but-real (18): {7,16,18,19,30,31,34,45,46,47,48,56,62,70,73,77,86,93}
"""

import sys, os, random, math, time, json
from itertools import permutations
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CRIB_POSITIONS

CT97 = CT
N = 97; N_NULLS = 24; N_PT = 73
ENE_WORD = "EASTNORTHEAST"; BCL_WORD = "BERLINCLOCK"
ENE_START = 21; BCL_START = 63

# Non-crib positions are the only ones eligible for null placement
NON_CRIB = sorted([i for i in range(N) if i not in CRIB_POSITIONS])
NC_SET = frozenset(NON_CRIB)

# Consensus null positions (17 known)
CONSENSUS_17 = frozenset([0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85])

# Palette-but-real: positions with palette letters {B,G,I,K,O,W,Z} that are
# NOT in the 17 consensus set. These are the first candidates for the 7 remaining nulls.
PALETTE_BUT_REAL = frozenset([7,16,18,19,30,31,34,45,46,47,48,56,62,70,73,77,86,93])

# KA alphabet
KA_STR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
AZ_TO_KA = [KA_IDX[chr(65+i)] for i in range(26)]


# ============================================================
# Transposition helpers
# ============================================================

def columnar_perm(n, width):
    """Write row-by-row, read column-by-column (ascending order). Returns gather perm."""
    n_rows = (n + width - 1) // width
    grid = []
    for row in range(n_rows):
        start = row * width
        grid.append(list(range(start, min(start + width, n))))
    perm = []
    for col in range(width):
        for row in range(n_rows):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm


def columnar_perm_ordered(n, width, col_order):
    """Write row-by-row, read columns in col_order. Returns gather perm."""
    n_rows = (n + width - 1) // width
    grid = []
    for row in range(n_rows):
        start = row * width
        grid.append(list(range(start, min(start + width, n))))
    perm = []
    for col in col_order:
        for row in range(n_rows):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm


def reverse_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def keyword_col_order(word_nums):
    """Column order from keyword: sort positions by letter value, preserving order for ties."""
    indexed = sorted(range(len(word_nums)), key=lambda i: (word_nums[i], i))
    return indexed


# ============================================================
# Autokey decryption
# ============================================================

def autokey_decrypt_az(ct_list, kw, beau=False):
    """AZ autokey: Beaufort P = (K-C) mod 26, Vigenere P = (C-K) mod 26."""
    pt = []; kw_n = [ord(c) - 65 for c in kw.upper()]; L = len(kw_n)
    for i, ci in enumerate(ct_list):
        ki = kw_n[i] if i < L else pt[i - L]
        pt.append(((ki - ci) if beau else (ci - ki)) % 26)
    return pt


def autokey_decrypt_ka(ct73_az, kw, beau=False):
    """KA autokey."""
    ct73_ka = [AZ_TO_KA[ci] for ci in ct73_az]
    kw_ka = [KA_IDX[c] for c in kw.upper() if c in KA_IDX]
    L = len(kw_ka)
    pt_ka_indices = []
    for i, cki in enumerate(ct73_ka):
        ki = kw_ka[i] if i < L else pt_ka_indices[i - L]
        pt_ki = ((ki - cki) if beau else (cki - ki)) % 26
        pt_ka_indices.append(pt_ki)
    return pt_ka_indices


# ============================================================
# Scoring
# ============================================================

def count_crib_hits(pt_nums, ene_s, bcl_s):
    """Count matching crib positions. pt_nums is list of ints 0-25."""
    ene_nums = [ord(c) - 65 for c in ENE_WORD]
    bcl_nums = [ord(c) - 65 for c in BCL_WORD]
    e = sum(1 for j, c in enumerate(ene_nums) if ene_s + j < N_PT and pt_nums[ene_s + j] == c)
    b = sum(1 for j, c in enumerate(bcl_nums) if bcl_s + j < N_PT and pt_nums[bcl_s + j] == c)
    return e + b, e, b


def eval_mask(null_set, kw, beau, ka, inv_perm):
    """Extract CT73, untranspose, decrypt, score."""
    null_set = frozenset(null_set)
    ct73_raw = ''.join(CT97[i] for i in range(N) if i not in null_set)
    if len(ct73_raw) != N_PT:
        return 0, 0, 0, ""
    ct73_az = [ord(c) - 65 for c in ct73_raw]

    # Compute shifted crib positions
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1
    bcl_s = BCL_START - n2

    # Untranspose then decrypt
    ct73_t = [ct73_az[inv_perm[i]] for i in range(N_PT)]

    if ka:
        pt_nums = autokey_decrypt_ka(ct73_t, kw, beau)
    else:
        pt_nums = autokey_decrypt_az(ct73_t, kw, beau)

    total, e, b = count_crib_hits(pt_nums, ene_s, bcl_s)
    pt_str = ''.join(chr(p + 65) if not ka else KA_STR[p] for p in pt_nums)
    return total, e, b, pt_str


def score_mask(null_set, kw, beau, ka, inv_perm):
    total, e, b, pt = eval_mask(null_set, kw, beau, ka, inv_perm)
    return float(total)


# ============================================================
# SA mask optimizer
# ============================================================

def sa_optimize(kw, beau, ka, inv_perm, n_restarts, steps_per_restart,
                seed_nulls=None, palette_only=False, rng_seed_base=0):
    """Run SA to optimize null mask for given cipher + transposition.

    If palette_only=True, the 7 varying positions are constrained to
    the 18 palette-but-real positions.
    """
    results = []
    overall_best_sc = 0
    overall_best = None

    for restart in range(n_restarts):
        rng = random.Random(restart * 37 + rng_seed_base)

        if seed_nulls is not None and restart == 0:
            # First restart: use seed
            null_set = set(seed_nulls)
        else:
            # Random start from consensus + 7 random non-crib positions
            if palette_only:
                candidates = sorted(PALETTE_BUT_REAL - CONSENSUS_17)
                extra = set(rng.sample(candidates, min(7, len(candidates))))
            else:
                candidates = sorted(NC_SET - CONSENSUS_17)
                extra = set(rng.sample(candidates, 7))
            null_set = set(CONSENSUS_17) | extra

        non_null = NC_SET - null_set

        sc = score_mask(frozenset(null_set), kw, beau, ka, inv_perm)
        best_sc = sc
        best_null = frozenset(null_set)

        T0 = 0.3; Tf = 0.01
        for step in range(steps_per_restart):
            T = T0 * (Tf / T0) ** (step / steps_per_restart)

            # Swap: move one position out of nulls, one in
            if palette_only:
                # Only swap within palette-but-real positions (keep consensus fixed)
                swappable_null = null_set - CONSENSUS_17
                swappable_real = (PALETTE_BUT_REAL & non_null) - CONSENSUS_17
                if not swappable_null or not swappable_real:
                    continue
                out = rng.choice(list(swappable_null))
                into = rng.choice(list(swappable_real))
            else:
                out = rng.choice(list(null_set))
                into = rng.choice(list(non_null))

            null_set = (null_set - {out}) | {into}
            non_null = (non_null - {into}) | {out}
            new_sc = score_mask(frozenset(null_set), kw, beau, ka, inv_perm)
            delta = new_sc - sc
            if delta > 0 or rng.random() < math.exp(delta / max(T, 1e-10)):
                sc = new_sc
                if sc > best_sc:
                    best_sc = sc
                    best_null = frozenset(null_set)
            else:
                null_set = (null_set - {into}) | {out}
                non_null = (non_null - {out}) | {into}

        total, e, b, pt = eval_mask(best_null, kw, beau, ka, inv_perm)
        results.append({
            'score': total, 'e': e, 'b': b, 'pt': pt,
            'mask': sorted(best_null), 'restart': restart
        })

        if total > overall_best_sc:
            overall_best_sc = total
            overall_best = results[-1]

        if total >= 14 or restart % 50 == 0:
            print(f"    r={restart:3d}: {total}/24 (e={e}/13, b={b}/11)", flush=True)
            if total >= 14:
                print(f"    *** {total}/24 mask={sorted(best_null)}", flush=True)
                print(f"    PT={pt}", flush=True)

    return results, overall_best


# ============================================================
# Main
# ============================================================

def main():
    t0 = time.time()
    all_results = {}
    global_best_score = 0
    global_best_desc = ""
    global_best_pt = ""

    print("=" * 70)
    print("COL6 DEFECTOR PALETTE — 5-Phase Investigation")
    print("=" * 70)
    print(f"CT97 = {CT97}")
    print(f"Consensus 17: {sorted(CONSENSUS_17)}")
    print()

    # Pre-compute col6 ascending permutation
    perm_col6_asc = columnar_perm(N_PT, 6)
    inv_col6_asc = reverse_perm(perm_col6_asc)

    # Pre-compute DEFECT keyword column order
    defect_nums = [ord(c) - 65 for c in "DEFECT"]
    defect_col_order = keyword_col_order(defect_nums)
    print(f"DEFECT keyword col order: {defect_col_order}")
    perm_col6_defect = columnar_perm_ordered(N_PT, 6, defect_col_order)
    inv_col6_defect = reverse_perm(perm_col6_defect)

    # Also pre-compute col7 for baseline comparison
    perm_col7 = columnar_perm(N_PT, 7)
    inv_col7 = reverse_perm(perm_col7)

    # ========================================
    # PHASE 1: DEFECTOR:AZ_beau + col6 + SA mask (200 restarts)
    # ========================================
    print("=" * 70)
    print("PHASE 1: DEFECTOR:AZ_beau + col6 ascending + SA mask (200 restarts)")
    print("=" * 70)
    sys.stdout.flush()

    # Build seed: consensus 17 + best 7 from palette
    seed_extra = sorted(PALETTE_BUT_REAL - CONSENSUS_17)[:7]
    seed_24 = frozenset(CONSENSUS_17 | set(seed_extra))

    phase1_results, phase1_best = sa_optimize(
        kw='DEFECTOR', beau=True, ka=False,
        inv_perm=inv_col6_asc,
        n_restarts=200, steps_per_restart=120_000,
        seed_nulls=seed_24,
        palette_only=False,
        rng_seed_base=42
    )

    p1_scores = {}
    for r in phase1_results:
        s = r['score']
        p1_scores[s] = p1_scores.get(s, 0) + 1

    best_p1 = phase1_best
    print(f"\nPhase 1 BEST: {best_p1['score']}/24 (e={best_p1['e']}/13, b={best_p1['b']}/11)")
    print(f"  PT={best_p1['pt']}")
    print(f"  mask={best_p1['mask']}")
    print(f"  Score distribution: {dict(sorted(p1_scores.items()))}")
    print(f"  Elapsed: {time.time()-t0:.1f}s")
    sys.stdout.flush()

    if best_p1['score'] > global_best_score:
        global_best_score = best_p1['score']
        global_best_desc = f"Phase1:DEFECTOR:AZ_beau+col6_asc"
        global_best_pt = best_p1['pt']

    all_results['phase1_defector_az_beau_col6'] = {
        'best_score': best_p1['score'],
        'best_e': best_p1['e'],
        'best_b': best_p1['b'],
        'best_pt': best_p1['pt'],
        'best_mask': best_p1['mask'],
        'score_dist': p1_scores,
        'n_restarts': 200,
    }

    # ========================================
    # PHASE 2: Multiple keywords x col6
    # ========================================
    print("\n" + "=" * 70)
    print("PHASE 2: Multiple keywords x col6 (50 restarts each)")
    print("=" * 70)
    sys.stdout.flush()

    PHASE2_KEYWORDS = [
        ('DEFECTOR', True, False, 'AZ_beau'),
        ('DEFECTOR', False, False, 'AZ_vig'),
        ('KRYPTOS', True, False, 'AZ_beau'),
        ('KRYPTOS', False, False, 'AZ_vig'),
        ('KRYPTOS', False, True, 'KA_vig'),
        ('KRYPTOS', True, True, 'KA_beau'),
        ('ABSCISSA', True, False, 'AZ_beau'),
        ('ABSCISSA', False, True, 'KA_vig'),
        ('KOMPASS', True, False, 'AZ_beau'),
        ('KOMPASS', False, True, 'KA_vig'),
        ('PALIMPSEST', True, False, 'AZ_beau'),
        ('PALIMPSEST', False, False, 'AZ_vig'),
        ('DEFECT', True, False, 'AZ_beau'),
        ('DEFECT', False, False, 'AZ_vig'),
    ]

    phase2_all = {}
    for kw, beau, ka, var_label in PHASE2_KEYWORDS:
        label = f"{kw}:{var_label}:col6_asc"
        print(f"\n  {label}:")
        sys.stdout.flush()

        results, best = sa_optimize(
            kw=kw, beau=beau, ka=ka,
            inv_perm=inv_col6_asc,
            n_restarts=50, steps_per_restart=80_000,
            seed_nulls=seed_24,
            palette_only=False,
            rng_seed_base=hash(label) % 10000
        )

        scores = {}
        for r in results:
            s = r['score']
            scores[s] = scores.get(s, 0) + 1

        print(f"  -> {label} BEST: {best['score']}/24 (e={best['e']}/13, b={best['b']}/11)")
        print(f"     Dist: {dict(sorted(scores.items()))}")
        sys.stdout.flush()

        phase2_all[label] = {
            'best_score': best['score'],
            'best_e': best['e'],
            'best_b': best['b'],
            'best_pt': best['pt'],
            'best_mask': best['mask'],
            'score_dist': scores,
        }

        if best['score'] > global_best_score:
            global_best_score = best['score']
            global_best_desc = f"Phase2:{label}"
            global_best_pt = best['pt']

    all_results['phase2_keyword_sweep'] = phase2_all

    # ========================================
    # PHASE 3: Exhaustive 720 column orderings for best Phase 1 mask
    # ========================================
    print("\n" + "=" * 70)
    print("PHASE 3: Exhaustive 720 col6 orderings (best Phase 1 mask)")
    print("=" * 70)
    sys.stdout.flush()

    best_p1_mask = frozenset(best_p1['mask'])
    # Also use top-3 masks from Phase 1
    top_p1_masks = sorted(phase1_results, key=lambda x: -x['score'])[:6]
    unique_masks = []
    seen = set()
    for r in top_p1_masks:
        mk = tuple(sorted(r['mask']))
        if mk not in seen:
            seen.add(mk)
            unique_masks.append(frozenset(r['mask']))

    all_orderings = list(permutations(range(6)))
    phase3_best_score = 0
    phase3_best_info = None
    phase3_hits = []

    for mi, mask in enumerate(unique_masks):
        ct73_raw = ''.join(CT97[i] for i in range(N) if i not in mask)
        ct73_az = [ord(c) - 65 for c in ct73_raw]
        n1 = sum(1 for p in mask if p < ENE_START)
        n2 = sum(1 for p in mask if p < BCL_START)
        ene_s = ENE_START - n1
        bcl_s = BCL_START - n2

        for order in all_orderings:
            perm = columnar_perm_ordered(N_PT, 6, list(order))
            inv_p = reverse_perm(perm)
            ct73_t = [ct73_az[inv_p[i]] for i in range(N_PT)]

            # DEFECTOR:AZ_beau
            pt = autokey_decrypt_az(ct73_t, 'DEFECTOR', beau=True)
            total, e, b = count_crib_hits(pt, ene_s, bcl_s)
            if total >= 14:
                pt_str = ''.join(chr(p + 65) for p in pt)
                phase3_hits.append({
                    'score': total, 'e': e, 'b': b,
                    'order': list(order), 'mask_idx': mi,
                    'variant': 'AZ_beau', 'pt': pt_str
                })
                print(f"  {total}/24 (e={e}/13, b={b}/11) order={order} mask={mi} AZ_beau", flush=True)

            if total > phase3_best_score:
                phase3_best_score = total
                pt_str = ''.join(chr(p + 65) for p in pt)
                phase3_best_info = {
                    'score': total, 'e': e, 'b': b,
                    'order': list(order), 'mask_idx': mi,
                    'variant': 'AZ_beau', 'pt': pt_str
                }

            # DEFECTOR:AZ_vig
            pt = autokey_decrypt_az(ct73_t, 'DEFECTOR', beau=False)
            total, e, b = count_crib_hits(pt, ene_s, bcl_s)
            if total >= 14:
                pt_str = ''.join(chr(p + 65) for p in pt)
                phase3_hits.append({
                    'score': total, 'e': e, 'b': b,
                    'order': list(order), 'mask_idx': mi,
                    'variant': 'AZ_vig', 'pt': pt_str
                })
                print(f"  {total}/24 (e={e}/13, b={b}/11) order={order} mask={mi} AZ_vig", flush=True)

            if total > phase3_best_score:
                phase3_best_score = total
                pt_str = ''.join(chr(p + 65) for p in pt)
                phase3_best_info = {
                    'score': total, 'e': e, 'b': b,
                    'order': list(order), 'mask_idx': mi,
                    'variant': 'AZ_vig', 'pt': pt_str
                }

    print(f"\nPhase 3 BEST: {phase3_best_score}/24")
    if phase3_best_info:
        print(f"  {phase3_best_info}")
    print(f"  Hits >= 14: {len(phase3_hits)}")
    print(f"  Elapsed: {time.time()-t0:.1f}s")
    sys.stdout.flush()

    if phase3_best_score > global_best_score:
        global_best_score = phase3_best_score
        global_best_desc = f"Phase3:col6_order={phase3_best_info['order']}:{phase3_best_info['variant']}"
        global_best_pt = phase3_best_info['pt']

    all_results['phase3_720_orderings'] = {
        'best_score': phase3_best_score,
        'best_info': phase3_best_info,
        'n_hits_14plus': len(phase3_hits),
        'top_hits': sorted(phase3_hits, key=lambda x: -x['score'])[:20],
        'n_masks_tested': len(unique_masks),
        'total_evals': len(unique_masks) * 720 * 2,
    }

    # ========================================
    # PHASE 4: Width sweep (5, 6, 9, 11) comparison
    # ========================================
    print("\n" + "=" * 70)
    print("PHASE 4: Width sweep — 5, 6, 9, 11 + col7 baseline (50 restarts)")
    print("=" * 70)
    sys.stdout.flush()

    WIDTHS = [5, 6, 9, 11, 7]  # 7 = baseline
    phase4_all = {}

    for w in WIDTHS:
        perm_w = columnar_perm(N_PT, w)
        inv_w = reverse_perm(perm_w)
        label = f"DEFECTOR:AZ_beau:col{w}"
        print(f"\n  {label}:")
        sys.stdout.flush()

        results, best = sa_optimize(
            kw='DEFECTOR', beau=True, ka=False,
            inv_perm=inv_w,
            n_restarts=50, steps_per_restart=80_000,
            seed_nulls=seed_24,
            palette_only=False,
            rng_seed_base=w * 1000
        )

        scores = {}
        for r in results:
            s = r['score']
            scores[s] = scores.get(s, 0) + 1

        print(f"  -> {label} BEST: {best['score']}/24 (e={best['e']}/13, b={best['b']}/11)")
        print(f"     Dist: {dict(sorted(scores.items()))}")
        sys.stdout.flush()

        phase4_all[label] = {
            'best_score': best['score'],
            'best_e': best['e'],
            'best_b': best['b'],
            'best_pt': best['pt'],
            'best_mask': best['mask'],
            'score_dist': scores,
        }

        if best['score'] > global_best_score:
            global_best_score = best['score']
            global_best_desc = f"Phase4:{label}"
            global_best_pt = best['pt']

    all_results['phase4_width_sweep'] = phase4_all

    # ========================================
    # PHASE 5: DEFECT as col6 transposition keyword
    # ========================================
    print("\n" + "=" * 70)
    print("PHASE 5: DEFECT as col6 transposition keyword")
    print(f"  DEFECT col order: {defect_col_order}")
    print("=" * 70)
    sys.stdout.flush()

    PHASE5_CIPHERS = [
        ('DEFECTOR', True, False, 'AZ_beau'),
        ('DEFECTOR', False, False, 'AZ_vig'),
        ('DEFECT', True, False, 'AZ_beau'),
        ('DEFECT', False, False, 'AZ_vig'),
        ('KRYPTOS', True, False, 'AZ_beau'),
        ('KRYPTOS', False, True, 'KA_vig'),
    ]

    phase5_all = {}
    for kw, beau, ka, var_label in PHASE5_CIPHERS:
        label = f"{kw}:{var_label}:col6_DEFECT"
        print(f"\n  {label}:")
        sys.stdout.flush()

        results, best = sa_optimize(
            kw=kw, beau=beau, ka=ka,
            inv_perm=inv_col6_defect,
            n_restarts=50, steps_per_restart=80_000,
            seed_nulls=seed_24,
            palette_only=False,
            rng_seed_base=hash(label) % 10000 + 5000
        )

        scores = {}
        for r in results:
            s = r['score']
            scores[s] = scores.get(s, 0) + 1

        print(f"  -> {label} BEST: {best['score']}/24 (e={best['e']}/13, b={best['b']}/11)")
        print(f"     Dist: {dict(sorted(scores.items()))}")
        sys.stdout.flush()

        phase5_all[label] = {
            'best_score': best['score'],
            'best_e': best['e'],
            'best_b': best['b'],
            'best_pt': best['pt'],
            'best_mask': best['mask'],
            'score_dist': scores,
        }

        if best['score'] > global_best_score:
            global_best_score = best['score']
            global_best_desc = f"Phase5:{label}"
            global_best_pt = best['pt']

    all_results['phase5_defect_keyword'] = phase5_all

    # ========================================
    # Summary
    # ========================================
    elapsed = time.time() - t0
    print("\n" + "=" * 70)
    print(f"FINAL SUMMARY (elapsed {elapsed:.1f}s)")
    print("=" * 70)
    print(f"GLOBAL BEST: {global_best_score}/24")
    print(f"  Description: {global_best_desc}")
    print(f"  PT: {global_best_pt}")
    print()

    # Compare col6 vs col7
    p4 = all_results.get('phase4_width_sweep', {})
    col6_best = p4.get('DEFECTOR:AZ_beau:col6', {}).get('best_score', 0)
    col7_best = p4.get('DEFECTOR:AZ_beau:col7', {}).get('best_score', 0)
    print(f"Col6 vs Col7 (DEFECTOR:AZ_beau, 50 restarts each):")
    print(f"  Col6 best: {col6_best}/24")
    print(f"  Col7 best: {col7_best}/24")
    if col6_best > col7_best:
        print(f"  *** Col6 EXCEEDS Col7 by {col6_best - col7_best} points ***")
    elif col6_best == col7_best:
        print(f"  Col6 = Col7 (same ceiling)")
    else:
        print(f"  Col7 still ahead by {col7_best - col6_best} points")
    print()

    if global_best_score >= 16:
        print("!!! SIGNAL: Score >= 16 exceeds prior col7 ceiling of 15/24 !!!")
    elif global_best_score == 15:
        print("Col6 MATCHES col7 ceiling of 15/24 but does not exceed it.")
    else:
        print(f"Col6 does NOT reach col7 ceiling (best {global_best_score} < 15)")

    # Save results
    output = {
        'timestamp': datetime.now().isoformat(),
        'elapsed_seconds': elapsed,
        'global_best_score': global_best_score,
        'global_best_desc': global_best_desc,
        'global_best_pt': global_best_pt,
        'phases': all_results,
    }

    out_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results',
                            'col6_defector_palette.json')
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
