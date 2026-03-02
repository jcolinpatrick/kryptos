#!/usr/bin/env python3
"""E-HYBRID-04: Reverse-K3 Hybrid — Vigenère FIRST, Columnar Trans SECOND.

HYPOTHESIS
==========
K3 encryption order: PT → Columnar Transposition → Vigenère → CT  (Trans→Vig)
K4 MIGHT use the reverse: PT → Vigenère → Columnar Transposition → CT  (Vig→Trans)

This script tests BOTH models comprehensively:

  Model A (Vig→Trans encrypt — REVERSE of K3):
    Encrypt: intermediate = Vig(PT, K at PT position), CT = ColTrans(intermediate)
    Decrypt: intermediate[pos] = CT[inv_perm[pos]], PT[pos] = VigDec(intermediate[pos], K[pos%p])
    Key recovery: K[pos%p] = (CT[inv_perm[pos]] - PT[pos]) % 26  [Vigenère]

  Model B (Trans→Vig encrypt — SAME as K3):
    Encrypt: intermediate = ColTrans(PT), CT = Vig(intermediate, K at CT position)
    Decrypt: intermediate[j] = VigDec(CT[j], K[j%p]), PT = InvColTrans(intermediate)
    Key recovery: K[j%p] = (CT[j] - PT_at_j) % 26 where j = inv_perm[pos]

PRIOR COVERAGE
==============
E-HYBRID-01: Model A+B, widths 5-9, periods 8/13, ~30 keywords, best 10/24
E-HYBRID-02: Model A+B crib-derived, widths 2-9, periods {7,8,10,13,16,19,20,23,24,26}
             MC 100K at widths 10-15, same periods. Vig+Beau only. 5 keywords.
E-HYBRID-03: Model A+B, period-13 focus, widths 7-11

NEW TERRITORY (what this script adds)
======================================
1. Periods {4,5,6,9,11,12} — NEVER TESTED for either model in crib-derived
2. Extended keyword list (40+ keywords, lengths 4-12) with quadgram scoring
3. Variant Beaufort for keyword tests (proven identical to Vig for crib-derived)
4. Cross-keyword tests (Vig keyword ≠ Trans keyword, like K3)
5. Quadgram scoring as secondary discriminator for all candidates

EXPECTED RESULT
===============
For crib-derived approach: P(random ordering consistent) ≈ (1/26)^(24-p), effectively 0.
Any consistent hit with English quadgrams would be a BREAKTHROUGH.
"""
import json
import os
import random
import sys
import time
from itertools import permutations
from math import factorial

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, BEAN_EQ, BEAN_INEQ,
    KRYPTOS_ALPHABET,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.scoring.ngram import NgramScorer
from kryptos.kernel.transforms.transposition import (
    columnar_perm, invert_perm, apply_perm,
)

# ── Precomputed numeric arrays ───────────────────────────────────────────────
CT_IDX = [ALPH_IDX[c] for c in CT]
ALL_CRIB = sorted([(pos, ALPH_IDX[ch]) for pos, ch in CRIB_DICT.items()])
assert len(ALL_CRIB) == 24

# Separate for early-exit optimization
BC_CRIB = [(pos, ALPH_IDX[ch]) for pos, ch in CRIB_DICT.items() if 63 <= pos <= 73]
ENE_CRIB = [(pos, ALPH_IDX[ch]) for pos, ch in CRIB_DICT.items() if 21 <= pos <= 33]

# ── Key recovery and decrypt functions ────────────────────────────────────────
def vig_key_recover(c, p):   return (c - p) % MOD
def beau_key_recover(c, p):  return (c + p) % MOD
def varbeau_key_recover(c, p): return (p - c) % MOD

def vig_dec(c, k):   return (c - k) % MOD
def beau_dec(c, k):  return (k - c) % MOD
def varbeau_dec(c, k): return (c + k) % MOD

VARIANTS_CRIB = {
    'vig':  (vig_key_recover, vig_dec),
    'beau': (beau_key_recover, beau_dec),
    # VarBeau = Vig for crib-derived (algebraically proven), omitted here
}

VARIANTS_KEYWORD = {
    'vig':     vig_dec,
    'beau':    beau_dec,
    'varbeau': varbeau_dec,
}

# ── Columnar transposition utilities ──────────────────────────────────────────
def build_col_positions(width, n=CT_LEN):
    """col_positions[c] = list of input positions in column c."""
    cols = [[] for _ in range(width)]
    for pos in range(n):
        cols[pos % width].append(pos)
    return cols


def build_inv_perm_scatter(col_order, col_positions, n=CT_LEN):
    """Build scatter inv_perm: inv_perm[input_pos] = output_pos.
    col_order[c] = rank of column c (0 = first column read out).
    """
    width = len(col_order)
    rank_to_col = [0] * width
    for col_idx, rank in enumerate(col_order):
        rank_to_col[rank] = col_idx

    inv_perm = [0] * n
    out_pos = 0
    for rank in range(width):
        col_idx = rank_to_col[rank]
        for inp_pos in col_positions[col_idx]:
            inv_perm[inp_pos] = out_pos
            out_pos += 1
    return inv_perm


# ── Bean constraint check on derived key ──────────────────────────────────────
def check_bean_from_key(key_by_residue, period):
    """Check Bean equality and 21 inequalities on crib-derived key."""
    # Equality: k[27%p] == k[65%p]
    r27 = 27 % period
    r65 = 65 % period
    if r27 in key_by_residue and r65 in key_by_residue:
        if key_by_residue[r27] != key_by_residue[r65]:
            return False

    # 21 inequalities
    for a, b in BEAN_INEQ:
        ra = a % period
        rb = b % period
        if ra in key_by_residue and rb in key_by_residue:
            if key_by_residue[ra] == key_by_residue[rb]:
                return False
    return True


# ── Crib-derived key extraction ───────────────────────────────────────────────
def derive_key_model_a(inv_perm, period, key_fn):
    """Model A: key at PT position. K[pos%p] = key_fn(CT[inv_perm[pos]], PT[pos])."""
    key_by_residue = {}
    for pos, pt_val in ALL_CRIB:
        ct_val = CT_IDX[inv_perm[pos]]
        k_val = key_fn(ct_val, pt_val)
        residue = pos % period
        if residue in key_by_residue:
            if key_by_residue[residue] != k_val:
                return None
        else:
            key_by_residue[residue] = k_val
    return key_by_residue


def derive_key_model_b(inv_perm, period, key_fn):
    """Model B: key at CT position. K[inv_perm[pos]%p] = key_fn(CT[inv_perm[pos]], PT[pos])."""
    key_by_residue = {}
    for pos, pt_val in ALL_CRIB:
        j = inv_perm[pos]
        ct_val = CT_IDX[j]
        k_val = key_fn(ct_val, pt_val)
        residue = j % period
        if residue in key_by_residue:
            if key_by_residue[residue] != k_val:
                return None
        else:
            key_by_residue[residue] = k_val
    return key_by_residue


# ── Full decryption ──────────────────────────────────────────────────────────
def decrypt_model_a(inv_perm, key_by_residue, period, dec_fn):
    """Model A: PT[pos] = dec_fn(CT[inv_perm[pos]], K[pos%p])."""
    chars = []
    for pos in range(CT_LEN):
        ct_val = CT_IDX[inv_perm[pos]]
        k_val = key_by_residue.get(pos % period, 0)
        chars.append(ALPH[dec_fn(ct_val, k_val)])
    return ''.join(chars)


def decrypt_model_b(inv_perm, key_by_residue, period, dec_fn):
    """Model B: intermediate[j] = dec_fn(CT[j], K[j%p]), PT = InvColTrans(intermediate)."""
    # First compute intermediate at all CT positions
    intermediate = [0] * CT_LEN
    for j in range(CT_LEN):
        k_val = key_by_residue.get(j % period, 0)
        intermediate[j] = dec_fn(CT_IDX[j], k_val)

    # Then reverse transposition: PT[pos] = intermediate[inv_perm[pos]]
    chars = []
    for pos in range(CT_LEN):
        chars.append(ALPH[intermediate[inv_perm[pos]]])
    return ''.join(chars)


# ── Keyword utilities ────────────────────────────────────────────────────────
def keyword_to_numeric(kw):
    return [ALPH_IDX[c] for c in kw.upper()]


def keyword_to_col_order(kw, width=None):
    kw = kw.upper()
    w = width or len(kw)
    kw = kw[:w]
    if len(kw) < w:
        return None
    indexed = [(ch, i) for i, ch in enumerate(kw)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * w
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return order


# ── Keywords from Kryptos context (lengths 4-12) ────────────────────────────
KRYPTOS_KEYWORDS = [
    # Length 4
    "EAST", "WEST", "MASK", "CODE", "CLUE", "DARK",
    # Length 5
    "NORTH", "SOUTH", "LIGHT", "CLOCK", "LAYER", "SHIFT",
    # Length 6
    "BERLIN", "SHADOW", "MASKED", "CIPHER", "HIDDEN", "BURIED",
    # Length 7
    "KRYPTOS", "SANBORN", "SCHEIDT", "LANGLEY", "CENTRAL", "WEBSTER",
    "SHADOWS",
    # Length 8
    "ABSCISSA", "MAGNETIC", "ILLUSION", "IQLUSION", "POSITION", "LOCATION",
    "TREASURE", "BERLINER", "SCULPTOR", "MERIDIAN", "LANGUAGE", "CALENDAR",
    "NAVIGATE", "EGYPTIAN", "COMPLETE", "UNVEILED", "OBSERVER", "BASELINE",
    # Length 9
    "INVISIBLE", "SCULPTURE", "ANTIQUITY", "DECRYPTED",
    # Length 10
    "PALIMPSEST", "UNDERMINES", "COMPLETELY",
    # Length 11
    "BERLINCLOCK", "UNDERGROUND",
    # Length 12
    "INTELLIGENCE", "CRYPTOGRAPHY",
]

# Trans keywords (for cross-keyword tests: Vig key ≠ Trans ordering keyword)
TRANS_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SANBORN", "SCHEIDT",
    "BERLINCLOCK", "LANGLEY", "SHADOW", "BERLIN", "CLOCK",
    "EAST", "LIGHT", "MASKED",
]

# Periods: user requested 4-12, plus Bean-surviving extras for completeness
PERIODS_NEW = [4, 5, 6, 9, 11, 12]  # Never tested before
PERIODS_RETEST = [7, 8, 10, 13]      # Re-tested with new coverage (VarBeau, new keywords)
ALL_PERIODS = PERIODS_NEW + PERIODS_RETEST

MC_SAMPLES_LARGE = 200_000  # For crib-derived at widths 10-15
MC_SAMPLES_KW = 50_000      # For keyword at widths 8-9
MC_SAMPLES_KW_LARGE = 10_000  # For keyword at widths 10-15


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    print("=" * 78)
    print("E-HYBRID-04: Vigenère-First Hybrid (Reverse of K3)")
    print("=" * 78)
    print(f"CT: {CT}")
    print(f"Testing BOTH Model A (Vig→Trans encrypt) and Model B (Trans→Vig encrypt)")
    print(f"New periods: {PERIODS_NEW} (never tested)")
    print(f"Retest periods: {PERIODS_RETEST} (with new coverage)")
    print(f"Widths: 2-15 (exhaustive ≤9, MC for 10-15)")
    print(f"Keywords: {len(KRYPTOS_KEYWORDS)}")
    print()

    # Load quadgram scorer
    qg_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
    ngram_scorer = None
    try:
        ngram_scorer = NgramScorer.from_file(qg_path)
        print(f"✓ Quadgram scorer loaded")
    except Exception as e:
        print(f"⚠ Could not load quadgram scorer: {e}")

    random.seed(42)  # Reproducibility

    # Global tracking
    global_best_score = 0
    global_best_ngram = -999.0
    global_best_pt = None
    global_best_config = None
    phase_stats = {}
    all_hits = []

    t_start = time.time()

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 1: Crib-derived approach — both models, new periods
    # ══════════════════════════════════════════════════════════════════════════
    print("\n" + "─" * 78)
    print("PHASE 1: Crib-derived — widths 2-15, both models, all periods")
    print("  NEW periods: 4,5,6,9,11,12 | RETEST: 7,8,10,13 (for verification)")
    print("─" * 78)

    p1_tested = 0
    p1_consistent = 0
    p1_best_score = 0
    p1_best_ngram = -999.0

    for width in range(2, 16):
        col_positions = build_col_positions(width)
        w_t = time.time()
        w_tested = 0
        w_consistent = 0
        w_best_score = 0
        w_best_ngram = -999.0

        # Determine orderings to test
        if width <= 9:
            orderings = list(permutations(range(width)))
            exhaustive = True
        else:
            orderings = []
            seen = set()
            for _ in range(MC_SAMPLES_LARGE):
                co = list(range(width))
                random.shuffle(co)
                co_t = tuple(co)
                if co_t not in seen:
                    seen.add(co_t)
                    orderings.append(co_t)
            exhaustive = False

        for col_order in orderings:
            inv_perm = build_inv_perm_scatter(list(col_order), col_positions)

            for period in ALL_PERIODS:
                for vname, (key_fn, dec_fn) in VARIANTS_CRIB.items():
                    # ── Model A (Vig→Trans encrypt) ──
                    w_tested += 1
                    key_a = derive_key_model_a(inv_perm, period, key_fn)
                    if key_a is not None:
                        if check_bean_from_key(key_a, period):
                            w_consistent += 1
                            candidate = decrypt_model_a(inv_perm, key_a, period, dec_fn)
                            bd = score_candidate(candidate, ngram_scorer=ngram_scorer)
                            sc = bd.crib_score
                            ng = bd.ngram_per_char if bd.ngram_per_char is not None else -999.0
                            if sc > w_best_score or (sc == w_best_score and ng > w_best_ngram):
                                w_best_score = sc
                                w_best_ngram = ng
                            if sc >= 24 or ng > -5.0:
                                hit = {
                                    'phase': 1, 'model': 'A', 'width': width,
                                    'period': period, 'variant': vname,
                                    'order': list(col_order),
                                    'crib_score': sc, 'ngram': ng,
                                    'ic': bd.ic_value, 'pt': candidate,
                                    'key': {str(k): v for k, v in key_a.items()},
                                }
                                all_hits.append(hit)
                                print(f"  ★ MODEL A HIT: w={width} p={period} {vname} "
                                      f"| {bd.summary}")
                                print(f"    PT: {candidate}")
                            if sc > global_best_score or (sc == global_best_score and ng > global_best_ngram):
                                global_best_score = sc
                                global_best_ngram = ng
                                global_best_pt = candidate
                                global_best_config = f"Model A w={width} p={period} {vname}"

                    # ── Model B (Trans→Vig encrypt, K3-like) ──
                    w_tested += 1
                    key_b = derive_key_model_b(inv_perm, period, key_fn)
                    if key_b is not None:
                        if check_bean_from_key(key_b, period):
                            w_consistent += 1
                            candidate = decrypt_model_b(inv_perm, key_b, period, dec_fn)
                            bd = score_candidate(candidate, ngram_scorer=ngram_scorer)
                            sc = bd.crib_score
                            ng = bd.ngram_per_char if bd.ngram_per_char is not None else -999.0
                            if sc > w_best_score or (sc == w_best_score and ng > w_best_ngram):
                                w_best_score = sc
                                w_best_ngram = ng
                            if sc >= 24 or ng > -5.0:
                                hit = {
                                    'phase': 1, 'model': 'B', 'width': width,
                                    'period': period, 'variant': vname,
                                    'order': list(col_order),
                                    'crib_score': sc, 'ngram': ng,
                                    'ic': bd.ic_value, 'pt': candidate,
                                    'key': {str(k): v for k, v in key_b.items()},
                                }
                                all_hits.append(hit)
                                print(f"  ★ MODEL B HIT: w={width} p={period} {vname} "
                                      f"| {bd.summary}")
                                print(f"    PT: {candidate}")
                            if sc > global_best_score or (sc == global_best_score and ng > global_best_ngram):
                                global_best_score = sc
                                global_best_ngram = ng
                                global_best_pt = candidate
                                global_best_config = f"Model B w={width} p={period} {vname}"

        w_elapsed = time.time() - w_t
        label = "exhaustive" if exhaustive else f"MC {len(orderings):,}"
        print(f"  Width {width:2d} ({label:>12s}): {w_tested:>10,} tested, "
              f"{w_consistent:>4} consistent, best crib={w_best_score}/24, "
              f"ngram={w_best_ngram:.2f} [{w_elapsed:.1f}s]")

        p1_tested += w_tested
        p1_consistent += w_consistent
        if w_best_score > p1_best_score:
            p1_best_score = w_best_score
        if w_best_ngram > p1_best_ngram:
            p1_best_ngram = w_best_ngram

    phase_stats['phase1'] = {
        'tested': p1_tested, 'consistent': p1_consistent,
        'best_score': p1_best_score, 'best_ngram': round(p1_best_ngram, 3),
    }
    print(f"\n  Phase 1 total: {p1_tested:,} tested, {p1_consistent} consistent, "
          f"best={p1_best_score}/24, best_ngram={p1_best_ngram:.2f}")

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 2: Keyword-based — user's described approach + cross-keywords
    # ══════════════════════════════════════════════════════════════════════════
    print("\n" + "─" * 78)
    print("PHASE 2: Keyword-based — VigDecrypt(CT, keyword) → InvColTrans → PT")
    print("  Tests Model B decryption: Vig decrypt first, then reverse transposition")
    print(f"  {len(KRYPTOS_KEYWORDS)} keywords × widths 2-15 × 3 variants")
    print("─" * 78)

    p2_tested = 0
    p2_best_score = 0
    p2_best_ngram = -999.0

    for keyword in KRYPTOS_KEYWORDS:
        kw_key = keyword_to_numeric(keyword)
        period = len(kw_key)
        kw_best_score = 0
        kw_best_ngram = -999.0

        for vname, dec_fn in VARIANTS_KEYWORD.items():
            # Step 1: Vig decrypt CT at CT positions → intermediate (fixed per keyword+variant)
            intermediate = [dec_fn(CT_IDX[j], kw_key[j % period]) for j in range(CT_LEN)]

            for width in range(2, 16):
                col_positions = build_col_positions(width)

                # Determine orderings to test
                orderings_to_test = []

                # Keyword-derived column order (if long enough)
                if len(keyword) >= width:
                    co = keyword_to_col_order(keyword, width)
                    if co is not None:
                        orderings_to_test.append(tuple(co))

                # Cross-keyword orderings
                for tkw in TRANS_KEYWORDS:
                    if len(tkw) >= width and tkw != keyword:
                        co = keyword_to_col_order(tkw, width)
                        if co is not None:
                            co_t = tuple(co)
                            if co_t not in orderings_to_test:
                                orderings_to_test.append(co_t)

                # Exhaustive or MC orderings
                if width <= 7:
                    seen = set(orderings_to_test)
                    for co in permutations(range(width)):
                        if co not in seen:
                            orderings_to_test.append(co)
                            seen.add(co)
                elif width <= 9:
                    seen = set(orderings_to_test)
                    for _ in range(MC_SAMPLES_KW):
                        co = list(range(width))
                        random.shuffle(co)
                        co_t = tuple(co)
                        if co_t not in seen:
                            seen.add(co_t)
                            orderings_to_test.append(co_t)
                else:
                    seen = set(orderings_to_test)
                    for _ in range(MC_SAMPLES_KW_LARGE):
                        co = list(range(width))
                        random.shuffle(co)
                        co_t = tuple(co)
                        if co_t not in seen:
                            seen.add(co_t)
                            orderings_to_test.append(co_t)

                for col_order in orderings_to_test:
                    inv_perm = build_inv_perm_scatter(list(col_order), col_positions)
                    p2_tested += 1

                    # Model B decryption: PT[pos] = intermediate[inv_perm[pos]]
                    # Fast crib check (24 comparisons)
                    sc = 0
                    for pos, pt_val in ALL_CRIB:
                        if intermediate[inv_perm[pos]] == pt_val:
                            sc += 1

                    if sc > kw_best_score:
                        kw_best_score = sc
                    if sc > p2_best_score:
                        p2_best_score = sc

                    if sc >= 10:  # Above noise — do full scoring
                        candidate = ''.join(ALPH[intermediate[inv_perm[pos]]]
                                            for pos in range(CT_LEN))
                        bd = score_candidate(candidate, ngram_scorer=ngram_scorer)
                        ng = bd.ngram_per_char if bd.ngram_per_char is not None else -999.0

                        if ng > kw_best_ngram:
                            kw_best_ngram = ng
                        if ng > p2_best_ngram:
                            p2_best_ngram = ng

                        print(f"  HIT: kw={keyword} w={width} {vname} | {bd.summary}")
                        print(f"    PT: {candidate[:50]}...")

                        hit = {
                            'phase': 2, 'model': 'B_kw', 'keyword': keyword,
                            'width': width, 'variant': vname,
                            'order': list(col_order),
                            'crib_score': sc, 'ngram': ng,
                            'pt': candidate,
                        }
                        all_hits.append(hit)

                        if sc > global_best_score or (sc == global_best_score and ng > global_best_ngram):
                            global_best_score = sc
                            global_best_ngram = ng
                            global_best_pt = candidate
                            global_best_config = f"kw={keyword} w={width} {vname}"

        print(f"  Keyword '{keyword}' (p={period}): best crib={kw_best_score}/24, "
              f"best_ngram={kw_best_ngram:.2f}")

    phase_stats['phase2'] = {
        'tested': p2_tested, 'best_score': p2_best_score,
        'best_ngram': round(p2_best_ngram, 3),
    }
    print(f"\n  Phase 2 total: {p2_tested:,} tested, best={p2_best_score}/24, "
          f"best_ngram={p2_best_ngram:.2f}")

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 3: Keyword-based Model A (reverse direction — key at PT positions)
    # ══════════════════════════════════════════════════════════════════════════
    print("\n" + "─" * 78)
    print("PHASE 3: Keyword-based Model A — VigDecrypt at PT positions")
    print("  Decrypt: intermediate[pos] = CT[inv_perm[pos]], "
          "PT[pos] = VigDec(intermediate, K[pos%p])")
    print(f"  {len(KRYPTOS_KEYWORDS)} keywords × widths 2-15 × 3 variants")
    print("─" * 78)

    p3_tested = 0
    p3_best_score = 0
    p3_best_ngram = -999.0

    for keyword in KRYPTOS_KEYWORDS:
        kw_key = keyword_to_numeric(keyword)
        period = len(kw_key)
        kw_best_score = 0
        kw_best_ngram = -999.0

        for vname, dec_fn in VARIANTS_KEYWORD.items():

            for width in range(2, 16):
                col_positions = build_col_positions(width)

                # Determine orderings (same logic as Phase 2)
                orderings_to_test = []

                if len(keyword) >= width:
                    co = keyword_to_col_order(keyword, width)
                    if co is not None:
                        orderings_to_test.append(tuple(co))

                for tkw in TRANS_KEYWORDS:
                    if len(tkw) >= width and tkw != keyword:
                        co = keyword_to_col_order(tkw, width)
                        if co is not None:
                            co_t = tuple(co)
                            if co_t not in orderings_to_test:
                                orderings_to_test.append(co_t)

                if width <= 7:
                    seen = set(orderings_to_test)
                    for co in permutations(range(width)):
                        if co not in seen:
                            orderings_to_test.append(co)
                            seen.add(co)
                elif width <= 9:
                    seen = set(orderings_to_test)
                    for _ in range(MC_SAMPLES_KW):
                        co = list(range(width))
                        random.shuffle(co)
                        co_t = tuple(co)
                        if co_t not in seen:
                            seen.add(co_t)
                            orderings_to_test.append(co_t)
                else:
                    seen = set(orderings_to_test)
                    for _ in range(MC_SAMPLES_KW_LARGE):
                        co = list(range(width))
                        random.shuffle(co)
                        co_t = tuple(co)
                        if co_t not in seen:
                            seen.add(co_t)
                            orderings_to_test.append(co_t)

                for col_order in orderings_to_test:
                    inv_perm = build_inv_perm_scatter(list(col_order), col_positions)
                    p3_tested += 1

                    # Model A: PT[pos] = dec_fn(CT[inv_perm[pos]], kw_key[pos%p])
                    # Fast crib check
                    sc = 0
                    for pos, pt_val in ALL_CRIB:
                        ct_val = CT_IDX[inv_perm[pos]]
                        if dec_fn(ct_val, kw_key[pos % period]) == pt_val:
                            sc += 1

                    if sc > kw_best_score:
                        kw_best_score = sc
                    if sc > p3_best_score:
                        p3_best_score = sc

                    if sc >= 10:  # Above noise — full scoring
                        candidate = ''.join(
                            ALPH[dec_fn(CT_IDX[inv_perm[pos]], kw_key[pos % period])]
                            for pos in range(CT_LEN)
                        )
                        bd = score_candidate(candidate, ngram_scorer=ngram_scorer)
                        ng = bd.ngram_per_char if bd.ngram_per_char is not None else -999.0

                        if ng > kw_best_ngram:
                            kw_best_ngram = ng
                        if ng > p3_best_ngram:
                            p3_best_ngram = ng

                        print(f"  HIT: kw={keyword} w={width} {vname} | {bd.summary}")
                        print(f"    PT: {candidate[:50]}...")

                        hit = {
                            'phase': 3, 'model': 'A_kw', 'keyword': keyword,
                            'width': width, 'variant': vname,
                            'order': list(col_order),
                            'crib_score': sc, 'ngram': ng,
                            'pt': candidate,
                        }
                        all_hits.append(hit)

                        if sc > global_best_score or (sc == global_best_score and ng > global_best_ngram):
                            global_best_score = sc
                            global_best_ngram = ng
                            global_best_pt = candidate
                            global_best_config = f"ModelA kw={keyword} w={width} {vname}"

        print(f"  Keyword '{keyword}' (p={period}): best crib={kw_best_score}/24, "
              f"best_ngram={kw_best_ngram:.2f}")

    phase_stats['phase3'] = {
        'tested': p3_tested, 'best_score': p3_best_score,
        'best_ngram': round(p3_best_ngram, 3),
    }
    print(f"\n  Phase 3 total: {p3_tested:,} tested, best={p3_best_score}/24, "
          f"best_ngram={p3_best_ngram:.2f}")

    # ══════════════════════════════════════════════════════════════════════════
    # FINAL SUMMARY
    # ══════════════════════════════════════════════════════════════════════════
    elapsed = time.time() - t_start
    total = p1_tested + p2_tested + p3_tested

    print("\n" + "=" * 78)
    print("E-HYBRID-04 SUMMARY")
    print("=" * 78)
    print(f"Total configurations tested: {total:,}")
    print(f"Elapsed: {elapsed:.1f}s ({elapsed/60:.1f}m)")
    print()
    print(f"Phase 1 (crib-derived, both models): {p1_tested:,} tested, "
          f"{p1_consistent} consistent, best={p1_best_score}/24")
    print(f"Phase 2 (keyword Model B): {p2_tested:,} tested, best={p2_best_score}/24")
    print(f"Phase 3 (keyword Model A): {p3_tested:,} tested, best={p3_best_score}/24")
    print()
    print(f"GLOBAL BEST: crib={global_best_score}/24, ngram={global_best_ngram:.2f}")
    print(f"  Config: {global_best_config}")
    if global_best_pt:
        print(f"  PT: {global_best_pt}")
    print()
    print(f"Hits above noise (score≥10 or ngram>-5.0): {len(all_hits)}")
    for h in all_hits[:20]:  # Show first 20
        print(f"  {h.get('model','?')} w={h.get('width','?')} p={h.get('period', h.get('keyword','?'))} "
              f"{h.get('variant','?')} crib={h.get('crib_score','?')}/24 "
              f"ngram={h.get('ngram', -999):.2f}")

    # ── Verdict ──
    print()
    if global_best_score >= 24 and global_best_ngram > -5.0:
        verdict = "promising"
        print("VERDICT: PROMISING — candidate found with full crib match + English quality")
    elif p1_consistent == 0 and p2_best_score <= 9 and p3_best_score <= 9:
        verdict = "disproved"
        print("VERDICT: DISPROVED — Vigenère + Columnar Transposition hybrid (both orders) "
              "at periods 4-13 with widths 2-15. Zero consistent crib-derived solutions, "
              "keyword-based all noise.")
    else:
        verdict = "inconclusive"
        print("VERDICT: INCONCLUSIVE — some signal but below breakthrough threshold")

    # ── Save results ──
    out_dir = os.path.join(os.path.dirname(__file__), '..', 'results')
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, 'e_hybrid_04_reverse_k3.json')
    with open(out_file, 'w') as f:
        json.dump({
            'experiment': 'E-HYBRID-04',
            'hypothesis': 'K4 = Vig FIRST → ColTrans (reverse K3) OR ColTrans → Vig (K3 method)',
            'total_tested': total,
            'global_best_score': global_best_score,
            'global_best_ngram': round(global_best_ngram, 3),
            'global_best_config': global_best_config,
            'global_best_pt': global_best_pt,
            'phases': phase_stats,
            'hits': all_hits[:100],
            'elapsed_seconds': round(elapsed, 1),
            'verdict': verdict,
            'new_territory': {
                'new_periods': PERIODS_NEW,
                'variant_beaufort_keyword': True,
                'quadgram_scoring': True,
                'cross_keyword_pairs': True,
                'extended_keywords': len(KRYPTOS_KEYWORDS),
            },
        }, f, indent=2)
    print(f"\nResults saved to {out_file}")

    return verdict, global_best_score


if __name__ == '__main__':
    main()
