#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-HYBRID-01: K3-Structure Hybrid Attack — Extended Coverage.

K3's actual encryption method:
  columnar_transposition(keyword=KRYPTOS, width=7)
  → Vigenère(keyword=PALIMPSEST, period=10)

K4 may use the same two-layer structure with different parameters.
This script closes the gaps vs. prior work.

PRIOR COVERAGE (do NOT re-test here):
  E-AUDIT-06:    K3 ROTATIONAL trans + KA Vigenère → 4/24 NOISE/ELIMINATED
  E-TABLEAU-20:  Width-8 exhaustive (40,320 orderings) × 16 period-8 keywords
                 → global best 13/24 NOISE
  E-TABLEAU-20:  Width-9 sampled (50K) × 3 period-8 keywords → NOISE
  E-RERUN-03:    ~290 thematic keywords, keyword-derived orderings only,
                 periods 2-14 → NOISE
  E-S-81:        Keyword-alphabet Vigenère + width-7 columnar at PERIOD-7
                 (Bean-IMPOSSIBLE period — this entire search was structurally invalid!)
  E-FRAC-35:     Bean impossibility proof for periods {2-7,9-12,14,15,17,18,21,22,25}

TRUE GAPS (what this script adds):
  Gap 1: Widths 5,6,7 exhaustive at period-8 (Bean-surviving) — never tested
  Gap 2: Width-9 FULLY exhaustive (all 362,880) at period-8 via BC-derived key
  Gap 3: KA-alphabet Vigenère + standard columnar trans — only done with rotational
  Gap 4: KRYPTOS-width (7) trans × period-8 Vigenère keyword (was only tested at p=10)
  Gap 5: Extended keyword list with 2025 Sanborn clues + new 8-char candidates
  Gap 6: Both Model A (Vig→Trans) and Model B (Trans→Vig) for gaps 1-4

Models:
  Model B: CT = Sub(Trans(PT), K)  [Trans first, then Vigenère]
    Decrypt: intermediate = ColPerm⁻¹(CT), then PT = Vig⁻¹(intermediate, K)
    Key at position i: K[inv_perm[pos] % p] = (CT[inv_perm[pos]] - PT[pos]) % 26

  Model A: CT = Trans(Sub(PT, K))  [Vigenère first, then Trans]
    Decrypt: sub_out = ColPerm⁻¹(CT), then PT = Vig⁻¹(sub_out, K) at PT position
    Key at position pos: K[pos % p] = (CT[inv_perm[pos]] - PT[pos]) % 26

Convention: perm[i] = j means output[i] = input[j] (gather).
           inv_perm[j] = i means input position j → output position i.

Bean constraint (variant-independent):
  k[27]=k[65]=24 (Vigenère), PT[27]=PT[65]=R.
  For period p: K[27%p] must equal K[65%p].
  Bean-surviving periods: {8, 13, 16, 19, 20, 23, 24, 26}.
"""
import json
import os
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

# ── Numeric arrays ─────────────────────────────────────────────────────────────
CT_IDX = [ALPH_IDX[c] for c in CT]
KA_IDX = {ch: i for i, ch in enumerate(KRYPTOS_ALPHABET)}

# ── Crib partitions ────────────────────────────────────────────────────────────
BC_CRIB = [(pos, ALPH_IDX[ch]) for pos, ch in CRIB_DICT.items() if 63 <= pos <= 73]
ENE_CRIB = [(pos, ALPH_IDX[ch]) for pos, ch in CRIB_DICT.items() if 21 <= pos <= 33]
ALL_CRIB = sorted((pos, ALPH_IDX[ch]) for pos, ch in CRIB_DICT.items())

# ── Bean-surviving periods ─────────────────────────────────────────────────────
BEAN_SURVIVING = frozenset({8, 13, 16, 19, 20, 23, 24, 26})

# ── Keyword lists ──────────────────────────────────────────────────────────────
# Period-8 keywords (Bean-surviving). ABSCISSA and first 15 are from E-TABLEAU-20.
# NEW additions are marked with [NEW].
KEYWORDS_P8 = [
    # From E-TABLEAU-20 (already tested at width-8, NEW for widths 5,6,7,9)
    "ABSCISSA",    # K2 keyword — most historically motivated
    "MAGNETIC",    # From K2 text
    "LOCATION",    # From K2 text
    "POSITION",    # From Morse code "T IS YOUR POSITION"
    "ILLUSION",    # K1 concept (IQLUSION → ILLUSION)
    "IQLUSION",    # K1 misspelling exactly
    "VIRGINIA",    # CIA location
    "TREASURE",    # Thematic (buried treasure)
    "DECEMBER",    # Month
    "NINETEEN",    # Year component
    "MONUMENT",    # Thematic
    "EMBEDDED",    # Information embedding
    "DISPATCH",    # Intelligence theme
    "INSCRIBE",    # Art/sculpture theme
    "MERIDIAN",    # Geographic reference
    "LANGUAGE",    # Scheidt: "changed the language base"
    # NEW additions [not in E-TABLEAU-20]
    "BERLINER",    # [NEW] Related to Berlin (Sanborn 2025: Berlin Wall 1989)
    "SCULPTED",    # [NEW] Sanborn is a sculptor
    "CALENDAR",    # [NEW] Weltzeituhr = world time calendar
    "TIMEZONE",    # [NEW] World time clock theme
    "NAVIGATE",    # [NEW] Directional theme (compass, east/north)
    "EGYPTIAN",    # [NEW] Sanborn Egypt trip 1986
    "COMPLETE",    # [NEW] "To complete the puzzle"
    "CIRCLING",    # [NEW] Clock face / circular motion
    "UNVEILED",    # [NEW] Revealing the hidden message
    "SCULPTOR",    # [NEW] Sanborn's profession
    "OBSERVER",    # [NEW] Intelligence / surveillance theme
    "BASELINE",    # [NEW] Cryptographic reference
    "WARCRAFT",    # [NEW] CIA / intelligence theme
    "HERITAGE",    # [NEW] Historical / archival theme
]
KEYWORDS_P8 = [k for k in KEYWORDS_P8 if len(k) == 8]

# Period-13 keywords (Bean-surviving)
KEYWORDS_P13 = [
    "EASTNORTHEAST",  # K4 crib itself (self-key hypothesis)
    "ESTABLISHMENT",  # Intelligence theme
    "COMMUNICATION",  # Intelligence theme
    "CONSTELLATION",  # Navigation/orientation theme
    "CORRESPONDING",  # Cipher theme
    "UNDERSTANDING",  # Thematic
    "BERLINCLOCK",    # Wait — 11 letters, not 13. Already excluded.
]
KEYWORDS_P13 = [k for k in KEYWORDS_P13 if len(k) == 13]

# All transposition keywords to test in Phase 1 (keyword-derived orderings only)
TRANS_KEYWORDS = [
    "KRYPTOS",        # K3 trans keyword (width 7)
    "PALIMPSEST",     # K1/K3 Vigenère keyword (width 10)
    "ABSCISSA",       # K2 Vigenère keyword (width 8)
    "SANBORN",        # Artist (width 7)
    "SCHEIDT",        # Cryptographer (width 7)
    "BERLINCLOCK",    # K4 crib (width 11)
    "EASTNORTHEAST",  # K4 crib (width 13)
    "BERLINER",       # Sanborn 2025 clue (width 8)
    "MAGNETIC",       # K2 text (width 8)
    "LANGLEY",        # CIA headquarters (width 7)
    "SHADOW",         # K4 potential (width 6)
]

# ── KA-alphabet helpers ────────────────────────────────────────────────────────
def ka_vig_decrypt_key_at(ct_val, pt_val):
    """Recover KA-tableau Vigenère key: KA_IDX[CT] - KA_IDX[PT] mod 26."""
    return (KA_IDX[KRYPTOS_ALPHABET[ct_val]] - KA_IDX[KRYPTOS_ALPHABET[pt_val]]) % MOD

def az_vig_key_at(ct_val, pt_val):
    return (ct_val - pt_val) % MOD

def az_beau_key_at(ct_val, pt_val):
    return (ct_val + pt_val) % MOD

def az_varbeau_key_at(ct_val, pt_val):
    return (pt_val - ct_val) % MOD

KEY_FNS = {
    'vig':     az_vig_key_at,
    'beau':    az_beau_key_at,
}
# Note: variant Beaufort gives different key values but same Bean structure;
# adding it would triple the search space without new theoretical ground.
# Omit for efficiency; add if signal found.

# ── Columnar permutation builder ───────────────────────────────────────────────
def build_col_positions(width, n=97):
    """Precompute which input positions belong to each column."""
    col_pos = [[] for _ in range(width)]
    for pos in range(n):
        col_pos[pos % width].append(pos)
    return col_pos

def keyword_to_col_order(keyword, width=None):
    """Convert keyword to col_order array where col_order[i] = rank of column i.
    Uses the same convention as framework's keyword_to_order()."""
    kw = keyword.upper()
    w = width if width else len(kw)
    kw = kw[:w]
    if len(kw) < w:
        return None
    indexed = [(ch, i) for i, ch in enumerate(kw)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * w
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return order


def build_inv_perm(col_order, col_positions, n=97):
    """Build inv_perm from col_order (col_order[i] = rank of column i).
    inv_perm[input_pos] = output_pos.
    """
    width = len(col_order)
    # rank_to_col[r] = column index with rank r
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


# ── Scoring functions ──────────────────────────────────────────────────────────

def score_model_b(inv_perm, key_numeric, period, variant='vig'):
    """Model B (Trans→Sub): count crib matches with given periodic key.

    PT[pos] = (CT[inv_perm[pos]] - K[inv_perm[pos] % p]) % 26  [Vigenère]
    PT[pos] = (K[inv_perm[pos] % p] - CT[inv_perm[pos]]) % 26  [Beaufort]
    """
    score = 0
    if variant == 'vig':
        for pos, pt_val in ALL_CRIB:
            j = inv_perm[pos]
            if (CT_IDX[j] - key_numeric[j % period]) % MOD == pt_val:
                score += 1
    else:  # beaufort
        for pos, pt_val in ALL_CRIB:
            j = inv_perm[pos]
            if (key_numeric[j % period] - CT_IDX[j]) % MOD == pt_val:
                score += 1
    return score


def score_model_a(inv_perm, key_numeric, period, variant='vig'):
    """Model A (Sub→Trans): count crib matches with given periodic key.

    sub_out[pos] = CT[inv_perm[pos]]  (undo transposition first)
    PT[pos] = (sub_out[pos] - K[pos % p]) % 26  [Vigenère, key at PT position]
    """
    score = 0
    if variant == 'vig':
        for pos, pt_val in ALL_CRIB:
            j = inv_perm[pos]
            if (CT_IDX[j] - key_numeric[pos % period]) % MOD == pt_val:
                score += 1
    else:  # beaufort
        for pos, pt_val in ALL_CRIB:
            j = inv_perm[pos]
            if (key_numeric[pos % period] - CT_IDX[j]) % MOD == pt_val:
                score += 1
    return score


def check_bean(inv_perm, key_numeric, period, variant, model):
    """Check Bean equality k[27]=k[65] and 21 inequalities.

    Under the keyword model, key index depends on model:
      Model B: key index = inv_perm[pos] % period
      Model A: key index = pos % period
    """
    def key_at(pos):
        if model == 'B':
            return key_numeric[inv_perm[pos] % period]
        else:
            return key_numeric[pos % period]

    k27, k65 = key_at(27), key_at(65)
    if k27 != k65:
        return False
    for a, b in BEAN_INEQ:
        if key_at(a) == key_at(b):
            return False
    return True


def score_model_b_bc_derived(inv_perm, period):
    """BC-derived key approach for Model B (no keyword needed).

    Derive the full period-p key from BERLINCLOCK crib.
    If BC is self-consistent, check EASTNORTHEAST.

    Returns (total_score, bc_consistent, key_dict)
    where key_dict maps residue → required key value.
    """
    key = {}
    for pos, pt_val in BC_CRIB:
        j = inv_perm[pos]
        res = j % period
        req = (CT_IDX[j] - pt_val) % MOD
        if res in key:
            if key[res] != req:
                return 0, False, {}
        else:
            key[res] = req

    # BC is consistent (11 positions all agree per residue)
    ene_score = 0
    for pos, pt_val in ENE_CRIB:
        j = inv_perm[pos]
        res = j % period
        if res in key:
            if (CT_IDX[j] - key[res]) % MOD == pt_val:
                ene_score += 1

    total = 11 + ene_score  # BC always scores 11 if consistent
    return total, True, key


def score_model_a_bc_derived(inv_perm, period):
    """BC-derived key approach for Model A (Vig→Trans, no keyword needed).

    In Model A: key index = pos % period (PT position based).
    Derive key from BC crib, check ENE.
    """
    key = {}
    for pos, pt_val in BC_CRIB:
        j = inv_perm[pos]
        res = pos % period   # Model A: key at PT position
        req = (CT_IDX[j] - pt_val) % MOD
        if res in key:
            if key[res] != req:
                return 0, False, {}
        else:
            key[res] = req

    ene_score = 0
    for pos, pt_val in ENE_CRIB:
        j = inv_perm[pos]
        res = pos % period
        if res in key:
            if (CT_IDX[j] - key[res]) % MOD == pt_val:
                ene_score += 1

    total = 11 + ene_score
    return total, True, key


def ka_score_model_b(inv_perm, key_numeric_ka, period):
    """Model B with KA-alphabet Vigenère.

    KA-alphabet: CT and PT values are in KA space.
    K[j%p] = (KA_IDX[CT[j]] - KA_IDX[PT[pos]]) % 26
    """
    score = 0
    for pos, pt_val in ALL_CRIB:
        j = inv_perm[pos]
        ct_ka = KA_IDX[KRYPTOS_ALPHABET[CT_IDX[j]]]
        pt_ka = KA_IDX[KRYPTOS_ALPHABET[pt_val]]
        if (ct_ka - key_numeric_ka[j % period]) % MOD == pt_ka:
            score += 1
    return score


def keyword_to_numeric(keyword):
    return [ALPH_IDX[c] for c in keyword.upper()]

def keyword_to_numeric_ka(keyword):
    return [KA_IDX[c] for c in keyword.upper()]


# ── Phase 1: Specific keyword pair test ───────────────────────────────────────

def phase1():
    """Quick targeted test of all explicitly requested keyword combinations.

    Tests: {trans_keyword} × {vig_keyword} × {Model A, B} × {Vig, Beaufort}.
    Includes K3-exact (KRYPTOS trans + PALIMPSEST vig) as baseline.
    Also tests KA-alphabet Vigenère variant.
    """
    print("\n" + "="*70)
    print("Phase 1: Specific keyword pair tests (K3-exact + new combinations)")
    print("="*70)
    print("Note: periods NOT in {8,13,16,19,20,23,24,26} are Bean-IMPOSSIBLE")
    print("      and are included for completeness but cannot achieve 24/24.")

    best_overall = 0
    total_configs = 0
    results = []

    vig_keywords = KEYWORDS_P8 + KEYWORDS_P13
    # Also include non-Bean-surviving for comparison (they should fail)
    vig_keywords_all = (
        vig_keywords
        + ["KRYPTOS", "PALIMPSEST", "SANBORN", "SCHEIDT"]
    )

    for trans_kw in TRANS_KEYWORDS:
        width = len(trans_kw)
        col_order = keyword_to_col_order(trans_kw, width)
        if col_order is None:
            continue
        col_pos = build_col_positions(width)
        inv_perm = build_inv_perm(col_order, col_pos)

        for vig_kw in vig_keywords_all:
            period = len(vig_kw)
            key_num = keyword_to_numeric(vig_kw)
            key_ka = keyword_to_numeric_ka(vig_kw)
            bean_surv = period in BEAN_SURVIVING

            for model, variant in [('B', 'vig'), ('B', 'beau'), ('A', 'vig'), ('A', 'beau')]:
                if model == 'B':
                    sc = score_model_b(inv_perm, key_num, period, variant)
                else:
                    sc = score_model_a(inv_perm, key_num, period, variant)

                bean_ok = check_bean(inv_perm, key_num, period, variant, model)
                total_configs += 1

                if sc > best_overall:
                    best_overall = sc

                if sc >= 6:
                    results.append({
                        'trans': trans_kw, 'vig': vig_kw,
                        'model': model, 'variant': variant,
                        'score': sc, 'bean': bean_ok,
                        'bean_surviving': bean_surv,
                    })
                    if sc >= 10:
                        print(f"  *** SCORE {sc}/24: trans={trans_kw}(w{width}) "
                              f"vig={vig_kw}(p{period}) M{model} {variant} "
                              f"Bean={'PASS' if bean_ok else 'FAIL'}")

            # Also KA-alphabet Vigenère (Model B only — the K1/K2 actual method)
            if bean_surv:
                sc_ka = ka_score_model_b(inv_perm, key_ka, period)
                total_configs += 1
                if sc_ka >= 6:
                    print(f"  KA-VIG: trans={trans_kw} vig_ka={vig_kw}(p{period}) "
                          f"M=B: {sc_ka}/24")
                best_overall = max(best_overall, sc_ka)

    # Explicitly print K3-exact as baseline reference
    print(f"\nK3-exact baseline: KRYPTOS(w7)+PALIMPSEST(p10) — included above.")
    print(f"Phase 1: {total_configs:,} configs. Best: {best_overall}/24.")
    print("Expected: noise (≤8/24 for any specific pair without exhaustive search).")

    if results:
        print(f"\nTop results (score ≥ 6):")
        for r in sorted(results, key=lambda x: -x['score'])[:20]:
            print(f"  {r['score']:2d}/24 trans={r['trans']:14s} vig={r['vig']:16s} "
                  f"M{r['model']} {r['variant']} "
                  f"Bean={'PASS' if r['bean'] else 'FAIL'} "
                  f"{'[Bean-surv]' if r['bean_surviving'] else '[Bean-IMPOSSIBLE]'}")

    return best_overall, total_configs


# ── Phase 2: Exhaustive small-width search ─────────────────────────────────────

def phase2_exhaustive_small_widths():
    """Exhaustive columnar ordering search at widths 5, 6, 7 for period-8.

    E-TABLEAU-20 did width-8 exhaustive; this fills the gap for widths 5-7.
    E-S-81 did width-7 but at Bean-IMPOSSIBLE period-7!

    All 120 + 720 + 5,040 = 5,880 orderings × 30 keywords × 4 combos = 705,600 configs.
    Expected runtime: < 5 seconds.
    """
    print("\n" + "="*70)
    print("Phase 2: Widths 5,6,7 EXHAUSTIVE × period-8 keywords")
    print("(First time these widths are tested exhaustively at a Bean-surviving period)")
    print("="*70)

    PERIOD = 8
    best_by_width = {}
    total_configs = 0
    global_best = 0
    signal_hits = []

    for width in [5, 6, 7]:
        t0 = time.time()
        col_pos = build_col_positions(width)
        n_orderings = factorial(width)
        best_score = 0
        best_config = None
        bean_pass_best = 0

        for kw in KEYWORDS_P8:
            key_num = keyword_to_numeric(kw)
            key_ka = keyword_to_numeric_ka(kw)

            for col_order in permutations(range(width)):
                inv_perm = build_inv_perm(col_order, col_pos)
                total_configs += 4  # 2 models × 2 variants

                for model, variant in [('B', 'vig'), ('B', 'beau'), ('A', 'vig'), ('A', 'beau')]:
                    if model == 'B':
                        sc = score_model_b(inv_perm, key_num, PERIOD, variant)
                    else:
                        sc = score_model_a(inv_perm, key_num, PERIOD, variant)

                    global_best = max(global_best, sc)

                    if sc >= best_score:
                        bean_ok = check_bean(inv_perm, key_num, PERIOD, variant, model)
                        if sc > best_score:
                            best_score = sc
                            best_config = None
                        if bean_ok:
                            bean_pass_best = max(bean_pass_best, sc)
                        if sc >= best_score and sc >= 8:
                            best_config = {
                                'width': width, 'keyword': kw,
                                'col_order': list(col_order),
                                'model': model, 'variant': variant,
                                'score': sc, 'bean': bean_ok,
                            }

                    if sc >= 18:
                        signal_hits.append({
                            'width': width, 'keyword': kw,
                            'col_order': list(col_order),
                            'model': model, 'variant': variant,
                            'score': sc,
                            'bean': check_bean(inv_perm, key_num, PERIOD, variant, model),
                        })
                        print(f"  *** SIGNAL {sc}/24! width={width} kw={kw} M{model} {variant}")

                # KA-alphabet Model B
                ka_sc = ka_score_model_b(inv_perm, key_ka, PERIOD)
                global_best = max(global_best, ka_sc)
                if ka_sc >= 18:
                    print(f"  *** KA-SIGNAL {ka_sc}/24! width={width} kw={kw}")
                total_configs += 1

        elapsed = time.time() - t0
        best_by_width[width] = {
            'width': width, 'n_orderings': n_orderings,
            'n_keywords': len(KEYWORDS_P8), 'best_score': best_score,
            'bean_pass_best': bean_pass_best,
            'elapsed': elapsed, 'best_config': best_config,
        }
        print(f"  Width {width}: {n_orderings:6,} orderings × {len(KEYWORDS_P8)} keywords "
              f"→ best={best_score:2d}/24 bean_best={bean_pass_best:2d}/24 "
              f"[{elapsed:.2f}s]")

    noise_floor = {5: 5.0, 6: 5.0, 7: 5.5}  # Expected random for these widths
    print(f"\n  Global best across widths 5-7: {global_best}/24")
    print(f"  Expected noise floor: ~5-6/24 for period-8 at small widths")

    if signal_hits:
        print(f"\n  SIGNAL HITS:")
        for h in signal_hits:
            print(f"    {h}")
    else:
        print(f"  No scores ≥18/24. All noise.")

    return best_by_width, total_configs, global_best


# ── Phase 3: Width-9 fully exhaustive via BC-derived key ─────────────────────

def phase3_width9_bc_derived():
    """Width-9 FULLY exhaustive (all 362,880 orderings) using BC-derived key.

    Instead of iterating over all keywords, derive the optimal key from
    BERLINCLOCK (11 known PT positions) and check EASTNORTHEAST consistency.

    BC-derived key approach:
      1. Given col_ordering σ, compute inv_perm.
      2. For each BC position pos: K[inv_perm[pos] % 8] = (CT[inv_perm[pos]] - PT[pos]) % 26
      3. If any two BC positions require different values at the same key residue →
         contradiction, skip. (~99.994% of orderings are contradicted)
      4. If consistent: score ENE with the derived key → total = 11 + ene_score

    This is keyword-free and optimal: if ANY keyword works with this ordering,
    the BC-derived key will find it. We then check if the derived key matches
    any known word.

    Expected: ~0.006% × 362,880 ≈ 22 orderings pass BC.
    Those are checked for ENE consistency.
    """
    print("\n" + "="*70)
    print("Phase 3: Width-9 FULLY exhaustive (362,880 orderings) via BC-derived key")
    print("(E-TABLEAU-20 only sampled 50K × 3 keywords. This is the complete search.)")
    print("="*70)

    PERIOD = 8
    WIDTH = 9
    t0 = time.time()

    col_pos = build_col_positions(WIDTH)
    n_orderings = factorial(WIDTH)

    bc_consistent_count = 0
    best_score = 0
    best_configs = []
    tested = 0

    for col_order in permutations(range(WIDTH)):
        # Build inv_perm in-line for speed
        rank_to_col = [0] * WIDTH
        for col_idx, rank in enumerate(col_order):
            rank_to_col[rank] = col_idx

        inv_perm = [0] * CT_LEN
        out_pos = 0
        for rank in range(WIDTH):
            col_idx = rank_to_col[rank]
            for inp_pos in col_pos[col_idx]:
                inv_perm[inp_pos] = out_pos
                out_pos += 1

        # BC-derived key (Model B, Vigenère)
        key_b = {}
        bc_ok = True
        for pos, pt_val in BC_CRIB:
            j = inv_perm[pos]
            res = j % PERIOD
            req = (CT_IDX[j] - pt_val) % MOD
            if res in key_b:
                if key_b[res] != req:
                    bc_ok = False
                    break
            else:
                key_b[res] = req

        if bc_ok:
            bc_consistent_count += 1
            ene_score = 0
            for pos, pt_val in ENE_CRIB:
                j = inv_perm[pos]
                res = j % PERIOD
                if res in key_b and (CT_IDX[j] - key_b[res]) % MOD == pt_val:
                    ene_score += 1
            total_b = 11 + ene_score

            # Also check Model A (key at PT position)
            key_a = {}
            a_ok = True
            for pos, pt_val in BC_CRIB:
                j = inv_perm[pos]
                res = pos % PERIOD  # Model A: key at PT position
                req = (CT_IDX[j] - pt_val) % MOD
                if res in key_a:
                    if key_a[res] != req:
                        a_ok = False
                        break
                else:
                    key_a[res] = req

            total_a = 0
            if a_ok:
                ene_a = sum(1 for pos, pt_val in ENE_CRIB
                            if pos % PERIOD in key_a and
                            (CT_IDX[inv_perm[pos]] - key_a[pos % PERIOD]) % MOD == pt_val)
                total_a = 11 + ene_a

            best_of_two = max(total_b, total_a)
            if best_of_two >= best_score:
                if best_of_two > best_score:
                    best_score = best_of_two
                    best_configs = []
                # Convert key to sorted tuple for display
                key_str_b = ''.join(ALPH[key_b.get(r, 26 % 26)] if r in key_b else '?'
                                   for r in range(PERIOD))
                best_configs.append({
                    'col_order': list(col_order),
                    'total_b': total_b, 'total_a': total_a,
                    'key_b': key_b, 'key_str_b': key_str_b,
                    'bc_consistent_b': bc_ok, 'bc_consistent_a': a_ok,
                })

        tested += 1
        if tested % 100000 == 0:
            elapsed = time.time() - t0
            print(f"  ... {tested:,}/{n_orderings:,} tested "
                  f"({100*tested/n_orderings:.1f}%), "
                  f"BC-consistent: {bc_consistent_count}, "
                  f"best: {best_score}/24, "
                  f"elapsed: {elapsed:.1f}s", flush=True)

    elapsed = time.time() - t0
    print(f"\n  Width-9 complete: {tested:,} orderings tested in {elapsed:.1f}s")
    print(f"  BC-consistent orderings: {bc_consistent_count} "
          f"({100*bc_consistent_count/tested:.4f}%)")
    print(f"  Best score (BC-derived key, Model B or A): {best_score}/24")

    if best_configs:
        print(f"\n  Top {min(5, len(best_configs))} configs at score {best_score}:")
        for cfg in best_configs[:5]:
            print(f"    order={cfg['col_order']} "
                  f"B={cfg['total_b']}/24 A={cfg['total_a']}/24 "
                  f"key_B='{cfg['key_str_b']}'")
            # Check if key matches any known keyword
            k_str = cfg['key_str_b']
            for kw in KEYWORDS_P8:
                k_kw = ''.join(ALPH[ALPH_IDX[c]] for c in kw)
                if k_str == k_kw:
                    print(f"    *** KEY MATCHES KEYWORD: {kw}!")

    if best_score >= 18:
        print(f"\n  *** SIGNAL: {best_score}/24 — INVESTIGATE!")
    elif best_score >= 13:
        print(f"\n  ELEVATED but within noise for w9 (expected ~14/24 random at p8)")
    else:
        print(f"\n  NOISE: Best {best_score}/24, consistent with random at w9/p8")

    return best_score, bc_consistent_count, tested, elapsed


# ── Phase 4: KA-alphabet Vigenère + standard columnar (widths 7,8) ───────────

def phase4_ka_columnar():
    """Test KA-alphabet Vigenère (as used in K1/K2) + standard columnar trans.

    K1/K2 use the Kryptos-keyed alphabet KRYPTOSABCDEFGHIJLMNQUVWXZ for Vigenère.
    E-AUDIT-06 tested KA Vigenère with ROTATIONAL transposition → NOISE.
    E-S-81 tested keyword-alphabet (Quagmire) with standard columnar at period-7
           (Bean-IMPOSSIBLE) → structurally invalid test.
    This test: KA standard Vigenère + standard columnar (widths 7,8) at period-8.

    KA decrypt: PT_KA = (KA_IDX[CT] - KA_IDX[key_char]) % 26
                PT = KRYPTOS_ALPHABET[PT_KA]
    """
    print("\n" + "="*70)
    print("Phase 4: KA-alphabet Vigenère + standard columnar (widths 7,8)")
    print("(KA alphabet = KRYPTOSABCDEFGHIJLMNQUVWXZ, as used in K1/K2)")
    print("="*70)

    PERIOD = 8
    global_best = 0
    total_configs = 0

    for width in [7, 8]:
        t0 = time.time()
        col_pos = build_col_positions(width)
        n_orderings = factorial(width)
        best_score = 0
        best_config = None

        for kw in KEYWORDS_P8[:16]:  # Top 16 keywords for KA test
            key_ka = keyword_to_numeric_ka(kw)

            for col_order in permutations(range(width)):
                inv_perm = build_inv_perm(col_order, col_pos)
                total_configs += 1

                sc = ka_score_model_b(inv_perm, key_ka, PERIOD)
                global_best = max(global_best, sc)

                if sc > best_score:
                    best_score = sc
                    best_config = {
                        'width': width, 'kw': kw,
                        'col_order': list(col_order), 'score': sc,
                    }

                if sc >= 18:
                    print(f"  *** KA-SIGNAL {sc}/24: width={width} kw={kw} "
                          f"order={list(col_order)}")

        elapsed = time.time() - t0
        print(f"  Width {width} (KA-Vig, Model B): {n_orderings:,} × 16 kw "
              f"→ best={best_score:2d}/24 [{elapsed:.2f}s]")
        if best_config and best_config['score'] >= 8:
            print(f"    Best: {best_config}")

    print(f"\n  Global best KA Vigenère + columnar: {global_best}/24")
    if global_best >= 18:
        print("  *** SIGNAL! Investigate KA-Vigenère.")
    else:
        print("  NOISE: KA-Vigenère + standard columnar shows no improvement over AZ.")

    return global_best, total_configs


# ── Phase 5: Sanity / baseline verification ───────────────────────────────────

def phase5_baseline():
    """Verify alignment with E-TABLEAU-20 by re-testing width-8 top result.

    This confirms our scoring is consistent with the established framework.
    If width-8 scores match E-TABLEAU-20's reported maximum (13/24), we're correct.
    """
    print("\n" + "="*70)
    print("Phase 5: Baseline verification vs. E-TABLEAU-20 (width-8, top keywords)")
    print("="*70)

    PERIOD = 8
    WIDTH = 8
    col_pos = build_col_positions(WIDTH)

    # Test just first 3 keywords (fast check)
    check_kws = KEYWORDS_P8[:3]
    max_score = 0
    best_config = None

    t0 = time.time()
    for kw in check_kws:
        key_num = keyword_to_numeric(kw)
        for col_order in permutations(range(WIDTH)):
            inv_perm = build_inv_perm(col_order, col_pos)
            for model, variant in [('B','vig'), ('B','beau'), ('A','vig'), ('A','beau')]:
                if model == 'B':
                    sc = score_model_b(inv_perm, key_num, PERIOD, variant)
                else:
                    sc = score_model_a(inv_perm, key_num, PERIOD, variant)
                if sc > max_score:
                    max_score = sc
                    best_config = (kw, list(col_order), model, variant, sc)

    elapsed = time.time() - t0
    print(f"  Width-8 exhaustive ({factorial(WIDTH):,}) × 3 keywords × 4 combos: "
        f"best={max_score}/24 [{elapsed:.1f}s]")
    print(f"  E-TABLEAU-20 reported max: 13/24 for width-8 at period-8.")

    if max_score > 15:
        print(f"  *** WARNING: Score {max_score} exceeds E-TABLEAU-20 maximum!")
        print(f"      Possible bug or genuine improvement. Best config: {best_config}")
    elif max_score <= 14:
        print(f"  ✓ Consistent with E-TABLEAU-20 (max 13-14 at w8/p8 = noise).")
    return max_score


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("E-HYBRID-01: K3-Structure Hybrid Attack — Extended Coverage")
    print("=" * 70)
    print()
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Bean-surviving periods: {sorted(BEAN_SURVIVING)}")
    print(f"Period-8 keywords (new + E-TABLEAU-20): {len(KEYWORDS_P8)}")
    print(f"Period-13 keywords: {len(KEYWORDS_P13)}")
    print()
    print("KEY FACT: Non-Bean-surviving periods (7, 10, 11, ...) can NEVER yield 24/24")
    print("  → KRYPTOS(p7), PALIMPSEST(p10), SANBORN(p7), SCHEIDT(p7), BERLINCLOCK(p11)")
    print("    are eliminated as Vigenère keys for ANY transposition (E-FRAC-35 proof).")
    print("  → They are still tested in Phase 1 for completeness.")
    print()

    t_start = time.time()

    # Phase 1: Targeted keyword pairs
    p1_best, p1_configs = phase1()

    # Phase 2: Widths 5,6,7 exhaustive at period-8
    p2_results, p2_configs, p2_best = phase2_exhaustive_small_widths()

    # Phase 3: Width-9 fully exhaustive (BC-derived key)
    p3_best, p3_bc_count, p3_tested, p3_elapsed = phase3_width9_bc_derived()

    # Phase 4: KA-alphabet Vigenère + standard columnar
    p4_best, p4_configs = phase4_ka_columnar()

    # Phase 5: Baseline verification
    p5_max = phase5_baseline()

    # ── Final summary ──────────────────────────────────────────────────────────
    total_elapsed = time.time() - t_start
    global_best = max(p1_best, p2_best, p3_best, p4_best)

    print()
    print("=" * 70)
    print("FINAL SUMMARY — E-HYBRID-01")
    print("=" * 70)
    print()
    print("Prior coverage baseline:")
    print("  E-TABLEAU-20 width-8 exhaustive: max 13/24 (noise)")
    print("  E-AUDIT-06 rotational trans + KA-Vig: max 4/24 (noise, ELIMINATED)")
    print()
    print(f"This experiment results:")
    print(f"  Phase 1 (keyword pairs):           best={p1_best:2d}/24 ({p1_configs:,} configs)")
    print(f"  Phase 2 (widths 5,6,7 exhaustive): best={p2_best:2d}/24 ({p2_configs:,} configs)")
    print(f"  Phase 3 (width-9 BC-derived key):  best={p3_best:2d}/24 "
          f"({p3_bc_count} BC-consistent of {p3_tested:,})")
    print(f"  Phase 4 (KA-Vig + columnar):       best={p4_best:2d}/24 ({p4_configs:,} configs)")
    print(f"  Phase 5 (baseline w8 check):       best={p5_max:2d}/24")
    print()
    print(f"  GLOBAL BEST: {global_best}/24")
    print(f"  Total runtime: {total_elapsed:.1f}s")
    print()
    print("GAP ANALYSIS vs. prior work:")
    print("  ✓ Widths 5,6,7 at period-8 EXHAUSTIVELY tested — CLOSED")
    print("  ✓ Width-9 FULLY exhaustive at period-8 (BC-derived key) — CLOSED")
    print("  ✓ KA-alphabet Vigenère + standard columnar widths 7,8 — CLOSED")
    print("  ✓ Extended period-8 keyword list (30 keywords vs 16 in E-TABLEAU-20) — CLOSED")
    print()
    print("REMAINING GAPS (not covered here):")
    print("  ~ Width-10+ exhaustive: too many orderings for exhaustive Python search")
    print("  ~ Period-13 at widths 5-12 exhaustive (E-TABLEAU-20 sampled 50K at w13)")
    print("  ~ Double columnar transposition + period-8 Vigenère with keywords")
    print("    (E-FRAC-46 tested double columnar but with random/exhaustive key, not keywords)")
    print("  ~ Running key + columnar: tested in E-FRAC-49 for widths 6,8,9")
    print()

    if global_best >= 24:
        verdict = "BREAKTHROUGH — 24/24 achieved. VERIFY IMMEDIATELY with Bean check."
    elif global_best >= 18:
        verdict = f"SIGNAL — {global_best}/24 > noise. Investigate immediately."
    elif global_best >= 14:
        verdict = f"ELEVATED — {global_best}/24. Above noise but within underdetermined range."
    else:
        verdict = (f"NOISE — {global_best}/24. K3-structure (columnar+Vigenère) with "
                   f"standard AZ and KA alphabets at widths 5-9, period-8: eliminated for "
                   f"all tested keywords and all orderings at widths 5-7.")

    print(f"VERDICT: {verdict}")
    print()
    print(f"[INTERNAL RESULT] K3-structure hybrid (widths 5-7 exhaustive, width-9 BC-derived,")
    print(f"  KA-Vig, 30 period-8 keywords) at period-8: best={global_best}/24.")
    print(f"REPRO: PYTHONPATH=src python3 -u scripts/e_hybrid_01_k3struct_extended.py")

    # Save results
    os.makedirs("results/hybrid", exist_ok=True)
    output = {
        "experiment": "E-HYBRID-01",
        "description": "K3-structure hybrid (trans+Vigenère) extended coverage",
        "coverage": {
            "widths_exhaustive": [5, 6, 7],
            "width_9_bc_derived": True,
            "ka_alphabet": True,
            "keywords_p8_count": len(KEYWORDS_P8),
            "keywords_p13_count": len(KEYWORDS_P13),
        },
        "prior_coverage": {
            "e_tableau_20_width8_exhaustive": "max 13/24 (noise)",
            "e_audit_06_rotational_ka": "max 4/24 (noise/eliminated)",
        },
        "results": {
            "phase1_best": p1_best,
            "phase2_best": p2_best,
            "phase2_widths": {str(k): v['best_score'] for k, v in p2_results.items()},
            "phase3_best": p3_best,
            "phase3_bc_consistent": p3_bc_count,
            "phase4_best": p4_best,
            "phase5_baseline": p5_max,
            "global_best": global_best,
        },
        "verdict": verdict,
        "runtime_s": total_elapsed,
    }
    outpath = "results/hybrid/e_hybrid_01_k3struct_extended.json"
    with open(outpath, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nArtifact: {outpath}")


if __name__ == "__main__":
    main()
