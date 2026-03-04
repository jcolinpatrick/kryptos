#!/usr/bin/env python3
"""
Cipher: tableau analysis
Family: tableau
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-CHART-03b: Reduced Misspelling Set (4-pair) Tableau Variants for K4

RATIONALE: The O->U misspelling (UNDERGRUUND) is CORRECTED to UNDERGROUND
on the Antipodes sculpture. This suggests O->U may be a genuine transcription
error, not a deliberate cipher instruction. Test the reduced 4-pair set.

Reduced misspelling substitutions (correct -> wrong):
  S->C (PALIMPCEST->PALIMPSEST)
  L->Q (IQLUSION->ILLUSION)
  E->A (DESPARATLY->DESPERATELY)
  I->E (DIGETAL->DIGITAL)

Wrong letters: C, Q, A, E
Right letters: S, L, E, I

Keywords from reduced set: SLEI, CQAE, ACQE, EQAC, IELS, LEIS, SEAL, ISLE,
  LICE, CEIL, LACE, ACE, ICE, ICES, LACES

Modifications tested:
  1. ROW SWAPS (independent and chained, forward and reverse)
  2. COLUMN SWAPS (independent and chained, forward and reverse)
  3. BOTH row + column swaps
  4. LETTER REPLACEMENT in tableau (4-pair only)
  5. ROW PERMUTATION by misspelling offsets (cyclic, 4-value)
  6. Keywords from reduced misspelling letters + anagram words

Output: results/e_chart_03b_reduced_misspelling.json
Repro:  PYTHONPATH=src python3 -u scripts/e_chart_03b_reduced_misspelling.py
"""

import json
import os
import sys
import time
from itertools import permutations
from copy import deepcopy

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD, KRYPTOS_ALPHABET, N_CRIBS,
)
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed
from kryptos.kernel.constraints.bean import verify_bean_simple

# ── Constants ──────────────────────────────────────────────────────────

KA = KRYPTOS_ALPHABET  # KRYPTOSABCDEFGHIJLMNQUVWXZ
KA_IDX = {c: i for i, c in enumerate(KA)}
N = CT_LEN

# REDUCED misspelling pairs (4 only, O->U excluded)
MISSPELLINGS_REDUCED = [
    ('S', 'C'),
    ('L', 'Q'),
    ('E', 'A'),
    ('I', 'E'),
]

# Misspelling shifts in standard alphabet (reduced set)
# S(18)->C(2) = -16 mod 26 = 10
# L(11)->Q(16) = +5
# E(4)->A(0) = -4 mod 26 = 22
# I(8)->E(4) = -4 mod 26 = 22
MISSPELLING_OFFSETS_REDUCED = [10, 5, 22, 22]

# KA-position shifts for the reduced set
# S is at KA pos 6, C is at KA pos 9:  diff = +3
# L is at KA pos 17, Q is at KA pos 20: diff = +3
# E is at KA pos 11, A is at KA pos 7:  diff = -4 mod 26 = 22
# I is at KA pos 15, E is at KA pos 11: diff = -4 mod 26 = 22
KA_OFFSETS_REDUCED = [3, 3, 22, 22]

# Keywords to test - thematic + derived from misspelling letters
KEYWORDS = [
    # Thematic
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "LAYERTWO", "YAR",
    "STOPWATCH", "BERLINCLOCK", "EASTNORTHEAST",
    # From reduced wrong letters: C, Q, A, E
    "CQAE", "ACQE", "EQAC", "EACQ",
    # From reduced right letters: S, L, E, I
    "SLEI", "IELS", "LEIS", "SILE",
    # Real English words from {C,Q,A,E} + nearby
    "ACE", "ICE",
    # Real English words from {S,L,E,I}
    "SEAL", "ISLE", "LEIS", "LIES", "SEIL",
    # Mixed correct+wrong
    "CEIL", "LICE", "LACE", "ICES", "LACES",
    # EQUAL (from 5-pair set, community noted anagram)
    "EQUAL",
    # Other thematic
    "CHARLIE", "CHECKPOINT",
]

# Running key sources
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUABORHNDIREWMYLVYFHLAYCEPSMKYWFVDHWIOKNCLSZQSCQHNRETYJPRJKWLBHVAKQSXOGNIFEAYFRO"
K3_PT = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBABORHHRISWASOIFRRRISCOVEREDLEADINGTOKING"

RUNNING_KEYS = {
    "K3_PT": K3_PT,
    "K1_PT": K1_PT,
    "K2_PT": K2_PT,
    "K1K2K3": K1_PT + K2_PT + K3_PT,
}


def build_ka_tableau():
    """Build the standard KA Vigenere tableau."""
    tableau = []
    for i in range(26):
        row = KA[i:] + KA[:i]
        tableau.append(list(row))
    return tableau


def build_std_tableau():
    """Build the standard A-Z Vigenere tableau."""
    ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    tableau = []
    for i in range(26):
        row = ALPH[i:] + ALPH[:i]
        tableau.append(list(row))
    return tableau


def decrypt_with_tableau(ct_str, key_str, tableau, variant, idx_map, alpha):
    """Decrypt CT with a key through a (possibly modified) tableau.

    Args:
        ct_str: ciphertext string
        key_str: key string (repeated to length)
        tableau: 26x26 list of lists
        variant: 'vigenere', 'beaufort', 'variant_beaufort'
        idx_map: dict mapping char to index (KA_IDX or std_idx)
        alpha: alphabet string (KA or ALPH)
    """
    pt = []
    for i in range(len(ct_str)):
        ct_c = ct_str[i]
        key_c = key_str[i % len(key_str)]

        if key_c not in idx_map:
            pt.append('?')
            continue

        if variant == "vigenere":
            row_idx = idx_map[key_c]
            row = tableau[row_idx]
            try:
                col = row.index(ct_c)
            except ValueError:
                pt.append('?')
                continue
            pt.append(alpha[col])
        elif variant in ("beaufort", "variant_beaufort"):
            key_col = idx_map[key_c]
            found = False
            for row_idx in range(26):
                if tableau[row_idx][key_col] == ct_c:
                    pt.append(alpha[row_idx])
                    found = True
                    break
            if not found:
                pt.append('?')
        else:
            pt.append('?')
    return ''.join(pt)


def apply_row_swaps(tableau, pairs, idx_map):
    """Swap rows. Applied sequentially (chained)."""
    t = deepcopy(tableau)
    for a, b in pairs:
        r1 = idx_map[a]
        r2 = idx_map[b]
        t[r1], t[r2] = t[r2], t[r1]
    return t


def apply_col_swaps(tableau, pairs, idx_map):
    """Swap columns. Applied sequentially (chained)."""
    t = deepcopy(tableau)
    for a, b in pairs:
        c1 = idx_map[a]
        c2 = idx_map[b]
        for row in t:
            row[c1], row[c2] = row[c2], row[c1]
    return t


def apply_letter_replacement(tableau, pairs):
    """Replace every instance of correct letter with wrong letter."""
    t = deepcopy(tableau)
    replacements = {p[0]: p[1] for p in pairs}
    for r in range(26):
        for c in range(26):
            if t[r][c] in replacements:
                t[r][c] = replacements[t[r][c]]
    return t


def columnar_perm(col_order, width, length):
    """Generate columnar transposition permutation (gather convention)."""
    n_rows = (length + width - 1) // width
    n_long = length % width
    if n_long == 0:
        n_long = width
    sigma = [0] * length
    ct_pos = 0
    for col in col_order:
        col_len = n_rows if col < n_long else n_rows - 1
        for row in range(col_len):
            inter_pos = row * width + col
            if inter_pos < length:
                sigma[inter_pos] = ct_pos
                ct_pos += 1
    return sigma


def keyword_to_key(keyword, length):
    """Repeat keyword to cover the required length."""
    return (keyword * ((length // len(keyword)) + 1))[:length]


def score_plaintext(pt):
    """Score a plaintext candidate."""
    return score_cribs_detailed(pt)


def test_tableau_suite(tableau, tab_name, idx_map, alpha, keywords, running_keys,
                       variants, results_list, log_threshold=4):
    """Test a single tableau modification with all keys and variants.
    Returns number of configs tested."""
    configs = 0
    bijective = all(len(set(row)) == 26 for row in tableau)

    for variant in variants:
        if not bijective and variant == "vigenere":
            continue

        for kw in keywords:
            key = keyword_to_key(kw, N)
            pt = decrypt_with_tableau(CT, key, tableau, variant, idx_map, alpha)
            if '?' in pt:
                continue
            configs += 1
            detail = score_plaintext(pt)
            score = detail["score"]
            if score > log_threshold:
                results_list.append({
                    "tableau": tab_name,
                    "variant": variant,
                    "key_type": "keyword",
                    "key": kw,
                    "score": score,
                    "ene": detail["ene_score"],
                    "bc": detail["bc_score"],
                    "classification": detail["classification"],
                    "pt_snippet": pt[:40],
                })

        for rk_name, rk_text in running_keys.items():
            if len(rk_text) < N:
                continue
            key = rk_text[:N]
            pt = decrypt_with_tableau(CT, key, tableau, variant, idx_map, alpha)
            if '?' in pt:
                continue
            configs += 1
            detail = score_plaintext(pt)
            score = detail["score"]
            if score > log_threshold:
                results_list.append({
                    "tableau": tab_name,
                    "variant": variant,
                    "key_type": "running_key",
                    "key": rk_name,
                    "score": score,
                    "ene": detail["ene_score"],
                    "bc": detail["bc_score"],
                    "classification": detail["classification"],
                    "pt_snippet": pt[:40],
                })
    return configs


def main():
    print("=" * 70)
    print("E-CHART-03b: Reduced Misspelling Set (4-pair, no O->U)")
    print("=" * 70)
    t0 = time.time()

    base_ka = build_ka_tableau()
    base_std = build_std_tableau()
    ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    std_idx = {c: i for i, c in enumerate(ALPH)}

    print(f"  Reduced misspellings: {['->'.join(p) for p in MISSPELLINGS_REDUCED]}")
    print(f"  Wrong letters: {''.join(p[1] for p in MISSPELLINGS_REDUCED)}")
    print(f"  Right letters: {''.join(p[0] for p in MISSPELLINGS_REDUCED)}")
    print(f"  Std-alph offsets: {MISSPELLING_OFFSETS_REDUCED}")
    print(f"  KA-alph offsets:  {KA_OFFSETS_REDUCED}")

    variants = ["vigenere", "beaufort", "variant_beaufort"]
    all_results = []
    total_configs = 0

    # ═══════════════════════════════════════════════════════════════
    # Phase 1: KA tableau modifications (reduced 4-pair set)
    # ═══════════════════════════════════════════════════════════════

    print(f"\n  Phase 1: KA tableau modifications...")
    ka_tableaux = {}

    # Baseline
    ka_tableaux["unmodified_ka"] = deepcopy(base_ka)

    # Row swaps - forward order
    ka_tableaux["r4_row_swap_fwd"] = apply_row_swaps(base_ka, MISSPELLINGS_REDUCED, KA_IDX)
    # Row swaps - reverse order (chaining order matters for E->A then I->E)
    ka_tableaux["r4_row_swap_rev"] = apply_row_swaps(base_ka, list(reversed(MISSPELLINGS_REDUCED)), KA_IDX)

    # Column swaps - forward
    ka_tableaux["r4_col_swap_fwd"] = apply_col_swaps(base_ka, MISSPELLINGS_REDUCED, KA_IDX)
    # Column swaps - reverse
    ka_tableaux["r4_col_swap_rev"] = apply_col_swaps(base_ka, list(reversed(MISSPELLINGS_REDUCED)), KA_IDX)

    # Both row + column (forward)
    t = apply_row_swaps(base_ka, MISSPELLINGS_REDUCED, KA_IDX)
    ka_tableaux["r4_both_fwd"] = apply_col_swaps(t, MISSPELLINGS_REDUCED, KA_IDX)
    # Both (reverse)
    t = apply_row_swaps(base_ka, list(reversed(MISSPELLINGS_REDUCED)), KA_IDX)
    ka_tableaux["r4_both_rev"] = apply_col_swaps(t, list(reversed(MISSPELLINGS_REDUCED)), KA_IDX)
    # Row forward + col reverse
    t = apply_row_swaps(base_ka, MISSPELLINGS_REDUCED, KA_IDX)
    ka_tableaux["r4_row_fwd_col_rev"] = apply_col_swaps(t, list(reversed(MISSPELLINGS_REDUCED)), KA_IDX)

    # Letter replacement (4-pair)
    ka_tableaux["r4_letter_replace"] = apply_letter_replacement(base_ka, MISSPELLINGS_REDUCED)

    # E-involved pairs only: E->A, I->E
    e_pairs = [('E', 'A'), ('I', 'E')]
    ka_tableaux["r4_E_only_row"] = apply_row_swaps(base_ka, e_pairs, KA_IDX)
    ka_tableaux["r4_E_only_col"] = apply_col_swaps(base_ka, e_pairs, KA_IDX)
    t = apply_row_swaps(base_ka, e_pairs, KA_IDX)
    ka_tableaux["r4_E_only_both"] = apply_col_swaps(t, e_pairs, KA_IDX)

    # S->C, L->Q only (consonant-like pairs)
    sl_pairs = [('S', 'C'), ('L', 'Q')]
    ka_tableaux["r4_SL_only_row"] = apply_row_swaps(base_ka, sl_pairs, KA_IDX)
    ka_tableaux["r4_SL_only_col"] = apply_col_swaps(base_ka, sl_pairs, KA_IDX)
    t = apply_row_swaps(base_ka, sl_pairs, KA_IDX)
    ka_tableaux["r4_SL_only_both"] = apply_col_swaps(t, sl_pairs, KA_IDX)

    # Each pair individually
    for a, b in MISSPELLINGS_REDUCED:
        pair = [(a, b)]
        ka_tableaux[f"r4_single_{a}{b}_row"] = apply_row_swaps(base_ka, pair, KA_IDX)
        ka_tableaux[f"r4_single_{a}{b}_col"] = apply_col_swaps(base_ka, pair, KA_IDX)

    print(f"  KA tableaux generated: {len(ka_tableaux)}")

    for tab_name, tableau in ka_tableaux.items():
        n = test_tableau_suite(tableau, tab_name, KA_IDX, KA,
                               KEYWORDS, RUNNING_KEYS, variants, all_results)
        total_configs += n

    print(f"  Phase 1 done: {total_configs} configs ({time.time()-t0:.1f}s)")

    # ═══════════════════════════════════════════════════════════════
    # Phase 2: Standard tableau modifications (reduced 4-pair set)
    # ═══════════════════════════════════════════════════════════════

    print(f"\n  Phase 2: Standard A-Z tableau modifications...")
    std_tableaux = {}

    std_tableaux["r4_std_row_fwd"] = apply_row_swaps(base_std, MISSPELLINGS_REDUCED, std_idx)
    std_tableaux["r4_std_row_rev"] = apply_row_swaps(base_std, list(reversed(MISSPELLINGS_REDUCED)), std_idx)
    std_tableaux["r4_std_col_fwd"] = apply_col_swaps(base_std, MISSPELLINGS_REDUCED, std_idx)
    std_tableaux["r4_std_col_rev"] = apply_col_swaps(base_std, list(reversed(MISSPELLINGS_REDUCED)), std_idx)
    t = apply_row_swaps(base_std, MISSPELLINGS_REDUCED, std_idx)
    std_tableaux["r4_std_both_fwd"] = apply_col_swaps(t, MISSPELLINGS_REDUCED, std_idx)
    std_tableaux["r4_std_letter_replace"] = apply_letter_replacement(base_std, MISSPELLINGS_REDUCED)

    print(f"  Std tableaux generated: {len(std_tableaux)}")

    phase2 = 0
    for tab_name, tableau in std_tableaux.items():
        n = test_tableau_suite(tableau, tab_name, std_idx, ALPH,
                               KEYWORDS, RUNNING_KEYS, variants, all_results)
        phase2 += n
    total_configs += phase2
    print(f"  Phase 2 done: {phase2} configs ({time.time()-t0:.1f}s)")

    # ═══════════════════════════════════════════════════════════════
    # Phase 3: Cyclic row offset with 4-value reduced offsets
    # ═══════════════════════════════════════════════════════════════

    print(f"\n  Phase 3: Cyclic row offset (4-value reduced)...")
    phase3 = 0

    # Test both standard-alphabet offsets and KA-alphabet offsets
    offset_sets = {
        "std_offsets": MISSPELLING_OFFSETS_REDUCED,   # [10, 5, 22, 22]
        "ka_offsets": KA_OFFSETS_REDUCED,             # [3, 3, 22, 22]
    }

    for offset_name, offsets in offset_sets.items():
        for variant in variants:
            for kw in KEYWORDS:
                key = keyword_to_key(kw, N)
                pt = []
                valid = True

                for i in range(N):
                    key_c = key[i]
                    ct_c = CT[i]
                    offset = offsets[i % len(offsets)]
                    effective_row = (KA_IDX[key_c] + offset) % 26

                    if variant == "vigenere":
                        row = base_ka[effective_row]
                        try:
                            col = row.index(ct_c)
                        except ValueError:
                            valid = False
                            break
                        pt.append(KA[col])
                    elif variant in ("beaufort", "variant_beaufort"):
                        key_col = KA_IDX[key_c]
                        found = False
                        for row_idx in range(26):
                            eff = (row_idx + offset) % 26
                            if base_ka[eff][key_col] == ct_c:
                                pt.append(KA[row_idx])
                                found = True
                                break
                        if not found:
                            valid = False
                            break

                if not valid:
                    continue

                pt_str = ''.join(pt)
                phase3 += 1
                detail = score_plaintext(pt_str)
                score = detail["score"]

                if score > 4:
                    all_results.append({
                        "tableau": f"cyclic_{offset_name}",
                        "variant": variant,
                        "key_type": "keyword",
                        "key": kw,
                        "score": score,
                        "ene": detail["ene_score"],
                        "bc": detail["bc_score"],
                        "classification": detail["classification"],
                        "pt_snippet": pt_str[:40],
                    })

            for rk_name, rk_text in RUNNING_KEYS.items():
                if len(rk_text) < N:
                    continue
                key = rk_text[:N]
                pt = []
                valid = True

                for i in range(N):
                    key_c = key[i]
                    ct_c = CT[i]
                    offset = offsets[i % len(offsets)]
                    effective_row = (KA_IDX[key_c] + offset) % 26

                    if variant == "vigenere":
                        row = base_ka[effective_row]
                        try:
                            col = row.index(ct_c)
                        except ValueError:
                            valid = False
                            break
                        pt.append(KA[col])
                    elif variant in ("beaufort", "variant_beaufort"):
                        key_col = KA_IDX[key_c]
                        found = False
                        for row_idx in range(26):
                            eff = (row_idx + offset) % 26
                            if base_ka[eff][key_col] == ct_c:
                                pt.append(KA[row_idx])
                                found = True
                                break
                        if not found:
                            valid = False
                            break

                if not valid:
                    continue

                pt_str = ''.join(pt)
                phase3 += 1
                detail = score_plaintext(pt_str)
                score = detail["score"]

                if score > 4:
                    all_results.append({
                        "tableau": f"cyclic_{offset_name}",
                        "variant": variant,
                        "key_type": "running_key",
                        "key": rk_name,
                        "score": score,
                        "ene": detail["ene_score"],
                        "bc": detail["bc_score"],
                        "classification": detail["classification"],
                        "pt_snippet": pt_str[:40],
                    })

    total_configs += phase3
    print(f"  Phase 3 done: {phase3} configs ({time.time()-t0:.1f}s)")

    # ═══════════════════════════════════════════════════════════════
    # Phase 4: Width-8 columnar transposition on top configs
    # ═══════════════════════════════════════════════════════════════

    all_results.sort(key=lambda r: -r["score"])

    # Collect top unique configs for transposition testing
    top_configs = []
    seen = set()
    for r in all_results:
        key_id = (r["tableau"], r["variant"], r["key_type"], r["key"])
        if key_id not in seen:
            seen.add(key_id)
            top_configs.append(r)
        if len(top_configs) >= 10:
            break

    # Pad with representative configs if we don't have 10
    if len(top_configs) < 10:
        for tab_name in ["r4_row_swap_fwd", "r4_col_swap_fwd", "r4_both_fwd",
                         "r4_letter_replace", "unmodified_ka"]:
            if tab_name in ka_tableaux:
                for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                    key_id = (tab_name, "vigenere", "keyword", kw)
                    if key_id not in seen:
                        seen.add(key_id)
                        top_configs.append({
                            "tableau": tab_name,
                            "variant": "vigenere",
                            "key_type": "keyword",
                            "key": kw,
                            "score": 0,
                        })
                    if len(top_configs) >= 10:
                        break
            if len(top_configs) >= 10:
                break

    print(f"\n  Phase 4: Width-8 columnar on top {len(top_configs)} configs...")
    width = 8
    n_perms = 1
    for i in range(1, width + 1):
        n_perms *= i
    print(f"  Testing {n_perms} orderings per config")

    phase4 = 0
    trans_results = []

    for cfg in top_configs:
        tab_name = cfg["tableau"]
        variant = cfg["variant"]
        key_type = cfg["key_type"]
        key_val = cfg["key"]

        # Resolve tableau and index map
        if tab_name in ka_tableaux:
            tableau = ka_tableaux[tab_name]
            idx_map = KA_IDX
            alpha = KA
        elif tab_name in std_tableaux:
            tableau = std_tableaux[tab_name]
            idx_map = std_idx
            alpha = ALPH
        elif tab_name.startswith("cyclic_"):
            continue  # Skip cyclic offset for transposition (complex interaction)
        else:
            continue

        # Build key
        if key_type == "keyword":
            key = keyword_to_key(key_val, N)
        else:
            rk_text = RUNNING_KEYS.get(key_val, "")
            if len(rk_text) < N:
                continue
            key = rk_text[:N]

        for order_tuple in permutations(range(width)):
            order = list(order_tuple)
            perm = columnar_perm(order, width, N)

            # Un-transpose then decrypt
            ct_untrans = ''.join(CT[perm[i]] for i in range(N))
            pt = decrypt_with_tableau(ct_untrans, key, tableau, variant, idx_map, alpha)

            if '?' in pt:
                continue

            phase4 += 1
            detail = score_plaintext(pt)
            score = detail["score"]

            if score > 6:
                trans_results.append({
                    "tableau": tab_name,
                    "variant": variant,
                    "key_type": key_type,
                    "key": key_val,
                    "width": width,
                    "col_order": order,
                    "score": score,
                    "ene": detail["ene_score"],
                    "bc": detail["bc_score"],
                    "classification": detail["classification"],
                    "pt_snippet": pt[:40],
                })

        if phase4 % 100000 == 0 and phase4 > 0:
            print(f"    ... {phase4:,} transposition configs ({time.time()-t0:.1f}s)", flush=True)

    total_configs += phase4
    print(f"  Phase 4 done: {phase4:,} configs ({time.time()-t0:.1f}s)")

    # ═══════════════════════════════════════════════════════════════
    # Final summary
    # ═══════════════════════════════════════════════════════════════

    all_results.extend(trans_results)
    all_results.sort(key=lambda r: -r["score"])

    elapsed = time.time() - t0
    best_score = all_results[0]["score"] if all_results else 0

    print(f"\n{'='*70}")
    print(f"RESULTS SUMMARY")
    print(f"{'='*70}")
    print(f"  Total configs tested: {total_configs:,}")
    print(f"  Results above threshold: {len(all_results)}")
    print(f"  Best score: {best_score}/24")
    print(f"  Elapsed: {elapsed:.1f}s")

    if all_results:
        print(f"\n  TOP 20 RESULTS:")
        for i, r in enumerate(all_results[:20]):
            trans_info = f" w={r.get('width','-')} order={r.get('col_order','-')}" if 'width' in r else ""
            print(f"  {i+1:3d}. score={r['score']:2d}/24 ENE={r['ene']:2d} BC={r['bc']:2d}"
                  f" [{r['classification']:12s}] {r['tableau']:25s} {r['variant']:18s}"
                  f" {r['key_type']:11s} key={r['key']}{trans_info}")
            print(f"       PT: {r['pt_snippet']}")

    # Score distribution
    score_dist = {}
    for r in all_results:
        s = r["score"]
        score_dist[s] = score_dist.get(s, 0) + 1
    if score_dist:
        print(f"\n  SCORE DISTRIBUTION:")
        for s in sorted(score_dist.keys(), reverse=True):
            print(f"    score {s:2d}: {score_dist[s]:5d} configs")

    if best_score >= 18:
        verdict = "SIGNAL"
    elif best_score >= 10:
        verdict = "INTERESTING"
    else:
        verdict = "NOISE"

    print(f"\n  VERDICT: {verdict}")

    if trans_results:
        best_trans = max(trans_results, key=lambda r: r["score"])
        print(f"\n  Best transposition score: {best_trans['score']}/24 (width-8)")

    # Compare reduced (4-pair) vs full (5-pair) from prior run
    print(f"\n  NOTE: Prior E-CHART-03 (5-pair with O->U) best = 8/24")
    print(f"  This run (4-pair without O->U) best = {best_score}/24")

    # ── Save ──

    os.makedirs("results", exist_ok=True)
    output = {
        "experiment": "E-CHART-03b",
        "description": "Reduced misspelling set (4-pair, O->U excluded) tableau variants",
        "rationale": "O->U (UNDERGRUUND) corrected on Antipodes sculpture, likely not deliberate",
        "misspellings_reduced": [f"{c}->{w}" for c, w in MISSPELLINGS_REDUCED],
        "std_offsets": MISSPELLING_OFFSETS_REDUCED,
        "ka_offsets": KA_OFFSETS_REDUCED,
        "ka_tableaux_tested": list(ka_tableaux.keys()),
        "std_tableaux_tested": list(std_tableaux.keys()),
        "keywords_tested": KEYWORDS,
        "running_keys_tested": list(RUNNING_KEYS.keys()),
        "variants_tested": variants,
        "total_configs": total_configs,
        "best_score": best_score,
        "verdict": verdict,
        "elapsed_seconds": round(elapsed, 1),
        "top_50": all_results[:50],
        "score_distribution": score_dist,
        "transposition_results_count": len(trans_results),
        "comparison_to_5pair": "5-pair best = 8/24",
    }

    with open("results/e_chart_03b_reduced_misspelling.json", "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n  Artifact: results/e_chart_03b_reduced_misspelling.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_chart_03b_reduced_misspelling.py")


if __name__ == "__main__":
    main()
