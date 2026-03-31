#!/usr/bin/env python3
"""
# ── Metadata ──────────────────────────────────────────────────────────────
# Cipher:     2D Matrix Keying (punch-card / Hollerith model)
# Family:     novel
# Status:     active
# Keyspace:   ~300² × 16 widths × 3 variants × 2 modes ≈ 8.6M configs
# Last run:   2026-03-24
# Best score: TBD
# ──────────────────────────────────────────────────────────────────────────
#
# HYPOTHESIS: K4's encryption uses a 2D position-dependent key derived from
# two keywords: one indexing rows, one indexing columns, in a fixed-width
# grid. Key at position i = (row_key[row] + col_key[col]) mod 26, where
# row = i // width, col = i % width.
#
# Inspired by IBM Hollerith punch card encoding where each character is
# determined by zone row + digit row coordinates in a physical matrix.
# Scheidt explicitly taught Sanborn "matrix codes" and "shifting matrices."
#
# This is DISTINCT from:
# - Periodic Vigenère (1D: key = kw[i % period])
# - Polybius fractionation (letter → coordinates, not position → coordinates)
# - Standard transposition (reorders positions, doesn't add position-dependent key)
#
# Two modes tested:
# A) Direct 97-char CT (cipher operates on full text including null positions)
# B) 80-char CT (17 consensus nulls removed first, then cipher operates)
#
# Key combination rules:
# ADD: key = (R[row] + C[col]) mod 26  (Vigenère tableau double-index)
# SUB: key = (R[row] - C[col]) mod 26  (asymmetric combination)
#
# Sanborn's legal pad: "8 lines / 73" → width 10 gives ceil(73/10) = 8 rows
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

from __future__ import annotations

import sys
import os
import time
import json

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD,
)

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

WIDTHS = range(5, 21)  # grid widths to test (16 values)
COMBO_RULES = ('add', 'sub')  # key combination rules
CIPHER_VARIANTS = ('vig', 'beau', 'varbeau')

# ═══════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def load_keywords(path: str) -> list[str]:
    """Load thematic keywords, filter to alpha-only uppercase, deduplicate."""
    keywords = set()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            word = ''.join(c for c in line if c.isalpha()).upper()
            if 2 <= len(word) <= 20:
                keywords.add(word)
    return sorted(keywords)


def extract_non_null(ct: str, null_positions: frozenset[int]) -> tuple[str, list[int]]:
    """Remove null positions from CT.
    Returns (compressed_ct, position_map) where position_map[i] = original index.
    """
    chars = []
    pos_map = []
    for i, c in enumerate(ct):
        if i not in null_positions:
            chars.append(c)
            pos_map.append(i)
    return ''.join(chars), pos_map


def map_cribs(crib_dict: dict[int, str], pos_map: list[int]) -> list[tuple[int, int]]:
    """Map original crib positions to compressed indices.
    Returns list of (compressed_pos, expected_pt_value).
    """
    rev = {orig: comp for comp, orig in enumerate(pos_map)}
    mapped = []
    for orig_pos, letter in crib_dict.items():
        if orig_pos in rev:
            mapped.append((rev[orig_pos], ALPH_IDX[letter]))
    return mapped


def make_crib_list(crib_dict: dict[int, str]) -> list[tuple[int, int]]:
    """Convert crib dict to list of (position, expected_pt_value)."""
    return [(pos, ALPH_IDX[letter]) for pos, letter in crib_dict.items()]


def score_2d_fast(
    ct_nums: list[int],
    ct_len: int,
    width: int,
    rk_nums: list[int],
    ck_nums: list[int],
    variant: str,
    combo: str,
    cribs: list[tuple[int, int]],
) -> int:
    """Decrypt ONLY at crib positions and count matches. O(24) per call."""
    rk_len = len(rk_nums)
    ck_len = len(ck_nums)
    matches = 0
    for pos, expected in cribs:
        if pos >= ct_len:
            continue
        row = pos // width
        col = pos % width
        r = rk_nums[row % rk_len]
        c_val = ck_nums[col % ck_len]
        if combo == 'add':
            key = (r + c_val) % 26
        else:  # sub
            key = (r - c_val) % 26
        ct_val = ct_nums[pos]
        if variant == 'vig':
            p = (ct_val - key) % 26
        elif variant == 'beau':
            p = (key - ct_val) % 26
        else:  # varbeau
            p = (ct_val + key) % 26
        if p == expected:
            matches += 1
    return matches


def decrypt_full(
    ct_nums: list[int],
    width: int,
    rk_nums: list[int],
    ck_nums: list[int],
    variant: str,
    combo: str,
) -> str:
    """Full decryption for display purposes."""
    rk_len = len(rk_nums)
    ck_len = len(ck_nums)
    pt = []
    for i, ct_val in enumerate(ct_nums):
        row = i // width
        col = i % width
        r = rk_nums[row % rk_len]
        c_val = ck_nums[col % ck_len]
        if combo == 'add':
            key = (r + c_val) % 26
        else:
            key = (r - c_val) % 26
        if variant == 'vig':
            p = (ct_val - key) % 26
        elif variant == 'beau':
            p = (key - ct_val) % 26
        else:
            p = (ct_val + key) % 26
        pt.append(ALPH[p])
    return ''.join(pt)


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ATTACK
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 78)
    print("2D MATRIX KEYING ATTACK (Punch-Card / Hollerith Model)")
    print("=" * 78)
    print()

    # Load keywords
    kw_path = os.path.join(_ROOT, "wordlists", "thematic_keywords.txt")
    keywords = load_keywords(kw_path)
    print(f"Keywords loaded: {len(keywords)}")

    # Precompute keyword numeric values
    kw_nums = {kw: [ALPH_IDX[c] for c in kw] for kw in keywords}

    # ── Mode A: Direct 97-char CT ──
    ct_nums_97 = [ALPH_IDX[c] for c in CT]
    cribs_97 = make_crib_list(CRIB_DICT)

    # ── Mode B: 80-char (17 consensus nulls removed) ──
    ct_80, pos_map_80 = extract_non_null(CT, CONSENSUS_NULL_POSITIONS)
    ct_nums_80 = [ALPH_IDX[c] for c in ct_80]
    cribs_80 = map_cribs(CRIB_DICT, pos_map_80)

    print(f"Mode A: {CT_LEN} chars, {len(cribs_97)} cribs")
    print(f"Mode B: {len(ct_80)} chars, {len(cribs_80)} cribs")
    print(f"Widths: {list(WIDTHS)}")
    print(f"Combo rules: {COMBO_RULES}")
    print(f"Cipher variants: {CIPHER_VARIANTS}")

    n_kw = len(keywords)
    n_widths = len(WIDTHS)
    n_combos = len(COMBO_RULES)
    n_variants = len(CIPHER_VARIANTS)
    configs_per_mode = n_kw * n_kw * n_widths * n_combos * n_variants
    total_configs = configs_per_mode * 2  # modes A + B
    print(f"Configs per mode: {n_kw}² × {n_widths} × {n_combos} × {n_variants} = {configs_per_mode:,}")
    print(f"Total configs: {total_configs:,}")
    print()

    # ── Sweep ──
    best_score = 0
    best_results: list[dict] = []
    configs_done = 0
    t0 = time.time()

    modes = [
        ("A_97", ct_nums_97, CT_LEN, cribs_97),
        ("B_80", ct_nums_80, len(ct_80), cribs_80),
    ]

    for mode_name, ct_nums, ct_len, cribs in modes:
        print(f"── Mode {mode_name} ({ct_len} chars, {len(cribs)} cribs) ──")
        mode_best = 0

        for combo in COMBO_RULES:
            for variant in CIPHER_VARIANTS:
                for w in WIDTHS:
                    for rk in keywords:
                        rk_n = kw_nums[rk]
                        for ck in keywords:
                            ck_n = kw_nums[ck]
                            s = score_2d_fast(
                                ct_nums, ct_len, w,
                                rk_n, ck_n,
                                variant, combo, cribs
                            )
                            configs_done += 1

                            if s > mode_best:
                                mode_best = s

                            if s > best_score:
                                best_score = s
                                # Clear inferior results
                                best_results = [r for r in best_results if r['score'] >= s]

                            if s >= max(best_score, NOISE_FLOOR):
                                best_results.append({
                                    'score': s,
                                    'mode': mode_name,
                                    'width': w,
                                    'combo': combo,
                                    'variant': variant,
                                    'row_key': rk,
                                    'col_key': ck,
                                })
                                # Keep only top 50
                                if len(best_results) > 50:
                                    best_results.sort(key=lambda x: -x['score'])
                                    best_results = best_results[:50]

                    if configs_done % 1_000_000 == 0:
                        elapsed = time.time() - t0
                        rate = configs_done / elapsed if elapsed > 0 else 0
                        print(f"  [{configs_done:,}/{total_configs:,}] "
                              f"best={best_score}/{N_CRIBS} "
                              f"mode_best={mode_best} "
                              f"rate={rate:,.0f}/s "
                              f"elapsed={elapsed:.1f}s")

        print(f"  Mode {mode_name} complete: best={mode_best}/{N_CRIBS}")
        print()

    elapsed = time.time() - t0
    print("=" * 78)
    print(f"COMPLETE: {configs_done:,} configs in {elapsed:.1f}s")
    print(f"Rate: {configs_done / elapsed:,.0f} configs/s")
    print(f"Best score: {best_score}/{N_CRIBS}")
    print()

    # ── Report ──
    if best_results:
        # Add full PT for top results
        print(f"Top results (score >= {max(best_score, NOISE_FLOOR)}):")
        print("-" * 78)
        for r in sorted(best_results, key=lambda x: -x['score'])[:20]:
            # Decrypt full text for display
            if r['mode'] == 'A_97':
                ct_n = ct_nums_97
            else:
                ct_n = ct_nums_80
            pt = decrypt_full(
                ct_n, r['width'],
                kw_nums[r['row_key']], kw_nums[r['col_key']],
                r['variant'], r['combo']
            )
            print(f"  {r['score']}/{N_CRIBS} | {r['mode']} w={r['width']} "
                  f"{r['combo']}/{r['variant']} "
                  f"row={r['row_key']} col={r['col_key']}")
            print(f"    PT: {pt}")
            print()
    else:
        print("No results above noise floor.")

    # ── Save results ──
    result_path = os.path.join(_ROOT, "results", "2d_matrix_keying_01.json")
    result_data = {
        'experiment': 'e_2d_matrix_keying_01',
        'hypothesis': '2D matrix keying (punch-card model)',
        'configs_tested': configs_done,
        'elapsed_s': round(elapsed, 1),
        'best_score': best_score,
        'n_cribs': N_CRIBS,
        'widths_tested': list(WIDTHS),
        'combo_rules': list(COMBO_RULES),
        'cipher_variants': list(CIPHER_VARIANTS),
        'n_keywords': len(keywords),
        'modes': ['A_97char', 'B_80char_17nulls'],
        'top_results': sorted(best_results, key=lambda x: -x['score'])[:20],
        'verdict': 'TBD',
    }
    with open(result_path, 'w') as f:
        json.dump(result_data, f, indent=2)
    print(f"Results saved to {result_path}")

    # ── Verdict ──
    print()
    if best_score >= SIGNAL_THRESHOLD:
        print(f"*** SIGNAL: {best_score}/{N_CRIBS} — INVESTIGATE ***")
    elif best_score >= STORE_THRESHOLD:
        print(f"INTERESTING: {best_score}/{N_CRIBS} — worth logging but likely noise")
    else:
        print(f"NOISE: {best_score}/{N_CRIBS} — 2D matrix keying (ADD/SUB combos) "
              f"produces no signal with thematic keywords")

    return best_score


if __name__ == "__main__":
    main()
