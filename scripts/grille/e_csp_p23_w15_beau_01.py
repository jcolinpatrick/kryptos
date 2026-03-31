#!/usr/bin/env python3
"""
# ── Metadata ──────────────────────────────────────────────────────────────
# Cipher:     P=23 Beaufort + width-15 columnar transposition on 73-char
# Family:     grille
# Status:     active
# Keyspace:   196,911 masks (C(13,5) × C(18,2))
# Last run:   2026-03-24
# Best score: TBD
# ──────────────────────────────────────────────────────────────────────────
#
# From constraint-satisfaction search (e_null_mask_csp_01.py):
# The ONLY fully-determined survivor at a discriminating-ish period is:
#   - Period 23, Beaufort, width-15 columnar transposition
#   - Mask config (5,0,2): 5 extra nulls in seg1, 0 in seg2, 2 in seg3
#   - All 23 key values are determined by the 24 cribs
#
# This script enumerates all 196,911 possible masks matching (5,0,2),
# extracts the 73-char real CT, applies inverse width-15 columnar
# transposition, decrypts with the known 23-value Beaufort key,
# and scores the plaintext.
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

from __future__ import annotations

import sys
import os
import time
import json
from itertools import combinations
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD,
)

# ═══════════════════════════════════════════════════════════════════════════
# KNOWN KEY (from CSP analysis — all 23 values determined)
# ═══════════════════════════════════════════════════════════════════════════

# From the CSP output for (5,0,2) w=15 P=23 beau:
KNOWN_KEY = [6, 10, 19, 11, 9, 1, 20, 17, 14, 14, 6, 10, 20, 2, 3, 14, 10, 9, 6, 4, 10, 10, 11]
PERIOD = 23
WIDTH = 15
CT_EXTRACTED_LEN = 73

# ═══════════════════════════════════════════════════════════════════════════
# TRANSPOSITION
# ═══════════════════════════════════════════════════════════════════════════

def columnar_perm_identity(length, width):
    """Columnar transposition: write by rows, read by columns (identity col order)."""
    n_full_rows = length // width
    remainder = length % width
    perm = []
    for col in range(width):
        col_length = n_full_rows + (1 if col < remainder else 0)
        for row in range(col_length):
            perm.append(row * width + col)
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, j in enumerate(perm):
        inv[j] = i
    return inv


# Precompute the inverse transposition permutation
TRANS_PERM = columnar_perm_identity(CT_EXTRACTED_LEN, WIDTH)
INV_PERM = invert_perm(TRANS_PERM)


# ═══════════════════════════════════════════════════════════════════════════
# QUADGRAM SCORER
# ═══════════════════════════════════════════════════════════════════════════

QG_PATH = os.path.join(_ROOT, "data", "english_quadgrams.json")
with open(QG_PATH) as f:
    _qg_raw = json.load(f)
QG_FLOOR = min(_qg_raw.values()) - 1.0
QG = [QG_FLOOR] * (26 ** 4)
for gram, logp in _qg_raw.items():
    if len(gram) == 4:
        a, b, c, d = [ord(ch) - 65 for ch in gram]
        QG[a * 17576 + b * 676 + c * 26 + d] = logp
del _qg_raw


def qg_score(text):
    """Quadgram log-probability score."""
    n = len(text)
    if n < 4:
        return -999.0
    total = 0.0
    for i in range(n - 3):
        a = ord(text[i]) - 65
        b = ord(text[i+1]) - 65
        c = ord(text[i+2]) - 65
        d = ord(text[i+3]) - 65
        total += QG[a * 17576 + b * 676 + c * 26 + d]
    return total / (n - 3)


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ATTACK
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 78)
    print("CSP SURVIVOR TEST: P=23, Width-15 Columnar, Beaufort")
    print("Mask config (5,0,2) — fully determined key")
    print("=" * 78)
    print()
    print(f"Known key ({PERIOD} values): {KNOWN_KEY}")
    print(f"Key as letters: {''.join(ALPH[k] for k in KNOWN_KEY)}")
    print(f"Transposition width: {WIDTH}")
    print(f"Extracted CT length: {CT_EXTRACTED_LEN}")
    print()

    # ── Identify candidate null positions in each segment ──

    # Segment 1: positions 0-20 that are NOT already consensus nulls
    seg1_candidates = [p for p in range(21) if p not in CONSENSUS_NULL_POSITIONS]
    # Segment 3: positions 74-96 that are NOT already consensus nulls
    seg3_candidates = [p for p in range(74, 97) if p not in CONSENSUS_NULL_POSITIONS]

    print(f"Segment 1 candidates ({len(seg1_candidates)}): {seg1_candidates}")
    print(f"Segment 3 candidates ({len(seg3_candidates)}): {seg3_candidates}")

    n_masks = len(list(combinations(seg1_candidates, 5))) * len(list(combinations(seg3_candidates, 2)))
    print(f"Total masks to test: {n_masks:,}")
    print()

    # ── Precompute CT as numbers ──
    ct_nums = [ALPH_IDX[c] for c in CT]

    # ── Sweep all masks ──
    t0 = time.time()
    best_qg = -999.0
    best_results = []
    tested = 0

    for seg1_extra in combinations(seg1_candidates, 5):
        for seg3_extra in combinations(seg3_candidates, 2):
            # Full null mask
            null_mask = CONSENSUS_NULL_POSITIONS | set(seg1_extra) | set(seg3_extra)
            assert len(null_mask) == 24

            # Extract 73-char CT
            extracted = []
            pos_map = []  # compressed_idx → original_pos
            for i in range(CT_LEN):
                if i not in null_mask:
                    extracted.append(ct_nums[i])
                    pos_map.append(i)
            assert len(extracted) == CT_EXTRACTED_LEN

            # Apply inverse columnar transposition
            detransposed = [0] * CT_EXTRACTED_LEN
            for i in range(CT_EXTRACTED_LEN):
                detransposed[INV_PERM[i]] = extracted[i]

            # Decrypt with Beaufort: PT = (Key - CT) mod 26
            pt_nums = [(KNOWN_KEY[i % PERIOD] - detransposed[i]) % 26
                       for i in range(CT_EXTRACTED_LEN)]
            pt_text = ''.join(ALPH[v] for v in pt_nums)

            # Score
            qg = qg_score(pt_text)

            # Check crib matches (in the decrypted text, map back to original positions)
            # After inverse transposition, position i in detransposed corresponds to
            # the i-th character of the pre-transposition plaintext.
            # The cribs are at compressed positions in the extracted text.
            # We need to map: original crib pos → compressed pos → transposed pos → key pos
            crib_matches = 0
            for orig_pos, expected_char in CRIB_DICT.items():
                if orig_pos in null_mask:
                    continue  # crib position was nulled (shouldn't happen)
                # Find compressed index
                try:
                    comp_idx = pos_map.index(orig_pos)
                except ValueError:
                    continue
                # The extracted text at comp_idx was placed at INV_PERM[comp_idx]
                # after inverse transposition, then decrypted
                detrans_idx = INV_PERM[comp_idx]
                pt_val = (KNOWN_KEY[detrans_idx % PERIOD] - extracted[comp_idx]) % 26
                if ALPH[pt_val] == expected_char:
                    crib_matches += 1

            tested += 1

            if qg > best_qg or crib_matches >= STORE_THRESHOLD:
                if qg > best_qg:
                    best_qg = qg
                best_results.append({
                    'qg_score': round(qg, 3),
                    'crib_matches': crib_matches,
                    'seg1_extra': list(seg1_extra),
                    'seg3_extra': list(seg3_extra),
                    'plaintext': pt_text,
                })
                # Keep only top 20 by qg
                best_results.sort(key=lambda x: -x['qg_score'])
                best_results = best_results[:20]

            if tested % 50000 == 0:
                elapsed = time.time() - t0
                print(f"  [{tested:,}/{n_masks:,}] best_qg={best_qg:.3f} "
                      f"rate={tested/elapsed:,.0f}/s")

    elapsed = time.time() - t0
    print()
    print("=" * 78)
    print(f"COMPLETE: {tested:,} masks in {elapsed:.2f}s ({tested/elapsed:,.0f}/s)")
    print(f"Best quadgram: {best_qg:.3f}/char")
    print()

    # ── Report ──
    print("Top results by quadgram score:")
    print("-" * 78)
    for i, r in enumerate(best_results[:10]):
        print(f"  #{i+1} qg={r['qg_score']:.3f} cribs={r['crib_matches']}/{N_CRIBS}")
        print(f"    seg1_extra={r['seg1_extra']} seg3_extra={r['seg3_extra']}")
        print(f"    PT: {r['plaintext']}")
        print()

    # Check if any result has meaningful crib matches
    max_cribs = max(r['crib_matches'] for r in best_results) if best_results else 0

    # English quadgram reference: random ≈ -4.8, English ≈ -3.9
    print(f"Best quadgram: {best_qg:.3f}/char (English ≈ -3.9, random ≈ -4.8)")
    print(f"Best crib matches: {max_cribs}/{N_CRIBS}")
    print()

    if best_qg > -4.0 or max_cribs >= SIGNAL_THRESHOLD:
        print("*** SIGNAL — INVESTIGATE ***")
    elif best_qg > -4.5 or max_cribs >= STORE_THRESHOLD:
        print("INTERESTING — worth deeper investigation")
    else:
        print(f"NOISE — P=23/w15/Beaufort produces no English-like plaintext "
              f"for any of {tested:,} mask configurations")

    # Save
    result_path = os.path.join(_ROOT, "results", "csp_p23_w15_beau.json")
    os.makedirs(os.path.dirname(result_path), exist_ok=True)
    with open(result_path, 'w') as f:
        json.dump({
            'experiment': 'e_csp_p23_w15_beau_01',
            'period': PERIOD,
            'width': WIDTH,
            'variant': 'beaufort',
            'key': KNOWN_KEY,
            'key_letters': ''.join(ALPH[k] for k in KNOWN_KEY),
            'masks_tested': tested,
            'elapsed_s': round(elapsed, 2),
            'best_qg': round(best_qg, 3),
            'best_crib_matches': max_cribs,
            'top_results': best_results[:10],
        }, f, indent=2)
    print(f"Results saved to {result_path}")


if __name__ == "__main__":
    main()
