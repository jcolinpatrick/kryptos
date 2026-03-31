#!/usr/bin/env python3
"""INCLINARE stacking hypothesis for K4 null mask derivation.

Sanborn's 1992 work "Bias Filter, INCLINARE" uses THREE metal sheets stacked
vertically with the middle sheet TILTED. Light passes through cut-out text on
the top sheet, through the tilted middle sheet, onto the bottom sheet. The tilt
creates an OFFSET between layers.

Hypothesis: Write CT97 into blocks of width W. A palette letter {B,G,I,K,O,W,Z}
at position P is NULL if and only if the SAME column in one or more OTHER blocks
also contains a palette letter. The "tilt" = an offset/shift between layers.

7 phases:
  Phase 1: Basic stacking (no offset)
  Phase 2: Stacking with linear offset (tilt)
  Phase 3: Row offset stacking
  Phase 4: Three-layer model (like INCLINARE)
  Phase 5: KA grid as the middle sheet
  Phase 6: Polybius stacking
  Phase 7: Drop first/last character variants

Cipher: null_mask_derivation
Family: analysis
Status: active
Keyspace: ~50K+ configs across 7 phases
Last run: never
Best score: TBD
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys
import os
import json
import time
import math
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CRIB_POSITIONS, KRYPTOS_ALPHABET

# ── Constants ─────────────────────────────────────────────────────────
CT97 = CT
N = 97
N_NULLS = 24
N_PT = 73
PALETTE = frozenset('BGIKOWZ')
ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_START = 21
BCL_START = 63

KA_STR = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
AZ_TO_KA = [KA_IDX[chr(i + 65)] for i in range(26)]

# Consensus null positions (17 positions, 100% agreement across all 6 known 15/24 masks)
CONSENSUS_17 = frozenset({0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85})

# All palette positions in CT97
PALETTE_POS = frozenset(i for i in range(N) if CT97[i] in PALETTE)

# ── Transposition helpers ─────────────────────────────────────────────
def columnar_perm(n, width):
    """Write row-by-row, read column-by-col. Returns gather perm."""
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


def reverse_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


# ── Autokey decrypt ───────────────────────────────────────────────────
def autokey_decrypt_az(ct_list, kw_str, beau=False):
    """AZ autokey decrypt. ct_list = list of ints 0-25."""
    kw = [ord(c) - 65 for c in kw_str.upper()]
    L = len(kw)
    pt = []
    for i, c in enumerate(ct_list):
        k = kw[i] if i < L else pt[i - L]
        p = (k - c) % 26 if beau else (c - k) % 26
        pt.append(p)
    return pt


def autokey_decrypt_ka(ct_list, kw_str, beau=False):
    """KA autokey decrypt. ct_list = list of ints 0-25 (AZ-indexed)."""
    ct_ka = [AZ_TO_KA[c] for c in ct_list]
    kw_ka = [KA_IDX[c] for c in kw_str.upper()]
    L = len(kw_ka)
    pt_ka = []
    for i, c in enumerate(ct_ka):
        k = kw_ka[i] if i < L else pt_ka[i - L]
        p = (k - c) % 26 if beau else (c - k) % 26
        pt_ka.append(p)
    return pt_ka


def pt_to_text_az(pt_indices):
    return ''.join(chr(p + 65) for p in pt_indices)


def pt_to_text_ka(pt_ka_indices):
    return ''.join(KA_STR[p] for p in pt_ka_indices)


# ── Crib scoring ──────────────────────────────────────────────────────
def count_crib_hits(pt_text, ene_s, bcl_s):
    """Score cribs against plaintext string. Returns (total, ene, bcl)."""
    e = sum(1 for j, c in enumerate(ENE_WORD)
            if ene_s + j < len(pt_text) and pt_text[ene_s + j] == c)
    b = sum(1 for j, c in enumerate(BCL_WORD)
            if bcl_s + j < len(pt_text) and pt_text[bcl_s + j] == c)
    return e + b, e, b


def count_crib_hits_az(pt_indices, ene_s, bcl_s, n_pt):
    e = sum(1 for j, c in enumerate(ENE_WORD)
            if ene_s + j < n_pt and pt_indices[ene_s + j] == ord(c) - 65)
    b = sum(1 for j, c in enumerate(BCL_WORD)
            if bcl_s + j < n_pt and pt_indices[bcl_s + j] == ord(c) - 65)
    return e + b, e, b


def count_crib_hits_ka(pt_ka, ene_s, bcl_s, n_pt):
    e = sum(1 for j, c in enumerate(ENE_WORD)
            if ene_s + j < n_pt and pt_ka[ene_s + j] == KA_IDX[c])
    b = sum(1 for j, c in enumerate(BCL_WORD)
            if bcl_s + j < n_pt and pt_ka[bcl_s + j] == KA_IDX[c])
    return e + b, e, b


# ── Mask scoring ──────────────────────────────────────────────────────
def score_mask_consensus(null_set):
    """Score a null mask against the 17 consensus nulls.
    Returns (tp, fp, fn, precision, recall, f1)."""
    tp = len(null_set & CONSENSUS_17)
    fp = len(null_set - CONSENSUS_17)
    fn = len(CONSENSUS_17 - null_set)
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    return tp, fp, fn, prec, rec, f1


def evaluate_mask_with_ciphers(null_set, ct_str=CT97, ct_len=N):
    """Evaluate a null mask with DEFECTOR:AZ_beau + col6/col7.
    Returns best (crib_score, ene, bcl, pt_text, method)."""
    # Only evaluate if we have between 20 and 28 nulls
    n_nulls = len(null_set)
    if n_nulls < 10 or n_nulls > 40:
        return 0, 0, 0, "", "skip"

    n_pt = ct_len - n_nulls

    # Extract non-null chars
    ct_extract = [ct_str[i] for i in range(ct_len) if i not in null_set]
    ct_az = [ord(c) - 65 for c in ct_extract]

    # Compute shifted crib positions
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1
    bcl_s = BCL_START - n2

    if ene_s < 0 or bcl_s < 0 or ene_s + len(ENE_WORD) > n_pt or bcl_s + len(BCL_WORD) > n_pt:
        return 0, 0, 0, "", "skip_bounds"

    best = (0, 0, 0, "", "none")

    configs = [
        ("DEFECTOR", True, False, True, 7, "DEFECTOR:AZ_beau+col7"),
        ("DEFECTOR", True, False, True, 6, "DEFECTOR:AZ_beau+col6"),
        ("DEFECTOR", True, False, False, 0, "DEFECTOR:AZ_beau_direct"),
        ("KRYPTOS", False, True, True, 7, "KRYPTOS:KA_vig+col7"),
        ("KRYPTOS", False, True, False, 0, "KRYPTOS:KA_vig_direct"),
        ("DEFECTOR", False, False, True, 7, "DEFECTOR:AZ_vig+col7"),
        ("KRYPTOS", True, True, True, 7, "KRYPTOS:KA_beau+col7"),
        ("KRYPTOS", True, True, False, 0, "KRYPTOS:KA_beau_direct"),
    ]

    for kw, beau, ka, use_col, width, label in configs:
        work = list(ct_az)

        if use_col and width > 0:
            perm = columnar_perm(n_pt, width)
            inv = reverse_perm(perm)
            work = [ct_az[inv[i]] for i in range(n_pt)]

        if ka:
            pt = autokey_decrypt_ka(work, kw, beau)
            total, e, b = count_crib_hits_ka(pt, ene_s, bcl_s, n_pt)
            pt_text = pt_to_text_ka(pt)
        else:
            pt = autokey_decrypt_az(work, kw, beau)
            total, e, b = count_crib_hits_az(pt, ene_s, bcl_s, n_pt)
            pt_text = pt_to_text_az(pt)

        if total > best[0]:
            best = (total, e, b, pt_text, label)

    return best


# ══════════════════════════════════════════════════════════════════════
# PHASE 1: Basic stacking (no offset)
# ══════════════════════════════════════════════════════════════════════
def phase1_basic_stacking(ct_str, ct_len, label="CT97"):
    """For each block width W, palette positions overlapping across blocks = null."""
    results = []
    palette_pos = frozenset(i for i in range(ct_len) if ct_str[i] in PALETTE)

    for W in range(4, 33):
        n_blocks = math.ceil(ct_len / W)

        # For each column, find which blocks have a palette letter
        col_palette_blocks = defaultdict(list)
        for pos in palette_pos:
            block = pos // W
            col = pos % W
            col_palette_blocks[col].append((block, pos))

        # Nulls: positions in columns where 2+ blocks have palette letters
        null_set = set()
        for col, entries in col_palette_blocks.items():
            if len(entries) >= 2:
                for _, pos in entries:
                    null_set.add(pos)

        null_set = frozenset(null_set)
        n_nulls = len(null_set)
        tp, fp, fn, prec, rec, f1 = score_mask_consensus(null_set)

        # Cipher evaluation
        crib_total, crib_e, crib_b, pt_text, method = evaluate_mask_with_ciphers(
            null_set, ct_str, ct_len)

        results.append({
            "phase": 1, "variant": label, "width": W, "offset": 0,
            "n_nulls": n_nulls, "null_positions": sorted(null_set),
            "tp": tp, "fp": fp, "fn": fn,
            "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
            "crib_score": crib_total, "crib_ene": crib_e, "crib_bcl": crib_b,
            "method": method, "pt_prefix": pt_text[:40] if pt_text else ""
        })

    return results


# ══════════════════════════════════════════════════════════════════════
# PHASE 2: Stacking with linear offset (the TILT)
# ══════════════════════════════════════════════════════════════════════
def phase2_tilt_stacking(ct_str, ct_len, label="CT97"):
    """Each block i is shifted by i*D columns before comparing."""
    results = []
    palette_pos = frozenset(i for i in range(ct_len) if ct_str[i] in PALETTE)

    for W in range(4, 33):
        n_blocks = math.ceil(ct_len / W)

        for D in range(0, W):
            if D == 0:
                continue  # D=0 is Phase 1

            # For each block, compute shifted column position for each palette letter
            shifted_col_blocks = defaultdict(list)
            for pos in palette_pos:
                block = pos // W
                col = pos % W
                shifted_col = (col + block * D) % W
                shifted_col_blocks[shifted_col].append((block, pos))

            # Nulls: positions where shifted column overlaps
            null_set = set()
            for shifted_col, entries in shifted_col_blocks.items():
                if len(entries) >= 2:
                    for _, pos in entries:
                        null_set.add(pos)

            null_set = frozenset(null_set)
            n_nulls = len(null_set)
            tp, fp, fn, prec, rec, f1 = score_mask_consensus(null_set)

            crib_total, crib_e, crib_b, pt_text, method = evaluate_mask_with_ciphers(
                null_set, ct_str, ct_len)

            results.append({
                "phase": 2, "variant": label, "width": W, "offset": D,
                "n_nulls": n_nulls, "null_positions": sorted(null_set),
                "tp": tp, "fp": fp, "fn": fn,
                "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
                "crib_score": crib_total, "crib_ene": crib_e, "crib_bcl": crib_b,
                "method": method, "pt_prefix": pt_text[:40] if pt_text else ""
            })

    return results


# ══════════════════════════════════════════════════════════════════════
# PHASE 3: Row offset stacking
# ══════════════════════════════════════════════════════════════════════
def phase3_row_offset(ct_str, ct_len, label="CT97"):
    """Compare row i with row (i+D) mod num_rows -- shared palette columns = null."""
    results = []
    palette_pos = frozenset(i for i in range(ct_len) if ct_str[i] in PALETTE)

    for W in range(4, 33):
        n_rows = math.ceil(ct_len / W)

        # Build grid: row -> set of palette columns
        row_palette_cols = defaultdict(set)
        row_palette_pos = defaultdict(dict)  # row -> {col: position}
        for pos in palette_pos:
            row = pos // W
            col = pos % W
            row_palette_cols[row].add(col)
            row_palette_pos[row][col] = pos

        for D in range(1, n_rows):
            null_set = set()
            for row in range(n_rows):
                other = (row + D) % n_rows
                # Shared palette columns
                shared = row_palette_cols[row] & row_palette_cols[other]
                for col in shared:
                    if col in row_palette_pos[row]:
                        null_set.add(row_palette_pos[row][col])
                    if col in row_palette_pos[other]:
                        null_set.add(row_palette_pos[other][col])

            null_set = frozenset(null_set)
            n_nulls = len(null_set)
            tp, fp, fn, prec, rec, f1 = score_mask_consensus(null_set)

            crib_total, crib_e, crib_b, pt_text, method = evaluate_mask_with_ciphers(
                null_set, ct_str, ct_len)

            results.append({
                "phase": 3, "variant": label, "width": W, "row_offset": D,
                "n_nulls": n_nulls, "null_positions": sorted(null_set),
                "tp": tp, "fp": fp, "fn": fn,
                "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
                "crib_score": crib_total, "crib_ene": crib_e, "crib_bcl": crib_b,
                "method": method, "pt_prefix": pt_text[:40] if pt_text else ""
            })

    return results


# ══════════════════════════════════════════════════════════════════════
# PHASE 4: Three-layer model (like INCLINARE)
# ══════════════════════════════════════════════════════════════════════
def phase4_three_layer(ct_str, ct_len, label="CT97"):
    """Split CT into 3 layers (top/middle/bottom). Middle is offset.
    Palette overlap across any two layers = null."""
    results = []

    # Fixed split points to try
    splits = [
        (25, 25, 47), (24, 24, 49), (31, 31, 35), (33, 33, 31), (35, 35, 27),
        (32, 33, 32), (33, 32, 32), (24, 49, 24), (49, 24, 24),
        (31, 35, 31), (35, 31, 31), (14, 69, 14), (48, 1, 48),
        (24, 73, 0),  # two layers: top 24 + bottom 73
        (0, 73, 24),  # two layers: top 73 + bottom 24
        (13, 71, 13), (11, 75, 11),
    ]

    for W in [5, 6, 7, 8, 9, 10, 11, 13, 14, 31]:
        for n1, n2, n3 in splits:
            if n1 + n2 + n3 != ct_len:
                continue

            for D in range(0, W):
                # Layer 1: positions 0..n1-1
                # Layer 2: positions n1..n1+n2-1 (with offset D)
                # Layer 3: positions n1+n2..ct_len-1
                layers_palette = [defaultdict(list) for _ in range(3)]

                for pos in range(ct_len):
                    if ct_str[pos] not in PALETTE:
                        continue
                    if pos < n1:
                        layer = 0
                        col = pos % W
                    elif pos < n1 + n2:
                        layer = 1
                        local = pos - n1
                        col = (local % W + D) % W  # tilted
                    else:
                        layer = 2
                        local = pos - n1 - n2
                        col = local % W

                    layers_palette[layer][col].append(pos)

                # Find overlapping columns across layers
                null_set = set()
                for c in range(W):
                    # Get all positions in this (shifted) column across layers
                    all_entries = []
                    for layer_idx in range(3):
                        all_entries.extend(layers_palette[layer_idx].get(c, []))

                    # Count how many LAYERS have entries at this column
                    layers_present = sum(
                        1 for layer_idx in range(3) if c in layers_palette[layer_idx])

                    if layers_present >= 2:
                        for pos in all_entries:
                            null_set.add(pos)

                null_set = frozenset(null_set)
                n_nulls = len(null_set)
                tp, fp, fn, prec, rec, f1 = score_mask_consensus(null_set)

                crib_total, crib_e, crib_b, pt_text, method = evaluate_mask_with_ciphers(
                    null_set, ct_str, ct_len)

                results.append({
                    "phase": 4, "variant": label, "width": W,
                    "split": f"{n1}/{n2}/{n3}", "offset": D,
                    "n_nulls": n_nulls, "null_positions": sorted(null_set),
                    "tp": tp, "fp": fp, "fn": fn,
                    "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
                    "crib_score": crib_total, "crib_ene": crib_e, "crib_bcl": crib_b,
                    "method": method, "pt_prefix": pt_text[:40] if pt_text else ""
                })

    return results


# ══════════════════════════════════════════════════════════════════════
# PHASE 5: KA grid as the middle sheet
# ══════════════════════════════════════════════════════════════════════
def phase5_ka_middle_sheet(ct_str, ct_len, label="CT97"):
    """KA 5-wide grid has palette at specific cells. CT written in width-5 blocks.
    A CT position is null if it's a palette letter AND falls on a KA palette cell."""
    results = []

    # KA 5-wide grid palette positions (row, col)
    # K(0,0), O(1,0), B(1,3), G(2,3), I(3,0), W(4,3), Z(5,0)
    ka_palette_cells = {(0, 0), (1, 0), (1, 3), (2, 3), (3, 0), (4, 3), (5, 0)}

    for W in [5, 6, 7, 10, 13, 26]:
        n_ka_rows = 6 if W == 5 else (26 + W - 1) // W  # KA has 26 letters

        # For width != 5, recompute KA palette cells
        if W != 5:
            ka_cells = set()
            for i, ch in enumerate(KA_STR):
                if ch in PALETTE:
                    ka_cells.add((i // W, i % W))
        else:
            ka_cells = ka_palette_cells

        for row_offset in range(0, max(1, (ct_len + W - 1) // W)):
            null_set = set()
            for pos in range(ct_len):
                if ct_str[pos] not in PALETTE:
                    continue
                ct_row = pos // W
                ct_col = pos % W
                # Map CT row to KA row with offset
                ka_row = (ct_row + row_offset) % n_ka_rows if n_ka_rows > 0 else 0
                if (ka_row, ct_col) in ka_cells:
                    null_set.add(pos)

            null_set = frozenset(null_set)
            n_nulls = len(null_set)
            tp, fp, fn, prec, rec, f1 = score_mask_consensus(null_set)

            crib_total, crib_e, crib_b, pt_text, method = evaluate_mask_with_ciphers(
                null_set, ct_str, ct_len)

            results.append({
                "phase": 5, "variant": label, "width": W, "ka_row_offset": row_offset,
                "n_nulls": n_nulls, "null_positions": sorted(null_set),
                "tp": tp, "fp": fp, "fn": fn,
                "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
                "crib_score": crib_total, "crib_ene": crib_e, "crib_bcl": crib_b,
                "method": method, "pt_prefix": pt_text[:40] if pt_text else ""
            })

    return results


# ══════════════════════════════════════════════════════════════════════
# PHASE 6: Polybius stacking
# ══════════════════════════════════════════════════════════════════════
def phase6_polybius_stacking(ct_str, ct_len, label="CT97"):
    """Map CT chars to KA grid (row,col). Consecutive pairs that share
    a palette row/col = null under various conditions."""
    results = []

    # KA grid coordinates for each letter
    def ka_coords(ch):
        idx = KA_IDX.get(ch, -1)
        if idx < 0:
            return (-1, -1)
        return (idx // 5, idx % 5)

    ka_palette_rows = {0, 1, 2, 3, 4, 5}  # All rows have palette
    ka_palette_cols = {0, 3}  # Palette is only in cols 0 and 3

    # Condition A: position i is null if CT[i] is palette AND CT[i+1] is also palette
    null_a = set()
    for i in range(ct_len - 1):
        if ct_str[i] in PALETTE and ct_str[i + 1] in PALETTE:
            null_a.add(i)
            null_a.add(i + 1)

    tp, fp, fn, prec, rec, f1 = score_mask_consensus(frozenset(null_a))
    crib_total, crib_e, crib_b, pt_text, method = evaluate_mask_with_ciphers(
        frozenset(null_a), ct_str, ct_len)
    results.append({
        "phase": 6, "variant": label, "condition": "adjacent_palette",
        "n_nulls": len(null_a), "null_positions": sorted(null_a),
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
        "crib_score": crib_total, "crib_ene": crib_e, "crib_bcl": crib_b,
        "method": method, "pt_prefix": pt_text[:40] if pt_text else ""
    })

    # Condition B: position i is null if KA_row(CT[i]) == KA_row(CT[i+1])
    # and CT[i] is in palette
    null_b = set()
    for i in range(ct_len - 1):
        r1, c1 = ka_coords(ct_str[i])
        r2, c2 = ka_coords(ct_str[i + 1])
        if ct_str[i] in PALETTE and r1 == r2:
            null_b.add(i)

    tp, fp, fn, prec, rec, f1 = score_mask_consensus(frozenset(null_b))
    crib_total, crib_e, crib_b, pt_text, method = evaluate_mask_with_ciphers(
        frozenset(null_b), ct_str, ct_len)
    results.append({
        "phase": 6, "variant": label, "condition": "same_ka_row",
        "n_nulls": len(null_b), "null_positions": sorted(null_b),
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
        "crib_score": crib_total, "crib_ene": crib_e, "crib_bcl": crib_b,
        "method": method, "pt_prefix": pt_text[:40] if pt_text else ""
    })

    # Condition C: position i is null if KA_col(CT[i]) is in palette cols {0,3}
    null_c = set()
    for i in range(ct_len):
        r, c = ka_coords(ct_str[i])
        if c in ka_palette_cols:
            null_c.add(i)

    tp, fp, fn, prec, rec, f1 = score_mask_consensus(frozenset(null_c))
    crib_total, crib_e, crib_b, pt_text, method = evaluate_mask_with_ciphers(
        frozenset(null_c), ct_str, ct_len)
    results.append({
        "phase": 6, "variant": label, "condition": "ka_palette_col",
        "n_nulls": len(null_c), "null_positions": sorted(null_c),
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
        "crib_score": crib_total, "crib_ene": crib_e, "crib_bcl": crib_b,
        "method": method, "pt_prefix": pt_text[:40] if pt_text else ""
    })

    # Condition D: Pair stacking -- (CT[2i], CT[2i+1]) both palette = null
    null_d = set()
    for i in range(0, ct_len - 1, 2):
        if ct_str[i] in PALETTE and ct_str[i + 1] in PALETTE:
            null_d.add(i)
            null_d.add(i + 1)

    tp, fp, fn, prec, rec, f1 = score_mask_consensus(frozenset(null_d))
    crib_total, crib_e, crib_b, pt_text, method = evaluate_mask_with_ciphers(
        frozenset(null_d), ct_str, ct_len)
    results.append({
        "phase": 6, "variant": label, "condition": "pair_both_palette",
        "n_nulls": len(null_d), "null_positions": sorted(null_d),
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
        "crib_score": crib_total, "crib_ene": crib_e, "crib_bcl": crib_b,
        "method": method, "pt_prefix": pt_text[:40] if pt_text else ""
    })

    # Condition E: for each gap g (2-8), palette at pos i AND palette at pos i+g = null
    for gap in range(2, 9):
        null_e = set()
        for i in range(ct_len - gap):
            if ct_str[i] in PALETTE and ct_str[i + gap] in PALETTE:
                null_e.add(i)
                null_e.add(i + gap)

        null_e = frozenset(null_e)
        tp, fp, fn, prec, rec, f1 = score_mask_consensus(null_e)
        crib_total, crib_e, crib_b, pt_text, method = evaluate_mask_with_ciphers(
            null_e, ct_str, ct_len)
        results.append({
            "phase": 6, "variant": label, "condition": f"gap_{gap}_overlap",
            "n_nulls": len(null_e), "null_positions": sorted(null_e),
            "tp": tp, "fp": fp, "fn": fn,
            "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
            "crib_score": crib_total, "crib_ene": crib_e, "crib_bcl": crib_b,
            "method": method, "pt_prefix": pt_text[:40] if pt_text else ""
        })

    return results


# ══════════════════════════════════════════════════════════════════════
# PHASE 7: Drop first/last character variants
# ══════════════════════════════════════════════════════════════════════
def phase7_trimmed(all_phases_fn):
    """Run all phases on trimmed CT variants."""
    results = []
    variants = [
        ("drop_first", CT97[1:]),     # Drop O (palette, consensus null)
        ("drop_last", CT97[:-1]),      # Drop R (not palette)
        ("drop_both", CT97[1:-1]),     # 95 chars = 5 x 19
    ]

    for vname, vtext in variants:
        vlen = len(vtext)
        # We run phase 1 and 2 on each variant (most impactful)
        r1 = phase1_basic_stacking(vtext, vlen, vname)
        r2 = phase2_tilt_stacking(vtext, vlen, vname)
        for r in r1 + r2:
            r["phase"] = 7
            r["sub_phase"] = r.get("phase", 0)
        results.extend(r1 + r2)

    return results


# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════
def main():
    t0 = time.time()

    print("=" * 72)
    print("INCLINARE STACKED NULL MASK HYPOTHESIS")
    print("=" * 72)
    print(f"CT97 = {CT97}")
    print(f"Palette letters: {sorted(PALETTE)} ({len(PALETTE)} letters)")
    print(f"Palette positions in CT ({len(PALETTE_POS)}): {sorted(PALETTE_POS)}")
    print(f"Consensus nulls (17): {sorted(CONSENSUS_17)}")
    print(f"  Letters: {''.join(CT97[i] for i in sorted(CONSENSUS_17))}")
    print()

    all_results = []

    # Phase 1
    print("--- Phase 1: Basic stacking (no offset) ---")
    r1 = phase1_basic_stacking(CT97, N)
    all_results.extend(r1)
    best1 = max(r1, key=lambda x: x["f1"])
    print(f"  {len(r1)} configs. Best F1={best1['f1']:.3f} at W={best1['width']} "
          f"(TP={best1['tp']}, FP={best1['fp']}, FN={best1['fn']}, "
          f"n_nulls={best1['n_nulls']}, crib={best1['crib_score']}/24)")

    # Phase 2
    print("--- Phase 2: Stacking with linear offset (tilt) ---")
    r2 = phase2_tilt_stacking(CT97, N)
    all_results.extend(r2)
    best2 = max(r2, key=lambda x: x["f1"])
    print(f"  {len(r2)} configs. Best F1={best2['f1']:.3f} at W={best2['width']}, D={best2['offset']} "
          f"(TP={best2['tp']}, FP={best2['fp']}, FN={best2['fn']}, "
          f"n_nulls={best2['n_nulls']}, crib={best2['crib_score']}/24)")

    # Phase 3
    print("--- Phase 3: Row offset stacking ---")
    r3 = phase3_row_offset(CT97, N)
    all_results.extend(r3)
    best3 = max(r3, key=lambda x: x["f1"])
    print(f"  {len(r3)} configs. Best F1={best3['f1']:.3f} at W={best3['width']}, D={best3.get('row_offset',0)} "
          f"(TP={best3['tp']}, FP={best3['fp']}, FN={best3['fn']}, "
          f"n_nulls={best3['n_nulls']}, crib={best3['crib_score']}/24)")

    # Phase 4
    print("--- Phase 4: Three-layer model ---")
    r4 = phase4_three_layer(CT97, N)
    all_results.extend(r4)
    best4 = max(r4, key=lambda x: x["f1"])
    print(f"  {len(r4)} configs. Best F1={best4['f1']:.3f} at W={best4['width']}, "
          f"split={best4.get('split','?')}, D={best4['offset']} "
          f"(TP={best4['tp']}, FP={best4['fp']}, FN={best4['fn']}, "
          f"n_nulls={best4['n_nulls']}, crib={best4['crib_score']}/24)")

    # Phase 5
    print("--- Phase 5: KA grid as middle sheet ---")
    r5 = phase5_ka_middle_sheet(CT97, N)
    all_results.extend(r5)
    best5 = max(r5, key=lambda x: x["f1"])
    print(f"  {len(r5)} configs. Best F1={best5['f1']:.3f} at W={best5['width']} "
          f"(TP={best5['tp']}, FP={best5['fp']}, FN={best5['fn']}, "
          f"n_nulls={best5['n_nulls']}, crib={best5['crib_score']}/24)")

    # Phase 6
    print("--- Phase 6: Polybius stacking ---")
    r6 = phase6_polybius_stacking(CT97, N)
    all_results.extend(r6)
    best6 = max(r6, key=lambda x: x["f1"])
    print(f"  {len(r6)} configs. Best F1={best6['f1']:.3f} condition={best6.get('condition','?')} "
          f"(TP={best6['tp']}, FP={best6['fp']}, FN={best6['fn']}, "
          f"n_nulls={best6['n_nulls']}, crib={best6['crib_score']}/24)")

    # Phase 7
    print("--- Phase 7: Drop first/last char variants ---")
    r7 = phase7_trimmed(None)  # phases 1+2 on trimmed variants
    all_results.extend(r7)
    if r7:
        best7 = max(r7, key=lambda x: x["f1"])
        print(f"  {len(r7)} configs. Best F1={best7['f1']:.3f} variant={best7.get('variant','?')} "
              f"W={best7['width']} (TP={best7['tp']}, FP={best7['fp']}, FN={best7['fn']}, "
              f"n_nulls={best7['n_nulls']}, crib={best7['crib_score']}/24)")

    elapsed = time.time() - t0
    print()
    print("=" * 72)
    print(f"TOTAL: {len(all_results)} configs evaluated in {elapsed:.1f}s")
    print()

    # ── Top 20 by F1 score ──────────────────────────────────────────
    print("--- TOP 20 BY F1 SCORE ---")
    top_f1 = sorted(all_results, key=lambda x: (-x["f1"], -x["tp"]))[:20]
    for i, r in enumerate(top_f1):
        phase = r["phase"]
        extra = ""
        if phase == 2:
            extra = f" D={r.get('offset', 0)}"
        elif phase == 3:
            extra = f" D={r.get('row_offset', 0)}"
        elif phase == 4:
            extra = f" split={r.get('split', '?')} D={r.get('offset', 0)}"
        elif phase == 5:
            extra = f" ka_off={r.get('ka_row_offset', 0)}"
        elif phase == 6:
            extra = f" cond={r.get('condition', '?')}"
        elif phase == 7:
            extra = f" var={r.get('variant', '?')}"

        print(f"  {i+1:2d}. P{phase} W={str(r.get('width', '-')):>3s}{extra}"
              f"  F1={r['f1']:.3f} TP={r['tp']:2d} FP={r['fp']:2d} FN={r['fn']:2d}"
              f"  n={r['n_nulls']:2d}"
              f"  crib={r['crib_score']}/24 [{r['method']}]")

    # ── Top 20 by crib score ────────────────────────────────────────
    print()
    print("--- TOP 20 BY CRIB SCORE ---")
    top_crib = sorted(all_results, key=lambda x: (-x["crib_score"], -x["f1"]))[:20]
    for i, r in enumerate(top_crib):
        phase = r["phase"]
        extra = ""
        if phase == 2:
            extra = f" D={r.get('offset', 0)}"
        elif phase == 3:
            extra = f" D={r.get('row_offset', 0)}"
        elif phase == 4:
            extra = f" split={r.get('split', '?')} D={r.get('offset', 0)}"
        elif phase == 5:
            extra = f" ka_off={r.get('ka_row_offset', 0)}"
        elif phase == 6:
            extra = f" cond={r.get('condition', '?')}"
        elif phase == 7:
            extra = f" var={r.get('variant', '?')}"

        print(f"  {i+1:2d}. P{phase} W={str(r.get('width', '-')):>3s}{extra}"
              f"  F1={r['f1']:.3f} TP={r['tp']:2d} FP={r['fp']:2d} FN={r['fn']:2d}"
              f"  n={r['n_nulls']:2d}"
              f"  crib={r['crib_score']}/24 [{r['method']}]"
              f"  PT={r['pt_prefix']}")

    # ── Masks with exactly 24 nulls ─────────────────────────────────
    exact24 = [r for r in all_results if r["n_nulls"] == 24]
    print()
    print(f"--- MASKS WITH EXACTLY 24 NULLS: {len(exact24)} ---")
    if exact24:
        top24 = sorted(exact24, key=lambda x: (-x["f1"], -x["crib_score"]))[:10]
        for r in top24:
            print(f"  P{r['phase']} W={r.get('width','-')} F1={r['f1']:.3f} "
                  f"crib={r['crib_score']}/24 n={r['n_nulls']}")

    # ── Save results ────────────────────────────────────────────────
    output = {
        "experiment": "inclinare_stacked_null_mask",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ct": CT97,
        "palette": sorted(PALETTE),
        "consensus_17": sorted(CONSENSUS_17),
        "total_configs": len(all_results),
        "elapsed_seconds": round(elapsed, 1),
        "phase_counts": {
            f"phase_{p}": sum(1 for r in all_results if r["phase"] == p)
            for p in range(1, 8)
        },
        "best_f1": {
            "f1": top_f1[0]["f1"] if top_f1 else 0,
            "config": top_f1[0] if top_f1 else None
        },
        "best_crib": {
            "score": top_crib[0]["crib_score"] if top_crib else 0,
            "config": top_crib[0] if top_crib else None
        },
        "exact_24_count": len(exact24),
        "top_20_f1": top_f1,
        "top_20_crib": top_crib,
        "conclusion": "TBD"
    }

    # Determine conclusion
    max_crib = max(r["crib_score"] for r in all_results) if all_results else 0
    max_f1 = max(r["f1"] for r in all_results) if all_results else 0.0
    if max_crib >= 18:
        output["conclusion"] = "SIGNAL"
    elif max_crib >= 10:
        output["conclusion"] = "INTERESTING"
    elif max_f1 >= 0.6:
        output["conclusion"] = "INTERESTING_CONSENSUS"
    else:
        output["conclusion"] = "NOISE"

    outpath = os.path.join(os.path.dirname(__file__), '..', '..', 'results',
                           'inclinare_stacked_null_mask.json')
    outpath = os.path.normpath(outpath)
    with open(outpath, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nResults saved to {outpath}")

    print()
    print(f"VERDICT: {output['conclusion']}")
    print(f"Best F1={max_f1:.3f}, Best crib={max_crib}/24")
    if max_crib <= 9:
        print("All crib scores within noise range (<=9/24).")
    print(f"Elapsed: {elapsed:.1f}s")


if __name__ == "__main__":
    main()
