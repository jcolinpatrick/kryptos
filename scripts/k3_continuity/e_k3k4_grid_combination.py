#!/usr/bin/env python3
"""
Cipher:   K3-K4 grid combination
Family:   k3_continuity
Status:   active
Keyspace: ~2,000 configs
Last run:
Best score:

HYPOTHESIS: "X LAYER TWO" means K4 decodes when combined with K3 on the
shared 14×31 panel grid. K3 PT/CT at column-aligned positions provides
the cipher key for K4.

Evidence:
- K2 PT ends with "X LAYERTWO" (standalone instruction after X delimiter)
- Physical copper reads "IDBYROWS" at the same position
- K3+?+K4 = 434 = 14×31 (perfect grid fit)
- K3 and K4 share physical panel space on the sculpture

Models tested:
  A: Column-aligned keying — K3 PT/CT at (row_k3, col) keys K4 at (row_k4, col)
     All 11 K3 rows × 2 sources (PT/CT) × 3 variants × 2 alphabets = 132 configs
  B: Multi-row key — average, XOR, or cycling across K3 rows at same column
  C: K3 column-read as running key — read K3 by columns, use as sequential key
  D: K3 double-rotation intermediate — text between the two K3 rotations as key
  E: K3 permutation on combined 434-block — K3's transposition extends to K4
  F: Offset keying — K3 PT offset by crib length (13/11) as running key
  G: Row-pair keying — use 2 K3 rows (stacked) for Polybius-like coordinates
"""

import sys
import os
import json
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    KRYPTOS_ALPHABET, BEAN_EQ, BEAN_INEQ,
)

RESULTS_PATH = os.path.join(_ROOT, "results", "e_k3k4_grid_combination.json")

# ── Texts ──────────────────────────────────────────────────────────────────

K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA"
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNETP"
    "RNGATIHNRARPESLNNELEBLPIIACAEWMTW"
    "NDITEENRAHCTENEUDRETNHAEOETFOLSED"
    "TIWENHAEIOYTEYQHEENCTAYCREIFTBRSP"
    "AMHHEWENATAMATEGYEERLBTEEFOASFIOT"
    "UETUAEOTOARMAEERTNRTIBSEDDNIAAHTT"
    "MSTEWPIEROAGRIEWFEBAECTDDHILCEIHS"
    "ITEGOEAOSDDRYDLORITRKLMLEHAGTDHAR"
    "DPNEOHMGFMFEUHEECDMRIPFEIMEHNLSS"
    "TTRTVDOHW"
)

K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBERED"
    "THELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINY"
    "BREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLE"
    "IINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBER"
    "CAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHIN"
    "EMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"
)

K4_CT = CT

# ── Alphabets ──────────────────────────────────────────────────────────────

AZ = ALPH
AZ_IDX = ALPH_IDX
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

ALPHABETS = {"AZ": (AZ, AZ_IDX), "KA": (KA, KA_IDX)}

# ── Cipher variants ────────────────────────────────────────────────────────

def decrypt_vig(ct_num, key_num):
    return (ct_num - key_num) % MOD

def decrypt_beau(ct_num, key_num):
    return (key_num - ct_num) % MOD

def decrypt_vbeau(ct_num, key_num):
    return (ct_num + key_num) % MOD

VARIANTS = {"vig": decrypt_vig, "beau": decrypt_beau, "vbeau": decrypt_vbeau}

# ── Grid constants ─────────────────────────────────────────────────────────

GRID_ROWS = 14
GRID_COLS = 31
K3_LEN = 336
K4_START = 337  # K3(336) + ?(1) = 337

CRIB_POS_SORTED = sorted(CRIB_DICT.keys())

# ── Scoring ────────────────────────────────────────────────────────────────

def score_at_cribs(pt_at_cribs):
    """Score a dict {k4_pos: decrypted_letter} against known plaintext."""
    hits = sum(1 for pos, ch in pt_at_cribs.items() if CRIB_DICT.get(pos) == ch)
    return hits

def check_bean(key_at_cribs):
    """Check Bean equality constraint: key at pos 27 == key at pos 65."""
    k27 = key_at_cribs.get(27)
    k65 = key_at_cribs.get(65)
    if k27 is not None and k65 is not None:
        return k27 == k65
    return None  # can't check

def full_decrypt(key_source, variant_fn, alpha_idx, alpha_str):
    """Decrypt all 97 K4 positions given a key source mapping {k4_pos: key_letter}."""
    pt = {}
    for k4_pos in range(CT_LEN):
        if k4_pos in key_source:
            ct_n = alpha_idx[K4_CT[k4_pos]]
            key_n = alpha_idx[key_source[k4_pos]]
            pt_n = variant_fn(ct_n, key_n)
            pt[k4_pos] = alpha_str[pt_n]
    return pt

# ── Model A: Column-aligned keying ─────────────────────────────────────────

def model_a_column_aligned():
    """For each K3 row, use K3 PT/CT at same grid column as key for K4."""
    results = []

    for source_name, source_text in [("K3_PT", K3_PT), ("K3_CT", K3_CT)]:
        for k3_row in range(11):  # K3 occupies rows 0-10
            for alpha_name, (alpha_str, alpha_idx) in ALPHABETS.items():
                for var_name, var_fn in VARIANTS.items():
                    # Build key: for each K4 position, find same column in K3 row
                    key_map = {}
                    for k4_pos in range(CT_LEN):
                        combined_pos = K4_START + k4_pos
                        col = combined_pos % GRID_COLS
                        k3_pos = k3_row * GRID_COLS + col
                        if k3_pos < len(source_text):
                            key_map[k4_pos] = source_text[k3_pos]

                    # Decrypt at crib positions
                    pt = full_decrypt(key_map, var_fn, alpha_idx, alpha_str)
                    pt_at_cribs = {p: pt[p] for p in CRIB_POS_SORTED if p in pt}
                    hits = score_at_cribs(pt_at_cribs)
                    bean = check_bean({p: key_map.get(p, '?') for p in [27, 65]})

                    label = f"A:{source_name}_row{k3_row}_{var_name}_{alpha_name}"
                    results.append({
                        "model": "A",
                        "label": label,
                        "score": hits,
                        "bean_eq": bean,
                        "params": {"source": source_name, "k3_row": k3_row,
                                   "variant": var_name, "alphabet": alpha_name},
                    })
                    if hits >= 4:
                        pt_str = "".join(pt.get(i, ".") for i in range(CT_LEN))
                        results[-1]["pt_preview"] = pt_str[:40]

    return results

# ── Model B: Multi-row key ─────────────────────────────────────────────────

def model_b_multirow():
    """Key = function across multiple K3 rows at the same column."""
    results = []

    for source_name, source_text in [("K3_PT", K3_PT), ("K3_CT", K3_CT)]:
        for alpha_name, (alpha_str, alpha_idx) in ALPHABETS.items():
            for var_name, var_fn in VARIANTS.items():
                # B1: Sum of all K3 row values at column, mod 26
                key_map = {}
                for k4_pos in range(CT_LEN):
                    combined_pos = K4_START + k4_pos
                    col = combined_pos % GRID_COLS
                    total = 0
                    count = 0
                    for k3_row in range(11):
                        k3_pos = k3_row * GRID_COLS + col
                        if k3_pos < len(source_text):
                            total += alpha_idx[source_text[k3_pos]]
                            count += 1
                    if count > 0:
                        key_map[k4_pos] = alpha_str[total % MOD]

                pt = full_decrypt(key_map, var_fn, alpha_idx, alpha_str)
                pt_at_cribs = {p: pt[p] for p in CRIB_POS_SORTED if p in pt}
                hits = score_at_cribs(pt_at_cribs)

                label = f"B1:sum_{source_name}_{var_name}_{alpha_name}"
                results.append({"model": "B1", "label": label, "score": hits,
                                "params": {"method": "sum", "source": source_name,
                                           "variant": var_name, "alphabet": alpha_name}})

                # B2: Key = K3 row that matches K4's row offset
                # Row 11 → K3 row 0, Row 12 → K3 row 1, Row 13 → K3 row 2
                key_map2 = {}
                for k4_pos in range(CT_LEN):
                    combined_pos = K4_START + k4_pos
                    row = combined_pos // GRID_COLS
                    col = combined_pos % GRID_COLS
                    k3_row = row - 11  # offset so K4 row 11 → K3 row 0, etc.
                    if k3_row < 0:
                        k3_row += 11  # wrap
                    k3_pos = k3_row * GRID_COLS + col
                    if k3_pos < len(source_text):
                        key_map2[k4_pos] = source_text[k3_pos]

                pt = full_decrypt(key_map2, var_fn, alpha_idx, alpha_str)
                pt_at_cribs = {p: pt[p] for p in CRIB_POS_SORTED if p in pt}
                hits = score_at_cribs(pt_at_cribs)

                label = f"B2:row_offset_{source_name}_{var_name}_{alpha_name}"
                results.append({"model": "B2", "label": label, "score": hits,
                                "params": {"method": "row_offset", "source": source_name,
                                           "variant": var_name, "alphabet": alpha_name}})

                # B3: Cycling through K3 rows per K4 position index
                for cycle_len in [3, 7, 10, 11]:
                    key_map3 = {}
                    for k4_pos in range(CT_LEN):
                        combined_pos = K4_START + k4_pos
                        col = combined_pos % GRID_COLS
                        k3_row = k4_pos % cycle_len
                        if k3_row >= 11:
                            k3_row = k3_row % 11
                        k3_pos = k3_row * GRID_COLS + col
                        if k3_pos < len(source_text):
                            key_map3[k4_pos] = source_text[k3_pos]

                    pt = full_decrypt(key_map3, var_fn, alpha_idx, alpha_str)
                    pt_at_cribs = {p: pt[p] for p in CRIB_POS_SORTED if p in pt}
                    hits = score_at_cribs(pt_at_cribs)

                    label = f"B3:cycle{cycle_len}_{source_name}_{var_name}_{alpha_name}"
                    results.append({"model": "B3", "label": label, "score": hits,
                                    "params": {"method": f"cycle_{cycle_len}", "source": source_name,
                                               "variant": var_name, "alphabet": alpha_name}})

    return results

# ── Model C: K3 column-read as running key ─────────────────────────────────

def model_c_column_read():
    """Read K3 PT/CT by columns on 14×31 grid, use as running key for K4."""
    results = []

    for source_name, source_text in [("K3_PT", K3_PT), ("K3_CT", K3_CT)]:
        # Read by columns (top to bottom, left to right)
        col_read = []
        for c in range(GRID_COLS):
            for r in range(11):  # K3 rows 0-10
                pos = r * GRID_COLS + c
                if pos < len(source_text):
                    col_read.append(source_text[pos])
        col_read_str = "".join(col_read)

        # Also read bottom-to-top
        col_read_btt = []
        for c in range(GRID_COLS):
            for r in range(10, -1, -1):
                pos = r * GRID_COLS + c
                if pos < len(source_text):
                    col_read_btt.append(source_text[pos])
        col_read_btt_str = "".join(col_read_btt)

        for read_name, read_str in [("col_ttb", col_read_str), ("col_btt", col_read_btt_str)]:
            for alpha_name, (alpha_str, alpha_idx) in ALPHABETS.items():
                for var_name, var_fn in VARIANTS.items():
                    # Try various offsets into the column-read text
                    for offset in range(0, min(len(read_str) - CT_LEN, 50)):
                        key_map = {}
                        for k4_pos in range(CT_LEN):
                            key_idx = offset + k4_pos
                            if key_idx < len(read_str):
                                key_map[k4_pos] = read_str[key_idx]

                        pt = full_decrypt(key_map, var_fn, alpha_idx, alpha_str)
                        pt_at_cribs = {p: pt[p] for p in CRIB_POS_SORTED if p in pt}
                        hits = score_at_cribs(pt_at_cribs)

                        if hits >= 3 or offset < 5:  # always log first few offsets
                            label = f"C:{read_name}_{source_name}_off{offset}_{var_name}_{alpha_name}"
                            results.append({"model": "C", "label": label, "score": hits,
                                            "params": {"read": read_name, "source": source_name,
                                                       "offset": offset, "variant": var_name,
                                                       "alphabet": alpha_name}})

    return results

# ── Model D: K3 intermediate text as key ───────────────────────────────────

def k3_intermediate():
    """Compute K3's intermediate text (between the two rotations).

    K3 encrypt: PT → write into 24×14 grid row-by-row → CW rotate → read row-by-row
                → write into 8×42 grid row-by-row → CW rotate → read row-by-row → CT

    The intermediate is the text after the first rotation but before writing into
    the second grid (they're the same text since reading row-by-row IS the text).
    """
    # K3 decrypt step 1: write CT into 24×14, rotate CW, read
    # Rotation CW of 24-wide × 14-tall: old[r][c] → new[c][23-r]
    # New grid: 14-wide × 24-tall

    # Forward: K3_CT → write 24-wide → rotate CW → read → intermediate
    ct = K3_CT
    n = len(ct)  # 336

    # Write into 24×14 (24 cols, 14 rows)
    w1, h1 = 24, 14
    grid1 = [[' '] * w1 for _ in range(h1)]
    for i, ch in enumerate(ct):
        r, c = divmod(i, w1)
        grid1[r][c] = ch

    # CW rotate: grid1[r][c] → new grid at [c][h1-1-r]
    # New grid: w1 rows × h1 cols (24 rows × 14 cols)
    grid1r = [[' '] * h1 for _ in range(w1)]
    for r in range(h1):
        for c in range(w1):
            grid1r[c][h1 - 1 - r] = grid1[r][c]

    # Read row-by-row → intermediate
    intermediate = ""
    for r in range(w1):
        for c in range(h1):
            intermediate += grid1r[r][c]

    return intermediate

def model_d_intermediate():
    """Use K3 intermediate text as running key for K4."""
    results = []
    inter = k3_intermediate()

    for alpha_name, (alpha_str, alpha_idx) in ALPHABETS.items():
        for var_name, var_fn in VARIANTS.items():
            for offset in range(min(len(inter) - CT_LEN + 1, 250)):
                key_map = {}
                for k4_pos in range(CT_LEN):
                    key_idx = offset + k4_pos
                    if key_idx < len(inter):
                        key_map[k4_pos] = inter[key_idx]

                pt = full_decrypt(key_map, var_fn, alpha_idx, alpha_str)
                pt_at_cribs = {p: pt[p] for p in CRIB_POS_SORTED if p in pt}
                hits = score_at_cribs(pt_at_cribs)

                if hits >= 3 or offset < 3:
                    label = f"D:inter_off{offset}_{var_name}_{alpha_name}"
                    results.append({"model": "D", "label": label, "score": hits,
                                    "params": {"offset": offset, "variant": var_name,
                                               "alphabet": alpha_name}})

    return results

# ── Model E: K3 permutation on combined 434-block ──────────────────────────

def k3_permutation():
    """Compute K3's full 336-position transposition permutation.

    K3: write into 24×14, CW rotate, read → write into 8×42, CW rotate, read.
    Combined permutation: output[i] = input[perm[i]] (gather convention).
    """
    n = 336

    # First rotation: write 24×14, rotate CW
    # Position mapping: input pos i → (r=i//24, c=i%24) → after CW rotate: (c, 13-r)
    # Read from new grid (24 rows × 14 cols): new pos = c * 14 + (13 - r)
    # So intermediate_pos = (i%24)*14 + 13 - (i//24)

    # Second rotation: write 8×42, rotate CW
    # intermediate pos j → (r=j//8, c=j%8) → after CW rotate: (c, 41-r)
    # Read from new grid (8 rows × 42 cols): new pos = c * 42 + (41 - r)
    # So output_pos = (j%8)*42 + 41 - (j//8)

    perm = [0] * n  # perm[output] = input
    for i in range(n):
        # First rotation
        j = (i % 24) * 14 + 13 - (i // 24)
        # Second rotation
        out = (j % 8) * 42 + 41 - (j // 8)
        perm[out] = i

    return perm

def model_e_permutation():
    """Apply K3's permutation to the combined 434-char block, check K4 region."""
    results = []
    perm336 = k3_permutation()

    # Verify the K3 permutation works
    k3_decrypted = "".join(K3_CT[perm336[i]] for i in range(336))
    k3_check = k3_decrypted == K3_PT

    combined_ct = K3_CT + "?" + K4_CT  # 434 chars
    combined_pt_known = K3_PT + "?" + "?" * 97  # K3 PT known, K4 unknown

    # Extend K3 perm to 434: identity for positions 336+
    # Option 1: perm336 for first 336, identity for rest
    perm434_identity = list(range(434))
    for i in range(336):
        perm434_identity[i] = perm336[i]

    # Apply to combined CT
    result1 = "".join(combined_ct[perm434_identity[i]] for i in range(434))
    k4_region1 = result1[337:]

    # Option 2: perm336 cyclically extended
    perm434_cyclic = []
    for i in range(434):
        perm434_cyclic.append(perm336[i % 336])
    result2 = "".join(combined_ct[perm434_cyclic[i]] for i in range(434))
    k4_region2 = result2[337:]

    # Option 3: K3 inverse perm applied to K4 region (positions 337-433 mapped mod 336)
    inv_perm = [0] * 336
    for i, p in enumerate(perm336):
        inv_perm[p] = i

    k4_permuted = ""
    for k4_pos in range(97):
        src = inv_perm[(K4_START + k4_pos) % 336]
        k4_permuted += combined_ct[src]

    # Score each against K4 cribs under Vig/Beau
    for alpha_name, (alpha_str, alpha_idx) in ALPHABETS.items():
        for var_name, var_fn in VARIANTS.items():
            for perm_name, k4_text in [
                ("identity_ext", k4_region1),
                ("cyclic_ext", k4_region2),
                ("inv_mod336", k4_permuted),
            ]:
                # Try as: the permuted text IS the plaintext
                pt_direct = {i: k4_text[i] for i in range(min(97, len(k4_text)))}
                hits_direct = score_at_cribs(pt_direct)

                # Try as: permuted text is intermediate, then decrypt
                key_map = {i: k4_text[i] for i in range(min(97, len(k4_text)))}
                # Use K4_CT against permuted text
                pt = {}
                for k4_pos in range(min(97, len(k4_text))):
                    ct_n = alpha_idx[K4_CT[k4_pos]]
                    key_n = alpha_idx[k4_text[k4_pos]]
                    pt[k4_pos] = alpha_str[var_fn(ct_n, key_n)]
                hits_keyed = score_at_cribs(pt)

                label = f"E:{perm_name}_{var_name}_{alpha_name}"
                results.append({"model": "E", "label": label,
                                "score_direct": hits_direct, "score_keyed": hits_keyed,
                                "score": max(hits_direct, hits_keyed),
                                "k3_perm_valid": k3_check,
                                "params": {"perm": perm_name, "variant": var_name,
                                           "alphabet": alpha_name}})

    return results

# ── Model F: K3 PT at crib-length offsets ──────────────────────────────────

def model_f_offset_key():
    """K3 PT/CT used as running key with structured offsets (crib lengths, grid dims)."""
    results = []

    special_offsets = [
        0, 7, 13, 14, 11, 24, 31, 42, 97, 168, 239, 336 - 97,
        # From K3 grid dims
        24 * 14 - 97,  # 239
        8 * 42 - 97,   # 239 (same!)
        # From K4 position on panel
        310,  # K3 chars before K4 starts on row 10
    ]

    for source_name, source_text in [("K3_PT", K3_PT), ("K3_CT", K3_CT)]:
        for alpha_name, (alpha_str, alpha_idx) in ALPHABETS.items():
            for var_name, var_fn in VARIANTS.items():
                for offset in special_offsets:
                    if offset + CT_LEN > len(source_text):
                        continue
                    key_map = {}
                    for k4_pos in range(CT_LEN):
                        key_map[k4_pos] = source_text[offset + k4_pos]

                    pt = full_decrypt(key_map, var_fn, alpha_idx, alpha_str)
                    pt_at_cribs = {p: pt[p] for p in CRIB_POS_SORTED if p in pt}
                    hits = score_at_cribs(pt_at_cribs)

                    label = f"F:{source_name}_off{offset}_{var_name}_{alpha_name}"
                    results.append({"model": "F", "label": label, "score": hits,
                                    "params": {"source": source_name, "offset": offset,
                                               "variant": var_name, "alphabet": alpha_name}})

    return results

# ── Model G: Row-pair Polybius coordinate keying ───────────────────────────

def model_g_row_pair():
    """Use pairs of K3 rows at same column as Polybius-like (row, col) coordinates.

    If the two K3 rows give letters with KA indices (r, c) on the 5-wide grid,
    combine as key = r*5 + c mod 26 (or similar).
    """
    results = []

    for alpha_name, (alpha_str, alpha_idx) in ALPHABETS.items():
        for var_name, var_fn in VARIANTS.items():
            for row_a in range(10):
                for row_b in range(row_a + 1, 11):
                    key_map = {}
                    for k4_pos in range(CT_LEN):
                        combined_pos = K4_START + k4_pos
                        col = combined_pos % GRID_COLS

                        pos_a = row_a * GRID_COLS + col
                        pos_b = row_b * GRID_COLS + col

                        if pos_a < K3_LEN and pos_b < K3_LEN:
                            val_a = alpha_idx[K3_PT[pos_a]]
                            val_b = alpha_idx[K3_PT[pos_b]]
                            # Combine: (a + b) mod 26
                            combined_val = (val_a + val_b) % MOD
                            key_map[k4_pos] = alpha_str[combined_val]

                    pt = full_decrypt(key_map, var_fn, alpha_idx, alpha_str)
                    pt_at_cribs = {p: pt[p] for p in CRIB_POS_SORTED if p in pt}
                    hits = score_at_cribs(pt_at_cribs)

                    if hits >= 4:
                        label = f"G:rows{row_a}+{row_b}_{var_name}_{alpha_name}"
                        results.append({"model": "G", "label": label, "score": hits,
                                        "params": {"row_a": row_a, "row_b": row_b,
                                                   "variant": var_name, "alphabet": alpha_name}})

    # Report best from G even if < 4
    return results

# ── Model H: K3 PT diagonal reading as key ─────────────────────────────────

def model_h_diagonal():
    """Read K3 PT along diagonals of the 14×31 grid as running key."""
    results = []

    # Main diagonal: (0,0), (1,1), ..., wrapping
    for start_col in range(GRID_COLS):
        diag_text = ""
        for step in range(K3_LEN):
            r = step % 11  # K3 rows 0-10
            c = (start_col + step) % GRID_COLS
            pos = r * GRID_COLS + c
            if pos < K3_LEN:
                diag_text += K3_PT[pos]

        if len(diag_text) < CT_LEN:
            continue

        for alpha_name, (alpha_str, alpha_idx) in ALPHABETS.items():
            for var_name, var_fn in VARIANTS.items():
                key_map = {i: diag_text[i] for i in range(CT_LEN)}
                pt = full_decrypt(key_map, var_fn, alpha_idx, alpha_str)
                pt_at_cribs = {p: pt[p] for p in CRIB_POS_SORTED if p in pt}
                hits = score_at_cribs(pt_at_cribs)

                if hits >= 3:
                    label = f"H:diag_start{start_col}_{var_name}_{alpha_name}"
                    results.append({"model": "H", "label": label, "score": hits,
                                    "params": {"start_col": start_col,
                                               "variant": var_name, "alphabet": alpha_name}})

    return results

# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════

def main():
    t0 = time.time()
    all_results = []
    model_bests = {}

    print("=" * 70)
    print("E-K3K4-GRID: K3-K4 Grid Combination Tests")
    print("=" * 70)

    # Verify K3 permutation
    perm = k3_permutation()
    k3_dec = "".join(K3_CT[perm[i]] for i in range(336))
    print(f"\nK3 perm verification: {'PASS' if k3_dec == K3_PT else 'FAIL'}")
    inter = k3_intermediate()
    print(f"K3 intermediate (first 40): {inter[:40]}")
    print()

    for model_name, model_fn in [
        ("A: Column-aligned keying", model_a_column_aligned),
        ("B: Multi-row key", model_b_multirow),
        ("C: K3 column-read running key", model_c_column_read),
        ("D: K3 intermediate running key", model_d_intermediate),
        ("E: K3 permutation on combined block", model_e_permutation),
        ("F: K3 offset running key", model_f_offset_key),
        ("G: Row-pair Polybius coordinate key", model_g_row_pair),
        ("H: Diagonal reading key", model_h_diagonal),
    ]:
        print(f"\n--- {model_name} ---")
        results = model_fn()
        all_results.extend(results)

        if results:
            best = max(results, key=lambda x: x["score"])
            model_bests[model_name] = best
            print(f"  Configs tested: {len(results)}")
            print(f"  Best score: {best['score']}/24 — {best['label']}")
            if best["score"] >= 4:
                print(f"  Params: {best['params']}")
        else:
            print("  No results (all below threshold)")

    elapsed = time.time() - t0

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    overall_best = max(all_results, key=lambda x: x["score"]) if all_results else None

    for model_name, best in sorted(model_bests.items(), key=lambda x: -x[1]["score"]):
        marker = " <<<" if best["score"] >= 6 else ""
        print(f"  {model_name}: {best['score']}/24 — {best['label']}{marker}")

    print(f"\n  Overall best: {overall_best['score']}/24 — {overall_best['label']}" if overall_best else "  No results")
    print(f"  Total configs: {len(all_results)}")
    print(f"  Elapsed: {elapsed:.1f}s")

    # Verdict
    if overall_best and overall_best["score"] >= 10:
        verdict = "INTERESTING"
    elif overall_best and overall_best["score"] >= 6:
        verdict = "MARGINAL"
    else:
        verdict = "NOISE"

    print(f"\n  VERDICT: {verdict}")

    # Save
    output = {
        "experiment": "E-K3K4-GRID",
        "description": "K3-K4 grid combination: column-aligned keying, multi-row, "
                       "column-read, intermediate, permutation, offset, row-pair, diagonal",
        "verdict": verdict,
        "best_score": overall_best["score"] if overall_best else 0,
        "total_configs": len(all_results),
        "elapsed_seconds": round(elapsed, 1),
        "timestamp": time.strftime("%Y-%m-%d %H:%M"),
        "model_bests": {k: v for k, v in model_bests.items()},
        "top_results": sorted(all_results, key=lambda x: -x["score"])[:20],
    }

    with open(RESULTS_PATH, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n  Results saved to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
