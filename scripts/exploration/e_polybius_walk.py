#!/usr/bin/env python3
"""
Cipher: Polybius grid walk analysis
Family: exploration
Status: active
Keyspace: analytical + linear/step/CT-dep/KRYPTOS-seeded walks
Last run:
Best score:
"""
"""
E-POLYBIUS-WALK: Keystream Grid Walk Analysis

The Beaufort keystream JLJODEGKUKKKLOCGGBGOKTRU shows significant row
clustering when mapped to the 5-wide KA Polybius grid (p=0.0057).
10 out of 23 consecutive pairs share the same row -- 2.3x random expectation.

This script characterizes the row/column transition structure and tests
whether any deterministic grid walk can reproduce the keystream at crib positions.

Part A: Characterize row/column structure and transitions
Part B: Test grid-walk key generation models
Part C: Row-transition Markov analysis + comparison across cipher variants
"""

import sys
import os
import json
import math
import time
import itertools
from pathlib import Path
from collections import Counter, defaultdict

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC, CRIB_POSITIONS,
)

# ---------------------------------------------------------------------------
# Grid definition: KA alphabet in 5-wide Polybius grid
# ---------------------------------------------------------------------------

KA = KRYPTOS_ALPHABET  # KRYPTOSABCDEFGHIJLMNQUVWXZ
GRID_WIDTH = 5
GRID_ROWS = 6  # 26 letters, 5 per row, last row has 1

# Map each letter to (row, col) in the grid
LETTER_TO_RC = {}
RC_TO_LETTER = {}
for idx, ch in enumerate(KA):
    r, c = divmod(idx, GRID_WIDTH)
    LETTER_TO_RC[ch] = (r, c)
    RC_TO_LETTER[(r, c)] = ch

# Also map by standard alphabet index for cipher operations
KA_IDX = {ch: i for i, ch in enumerate(KA)}

# ---------------------------------------------------------------------------
# Beaufort keystream at crib positions (the 24 known values)
# ---------------------------------------------------------------------------

# Build the full keystream letter sequence at crib positions
CRIB_POS_SORTED = sorted(CRIB_DICT.keys())
BEAUFORT_KEY_LETTERS = []
bk_ene = list(BEAUFORT_KEY_ENE)  # positions 21-33
bk_bc = list(BEAUFORT_KEY_BC)    # positions 63-73

for pos in CRIB_POS_SORTED:
    if 21 <= pos <= 33:
        val = bk_ene[pos - 21]
    elif 63 <= pos <= 73:
        val = bk_bc[pos - 63]
    else:
        raise ValueError(f"Unexpected crib position {pos}")
    BEAUFORT_KEY_LETTERS.append(ALPH[val])

BEAUFORT_KS_STR = "".join(BEAUFORT_KEY_LETTERS)
# Expected: JLJODEGKUKKKLOCGGBGOKTRU

# Similarly for Vigenere
VIGENERE_KEY_LETTERS = []
vk_ene = list(VIGENERE_KEY_ENE)
vk_bc = list(VIGENERE_KEY_BC)
for pos in CRIB_POS_SORTED:
    if 21 <= pos <= 33:
        val = vk_ene[pos - 21]
    elif 63 <= pos <= 73:
        val = vk_bc[pos - 63]
    else:
        raise ValueError(f"Unexpected crib position {pos}")
    VIGENERE_KEY_LETTERS.append(ALPH[val])

VIGENERE_KS_STR = "".join(VIGENERE_KEY_LETTERS)


def map_to_grid(text):
    """Map a string to list of (row, col) in KA Polybius grid."""
    return [LETTER_TO_RC[ch] for ch in text]


# =========================================================================
# PART A: Characterize the row/column structure
# =========================================================================

def part_a_characterize():
    """Full statistical characterization of keystream grid coordinates."""
    results = {}

    ks = BEAUFORT_KS_STR
    coords = map_to_grid(ks)
    rows = [r for r, c in coords]
    cols = [c for r, c in coords]

    results["keystream"] = ks
    results["coords"] = [(r, c) for r, c in coords]
    results["rows"] = rows
    results["cols"] = cols

    # --- Row statistics ---
    row_counts = Counter(rows)
    results["row_frequency"] = dict(sorted(row_counts.items()))

    # Row transitions (consecutive pairs in the keystream)
    row_transitions = []
    same_row_count = 0
    adj_row_count = 0
    for i in range(len(rows) - 1):
        r1, r2 = rows[i], rows[i + 1]
        row_transitions.append((r1, r2))
        if r1 == r2:
            same_row_count += 1
        if abs(r1 - r2) <= 1:
            adj_row_count += 1

    results["row_transitions"] = row_transitions
    results["same_row_pairs"] = same_row_count
    results["adj_row_pairs"] = adj_row_count  # includes same row
    results["total_consecutive_pairs"] = len(row_transitions)

    # Expected same-row under random: sum of (count_r/24 * count_r/24) for each row
    # For 24 draws from 6 rows (unequal probs based on row size: 5,5,5,5,5,1)
    # Under uniform random letter: P(same row) = sum(5/26)^2 * 5 + (1/26)^2 = 5*25/676 + 1/676 = 126/676 = 0.1864
    p_same_row_uniform = 5 * (5/26)**2 + (1/26)**2
    expected_same_row = p_same_row_uniform * len(row_transitions)
    results["p_same_row_uniform"] = round(p_same_row_uniform, 6)
    results["expected_same_row_pairs"] = round(expected_same_row, 2)
    results["same_row_ratio"] = round(same_row_count / expected_same_row if expected_same_row > 0 else 0, 3)

    # --- Column statistics ---
    col_counts = Counter(cols)
    results["col_frequency"] = dict(sorted(col_counts.items()))

    col_transitions = []
    same_col_count = 0
    adj_col_count = 0
    for i in range(len(cols) - 1):
        c1, c2 = cols[i], cols[i + 1]
        col_transitions.append((c1, c2))
        if c1 == c2:
            same_col_count += 1
        if abs(c1 - c2) <= 1 or abs(c1 - c2) == GRID_WIDTH - 1:  # wrap-adjacent
            adj_col_count += 1

    results["col_transitions"] = col_transitions
    results["same_col_pairs"] = same_col_count
    results["adj_col_pairs_wrap"] = adj_col_count

    p_same_col_uniform = 5 * (5/26)**2 + 1 * (1/26)**2  # col 0 has 6 letters, cols 1-4 have 5 each
    # Actually: col distribution: col 0 has K,O,D,I,Q,Z=6; cols 1-4 have 5 each
    col_letter_counts = defaultdict(int)
    for ch in KA:
        _, c = LETTER_TO_RC[ch]
        col_letter_counts[c] += 1
    p_same_col_actual = sum((cnt/26)**2 for cnt in col_letter_counts.values())
    results["p_same_col_uniform"] = round(p_same_col_actual, 6)
    results["expected_same_col_pairs"] = round(p_same_col_actual * len(col_transitions), 2)

    # --- Row difference sequence ---
    row_diffs = [rows[i+1] - rows[i] for i in range(len(rows)-1)]
    col_diffs = [cols[i+1] - cols[i] for i in range(len(cols)-1)]
    results["row_diff_sequence"] = row_diffs
    results["col_diff_sequence"] = col_diffs
    results["row_diff_counts"] = dict(sorted(Counter(row_diffs).items()))
    results["col_diff_counts"] = dict(sorted(Counter(col_diffs).items()))

    # --- Run-length encoding of rows ---
    runs = []
    current_row = rows[0]
    run_len = 1
    for i in range(1, len(rows)):
        if rows[i] == current_row:
            run_len += 1
        else:
            runs.append((current_row, run_len))
            current_row = rows[i]
            run_len = 1
    runs.append((current_row, run_len))
    results["row_runs"] = runs
    results["max_run_length"] = max(rl for _, rl in runs)
    results["mean_run_length"] = round(sum(rl for _, rl in runs) / len(runs), 3)

    # --- Manhattan distance between consecutive keystream letters ---
    manhattan_dists = []
    for i in range(len(coords) - 1):
        r1, c1 = coords[i]
        r2, c2 = coords[i + 1]
        d = abs(r2 - r1) + abs(c2 - c1)
        manhattan_dists.append(d)
    results["manhattan_distances"] = manhattan_dists
    results["mean_manhattan"] = round(sum(manhattan_dists) / len(manhattan_dists), 3)

    # Expected Manhattan distance under uniform random
    # E[|r1-r2|] + E[|c1-c2|] where r,c drawn from the grid distribution
    # We'll compute empirically
    all_pairs_row_diff = []
    all_pairs_col_diff = []
    for ch1 in KA:
        for ch2 in KA:
            r1, c1 = LETTER_TO_RC[ch1]
            r2, c2 = LETTER_TO_RC[ch2]
            all_pairs_row_diff.append(abs(r2 - r1))
            all_pairs_col_diff.append(abs(c2 - c1))
    expected_manhattan = (sum(all_pairs_row_diff) + sum(all_pairs_col_diff)) / (26 * 26)
    results["expected_manhattan_uniform"] = round(expected_manhattan, 3)

    # --- Diagonal patterns? ---
    # Check if row_diff == col_diff (diagonal movement)
    diagonal_count = sum(1 for rd, cd in zip(row_diffs, col_diffs) if rd == cd and rd != 0)
    anti_diagonal_count = sum(1 for rd, cd in zip(row_diffs, col_diffs) if rd == -cd and rd != 0)
    results["diagonal_moves"] = diagonal_count
    results["anti_diagonal_moves"] = anti_diagonal_count

    # --- Named path checks ---
    # Generate some simple named paths through the grid and compare
    simple_paths = {}

    # Row-by-row L->R
    simple_paths["row_LR"] = list(KA)

    # Row-by-row R->L alternating (boustrophedon)
    bous = []
    for r in range(GRID_ROWS):
        row_letters = [KA[r * GRID_WIDTH + c] for c in range(GRID_WIDTH) if r * GRID_WIDTH + c < 26]
        if r % 2 == 0:
            bous.extend(row_letters)
        else:
            bous.extend(reversed(row_letters))
    simple_paths["boustrophedon"] = bous

    # Column-by-column top->bottom
    col_path = []
    for c in range(GRID_WIDTH):
        for r in range(GRID_ROWS):
            idx = r * GRID_WIDTH + c
            if idx < 26:
                col_path.append(KA[idx])
    simple_paths["col_TB"] = col_path

    # Spiral outward from center
    # (skip for now, complex to implement for 6x5)

    # Diagonal sweep
    diag_path = []
    for s in range(GRID_ROWS + GRID_WIDTH - 1):
        for r in range(GRID_ROWS):
            c = s - r
            if 0 <= c < GRID_WIDTH:
                idx = r * GRID_WIDTH + c
                if idx < 26:
                    diag_path.append(KA[idx])
    simple_paths["diagonal"] = diag_path

    # For each named path, compute how many consecutive keystream letters
    # appear in the same cycled position as the path
    path_match_results = {}
    for name, path in simple_paths.items():
        # Cycle the path to length 97, then check at crib positions
        cycled = [path[i % len(path)] for i in range(97)]
        matches = sum(1 for pos in CRIB_POS_SORTED if cycled[pos] == BEAUFORT_KEY_LETTERS[CRIB_POS_SORTED.index(pos)])
        path_match_results[name] = matches
    results["named_path_crib_matches"] = path_match_results

    return results


# =========================================================================
# PART B: Test grid-walk key generation
# =========================================================================

def _beaufort_decrypt_char(ct_char, key_char):
    """Beaufort decrypt: PT = (KEY - CT) mod 26, using standard A=0."""
    return ALPH[(ALPH_IDX[key_char] - ALPH_IDX[ct_char]) % MOD]


def _crib_match_count(key_sequence_97):
    """Count how many crib positions match if we use key_sequence_97 as Beaufort key."""
    matches = 0
    for pos, expected_pt in CRIB_DICT.items():
        pt = _beaufort_decrypt_char(CT[pos], key_sequence_97[pos])
        if pt == expected_pt:
            matches += 1
    return matches


def part_b_grid_walks():
    """Test deterministic grid walks as key generators."""
    results = {}
    best_overall = {"method": None, "matches": 0}

    # --- B1: Linear walks ---
    linear_results = []

    # All starting positions, 4 directions: R, D, diagonal-DR, diagonal-DL
    # plus wrapping variants
    walk_specs = []

    # Row-major walks with different starting cells
    for start_r in range(GRID_ROWS):
        for start_c in range(GRID_WIDTH):
            if start_r * GRID_WIDTH + start_c >= 26:
                continue
            # Walk right, wrap to next row
            path = []
            idx = start_r * GRID_WIDTH + start_c
            for _ in range(97):
                if idx >= 26:
                    idx = idx % 26
                path.append(KA[idx])
                idx = (idx + 1) % 26
            walk_specs.append((f"row_major_start({start_r},{start_c})", path))

            # Walk down columns
            path = []
            r, c = start_r, start_c
            for _ in range(97):
                ka_idx = r * GRID_WIDTH + c
                if ka_idx >= 26:
                    ka_idx = ka_idx % 26
                path.append(KA[ka_idx])
                r = (r + 1) % GRID_ROWS
                if r * GRID_WIDTH + c >= 26:
                    r = 0
                    c = (c + 1) % GRID_WIDTH
            walk_specs.append((f"col_major_start({start_r},{start_c})", path))

    # Boustrophedon from each starting position
    for start_idx in range(26):
        bous_order = []
        for r in range(GRID_ROWS):
            row_letters = [KA[r * GRID_WIDTH + c] for c in range(GRID_WIDTH) if r * GRID_WIDTH + c < 26]
            if r % 2 == 0:
                bous_order.extend(row_letters)
            else:
                bous_order.extend(reversed(row_letters))
        # Rotate to start at start_idx
        rotated = bous_order[start_idx:] + bous_order[:start_idx]
        path = [rotated[i % len(rotated)] for i in range(97)]
        walk_specs.append((f"boustrophedon_offset({start_idx})", path))

    # Diagonal walks
    for start_r in range(GRID_ROWS):
        for start_c in range(GRID_WIDTH):
            if start_r * GRID_WIDTH + start_c >= 26:
                continue
            for dr, dc, name in [(1, 1, "DR"), (1, -1, "DL"), (-1, 1, "UR"), (-1, -1, "UL")]:
                path = []
                r, c = start_r, start_c
                for _ in range(97):
                    ka_idx = r * GRID_WIDTH + c
                    if ka_idx < 26:
                        path.append(KA[ka_idx])
                    else:
                        path.append(KA[0])  # fallback
                    r = (r + dr) % GRID_ROWS
                    c = (c + dc) % GRID_WIDTH
                    # Ensure valid cell
                    while r * GRID_WIDTH + c >= 26:
                        r = (r + dr) % GRID_ROWS
                        c = (c + dc) % GRID_WIDTH
                walk_specs.append((f"diag_{name}_start({start_r},{start_c})", path))

    for name, path in walk_specs:
        matches = _crib_match_count(path)
        if matches >= 3:
            linear_results.append({"method": name, "matches": matches})
        if matches > best_overall["matches"]:
            best_overall = {"method": f"linear:{name}", "matches": matches}

    linear_results.sort(key=lambda x: -x["matches"])
    results["linear_walks"] = {
        "total_tested": len(walk_specs),
        "top_results": linear_results[:20],
        "best_matches": linear_results[0]["matches"] if linear_results else 0,
    }

    # --- B2: Step-based walks ---
    step_results = []
    step_count = 0

    # All starting cells x all step vectors (dr, dc) including knight moves
    step_vectors = []
    for dr in range(-5, 6):
        for dc in range(-4, 5):
            if dr == 0 and dc == 0:
                continue
            step_vectors.append((dr, dc))

    for start_r in range(GRID_ROWS):
        for start_c in range(GRID_WIDTH):
            if start_r * GRID_WIDTH + start_c >= 26:
                continue
            for dr, dc in step_vectors:
                path = []
                r, c = start_r, start_c
                for _ in range(97):
                    ka_idx = r * GRID_WIDTH + c
                    if 0 <= ka_idx < 26:
                        path.append(KA[ka_idx])
                    else:
                        path.append(KA[0])
                    r = (r + dr) % GRID_ROWS
                    c = (c + dc) % GRID_WIDTH
                    # Wrap to valid cell
                    attempts = 0
                    while r * GRID_WIDTH + c >= 26 and attempts < 30:
                        r = (r + dr) % GRID_ROWS
                        c = (c + dc) % GRID_WIDTH
                        attempts += 1
                    if attempts >= 30:
                        r, c = 0, 0

                matches = _crib_match_count(path)
                step_count += 1
                if matches >= 3:
                    step_results.append({
                        "start": (start_r, start_c),
                        "step": (dr, dc),
                        "matches": matches,
                    })
                if matches > best_overall["matches"]:
                    best_overall = {"method": f"step:start({start_r},{start_c})_step({dr},{dc})", "matches": matches}

    step_results.sort(key=lambda x: -x["matches"])
    results["step_walks"] = {
        "total_tested": step_count,
        "top_results": step_results[:20],
        "best_matches": step_results[0]["matches"] if step_results else 0,
    }

    # --- B3: CT-dependent walks ---
    ct_dep_results = []
    ct_dep_count = 0

    # For each CT char, its grid position determines the step to the next key
    # Model: key[0] = grid[start_r][start_c], then step determined by CT[i]
    ct_coords = map_to_grid(CT)

    for start_r in range(GRID_ROWS):
        for start_c in range(GRID_WIDTH):
            if start_r * GRID_WIDTH + start_c >= 26:
                continue

            # Model 1: row of CT[i] = row offset, col of CT[i] = col offset
            path = []
            r, c = start_r, start_c
            for i in range(97):
                ka_idx = r * GRID_WIDTH + c
                if 0 <= ka_idx < 26:
                    path.append(KA[ka_idx])
                else:
                    path.append(KA[0])
                ct_r, ct_c = ct_coords[i]
                r = (r + ct_r) % GRID_ROWS
                c = (c + ct_c) % GRID_WIDTH
                while r * GRID_WIDTH + c >= 26:
                    c = (c + 1) % GRID_WIDTH
            matches = _crib_match_count(path)
            ct_dep_count += 1
            if matches >= 3:
                ct_dep_results.append({
                    "start": (start_r, start_c),
                    "model": "CT_rc_offset",
                    "matches": matches,
                })
            if matches > best_overall["matches"]:
                best_overall = {"method": f"ct_dep:CT_rc_offset_start({start_r},{start_c})", "matches": matches}

            # Model 2: CT letter's KA index determines step in KA sequence
            path = []
            ka_pos = start_r * GRID_WIDTH + start_c
            for i in range(97):
                path.append(KA[ka_pos % 26])
                ct_ka_idx = KA_IDX[CT[i]]
                ka_pos = (ka_pos + ct_ka_idx) % 26
            matches = _crib_match_count(path)
            ct_dep_count += 1
            if matches >= 3:
                ct_dep_results.append({
                    "start": (start_r, start_c),
                    "model": "CT_ka_idx_step",
                    "matches": matches,
                })
            if matches > best_overall["matches"]:
                best_overall = {"method": f"ct_dep:CT_ka_idx_step_start({start_r},{start_c})", "matches": matches}

            # Model 3: CT row determines NEXT row, CT col determines NEXT col
            path = []
            r, c = start_r, start_c
            for i in range(97):
                ka_idx = r * GRID_WIDTH + c
                if 0 <= ka_idx < 26:
                    path.append(KA[ka_idx])
                else:
                    path.append(KA[0])
                ct_r, ct_c = ct_coords[i]
                r = ct_r  # jump to CT's row
                c = ct_c  # jump to CT's col
            matches = _crib_match_count(path)
            ct_dep_count += 1
            if matches >= 3:
                ct_dep_results.append({
                    "start": (start_r, start_c),
                    "model": "CT_rc_jump",
                    "matches": matches,
                })
            if matches > best_overall["matches"]:
                best_overall = {"method": f"ct_dep:CT_rc_jump_start({start_r},{start_c})", "matches": matches}

            # Model 4: row of CT[i] determines row step, col stays fixed
            path = []
            r, c = start_r, start_c
            for i in range(97):
                ka_idx = r * GRID_WIDTH + c
                if 0 <= ka_idx < 26:
                    path.append(KA[ka_idx])
                else:
                    path.append(KA[0])
                ct_r, _ = ct_coords[i]
                r = (r + ct_r) % GRID_ROWS
                while r * GRID_WIDTH + c >= 26:
                    r = (r + 1) % GRID_ROWS
            matches = _crib_match_count(path)
            ct_dep_count += 1
            if matches >= 3:
                ct_dep_results.append({
                    "start": (start_r, start_c),
                    "model": "CT_row_step_only",
                    "matches": matches,
                })
            if matches > best_overall["matches"]:
                best_overall = {"method": f"ct_dep:CT_row_step_only_start({start_r},{start_c})", "matches": matches}

            # Model 5: col of CT[i] determines col step, row stays fixed
            path = []
            r, c = start_r, start_c
            for i in range(97):
                ka_idx = r * GRID_WIDTH + c
                if 0 <= ka_idx < 26:
                    path.append(KA[ka_idx])
                else:
                    path.append(KA[0])
                _, ct_c = ct_coords[i]
                c = (c + ct_c) % GRID_WIDTH
            matches = _crib_match_count(path)
            ct_dep_count += 1
            if matches >= 3:
                ct_dep_results.append({
                    "start": (start_r, start_c),
                    "model": "CT_col_step_only",
                    "matches": matches,
                })
            if matches > best_overall["matches"]:
                best_overall = {"method": f"ct_dep:CT_col_step_only_start({start_r},{start_c})", "matches": matches}

            # Model 6: CT char's standard ALPH index mod 6 = row, mod 5 = col
            path = []
            for i in range(97):
                ct_std = ALPH_IDX[CT[i]]
                key_r = ct_std % GRID_ROWS
                key_c = ct_std % GRID_WIDTH
                ka_idx = key_r * GRID_WIDTH + key_c
                if ka_idx < 26:
                    path.append(KA[ka_idx])
                else:
                    path.append(KA[ka_idx % 26])
            matches = _crib_match_count(path)
            ct_dep_count += 1
            if matches >= 3:
                ct_dep_results.append({
                    "start": "N/A",
                    "model": "CT_mod6_mod5",
                    "matches": matches,
                })
            if matches > best_overall["matches"]:
                best_overall = {"method": "ct_dep:CT_mod6_mod5", "matches": matches}
            # Only need to test this once (no start dependency)
            break
        else:
            continue
        break

    # Model 7: Previous key char determines next position
    # key[i+1] = grid[key_row[i] + ct_row[i], key_col[i] + ct_col[i]]
    for start_r in range(GRID_ROWS):
        for start_c in range(GRID_WIDTH):
            if start_r * GRID_WIDTH + start_c >= 26:
                continue
            path = []
            r, c = start_r, start_c
            for i in range(97):
                ka_idx = r * GRID_WIDTH + c
                if 0 <= ka_idx < 26:
                    key_ch = KA[ka_idx]
                    path.append(key_ch)
                    key_r, key_c = r, c
                else:
                    path.append(KA[0])
                    key_r, key_c = 0, 0
                ct_r, ct_c = ct_coords[i]
                r = (key_r + ct_r) % GRID_ROWS
                c = (key_c + ct_c) % GRID_WIDTH
                while r * GRID_WIDTH + c >= 26:
                    c = (c + 1) % GRID_WIDTH
            matches = _crib_match_count(path)
            ct_dep_count += 1
            if matches >= 3:
                ct_dep_results.append({
                    "start": (start_r, start_c),
                    "model": "key_plus_ct_offset",
                    "matches": matches,
                })
            if matches > best_overall["matches"]:
                best_overall = {"method": f"ct_dep:key_plus_ct_offset_start({start_r},{start_c})", "matches": matches}

    ct_dep_results.sort(key=lambda x: -x["matches"])
    results["ct_dependent_walks"] = {
        "total_tested": ct_dep_count,
        "top_results": ct_dep_results[:20],
        "best_matches": ct_dep_results[0]["matches"] if ct_dep_results else 0,
    }

    # --- B4: KRYPTOS-seeded walks ---
    kryptos_results = []
    kryptos_count = 0
    kryptos_word = "KRYPTOS"
    kryptos_coords = map_to_grid(kryptos_word)

    # Model 1: KRYPTOS letters as repeating step pattern
    for start_r in range(GRID_ROWS):
        for start_c in range(GRID_WIDTH):
            if start_r * GRID_WIDTH + start_c >= 26:
                continue

            # Steps from KRYPTOS grid coordinates
            kryptos_steps_row = [LETTER_TO_RC[ch][0] for ch in kryptos_word]
            kryptos_steps_col = [LETTER_TO_RC[ch][1] for ch in kryptos_word]

            # Use KRYPTOS positions as step offsets
            path = []
            r, c = start_r, start_c
            for i in range(97):
                ka_idx = r * GRID_WIDTH + c
                if 0 <= ka_idx < 26:
                    path.append(KA[ka_idx])
                else:
                    path.append(KA[0])
                step_idx = i % len(kryptos_word)
                r = (r + kryptos_steps_row[step_idx]) % GRID_ROWS
                c = (c + kryptos_steps_col[step_idx]) % GRID_WIDTH
                while r * GRID_WIDTH + c >= 26:
                    c = (c + 1) % GRID_WIDTH

            matches = _crib_match_count(path)
            kryptos_count += 1
            if matches >= 3:
                kryptos_results.append({
                    "start": (start_r, start_c),
                    "model": "KRYPTOS_rc_steps",
                    "matches": matches,
                })
            if matches > best_overall["matches"]:
                best_overall = {"method": f"kryptos:KRYPTOS_rc_steps_start({start_r},{start_c})", "matches": matches}

            # Model 2: KRYPTOS KA indices as step sizes in flat KA
            path = []
            ka_pos = start_r * GRID_WIDTH + start_c
            for i in range(97):
                path.append(KA[ka_pos % 26])
                step = KA_IDX[kryptos_word[i % len(kryptos_word)]]
                ka_pos = (ka_pos + step) % 26

            matches = _crib_match_count(path)
            kryptos_count += 1
            if matches >= 3:
                kryptos_results.append({
                    "start": (start_r, start_c),
                    "model": "KRYPTOS_ka_idx_step",
                    "matches": matches,
                })
            if matches > best_overall["matches"]:
                best_overall = {"method": f"kryptos:KRYPTOS_ka_idx_step_start({start_r},{start_c})", "matches": matches}

            # Model 3: KRYPTOS row diffs as steps
            kryptos_row_diffs = [(kryptos_coords[(i+1) % len(kryptos_word)][0] - kryptos_coords[i][0]) % GRID_ROWS
                                 for i in range(len(kryptos_word))]
            kryptos_col_diffs = [(kryptos_coords[(i+1) % len(kryptos_word)][1] - kryptos_coords[i][1]) % GRID_WIDTH
                                 for i in range(len(kryptos_word))]

            path = []
            r, c = start_r, start_c
            for i in range(97):
                ka_idx = r * GRID_WIDTH + c
                if 0 <= ka_idx < 26:
                    path.append(KA[ka_idx])
                else:
                    path.append(KA[0])
                step_idx = i % len(kryptos_word)
                r = (r + kryptos_row_diffs[step_idx]) % GRID_ROWS
                c = (c + kryptos_col_diffs[step_idx]) % GRID_WIDTH
                while r * GRID_WIDTH + c >= 26:
                    c = (c + 1) % GRID_WIDTH

            matches = _crib_match_count(path)
            kryptos_count += 1
            if matches >= 3:
                kryptos_results.append({
                    "start": (start_r, start_c),
                    "model": "KRYPTOS_diff_steps",
                    "matches": matches,
                })
            if matches > best_overall["matches"]:
                best_overall = {"method": f"kryptos:KRYPTOS_diff_steps_start({start_r},{start_c})", "matches": matches}

    # Also test other keywords
    keywords = ["PALIMPSEST", "ABSCISSA", "DEFECTOR", "SHADOW", "MEDUSA",
                "SANBORN", "ROSETTA", "BERLIN", "KOMPASS", "ENIGMA",
                "COLOPHON", "EAST", "CLOCK", "SEVEN"]

    for kw in keywords:
        kw_coords = map_to_grid(kw)
        kw_steps_r = [LETTER_TO_RC[ch][0] for ch in kw]
        kw_steps_c = [LETTER_TO_RC[ch][1] for ch in kw]

        for start_r in range(GRID_ROWS):
            for start_c in range(GRID_WIDTH):
                if start_r * GRID_WIDTH + start_c >= 26:
                    continue

                path = []
                r, c = start_r, start_c
                for i in range(97):
                    ka_idx = r * GRID_WIDTH + c
                    if 0 <= ka_idx < 26:
                        path.append(KA[ka_idx])
                    else:
                        path.append(KA[0])
                    step_idx = i % len(kw)
                    r = (r + kw_steps_r[step_idx]) % GRID_ROWS
                    c = (c + kw_steps_c[step_idx]) % GRID_WIDTH
                    while r * GRID_WIDTH + c >= 26:
                        c = (c + 1) % GRID_WIDTH

                matches = _crib_match_count(path)
                kryptos_count += 1
                if matches >= 3:
                    kryptos_results.append({
                        "start": (start_r, start_c),
                        "model": f"{kw}_rc_steps",
                        "matches": matches,
                    })
                if matches > best_overall["matches"]:
                    best_overall = {"method": f"kw:{kw}_rc_steps_start({start_r},{start_c})", "matches": matches}

    kryptos_results.sort(key=lambda x: -x["matches"])
    results["kryptos_seeded_walks"] = {
        "total_tested": kryptos_count,
        "top_results": kryptos_results[:20],
        "best_matches": kryptos_results[0]["matches"] if kryptos_results else 0,
    }

    results["best_overall"] = best_overall
    return results


# =========================================================================
# PART C: Row-transition Markov analysis
# =========================================================================

def part_c_markov_analysis():
    """Markov chain analysis of row transitions + cipher variant comparison."""
    results = {}

    # --- C1: Transition matrix for Beaufort keystream ---
    beau_coords = map_to_grid(BEAUFORT_KS_STR)
    beau_rows = [r for r, c in beau_coords]

    # Build transition count matrix (6x6 for 6 rows)
    trans_matrix = [[0] * GRID_ROWS for _ in range(GRID_ROWS)]
    for i in range(len(beau_rows) - 1):
        trans_matrix[beau_rows[i]][beau_rows[i + 1]] += 1

    # Normalize to probabilities
    trans_prob = []
    for r in range(GRID_ROWS):
        row_sum = sum(trans_matrix[r])
        if row_sum > 0:
            trans_prob.append([round(trans_matrix[r][c] / row_sum, 3) for c in range(GRID_ROWS)])
        else:
            trans_prob.append([0.0] * GRID_ROWS)

    results["beaufort_transition_counts"] = trans_matrix
    results["beaufort_transition_probs"] = trans_prob

    # --- C2: Key transition statistics ---
    row_transitions_str = " -> ".join(str(r) for r in beau_rows)
    results["beaufort_row_sequence"] = beau_rows

    # Self-transition rate (diagonal of transition matrix)
    total_trans = len(beau_rows) - 1
    self_trans = sum(trans_matrix[r][r] for r in range(GRID_ROWS))
    results["beaufort_self_transition_rate"] = round(self_trans / total_trans, 4)

    # Adjacent transition rate (|r1-r2| <= 1)
    adj_trans = sum(trans_matrix[r1][r2]
                    for r1 in range(GRID_ROWS)
                    for r2 in range(GRID_ROWS)
                    if abs(r1 - r2) <= 1)
    results["beaufort_adjacent_transition_rate"] = round(adj_trans / total_trans, 4)

    # --- C3: Column transition analysis ---
    beau_cols = [c for r, c in beau_coords]
    col_trans_matrix = [[0] * GRID_WIDTH for _ in range(GRID_WIDTH)]
    for i in range(len(beau_cols) - 1):
        col_trans_matrix[beau_cols[i]][beau_cols[i + 1]] += 1

    col_trans_prob = []
    for r in range(GRID_WIDTH):
        row_sum = sum(col_trans_matrix[r])
        if row_sum > 0:
            col_trans_prob.append([round(col_trans_matrix[r][c] / row_sum, 3) for c in range(GRID_WIDTH)])
        else:
            col_trans_prob.append([0.0] * GRID_WIDTH)

    results["beaufort_col_transition_counts"] = col_trans_matrix
    results["beaufort_col_transition_probs"] = col_trans_prob

    col_self_trans = sum(col_trans_matrix[c][c] for c in range(GRID_WIDTH))
    results["beaufort_col_self_transition_rate"] = round(col_self_trans / total_trans, 4)

    # --- C4: Compare with Vigenere keystream ---
    vig_coords = map_to_grid(VIGENERE_KS_STR)
    vig_rows = [r for r, c in vig_coords]

    vig_trans = [[0] * GRID_ROWS for _ in range(GRID_ROWS)]
    for i in range(len(vig_rows) - 1):
        vig_trans[vig_rows[i]][vig_rows[i + 1]] += 1

    vig_self_trans = sum(vig_trans[r][r] for r in range(GRID_ROWS))
    results["vigenere_self_transition_rate"] = round(vig_self_trans / total_trans, 4)
    results["vigenere_row_sequence"] = vig_rows

    # Vigenere same-row pairs
    vig_same_row = sum(1 for i in range(len(vig_rows) - 1) if vig_rows[i] == vig_rows[i + 1])
    results["vigenere_same_row_pairs"] = vig_same_row

    # --- C5: Monte Carlo significance test ---
    # Is Beaufort's row clustering significantly higher than random 24-char strings?
    import random
    random.seed(20260321)
    n_mc = 100000
    observed_same_row = self_trans

    count_ge = 0
    for _ in range(n_mc):
        # Random 24 letters from uniform A-Z distribution
        rand_letters = [ALPH[random.randint(0, 25)] for _ in range(24)]
        rand_rows = [LETTER_TO_RC[ch][0] for ch in rand_letters]
        same = sum(1 for i in range(len(rand_rows) - 1) if rand_rows[i] == rand_rows[i + 1])
        if same >= observed_same_row:
            count_ge += 1

    p_value = count_ge / n_mc
    results["mc_p_value_same_row"] = round(p_value, 6)
    results["mc_trials"] = n_mc
    results["observed_same_row_pairs"] = observed_same_row

    # --- C6: Also test column clustering ---
    observed_same_col = col_self_trans
    count_ge_col = 0
    random.seed(20260321 + 1)
    for _ in range(n_mc):
        rand_letters = [ALPH[random.randint(0, 25)] for _ in range(24)]
        rand_cols = [LETTER_TO_RC[ch][1] for ch in rand_letters]
        same = sum(1 for i in range(len(rand_cols) - 1) if rand_cols[i] == rand_cols[i + 1])
        if same >= observed_same_col:
            count_ge_col += 1

    results["mc_p_value_same_col"] = round(count_ge_col / n_mc, 6)
    results["observed_same_col_pairs"] = observed_same_col

    # --- C7: Row run-length distribution ---
    run_lengths = []
    current_run = 1
    for i in range(1, len(beau_rows)):
        if beau_rows[i] == beau_rows[i - 1]:
            current_run += 1
        else:
            run_lengths.append(current_run)
            current_run = 1
    run_lengths.append(current_run)

    results["row_run_lengths"] = run_lengths
    results["row_run_length_distribution"] = dict(Counter(run_lengths))
    results["max_row_run"] = max(run_lengths)
    results["mean_row_run"] = round(sum(run_lengths) / len(run_lengths), 3)

    # Monte Carlo: probability of max_run >= observed under random
    max_run_observed = max(run_lengths)
    count_ge_maxrun = 0
    random.seed(20260321 + 2)
    for _ in range(n_mc):
        rand_letters = [ALPH[random.randint(0, 25)] for _ in range(24)]
        rand_rows = [LETTER_TO_RC[ch][0] for ch in rand_letters]
        rl = []
        cr = 1
        for j in range(1, len(rand_rows)):
            if rand_rows[j] == rand_rows[j - 1]:
                cr += 1
            else:
                rl.append(cr)
                cr = 1
        rl.append(cr)
        if max(rl) >= max_run_observed:
            count_ge_maxrun += 1

    results["mc_p_value_max_run"] = round(count_ge_maxrun / n_mc, 6)

    # --- C8: Are the crib-gap transitions special? ---
    # The 24 keystream values span two separate regions (pos 21-33, 63-73)
    # with a 29-position gap. The transition from pos 33 -> 63 is NOT
    # a consecutive key transition. Let's analyze ENE and BC separately.
    ene_rows = beau_rows[:13]
    bc_rows = beau_rows[13:]

    ene_same = sum(1 for i in range(len(ene_rows) - 1) if ene_rows[i] == ene_rows[i + 1])
    bc_same = sum(1 for i in range(len(bc_rows) - 1) if bc_rows[i] == bc_rows[i + 1])

    results["ene_same_row_pairs"] = ene_same
    results["ene_total_pairs"] = len(ene_rows) - 1
    results["bc_same_row_pairs"] = bc_same
    results["bc_total_pairs"] = len(bc_rows) - 1

    # --- C9: Absorbing/reflecting patterns ---
    # Which rows are "sticky" (high self-transition)?
    sticky_rows = {}
    for r in range(GRID_ROWS):
        if sum(trans_matrix[r]) > 0:
            sticky_rows[r] = round(trans_matrix[r][r] / sum(trans_matrix[r]), 3)
    results["row_stickiness"] = sticky_rows

    return results


# =========================================================================
# Main
# =========================================================================

def main():
    print("=" * 70)
    print("E-POLYBIUS-WALK: Keystream Grid Walk Analysis")
    print("=" * 70)

    start_time = time.time()
    all_results = {
        "experiment": "e_polybius_walk",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "description": "Polybius grid walk analysis of Beaufort keystream",
    }

    # Verify keystream
    print(f"\nBeaufort keystream: {BEAUFORT_KS_STR}")
    print(f"Vigenere keystream: {VIGENERE_KS_STR}")
    assert len(BEAUFORT_KS_STR) == 24, f"Expected 24 keystream chars, got {len(BEAUFORT_KS_STR)}"

    # Grid display
    print(f"\nKA Polybius Grid (5-wide):")
    for r in range(GRID_ROWS):
        row_chars = [KA[r * GRID_WIDTH + c] for c in range(GRID_WIDTH) if r * GRID_WIDTH + c < 26]
        print(f"  Row {r}: {' '.join(row_chars)}")

    # --- Part A ---
    print("\n" + "=" * 50)
    print("PART A: Characterize row/column structure")
    print("=" * 50)

    part_a = part_a_characterize()
    all_results["part_a"] = part_a

    print(f"\nCoordinates (row,col):")
    for i, (ch, (r, c)) in enumerate(zip(BEAUFORT_KS_STR, part_a["coords"])):
        print(f"  {ch} -> ({r},{c})", end="  ")
        if (i + 1) % 8 == 0:
            print()
    print()

    print(f"\nRow sequence: {part_a['rows']}")
    print(f"Col sequence: {part_a['cols']}")
    print(f"\nRow frequency: {part_a['row_frequency']}")
    print(f"Col frequency: {part_a['col_frequency']}")

    print(f"\nSame-row consecutive pairs: {part_a['same_row_pairs']} / {part_a['total_consecutive_pairs']}")
    print(f"Expected (uniform): {part_a['expected_same_row_pairs']}")
    print(f"Ratio (observed/expected): {part_a['same_row_ratio']}x")

    print(f"\nSame-col consecutive pairs: {part_a['same_col_pairs']} / {part_a['total_consecutive_pairs']}")
    print(f"Expected (uniform): {part_a['expected_same_col_pairs']}")

    print(f"\nRow diff sequence: {part_a['row_diff_sequence']}")
    print(f"Col diff sequence: {part_a['col_diff_sequence']}")
    print(f"Row diff counts: {part_a['row_diff_counts']}")
    print(f"Col diff counts: {part_a['col_diff_counts']}")

    print(f"\nRow runs: {part_a['row_runs']}")
    print(f"Max run length: {part_a['max_run_length']}")
    print(f"Mean run length: {part_a['mean_run_length']}")

    print(f"\nMean Manhattan distance: {part_a['mean_manhattan']}")
    print(f"Expected Manhattan (uniform): {part_a['expected_manhattan_uniform']}")

    print(f"\nDiagonal moves: {part_a['diagonal_moves']}")
    print(f"Anti-diagonal moves: {part_a['anti_diagonal_moves']}")

    print(f"\nNamed path crib matches (cycling 97): {part_a['named_path_crib_matches']}")

    # --- Part B ---
    print("\n" + "=" * 50)
    print("PART B: Test grid-walk key generation")
    print("=" * 50)

    part_b = part_b_grid_walks()
    all_results["part_b"] = part_b

    print(f"\nLinear walks: tested {part_b['linear_walks']['total_tested']}, best = {part_b['linear_walks']['best_matches']}/24")
    if part_b['linear_walks']['top_results']:
        for r in part_b['linear_walks']['top_results'][:5]:
            print(f"  {r['method']}: {r['matches']}/24")

    print(f"\nStep walks: tested {part_b['step_walks']['total_tested']}, best = {part_b['step_walks']['best_matches']}/24")
    if part_b['step_walks']['top_results']:
        for r in part_b['step_walks']['top_results'][:5]:
            print(f"  start={r['start']} step={r['step']}: {r['matches']}/24")

    print(f"\nCT-dependent walks: tested {part_b['ct_dependent_walks']['total_tested']}, best = {part_b['ct_dependent_walks']['best_matches']}/24")
    if part_b['ct_dependent_walks']['top_results']:
        for r in part_b['ct_dependent_walks']['top_results'][:5]:
            print(f"  {r['model']} start={r['start']}: {r['matches']}/24")

    print(f"\nKRYPTOS-seeded walks: tested {part_b['kryptos_seeded_walks']['total_tested']}, best = {part_b['kryptos_seeded_walks']['best_matches']}/24")
    if part_b['kryptos_seeded_walks']['top_results']:
        for r in part_b['kryptos_seeded_walks']['top_results'][:5]:
            print(f"  {r['model']} start={r['start']}: {r['matches']}/24")

    print(f"\n*** BEST OVERALL: {part_b['best_overall']['method']} = {part_b['best_overall']['matches']}/24 ***")

    # --- Part C ---
    print("\n" + "=" * 50)
    print("PART C: Row-transition Markov analysis")
    print("=" * 50)

    part_c = part_c_markov_analysis()
    all_results["part_c"] = part_c

    print(f"\nBeaufort row transition matrix (counts):")
    for r in range(GRID_ROWS):
        print(f"  Row {r}: {part_c['beaufort_transition_counts'][r]}")

    print(f"\nBeaufort row transition matrix (probabilities):")
    for r in range(GRID_ROWS):
        print(f"  Row {r}: {part_c['beaufort_transition_probs'][r]}")

    print(f"\nBeaufort self-transition rate: {part_c['beaufort_self_transition_rate']}")
    print(f"Beaufort adjacent-transition rate: {part_c['beaufort_adjacent_transition_rate']}")

    print(f"\nBeaufort col transition matrix (counts):")
    for c in range(GRID_WIDTH):
        print(f"  Col {c}: {part_c['beaufort_col_transition_counts'][c]}")

    print(f"\nBeaufort col self-transition rate: {part_c['beaufort_col_self_transition_rate']}")

    print(f"\nVigenere self-transition rate: {part_c['vigenere_self_transition_rate']}")
    print(f"Vigenere same-row pairs: {part_c['vigenere_same_row_pairs']}")

    print(f"\nMonte Carlo p-values (100K trials):")
    print(f"  Same-row clustering: p = {part_c['mc_p_value_same_row']}")
    print(f"  Same-col clustering: p = {part_c['mc_p_value_same_col']}")
    print(f"  Max row run >= {part_c['max_row_run']}: p = {part_c['mc_p_value_max_run']}")

    print(f"\nENE crib same-row: {part_c['ene_same_row_pairs']}/{part_c['ene_total_pairs']}")
    print(f"BC crib same-row: {part_c['bc_same_row_pairs']}/{part_c['bc_total_pairs']}")

    print(f"\nRow stickiness: {part_c['row_stickiness']}")

    print(f"\nRow run lengths: {part_c['row_run_lengths']}")
    print(f"Distribution: {part_c['row_run_length_distribution']}")

    # --- Summary ---
    elapsed = time.time() - start_time

    summary = {
        "row_clustering_significant": part_c["mc_p_value_same_row"] < 0.01,
        "col_clustering_significant": part_c["mc_p_value_same_col"] < 0.01,
        "best_walk_matches": part_b["best_overall"]["matches"],
        "best_walk_method": part_b["best_overall"]["method"],
        "beaufort_vs_vigenere_same_row": f"{part_c['observed_same_row_pairs']} vs {part_c['vigenere_same_row_pairs']}",
        "verdict": "CHARACTERIZATION_COMPLETE",
        "elapsed_seconds": round(elapsed, 1),
    }

    # Determine if any walk exceeds noise
    if part_b["best_overall"]["matches"] >= 6:
        summary["walk_signal"] = "POTENTIAL_SIGNAL"
    else:
        summary["walk_signal"] = "NOISE"
        summary["interpretation"] = (
            "No deterministic grid walk produces more than noise-level crib matches. "
            "The row clustering, while statistically significant, does not correspond to "
            "any simple path through the Polybius grid."
        )

    all_results["summary"] = summary

    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    for k, v in summary.items():
        print(f"  {k}: {v}")

    # Write results
    out_path = _ROOT / "results" / "e_polybius_walk.json"
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\nResults written to: {out_path}")
    print(f"Elapsed: {elapsed:.1f}s")


if __name__ == "__main__":
    main()
