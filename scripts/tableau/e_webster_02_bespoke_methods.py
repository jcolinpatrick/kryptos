#!/usr/bin/env python3
"""
Cipher: tableau analysis
Family: tableau
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-WEBSTER-02: Bespoke Webster/Judge-Themed Cipher Methods on K4.

[HYPOTHESIS] William Webster ("Judge") was CIA Director when Kryptos was
installed (1987-1991). His name, title, and career parameters could inform
K4's cipher method. This tests creative, non-standard approaches that a
human could execute with pencil and paper in 1989.

Test plan:
- Phase 1: JUDGE as columnar transposition key (5 columns, various read orders)
- Phase 2: JUDGE letter values as progressive/cyclic shift
- Phase 3: K4 follows K1-K3 pattern — JUDGE as keyword (Vigenère + transposition)
- Phase 4: JUDGE-derived grid dimensions with double rotational transposition
- Phase 5: JUDGE as autokey/progressive Vigenère primer
- Phase 6: Two-keyword combos (JUDGE + KRYPTOS, PALIMPSEST, ABSCISSA, WEBSTER)
- Phase 7: Route cipher in JUDGE-derived grids
- Phase 8: Judicial numbering / career parameters as cipher inputs

Uses BOTH anchored and free crib scoring.
"""
import json
import math
import os
import sys
import time
from collections import defaultdict
from itertools import permutations, product
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_WORDS, CRIB_DICT, N_CRIBS,
    KRYPTOS_ALPHABET,
    BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed
from kryptos.kernel.scoring.ic import ic
from kryptos.kernel.constraints.bean import verify_bean, BeanResult

# KA alphabet index
KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

# ── Global tracking ─────────────────────────────────────────────────────

best_results = []  # top results across all phases
total_configs = 0

def track(pt: str, method: str, detail: str = ""):
    """Score and track a candidate plaintext."""
    global total_configs
    total_configs += 1
    if len(pt) < CT_LEN:
        return 0
    pt = pt[:CT_LEN].upper()

    # Quick crib score
    crib_sc = score_cribs(pt)

    # Compute keystream for Bean check
    keystream = [(ALPH_IDX[CT[i]] - ALPH_IDX[pt[i]]) % MOD for i in range(CT_LEN)]
    bean_result = verify_bean(keystream)

    # Full scoring for interesting results
    if crib_sc >= 3 or bean_result.passed:
        sc = score_candidate(pt, bean_result=bean_result)
        ic_val = sc.ic_value
    else:
        ic_val = ic(pt)

    result = {
        "method": method,
        "detail": detail,
        "crib_score": crib_sc,
        "ic": ic_val,
        "bean_pass": bean_result.passed,
        "bean_eq": bean_result.eq_satisfied,
        "bean_ineq": bean_result.ineq_satisfied,
        "pt_preview": pt[:50],
    }

    if crib_sc >= 3:
        best_results.append(result)
        print(f"  [{crib_sc}/24] {method}: {detail} | IC={ic_val:.4f} | "
              f"bean={'PASS' if bean_result.passed else 'FAIL'} | {pt[:40]}...")

    return crib_sc


# ── Cipher primitives ───────────────────────────────────────────────────

def vigenere_decrypt(ct: str, key_shifts: List[int]) -> str:
    """Vigenère decryption: PT = (CT - K) mod 26."""
    result = []
    klen = len(key_shifts)
    for i, ch in enumerate(ct):
        pt_idx = (ALPH_IDX[ch] - key_shifts[i % klen]) % MOD
        result.append(ALPH[pt_idx])
    return ''.join(result)


def beaufort_decrypt(ct: str, key_shifts: List[int]) -> str:
    """Beaufort decryption: PT = (K - CT) mod 26."""
    result = []
    klen = len(key_shifts)
    for i, ch in enumerate(ct):
        pt_idx = (key_shifts[i % klen] - ALPH_IDX[ch]) % MOD
        result.append(ALPH[pt_idx])
    return ''.join(result)


def variant_beaufort_decrypt(ct: str, key_shifts: List[int]) -> str:
    """Variant Beaufort decryption: PT = (CT + K) mod 26."""
    result = []
    klen = len(key_shifts)
    for i, ch in enumerate(ct):
        pt_idx = (ALPH_IDX[ch] + key_shifts[i % klen]) % MOD
        result.append(ALPH[pt_idx])
    return ''.join(result)


def keyword_to_shifts_az(keyword: str) -> List[int]:
    """Convert keyword to AZ shifts (A=0, B=1, ...)."""
    return [ALPH_IDX[ch] for ch in keyword.upper() if ch in ALPH_IDX]


def keyword_to_shifts_ka(keyword: str) -> List[int]:
    """Convert keyword to KA shifts (K=0, R=1, ...)."""
    return [KA_IDX[ch] for ch in keyword.upper() if ch in KA_IDX]


def columnar_encrypt(text: str, col_order: List[int]) -> str:
    """Columnar transposition encryption.

    Write text in rows of width=len(col_order), read off columns
    in the order specified by col_order.
    """
    width = len(col_order)
    nrows = math.ceil(len(text) / width)
    # Pad with X
    padded = text.ljust(nrows * width, 'X')

    result = []
    for col in col_order:
        for row in range(nrows):
            idx = row * width + col
            if idx < len(text):
                result.append(text[idx])
    return ''.join(result)


def columnar_decrypt(ct: str, col_order: List[int]) -> str:
    """Columnar transposition decryption.

    Undo: text was written in rows, columns read in col_order.
    To decrypt: figure out column lengths, fill columns in col_order, read rows.
    """
    width = len(col_order)
    n = len(ct)
    nrows = math.ceil(n / width)

    # Number of "full" columns (with nrows chars)
    full_cols_count = n - width * (nrows - 1)

    # Determine which columns are "full" (nrows chars) vs "short" (nrows-1)
    # Columns 0..full_cols_count-1 are full
    col_lengths = {}
    for c in range(width):
        col_lengths[c] = nrows if c < full_cols_count else nrows - 1

    # Fill columns in col_order
    cols = {}
    pos = 0
    for c in col_order:
        clen = col_lengths[c]
        cols[c] = ct[pos:pos + clen]
        pos += clen

    # Read rows
    result = []
    for row in range(nrows):
        for c in range(width):
            if row < len(cols.get(c, '')):
                result.append(cols[c][row])
    return ''.join(result)


def apply_permutation(text: str, perm: List[int]) -> str:
    """Apply a fixed permutation cyclically: output[i] = input[perm[i % len(perm)]]
    where the perm is applied in blocks."""
    width = len(perm)
    result = []
    n = len(text)
    nblocks = math.ceil(n / width)
    for block in range(nblocks):
        for p in perm:
            idx = block * width + p
            if idx < n:
                result.append(text[idx])
    return ''.join(result)


def invert_permutation(perm: List[int]) -> List[int]:
    """Compute the inverse of a permutation."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def route_cipher_spiral(text: str, nrows: int, ncols: int, clockwise: bool = True) -> str:
    """Read text placed in a grid via spiral route."""
    n = len(text)
    if nrows * ncols < n:
        return text  # Can't fit

    # Place text in grid row by row
    grid = [['' for _ in range(ncols)] for _ in range(nrows)]
    idx = 0
    for r in range(nrows):
        for c in range(ncols):
            if idx < n:
                grid[r][c] = text[idx]
                idx += 1

    # Spiral read
    result = []
    top, bottom, left, right = 0, nrows - 1, 0, ncols - 1

    while top <= bottom and left <= right and len(result) < n:
        if clockwise:
            # Right along top
            for c in range(left, right + 1):
                if grid[top][c]:
                    result.append(grid[top][c])
            top += 1
            # Down along right
            for r in range(top, bottom + 1):
                if grid[r][right]:
                    result.append(grid[r][right])
            right -= 1
            # Left along bottom
            if top <= bottom:
                for c in range(right, left - 1, -1):
                    if grid[bottom][c]:
                        result.append(grid[bottom][c])
                bottom -= 1
            # Up along left
            if left <= right:
                for r in range(bottom, top - 1, -1):
                    if grid[r][left]:
                        result.append(grid[r][left])
                left += 1
        else:
            # Down along left
            for r in range(top, bottom + 1):
                if grid[r][left]:
                    result.append(grid[r][left])
            left += 1
            # Right along bottom
            for c in range(left, right + 1):
                if grid[bottom][c]:
                    result.append(grid[bottom][c])
            bottom -= 1
            # Up along right
            if left <= right:
                for r in range(bottom, top - 1, -1):
                    if grid[r][right]:
                        result.append(grid[r][right])
                right -= 1
            # Left along top
            if top <= bottom:
                for c in range(right, left - 1, -1):
                    if grid[top][c]:
                        result.append(grid[top][c])
                top += 1

    return ''.join(result[:n])


def route_cipher_serpentine(text: str, nrows: int, ncols: int) -> str:
    """Serpentine (boustrophedon) reading of a grid."""
    n = len(text)
    if nrows * ncols < n:
        return text

    grid = [['' for _ in range(ncols)] for _ in range(nrows)]
    idx = 0
    for r in range(nrows):
        for c in range(ncols):
            if idx < n:
                grid[r][c] = text[idx]
                idx += 1

    result = []
    for r in range(nrows):
        if r % 2 == 0:
            for c in range(ncols):
                if grid[r][c]:
                    result.append(grid[r][c])
        else:
            for c in range(ncols - 1, -1, -1):
                if grid[r][c]:
                    result.append(grid[r][c])
    return ''.join(result[:n])


def route_cipher_col_serpentine(text: str, nrows: int, ncols: int) -> str:
    """Column-first serpentine: read columns, alternating top-down/bottom-up."""
    n = len(text)
    if nrows * ncols < n:
        return text

    grid = [['' for _ in range(ncols)] for _ in range(nrows)]
    idx = 0
    for r in range(nrows):
        for c in range(ncols):
            if idx < n:
                grid[r][c] = text[idx]
                idx += 1

    result = []
    for c in range(ncols):
        if c % 2 == 0:
            for r in range(nrows):
                if grid[r][c]:
                    result.append(grid[r][c])
        else:
            for r in range(nrows - 1, -1, -1):
                if grid[r][c]:
                    result.append(grid[r][c])
    return ''.join(result[:n])


# ── Phase 1: JUDGE as columnar transposition key ────────────────────────

def phase1_judge_columnar():
    """JUDGE sorted alphabetically gives column permutation."""
    print()
    print("=" * 72)
    print("Phase 1: JUDGE as columnar transposition key")
    print("=" * 72)

    # JUDGE: J=10, U=21, D=4, G=7, E=5
    # Sorted alphabetically: D(1), E(2), G(3), J(4), U(5)
    # So column read order is: col_of_D=2, col_of_E=4, col_of_G=3, col_of_J=0, col_of_U=1
    # i.e., the permutation by position: J is at pos 0, U at pos 1, D at pos 2, G at pos 3, E at pos 4
    # Alphabetical rank: D=0, E=1, G=2, J=3, U=4
    # So col_order = [3, 4, 0, 2, 1]  (position -> alphabetical rank tells us the read order)

    # Actually: JUDGE letters and their alphabetical sort order:
    # Position 0: J -> rank among {D,E,G,J,U} = 3
    # Position 1: U -> rank = 4
    # Position 2: D -> rank = 0
    # Position 3: G -> rank = 2
    # Position 4: E -> rank = 1
    # col_order = [3, 4, 0, 2, 1] means: read column 3 first, then 4, 0, 2, 1
    # BUT standard columnar: the column with rank 0 is read first.
    # Column at position 2 (D) has rank 0 -> read first
    # Column at position 4 (E) has rank 1 -> read second
    # Column at position 3 (G) has rank 2 -> read third
    # Column at position 0 (J) has rank 3 -> read fourth
    # Column at position 1 (U) has rank 4 -> read fifth
    # So col_order = [2, 4, 3, 0, 1]

    judge_col_order = [2, 4, 3, 0, 1]

    # Also test all permutations of 5 columns (5! = 120)
    print(f"  JUDGE standard col_order: {judge_col_order}")
    print(f"  Testing JUDGE columnar + all 120 permutations of width 5")

    n_tested = 0
    phase_best = 0

    # First: standard JUDGE columnar
    for direction in ["encrypt", "decrypt"]:
        if direction == "encrypt":
            pt = columnar_encrypt(CT, judge_col_order)
        else:
            pt = columnar_decrypt(CT, judge_col_order)
        sc = track(pt, "judge_columnar", f"dir={direction}")
        phase_best = max(phase_best, sc)
        n_tested += 1

        # Also the inverse permutation
        inv_order = invert_permutation(judge_col_order)
        if direction == "encrypt":
            pt2 = columnar_encrypt(CT, inv_order)
        else:
            pt2 = columnar_decrypt(CT, inv_order)
        sc2 = track(pt2, "judge_columnar_inv", f"dir={direction}")
        phase_best = max(phase_best, sc2)
        n_tested += 1

    # All 120 permutations of 5 columns with substitution
    keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "JUDGE", "WEBSTER",
                "BERLIN", "CLOCK", "SHADOW", "LANGLEY"]

    for perm in permutations(range(5)):
        perm_list = list(perm)
        # Columnar decrypt, then substitution
        pt_dec = columnar_decrypt(CT, perm_list)
        sc = track(pt_dec, "col5_perm_dec", f"perm={perm_list}")
        phase_best = max(phase_best, sc)
        n_tested += 1

        # Columnar encrypt (inverse direction)
        pt_enc = columnar_encrypt(CT, perm_list)
        sc = track(pt_enc, "col5_perm_enc", f"perm={perm_list}")
        phase_best = max(phase_best, sc)
        n_tested += 1

        # Columnar + Vigenère/Beaufort with keywords
        for kw in keywords:
            shifts = keyword_to_shifts_az(kw)
            for cipher_fn, cn in [(vigenere_decrypt, "vig"),
                                   (beaufort_decrypt, "beau")]:
                # Trans then sub
                pt_ts = cipher_fn(pt_dec, shifts)
                sc = track(pt_ts, f"col5+{cn}", f"perm={perm_list}, kw={kw}")
                phase_best = max(phase_best, sc)
                n_tested += 1

                # Sub then trans
                ct_sub = cipher_fn(CT, shifts)
                pt_st = columnar_decrypt(ct_sub, perm_list)
                sc = track(pt_st, f"{cn}+col5", f"kw={kw}, perm={perm_list}")
                phase_best = max(phase_best, sc)
                n_tested += 1

    print(f"  Phase 1: {n_tested:,} configs, best={phase_best}/24")
    return n_tested, phase_best


# ── Phase 2: JUDGE letter values as progressive shift ───────────────────

def phase2_judge_shifts():
    """JUDGE letter values as cyclic shift key."""
    print()
    print("=" * 72)
    print("Phase 2: JUDGE letter values as progressive/cyclic shifts")
    print("=" * 72)

    n_tested = 0
    phase_best = 0

    # AZ values: J=9, U=20, D=3, G=6, E=4
    az_shifts = [ALPH_IDX[c] for c in "JUDGE"]
    print(f"  JUDGE AZ shifts: {az_shifts}")

    # KA values
    ka_shifts = [KA_IDX[c] for c in "JUDGE"]
    print(f"  JUDGE KA shifts: {ka_shifts}")

    # WEBSTER: W=22, E=4, B=1, S=18, T=19, E=4, R=17
    webster_az = [ALPH_IDX[c] for c in "WEBSTER"]
    webster_ka = [KA_IDX[c] for c in "WEBSTER"]

    # WILLIAMWEBSTER
    ww_az = [ALPH_IDX[c] for c in "WILLIAMWEBSTER"]

    all_shift_sets = [
        ("JUDGE_AZ", az_shifts),
        ("JUDGE_KA", ka_shifts),
        ("WEBSTER_AZ", webster_az),
        ("WEBSTER_KA", webster_ka),
        ("WILLIAMWEBSTER_AZ", ww_az),
        ("JUDGEWEBSTER_AZ", [ALPH_IDX[c] for c in "JUDGEWEBSTER"]),
    ]

    for name, shifts in all_shift_sets:
        for cipher_fn, cn in [(vigenere_decrypt, "vig"),
                               (beaufort_decrypt, "beau"),
                               (variant_beaufort_decrypt, "vbeau")]:
            # Simple repeating key
            pt = cipher_fn(CT, shifts)
            sc = track(pt, f"{cn}_{name}", f"key={shifts}")
            phase_best = max(phase_best, sc)
            n_tested += 1

            # Progressive: shift increases each cycle
            for increment in range(1, 26):
                prog_shifts = []
                for i in range(CT_LEN):
                    cycle = i // len(shifts)
                    base = shifts[i % len(shifts)]
                    prog_shifts.append((base + cycle * increment) % MOD)
                pt = cipher_fn(CT, prog_shifts)
                sc = track(pt, f"{cn}_{name}_prog", f"inc={increment}")
                phase_best = max(phase_best, sc)
                n_tested += 1

            # Cumulative: each position adds the shift to a running total
            cumulative = []
            running = 0
            for i in range(CT_LEN):
                running = (running + shifts[i % len(shifts)]) % MOD
                cumulative.append(running)
            pt = cipher_fn(CT, cumulative)
            sc = track(pt, f"{cn}_{name}_cumulative", "running total")
            phase_best = max(phase_best, sc)
            n_tested += 1

    print(f"  Phase 2: {n_tested:,} configs, best={phase_best}/24")
    return n_tested, phase_best


# ── Phase 3: K4 follows K1-K3 keyword pattern ──────────────────────────

def phase3_section_keyword_pattern():
    """K1=PALIMPSEST, K2=ABSCISSA, K3=KRYPTOS. K4=JUDGE?"""
    print()
    print("=" * 72)
    print("Phase 3: K4 follows K1-K3 pattern (JUDGE as section keyword)")
    print("=" * 72)

    n_tested = 0
    phase_best = 0

    # K1: Vigenère with PALIMPSEST
    # K2: Vigenère with ABSCISSA
    # K3: Transposition keyed by KRYPTOS (double columnar)
    # K4: JUDGE could be used in Vigenère (like K1/K2) or transposition (like K3)

    # Test keywords that could follow the pattern
    keywords = [
        "JUDGE", "WEBSTER", "WILLIAM", "WILLIAMWEBSTER",
        "DIRECTOR", "LANGLEY", "AGENCY",
        "JUDGEWEBSTER", "WILLIAMHJUDGEWEBSTER",
        # Previous section keywords as potential K4 keys
        "PALIMPSEST", "ABSCISSA", "KRYPTOS",
        # Combinations
        "JUDGELANGLEY", "WEBSTERKRYPTOS",
    ]

    for kw in keywords:
        shifts_az = keyword_to_shifts_az(kw)
        shifts_ka = keyword_to_shifts_ka(kw)

        for shifts, alpha_name in [(shifts_az, "AZ"), (shifts_ka, "KA")]:
            for cipher_fn, cn in [(vigenere_decrypt, "vig"),
                                   (beaufort_decrypt, "beau"),
                                   (variant_beaufort_decrypt, "vbeau")]:
                pt = cipher_fn(CT, shifts)
                sc = track(pt, f"p3_{cn}_{alpha_name}", f"kw={kw}")
                phase_best = max(phase_best, sc)
                n_tested += 1

        # K3-style transposition: use keyword to derive column order
        # Standard keyword columnar: sort letters to get column order
        if len(kw) <= 20:  # reasonable width
            # Build column order from keyword
            indexed = sorted(enumerate(kw), key=lambda x: (x[1], x[0]))
            col_order = [0] * len(kw)
            for rank, (orig_pos, _) in enumerate(indexed):
                col_order[orig_pos] = rank
            # col_order[i] = rank of column i in the read order
            # For columnar decrypt, we need the READ order
            read_order = [orig_pos for _, (orig_pos, _) in enumerate(
                sorted(enumerate(kw), key=lambda x: (x[1], x[0])))]

            for direction in ["decrypt", "encrypt"]:
                if direction == "decrypt":
                    pt = columnar_decrypt(CT, read_order)
                else:
                    pt = columnar_encrypt(CT, read_order)
                sc = track(pt, f"p3_columnar_{direction}", f"kw={kw}, order={read_order}")
                phase_best = max(phase_best, sc)
                n_tested += 1

                # Double columnar (K3-style): transposition twice
                pt2 = columnar_decrypt(pt, read_order) if direction == "decrypt" \
                    else columnar_encrypt(pt, read_order)
                sc = track(pt2, f"p3_double_columnar_{direction}", f"kw={kw}")
                phase_best = max(phase_best, sc)
                n_tested += 1

    print(f"  Phase 3: {n_tested:,} configs, best={phase_best}/24")
    return n_tested, phase_best


# ── Phase 4: JUDGE-derived grid with rotational transposition ───────────

def phase4_judge_grid_transposition():
    """Double rotational transposition with JUDGE-derived grid dimensions."""
    print()
    print("=" * 72)
    print("Phase 4: JUDGE-derived grid + rotational transposition")
    print("=" * 72)

    n_tested = 0
    phase_best = 0

    # 97 doesn't divide by 5. Possible grid sizes:
    # 97 = prime, so no perfect grid.
    # Try: 5x20 (pad 3), 10x10 (pad 3), 7x14 (pad 1),
    #       20x5 (pad 3), 13x8 (pad 7), 8x13 (pad 7)
    # Also: 5x5 blocks with partial final block

    grid_dims = [
        (5, 20), (20, 5), (5, 19), (19, 5),
        (7, 14), (14, 7), (10, 10), (8, 13), (13, 8),
        (11, 9), (9, 11), (4, 25), (25, 4),
        # Factorings close to 97
        (7, 14), (14, 7),
        # JUDGE-letter-derived dimensions
        (5, 20),  # 5 letters in JUDGE, nearest multiple = 100
        (9, 11),  # J=10th letter, near 9x11=99
    ]
    # Deduplicate
    grid_dims = list(set(grid_dims))

    for nrows, ncols in grid_dims:
        total_cells = nrows * ncols
        if total_cells < CT_LEN:
            continue

        # Route cipher readings
        for cw in [True, False]:
            # Spiral in, then read
            pt_spiral = route_cipher_spiral(CT, nrows, ncols, clockwise=cw)
            sc = track(pt_spiral, "spiral_in",
                      f"grid={nrows}x{ncols}, cw={cw}")
            phase_best = max(phase_best, sc)
            n_tested += 1

            # Spiral out (reverse the spiral reading as decryption)
            # The reverse of a spiral-read ciphertext
            pt_spiral_rev = route_cipher_spiral(CT[::-1], nrows, ncols, clockwise=cw)[::-1]
            sc = track(pt_spiral_rev, "spiral_out_rev",
                      f"grid={nrows}x{ncols}, cw={cw}")
            phase_best = max(phase_best, sc)
            n_tested += 1

        # Serpentine (boustrophedon)
        pt_serp = route_cipher_serpentine(CT, nrows, ncols)
        sc = track(pt_serp, "serpentine",
                  f"grid={nrows}x{ncols}")
        phase_best = max(phase_best, sc)
        n_tested += 1

        # Column serpentine
        pt_cserp = route_cipher_col_serpentine(CT, nrows, ncols)
        sc = track(pt_cserp, "col_serpentine",
                  f"grid={nrows}x{ncols}")
        phase_best = max(phase_best, sc)
        n_tested += 1

        # Double rotation: write in grid, rotate 90°, read rows
        # Place CT in grid row by row
        grid = [['' for _ in range(ncols)] for _ in range(nrows)]
        idx = 0
        for r in range(nrows):
            for c in range(ncols):
                if idx < CT_LEN:
                    grid[r][c] = CT[idx]
                    idx += 1

        # Rotate 90° clockwise: new[c][nrows-1-r] = old[r][c]
        rotated_cw = [['' for _ in range(nrows)] for _ in range(ncols)]
        for r in range(nrows):
            for c in range(ncols):
                rotated_cw[c][nrows - 1 - r] = grid[r][c]
        pt_rot_cw = ''.join(''.join(row) for row in rotated_cw)
        pt_rot_cw = ''.join(c for c in pt_rot_cw if c)[:CT_LEN]
        sc = track(pt_rot_cw, "rotate_90cw",
                  f"grid={nrows}x{ncols}")
        phase_best = max(phase_best, sc)
        n_tested += 1

        # Rotate 90° counter-clockwise: new[ncols-1-c][r] = old[r][c]
        rotated_ccw = [['' for _ in range(nrows)] for _ in range(ncols)]
        for r in range(nrows):
            for c in range(ncols):
                rotated_ccw[ncols - 1 - c][r] = grid[r][c]
        pt_rot_ccw = ''.join(''.join(row) for row in rotated_ccw)
        pt_rot_ccw = ''.join(c for c in pt_rot_ccw if c)[:CT_LEN]
        sc = track(pt_rot_ccw, "rotate_90ccw",
                  f"grid={nrows}x{ncols}")
        phase_best = max(phase_best, sc)
        n_tested += 1

        # Rotate 180°
        pt_rot_180 = CT[::-1]
        sc = track(pt_rot_180, "rotate_180",
                  f"grid={nrows}x{ncols}")
        phase_best = max(phase_best, sc)
        n_tested += 1

        # Read columns instead of rows
        pt_cols = ''.join(
            grid[r][c]
            for c in range(ncols)
            for r in range(nrows)
            if grid[r][c]
        )[:CT_LEN]
        sc = track(pt_cols, "read_columns",
                  f"grid={nrows}x{ncols}")
        phase_best = max(phase_best, sc)
        n_tested += 1

        # Diagonal reading
        diags = defaultdict(list)
        for r in range(nrows):
            for c in range(ncols):
                if grid[r][c]:
                    diags[r + c].append(grid[r][c])
        pt_diag = ''.join(''.join(diags[k]) for k in sorted(diags))[:CT_LEN]
        sc = track(pt_diag, "diagonal_nwse",
                  f"grid={nrows}x{ncols}")
        phase_best = max(phase_best, sc)
        n_tested += 1

    print(f"  Phase 4: {n_tested:,} configs, best={phase_best}/24")
    return n_tested, phase_best


# ── Phase 5: JUDGE as autokey/progressive primer ────────────────────────

def phase5_autokey():
    """JUDGE as primer for autokey cipher variants."""
    print()
    print("=" * 72)
    print("Phase 5: JUDGE as autokey/progressive primer")
    print("=" * 72)

    n_tested = 0
    phase_best = 0

    primers = [
        ("JUDGE", "JUDGE"),
        ("WEBSTER", "WEBSTER"),
        ("WILLIAM", "WILLIAM"),
        ("KRYPTOS", "KRYPTOS"),
        ("PALIMPSEST", "PALIMPSEST"),
        ("ABSCISSA", "ABSCISSA"),
        ("JUDGEWEBSTER", "JUDGEWEBSTER"),
    ]

    for name, primer_word in primers:
        primer = keyword_to_shifts_az(primer_word)
        primer_ka = keyword_to_shifts_ka(primer_word)

        for shifts_set, alpha_name in [(primer, "AZ"), (primer_ka, "KA")]:
            # Plaintext autokey: K[i] = primer for i<len(primer), then K[i] = PT[i-len(primer)]
            # Decrypt iteratively
            plen = len(shifts_set)

            # Vigenère autokey (plaintext feedback)
            pt_chars = []
            for i in range(CT_LEN):
                if i < plen:
                    k = shifts_set[i]
                else:
                    k = ALPH_IDX[pt_chars[i - plen]]
                pt_idx = (ALPH_IDX[CT[i]] - k) % MOD
                pt_chars.append(ALPH[pt_idx])
            pt = ''.join(pt_chars)
            sc = track(pt, f"autokey_pt_vig_{alpha_name}", f"primer={name}")
            phase_best = max(phase_best, sc)
            n_tested += 1

            # Beaufort autokey (plaintext feedback)
            pt_chars = []
            for i in range(CT_LEN):
                if i < plen:
                    k = shifts_set[i]
                else:
                    k = ALPH_IDX[pt_chars[i - plen]]
                pt_idx = (k - ALPH_IDX[CT[i]]) % MOD
                pt_chars.append(ALPH[pt_idx])
            pt = ''.join(pt_chars)
            sc = track(pt, f"autokey_pt_beau_{alpha_name}", f"primer={name}")
            phase_best = max(phase_best, sc)
            n_tested += 1

            # Ciphertext autokey: K[i] = primer for i<len(primer), then K[i] = CT[i-len(primer)]
            ct_shifts = []
            for i in range(CT_LEN):
                if i < plen:
                    ct_shifts.append(shifts_set[i])
                else:
                    ct_shifts.append(ALPH_IDX[CT[i - plen]])

            for cipher_fn, cn in [(vigenere_decrypt, "vig"),
                                   (beaufort_decrypt, "beau"),
                                   (variant_beaufort_decrypt, "vbeau")]:
                pt = cipher_fn(CT, ct_shifts)
                sc = track(pt, f"autokey_ct_{cn}_{alpha_name}", f"primer={name}")
                phase_best = max(phase_best, sc)
                n_tested += 1

            # Progressive Vigenère: key repeats but shifts by 1 each cycle
            for shift_inc in range(1, 26):
                prog_key = []
                for i in range(CT_LEN):
                    cycle = i // plen
                    base = shifts_set[i % plen]
                    prog_key.append((base + cycle * shift_inc) % MOD)
                pt = vigenere_decrypt(CT, prog_key)
                sc = track(pt, f"progressive_vig_{alpha_name}", f"primer={name}, inc={shift_inc}")
                phase_best = max(phase_best, sc)
                n_tested += 1

            # Key autokey: K[i] = primer for i<len, then K[i] = K[i-len]
            # (just repeating — but also try K[i] = K[i-1] + primer[i%len])
            growing_key = list(shifts_set)
            for i in range(plen, CT_LEN):
                growing_key.append((growing_key[i - 1] + shifts_set[i % plen]) % MOD)
            pt = vigenere_decrypt(CT, growing_key)
            sc = track(pt, f"growing_key_vig_{alpha_name}", f"primer={name}")
            phase_best = max(phase_best, sc)
            n_tested += 1

            # Fibonacci-like key: K[i] = K[i-1] + K[i-2] mod 26
            if plen >= 2:
                fib_key = list(shifts_set)
                for i in range(plen, CT_LEN):
                    fib_key.append((fib_key[i - 1] + fib_key[i - 2]) % MOD)
                pt = vigenere_decrypt(CT, fib_key)
                sc = track(pt, f"fibonacci_vig_{alpha_name}", f"primer={name}")
                phase_best = max(phase_best, sc)
                n_tested += 1

    print(f"  Phase 5: {n_tested:,} configs, best={phase_best}/24")
    return n_tested, phase_best


# ── Phase 6: Two-keyword combinations ──────────────────────────────────

def phase6_two_keyword():
    """Combine JUDGE with other Kryptos keywords in multi-layer decryption."""
    print()
    print("=" * 72)
    print("Phase 6: Two-keyword combinations (JUDGE + other keywords)")
    print("=" * 72)

    n_tested = 0
    phase_best = 0

    # First keyword for substitution, second for transposition (or vice versa)
    kw_pairs = [
        ("JUDGE", "KRYPTOS"),
        ("JUDGE", "ABSCISSA"),
        ("JUDGE", "PALIMPSEST"),
        ("JUDGE", "WEBSTER"),
        ("JUDGE", "BERLIN"),
        ("JUDGE", "BERLINCLOCK"),
        ("KRYPTOS", "JUDGE"),
        ("ABSCISSA", "JUDGE"),
        ("PALIMPSEST", "JUDGE"),
        ("WEBSTER", "KRYPTOS"),
        ("WEBSTER", "PALIMPSEST"),
        ("WEBSTER", "ABSCISSA"),
        ("JUDGE", "IQLUSION"),
        ("JUDGE", "SANBORN"),
        ("JUDGE", "SCHEIDT"),
    ]

    for kw_sub, kw_trans in kw_pairs:
        sub_shifts = keyword_to_shifts_az(kw_sub)

        # Build columnar order from transposition keyword
        indexed = sorted(enumerate(kw_trans), key=lambda x: (x[1], x[0]))
        read_order = [orig_pos for _, (orig_pos, _) in enumerate(
            sorted(enumerate(kw_trans), key=lambda x: (x[1], x[0])))]

        for cipher_fn, cn in [(vigenere_decrypt, "vig"),
                               (beaufort_decrypt, "beau")]:
            # Sub then trans
            ct_sub = cipher_fn(CT, sub_shifts)
            pt_st = columnar_decrypt(ct_sub, read_order)
            sc = track(pt_st, f"p6_{cn}+col",
                      f"sub={kw_sub}, trans={kw_trans}")
            phase_best = max(phase_best, sc)
            n_tested += 1

            # Trans then sub
            pt_trans = columnar_decrypt(CT, read_order)
            pt_ts = cipher_fn(pt_trans, sub_shifts)
            sc = track(pt_ts, f"p6_col+{cn}",
                      f"trans={kw_trans}, sub={kw_sub}")
            phase_best = max(phase_best, sc)
            n_tested += 1

            # Double sub: both keywords as Vigenère keys concatenated
            combined_shifts = sub_shifts + keyword_to_shifts_az(kw_trans)
            pt_double = cipher_fn(CT, combined_shifts)
            sc = track(pt_double, f"p6_double_{cn}",
                      f"key={kw_sub}+{kw_trans}")
            phase_best = max(phase_best, sc)
            n_tested += 1

            # Interleaved: alternate shifts from each keyword
            interleaved = []
            for i in range(max(len(sub_shifts), len(keyword_to_shifts_az(kw_trans))) * 2):
                if i % 2 == 0:
                    interleaved.append(sub_shifts[(i // 2) % len(sub_shifts)])
                else:
                    trans_shifts = keyword_to_shifts_az(kw_trans)
                    interleaved.append(trans_shifts[(i // 2) % len(trans_shifts)])
            pt_interleaved = cipher_fn(CT, interleaved[:CT_LEN])
            sc = track(pt_interleaved, f"p6_interleaved_{cn}",
                      f"kw1={kw_sub}, kw2={kw_trans}")
            phase_best = max(phase_best, sc)
            n_tested += 1

            # XOR-combined: add both key shifts at each position
            shifts_a = sub_shifts
            shifts_b = keyword_to_shifts_az(kw_trans)
            xor_shifts = [(shifts_a[i % len(shifts_a)] + shifts_b[i % len(shifts_b)]) % MOD
                         for i in range(CT_LEN)]
            pt_xor = cipher_fn(CT, xor_shifts)
            sc = track(pt_xor, f"p6_addkeys_{cn}",
                      f"kw1={kw_sub}, kw2={kw_trans}")
            phase_best = max(phase_best, sc)
            n_tested += 1

    print(f"  Phase 6: {n_tested:,} configs, best={phase_best}/24")
    return n_tested, phase_best


# ── Phase 7: Route cipher in JUDGE-derived grids ───────────────────────

def phase7_route_cipher():
    """Route ciphers in grids derived from JUDGE parameters."""
    print()
    print("=" * 72)
    print("Phase 7: Route cipher in JUDGE-derived grids")
    print("=" * 72)

    n_tested = 0
    phase_best = 0

    # JUDGE = 5 letters. Grid dimensions related to JUDGE:
    # 5x20=100 (pad 3), 5x19=95 (truncate 2), etc.
    # Also career parameters: FBI director 1978-1987, CIA 1987-1991
    # FBI = 3 letters, CIA = 3 letters
    # Years: 78, 87, 91 -> grid widths

    grids = [
        (5, 20, "JUDGE_5x20"),
        (5, 19, "JUDGE_5x19"),
        (20, 5, "JUDGE_20x5"),
        (19, 5, "JUDGE_19x5"),
        (7, 14, "7x14"),
        (14, 7, "14x7"),
        (8, 13, "8x13"),
        (13, 8, "13x8"),
        (11, 9, "11x9"),
        (9, 11, "9x11"),
        (10, 10, "10x10"),
    ]

    for nrows, ncols, label in grids:
        if nrows * ncols < CT_LEN:
            continue

        # Write CT in different orders, read in different orders
        # Standard: write rows, read spiral
        for cw in [True, False]:
            # CT written in rows, read by spiral
            pt = route_cipher_spiral(CT, nrows, ncols, clockwise=cw)
            sc = track(pt, f"route_write_rows_read_spiral_{label}",
                      f"cw={cw}")
            phase_best = max(phase_best, sc)
            n_tested += 1

        # CT written in spiral, read rows
        # To "undo" spiral write: place CT in spiral order, read rows
        # Build reverse mapping
        positions = []
        top, bottom, left, right = 0, nrows - 1, 0, ncols - 1
        while top <= bottom and left <= right:
            for c in range(left, right + 1):
                positions.append((top, c))
            top += 1
            for r in range(top, bottom + 1):
                positions.append((r, right))
            right -= 1
            if top <= bottom:
                for c in range(right, left - 1, -1):
                    positions.append((bottom, c))
                bottom -= 1
            if left <= right:
                for r in range(bottom, top - 1, -1):
                    positions.append((r, left))
                left += 1

        if len(positions) >= CT_LEN:
            # Place CT in spiral positions
            grid = [['' for _ in range(ncols)] for _ in range(nrows)]
            for i in range(CT_LEN):
                r, c = positions[i]
                grid[r][c] = CT[i]
            # Read rows
            pt_rows = ''.join(grid[r][c] for r in range(nrows)
                             for c in range(ncols) if grid[r][c])[:CT_LEN]
            sc = track(pt_rows, f"route_write_spiral_read_rows_{label}", "")
            phase_best = max(phase_best, sc)
            n_tested += 1

        # Serpentine
        pt_serp = route_cipher_serpentine(CT, nrows, ncols)
        sc = track(pt_serp, f"route_serpentine_{label}", "")
        phase_best = max(phase_best, sc)
        n_tested += 1

        # Column serpentine
        pt_cserp = route_cipher_col_serpentine(CT, nrows, ncols)
        sc = track(pt_cserp, f"route_col_serp_{label}", "")
        phase_best = max(phase_best, sc)
        n_tested += 1

        # Route + JUDGE Vigenère
        judge_shifts = keyword_to_shifts_az("JUDGE")
        for route_fn, rn in [(route_cipher_spiral, "spiral"),
                              (route_cipher_serpentine, "serp")]:
            if rn == "spiral":
                transposed = route_fn(CT, nrows, ncols, clockwise=True)
            else:
                transposed = route_fn(CT, nrows, ncols)
            for cipher_fn, cn in [(vigenere_decrypt, "vig"),
                                   (beaufort_decrypt, "beau")]:
                # Route then Vig
                pt = cipher_fn(transposed, judge_shifts)
                sc = track(pt, f"route_{rn}+{cn}_JUDGE_{label}", "")
                phase_best = max(phase_best, sc)
                n_tested += 1

                # Vig then route
                ct_sub = cipher_fn(CT, judge_shifts)
                if rn == "spiral":
                    pt2 = route_fn(ct_sub, nrows, ncols, clockwise=True)
                else:
                    pt2 = route_fn(ct_sub, nrows, ncols)
                sc = track(pt2, f"{cn}_JUDGE+route_{rn}_{label}", "")
                phase_best = max(phase_best, sc)
                n_tested += 1

    print(f"  Phase 7: {n_tested:,} configs, best={phase_best}/24")
    return n_tested, phase_best


# ── Phase 8: Judicial/career parameters as cipher inputs ────────────────

def phase8_career_parameters():
    """Use Webster's career dates, positions, and judicial parameters."""
    print()
    print("=" * 72)
    print("Phase 8: Career parameters as cipher inputs")
    print("=" * 72)

    n_tested = 0
    phase_best = 0

    # William H. Webster career dates:
    # Born: March 6, 1924 (died May 26, 2025)
    # Federal judge: 1970-1973 (US District Court, Eastern Missouri)
    # Appellate judge: 1973-1978 (8th Circuit)
    # FBI Director: 1978-1987
    # CIA Director: 1987-1991
    # Kryptos dedicated: November 3, 1990

    # Numeric sequences from career
    numeric_keys = [
        ("year_born", [1, 9, 2, 4]),
        ("bday_030624", [0, 3, 0, 6, 2, 4]),
        ("bday_3624", [3, 6, 2, 4]),
        ("year_fbi_start", [1, 9, 7, 8]),
        ("year_cia_start", [1, 9, 8, 7]),
        ("year_cia_end", [1, 9, 9, 1]),
        ("year_kryptos", [1, 9, 9, 0]),
        ("kryptos_date", [1, 1, 0, 3, 9, 0]),  # Nov 3, 1990
        ("kryptos_date2", [1, 1, 3, 1, 9, 9, 0]),  # 11/3/1990
        ("circuit_8", [8]),
        ("fbi_cia_years", [7, 8, 8, 7, 8, 7, 9, 1]),  # 78-87, 87-91
        ("webster_years_service", [7, 8, 7, 3, 7, 0, 8, 7, 9, 1]),  # start years
        ("consecutive_roles", [1, 9, 7, 0, 1, 9, 7, 8, 1, 9, 8, 7]),  # judge->FBI->CIA
    ]

    for name, nums in numeric_keys:
        shifts = [(n % MOD) for n in nums]

        for cipher_fn, cn in [(vigenere_decrypt, "vig"),
                               (beaufort_decrypt, "beau")]:
            pt = cipher_fn(CT, shifts)
            sc = track(pt, f"p8_{cn}", f"key={name}, shifts={shifts}")
            phase_best = max(phase_best, sc)
            n_tested += 1

    # Federal judicial oath text as running key
    # "I do solemnly swear that I will administer justice without respect
    #  to persons and do equal right to the poor and to the rich..."
    oath_text = (
        "IDOSOLEMNLYSWEARTHATIWILLADMINISTERJUSTICEWITHOUT"
        "RESPECTTOPERSONSANDDOEQUALRIGHTTOTHEPOORANDTOTHERICH"
    )

    oath_shifts = [ALPH_IDX[c] for c in oath_text[:CT_LEN]]
    for cipher_fn, cn in [(vigenere_decrypt, "vig"),
                           (beaufort_decrypt, "beau")]:
        pt = cipher_fn(CT, oath_shifts)
        sc = track(pt, f"p8_oath_{cn}", "judicial oath running key")
        phase_best = max(phase_best, sc)
        n_tested += 1

    # CIA motto: "The Work of a Nation. The Center of Intelligence."
    cia_motto = "THEWORKOFANATIONTHECENTERFORINTELLIGENCE"
    motto_shifts = [ALPH_IDX[c] for c in cia_motto]
    for cipher_fn, cn in [(vigenere_decrypt, "vig"),
                           (beaufort_decrypt, "beau")]:
        pt = cipher_fn(CT, motto_shifts)
        sc = track(pt, f"p8_ciamotto_{cn}", "CIA motto running key")
        phase_best = max(phase_best, sc)
        n_tested += 1

    # Webster's confirmation/swearing-in dates as shift sequences
    # Confirmed as FBI director: Feb 23, 1978
    # Confirmed as CIA director: May 26, 1987
    date_shifts = [
        ("fbi_confirm", [2, 23, 19, 7, 8]),   # Feb 23 1978
        ("cia_confirm", [5, 26, 19, 8, 7]),    # May 26 1987
        ("both_confirms", [2, 23, 19, 7, 8, 5, 26, 19, 8, 7]),
    ]

    for name, shifts in date_shifts:
        mod_shifts = [(s % MOD) for s in shifts]
        for cipher_fn, cn in [(vigenere_decrypt, "vig"),
                               (beaufort_decrypt, "beau")]:
            pt = cipher_fn(CT, mod_shifts)
            sc = track(pt, f"p8_dates_{cn}", f"key={name}, shifts={mod_shifts}")
            phase_best = max(phase_best, sc)
            n_tested += 1

    # Combination: JUDGE + career number
    judge_shifts = keyword_to_shifts_az("JUDGE")
    for name, nums in numeric_keys:
        # Add career numbers to JUDGE key
        combined = [(judge_shifts[i % len(judge_shifts)] + nums[i % len(nums)]) % MOD
                    for i in range(CT_LEN)]
        pt = vigenere_decrypt(CT, combined)
        sc = track(pt, "p8_judge_plus_career", f"JUDGE+{name}")
        phase_best = max(phase_best, sc)
        n_tested += 1

    print(f"  Phase 8: {n_tested:,} configs, best={phase_best}/24")
    return n_tested, phase_best


# ── Phase 9: Block transposition with JUDGE permutation ─────────────────

def phase9_block_permutation():
    """Apply JUDGE-derived permutation in blocks across K4."""
    print()
    print("=" * 72)
    print("Phase 9: Block permutation with JUDGE ordering")
    print("=" * 72)

    n_tested = 0
    phase_best = 0

    # JUDGE column order: [2, 4, 3, 0, 1] (D=0, E=1, G=2, J=3, U=4)
    judge_perm = [2, 4, 3, 0, 1]
    judge_inv = invert_permutation(judge_perm)

    # Also try all 5! permutations explicitly related to JUDGE
    # J=3, U=4, D=0, G=2, E=1 (alphabetical ranks of JUDGE letters)
    judge_rank_perm = [3, 4, 0, 2, 1]

    perms_to_test = [
        ("judge_col_order", judge_perm),
        ("judge_col_inv", judge_inv),
        ("judge_rank", judge_rank_perm),
        ("judge_rank_inv", invert_permutation(judge_rank_perm)),
        ("identity", [0, 1, 2, 3, 4]),
        ("reverse", [4, 3, 2, 1, 0]),
    ]

    for pname, perm in perms_to_test:
        inv = invert_permutation(perm)

        # Apply permutation in blocks
        pt_fwd = apply_permutation(CT, perm)
        sc = track(pt_fwd, f"block_perm_{pname}", "forward")
        phase_best = max(phase_best, sc)
        n_tested += 1

        pt_inv = apply_permutation(CT, inv)
        sc = track(pt_inv, f"block_perm_{pname}_inv", "inverse")
        phase_best = max(phase_best, sc)
        n_tested += 1

        # Block perm + Vigenère with various keywords
        for kw in ["JUDGE", "KRYPTOS", "WEBSTER", "PALIMPSEST", "ABSCISSA"]:
            shifts = keyword_to_shifts_az(kw)

            for cipher_fn, cn in [(vigenere_decrypt, "vig"), (beaufort_decrypt, "beau")]:
                # Perm then sub
                pt = cipher_fn(pt_fwd, shifts)
                sc = track(pt, f"block_{pname}+{cn}", f"kw={kw}")
                phase_best = max(phase_best, sc)
                n_tested += 1

                # Sub then perm
                ct_sub = cipher_fn(CT, shifts)
                pt2 = apply_permutation(ct_sub, perm)
                sc = track(pt2, f"{cn}+block_{pname}", f"kw={kw}")
                phase_best = max(phase_best, sc)
                n_tested += 1

        # Double permutation: apply twice
        pt_double = apply_permutation(apply_permutation(CT, perm), perm)
        sc = track(pt_double, f"double_block_{pname}", "applied twice")
        phase_best = max(phase_best, sc)
        n_tested += 1

    # Multi-round: apply JUDGE perm N times
    judge_perm_main = judge_perm
    for rounds in range(3, 8):
        text = CT
        for _ in range(rounds):
            text = apply_permutation(text, judge_perm_main)
        sc = track(text, "multi_round_judge", f"rounds={rounds}")
        phase_best = max(phase_best, sc)
        n_tested += 1

    print(f"  Phase 9: {n_tested:,} configs, best={phase_best}/24")
    return n_tested, phase_best


# ── Phase 10: JUDGE + K3 ending as running key ─────────────────────────

def phase10_k3_continuation():
    """K3 ends mid-sentence. Use K3 plaintext ending + JUDGE as running key."""
    print()
    print("=" * 72)
    print("Phase 10: K3 continuation + JUDGE as running key")
    print("=" * 72)

    n_tested = 0
    phase_best = 0

    # K3 plaintext ends with:
    # "SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS THAT
    #  ENCUMBERED THE LOWER PART OF THE DOORWAY WAS REMOVED WITH
    #  TREMBLING HANDS I MADE A SMALL HOLE IN THE UPPER LEFT HAND
    #  CORNER AND THEN WIDENING THE HOLE A LITTLE I INSERTED THE
    #  CANDLE AND PEERED IN THE HOT AIR ESCAPING FROM THE CHAMBER
    #  CAUSED THE FLAME TO FLICKER BUT PRESENTLY DETAILS OF THE ROOM
    #  WITHIN EMERGED FROM THE MIST X CAN YOU SEE ANYTHING Q"
    # Last few words: "CANYYOUSEEANYTHINGQ" (? → Q)

    k3_ending = "CANYOUSEEANYTHINGQ"

    # What if K3's plaintext continues into K4 as a running key?
    # The text after "CAN YOU SEE ANYTHING?" in Tutankhamun discovery:
    # "Yes, wonderful things." (Howard Carter's response)
    continuation_texts = [
        ("carter_response", "YESWONDERFULTHINGS"),
        ("carter_full", "YESWONDERFULTHINGSATFIRSTICOULDSEENOTHINGTHETHOTAIRESCAPINGFROMTHECHAMBERCAUSINGTHECANDLE"),
        ("k3_tail_18", k3_ending),
        ("judge_repeat", "JUDGE" * 20),
        ("webster_repeat", "WEBSTER" * 14),
    ]

    for name, running_text in continuation_texts:
        shifts = [ALPH_IDX[c] for c in running_text[:CT_LEN]]
        # Pad if shorter than CT
        while len(shifts) < CT_LEN:
            shifts.append(shifts[len(shifts) % len(running_text)] if running_text else 0)

        for cipher_fn, cn in [(vigenere_decrypt, "vig"),
                               (beaufort_decrypt, "beau")]:
            pt = cipher_fn(CT, shifts[:CT_LEN])
            sc = track(pt, f"p10_{cn}_running", f"text={name}")
            phase_best = max(phase_best, sc)
            n_tested += 1

    # JUDGE prepended to K3 ending as combined running key
    combined_keys = [
        ("judge_k3end", "JUDGE" + k3_ending),
        ("k3end_judge", k3_ending + "JUDGE"),
        ("webster_k3end", "WEBSTER" + k3_ending),
        ("judge_carter", "JUDGE" + "YESWONDERFULTHINGS"),
    ]

    for name, key_text in combined_keys:
        shifts = [ALPH_IDX[c] for c in key_text]
        while len(shifts) < CT_LEN:
            shifts.append(shifts[len(shifts) % len(key_text)])

        for cipher_fn, cn in [(vigenere_decrypt, "vig"),
                               (beaufort_decrypt, "beau")]:
            pt = cipher_fn(CT, shifts[:CT_LEN])
            sc = track(pt, f"p10_{cn}_combined", f"key={name}")
            phase_best = max(phase_best, sc)
            n_tested += 1

    print(f"  Phase 10: {n_tested:,} configs, best={phase_best}/24")
    return n_tested, phase_best


# ── Phase 11: Polybius / ADFGX-like with JUDGE ─────────────────────────

def phase11_polybius_judge():
    """JUDGE as Polybius key — 5 letters = perfect for 5x5 square rows/cols.

    But K4 has all 26 letters, so standard 5x5 Polybius won't work.
    Test 6x5=30 (extended) and other variants.
    """
    print()
    print("=" * 72)
    print("Phase 11: JUDGE Polybius / fractionation variants")
    print("=" * 72)

    n_tested = 0
    phase_best = 0

    # Build a 5x6 Polybius square keyed by JUDGE
    # Use JUDGE as row/column headers for a 5x5+1 grid
    # Actually: use JUDGE to build a keyed alphabet for a Polybius square

    # Build keyed alphabet: JUDGE + remaining letters
    seen = set()
    keyed_alpha = []
    for c in "JUDGE":
        if c not in seen:
            keyed_alpha.append(c)
            seen.add(c)
    for c in ALPH:
        if c not in seen:
            keyed_alpha.append(c)
            seen.add(c)

    # For 6x5 grid (30 cells, 26 letters + 4 empty)
    # Map each letter to (row, col) pair
    letter_to_pos = {}
    for i, c in enumerate(keyed_alpha):
        row = i // 5
        col = i % 5
        letter_to_pos[c] = (row, col)

    # Polybius encoding: each letter -> two digits (row, col)
    # Then apply various reading orders to the digit pairs

    # Encode CT as digit pairs
    digits = []
    for c in CT:
        r, c_pos = letter_to_pos[c]
        digits.append(r)
        digits.append(c_pos)

    # Now try various "defractionation" approaches:
    # Read digits in different patterns and reconvert to letters

    # Standard: pairs are (d[0],d[1]), (d[2],d[3]), ...
    # Already the identity — skip

    # Columnar read: split digits into rows of width W, read columns
    for width in [5, 10, 14, 19, 97]:
        n_digits = len(digits)
        nrows_d = math.ceil(n_digits / width)

        # Write digits in rows of width, read columns
        cols_text = []
        for col in range(width):
            for row in range(nrows_d):
                idx = row * width + col
                if idx < n_digits:
                    cols_text.append(digits[idx])

        # Now pair up and decode
        if len(cols_text) >= 2 * CT_LEN:
            pt_chars = []
            for i in range(0, 2 * CT_LEN, 2):
                r, c = cols_text[i], cols_text[i + 1]
                idx = r * 5 + c
                if idx < len(keyed_alpha):
                    pt_chars.append(keyed_alpha[idx])
                else:
                    pt_chars.append('X')
            pt = ''.join(pt_chars)
            sc = track(pt, "polybius_col_read", f"width={width}")
            phase_best = max(phase_best, sc)
            n_tested += 1

    # Row-column swap: interpret as (col, row) instead of (row, col)
    pt_chars = []
    for i in range(0, 2 * CT_LEN, 2):
        r, c = digits[i + 1], digits[i]  # swapped
        idx = r * 5 + c
        if idx < len(keyed_alpha):
            pt_chars.append(keyed_alpha[idx])
        else:
            pt_chars.append('X')
    pt = ''.join(pt_chars)
    sc = track(pt, "polybius_swap_rc", "JUDGE keyed square")
    phase_best = max(phase_best, sc)
    n_tested += 1

    # Split-and-recombine: first half of digits = rows, second half = cols
    mid = len(digits) // 2
    rows_d = digits[:mid]
    cols_d = digits[mid:]
    if len(rows_d) == len(cols_d):
        pt_chars = []
        for i in range(min(len(rows_d), CT_LEN)):
            r, c = rows_d[i], cols_d[i]
            idx = r * 5 + c
            if idx < len(keyed_alpha):
                pt_chars.append(keyed_alpha[idx])
            else:
                pt_chars.append('X')
        pt = ''.join(pt_chars)
        sc = track(pt, "polybius_split_recombine", "JUDGE keyed")
        phase_best = max(phase_best, sc)
        n_tested += 1

    # ADFGX-style: use JUDGE as the column key for the digit transposition
    judge_col = [2, 4, 3, 0, 1]  # JUDGE columnar order
    for width in [5]:
        nrows_d = math.ceil(len(digits) / width)
        padded_digits = digits + [0] * (nrows_d * width - len(digits))

        # Write digits in grid, read by JUDGE column order
        grid_d = []
        for row in range(nrows_d):
            grid_d.append(padded_digits[row * width:(row + 1) * width])

        # Read columns in JUDGE order
        transposed_digits = []
        for col in judge_col:
            for row in range(nrows_d):
                transposed_digits.append(grid_d[row][col])

        if len(transposed_digits) >= 2 * CT_LEN:
            pt_chars = []
            for i in range(0, 2 * CT_LEN, 2):
                r, c = transposed_digits[i], transposed_digits[i + 1]
                idx = r * 5 + c
                if idx < len(keyed_alpha):
                    pt_chars.append(keyed_alpha[idx])
                else:
                    pt_chars.append('X')
            pt = ''.join(pt_chars)
            sc = track(pt, "adfgx_judge", f"width={width}")
            phase_best = max(phase_best, sc)
            n_tested += 1

    print(f"  Phase 11: {n_tested:,} configs, best={phase_best}/24")
    return n_tested, phase_best


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    global total_configs, best_results

    print("=" * 72)
    print("E-WEBSTER-02: Bespoke Webster/Judge-Themed Cipher Methods")
    print("=" * 72)
    print(f"CT: {CT}")
    print(f"CT_LEN: {CT_LEN}")
    print(f"JUDGE AZ shifts: {[ALPH_IDX[c] for c in 'JUDGE']}")
    print(f"JUDGE KA shifts: {[KA_IDX[c] for c in 'JUDGE']}")
    print(f"JUDGE col order: [2, 4, 3, 0, 1] (D=0, E=1, G=2, J=3, U=4)")

    t0 = time.time()

    n1, b1 = phase1_judge_columnar()
    n2, b2 = phase2_judge_shifts()
    n3, b3 = phase3_section_keyword_pattern()
    n4, b4 = phase4_judge_grid_transposition()
    n5, b5 = phase5_autokey()
    n6, b6 = phase6_two_keyword()
    n7, b7 = phase7_route_cipher()
    n8, b8 = phase8_career_parameters()
    n9, b9 = phase9_block_permutation()
    n10, b10 = phase10_k3_continuation()
    n11, b11 = phase11_polybius_judge()

    elapsed = time.time() - t0
    overall_best = max(b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11)

    # Summary
    print()
    print("=" * 72)
    print("FINAL SUMMARY")
    print("=" * 72)
    print(f"Total configurations tested: {total_configs:,}")
    print(f"Time: {elapsed:.1f}s")
    print(f"Overall best crib score: {overall_best}/24")
    print()

    phase_results = [
        ("Phase 1: JUDGE columnar transposition", n1, b1),
        ("Phase 2: JUDGE progressive shifts", n2, b2),
        ("Phase 3: K1-K3 keyword pattern", n3, b3),
        ("Phase 4: Grid rotational transposition", n4, b4),
        ("Phase 5: Autokey/progressive primer", n5, b5),
        ("Phase 6: Two-keyword combinations", n6, b6),
        ("Phase 7: Route cipher", n7, b7),
        ("Phase 8: Career parameters", n8, b8),
        ("Phase 9: Block permutation", n9, b9),
        ("Phase 10: K3 continuation running key", n10, b10),
        ("Phase 11: Polybius/fractionation", n11, b11),
    ]

    for label, n, b in phase_results:
        print(f"  {label}: {n:,} configs, best={b}/24")

    print()
    if best_results:
        # Sort by crib score descending
        best_results.sort(key=lambda x: -x["crib_score"])
        print(f"Top results (crib >= 3):")
        for r in best_results[:20]:
            print(f"  [{r['crib_score']}/24] {r['method']}: {r['detail']} | "
                  f"IC={r['ic']:.4f} | bean={'PASS' if r['bean_pass'] else 'FAIL'} | "
                  f"eq={r['bean_eq']}/1 ineq={r['bean_ineq']}/21")
            print(f"    PT: {r['pt_preview']}")
    else:
        print("No results scored >= 3 on crib matching.")

    print()
    if overall_best >= 24:
        print("*** BREAKTHROUGH: Full crib match! Investigate immediately. ***")
    elif overall_best >= 18:
        print("*** SIGNAL: Score >= 18. Worth deeper investigation. ***")
    elif overall_best >= 10:
        print("*** INTERESTING: Score >= 10. Log and review. ***")
    else:
        print("NOISE: All Webster/Judge bespoke methods produce noise-level scores.")
        print("No creative cipher method involving JUDGE, WEBSTER, or career")
        print("parameters yields meaningful crib alignment on K4.")

    # Save results
    os.makedirs("results/webster", exist_ok=True)
    output = {
        "experiment": "E-WEBSTER-02",
        "description": "Bespoke Webster/Judge-themed cipher methods on K4",
        "total_configs": total_configs,
        "elapsed_seconds": elapsed,
        "overall_best_crib": overall_best,
        "phases": {label: {"configs": n, "best_crib": b}
                   for label, n, b in phase_results},
        "top_results": best_results[:20],
    }
    outpath = "results/webster/e_webster_02_bespoke_methods.json"
    with open(outpath, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nResults saved to {outpath}")


if __name__ == "__main__":
    main()
