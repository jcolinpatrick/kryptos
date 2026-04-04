#!/usr/bin/env python3
"""
Cipher: multi-model
Family: analysis
Status: active
Keyspace: ~50M configs
Last run: 2026-04-04
Best score: TBD

PROCEDURAL ANOMALY ATTACKS: Deep exploitation of specific anomaly-derived
procedural models that go beyond simple running-key or keyword tests.

Attacks:
  P01: COMSEC T-column extraction — "T IS YOUR POSITION" means use column T
       of the tableau as the keystream, or start at position T=19
  P02: Self-referential key from tableau row/column selected by YAR values
  P03: Multi-width columnar chain: "4,8,10,26=Col" as sequential transpositions
  P04: Tableau diagonal/anti-diagonal as key with columnar pre-processing
  P05: "LAYER TWO" literal — decrypt K4 CT using K3 method (transposition)
       then decrypt result with K1/K2 method (Vigenère with KRYPTOS/ABSCISSA)
  P06: K3 rotation method applied to K4 (42×8 → rotate → read)
  P07: Width-21 de-interleave + substitution
  P08: Bean mod-5 exploitation: key values at crib positions have 13/24 as
       multiples of 5 under reversed KA. Test cipher with this constraint.
  P09: Stehle interval-4 difference-5 pattern extension
  P10: DRYAD-style column selection — treat sculpture rows as a DRYAD table

Usage: PYTHONPATH=src python3 -u scripts/analysis/e_procedural_anomaly_attacks.py
"""

import sys
import os
import json
import time
import itertools
from collections import Counter
from multiprocessing import Pool, cpu_count
from typing import List, Dict, Tuple

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, N_CRIBS, NOISE_FLOOR, STORE_THRESHOLD,
    BEAN_EQ,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, vig_decrypt, beau_decrypt, varbeau_decrypt,
)

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
KA_REV = KA[::-1]  # Reversed Kryptos alphabet
KA_REV_IDX = {c: i for i, c in enumerate(KA_REV)}

CT_NUMS = [ALPH_IDX[c] for c in CT]
CT_KA = [KA_IDX[c] for c in CT]

CRIB_POS = sorted(CRIB_DICT.keys())
VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

best_score = 0
results = []

def log_hit(attack: str, score: int, pt: str, method: str):
    global best_score
    results.append({"attack": attack, "score": score, "pt": pt[:60], "method": method})
    if score > best_score:
        best_score = score
        print(f"  *** NEW BEST: {score}/{N_CRIBS} | {attack} | {method}")
        print(f"      PT: {pt[:70]}")

def decrypt_with_key(ct_nums, key_nums, variant):
    dfn = {CipherVariant.VIGENERE: vig_decrypt,
           CipherVariant.BEAUFORT: beau_decrypt,
           CipherVariant.VAR_BEAUFORT: varbeau_decrypt}[variant]
    pt_nums = [dfn(ct_nums[i], key_nums[i]) for i in range(len(ct_nums))]
    pt = "".join(ALPH[n] for n in pt_nums)
    return pt


# ══════════════════════════════════════════════════════════════════════════════
# P01: COMSEC T-column extraction
# ══════════════════════════════════════════════════════════════════════════════

def attack_P01():
    """'T IS YOUR POSITION' — use column T of the KA tableau as keystream."""
    print("\n[P01] COMSEC T-column extraction...")
    count = 0

    # Build KA tableau
    tableau = []
    for r in range(26):
        row = [KA[(r + c) % 26] for c in range(26)]
        tableau.append(row)

    # T = position 19 in A=0 (or position 8 in KA since T is at index 8 in KRYPTOS alphabet)
    t_az = ALPH_IDX['T']  # = 19
    t_ka = KA_IDX['T']    # position of T in KRYPTOS alphabet

    # Method A: Read column T (AZ index 19) of the AZ Vigenere tableau
    for col_idx in [t_az, t_ka]:
        key_col = [ALPH[(r + col_idx) % 26] for r in range(26)]
        # Use this column cyclically as key
        key_nums = [ALPH_IDX[key_col[i % 26]] for i in range(CT_LEN)]
        for variant in VARIANTS:
            pt = decrypt_with_key(CT_NUMS, key_nums, variant)
            sc = score_cribs(pt)
            if sc >= NOISE_FLOOR:
                log_hit("P01", sc, pt, f"col_T_idx{col_idx}_{variant.value}")
            count += 1

    # Method B: Read column T of the KA tableau
    for col_idx in [t_az, t_ka]:
        key_col = [KA_IDX[KA[(r + col_idx) % 26]] for r in range(26)]
        key_nums = [key_col[i % 26] for i in range(CT_LEN)]
        for variant in VARIANTS:
            pt = decrypt_with_key(CT_NUMS, key_nums, variant)
            sc = score_cribs(pt)
            if sc >= NOISE_FLOOR:
                log_hit("P01", sc, pt, f"KA_col_T_idx{col_idx}_{variant.value}")
            count += 1

    # Method C: Use position 19 as a starting row, read rows sequentially
    for start_row in range(26):
        key_nums = []
        for i in range(CT_LEN):
            row = (start_row + i // 26) % 26
            col = i % 26
            key_nums.append(ALPH_IDX[KA[(row + col) % 26]])
        for variant in VARIANTS:
            pt = decrypt_with_key(CT_NUMS, key_nums, variant)
            sc = score_cribs(pt)
            if sc >= NOISE_FLOOR:
                log_hit("P01", sc, pt, f"row_start{start_row}_{variant.value}")
            count += 1

    # Method D: "T is your position" = start keystream at position T=19 of the
    # tableau read as one long string (676 chars starting from pos 19*26)
    tab_flat = "".join("".join(row) for row in tableau)
    for start in range(0, 676 - CT_LEN):
        key_str = tab_flat[start:start + CT_LEN]
        key_nums = [ALPH_IDX[c] for c in key_str]
        for variant in VARIANTS:
            pt = decrypt_with_key(CT_NUMS, key_nums, variant)
            sc = score_cribs(pt)
            if sc >= NOISE_FLOOR:
                log_hit("P01", sc, pt, f"tab_flat_start{start}_{variant.value}")
            count += 1

    print(f"  P01 complete: {count:,} configs")


# ══════════════════════════════════════════════════════════════════════════════
# P02: YAR-selected tableau rows/columns as key
# ══════════════════════════════════════════════════════════════════════════════

def attack_P02():
    """Use YAR numeric values to select specific tableau rows/columns as key."""
    print("\n[P02] YAR-selected tableau key extraction...")
    count = 0

    # Y=24, A=0, R=17
    # D=3, Y=24, A=0, H=7, R=17
    yar_values = [24, 0, 17]
    dyahr_values = [3, 24, 0, 7, 17]

    # Build KA tableau
    tableau = []
    for r in range(26):
        row = "".join(KA[(r + c) % 26] for c in range(26))
        tableau.append(row)

    for param_name, params in [("YAR", yar_values), ("DYAHR", dyahr_values)]:
        # Method A: Concatenate rows at these indices
        key_text = "".join(tableau[p % 26] for p in params)
        key_nums = [ALPH_IDX[c] for c in key_text]
        key_ext = (key_nums * ((CT_LEN // len(key_nums)) + 1))[:CT_LEN]
        for variant in VARIANTS:
            pt = decrypt_with_key(CT_NUMS, key_ext, variant)
            sc = score_cribs(pt)
            if sc >= NOISE_FLOOR:
                log_hit("P02", sc, pt, f"{param_name}_rows_{variant.value}")
            count += 1

        # Method B: Concatenate columns at these indices
        key_text = ""
        for p in params:
            col = "".join(tableau[r][p % 26] for r in range(26))
            key_text += col
        key_nums = [ALPH_IDX[c] for c in key_text]
        key_ext = (key_nums * ((CT_LEN // len(key_nums)) + 1))[:CT_LEN]
        for variant in VARIANTS:
            pt = decrypt_with_key(CT_NUMS, key_ext, variant)
            sc = score_cribs(pt)
            if sc >= NOISE_FLOOR:
                log_hit("P02", sc, pt, f"{param_name}_cols_{variant.value}")
            count += 1

        # Method C: Use values as progressive key offsets
        # Key[i] = (params[i % len(params)] * (i // len(params) + 1)) % 26
        for multiplier in range(1, 26):
            key_nums = [(params[i % len(params)] * multiplier + i) % 26
                        for i in range(CT_LEN)]
            for variant in VARIANTS:
                pt = decrypt_with_key(CT_NUMS, key_nums, variant)
                sc = score_cribs(pt)
                if sc >= NOISE_FLOOR:
                    log_hit("P02", sc, pt,
                            f"{param_name}_prog_mult{multiplier}_{variant.value}")
                count += 1

    print(f"  P02 complete: {count:,} configs")


# ══════════════════════════════════════════════════════════════════════════════
# P03: Multi-width columnar chain: "4,8,10,26=Col"
# ══════════════════════════════════════════════════════════════════════════════

def attack_P03():
    """Test sequential columnar transpositions at widths 4,8,10,26."""
    print("\n[P03] Multi-width columnar chain (4,8,10,26)...")
    count = 0

    def columnar_read(text: str, width: int) -> str:
        """Read text column-by-column from a grid of given width."""
        nrows = (len(text) + width - 1) // width
        result = []
        for c in range(width):
            for r in range(nrows):
                idx = r * width + c
                if idx < len(text):
                    result.append(text[idx])
        return "".join(result)

    def columnar_unread(text: str, width: int) -> str:
        """Inverse of columnar_read: given col-read output, reconstruct row-read."""
        n = len(text)
        nrows = (n + width - 1) // width
        full_cols = n - width * (nrows - 1)  # number of columns with nrows chars
        # Place chars back into columns
        cols = []
        pos = 0
        for c in range(width):
            clen = nrows if c < full_cols else nrows - 1
            cols.append(text[pos:pos + clen])
            pos += clen
        # Read row by row
        result = []
        for r in range(nrows):
            for c in range(width):
                if r < len(cols[c]):
                    result.append(cols[c][r])
        return "".join(result)

    widths = [4, 8, 10, 26]

    # Test all permutations of 1-4 sequential columnar operations
    for n_ops in range(1, 5):
        for width_combo in itertools.permutations(widths, n_ops):
            # Apply sequential columnar reads
            text = CT
            for w in width_combo:
                text = columnar_unread(text, w)

            sc = score_cribs(text)
            if sc >= NOISE_FLOOR:
                log_hit("P03", sc, text,
                        f"chain_{'_'.join(str(w) for w in width_combo)}_unread")
            count += 1

            # Also try read direction
            text = CT
            for w in width_combo:
                text = columnar_read(text, w)
            sc = score_cribs(text)
            if sc >= NOISE_FLOOR:
                log_hit("P03", sc, text,
                        f"chain_{'_'.join(str(w) for w in width_combo)}_read")
            count += 1

    # Also test with keyword decrypt after each transposition chain
    for width_combo in itertools.permutations(widths, 2):
        text = CT
        for w in width_combo:
            text = columnar_unread(text, w)
        text_nums = [ALPH_IDX[c] for c in text]

        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "POINT", "SECRET"]:
            key = [ALPH_IDX[c] for c in kw]
            key_ext = (key * ((CT_LEN // len(key)) + 1))[:CT_LEN]
            for variant in VARIANTS:
                pt = decrypt_with_key(text_nums, key_ext, variant)
                sc = score_cribs(pt)
                if sc >= NOISE_FLOOR:
                    log_hit("P03", sc, pt,
                            f"chain_{'_'.join(str(w) for w in width_combo)}_then_{kw}_{variant.value}")
                count += 1

    print(f"  P03 complete: {count:,} configs")


# ══════════════════════════════════════════════════════════════════════════════
# P05: "LAYER TWO" literal — K3 method then K1/K2 method
# ══════════════════════════════════════════════════════════════════════════════

def attack_P05():
    """'LAYER TWO' = apply K3 transposition, then K1/K2 Vigenère with known keywords."""
    print("\n[P05] LAYER TWO: K3 transposition then K1/K2 Vigenère...")
    count = 0

    # K3 was encoded by rotation: write in 42×8 grid, rotate 90° CW, read.
    # To DECODE: reverse the process.
    # For K4 (97 chars), test various grid dimensions.

    grid_dims = [
        (97, 1), (1, 97),  # trivial
        (7, 14), (14, 7),
        (8, 13), (13, 8),  # close to 97 = 8*12+1
        (4, 25), (25, 4),  # 4*24+1
        (3, 33), (33, 3),  # "3 Lines 93" + 4
        (11, 9), (9, 11),  # 11*9 = 99 close
    ]

    def rotate_90_cw(text, rows, cols):
        """Write text in rows×cols grid, rotate 90° CW, read row-by-row."""
        grid = []
        idx = 0
        for r in range(rows):
            row = []
            for c in range(cols):
                if idx < len(text):
                    row.append(text[idx])
                    idx += 1
                else:
                    row.append('X')
            grid.append(row)
        # Rotate: new grid is cols×rows, new[c][rows-1-r] = old[r][c]
        result = []
        for c in range(cols):
            for r in range(rows - 1, -1, -1):
                result.append(grid[r][c])
        return "".join(result[:len(text)])

    def rotate_90_ccw(text, rows, cols):
        """Write text in rows×cols grid, rotate 90° CCW, read row-by-row."""
        grid = []
        idx = 0
        for r in range(rows):
            row = []
            for c in range(cols):
                if idx < len(text):
                    row.append(text[idx])
                    idx += 1
                else:
                    row.append('X')
            grid.append(row)
        # Rotate CCW: new[cols-1-c][r] = old[r][c]
        result = []
        for c in range(cols - 1, -1, -1):
            for r in range(rows):
                result.append(grid[r][c])
        return "".join(result[:len(text)])

    keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "POINT", "SECRET",
                "SEVEN", "SHADOW", "BERLIN"]

    for rows, cols in grid_dims:
        if rows * cols < CT_LEN:
            continue

        # Step 1: Undo rotation (try both CW and CCW)
        for rot_fn, rot_name in [(rotate_90_cw, "cw"), (rotate_90_ccw, "ccw")]:
            intermediate = rot_fn(CT, rows, cols)

            # Score directly (pure transposition)
            sc = score_cribs(intermediate)
            if sc >= NOISE_FLOOR:
                log_hit("P05", sc, intermediate,
                        f"rot_{rot_name}_{rows}x{cols}_direct")
            count += 1

            # Step 2: Apply Vigenère decrypt with each keyword
            int_nums = [ALPH_IDX[c] for c in intermediate[:CT_LEN]]
            for kw in keywords:
                key = [ALPH_IDX[c] for c in kw]
                key_ext = (key * ((CT_LEN // len(key)) + 1))[:CT_LEN]
                for variant in VARIANTS:
                    pt = decrypt_with_key(int_nums, key_ext, variant)
                    sc = score_cribs(pt)
                    if sc >= NOISE_FLOOR:
                        log_hit("P05", sc, pt,
                                f"rot_{rot_name}_{rows}x{cols}_then_{kw}_{variant.value}")
                    count += 1

            # Also try double rotation
            for rows2, cols2 in [(cols, rows)]:
                double = rot_fn(intermediate, rows2, cols2)
                sc = score_cribs(double[:CT_LEN])
                if sc >= NOISE_FLOOR:
                    log_hit("P05", sc, double[:CT_LEN],
                            f"double_rot_{rot_name}_{rows}x{cols}")
                count += 1

    print(f"  P05 complete: {count:,} configs")


# ══════════════════════════════════════════════════════════════════════════════
# P07: Width-21 de-interleave + substitution
# ══════════════════════════════════════════════════════════════════════════════

def attack_P07():
    """Width-21 is the strongest statistical anomaly. Test de-interleaving."""
    print("\n[P07] Width-21 de-interleave + substitution...")
    count = 0

    # Write K4 at width 21: 4 full rows + 1 partial (97 = 4*21 + 13)
    width = 21
    nrows = (CT_LEN + width - 1) // width  # = 5

    # De-interleave: read every 21st character starting from each position
    for start_col in range(width):
        # Extract characters at positions start_col, start_col+21, start_col+42, ...
        extracted = [CT[start_col + i * width]
                     for i in range(nrows)
                     if start_col + i * width < CT_LEN]
        # These form one "column" of the width-21 grid

    # Full column extraction (all 21 columns)
    columns = []
    for c in range(width):
        col = [CT[c + r * width] for r in range(nrows) if c + r * width < CT_LEN]
        columns.append("".join(col))

    # Read columns in various orders
    # Standard column order
    col_text = "".join(columns)
    sc = score_cribs(col_text + "X" * (CT_LEN - len(col_text)))
    count += 1

    # Try all keyword-derived column orderings
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "POINT", "SECRET", "SEVEN"]:
        if len(kw) < width:
            # Pad keyword to width
            kw_padded = kw + ALPH[:width - len(kw)]
        else:
            kw_padded = kw[:width]
        order = sorted(range(width), key=lambda i: kw_padded[i])

        reordered = "".join(columns[order[i]] for i in range(width) if order[i] < len(columns))
        if len(reordered) >= CT_LEN:
            reordered = reordered[:CT_LEN]
        else:
            reordered += "X" * (CT_LEN - len(reordered))

        sc = score_cribs(reordered)
        if sc >= NOISE_FLOOR:
            log_hit("P07", sc, reordered, f"w21_colorder_{kw}")
        count += 1

        # Then apply substitution
        reord_nums = [ALPH_IDX[c] for c in reordered[:CT_LEN]]
        for sub_kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            sub_key = [ALPH_IDX[c] for c in sub_kw]
            sub_ext = (sub_key * ((CT_LEN // len(sub_key)) + 1))[:CT_LEN]
            for variant in VARIANTS:
                pt = decrypt_with_key(reord_nums, sub_ext, variant)
                sc = score_cribs(pt)
                if sc >= NOISE_FLOOR:
                    log_hit("P07", sc, pt,
                            f"w21_{kw}_then_{sub_kw}_{variant.value}")
                count += 1

    print(f"  P07 complete: {count:,} configs")


# ══════════════════════════════════════════════════════════════════════════════
# P08: Bean mod-5 exploitation
# ══════════════════════════════════════════════════════════════════════════════

def attack_P08():
    """Exploit Bean's mod-5 pattern with reversed KA alphabet."""
    print("\n[P08] Bean mod-5 exploitation (reversed KA)...")
    count = 0

    # Under reversed KA: 13/24 crib keystream values are multiples of 5
    # This suggests the cipher operates with a base-5 component

    # Compute known keystream under reversed KA
    known_ks = {}
    for pos, pt_ch in CRIB_DICT.items():
        ct_val = KA_REV_IDX.get(CT[pos], ALPH_IDX[CT[pos]])
        pt_val = ALPH_IDX[pt_ch]
        # Try all three variants
        known_ks[pos] = {
            'vig': (ct_val - pt_val) % 26,
            'beau': (ct_val + pt_val) % 26,
            'vbeau': (pt_val - ct_val) % 26,
        }

    # For Beaufort (most promising): check which crib positions have k%5==0
    for var_name in ['vig', 'beau', 'vbeau']:
        mod5_positions = [pos for pos in CRIB_POS
                          if known_ks[pos][var_name] % 5 == 0]
        non_mod5 = [pos for pos in CRIB_POS
                    if known_ks[pos][var_name] % 5 != 0]

        # Build keystream assuming mod-5 pattern holds everywhere
        # Key at position i = 5 * f(i) for some function f
        # Test: f(i) = i mod 5, i mod 6, i div 5, etc.
        for period in range(1, 26):
            for base in range(5):
                key_nums = [(5 * ((i * period + base) % 6)) % 26
                            for i in range(CT_LEN)]
                ct_rev_ka = [KA_REV_IDX.get(c, ALPH_IDX[c]) for c in CT]
                dfn = {'vig': vig_decrypt, 'beau': beau_decrypt,
                       'vbeau': varbeau_decrypt}[var_name]
                pt_nums = [dfn(ct_rev_ka[i], key_nums[i]) for i in range(CT_LEN)]
                pt = "".join(KA_REV[n % 26] for n in pt_nums)
                sc = score_cribs(pt)
                if sc >= NOISE_FLOOR:
                    log_hit("P08", sc, pt,
                            f"mod5_{var_name}_period{period}_base{base}")
                count += 1

    print(f"  P08 complete: {count:,} configs")


# ══════════════════════════════════════════════════════════════════════════════
# P09: Stehle interval-4 difference-5 extension
# ══════════════════════════════════════════════════════════════════════════════

def attack_P09():
    """Extend Stehle's observation: every 4th character differs by 5 in positions 55-63.
    What if this pattern extends to the full CT with a structured keystream?"""
    print("\n[P09] Stehle interval-4 difference-5 extension...")
    count = 0

    # Stehle: CT[i+4] - CT[i] = 5 (mod 26) for i in 55..59
    # If the keystream has K[i+4] - K[i] = constant, this implies a linear recurrence

    # Test: keystream is K[i] = (a*i + b) mod 26 with (a*4) mod 26 = 5
    # 4a ≡ 5 (mod 26) → a ≡ 5 * 4^(-1) (mod 26)
    # 4^(-1) mod 26: 4*20 = 80 ≡ 2 (mod 26)... try 4*7=28≡2, no.
    # Actually gcd(4,26)=2, 2|5 is false → no solution exists for 4a≡5(mod 26)
    # So the constant-difference property can't come from a simple linear key

    # Try: keystream with period 4 that has specific differences
    # K[i] = base + (i%4) * step, for various base, step
    for step in range(26):
        for base in range(26):
            key_nums = [(base + (i % 4) * step) % 26 for i in range(CT_LEN)]
            for variant in VARIANTS:
                dfn = {CipherVariant.VIGENERE: vig_decrypt,
                       CipherVariant.BEAUFORT: beau_decrypt,
                       CipherVariant.VAR_BEAUFORT: varbeau_decrypt}[variant]
                pt_nums = [dfn(CT_NUMS[i], key_nums[i]) for i in range(CT_LEN)]
                pt = "".join(ALPH[n] for n in pt_nums)
                sc = score_cribs(pt)
                if sc >= NOISE_FLOOR:
                    log_hit("P09", sc, pt,
                            f"period4_step{step}_base{base}_{variant.value}")
                count += 1

    # Also try period-4 with independent values
    # This is 26^4 ≈ 456K per variant × 3 = 1.4M — manageable
    for k0 in range(26):
        for k1 in range(26):
            for k2 in range(26):
                for k3 in range(26):
                    key_cycle = [k0, k1, k2, k3]
                    key_nums = [key_cycle[i % 4] for i in range(CT_LEN)]
                    # Only test Beaufort (strongest anomaly support)
                    pt_nums = [beau_decrypt(CT_NUMS[i], key_nums[i])
                               for i in range(CT_LEN)]
                    pt = "".join(ALPH[n] for n in pt_nums)
                    sc = score_cribs(pt)
                    if sc >= NOISE_FLOOR:
                        log_hit("P09", sc, pt,
                                f"period4_free_{k0}_{k1}_{k2}_{k3}_beau")
                    count += 1
                    if count % 100000 == 0:
                        print(f"    P09 progress: {count:,}...")

    print(f"  P09 complete: {count:,} configs")


# ══════════════════════════════════════════════════════════════════════════════
# P10: DRYAD-style column selection
# ══════════════════════════════════════════════════════════════════════════════

def attack_P10():
    """Treat the KA tableau as a DRYAD table. Use anomaly-derived row/column
    selectors to extract a keystream."""
    print("\n[P10] DRYAD-style tableau column selection...")
    count = 0

    # DRYAD: a one-time matrix with 26 rows (keyed by call sign) × 10 columns
    # Operator reads a row and column to get a substitution character
    # For Kryptos: the tableau IS the DRYAD matrix

    # "T IS YOUR POSITION" = use row T as the call sign
    # Then each CT character selects a column → read the intersection

    # Build KA tableau
    tab = {}
    for r in range(26):
        for c in range(26):
            tab[(r, c)] = KA[(r + c) % 26]

    # Method: For each CT character, look up in row T_idx
    for t_idx in range(26):
        pt_chars = []
        for i in range(CT_LEN):
            ct_col = ALPH_IDX[CT[i]]
            pt_ch = tab[(t_idx, ct_col)]
            pt_chars.append(pt_ch)
        pt = "".join(pt_chars)
        sc = score_cribs(pt)
        if sc >= NOISE_FLOOR:
            log_hit("P10", sc, pt, f"DRYAD_row{t_idx}")
        count += 1

        # Also: CT character selects the ROW, fixed column
        pt_chars2 = []
        for i in range(CT_LEN):
            ct_row = ALPH_IDX[CT[i]]
            pt_ch = tab[(ct_row, t_idx)]
            pt_chars2.append(pt_ch)
        pt2 = "".join(pt_chars2)
        sc2 = score_cribs(pt2)
        if sc2 >= NOISE_FLOOR:
            log_hit("P10", sc2, pt2, f"DRYAD_col{t_idx}")
        count += 1

    # Method: Progressive row selection — row shifts by 1 for each character
    for start in range(26):
        pt_chars = []
        for i in range(CT_LEN):
            row = (start + i) % 26
            col = ALPH_IDX[CT[i]]
            pt_chars.append(tab[(row, col)])
        pt = "".join(pt_chars)
        sc = score_cribs(pt)
        if sc >= NOISE_FLOOR:
            log_hit("P10", sc, pt, f"DRYAD_progressive_start{start}")
        count += 1

    # Method: Row = CT[i], Col = position i mod 26 (tableau lookup)
    for offset in range(26):
        pt_chars = []
        for i in range(CT_LEN):
            row = ALPH_IDX[CT[i]]
            col = (i + offset) % 26
            pt_chars.append(tab[(row, col)])
        pt = "".join(pt_chars)
        sc = score_cribs(pt)
        if sc >= NOISE_FLOOR:
            log_hit("P10", sc, pt, f"DRYAD_posmod26_offset{offset}")
        count += 1

    print(f"  P10 complete: {count:,} configs")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    start = time.time()
    print("=" * 80)
    print("PROCEDURAL ANOMALY ATTACKS")
    print("=" * 80)

    attacks = [
        attack_P01,
        attack_P02,
        attack_P03,
        attack_P05,
        attack_P07,
        attack_P08,
        attack_P10,
        # P09 is the heavy one — period-4 exhaustive
        attack_P09,
    ]

    for fn in attacks:
        try:
            fn()
        except Exception as e:
            print(f"  ERROR in {fn.__name__}: {e}")
            import traceback
            traceback.print_exc()

    elapsed = time.time() - start

    print("\n" + "=" * 80)
    print(f"PROCEDURAL ATTACKS COMPLETE — {elapsed:.1f}s")
    print(f"Results above noise ({NOISE_FLOOR}): {len(results)}")
    print("=" * 80)

    if results:
        print("\nAll hits:")
        for r in sorted(results, key=lambda x: -x['score']):
            print(f"  Score {r['score']:2d} | {r['attack']} | {r['method']}")
            print(f"           PT: {r['pt']}")

    # Save
    out_path = os.path.join(_ROOT, "results", "procedural_anomaly_attacks.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "elapsed_seconds": elapsed,
            "best_score": best_score,
            "total_hits": len(results),
            "results": results,
        }, f, indent=2)
    print(f"\nResults: {out_path}")


if __name__ == "__main__":
    main()
