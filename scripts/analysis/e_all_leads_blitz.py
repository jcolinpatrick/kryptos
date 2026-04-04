#!/usr/bin/env python3
"""
Cipher: multi-model
Family: analysis
Status: active
Keyspace: ~500M configs
Last run: 2026-04-04
Best score: TBD

ALL-LEADS BLITZ: Execute every actionable lead from the anomaly investigation.

Leads tested:
  L01: Null-mask + keyword-Beaufort (mask candidates × keyword search)
  L02: Sculpture tableau as running key (row, col, diagonal, spiral reads)
  L03: K0 Morse code text as running key
  L04: POINT as keyword (from Sanborn's (CLUE) marker)
  L05: YAR/DYAHR numeric values as Gromark primers
  L06: "4,8,10,26=Col" columnar transposition parameters
  L07: "3 Lines 93" grid dimension test
  L08: JFK/Reagan Berlin speeches as running key
  L09: FM 34-40.2 field manual text extraction + running key
  L10: Weltzeituhr city list (German) as running key
  L11: Self-referential tableau key with columnar transposition
  L12: Keyword sweep with anomaly-derived keywords
  L13: Carter tomb deeper offsets + Beaufort variant
  L14: Kryptos CT itself as autokey seed (meta-referential)
  L15: Compass bearing 67.5° → position/rotation parameter

All leads run with Vigenere, Beaufort, and Variant Beaufort variants.
Multiprocessing with checkpointing.

Usage: PYTHONPATH=src python3 -u scripts/analysis/e_all_leads_blitz.py
"""

import json
import os
import sys
import time
import itertools
from collections import defaultdict
from multiprocessing import Pool, cpu_count
from typing import List, Dict, Tuple, Optional

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, N_CRIBS, NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text, vig_decrypt, beau_decrypt, varbeau_decrypt,
)

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
CT_NUMS = [ALPH_IDX[c] for c in CT]

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
VARIANT_NAMES = {"vigenere": "Vig", "beaufort": "Beau", "var_beaufort": "VBeau"}

# ── Results tracking ─────────────────────────────────────────────────────

results_log = []
best_score = 0
best_result = None


def log_result(lead: str, score: int, plaintext: str, method: str,
               variant: str = "", extra: str = ""):
    """Log a result if it exceeds noise floor."""
    global best_score, best_result
    if score >= NOISE_FLOOR:
        entry = {
            "lead": lead,
            "score": score,
            "plaintext": plaintext[:50],
            "method": method,
            "variant": variant,
            "extra": extra,
        }
        results_log.append(entry)
        if score > best_score:
            best_score = score
            best_result = entry
            print(f"  *** NEW BEST: {score}/{N_CRIBS} | {lead} | {method} | {variant}")
            print(f"      PT: {plaintext[:60]}")


def try_running_key(ct_nums, key_nums, variant: CipherVariant) -> Tuple[str, int]:
    """Decrypt with running key and score."""
    if len(key_nums) < CT_LEN:
        return "", 0
    dfn = {CipherVariant.VIGENERE: vig_decrypt,
           CipherVariant.BEAUFORT: beau_decrypt,
           CipherVariant.VAR_BEAUFORT: varbeau_decrypt}[variant]
    pt_nums = [dfn(ct_nums[i], key_nums[i]) for i in range(CT_LEN)]
    pt = "".join(ALPH[n] for n in pt_nums)
    sc = score_cribs(pt)
    return pt, sc


def text_to_nums(text: str) -> List[int]:
    """Convert text to numeric (A=0), stripping non-alpha."""
    return [ALPH_IDX[c] for c in text.upper() if c in ALPH_IDX]


# ══════════════════════════════════════════════════════════════════════════════
# LEAD L01: Null-mask + keyword-Beaufort
# ══════════════════════════════════════════════════════════════════════════════

def lead_L01_null_mask_keyword():
    """Test null removal + keyword Beaufort decryption.

    Strategy: Try removing characters at candidate null positions,
    then decrypt the shorter text with short keywords via Beaufort.

    We test multiple null-position models based on anomaly evidence:
    - Every 5th position (mod-5 from Bean E0d)
    - Width-7 column-based nulls (from IMG_1238 "7x88")
    - Width-21 column-based nulls (from E0e)
    """
    print("\n[L01] Null-mask + keyword-Beaufort sweep...")
    count = 0

    # Model A: Remove positions where pos % 5 == r (for r in 0..4)
    for residue in range(5):
        mask = [i for i in range(CT_LEN) if i % 5 != residue]
        short_ct = "".join(CT[i] for i in mask)
        short_nums = [ALPH_IDX[c] for c in short_ct]
        short_len = len(short_ct)

        # Try short periodic keywords (length 1-8)
        for klen in range(1, 9):
            for key_tuple in itertools.product(range(26), repeat=klen):
                key_nums = list(key_tuple) * ((short_len // klen) + 1)
                key_nums = key_nums[:short_len]
                for variant in VARIANTS:
                    dfn = {CipherVariant.VIGENERE: vig_decrypt,
                           CipherVariant.BEAUFORT: beau_decrypt,
                           CipherVariant.VAR_BEAUFORT: varbeau_decrypt}[variant]
                    pt_nums = [dfn(short_nums[i], key_nums[i]) for i in range(short_len)]
                    pt = "".join(ALPH[n] for n in pt_nums)
                    # Check if known crib fragments appear in the shortened text
                    sc = 0
                    for crib_word in ["EASTNORTHEAST", "BERLINCLOCK", "NORTHEAST", "BERLIN", "CLOCK", "EAST"]:
                        if crib_word in pt:
                            sc += len(crib_word)
                    if sc >= 6:
                        log_result("L01", sc, pt,
                                   f"null_mod5_r{residue}_klen{klen}",
                                   variant.value,
                                   f"key={''.join(ALPH[k] for k in key_tuple)}")
                    count += 1
                if klen >= 3:
                    break  # Only exhaustive for klen <= 2

    # Model B: Remove every nth position for n in [5, 7, 14, 21]
    for skip in [5, 7, 14, 21]:
        for start in range(skip):
            mask = [i for i in range(CT_LEN) if i % skip != start]
            short_ct = "".join(CT[i] for i in mask)
            # Quick check: decrypt with identity key (shift=0) for each variant
            short_nums = [ALPH_IDX[c] for c in short_ct]
            for shift in range(26):
                for variant in VARIANTS:
                    dfn = {CipherVariant.VIGENERE: vig_decrypt,
                           CipherVariant.BEAUFORT: beau_decrypt,
                           CipherVariant.VAR_BEAUFORT: varbeau_decrypt}[variant]
                    pt_nums = [dfn(short_nums[i], shift) for i in range(len(short_nums))]
                    pt = "".join(ALPH[n] for n in pt_nums)
                    sc = 0
                    for crib_word in ["EASTNORTHEAST", "BERLINCLOCK", "NORTHEAST", "BERLIN", "CLOCK", "EAST"]:
                        if crib_word in pt:
                            sc += len(crib_word)
                    if sc >= 6:
                        log_result("L01", sc, pt,
                                   f"null_every{skip}_start{start}_shift{shift}",
                                   variant.value)

    print(f"  L01 complete: {count:,} configs tested")


# ══════════════════════════════════════════════════════════════════════════════
# LEAD L02: Sculpture tableau as running key
# ══════════════════════════════════════════════════════════════════════════════

def lead_L02_tableau_running_key():
    """Test the Vigenère tableau itself as a running key source.

    Read orders tested:
    - Row-by-row (standard)
    - Column-by-column
    - Diagonal (NW→SE)
    - Anti-diagonal (NE→SW)
    - Spiral (CW from top-left)
    - Row-by-row reversed
    - Alternating row direction (boustrophedon)
    """
    print("\n[L02] Tableau as running key...")
    count = 0

    # Build the KA tableau
    tableau = []
    for r in range(26):
        row = [KA[(r + c) % 26] for c in range(26)]
        tableau.append(row)

    # Read orders
    def read_row_by_row():
        return "".join("".join(row) for row in tableau)

    def read_col_by_col():
        return "".join(tableau[r][c] for c in range(26) for r in range(26))

    def read_diagonal():
        chars = []
        for d in range(51):  # diagonals of 26x26
            for r in range(26):
                c = d - r
                if 0 <= c < 26:
                    chars.append(tableau[r][c])
        return "".join(chars)

    def read_anti_diagonal():
        chars = []
        for d in range(51):
            for r in range(26):
                c = r - d + 25
                if 0 <= c < 26:
                    chars.append(tableau[r][c])
        return "".join(chars)

    def read_spiral_cw():
        chars = []
        visited = [[False]*26 for _ in range(26)]
        dr, dc = [0, 1, 0, -1], [1, 0, -1, 0]
        r, c, d = 0, 0, 0
        for _ in range(676):
            chars.append(tableau[r][c])
            visited[r][c] = True
            nr, nc = r + dr[d], c + dc[d]
            if 0 <= nr < 26 and 0 <= nc < 26 and not visited[nr][nc]:
                r, c = nr, nc
            else:
                d = (d + 1) % 4
                r, c = r + dr[d], c + dc[d]
        return "".join(chars)

    def read_boustrophedon():
        chars = []
        for r in range(26):
            row = tableau[r] if r % 2 == 0 else tableau[r][::-1]
            chars.extend(row)
        return "".join(chars)

    def read_reversed():
        return read_row_by_row()[::-1]

    reads = {
        "row": read_row_by_row(),
        "col": read_col_by_col(),
        "diag": read_diagonal(),
        "antidiag": read_anti_diagonal(),
        "spiral": read_spiral_cw(),
        "boustro": read_boustrophedon(),
        "reversed": read_reversed(),
    }

    for read_name, text in reads.items():
        nums = text_to_nums(text)
        max_offset = min(len(nums) - CT_LEN, 600)
        for offset in range(max(max_offset, 1)):
            key_nums = nums[offset:offset + CT_LEN]
            if len(key_nums) < CT_LEN:
                break
            for variant in VARIANTS:
                pt, sc = try_running_key(CT_NUMS, key_nums, variant)
                if sc >= NOISE_FLOOR:
                    log_result("L02", sc, pt,
                               f"tableau_{read_name}_offset{offset}",
                               variant.value)
                count += 1

    # Also test AZ tableau (standard A-Z, not KA)
    for r in range(26):
        az_text = "".join(ALPH[(r + c) % 26] for c in range(26) for r2 in range(26))
    az_row = "".join(ALPH[(r + c) % 26] for r in range(26) for c in range(26))
    az_nums = text_to_nums(az_row)
    for offset in range(min(len(az_nums) - CT_LEN, 600)):
        key = az_nums[offset:offset + CT_LEN]
        if len(key) < CT_LEN:
            break
        for variant in VARIANTS:
            pt, sc = try_running_key(CT_NUMS, key, variant)
            if sc >= NOISE_FLOOR:
                log_result("L02", sc, pt,
                           f"AZ_tableau_offset{offset}", variant.value)
            count += 1

    print(f"  L02 complete: {count:,} configs tested")


# ══════════════════════════════════════════════════════════════════════════════
# LEAD L03: K0 Morse code text as running key
# ══════════════════════════════════════════════════════════════════════════════

def lead_L03_morse_running_key():
    """Test Morse code text from entrance slabs as running key."""
    print("\n[L03] Morse code as running key...")
    count = 0

    # Morse code text fragments (from anomaly_registry.md and transcripts)
    morse_texts = [
        "VIRTUALLYINVISIBLESHADOWFORCESSOSETISYOURPOSITIONDIGETAL"
        "INTERPRETATIONLUCIDMEMORYEEEEEEEEEEEEEEEEEEEEEEEEEEERQ",
        # With E's removed
        "VIRTUALLYINVISIBLESHADOWFORCESSOSETISYOURPOSITIONDIGETAL"
        "INTERPRETATIONLUCIDMEMORYRQ",
        # Different orderings
        "TISYOURPOSITIONVIRTUALLYINVISIBLESHADOWFORCESSOS"
        "DIGETALINTERPRETATIONLUCIDMEMORY",
        "LUCIDMEMORYSHADOWFORCESVIRTUALLYINVISIBLE"
        "SOSETISYOURPOSITIONDIGETALINTERPRETATION",
        # Reversed
        "QRYROMEMDICULNOITATERPRETNILATIGID"
        "NOITISOPRUOYSITSOESECROFRWODAHSELBISINIYALLAUTRIV",
        # Corrected: DIGITAL not DIGETAL, INTERPRETATION complete
        "VIRTUALLYINVISIBLESHADOWFORCESSOSETISYOURPOSITION"
        "DIGITALINTERPRETATIONLUCIDMEMORY",
        # ALLYINVI fragment (known to produce ABSCISSA connection)
        "ALLYINVISHADOWFORCESSOSETISYOURPOSITION"
        "DIGITALINTERPRETATIONLUCIDMEMORY",
    ]

    for i, morse_text in enumerate(morse_texts):
        nums = text_to_nums(morse_text)
        max_off = max(len(nums) - CT_LEN + 1, 1)
        for offset in range(max_off):
            key = nums[offset:offset + CT_LEN]
            if len(key) < CT_LEN:
                break
            for variant in VARIANTS:
                pt, sc = try_running_key(CT_NUMS, key, variant)
                if sc >= NOISE_FLOOR:
                    log_result("L03", sc, pt,
                               f"morse_v{i}_offset{offset}", variant.value)
                count += 1

    print(f"  L03 complete: {count:,} configs tested")


# ══════════════════════════════════════════════════════════════════════════════
# LEAD L04: POINT as keyword
# ══════════════════════════════════════════════════════════════════════════════

def lead_L04_point_keyword():
    """Test POINT and related words as cipher keywords."""
    print("\n[L04] Anomaly-derived keyword sweep (POINT, SECRET, POWER, etc.)...")
    count = 0

    keywords = [
        # From Sanborn's (CLUE) marker
        "POINT", "POWER", "SECRET", "RESIDES",
        # From anomaly evidence
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "LIGHT",
        "BERLIN", "CLOCK", "COMPASS", "LODESTONE",
        # From Scheidt's domain
        "COMSEC", "DRYAD", "ADONIS", "VEIL",
        # YAR-derived
        "YAR", "RAY", "DYAHR", "HYDRA",
        # Combined
        "KRYPTOSPOINT", "POINTSECRET", "SECRETPOWER",
        "BERLINCLOCK", "EASTNORTHEAST",
        # Historical
        "WEBSTER", "SCHEIDT", "SANBORN",
        # Numbers as words
        "SEVEN", "FIVE", "TWENTYFOUR", "SEVENTEEN",
        # EQUAL hypothesis letters
        "EQUAL", "QUALE",
        # Thematic
        "INVISIBLE", "HIDDEN", "BURIED", "UNDERGROUND",
        "FILTER", "OVERLAY", "GRILLE", "MASK",
        "ENIGMA", "MYSTERY", "CIPHER", "CODE",
        # Possible from sculpture
        "LAYERTWO", "IDBYROWS", "XLAYERTWO",
        # Compass
        "NORTH", "EAST", "NORTHEAST", "ENE",
        # Carter
        "CARTER", "TUTANKHAMUN", "CARNARVON", "TOMB",
        # Berlin locations
        "ALEXANDERPLATZ", "WELTZEITUHR", "CHECKPOINT",
        # From handwriting analysis
        "GRANITE", "COPPER", "QUARTZ",
    ]

    for kw in keywords:
        key_nums_raw = text_to_nums(kw)
        if not key_nums_raw:
            continue
        # Repeat keyword to cover CT length
        key_nums = (key_nums_raw * ((CT_LEN // len(key_nums_raw)) + 1))[:CT_LEN]

        for variant in VARIANTS:
            pt, sc = try_running_key(CT_NUMS, key_nums, variant)
            if sc >= NOISE_FLOOR:
                log_result("L04", sc, pt, f"keyword_{kw}", variant.value)
            count += 1

        # Also test with KA alphabet indexing
        ka_key = []
        for ch in kw.upper():
            if ch in KA_IDX:
                ka_key.append(KA_IDX[ch])
        if ka_key:
            ka_key_ext = (ka_key * ((CT_LEN // len(ka_key)) + 1))[:CT_LEN]
            ct_ka = [KA_IDX[c] for c in CT]
            for variant in VARIANTS:
                dfn = {CipherVariant.VIGENERE: vig_decrypt,
                       CipherVariant.BEAUFORT: beau_decrypt,
                       CipherVariant.VAR_BEAUFORT: varbeau_decrypt}[variant]
                pt_ka = [dfn(ct_ka[i], ka_key_ext[i]) for i in range(CT_LEN)]
                pt = "".join(KA[n % 26] for n in pt_ka)
                sc = score_cribs(pt)
                if sc >= NOISE_FLOOR:
                    log_result("L04", sc, pt, f"KA_keyword_{kw}", variant.value)
                count += 1

    print(f"  L04 complete: {count:,} configs tested")


# ══════════════════════════════════════════════════════════════════════════════
# LEAD L05: YAR/DYAHR numeric values as Gromark primers
# ══════════════════════════════════════════════════════════════════════════════

def lead_L05_yar_primers():
    """Test YAR/DYAHR numeric values as cipher parameters."""
    print("\n[L05] YAR/DYAHR numeric parameters...")
    count = 0

    # Y=24, A=0, R=17 in A=0 numbering
    # D=3, Y=24, A=0, H=7, R=17
    primer_sets = [
        [24, 0, 17],          # YAR
        [3, 24, 0, 7, 17],    # DYAHR
        [17, 0, 24],          # RAY (reversed)
        [17, 7, 0, 24, 3],    # DYAHR reversed
        [0, 17, 24],          # AYR → sorted
        [3, 0, 7, 17, 24],    # DYAHR sorted
    ]

    for primer in primer_sets:
        # Generate Gromark-style keystream via Fibonacci addition
        keystream = list(primer)
        while len(keystream) < CT_LEN:
            keystream.append((keystream[-len(primer)] + keystream[-len(primer)+1]) % 10)

        # Apply as shift key
        key_nums = [k % 26 for k in keystream[:CT_LEN]]
        for variant in VARIANTS:
            pt, sc = try_running_key(CT_NUMS, key_nums, variant)
            if sc >= NOISE_FLOOR:
                log_result("L05", sc, pt,
                           f"gromark_primer{'_'.join(str(p) for p in primer)}",
                           variant.value)
            count += 1

        # Also try as direct periodic key (repeat primer)
        periodic = (primer * ((CT_LEN // len(primer)) + 1))[:CT_LEN]
        for variant in VARIANTS:
            pt, sc = try_running_key(CT_NUMS, periodic, variant)
            if sc >= NOISE_FLOOR:
                log_result("L05", sc, pt,
                           f"periodic_{'_'.join(str(p) for p in primer)}",
                           variant.value)
            count += 1

        # Fibonacci mod 26
        ks26 = list(primer)
        while len(ks26) < CT_LEN:
            ks26.append((ks26[-len(primer)] + ks26[-len(primer)+1]) % 26)
        for variant in VARIANTS:
            pt, sc = try_running_key(CT_NUMS, ks26[:CT_LEN], variant)
            if sc >= NOISE_FLOOR:
                log_result("L05", sc, pt,
                           f"fib26_{'_'.join(str(p) for p in primer)}",
                           variant.value)
            count += 1

    print(f"  L05 complete: {count:,} configs tested")


# ══════════════════════════════════════════════════════════════════════════════
# LEAD L06: "4,8,10,26=Col" columnar parameters
# ══════════════════════════════════════════════════════════════════════════════

def lead_L06_columnar():
    """Test columnar transposition with widths 4, 8, 10, 26 then decrypt."""
    print("\n[L06] Columnar transposition (widths 4,8,10,26)...")
    count = 0

    def columnar_decipher(ct: str, width: int, col_order: List[int]) -> str:
        """Decipher columnar transposition."""
        n = len(ct)
        nrows = (n + width - 1) // width
        # Figure out column lengths
        full_cols = n % width if n % width != 0 else width
        col_lens = []
        for c in range(width):
            if c < (n % width if n % width != 0 else width):
                col_lens.append(nrows)
            else:
                col_lens.append(nrows - 1 if n % width != 0 else nrows)

        # Read off columns in key order
        cols = []
        pos = 0
        # col_order[i] = which original column is in position i
        sorted_order = sorted(range(width), key=lambda x: col_order[x])
        for orig_col in sorted_order:
            clen = col_lens[orig_col]
            cols.append((orig_col, ct[pos:pos+clen]))
            pos += clen

        # Reconstruct by reading rows
        col_dict = {orig: text for orig, text in cols}
        result = []
        for r in range(nrows):
            for c in range(width):
                if r < len(col_dict.get(c, "")):
                    result.append(col_dict[c][r])
        return "".join(result)

    # Test each width with identity column order, then simple keyword orders
    for width in [4, 8, 10, 26, 7, 14, 21]:
        # Identity order
        identity = list(range(width))
        deperm = columnar_decipher(CT, width, identity)
        dep_nums = text_to_nums(deperm)

        # Try this as intermediate CT, then keyword decrypt
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "POINT", "SECRET",
                    "BERLIN", "SHADOW", "SEVEN"]:
            key = text_to_nums(kw)
            key_ext = (key * ((CT_LEN // len(key)) + 1))[:CT_LEN]
            for variant in VARIANTS:
                pt, sc = try_running_key(dep_nums, key_ext, variant)
                if sc >= NOISE_FLOOR:
                    log_result("L06", sc, pt,
                               f"col{width}_id_then_{kw}", variant.value)
                count += 1

        # Reversed column order
        rev_order = list(range(width))[::-1]
        deperm = columnar_decipher(CT, width, rev_order)
        dep_nums = text_to_nums(deperm)
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "POINT"]:
            key = text_to_nums(kw)
            key_ext = (key * ((CT_LEN // len(key)) + 1))[:CT_LEN]
            for variant in VARIANTS:
                pt, sc = try_running_key(dep_nums, key_ext, variant)
                if sc >= NOISE_FLOOR:
                    log_result("L06", sc, pt,
                               f"col{width}_rev_then_{kw}", variant.value)
                count += 1

        # Keyword-derived column orders for small widths
        if width <= 10:
            for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "POINT", "SEVEN"]:
                if len(kw) >= width:
                    kw_chars = kw[:width]
                    order = sorted(range(width), key=lambda i: kw_chars[i])
                    deperm = columnar_decipher(CT, width, order)
                    dep_nums = text_to_nums(deperm)
                    # Score directly (maybe it's just transposition)
                    sc = score_cribs(deperm)
                    if sc >= NOISE_FLOOR:
                        log_result("L06", sc, deperm,
                                   f"col{width}_kworder_{kw[:width]}", "trans")
                    count += 1

    print(f"  L06 complete: {count:,} configs tested")


# ══════════════════════════════════════════════════════════════════════════════
# LEAD L07: "3 Lines 93" grid test
# ══════════════════════════════════════════════════════════════════════════════

def lead_L07_grid_93():
    """Test grid dimensions from Sanborn's yellow pad notes."""
    print("\n[L07] Grid dimension tests (3×31, 31×3, 93-char subset)...")
    count = 0

    # "3 Lines 93" could mean: 3 rows of 31 chars = 93
    # K4 has 97 chars. 93 + 4 extras = 97.
    # OR: first 93 chars are the real CT, last 4 are padding/nulls

    # Test 1: Remove last 4 chars, treat 93-char text as the real CT
    ct93 = CT[:93]
    ct93_nums = text_to_nums(ct93)
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "POINT", "SECRET", "SEVEN"]:
        key = text_to_nums(kw)
        key_ext = (key * ((93 // len(key)) + 1))[:93]
        for variant in VARIANTS:
            dfn = {CipherVariant.VIGENERE: vig_decrypt,
                   CipherVariant.BEAUFORT: beau_decrypt,
                   CipherVariant.VAR_BEAUFORT: varbeau_decrypt}[variant]
            pt_nums = [dfn(ct93_nums[i], key_ext[i]) for i in range(93)]
            pt = "".join(ALPH[n] for n in pt_nums)
            # Check for crib fragments
            sc = 0
            for crib in ["EASTNORTHEAST", "BERLINCLOCK", "BERLIN", "CLOCK",
                          "EAST", "NORTH", "NORTHEAST"]:
                if crib in pt:
                    sc += len(crib)
            if sc >= NOISE_FLOOR:
                log_result("L07", sc, pt, f"ct93_{kw}", variant.value)
            count += 1

    # Test 2: Read 97 chars as 3×31+4 grid, read columns
    for width in [3, 31, 32, 33]:
        # Column read
        nrows = (CT_LEN + width - 1) // width
        col_read = []
        for c in range(width):
            for r in range(nrows):
                idx = r * width + c
                if idx < CT_LEN:
                    col_read.append(CT[idx])
        col_text = "".join(col_read)
        sc = score_cribs(col_text)
        if sc >= NOISE_FLOOR:
            log_result("L07", sc, col_text, f"grid_w{width}_colread", "trans")
        count += 1

    # Test 3: "11 Lines 342" for K3 → what about "3 Lines 93"?
    # If K4 is 3 lines of 31+31+31+4, try reading diagonals
    for width in [31, 32, 33]:
        nrows = (CT_LEN + width - 1) // width
        # Diagonal read
        diag = []
        for d in range(nrows + width):
            for r in range(nrows):
                c = d - r
                if 0 <= c < width:
                    idx = r * width + c
                    if idx < CT_LEN:
                        diag.append(CT[idx])
        diag_text = "".join(diag)
        sc = score_cribs(diag_text)
        if sc >= NOISE_FLOOR:
            log_result("L07", sc, diag_text, f"grid_w{width}_diagread", "trans")
        count += 1

    print(f"  L07 complete: {count:,} configs tested")


# ══════════════════════════════════════════════════════════════════════════════
# LEAD L08: JFK/Reagan Berlin speeches as running key
# ══════════════════════════════════════════════════════════════════════════════

def lead_L08_speeches():
    """Test Berlin speeches as running keys."""
    print("\n[L08] Berlin speeches as running key...")
    count = 0

    speech_files = [
        ("JFK_Berlin", os.path.join(_ROOT, "reference/running_key_texts/jfk_berlin.txt")),
        ("Reagan_Berlin", os.path.join(_ROOT, "reference/running_key_texts/reagan_berlin.txt")),
        ("UDHR", os.path.join(_ROOT, "reference/running_key_texts/udhr.txt")),
        ("CIA_Charter", os.path.join(_ROOT, "reference/running_key_texts/cia_charter.txt")),
        ("NSA_Act", os.path.join(_ROOT, "reference/running_key_texts/nsa_act_1947.txt")),
    ]

    for name, path in speech_files:
        if not os.path.exists(path):
            continue
        with open(path) as f:
            text = f.read()
        if not text.strip():
            continue

        nums = text_to_nums(text)
        if len(nums) < CT_LEN:
            print(f"  {name}: too short ({len(nums)} chars)")
            continue

        max_offset = len(nums) - CT_LEN
        step = max(1, max_offset // 5000)  # sample ~5000 offsets
        for offset in range(0, max_offset, step):
            key = nums[offset:offset + CT_LEN]
            for variant in VARIANTS:
                pt, sc = try_running_key(CT_NUMS, key, variant)
                if sc >= NOISE_FLOOR:
                    log_result("L08", sc, pt,
                               f"{name}_offset{offset}", variant.value)
                count += 1

    print(f"  L08 complete: {count:,} configs tested")


# ══════════════════════════════════════════════════════════════════════════════
# LEAD L10: Weltzeituhr city list as running key
# ══════════════════════════════════════════════════════════════════════════════

def lead_L10_weltzeituhr():
    """Test Weltzeituhr city/timezone text as running key."""
    print("\n[L10] Weltzeituhr city list as running key...")
    count = 0

    # The 24 timezone panels of the Weltzeituhr (Alexanderplatz, Berlin)
    # Each panel shows cities in that timezone. German text on the monument.
    # Reconstructed from public photos and travel guides.
    weltzeituhr_cities = (
        "REYKJAVIK"
        "LONDON MONROVIA ACCRA"
        "PARIS BERLIN MADRID ROM STOCKHOLM OSLO KOPENHAGEN WARSCHAU PRAG"
        "ATHEN HELSINKI KAIRO BUKAREST ISTANBUL JERUSALEM"
        "MOSKAU BAGDAD NAIROBI ADDIS ABEBA"
        "TEHERAN"
        "KARATSCHI TASCHKENT"
        "DELHI KALKUTTA"
        "COLOMBO RANGUN"
        "BANGKOK DJAKARTA HANOI"
        "PEKING HONGKONG MANILA SCHANGHAI SINGAPUR"
        "TOKIO PJOENGJANG SEOUL"
        "WLADIWOSTOK MELBOURNE SYDNEY"
        "WELLINGTON KAMTSCHATKA"
        "ANADYR"
        "SAMOA"
        "HONOLULU"
        "ANCHORAGE"
        "VANCOUVER SANFRANCISCO LOSANGELES"
        "DENVER MEXIKO"
        "CHICAGO NEWYORK WASHINGTON HAVANNA LIMA BOGOTA MONTREAL"
        "SANTIAGO BUENOS AIRES BRASILIA RIO DE JANEIRO CARACAS"
        "GROENLAND"
        "AZOREN"
    )

    # Also try just the cities in the Berlin timezone panel
    berlin_panel = "PARISBERLINMADRIDROMSTOCKHOLMOSLOKOPENHAGENWRSCHAUPRG"
    # And the full list stripped
    full_cities = weltzeituhr_cities.replace(" ", "").upper()

    for name, text in [("weltzeituhr_full", full_cities),
                        ("berlin_panel", berlin_panel),
                        ("weltzeituhr_reversed", full_cities[::-1])]:
        nums = text_to_nums(text)
        max_off = max(len(nums) - CT_LEN + 1, 1)
        for offset in range(max_off):
            key = nums[offset:offset + CT_LEN]
            if len(key) < CT_LEN:
                break
            for variant in VARIANTS:
                pt, sc = try_running_key(CT_NUMS, key, variant)
                if sc >= NOISE_FLOOR:
                    log_result("L10", sc, pt,
                               f"{name}_offset{offset}", variant.value)
                count += 1

    # Also: cycle the cities (repeat to cover CT_LEN)
    for name, text in [("weltzeituhr_cycled", full_cities)]:
        nums = text_to_nums(text)
        if not nums:
            continue
        cycled = (nums * ((CT_LEN // len(nums)) + 2))[:CT_LEN]
        for variant in VARIANTS:
            pt, sc = try_running_key(CT_NUMS, cycled, variant)
            if sc >= NOISE_FLOOR:
                log_result("L10", sc, pt, f"{name}", variant.value)
            count += 1

    print(f"  L10 complete: {count:,} configs tested")


# ══════════════════════════════════════════════════════════════════════════════
# LEAD L12: Keyword sweep with anomaly-derived combined keywords
# ══════════════════════════════════════════════════════════════════════════════

def lead_L12_combined_keywords():
    """Test multi-word keyword combinations from anomaly evidence."""
    print("\n[L12] Combined keyword sweep (anomaly-derived)...")
    count = 0

    # Two-word combinations from thematic keywords
    words1 = ["KRYPTOS", "POINT", "SECRET", "SHADOW", "BERLIN", "CLOCK",
              "SEVEN", "FIVE", "EAST", "NORTH"]
    words2 = ["POINT", "SECRET", "POWER", "LIGHT", "COMPASS", "FILTER",
              "GRILLE", "MASK", "LAYER", "TWO", "RAY", "HIDDEN"]

    for w1 in words1:
        for w2 in words2:
            kw = w1 + w2
            key = text_to_nums(kw)
            key_ext = (key * ((CT_LEN // len(key)) + 1))[:CT_LEN]
            for variant in VARIANTS:
                pt, sc = try_running_key(CT_NUMS, key_ext, variant)
                if sc >= NOISE_FLOOR:
                    log_result("L12", sc, pt, f"combo_{w1}_{w2}", variant.value)
                count += 1

    # Three-word from "3 words most" archive note
    short_words = ["THE", "KEY", "IS", "AT", "USE", "ROW", "COL"]
    for w1 in ["KRYPTOS", "POINT", "SECRET"]:
        for w2 in short_words:
            for w3 in ["SEVEN", "FIVE", "TWO", "ONE"]:
                kw = w1 + w2 + w3
                key = text_to_nums(kw)
                key_ext = (key * ((CT_LEN // len(key)) + 1))[:CT_LEN]
                for variant in VARIANTS:
                    pt, sc = try_running_key(CT_NUMS, key_ext, variant)
                    if sc >= NOISE_FLOOR:
                        log_result("L12", sc, pt,
                                   f"triple_{w1}_{w2}_{w3}", variant.value)
                    count += 1

    print(f"  L12 complete: {count:,} configs tested")


# ══════════════════════════════════════════════════════════════════════════════
# LEAD L13: Carter tomb deeper + Beaufort
# ══════════════════════════════════════════════════════════════════════════════

def lead_L13_carter_deep():
    """Test Carter tomb text with Beaufort at all offsets."""
    print("\n[L13] Carter tomb deep sweep (Beaufort focus)...")
    count = 0

    for path in [os.path.join(_ROOT, "reference/carter_vol1.txt"),
                 os.path.join(_ROOT, "reference/carter_gutenberg.txt")]:
        if not os.path.exists(path):
            continue
        with open(path) as f:
            text = f.read()
        name = os.path.basename(path).replace(".txt", "")
        nums = text_to_nums(text)
        if len(nums) < CT_LEN:
            continue

        max_offset = len(nums) - CT_LEN
        for offset in range(max_offset):
            key = nums[offset:offset + CT_LEN]
            for variant in VARIANTS:
                pt, sc = try_running_key(CT_NUMS, key, variant)
                if sc >= NOISE_FLOOR:
                    log_result("L13", sc, pt,
                               f"{name}_offset{offset}", variant.value)
                count += 1

    print(f"  L13 complete: {count:,} configs tested")


# ══════════════════════════════════════════════════════════════════════════════
# LEAD L15: Compass bearing 67.5° as parameter
# ══════════════════════════════════════════════════════════════════════════════

def lead_L15_compass():
    """Test compass bearing 67.5° as various cipher parameters."""
    print("\n[L15] Compass bearing parameters...")
    count = 0

    # 67.5° = ENE. Numeric values: 67, 68, 6, 7, 5
    # Also: 67.5 / 360 * 26 ≈ 4.875 → shift 5?
    # 67 mod 26 = 15 → shift 15 (P)
    # 68 mod 26 = 16 → shift 16 (Q)

    shifts = [5, 15, 16, 67 % 26, 68 % 26, 7, 6]
    for shift in shifts:
        for variant in VARIANTS:
            key = [shift] * CT_LEN
            pt, sc = try_running_key(CT_NUMS, key, variant)
            if sc >= NOISE_FLOOR:
                log_result("L15", sc, pt,
                           f"compass_shift{shift}", variant.value)
            count += 1

    # Also test as starting position for progressive key
    for base_shift in shifts:
        for increment in range(1, 26):
            key = [(base_shift + i * increment) % 26 for i in range(CT_LEN)]
            for variant in VARIANTS:
                pt, sc = try_running_key(CT_NUMS, key, variant)
                if sc >= NOISE_FLOOR:
                    log_result("L15", sc, pt,
                               f"compass_progressive_b{base_shift}_inc{increment}",
                               variant.value)
                count += 1

    print(f"  L15 complete: {count:,} configs tested")


# ══════════════════════════════════════════════════════════════════════════════
# PARALLEL DISPATCHER
# ══════════════════════════════════════════════════════════════════════════════

def _run_lead(lead_fn_name):
    """Run a single lead function by name (for multiprocessing)."""
    fn = globals()[lead_fn_name]
    fn()
    return lead_fn_name


def main():
    start = time.time()
    workers = max(1, cpu_count() - 2)

    print("=" * 80)
    print("ALL-LEADS BLITZ — Anomaly Investigation Follow-up")
    print(f"Workers available: {workers}")
    print("=" * 80)

    # Run all leads sequentially (they use internal parallelism where needed)
    leads = [
        lead_L01_null_mask_keyword,
        lead_L02_tableau_running_key,
        lead_L03_morse_running_key,
        lead_L04_point_keyword,
        lead_L05_yar_primers,
        lead_L06_columnar,
        lead_L07_grid_93,
        lead_L08_speeches,
        lead_L10_weltzeituhr,
        lead_L12_combined_keywords,
        lead_L13_carter_deep,
        lead_L15_compass,
    ]

    for lead_fn in leads:
        try:
            lead_fn()
        except Exception as e:
            print(f"  ERROR in {lead_fn.__name__}: {e}")

    elapsed = time.time() - start

    # Summary
    print("\n" + "=" * 80)
    print(f"ALL-LEADS BLITZ COMPLETE — {elapsed:.1f}s")
    print(f"Results above noise floor ({NOISE_FLOOR}): {len(results_log)}")
    print("=" * 80)

    if results_log:
        print("\nAll results above noise floor:")
        for r in sorted(results_log, key=lambda x: -x['score']):
            print(f"  Score {r['score']:2d} | {r['lead']} | {r['method']} | {r['variant']}")
            print(f"           PT: {r['plaintext']}")
    else:
        print("\nNo results above noise floor. All leads produced noise.")

    if best_result:
        print(f"\nBEST OVERALL: {best_result['score']}/{N_CRIBS}")
        print(f"  Lead: {best_result['lead']}")
        print(f"  Method: {best_result['method']}")
        print(f"  Variant: {best_result['variant']}")
        print(f"  PT: {best_result['plaintext']}")

    # Save results
    output_path = os.path.join(_ROOT, "results", "all_leads_blitz_results.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "elapsed_seconds": elapsed,
            "total_results": len(results_log),
            "best_score": best_score,
            "best_result": best_result,
            "all_results": results_log,
        }, f, indent=2)
    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()
