#!/usr/bin/env python3
"""
Cipher: YAR grille
Family: yar
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
e_yar_gridkey.py — Grid-Position Key Derivation for K4

CONVERGENT THEORY: Combines two ideas:
  1. YAR selective substitution: At positions where Y/A/R appear in K4,
     the cipher char is replaced by the tableau char. This produces a
     "modified CT" with IC spike at period 7.
  2. Grid-position key: Instead of a periodic key, each position's key
     is determined by its location in the 28x31 master grid.

Tests 8 key-derivation methods on BOTH original and YAR-modified CT,
across Vigenere/Beaufort/VarBeaufort, AZ/KA alphabets.

Grid layout:
  K4 starts at row 24, col 27 (OBKR at end of row 24)
  Row 25: K4[4:35]   cols 0-30
  Row 26: K4[35:66]  cols 0-30
  Row 27: K4[66:97]  cols 0-30
"""
from __future__ import annotations

import json
import math
import sys
import time
from collections import Counter
from pathlib import Path
from typing import List, Tuple, Dict, Optional

# ── Constants ────────────────────────────────────────────────────────────────

K4_CARVED = (
    "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWAT"
    "JKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
)
assert len(K4_CARVED) == 97

# YAR-modified CT (Y->tableau, A->tableau, R->tableau at their positions)
# From the user's specification
K4_YAR = (
    "OBKKUOXOGHULBSOLIFBBWFLJVQQPUNGKSSOTWTQSJQSSEKZZWFT"
    "JKLUDIQWINFBNRPVTTMZFPKWGDKZXTJCDIGKUHUXUEKCCD"
)
assert len(K4_YAR) == 97

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN",
    "SCHEIDT", "BERLIN", "CLOCK", "EAST", "NORTH",
    "LIGHT", "ANTIPODES", "MEDUSA", "ENIGMA",
    "BERLINCLOCK", "EASTNORTHEAST",
]

# Cribs (0-indexed positions in K4)
CRIB_ENE = (21, "EASTNORTHEAST")   # 13 chars, positions 21-33
CRIB_BC = (63, "BERLINCLOCK")      # 11 chars, positions 63-73
CRIB_DICT = {}
for _start, _word in [CRIB_ENE, CRIB_BC]:
    for _i, _ch in enumerate(_word):
        CRIB_DICT[_start + _i] = _ch

# K3 plaintext (336 chars)
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHAT"
    "ENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITH"
    "TREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFTHAND"
    "CORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTEDTHE"
    "CANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBER"
    "CAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHE"
    "ROOMWITHINemergedfromthemistxcanyouseeanythingq"
).upper()
K3_PT = ''.join(c for c in K3_PT if c.isalpha())
assert len(K3_PT) == 336, f"K3 PT length: {len(K3_PT)}"


# ── Grid geometry ────────────────────────────────────────────────────────────

GRID_ROWS = 28
GRID_COLS = 31

# K4 starts at row 24, col 27
K4_GRID_START_ROW = 24
K4_GRID_START_COL = 27

def k4_pos_to_grid(pos: int) -> Tuple[int, int]:
    """Convert K4 position (0-96) to (row, col) in 28x31 grid."""
    # K4 starts at row 24, col 27
    # First 4 chars: row 24, cols 27,28,29,30
    # Next 31 chars: row 25, cols 0-30
    # Next 31 chars: row 26, cols 0-30
    # Next 31 chars: row 27, cols 0-30
    flat = K4_GRID_START_ROW * GRID_COLS + K4_GRID_START_COL + pos
    row = flat // GRID_COLS
    col = flat % GRID_COLS
    return (row, col)

# Precompute grid coordinates for all 97 K4 positions
K4_GRID = [k4_pos_to_grid(i) for i in range(97)]

# Verify layout
assert K4_GRID[0] == (24, 27), f"pos 0 should be (24,27), got {K4_GRID[0]}"
assert K4_GRID[4] == (25, 0), f"pos 4 should be (25,0), got {K4_GRID[4]}"
assert K4_GRID[35] == (26, 0), f"pos 35 should be (26,0), got {K4_GRID[35]}"
assert K4_GRID[66] == (27, 0), f"pos 66 should be (27,0), got {K4_GRID[66]}"
assert K4_GRID[96] == (27, 30), f"pos 96 should be (27,30), got {K4_GRID[96]}"


# ── Quadgram scoring ─────────────────────────────────────────────────────────

QUADGRAM_PATH = Path(__file__).resolve().parents[2] / "data" / "english_quadgrams.json"
QUADGRAMS: Dict[str, float] = json.loads(QUADGRAM_PATH.read_text())
FLOOR_LOG = -10.0


def score_text(text: str) -> float:
    """Total quadgram log-probability."""
    s = text.upper()
    return sum(QUADGRAMS.get(s[i:i+4], FLOOR_LOG) for i in range(len(s) - 3))


def score_per_char(text: str) -> float:
    """Quadgram log-prob per quadgram."""
    n = len(text)
    if n < 4:
        return FLOOR_LOG
    return score_text(text) / (n - 3)


def ic(text: str) -> float:
    """Index of coincidence."""
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text.upper())
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


# ── Cipher functions ─────────────────────────────────────────────────────────

def vig_decrypt_numeric(ct: str, keys: List[int], alpha: str = AZ) -> str:
    """Vigenere: PT[i] = (CT[i] - K[i]) mod 26, using alpha for indexing."""
    result = []
    for i, c in enumerate(ct):
        ci = alpha.index(c)
        k = keys[i]
        result.append(alpha[(ci - k) % 26])
    return "".join(result)


def beau_decrypt_numeric(ct: str, keys: List[int], alpha: str = AZ) -> str:
    """Beaufort: PT[i] = (K[i] - CT[i]) mod 26."""
    result = []
    for i, c in enumerate(ct):
        ci = alpha.index(c)
        k = keys[i]
        result.append(alpha[(k - ci) % 26])
    return "".join(result)


def varbeau_decrypt_numeric(ct: str, keys: List[int], alpha: str = AZ) -> str:
    """Variant Beaufort: PT[i] = (CT[i] + K[i]) mod 26."""
    result = []
    for i, c in enumerate(ct):
        ci = alpha.index(c)
        k = keys[i]
        result.append(alpha[(ci + k) % 26])
    return "".join(result)


def vig_decrypt_str(ct: str, key: str, alpha: str = AZ) -> str:
    """Vigenere decryption with string key (repeating)."""
    result = []
    klen = len(key)
    for i, c in enumerate(ct):
        ci = alpha.index(c)
        ki = alpha.index(key[i % klen])
        result.append(alpha[(ci - ki) % 26])
    return "".join(result)


def beau_decrypt_str(ct: str, key: str, alpha: str = AZ) -> str:
    """Beaufort decryption with string key (repeating)."""
    result = []
    klen = len(key)
    for i, c in enumerate(ct):
        ci = alpha.index(c)
        ki = alpha.index(key[i % klen])
        result.append(alpha[(ki - ci) % 26])
    return "".join(result)


def varbeau_decrypt_str(ct: str, key: str, alpha: str = AZ) -> str:
    """Variant Beaufort decryption with string key (repeating)."""
    result = []
    klen = len(key)
    for i, c in enumerate(ct):
        ci = alpha.index(c)
        ki = alpha.index(key[i % klen])
        result.append(alpha[(ci + ki) % 26])
    return "".join(result)


# ── Crib checking ────────────────────────────────────────────────────────────

def check_cribs(pt: str) -> Tuple[int, List[str]]:
    """Check how many crib positions match. Returns (count, details)."""
    matches = 0
    details = []
    for pos, expected in CRIB_DICT.items():
        if pos < len(pt) and pt[pos] == expected:
            matches += 1

    # Also check if full crib words appear at expected positions
    if pt[21:34] == "EASTNORTHEAST":
        details.append("ENE at 21-33")
    if pt[63:74] == "BERLINCLOCK":
        details.append("BC at 63-73")

    # Check if they appear anywhere
    if "EASTNORTHEAST" in pt and "ENE at 21-33" not in details:
        idx = pt.find("EASTNORTHEAST")
        details.append(f"ENE at {idx} (wrong pos)")
    if "BERLINCLOCK" in pt and "BC at 63-73" not in details:
        idx = pt.find("BERLINCLOCK")
        details.append(f"BC at {idx} (wrong pos)")

    return matches, details


def recover_key_at_cribs(ct: str, cipher: str, alpha: str = AZ) -> Dict[int, int]:
    """Recover key values at crib positions."""
    keys = {}
    for pos, pt_ch in CRIB_DICT.items():
        ci = alpha.index(ct[pos])
        pi = alpha.index(pt_ch)
        if cipher == "vig":
            keys[pos] = (ci - pi) % 26
        elif cipher == "beau":
            keys[pos] = (ci + pi) % 26
        elif cipher == "varbeau":
            keys[pos] = (pi - ci) % 26
    return keys


# ── Tableau functions ─────────────────────────────────────────────────────────

def ka_tableau(row: int, col: int) -> str:
    """KA Vigenere tableau value at (row, col).
    Row determines the key letter (AZ[row % 26]).
    The row of the KA tableau for key letter K is: KA shifted so that
    KA[0] = AZ[row % 26], then KA cycle continues.
    Actually the Kryptos tableau: row header = A-Z (standard),
    each row is KA rotated so that position 0 = row's key letter.
    """
    key_letter = AZ[row % 26]
    key_idx = KA.index(key_letter)
    return KA[(key_idx + col) % 26]


def az_tableau(row: int, col: int) -> str:
    """Standard AZ Vigenere tableau at (row, col)."""
    return AZ[(row + col) % 26]


# Precompute KA tableau chars at K4 grid positions
K4_KA_TABLEAU = [ka_tableau(r, c) for r, c in K4_GRID]
K4_AZ_TABLEAU = [az_tableau(r, c) for r, c in K4_GRID]


# ── Full ciphertext in the grid ──────────────────────────────────────────────

# All cipher text rows (28 rows x 31 cols = 868 chars)
# We need the full cipher grid for method 5 (tableau as key source)
# K3 occupies rows 14-24 (336 chars K3 + 1 positional ? + first bit of K4)
# For K3, the plaintext at grid positions gives us a running key for K4

# K3 plaintext in grid: K3 occupies 336 chars starting at row 14, col 0
# K3 ends at row 24, col 26 (336 = 10*31 + 26, so row 14+10=24, col 26)
# K4 starts at row 24, col 27

# So the grid positions for K4 overlap with rows 24-27
# K3 plaintext at the grid:
#   Row 14-23: K3 PT chars
#   Row 24, cols 0-25: K3 PT chars (last ones)
#   Row 24, col 26: ? (positional)
#   Row 24, cols 27-30: K4 starts (OBKR)


# ── Method implementations ────────────────────────────────────────────────────

def method_1_col_mod26(ct: str, label: str) -> None:
    """Key = column index mod 26."""
    print(f"\n{'='*70}")
    print(f"METHOD 1: Key = column mod 26 [{label}]")
    print(f"{'='*70}")

    keys = [K4_GRID[i][1] % 26 for i in range(97)]
    print(f"Key values (first 20): {keys[:20]}")
    print(f"Key letters AZ: {''.join(AZ[k] for k in keys[:20])}...")

    results = []
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for cipher_name, decrypt_fn in [
            ("vig", vig_decrypt_numeric),
            ("beau", beau_decrypt_numeric),
            ("varbeau", varbeau_decrypt_numeric),
        ]:
            pt = decrypt_fn(ct, keys, alpha)
            crib_count, crib_details = check_cribs(pt)
            qg = score_per_char(pt)
            ic_val = ic(pt)
            results.append((crib_count, qg, cipher_name, alpha_name, pt, crib_details, ic_val))

    results.sort(key=lambda x: (-x[0], -x[1]))
    for count, qg, cipher, alph, pt, details, ic_val in results[:6]:
        det_str = f" [{', '.join(details)}]" if details else ""
        print(f"  {cipher:8s}/{alph} crib={count:2d}/24 qg={qg:.4f} IC={ic_val:.4f}{det_str}")
        print(f"    PT: {pt}")


def method_2_row_key(ct: str, label: str) -> None:
    """Key = row index (only 4 values: 24, 25, 26, 27)."""
    print(f"\n{'='*70}")
    print(f"METHOD 2: Key = row index [{label}]")
    print(f"{'='*70}")

    keys = [K4_GRID[i][0] % 26 for i in range(97)]
    print(f"Key values: {sorted(set(keys))} (rows 24-27 mod 26 = {[24%26, 25%26, 26%26, 27%26]})")

    results = []
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for cipher_name, decrypt_fn in [
            ("vig", vig_decrypt_numeric),
            ("beau", beau_decrypt_numeric),
            ("varbeau", varbeau_decrypt_numeric),
        ]:
            pt = decrypt_fn(ct, keys, alpha)
            crib_count, crib_details = check_cribs(pt)
            qg = score_per_char(pt)
            ic_val = ic(pt)
            results.append((crib_count, qg, cipher_name, alpha_name, pt, crib_details, ic_val))

    results.sort(key=lambda x: (-x[0], -x[1]))
    for count, qg, cipher, alph, pt, details, ic_val in results[:6]:
        det_str = f" [{', '.join(details)}]" if details else ""
        print(f"  {cipher:8s}/{alph} crib={count:2d}/24 qg={qg:.4f} IC={ic_val:.4f}{det_str}")
        print(f"    PT: {pt}")


def method_3_diagonal(ct: str, label: str) -> None:
    """Key = (row + col) mod 26."""
    print(f"\n{'='*70}")
    print(f"METHOD 3: Key = (row + col) mod 26 [diagonal] [{label}]")
    print(f"{'='*70}")

    keys = [(K4_GRID[i][0] + K4_GRID[i][1]) % 26 for i in range(97)]
    print(f"Key values (first 20): {keys[:20]}")

    results = []
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for cipher_name, decrypt_fn in [
            ("vig", vig_decrypt_numeric),
            ("beau", beau_decrypt_numeric),
            ("varbeau", varbeau_decrypt_numeric),
        ]:
            pt = decrypt_fn(ct, keys, alpha)
            crib_count, crib_details = check_cribs(pt)
            qg = score_per_char(pt)
            ic_val = ic(pt)
            results.append((crib_count, qg, cipher_name, alpha_name, pt, crib_details, ic_val))

    results.sort(key=lambda x: (-x[0], -x[1]))
    for count, qg, cipher, alph, pt, details, ic_val in results[:6]:
        det_str = f" [{', '.join(details)}]" if details else ""
        print(f"  {cipher:8s}/{alph} crib={count:2d}/24 qg={qg:.4f} IC={ic_val:.4f}{det_str}")
        print(f"    PT: {pt}")


def method_4_multiplicative(ct: str, label: str) -> None:
    """Key = (row * col) mod 26."""
    print(f"\n{'='*70}")
    print(f"METHOD 4: Key = (row * col) mod 26 [multiplicative] [{label}]")
    print(f"{'='*70}")

    keys = [(K4_GRID[i][0] * K4_GRID[i][1]) % 26 for i in range(97)]
    print(f"Key values (first 20): {keys[:20]}")

    results = []
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for cipher_name, decrypt_fn in [
            ("vig", vig_decrypt_numeric),
            ("beau", beau_decrypt_numeric),
            ("varbeau", varbeau_decrypt_numeric),
        ]:
            pt = decrypt_fn(ct, keys, alpha)
            crib_count, crib_details = check_cribs(pt)
            qg = score_per_char(pt)
            ic_val = ic(pt)
            results.append((crib_count, qg, cipher_name, alpha_name, pt, crib_details, ic_val))

    results.sort(key=lambda x: (-x[0], -x[1]))
    for count, qg, cipher, alph, pt, details, ic_val in results[:6]:
        det_str = f" [{', '.join(details)}]" if details else ""
        print(f"  {cipher:8s}/{alph} crib={count:2d}/24 qg={qg:.4f} IC={ic_val:.4f}{det_str}")
        print(f"    PT: {pt}")


def method_5_tableau_key(ct: str, label: str) -> None:
    """Key = tableau value at (row, col) on the OTHER side of the sculpture.

    The Vigenere tableau IS the key source. We read the tableau character
    at each K4 grid position and use it as the key.

    Two interpretations:
      5a. KA tableau value -> key index
      5b. AZ tableau value -> key index
    """
    print(f"\n{'='*70}")
    print(f"METHOD 5: Key = tableau value at grid position [{label}]")
    print(f"{'='*70}")

    # 5a: KA tableau as key
    keys_ka = [KA.index(K4_KA_TABLEAU[i]) for i in range(97)]
    # 5b: AZ tableau as key
    keys_az = [AZ.index(K4_AZ_TABLEAU[i]) for i in range(97)]

    print(f"KA tableau chars (first 20): {''.join(K4_KA_TABLEAU[:20])}")
    print(f"AZ tableau chars (first 20): {''.join(K4_AZ_TABLEAU[:20])}")

    results = []
    for key_label, keys in [("KA_tab", keys_ka), ("AZ_tab", keys_az)]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, decrypt_fn in [
                ("vig", vig_decrypt_numeric),
                ("beau", beau_decrypt_numeric),
                ("varbeau", varbeau_decrypt_numeric),
            ]:
                pt = decrypt_fn(ct, keys, alpha)
                crib_count, crib_details = check_cribs(pt)
                qg = score_per_char(pt)
                ic_val = ic(pt)
                results.append((crib_count, qg, cipher_name, f"{alpha_name}/{key_label}", pt, crib_details, ic_val))

    results.sort(key=lambda x: (-x[0], -x[1]))
    for count, qg, cipher, alph, pt, details, ic_val in results[:8]:
        det_str = f" [{', '.join(details)}]" if details else ""
        print(f"  {cipher:8s}/{alph:12s} crib={count:2d}/24 qg={qg:.4f} IC={ic_val:.4f}{det_str}")
        print(f"    PT: {pt}")


def method_6_kryptos_grid_col(ct: str, label: str) -> None:
    """Key = KRYPTOS[col mod 7] -- standard period-7 but using GRID column.

    Different from period-7 by K4 position because K4 starts at col 27,
    not col 0. So position 0 uses KRYPTOS[27 mod 7] = KRYPTOS[6] = S, etc.
    """
    print(f"\n{'='*70}")
    print(f"METHOD 6: Key = KRYPTOS[col mod 7] (grid column) [{label}]")
    print(f"{'='*70}")

    KRYPTOS_KW = "KRYPTOS"
    keys = [AZ.index(KRYPTOS_KW[K4_GRID[i][1] % 7]) for i in range(97)]
    key_letters = [KRYPTOS_KW[K4_GRID[i][1] % 7] for i in range(97)]
    print(f"Key letters (first 35): {''.join(key_letters[:35])}")
    print(f"  vs period-7 by position: {''.join(KRYPTOS_KW[i%7] for i in range(35))}")

    # Also try other keywords
    all_keywords_to_try = ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]

    results = []
    for kw in all_keywords_to_try:
        kw_len = len(kw)
        keys_this = [AZ.index(kw[K4_GRID[i][1] % kw_len]) for i in range(97)]

        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, decrypt_fn in [
                ("vig", vig_decrypt_numeric),
                ("beau", beau_decrypt_numeric),
                ("varbeau", varbeau_decrypt_numeric),
            ]:
                pt = decrypt_fn(ct, keys_this, alpha)
                crib_count, crib_details = check_cribs(pt)
                qg = score_per_char(pt)
                ic_val = ic(pt)
                results.append((crib_count, qg, cipher_name, f"{alpha_name}/{kw}", pt, crib_details, ic_val))

    results.sort(key=lambda x: (-x[0], -x[1]))
    for count, qg, cipher, alph, pt, details, ic_val in results[:8]:
        det_str = f" [{', '.join(details)}]" if details else ""
        print(f"  {cipher:8s}/{alph:18s} crib={count:2d}/24 qg={qg:.4f} IC={ic_val:.4f}{det_str}")
        print(f"    PT: {pt}")


def method_7_k3_pt_running_key(ct: str, label: str) -> None:
    """Key from K3 plaintext at same grid positions.

    K3 occupies rows 14-24 (336 chars). K3 PT mapped into the grid provides
    a running key. K4 overlaps in rows 24-27. Specifically:
      K3 starts at row 14, col 0 (grid position 14*31 = 434)
      K3 length = 336 chars
      K3 ends at grid position 434+335 = 769 = row 24, col 25

    K4 starts at row 24, col 27 (grid position 771).
    So K4 does NOT overlap K3 grid positions directly.

    But the theory could be: use K3 PT cyclically as a running key for K4,
    or use K3 PT at corresponding column positions.
    """
    print(f"\n{'='*70}")
    print(f"METHOD 7: Key from K3 plaintext [{label}]")
    print(f"{'='*70}")

    assert len(K3_PT) == 336

    results = []

    # 7a: K3 PT as running key (direct: K3_PT[i] for i in range(97))
    keys_7a = [AZ.index(K3_PT[i]) for i in range(97)]
    # 7b: K3 PT starting from end (last 97 chars)
    keys_7b = [AZ.index(K3_PT[336 - 97 + i]) for i in range(97)]
    # 7c: K3 PT at same column positions -- for each K4 position, find the K3 PT char
    # at the same column in the previous row. K4 rows are 24-27, K3 rows are 14-24.
    # For K4 row r, col c: use K3 row (r - 10 or r - 11 depending on mapping).
    # Row 25 -> row 15, row 26 -> row 16, row 27 -> row 17 (offset 10)
    # K3 grid: row 14 + offset -> K3_PT index = (row - 14)*31 + col
    keys_7c = []
    for i in range(97):
        r, c = K4_GRID[i]
        # Map to K3 row: r - 10 (so row 24->14, 25->15, 26->16, 27->17)
        k3_row = r - 10
        k3_idx = (k3_row - 14) * 31 + c
        if 0 <= k3_idx < 336:
            keys_7c.append(AZ.index(K3_PT[k3_idx]))
        else:
            keys_7c.append(0)  # default A

    # 7d: K3 PT at offset 11 (row 25->14, 26->15, 27->16, 24->13 oob)
    keys_7d = []
    for i in range(97):
        r, c = K4_GRID[i]
        k3_row = r - 11
        k3_idx = (k3_row - 14) * 31 + c
        if 0 <= k3_idx < 336:
            keys_7d.append(AZ.index(K3_PT[k3_idx]))
        else:
            keys_7d.append(0)

    # 7e: K3 PT cyclic (K3_PT[i % 336] as running key, full 336-char cycle)
    keys_7e = [AZ.index(K3_PT[i % 336]) for i in range(97)]

    for key_label, keys in [
        ("K3_start", keys_7a),
        ("K3_end97", keys_7b),
        ("K3_col_off10", keys_7c),
        ("K3_col_off11", keys_7d),
        ("K3_cyclic", keys_7e),
    ]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, decrypt_fn in [
                ("vig", vig_decrypt_numeric),
                ("beau", beau_decrypt_numeric),
                ("varbeau", varbeau_decrypt_numeric),
            ]:
                pt = decrypt_fn(ct, keys, alpha)
                crib_count, crib_details = check_cribs(pt)
                qg = score_per_char(pt)
                ic_val = ic(pt)
                results.append((crib_count, qg, cipher_name, f"{alpha_name}/{key_label}", pt, crib_details, ic_val))

    results.sort(key=lambda x: (-x[0], -x[1]))
    for count, qg, cipher, alph, pt, details, ic_val in results[:8]:
        det_str = f" [{', '.join(details)}]" if details else ""
        print(f"  {cipher:8s}/{alph:18s} crib={count:2d}/24 qg={qg:.4f} IC={ic_val:.4f}{det_str}")
        print(f"    PT: {pt}")


def method_8_spiral_read(ct: str, label: str) -> None:
    """Weltzeituhr (circular clock) reading: read K4 from the grid in
    a circular/spiral pattern, then apply standard Vigenere.

    K4 occupies a block: 4 chars in row 24 (cols 27-30) + 3 full rows (25-27).
    We can treat this as a sub-grid and read it in various patterns.

    Sub-grid dimensions: effectively 4 rows. Row 24 has 4 cols, rows 25-27 have 31 cols each.
    For spiraling, we rearrange the 97 chars into a rectangular block and read spirally.

    Interpretations:
      8a: Read K4 in column-major order from the 4-row grid
      8b: Read K4 in reverse-row boustrophedon
      8c: Spiral reading of a 97-char rectangle (various widths)
    """
    print(f"\n{'='*70}")
    print(f"METHOD 8: Spiral/circular grid readings [{label}]")
    print(f"{'='*70}")

    results = []

    # 8a: Column-major reading of K4's grid positions
    # K4 in the grid: row 24 cols 27-30, row 25 cols 0-30, row 26 cols 0-30, row 27 cols 0-30
    # Column-major: read col 0 down (rows 25,26,27), then col 1, ..., col 26, then cols 27-30 (rows 24,25,26,27)
    col_major_order = []
    # Cols 0-26: only rows 25,26,27
    for c in range(27):
        for r in [25, 26, 27]:
            pos = (r - 25) * 31 + c + 4  # +4 because first 4 chars are row 24
            if 0 <= pos < 97:
                col_major_order.append(pos)
    # Cols 27-30: rows 24,25,26,27
    for c in range(27, 31):
        for r in [24, 25, 26, 27]:
            pos_in_row24 = c - 27  # 0,1,2,3
            if r == 24:
                pos = pos_in_row24
            else:
                pos = (r - 25) * 31 + c + 4
            if 0 <= pos < 97:
                col_major_order.append(pos)

    if len(col_major_order) == 97 and len(set(col_major_order)) == 97:
        reordered = "".join(ct[p] for p in col_major_order)
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for cipher_name, fn in [("vig", vig_decrypt_str), ("beau", beau_decrypt_str)]:
                    pt = fn(reordered, kw, alpha)
                    crib_count, crib_details = check_cribs(pt)
                    qg = score_per_char(pt)
                    ic_val = ic(pt)
                    results.append((crib_count, qg, cipher_name, f"{alpha_name}/{kw}/colmaj", pt, crib_details, ic_val))
    else:
        print(f"  WARNING: Column-major order has {len(col_major_order)} positions ({len(set(col_major_order))} unique)")

    # 8b: Boustrophedon (reverse every other row)
    # Row 24: positions 0-3 (normal)
    # Row 25: positions 4-34 (reversed)
    # Row 26: positions 35-65 (normal)
    # Row 27: positions 66-96 (reversed)
    boust_order = list(range(0, 4))  # row 24 normal
    boust_order += list(range(34, 3, -1))  # row 25 reversed
    boust_order += list(range(35, 66))  # row 26 normal
    boust_order += list(range(96, 65, -1))  # row 27 reversed

    if len(boust_order) == 97 and len(set(boust_order)) == 97:
        reordered = "".join(ct[p] for p in boust_order)
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for cipher_name, fn in [("vig", vig_decrypt_str), ("beau", beau_decrypt_str)]:
                    pt = fn(reordered, kw, alpha)
                    crib_count, crib_details = check_cribs(pt)
                    qg = score_per_char(pt)
                    ic_val = ic(pt)
                    results.append((crib_count, qg, cipher_name, f"{alpha_name}/{kw}/boust", pt, crib_details, ic_val))

    # 8c: Spiral reading of various rectangular arrangements
    def spiral_read(grid: List[List[str]]) -> str:
        """Read a 2D grid in clockwise spiral order."""
        result = []
        if not grid or not grid[0]:
            return ""
        top, bottom, left, right = 0, len(grid) - 1, 0, len(grid[0]) - 1
        while top <= bottom and left <= right:
            for c in range(left, right + 1):
                result.append(grid[top][c])
            top += 1
            for r in range(top, bottom + 1):
                result.append(grid[r][right])
            right -= 1
            if top <= bottom:
                for c in range(right, left - 1, -1):
                    result.append(grid[bottom][c])
                bottom -= 1
            if left <= right:
                for r in range(bottom, top - 1, -1):
                    result.append(grid[r][left])
                left += 1
        return "".join(result)

    for width in [7, 8, 10, 13, 14, 31]:
        nrows = (97 + width - 1) // width
        # Pad with X
        padded = ct + "X" * (nrows * width - 97)
        grid = [list(padded[r*width:(r+1)*width]) for r in range(nrows)]
        spiraled = spiral_read(grid)[:97]

        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for cipher_name, fn in [("vig", vig_decrypt_str), ("beau", beau_decrypt_str)]:
                    pt = fn(spiraled, kw, alpha)
                    crib_count, crib_details = check_cribs(pt)
                    qg = score_per_char(pt)
                    ic_val = ic(pt)
                    results.append((crib_count, qg, cipher_name, f"{alpha_name}/{kw}/spiral_w{width}", pt, crib_details, ic_val))

    results.sort(key=lambda x: (-x[0], -x[1]))
    print(f"  Total configs tested: {len(results)}")
    for count, qg, cipher, alph, pt, details, ic_val in results[:8]:
        det_str = f" [{', '.join(details)}]" if details else ""
        print(f"  {cipher:8s}/{alph:30s} crib={count:2d}/24 qg={qg:.4f} IC={ic_val:.4f}{det_str}")
        print(f"    PT: {pt}")


# ── Extended grid key derivations ─────────────────────────────────────────────

def method_extended(ct: str, label: str) -> None:
    """Additional grid-based key derivations:
    - (row - col) mod 26
    - (col - row) mod 26
    - (row XOR col) mod 26
    - (row^2 + col) mod 26
    - (row + col^2) mod 26
    - abs(row - col) mod 26
    - (row * 31 + col) mod 26  (flat grid index mod 26)
    - (row + col * 7) mod 26
    - Fibonacci-like: f(i) = (row_i + col_(i-1)) mod 26
    """
    print(f"\n{'='*70}")
    print(f"EXTENDED: Additional grid key functions [{label}]")
    print(f"{'='*70}")

    formulas = {
        "row-col": [(K4_GRID[i][0] - K4_GRID[i][1]) % 26 for i in range(97)],
        "col-row": [(K4_GRID[i][1] - K4_GRID[i][0]) % 26 for i in range(97)],
        "row^col": [(K4_GRID[i][0] ^ K4_GRID[i][1]) % 26 for i in range(97)],
        "r2+c": [(K4_GRID[i][0]**2 + K4_GRID[i][1]) % 26 for i in range(97)],
        "r+c2": [(K4_GRID[i][0] + K4_GRID[i][1]**2) % 26 for i in range(97)],
        "abs_r-c": [abs(K4_GRID[i][0] - K4_GRID[i][1]) % 26 for i in range(97)],
        "flat%26": [(K4_GRID[i][0] * 31 + K4_GRID[i][1]) % 26 for i in range(97)],
        "r+7c": [(K4_GRID[i][0] + K4_GRID[i][1] * 7) % 26 for i in range(97)],
    }

    results = []
    for formula_name, keys in formulas.items():
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, decrypt_fn in [
                ("vig", vig_decrypt_numeric),
                ("beau", beau_decrypt_numeric),
                ("varbeau", varbeau_decrypt_numeric),
            ]:
                pt = decrypt_fn(ct, keys, alpha)
                crib_count, crib_details = check_cribs(pt)
                qg = score_per_char(pt)
                ic_val = ic(pt)
                results.append((crib_count, qg, cipher_name, f"{alpha_name}/{formula_name}", pt, crib_details, ic_val))

    results.sort(key=lambda x: (-x[0], -x[1]))
    print(f"  Total formula configs: {len(results)}")
    for count, qg, cipher, alph, pt, details, ic_val in results[:8]:
        det_str = f" [{', '.join(details)}]" if details else ""
        print(f"  {cipher:8s}/{alph:18s} crib={count:2d}/24 qg={qg:.4f} IC={ic_val:.4f}{det_str}")
        print(f"    PT: {pt}")


# ── Crib consistency analysis ─────────────────────────────────────────────────

def crib_analysis(ct: str, label: str) -> None:
    """For each grid-key method, recover key values at crib positions
    and check if they're consistent with a grid-based formula."""
    print(f"\n{'='*70}")
    print(f"CRIB CONSISTENCY ANALYSIS [{label}]")
    print(f"{'='*70}")

    for cipher in ["vig", "beau", "varbeau"]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            recovered = {}
            for pos, pt_ch in CRIB_DICT.items():
                ci = alpha.index(ct[pos])
                pi = alpha.index(pt_ch)
                if cipher == "vig":
                    recovered[pos] = (ci - pi) % 26
                elif cipher == "beau":
                    recovered[pos] = (ci + pi) % 26
                else:  # varbeau
                    recovered[pos] = (pi - ci) % 26

            # Check which grid formulas match at crib positions
            formulas = {
                "col%26": lambda r, c: c % 26,
                "row%26": lambda r, c: r % 26,
                "(r+c)%26": lambda r, c: (r + c) % 26,
                "(r*c)%26": lambda r, c: (r * c) % 26,
                "(r-c)%26": lambda r, c: (r - c) % 26,
                "(c-r)%26": lambda r, c: (c - r) % 26,
                "flat%26": lambda r, c: (r * 31 + c) % 26,
                "(r^c)%26": lambda r, c: (r ^ c) % 26,
                "(r+7c)%26": lambda r, c: (r + 7 * c) % 26,
                "(7r+c)%26": lambda r, c: (7 * r + c) % 26,
            }

            for fname, ffunc in formulas.items():
                matches = 0
                for pos in sorted(recovered):
                    r, c = K4_GRID[pos]
                    expected = ffunc(r, c)
                    if expected == recovered[pos]:
                        matches += 1
                if matches >= 10:  # Only report if many match
                    print(f"  {cipher}/{alpha_name} x {fname}: {matches}/24 crib positions match")

            # Print recovered key values for manual inspection
            key_vals = [f"{pos}:{recovered[pos]:2d}({AZ[recovered[pos]]})" for pos in sorted(recovered)]
            if cipher == "vig" and alpha_name == "AZ":
                print(f"\n  Key recovery [{cipher}/{alpha_name}]:")
                for kv in key_vals:
                    print(f"    {kv}", end="")
                print()

                # Show key values with grid position
                print(f"  Position -> key -> grid(row,col):")
                for pos in sorted(recovered):
                    r, c = K4_GRID[pos]
                    k = recovered[pos]
                    print(f"    K4[{pos:2d}] ct={ct[pos]} pt={CRIB_DICT[pos]} "
                          f"key={k:2d}({AZ[k]}) grid=({r},{c:2d}) "
                          f"col%26={c%26:2d} r+c={r+c:2d} r*c={r*c:3d}")


# ── Keyword × grid-column with offsets ────────────────────────────────────────

def method_6_extended(ct: str, label: str) -> None:
    """Try KRYPTOS[(col + offset) mod 7] for all offsets 0-6,
    plus KRYPTOS[(col * stride + offset) mod 7] for strides 1-6.
    Also try the same for other period-7 keywords and period-8 (ABSCISSA).
    """
    print(f"\n{'='*70}")
    print(f"METHOD 6-EXT: Keyword[f(col) mod period] with offsets [{label}]")
    print(f"{'='*70}")

    results = []

    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK"]:
        period = len(kw)
        for offset in range(period):
            keys = [AZ.index(kw[(K4_GRID[i][1] + offset) % period]) for i in range(97)]
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for cipher_name, decrypt_fn in [
                    ("vig", vig_decrypt_numeric),
                    ("beau", beau_decrypt_numeric),
                ]:
                    pt = decrypt_fn(ct, keys, alpha)
                    crib_count, crib_details = check_cribs(pt)
                    qg = score_per_char(pt)
                    ic_val = ic(pt)
                    results.append((crib_count, qg, cipher_name,
                                    f"{alpha_name}/{kw}/col+{offset}", pt, crib_details, ic_val))

    # Also: key from row position in keyword
    for kw in ["KRYPTOS", "ABSCISSA"]:
        period = len(kw)
        for offset in range(period):
            keys = [AZ.index(kw[(K4_GRID[i][0] + offset) % period]) for i in range(97)]
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for cipher_name, decrypt_fn in [
                    ("vig", vig_decrypt_numeric),
                    ("beau", beau_decrypt_numeric),
                ]:
                    pt = decrypt_fn(ct, keys, alpha)
                    crib_count, crib_details = check_cribs(pt)
                    qg = score_per_char(pt)
                    ic_val = ic(pt)
                    results.append((crib_count, qg, cipher_name,
                                    f"{alpha_name}/{kw}/row+{offset}", pt, crib_details, ic_val))

    results.sort(key=lambda x: (-x[0], -x[1]))
    print(f"  Total configs tested: {len(results)}")
    for count, qg, cipher, alph, pt, details, ic_val in results[:10]:
        det_str = f" [{', '.join(details)}]" if details else ""
        print(f"  {cipher:8s}/{alph:28s} crib={count:2d}/24 qg={qg:.4f} IC={ic_val:.4f}{det_str}")
        print(f"    PT: {pt}")


# ── Brute-force: find ANY additive key offset for grid-col that satisfies cribs ──

def method_brute_col_key(ct: str, label: str) -> None:
    """For each cipher and alphabet, find all possible single-letter key offsets (a,b)
    such that key[i] = (a*col + b) mod 26 satisfies ALL 24 crib positions.

    Also try key[i] = (a*row + b*col + c) mod 26 for small a,b,c.
    """
    print(f"\n{'='*70}")
    print(f"BRUTE FORCE: key = (a*col + b) mod 26 at cribs [{label}]")
    print(f"{'='*70}")

    for cipher in ["vig", "beau", "varbeau"]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            # Recover required key values at crib positions
            required = {}
            for pos, pt_ch in CRIB_DICT.items():
                ci = alpha.index(ct[pos])
                pi = alpha.index(pt_ch)
                if cipher == "vig":
                    required[pos] = (ci - pi) % 26
                elif cipher == "beau":
                    required[pos] = (ci + pi) % 26
                else:
                    required[pos] = (pi - ci) % 26

            # Try key = (a*col + b) mod 26
            for a in range(26):
                for b in range(26):
                    match = True
                    for pos, k_needed in required.items():
                        _, c = K4_GRID[pos]
                        if (a * c + b) % 26 != k_needed:
                            match = False
                            break
                    if match:
                        keys = [(a * K4_GRID[i][1] + b) % 26 for i in range(97)]
                        pt = vig_decrypt_numeric(ct, keys, alpha) if cipher == "vig" else \
                             beau_decrypt_numeric(ct, keys, alpha) if cipher == "beau" else \
                             varbeau_decrypt_numeric(ct, keys, alpha)
                        qg = score_per_char(pt)
                        print(f"  MATCH: {cipher}/{alpha_name} a={a} b={b}: qg={qg:.4f} PT={pt}")

            # Try key = (a*row + b*col + c) mod 26
            found = 0
            for a in range(26):
                for b in range(26):
                    for c in range(26):
                        match = True
                        for pos, k_needed in required.items():
                            r, col = K4_GRID[pos]
                            if (a * r + b * col + c) % 26 != k_needed:
                                match = False
                                break
                        if match:
                            keys = [(a * K4_GRID[i][0] + b * K4_GRID[i][1] + c) % 26 for i in range(97)]
                            if cipher == "vig":
                                pt = vig_decrypt_numeric(ct, keys, alpha)
                            elif cipher == "beau":
                                pt = beau_decrypt_numeric(ct, keys, alpha)
                            else:
                                pt = varbeau_decrypt_numeric(ct, keys, alpha)
                            qg = score_per_char(pt)
                            ic_val = ic(pt)
                            crib_count, crib_details = check_cribs(pt)
                            det_str = f" [{', '.join(crib_details)}]" if crib_details else ""
                            print(f"  AFFINE: {cipher}/{alpha_name} a={a} b={b} c={c}: "
                                  f"crib={crib_count}/24 qg={qg:.4f} IC={ic_val:.4f}{det_str}")
                            print(f"    PT: {pt}")
                            found += 1
                            if found > 20:
                                print(f"  ... (stopping after 20, more exist)")
                                break
                    if found > 20:
                        break
                if found > 20:
                    break


# ── YAR position analysis ────────────────────────────────────────────────────

def yar_analysis() -> None:
    """Show details about YAR positions and what changes the modified CT makes."""
    print(f"\n{'='*70}")
    print("YAR POSITION ANALYSIS")
    print(f"{'='*70}")

    yar_positions = [i for i, c in enumerate(K4_CARVED) if c in "YAR"]
    print(f"YAR positions in K4: {yar_positions}")
    print(f"YAR chars:           {[K4_CARVED[i] for i in yar_positions]}")
    print(f"Modified chars:      {[K4_YAR[i] for i in yar_positions]}")
    print(f"Grid coords:         {[K4_GRID[i] for i in yar_positions]}")

    print(f"\nDifferences between original and YAR-modified CT:")
    diffs = [(i, K4_CARVED[i], K4_YAR[i]) for i in range(97) if K4_CARVED[i] != K4_YAR[i]]
    for pos, orig, mod in diffs:
        r, c = K4_GRID[pos]
        is_crib = "CRIB" if pos in CRIB_DICT else ""
        print(f"  pos {pos:2d} ({r},{c:2d}): {orig} -> {mod}  {is_crib}")

    # Check IC of both CTs at various periods
    print(f"\nIC comparison:")
    print(f"  Original: {ic(K4_CARVED):.4f}")
    print(f"  YAR mod:  {ic(K4_YAR):.4f}")

    for period in [7, 8, 10, 13]:
        # Friedman-style IC for periodic key
        ic_orig = []
        ic_mod = []
        for offset in range(period):
            slice_orig = K4_CARVED[offset::period]
            slice_mod = K4_YAR[offset::period]
            ic_orig.append(ic(slice_orig))
            ic_mod.append(ic(slice_mod))
        avg_orig = sum(ic_orig) / len(ic_orig)
        avg_mod = sum(ic_mod) / len(ic_mod)
        print(f"  Period {period:2d}: orig avg IC={avg_orig:.4f}, YAR avg IC={avg_mod:.4f}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    start_time = time.time()

    print("=" * 70)
    print("E-YAR-GRIDKEY: Grid-Position Key Derivation for K4")
    print("Tests 8 key methods on original AND YAR-modified CT")
    print("=" * 70)
    print(f"\nK4 Original: {K4_CARVED}")
    print(f"K4 YAR Mod:  {K4_YAR}")
    print(f"KA alphabet: {KA}")
    print(f"AZ alphabet: {AZ}")
    print(f"\nGrid layout: K4 starts at row {K4_GRID_START_ROW}, col {K4_GRID_START_COL}")
    print(f"  pos  0-3:  row 24, cols 27-30 (OBKR)")
    print(f"  pos  4-34: row 25, cols 0-30")
    print(f"  pos 35-65: row 26, cols 0-30")
    print(f"  pos 66-96: row 27, cols 0-30")

    # YAR analysis
    yar_analysis()

    # Run all methods on both CTs
    for ct_label, ct in [("ORIGINAL", K4_CARVED), ("YAR-MODIFIED", K4_YAR)]:
        print(f"\n\n{'#'*70}")
        print(f"#  TESTING ON: {ct_label} CT")
        print(f"{'#'*70}")

        method_1_col_mod26(ct, ct_label)
        method_2_row_key(ct, ct_label)
        method_3_diagonal(ct, ct_label)
        method_4_multiplicative(ct, ct_label)
        method_5_tableau_key(ct, ct_label)
        method_6_kryptos_grid_col(ct, ct_label)
        method_7_k3_pt_running_key(ct, ct_label)
        method_8_spiral_read(ct, ct_label)
        method_extended(ct, ct_label)
        method_6_extended(ct, ct_label)

    # Crib consistency analysis (most important -- what key does the grid need?)
    for ct_label, ct in [("ORIGINAL", K4_CARVED), ("YAR-MODIFIED", K4_YAR)]:
        crib_analysis(ct, ct_label)

    # Brute force linear key search
    for ct_label, ct in [("ORIGINAL", K4_CARVED), ("YAR-MODIFIED", K4_YAR)]:
        method_brute_col_key(ct, ct_label)

    elapsed = time.time() - start_time
    print(f"\n{'='*70}")
    print(f"COMPLETED in {elapsed:.1f}s")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
