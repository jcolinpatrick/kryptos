#!/usr/bin/env python3
"""
Cipher:   Multi-layer (Vigenère / Beaufort / Autokey / Two-keyword compound)
Family:   team
Status:   active
Keyspace: ~50,000 configs
Last run: 2026-03-09
Best score: TBD

Exhaustive test of POINT and POINT-derived keywords for K4 decryption.
Tests: direct decrypt, null-mask + decrypt, autokey, two-keyword compound.
"""
from __future__ import annotations

import json
import math
import sys
import os
from collections import Counter
from typing import Dict, List, Optional, Tuple

# ── Constants (from kernel) ──────────────────────────────────────────────────

CT = (
    "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWAT"
    "JKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
)
CT_LEN = 97
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ_IDX = {c: i for i, c in enumerate(AZ)}
KA_IDX = {c: i for i, c in enumerate(KA)}

CRIBS = [
    "EASTNORTHEAST", "BERLINCLOCK", "EAST", "NORTH", "BERLIN",
    "CLOCK", "THE", "THAT", "SLOWLY", "INVISIBLE", "THIS",
    "SOUTH", "WEST"
]

# ── Quadgram scorer ─────────────────────────────────────────────────────────

QUADGRAMS: Dict[str, float] = {}
QG_FLOOR: float = -10.0

def load_quadgrams():
    global QUADGRAMS, QG_FLOOR
    qg_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "english_quadgrams.json")
    qg_path = os.path.normpath(qg_path)
    if not os.path.exists(qg_path):
        qg_path = "/home/cpatrick/kryptos/data/english_quadgrams.json"
    with open(qg_path) as f:
        QUADGRAMS.update(json.load(f))
    if QUADGRAMS:
        QG_FLOOR = min(QUADGRAMS.values()) - 1.0

def qg_score(text: str) -> float:
    """Quadgram log-probability score per character."""
    if len(text) < 4:
        return -99.0
    total = 0.0
    for i in range(len(text) - 3):
        gram = text[i:i+4]
        total += QUADGRAMS.get(gram, QG_FLOOR)
    return total / len(text)

def ic(text: str) -> float:
    """Index of coincidence."""
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    return sum(f * (f - 1) for f in counts.values()) / (n * (n - 1))

def check_cribs(text: str) -> List[str]:
    """Return list of crib substrings found in text."""
    found = []
    for crib in CRIBS:
        if crib in text:
            found.append(crib)
    return found

# ── Cipher operations ────────────────────────────────────────────────────────

def char_to_num(c: str, alpha: str, idx: dict) -> int:
    return idx[c]

def num_to_char(n: int, alpha: str) -> str:
    return alpha[n % 26]

def vig_decrypt(ct: str, key: str, alpha: str = AZ, idx: dict = None) -> str:
    """Vigenère decrypt: PT[i] = (CT[i] - KEY[i]) mod 26"""
    if idx is None:
        idx = AZ_IDX if alpha == AZ else KA_IDX
    klen = len(key)
    out = []
    for i, c in enumerate(ct):
        ci = idx[c]
        ki = idx[key[i % klen]]
        pi = (ci - ki) % 26
        out.append(alpha[pi])
    return "".join(out)

def beau_decrypt(ct: str, key: str, alpha: str = AZ, idx: dict = None) -> str:
    """Beaufort decrypt: PT[i] = (KEY[i] - CT[i]) mod 26"""
    if idx is None:
        idx = AZ_IDX if alpha == AZ else KA_IDX
    klen = len(key)
    out = []
    for i, c in enumerate(ct):
        ci = idx[c]
        ki = idx[key[i % klen]]
        pi = (ki - ci) % 26
        out.append(alpha[pi])
    return "".join(out)

def var_beau_decrypt(ct: str, key: str, alpha: str = AZ, idx: dict = None) -> str:
    """Variant Beaufort: PT[i] = (CT[i] + KEY[i]) mod 26"""
    if idx is None:
        idx = AZ_IDX if alpha == AZ else KA_IDX
    klen = len(key)
    out = []
    for i, c in enumerate(ct):
        ci = idx[c]
        ki = idx[key[i % klen]]
        pi = (ci + ki) % 26
        out.append(alpha[pi])
    return "".join(out)

def autokey_pt_decrypt(ct: str, primer: str, alpha: str = AZ, idx: dict = None) -> str:
    """Autokey Vigenère (plaintext autokey): key = primer + plaintext"""
    if idx is None:
        idx = AZ_IDX if alpha == AZ else KA_IDX
    key_stream = list(idx[c] for c in primer)
    out = []
    for i, c in enumerate(ct):
        ci = idx[c]
        ki = key_stream[i] if i < len(key_stream) else idx[out[i - len(primer)]]
        pi = (ci - ki) % 26
        pt_char = alpha[pi]
        out.append(pt_char)
        if i >= len(primer) - 1:
            pass  # plaintext already appended
        key_stream.append(idx[pt_char])
    return "".join(out)

def autokey_ct_decrypt(ct: str, primer: str, alpha: str = AZ, idx: dict = None) -> str:
    """Autokey Vigenère (ciphertext autokey): key = primer + ciphertext"""
    if idx is None:
        idx = AZ_IDX if alpha == AZ else KA_IDX
    out = []
    for i, c in enumerate(ct):
        ci = idx[c]
        if i < len(primer):
            ki = idx[primer[i]]
        else:
            ki = idx[ct[i - len(primer)]]
        pi = (ci - ki) % 26
        out.append(alpha[pi])
    return "".join(out)

def autokey_beau_pt_decrypt(ct: str, primer: str, alpha: str = AZ, idx: dict = None) -> str:
    """Beaufort autokey (plaintext): PT[i] = (KEY[i] - CT[i]) mod 26"""
    if idx is None:
        idx = AZ_IDX if alpha == AZ else KA_IDX
    key_stream = list(idx[c] for c in primer)
    out = []
    for i, c in enumerate(ct):
        ci = idx[c]
        ki = key_stream[i] if i < len(key_stream) else idx[out[i - len(primer)]]
        pi = (ki - ci) % 26
        pt_char = alpha[pi]
        out.append(pt_char)
        key_stream.append(idx[pt_char])
    return "".join(out)

def autokey_beau_ct_decrypt(ct: str, primer: str, alpha: str = AZ, idx: dict = None) -> str:
    """Beaufort autokey (ciphertext): PT[i] = (KEY[i] - CT[i]) mod 26"""
    if idx is None:
        idx = AZ_IDX if alpha == AZ else KA_IDX
    out = []
    for i, c in enumerate(ct):
        ci = idx[c]
        if i < len(primer):
            ki = idx[primer[i]]
        else:
            ki = idx[ct[i - len(primer)]]
        pi = (ki - ci) % 26
        out.append(alpha[pi])
    return "".join(out)

# ── Results collection ───────────────────────────────────────────────────────

class Result:
    __slots__ = ("test", "keywords", "cipher", "alphabet", "plaintext", "qg", "ic_val", "cribs_found")

    def __init__(self, test: str, keywords: str, cipher: str, alphabet: str,
                 plaintext: str, qg: float, ic_val: float, cribs_found: List[str]):
        self.test = test
        self.keywords = keywords
        self.cipher = cipher
        self.alphabet = alphabet
        self.plaintext = plaintext
        self.qg = qg
        self.ic_val = ic_val
        self.cribs_found = cribs_found

    def __repr__(self):
        cribs_str = f"  *** CRIBS: {self.cribs_found}" if self.cribs_found else ""
        return (f"[{self.test}] {self.keywords} | {self.cipher} | {self.alphabet} | "
                f"QG={self.qg:.4f} IC={self.ic_val:.4f} | {self.plaintext[:60]}...{cribs_str}")

ALL_RESULTS: List[Result] = []
CRIB_HITS: List[Result] = []
CONFIGS_TESTED = 0

def record(test: str, keywords: str, cipher: str, alphabet: str, pt: str):
    global CONFIGS_TESTED
    CONFIGS_TESTED += 1
    qg = qg_score(pt)
    ic_val = ic(pt)
    cribs_found = check_cribs(pt)
    r = Result(test, keywords, cipher, alphabet, pt, qg, ic_val, cribs_found)
    if cribs_found:
        CRIB_HITS.append(r)
        print(f"\n*** CRIB HIT *** {r}\n", flush=True)
    if qg > -6.0:
        ALL_RESULTS.append(r)
    elif len(ALL_RESULTS) < 500:
        # Keep top results even below threshold for final ranking
        ALL_RESULTS.append(r)

# ── Test 1: Direct decryption ────────────────────────────────────────────────

def test1_direct():
    print("=" * 80)
    print("TEST 1: Direct decryption of full K4 (97 chars)")
    print("=" * 80, flush=True)

    keywords = [
        "POINT", "EEXBD", "SIXPOINTFIVE", "FVOEEXBDMVPN", "POINTFIVE",
        "SIXPOINT", "THEPOINT", "WHATSTHEPOINT", "COMPASSPOINT", "DECIMALPOINT"
    ]

    for kw in keywords:
        # Map keyword to KA if needed (check all chars are in AZ)
        kw_az = kw  # all are standard A-Z

        for alpha_name, alpha, idx in [("AZ", AZ, AZ_IDX), ("KA", KA, KA_IDX)]:
            # Vigenère
            pt = vig_decrypt(CT, kw, alpha, idx)
            record("T1-direct", kw, "Vig", alpha_name, pt)

            # Beaufort
            pt = beau_decrypt(CT, kw, alpha, idx)
            record("T1-direct", kw, "Beau", alpha_name, pt)

            # Variant Beaufort
            pt = var_beau_decrypt(CT, kw, alpha, idx)
            record("T1-direct", kw, "VBeau", alpha_name, pt)

    print(f"  Test 1 complete: {CONFIGS_TESTED} configs tested", flush=True)

# ── Test 2 & 3: Null-mask keyword + second keyword decrypt ───────────────────

def compute_d_values(ct: str, key: str, mode: str = "vig", alpha: str = AZ, idx: dict = None) -> List[int]:
    """Compute D[i] values for null-mask generation."""
    if idx is None:
        idx = AZ_IDX if alpha == AZ else KA_IDX
    klen = len(key)
    d_vals = []
    for i, c in enumerate(ct):
        ci = idx[c]
        ki = idx[key[i % klen]]
        if mode == "vig":
            d_vals.append((ci - ki) % 26)
        else:  # beaufort
            d_vals.append((ki - ci) % 26)
    return d_vals

def null_masks_from_d(d_vals: List[int]) -> List[Tuple[str, List[int]]]:
    """Generate null masks from D values. Returns (description, null_positions) pairs."""
    n = len(d_vals)
    masks = []

    # Method 1: D[i] mod 4 == r
    for r in range(4):
        nulls = [i for i in range(n) if d_vals[i] % 4 == r]
        if 20 <= len(nulls) <= 28:  # near 24
            masks.append((f"mod4=={r}(n={len(nulls)})", nulls))

    # Method 2: D[i] mod 5 == r
    for r in range(5):
        nulls = [i for i in range(n) if d_vals[i] % 5 == r]
        if 15 <= len(nulls) <= 28:
            masks.append((f"mod5=={r}(n={len(nulls)})", nulls))

    # Method 3: D[i] < threshold
    for thresh in range(1, 26):
        nulls = [i for i in range(n) if d_vals[i] < thresh]
        if len(nulls) == 24:
            masks.append((f"D<{thresh}(n=24)", nulls))
        elif 22 <= len(nulls) <= 26 and len(nulls) != 24:
            masks.append((f"D<{thresh}(n={len(nulls)})", nulls))

    # Method 4: Bottom 24 by D value (lowest D = null)
    ranked = sorted(range(n), key=lambda i: (d_vals[i], i))
    masks.append(("bottom24", ranked[:24]))

    # Method 5: Top 24 by D value (highest D = null)
    masks.append(("top24", ranked[-24:]))

    # Method 6: D[i] == 0 (exact matches)
    zeros = [i for i in range(n) if d_vals[i] == 0]
    if 5 <= len(zeros) <= 40:
        masks.append((f"D==0(n={len(zeros)})", zeros))

    # Method 7: D[i] is even
    evens = [i for i in range(n) if d_vals[i] % 2 == 0]
    if 20 <= len(evens) <= 28:
        masks.append((f"even(n={len(evens)})", evens))

    # Method 8: D[i] is odd
    odds = [i for i in range(n) if d_vals[i] % 2 == 1]
    if 20 <= len(odds) <= 28:
        masks.append((f"odd(n={len(odds)})", odds))

    return masks

def remove_nulls(ct: str, null_positions: List[int]) -> str:
    """Remove characters at null positions, return remaining."""
    null_set = set(null_positions)
    return "".join(c for i, c in enumerate(ct) if i not in null_set)

def test_null_mask(test_name: str, mask_kw: str):
    print(f"\n{'=' * 80}")
    print(f"{test_name}: Null-mask keyword={mask_kw}")
    print("=" * 80, flush=True)

    decrypt_keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "PARALLAX",
        "COLOPHON", "HOROLOGE", "SHADOW", "POINT", "EEXBD",
        "SIXPOINTFIVE", "THEPOINT", "WHATSTHEPOINT"
    ]

    total = 0
    for mode_name, mode in [("Vig", "vig"), ("Beau", "beau")]:
        for alpha_name, alpha, idx in [("AZ", AZ, AZ_IDX), ("KA", KA, KA_IDX)]:
            d_vals = compute_d_values(CT, mask_kw, mode, alpha, idx)
            masks = null_masks_from_d(d_vals)

            for mask_desc, null_pos in masks:
                reduced_ct = remove_nulls(CT, null_pos)
                rlen = len(reduced_ct)
                if rlen < 30 or rlen > 90:
                    continue

                for dkw in decrypt_keywords:
                    for da_name, da, di in [("AZ", AZ, AZ_IDX), ("KA", KA, KA_IDX)]:
                        # Vigenère decrypt
                        pt = vig_decrypt(reduced_ct, dkw, da, di)
                        record(test_name, f"{mask_kw}({mode_name}/{alpha_name})→{mask_desc}→{dkw}",
                               "Vig", da_name, pt)
                        total += 1

                        # Beaufort decrypt
                        pt = beau_decrypt(reduced_ct, dkw, da, di)
                        record(test_name, f"{mask_kw}({mode_name}/{alpha_name})→{mask_desc}→{dkw}",
                               "Beau", da_name, pt)
                        total += 1

                        # Variant Beaufort
                        pt = var_beau_decrypt(reduced_ct, dkw, da, di)
                        record(test_name, f"{mask_kw}({mode_name}/{alpha_name})→{mask_desc}→{dkw}",
                               "VBeau", da_name, pt)
                        total += 1

    print(f"  {test_name} complete: {total} configs tested this test", flush=True)

# ── Test 4: Coordinate digits as key ─────────────────────────────────────────

def test4_coordinates():
    print(f"\n{'=' * 80}")
    print("TEST 4: Coordinate digits as null-mask key + POINT/EEXBD decrypt")
    print("=" * 80, flush=True)

    # Digits from K2 coordinates: 38°57'6.5"N, 77°8'44"W
    digits = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]

    # A=0 mapping
    key_a0 = "".join(AZ[d] for d in digits)  # DIFHGFHHIEE
    # A=1 mapping
    key_a1 = "".join(AZ[d - 1] if d > 0 else AZ[25] for d in digits)  # CHEGFEGGHDD

    print(f"  Coord key (A=0): {key_a0}")
    print(f"  Coord key (A=1): {key_a1}", flush=True)

    decrypt_kws = [
        "POINT", "EEXBD", "KRYPTOS", "ABSCISSA", "PALIMPSEST",
        "SIXPOINTFIVE", "THEPOINT", "DEFECTOR", "PARALLAX"
    ]

    total = 0
    for coord_key_name, coord_key in [("coordA0", key_a0), ("coordA1", key_a1)]:
        for mode_name, mode in [("Vig", "vig"), ("Beau", "beau")]:
            for alpha_name, alpha, idx in [("AZ", AZ, AZ_IDX), ("KA", KA, KA_IDX)]:
                d_vals = compute_d_values(CT, coord_key, mode, alpha, idx)
                masks = null_masks_from_d(d_vals)

                for mask_desc, null_pos in masks:
                    reduced_ct = remove_nulls(CT, null_pos)
                    rlen = len(reduced_ct)
                    if rlen < 30 or rlen > 90:
                        continue

                    for dkw in decrypt_kws:
                        for da_name, da, di in [("AZ", AZ, AZ_IDX), ("KA", KA, KA_IDX)]:
                            pt = vig_decrypt(reduced_ct, dkw, da, di)
                            record("T4-coord", f"{coord_key_name}({mode_name}/{alpha_name})→{mask_desc}→{dkw}",
                                   "Vig", da_name, pt)
                            total += 1

                            pt = beau_decrypt(reduced_ct, dkw, da, di)
                            record("T4-coord", f"{coord_key_name}({mode_name}/{alpha_name})→{mask_desc}→{dkw}",
                                   "Beau", da_name, pt)
                            total += 1

    print(f"  Test 4 complete: {total} configs tested this test", flush=True)

# ── Test 5: Autokey ──────────────────────────────────────────────────────────

def test5_autokey():
    print(f"\n{'=' * 80}")
    print("TEST 5: POINT-derived autokey")
    print("=" * 80, flush=True)

    primers = [
        "POINT", "EEXBD", "SIXPOINTFIVE", "THEPOINT", "WHATSTHEPOINT",
        "KRYPTOS", "ABSCISSA", "PALIMPSEST", "POINTFIVE", "SIXPOINT",
        "COMPASSPOINT", "DECIMALPOINT", "FVOEEXBDMVPN"
    ]

    total = 0
    for primer in primers:
        for alpha_name, alpha, idx in [("AZ", AZ, AZ_IDX), ("KA", KA, KA_IDX)]:
            # Plaintext autokey (Vigenère)
            pt = autokey_pt_decrypt(CT, primer, alpha, idx)
            record("T5-autokey", primer, "AutokeyPT-Vig", alpha_name, pt)
            total += 1

            # Ciphertext autokey (Vigenère)
            pt = autokey_ct_decrypt(CT, primer, alpha, idx)
            record("T5-autokey", primer, "AutokeyCT-Vig", alpha_name, pt)
            total += 1

            # Plaintext autokey (Beaufort)
            pt = autokey_beau_pt_decrypt(CT, primer, alpha, idx)
            record("T5-autokey", primer, "AutokeyPT-Beau", alpha_name, pt)
            total += 1

            # Ciphertext autokey (Beaufort)
            pt = autokey_beau_ct_decrypt(CT, primer, alpha, idx)
            record("T5-autokey", primer, "AutokeyCT-Beau", alpha_name, pt)
            total += 1

    print(f"  Test 5 complete: {total} configs tested this test", flush=True)

# ── Test 6: Two-keyword compound ─────────────────────────────────────────────

def test6_compound():
    print(f"\n{'=' * 80}")
    print("TEST 6: Two-keyword compound decryption")
    print("=" * 80, flush=True)

    point_kws = ["POINT", "EEXBD", "SIXPOINTFIVE", "FVOEEXBDMVPN", "THEPOINT",
                 "WHATSTHEPOINT", "POINTFIVE", "SIXPOINT", "COMPASSPOINT", "DECIMALPOINT"]
    base_kws = ["KRYPTOS", "ABSCISSA", "PALIMPSEST"]

    # All pairs from both sets, plus intra-set pairs for point keywords
    pairs = []
    for pk in point_kws:
        for bk in base_kws:
            pairs.append((pk, bk))
            pairs.append((bk, pk))
    # Also pairs within point keywords
    for i, pk1 in enumerate(point_kws):
        for pk2 in point_kws[i+1:]:
            pairs.append((pk1, pk2))
            pairs.append((pk2, pk1))

    modes = [
        ("Vig+Vig", vig_decrypt, vig_decrypt),
        ("Beau+Vig", beau_decrypt, vig_decrypt),
        ("Vig+Beau", vig_decrypt, beau_decrypt),
        ("Beau+Beau", beau_decrypt, beau_decrypt),
        ("VBeau+Vig", var_beau_decrypt, vig_decrypt),
        ("Vig+VBeau", vig_decrypt, var_beau_decrypt),
    ]

    total = 0
    for w1, w2 in pairs:
        for mode_name, fn1, fn2 in modes:
            for alpha_name, alpha, idx in [("AZ", AZ, AZ_IDX), ("KA", KA, KA_IDX)]:
                intermediate = fn1(CT, w1, alpha, idx)
                pt = fn2(intermediate, w2, alpha, idx)
                record("T6-compound", f"{w1}+{w2}", mode_name, alpha_name, pt)
                total += 1

    print(f"  Test 6 complete: {total} configs tested this test", flush=True)

# ── Test 7: POINT keywords with known K1-K3 keys on K4 ──────────────────────

def test7_k123_keys_with_point():
    """Test POINT keywords combined with K1-K3 known keys."""
    print(f"\n{'=' * 80}")
    print("TEST 7: POINT keywords with K1-K3 historical keys")
    print("=" * 80, flush=True)

    # K1 used PALIMPSEST, K2 used ABSCISSA, K3 used unknown transposition
    # Try POINT combined with these in different ways

    point_kws = ["POINT", "EEXBD", "THEPOINT", "WHATSTHEPOINT", "SIXPOINTFIVE"]

    total = 0
    for pk in point_kws:
        # Interleaved keys: alternate characters from two keywords
        for bk in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            # Method A: Concatenated key
            concat_key = pk + bk
            for alpha_name, alpha, idx in [("AZ", AZ, AZ_IDX), ("KA", KA, KA_IDX)]:
                pt = vig_decrypt(CT, concat_key, alpha, idx)
                record("T7-concat", f"{pk}+{bk}", "Vig-concat", alpha_name, pt)
                total += 1
                pt = beau_decrypt(CT, concat_key, alpha, idx)
                record("T7-concat", f"{pk}+{bk}", "Beau-concat", alpha_name, pt)
                total += 1

            # Method B: XOR'd key (add mod 26)
            max_len = max(len(pk), len(bk))
            xor_key = ""
            for i in range(max_len):
                p = AZ_IDX[pk[i % len(pk)]]
                b = AZ_IDX[bk[i % len(bk)]]
                xor_key += AZ[(p + b) % 26]
            for alpha_name, alpha, idx in [("AZ", AZ, AZ_IDX), ("KA", KA, KA_IDX)]:
                pt = vig_decrypt(CT, xor_key, alpha, idx)
                record("T7-xor", f"XOR({pk},{bk})={xor_key}", "Vig", alpha_name, pt)
                total += 1
                pt = beau_decrypt(CT, xor_key, alpha, idx)
                record("T7-xor", f"XOR({pk},{bk})={xor_key}", "Beau", alpha_name, pt)
                total += 1

    print(f"  Test 7 complete: {total} configs tested this test", flush=True)

# ── Test 8: POINT as period marker for segmented decryption ──────────────────

def test8_segmented():
    """Segment K4 by POINT length (5) and try different keys per segment."""
    print(f"\n{'=' * 80}")
    print("TEST 8: POINT-period segmented decryption")
    print("=" * 80, flush=True)

    # Use POINT's numeric values [15, 14, 8, 13, 19] as segment boundaries or offsets

    point_vals = [AZ_IDX[c] for c in "POINT"]  # [15, 14, 8, 13, 19]

    decrypt_kws = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "POINT", "EEXBD"]

    total = 0

    # Method: shift each position by POINT value + running offset
    for dkw in decrypt_kws:
        for alpha_name, alpha, idx in [("AZ", AZ, AZ_IDX), ("KA", KA, KA_IDX)]:
            # Progressive key: POINT values used as offsets into the decrypt key
            out = []
            dk_len = len(dkw)
            for i, c in enumerate(CT):
                ci = idx[c]
                # Key position shifted by POINT[i%5]
                ki = idx[dkw[(i + point_vals[i % 5]) % dk_len]]
                pi = (ci - ki) % 26
                out.append(alpha[pi])
            pt = "".join(out)
            record("T8-segment", f"POINT-shift→{dkw}", "Vig-shifted", alpha_name, pt)
            total += 1

            # Beaufort version
            out = []
            for i, c in enumerate(CT):
                ci = idx[c]
                ki = idx[dkw[(i + point_vals[i % 5]) % dk_len]]
                pi = (ki - ci) % 26
                out.append(alpha[pi])
            pt = "".join(out)
            record("T8-segment", f"POINT-shift→{dkw}", "Beau-shifted", alpha_name, pt)
            total += 1

    print(f"  Test 8 complete: {total} configs tested this test", flush=True)

# ── Test 9: POINT with W-position awareness ─────────────────────────────────

def test9_w_positions():
    """Test POINT decryption aware of W positions (potential delimiters)."""
    print(f"\n{'=' * 80}")
    print("TEST 9: POINT + W-position null removal")
    print("=" * 80, flush=True)

    # W positions in K4
    w_positions = [i for i, c in enumerate(CT) if c == "W"]
    print(f"  W positions: {w_positions}", flush=True)

    # Try removing W positions as nulls, then decrypting
    # Also try W positions + additional nulls to reach 24

    point_kws = ["POINT", "EEXBD", "KRYPTOS", "ABSCISSA", "PALIMPSEST",
                 "SIXPOINTFIVE", "THEPOINT", "DEFECTOR", "PARALLAX"]

    total = 0

    # Method 1: Just remove W's
    ct_no_w = "".join(c for i, c in enumerate(CT) if i not in set(w_positions))
    print(f"  CT without W's ({len(ct_no_w)} chars): {ct_no_w[:50]}...", flush=True)

    for kw in point_kws:
        for alpha_name, alpha, idx in [("AZ", AZ, AZ_IDX), ("KA", KA, KA_IDX)]:
            pt = vig_decrypt(ct_no_w, kw, alpha, idx)
            record("T9-W", f"noW→{kw}", "Vig", alpha_name, pt)
            total += 1
            pt = beau_decrypt(ct_no_w, kw, alpha, idx)
            record("T9-W", f"noW→{kw}", "Beau", alpha_name, pt)
            total += 1
            pt = var_beau_decrypt(ct_no_w, kw, alpha, idx)
            record("T9-W", f"noW→{kw}", "VBeau", alpha_name, pt)
            total += 1

    # Method 2: Remove W's + use POINT D-values to select remaining 19 nulls
    for mode_name, mode in [("Vig", "vig"), ("Beau", "beau")]:
        for alpha_name, alpha, idx in [("AZ", AZ, AZ_IDX), ("KA", KA, KA_IDX)]:
            d_vals = compute_d_values(CT, "POINT", mode, alpha, idx)
            # Set W positions aside, find 19 more nulls from remaining positions
            non_w = [i for i in range(CT_LEN) if i not in set(w_positions)]
            non_w_d = [(d_vals[i], i) for i in non_w]
            non_w_d.sort()

            # Bottom 19 non-W positions by D value
            extra_nulls = [pos for _, pos in non_w_d[:19]]
            all_nulls = sorted(set(w_positions + extra_nulls))
            reduced = remove_nulls(CT, all_nulls)

            if 60 <= len(reduced) <= 80:
                for dkw in ["KRYPTOS", "ABSCISSA", "PALIMPSEST", "POINT", "EEXBD", "DEFECTOR"]:
                    for da_name, da, di in [("AZ", AZ, AZ_IDX), ("KA", KA, KA_IDX)]:
                        pt = vig_decrypt(reduced, dkw, da, di)
                        record("T9-W+null", f"W+POINT-{mode_name}bot19({alpha_name})→{dkw}",
                               "Vig", da_name, pt)
                        total += 1
                        pt = beau_decrypt(reduced, dkw, da, di)
                        record("T9-W+null", f"W+POINT-{mode_name}bot19({alpha_name})→{dkw}",
                               "Beau", da_name, pt)
                        total += 1

            # Top 19 non-W positions by D value
            extra_nulls = [pos for _, pos in non_w_d[-19:]]
            all_nulls = sorted(set(w_positions + extra_nulls))
            reduced = remove_nulls(CT, all_nulls)

            if 60 <= len(reduced) <= 80:
                for dkw in ["KRYPTOS", "ABSCISSA", "PALIMPSEST", "POINT", "EEXBD", "DEFECTOR"]:
                    for da_name, da, di in [("AZ", AZ, AZ_IDX), ("KA", KA, KA_IDX)]:
                        pt = vig_decrypt(reduced, dkw, da, di)
                        record("T9-W+null", f"W+POINT-{mode_name}top19({alpha_name})→{dkw}",
                               "Vig", da_name, pt)
                        total += 1
                        pt = beau_decrypt(reduced, dkw, da, di)
                        record("T9-W+null", f"W+POINT-{mode_name}top19({alpha_name})→{dkw}",
                               "Beau", da_name, pt)
                        total += 1

    print(f"  Test 9 complete: {total} configs tested this test", flush=True)

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("KRYPTOS K4 — POINT Keyword Exhaustive Test")
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"AZ: {AZ}")
    print(f"KA: {KA}")
    print()

    load_quadgrams()
    print(f"Loaded {len(QUADGRAMS)} quadgrams (floor={QG_FLOOR:.2f})")
    print()

    # Validate cipher operations
    test_ct = "HELLO"
    test_key = "KEY"
    enc = vig_decrypt(test_ct, test_key, AZ, AZ_IDX)
    # Sanity: vig_decrypt(vig_encrypt(PT, KEY), KEY) == PT
    # We just verify it runs without error
    print(f"Sanity check: Vig decrypt('HELLO', 'KEY') = {enc}")
    print()

    test1_direct()
    test_null_mask("T2-null-POINT", "POINT")
    test_null_mask("T3-null-EEXBD", "EEXBD")
    test4_coordinates()
    test5_autokey()
    test6_compound()
    test7_k123_keys_with_point()
    test8_segmented()
    test9_w_positions()

    # ── Final report ─────────────────────────────────────────────────────────
    print()
    print("=" * 80)
    print("FINAL REPORT")
    print("=" * 80)
    print(f"Total configurations tested: {CONFIGS_TESTED}")
    print()

    # Crib hits
    if CRIB_HITS:
        print(f"*** CRIB HITS: {len(CRIB_HITS)} ***")
        for r in CRIB_HITS:
            print(f"  {r}")
        print()
    else:
        print("No crib hits found.")
        print()

    # Results above -6.0
    above_threshold = [r for r in ALL_RESULTS if r.qg > -6.0]
    if above_threshold:
        above_threshold.sort(key=lambda r: r.qg, reverse=True)
        print(f"Results with QG/char > -6.0: {len(above_threshold)}")
        for r in above_threshold[:50]:
            print(f"  {r}")
        print()

    # Top 30 overall
    ALL_RESULTS.sort(key=lambda r: r.qg, reverse=True)
    print(f"TOP 30 RESULTS (by QG score, from {len(ALL_RESULTS)} stored):")
    for i, r in enumerate(ALL_RESULTS[:30]):
        print(f"  {i+1:2d}. {r}")
    print()

    # IC distribution of top results
    print("IC of top 10:")
    for r in ALL_RESULTS[:10]:
        print(f"  IC={r.ic_val:.4f} | {r.keywords} | {r.cipher}")
    print()

    print("Done.", flush=True)


if __name__ == "__main__":
    main()
