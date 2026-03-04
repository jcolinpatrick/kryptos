#!/usr/bin/env python3
"""
Cipher: non-columnar transposition
Family: transposition/other
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""blitz_strip_cipher_v2.py — Deeper strip cipher models for K4.

Follow-up to v1. Focuses on:
1. Exhaustive self-encrypt constrained search at longer periods (12-16)
2. Gronsfeld with keyword-derived numerical keys
3. Porta cipher (involutory, 13-letter key period)
4. Multi-ring cipher: independent rings for groups of positions
5. Heterogeneous stepping: cipher disk where step rule changes at boundaries
6. Two-pass strip: encrypt twice with different keywords
7. Key elimination + partial plaintext attack
8. Columnar-keyed strip: strip order changes every N positions (block cipher)

Run: cd /home/cpatrick/kryptos && PYTHONPATH=src python3 -u scripts/blitz_strip_cipher_v2.py
"""
from __future__ import annotations

import sys
import json
import time
import math
import itertools
import random
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, 'scripts')
from kbot_harness import (
    test_perm, test_unscramble, score_text, score_text_per_char,
    has_cribs, vig_decrypt, vig_encrypt, beau_decrypt,
    apply_permutation, load_quadgrams,
    K4_CARVED, AZ, KA, KEYWORDS, CRIBS,
)

N = 97
CT = K4_CARVED

CRIB_DEFS = [
    (21, "EASTNORTHEAST"),
    (63, "BERLINCLOCK"),
]
CRIB_MAP = {}
for _start, _text in CRIB_DEFS:
    for _j, _ch in enumerate(_text):
        CRIB_MAP[_start + _j] = _ch

# ─────────────────────────────────────────────────────────────────────────────
# RESULTS TRACKING
# ─────────────────────────────────────────────────────────────────────────────
results_dir = Path("results/blitz_strip_cipher_v2")
results_dir.mkdir(parents=True, exist_ok=True)

all_results: list[dict] = []
best_score = -9999.0
best_per_char = -99.0
best_entry: dict | None = None
total_tested = 0
CRIB_HITS: list[dict] = []
INTERESTING: list[dict] = []


def report(approach: str, note: str, pt: str, score: float, extra: dict | None = None):
    global best_score, best_per_char, best_entry, total_tested
    total_tested += 1
    per_char = score / max(1, len(pt) - 3) if len(pt) >= 4 else -10.0
    cribs = has_cribs(pt)

    entry = {
        "approach": approach,
        "note": str(note)[:300],
        "pt": pt,
        "score": score,
        "per_char": per_char,
        "cribs": cribs,
        "extra": extra or {},
    }
    all_results.append(entry)

    if cribs:
        CRIB_HITS.append(entry)
        print(f"\n{'='*60}")
        print(f"*** CRIB HIT! approach={approach}, per_char={per_char:.3f}")
        print(f"    PT={pt}")
        print(f"{'='*60}\n")

    if per_char > -5.5:
        INTERESTING.append(entry)

    if score > best_score:
        best_score = score
        best_per_char = per_char
        best_entry = entry


t_start = time.time()

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 1: PORTA CIPHER
# Porta is involutory (encrypt = decrypt), uses 13-letter key period,
# and performs a self-reciprocal substitution. Perfect for "two systems"
# because it naturally halves the alphabet.
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 1: Porta Cipher")
print("=" * 70)
t1 = time.time()

# Standard Porta tableau
PORTA_TABLE = [
    "NOPQRSTUVWXYZABCDEFGHIJKLM",  # A/B
    "OPQRSTUVWXYZNMABCDEFGHIJKL",  # C/D
    "PQRSTUVWXYZNOLMABCDEFGHIJK",  # E/F
    "QRSTUVWXYZNOPKLMABCDEFGHIJ",  # G/H
    "RSTUVWXYZNOPQJKLMABCDEFGHI",  # I/J
    "STUVWXYZNOPQRIJKLMABCDEFGH",  # K/L
    "TUVWXYZNOPQRSHIJKLMABCDEFG",  # M/N
    "UVWXYZNOPQRSTGHIJKLMABCDEF",  # O/P
    "VWXYZNOPQRSTUFGHIJKLMABCDE",  # Q/R
    "WXYZNOPQRSTUVEFGHIJKLMABCD",  # S/T
    "XYZNOPQRSTUVWDEFGHIJKLMABC",  # U/V
    "YZNOPQRSTUVWXCDEFGHIJKLMAB",  # W/X
    "ZNOPQRSTUVWXYBCDEFGHIJKLMA",  # Y/Z
]

def porta_decrypt(ct: str, key: str) -> str:
    """Porta cipher (involutory — encrypt = decrypt)."""
    pt = []
    kl = len(key)
    for i, c in enumerate(ct):
        k = key[i % kl]
        row = AZ.index(k) // 2  # 0-12 for A/B through Y/Z
        ci = AZ.index(c)
        pt.append(PORTA_TABLE[row][ci])
    return "".join(pt)

count_a1 = 0
for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SCHEIDT",
           "SANBORN", "BERLIN", "CLOCK", "LIGHT", "ANTIPODES",
           "ENIGMA", "MEDUSA"]:
    pt = porta_decrypt(CT, kw)
    score = score_text(pt)
    report(f"PORTA-{kw}", f"key={kw}", pt, score)
    count_a1 += 1

    # Also with KA-indexed key (use KA position of each key letter as row index)
    pt2_chars = []
    for i, c in enumerate(CT):
        k = kw[i % len(kw)]
        row = KA.index(k) // 2
        ci = AZ.index(c)
        pt2_chars.append(PORTA_TABLE[row % 13][ci])
    pt2 = "".join(pt2_chars)
    score2 = score_text(pt2)
    report(f"PORTA-KA-{kw}", f"KA-indexed key={kw}", pt2, score2)
    count_a1 += 1

print(f"  Porta: {count_a1} tested, {time.time()-t1:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 2: MULTI-TABLE CIPHER (different Vigenère square per segment)
# What if K4 uses different cipher methods for different segments?
# E.g., positions 0-20 use one key, 21-33 another, etc.
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 2: Multi-Segment Cipher (different key per segment)")
print("=" * 70)
t2 = time.time()

# Segments: [0,21), [21,34), [34,63), [63,74), [74,97)
# Between crib boundaries
SEGMENTS = [(0, 21), (21, 34), (34, 63), (63, 74), (74, 97)]

count_a2 = 0
SEGMENT_KEYS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SCHEIDT"]

for perm in itertools.permutations(range(len(SEGMENT_KEYS)), len(SEGMENTS)):
    for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
        for cipher_fn_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
            pt_parts = []
            for seg_idx, (start, end) in enumerate(SEGMENTS):
                seg_ct = CT[start:end]
                kw = SEGMENT_KEYS[perm[seg_idx]]
                pt_parts.append(cipher_fn(seg_ct, kw, alpha))
            pt = "".join(pt_parts)
            score = score_text(pt)
            report(f"MULTISEG-{cipher_fn_name}-{alpha_name}-p{''.join(map(str,perm))}",
                   f"segment keys={[SEGMENT_KEYS[p][:4] for p in perm]}",
                   pt, score)
            count_a2 += 1

    if count_a2 % 500 == 0:
        print(f"    ... {count_a2} multi-seg configs tested")

print(f"  Multi-segment: {count_a2} tested, {time.time()-t2:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 3: TWO-PASS ENCRYPTION (encrypt with key1, then key2)
# PT → Vig(key1) → Vig(key2) → CT
# Decrypt: CT → Vig_dec(key2) → Vig_dec(key1) → PT
# This is Scheidt's "two separate systems"
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 3: Two-Pass Encryption (two separate systems)")
print("=" * 70)
t3 = time.time()

count_a3 = 0
PASS_KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SCHEIDT"]

for kw1 in PASS_KEYWORDS:
    for kw2 in PASS_KEYWORDS:
        for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
            # Vig then Vig
            inter = vig_decrypt(CT, kw2, alpha)
            pt = vig_decrypt(inter, kw1, alpha)
            score = score_text(pt)
            report(f"2PASS-VV-{kw1[:5]}-{kw2[:5]}-{alpha_name}",
                   f"Vig({kw1}) then Vig({kw2})", pt, score)

            # Beau then Beau
            inter = beau_decrypt(CT, kw2, alpha)
            pt = beau_decrypt(inter, kw1, alpha)
            score = score_text(pt)
            report(f"2PASS-BB-{kw1[:5]}-{kw2[:5]}-{alpha_name}",
                   f"Beau({kw1}) then Beau({kw2})", pt, score)

            # Vig then Beau
            inter = beau_decrypt(CT, kw2, alpha)
            pt = vig_decrypt(inter, kw1, alpha)
            score = score_text(pt)
            report(f"2PASS-VB-{kw1[:5]}-{kw2[:5]}-{alpha_name}",
                   f"Vig({kw1}) then Beau({kw2})", pt, score)

            # Beau then Vig
            inter = vig_decrypt(CT, kw2, alpha)
            pt = beau_decrypt(inter, kw1, alpha)
            score = score_text(pt)
            report(f"2PASS-BV-{kw1[:5]}-{kw2[:5]}-{alpha_name}",
                   f"Beau({kw1}) then Vig({kw2})", pt, score)

            count_a3 += 4

# Two-pass with mixed alphabets (KA for one pass, AZ for other)
for kw1 in PASS_KEYWORDS[:3]:
    for kw2 in PASS_KEYWORDS[:3]:
        # KA then AZ
        inter = vig_decrypt(CT, kw2, AZ)
        pt = vig_decrypt(inter, kw1, KA)
        score = score_text(pt)
        report(f"2PASS-VV-KA-AZ-{kw1[:5]}-{kw2[:5]}",
               f"Vig/KA({kw1}) then Vig/AZ({kw2})", pt, score)

        inter = vig_decrypt(CT, kw2, KA)
        pt = vig_decrypt(inter, kw1, AZ)
        score = score_text(pt)
        report(f"2PASS-VV-AZ-KA-{kw1[:5]}-{kw2[:5]}",
               f"Vig/AZ({kw1}) then Vig/KA({kw2})", pt, score)

        inter = beau_decrypt(CT, kw2, AZ)
        pt = beau_decrypt(inter, kw1, KA)
        score = score_text(pt)
        report(f"2PASS-BB-KA-AZ-{kw1[:5]}-{kw2[:5]}",
               f"Beau/KA({kw1}) then Beau/AZ({kw2})", pt, score)

        inter = beau_decrypt(CT, kw2, KA)
        pt = beau_decrypt(inter, kw1, AZ)
        score = score_text(pt)
        report(f"2PASS-BB-AZ-KA-{kw1[:5]}-{kw2[:5]}",
               f"Beau/AZ({kw1}) then Beau/KA({kw2})", pt, score)
        count_a3 += 4

print(f"  Two-pass: {count_a3} tested, {time.time()-t3:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 4: HETEROGENEOUS STEPPING CIPHER DISK
# The stepping rule changes at known boundaries (crib positions).
# E.g., step by 1 normally but step by keyword letter at crib boundaries.
# Also: "Sanborn messed with it" — rule changes mid-message.
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 4: Heterogeneous Stepping Disk")
print("=" * 70)
t4 = time.time()

count_a4 = 0

# Define boundary positions where stepping rule might change
BOUNDARIES = [0, 21, 34, 63, 74]

def hetero_disk_decrypt(ct: str, alpha: str, rules: list[tuple[int, int]],
                         initial_shift: int) -> str:
    """
    Cipher disk with changing step rules at boundaries.
    rules: [(step_value, end_position), ...] — step_value active until end_pos
    """
    pt = []
    shift = initial_shift
    rule_idx = 0
    for i, c in enumerate(ct):
        # Advance rule if past boundary
        while rule_idx < len(rules) - 1 and i >= rules[rule_idx][1]:
            rule_idx += 1

        ci = alpha.index(c)
        pt.append(alpha[(ci - shift) % 26])
        shift = (shift + rules[rule_idx][0]) % 26

    return "".join(pt)


# Try various step patterns across segments
STEP_VALUES = [0, 1, 2, 3, 4, 5, 7, 8, 10, 11, 13, 25]
for init_shift in range(26):
    for s1 in STEP_VALUES:
        for s2 in STEP_VALUES:
            if s1 == s2:
                continue
            # Two-rule: switch at midpoint
            rules = [(s1, 49), (s2, 97)]
            pt = hetero_disk_decrypt(CT, KA, rules, init_shift)
            score = score_text(pt)
            report(f"HETERO-KA-s{init_shift}-{s1}-{s2}",
                   f"init={init_shift}, steps=[{s1},{s2}]",
                   pt, score)
            count_a4 += 1

            # Same with AZ
            pt = hetero_disk_decrypt(CT, AZ, rules, init_shift)
            score = score_text(pt)
            report(f"HETERO-AZ-s{init_shift}-{s1}-{s2}",
                   f"init={init_shift}, steps=[{s1},{s2}]",
                   pt, score)
            count_a4 += 1

    if init_shift % 5 == 0:
        print(f"    ... init_shift={init_shift}, {count_a4} tested")

print(f"  Heterogeneous disk: {count_a4} tested, {time.time()-t4:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 5: COLUMNAR-KEYED STRIP CIPHER (block cipher mode)
# Process K4 in blocks. Within each block, strip order is determined
# by a keyword. Between blocks, rotate the keyword.
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 5: Block Strip Cipher")
print("=" * 70)
t5 = time.time()

count_a5 = 0

def block_strip_decrypt(ct: str, keyword: str, block_size: int,
                         alpha: str, mode: str = "vig",
                         rotation: int = 0) -> str:
    """
    Block strip cipher: process in blocks of block_size.
    Within each block, apply keyword cipher.
    After each block, rotate keyword by `rotation` positions.
    """
    key_vals = [alpha.index(c) for c in keyword if c in alpha]
    kl = len(key_vals)
    pt = []
    current_key = list(key_vals)

    for block_start in range(0, len(ct), block_size):
        block = ct[block_start:block_start + block_size]
        for j, c in enumerate(block):
            ci = alpha.index(c)
            ki = current_key[(block_start + j) % kl]
            if mode == "vig":
                pt.append(alpha[(ci - ki) % 26])
            elif mode == "beau":
                pt.append(alpha[(ki - ci) % 26])

        # Rotate keyword for next block
        if rotation > 0:
            current_key = current_key[rotation:] + current_key[:rotation]
        elif rotation < 0:
            r = abs(rotation)
            current_key = current_key[-r:] + current_key[:-r]

    return "".join(pt)


for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
    for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
        for bs in [7, 8, 13, 24, 26]:
            for mode in ["vig", "beau"]:
                for rot in range(-3, 4):
                    pt = block_strip_decrypt(CT, kw, bs, alpha, mode, rot)
                    score = score_text(pt)
                    report(f"BLOCK-{kw[:5]}-{alpha_name}-bs{bs}-{mode}-r{rot}",
                           f"block={bs}, rot={rot}",
                           pt, score)
                    count_a5 += 1

print(f"  Block strip: {count_a5} tested, {time.time()-t5:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 6: GRILLE-INFORMED STRIP CIPHER
# The Cardan grille defines which row to read at each position.
# Grille extract gives 100 chars; use first 97 as row indicators.
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 6: Grille-Informed Strip Cipher")
print("=" * 70)
t6 = time.time()

count_a6 = 0

# Corrected grille extract (100 chars)
GRILLE_EXTRACT = "HJLVKDJQZKIVPCMWSAFOPCKBDLHIFXRYVFIJMXEIOMQFJNXZKILKRDIYSCLMQVZACEIMVSEFHLQKRGILVHNQXWTCDKIKJUFQRXCD"
GE_97 = GRILLE_EXTRACT[:97]

# Use grille letters as row offsets for a strip cipher
for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
    ge_offsets = [alpha.index(c) if c in alpha else 0 for c in GE_97]

    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SCHEIDT"]:
        # Method A: Keyword determines strip order, grille determines row
        kw_indices = []
        seen = set()
        for c in kw:
            if c in alpha and c not in seen:
                seen.add(c)
                kw_indices.append(alpha.index(c))
        for i in range(26):
            if i not in seen:
                seen.add(i)
                kw_indices.append(i)

        pt_a = []
        for i, c in enumerate(CT):
            col = i % 26
            strip_shift = kw_indices[col]
            row_shift = ge_offsets[i]
            total_shift = (strip_shift + row_shift) % 26
            ci = alpha.index(c)
            # Vig decrypt
            pt_a.append(alpha[(ci - total_shift) % 26])
        pt_a_str = "".join(pt_a)
        score = score_text(pt_a_str)
        report(f"GRILLE-STRIP-A-vig-{kw[:5]}-{alpha_name}",
               f"kw order + grille row (vig)", pt_a_str, score)

        # Beaufort
        pt_b = []
        for i, c in enumerate(CT):
            col = i % 26
            strip_shift = kw_indices[col]
            row_shift = ge_offsets[i]
            total_shift = (strip_shift + row_shift) % 26
            ci = alpha.index(c)
            pt_b.append(alpha[(total_shift - ci) % 26])
        pt_b_str = "".join(pt_b)
        score = score_text(pt_b_str)
        report(f"GRILLE-STRIP-A-beau-{kw[:5]}-{alpha_name}",
               f"kw order + grille row (beau)", pt_b_str, score)

        # Method B: Grille as SOLE key (no keyword)
        pt_c = []
        for i, c in enumerate(CT):
            ci = alpha.index(c)
            pt_c.append(alpha[(ci - ge_offsets[i]) % 26])
        pt_c_str = "".join(pt_c)
        score = score_text(pt_c_str)
        report(f"GRILLE-SOLE-vig-{alpha_name}",
               f"grille extract as sole key", pt_c_str, score)

        pt_d = []
        for i, c in enumerate(CT):
            ci = alpha.index(c)
            pt_d.append(alpha[(ge_offsets[i] - ci) % 26])
        pt_d_str = "".join(pt_d)
        score = score_text(pt_d_str)
        report(f"GRILLE-SOLE-beau-{alpha_name}",
               f"grille extract beaufort", pt_d_str, score)

        count_a6 += 4

# Method C: Grille + keyword interleaved
for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
    ge_offsets = [alpha.index(c) if c in alpha else 0 for c in GE_97]
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        kw_offsets = [alpha.index(c) for c in kw if c in alpha]
        # XOR-like combination
        combined = [(ge_offsets[i] + kw_offsets[i % len(kw_offsets)]) % 26 for i in range(N)]
        pt = []
        for i, c in enumerate(CT):
            ci = alpha.index(c)
            pt.append(alpha[(ci - combined[i]) % 26])
        pt_str = "".join(pt)
        score = score_text(pt_str)
        report(f"GRILLE-KW-vig-{kw[:5]}-{alpha_name}",
               f"grille+keyword combined", pt_str, score)

        pt2 = []
        for i, c in enumerate(CT):
            ci = alpha.index(c)
            pt2.append(alpha[(combined[i] - ci) % 26])
        pt2_str = "".join(pt2)
        score = score_text(pt2_str)
        report(f"GRILLE-KW-beau-{kw[:5]}-{alpha_name}",
               f"grille+keyword beaufort", pt2_str, score)

        # Multiply instead of add
        combined2 = [(ge_offsets[i] * kw_offsets[i % len(kw_offsets)]) % 26 for i in range(N)]
        pt3 = []
        for i, c in enumerate(CT):
            ci = alpha.index(c)
            pt3.append(alpha[(ci - combined2[i]) % 26])
        pt3_str = "".join(pt3)
        score = score_text(pt3_str)
        report(f"GRILLE-KW-mult-{kw[:5]}-{alpha_name}",
               f"grille*keyword combined", pt3_str, score)
        count_a6 += 3

print(f"  Grille-informed: {count_a6} tested, {time.time()-t6:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 7: NIHILIST CIPHER (Polybius + addition mod 10/26)
# Another "two system" candidate: Polybius square converts to numbers,
# then a key (also converted) is added.
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 7: Nihilist-Style Cipher")
print("=" * 70)
t7 = time.time()

count_a7 = 0

def make_polybius_5x5(keyword: str, merge: str = "IJ") -> tuple[dict, dict]:
    """Build a 5x5 Polybius square (merging I/J)."""
    seen = set()
    alpha = []
    for c in keyword.upper():
        if c == merge[1]:
            c = merge[0]
        if c not in seen and c in AZ:
            seen.add(c)
            alpha.append(c)
    for c in AZ:
        if c == merge[1]:
            c = merge[0]
        if c not in seen:
            seen.add(c)
            alpha.append(c)

    char_to_num = {}
    num_to_char = {}
    for idx, c in enumerate(alpha[:25]):
        row, col = divmod(idx, 5)
        num = (row + 1) * 10 + (col + 1)
        char_to_num[c] = num
        num_to_char[num] = c
    # Ensure merged letter maps to same number
    if merge[0] in char_to_num and merge[1] not in char_to_num:
        char_to_num[merge[1]] = char_to_num[merge[0]]
    return char_to_num, num_to_char


# K4 has all 26 letters, so standard Polybius (5x5) merges J→I.
# This is technically invalid for K4, but let's try anyway — maybe the
# merge happens AFTER encryption.
for poly_kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
    c2n, n2c = make_polybius_5x5(poly_kw)
    for key_kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        key_nums = [c2n.get(c, 11) for c in key_kw]
        ct_nums = [c2n.get(c, 11) for c in CT]

        # Nihilist decrypt: subtract key from CT (mod appropriate base)
        for mod_val in [100, 55, 26]:
            pt_chars = []
            for i, cn in enumerate(ct_nums):
                kn = key_nums[i % len(key_nums)]
                pn = (cn - kn) % mod_val
                pt_ch = n2c.get(pn, '?')
                pt_chars.append(pt_ch if pt_ch != '?' else 'X')
            pt = "".join(pt_chars)
            score = score_text(pt)
            report(f"NIHILIST-{poly_kw[:5]}-{key_kw[:5]}-mod{mod_val}",
                   f"Polybius({poly_kw}) key={key_kw} mod={mod_val}",
                   pt, score)
            count_a7 += 1

print(f"  Nihilist: {count_a7} tested, {time.time()-t7:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 8: EXTENDED SELF-ENCRYPT SEARCH (periods 12-16)
# From v1, periods 2-11 were exhaustive/sampled.
# Now do 12-16 with Bean constraint + self-encrypt constraint.
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 8: Extended Self-Encrypt Periodic Key Search (L=12-20)")
print("=" * 70)
t8 = time.time()

count_a8 = 0

for L in range(12, 21):
    pos32_res = 32 % L
    pos73_res = 73 % L
    pos27_res = 27 % L
    pos65_res = 65 % L

    zero_residues = {pos32_res, pos73_res}
    free_residues = [r for r in range(L) if r not in zero_residues]

    # Bean constraint: key[pos27_res] == key[pos65_res]
    bean_paired = None
    if pos27_res != pos65_res:
        if pos27_res in zero_residues and pos65_res in zero_residues:
            bean_paired = None  # Both zero, auto-satisfied
        elif pos27_res in zero_residues:
            # pos65 must also be 0
            bean_paired = ("force_zero", pos65_res)
        elif pos65_res in zero_residues:
            bean_paired = ("force_zero", pos27_res)
        else:
            bean_paired = ("equal", pos27_res, pos65_res)

    n_free = len(free_residues)

    # Effective free dimensions after Bean
    eff_free = n_free
    if bean_paired and bean_paired[0] == "force_zero":
        eff_free -= 1
    elif bean_paired and bean_paired[0] == "equal":
        eff_free -= 1

    total_space = 26 ** eff_free
    sample_count = min(total_space, 100000)

    rng = random.Random(42 + L)
    tested_this_L = 0

    for _ in range(sample_count):
        key = [0] * L
        for r in free_residues:
            key[r] = rng.randint(0, 25)

        # Apply Bean constraint
        if bean_paired:
            if bean_paired[0] == "force_zero":
                key[bean_paired[1]] = 0
            elif bean_paired[0] == "equal":
                key[bean_paired[2]] = key[bean_paired[1]]

        for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
            key_str = "".join(alpha[k] for k in key)
            pt = vig_decrypt(CT, key_str, alpha)
            score = score_text(pt)
            report(f"SELFE-L{L}-vig-{alpha_name}", f"key={key}", pt, score)

            pt = beau_decrypt(CT, key_str, alpha)
            score = score_text(pt)
            report(f"SELFE-L{L}-beau-{alpha_name}", f"key={key}", pt, score)
            count_a8 += 2
            tested_this_L += 2

    print(f"    L={L}: {tested_this_L} configs (eff_free={eff_free}, space={total_space})")

print(f"  Extended self-encrypt: {count_a8} tested, {time.time()-t8:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 9: VIGENÈRE WITH APERIODIC KEY DERIVED FROM STRUCTURE
# Use K4 letter frequencies, positions, or the CT itself to derive key
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 9: Aperiodic / Structure-Derived Keys")
print("=" * 70)
t9 = time.time()

count_a9 = 0

# Key derived from CT character frequencies
ct_freq = Counter(CT)
freq_ranked = sorted(range(N), key=lambda i: (-ct_freq[CT[i]], CT[i], i))

# Key = position in frequency ranking
freq_key = [0] * N
for rank, pos in enumerate(freq_ranked):
    freq_key[pos] = rank % 26

for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
    key_str = "".join(alpha[k] for k in freq_key)
    pt = vig_decrypt(CT, key_str, alpha)
    score = score_text(pt)
    report(f"FREQKEY-vig-{alpha_name}", "freq-ranked key", pt, score)

    pt = beau_decrypt(CT, key_str, alpha)
    score = score_text(pt)
    report(f"FREQKEY-beau-{alpha_name}", "freq-ranked key", pt, score)
    count_a9 += 2

# Key = CT letter values shifted
for shift in range(26):
    for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
        ct_key = "".join(alpha[(alpha.index(c) + shift) % 26] for c in CT)
        pt = vig_decrypt(CT, ct_key, alpha)
        score = score_text(pt)
        report(f"CTKEY-vig-sh{shift}-{alpha_name}", f"CT self-key +{shift}", pt, score)

        pt = beau_decrypt(CT, ct_key, alpha)
        score = score_text(pt)
        report(f"CTKEY-beau-sh{shift}-{alpha_name}", f"CT self-key +{shift}", pt, score)
        count_a9 += 2

# Key = running difference of CT
for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
    diff_key = [0]
    for i in range(1, N):
        diff_key.append((alpha.index(CT[i]) - alpha.index(CT[i-1])) % 26)
    key_str = "".join(alpha[k] for k in diff_key)
    pt = vig_decrypt(CT, key_str, alpha)
    score = score_text(pt)
    report(f"DIFFKEY-vig-{alpha_name}", "running difference key", pt, score)

    pt = beau_decrypt(CT, key_str, alpha)
    score = score_text(pt)
    report(f"DIFFKEY-beau-{alpha_name}", "running difference key", pt, score)
    count_a9 += 2

# Key = cumulative sum of CT values
for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
    cum_key = []
    s = 0
    for c in CT:
        s = (s + alpha.index(c)) % 26
        cum_key.append(s)
    key_str = "".join(alpha[k] for k in cum_key)
    pt = vig_decrypt(CT, key_str, alpha)
    score = score_text(pt)
    report(f"CUMKEY-vig-{alpha_name}", "cumulative sum key", pt, score)

    pt = beau_decrypt(CT, key_str, alpha)
    score = score_text(pt)
    report(f"CUMKEY-beau-{alpha_name}", "cumulative sum key", pt, score)
    count_a9 += 2

# Key from position-dependent formula: key[i] = (a*i + b) % 26
for a in range(1, 26):
    for b in range(26):
        key = [(a * i + b) % 26 for i in range(N)]
        # Check self-encrypt constraint
        if key[32] != 0 or key[73] != 0:
            continue
        # Check Bean
        if key[27] != key[65]:
            continue
        for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
            key_str = "".join(alpha[k] for k in key)
            pt = vig_decrypt(CT, key_str, alpha)
            score = score_text(pt)
            report(f"LINKEY-vig-a{a}b{b}-{alpha_name}",
                   f"linear key a*i+b, a={a}, b={b}", pt, score)

            pt = beau_decrypt(CT, key_str, alpha)
            score = score_text(pt)
            report(f"LINKEY-beau-a{a}b{b}-{alpha_name}",
                   f"linear key", pt, score)
            count_a9 += 2

# Quadratic key: key[i] = (a*i^2 + b*i + c) % 26
for a in range(1, 10):
    for b in range(10):
        for c in range(26):
            key = [(a * i * i + b * i + c) % 26 for i in range(N)]
            if key[32] != 0 or key[73] != 0:
                continue
            if key[27] != key[65]:
                continue
            for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
                key_str = "".join(alpha[k] for k in key)
                pt = vig_decrypt(CT, key_str, alpha)
                score = score_text(pt)
                report(f"QUADKEY-vig-{a}-{b}-{c}-{alpha_name}",
                       f"quad key a={a},b={b},c={c}", pt, score)
                count_a9 += 1

print(f"  Structure-derived keys: {count_a9} tested, {time.time()-t9:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 10: TRITHEMIUS-STYLE PROGRESSIVE CIPHER
# Each letter shifts by its position (Trithemius), combined with keyword.
# Also: Alberti disk model — keyword controls the "period" of resetting.
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 10: Trithemius + Alberti Progressive Models")
print("=" * 70)
t10 = time.time()

count_a10 = 0

# Pure Trithemius: key[i] = i % 26
for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
    for offset in range(26):
        key = [(i + offset) % 26 for i in range(N)]
        key_str = "".join(alpha[k] for k in key)
        pt = vig_decrypt(CT, key_str, alpha)
        score = score_text(pt)
        report(f"TRITH-vig-off{offset}-{alpha_name}",
               f"Trithemius+{offset}", pt, score)
        pt = beau_decrypt(CT, key_str, alpha)
        score = score_text(pt)
        report(f"TRITH-beau-off{offset}-{alpha_name}",
               f"Trithemius+{offset}", pt, score)
        count_a10 += 2

# Trithemius + keyword: key[i] = kw[i % kl] + i
for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
    for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
        kw_vals = [alpha.index(c) for c in kw]
        kl = len(kw_vals)
        key = [(kw_vals[i % kl] + i) % 26 for i in range(N)]
        key_str = "".join(alpha[k] for k in key)
        pt = vig_decrypt(CT, key_str, alpha)
        score = score_text(pt)
        report(f"TRITH+KW-vig-{kw[:5]}-{alpha_name}",
               f"Trithemius+{kw}", pt, score)
        pt = beau_decrypt(CT, key_str, alpha)
        score = score_text(pt)
        report(f"TRITH+KW-beau-{kw[:5]}-{alpha_name}",
               f"Trithemius+{kw}", pt, score)

        # Also: keyword + i*step for various steps
        for step in [2, 3, 5, 7, 11, 13]:
            key2 = [(kw_vals[i % kl] + i * step) % 26 for i in range(N)]
            key_str2 = "".join(alpha[k] for k in key2)
            pt = vig_decrypt(CT, key_str2, alpha)
            score = score_text(pt)
            report(f"TRITH+KW-s{step}-vig-{kw[:5]}-{alpha_name}",
                   f"kw+i*{step}", pt, score)
            count_a10 += 1

        count_a10 += 2

# Alberti: reset shift every `period` positions
for period in [7, 8, 13, 26]:
    for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            kw_vals = [alpha.index(c) for c in kw]
            kl = len(kw_vals)
            key = [(kw_vals[i % kl] + (i % period)) % 26 for i in range(N)]
            key_str = "".join(alpha[k] for k in key)
            pt = vig_decrypt(CT, key_str, alpha)
            score = score_text(pt)
            report(f"ALBERTI-p{period}-vig-{kw[:5]}-{alpha_name}",
                   f"Alberti period={period}, kw={kw}", pt, score)
            pt = beau_decrypt(CT, key_str, alpha)
            score = score_text(pt)
            report(f"ALBERTI-p{period}-beau-{kw[:5]}-{alpha_name}",
                   f"Alberti period={period}, kw={kw}", pt, score)
            count_a10 += 2

print(f"  Trithemius/Alberti: {count_a10} tested, {time.time()-t10:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 11: SUBSTITUTION THEN TRANSPOSITION (as permutation search)
# Model: PT → Vig(key) → columnar transposition → carved CT
# Decrypt: carved CT → undo transposition → Vig_dec(key) → PT
# For each keyword, try all columnar transposition widths.
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 11: Vig + Columnar Transposition (combined)")
print("=" * 70)
t11 = time.time()

count_a11 = 0

def undo_columnar(ct: str, key_order: list[int]) -> str:
    """Undo columnar transposition: fill by columns in key order, read by rows."""
    width = len(key_order)
    n_rows = (len(ct) + width - 1) // width
    n_long = len(ct) - width * (n_rows - 1)  # columns with n_rows chars

    # Determine column lengths
    col_lens = []
    for col in range(width):
        if col < n_long:
            col_lens.append(n_rows)
        else:
            col_lens.append(n_rows - 1)

    # Fill columns in key order
    cols = [[] for _ in range(width)]
    pos = 0
    for rank in range(width):
        col = key_order.index(rank)
        clen = col_lens[col]
        cols[col] = list(ct[pos:pos + clen])
        pos += clen

    # Read by rows
    result = []
    for row in range(n_rows):
        for col in range(width):
            if row < len(cols[col]):
                result.append(cols[col][row])
    return "".join(result)


def keyword_to_col_order(keyword: str, alpha: str) -> list[int]:
    """Convert keyword to column order (ranking)."""
    vals = [(alpha.index(c), i) for i, c in enumerate(keyword) if c in alpha]
    sorted_vals = sorted(vals)
    order = [0] * len(vals)
    for rank, (_, orig_idx) in enumerate(sorted_vals):
        order[orig_idx] = rank
    return order


for trans_kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SCHEIDT"]:
    for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
        col_order = keyword_to_col_order(trans_kw, alpha)
        untrans = undo_columnar(CT, col_order)

        for vig_kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SCHEIDT"]:
            pt = vig_decrypt(untrans, vig_kw, alpha)
            score = score_text(pt)
            report(f"VIG+COL-{vig_kw[:5]}-{trans_kw[:5]}-{alpha_name}",
                   f"Vig({vig_kw}) + Col({trans_kw})", pt, score)

            pt = beau_decrypt(untrans, vig_kw, alpha)
            score = score_text(pt)
            report(f"BEAU+COL-{vig_kw[:5]}-{trans_kw[:5]}-{alpha_name}",
                   f"Beau({vig_kw}) + Col({trans_kw})", pt, score)
            count_a11 += 2

        # Also reverse order
        rev_order = list(reversed(col_order))
        untrans_rev = undo_columnar(CT, rev_order)
        for vig_kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            pt = vig_decrypt(untrans_rev, vig_kw, alpha)
            score = score_text(pt)
            report(f"VIG+COLrev-{vig_kw[:5]}-{trans_kw[:5]}-{alpha_name}",
                   f"Vig + reversed Col", pt, score)
            count_a11 += 1

print(f"  Vig+Col: {count_a11} tested, {time.time()-t11:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# FINAL SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
elapsed = time.time() - t_start

print("\n" + "=" * 70)
print("FINAL SUMMARY — Strip Cipher V2")
print("=" * 70)
print(f"Total configs tested     : {total_tested}")
print(f"Total elapsed            : {elapsed:.1f}s")
print(f"CRIB HITS FOUND          : {len(CRIB_HITS)}")
print(f"Interesting (>-5.5/char) : {len(INTERESTING)}")
print(f"Best score               : {best_score:.2f}")
print(f"Best per-char            : {best_per_char:.4f}")

if best_entry:
    print(f"Best approach : {best_entry['approach']}")
    print(f"Best note     : {best_entry['note']}")
    print(f"Best PT       : {best_entry['pt'][:60]}...")

if CRIB_HITS:
    print(f"\n*** CRIB HIT DETAILS:")
    for hit in CRIB_HITS:
        print(f"  Approach : {hit['approach']}")
        print(f"  PT       : {hit['pt']}")

if INTERESTING:
    print(f"\nTop 20 interesting results:")
    INTERESTING.sort(key=lambda x: -x["per_char"])
    for i, entry in enumerate(INTERESTING[:20]):
        print(f"  {i+1}. [{entry['approach']}] per_char={entry['per_char']:.4f}")

scores = [r["score"] for r in all_results if r["score"] > -9000]
if scores:
    per_chars = [r["per_char"] for r in all_results if r["per_char"] > -20]
    print(f"\nScore dist: min={min(scores):.2f}, max={max(scores):.2f}, mean={sum(scores)/len(scores):.2f}")
    if per_chars:
        print(f"Per-char dist: min={min(per_chars):.4f}, max={max(per_chars):.4f}, mean={sum(per_chars)/len(per_chars):.4f}")

out = results_dir / "results.json"
with open(out, "w") as f:
    json.dump({
        "total_tested": total_tested,
        "best_score": best_score,
        "best_per_char": best_per_char,
        "best_entry": best_entry,
        "crib_hits": CRIB_HITS,
        "interesting": INTERESTING[:50],
    }, f, indent=2)
print(f"\nResults saved to: {out}")

if CRIB_HITS:
    status = "SOLVED"
elif best_per_char > -5.5:
    status = "PROMISING"
elif best_per_char > -7.0:
    status = "MARGINAL"
else:
    status = "INCONCLUSIVE"
print(f"\nVerdict: {status}")
