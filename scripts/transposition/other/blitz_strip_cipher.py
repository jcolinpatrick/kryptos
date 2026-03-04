#!/usr/bin/env python3
"""
Cipher: non-columnar transposition
Family: transposition/other
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""blitz_strip_cipher.py — Strip cipher / simultaneous sub+trans model for K4.

Hypothesis: The KA Vigenère tableau IS a physical strip cipher device.
26 strips, each a cyclic shift of KA. A keyword determines strip ORDER
(= transposition), and a second keyword/rule determines which ROW to read
(= substitution). Both operations happen simultaneously via physical
strip manipulation. This models Scheidt's "medieval guild code circles/rings
fixed in place" + "shifting matrices".

Also tests cipher disk models with non-uniform stepping (step by PT value,
keyword letter, position, etc.). Self-encrypting positions (shift=0 at
positions 32, 73) constrain the stepping pattern.

Approaches:
  1. Standard strip cipher: keyword orders strips, repeating key picks rows
  2. Autokey strip cipher: PT letter feeds back to select next strip/row
  3. Quagmire I-IV models on KA alphabet
  4. Cipher disk with variable stepping (step by PT, by keyword, by position)
  5. "Fixed rings" model: two concentric KA rings, keyword-governed stepping
  6. Beaufort strip cipher variants
  7. Double-keyword strip: one keyword orders strips, another picks rows
  8. Progressive/accumulating key: keystream builds from prior operations
  9. Running-key strip cipher (K1/K3 PT as running key)
 10. Non-standard tableau constructions (reversed rows, alternating direction)

Run: cd /home/cpatrick/kryptos && PYTHONPATH=src python3 -u scripts/blitz_strip_cipher.py
"""
from __future__ import annotations

import sys
import os
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

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
N = 97
CT = K4_CARVED

# Extended keyword list: add thematic keywords for strip ordering
STRIP_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN",
    "SCHEIDT", "BERLIN", "CLOCK", "EAST", "NORTH",
    "LIGHT", "ANTIPODES", "MEDUSA", "ENIGMA",
    "IQLUSION", "DESPARATLY", "UNDERGRUUND",
    "KRYPTOSABCDEFGHIJLMNQUVWXZ",  # full KA as key
]

# Known cribs
CRIB_DEFS = [
    (21, "EASTNORTHEAST"),   # positions 21-33
    (63, "BERLINCLOCK"),     # positions 63-73
]
CRIB_MAP = {}
for _start, _text in CRIB_DEFS:
    for _j, _ch in enumerate(_text):
        CRIB_MAP[_start + _j] = _ch

# Self-encrypting: CT[32]=PT[32]=S, CT[73]=PT[73]=K → shift=0
SELF_ENCRYPT = {32: 'S', 73: 'K'}

# ─────────────────────────────────────────────────────────────────────────────
# RESULTS TRACKING
# ─────────────────────────────────────────────────────────────────────────────
results_dir = Path("results/blitz_strip_cipher")
results_dir.mkdir(parents=True, exist_ok=True)

all_results: list[dict] = []
best_score = -9999.0
best_per_char = -99.0
best_entry: dict | None = None
total_tested = 0
CRIB_HITS: list[dict] = []
INTERESTING: list[dict] = []  # score > -5.5/char


def report_result(approach: str, note: str, pt: str, score: float, extra: dict | None = None):
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
        print(f"*** CRIB HIT! approach={approach}, score={score:.2f}, per_char={per_char:.3f}")
        print(f"    cribs={cribs}, note={note}")
        print(f"    PT={pt}")
        print(f"{'='*60}\n")

    if per_char > -5.5:
        INTERESTING.append(entry)
        if per_char > -5.0:
            print(f"  INTERESTING [{approach}]: per_char={per_char:.3f}, score={score:.2f}")

    if score > best_score:
        best_score = score
        best_per_char = per_char
        best_entry = entry


def save_results():
    out = results_dir / "results.json"
    with open(out, "w") as f:
        json.dump({
            "total_tested": total_tested,
            "best_score": best_score,
            "best_per_char": best_per_char,
            "crib_hits": len(CRIB_HITS),
            "interesting": len(INTERESTING),
            "best_entry": best_entry,
            "crib_hit_details": CRIB_HITS,
            "interesting_details": INTERESTING[:100],
            "all_results": all_results[-2000:],
        }, f, indent=2)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# KA TABLEAU CONSTRUCTION
# ─────────────────────────────────────────────────────────────────────────────

def build_tableau(alpha: str) -> list[str]:
    """Build 26 rows: row i is alpha shifted by i positions."""
    return [alpha[i:] + alpha[:i] for i in range(26)]


def build_mixed_tableau(alpha: str, keyword: str) -> list[str]:
    """Build mixed tableau: each row is keyword-mixed then shifted."""
    # Create keyword-mixed alphabet from alpha
    seen = set()
    mixed = []
    for ch in keyword.upper():
        if ch in alpha and ch not in seen:
            seen.add(ch)
            mixed.append(ch)
    for ch in alpha:
        if ch not in seen:
            seen.add(ch)
            mixed.append(ch)
    mixed_str = "".join(mixed)
    return [mixed_str[i:] + mixed_str[:i] for i in range(26)]


KA_TABLEAU = build_tableau(KA)
AZ_TABLEAU = build_tableau(AZ)


def tab_encrypt(pt_char: str, key_char: str, tableau: list[str], alpha: str) -> str:
    """Encrypt: row=key_char index in alpha, col=pt_char index in alpha."""
    row = alpha.index(key_char)
    col = alpha.index(pt_char)
    return tableau[row][col]


def tab_decrypt(ct_char: str, key_char: str, tableau: list[str], alpha: str) -> str:
    """Decrypt: find ct_char in row indexed by key_char."""
    row = alpha.index(key_char)
    col = tableau[row].index(ct_char)
    return alpha[col]


# ─────────────────────────────────────────────────────────────────────────────
# STRIP CIPHER CORE
# ─────────────────────────────────────────────────────────────────────────────

def strip_cipher_decrypt(ct: str, strip_order: list[int], row_key: list[int],
                          strips: list[str]) -> str:
    """
    Strip cipher decryption.
    - strips: list of 26 strips, each 26 chars (cyclic shifts of an alphabet)
    - strip_order: permutation of 0..25 giving which strip goes in each column
    - row_key: for each position i, which row offset to apply to strip_order[i%26]

    Encryption: for position i, the strip in column (i%26) is strips[strip_order[i%26]].
    The row offset is row_key[i]. CT[i] = strip at col (i%26), row row_key[i].
    To decrypt: find CT[i] in that strip, get column = PT index.
    """
    pt = []
    n_strips = len(strip_order)
    for i, c in enumerate(ct):
        strip_idx = strip_order[i % n_strips]
        row = row_key[i % len(row_key)]
        # The strip is shifted by strip_idx, reading row `row`
        # Effective: cipher char = strips[strip_idx][row] at column = PT pos
        # Actually: the strip is the full row of the tableau.
        # CT[i] is at some position in the shifted strip
        strip = strips[strip_idx]
        # Shift the strip by row positions
        shifted = strip[row:] + strip[:row]
        if c in shifted:
            pt_idx = shifted.index(c)
            pt.append(strips[0][pt_idx])  # PT char from base strip
        else:
            pt.append('?')
    return "".join(pt)


# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 1: STANDARD STRIP CIPHER
# Keyword determines strip order (transposition).
# Repeating key determines row offset (substitution).
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 1: Standard Strip Cipher (keyword strip order + key row)")
print("=" * 70)
t0 = time.time()
t1 = t0

def keyword_to_strip_order(keyword: str, alpha: str) -> list[int]:
    """Convert keyword to a permutation of 0..25 for strip ordering."""
    key_indices = [alpha.index(c) for c in keyword.upper() if c in alpha]
    # Use keyword to define column ordering: rank of each keyword letter
    if not key_indices:
        return list(range(26))
    # Extend keyword to 26 by appending remaining alphabet chars
    seen = set()
    full_key = []
    for c in keyword.upper():
        if c in alpha and c not in seen:
            seen.add(c)
            full_key.append(alpha.index(c))
    for i in range(26):
        if i not in seen:
            seen.add(i)
            full_key.append(i)
    # Argsort to get strip order
    order = sorted(range(26), key=lambda x: full_key[x])
    return order


def repeating_key_offsets(keyword: str, alpha: str, length: int) -> list[int]:
    """Convert repeating keyword to row offsets."""
    key_vals = [alpha.index(c) for c in keyword.upper() if c in alpha]
    if not key_vals:
        return [0] * length
    return [key_vals[i % len(key_vals)] for i in range(length)]


# For each pair of keywords (one for strip order, one for row key),
# try to decrypt CT
def try_strip_decrypt(ct: str, strip_order_kw: str, row_kw: str,
                       alpha: str, alpha_name: str, approach_tag: str = ""):
    """Try strip cipher decryption with given keywords."""
    strips = build_tableau(alpha)
    strip_order = keyword_to_strip_order(strip_order_kw, alpha)
    row_offsets = repeating_key_offsets(row_kw, alpha, len(ct))

    pt = []
    for i, c in enumerate(ct):
        col_in_strips = i % 26
        s_idx = strip_order[col_in_strips]
        row_off = row_offsets[i]
        # Strip s_idx shifted by row_off
        strip = strips[s_idx]
        shifted_strip = strip[row_off:] + strip[:row_off]
        if c in shifted_strip:
            pt_col = shifted_strip.index(c)
            pt.append(alpha[pt_col])
        else:
            pt.append('?')
    pt_str = "".join(pt)
    score = score_text(pt_str)
    tag = f"STRIP-{approach_tag}" if approach_tag else "STRIP"
    report_result(f"{tag}-{strip_order_kw[:8]}-{row_kw[:8]}-{alpha_name}",
                  f"strip_order={strip_order_kw}, row_key={row_kw}",
                  pt_str, score)
    return pt_str, score


# Also try the direct Vigenère interpretation:
# strip_order defines the transposition, row_key defines substitution
# This is a Quagmire cipher family
def quagmire_decrypt(ct: str, pt_alpha: str, ct_alpha: str, key: str,
                      indicator: str, alpha_name: str, variant: str):
    """
    Quagmire cipher family.
    - Quagmire I: plain alpha is keyed, cipher alpha is standard
    - Quagmire II: plain alpha is standard, cipher alpha is keyed
    - Quagmire III: both alphabets are keyed with SAME keyword
    - Quagmire IV: both alphabets are keyed with DIFFERENT keywords
    """
    key_len = len(key)
    pt = []
    for i, c in enumerate(ct):
        ki = key[i % key_len]
        # Find the shift for this position
        shift = ct_alpha.index(ki) - ct_alpha.index(indicator)
        shifted_ct = ct_alpha[shift % 26:] + ct_alpha[:shift % 26]
        if c in shifted_ct:
            ct_pos = shifted_ct.index(c)
            pt.append(pt_alpha[ct_pos])
        else:
            pt.append('?')
    pt_str = "".join(pt)
    score = score_text(pt_str)
    report_result(f"QUAG-{variant}-{key[:8]}-{indicator}-{alpha_name}",
                  f"key={key}, ind={indicator}, variant={variant}",
                  pt_str, score)
    return pt_str, score


count_a1 = 0
# Standard strip: try all keyword pairs
for strip_kw in STRIP_KEYWORDS[:14]:  # limit to main keywords
    for row_kw in STRIP_KEYWORDS[:14]:
        for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
            try_strip_decrypt(CT, strip_kw, row_kw, alpha, alpha_name, "std")
            count_a1 += 1

print(f"  Standard strip: {count_a1} combos tested, {time.time()-t1:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 2: QUAGMIRE CIPHER FAMILY
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 2: Quagmire Cipher Family (I, II, III, IV)")
print("=" * 70)
t2 = time.time()

# Build keyed alphabets
def make_keyed_alpha(keyword: str, base: str = AZ) -> str:
    seen = set()
    result = []
    for c in keyword.upper():
        if c in base and c not in seen:
            seen.add(c)
            result.append(c)
    for c in base:
        if c not in seen:
            seen.add(c)
            result.append(c)
    return "".join(result)


count_a2 = 0
for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN", "SCHEIDT"]:
    keyed = make_keyed_alpha(kw)
    for row_key in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN", "SCHEIDT"]:
        for indicator in "AKRSZ":  # test a few indicator letters
            # Quagmire I: keyed PT alpha, standard CT alpha
            quagmire_decrypt(CT, keyed, AZ, row_key, indicator, "AZ", f"I-{kw}")
            count_a2 += 1

            # Quagmire II: standard PT alpha, keyed CT alpha
            quagmire_decrypt(CT, AZ, keyed, row_key, indicator, "AZ", f"II-{kw}")
            count_a2 += 1

            # Quagmire III: same keyed alpha for both
            quagmire_decrypt(CT, keyed, keyed, row_key, indicator, "KW", f"III-{kw}")
            count_a2 += 1

    # Also try KA as the keyed alphabet
    for row_key in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        for indicator in "KAZ":
            quagmire_decrypt(CT, KA, KA, row_key, indicator, "KA", f"III-KA")
            quagmire_decrypt(CT, KA, AZ, row_key, indicator, "KA-AZ", f"I-KA")
            quagmire_decrypt(CT, AZ, KA, row_key, indicator, "AZ-KA", f"II-KA")
            count_a2 += 3

# Quagmire IV: two different keyed alphabets
for kw1 in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
    keyed1 = make_keyed_alpha(kw1)
    for kw2 in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        if kw1 != kw2:
            keyed2 = make_keyed_alpha(kw2)
            for row_key in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                for indicator in "KAZ":
                    quagmire_decrypt(CT, keyed1, keyed2, row_key, indicator,
                                     f"{kw1[:4]}-{kw2[:4]}", f"IV")
                    count_a2 += 1

print(f"  Quagmire: {count_a2} combos tested, {time.time()-t2:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 3: CIPHER DISK WITH VARIABLE STEPPING
# Two rings: outer = KA (or AZ), inner = AZ (or KA)
# Keyword sets initial alignment. After each letter, step by some rule.
# Self-encrypting: positions 32 and 73 have shift=0 (rings aligned).
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 3: Cipher Disk with Variable Stepping")
print("=" * 70)
t3 = time.time()


def cipher_disk_decrypt(ct: str, outer: str, inner: str, initial_shift: int,
                         step_fn, approach_name: str, note: str = ""):
    """
    Cipher disk: outer ring is fixed, inner ring rotates.
    initial_shift: how much inner ring is shifted at start.
    step_fn(i, ct_char, pt_char, shift): returns new shift for next position.
    """
    pt = []
    shift = initial_shift
    for i, c in enumerate(ct):
        # Current alignment: inner[j] aligns with outer[(j + shift) % 26]
        # CT char is on outer ring, find its position
        if c not in outer:
            pt.append('?')
            continue
        outer_pos = outer.index(c)
        # Inner ring position aligned with this outer position
        inner_pos = (outer_pos - shift) % 26
        pt_char = inner[inner_pos]
        pt.append(pt_char)
        # Step
        shift = step_fn(i, c, pt_char, shift)

    pt_str = "".join(pt)
    score = score_text(pt_str)
    report_result(approach_name, note, pt_str, score)
    return pt_str, score


# Step functions
def step_by_pt_value(alpha):
    """Step by plaintext letter value in given alphabet."""
    def fn(i, ct_ch, pt_ch, shift):
        return (shift + alpha.index(pt_ch)) % 26
    return fn

def step_by_ct_value(alpha):
    """Step by ciphertext letter value."""
    def fn(i, ct_ch, pt_ch, shift):
        return (shift + alpha.index(ct_ch)) % 26
    return fn

def step_by_position():
    """Step by position number."""
    def fn(i, ct_ch, pt_ch, shift):
        return (shift + i + 1) % 26
    return fn

def step_by_keyword(keyword, alpha):
    """Step by repeating keyword."""
    vals = [alpha.index(c) for c in keyword if c in alpha]
    def fn(i, ct_ch, pt_ch, shift):
        return (shift + vals[i % len(vals)]) % 26
    return fn

def step_by_constant(k):
    """Constant step."""
    def fn(i, ct_ch, pt_ch, shift):
        return (shift + k) % 26
    return fn

def step_by_pt_plus_key(keyword, alpha):
    """Step by PT + keyword letter."""
    vals = [alpha.index(c) for c in keyword if c in alpha]
    def fn(i, ct_ch, pt_ch, shift):
        return (shift + alpha.index(pt_ch) + vals[i % len(vals)]) % 26
    return fn

def step_accumulate_pt(alpha):
    """Accumulate: shift += PT value (progressive key)."""
    def fn(i, ct_ch, pt_ch, shift):
        return (shift + alpha.index(pt_ch)) % 26
    return fn

def step_by_ct_minus_pt(alpha):
    """Step by CT - PT difference (autokey variant)."""
    def fn(i, ct_ch, pt_ch, shift):
        diff = (alpha.index(ct_ch) - alpha.index(pt_ch)) % 26
        return (shift + diff) % 26
    return fn


count_a3 = 0
for outer_name, outer in [("KA", KA), ("AZ", AZ)]:
    for inner_name, inner in [("KA", KA), ("AZ", AZ)]:
        for initial_shift in range(26):
            # Constant step
            for k in range(1, 26):
                cipher_disk_decrypt(
                    CT, outer, inner, initial_shift,
                    step_by_constant(k),
                    f"DISK-const-{outer_name}-{inner_name}-s{initial_shift}-k{k}",
                    f"outer={outer_name}, inner={inner_name}, init={initial_shift}, step={k}"
                )
                count_a3 += 1

            # Step by keyword
            for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                for step_alpha_name, step_alpha in [("KA", KA), ("AZ", AZ)]:
                    cipher_disk_decrypt(
                        CT, outer, inner, initial_shift,
                        step_by_keyword(kw, step_alpha),
                        f"DISK-kw-{outer_name}-{inner_name}-s{initial_shift}-{kw[:5]}-{step_alpha_name}",
                        f"keyword step, kw={kw}"
                    )
                    count_a3 += 1

            if count_a3 % 5000 == 0:
                print(f"    ... {count_a3} disk configs tested")

print(f"  Cipher disk (constant + keyword step): {count_a3} tested, {time.time()-t3:.1f}s")

# Now the more exotic step functions — only test at promising initial shifts
# Self-encrypt constraint: shift must be 0 at positions 32 and 73
# This constrains which initial_shift + step combos are valid
print("\n  Testing PT-value / CT-value / position stepping...")
t3b = time.time()
count_a3b = 0

for outer_name, outer in [("KA", KA), ("AZ", AZ)]:
    for inner_name, inner in [("KA", KA), ("AZ", AZ)]:
        for initial_shift in range(26):
            for step_name, step_fn in [
                ("pt_val_KA", step_by_pt_value(KA)),
                ("pt_val_AZ", step_by_pt_value(AZ)),
                ("ct_val_KA", step_by_ct_value(KA)),
                ("ct_val_AZ", step_by_ct_value(AZ)),
                ("position", step_by_position()),
                ("accum_pt_KA", step_accumulate_pt(KA)),
                ("accum_pt_AZ", step_accumulate_pt(AZ)),
                ("ct_m_pt_KA", step_by_ct_minus_pt(KA)),
                ("ct_m_pt_AZ", step_by_ct_minus_pt(AZ)),
            ]:
                cipher_disk_decrypt(
                    CT, outer, inner, initial_shift,
                    step_fn,
                    f"DISK-{step_name}-{outer_name}-{inner_name}-s{initial_shift}",
                    f"step={step_name}"
                )
                count_a3b += 1

            # PT + keyword step
            for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                for sa_name, sa in [("KA", KA), ("AZ", AZ)]:
                    cipher_disk_decrypt(
                        CT, outer, inner, initial_shift,
                        step_by_pt_plus_key(kw, sa),
                        f"DISK-pt+kw-{outer_name}-{inner_name}-s{initial_shift}-{kw[:5]}-{sa_name}",
                        f"step=PT+{kw}"
                    )
                    count_a3b += 1

print(f"  Exotic stepping: {count_a3b} tested, {time.time()-t3b:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 4: BEAUFORT STRIP CIPHER VARIANTS
# Beaufort: K = (CT + PT) mod 26, so PT = (K - CT) mod 26
# On a strip cipher this means reading the strip backwards
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 4: Beaufort Strip Cipher / Reverse Reading")
print("=" * 70)
t4 = time.time()

count_a4 = 0
for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
    strips = build_tableau(alpha)
    rev_strips = [s[::-1] for s in strips]  # Reverse each strip

    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SCHEIDT"]:
        strip_order = keyword_to_strip_order(kw, alpha)
        for row_kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SCHEIDT"]:
            row_offsets = repeating_key_offsets(row_kw, alpha, N)
            pt = []
            for i, c in enumerate(CT):
                col_in_strips = i % 26
                s_idx = strip_order[col_in_strips]
                row_off = row_offsets[i]
                # Beaufort: use reversed strip
                strip = rev_strips[s_idx]
                shifted = strip[row_off:] + strip[:row_off]
                if c in shifted:
                    pt_col = shifted.index(c)
                    pt.append(alpha[pt_col])
                else:
                    pt.append('?')
            pt_str = "".join(pt)
            score = score_text(pt_str)
            report_result(f"BEAU-STRIP-{kw[:5]}-{row_kw[:5]}-{alpha_name}",
                          f"beaufort strip: order={kw}, row={row_kw}",
                          pt_str, score)
            count_a4 += 1

    # Also: Variant Beaufort (K = PT - CT)
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        for row_kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            row_offsets = repeating_key_offsets(row_kw, alpha, N)
            strip_order = keyword_to_strip_order(kw, alpha)
            pt = []
            for i, c in enumerate(CT):
                col_in_strips = i % 26
                s_idx = strip_order[col_in_strips]
                row_off = row_offsets[i]
                # Variant Beaufort: PT[i] = (CT[i] - key[i]) is same as Vigenère decrypt
                # but with strip ordering doing transposition
                ci = alpha.index(c)
                pt_idx = (ci - row_off) % 26
                # Apply strip ordering: the transposition reindexes
                pt_char = alpha[(pt_idx - s_idx) % 26]
                pt.append(pt_char)
            pt_str = "".join(pt)
            score = score_text(pt_str)
            report_result(f"VARBEAU-STRIP-{kw[:5]}-{row_kw[:5]}-{alpha_name}",
                          f"variant beaufort strip",
                          pt_str, score)
            count_a4 += 1

print(f"  Beaufort strip: {count_a4} tested, {time.time()-t4:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 5: AUTOKEY STRIP CIPHER
# After initial keyword priming, subsequent key is derived from PT (or CT)
# This is the "autokey" principle applied to strip selection/row offset
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 5: Autokey Strip / Cipher Disk")
print("=" * 70)
t5 = time.time()

count_a5 = 0

def autokey_vig_decrypt(ct: str, primer: str, alpha: str) -> str:
    """Vigenère autokey: key = primer + plaintext."""
    pt = []
    key = list(primer.upper())
    for i, c in enumerate(ct):
        ki = alpha.index(key[i])
        ci = alpha.index(c)
        p = alpha[(ci - ki) % 26]
        pt.append(p)
        key.append(p)
    return "".join(pt)

def autokey_beau_decrypt(ct: str, primer: str, alpha: str) -> str:
    """Beaufort autokey: key = primer + plaintext."""
    pt = []
    key = list(primer.upper())
    for i, c in enumerate(ct):
        ki = alpha.index(key[i])
        ci = alpha.index(c)
        p = alpha[(ki - ci) % 26]
        pt.append(p)
        key.append(p)
    return "".join(pt)

def autokey_ct_vig_decrypt(ct: str, primer: str, alpha: str) -> str:
    """Vigenère CT-autokey: key = primer + ciphertext."""
    pt = []
    key = list(primer.upper())
    for i, c in enumerate(ct):
        ki = alpha.index(key[i])
        ci = alpha.index(c)
        p = alpha[(ci - ki) % 26]
        pt.append(p)
        key.append(c)
    return "".join(pt)

def autokey_ct_beau_decrypt(ct: str, primer: str, alpha: str) -> str:
    """Beaufort CT-autokey: key = primer + ciphertext."""
    pt = []
    key = list(primer.upper())
    for i, c in enumerate(ct):
        ki = alpha.index(key[i])
        ci = alpha.index(c)
        p = alpha[(ki - ci) % 26]
        pt.append(p)
        key.append(c)
    return "".join(pt)

# All keywords as primers, both alphabets, all 4 autokey variants
for kw in STRIP_KEYWORDS[:14]:
    for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
        for name, fn in [
            ("AK-VIG-PT", autokey_vig_decrypt),
            ("AK-BEAU-PT", autokey_beau_decrypt),
            ("AK-VIG-CT", autokey_ct_vig_decrypt),
            ("AK-BEAU-CT", autokey_ct_beau_decrypt),
        ]:
            pt_str = fn(CT, kw, alpha)
            score = score_text(pt_str)
            report_result(f"{name}-{kw[:8]}-{alpha_name}",
                          f"autokey primer={kw}",
                          pt_str, score)
            count_a5 += 1

# Also: autokey with mixed alphabet
for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
    keyed = make_keyed_alpha(kw)
    for primer in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        for name, fn in [
            ("AK-VIG-PT", autokey_vig_decrypt),
            ("AK-BEAU-PT", autokey_beau_decrypt),
        ]:
            pt_str = fn(CT, primer, keyed)
            score = score_text(pt_str)
            report_result(f"{name}-keyed-{kw[:5]}-{primer[:5]}",
                          f"keyed alpha={kw}, primer={primer}",
                          pt_str, score)
            count_a5 += 1

print(f"  Autokey: {count_a5} tested, {time.time()-t5:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 6: DOUBLE-KEYWORD STRIP (one for strip ORDER, one for ROW)
# Explicit transposition+substitution as single operation via strip
# The strip order keyword rearranges which strip goes in which column.
# The row keyword selects the row to read.
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 6: Double-Keyword Strip (order + row, explicit T+S)")
print("=" * 70)
t6 = time.time()

count_a6 = 0

def double_keyword_strip_decrypt(ct: str, order_kw: str, row_kw: str,
                                   alpha: str) -> str:
    """
    True strip cipher with two keywords.
    1. Build 26 strips = cyclic shifts of alpha.
    2. Order strips by order_kw (keyword ordering).
    3. For each CT position, the strip in that column provides the cipher alphabet.
    4. The row keyword gives the shift within that strip.
    """
    # Build keyword-ordered strip indices
    # Step 1: Create numbered strips (strip i = alpha shifted by i)
    # Step 2: Reorder by keyword
    kw_chars = []
    seen = set()
    for c in order_kw:
        if c in alpha and c not in seen:
            seen.add(c)
            kw_chars.append(alpha.index(c))
    for i in range(26):
        if i not in seen:
            seen.add(i)
            kw_chars.append(i)

    # kw_chars[j] = which strip goes in position j
    # Row key
    row_vals = [alpha.index(c) for c in row_kw if c in alpha]
    if not row_vals:
        row_vals = [0]

    pt = []
    for i, c in enumerate(ct):
        col = i % 26
        strip_num = kw_chars[col]
        row_shift = row_vals[i % len(row_vals)]

        # The strip: alpha shifted by strip_num, then row_shift applied
        total_shift = (strip_num + row_shift) % 26
        cipher_alpha = alpha[total_shift:] + alpha[:total_shift]

        # CT char position in cipher alphabet → PT char at same position in base alpha
        if c in cipher_alpha:
            pos = cipher_alpha.index(c)
            pt.append(alpha[pos])
        else:
            pt.append('?')
    return "".join(pt)


for order_kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SCHEIDT", "SANBORN"]:
    for row_kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SCHEIDT", "SANBORN"]:
        for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
            pt_str = double_keyword_strip_decrypt(CT, order_kw, row_kw, alpha)
            score = score_text(pt_str)
            report_result(f"DBLSTRIP-{order_kw[:5]}-{row_kw[:5]}-{alpha_name}",
                          f"order={order_kw}, row={row_kw}",
                          pt_str, score)
            count_a6 += 1

print(f"  Double-keyword strip: {count_a6} tested, {time.time()-t6:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 7: NON-STANDARD TABLEAU CONSTRUCTIONS
# What if the tableau isn't a standard Vigenère square but has:
# - Reversed rows, alternating directions, Latin square permutations
# - Rows ordered by keyword rather than sequential shift
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 7: Non-Standard Tableau Constructions")
print("=" * 70)
t7 = time.time()

count_a7 = 0

# 7a: Alternating direction rows (boustrophedon)
for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
    boustro_tableau = []
    for i in range(26):
        row = alpha[i:] + alpha[:i]
        if i % 2 == 1:
            row = row[::-1]
        boustro_tableau.append(row)

    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        key_vals = [alpha.index(c) for c in kw if c in alpha]
        pt = []
        for i, c in enumerate(CT):
            row_idx = key_vals[i % len(key_vals)]
            row = boustro_tableau[row_idx]
            if c in row:
                pt.append(alpha[row.index(c)])
            else:
                pt.append('?')
        pt_str = "".join(pt)
        score = score_text(pt_str)
        report_result(f"BOUSTRO-{kw[:8]}-{alpha_name}",
                      f"boustrophedon tableau",
                      pt_str, score)
        count_a7 += 1

# 7b: Keyword-ordered rows (rows are reordered by keyword ranking)
for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
    for order_kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        row_order = keyword_to_strip_order(order_kw, alpha)
        reordered_tableau = [build_tableau(alpha)[row_order[i]] for i in range(26)]

        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            key_vals = [alpha.index(c) for c in kw if c in alpha]
            pt = []
            for i, c in enumerate(CT):
                row_idx = key_vals[i % len(key_vals)]
                row = reordered_tableau[row_idx]
                if c in row:
                    pt.append(alpha[row.index(c)])
                else:
                    pt.append('?')
            pt_str = "".join(pt)
            score = score_text(pt_str)
            report_result(f"ROWORDER-{order_kw[:5]}-{kw[:5]}-{alpha_name}",
                          f"row order={order_kw}, key={kw}",
                          pt_str, score)
            count_a7 += 1

# 7c: Mixed-alphabet tableau (keyword-mixed alphabet as base)
for kw_base in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
    mixed = make_keyed_alpha(kw_base)
    mixed_tab = build_tableau(mixed)
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        for alpha_name, ref_alpha in [("KA", KA), ("AZ", AZ), ("MIX", mixed)]:
            key_vals = [ref_alpha.index(c) if c in ref_alpha else 0 for c in kw]
            pt = []
            for i, c in enumerate(CT):
                row_idx = key_vals[i % len(key_vals)]
                row = mixed_tab[row_idx]
                if c in row:
                    pt.append(mixed[row.index(c)])
                else:
                    pt.append('?')
            pt_str = "".join(pt)
            score = score_text(pt_str)
            report_result(f"MIXTAB-{kw_base[:5]}-{kw[:5]}-{alpha_name}",
                          f"mixed base={kw_base}, key={kw}",
                          pt_str, score)
            count_a7 += 1

print(f"  Non-standard tableaux: {count_a7} tested, {time.time()-t7:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 8: RUNNING KEY (K1/K3 PT as key for strip/disk)
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 8: Running Key (K1/K3 PT)")
print("=" * 70)
t8 = time.time()

K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHE"
    "LOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINYBREAC"
    "HINTHEUPPE"
)

count_a8 = 0

# Use K1/K3 PT as running key
for source_name, source in [("K1PT", K1_PT), ("K3PT", K3_PT)]:
    # Extend to 97 chars
    extended = (source * ((N // len(source)) + 2))[:N]

    for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
        # Vigenère decrypt with running key
        pt = vig_decrypt(CT, extended, alpha)
        score = score_text(pt)
        report_result(f"RUNKEY-VIG-{source_name}-{alpha_name}",
                      f"running key from {source_name}",
                      pt, score)
        count_a8 += 1

        # Beaufort decrypt
        pt = beau_decrypt(CT, extended, alpha)
        score = score_text(pt)
        report_result(f"RUNKEY-BEAU-{source_name}-{alpha_name}",
                      f"running key from {source_name}",
                      pt, score)
        count_a8 += 1

        # K3 PT at various offsets
        for offset in range(min(len(source), 50)):
            ext = (source[offset:] + source[:offset])
            ext = (ext * ((N // len(ext)) + 2))[:N]
            pt = vig_decrypt(CT, ext, alpha)
            score = score_text(pt)
            report_result(f"RUNKEY-VIG-{source_name}-off{offset}-{alpha_name}",
                          f"offset={offset}",
                          pt, score)
            pt = beau_decrypt(CT, ext, alpha)
            score = score_text(pt)
            report_result(f"RUNKEY-BEAU-{source_name}-off{offset}-{alpha_name}",
                          f"offset={offset}",
                          pt, score)
            count_a8 += 2

print(f"  Running key: {count_a8} tested, {time.time()-t8:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 9: PROGRESSIVE KEY / ACCUMULATING SHIFT
# Scheidt's "shifting matrices" — the shift accumulates or progresses
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 9: Progressive / Accumulating Key")
print("=" * 70)
t9 = time.time()

count_a9 = 0

def progressive_decrypt(ct: str, keyword: str, alpha: str, mode: str,
                         accumulate: str = "none") -> str:
    """
    Progressive key cipher: each repetition of the keyword is shifted.
    mode: 'vig' or 'beau'
    accumulate: 'none' (standard Vig), 'shift1' (each rep shifts by 1),
                'shift_key' (each rep shifts by keyword length),
                'double' (shift doubles each rep)
    """
    key_vals = [alpha.index(c) for c in keyword if c in alpha]
    kl = len(key_vals)
    pt = []
    extra_shift = 0

    for i, c in enumerate(ct):
        pos_in_key = i % kl
        rep_num = i // kl

        # Calculate progressive shift
        if accumulate == "none":
            extra_shift = 0
        elif accumulate == "shift1":
            extra_shift = rep_num
        elif accumulate == "shift_key":
            extra_shift = rep_num * kl
        elif accumulate == "double":
            extra_shift = rep_num * 2
        elif accumulate == "triangular":
            extra_shift = rep_num * (rep_num + 1) // 2
        elif accumulate == "position":
            extra_shift = i

        ki = (key_vals[pos_in_key] + extra_shift) % 26
        ci = alpha.index(c)

        if mode == "vig":
            pt.append(alpha[(ci - ki) % 26])
        elif mode == "beau":
            pt.append(alpha[(ki - ci) % 26])
    return "".join(pt)


for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SCHEIDT"]:
    for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
        for mode in ["vig", "beau"]:
            for acc in ["none", "shift1", "shift_key", "double", "triangular", "position"]:
                pt_str = progressive_decrypt(CT, kw, alpha, mode, acc)
                score = score_text(pt_str)
                report_result(f"PROG-{mode}-{acc}-{kw[:5]}-{alpha_name}",
                              f"progressive {acc}, key={kw}",
                              pt_str, score)
                count_a9 += 1

print(f"  Progressive key: {count_a9} tested, {time.time()-t9:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 10: GRONSFELD / NUMERICAL KEY VARIANTS
# Use pure numerical keys instead of alphabetic ones
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 10: Gronsfeld / Numerical Key Variants")
print("=" * 70)
t10 = time.time()

count_a10 = 0

# Numerical keys from K4 metadata
NUMERICAL_KEYS = [
    [3, 8, 7, 3],             # "8 Lines 73" → 8,7,3
    [8, 7, 3],                # Just the digits
    [8, 1, 7, 3],             # 8 lines 73
    [1, 9, 9, 0],             # Year of Kryptos
    [1, 9, 8, 9],             # Scheidt retired
    [9, 7],                   # Length of K4
    [2, 1, 3, 3, 6, 3, 7, 3], # Crib positions
    [3, 8, 1, 2, 1, 4, 6, 3], # lat/long digits
    [7],                       # len(KRYPTOS)
    [8],                       # period 8
    [1, 3],                    # 13 chars in ENE crib
    [1, 1],                    # 11 chars in BC crib
    [3, 2, 7, 3],              # self-encrypt pos
    [2, 6],                    # alphabet size
    [2, 8, 3, 1],              # grid dims
]

for nk in NUMERICAL_KEYS:
    for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
        key_str = "".join(alpha[v % 26] for v in nk)
        # Vigenère
        pt = vig_decrypt(CT, key_str, alpha)
        score = score_text(pt)
        nk_str = "".join(map(str, nk))
        report_result(f"GRONS-vig-{nk_str}-{alpha_name}",
                      f"Gronsfeld key={nk}",
                      pt, score)
        count_a10 += 1

        # Beaufort
        pt = beau_decrypt(CT, key_str, alpha)
        score = score_text(pt)
        report_result(f"GRONS-beau-{nk_str}-{alpha_name}",
                      f"Gronsfeld key={nk}",
                      pt, score)
        count_a10 += 1

print(f"  Gronsfeld: {count_a10} tested, {time.time()-t10:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 11: STRIP CIPHER WITH PERMUTATION-DERIVED UNSCRAMBLING
# Model: carved text is simultaneously encrypted+transposed by strip cipher.
# For each keyword pair, the strip cipher produces a specific permutation.
# Extract that permutation and test it.
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 11: Strip-Derived Permutations (sub+trans as one op)")
print("=" * 70)
t11 = time.time()

count_a11 = 0

def strip_permutation(order_kw: str, row_kw: str, alpha: str) -> list[int]:
    """
    Derive the effective permutation from a strip cipher configuration.

    The strip cipher works position-by-position. For each position i:
    - The strip in column (i % 26) is selected by the ordering keyword
    - The row offset comes from the row keyword
    - Together these give a unique (strip, row) pair = unique shift

    The effective shift at position i determines a monoalphabetic substitution.
    But the strip ORDER also creates a position-dependent permutation of
    which cipher alphabet is used where.

    We can compute the effective shift sequence and use it as a permutation key.
    """
    kw_chars = []
    seen = set()
    for c in order_kw:
        if c in alpha and c not in seen:
            seen.add(c)
            kw_chars.append(alpha.index(c))
    for i in range(26):
        if i not in seen:
            seen.add(i)
            kw_chars.append(i)

    row_vals = [alpha.index(c) for c in row_kw if c in alpha]
    if not row_vals:
        row_vals = [0]

    # Compute effective shift at each position
    shifts = []
    for i in range(N):
        col = i % 26
        strip_num = kw_chars[col]
        row_shift = row_vals[i % len(row_vals)]
        total_shift = (strip_num + row_shift) % 26
        shifts.append(total_shift)

    return shifts


# For each config, extract shift sequence, use it to generate permutation candidates
for order_kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SCHEIDT"]:
    for row_kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SCHEIDT"]:
        for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
            shifts = strip_permutation(order_kw, row_kw, alpha)

            # Method A: argsort of shifts = reading order
            sig = sorted(range(N), key=lambda i: (shifts[i], i))
            if len(sig) == N and sorted(sig) == list(range(N)):
                real_ct = "".join(CT[sig[j]] for j in range(N))
                result = test_unscramble(real_ct)
                if result:
                    score = result.get("score", -9999)
                    report_result(
                        f"STRIP-PERM-A-{order_kw[:5]}-{row_kw[:5]}-{alpha_name}",
                        f"shift-argsort as unscramble",
                        result.get("plaintext", ""),
                        score, result
                    )
                    count_a11 += 1

            # Method B: shifts as direct index (mod 97)
            sig_b = [(s * (i + 1)) % N for i, s in enumerate(shifts)]
            if sorted(sig_b) == list(range(N)):
                real_ct = "".join(CT[sig_b[j]] for j in range(N))
                result = test_unscramble(real_ct)
                if result:
                    score = result.get("score", -9999)
                    report_result(
                        f"STRIP-PERM-B-{order_kw[:5]}-{row_kw[:5]}-{alpha_name}",
                        f"shift*pos mod 97 as perm",
                        result.get("plaintext", ""),
                        score, result
                    )
                    count_a11 += 1

            # Method C: inverse of shift sequence argsort
            sig_c = [0] * N
            for rank, pos in enumerate(sig):
                sig_c[pos] = rank
            if sorted(sig_c) == list(range(N)):
                real_ct = "".join(CT[sig_c[j]] for j in range(N))
                result = test_unscramble(real_ct)
                if result:
                    score = result.get("score", -9999)
                    report_result(
                        f"STRIP-PERM-C-{order_kw[:5]}-{row_kw[:5]}-{alpha_name}",
                        f"inverse shift-argsort",
                        result.get("plaintext", ""),
                        score, result
                    )
                    count_a11 += 1

print(f"  Strip permutations: {count_a11} tested, {time.time()-t11:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 12: CONCENTRIC RING / JEFFERSON WHEEL MODEL
# Multiple alphabet rings stacked. Position i uses ring (i mod num_rings).
# Each ring has its own KA-shift. Keyword controls the phase offset.
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 12: Jefferson Wheel / Concentric Ring Model")
print("=" * 70)
t12 = time.time()

count_a12 = 0

def jefferson_decrypt(ct: str, ring_shifts: list[int], alpha: str,
                       read_offset: int, mode: str = "vig") -> str:
    """
    Jefferson wheel cipher.
    - ring_shifts: one shift per ring. Position i uses ring (i mod num_rings).
    - read_offset: which row to read the plaintext from (like choosing the
      generatrix on the physical device).
    """
    n_rings = len(ring_shifts)
    pt = []
    for i, c in enumerate(ct):
        ring_idx = i % n_rings
        shift = ring_shifts[ring_idx]
        total = (shift + read_offset) % 26
        ci = alpha.index(c)
        if mode == "vig":
            pt.append(alpha[(ci - total) % 26])
        elif mode == "beau":
            pt.append(alpha[(total - ci) % 26])
    return "".join(pt)


# Use keyword letters as ring shifts
for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SCHEIDT"]:
    for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
        ring_shifts = [alpha.index(c) for c in kw if c in alpha]
        for read_offset in range(26):
            for mode in ["vig", "beau"]:
                pt_str = jefferson_decrypt(CT, ring_shifts, alpha, read_offset, mode)
                score = score_text(pt_str)
                report_result(
                    f"JEFF-{kw[:5]}-{alpha_name}-off{read_offset}-{mode}",
                    f"Jefferson wheel, key={kw}, offset={read_offset}",
                    pt_str, score
                )
                count_a12 += 1

# Double wheel: inner keyword + outer keyword
for kw1 in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
    for kw2 in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        if kw1 == kw2:
            continue
        for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
            shifts1 = [alpha.index(c) for c in kw1 if c in alpha]
            shifts2 = [alpha.index(c) for c in kw2 if c in alpha]
            # Combined: alternating or interleaved
            combined = []
            for i in range(N):
                s1 = shifts1[i % len(shifts1)]
                s2 = shifts2[i % len(shifts2)]
                combined.append((s1 + s2) % 26)

            pt = []
            for i, c in enumerate(CT):
                ci = alpha.index(c)
                pt.append(alpha[(ci - combined[i]) % 26])
            pt_str = "".join(pt)
            score = score_text(pt_str)
            report_result(f"JEFF-DBL-{kw1[:5]}-{kw2[:5]}-{alpha_name}",
                          f"double wheel, {kw1}+{kw2}",
                          pt_str, score)

            # Beaufort
            pt = []
            for i, c in enumerate(CT):
                ci = alpha.index(c)
                pt.append(alpha[(combined[i] - ci) % 26])
            pt_str = "".join(pt)
            score = score_text(pt_str)
            report_result(f"JEFF-DBL-BEAU-{kw1[:5]}-{kw2[:5]}-{alpha_name}",
                          f"double wheel beaufort",
                          pt_str, score)
            count_a12 += 2

print(f"  Jefferson wheel: {count_a12} tested, {time.time()-t12:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 13: SELF-ENCRYPTING POSITION CONSTRAINT EXPLOITATION
# Use the fact that shift=0 at positions 32 and 73 to narrow search.
# For any cipher model, the effective keystream must be 0 at those positions.
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("APPROACH 13: Self-Encrypting Constraint Exploitation")
print("=" * 70)
t13 = time.time()

count_a13 = 0

# For any periodic key of length L, key[32 % L] = 0 and key[73 % L] = 0
# For L=7: 32%7=4, 73%7=3 → key[3]=key[4]=0
# For L=8: 32%8=0, 73%8=1 → key[0]=key[1]=0
# For L=13: 32%13=6, 73%13=8 → key[6]=key[8]=0

# Bean constraint: key[27]=key[65]. For period L: 27%L = 65%L → only if L divides 38.
# 38 = 2*19. Divisors: 1,2,19,38. So periods 1,2,19,38 satisfy Bean EQ trivially.
# For other periods, need key[27%L] = key[65%L] (different residues, same value).

print("  Constraint analysis for periodic keys:")
for L in range(2, 30):
    pos32_res = 32 % L
    pos73_res = 73 % L
    pos27_res = 27 % L
    pos65_res = 65 % L
    bean_auto = (pos27_res == pos65_res)
    zero_positions = {pos32_res, pos73_res}
    bean_zero = pos27_res in zero_positions and pos65_res in zero_positions

    constraints = f"L={L:2d}: zero@res{pos32_res},{pos73_res}"
    if bean_auto:
        constraints += f" Bean=AUTO(res{pos27_res})"
    else:
        constraints += f" Bean=key[{pos27_res}]==key[{pos65_res}]"
        if bean_zero:
            constraints += " (both zero!)"
    print(f"    {constraints}")

# Exhaustive search of short periodic keys with self-encrypt constraint
print("\n  Exhaustive periodic key search with self-encrypt constraint...")
for L in range(2, 12):
    pos32_res = 32 % L
    pos73_res = 73 % L
    pos27_res = 27 % L
    pos65_res = 65 % L

    # Generate all keys of length L with zeros at required positions
    zero_residues = {pos32_res, pos73_res}
    free_residues = [r for r in range(L) if r not in zero_residues]
    n_free = len(free_residues)

    # Cap at reasonable number
    max_per_free = min(26, 26)
    if 26 ** n_free > 500000:
        # Sample randomly
        rng = random.Random(42 + L)
        sample_count = 50000
        tested_this_L = 0
        for _ in range(sample_count):
            key = [0] * L
            for r in free_residues:
                key[r] = rng.randint(0, 25)
            # Bean constraint
            if pos27_res != pos65_res and key[pos27_res] != key[pos65_res]:
                continue
            for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
                key_str = "".join(alpha[k] for k in key)
                pt = vig_decrypt(CT, key_str, alpha)
                score = score_text(pt)
                report_result(f"SELFE-L{L}-vig-{alpha_name}",
                              f"key={key}", pt, score)
                pt = beau_decrypt(CT, key_str, alpha)
                score = score_text(pt)
                report_result(f"SELFE-L{L}-beau-{alpha_name}",
                              f"key={key}", pt, score)
                count_a13 += 2
                tested_this_L += 2
        print(f"    L={L}: sampled {tested_this_L} configs (random)")
    else:
        # Enumerate all
        tested_this_L = 0
        for combo in itertools.product(range(26), repeat=n_free):
            key = [0] * L
            for idx, r in enumerate(free_residues):
                key[r] = combo[idx]
            # Bean constraint
            if pos27_res != pos65_res and key[pos27_res] != key[pos65_res]:
                continue
            for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
                key_str = "".join(alpha[k] for k in key)
                pt = vig_decrypt(CT, key_str, alpha)
                score = score_text(pt)
                report_result(f"SELFE-L{L}-vig-{alpha_name}",
                              f"key={key}", pt, score)
                pt = beau_decrypt(CT, key_str, alpha)
                score = score_text(pt)
                report_result(f"SELFE-L{L}-beau-{alpha_name}",
                              f"key={key}", pt, score)
                count_a13 += 2
                tested_this_L += 2
        print(f"    L={L}: exhaustive {tested_this_L} configs")

print(f"  Self-encrypt constraint: {count_a13} tested, {time.time()-t13:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# FINAL SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
elapsed_total = time.time() - t0

print("\n" + "=" * 70)
print("FINAL SUMMARY — Strip Cipher / Simultaneous Sub+Trans")
print("=" * 70)
print(f"Total configs tested     : {total_tested}")
print(f"Total elapsed            : {elapsed_total:.1f}s")
print(f"CRIB HITS FOUND          : {len(CRIB_HITS)}")
print(f"Interesting (>-5.5/char) : {len(INTERESTING)}")
print(f"Best score               : {best_score:.2f}")
print(f"Best per-char            : {best_per_char:.4f}")

if best_entry:
    print(f"Best approach : {best_entry['approach']}")
    print(f"Best note     : {best_entry['note']}")
    print(f"Best PT       : {best_entry['pt'][:50]}...")

if CRIB_HITS:
    print(f"\n*** CRIB HIT DETAILS:")
    for hit in CRIB_HITS:
        print(f"  Approach : {hit['approach']}")
        print(f"  Score    : {hit['score']:.2f}")
        print(f"  Per char : {hit['per_char']:.4f}")
        print(f"  PT       : {hit['pt']}")
        print(f"  Cribs    : {hit['cribs']}")

if INTERESTING:
    print(f"\nTop 20 interesting results (>-5.5/char):")
    INTERESTING.sort(key=lambda x: -x["per_char"])
    for i, entry in enumerate(INTERESTING[:20]):
        print(f"  {i+1}. [{entry['approach']}] per_char={entry['per_char']:.4f}, "
              f"score={entry['score']:.2f}")
        print(f"     PT={entry['pt'][:60]}...")

# Score distribution
scores = [r["score"] for r in all_results if r["score"] > -9000]
if scores:
    print(f"\nScore distribution: min={min(scores):.2f}, max={max(scores):.2f}, "
          f"mean={sum(scores)/len(scores):.2f}")
    per_chars = [r["per_char"] for r in all_results if r["per_char"] > -20]
    if per_chars:
        print(f"Per-char distribution: min={min(per_chars):.4f}, max={max(per_chars):.4f}, "
              f"mean={sum(per_chars)/len(per_chars):.4f}")

# Save
out_path = save_results()
print(f"\nResults saved to: {out_path}")

if CRIB_HITS:
    status = "SOLVED"
elif best_per_char > -5.5:
    status = "PROMISING"
elif best_per_char > -7.0:
    status = "MARGINAL"
else:
    status = "INCONCLUSIVE"

print(f"\nVerdict: {status}")
