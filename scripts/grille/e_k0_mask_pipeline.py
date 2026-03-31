#!/usr/bin/env python3
"""
E-K0-MASK-PIPELINE: Test the single clean K0-derived null mask through
the full cipher pipeline with all keyword × cipher × transposition combos.

The mask: positions {9,10,11,19,20,34,35,42,43,44,45,46,53,54,55,61,
80,81,82,83,84,85,86,96} — derived from K0 Morse E-group run-length
at offset 80.

Extracted 73-char CT: OBKRUOXOGBSOLIFBFLRVQQPRNGKSSWTQSJQZWATJKIAWINBNYPVTTMZFPKWGDKZXUHUAUEKCA

Tests:
  - 30 thematic keywords × 5 cipher variants × 7 transpositions
  - Plus autokey variants
  - Score against shifted cribs (Model A)

Cipher: k0-mask-pipeline
Family: grille
Status: active
Keyspace: ~2,100 keyword×cipher×trans combos + autokey
Last run: never
Best score: n/a
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CRIB_DICT
from kryptos.kernel.text import sanitize
from kryptos.kernel.alphabet import AZ, KA, keyword_mixed_alphabet

# --- The K0-derived null mask ---
NULL_POS = [9, 10, 11, 19, 20, 34, 35, 42, 43, 44, 45, 46, 53, 54, 55, 61,
            80, 81, 82, 83, 84, 85, 86, 96]
NULL_SET = set(NULL_POS)

# Extract CT and remap cribs (Model A)
def extract_and_remap():
    extracted = []
    crib_map = {}  # new_pos → expected_char
    new_idx = 0
    for i in range(len(CT)):
        if i not in NULL_SET:
            extracted.append(CT[i])
            if i in CRIB_DICT:
                crib_map[new_idx] = CRIB_DICT[i]
            new_idx += 1
    return "".join(extracted), crib_map

ECT, CRIBS = extract_and_remap()
assert len(ECT) == 73, f"Expected 73, got {len(ECT)}"
print(f"Extracted CT ({len(ECT)} chars): {ECT}")
print(f"Remapped cribs ({len(CRIBS)} positions): { {k: CRIBS[k] for k in sorted(CRIBS)} }")
print()

# --- Cipher implementations ---
AZ_STR = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA_STR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

def alpha_idx(ch, alpha):
    return alpha.index(ch)

def vigenere_dec(ct, key, alpha):
    pt = []
    for i, c in enumerate(ct):
        ci = alpha_idx(c, alpha)
        ki = alpha_idx(key[i % len(key)], alpha)
        pt.append(alpha[(ci - ki) % 26])
    return "".join(pt)

def beaufort_dec(ct, key, alpha):
    pt = []
    for i, c in enumerate(ct):
        ci = alpha_idx(c, alpha)
        ki = alpha_idx(key[i % len(key)], alpha)
        pt.append(alpha[(ki - ci) % 26])
    return "".join(pt)

def varbeaufort_dec(ct, key, alpha):
    pt = []
    for i, c in enumerate(ct):
        ci = alpha_idx(c, alpha)
        ki = alpha_idx(key[i % len(key)], alpha)
        pt.append(alpha[(ci + ki) % 26])
    return "".join(pt)

def autokey_vig_dec(ct, key, alpha):
    pt = []
    full_key = list(key)
    for i, c in enumerate(ct):
        ci = alpha_idx(c, alpha)
        ki = alpha_idx(full_key[i], alpha)
        p = (ci - ki) % 26
        pt.append(alpha[p])
        full_key.append(alpha[p])
    return "".join(pt)

def autokey_beau_dec(ct, key, alpha):
    pt = []
    full_key = list(key)
    for i, c in enumerate(ct):
        ci = alpha_idx(c, alpha)
        ki = alpha_idx(full_key[i], alpha)
        p = (ki - ci) % 26
        pt.append(alpha[p])
        full_key.append(alpha[p])
    return "".join(pt)

# --- Transpositions ---
def columnar_undo(ct, width):
    n = len(ct)
    rows = -(-n // width)  # ceil div
    remainder = n % width
    result = [''] * n
    pos = 0
    for col in range(width):
        col_len = rows if (remainder == 0 or col < remainder) else rows - 1
        for row in range(col_len):
            result[row * width + col] = ct[pos]
            pos += 1
    return "".join(result)

def railfence_undo(ct, depth):
    n = len(ct)
    if depth <= 1 or depth >= n:
        return ct
    rail_lens = [0] * depth
    rail, d = 0, 1
    for _ in range(n):
        rail_lens[rail] += 1
        if rail == 0: d = 1
        elif rail == depth - 1: d = -1
        rail += d
    rails = []
    pos = 0
    for r in range(depth):
        rails.append(ct[pos:pos + rail_lens[r]])
        pos += rail_lens[r]
    result = []
    indices = [0] * depth
    rail, d = 0, 1
    for _ in range(n):
        result.append(rails[rail][indices[rail]])
        indices[rail] += 1
        if rail == 0: d = 1
        elif rail == depth - 1: d = -1
        rail += d
    return "".join(result)

# --- Score ---
def score_cribs(pt, cribs):
    ene_hits = bc_hits = 0
    for pos, expected in cribs.items():
        if pos < len(pt) and pt[pos] == expected:
            # Determine original CT97 position to classify ENE vs BC
            # We need to reverse-map, but simpler: ENE cribs are first 13, BC are last 11
            # In sorted order, first 13 remapped positions = ENE, last 11 = BC
            pass
    # Simple: count by position order in sorted cribs
    sorted_pos = sorted(cribs.keys())
    ene_positions = sorted_pos[:13]  # First 13 = EASTNORTHEAST
    bc_positions = sorted_pos[13:]   # Last 11 = BERLINCLOCK

    for pos in ene_positions:
        if pos < len(pt) and pt[pos] == cribs[pos]:
            ene_hits += 1
    for pos in bc_positions:
        if pos < len(pt) and pt[pos] == cribs[pos]:
            bc_hits += 1
    return ene_hits + bc_hits, ene_hits, bc_hits

# --- Keywords ---
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "KOMPASS",
    "COLOPHON", "PARALLAX", "SHADOW", "LUCID", "INVISIBLE",
    "VIRTUALLY", "FORCES", "MEMORY", "POSITION", "DIGETAL",
    "BERLINCLOCK", "EASTNORTHEAST", "UNDERGROUND", "ILLUSION",
    "DESPERATELY", "MASQUERADE", "INTERPRET", "IQLUSION",
    "NORTHEAST", "COMPASS", "LODESTONE", "CIPHER", "ENIGMA",
    "LAYERTWO", "TELEGRAPHIC",
]

CIPHERS = [
    ("vig", "AZ", vigenere_dec, AZ_STR),
    ("beau", "AZ", beaufort_dec, AZ_STR),
    ("vbeau", "AZ", varbeaufort_dec, AZ_STR),
    ("vig", "KA", vigenere_dec, KA_STR),
    ("beau", "KA", beaufort_dec, KA_STR),
    ("akey_vig", "AZ", autokey_vig_dec, AZ_STR),
    ("akey_beau", "AZ", autokey_beau_dec, AZ_STR),
    ("akey_vig", "KA", autokey_vig_dec, KA_STR),
    ("akey_beau", "KA", autokey_beau_dec, KA_STR),
]

TRANSPOSITIONS = [
    ("none", lambda ct: ct),
    ("col5", lambda ct: columnar_undo(ct, 5)),
    ("col7", lambda ct: columnar_undo(ct, 7)),
    ("col9", lambda ct: columnar_undo(ct, 9)),
    ("col10", lambda ct: columnar_undo(ct, 10)),
    ("col11", lambda ct: columnar_undo(ct, 11)),
    ("col13", lambda ct: columnar_undo(ct, 13)),
    ("rail3", lambda ct: railfence_undo(ct, 3)),
    ("rail4", lambda ct: railfence_undo(ct, 4)),
    ("rail5", lambda ct: railfence_undo(ct, 5)),
    ("rail7", lambda ct: railfence_undo(ct, 7)),
]


def main():
    print("=" * 70)
    print("K0 MORSE NULL MASK — FULL PIPELINE TEST")
    print(f"Null positions: {NULL_POS}")
    print(f"Extracted CT: {ECT}")
    print(f"Testing: {len(KEYWORDS)} keywords × {len(CIPHERS)} ciphers × {len(TRANSPOSITIONS)} transpositions")
    total = len(KEYWORDS) * len(CIPHERS) * len(TRANSPOSITIONS)
    print(f"Total configs: {total}")
    print("=" * 70)

    results = []
    tested = 0

    for trans_name, trans_fn in TRANSPOSITIONS:
        working_ct = trans_fn(ECT)
        for kw in KEYWORDS:
            for cipher_name, alpha_name, cipher_fn, alpha in CIPHERS:
                try:
                    pt = cipher_fn(working_ct, kw, alpha)
                except Exception:
                    continue
                total_score, ene, bc = score_cribs(pt, CRIBS)
                tested += 1

                if total_score >= 6:
                    desc = f"{kw}:{alpha_name}_{cipher_name}+{trans_name}"
                    results.append((total_score, ene, bc, desc, pt[:50]))

                if tested % 500 == 0:
                    print(f"  ...tested {tested}/{total}")

    # Sort by score descending
    results.sort(key=lambda x: (-x[0], -x[1]))

    print(f"\nTested: {tested} configs")
    print(f"Scores >= 6: {len(results)}")
    print()

    if results:
        print("TOP RESULTS:")
        print("-" * 70)
        for score, ene, bc, desc, pt_preview in results[:30]:
            print(f"  {score:2d}/24 (ene={ene:2d}/13 bc={bc:2d}/11) {desc}")
            print(f"         PT: {pt_preview}...")
        print("-" * 70)

    # Also test with NO cipher (passthrough) to see if transposition alone reveals cribs
    print("\nPASSTHROUGH (no substitution) — does transposition alone align cribs?")
    for trans_name, trans_fn in TRANSPOSITIONS:
        working_ct = trans_fn(ECT)
        total_score, ene, bc = score_cribs(working_ct, CRIBS)
        if total_score > 0:
            print(f"  {trans_name}: {total_score}/24 (ene={ene} bc={bc})")

    # Best score summary
    if results:
        best = results[0]
        print(f"\n{'=' * 70}")
        print(f"BEST: {best[0]}/24 (ene={best[1]}/13 bc={best[2]}/11) — {best[3]}")
        print(f"PT: {best[4]}...")
        if best[0] >= 10:
            print("*** ABOVE NOISE THRESHOLD — INVESTIGATE ***")
        elif best[0] >= 6:
            print("Above random floor but likely noise.")
        print(f"{'=' * 70}")
    else:
        print("\nNo scores >= 6. This mask produces only noise with tested ciphers.")


if __name__ == "__main__":
    main()
