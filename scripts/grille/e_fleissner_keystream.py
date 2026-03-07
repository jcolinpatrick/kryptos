#!/usr/bin/env python3
"""
Cipher: Fleissner grille keystream
Family: grille
Status: active
Keyspace: 4^25 * 676 offsets * 6 variants ~= 4.6e18 (sampled)
Last run:
Best score:
"""
"""
E-FLEISSNER-KEYSTREAM: Fleissner Grille on Vigenère Tableau → Keystream

NEW HYPOTHESIS: The Cardan/Fleissner grille applied to the Vigenère tableau
produces a KEYSTREAM (not a permutation of ciphertext positions). That key
is then used for Vigenère/Beaufort decryption of the carved CT IN ITS
ORIGINAL ORDER.

K4 has 97 characters. 97 + 3 padding = 100 = 10x10. A Fleissner (turning)
grille on a 10x10 grid has 25 holes. The grille is placed, 25 characters
are read, rotated 90° three more times → 100 total.

TWO APPROACHES:
  A) KEYSTREAM MODE: Read keystream from Vigenère tableau through grille,
     use as running key against carved CT.
  B) TRANSPOSITION + KEYWORD: Fill 10x10 with K4, read through grille for
     reordered CT, then Vig/Beaufort with known keywords.

Approach A: For each Fleissner mask + tableau offset, extract 100 chars from
the KA Vigenère tableau (26x26). Use first 97 as running key.

Approach B: For each Fleissner mask, reorder K4 characters, then try all
thematic keywords with Vig/Beaufort.

Uses 28-core multiprocessing, quadgram scoring, crib detection.
"""

import json
import math
import os
import random
import sys
import time
from collections import Counter
from multiprocessing import Pool, cpu_count, Manager

# ── Setup path ────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
)

# ── Constants ─────────────────────────────────────────────────────────────
AZ = ALPH
KA = KRYPTOS_ALPHABET
AZ_IDX = ALPH_IDX
KA_IDX = {c: i for i, c in enumerate(KA)}
CT_AZ = [AZ_IDX[c] for c in CT]  # CT as AZ indices
CT_KA = [KA_IDX[c] for c in CT]  # CT as KA indices

CRIB_AZ = {p: AZ_IDX[c] for p, c in CRIB_DICT.items()}

N_WORKERS = min(28, cpu_count())
GRID_SIZE = 10
N_CELLS = 100

# ── Load quadgrams ───────────────────────────────────────────────────────
QUADGRAM_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json')

print("Loading quadgrams...", flush=True)
with open(QUADGRAM_PATH) as f:
    _qg_raw = json.load(f)

# Build a flat lookup: tuple(4 indices) -> log_prob
QG_FLOOR = -10.0
QG_TABLE = {}
for quad, score in _qg_raw.items():
    if len(quad) == 4:
        key = (ord(quad[0]) - 65, ord(quad[1]) - 65, ord(quad[2]) - 65, ord(quad[3]) - 65)
        QG_TABLE[key] = score
del _qg_raw
print(f"Loaded {len(QG_TABLE)} quadgrams.", flush=True)


def qg_score_nums(nums):
    """Score a list of 0-25 integers by quadgram fitness."""
    if len(nums) < 4:
        return QG_FLOOR
    total = 0.0
    for i in range(len(nums) - 3):
        key = (nums[i], nums[i+1], nums[i+2], nums[i+3])
        total += QG_TABLE.get(key, QG_FLOOR)
    return total / (len(nums) - 3)


def qg_score_text(text):
    """Score uppercase text by quadgram fitness."""
    nums = [ord(c) - 65 for c in text]
    return qg_score_nums(nums)


# ── Crib checking ────────────────────────────────────────────────────────
CRIB_ENE = [(p, CRIB_DICT[p]) for p in range(21, 34)]  # EASTNORTHEAST
CRIB_BC = [(p, CRIB_DICT[p]) for p in range(63, 74)]    # BERLINCLOCK


def count_crib_matches(pt_text):
    """Count how many crib positions match in plaintext string."""
    matches = 0
    for p, ch in CRIB_ENE:
        if p < len(pt_text) and pt_text[p] == ch:
            matches += 1
    for p, ch in CRIB_BC:
        if p < len(pt_text) and pt_text[p] == ch:
            matches += 1
    return matches


def free_crib_search(pt_text):
    """Search for EASTNORTHEAST and BERLINCLOCK anywhere in text."""
    ene_best = 0
    bc_best = 0
    for start in range(len(pt_text) - 12):
        m = sum(1 for i, ch in enumerate("EASTNORTHEAST") if start + i < len(pt_text) and pt_text[start + i] == ch)
        if m > ene_best:
            ene_best = m
    for start in range(len(pt_text) - 10):
        m = sum(1 for i, ch in enumerate("BERLINCLOCK") if start + i < len(pt_text) and pt_text[start + i] == ch)
        if m > bc_best:
            bc_best = m
    return ene_best + bc_best


# ── Fleissner grille mechanics ───────────────────────────────────────────
def rotate_90(r, c, size=GRID_SIZE):
    """Rotate (r,c) 90 degrees clockwise in size x size grid."""
    return (c, size - 1 - r)


def build_orbits(size=GRID_SIZE):
    """Build 25 rotation orbits for a 10x10 Fleissner grille.
    Each orbit = 4 positions that map to each other under 90° rotation.
    """
    orbits = []
    visited = set()
    for r in range(size):
        for c in range(size):
            if (r, c) not in visited:
                orbit = [(r, c)]
                cr, cc = r, c
                for _ in range(3):
                    cr, cc = rotate_90(cr, cc, size)
                    orbit.append((cr, cc))
                unique = list(dict.fromkeys(orbit))
                if len(unique) == 4:
                    orbits.append(unique)
                    visited.update(unique)
    return orbits


ORBITS = build_orbits(GRID_SIZE)
assert len(ORBITS) == 25, f"Expected 25 orbits, got {len(ORBITS)}"

# Precompute orbit linear indices: ORBIT_LINEAR[i][k] = linear index of orbit i, rotation k
ORBIT_LINEAR = [[r * GRID_SIZE + c for (r, c) in orb] for orb in ORBITS]


def fleissner_reading_order(hole_choices):
    """Generate the 100-position reading order for a Fleissner grille.

    hole_choices: list of 25 values (0-3). For orbit i, the hole is at
                  position hole_choices[i] in that orbit.

    Returns list of 100 linear grid indices in reading order.
    At each rotation, holes are sorted by row-major order before reading.
    """
    reading = []
    for rotation in range(4):
        holes = []
        for i in range(25):
            pos_idx = (hole_choices[i] + rotation) % 4
            holes.append(ORBIT_LINEAR[i][pos_idx])
        holes.sort()  # Read in row-major order
        reading.extend(holes)
    return reading


# ── Build Vigenère tableaux ──────────────────────────────────────────────
def build_tableau(alphabet):
    """Build 26x26 Vigenère tableau for the given alphabet.
    Row r, Col c -> alphabet[(alphabet.index(alphabet[r]) + c) % 26]
    Which simplifies to: alphabet[(r + c) % 26]
    Returns 26x26 list of lists (character indices in AZ).
    """
    idx = {c: i for i, c in enumerate(alphabet)}
    tableau = []
    for r in range(26):
        row = []
        for c in range(26):
            ch = alphabet[(r + c) % 26]
            row.append(ch)
        tableau.append(row)
    return tableau


# Pre-build tableaux as character arrays
TABLEAU_KA = build_tableau(KA)  # [row][col] -> character
TABLEAU_AZ = build_tableau(AZ)  # [row][col] -> character

# Also as numeric (AZ index)
TABLEAU_KA_NUM = [[AZ_IDX[ch] for ch in row] for row in TABLEAU_KA]
TABLEAU_AZ_NUM = [[AZ_IDX[ch] for ch in row] for row in TABLEAU_AZ]


def extract_keystream_from_tableau(hole_choices, row_off, col_off, tableau):
    """Extract 100-char keystream from tableau using Fleissner grille.

    Places the 10x10 grille window at (row_off, col_off) on the 26x26 tableau
    (with wrapping). Reads through holes at each rotation.

    Returns list of 100 AZ-index values.
    """
    reading = fleissner_reading_order(hole_choices)
    keystream = []
    for linear_idx in reading:
        grid_r = linear_idx // GRID_SIZE
        grid_c = linear_idx % GRID_SIZE
        tab_r = (row_off + grid_r) % 26
        tab_c = (col_off + grid_c) % 26
        keystream.append(tableau[tab_r][tab_c])
    return keystream


# ── Decryption functions ─────────────────────────────────────────────────
def decrypt_vig_az(ct_nums, key_nums):
    """Vigenère decrypt: PT = (CT - KEY) mod 26, AZ alphabet."""
    return [(ct_nums[i] - key_nums[i]) % 26 for i in range(len(ct_nums))]


def decrypt_beau_az(ct_nums, key_nums):
    """Beaufort decrypt: PT = (KEY - CT) mod 26, AZ alphabet."""
    return [(key_nums[i] - ct_nums[i]) % 26 for i in range(len(ct_nums))]


def decrypt_varbeau_az(ct_nums, key_nums):
    """Variant Beaufort decrypt: PT = (CT + KEY) mod 26, AZ alphabet."""
    return [(ct_nums[i] + key_nums[i]) % 26 for i in range(len(ct_nums))]


def decrypt_vig_ka(ct_ka, key_ka):
    """Vigenère decrypt in KA space: PT_ka = (CT_ka - KEY_ka) mod 26."""
    return [(ct_ka[i] - key_ka[i]) % 26 for i in range(len(ct_ka))]


def decrypt_beau_ka(ct_ka, key_ka):
    """Beaufort decrypt in KA space: PT_ka = (KEY_ka - CT_ka) mod 26."""
    return [(key_ka[i] - ct_ka[i]) % 26 for i in range(len(ct_ka))]


def decrypt_varbeau_ka(ct_ka, key_ka):
    """Variant Beaufort in KA space: PT_ka = (CT_ka + KEY_ka) mod 26."""
    return [(ct_ka[i] + key_ka[i]) % 26 for i in range(len(ct_ka))]


def ka_nums_to_text(nums):
    """Convert KA-index numbers to text."""
    return ''.join(KA[n % 26] for n in nums)


def az_nums_to_text(nums):
    """Convert AZ-index numbers to text."""
    return ''.join(AZ[n % 26] for n in nums)


# ── APPROACH A: Keystream from Tableau ───────────────────────────────────

def worker_approach_a(args):
    """Worker for Approach A: random Fleissner masks, all offsets, all variants."""
    worker_id, n_masks, seed, report_threshold_qg, report_threshold_crib = args

    rng = random.Random(seed)
    best_qg = -999.0
    best_crib = 0
    results = []
    checked = 0

    for mask_idx in range(n_masks):
        holes = [rng.randint(0, 3) for _ in range(25)]

        # Sample offsets: for random masks, try a subset of offsets
        # Full 676 would be ideal but expensive; sample strategically
        offsets_to_try = []
        # Always try (0,0) and a spread
        for ro in range(0, 26, 2):  # every other row
            for co in range(0, 26, 2):  # every other column
                offsets_to_try.append((ro, co))

        for row_off, col_off in offsets_to_try:
            # Extract keystream from KA tableau
            ks_az = extract_keystream_from_tableau(holes, row_off, col_off, TABLEAU_KA_NUM)
            ks_97 = ks_az[:97]

            # Also get KA-indexed keystream
            ks_ka_chars = extract_keystream_from_tableau(holes, row_off, col_off, TABLEAU_KA)
            ks_ka = [KA_IDX[ch] for ch in ks_ka_chars[:97]]

            # Try all 6 decryption variants
            for variant_name, pt_nums, alph_name in [
                ("Vig-AZ", decrypt_vig_az(CT_AZ, ks_97), "AZ"),
                ("Beau-AZ", decrypt_beau_az(CT_AZ, ks_97), "AZ"),
                ("VarBeau-AZ", decrypt_varbeau_az(CT_AZ, ks_97), "AZ"),
                ("Vig-KA", decrypt_vig_ka(CT_KA, ks_ka), "KA"),
                ("Beau-KA", decrypt_beau_ka(CT_KA, ks_ka), "KA"),
                ("VarBeau-KA", decrypt_varbeau_ka(CT_KA, ks_ka), "KA"),
            ]:
                # Convert to text for scoring
                if alph_name == "AZ":
                    pt_text = az_nums_to_text(pt_nums)
                    pt_az_nums = pt_nums
                else:
                    pt_text = ka_nums_to_text(pt_nums)
                    pt_az_nums = [AZ_IDX[c] for c in pt_text]

                # Quick crib check first (cheap)
                crib_count = count_crib_matches(pt_text)

                # Only compute quadgram if cribs or random check
                checked += 1
                if crib_count >= report_threshold_crib or checked % 50 == 0:
                    qg = qg_score_nums(pt_az_nums)

                    if qg > report_threshold_qg or crib_count >= report_threshold_crib:
                        result = {
                            'worker': worker_id,
                            'mask': mask_idx,
                            'holes': holes[:],
                            'row_off': row_off,
                            'col_off': col_off,
                            'variant': variant_name,
                            'qg_score': qg,
                            'crib_count': crib_count,
                            'pt': pt_text[:60],
                        }
                        results.append(result)
                        if qg > best_qg:
                            best_qg = qg
                        if crib_count > best_crib:
                            best_crib = crib_count

            # Also try AZ tableau
            ks_az2 = extract_keystream_from_tableau(holes, row_off, col_off, TABLEAU_AZ_NUM)
            ks_97_az2 = ks_az2[:97]

            for variant_name, pt_nums in [
                ("Vig-AZ-AZtab", decrypt_vig_az(CT_AZ, ks_97_az2)),
                ("Beau-AZ-AZtab", decrypt_beau_az(CT_AZ, ks_97_az2)),
                ("VarBeau-AZ-AZtab", decrypt_varbeau_az(CT_AZ, ks_97_az2)),
            ]:
                pt_text = az_nums_to_text(pt_nums)
                crib_count = count_crib_matches(pt_text)
                checked += 1
                if crib_count >= report_threshold_crib or checked % 50 == 0:
                    qg = qg_score_nums(pt_nums)
                    if qg > report_threshold_qg or crib_count >= report_threshold_crib:
                        result = {
                            'worker': worker_id,
                            'mask': mask_idx,
                            'holes': holes[:],
                            'row_off': row_off,
                            'col_off': col_off,
                            'variant': variant_name,
                            'qg_score': qg,
                            'crib_count': crib_count,
                            'pt': pt_text[:60],
                        }
                        results.append(result)
                        if qg > best_qg:
                            best_qg = qg
                        if crib_count > best_crib:
                            best_crib = crib_count

    return {
        'worker': worker_id,
        'n_masks': n_masks,
        'checked': checked,
        'best_qg': best_qg,
        'best_crib': best_crib,
        'results': results,
    }


# ── APPROACH B: Fleissner Transposition + Keyword Substitution ───────────

# Keywords to try
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "MONOLITH", "COLOPHON",
    "PARALLAX", "VERDIGRIS", "TRIPTYCH", "ARMATURE", "OCULUS",
    "ESCUTCHEON", "OUBLIETTE", "CENOTAPH", "REVETEMENT", "FILIGREE",
    "GNOMON", "DOLMEN", "SANBORN", "SCHEIDT", "BERLIN",
    "SHADOW", "SPHINX", "ENIGMA", "LODESTONE", "QUARTZ",
    "ANTIPODES", "MAGNETIC", "COMPASS", "URANIA", "WELTZEITUHR",
]


def worker_approach_b(args):
    """Worker for Approach B: Fleissner transposition + keyword Vig/Beaufort."""
    worker_id, n_masks, seed, report_threshold_qg, report_threshold_crib = args

    rng = random.Random(seed)
    best_qg = -999.0
    best_crib = 0
    results = []
    checked = 0

    # Pre-compute CT in grid + padding
    grid_text = list(CT) + ['X', 'X', 'X']  # Pad with X
    grid_az = [AZ_IDX[c] for c in grid_text]

    for mask_idx in range(n_masks):
        holes = [rng.randint(0, 3) for _ in range(25)]
        reading = fleissner_reading_order(holes)

        # Read K4 through grille → reordered CT
        reordered = [grid_az[reading[i]] for i in range(97)]

        # Try each keyword with Vig/Beaufort
        for keyword in KEYWORDS:
            kw_az = [AZ_IDX[c] for c in keyword]
            kw_len = len(keyword)
            # Build repeating key
            key_stream = [kw_az[i % kw_len] for i in range(97)]

            for variant_name, decrypt_fn in [
                (f"Vig-{keyword}", decrypt_vig_az),
                (f"Beau-{keyword}", decrypt_beau_az),
                (f"VarBeau-{keyword}", decrypt_varbeau_az),
            ]:
                pt_nums = decrypt_fn(reordered, key_stream)
                pt_text = az_nums_to_text(pt_nums)

                crib_count = count_crib_matches(pt_text)
                # Also check free cribs (crib might not be at standard positions)
                free_count = 0

                checked += 1
                if crib_count >= report_threshold_crib or checked % 100 == 0:
                    qg = qg_score_nums(pt_nums)
                    if qg > report_threshold_qg or crib_count >= report_threshold_crib:
                        free_count = free_crib_search(pt_text)
                        result = {
                            'worker': worker_id,
                            'mask': mask_idx,
                            'holes': holes[:],
                            'variant': variant_name,
                            'qg_score': qg,
                            'crib_count': crib_count,
                            'free_crib': free_count,
                            'pt': pt_text[:60],
                        }
                        results.append(result)
                        if qg > best_qg:
                            best_qg = qg
                        if crib_count > best_crib:
                            best_crib = crib_count

            # Also try KA-alphabet Vigenère with keyword in KA
            kw_ka = [KA_IDX[c] for c in keyword]
            key_stream_ka = [kw_ka[i % kw_len] for i in range(97)]
            reordered_ka = [KA_IDX[grid_text[reading[i]]] for i in range(97)]

            for variant_name, decrypt_fn in [
                (f"VigKA-{keyword}", decrypt_vig_ka),
                (f"BeauKA-{keyword}", decrypt_beau_ka),
            ]:
                pt_nums = decrypt_fn(reordered_ka, key_stream_ka)
                pt_text = ka_nums_to_text(pt_nums)
                crib_count = count_crib_matches(pt_text)
                checked += 1
                if crib_count >= report_threshold_crib or checked % 100 == 0:
                    pt_az = [AZ_IDX[c] for c in pt_text]
                    qg = qg_score_nums(pt_az)
                    if qg > report_threshold_qg or crib_count >= report_threshold_crib:
                        result = {
                            'worker': worker_id,
                            'mask': mask_idx,
                            'holes': holes[:],
                            'variant': variant_name,
                            'qg_score': qg,
                            'crib_count': crib_count,
                            'pt': pt_text[:60],
                        }
                        results.append(result)
                        if qg > best_qg:
                            best_qg = qg
                        if crib_count > best_crib:
                            best_crib = crib_count

    return {
        'worker': worker_id,
        'n_masks': n_masks,
        'checked': checked,
        'best_qg': best_qg,
        'best_crib': best_crib,
        'results': results,
    }


# ── APPROACH C: Specific Fleissner masks from grille extract ─────────────

GRILLE_EXTRACT = "HJLVKDJQZKIVPCMWSAFOPCKBDLHIFXRYVFIJMXEIOMQFJNXZKILKRDIYSCLMQVZACEIMVSEFHLQKRGILVHNQXWTCDKIKJUFQRXCD"


def approach_c_grille_extract():
    """Try using the 100-char grille extract to define Fleissner masks."""
    results = []

    # Theory 1: Each char's position in KA mod 4 defines the orbit choice
    for alph_name, alph, idx_fn in [("KA", KA, KA_IDX), ("AZ", AZ, AZ_IDX)]:
        holes_mod4 = [idx_fn[GRILLE_EXTRACT[i * 4]] % 4 for i in range(25)]
        reading = fleissner_reading_order(holes_mod4)
        grid_text = list(CT) + ['X', 'X', 'X']

        # Pure transposition
        pt = ''.join(grid_text[reading[i]] for i in range(97))
        crib = count_crib_matches(pt)
        qg = qg_score_text(pt)
        results.append(f"  Mod4-{alph_name} (first of 4): pure trans → cribs={crib}/24 qg={qg:.3f} pt={pt[:50]}")

        # Also try: letter index of each group-of-4 representative
        for pick in range(4):
            holes = [idx_fn[GRILLE_EXTRACT[i * 4 + pick]] % 4 for i in range(25)]
            reading = fleissner_reading_order(holes)
            pt = ''.join(grid_text[reading[i]] for i in range(97))
            crib = count_crib_matches(pt)
            qg = qg_score_text(pt)
            results.append(f"  Mod4-{alph_name} (pick={pick}): pure trans → cribs={crib}/24 qg={qg:.3f}")

    # Theory 2: Group extract into 25 groups of 4, each group defines one orbit
    # The orbit choice is which of the 4 chars in the group matches some criterion
    for criterion_name, criterion_fn in [
        ("max_val", lambda g: g.index(max(g))),
        ("min_val", lambda g: g.index(min(g))),
        ("first_vowel", lambda g: next((i for i, c in enumerate(g) if c in "AEIOU"), 0)),
    ]:
        groups = [GRILLE_EXTRACT[i*4:(i+1)*4] for i in range(25)]
        holes = [criterion_fn(list(g)) for g in groups]
        reading = fleissner_reading_order(holes)
        grid_text = list(CT) + ['X', 'X', 'X']
        pt = ''.join(grid_text[reading[i]] for i in range(97))
        crib = count_crib_matches(pt)
        qg = qg_score_text(pt)
        results.append(f"  Criterion '{criterion_name}': pure trans → cribs={crib}/24 qg={qg:.3f}")

    # Theory 3: First 25 chars = rotation 0 holes; character encodes orbit
    # Map chars to orbit indices (0-24) via their position in the extract
    for chunk_idx in range(4):
        chunk = GRILLE_EXTRACT[chunk_idx * 25:(chunk_idx + 1) * 25]
        holes = [KA_IDX[c] % 4 for c in chunk]
        reading = fleissner_reading_order(holes)
        grid_text = list(CT) + ['X', 'X', 'X']
        pt = ''.join(grid_text[reading[i]] for i in range(97))
        crib = count_crib_matches(pt)
        qg = qg_score_text(pt)
        results.append(f"  Rotation-chunk {chunk_idx} → cribs={crib}/24 qg={qg:.3f}")

    # Theory 4: Use grille extract directly as running key (already tested in
    # e_fleissner_exploration.py but included for completeness with all variants)
    for alph_name, ct_nums, idx_fn, alph in [
        ("AZ", CT_AZ, AZ_IDX, AZ),
        ("KA", CT_KA, KA_IDX, KA),
    ]:
        ke = [idx_fn[c] for c in GRILLE_EXTRACT[:97]]
        for var_name, fn in [("Vig", lambda c, k: (c - k) % 26),
                             ("Beau", lambda c, k: (k - c) % 26),
                             ("VarBeau", lambda c, k: (c + k) % 26)]:
            pt_nums = [fn(ct_nums[i], ke[i]) for i in range(97)]
            pt_text = ''.join(alph[n] for n in pt_nums)
            pt_az = [AZ_IDX[c] for c in pt_text]
            crib = count_crib_matches(pt_text)
            qg = qg_score_nums(pt_az)
            results.append(f"  Direct key {var_name}-{alph_name}: cribs={crib}/24 qg={qg:.3f} pt={pt_text[:50]}")

    return results


# ── Main execution ───────────────────────────────────────────────────────

def main():
    t0 = time.time()

    # Create output directory
    outdir = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'fleissner_keystream')
    os.makedirs(outdir, exist_ok=True)

    print("=" * 70)
    print("E-FLEISSNER-KEYSTREAM: Fleissner Grille → Keystream Hypothesis")
    print(f"  Grid: {GRID_SIZE}x{GRID_SIZE}, orbits: {len(ORBITS)}")
    print(f"  Workers: {N_WORKERS}")
    print(f"  CT: {CT[:30]}... (len={CT_LEN})")
    print("=" * 70)

    all_results = {
        'approach_a': [],
        'approach_b': [],
        'approach_c': [],
    }

    # ── Approach C: Grille extract analysis (quick, deterministic) ────────
    print("\n--- APPROACH C: Grille extract → Fleissner mask (deterministic) ---")
    c_results = approach_c_grille_extract()
    for line in c_results:
        print(line)
    all_results['approach_c'] = c_results

    # ── Approach A: Random Fleissner masks → keystream from tableau ────────
    print("\n--- APPROACH A: Fleissner mask → tableau keystream → decrypt CT ---")
    # Each worker gets ~360 random masks, tries 169 offsets (13x13 grid of offsets),
    # 9 cipher variants each → 360 * 169 * 9 ≈ 548K evaluations per worker.
    # 28 workers → ~15M evaluations total. Roughly equivalent to 10K random masks
    # with full offset coverage.

    N_MASKS_PER_WORKER_A = 400
    TOTAL_MASKS_A = N_MASKS_PER_WORKER_A * N_WORKERS
    print(f"  Masks per worker: {N_MASKS_PER_WORKER_A}")
    print(f"  Total masks: {TOTAL_MASKS_A}")
    print(f"  Offsets per mask: 169 (13x13 grid)")
    print(f"  Variants per offset: 9 (3 cipher × {2} tableaux + 3 extra)")
    print(f"  Estimated evaluations: ~{TOTAL_MASKS_A * 169 * 9:,}")
    print(f"  Report thresholds: qg > -5.5, crib >= 3", flush=True)

    args_a = [
        (i, N_MASKS_PER_WORKER_A, 1000 + i * 17, -5.5, 3)
        for i in range(N_WORKERS)
    ]

    t_a = time.time()
    with Pool(N_WORKERS) as pool:
        worker_results_a = pool.map(worker_approach_a, args_a)

    best_qg_a = max(r['best_qg'] for r in worker_results_a)
    best_crib_a = max(r['best_crib'] for r in worker_results_a)
    total_checked_a = sum(r['checked'] for r in worker_results_a)
    all_hits_a = []
    for r in worker_results_a:
        all_hits_a.extend(r['results'])

    # Sort by quadgram score
    all_hits_a.sort(key=lambda x: x['qg_score'], reverse=True)

    print(f"\n  Approach A complete: {time.time() - t_a:.1f}s")
    print(f"  Total evaluations: {total_checked_a:,}")
    print(f"  Best quadgram: {best_qg_a:.3f}")
    print(f"  Best crib count: {best_crib_a}/24")
    print(f"  Hits above threshold: {len(all_hits_a)}")

    if all_hits_a:
        print(f"\n  Top 20 results (Approach A):")
        for hit in all_hits_a[:20]:
            print(f"    qg={hit['qg_score']:.3f} crib={hit['crib_count']}/24 "
                  f"var={hit['variant']} off=({hit.get('row_off','?')},{hit.get('col_off','?')}) "
                  f"pt={hit['pt'][:40]}")

    all_results['approach_a'] = all_hits_a[:100]  # Save top 100

    # ── Approach B: Fleissner transposition + keyword Vig/Beaufort ────────
    print("\n--- APPROACH B: Fleissner transposition + keyword substitution ---")
    N_MASKS_PER_WORKER_B = 40000
    TOTAL_MASKS_B = N_MASKS_PER_WORKER_B * N_WORKERS
    print(f"  Masks per worker: {N_MASKS_PER_WORKER_B}")
    print(f"  Total masks: {TOTAL_MASKS_B:,}")
    print(f"  Keywords: {len(KEYWORDS)}")
    print(f"  Variants per keyword: 5 (Vig/Beau/VarBeau AZ + Vig/Beau KA)")
    print(f"  Estimated evaluations: ~{TOTAL_MASKS_B * len(KEYWORDS) * 5:,}")
    print(f"  Report thresholds: qg > -5.5, crib >= 3", flush=True)

    args_b = [
        (i, N_MASKS_PER_WORKER_B, 5000 + i * 31, -5.5, 3)
        for i in range(N_WORKERS)
    ]

    t_b = time.time()
    with Pool(N_WORKERS) as pool:
        worker_results_b = pool.map(worker_approach_b, args_b)

    best_qg_b = max(r['best_qg'] for r in worker_results_b)
    best_crib_b = max(r['best_crib'] for r in worker_results_b)
    total_checked_b = sum(r['checked'] for r in worker_results_b)
    all_hits_b = []
    for r in worker_results_b:
        all_hits_b.extend(r['results'])

    all_hits_b.sort(key=lambda x: x['qg_score'], reverse=True)

    print(f"\n  Approach B complete: {time.time() - t_b:.1f}s")
    print(f"  Total evaluations: {total_checked_b:,}")
    print(f"  Best quadgram: {best_qg_b:.3f}")
    print(f"  Best crib count: {best_crib_b}/24")
    print(f"  Hits above threshold: {len(all_hits_b)}")

    if all_hits_b:
        print(f"\n  Top 20 results (Approach B):")
        for hit in all_hits_b[:20]:
            print(f"    qg={hit['qg_score']:.3f} crib={hit['crib_count']}/24 "
                  f"var={hit['variant']} "
                  f"pt={hit['pt'][:40]}")

    all_results['approach_b'] = all_hits_b[:100]

    # ── Approach D: SA optimization for keystream mode ────────────────────
    print("\n--- APPROACH D: SA optimization for keystream approach ---")
    print("  Objective: maximize quadgram score of decrypted text")
    print("  Search: Fleissner mask + tableau offset + variant", flush=True)

    best_sa_overall = {'qg': -999.0, 'text': '', 'detail': ''}
    sa_results = []

    # Run SA across all variants/tableaux
    for tab_name, tableau, ct_for_decrypt in [
        ("KA-tab", TABLEAU_KA_NUM, CT_AZ),
        ("AZ-tab", TABLEAU_AZ_NUM, CT_AZ),
    ]:
        for var_name, decrypt_fn in [
            ("Vig", decrypt_vig_az),
            ("Beau", decrypt_beau_az),
            ("VarBeau", decrypt_varbeau_az),
        ]:
            for restart in range(3):
                rng = random.Random(42 + restart * 1000 + hash(tab_name + var_name))
                holes = [rng.randint(0, 3) for _ in range(25)]
                row_off = rng.randint(0, 25)
                col_off = rng.randint(0, 25)

                # Evaluate current
                ks = extract_keystream_from_tableau(holes, row_off, col_off, tableau)[:97]
                pt_nums = decrypt_fn(ct_for_decrypt, ks)
                current_qg = qg_score_nums(pt_nums)
                best_qg_this = current_qg

                T = 2.0
                for step in range(200_000):
                    # Mutate: either change a hole orientation or shift offset
                    r = rng.random()
                    old_holes = holes[:]
                    old_ro, old_co = row_off, col_off

                    if r < 0.8:
                        # Change one hole
                        idx = rng.randint(0, 24)
                        holes[idx] = (holes[idx] + rng.randint(1, 3)) % 4
                    elif r < 0.9:
                        row_off = (row_off + rng.choice([-1, 1])) % 26
                    else:
                        col_off = (col_off + rng.choice([-1, 1])) % 26

                    ks = extract_keystream_from_tableau(holes, row_off, col_off, tableau)[:97]
                    pt_nums = decrypt_fn(ct_for_decrypt, ks)
                    new_qg = qg_score_nums(pt_nums)

                    delta = new_qg - current_qg
                    if delta > 0 or rng.random() < math.exp(delta / max(T, 0.001)):
                        current_qg = new_qg
                        if current_qg > best_qg_this:
                            best_qg_this = current_qg
                            best_holes = holes[:]
                            best_ro = row_off
                            best_co = col_off
                    else:
                        holes = old_holes
                        row_off = old_ro
                        col_off = old_co

                    T *= 0.99997

                # Final evaluation of best
                ks = extract_keystream_from_tableau(best_holes if best_qg_this > -999 else holes,
                                                    best_ro if best_qg_this > -999 else row_off,
                                                    best_co if best_qg_this > -999 else col_off,
                                                    tableau)[:97]
                pt_nums = decrypt_fn(ct_for_decrypt, ks)
                pt_text = az_nums_to_text(pt_nums)
                crib = count_crib_matches(pt_text)
                free = free_crib_search(pt_text)

                detail = f"{tab_name} {var_name} restart={restart}"
                print(f"  SA {detail}: qg={best_qg_this:.3f} crib={crib}/24 free_crib={free} "
                      f"off=({best_ro if best_qg_this > -999 else row_off},"
                      f"{best_co if best_qg_this > -999 else col_off}) "
                      f"pt={pt_text[:40]}")

                sa_results.append({
                    'detail': detail,
                    'qg_score': best_qg_this,
                    'crib_count': crib,
                    'free_crib': free,
                    'pt': pt_text[:60],
                })

                if best_qg_this > best_sa_overall['qg']:
                    best_sa_overall = {
                        'qg': best_qg_this,
                        'text': pt_text,
                        'detail': detail,
                        'crib': crib,
                    }

    # Also SA for Approach B (transposition + keyword)
    print("\n  SA for transposition + keyword mode:")
    for keyword in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "VERDIGRIS"]:
        kw_az = [AZ_IDX[c] for c in keyword]
        kw_len = len(keyword)
        key_stream = [kw_az[i % kw_len] for i in range(97)]

        grid_text_list = list(CT) + ['X', 'X', 'X']
        grid_az = [AZ_IDX[c] for c in grid_text_list]

        for var_name, decrypt_fn in [
            ("Vig", decrypt_vig_az),
            ("Beau", decrypt_beau_az),
        ]:
            for restart in range(5):
                rng = random.Random(77 + restart + hash(keyword + var_name))
                holes = [rng.randint(0, 3) for _ in range(25)]
                reading = fleissner_reading_order(holes)
                reordered = [grid_az[reading[i]] for i in range(97)]
                pt_nums = decrypt_fn(reordered, key_stream)
                current_qg = qg_score_nums(pt_nums)
                best_qg_this = current_qg

                T = 2.0
                for step in range(300_000):
                    idx = rng.randint(0, 24)
                    old = holes[idx]
                    holes[idx] = (old + rng.randint(1, 3)) % 4

                    reading = fleissner_reading_order(holes)
                    reordered = [grid_az[reading[i]] for i in range(97)]
                    pt_nums = decrypt_fn(reordered, key_stream)
                    new_qg = qg_score_nums(pt_nums)

                    delta = new_qg - current_qg
                    if delta > 0 or rng.random() < math.exp(delta / max(T, 0.001)):
                        current_qg = new_qg
                        if current_qg > best_qg_this:
                            best_qg_this = current_qg
                    else:
                        holes[idx] = old

                    T *= 0.99997

                reading = fleissner_reading_order(holes)
                reordered = [grid_az[reading[i]] for i in range(97)]
                pt_nums = decrypt_fn(reordered, key_stream)
                pt_text = az_nums_to_text(pt_nums)
                crib = count_crib_matches(pt_text)

                print(f"    {var_name}-{keyword} r={restart}: qg={best_qg_this:.3f} "
                      f"crib={crib}/24 pt={pt_text[:40]}")

                sa_results.append({
                    'detail': f"Trans+{var_name}-{keyword} r={restart}",
                    'qg_score': best_qg_this,
                    'crib_count': crib,
                    'pt': pt_text[:60],
                })

    all_results['approach_d_sa'] = sa_results

    # ── Summary ──────────────────────────────────────────────────────────
    total_time = time.time() - t0

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Approach A (keystream from tableau): {total_checked_a:,} evals, "
          f"best_qg={best_qg_a:.3f}, best_crib={best_crib_a}/24")
    print(f"  Approach B (transposition + keyword): {total_checked_b:,} evals, "
          f"best_qg={best_qg_b:.3f}, best_crib={best_crib_b}/24")
    print(f"  Approach C (grille extract masks): see above")
    print(f"  Approach D (SA optimization): best_qg={best_sa_overall['qg']:.3f}, "
          f"crib={best_sa_overall.get('crib', 0)}/24")
    if best_sa_overall['text']:
        print(f"    Best SA text: {best_sa_overall['text'][:60]}")
        print(f"    Detail: {best_sa_overall['detail']}")
    print(f"  Total time: {total_time:.1f}s")

    # Save full results
    output_file = os.path.join(outdir, "results.json")
    # Convert results for JSON serialization
    json_safe = {
        'experiment': 'E-FLEISSNER-KEYSTREAM',
        'description': 'Fleissner grille on Vigenère tableau as keystream source',
        'total_time': total_time,
        'approach_a': {
            'total_evals': total_checked_a,
            'best_qg': best_qg_a,
            'best_crib': best_crib_a,
            'top_hits': [{k: (v if not isinstance(v, float) or not math.isinf(v) else str(v))
                          for k, v in h.items()} for h in all_hits_a[:50]],
        },
        'approach_b': {
            'total_evals': total_checked_b,
            'best_qg': best_qg_b,
            'best_crib': best_crib_b,
            'top_hits': [{k: (v if not isinstance(v, float) or not math.isinf(v) else str(v))
                          for k, v in h.items()} for h in all_hits_b[:50]],
        },
        'approach_c': c_results,
        'approach_d_sa': [{k: (v if not isinstance(v, float) or not math.isinf(v) else str(v))
                           for k, v in h.items()} for h in sa_results],
        'best_overall': {
            'qg': best_sa_overall['qg'] if not math.isinf(best_sa_overall['qg']) else str(best_sa_overall['qg']),
            'text': best_sa_overall.get('text', '')[:80],
            'detail': best_sa_overall.get('detail', ''),
        },
    }

    with open(output_file, 'w') as f:
        json.dump(json_safe, f, indent=2, default=str)

    print(f"\n  Artifact: {output_file}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/grille/e_fleissner_keystream.py")


if __name__ == '__main__':
    main()
