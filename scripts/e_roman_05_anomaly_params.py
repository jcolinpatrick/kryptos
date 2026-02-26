#!/usr/bin/env python3
"""E-ROMAN-05: Anomaly-Derived Cipher Parameters.

Hypothesis: Physical anomalies on the Kryptos sculpture (misspellings, YAR,
extra L, "T IS YOUR POSITION", 26 extra E's, DESPARATLY) are "component parts
of a single object" — like artifacts in Howard Carter's Chapter X — that encode
cipher parameters when cross-referenced.

Tests seven phases of increasingly combined models:
  Phase 1: Shift-4 cipher models (from misspelling "foundation deposit")
  Phase 2: T=19 start position + grid models
  Phase 3: YAR as key primer (autokey models)
  Phase 4: DESPARATLY position parameters (width-5, width-8)
  Phase 5: Combined anomaly model (rotation + transposition + substitution)
  Phase 6: EQUAL as instruction (replacement letters C,Q,U,A,E anagram)
  Phase 7: Comprehensive cross-product of strongest parameters
"""
import itertools
import json
import math
import os
import sys
import time

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, CRIB_DICT, N_CRIBS
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.scoring.aggregate import score_candidate

# ── Global tracking ──
best_score = 0
best_config = {}
best_pt = ""
total_configs = 0
phase_results = {}
start_time = time.time()

RESULTS_DIR = "results"
os.makedirs(RESULTS_DIR, exist_ok=True)


# ── Cipher helpers ──

def vig_decrypt(ct, key_vals):
    """Vigenere: PT = (CT - KEY) mod 26."""
    pt = []
    klen = len(key_vals)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = key_vals[i % klen]
        pt.append(ALPH[(ci - ki) % 26])
    return ''.join(pt)


def beau_decrypt(ct, key_vals):
    """Beaufort: PT = (KEY - CT) mod 26."""
    pt = []
    klen = len(key_vals)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = key_vals[i % klen]
        pt.append(ALPH[(ki - ci) % 26])
    return ''.join(pt)


def vb_decrypt(ct, key_vals):
    """Variant Beaufort: PT = (CT + KEY) mod 26."""
    pt = []
    klen = len(key_vals)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = key_vals[i % klen]
        pt.append(ALPH[(ci + ki) % 26])
    return ''.join(pt)


def autokey_pt_decrypt(ct, primer, variant='vig'):
    """Autokey (plaintext feedback) decryption.
    Vig: PT[i] = (CT[i] - KEY[i]) mod 26; KEY[i] = primer[i] if i < len(primer), else PT[i-len(primer)]
    Beau: PT[i] = (KEY[i] - CT[i]) mod 26
    VB: PT[i] = (CT[i] + KEY[i]) mod 26
    """
    pt = []
    key = list(primer)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = key[i] if i < len(key) else ALPH_IDX[pt[i - len(primer)]]
        if i >= len(key):
            key.append(ALPH_IDX[pt[i - len(primer)]])
        if variant == 'vig':
            pi = (ci - ki) % 26
        elif variant == 'beau':
            pi = (ki - ci) % 26
        else:  # vb
            pi = (ci + ki) % 26
        pt.append(ALPH[pi])
    return ''.join(pt)


def autokey_ct_decrypt(ct, primer, variant='vig'):
    """Autokey (ciphertext feedback) decryption.
    KEY[i] = primer[i] if i < len(primer), else CT_IDX[i-len(primer)]
    """
    pt = []
    ct_idx = [ALPH_IDX[c] for c in ct]
    for i in range(len(ct)):
        if i < len(primer):
            ki = primer[i]
        else:
            ki = ct_idx[i - len(primer)]
        ci = ct_idx[i]
        if variant == 'vig':
            pi = (ci - ki) % 26
        elif variant == 'beau':
            pi = (ki - ci) % 26
        else:  # vb
            pi = (ci + ki) % 26
        pt.append(ALPH[pi])
    return ''.join(pt)


def rotate_text(text, n):
    """Rotate text by n positions: text[n:] + text[:n]."""
    n = n % len(text)
    return text[n:] + text[:n]


def keyword_to_col_order(keyword, width):
    """Convert keyword to column ordering for columnar transposition."""
    kw = keyword[:width].upper()
    if len(kw) < width:
        # Pad with subsequent alphabet letters
        used = set(kw)
        for c in ALPH:
            if c not in used:
                kw += c
                if len(kw) >= width:
                    break
    indexed = [(ch, i) for i, ch in enumerate(kw)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * width
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return tuple(order)


def columnar_decrypt(ct_text, width, col_order):
    """Decrypt columnar transposition: given CT read off by columns in col_order,
    recover original row-by-row text.

    This reverses: write plaintext in rows of width, read columns in col_order.
    To decrypt: figure out which columns have extra chars (for incomplete last row),
    then reassemble rows.
    """
    n = len(ct_text)
    nrows = math.ceil(n / width)
    # Number of full columns (ones that have nrows chars)
    full_cols = n - (nrows - 1) * width  # cols with nrows entries
    # Columns ranked 0..full_cols-1 (in col_order) have nrows chars; rest have nrows-1

    # Build column contents from CT
    columns = [[] for _ in range(width)]
    pos = 0
    for rank in range(width):
        # Find which column index has this rank
        col_idx = col_order.index(rank)
        col_len = nrows if col_idx < full_cols else nrows - 1
        columns[col_idx] = list(ct_text[pos:pos + col_len])
        pos += col_len

    # Read off row by row
    result = []
    for r in range(nrows):
        for c in range(width):
            if r < len(columns[c]):
                result.append(columns[c][r])
    return ''.join(result[:n])


def columnar_encrypt(text, width, col_order):
    """Encrypt with columnar transposition: write in rows, read by col_order."""
    n = len(text)
    nrows = math.ceil(n / width)
    full_cols = n - (nrows - 1) * width

    result = []
    for rank in range(width):
        col_idx = col_order.index(rank)
        for r in range(nrows):
            pos = r * width + col_idx
            if pos < n:
                result.append(text[pos])
    return ''.join(result)


def all_orderings(width):
    """Generate all permutations of range(width). Only feasible for width <= 8."""
    if width > 8:
        return []  # Too many
    return list(itertools.permutations(range(width)))


def check_and_update(pt, config_desc, phase):
    """Score a plaintext and update global best."""
    global best_score, best_config, best_pt, total_configs
    total_configs += 1

    sc = score_cribs(pt)
    if sc > best_score:
        best_score = sc
        best_config = config_desc.copy()
        best_pt = pt
        if sc > 6:
            print(f"  ** NEW BEST: {sc}/24 — {config_desc}")
            print(f"     PT: {pt[:50]}...")
    return sc


def phase_summary(phase_name, phase_count, phase_best, phase_start):
    """Print and record phase summary."""
    elapsed = time.time() - phase_start
    result = {
        "configs_tested": phase_count,
        "best_score": phase_best,
        "elapsed_seconds": round(elapsed, 2),
    }
    phase_results[phase_name] = result
    print(f"  Phase complete: {phase_count} configs, best={phase_best}/24, {elapsed:.1f}s")
    return result


# ══════════════════════════════════════════════════════════════════════════
# Phase 1: Shift-4 cipher models
# ══════════════════════════════════════════════════════════════════════════
def phase1():
    print("\n" + "="*70)
    print("PHASE 1: Shift-4 Cipher Models (misspelling 'foundation deposit')")
    print("="*70)
    ps = time.time()
    pc = 0
    pb = 0

    # Misspelling shift sequences
    SHIFT_KEYS = {
        "misspell_fwd": [10, 5, 6, 22, 22],
        "misspell_rev": [22, 22, 6, 5, 10],
        "const_shift4": [22],  # constant -4 = 22 mod 26
        "const_shift4_p5": [22, 22, 22, 22, 22],
        "shift4_at_5_8": [0, 0, 0, 0, 0, 22, 0, 0, 22],  # -4 at positions 5 and 8
    }

    # Also test all permutations of [10, 5, 6, 22, 22]
    base_shifts = [10, 5, 6, 22, 22]
    perms_of_shifts = set(itertools.permutations(base_shifts))

    variants = [('vig', vig_decrypt), ('beau', beau_decrypt), ('vb', vb_decrypt)]

    # Test each key with each variant
    print("  Testing fixed shift keys...")
    for key_name, key_vals in SHIFT_KEYS.items():
        for var_name, var_fn in variants:
            pt = var_fn(CT, key_vals)
            sc = check_and_update(pt, {"phase": 1, "key": key_name, "variant": var_name,
                                       "key_vals": key_vals}, "P1")
            pb = max(pb, sc)
            pc += 1

    # Test all permutations of misspelling shifts
    print(f"  Testing {len(perms_of_shifts)} permutations of misspelling shifts...")
    for perm in perms_of_shifts:
        key_vals = list(perm)
        for var_name, var_fn in variants:
            pt = var_fn(CT, key_vals)
            sc = check_and_update(pt, {"phase": 1, "key": "misspell_perm",
                                       "variant": var_name, "key_vals": key_vals}, "P1")
            pb = max(pb, sc)
            pc += 1

    # Extended: repeat shift sequence to length 97 (position-dependent key)
    print("  Testing extended (position-dependent) shift keys...")
    for key_name, key_vals in SHIFT_KEYS.items():
        extended = (key_vals * ((CT_LEN // len(key_vals)) + 1))[:CT_LEN]
        for var_name, var_fn in variants:
            pt = var_fn(CT, extended)
            sc = check_and_update(pt, {"phase": 1, "key": f"{key_name}_ext97",
                                       "variant": var_name}, "P1")
            pb = max(pb, sc)
            pc += 1

    # Constant shift -4 with columnar transpositions at various widths
    print("  Testing constant shift-4 with columnar transpositions...")
    const_key = [22]
    for width in range(5, 14):
        nperms = math.factorial(width)
        if nperms > 5040:  # Skip width > 7 full enumeration
            # Just test identity and reverse
            for order in [tuple(range(width)), tuple(range(width-1, -1, -1))]:
                ct_dec = columnar_decrypt(CT, width, list(order))
                for var_name, var_fn in variants:
                    pt = var_fn(ct_dec, const_key)
                    sc = check_and_update(pt, {"phase": 1, "key": "const_shift4",
                                               "variant": var_name, "width": width,
                                               "col_order": list(order)}, "P1")
                    pb = max(pb, sc)
                    pc += 1
        else:
            for order in itertools.permutations(range(width)):
                ct_dec = columnar_decrypt(CT, width, list(order))
                for var_name, var_fn in variants:
                    pt = var_fn(ct_dec, const_key)
                    sc = check_and_update(pt, {"phase": 1, "key": "const_shift4",
                                               "variant": var_name, "width": width,
                                               "col_order": list(order)}, "P1")
                    pb = max(pb, sc)
                    pc += 1

    phase_summary("Phase 1: Shift-4 Models", pc, pb, ps)
    return pb


# ══════════════════════════════════════════════════════════════════════════
# Phase 2: T=19 start position + grid
# ══════════════════════════════════════════════════════════════════════════
def phase2():
    print("\n" + "="*70)
    print("PHASE 2: T=19 Start Position + Grid Models")
    print("="*70)
    ps = time.time()
    pc = 0
    pb = 0

    variants = [('vig', vig_decrypt), ('beau', beau_decrypt), ('vb', vb_decrypt)]

    # CT rotated by T=19
    ct_rot19 = rotate_text(CT, 19)

    # Test rotated CT with various grid reading orders
    print("  Testing T=19 rotation with grid reads...")
    for width in range(5, 14):
        nrows = math.ceil(CT_LEN / width)

        # Snake/serpentine read
        from kryptos.kernel.transforms.transposition import (
            serpentine_perm, spiral_perm, invert_perm, apply_perm
        )

        for vertical in [False, True]:
            perm = serpentine_perm(nrows, width, CT_LEN, vertical=vertical)
            if len(perm) == CT_LEN:
                inv = invert_perm(perm)
                transposed = apply_perm(ct_rot19, inv)
                sc = check_and_update(transposed, {"phase": 2, "model": "rot19_serpentine",
                                                    "width": width, "vertical": vertical}, "P2")
                pb = max(pb, sc)
                pc += 1

                # Also with substitution keys
                for var_name, var_fn in variants:
                    for key_name, key_vals in [("misspell", [10,5,6,22,22]),
                                                ("const4", [22])]:
                        pt = var_fn(transposed, key_vals)
                        sc = check_and_update(pt, {"phase": 2, "model": "rot19_serp_sub",
                                                    "width": width, "vertical": vertical,
                                                    "variant": var_name, "key": key_name}, "P2")
                        pb = max(pb, sc)
                        pc += 1

        # Spiral read
        for clockwise in [True, False]:
            perm = spiral_perm(nrows, width, CT_LEN, clockwise=clockwise)
            if len(perm) == CT_LEN:
                inv = invert_perm(perm)
                transposed = apply_perm(ct_rot19, inv)
                sc = check_and_update(transposed, {"phase": 2, "model": "rot19_spiral",
                                                    "width": width, "clockwise": clockwise}, "P2")
                pb = max(pb, sc)
                pc += 1

                for var_name, var_fn in variants:
                    for key_name, key_vals in [("misspell", [10,5,6,22,22]),
                                                ("const4", [22])]:
                        pt = var_fn(transposed, key_vals)
                        sc = check_and_update(pt, {"phase": 2, "model": "rot19_spiral_sub",
                                                    "width": width, "clockwise": clockwise,
                                                    "variant": var_name, "key": key_name}, "P2")
                        pb = max(pb, sc)
                        pc += 1

    # Columnar decrypt after rotation by 19
    print("  Testing T=19 rotation + columnar transposition...")
    for width in range(5, 9):  # Exhaustive only up to width 8
        for order in itertools.permutations(range(width)):
            ct_dec = columnar_decrypt(ct_rot19, width, list(order))
            sc = check_and_update(ct_dec, {"phase": 2, "model": "rot19_columnar",
                                           "width": width, "col_order": list(order)}, "P2")
            pb = max(pb, sc)
            pc += 1

    # Offset-19: rotated CT with thematic keyword Vig/Beau
    print("  Testing offset-19 + thematic keyword substitution...")
    THEMATIC_KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "CARTER", "EQUAL",
                          "BERLIN", "CLOCK", "NORTHEAST", "EASTNORTHEAST"]
    for kw in THEMATIC_KEYWORDS:
        kv = [ALPH_IDX[c] for c in kw]
        for var_name, var_fn in variants:
            # On rotated CT
            pt = var_fn(ct_rot19, kv)
            sc = check_and_update(pt, {"phase": 2, "model": "rot19_kw_sub",
                                       "keyword": kw, "variant": var_name}, "P2")
            pb = max(pb, sc)
            pc += 1
            # On original CT
            pt = var_fn(CT, kv)
            sc = check_and_update(pt, {"phase": 2, "model": "kw_sub_norot",
                                       "keyword": kw, "variant": var_name}, "P2")
            pb = max(pb, sc)
            pc += 1

    phase_summary("Phase 2: T=19 Models", pc, pb, ps)
    return pb


# ══════════════════════════════════════════════════════════════════════════
# Phase 3: YAR as key primer
# ══════════════════════════════════════════════════════════════════════════
def phase3():
    print("\n" + "="*70)
    print("PHASE 3: YAR as Key Primer (Autokey Models)")
    print("="*70)
    ps = time.time()
    pc = 0
    pb = 0

    variants = ['vig', 'beau', 'vb']

    # YAR primers
    PRIMERS = {
        "YAR": [24, 0, 17],
        "RAY": [17, 0, 24],
        "YAR_DESP_58": [24, 0, 17, 5, 8],
        "YAR_DESP_85": [24, 0, 17, 8, 5],
        "RAY_DESP_58": [17, 0, 24, 5, 8],
        "RAY_DESP_85": [17, 0, 24, 8, 5],
        "YART": [24, 0, 17, 19],  # YAR + T
        "TRAY": [19, 17, 0, 24],
        "YARL": [24, 0, 17, 11],  # YAR + L
        "LRAY": [11, 17, 0, 24],
        "YEAR": [24, 4, 0, 17],  # Y-E-A-R (anagram)
    }

    print("  Testing autokey with YAR-derived primers...")
    for primer_name, primer in PRIMERS.items():
        for variant in variants:
            # PT feedback autokey
            pt = autokey_pt_decrypt(CT, primer, variant)
            sc = check_and_update(pt, {"phase": 3, "model": "autokey_pt",
                                       "primer": primer_name, "variant": variant,
                                       "primer_vals": primer}, "P3")
            pb = max(pb, sc)
            pc += 1

            # CT feedback autokey
            pt = autokey_ct_decrypt(CT, primer, variant)
            sc = check_and_update(pt, {"phase": 3, "model": "autokey_ct",
                                       "primer": primer_name, "variant": variant,
                                       "primer_vals": primer}, "P3")
            pb = max(pb, sc)
            pc += 1

    # YAR values as rotation + autokey
    print("  Testing YAR rotation values + autokey...")
    for rot in [17, 24, 0]:
        ct_rot = rotate_text(CT, rot)
        for primer_name, primer in PRIMERS.items():
            for variant in variants:
                pt = autokey_pt_decrypt(ct_rot, primer, variant)
                sc = check_and_update(pt, {"phase": 3, "model": f"rot{rot}_autokey_pt",
                                           "primer": primer_name, "variant": variant}, "P3")
                pb = max(pb, sc)
                pc += 1

                pt = autokey_ct_decrypt(ct_rot, primer, variant)
                sc = check_and_update(pt, {"phase": 3, "model": f"rot{rot}_autokey_ct",
                                           "primer": primer_name, "variant": variant}, "P3")
                pb = max(pb, sc)
                pc += 1

    # Periodic key from YAR values
    print("  Testing YAR as periodic key...")
    for primer_name, primer in PRIMERS.items():
        for var_name, var_fn in [('vig', vig_decrypt), ('beau', beau_decrypt), ('vb', vb_decrypt)]:
            pt = var_fn(CT, primer)
            sc = check_and_update(pt, {"phase": 3, "model": "periodic_yar",
                                       "key": primer_name, "variant": var_name}, "P3")
            pb = max(pb, sc)
            pc += 1

    phase_summary("Phase 3: YAR Primer Models", pc, pb, ps)
    return pb


# ══════════════════════════════════════════════════════════════════════════
# Phase 4: DESPARATLY position parameters
# ══════════════════════════════════════════════════════════════════════════
def phase4():
    print("\n" + "="*70)
    print("PHASE 4: DESPARATLY Position Parameters (width-5, width-8)")
    print("="*70)
    ps = time.time()
    pc = 0
    pb = 0

    variants = [('vig', vig_decrypt), ('beau', beau_decrypt), ('vb', vb_decrypt)]

    # Width-5 columnar with all 120 orderings
    print("  Testing width-5 columnar (120 orderings)...")
    for order in itertools.permutations(range(5)):
        ct_dec = columnar_decrypt(CT, 5, list(order))
        sc = check_and_update(ct_dec, {"phase": 4, "model": "w5_columnar",
                                       "col_order": list(order)}, "P4")
        pb = max(pb, sc)
        pc += 1

        # With substitution
        for var_name, var_fn in variants:
            for key_name, key_vals in [("misspell", [10,5,6,22,22]),
                                        ("const4", [22]),
                                        ("equal", [4,16,20,0,11])]:
                pt = var_fn(ct_dec, key_vals)
                sc = check_and_update(pt, {"phase": 4, "model": "w5_col_sub",
                                           "col_order": list(order), "variant": var_name,
                                           "key": key_name}, "P4")
                pb = max(pb, sc)
                pc += 1

    # Width-8 columnar with all 40320 orderings (identity sub only for full enum)
    print("  Testing width-8 columnar (40320 orderings)...")
    w8_count = 0
    for order in itertools.permutations(range(8)):
        ct_dec = columnar_decrypt(CT, 8, list(order))
        sc = check_and_update(ct_dec, {"phase": 4, "model": "w8_columnar",
                                       "col_order": list(order)}, "P4")
        pb = max(pb, sc)
        pc += 1
        w8_count += 1

        # Only test substitution for promising ones (score >= 3)
        if sc >= 3:
            for var_name, var_fn in variants:
                for key_name, key_vals in [("misspell", [10,5,6,22,22]),
                                            ("const4", [22])]:
                    pt = var_fn(ct_dec, key_vals)
                    sc2 = check_and_update(pt, {"phase": 4, "model": "w8_col_sub",
                                                "col_order": list(order), "variant": var_name,
                                                "key": key_name}, "P4")
                    pb = max(pb, sc2)
                    pc += 1

    # Period-5 and period-8 substitution with all key offsets
    print("  Testing period-5 and period-8 substitution...")
    for period in [5, 8]:
        for offset in range(26):
            key_vals = [(offset + i) % 26 for i in range(period)]
            for var_name, var_fn in variants:
                pt = var_fn(CT, key_vals)
                sc = check_and_update(pt, {"phase": 4, "model": f"p{period}_sub",
                                           "offset": offset, "variant": var_name}, "P4")
                pb = max(pb, sc)
                pc += 1

    # Width-5 × period-8 and width-8 × period-5 combined
    print("  Testing width-5 × period-8 and width-8 × period-5 combined...")

    # Width-5 transposition then period-8 substitution (and vice versa)
    for w, p in [(5, 8), (8, 5)]:
        if w == 5:
            orderings = list(itertools.permutations(range(5)))
        else:
            # For width-8, use keyword-derived orderings only
            kw_list = ["KRYPTOS!", "ABSCISSA", "BERLINCL"]  # 8-letter
            orderings = []
            for kw in kw_list:
                kw = kw[:w]
                if len(kw) >= w:
                    order = keyword_to_col_order(kw, w)
                    orderings.append(order)
            # Also add identity and reverse
            orderings.append(tuple(range(w)))
            orderings.append(tuple(range(w-1, -1, -1)))

        for order in orderings:
            ct_dec = columnar_decrypt(CT, w, list(order))
            for offset in range(26):
                key_vals = [offset] * p  # simple periodic
                for var_name, var_fn in variants:
                    pt = var_fn(ct_dec, key_vals)
                    sc = check_and_update(pt, {"phase": 4, "model": f"w{w}_p{p}_combined",
                                               "col_order": list(order), "offset": offset,
                                               "variant": var_name}, "P4")
                    pb = max(pb, sc)
                    pc += 1

    # Double columnar: width-5 then width-8
    print("  Testing double columnar w5 then w8...")
    # Use keyword orderings for w8 to keep count manageable
    w8_orderings = [
        keyword_to_col_order("KRYPTOS!", 8) or tuple(range(8)),
        keyword_to_col_order("ABSCISSA", 8) or tuple(range(8)),
        keyword_to_col_order("BERLINCL", 8) or tuple(range(8)),
        tuple(range(8)),
        tuple(range(7, -1, -1)),
    ]
    # Deduplicate
    w8_orderings = list(set(w8_orderings))

    for o5 in itertools.permutations(range(5)):
        for o8 in w8_orderings:
            # Apply w8 columnar first, then w5
            ct_step1 = columnar_decrypt(CT, 8, list(o8))
            ct_step2 = columnar_decrypt(ct_step1, 5, list(o5))
            sc = check_and_update(ct_step2, {"phase": 4, "model": "double_col_w8w5",
                                              "w8_order": list(o8), "w5_order": list(o5)}, "P4")
            pb = max(pb, sc)
            pc += 1

            # And reversed: w5 first then w8
            ct_step1 = columnar_decrypt(CT, 5, list(o5))
            ct_step2 = columnar_decrypt(ct_step1, 8, list(o8))
            sc = check_and_update(ct_step2, {"phase": 4, "model": "double_col_w5w8",
                                              "w5_order": list(o5), "w8_order": list(o8)}, "P4")
            pb = max(pb, sc)
            pc += 1

    phase_summary("Phase 4: DESPARATLY Parameters", pc, pb, ps)
    return pb


# ══════════════════════════════════════════════════════════════════════════
# Phase 5: Combined anomaly model
# ══════════════════════════════════════════════════════════════════════════
def phase5():
    print("\n" + "="*70)
    print("PHASE 5: Combined Anomaly Model (rotation + transposition + substitution)")
    print("="*70)
    ps = time.time()
    pc = 0
    pb = 0

    variants = [('vig', vig_decrypt), ('beau', beau_decrypt), ('vb', vb_decrypt)]
    rotations = [0, 17, 19, 24]
    sub_keys = {
        "misspell": [10, 5, 6, 22, 22],
        "misspell_rev": [22, 22, 6, 5, 10],
        "const4": [22],
        "equal": [4, 16, 20, 0, 11],
    }

    # For width-5: all 120 orderings × 4 rotations × 4 keys × 3 variants = 5760
    print("  Testing rotation + width-5 columnar + substitution...")
    for rot in rotations:
        ct_rot = rotate_text(CT, rot)
        for order in itertools.permutations(range(5)):
            ct_dec = columnar_decrypt(ct_rot, 5, list(order))
            for key_name, key_vals in sub_keys.items():
                for var_name, var_fn in variants:
                    pt = var_fn(ct_dec, key_vals)
                    sc = check_and_update(pt, {"phase": 5, "model": "rot_w5_sub",
                                               "rotation": rot, "col_order": list(order),
                                               "key": key_name, "variant": var_name}, "P5")
                    pb = max(pb, sc)
                    pc += 1

    # For width-8: use keyword orderings only (too many permutations)
    print("  Testing rotation + width-8 keyword columnar + substitution...")
    w8_kws = ["KRYPTOSA", "ABSCISSA", "BERLINCL", "CARTERHX", "EQUALXYZ"]
    w8_orders = []
    for kw in w8_kws:
        o = keyword_to_col_order(kw, 8)
        if o:
            w8_orders.append(o)
    w8_orders.append(tuple(range(8)))
    w8_orders.append(tuple(range(7, -1, -1)))
    w8_orders = list(set(w8_orders))

    for rot in rotations:
        ct_rot = rotate_text(CT, rot)
        for order in w8_orders:
            ct_dec = columnar_decrypt(ct_rot, 8, list(order))
            for key_name, key_vals in sub_keys.items():
                for var_name, var_fn in variants:
                    pt = var_fn(ct_dec, key_vals)
                    sc = check_and_update(pt, {"phase": 5, "model": "rot_w8_sub",
                                               "rotation": rot, "col_order": list(order),
                                               "key": key_name, "variant": var_name}, "P5")
                    pb = max(pb, sc)
                    pc += 1

    # YAR primer autokey after rotation + transposition
    print("  Testing rotation + transposition + YAR autokey...")
    yar_primers = {
        "YAR": [24, 0, 17],
        "RAY": [17, 0, 24],
        "YART": [24, 0, 17, 19],
    }

    for rot in rotations:
        ct_rot = rotate_text(CT, rot)
        # Width-5
        for order in itertools.permutations(range(5)):
            ct_dec = columnar_decrypt(ct_rot, 5, list(order))
            for primer_name, primer in yar_primers.items():
                for variant in ['vig', 'beau', 'vb']:
                    pt = autokey_pt_decrypt(ct_dec, primer, variant)
                    sc = check_and_update(pt, {"phase": 5, "model": "rot_w5_autokey",
                                               "rotation": rot, "col_order": list(order),
                                               "primer": primer_name, "variant": variant}, "P5")
                    pb = max(pb, sc)
                    pc += 1

    # Insert L (=11th letter) at position 19, making CT 98 chars → 7×14 grid
    print("  Testing L-insertion at position 19 → 98-char grid models...")
    ct_with_L = CT[:19] + 'L' + CT[19:]  # 98 chars
    assert len(ct_with_L) == 98

    for width in [7, 14]:
        nrows = 98 // width  # 14 or 7 — exact fit
        # Test columnar with keyword orderings
        kw_list_w = ["KRYPTOS", "KRYPTOS", "ABSCISSA", "ABSCISSA"]  # trimmed to width

        for order in itertools.permutations(range(min(width, 7))):
            if width > 7:
                break  # Only enumerate for width 7
            ct_dec = columnar_decrypt(ct_with_L, width, list(order))
            # Truncate back to 97 for scoring
            ct_dec97 = ct_dec[:97]
            sc = check_and_update(ct_dec97, {"phase": 5, "model": "L_insert_w7",
                                              "col_order": list(order)}, "P5")
            pb = max(pb, sc)
            pc += 1

            # With substitution
            for var_name, var_fn in variants:
                for key_name, key_vals in sub_keys.items():
                    pt = var_fn(ct_dec97, key_vals)
                    sc = check_and_update(pt, {"phase": 5, "model": "L_insert_w7_sub",
                                               "col_order": list(order), "variant": var_name,
                                               "key": key_name}, "P5")
                    pb = max(pb, sc)
                    pc += 1

    phase_summary("Phase 5: Combined Anomaly", pc, pb, ps)
    return pb


# ══════════════════════════════════════════════════════════════════════════
# Phase 6: EQUAL as instruction
# ══════════════════════════════════════════════════════════════════════════
def phase6():
    print("\n" + "="*70)
    print("PHASE 6: EQUAL as Instruction (replacement letters C,Q,U,A,E)")
    print("="*70)
    ps = time.time()
    pc = 0
    pb = 0

    variants = [('vig', vig_decrypt), ('beau', beau_decrypt), ('vb', vb_decrypt)]

    # EQUAL letter values as key
    EQUAL_KEY = [4, 16, 20, 0, 11]  # E=4, Q=16, U=20, A=0, L=11

    # All permutations of EQUAL
    equal_perms = set(itertools.permutations(EQUAL_KEY))

    print(f"  Testing {len(equal_perms)} permutations of EQUAL as periodic key...")
    for perm in equal_perms:
        key_vals = list(perm)
        for var_name, var_fn in variants:
            pt = var_fn(CT, key_vals)
            sc = check_and_update(pt, {"phase": 6, "model": "equal_periodic",
                                       "key_vals": key_vals, "variant": var_name}, "P6")
            pb = max(pb, sc)
            pc += 1

    # EQUAL as keyword for width-5 columnar ordering
    print("  Testing EQUAL as keyword for columnar ordering...")
    equal_order = keyword_to_col_order("EQUAL", 5)
    if equal_order:
        ct_dec = columnar_decrypt(CT, 5, list(equal_order))
        sc = check_and_update(ct_dec, {"phase": 6, "model": "equal_col_w5",
                                       "col_order": list(equal_order)}, "P6")
        pb = max(pb, sc)
        pc += 1

        # With substitution
        for var_name, var_fn in variants:
            for key_name, key_vals in [("misspell", [10,5,6,22,22]),
                                        ("const4", [22]),
                                        ("equal", EQUAL_KEY)]:
                pt = var_fn(ct_dec, key_vals)
                sc = check_and_update(pt, {"phase": 6, "model": "equal_col_w5_sub",
                                           "col_order": list(equal_order),
                                           "variant": var_name, "key": key_name}, "P6")
                pb = max(pb, sc)
                pc += 1

    # CQUAE (the replacement letters in order of misspelling occurrence)
    # S→C, L→Q, O→U, E→A, I→E  → replacement letters = C, Q, U, A, E
    cquae_key = [2, 16, 20, 0, 4]  # C=2, Q=16, U=20, A=0, E=4
    cquae_perms = set(itertools.permutations(cquae_key))

    print(f"  Testing {len(cquae_perms)} permutations of CQUAE as periodic key...")
    for perm in cquae_perms:
        key_vals = list(perm)
        for var_name, var_fn in variants:
            pt = var_fn(CT, key_vals)
            sc = check_and_update(pt, {"phase": 6, "model": "cquae_periodic",
                                       "key_vals": key_vals, "variant": var_name}, "P6")
            pb = max(pb, sc)
            pc += 1

    # Test the misspelling original letters as key: S, L, O, E, I
    sloei_key = [18, 11, 14, 4, 8]
    sloei_perms = set(itertools.permutations(sloei_key))

    print(f"  Testing {len(sloei_perms)} permutations of SLOEI as periodic key...")
    for perm in sloei_perms:
        key_vals = list(perm)
        for var_name, var_fn in variants:
            pt = var_fn(CT, key_vals)
            sc = check_and_update(pt, {"phase": 6, "model": "sloei_periodic",
                                       "key_vals": key_vals, "variant": var_name}, "P6")
            pb = max(pb, sc)
            pc += 1

    # EQUAL with rotations + columnar
    print("  Testing EQUAL key + rotation + columnar...")
    for rot in [0, 17, 19, 24]:
        ct_rot = rotate_text(CT, rot)
        for width in [5, 7, 8]:
            if width == 5:
                orderings = [equal_order] if equal_order else []
                orderings += list(itertools.permutations(range(5)))[:20]  # Sample
            else:
                orderings = [tuple(range(width)), tuple(range(width-1, -1, -1))]
                kw_o = keyword_to_col_order("EQUAL" + "XYZ", width)
                if kw_o:
                    orderings.append(kw_o)

            for order in orderings:
                ct_dec = columnar_decrypt(ct_rot, width, list(order))
                for var_name, var_fn in variants:
                    pt = var_fn(ct_dec, EQUAL_KEY)
                    sc = check_and_update(pt, {"phase": 6, "model": "equal_rot_col_sub",
                                               "rotation": rot, "width": width,
                                               "col_order": list(order),
                                               "variant": var_name}, "P6")
                    pb = max(pb, sc)
                    pc += 1

    phase_summary("Phase 6: EQUAL Models", pc, pb, ps)
    return pb


# ══════════════════════════════════════════════════════════════════════════
# Phase 7: Comprehensive cross-product
# ══════════════════════════════════════════════════════════════════════════
def phase7():
    print("\n" + "="*70)
    print("PHASE 7: Comprehensive Cross-Product")
    print("="*70)
    ps = time.time()
    pc = 0
    pb = 0

    variants = [('vig', vig_decrypt), ('beau', beau_decrypt), ('vb', vb_decrypt)]

    rotations = [0, 17, 19, 24]
    widths = [5, 7, 8, 9, 10, 11, 13]

    sub_keys = {
        "misspell_fwd": [10, 5, 6, 22, 22],
        "misspell_rev": [22, 22, 6, 5, 10],
        "equal": [4, 16, 20, 0, 11],
        "yar": [24, 0, 17],
        "ray": [17, 0, 24],
        "const22": [22],
    }

    thematic_kws = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "CARTER", "EQUAL"]

    print(f"  Testing {len(rotations)} rotations × {len(widths)} widths × "
          f"{len(thematic_kws)} keywords × {len(sub_keys)} keys × 3 variants...")

    for rot in rotations:
        ct_rot = rotate_text(CT, rot)

        for width in widths:
            # Generate keyword-derived column orderings
            col_orderings = set()
            for kw in thematic_kws:
                # Pad keyword to width if needed
                kw_padded = kw
                while len(kw_padded) < width:
                    kw_padded += ALPH[len(kw_padded) % 26]
                o = keyword_to_col_order(kw_padded, width)
                if o:
                    col_orderings.add(o)
            # Also identity and reverse
            col_orderings.add(tuple(range(width)))
            col_orderings.add(tuple(range(width-1, -1, -1)))

            for order in col_orderings:
                ct_dec = columnar_decrypt(ct_rot, width, list(order))

                for key_name, key_vals in sub_keys.items():
                    for var_name, var_fn in variants:
                        pt = var_fn(ct_dec, key_vals)
                        sc = check_and_update(pt, {
                            "phase": 7, "model": "crossproduct",
                            "rotation": rot, "width": width,
                            "col_order": list(order),
                            "key": key_name, "variant": var_name
                        }, "P7")
                        pb = max(pb, sc)
                        pc += 1

    # Also test without transposition (just rotation + sub)
    print("  Testing rotation + substitution only (no transposition)...")
    for rot in rotations:
        ct_rot = rotate_text(CT, rot)
        for key_name, key_vals in sub_keys.items():
            for var_name, var_fn in variants:
                pt = var_fn(ct_rot, key_vals)
                sc = check_and_update(pt, {
                    "phase": 7, "model": "rot_sub_only",
                    "rotation": rot, "key": key_name, "variant": var_name
                }, "P7")
                pb = max(pb, sc)
                pc += 1

    # Test KRYPTOS-alphabet substitution variants
    print("  Testing KRYPTOS-alphabet substitution...")
    from kryptos.kernel.constants import KRYPTOS_ALPHABET
    KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

    def ka_vig_decrypt(ct_text, key_vals):
        """Vigenere with KRYPTOS alphabet."""
        pt = []
        klen = len(key_vals)
        for i, c in enumerate(ct_text):
            ci = KA_IDX[c]
            ki = key_vals[i % klen]
            pt.append(KRYPTOS_ALPHABET[(ci - ki) % 26])
        return ''.join(pt)

    def ka_beau_decrypt(ct_text, key_vals):
        """Beaufort with KRYPTOS alphabet."""
        pt = []
        klen = len(key_vals)
        for i, c in enumerate(ct_text):
            ci = KA_IDX[c]
            ki = key_vals[i % klen]
            pt.append(KRYPTOS_ALPHABET[(ki - ci) % 26])
        return ''.join(pt)

    ka_variants = [('ka_vig', ka_vig_decrypt), ('ka_beau', ka_beau_decrypt)]

    for rot in rotations:
        ct_rot = rotate_text(CT, rot)
        for key_name, key_vals in sub_keys.items():
            for var_name, var_fn in ka_variants:
                pt = var_fn(ct_rot, key_vals)
                sc = check_and_update(pt, {
                    "phase": 7, "model": "ka_rot_sub",
                    "rotation": rot, "key": key_name, "variant": var_name
                }, "P7")
                pb = max(pb, sc)
                pc += 1

    # Phase 7b: Two-layer with both transposition orderings
    # Rotation + columnar_w5 + Vig with all p5 keys exhaustive
    print("  Testing rot + w5 full + all shifts (comprehensive)...")
    for rot in [0, 19]:  # Most promising rotations
        ct_rot = rotate_text(CT, rot)
        for order in itertools.permutations(range(5)):
            ct_dec = columnar_decrypt(ct_rot, 5, list(order))
            # Test all 26 constant shifts
            for shift in range(26):
                for var_name, var_fn in variants:
                    pt = var_fn(ct_dec, [shift])
                    sc = check_and_update(pt, {
                        "phase": 7, "model": "rot_w5_allshifts",
                        "rotation": rot, "col_order": list(order),
                        "shift": shift, "variant": var_name
                    }, "P7")
                    pb = max(pb, sc)
                    pc += 1

    phase_summary("Phase 7: Cross-Product", pc, pb, ps)
    return pb


# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════
def main():
    print("="*70)
    print("E-ROMAN-05: Anomaly-Derived Cipher Parameters")
    print("="*70)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print()
    print("Anomaly-derived parameters:")
    print("  Misspelling shifts: [10, 5, 6, 22, 22] (S→C, L→Q, O→U, E→A, I→E)")
    print("  DESPARATLY positions: 5 and 8")
    print("  T IS YOUR POSITION: T=19")
    print("  YAR superscript: Y=24, A=0, R=17")
    print("  Extra L: L=11")
    print("  26 extra E's: E=4, count=26")
    print("  EQUAL (replacement letters): [4, 16, 20, 0, 11]")
    print()

    p1 = phase1()
    p2 = phase2()
    p3 = phase3()
    p4 = phase4()
    p5 = phase5()
    p6 = phase6()
    p7 = phase7()

    elapsed = time.time() - start_time

    print("\n" + "="*70)
    print("FINAL SUMMARY")
    print("="*70)
    print(f"Total configurations tested: {total_configs:,}")
    print(f"Total elapsed time: {elapsed:.1f}s")
    print(f"\nGlobal best score: {best_score}/24")
    if best_score > 0:
        print(f"Best config: {json.dumps(best_config, indent=2)}")
        print(f"Best PT: {best_pt}")

    print("\nPhase breakdown:")
    for phase_name, result in phase_results.items():
        print(f"  {phase_name}: {result['configs_tested']:,} configs, "
              f"best={result['best_score']}/24, {result['elapsed_seconds']}s")

    classification = "NOISE" if best_score <= 6 else (
        "STORE" if best_score <= 17 else (
            "SIGNAL" if best_score <= 23 else "BREAKTHROUGH"))
    print(f"\nClassification: {classification}")

    # Save results
    output = {
        "experiment": "E-ROMAN-05",
        "description": "Anomaly-derived cipher parameters",
        "total_configs": total_configs,
        "elapsed_seconds": round(elapsed, 2),
        "global_best_score": best_score,
        "global_best_config": best_config,
        "global_best_pt": best_pt,
        "classification": classification,
        "phase_results": phase_results,
    }

    outpath = os.path.join(RESULTS_DIR, "e_roman_05_anomaly_params.json")
    with open(outpath, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {outpath}")


if __name__ == "__main__":
    main()
