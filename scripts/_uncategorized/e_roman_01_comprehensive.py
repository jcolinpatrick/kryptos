#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-ROMAN-01: Comprehensive Roman Numeral Hypothesis Test.

Hypothesis: The "X" in K3's plaintext is Roman numeral 10, not a separator.
Howard Carter's book uses Roman numerals for chapters (I-XI in Vol 1) and
photographic plates (I-LXXIX). Key structural coincidences:
  - K3 source = Chapter V (5)
  - "LAYER TWO" reference = Chapter X (10)
  - Chapter VI ("A Preliminary Investigation") starts on page 97 = K4 length
  - Carter's excavation happened in stages (multiple dates, not just Nov 26)

Phases:
  1. Chapter-number-derived keys (I-XI values as key sequences)
  2. Excavation timeline dates (ALL key dates, not just Nov 26, 1922)
  3. Roman numeral letter extraction from CT (positions/values as key)
  4. Plate number sequences as keys
  5. X=10 interpretation (width-10, period-10, offset-10 combinations)
  6. Chapter progression (if K3=V, K4=VI → key parameter 6)
  7. Combined: Roman numeral keys + transposition
"""
import json, itertools, os, sys

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET, CRIB_DICT
from kryptos.kernel.scoring.aggregate import score_candidate

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

# ── Roman numeral helpers ──

ROMAN_VALS = {'I': 1, 'V': 5, 'X': 10, 'L': 50, 'C': 100, 'D': 500, 'M': 1000}
ROMAN_LETTERS = set(ROMAN_VALS.keys())

def roman_to_int(s):
    """Convert Roman numeral string to integer."""
    total = 0
    prev = 0
    for c in reversed(s.upper()):
        val = ROMAN_VALS.get(c, 0)
        if val < prev:
            total -= val
        else:
            total += val
        prev = val
    return total

# ── Cipher functions ──

def vig_decrypt(ct, key_vals):
    """Vigenere: PT = (CT - KEY) mod 26, key_vals is list of ints."""
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

def varbeau_decrypt(ct, key_vals):
    """Variant Beaufort: PT = (CT + KEY) mod 26."""
    pt = []
    klen = len(key_vals)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = key_vals[i % klen]
        pt.append(ALPH[(ci + ki) % 26])
    return ''.join(pt)

def autokey_pt_decrypt(ct, primer_vals, variant='vig'):
    """Plaintext-autokey with numeric primer."""
    pt = []
    key_vals = list(primer_vals)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = key_vals[i]
        if variant == 'vig':
            p = (ci - ki) % 26
        elif variant == 'beau':
            p = (ki - ci) % 26
        else:
            p = (ci + ki) % 26
        pt.append(ALPH[p])
        key_vals.append(p)
    return ''.join(pt)

def autokey_ct_decrypt(ct, primer_vals, variant='vig'):
    """Ciphertext-autokey with numeric primer."""
    pt = []
    key_vals = list(primer_vals)
    ct_vals = [ALPH_IDX[c] for c in ct]
    for i in range(len(ct_vals)):
        ci = ct_vals[i]
        ki = key_vals[i]
        if variant == 'vig':
            p = (ci - ki) % 26
        elif variant == 'beau':
            p = (ki - ci) % 26
        else:
            p = (ci + ki) % 26
        pt.append(ALPH[p])
        key_vals.append(ci)
    return ''.join(pt)

def columnar_decrypt(ct, width, order):
    """Columnar transposition decrypt."""
    n = len(ct)
    nrows = (n + width - 1) // width
    n_long = n % width if n % width != 0 else width
    col_lens = [nrows if col < n_long else nrows - 1 for col in range(width)]
    cols = {}
    pos = 0
    for rank in range(width):
        col_idx = order[rank]
        length = col_lens[col_idx]
        cols[col_idx] = ct[pos:pos + length]
        pos += length
    result = []
    for row in range(nrows):
        for col in range(width):
            if row < len(cols.get(col, '')):
                result.append(cols[col][row])
    return ''.join(result)

# ── Scoring wrapper ──

VARIANTS = [('vig', vig_decrypt), ('beau', beau_decrypt), ('varbeau', varbeau_decrypt)]

def test_key(ct_str, key_vals, label, results, stats):
    """Test a numeric key sequence against CT with all 3 variants."""
    for vname, vfunc in VARIANTS:
        pt = vfunc(ct_str, key_vals)
        sc = score_candidate(pt)
        stats['total'] += 1
        if sc.crib_score > stats['best_score']:
            stats['best_score'] = sc.crib_score
            stats['best_config'] = f"{label}/{vname}"
            print(f"  NEW BEST: {sc.crib_score}/24 — {label}/{vname}")
            print(f"    PT snippet: {pt[:50]}...")
        if sc.crib_score >= 6:
            results.append({
                'config': f"{label}/{vname}",
                'score': sc.crib_score,
                'pt_snippet': pt[:60],
            })

def test_autokey(ct_str, primer_vals, label, results, stats):
    """Test autokey (PT and CT feedback) with numeric primer."""
    for variant in ['vig', 'beau', 'varbeau']:
        for feedback in ['pt', 'ct']:
            if feedback == 'pt':
                pt = autokey_pt_decrypt(ct_str, primer_vals, variant)
            else:
                pt = autokey_ct_decrypt(ct_str, primer_vals, variant)
            sc = score_candidate(pt)
            stats['total'] += 1
            if sc.crib_score > stats['best_score']:
                stats['best_score'] = sc.crib_score
                stats['best_config'] = f"{label}/autokey-{feedback}/{variant}"
                print(f"  NEW BEST: {sc.crib_score}/24 — {label}/autokey-{feedback}/{variant}")
                print(f"    PT snippet: {pt[:50]}...")
            if sc.crib_score >= 6:
                results.append({
                    'config': f"{label}/autokey-{feedback}/{variant}",
                    'score': sc.crib_score,
                    'pt_snippet': pt[:60],
                })

# ── Main ──

results = []
stats = {'total': 0, 'best_score': 0, 'best_config': None}

print("=" * 70)
print("E-ROMAN-01: Comprehensive Roman Numeral Hypothesis")
print("=" * 70)

# ══════════════════════════════════════════════════════════════════════
# PHASE 1: Chapter-number-derived keys
# ══════════════════════════════════════════════════════════════════════
print("\n--- Phase 1: Chapter-number keys ---")

# Volume 1 chapters: I-XI (1-11)
vol1_chapters = list(range(1, 12))  # [1,2,3,4,5,6,7,8,9,10,11]
# Volume 2 chapters: I-VIII (1-8)
vol2_chapters = list(range(1, 9))
# Volume 3 chapters: I-V (1-5)
vol3_chapters = list(range(1, 6))
# All volumes concatenated
all_chapters = vol1_chapters + vol2_chapters + vol3_chapters  # 24 values!

chapter_keys = {
    'vol1_I-XI': vol1_chapters,
    'vol2_I-VIII': vol2_chapters,
    'vol3_I-V': vol3_chapters,
    'all_vols': all_chapters,  # 24 values — same as number of cribs!
    'vol1_mod26': [c % 26 for c in vol1_chapters],
    'vol1_reversed': list(reversed(vol1_chapters)),
    # Key chapters for K4
    'ch_V_VI': [5, 6],  # K3 source + next chapter
    'ch_V_X': [5, 10],  # K3 source + "LAYER TWO"
    'ch_VI': [6],  # Chapter starting on page 97
    'ch_VI_VII': [6, 7],
    'ch_V_VI_VII': [5, 6, 7],
    'ch_X_XI': [10, 11],  # "LAYER TWO" + burial chamber opening
    'ch_V_to_XI': list(range(5, 12)),  # Chapters V through XI
    'ch_VI_to_XI': list(range(6, 12)),  # Starting from "page 97" chapter
    # Differences between consecutive chapters (all 1's, but let's test)
    'ch_diffs': [j - i for i, j in zip(vol1_chapters, vol1_chapters[1:])],
}

for name, kv in chapter_keys.items():
    test_key(CT, kv, f"p1-chapter/{name}", results, stats)
    test_autokey(CT, kv, f"p1-chapter/{name}", results, stats)

# Also test chapter numbers as letter indices (A=1 style)
for name, kv in chapter_keys.items():
    letter_key = [ALPH[(v - 1) % 26] for v in kv]
    letter_vals = [ALPH_IDX[c] for c in letter_key]
    test_key(CT, letter_vals, f"p1-chapter-letter/{name}", results, stats)

print(f"  Phase 1: {stats['total']} configs, best {stats['best_score']}/24")

# ══════════════════════════════════════════════════════════════════════
# PHASE 2: Excavation timeline dates (ALL key dates)
# ══════════════════════════════════════════════════════════════════════
print("\n--- Phase 2: Excavation dates (comprehensive) ---")
p2_start = stats['total']

# ALL significant dates from excavation
excavation_dates = {
    # (month, day, year) — note: Nov=11, Feb=2
    'nov4_discovery':    (11, 4, 1922),   # Water boy finds step
    'nov5_staircase':    (11, 5, 1922),   # Staircase cleared, door found
    'nov23_carnarvon':   (11, 23, 1922),  # Carnarvon arrives
    'nov25_second_door': (11, 25, 1922),  # Second sealed door
    'nov26_breach':      (11, 26, 1922),  # "Can you see anything?"
    'nov27_explore':     (11, 27, 1922),  # Explore Antechamber
    'nov28_burial':      (11, 28, 1922),  # Enter Burial Chamber
    'nov29_official':    (11, 29, 1922),  # Official opening
    'feb16_sealed':      (2, 16, 1923),   # Sealed door officially opened
    'feb17_entry':       (2, 17, 1923),   # First entry burial chamber
    'apr5_carnarvon_dies': (4, 5, 1923),  # Carnarvon dies
    'jan25_resume':      (1, 25, 1925),   # Carter resumes work
}

def date_to_keys(m, d, y):
    """Generate multiple key representations from a date."""
    keys = {}
    # US format digits: 11/26/1922 → [1,1,2,6,1,9,2,2]
    ds = f"{m:02d}{d:02d}{y:04d}"
    keys['digits'] = [int(c) for c in ds]
    # Components: [11, 26, 19, 22]
    keys['components'] = [m, d, y // 100, y % 100]
    # Components mod 26
    keys['comp_mod26'] = [v % 26 for v in [m, d, y // 100, y % 100]]
    # Day + month only
    keys['md'] = [m, d]
    keys['dm'] = [d, m]
    # Roman numeral month: Nov=XI=11, Feb=II=2, etc.
    keys['roman_month'] = [m]  # Already numeric
    # Year digits only
    keys['year_digits'] = [int(c) for c in str(y)]
    # Day as single value
    keys['day_only'] = [d]
    # Full date as single large number mod 26
    full = m * 1000000 + d * 10000 + y
    keys['full_mod26'] = [full % 26]
    # Alternating: m,d,y digits interleaved
    keys['interleaved'] = [m // 10, d // 10, (y // 100) // 10,
                           m % 10, d % 10, (y // 100) % 10,
                           (y % 100) // 10, (y % 100) % 10]
    # Sum-based: m+d, d+y%100, etc.
    keys['sums'] = [(m + d) % 26, (d + y % 100) % 26, (m + y % 100) % 26]
    return keys

for date_name, (m, d, y) in excavation_dates.items():
    dk = date_to_keys(m, d, y)
    for kname, kvals in dk.items():
        if len(kvals) > 0 and all(isinstance(v, int) for v in kvals):
            test_key(CT, kvals, f"p2-date/{date_name}/{kname}", results, stats)
            if len(kvals) <= 12:  # Autokey only for short primers
                test_autokey(CT, kvals, f"p2-date/{date_name}/{kname}", results, stats)

# Multi-date combinations: sequence of discovery dates
multi_dates = {
    'discovery_sequence': [4, 5, 23, 25, 26, 27, 28, 29],  # Nov days in order
    'discovery_seq_mod26': [(d) % 26 for d in [4, 5, 23, 25, 26, 27, 28, 29]],
    'key_dates_days': [4, 26, 16],  # Discovery, breach, burial opening
    'key_dates_full': [11, 4, 11, 26, 2, 16],  # m/d for each key date
    'feb_dates': [16, 17],  # February chamber opening dates
    'antechamber_to_burial': [26, 16],  # Nov 26 → Feb 16 (days)
    'gap_days': [84],  # Nov 26 → Feb 16 = ~84 days apart
    'gap_mod26': [84 % 26],  # = 6!
}

for name, kvals in multi_dates.items():
    test_key(CT, kvals, f"p2-multidate/{name}", results, stats)
    test_autokey(CT, kvals, f"p2-multidate/{name}", results, stats)

print(f"  Phase 2: {stats['total'] - p2_start} configs, best {stats['best_score']}/24")

# ══════════════════════════════════════════════════════════════════════
# PHASE 3: Roman numeral letter extraction from CT
# ══════════════════════════════════════════════════════════════════════
print("\n--- Phase 3: Roman numeral extraction from CT ---")
p3_start = stats['total']

# Find positions of Roman numeral letters in CT
roman_positions = []
roman_values = []
non_roman_positions = []
for i, c in enumerate(CT):
    if c in ROMAN_LETTERS:
        roman_positions.append(i)
        roman_values.append(ROMAN_VALS[c])
    else:
        non_roman_positions.append(i)

print(f"  Roman numeral letters in CT: {len(roman_positions)}/97")
print(f"  Positions: {roman_positions}")
roman_letters_in_ct = ''.join(CT[p] for p in roman_positions)
print(f"  Letters: {roman_letters_in_ct}")
print(f"  Values: {roman_values}")

# 3a: Use Roman numeral positions as key
roman_pos_keys = {
    'positions': roman_positions,
    'positions_mod26': [p % 26 for p in roman_positions],
    'values': roman_values,
    'values_mod26': [v % 26 for v in roman_values],
    # Differences between consecutive Roman positions
    'pos_diffs': [roman_positions[i+1] - roman_positions[i]
                  for i in range(len(roman_positions)-1)],
    'pos_diffs_mod26': [(roman_positions[i+1] - roman_positions[i]) % 26
                        for i in range(len(roman_positions)-1)],
    # Roman letter indices in standard alphabet
    'roman_alph_idx': [ALPH_IDX[c] for c in roman_letters_in_ct],
    # Count of each Roman letter as key
    'counts': [roman_letters_in_ct.count(c) for c in 'IVXLCDM'],
}

for name, kvals in roman_pos_keys.items():
    if len(kvals) > 0:
        test_key(CT, kvals, f"p3-extract/{name}", results, stats)
        if len(kvals) <= 20:
            test_autokey(CT, kvals, f"p3-extract/{name}", results, stats)

# 3b: Position-dependent: Roman numeral letters get their value, others get 0 or position
full_key_roman_val = []
full_key_roman_or_pos = []
full_key_roman_binary = []
for i, c in enumerate(CT):
    if c in ROMAN_LETTERS:
        full_key_roman_val.append(ROMAN_VALS[c] % 26)
        full_key_roman_or_pos.append(ROMAN_VALS[c] % 26)
        full_key_roman_binary.append(1)
    else:
        full_key_roman_val.append(0)
        full_key_roman_or_pos.append(i % 26)
        full_key_roman_binary.append(0)

position_keys = {
    'roman_val_or_zero': full_key_roman_val,
    'roman_val_or_pos': full_key_roman_or_pos,
    'roman_binary': full_key_roman_binary,
}

for name, kvals in position_keys.items():
    for vname, vfunc in VARIANTS:
        pt = vfunc(CT, kvals)
        sc = score_candidate(pt)
        stats['total'] += 1
        if sc.crib_score > stats['best_score']:
            stats['best_score'] = sc.crib_score
            stats['best_config'] = f"p3-poskey/{name}/{vname}"
            print(f"  NEW BEST: {sc.crib_score}/24 — p3-poskey/{name}/{vname}")
            print(f"    PT snippet: {pt[:50]}...")

# 3c: Extract only non-Roman letters as the "real" CT, treat Roman as nulls
non_roman_ct = ''.join(CT[p] for p in non_roman_positions)
print(f"  Non-Roman CT ({len(non_roman_ct)} chars): {non_roman_ct[:50]}...")
# Test if this shorter text has any signal
for period in range(2, 8):
    for vname, vfunc in VARIANTS:
        for key_start in range(26):
            key = [(key_start + i) % 26 for i in range(period)]
            pt = vfunc(non_roman_ct, key)
            sc = score_candidate(pt)
            stats['total'] += 1
            if sc.crib_score > stats['best_score']:
                stats['best_score'] = sc.crib_score
                stats['best_config'] = f"p3-nullextract/{vname}/p{period}/k{key_start}"
                print(f"  NEW BEST: {sc.crib_score}/24 — {stats['best_config']}")

# 3d: Roman letters as null extraction — extract Roman-position chars as separate message
roman_ct = ''.join(CT[p] for p in roman_positions)
print(f"  Roman-only CT ({len(roman_ct)} chars): {roman_ct}")
# Quick check: does this 18-char extract contain any words?
for vname, vfunc in VARIANTS:
    for shift in range(26):
        pt = vfunc(roman_ct, [shift])
        stats['total'] += 1
        # Just print any interesting ones
        if any(w in pt for w in ['THE', 'AND', 'FOR', 'KEY', 'TEN', 'SIX']):
            print(f"    Roman-only shift={shift}/{vname}: {pt}")

print(f"  Phase 3: {stats['total'] - p3_start} configs, best {stats['best_score']}/24")

# ══════════════════════════════════════════════════════════════════════
# PHASE 4: Plate number sequences as keys
# ══════════════════════════════════════════════════════════════════════
print("\n--- Phase 4: Plate number sequences ---")
p4_start = stats['total']

# Known plates from Vol 1 (from the research)
vol1_plates = [1, 2, 4, 5, 6, 11, 12, 15, 20, 21, 22, 23, 24, 27, 29, 32,
               34, 35, 36, 38, 39, 43, 44, 46, 47, 48, 49, 50, 51, 52, 53,
               54, 55, 57, 58, 59, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
               71, 72, 73, 74, 75, 76, 77, 78, 79]

plate_keys = {
    'all_plates_mod26': [p % 26 for p in vol1_plates],
    'first_24_plates': [p % 26 for p in vol1_plates[:24]],  # 24 = crib count
    'plates_1_to_11': [p % 26 for p in vol1_plates[:6]],  # First 6 plates
    'plate_diffs': [(vol1_plates[i+1] - vol1_plates[i]) % 26
                    for i in range(len(vol1_plates)-1)],
    'plate_XV': [15],  # Plate XV on page 96 (just before page 97)
    'plate_VI': [6],   # Plate VI: Interior of Rameses IX tomb
    'missing_plates': [3, 7, 8, 9, 10, 13, 14, 16, 17, 18, 19, 25, 26, 28,
                       30, 31, 33, 37, 40, 41, 42, 45, 56, 60],  # Missing plate numbers
    'missing_mod26': [(p % 26) for p in [3, 7, 8, 9, 10, 13, 14, 16, 17, 18, 19,
                      25, 26, 28, 30, 31, 33, 37, 40, 41, 42, 45, 56, 60]],
    # Plates near the Antechamber discovery (XV and neighbors)
    'antechamber_plates': [p % 26 for p in [11, 12, 15, 20, 21, 22, 23, 24]],
}

for name, kvals in plate_keys.items():
    if len(kvals) > 0:
        test_key(CT, kvals, f"p4-plate/{name}", results, stats)
        if len(kvals) <= 24:
            test_autokey(CT, kvals, f"p4-plate/{name}", results, stats)

print(f"  Phase 4: {stats['total'] - p4_start} configs, best {stats['best_score']}/24")

# ══════════════════════════════════════════════════════════════════════
# PHASE 5: X=10 interpretation
# ══════════════════════════════════════════════════════════════════════
print("\n--- Phase 5: X=10 interpretation ---")
p5_start = stats['total']

# If K3's X = 10, test width-10 and period-10 specifically
# Width 10: 97/10 = 9.7 rows (10 rows, 7 long columns, 3 short)
print("  Testing width-10 columnar (all 3.6M orderings is too many; sample structured)")

# For width-10, test all keyword-derived orderings from thematic keywords
width10_keywords = [
    'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'BERLINCLOCK', 'EASTNORTHEAS',
    'TUTANKHAMUN', 'CARTER', 'HERBERT', 'ANTECHAMBER', 'GOLDGLINT',
    'WONDERFUL', 'TOMBOFTUT', 'DISCOVERY', 'EXCAVATION', 'PRELIMINARY',
    'CARNARVON', 'EVELYN', 'CANDLE', 'DESPARATLY', 'SANBORN',
    'CHECKPOINT', 'CHARLIE', 'STOPWATCH', 'HOWARDCARTER', 'LAYERTWO',
]

def keyword_to_order(kw, width):
    """Convert keyword to columnar transposition order."""
    # Take first 'width' unique chars, rank them alphabetically
    seen = []
    for c in kw.upper():
        if c not in seen:
            seen.append(c)
        if len(seen) == width:
            break
    if len(seen) < width:
        # Pad with remaining alphabet
        for c in ALPH:
            if c not in seen:
                seen.append(c)
            if len(seen) == width:
                break
    # Rank: position in sorted order
    indexed = sorted(range(width), key=lambda i: seen[i])
    order = [0] * width
    for rank, col in enumerate(indexed):
        order[col] = rank
    # Return as reading order (which column to read first)
    return [order.index(r) for r in range(width)]

for kw in width10_keywords:
    for width in [10, 6, 5]:  # X=10, VI=6, V=5
        try:
            order = keyword_to_order(kw, width)
            untrans = columnar_decrypt(CT, width, order)
            for vname, vfunc in VARIANTS:
                pt = vfunc(untrans, [0])  # Identity key first
                sc = score_candidate(pt)
                stats['total'] += 1
            # Now with periodic keys at interesting periods
            for period in [5, 6, 7, 10]:
                for key_offset in range(26):
                    key = [(key_offset + j) % 26 for j in range(period)]
                    for vname, vfunc in VARIANTS:
                        pt = vfunc(untrans, key)
                        sc = score_candidate(pt)
                        stats['total'] += 1
                        if sc.crib_score > stats['best_score']:
                            stats['best_score'] = sc.crib_score
                            stats['best_config'] = f"p5-w{width}/{kw}/{vname}/p{period}/k{key_offset}"
                            print(f"  NEW BEST: {sc.crib_score}/24 — {stats['best_config']}")
                            print(f"    PT snippet: {pt[:50]}...")
                        if sc.crib_score >= 6:
                            results.append({
                                'config': stats['best_config'],
                                'score': sc.crib_score,
                                'pt_snippet': pt[:60],
                            })
        except Exception:
            pass

# Width-10 with Roman numeral value keys
roman_keys_for_w10 = {
    'V': [5],
    'VI': [6],
    'X': [10],
    'XI': [11],
    'V_VI': [5, 6],
    'V_X': [5, 10],
    'VI_X': [6, 10],
    'V_VI_X_XI': [5, 6, 10, 11],
    'I_to_X': list(range(1, 11)),
    'ch5_mod26': [5 % 26],
}

for kw in width10_keywords[:10]:  # Top 10 keywords
    for width in [10, 6]:
        try:
            order = keyword_to_order(kw, width)
            untrans = columnar_decrypt(CT, width, order)
            for rname, rvals in roman_keys_for_w10.items():
                test_key(untrans, rvals, f"p5-w{width}/{kw}/roman-{rname}", results, stats)
                test_autokey(untrans, rvals, f"p5-w{width}/{kw}/roman-{rname}", results, stats)
        except Exception:
            pass

print(f"  Phase 5: {stats['total'] - p5_start} configs, best {stats['best_score']}/24")

# ══════════════════════════════════════════════════════════════════════
# PHASE 6: Chapter progression pattern
# ══════════════════════════════════════════════════════════════════════
print("\n--- Phase 6: Chapter progression ---")
p6_start = stats['total']

# Theory: K1=chapter I(1), K2=chapter II(2), K3=chapter V(5), K4=chapter VI(6)?
# Or: K3 width=7(VII), K4 width=6(VI)?
# Or: K3 period=10(X), K4 period=?

# Cross-product: widths from Roman numerals × periods from Roman numerals
roman_widths = [5, 6, 7, 8, 9, 10, 11]  # V through XI
roman_periods = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]  # I through XI

# For each width, test all keyword orderings + all periods
for width in roman_widths:
    for kw in ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'CARTER', 'HERBERT', 'TUTANKHAMUN']:
        try:
            order = keyword_to_order(kw, width)
            untrans = columnar_decrypt(CT, width, order)
            for period in [p for p in roman_periods if p <= 7]:  # Only meaningful periods
                for key_start in range(26):
                    key = [(key_start + j) % 26 for j in range(period)]
                    for vname, vfunc in VARIANTS:
                        pt = vfunc(untrans, key)
                        sc = score_candidate(pt)
                        stats['total'] += 1
                        if sc.crib_score > stats['best_score']:
                            stats['best_score'] = sc.crib_score
                            stats['best_config'] = f"p6-prog/w{width}/{kw}/{vname}/p{period}/k{key_start}"
                            print(f"  NEW BEST: {sc.crib_score}/24 — {stats['best_config']}")
                            print(f"    PT snippet: {pt[:50]}...")
                        if sc.crib_score >= 8:
                            results.append({
                                'config': f"p6-prog/w{width}/{kw}/{vname}/p{period}/k{key_start}",
                                'score': sc.crib_score,
                                'pt_snippet': pt[:60],
                            })
        except Exception:
            pass

# Special: K3 used KRYPTOS(w7) + PALIMPSEST(p10). What if K4 uses the NEXT?
# K4 = width from next keyword? Period from next keyword?
# ABSCISSA = 7 unique letters → width 7, or period 7
# Test ABSCISSA as width-7 keyword + period-6 (VI) key
for kw_w in ['ABSCISSA', 'CARTER', 'HERBERT']:
    for kw_p in ['ABSCISSA', 'CARTER', 'HERBERT', 'EVELYN', 'SANBORN']:
        width = min(len(set(kw_w)), 12)
        if width < 3:
            continue
        order = keyword_to_order(kw_w, width)
        untrans = columnar_decrypt(CT, width, order)
        # Use second keyword as repeating key
        key_vals = [ALPH_IDX[c] for c in kw_p]
        test_key(untrans, key_vals, f"p6-kwpair/w-{kw_w}/k-{kw_p}", results, stats)
        test_autokey(untrans, key_vals, f"p6-kwpair/w-{kw_w}/k-{kw_p}", results, stats)

print(f"  Phase 6: {stats['total'] - p6_start} configs, best {stats['best_score']}/24")

# ══════════════════════════════════════════════════════════════════════
# PHASE 7: Combined Roman numeral keys + transposition
# ══════════════════════════════════════════════════════════════════════
print("\n--- Phase 7: Combined Roman + transposition ---")
p7_start = stats['total']

# Date keys + width-8/9/10 columnar (Bean-compatible widths with Roman widths)
best_date_keys = {
    'nov4_digits': [1, 1, 0, 4, 1, 9, 2, 2],
    'nov26_digits': [1, 1, 2, 6, 1, 9, 2, 2],
    'feb16_digits': [0, 2, 1, 6, 1, 9, 2, 3],
    'feb17_digits': [0, 2, 1, 7, 1, 9, 2, 3],
    'nov4_comp': [11, 4, 19, 22],
    'nov26_comp': [11, 26, 19, 22],
    'feb16_comp': [2, 16, 19, 23],
    'discovery_days': [4, 5, 23, 25, 26, 27, 28, 29],
    'key3_days': [4, 26, 16],
    'gap84_mod26': [6],  # 84 days gap mod 26 = 6!
    'roman_V': [5],
    'roman_VI': [6],
    'roman_X': [10],
    'roman_XI': [11],
    'roman_V_VI': [5, 6],
    'roman_ch_seq': [5, 6, 7, 8, 9, 10, 11],
}

for width in [8, 9, 10, 13]:  # Bean-compatible widths + 10(X) + 13
    for kw in ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'CARTER', 'HERBERT', 'TUTANKHAMUN']:
        try:
            order = keyword_to_order(kw, width)
            untrans = columnar_decrypt(CT, width, order)
            for dname, dvals in best_date_keys.items():
                test_key(untrans, dvals, f"p7-combo/w{width}/{kw}/{dname}", results, stats)
        except Exception:
            pass

# Roman numeral position-dependent key + structured transposition
for width in [8, 9, 10]:
    for kw in ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'CARTER']:
        try:
            order = keyword_to_order(kw, width)
            untrans = columnar_decrypt(CT, width, order)
            # Apply Roman numeral position-dependent key
            for vname, vfunc in VARIANTS:
                # Map: if position's CT char is Roman numeral, key = its value mod 26
                # Otherwise key = 0
                pos_key = []
                for i, c in enumerate(untrans):
                    if c in ROMAN_LETTERS:
                        pos_key.append(ROMAN_VALS[c] % 26)
                    else:
                        pos_key.append(0)
                pt = vfunc(untrans, pos_key)
                sc = score_candidate(pt)
                stats['total'] += 1
                if sc.crib_score > stats['best_score']:
                    stats['best_score'] = sc.crib_score
                    stats['best_config'] = f"p7-romanpos/w{width}/{kw}/{vname}"
                    print(f"  NEW BEST: {sc.crib_score}/24 — {stats['best_config']}")
        except Exception:
            pass

print(f"  Phase 7: {stats['total'] - p7_start} configs, best {stats['best_score']}/24")

# ══════════════════════════════════════════════════════════════════════
# PHASE 8: "Page 97" and structural coincidences
# ══════════════════════════════════════════════════════════════════════
print("\n--- Phase 8: Page 97 / structural coincidences ---")
p8_start = stats['total']

# Chapter VI starts on page 97. K4 = 97 chars. VI = 6.
# What if the key is derived from page 97's content?
# Also: 97 is prime. The only factorization is 1×97.
# Roman numeral 97 = XCVII → X(10), C(100), V(5), I(1), I(1)
# XCVII letter values: X=23, C=2, V=21, I=8, I=8 (in standard alphabet)

xcvii_keys = {
    'XCVII_alpha': [ALPH_IDX[c] for c in 'XCVII'],
    'XCVII_roman': [10, 100 % 26, 5, 1, 1],  # [10, 22, 5, 1, 1]
    'XCVII_roman_raw': [10, 100, 5, 1, 1],
    '97_digits': [9, 7],
    '97_sum': [16],  # 9+7=16
    '97_roman_sum': [10 + 100 + 5 + 1 + 1],  # = 117, mod 26 = 13
    'page97_ch6': [97 % 26, 6],  # [19, 6]
    'ch6_p97': [6, 97 % 26],  # [6, 19]
}

for name, kvals in xcvii_keys.items():
    kvals_mod = [v % 26 for v in kvals]
    test_key(CT, kvals_mod, f"p8-page97/{name}", results, stats)
    test_autokey(CT, kvals_mod, f"p8-page97/{name}", results, stats)

# Width-6 (VI) columnar with all orderings (only 720)
print("  Width-6 exhaustive (720 orderings × all date keys)...")
for order in itertools.permutations(range(6)):
    untrans = columnar_decrypt(CT, 6, list(order))
    for dname, dvals in [('roman_V', [5]), ('roman_VI', [6]), ('roman_X', [10]),
                          ('97_digits', [9, 7]), ('ch_V_VI', [5, 6]),
                          ('days_nov', [4, 5, 23, 25, 26, 27, 28, 29])]:
        for vname, vfunc in VARIANTS:
            pt = vfunc(untrans, dvals)
            sc = score_candidate(pt)
            stats['total'] += 1
            if sc.crib_score > stats['best_score']:
                stats['best_score'] = sc.crib_score
                stats['best_config'] = f"p8-w6/order={list(order)}/{dname}/{vname}"
                print(f"  NEW BEST: {sc.crib_score}/24 — {stats['best_config']}")
                if sc.crib_score >= 10:
                    print(f"    PT: {pt}")
            if sc.crib_score >= 8:
                results.append({
                    'config': f"p8-w6/{dname}/{vname}",
                    'score': sc.crib_score,
                    'order': list(order),
                    'pt_snippet': pt[:60],
                })

# Width-10 (X) exhaustive is 3.6M — sample with keyword orderings only
# (already done in Phase 5, skip here)

# Width-5 (V) exhaustive (120 orderings)
print("  Width-5 exhaustive (120 orderings × date keys)...")
for order in itertools.permutations(range(5)):
    untrans = columnar_decrypt(CT, 5, list(order))
    for dname, dvals in [('roman_V', [5]), ('roman_VI', [6]), ('roman_X', [10]),
                          ('97_digits', [9, 7]), ('days_nov', [4, 26, 16])]:
        for vname, vfunc in VARIANTS:
            pt = vfunc(untrans, dvals)
            sc = score_candidate(pt)
            stats['total'] += 1
            if sc.crib_score > stats['best_score']:
                stats['best_score'] = sc.crib_score
                stats['best_config'] = f"p8-w5/order={list(order)}/{dname}/{vname}"
                print(f"  NEW BEST: {sc.crib_score}/24 — {stats['best_config']}")

print(f"  Phase 8: {stats['total'] - p8_start} configs, best {stats['best_score']}/24")

# ══════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print(f"TOTAL: {stats['total']} configurations tested")
print(f"GLOBAL BEST: {stats['best_score']}/24")
if stats['best_config']:
    print(f"BEST CONFIG: {stats['best_config']}")
print(f"Results above noise: {len(results)}")
if stats['best_score'] <= 9:
    print("CLASSIFICATION: NOISE")
elif stats['best_score'] <= 17:
    print("CLASSIFICATION: STORE")
else:
    print("CLASSIFICATION: SIGNAL — INVESTIGATE!")
print("=" * 70)

# Save results
os.makedirs('results', exist_ok=True)
with open('results/e_roman_01_comprehensive.json', 'w') as f:
    json.dump({
        'experiment': 'E-ROMAN-01',
        'description': 'Comprehensive Roman Numeral Hypothesis',
        'total_configs': stats['total'],
        'best_score': stats['best_score'],
        'best_config': stats['best_config'],
        'classification': 'NOISE' if stats['best_score'] <= 9 else 'STORE' if stats['best_score'] <= 17 else 'SIGNAL',
        'above_noise': results,
        'roman_positions_in_ct': roman_positions,
        'roman_letters_in_ct': roman_letters_in_ct,
    }, f, indent=2)
print(f"\nArtifact: results/e_roman_01_comprehensive.json")
