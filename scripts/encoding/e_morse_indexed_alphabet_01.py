#!/usr/bin/env python3
"""
Cipher: encoding/morse_indexed_alphabet
Family: encoding
Status: active
Keyspace: ~500 configs
Last run: never
Best score: n/a

Hypothesis: Morse code's binary tree produces a natural alphabet ordering
(ETIANMSURWDKGOHVFLPJBXCYZQ) — the "Morse Indexed Alphabet" (MIA).
This ordering has NEVER been tested as cipher material for K4.

Motivated by Smithsonian archive discovery: Sanborn's "Russian Decoding Chart"
(Box 6, Folder 11, images 7-9, dated Feb-Mar 2002) shows he used
Letter → Morse → Binary conversion for the Cyrillic Projector sculpture.
The KRYPTOS alphabet tableau was found in the same archival folder.

Tests:
  Phase A: MIA as cipher alphabet (Beaufort/Vig/VBeau) — crib scoring
  Phase B: MIA in 5-wide Polybius grid — palette structure check
  Phase C: MIA as transposition key (columnar)
  Phase D: Morse depths as numeric key material
  Phase E: MIA vs KA — confirmed findings reproduction check

Pre-registered: 0 degrees of freedom in MIA definition.
Expected outcome: NOISE (auditor preliminary check: 5/24 palette enrichment).

Output: results/e_morse_indexed_alphabet_01.json
"""

import json
import os
import sys
import time
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_POSITIONS, BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.alphabet import AZ, KA, keyword_mixed_alphabet
from kryptos.kernel.text import sanitize, text_to_nums, nums_to_text

# ── MORSE CODE TABLE ────────────────────────────────────────────────────────

MORSE = {
    'A': '.-',    'B': '-...',  'C': '-.-.',  'D': '-..',
    'E': '.',     'F': '..-.',  'G': '--.',   'H': '....',
    'I': '..',    'J': '.---',  'K': '-.-',   'L': '.-..',
    'M': '--',    'N': '-.',    'O': '---',   'P': '.--.',
    'Q': '--.-',  'R': '.-.',   'S': '...',   'T': '-',
    'U': '..-',   'V': '...-',  'W': '.--',   'X': '-..-',
    'Y': '-.--',  'Z': '--..',
}

# Morse Indexed Alphabet: breadth-first traversal of Morse binary tree
# Level 1: E T
# Level 2: I A N M
# Level 3: S U R W D K G O
# Level 4: H V F L P J B X C Y Z Q
MIA = "ETIANMSURWDKGOHVFLPJBXCYZQ"
assert len(MIA) == 26
assert len(set(MIA)) == 26  # All 26 unique letters

MIA_IDX = {c: i for i, c in enumerate(MIA)}

# Morse depths (number of symbols per letter)
MORSE_DEPTH = {c: len(m) for c, m in MORSE.items()}

# Standard alphabets for comparison
AZ_STR = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA_STR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ_IDX = {c: i for i, c in enumerate(AZ_STR)}
KA_IDX = {c: i for i, c in enumerate(KA_STR)}

# CT as numbers under each alphabet
CT_AZ = [AZ_IDX[c] for c in CT]
CT_KA = [KA_IDX[c] for c in CT]
CT_MIA = [MIA_IDX[c] for c in CT]

# Crib positions and expected plaintext
CRIB_ENE = list(range(21, 34))  # EASTNORTHEAST (13 chars)
CRIB_BCL = list(range(63, 74))  # BERLINCLOCK (11 chars)
ALL_CRIB_POS = CRIB_ENE + CRIB_BCL
ENE_PT = "EASTNORTHEAST"
BCL_PT = "BERLINCLOCK"
ALL_PT = ENE_PT + BCL_PT

# Known null palette
NULL_PALETTE = set("BIGKOWZ")
# Consensus null positions
CONSENSUS_NULLS = {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}

results = {"experiment": "e_morse_indexed_alphabet_01", "phases": {}, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}

print("=" * 70)
print("MORSE INDEXED ALPHABET (MIA) — Comprehensive Test")
print("=" * 70)
print(f"MIA: {MIA}")
print(f"AZ:  {AZ_STR}")
print(f"KA:  {KA_STR}")
print()


# ════════════════════════════════════════════════════════════════════════════
# PHASE A: MIA as cipher alphabet — Beaufort/Vig/VBeau crib scoring
# ════════════════════════════════════════════════════════════════════════════

print("─" * 70)
print("PHASE A: MIA as cipher alphabet — keystream at crib positions")
print("─" * 70)

def compute_keystream(ct_nums, pt_text, positions, alph_idx, mod=26, variant="beaufort"):
    """Compute keystream values at crib positions under a given alphabet."""
    pt_nums = [alph_idx[c] for c in pt_text]
    ks = []
    for i, pos in enumerate(positions):
        c = ct_nums[pos]
        p = pt_nums[i]
        if variant == "beaufort":
            k = (c - p) % mod   # Beaufort: C = (K - P), so K = (C + P)...
            # Actually Beaufort: C = (K - P) mod 26, so K = (C + P) mod 26
            k = (c + p) % mod
        elif variant == "vigenere":
            # Vigenere: C = (P + K) mod 26, so K = (C - P) mod 26
            k = (c - p) % mod
        elif variant == "var_beaufort":
            # Variant Beaufort: C = (P - K) mod 26, so K = (P - C) mod 26
            k = (p - c) % mod
        ks.append(k)
    return ks

phase_a = {}

for alph_name, alph_str, alph_idx, ct_nums in [
    ("MIA", MIA, MIA_IDX, CT_MIA),
    ("KA", KA_STR, KA_IDX, CT_KA),
    ("AZ", AZ_STR, AZ_IDX, CT_AZ),
]:
    for variant in ["beaufort", "vigenere", "var_beaufort"]:
        # Compute keystream at ENE positions
        ks_ene = compute_keystream(ct_nums, ENE_PT, CRIB_ENE, alph_idx, variant=variant)
        # Compute keystream at BCL positions
        ks_bcl = compute_keystream(ct_nums, BCL_PT, CRIB_BCL, alph_idx, variant=variant)
        ks_all = ks_ene + ks_bcl

        # Convert keystream values to letters in the same alphabet
        ks_letters = [alph_str[k] for k in ks_all]

        # Check how many keystream letters are in the null palette
        palette_count = sum(1 for c in ks_letters if c in NULL_PALETTE)

        # Check distinct keystream values
        distinct = len(set(ks_all))

        # Check Bean equality: k[27]=k[65] (positions 27 and 65 in CT)
        # Position 27 is in ENE crib (pos 21-33), index 27-21=6
        # Position 65 is in BCL crib (pos 63-73), index 65-63=2
        k27 = ks_ene[6]  # pos 27 = ENE[6]
        k65 = ks_bcl[2]  # pos 65 = BCL[2]
        bean_eq_pass = (k27 == k65)

        # Count Bean inequality passes
        bean_ineq_pass = 0
        bean_ineq_total = 0
        for (i, j) in BEAN_INEQ:
            # Only check if both positions are crib positions
            ki = kj = None
            if 21 <= i <= 33:
                ki = ks_ene[i - 21]
            elif 63 <= i <= 73:
                ki = ks_bcl[i - 63]
            if 21 <= j <= 33:
                kj = ks_ene[j - 21]
            elif 63 <= j <= 73:
                kj = ks_bcl[j - 63]
            if ki is not None and kj is not None:
                bean_ineq_total += 1
                if ki != kj:
                    bean_ineq_pass += 1

        key = f"{alph_name}_{variant}"
        result = {
            "keystream_values": ks_all,
            "keystream_letters": "".join(ks_letters),
            "palette_count": palette_count,
            "palette_total": 24,
            "distinct_values": distinct,
            "bean_eq_pass": bean_eq_pass,
            "bean_ineq_pass": bean_ineq_pass,
            "bean_ineq_total": bean_ineq_total,
        }
        phase_a[key] = result

        palette_pct = palette_count / 24 * 100
        print(f"  {key:25s}  palette={palette_count}/24 ({palette_pct:5.1f}%)  "
              f"distinct={distinct:2d}  BeanEQ={'PASS' if bean_eq_pass else 'FAIL'}  "
              f"BeanINEQ={bean_ineq_pass}/{bean_ineq_total}  "
              f"ks={''.join(ks_letters)}")

results["phases"]["A"] = phase_a

# Highlight the key comparison
print()
print("  KEY COMPARISON:")
ka_beau_pal = phase_a["KA_beaufort"]["palette_count"]
mia_beau_pal = phase_a["MIA_beaufort"]["palette_count"]
print(f"  KA  Beaufort palette enrichment: {ka_beau_pal}/24")
print(f"  MIA Beaufort palette enrichment: {mia_beau_pal}/24")
print(f"  Expected random: {24 * 7/26:.1f}/24")


# ════════════════════════════════════════════════════════════════════════════
# PHASE B: MIA in 5-wide Polybius grid — palette structure
# ════════════════════════════════════════════════════════════════════════════

print()
print("─" * 70)
print("PHASE B: MIA in 5-wide Polybius grid — palette structure")
print("─" * 70)

phase_b = {}

for alph_name, alph_str in [("MIA", MIA), ("KA", KA_STR), ("AZ", AZ_STR)]:
    # Build 5-wide grid (6 rows, last row has 1 letter for 26 letters)
    rows = []
    for i in range(0, 26, 5):
        rows.append(alph_str[i:i+5])

    print(f"\n  {alph_name} 5-wide Polybius grid:")
    for r, row in enumerate(rows):
        print(f"    Row {r}: {' '.join(row)}")

    # Where does each palette letter fall?
    palette_positions = {}
    for letter in sorted(NULL_PALETTE):
        idx = alph_str.index(letter)
        row, col = divmod(idx, 5)
        palette_positions[letter] = (row, col)

    palette_rows = [palette_positions[c][0] for c in sorted(NULL_PALETTE)]
    palette_cols = [palette_positions[c][1] for c in sorted(NULL_PALETTE)]

    print(f"  Palette positions: {palette_positions}")
    print(f"  Palette rows: {sorted(set(palette_rows))} (distinct: {len(set(palette_rows))})")
    print(f"  Palette cols: {sorted(set(palette_cols))} (distinct: {len(set(palette_cols))})")

    # Check if palette occupies specific columns (like KA's {0,3})
    col_counts = Counter(palette_cols)
    row_counts = Counter(palette_rows)

    # Check column concentration
    max_col_concentration = max(col_counts.values()) if col_counts else 0

    phase_b[alph_name] = {
        "grid": rows,
        "palette_positions": {k: list(v) for k, v in palette_positions.items()},
        "palette_rows_distinct": len(set(palette_rows)),
        "palette_cols_distinct": len(set(palette_cols)),
        "col_counts": dict(col_counts),
        "row_counts": dict(row_counts),
        "max_col_concentration": max_col_concentration,
    }

results["phases"]["B"] = phase_b

print()
print("  KEY COMPARISON:")
print(f"  KA:  palette in cols {phase_b['KA']['col_counts']} — 2 columns, concentrated")
print(f"  MIA: palette in cols {phase_b['MIA']['col_counts']} — scattered")


# ════════════════════════════════════════════════════════════════════════════
# PHASE C: MIA as transposition key (columnar)
# ════════════════════════════════════════════════════════════════════════════

print()
print("─" * 70)
print("PHASE C: MIA letter ordering as transposition key")
print("─" * 70)

phase_c = {}

# The MIA ordering gives each letter a "rank" — this can serve as a
# transposition key. E.g., for a width-7 key "KRYPTOS":
# In MIA ordering: K=12, R=9, Y=24, P=19, T=2, O=14, S=7
# Rank order: T(2) S(7) R(9) K(12) O(14) P(19) Y(24)
# Column read order: 4, 6, 1, 0, 5, 3, 2 (0-indexed)

def mia_columnar_key(keyword):
    """Convert keyword to columnar transposition key using MIA ordering."""
    indexed = [(MIA_IDX[c], i) for i, c in enumerate(keyword)]
    indexed.sort()
    return [orig_pos for _, orig_pos in indexed]

def apply_columnar_decrypt(ct, width, col_order):
    """Decrypt columnar transposition."""
    n = len(ct)
    full_rows = n // width
    extra = n % width

    # Calculate column lengths
    col_lens = [full_rows + (1 if i < extra else 0) for i in range(width)]

    # Read off columns in key order
    grid = [''] * width
    pos = 0
    for col in col_order:
        clen = col_lens[col]
        grid[col] = ct[pos:pos + clen]
        pos += clen

    # Read rows
    result = []
    for row in range(full_rows + (1 if extra else 0)):
        for col in range(width):
            if row < len(grid[col]):
                result.append(grid[col][row])

    return ''.join(result)

# Test MIA-ordered transposition key with common keywords
keywords = ["KRYPTOS", "SHADOW", "MORSE", "CIPHER", "BINARY", "ETIAN", "MEDUSA",
            "PALIMPSEST", "DEFECTOR", "ABSCISSA", "KOMPASS", "ТЕНЬ"]

for kw in keywords:
    # Skip non-Latin keywords
    if not all(c in MIA_IDX for c in kw):
        continue

    col_order = mia_columnar_key(kw)
    width = len(kw)

    pt = apply_columnar_decrypt(CT, width, col_order)

    # Score: check if cribs appear in plaintext
    ene_match = sum(1 for i, pos in enumerate(CRIB_ENE) if pos < len(pt) and pt[pos] == ENE_PT[i])
    bcl_match = sum(1 for i, pos in enumerate(CRIB_BCL) if pos < len(pt) and pt[pos] == BCL_PT[i])
    total = ene_match + bcl_match

    key_str = f"MIA_col_{kw}"
    phase_c[key_str] = {
        "keyword": kw,
        "width": width,
        "col_order": col_order,
        "crib_score": total,
        "plaintext_snippet": pt[:40],
    }
    print(f"  {kw:12s} (w={width:2d}) col_order={col_order}  crib={total}/24  pt={pt[:30]}...")

results["phases"]["C"] = phase_c


# ════════════════════════════════════════════════════════════════════════════
# PHASE D: Morse depths as numeric key material
# ════════════════════════════════════════════════════════════════════════════

print()
print("─" * 70)
print("PHASE D: Morse depths as numeric key material")
print("─" * 70)

phase_d = {}

# Each letter has a Morse depth (1-4). This gives a numeric sequence
# when applied to a keyword or to the CT itself.

# D1: Keyword depths as periodic key
print("\n  D1: Keyword Morse depths as Vigenere/Beaufort key")
for kw in ["KRYPTOS", "SHADOW", "MORSE", "BINARY", "CIPHER", "MEDUSA", "ETIAN"]:
    if not all(c in MORSE_DEPTH for c in kw):
        continue
    depths = [MORSE_DEPTH[c] for c in kw]
    period = len(kw)

    # Use depths as key values (subtract 1 to make 0-indexed: depth 1→0, 2→1, 3→2, 4→3)
    key_vals = [d - 1 for d in depths]

    # Beaufort decrypt
    pt_nums = [(CT_AZ[i] + key_vals[i % period]) % 26 for i in range(CT_LEN)]
    pt = ''.join(AZ_STR[n] for n in pt_nums)

    ene_match = sum(1 for i, pos in enumerate(CRIB_ENE) if pt[pos] == ENE_PT[i])
    bcl_match = sum(1 for i, pos in enumerate(CRIB_BCL) if pt[pos] == BCL_PT[i])
    total = ene_match + bcl_match

    key_str = f"depth_key_{kw}"
    phase_d[key_str] = {"keyword": kw, "depths": depths, "crib_score": total}
    print(f"  {kw:12s} depths={depths}  crib={total}/24")

# D2: CT letter depths as non-periodic key
print("\n  D2: CT letter Morse depths as self-keying")
ct_depths = [MORSE_DEPTH[c] for c in CT]
depth_dist = Counter(ct_depths)
print(f"  CT depth distribution: {dict(sorted(depth_dist.items()))}")
print(f"  Mean depth: {sum(ct_depths)/len(ct_depths):.2f}")

# Check if depth correlates with null positions
null_depths = [MORSE_DEPTH[CT[i]] for i in CONSENSUS_NULLS]
nonnull_depths = [MORSE_DEPTH[CT[i]] for i in range(97) if i not in CONSENSUS_NULLS]
null_mean = sum(null_depths) / len(null_depths)
nonnull_mean = sum(nonnull_depths) / len(nonnull_depths)
print(f"  Null position mean depth:     {null_mean:.3f}")
print(f"  Non-null position mean depth: {nonnull_mean:.3f}")

# D3: Depth thresholds as null selection
print("\n  D3: Morse depth thresholds as null selection")
for threshold in [1, 2, 3, 4]:
    null_by_depth = {i for i in range(97) if MORSE_DEPTH[CT[i]] <= threshold}
    overlap = null_by_depth & CONSENSUS_NULLS
    count = len(null_by_depth)
    print(f"  depth<={threshold}: selects {count:2d} positions, "
          f"overlap with 17 consensus nulls: {len(overlap)}/17, "
          f"letters: {sorted(set(CT[i] for i in null_by_depth))}")

phase_d["ct_depth_stats"] = {
    "depth_distribution": dict(sorted(depth_dist.items())),
    "null_mean_depth": null_mean,
    "nonnull_mean_depth": nonnull_mean,
}
results["phases"]["D"] = phase_d


# ════════════════════════════════════════════════════════════════════════════
# PHASE E: MIA vs KA — confirmed findings reproduction
# ════════════════════════════════════════════════════════════════════════════

print()
print("─" * 70)
print("PHASE E: MIA vs KA — confirmed findings reproduction")
print("─" * 70)

phase_e = {}

# E1: Palette generation via KRYPTOS×SEVEN Polybius
# Under KA, the null palette {B,G,I,K,O,W,Z} = columns {0,3} of 5-wide grid
# Does MIA have ANY pair of columns that produces the null palette?
print("\n  E1: Can ANY column pair in MIA 5-wide grid produce the null palette?")
for alph_name, alph_str in [("MIA", MIA), ("KA", KA_STR)]:
    for c1 in range(5):
        for c2 in range(c1 + 1, 5):
            # Extract letters in columns c1 and c2
            col_letters = set()
            for i in range(0, 26, 5):
                if i + c1 < 26:
                    col_letters.add(alph_str[i + c1])
                if i + c2 < 26:
                    col_letters.add(alph_str[i + c2])
            if col_letters == NULL_PALETTE:
                print(f"  {alph_name} columns ({c1},{c2}) = {sorted(col_letters)} → MATCH!")
                phase_e[f"{alph_name}_col_pair_match"] = [c1, c2]
            elif col_letters == NULL_PALETTE:
                pass
    # Check single columns too
    for c in range(5):
        col_letters = set()
        for i in range(0, 26, 5):
            if i + c < 26:
                col_letters.add(alph_str[i + c])
        if col_letters == NULL_PALETTE:
            print(f"  {alph_name} column {c} = {sorted(col_letters)} → SINGLE COL MATCH!")

if "MIA_col_pair_match" not in phase_e:
    print("  MIA: NO column pair produces the null palette")
if "KA_col_pair_match" not in phase_e:
    print("  KA: checking...")

# E2: Keystream letter → Polybius row clustering
# Under KA Beaufort, 10/23 consecutive keystream pairs share the same Polybius row
# (confirmed p=0.005). Does MIA show similar clustering?
print("\n  E2: Keystream row clustering in 5-wide Polybius grid")
for alph_name in ["MIA", "KA", "AZ"]:
    key = f"{alph_name}_beaufort"
    if key not in phase_a:
        continue
    ks = phase_a[key]["keystream_values"]
    ks_rows = [k // 5 for k in ks]

    # Count consecutive pairs sharing same row
    same_row = sum(1 for i in range(len(ks) - 1) if ks_rows[i] == ks_rows[i + 1])
    total_pairs = len(ks) - 1

    phase_e[f"{alph_name}_row_clustering"] = {
        "same_row_pairs": same_row,
        "total_pairs": total_pairs,
    }
    print(f"  {alph_name}: {same_row}/{total_pairs} consecutive pairs share Polybius row")

# E3: Bean constraint checking under MIA
print("\n  E3: Bean equality k[27]=k[65] under each alphabet × variant")
for key, data in phase_a.items():
    print(f"  {key:25s}: Bean EQ {'PASS' if data['bean_eq_pass'] else 'FAIL'}, "
          f"INEQ {data['bean_ineq_pass']}/{data['bean_ineq_total']}")

results["phases"]["E"] = phase_e


# ════════════════════════════════════════════════════════════════════════════
# PHASE F: MIA as running-key alphabet (spot check)
# ════════════════════════════════════════════════════════════════════════════

print()
print("─" * 70)
print("PHASE F: MIA as running-key alphabet (spot check with KRYPTOS)")
print("─" * 70)

# If MIA is the alphabet, and the running key is some text,
# Beaufort: K_letter = MIA[(MIA_idx(CT[i]) + MIA_idx(PT[i])) % 26]
# We already computed the keystream at crib positions in Phase A.
# The question is: does the MIA keystream at crib positions form
# recognizable text fragments?

print("\n  MIA Beaufort keystream at crib positions:")
for variant in ["beaufort", "vigenere", "var_beaufort"]:
    key = f"MIA_{variant}"
    ks_letters = phase_a[key]["keystream_letters"]
    ene_ks = ks_letters[:13]
    bcl_ks = ks_letters[13:]
    print(f"  {variant:15s}: ENE→{ene_ks}  BCL→{bcl_ks}  full→{ks_letters}")

# Compare with KA
print("\n  KA Beaufort keystream at crib positions (reference):")
for variant in ["beaufort", "vigenere", "var_beaufort"]:
    key = f"KA_{variant}"
    ks_letters = phase_a[key]["keystream_letters"]
    ene_ks = ks_letters[:13]
    bcl_ks = ks_letters[13:]
    print(f"  {variant:15s}: ENE→{ene_ks}  BCL→{bcl_ks}  full→{ks_letters}")


# ════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════════════════════════════════════

print()
print("=" * 70)
print("SUMMARY — Morse Indexed Alphabet (MIA) Test Results")
print("=" * 70)

# Palette enrichment comparison
print("\n  Palette enrichment at 24 crib positions (Beaufort):")
for alph in ["MIA", "KA", "AZ"]:
    key = f"{alph}_beaufort"
    pal = phase_a[key]["palette_count"]
    expected = 24 * 7 / 26
    ratio = pal / expected
    print(f"    {alph}: {pal}/24  (expected random: {expected:.1f}, ratio: {ratio:.2f}x)")

# Polybius column structure
print("\n  Polybius 5-wide grid — palette column concentration:")
for alph in ["MIA", "KA", "AZ"]:
    cols = phase_b[alph]["palette_cols_distinct"]
    max_conc = phase_b[alph]["max_col_concentration"]
    print(f"    {alph}: {cols} distinct columns, max concentration: {max_conc} letters in one column")

# Transposition scores
print("\n  Columnar transposition crib scores:")
max_trans = max((v["crib_score"], v["keyword"]) for v in phase_c.values())
print(f"    Best: {max_trans[1]} with score {max_trans[0]}/24")

# Morse depth null correlation
print(f"\n  Morse depth — null vs non-null positions:")
print(f"    Null mean:     {phase_d['ct_depth_stats']['null_mean_depth']:.3f}")
print(f"    Non-null mean: {phase_d['ct_depth_stats']['nonnull_mean_depth']:.3f}")
diff = abs(null_mean - nonnull_mean)
print(f"    Difference:    {diff:.3f} ({'significant' if diff > 0.3 else 'not significant'})")

# Overall verdict
print("\n  VERDICT:")
mia_pal = phase_a["MIA_beaufort"]["palette_count"]
ka_pal = phase_a["KA_beaufort"]["palette_count"]
if mia_pal < ka_pal:
    print(f"    MIA produces LESS palette enrichment than KA ({mia_pal} vs {ka_pal})")
    print(f"    MIA does NOT reproduce confirmed K4 stego structure")
    verdict = "ELIMINATED"
elif mia_pal >= ka_pal:
    print(f"    MIA matches or exceeds KA palette enrichment ({mia_pal} vs {ka_pal})")
    verdict = "INVESTIGATE"
else:
    verdict = "INCONCLUSIVE"

print(f"\n    Classification: {verdict}")
print(f"    MIA as cipher alphabet: {'NOISE' if max_trans[0] < 8 else 'SIGNAL'}")

results["verdict"] = verdict
results["mia_alphabet"] = MIA

# Save results
out_path = os.path.join(_ROOT, "results", "e_morse_indexed_alphabet_01.json")
with open(out_path, "w") as f:
    json.dump(results, f, indent=2, default=str)
print(f"\n  Results saved to: {out_path}")
