#!/usr/bin/env python3
"""
Cipher: NDYAHR displacement / running key
Family: k3_continuity
Status: active
Keyspace: ~25000 configs
Last run:
Best score:
"""
"""E-NDYAHR-K123CT-UNIFIED: Test NDYAHR displacement on K1+K2+K3 ciphertext.

HYPOTHESIS: The NDYAHR displaced letters are editing instructions that apply
to the K1+K2+K3 ciphertext block (not just K3). Since K1 and K2 are Vigenere
ciphertexts (ENGINEERED letter by letter), and K3 is transposition (letters
rearranged), removing or displacing the NDYAHR letters from the combined
K1+K2+K3 CT may produce:
  - A residue of length 73 or 97 (K4-relevant)
  - A text with unusual statistical properties
  - A running key for K4 decryption

Steps:
  1. Get full K1+K2+K3 ciphertext
  2. Count/locate NDYAHR letters, compute residue
  3. Check residue length for K4 relevance (73, 97, multiples)
  4. Try decrypting residue or using as running key
  5. Check all subsets of {N,D,Y,A,H,R} for interesting lengths
  6. Statistical analysis (IC, frequency, distribution)
  7. Grid-based displacement interpretation

Usage: PYTHONPATH=src python3 -u scripts/k3_continuity/e_ndyahr_k123ct_unified.py
"""

import sys
import os
import json
import time
from collections import Counter
from itertools import combinations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, CRIB_DICT, N_CRIBS,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.scoring.aggregate import (
    score_candidate, score_candidate_free,
)

# ── Alphabets ────────────────────────────────────────────────────────────

AZ = ALPH
AZ_IDX = ALPH_IDX
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

# ── K1+K2+K3 Ciphertexts ────────────────────────────────────────────────

K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"

K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)

K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)

# ── Helpers ──────────────────────────────────────────────────────────────

def clean(s):
    return ''.join(c for c in s.upper() if c.isalpha())

def ic(text):
    """Index of coincidence."""
    n = len(text)
    if n <= 1:
        return 0.0
    freq = Counter(text)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

def to_nums(text, idx_map):
    return [idx_map[c] for c in text]

def to_text(nums, alphabet):
    return ''.join(alphabet[n % len(alphabet)] for n in nums)

def vig_decrypt(ct_nums, key_nums):
    return [(c - k) % 26 for c, k in zip(ct_nums, key_nums)]

def beau_decrypt(ct_nums, key_nums):
    return [(k - c) % 26 for c, k in zip(ct_nums, key_nums)]

def vbeau_decrypt(ct_nums, key_nums):
    return [(c + k) % 26 for c, k in zip(ct_nums, key_nums)]

VARIANTS = {"Vig": vig_decrypt, "Beau": beau_decrypt, "VBeau": vbeau_decrypt}

def extend_key(key_text, length):
    if not key_text:
        return ""
    reps = (length // len(key_text)) + 1
    return (key_text * reps)[:length]

def score_pt(pt_text):
    anchored = score_candidate(pt_text)
    free = score_candidate_free(pt_text)
    return anchored, free

# ── Tracking ─────────────────────────────────────────────────────────────

results_log = []
best_overall_score = 0
best_overall_config = ""

def record(label, pt_text, anchored, free):
    global best_overall_score, best_overall_config
    score_a = anchored.crib_score
    score_f = free.crib_score
    best_score = max(score_a, score_f)
    if best_score > best_overall_score:
        best_overall_score = best_score
        best_overall_config = label
    if best_score > NOISE_FLOOR:
        tag = "FREE" if score_f > score_a else "ANCHORED"
        print(f"  ** {tag} {best_score}/24: {label}")
        print(f"     PT: {pt_text[:60]}...")
    if best_score >= STORE_THRESHOLD:
        results_log.append({
            "label": label,
            "anchored_score": score_a,
            "free_score": score_f,
            "ic": anchored.ic_value,
            "pt_sample": pt_text[:80],
        })
    return best_score


# ══════════════════════════════════════════════════════════════════════════
# MAIN ANALYSIS
# ══════════════════════════════════════════════════════════════════════════

t0 = time.time()
total_configs = 0

print("=" * 78)
print("E-NDYAHR-K123CT-UNIFIED: NDYAHR on K1+K2+K3 Ciphertext")
print("=" * 78)

k1 = clean(K1_CT)
k2 = clean(K2_CT)
k3 = clean(K3_CT)

print(f"\nK1 CT: {len(k1)} chars")
print(f"K2 CT: {len(k2)} chars")
print(f"K3 CT: {len(k3)} chars")
print(f"K4 CT: {CT_LEN} chars")

# Combined K1+K2+K3
k123 = k1 + k2 + k3
print(f"\nK1+K2+K3 combined: {len(k123)} chars")
print(f"K1+K2+K3+K4 total: {len(k123) + CT_LEN} chars")

# ══════════════════════════════════════════════════════════════════════════
# STEP 1: Count and locate NDYAHR letters in K1+K2+K3
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 78)
print("STEP 1: NDYAHR Letter Analysis in K1+K2+K3")
print("=" * 78)

NDYAHR = set("NDYAHR")
NDYAHR_str = "NDYAHR"

# Count per letter
for ch in NDYAHR_str:
    positions = [i for i, c in enumerate(k123) if c == ch]
    print(f"  {ch}: {len(positions)} occurrences")

# Count per section
for label, section in [("K1", k1), ("K2", k2), ("K3", k3), ("K4", CT)]:
    ndyahr_count = sum(1 for c in section if c in NDYAHR)
    total = len(section)
    pct = 100.0 * ndyahr_count / total
    print(f"  {label}: {ndyahr_count}/{total} NDYAHR chars ({pct:.1f}%)")

# Total NDYAHR in K1+K2+K3
ndyahr_positions = [i for i, c in enumerate(k123) if c in NDYAHR]
ndyahr_count = len(ndyahr_positions)
print(f"\n  Total NDYAHR in K1+K2+K3: {ndyahr_count}/{len(k123)} ({100.0*ndyahr_count/len(k123):.1f}%)")

# Residue
residue = ''.join(c for c in k123 if c not in NDYAHR)
print(f"  Residue (non-NDYAHR): {len(residue)} chars")
print(f"  Residue IC: {ic(residue):.6f}")
print(f"  Random IC: {1/26:.6f}")
print(f"  English IC: 0.0667")

# Key length checks
for target in [73, 97, 24, 48, 146, 194, 365, 434, 771, 868]:
    if len(residue) == target:
        print(f"  *** RESIDUE LENGTH = {target} ***")

# Check division relationships
print(f"\n  Residue / 73 = {len(residue) / 73:.4f}")
print(f"  Residue / 97 = {len(residue) / 97:.4f}")
print(f"  Residue mod 73 = {len(residue) % 73}")
print(f"  Residue mod 97 = {len(residue) % 97}")
print(f"  Residue mod 31 = {len(residue) % 31}")
print(f"  Residue mod 14 = {len(residue) % 14}")
print(f"  Residue mod 24 = {len(residue) % 24}")

# ══════════════════════════════════════════════════════════════════════════
# STEP 2: ALL subsets of {N,D,Y,A,H,R} → check for K4-relevant lengths
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 78)
print("STEP 2: All subsets of NDYAHR → residue lengths")
print("=" * 78)

TARGET_LENGTHS = {73, 97, 24, 48, 146, 194, 434, 771, 868}

for size in range(1, 7):
    for subset in combinations("NDYAHR", size):
        subset_set = set(subset)
        res = ''.join(c for c in k123 if c not in subset_set)
        subset_str = ''.join(subset)
        interesting = ""
        if len(res) in TARGET_LENGTHS:
            interesting = f" *** TARGET LENGTH ***"
        if len(res) % 73 == 0:
            interesting += f" (div by 73: {len(res)//73})"
        if len(res) % 97 == 0:
            interesting += f" (div by 97: {len(res)//97})"
        if interesting:
            print(f"  Remove {{{subset_str}}}: residue = {len(res)} chars{interesting}")

# Also show all lengths for full set and key subsets
for subset_str in ["NDYAHR", "DYAHR", "YAR", "ENDYAHR", "NDY", "AHR", "NDYAR", "NDYAH"]:
    subset_set = set(subset_str)
    res = ''.join(c for c in k123 if c not in subset_set)
    print(f"  Remove {{{subset_str}}}: residue = {len(res)} chars (mod97={len(res)%97}, mod73={len(res)%73})")

# Also check removal from individual sections
print("\n  Per-section removal of NDYAHR:")
for label, section in [("K1", k1), ("K2", k2), ("K3", k3)]:
    res_section = ''.join(c for c in section if c not in NDYAHR)
    print(f"    {label}: {len(section)} - {len(section)-len(res_section)} = {len(res_section)} chars")

# ══════════════════════════════════════════════════════════════════════════
# STEP 3: Use residue as running key for K4
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 78)
print("STEP 3: Residue as running key for K4")
print("=" * 78)

KEYWORDS = ["KRYPTOS", "DEFECTOR", "PALIMPSEST", "ABSCISSA", "KOMPASS", "COLOPHON"]

# 3a: Full NDYAHR removal residue as running key
print("\n--- 3a: Full NDYAHR-removed residue as running key ---")
best_3a = 0
for offset in range(min(len(residue) - CT_LEN + 1, 200)):
    key_slice = residue[offset:offset + CT_LEN]
    if len(key_slice) < CT_LEN:
        break
    for alph_name, aidx in [("AZ", AZ_IDX), ("KA", KA_IDX)]:
        alphabet = AZ if alph_name == "AZ" else KA
        ct_nums = to_nums(CT, aidx)
        key_nums = to_nums(key_slice, aidx)
        for var_name, decrypt_fn in VARIANTS.items():
            pt_nums = decrypt_fn(ct_nums, key_nums)
            pt_text = to_text(pt_nums, alphabet)
            anchored, free = score_pt(pt_text)
            s = record(f"3a:NDYAHR_residue/{alph_name}/{var_name}/off={offset}", pt_text, anchored, free)
            best_3a = max(best_3a, s)
            total_configs += 1
print(f"  Best 3a: {best_3a}/24 ({total_configs} configs)")

# 3b: NDYAHR-only letters as running key
print("\n--- 3b: NDYAHR-only letters as running key ---")
ndyahr_chars = ''.join(c for c in k123 if c in NDYAHR)
best_3b = 0
for offset in range(min(len(ndyahr_chars) - CT_LEN + 1, 50)):
    key_slice = ndyahr_chars[offset:offset + CT_LEN]
    if len(key_slice) < CT_LEN:
        break
    for alph_name, aidx in [("AZ", AZ_IDX), ("KA", KA_IDX)]:
        alphabet = AZ if alph_name == "AZ" else KA
        ct_nums = to_nums(CT, aidx)
        key_nums = to_nums(key_slice, aidx)
        for var_name, decrypt_fn in VARIANTS.items():
            pt_nums = decrypt_fn(ct_nums, key_nums)
            pt_text = to_text(pt_nums, alphabet)
            anchored, free = score_pt(pt_text)
            s = record(f"3b:NDYAHR_only/{alph_name}/{var_name}/off={offset}", pt_text, anchored, free)
            best_3b = max(best_3b, s)
            total_configs += 1
print(f"  Best 3b: {best_3b}/24 ({total_configs} configs)")

# 3c: Try decrypting residue directly (not as running key, but as a ciphertext)
print("\n--- 3c: Decrypt residue directly with keywords ---")
best_3c = 0
for kw in KEYWORDS:
    for alph_name, aidx in [("AZ", AZ_IDX), ("KA", KA_IDX)]:
        alphabet = AZ if alph_name == "AZ" else KA
        # Use first 97 chars of residue as ciphertext
        ct_portion = residue[:CT_LEN] if len(residue) >= CT_LEN else residue
        ct_nums = to_nums(ct_portion, aidx)
        key_text = extend_key(kw, len(ct_portion))
        key_nums = to_nums(key_text, aidx)
        for var_name, decrypt_fn in VARIANTS.items():
            pt_nums = decrypt_fn(ct_nums, key_nums)
            pt_text = to_text(pt_nums, alphabet)
            anchored, free = score_pt(pt_text)
            s = record(f"3c:residue_decrypt/{kw}/{alph_name}/{var_name}", pt_text, anchored, free)
            best_3c = max(best_3c, s)
            total_configs += 1
print(f"  Best 3c: {best_3c}/24")

# 3d: Autokey with residue
print("\n--- 3d: Autokey (PT-autokey) with residue as primer ---")
best_3d = 0
for primer_len in [7, 13, 24, 31, 73]:
    primer = residue[:primer_len]
    for alph_name, aidx in [("AZ", AZ_IDX), ("KA", KA_IDX)]:
        alphabet = AZ if alph_name == "AZ" else KA
        ct_nums = to_nums(CT, aidx)
        # PT-autokey: key[i] = primer[i] for i < primer_len, else PT[i-primer_len]
        pt_result = []
        key_stream = list(to_nums(primer, aidx))
        for i in range(CT_LEN):
            if i < len(key_stream):
                k = key_stream[i]
            else:
                k = pt_result[i - primer_len]
            for var_name, decrypt_fn in VARIANTS.items():
                p = decrypt_fn([ct_nums[i]], [k])[0]
                if var_name == "Vig":  # only do one variant for autokey internal
                    pt_result.append(p)
            # Actually, redo this properly for each variant
        # Reset and do properly
        for var_name in ["Vig", "Beau", "VBeau"]:
            pt_result = []
            key_vals = list(to_nums(primer, aidx))
            for i in range(CT_LEN):
                if i < len(key_vals):
                    k = key_vals[i]
                else:
                    k = pt_result[i - primer_len]
                c = ct_nums[i]
                if var_name == "Vig":
                    p = (c - k) % 26
                elif var_name == "Beau":
                    p = (k - c) % 26
                else:
                    p = (c + k) % 26
                pt_result.append(p)
            pt_text = to_text(pt_result, alphabet)
            anchored, free = score_pt(pt_text)
            s = record(f"3d:autokey/primer={primer_len}/{alph_name}/{var_name}", pt_text, anchored, free)
            best_3d = max(best_3d, s)
            total_configs += 1
print(f"  Best 3d: {best_3d}/24")

# ══════════════════════════════════════════════════════════════════════════
# STEP 4: Statistical analysis
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 78)
print("STEP 4: Statistical Analysis")
print("=" * 78)

# Expected NDYAHR frequency in English
# N: 6.75%, D: 4.25%, Y: 1.97%, A: 8.17%, H: 6.09%, R: 5.99%
# Total expected: ~33.2%
ENGLISH_FREQ = {"N": 0.0675, "D": 0.0425, "Y": 0.0197, "A": 0.0817, "H": 0.0609, "R": 0.0599}
expected_pct = sum(ENGLISH_FREQ.values()) * 100
actual_pct = 100.0 * ndyahr_count / len(k123)
print(f"\n  Expected NDYAHR in English text: {expected_pct:.1f}%")
print(f"  Actual NDYAHR in K1+K2+K3 CT: {actual_pct:.1f}%")
print(f"  Ratio actual/expected: {actual_pct/expected_pct:.3f}")

# Per-letter analysis
print("\n  Per-letter comparison:")
for ch in NDYAHR_str:
    actual = sum(1 for c in k123 if c == ch)
    exp = ENGLISH_FREQ.get(ch, 0) * len(k123)
    ratio = actual / exp if exp > 0 else 0
    print(f"    {ch}: actual={actual}, expected={exp:.1f}, ratio={ratio:.2f}")

# IC of various derived texts
print(f"\n  IC of K1+K2+K3 CT: {ic(k123):.6f}")
print(f"  IC of NDYAHR-removed residue: {ic(residue):.6f}")
print(f"  IC of NDYAHR-only chars: {ic(ndyahr_chars):.6f}")

# Distribution: are NDYAHR letters clustered?
print("\n  NDYAHR distribution across sections:")
for label, start, end in [("K1", 0, len(k1)), ("K2", len(k1), len(k1)+len(k2)), ("K3", len(k1)+len(k2), len(k123))]:
    section = k123[start:end]
    count = sum(1 for c in section if c in NDYAHR)
    pct = 100.0 * count / len(section)
    print(f"    {label} ({len(section)} chars): {count} NDYAHR = {pct:.1f}%")

# Gap analysis: distances between consecutive NDYAHR letters
gaps = []
for i in range(1, len(ndyahr_positions)):
    gaps.append(ndyahr_positions[i] - ndyahr_positions[i-1])
if gaps:
    print(f"\n  NDYAHR inter-letter gaps: min={min(gaps)}, max={max(gaps)}, mean={sum(gaps)/len(gaps):.1f}, median={sorted(gaps)[len(gaps)//2]}")

# ══════════════════════════════════════════════════════════════════════════
# STEP 5: Vigenere expected frequency check
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 78)
print("STEP 5: Expected NDYAHR Frequency in Vigenere CT")
print("=" * 78)

# For Vigenere with keyword K of length L applied to English plaintext,
# the expected CT frequency of letter C is:
# P(C) = sum over all key positions j: (1/L) * P_english(C - K[j] mod 26)
# For a keyword like PALIMPSEST or ABSCISSA, the CT distribution is flattened
# toward uniform (1/26 = 3.85%). The NDYAHR total should be close to 6*3.85% = 23.1%.

print("  Note: For Vigenere CT, letter frequencies are flattened toward uniform (1/26).")
print(f"  Uniform NDYAHR expected: {6/26*100:.1f}%")
print(f"  Actual in combined K1+K2 (Vig CT): {100.0*sum(1 for c in (k1+k2) if c in NDYAHR)/len(k1+k2):.1f}%")
print(f"  Actual in K3 (transposition, same as PT): {100.0*sum(1 for c in k3 if c in NDYAHR)/len(k3):.1f}%")

# ══════════════════════════════════════════════════════════════════════════
# STEP 6: Grid-based displacement interpretation
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 78)
print("STEP 6: Grid-Based Displacement on 28x31 Grid")
print("=" * 78)

# Build the 28x31 grid from the full sculpture text (K1+K2+K3+K4)
# Using the corrected text (BQCRTBJ -> BQCETBJ, squeezed ? removed)
FULL_CT_RAW = (
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ"
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE"
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA"
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI"
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX"
    "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ"
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP"
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA"
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAE"
    "WMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR"
    "EIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI"
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT"
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR"
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO"
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP"
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
)

# Apply corrections
corrected = FULL_CT_RAW.replace("BQCRTBJ", "BQCETBJ", 1)
# Remove squeezed ? (the third one, at GGTEZ?F)
corrected = corrected.replace("GGTEZ?F", "GGTEZF", 1)

assert len(corrected) == 868, f"Grid text should be 868 chars, got {len(corrected)}"

WIDTH = 31
NROWS = 28

# Build grid
grid = []
for r in range(NROWS):
    row = corrected[r*WIDTH:(r+1)*WIDTH]
    grid.append(row)

# K4 starts at row 24, col 27 approximately. Let's find it.
flat = corrected.replace("?", "")  # remove remaining ?s for search
# Actually the ?s are positional markers. Let's work with them.

# Find K1+K2+K3 region (rows 0-23 approx, i.e. before K4)
# K4 is in the last 4 rows (rows 24-27)
# The K3/K4 boundary is at DOHW|OBKR -- around row 24
# Let's identify K1+K2+K3 region in the grid

# K1 starts row 0 col 0
# K3 ends with ...ECDMRIPFEIMEHNLSSTTRTVDOHW
# Then K4: OBKRUOXOGHULBSOLIFBB...

# Find NDYAHR positions in grid (all rows, not just K1+K2+K3)
ndyahr_grid_positions = []
for r in range(NROWS):
    for c in range(WIDTH):
        ch = grid[r][c] if c < len(grid[r]) else ''
        if ch in NDYAHR:
            ndyahr_grid_positions.append((r, c, ch))

print(f"\n  Total NDYAHR in 28x31 grid: {len(ndyahr_grid_positions)}")
# Limit to K1+K2+K3 region (rows 0-23 plus start of row 24)
# K4 starts at approximately position 771 in the flat text
# Row 24: ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR
# The ? here and then OBKR = start of K4
# So K1+K2+K3 occupy rows 0-23 and the first part of row 24

# Direction vectors
DIR_VECTORS = {
    "N": (0, -1), "D": (1, 0), "Y": (0, -1), "A": (0, -1), "H": (1, 0), "R": (-1, -1)
}
# N=left(W), D=right(E), Y=up(N), A=up(N), H=right(E), R=up-left(NW)
LETTER_DIRS = {"N": (-1, 0), "D": (1, 0), "Y": (0, -1), "A": (0, -1), "H": (1, 0), "R": (-1, -1)}

# Apply displacements: shift each NDYAHR letter to its displaced position
print("\n  Applying NDYAHR grid displacements...")
displaced_grid = [list(row) for row in grid]  # mutable copy

shifts_applied = 0
for r, c, ch in ndyahr_grid_positions:
    if ch in LETTER_DIRS:
        dc, dr = LETTER_DIRS[ch]
        new_r = r + dr
        new_c = c + dc
        if 0 <= new_r < NROWS and 0 <= new_c < WIDTH:
            # Swap the letter with its target
            old_target = displaced_grid[new_r][new_c]
            displaced_grid[new_r][new_c] = ch
            displaced_grid[r][c] = old_target
            shifts_applied += 1

print(f"  Shifts applied: {shifts_applied}")

# Read the displaced grid and extract K4 region
displaced_flat = ''.join(''.join(row) for row in displaced_grid)
# Extract what would be K4 region (last ~97 chars of the letter stream)
displaced_letters = ''.join(c for c in displaced_flat if c.isalpha())
k4_region = displaced_letters[-CT_LEN:]
print(f"  Displaced K4 region: {k4_region[:50]}...")

# Try decrypting displaced K4 region
best_6 = 0
for kw in KEYWORDS:
    for alph_name, aidx in [("AZ", AZ_IDX), ("KA", KA_IDX)]:
        alphabet = AZ if alph_name == "AZ" else KA
        ct_nums = to_nums(k4_region, aidx)
        key_text = extend_key(kw, CT_LEN)
        key_nums = to_nums(key_text, aidx)
        for var_name, decrypt_fn in VARIANTS.items():
            pt_nums = decrypt_fn(ct_nums, key_nums)
            pt_text = to_text(pt_nums, alphabet)
            anchored, free = score_pt(pt_text)
            s = record(f"6:displaced_grid/{kw}/{alph_name}/{var_name}", pt_text, anchored, free)
            best_6 = max(best_6, s)
            total_configs += 1
print(f"  Best displaced grid decrypt: {best_6}/24")

# Also try REVERSE directions (RHAYDN)
print("\n  Trying REVERSE displacements (RHAYDN)...")
REVERSE_DIRS = {ch: (-dc, -dr) for ch, (dc, dr) in LETTER_DIRS.items()}

rev_grid = [list(row) for row in grid]
rev_shifts = 0
for r, c, ch in ndyahr_grid_positions:
    if ch in REVERSE_DIRS:
        dc, dr = REVERSE_DIRS[ch]
        new_r = r + dr
        new_c = c + dc
        if 0 <= new_r < NROWS and 0 <= new_c < WIDTH:
            old_target = rev_grid[new_r][new_c]
            rev_grid[new_r][new_c] = ch
            rev_grid[r][c] = old_target
            rev_shifts += 1

rev_flat = ''.join(''.join(row) for row in rev_grid)
rev_letters = ''.join(c for c in rev_flat if c.isalpha())
rev_k4_region = rev_letters[-CT_LEN:]

best_6r = 0
for kw in KEYWORDS:
    for alph_name, aidx in [("AZ", AZ_IDX), ("KA", KA_IDX)]:
        alphabet = AZ if alph_name == "AZ" else KA
        ct_nums = to_nums(rev_k4_region, aidx)
        key_text = extend_key(kw, CT_LEN)
        key_nums = to_nums(key_text, aidx)
        for var_name, decrypt_fn in VARIANTS.items():
            pt_nums = decrypt_fn(ct_nums, key_nums)
            pt_text = to_text(pt_nums, alphabet)
            anchored, free = score_pt(pt_text)
            s = record(f"6r:reversed_grid/{kw}/{alph_name}/{var_name}", pt_text, anchored, free)
            best_6r = max(best_6r, s)
            total_configs += 1
print(f"  Best reversed grid decrypt: {best_6r}/24")

# ══════════════════════════════════════════════════════════════════════════
# STEP 7: Subset removal → K4 length check
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 78)
print("STEP 7: Subset removal → K4-relevant lengths (comprehensive)")
print("=" * 78)

# Check ALL 63 non-empty subsets of {N,D,Y,A,H,R}
for size in range(1, 7):
    for subset in combinations("NDYAHR", size):
        subset_set = set(subset)
        subset_str = ''.join(sorted(subset))

        # Remove from full sculpture text (K1+K2+K3+K4)
        k1234 = k123 + CT
        res_full = ''.join(c for c in k1234 if c not in subset_set)

        # Remove from K1+K2+K3 only
        res_k123 = ''.join(c for c in k123 if c not in subset_set)

        # Check for interesting lengths
        for res, label in [(res_full, "K1234"), (res_k123, "K123")]:
            if len(res) in {73, 97, 146, 194, 219, 292, 365, 438, 584, 730, 771, 868}:
                print(f"  Remove {{{subset_str}}} from {label}: {len(res)} chars ***")
            if len(res) % 73 == 0:
                print(f"  Remove {{{subset_str}}} from {label}: {len(res)} = {len(res)//73} x 73")
            if len(res) % 97 == 0:
                print(f"  Remove {{{subset_str}}} from {label}: {len(res)} = {len(res)//97} x 97")

# ══════════════════════════════════════════════════════════════════════════
# STEP 8: K1+K2+K3 CT sections as separate running keys
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 78)
print("STEP 8: NDYAHR-filtered sections as running key")
print("=" * 78)

# Remove NDYAHR from each section separately
k1_filtered = ''.join(c for c in k1 if c not in NDYAHR)
k2_filtered = ''.join(c for c in k2 if c not in NDYAHR)
k3_filtered = ''.join(c for c in k3 if c not in NDYAHR)

print(f"  K1 filtered: {len(k1_filtered)} chars (from {len(k1)})")
print(f"  K2 filtered: {len(k2_filtered)} chars (from {len(k2)})")
print(f"  K3 filtered: {len(k3_filtered)} chars (from {len(k3)})")

best_8 = 0
for label, key_source in [("K1f", k1_filtered), ("K2f", k2_filtered), ("K3f", k3_filtered),
                            ("K123f", residue), ("K12f", k1_filtered+k2_filtered),
                            ("K23f", k2_filtered+k3_filtered)]:
    if len(key_source) < CT_LEN:
        key_text = extend_key(key_source, CT_LEN)
    else:
        key_text = key_source[:CT_LEN]

    for alph_name, aidx in [("AZ", AZ_IDX), ("KA", KA_IDX)]:
        alphabet = AZ if alph_name == "AZ" else KA
        ct_nums = to_nums(CT, aidx)
        key_nums = to_nums(key_text, aidx)
        for var_name, decrypt_fn in VARIANTS.items():
            pt_nums = decrypt_fn(ct_nums, key_nums)
            pt_text = to_text(pt_nums, alphabet)
            anchored, free = score_pt(pt_text)
            s = record(f"8:{label}/{alph_name}/{var_name}", pt_text, anchored, free)
            best_8 = max(best_8, s)
            total_configs += 1

print(f"  Best filtered running key: {best_8}/24")

# ══════════════════════════════════════════════════════════════════════════
# STEP 9: Position-based extraction (keep only NDYAHR positions)
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 78)
print("STEP 9: NDYAHR positions as extraction mask")
print("=" * 78)

# Use NDYAHR positions in K1+K2+K3 as a mask to extract from other texts
# Extract from K4
print(f"\n  NDYAHR positions in K1+K2+K3: {len(ndyahr_positions)} positions")
# These positions are in the K123 text. Map to K4 via modular arithmetic.
ndyahr_mod97 = sorted(set(p % CT_LEN for p in ndyahr_positions))
print(f"  NDYAHR positions mod 97: {len(ndyahr_mod97)} unique values")
print(f"  Positions: {ndyahr_mod97[:20]}...")

# Extract from K4 at these positions
extracted = ''.join(CT[p] for p in ndyahr_mod97 if p < CT_LEN)
print(f"  K4 chars at NDYAHR mod-97 positions: {extracted}")
print(f"  Length: {len(extracted)}")
print(f"  IC: {ic(extracted):.6f}")

# ══════════════════════════════════════════════════════════════════════════
# STEP 10: Reverse — NDYAHR in K4 as key
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 78)
print("STEP 10: NDYAHR in K4 itself")
print("=" * 78)

k4_ndyahr = [(i, c) for i, c in enumerate(CT) if c in NDYAHR]
k4_ndyahr_chars = ''.join(c for _, c in k4_ndyahr)
k4_non_ndyahr = ''.join(c for c in CT if c not in NDYAHR)
print(f"  K4 NDYAHR count: {len(k4_ndyahr)}")
print(f"  K4 NDYAHR chars: {k4_ndyahr_chars}")
print(f"  K4 non-NDYAHR: {len(k4_non_ndyahr)} chars")
print(f"  K4 non-NDYAHR = {k4_non_ndyahr}")
if len(k4_non_ndyahr) == 73:
    print(f"  *** K4 non-NDYAHR LENGTH = 73 ***")

# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════

elapsed = time.time() - t0

print("\n" + "=" * 78)
print("SUMMARY")
print("=" * 78)
print(f"  Total configs tested: {total_configs:,}")
print(f"  Elapsed: {elapsed:.1f}s")
print(f"  Best overall score: {best_overall_score}/24")
print(f"  Best config: {best_overall_config}")

if results_log:
    print(f"\n  Results above store threshold:")
    for r in sorted(results_log, key=lambda x: -max(x['anchored_score'], x['free_score'])):
        best_s = max(r['anchored_score'], r['free_score'])
        print(f"    {best_s}/24: {r['label']}")

# Key findings summary
print(f"\n  KEY FINDINGS:")
print(f"    K1+K2+K3 length: {len(k123)}")
print(f"    NDYAHR count in K1+K2+K3: {ndyahr_count} ({actual_pct:.1f}%)")
print(f"    Residue length: {len(residue)}")
print(f"    K4 NDYAHR count: {len(k4_ndyahr)}")
print(f"    K4 non-NDYAHR length: {len(k4_non_ndyahr)}")

if best_overall_score <= NOISE_FLOOR:
    verdict = f"NOISE -- {best_overall_score}/24"
elif best_overall_score < STORE_THRESHOLD:
    verdict = f"ABOVE NOISE -- {best_overall_score}/24"
else:
    verdict = f"INTERESTING -- {best_overall_score}/24"

print(f"\n  VERDICT: {verdict}")

# Save artifact
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.makedirs(os.path.join(_PROJECT_ROOT, "results"), exist_ok=True)
artifact = {
    "experiment": "E-NDYAHR-K123CT-UNIFIED",
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "description": "NDYAHR displacement on K1+K2+K3 ciphertext as unified block",
    "k123_length": len(k123),
    "ndyahr_count": ndyahr_count,
    "ndyahr_pct": actual_pct,
    "residue_length": len(residue),
    "k4_ndyahr_count": len(k4_ndyahr),
    "k4_non_ndyahr_length": len(k4_non_ndyahr),
    "total_configs": total_configs,
    "elapsed_seconds": elapsed,
    "best_overall_score": best_overall_score,
    "best_overall_config": best_overall_config,
    "results_above_threshold": results_log,
    "residue_ic": ic(residue),
    "verdict": verdict,
}
artifact_path = os.path.join(_PROJECT_ROOT, "results", "e_ndyahr_k123ct_unified.json")
with open(artifact_path, "w") as f:
    json.dump(artifact, f, indent=2)
print(f"\n  Artifact: {artifact_path}")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/k3_continuity/e_ndyahr_k123ct_unified.py")
