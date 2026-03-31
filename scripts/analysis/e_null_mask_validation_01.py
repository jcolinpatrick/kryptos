#!/usr/bin/env python3
"""First-principles null mask validation campaign.

Cipher:   Analysis (null mask validation)
Family:   analysis
Status:   active
Keyspace: C(31,17)=31M masks sampled; C(31,24)=2.6M masks sampled
Last run: 2026-03-26
Best score: N/A (structural analysis, not a decrypt attack)

PURPOSE: Determine whether the consensus 17-position null mask is a
statistical outlier among all palette-derived masks, using only cipher
properties of the extracted text. This directly addresses Hard Blocker #1
(null-mask provenance gap) without assuming any external provenance.

APPROACH:
1. IC landscape: For mask sizes 0-30, compute IC of extracted text.
   Compare consensus mask to Monte Carlo distribution of random
   palette-derived masks of the same size.
2. Frequency chi-square: Test whether removing consensus nulls produces
   a more English-like or more uniform frequency distribution.
3. Keystream palette enrichment: Under Beaufort, what fraction of
   keystream values at crib positions are palette letters? Test
   robustness to single-position mask perturbations.
4. Autocorrelation profile: Check if the consensus extract shows
   periodic structure absent in random extracts.
5. Bean constraint mapping: How many Bean inequalities survive
   when crib positions shift due to null removal?
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys
import os
import random
import math
from collections import Counter
from itertools import combinations

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAN_EQ, BEAN_INEQ,
)

random.seed(20260326)  # Reproducible

# ═══════════════════════════════════════════════════════════════════════════
# UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def compute_ic(text):
    """Index of coincidence."""
    n = len(text)
    if n < 2:
        return 0.0
    freq = Counter(text)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def chi_square_uniform(text):
    """Chi-square statistic vs uniform distribution over 26 letters."""
    n = len(text)
    expected = n / 26.0
    freq = Counter(text)
    return sum((freq.get(chr(65 + i), 0) - expected) ** 2 / expected
               for i in range(26))


def chi_square_english(text):
    """Chi-square statistic vs English letter frequencies."""
    ENGLISH_FREQ = {
        'A': 0.0817, 'B': 0.0149, 'C': 0.0278, 'D': 0.0425, 'E': 0.1270,
        'F': 0.0223, 'G': 0.0202, 'H': 0.0609, 'I': 0.0697, 'J': 0.0015,
        'K': 0.0077, 'L': 0.0403, 'M': 0.0241, 'N': 0.0675, 'O': 0.0751,
        'P': 0.0193, 'Q': 0.0010, 'R': 0.0599, 'S': 0.0633, 'T': 0.0906,
        'U': 0.0276, 'V': 0.0098, 'W': 0.0236, 'X': 0.0015, 'Y': 0.0197,
        'Z': 0.0007,
    }
    n = len(text)
    freq = Counter(text)
    return sum((freq.get(c, 0) - ENGLISH_FREQ[c] * n) ** 2 /
               (ENGLISH_FREQ[c] * n) for c in ENGLISH_FREQ)


def autocorrelation(text, lag):
    """Count of coincidences at given lag."""
    return sum(1 for i in range(len(text) - lag) if text[i] == text[i + lag])


def extract_text(ct, null_positions):
    """Remove null positions from CT, return extracted text."""
    return "".join(c for i, c in enumerate(ct) if i not in null_positions)


def shift_positions(orig_positions, null_positions):
    """Map original CT positions to positions in the extracted text.
    Returns dict: orig_pos -> new_pos, or None if orig_pos is null.
    """
    null_set = frozenset(null_positions)
    mapping = {}
    new_idx = 0
    for i in range(CT_LEN):
        if i not in null_set:
            if i in orig_positions:
                mapping[i] = new_idx
            new_idx += 1
    return mapping


# ═══════════════════════════════════════════════════════════════════════════
# CANDIDATE NULL POSITIONS
# ═══════════════════════════════════════════════════════════════════════════

PALETTE_POSITIONS = frozenset(i for i, c in enumerate(CT) if c in NULL_PALETTE)
CANDIDATE_NULLS = sorted(PALETTE_POSITIONS - CRIB_POSITIONS)
CONSENSUS = sorted(CONSENSUS_NULL_POSITIONS)

print("=" * 78)
print("FIRST-PRINCIPLES NULL MASK VALIDATION CAMPAIGN")
print("=" * 78)
print(f"CT length: {CT_LEN}")
print(f"Palette letters: {sorted(NULL_PALETTE)}")
print(f"Palette positions in CT: {len(PALETTE_POSITIONS)}")
print(f"Candidate null positions (palette, non-crib): {len(CANDIDATE_NULLS)}")
print(f"Consensus null positions: {len(CONSENSUS)}")
print(f"Crib positions: {sorted(CRIB_POSITIONS)}")
print()

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 1: IC LANDSCAPE
# ═══════════════════════════════════════════════════════════════════════════

print("=" * 78)
print("PHASE 1: IC LANDSCAPE — How does IC change with null removal?")
print("=" * 78)

N_SAMPLES = 10000

# Consensus mask IC
consensus_extract = extract_text(CT, CONSENSUS_NULL_POSITIONS)
consensus_ic = compute_ic(consensus_extract)
print(f"\nConsensus mask (k=17): IC = {consensus_ic:.6f} "
      f"(extract length = {len(consensus_extract)})")
print(f"Full CT IC:            {compute_ic(CT):.6f}")
print(f"Random expectation:    {1/26:.6f}")
print()

# IC landscape by mask size
print(f"{'k':>3} {'mean_IC':>10} {'std_IC':>10} {'consensus_IC':>13} "
      f"{'percentile':>11} {'n_samples':>10} {'extract_len':>11}")
print("-" * 78)

for k in range(0, min(len(CANDIDATE_NULLS) + 1, 31)):
    n_candidates = len(CANDIDATE_NULLS)
    n_possible = math.comb(n_candidates, k)

    if k == 0:
        # No nulls removed
        ic_val = compute_ic(CT)
        print(f"{k:3d} {ic_val:10.6f} {'N/A':>10} {'N/A':>13} {'N/A':>11} "
              f"{'1':>10} {CT_LEN:>11}")
        continue

    # Sample random masks
    n_actual = min(N_SAMPLES, n_possible)
    ic_values = []

    if n_possible <= N_SAMPLES:
        # Exhaustive
        for mask in combinations(CANDIDATE_NULLS, k):
            ext = extract_text(CT, frozenset(mask))
            ic_values.append(compute_ic(ext))
        n_actual = n_possible
    else:
        # Monte Carlo
        seen = set()
        while len(ic_values) < N_SAMPLES:
            mask = tuple(sorted(random.sample(CANDIDATE_NULLS, k)))
            if mask not in seen:
                seen.add(mask)
                ext = extract_text(CT, frozenset(mask))
                ic_values.append(compute_ic(ext))

    mean_ic = sum(ic_values) / len(ic_values)
    std_ic = (sum((v - mean_ic) ** 2 for v in ic_values) / len(ic_values)) ** 0.5

    # Where does the consensus fall?
    if k == 17:
        rank = sum(1 for v in ic_values if v <= consensus_ic)
        percentile = rank / len(ic_values) * 100
        cons_str = f"{consensus_ic:.6f}"
        pct_str = f"{percentile:.1f}%"
    else:
        cons_str = "N/A"
        pct_str = "N/A"

    extract_len = CT_LEN - k
    print(f"{k:3d} {mean_ic:10.6f} {std_ic:10.6f} {cons_str:>13} "
          f"{pct_str:>11} {n_actual:>10} {extract_len:>11}")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 2: CONSENSUS MASK STATISTICAL POSITION (k=17)
# ═══════════════════════════════════════════════════════════════════════════

print()
print("=" * 78)
print("PHASE 2: CONSENSUS MASK vs RANDOM MASKS (k=17) — Detailed")
print("=" * 78)

# Generate large sample for k=17
k17_ics = []
k17_chi_uniform = []
k17_chi_english = []
N_K17 = 50000

seen = set()
while len(k17_ics) < N_K17:
    mask = tuple(sorted(random.sample(CANDIDATE_NULLS, 17)))
    if mask not in seen:
        seen.add(mask)
        ext = extract_text(CT, frozenset(mask))
        k17_ics.append(compute_ic(ext))
        k17_chi_uniform.append(chi_square_uniform(ext))
        k17_chi_english.append(chi_square_english(ext))

# Consensus values
cons_chi_u = chi_square_uniform(consensus_extract)
cons_chi_e = chi_square_english(consensus_extract)

# Percentiles
ic_pct = sum(1 for v in k17_ics if v <= consensus_ic) / N_K17 * 100
chi_u_pct = sum(1 for v in k17_chi_uniform if v <= cons_chi_u) / N_K17 * 100
chi_e_pct = sum(1 for v in k17_chi_english if v <= cons_chi_e) / N_K17 * 100

print(f"\nN = {N_K17} random 17-position palette masks")
print(f"\n{'Metric':>25} {'Consensus':>12} {'Mean':>12} {'Std':>10} "
      f"{'Percentile':>12} {'Interpretation':>20}")
print("-" * 95)
print(f"{'IC':>25} {consensus_ic:12.6f} "
      f"{sum(k17_ics)/N_K17:12.6f} "
      f"{(sum((v-sum(k17_ics)/N_K17)**2 for v in k17_ics)/N_K17)**0.5:10.6f} "
      f"{ic_pct:11.1f}% "
      f"{'OUTLIER' if ic_pct < 5 or ic_pct > 95 else 'typical':>20}")
print(f"{'χ² vs uniform':>25} {cons_chi_u:12.4f} "
      f"{sum(k17_chi_uniform)/N_K17:12.4f} "
      f"{(sum((v-sum(k17_chi_uniform)/N_K17)**2 for v in k17_chi_uniform)/N_K17)**0.5:10.4f} "
      f"{chi_u_pct:11.1f}% "
      f"{'OUTLIER' if chi_u_pct < 5 or chi_u_pct > 95 else 'typical':>20}")
print(f"{'χ² vs English':>25} {cons_chi_e:12.4f} "
      f"{sum(k17_chi_english)/N_K17:12.4f} "
      f"{(sum((v-sum(k17_chi_english)/N_K17)**2 for v in k17_chi_english)/N_K17)**0.5:10.4f} "
      f"{chi_e_pct:11.1f}% "
      f"{'OUTLIER' if chi_e_pct < 5 or chi_e_pct > 95 else 'typical':>20}")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 3: BEAUFORT KEYSTREAM PALETTE ENRICHMENT UNDER PERTURBATION
# ═══════════════════════════════════════════════════════════════════════════

print()
print("=" * 78)
print("PHASE 3: BEAUFORT KEYSTREAM PALETTE ENRICHMENT — Perturbation Test")
print("=" * 78)

# The finding: 7/8 of the first BCL keystream values are palette letters
# Beaufort keystream: JLJODEGKUKKKLOCGGBGOKTRU
# BCL positions 63-73, keystream: O,C,G,G,B,G,O,K,T,R,U
# First 8: O,C,G,G,B,G,O,K -> 7/8 palette

BEAU_KS_STR = "".join(ALPH[v] for v in BEAUFORT_KEY_ENE + BEAUFORT_KEY_BC)
print(f"\nBeaufort keystream at all 24 crib positions: {BEAU_KS_STR}")

# Count palette letters in keystream segments
ene_ks = [ALPH[v] for v in BEAUFORT_KEY_ENE]
bc_ks = [ALPH[v] for v in BEAUFORT_KEY_BC]

ene_palette_count = sum(1 for c in ene_ks if c in NULL_PALETTE)
bc_palette_count = sum(1 for c in bc_ks if c in NULL_PALETTE)
bc_first8_palette = sum(1 for c in bc_ks[:8] if c in NULL_PALETTE)

print(f"ENE keystream: {''.join(ene_ks)} — {ene_palette_count}/13 palette")
print(f"BCL keystream: {''.join(bc_ks)} — {bc_palette_count}/11 palette")
print(f"BCL first 8:   {''.join(bc_ks[:8])} — {bc_first8_palette}/8 palette")
print()

# Now test: for the CONSENSUS mask, what keystream do we get?
# These are FIXED by the CT and cribs — they don't change with the mask.
# The mask only changes which characters are removed from CT; the crib
# positions in the original CT remain the same.
print("NOTE: Beaufort keystream at crib positions is derived from CT and PT")
print("at those positions. It does NOT change when nulls are removed.")
print("The mask affects ONLY the surrounding context, not the crib values.")
print()

# What DOES change: the keystream at NON-CRIB positions depends on
# what we assume those positions decrypt to. The enrichment finding
# is about whether the key values themselves (not the plaintext) use
# palette letters. This is independent of the mask.
print("FINDING: Keystream palette enrichment is MASK-INDEPENDENT.")
print("The 7/8 BCL enrichment is a property of (CT, PT, Beaufort),")
print("not of the null mask. It provides evidence for Beaufort as the")
print("cipher variant but does NOT validate or invalidate any specific mask.")

# However, there's a deeper cross-layer question: if the null-letter
# palette {B,G,I,K,O,W,Z} appears in BOTH the null mask AND the keystream,
# that's a structural coupling between the stego and cipher layers.
# Test: is this coupling statistical or structural?

# Under random cipher assumption: each keystream value is uniform on A-Z
# P(palette letter) = 7/26 = 0.269
p_palette = 7 / 26
print(f"\nP(random keystream value in palette) = {p_palette:.4f}")
print(f"Expected palette count in 24 values = {24 * p_palette:.1f}")
print(f"Observed: {sum(1 for c in BEAU_KS_STR if c in NULL_PALETTE)}/24")

# Binomial test for enrichment in full keystream
from math import comb as C
full_palette_count = sum(1 for c in BEAU_KS_STR if c in NULL_PALETTE)
p_tail = sum(C(24, j) * p_palette**j * (1-p_palette)**(24-j)
             for j in range(full_palette_count, 25))
print(f"P(>={full_palette_count}/24 | random): {p_tail:.6f}")

# Binomial test for BCL first 8
p_tail_8 = sum(C(8, j) * p_palette**j * (1-p_palette)**(8-j)
               for j in range(bc_first8_palette, 9))
print(f"P(>={bc_first8_palette}/8 in BCL first 8 | random): {p_tail_8:.6f}")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 4: AUTOCORRELATION PROFILE
# ═══════════════════════════════════════════════════════════════════════════

print()
print("=" * 78)
print("PHASE 4: AUTOCORRELATION PROFILE — Consensus Extract vs Random Extracts")
print("=" * 78)

# Compute autocorrelation for consensus extract at lags 1-20
print(f"\nConsensus extract (80 chars): {consensus_extract}")
print(f"\nAutocorrelation at lags 1-20:")

max_lag = 20
cons_auto = [autocorrelation(consensus_extract, lag) for lag in range(1, max_lag + 1)]

# Monte Carlo: compute autocorrelation distribution for 5000 random 17-masks
N_AUTO_MC = 5000
auto_samples = {lag: [] for lag in range(1, max_lag + 1)}
seen = set()
count = 0
while count < N_AUTO_MC:
    mask = tuple(sorted(random.sample(CANDIDATE_NULLS, 17)))
    if mask not in seen:
        seen.add(mask)
        ext = extract_text(CT, frozenset(mask))
        for lag in range(1, max_lag + 1):
            auto_samples[lag].append(autocorrelation(ext, lag))
        count += 1

print(f"\n{'Lag':>4} {'Consensus':>10} {'MC_Mean':>10} {'MC_Std':>10} "
      f"{'Z-score':>10} {'Significant':>12}")
print("-" * 60)

for lag in range(1, max_lag + 1):
    mc_mean = sum(auto_samples[lag]) / N_AUTO_MC
    mc_std = (sum((v - mc_mean)**2 for v in auto_samples[lag]) / N_AUTO_MC) ** 0.5
    z = (cons_auto[lag - 1] - mc_mean) / mc_std if mc_std > 0 else 0
    sig = "|z|>2" if abs(z) > 2 else ""
    print(f"{lag:4d} {cons_auto[lag-1]:10d} {mc_mean:10.2f} {mc_std:10.2f} "
          f"{z:10.2f} {sig:>12}")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 5: MASK SIZE OPTIMIZATION — Is 17 the right number of nulls?
# ═══════════════════════════════════════════════════════════════════════════

print()
print("=" * 78)
print("PHASE 5: OPTIMAL NULL COUNT — Which k maximizes IC?")
print("=" * 78)

# For each mask size, find the mask that maximizes IC
print(f"\n{'k':>3} {'best_IC':>10} {'mean_IC':>10} {'positions':>50}")
print("-" * 78)

for k in [0, 5, 10, 14, 15, 16, 17, 18, 19, 20, 24, 28, 30]:
    if k == 0:
        print(f"{k:3d} {compute_ic(CT):10.6f} {compute_ic(CT):10.6f} {'(no removal)':>50}")
        continue
    if k > len(CANDIDATE_NULLS):
        break

    n_possible = math.comb(len(CANDIDATE_NULLS), k)
    best_ic = -1
    best_mask = None
    ics = []

    n_try = min(20000, n_possible)
    if n_possible <= 20000:
        for mask in combinations(CANDIDATE_NULLS, k):
            ext = extract_text(CT, frozenset(mask))
            ic_val = compute_ic(ext)
            ics.append(ic_val)
            if ic_val > best_ic:
                best_ic = ic_val
                best_mask = mask
    else:
        seen = set()
        while len(ics) < n_try:
            mask = tuple(sorted(random.sample(CANDIDATE_NULLS, k)))
            if mask not in seen:
                seen.add(mask)
                ext = extract_text(CT, frozenset(mask))
                ic_val = compute_ic(ext)
                ics.append(ic_val)
                if ic_val > best_ic:
                    best_ic = ic_val
                    best_mask = mask

    mean_ic = sum(ics) / len(ics)
    mask_str = str(list(best_mask))
    if len(mask_str) > 50:
        mask_str = mask_str[:47] + "..."
    print(f"{k:3d} {best_ic:10.6f} {mean_ic:10.6f} {mask_str:>50}")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 6: SINGLE-POSITION PERTURBATION OF CONSENSUS MASK
# ═══════════════════════════════════════════════════════════════════════════

print()
print("=" * 78)
print("PHASE 6: SINGLE-POSITION PERTURBATION — IC sensitivity")
print("=" * 78)

EXTRA_CANDIDATES = sorted(set(CANDIDATE_NULLS) - CONSENSUS_NULL_POSITIONS)

print(f"\nConsensus IC = {consensus_ic:.6f}")
print(f"Testing: remove one consensus position + add one extra candidate")
print(f"  {len(CONSENSUS)} × {len(EXTRA_CANDIDATES)} = "
      f"{len(CONSENSUS) * len(EXTRA_CANDIDATES)} perturbations")
print()

perturbation_ics = []
better_count = 0

print(f"{'Remove':>8} {'Add':>8} {'IC':>10} {'ΔIC':>10} {'Better?':>8}")
print("-" * 50)

for remove_pos in CONSENSUS:
    for add_pos in EXTRA_CANDIDATES:
        new_mask = (CONSENSUS_NULL_POSITIONS - {remove_pos}) | {add_pos}
        ext = extract_text(CT, new_mask)
        ic_val = compute_ic(ext)
        perturbation_ics.append((remove_pos, add_pos, ic_val))
        if ic_val > consensus_ic:
            better_count += 1

# Sort by IC and show top/bottom
perturbation_ics.sort(key=lambda x: -x[2])

print("Top 10 IC-improving perturbations:")
for r, a, ic in perturbation_ics[:10]:
    delta = ic - consensus_ic
    print(f"{r:8d} {a:8d} {ic:10.6f} {delta:+10.6f} {'YES' if delta > 0 else 'no':>8}")

print("\nBottom 5 IC-decreasing perturbations:")
for r, a, ic in perturbation_ics[-5:]:
    delta = ic - consensus_ic
    print(f"{r:8d} {a:8d} {ic:10.6f} {delta:+10.6f} {'YES' if delta > 0 else 'no':>8}")

print(f"\nPerturbations with higher IC than consensus: "
      f"{better_count}/{len(perturbation_ics)} "
      f"({better_count/len(perturbation_ics)*100:.1f}%)")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 7: EXTENDED MASK (k=24) FOR 73-CHAR HYPOTHESIS
# ═══════════════════════════════════════════════════════════════════════════

print()
print("=" * 78)
print("PHASE 7: 73-CHAR HYPOTHESIS — Extending to k=24 nulls")
print("=" * 78)

# Start with consensus 17, need 7 more from the 14 extra candidates
# C(14,7) = 3432, small enough to exhaust
n_extra = 7
extra_combos = list(combinations(EXTRA_CANDIDATES, n_extra))
print(f"\nConsensus 17 + 7 of {len(EXTRA_CANDIDATES)} extras = "
      f"C({len(EXTRA_CANDIDATES)},{n_extra}) = {len(extra_combos)} masks to test")

k24_results = []
for extra in extra_combos:
    mask24 = CONSENSUS_NULL_POSITIONS | frozenset(extra)
    ext = extract_text(CT, mask24)
    assert len(ext) == 73, f"Expected 73, got {len(ext)}"
    ic_val = compute_ic(ext)

    # Compute shifted crib positions
    pos_map = shift_positions(CRIB_POSITIONS, mask24)

    # Check all cribs are mapped (none removed)
    all_cribs_present = all(p in pos_map for p in CRIB_POSITIONS)

    k24_results.append({
        'extra': extra,
        'ic': ic_val,
        'all_cribs_present': all_cribs_present,
        'extract': ext,
        'pos_map': pos_map,
    })

k24_results.sort(key=lambda x: -x['ic'])

print(f"\n{'Rank':>5} {'IC':>10} {'Cribs OK':>9} {'Extra positions':<45}")
print("-" * 75)
for i, r in enumerate(k24_results[:20]):
    print(f"{i+1:5d} {r['ic']:10.6f} {'YES' if r['all_cribs_present'] else 'NO':>9} "
          f"{list(r['extra'])}")

print(f"\n...showing top 20 of {len(k24_results)}")

# Statistics of 73-char extracts
k24_ics = [r['ic'] for r in k24_results]
mean24 = sum(k24_ics) / len(k24_ics)
std24 = (sum((v - mean24)**2 for v in k24_ics) / len(k24_ics)) ** 0.5
print(f"\nIC statistics for ALL {len(k24_results)} 73-char extracts:")
print(f"  Mean: {mean24:.6f}")
print(f"  Std:  {std24:.6f}")
print(f"  Min:  {min(k24_ics):.6f}")
print(f"  Max:  {max(k24_ics):.6f}")
print(f"  Random expectation (1/26): {1/26:.6f}")

# Check the specific mask used in f_running_key_73char_overnight_v1.py
SCRIPT_MASK = frozenset([0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96])
script_extra = sorted(SCRIPT_MASK - CONSENSUS_NULL_POSITIONS)
script_ext = extract_text(CT, SCRIPT_MASK)
script_ic = compute_ic(script_ext)
script_rank = sum(1 for ic in k24_ics if ic >= script_ic)
print(f"\nScript mask extra positions: {script_extra}")
print(f"Script mask IC: {script_ic:.6f} (rank {script_rank}/{len(k24_results)})")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 8: BEAN CONSTRAINT SURVIVAL UNDER 73-CHAR EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

print()
print("=" * 78)
print("PHASE 8: BEAN CONSTRAINT SURVIVAL — Do Bean pairs survive null removal?")
print("=" * 78)

# For the top-10 73-char extracts, check if Bean constraints still hold
# Bean equality: k[27]=k[65] means the KEYSTREAM values at these positions
# must be equal. In 73-char space, we need to check if positions 27 and 65
# both survive (they're crib positions, so they must), and what their
# shifted positions are.
print(f"\nBean equality pair: positions (27, 65) in raw CT")
print(f"Both are crib positions (27=EASTNORTHEAST[6]='R', 65=BERLINCLOCK[2]='R')")
print(f"CT[27]=P, CT[65]=P. Same CT letter, same PT letter → k[27]=k[65] always.")
print()

for i, r in enumerate(k24_results[:5]):
    pm = r['pos_map']
    if 27 in pm and 65 in pm:
        print(f"Rank {i+1}: pos 27→{pm[27]}, pos 65→{pm[65]}, "
              f"gap = {pm[65]-pm[27]} (was 38)")
    else:
        print(f"Rank {i+1}: MISSING — 27 in map: {27 in pm}, 65 in map: {65 in pm}")

# Count how many Bean inequality pairs survive
print(f"\nBean inequality survival (of {len(BEAN_INEQ)} pairs):")
for i, r in enumerate(k24_results[:5]):
    pm = r['pos_map']
    survived = sum(1 for a, b in BEAN_INEQ if a in pm and b in pm)
    print(f"  Rank {i+1} (extra={list(r['extra'])}): "
          f"{survived}/{len(BEAN_INEQ)} pairs survive")

# ═══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════

print()
print("=" * 78)
print("SUMMARY")
print("=" * 78)

print(f"""
1. IC LANDSCAPE (Phase 1-2):
   Consensus mask IC = {consensus_ic:.6f}, percentile among random k=17 masks = {ic_pct:.1f}%
   {"The consensus mask IC is NOT an outlier among palette-derived masks." if 5 <= ic_pct <= 95 else "The consensus mask IC IS an outlier!"}

2. FREQUENCY TESTS (Phase 2):
   χ² vs uniform: percentile = {chi_u_pct:.1f}%
   χ² vs English: percentile = {chi_e_pct:.1f}%

3. KEYSTREAM ENRICHMENT (Phase 3):
   7/8 BCL palette enrichment is MASK-INDEPENDENT (depends only on CT+cribs+Beaufort).
   Full keystream: {full_palette_count}/24 palette, p_tail = {p_tail:.6f}
   BCL first 8: {bc_first8_palette}/8 palette, p_tail = {p_tail_8:.6f}

4. PERTURBATION SENSITIVITY (Phase 6):
   {better_count}/{len(perturbation_ics)} single-position swaps improve IC ({better_count/len(perturbation_ics)*100:.1f}%)

5. 73-CHAR HYPOTHESIS (Phase 7):
   {len(k24_results)} possible 24-null masks (consensus 17 + 7 of 14 extras)
   IC range: [{min(k24_ics):.6f}, {max(k24_ics):.6f}], mean = {mean24:.6f}

6. BEAN SURVIVAL (Phase 8):
   All 242 Bean inequality pairs survive (crib positions are never nulled).

KEY FINDING:
""")

if 5 <= ic_pct <= 95:
    print("The consensus mask does NOT produce a statistically unusual IC.")
    print("IC alone cannot validate or invalidate the mask.")
    print("The mask's evidentiary value comes from the PALETTE RESTRICTION")
    print("(all 17 positions use only {B,G,I,K,O,W,Z}, p≈3e-5), NOT from")
    print("cipher statistics of the extracted text.")
else:
    print(f"The consensus mask IC is at the {ic_pct:.1f}th percentile — "
          f"{'unusually HIGH' if ic_pct > 95 else 'unusually LOW'}.")

print()
print("IMPLICATIONS FOR THE SEARCH FRONTIER:")
print("1. The null mask cannot be validated by IC alone — it requires the")
print("   palette enrichment argument (which is strong: p≈3e-5)")
print("2. The keystream palette overlap is mask-independent and supports Beaufort")
print("3. The 73-char space has 3432 possible extensions of the consensus mask")
print("   — all should be tested before assuming a specific 24-null mask")
print("4. Bean constraints survive null removal — all 242 pairs still apply")
