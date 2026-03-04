#!/usr/bin/env python3
"""
Cipher: YAR grille
Family: yar
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
Dissect which YAR replacements cause the period-7 IC spike.

9 replacements at positions: 3, 23, 28, 49, 57, 64, 90, 95, 96
Which ones contribute to the period-7 signal? Which ones hurt?
"""

import sys, json
from collections import Counter
from itertools import combinations

sys.path.insert(0, 'src')

ORIGINAL = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
MODIFIED = "OBKKUOXOGHULBSOLIFBBWFLJVQQPUNGKSSOTWTQSJQSSEKZZWFTJKLUDIQWINFBNRPVTTMZFPKWGDKZXTJCDIGKUHUXUEKCCD"

# The 9 replacements
REPLACEMENTS = {
    3:  ('R', 'K'),   # R→K
    23: ('R', 'J'),   # R→J
    28: ('R', 'U'),   # R→U
    49: ('A', 'F'),   # A→F
    57: ('A', 'Q'),   # A→Q
    64: ('Y', 'R'),   # Y→R
    90: ('A', 'X'),   # A→X
    95: ('A', 'C'),   # A→C
    96: ('R', 'D'),   # R→D
}

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

def ic(text):
    freq = Counter(text)
    n = len(text)
    if n < 2:
        return 0
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

def ic_at_period(text, period):
    columns = ['' for _ in range(period)]
    for i, c in enumerate(text):
        columns[i % period] += c
    return sum(ic(col) for col in columns) / period

def column_ics(text, period):
    columns = ['' for _ in range(period)]
    for i, c in enumerate(text):
        columns[i % period] += c
    return [ic(col) for col in columns]

# Load quadgrams
QG = {}
with open('data/english_quadgrams.json') as f:
    QG = json.load(f)

def qg_score(text):
    total = sum(QG.get(text[i:i+4], -10.0) for i in range(len(text) - 3))
    return total / max(1, len(text) - 3)

print("=" * 80)
print("DISSECTING THE PERIOD-7 IC SPIKE")
print("=" * 80)

# ═══════════════════════════════════════════════════════════════════════════
# 1. Which column does each replacement fall in (period 7)?
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n--- 1. Replacement positions mod 7 ---")
print(f"{'Pos':>4} {'Orig':>5} {'New':>5} {'Col(mod7)':>10} {'Effect':>30}")
for pos in sorted(REPLACEMENTS):
    orig, new = REPLACEMENTS[pos]
    col = pos % 7
    print(f"{pos:4d} {orig:>5} {new:>5} {col:>10}    Column {col}")

# Count replacements per column
col_counts = Counter(pos % 7 for pos in REPLACEMENTS)
print(f"\nReplacements per column: {dict(sorted(col_counts.items()))}")

# ═══════════════════════════════════════════════════════════════════════════
# 2. Per-column IC with and without each replacement
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n--- 2. Per-column IC analysis (period 7) ---")

orig_col_ics = column_ics(ORIGINAL, 7)
mod_col_ics = column_ics(MODIFIED, 7)

print(f"\n{'Col':>4} {'Orig IC':>10} {'Mod IC':>10} {'Delta':>10} {'Replacements':>20}")
for col in range(7):
    delta = mod_col_ics[col] - orig_col_ics[col]
    reps = [(pos, REPLACEMENTS[pos]) for pos in sorted(REPLACEMENTS) if pos % 7 == col]
    rep_str = ', '.join(f"{p}:{o}→{n}" for p, (o, n) in reps) if reps else "none"
    marker = " <<<" if abs(delta) > 0.01 else ""
    print(f"{col:4d} {orig_col_ics[col]:10.4f} {mod_col_ics[col]:10.4f} {delta:+10.4f} {rep_str}{marker}")

print(f"\nOverall: orig={sum(orig_col_ics)/7:.4f}, mod={sum(mod_col_ics)/7:.4f}, "
      f"delta={sum(mod_col_ics)/7 - sum(orig_col_ics)/7:+.4f}")

# ═══════════════════════════════════════════════════════════════════════════
# 3. Show each column's content before/after
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n--- 3. Column contents (period 7) ---")
for col in range(7):
    orig_col = ''.join(ORIGINAL[i] for i in range(col, 97, 7))
    mod_col = ''.join(MODIFIED[i] for i in range(col, 97, 7))
    changed = ''.join('^' if orig_col[j] != mod_col[j] else ' ' for j in range(len(orig_col)))
    positions = list(range(col, 97, 7))
    print(f"\n  Column {col} (positions {positions[:5]}...{positions[-1]}):")
    print(f"    Orig: {orig_col} (IC={ic(orig_col):.4f})")
    print(f"    Mod:  {mod_col} (IC={ic(mod_col):.4f})")
    print(f"    Diff: {changed}")
    print(f"    Orig freq: {dict(sorted(Counter(orig_col).items(), key=lambda x: -x[1]))}")
    print(f"    Mod freq:  {dict(sorted(Counter(mod_col).items(), key=lambda x: -x[1]))}")

# ═══════════════════════════════════════════════════════════════════════════
# 4. Leave-one-out: remove each replacement and measure IC change
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*80}")
print("4. LEAVE-ONE-OUT ANALYSIS")
print(f"{'='*80}")
print(f"\nFull modified IC(7) = {ic_at_period(MODIFIED, 7):.4f}")
print(f"Original IC(7) = {ic_at_period(ORIGINAL, 7):.4f}")
print(f"Delta = {ic_at_period(MODIFIED, 7) - ic_at_period(ORIGINAL, 7):+.4f}\n")

print(f"{'Removed':>10} {'IC(7)':>10} {'Delta from full mod':>20} {'Effect':>10}")
for pos in sorted(REPLACEMENTS):
    orig_ch, new_ch = REPLACEMENTS[pos]
    # Build text with this one replacement reverted
    text = list(MODIFIED)
    text[pos] = orig_ch
    text = ''.join(text)
    ic7 = ic_at_period(text, 7)
    delta = ic7 - ic_at_period(MODIFIED, 7)
    effect = "HELPS" if delta < -0.002 else ("HURTS" if delta > 0.002 else "neutral")
    print(f"  pos {pos:2d} ({orig_ch}→{new_ch}): {ic7:.4f}  {delta:+.4f}             {effect}")

# ═══════════════════════════════════════════════════════════════════════════
# 5. Leave-one-IN: apply each replacement individually
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*80}")
print("5. INDIVIDUAL REPLACEMENT CONTRIBUTION")
print(f"{'='*80}")
print(f"\nOriginal IC(7) = {ic_at_period(ORIGINAL, 7):.4f}")

print(f"\n{'Applied':>10} {'IC(7)':>10} {'Delta from orig':>20} {'Contribution':>15}")
for pos in sorted(REPLACEMENTS):
    orig_ch, new_ch = REPLACEMENTS[pos]
    text = list(ORIGINAL)
    text[pos] = new_ch
    text = ''.join(text)
    ic7 = ic_at_period(text, 7)
    delta = ic7 - ic_at_period(ORIGINAL, 7)
    contribution = "POSITIVE" if delta > 0.002 else ("NEGATIVE" if delta < -0.002 else "neutral")
    print(f"  pos {pos:2d} ({orig_ch}→{new_ch}): {ic7:.4f}  {delta:+.4f}             {contribution}")

# ═══════════════════════════════════════════════════════════════════════════
# 6. All subsets of replacements — which combination maximizes IC(7)?
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*80}")
print("6. ALL 512 SUBSETS — Best IC(7) combinations")
print(f"{'='*80}")

all_positions = sorted(REPLACEMENTS.keys())
results = []

for r in range(len(all_positions) + 1):
    for subset in combinations(all_positions, r):
        text = list(ORIGINAL)
        for pos in subset:
            _, new_ch = REPLACEMENTS[pos]
            text[pos] = new_ch
        text = ''.join(text)
        ic7 = ic_at_period(text, 7)
        results.append((ic7, subset, text))

results.sort(key=lambda x: -x[0])

print(f"\nTop 20 subsets by IC(7):")
for ic7, subset, text in results[:20]:
    n = len(subset)
    subset_str = ','.join(str(p) for p in subset) if subset else '(none)'
    print(f"  IC(7)={ic7:.4f}  n={n}  positions: {subset_str}")

print(f"\nBottom 5 (worst IC(7)):")
for ic7, subset, text in results[-5:]:
    subset_str = ','.join(str(p) for p in subset) if subset else '(none)'
    print(f"  IC(7)={ic7:.4f}  n={len(subset)}  positions: {subset_str}")

# Show the BEST subset in detail
best_ic7, best_subset, best_text = results[0]
print(f"\n--- BEST SUBSET ---")
print(f"IC(7) = {best_ic7:.4f}")
print(f"Positions: {best_subset}")
print(f"Replacements: {[(p, REPLACEMENTS[p]) for p in best_subset]}")
print(f"Text: {best_text}")

# ═══════════════════════════════════════════════════════════════════════════
# 7. Best subset with Vig/Beau decryption
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*80}")
print("7. DECRYPT TOP-5 IC SUBSETS WITH ALL KEYWORDS")
print(f"{'='*80}")

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN", "SCHEIDT",
            "BERLIN", "CLOCK", "EAST", "NORTH", "LIGHT"]

def vig_d(ct, key, alph=AZ):
    return ''.join(alph[(alph.index(c) - alph.index(key[i%len(key)])) % 26] for i,c in enumerate(ct))
def beau_d(ct, key, alph=AZ):
    return ''.join(alph[(alph.index(key[i%len(key)]) - alph.index(c)) % 26] for i,c in enumerate(ct))

for rank, (ic7, subset, text) in enumerate(results[:5]):
    print(f"\n  --- Rank {rank+1}: IC(7)={ic7:.4f}, positions={subset} ---")
    best_score = -99
    best_result = None
    for kw in KEYWORDS:
        for an, al in [("AZ", AZ), ("KA", KA)]:
            for cn, cf in [("VIG", vig_d), ("BEAU", beau_d)]:
                pt = cf(text, kw, al)
                score = qg_score(pt)
                if score > best_score:
                    best_score = score
                    best_result = (cn, kw, an, pt)
    cn, kw, an, pt = best_result
    print(f"    Best: {cn}/{kw}/{an} qg={best_score:+.3f}")
    print(f"    PT: {pt}")

# ═══════════════════════════════════════════════════════════════════════════
# 8. Does column 3 anomaly come from one specific replacement?
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*80}")
print("8. COLUMN 3 ANOMALY DISSECTION")
print(f"{'='*80}")

# Column 3 positions (mod 7): 3, 10, 17, 24, 31, 38, 45, 52, 59, 66, 73, 80, 87, 94
col3_positions = list(range(3, 97, 7))
print(f"\nColumn 3 positions: {col3_positions}")

# Which positions were replaced?
col3_replacements = [p for p in REPLACEMENTS if p % 7 == 3]
print(f"Replacements in column 3: {col3_replacements}")
for p in col3_replacements:
    orig, new = REPLACEMENTS[p]
    print(f"  pos {p}: {orig}→{new}")

# Show full column 3
print(f"\nColumn 3 letters:")
print(f"{'Pos':>4} {'Orig':>5} {'Mod':>5} {'Changed':>8}")
for pos in col3_positions:
    o = ORIGINAL[pos]
    m = MODIFIED[pos]
    ch = "***" if o != m else ""
    print(f"{pos:4d} {o:>5} {m:>5} {ch:>8}")

# K count analysis
orig_col3 = ''.join(ORIGINAL[i] for i in col3_positions)
mod_col3 = ''.join(MODIFIED[i] for i in col3_positions)
print(f"\nOrig col 3 K count: {orig_col3.count('K')}")
print(f"Mod col 3 K count:  {mod_col3.count('K')}")
print(f"\nThe replacement at pos 3 (R→K) ADDED one more K to a column that already had 4 K's!")
print(f"This created 5 K's out of 14 = 35.7% monographic concentration → IC spike")

# What if we DON'T replace pos 3?
text_no3 = list(MODIFIED)
text_no3[3] = 'R'  # revert pos 3
text_no3 = ''.join(text_no3)
ic7_no3 = ic_at_period(text_no3, 7)
print(f"\nIC(7) without pos 3 replacement: {ic7_no3:.4f} (vs full: {ic_at_period(MODIFIED, 7):.4f})")
print(f"Delta: {ic7_no3 - ic_at_period(MODIFIED, 7):+.4f}")

# ═══════════════════════════════════════════════════════════════════════════
# 9. Is the K-concentration in col 3 a REAL signal or artifact?
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*80}")
print("9. STATISTICAL SIGNIFICANCE OF COLUMN 3 K-CONCENTRATION")
print(f"{'='*80}")

# In original K4, how many K's are in column 3?
orig_k_count = orig_col3.count('K')
# K appears 9 times total in original K4 (97 chars)
total_k_orig = ORIGINAL.count('K')
total_k_mod = MODIFIED.count('K')
print(f"K count in original K4: {total_k_orig}/97 = {total_k_orig/97*100:.1f}%")
print(f"K count in modified K4: {total_k_mod}/97 = {total_k_mod/97*100:.1f}%")
print(f"K's in orig col 3:     {orig_k_count}/14 = {orig_k_count/14*100:.1f}%")
print(f"K's in mod col 3:      {mod_col3.count('K')}/14 = {mod_col3.count('K')/14*100:.1f}%")

# Expected K's in column 3 if random: (total_k / 97) * 14
expected = total_k_mod / 97 * 14
print(f"Expected K's in col 3 (random): {expected:.1f}")
print(f"Observed: {mod_col3.count('K')}")

# Binomial probability
from math import comb
p = total_k_mod / 97
n_col = 14
k_obs = mod_col3.count('K')
# P(X >= k_obs) where X ~ Binomial(14, p)
prob = sum(comb(n_col, k) * p**k * (1-p)**(n_col-k) for k in range(k_obs, n_col+1))
print(f"P(≥{k_obs} K's in 14 trials, p={p:.3f}): {prob:.6f}")
print(f"This {'IS' if prob < 0.05 else 'is NOT'} statistically significant at p<0.05")

# ═══════════════════════════════════════════════════════════════════════════
# 10. What does the K-concentration mean for the key?
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*80}")
print("10. KEY IMPLICATIONS OF COLUMN 3 K-CONCENTRATION")
print(f"{'='*80}")

print(f"\nIf CT column 3 is heavily K, and it decrypts to English under Vigenère:")
print(f"  K maps to the most common English letter in that column.")
print(f"  Under Vig/AZ with key letter X: K - X = K(10) - X(23) = -13 mod 26 = 13 = N")
print(f"  Under Vig/AZ with key letter C: K - C = K(10) - C(2) = 8 = I")
print(f"  Under Vig/AZ with key letter F: K - F = K(10) - F(5) = 5 = F")
print(f"  Under Vig/AZ with key letter H: K - H = K(10) - H(7) = 3 = D")

# For each possible key letter, what does K decrypt to?
print(f"\n  K decrypts to under Vig/AZ:")
for shift in range(26):
    result = AZ[(10 - shift) % 26]
    eng_rank = sorted(AZ, key=lambda c: -ENG_FREQ[c]).index(result)
    marker = " <<<" if result in 'ETAOINSHR' else ""
    if marker:
        print(f"    Key={AZ[shift]}: K → {result} (rank {eng_rank+1}){marker}")

print(f"\n  For K→E (most common), key = {AZ[(10 - 4) % 26]} = F")
print(f"  For K→T (2nd most common), key = {AZ[(10 - 19) % 26]} = R")
print(f"  For K→A (3rd), key = {AZ[(10 - 0) % 26]} = K")
print(f"  For K→N (6th), key = {AZ[(10 - 13) % 26]} = X")
print(f"  For K→S (7th), key = {AZ[(10 - 18) % 26]} = S")

# Column 3 is position 3 mod 7. In KRYPTOS, position 3 = P.
print(f"\n  KRYPTOS key at position 3: P")
print(f"  Under Vig/AZ with key P: K → {AZ[(10 - 15) % 26]} = V")
print(f"  V is rank {sorted(AZ, key=lambda c: -ENG_FREQ[c]).index('V')+1} — not a common letter.")
print(f"  This is another reason KRYPTOS doesn't work as a direct key.")

print(f"\n{'='*80}")
print("SUMMARY")
print(f"{'='*80}")
print(f"""
  The period-7 IC spike is REAL but partially driven by the pos 3 replacement (R→K)
  which created a 5-K concentration in column 3 (already had 4 K's).

  Column 3 accounts for a disproportionate share of the IC signal.
  However, the Kasiski analysis (spacings with factor 7) provides independent evidence.

  The IC signal is likely a MIXTURE of:
  1. Real period-7 structure in the underlying cipher (supported by Kasiski)
  2. Artifact amplification from the R→K replacement at position 3

  NEXT STEPS:
  - Test whether ALL K4 R's should map to tableau values (not just at pos 3,23,28)
  - The 4 R's at positions 3,23,28,96 ALL fall in the last 4 grid rows (24-27)
  - What about R's at OTHER positions in K4?
  - Consider: maybe ALL letters (not just Y,A,R) should be replaced at certain positions
""")
