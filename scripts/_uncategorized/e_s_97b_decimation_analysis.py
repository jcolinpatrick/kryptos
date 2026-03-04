#!/usr/bin/env python3
"""
Cipher: autokey
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-97b: Analysis of E-S-97 decimation autokey hit (10/24)

Investigates the 10/24 hit from E-S-97 P2:
  PT-autokey Beaufort, d=11, primer="CBG"

Questions:
1. Which 10 of 24 crib positions match?
2. Is the matching clustered in one block or spread?
3. What does the full plaintext look like?
4. Is the PT score explainable by autokey chain structure?
5. Are there other configs with score ≥8?
"""

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
I2N = {c: i for i, c in enumerate(AZ)}
CT_N = [I2N[c] for c in CT]

CRIBS = {
    21:'E',22:'A',23:'S',24:'T',25:'N',26:'O',27:'R',28:'T',29:'H',30:'E',31:'A',32:'S',33:'T',
    63:'B',64:'E',65:'R',66:'L',67:'I',68:'N',69:'C',70:'L',71:'O',72:'C',73:'K'}
PT_FULL = {p: I2N[c] for p, c in CRIBS.items()}
CPOS = sorted(CRIBS.keys())


def decimation_perm(d, n=97):
    return [(j * d) % n for j in range(n)]


def pt_autokey_decrypt_beaufort(intermed, primer):
    p = len(primer)
    pt = [0] * N
    for j in range(N):
        k = primer[j] if j < p else pt[j - p]
        pt[j] = (k - intermed[j]) % 26
    return pt


# ── Reproduce the hit ─────────────────────────────────────────────────
d = 11
primer = [I2N[c] for c in "CBG"]
perm = decimation_perm(d)
intermed = [CT_N[perm[j]] for j in range(N)]
pt = pt_autokey_decrypt_beaufort(intermed, primer)

print("=" * 70)
print("E-S-97b: Decimation Autokey Hit Analysis")
print(f"  d={d}, primer='CBG', variant=PT-autokey Beaufort")
print("=" * 70)

pt_text = ''.join(AZ[x] for x in pt)
print(f"\nFull PT: {pt_text}")

# Check each crib
print(f"\nCrib matches:")
match_count = 0
ene_matches = 0
bc_matches = 0
for p in CPOS:
    expected = AZ[PT_FULL[p]]
    actual = AZ[pt[p]]
    match = "✓" if pt[p] == PT_FULL[p] else "✗"
    if pt[p] == PT_FULL[p]:
        match_count += 1
        if p <= 33:
            ene_matches += 1
        else:
            bc_matches += 1
    print(f"  pos {p:2d}: expected={expected}, got={actual}  {match}")

print(f"\nTotal: {match_count}/24 (ENE: {ene_matches}/13, BC: {bc_matches}/11)")

# Analyze chain structure
print(f"\nAutokey chain analysis (primer length 3):")
for track in range(3):
    positions = [j for j in range(N) if j % 3 == track]
    crib_in_track = [(p, p in CPOS and pt[p] == PT_FULL[p]) for p in positions if p in CPOS]
    print(f"  Track {track}: crib positions = {[p for p, _ in crib_in_track]}")
    print(f"           matches = {[p for p, m in crib_in_track if m]}")


# ── Score distribution analysis ───────────────────────────────────────
print(f"\n{'='*70}")
print("Score distribution for PT-autokey Beaufort, primer len 3, all d")
print("=" * 70)

from itertools import product as iproduct
from collections import Counter

score_dist = Counter()
high_scorers = []

for dd in range(1, N):
    perm = decimation_perm(dd)
    intermed = [CT_N[perm[j]] for j in range(N)]

    for primer_tuple in iproduct(range(26), repeat=3):
        primer = list(primer_tuple)
        pt = pt_autokey_decrypt_beaufort(intermed, primer)

        score = sum(1 for p in CPOS if pt[p] == PT_FULL[p])
        score_dist[score] += 1

        if score >= 8:
            high_scorers.append((score, dd, ''.join(AZ[x] for x in primer)))

print(f"\nScore distribution (PT-autokey Beaufort, plen=3):")
for s in range(max(score_dist.keys()) + 1):
    if score_dist[s] > 0:
        print(f"  score {s:2d}: {score_dist[s]:>10,} configs")

total = sum(score_dist.values())
print(f"  total:    {total:>10,}")
print(f"  expected (random): ~{total/26:.0f} at score 1")

print(f"\nHigh scorers (≥8):")
high_scorers.sort(reverse=True)
for score, dd, primer in high_scorers[:20]:
    perm = decimation_perm(dd)
    intermed = [CT_N[perm[j]] for j in range(N)]
    p_vals = [I2N[c] for c in primer]
    pt = pt_autokey_decrypt_beaufort(intermed, p_vals)
    pt_text = ''.join(AZ[x] for x in pt)

    # Check which block matches
    ene = sum(1 for p in CPOS if p <= 33 and pt[p] == PT_FULL[p])
    bc = sum(1 for p in CPOS if p > 33 and pt[p] == PT_FULL[p])
    print(f"  {score}/24 d={dd:2d} primer={primer} ENE={ene}/13 BC={bc}/11 PT={pt_text[:40]}...")

print(f"\nArtifact: (diagnostic only)")
