#!/usr/bin/env python3
"""
E-GKO-AP-ANALYSIS: Arithmetic Progression Analysis of {G,K,O} in Crib Keystream

The Beaufort A=0 keystream k[i] = (CT[i] + PT[i]) mod 26 at 24 crib positions
shows G=4, K=5, O=3 occurrences. In AZ: G=6, K=10, O=14 — an AP with step 4.

Seven tests investigate whether this concentration is statistically significant,
what structural properties it implies, and whether it connects to the cipher mechanism.

Attack-type: analysis
Family: keystream-review
Status: active
"""

import sys, os, json, random
from datetime import datetime, timezone
from collections import Counter
from itertools import product

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, 'src'))

from kryptos.kernel.constants import CT, CRIB_POSITIONS
from kryptos.kernel.alphabet import AZ, KA

# ── Setup ────────────────────────────────────────────────────────────────────

# Known cribs: EASTNORTHEAST at positions 21-33, BERLINCLOCK at positions 63-73
ENE_POS = list(range(21, 34))   # 13 positions
BCL_POS = list(range(63, 74))   # 11 positions
ALL_CRIB_POS = sorted(ENE_POS + BCL_POS)  # 24 positions

ENE_PT = "EASTNORTHEAST"
BCL_PT = "BERLINCLOCK"
FULL_PT_AT_CRIBS = ENE_PT + BCL_PT  # 24 chars

# Beaufort A=0 keystream: k[i] = (CT[i] + PT[i]) mod 26
keystream_vals = []
keystream_chars = []
for i, pos in enumerate(ALL_CRIB_POS):
    ct_val = AZ.char_to_idx(CT[pos])
    pt_val = AZ.char_to_idx(FULL_PT_AT_CRIBS[i])
    k = (ct_val + pt_val) % 26
    keystream_vals.append(k)
    keystream_chars.append(AZ.idx_to_char(k))

print("=" * 70)
print("E-GKO-AP-ANALYSIS: Arithmetic Progression in Crib Keystream")
print("=" * 70)
print(f"\nCrib positions: {ALL_CRIB_POS}")
print(f"Keystream chars: {''.join(keystream_chars)}")
print(f"Keystream vals (AZ): {keystream_vals}")
print(f"Letter counts: {dict(Counter(keystream_chars).most_common())}")

PALETTE = set('BGIKOWZ')
GKO = {6, 10, 14}  # AZ indices

results = {"timestamp": datetime.now(timezone.utc).isoformat(), "tests": {}}

# ── Test 1: Is the AP with step 4 significant? ──────────────────────────────

print("\n" + "=" * 70)
print("TEST 1: AP step-4 significance and parity analysis")
print("=" * 70)

# Count even AZ indices in keystream
even_count = sum(1 for v in keystream_vals if v % 2 == 0)
print(f"\nEven AZ indices in keystream: {even_count}/24 (expected: 12.0)")
print(f"  -> GKO (6,10,14) are all even, but even enrichment is {even_count}/24")

# For each possible 3-element AP {s, s+d, s+2d} mod 26, count hits
ap_hits = {}
for d in range(1, 13):
    for s in range(26):
        ap_set = {s, (s + d) % 26, (s + 2*d) % 26}
        if len(ap_set) < 3:
            continue
        hits = sum(1 for v in keystream_vals if v in ap_set)
        ap_hits[(s, d)] = hits

# Rank all APs
ranked = sorted(ap_hits.items(), key=lambda x: -x[1])
gko_hits = ap_hits.get((6, 4), 0)
gko_rank = sum(1 for _, h in ap_hits.items() if h > gko_hits) + 1
total_aps = len(ap_hits)

print(f"\n{6,10,14} (s=6, d=4) hits: {gko_hits}/24")
print(f"Rank among all 3-element APs: {gko_rank}/{total_aps}")
print(f"Top 10 APs by hit count:")
for (s, d), h in ranked[:10]:
    ap = sorted([(s + i*d) % 26 for i in range(3)])
    chars = [AZ.idx_to_char(v) for v in ap]
    print(f"  s={s:2d} d={d:2d} -> {{{','.join(chars)}}} = {{{','.join(str(v) for v in ap)}}} : {h} hits")

# Monte Carlo: distribution of max-hit for any 3-element AP
N_MC = 100_000
random.seed(42)
max_hit_dist = Counter()
gko_hit_dist = Counter()
for _ in range(N_MC):
    sample = [random.randint(0, 25) for _ in range(24)]
    max_h = 0
    for d in range(1, 13):
        for s in range(26):
            ap_set = {s, (s + d) % 26, (s + 2*d) % 26}
            if len(ap_set) < 3:
                continue
            h = sum(1 for v in sample if v in ap_set)
            if h > max_h:
                max_h = h
    max_hit_dist[max_h] += 1
    # Also track hits for the specific AP {6,10,14}
    gko_h = sum(1 for v in sample if v in GKO)
    gko_hit_dist[gko_h] += 1

p_max_ge_observed = sum(v for k, v in max_hit_dist.items() if k >= gko_hits) / N_MC
p_gko_ge_observed = sum(v for k, v in gko_hit_dist.items() if k >= gko_hits) / N_MC

print(f"\nMonte Carlo ({N_MC:,} trials):")
print(f"  P(max AP hits >= {gko_hits}) = {p_max_ge_observed:.4f}")
print(f"  P(hits on {{6,10,14}} specifically >= {gko_hits}) = {p_gko_ge_observed:.4f}")
print(f"  Max-hit distribution: {dict(sorted(max_hit_dist.items()))}")

results["tests"]["T1_ap_significance"] = {
    "gko_hits": gko_hits,
    "gko_rank": gko_rank,
    "total_aps_tested": total_aps,
    "even_count": even_count,
    "p_max_ge": p_max_ge_observed,
    "p_gko_specific_ge": p_gko_ge_observed,
    "top_10": [{"s": s, "d": d, "hits": h, "set": sorted([(s+i*d)%26 for i in range(3)])} for (s,d), h in ranked[:10]],
}

# ── Test 2: Full AP ranking across all steps ─────────────────────────────────

print("\n" + "=" * 70)
print("TEST 2: Complete AP ranking (all steps, all starting values)")
print("=" * 70)

# Already computed in test 1, just report where {6,10,14} falls
aps_with_same_or_more = sum(1 for h in ap_hits.values() if h >= gko_hits)
print(f"\nAPs with >= {gko_hits} hits: {aps_with_same_or_more}/{total_aps}")
print(f"  -> {6,10,14} is {'RARE' if aps_with_same_or_more <= total_aps * 0.05 else 'NOT RARE'} (top {100*aps_with_same_or_more/total_aps:.1f}%)")

results["tests"]["T2_ap_ranking"] = {
    "aps_ge_threshold": aps_with_same_or_more,
    "total_aps": total_aps,
    "percentile": 100 * (1 - aps_with_same_or_more / total_aps),
}

# ── Test 3: Why K=10 dominates ───────────────────────────────────────────────

print("\n" + "=" * 70)
print("TEST 3: K=10 dominance analysis")
print("=" * 70)

k_positions = [i for i, v in enumerate(keystream_vals) if v == 10]
k_crib_pos = [ALL_CRIB_POS[i] for i in k_positions]
k_pt = [FULL_PT_AT_CRIBS[i] for i in k_positions]
k_ct = [CT[ALL_CRIB_POS[i]] for i in k_positions]

print(f"\nK=10 appears at crib indices: {k_positions}")
print(f"  Crib positions: {k_crib_pos}")
print(f"  PT at these positions: {''.join(k_pt)} ({k_pt})")
print(f"  CT at these positions: {''.join(k_ct)} ({k_ct})")

# How many K-producing positions have CT that is a GKO letter?
gko_letters = {'G', 'K', 'O'}
ct_gko_count = sum(1 for c in k_ct if c in gko_letters)
print(f"\n  CT letters in GKO at K-positions: {ct_gko_count}/{len(k_ct)}")
print(f"  CT letters in palette at K-positions: {sum(1 for c in k_ct if c in PALETTE)}/{len(k_ct)}")

# Self-reinforcement: check all 24 positions where keystream is GKO,
# how many have CT that is also GKO?
gko_ks_indices = [i for i, v in enumerate(keystream_vals) if v in GKO]
gko_ct_at_gko_ks = sum(1 for i in gko_ks_indices if CT[ALL_CRIB_POS[i]] in gko_letters)
print(f"\nSelf-reinforcement check:")
print(f"  Positions with GKO keystream: {len(gko_ks_indices)}")
print(f"  Of those, CT is also GKO: {gko_ct_at_gko_ks}/{len(gko_ks_indices)}")
expected_ct_gko = len(gko_ks_indices) * (sum(1 for c in CT if c in gko_letters) / len(CT))
print(f"  Expected (from CT GKO frequency): {expected_ct_gko:.1f}")

results["tests"]["T3_k_dominance"] = {
    "k_count": len(k_positions),
    "k_crib_positions": k_crib_pos,
    "k_pt_chars": k_pt,
    "k_ct_chars": k_ct,
    "ct_gko_at_k_positions": ct_gko_count,
    "gko_keystream_count": len(gko_ks_indices),
    "ct_gko_at_gko_ks": gko_ct_at_gko_ks,
    "expected_ct_gko": round(expected_ct_gko, 2),
}

# ── Test 4: CT+PT parity analysis ────────────────────────────────────────────

print("\n" + "=" * 70)
print("TEST 4: CT+PT parity correlation at crib positions")
print("=" * 70)

same_parity = 0
for i, pos in enumerate(ALL_CRIB_POS):
    ct_val = AZ.char_to_idx(CT[pos])
    pt_val = AZ.char_to_idx(FULL_PT_AT_CRIBS[i])
    if ct_val % 2 == pt_val % 2:
        same_parity += 1

print(f"\nSame-parity (CT, PT) at crib positions: {same_parity}/24")
print(f"  Expected under random: 12.0/24 (50%)")
print(f"  Observed rate: {100*same_parity/24:.1f}%")
print(f"  (Same parity => even keystream => could be in GKO's orbit)")

# Detailed parity table
print("\n  Pos  CT  CT_val  PT  PT_val  K_val  K_char  Parity")
for i, pos in enumerate(ALL_CRIB_POS):
    ct_c = CT[pos]
    pt_c = FULL_PT_AT_CRIBS[i]
    ct_v = AZ.char_to_idx(ct_c)
    pt_v = AZ.char_to_idx(pt_c)
    k_v = keystream_vals[i]
    k_c = keystream_chars[i]
    parity = "EVEN" if k_v % 2 == 0 else "ODD"
    gko_mark = " <-GKO" if k_v in GKO else ""
    print(f"  {pos:3d}  {ct_c}    {ct_v:2d}    {pt_c}    {pt_v:2d}    {k_v:2d}    {k_c}     {parity}{gko_mark}")

# Binomial test for same-parity enrichment
from math import comb
p_ge = sum(comb(24, k) * 0.5**24 for k in range(same_parity, 25))
print(f"\n  Binomial P(X >= {same_parity} | n=24, p=0.5) = {p_ge:.4f}")

results["tests"]["T4_parity_analysis"] = {
    "same_parity_count": same_parity,
    "expected": 12.0,
    "observed_rate": same_parity / 24,
    "binomial_p_ge": round(p_ge, 6),
}

# ── Test 5: Beaufort KA source analysis for GKO ─────────────────────────────

print("\n" + "=" * 70)
print("TEST 5: Beaufort KA source analysis — which key letters produce GKO?")
print("=" * 70)

# Under Beaufort with KA: PT = KA[(KA_idx(key) - KA_idx(CT)) % 26]
# So if keystream_val = (AZ_idx(CT) + AZ_idx(PT)) % 26, and we want to know
# what source (PT) letters produce GKO keystream values under a given key...
#
# Actually, the keystream IS the key under Beaufort AZ:
# Beaufort: key = (CT + PT) mod 26 in AZ indexing
# So keystream[i] = AZ index of key letter at position i
#
# For Beaufort KA with a single key letter:
# KA_decrypt: PT[i] = KA.idx_to_char((KA.char_to_idx(key) - KA.char_to_idx(CT[i])) % 26)
# The keystream in KA terms: k_ka[i] = KA.char_to_idx(key)  (constant for single key!)
# But in AZ terms, the observed keystream varies because it's (AZ_CT + AZ_PT) mod 26

print("\nFor each key letter K, what plaintext letters produce GKO keystream?")
print("(Beaufort AZ: key_val = CT_val + PT_val mod 26, so PT_val = key_val - CT_val mod 26)")
print("\nKey  Sources for G(6)  K(10)  O(14)  Combined  Structure?")

gko_source_analysis = {}
for key_val in range(26):
    key_char = AZ.idx_to_char(key_val)
    sources = {}
    for target_name, target_val in [('G', 6), ('K', 10), ('O', 14)]:
        # If keystream = target_val, and keystream = key_val for constant key...
        # No! keystream[i] = (CT[i] + PT[i]) mod 26 varies by position
        # Under Beaufort with key K: PT = (K - CT) mod 26, so keystream = (CT + K - CT) = K
        # That means keystream is CONSTANT for single-key Beaufort = key value itself!
        # So this test only makes sense if we're looking at what CT values would be needed
        pass

    # Actually, for a RUNNING key:
    # keystream[i] = (CT[i] + PT[i]) mod 26
    # If keystream[i] is a GKO value, then runkey[i] = keystream[i] (the key IS the keystream for Beaufort)
    # So the question is: under Beaufort KA with key letter K at position i:
    # KA_beau: CT[i] = KA.idx_to_char((KA.char_to_idx(K) - KA.char_to_idx(PT[i])) % 26)
    # We want: what PT letters, when encrypted with key K, produce CT such that (AZ(CT)+AZ(PT)) is in GKO?

    # For single-letter key in Beaufort AZ: keystream = key_val everywhere, so it's G,K, or O only if key IS G, K, or O
    # For Beaufort KA: more complex since KA indexing differs from AZ
    pass

# Let me reframe: the keystream at crib positions is KNOWN and position-dependent.
# The question from the task is: for each possible single key letter N (using KA Beaufort),
# what source letters encrypt to produce the GKO keystream pattern?

# Under Beaufort KA: CT[i] = KA.idx_to_char((KA.char_to_idx(key) - KA.char_to_idx(PT[i])) % 26)
# And AZ keystream[i] = (AZ.char_to_idx(CT[i]) + AZ.char_to_idx(PT[i])) % 26
# For a constant KA Beaufort key, the AZ keystream varies with position.

# Per the task: for key=N (KA idx of N = ?), what letters map to G, K, O?
# G: KA.char_to_idx(G) = 13. Source: KA.idx_to_char((KA.char_to_idx(N) - 13) % 26)
# K: KA.char_to_idx(K) = 0.  Source: KA.idx_to_char((KA.char_to_idx(N) - 0) % 26) = N itself
# O: KA.char_to_idx(O) = 5.  Source: KA.idx_to_char((KA.char_to_idx(N) - 5) % 26)

# Wait — this confuses CT and PT. Let me be precise.
# Beaufort KA encryption: CT = KA[(KA_idx(key) - KA_idx(PT)) % 26]
# So if we see CT at a position, the PT was: PT = KA[(KA_idx(key) - KA_idx(CT)) % 26]
# The AZ keystream = (AZ(CT) + AZ(PT)) mod 26

# For the GKO question: at which crib positions does the keystream = G(6), K(10), O(14)?
# The keystream is already computed and fixed. The question about "sources" is:
# If we model Beaufort KA with key letter K_letter, then
# CT[i] = KA[(KA_idx(K_letter) - KA_idx(PT[i])) % 26]
# This determines CT from PT. The AZ keystream would be (AZ(CT[i]) + AZ(PT[i])) % 26.
# For the keystream to equal g (a GKO value), we need PT such that:
# (AZ(KA[(KA_idx(K_letter) - KA_idx(PT)) % 26]) + AZ(PT)) % 26 = g

# This is complex. Let's just enumerate for each key letter, which PT letters
# produce a GKO keystream value.

print("\nKey  PT letters producing GKO keystream values (via Beaufort KA)")
print("     (i.e., which PT letters K, when encrypted with key under Beau KA, give AZ ks in {6,10,14})")

for key_idx in range(26):
    key_char = KA.idx_to_char(key_idx)
    gko_sources = set()
    source_by_target = {'G': [], 'K': [], 'O': []}
    for pt_idx in range(26):
        pt_char = KA.idx_to_char(pt_idx)
        ct_idx = (key_idx - pt_idx) % 26
        ct_char = KA.idx_to_char(ct_idx)
        az_ks = (AZ.char_to_idx(ct_char) + AZ.char_to_idx(pt_char)) % 26
        if az_ks in GKO:
            gko_sources.add(pt_char)
            target_char = AZ.idx_to_char(az_ks)
            source_by_target[target_char].append(pt_char)

    src_str = ''.join(sorted(gko_sources))
    detail = f"G<-{''.join(sorted(source_by_target['G']))} K<-{''.join(sorted(source_by_target['K']))} O<-{''.join(sorted(source_by_target['O']))}"

    # Check for structure in sources
    src_az = sorted([AZ.char_to_idx(c) for c in gko_sources])
    src_ka = sorted([KA.char_to_idx(c) for c in gko_sources])

    # Check if sources form a word
    notes = []
    if len(gko_sources) == 3:
        # Check if letters spell something recognizable
        for perm in [(0,1,2),(0,2,1),(1,0,2),(1,2,0),(2,0,1),(2,1,0)]:
            word = ''.join(sorted(gko_sources)[i] for i in perm)
            if word in ('THE', 'AND', 'FOR', 'ARE', 'HIS', 'HER', 'NOT', 'HAS', 'HAD', 'ANH', 'NAH'):
                notes.append(f"spells {word}")

    gko_source_analysis[key_char] = {
        "sources": src_str,
        "detail": detail,
        "az_indices": src_az,
        "ka_indices": src_ka,
    }

    note_str = f"  [{', '.join(notes)}]" if notes else ""
    if key_char == 'N':
        note_str += " <-- key=N (SEVEN)"
    print(f"  {key_char}({key_idx:2d})  {src_str:10s}  {detail:40s}  AZ:{src_az}  KA:{src_ka}{note_str}")

results["tests"]["T5_beaufort_ka_sources"] = gko_source_analysis

# ── Test 6: Position-dependent key model ─────────────────────────────────────

print("\n" + "=" * 70)
print("TEST 6: Position-dependent key model — GKO keystream as running key")
print("=" * 70)

# The keystream IS the key under Beaufort AZ. At 12 GKO positions, the key is G, K, or O.
gko_ks_pos = []
gko_ks_chars = []
for i, pos in enumerate(ALL_CRIB_POS):
    if keystream_vals[i] in GKO:
        gko_ks_pos.append(pos)
        gko_ks_chars.append(keystream_chars[i])

print(f"\nGKO keystream positions: {gko_ks_pos}")
print(f"GKO keystream values:   {''.join(gko_ks_chars)}")
print(f"  K count: {gko_ks_chars.count('K')}, G count: {gko_ks_chars.count('G')}, O count: {gko_ks_chars.count('O')}")

# Under Beaufort AZ, key = keystream value
# Under Beaufort KA, if key letter has KA index = keystream AZ value... no, that's wrong.
# The AZ keystream is (AZ(CT) + AZ(PT)) mod 26.
# For Beaufort AZ: CT = (key - PT) mod 26 in AZ, so key = (CT + PT) mod 26 in AZ = keystream.
# So key letters at GKO positions are: G,K,O,K,K,K,O,G,G,G,O,K (in AZ Beaufort)

# In KA Beaufort: CT = KA[(KA_key - KA_PT) % 26]
# So KA_key = (KA(CT) + KA(PT)) % 26 ... no:
# CT_KA_idx = (key_KA_idx - PT_KA_idx) % 26
# key_KA_idx = (CT_KA_idx + PT_KA_idx) % 26

print("\nKA Beaufort keystream at GKO positions:")
ka_ks_at_gko = []
for i, pos in enumerate(ALL_CRIB_POS):
    if keystream_vals[i] in GKO:
        ct_ka = KA.char_to_idx(CT[pos])
        pt_ka = KA.char_to_idx(FULL_PT_AT_CRIBS[ALL_CRIB_POS.index(pos)])
        ka_key = (ct_ka + pt_ka) % 26
        ka_key_char = KA.idx_to_char(ka_key)
        print(f"  pos {pos:3d}: CT={CT[pos]}(KA {ct_ka:2d}) PT={FULL_PT_AT_CRIBS[ALL_CRIB_POS.index(pos)]}(KA {pt_ka:2d}) -> KA_key={ka_key:2d} = {ka_key_char}  (AZ_ks={keystream_chars[ALL_CRIB_POS.index(pos)]})")
        ka_ks_at_gko.append(ka_key_char)

ka_gko_counter = Counter(ka_ks_at_gko)
print(f"\nKA key letter distribution at GKO-keystream positions: {dict(ka_gko_counter.most_common())}")

# What running key text would produce these key values?
# If the running key at these 12 positions is dominated by a few letters...
all_ka_ks = []
for i, pos in enumerate(ALL_CRIB_POS):
    ct_ka = KA.char_to_idx(CT[pos])
    pt_c = FULL_PT_AT_CRIBS[i]
    pt_ka = KA.char_to_idx(pt_c)
    ka_key = (ct_ka + pt_ka) % 26
    ka_key_char = KA.idx_to_char(ka_key)
    all_ka_ks.append(ka_key_char)

print(f"\nFull KA Beaufort keystream at all 24 crib positions:")
print(f"  {''.join(all_ka_ks)}")
print(f"  Distribution: {dict(Counter(all_ka_ks).most_common())}")

results["tests"]["T6_position_dependent_key"] = {
    "gko_positions": gko_ks_pos,
    "gko_keystream_chars": gko_ks_chars,
    "ka_key_chars_at_gko": ka_ks_at_gko,
    "ka_key_distribution": dict(Counter(ka_ks_at_gko).most_common()),
    "full_ka_keystream": ''.join(all_ka_ks),
    "full_ka_distribution": dict(Counter(all_ka_ks).most_common()),
}

# ── Test 7: Consecutive position analysis ────────────────────────────────────

print("\n" + "=" * 70)
print("TEST 7: Consecutive same-keystream-value runs")
print("=" * 70)

# Find runs of consecutive crib positions with same keystream value
runs = []
current_run = [0]
for i in range(1, 24):
    if keystream_vals[i] == keystream_vals[i-1] and ALL_CRIB_POS[i] == ALL_CRIB_POS[i-1] + 1:
        current_run.append(i)
    else:
        if len(current_run) >= 2:
            runs.append(current_run[:])
        current_run = [i]
if len(current_run) >= 2:
    runs.append(current_run[:])

print(f"\nConsecutive same-value runs (length >= 2):")
for run in runs:
    positions = [ALL_CRIB_POS[i] for i in run]
    val = keystream_vals[run[0]]
    char = keystream_chars[run[0]]
    ct_chars = [CT[p] for p in positions]
    pt_chars = [FULL_PT_AT_CRIBS[i] for i in run]
    print(f"  Positions {positions}: keystream={char}({val}) x{len(run)}")
    print(f"    CT: {''.join(ct_chars)}")
    print(f"    PT: {''.join(pt_chars)}")

    # Check if CT or PT at these positions show patterns
    ct_vals = [AZ.char_to_idx(c) for c in ct_chars]
    pt_vals = [AZ.char_to_idx(c) for c in pt_chars]
    ct_diffs = [ct_vals[i+1] - ct_vals[i] for i in range(len(ct_vals)-1)]
    pt_diffs = [pt_vals[i+1] - pt_vals[i] for i in range(len(pt_vals)-1)]
    print(f"    CT diffs: {ct_diffs}, PT diffs: {pt_diffs}")
    print(f"    Note: same keystream requires CT_diff = -PT_diff (mod 26)")

# Also check near-consecutive (within same crib region, gaps of 1-2)
print(f"\nAll keystream values at consecutive positions within each crib region:")
print(f"\n  ENE (pos 21-33):")
for i in range(13):
    pos = ALL_CRIB_POS[i]
    kc = keystream_chars[i]
    kv = keystream_vals[i]
    gko_mark = "*" if kv in GKO else " "
    print(f"    pos {pos}: CT={CT[pos]} PT={FULL_PT_AT_CRIBS[i]} -> ks={kc}({kv:2d}) {gko_mark}")

print(f"\n  BCL (pos 63-73):")
for i in range(13, 24):
    pos = ALL_CRIB_POS[i]
    kc = keystream_chars[i]
    kv = keystream_vals[i]
    gko_mark = "*" if kv in GKO else " "
    print(f"    pos {pos}: CT={CT[pos]} PT={FULL_PT_AT_CRIBS[i]} -> ks={kc}({kv:2d}) {gko_mark}")

# Monte Carlo: P(longest same-value consecutive run >= observed max)
max_run_len = max(len(r) for r in runs) if runs else 1
print(f"\nLongest consecutive same-value run: {max_run_len}")

N_MC2 = 100_000
random.seed(123)
mc_max_runs = []
for _ in range(N_MC2):
    sample = [random.randint(0, 25) for _ in range(24)]
    # Check runs in first 13 (ENE-like) and last 11 (BCL-like) separately
    max_r = 1
    for block_start, block_len in [(0, 13), (13, 11)]:
        cur = 1
        for j in range(block_start + 1, block_start + block_len):
            if sample[j] == sample[j-1]:
                cur += 1
                if cur > max_r:
                    max_r = cur
            else:
                cur = 1
    mc_max_runs.append(max_r)

p_run = sum(1 for r in mc_max_runs if r >= max_run_len) / N_MC2
print(f"Monte Carlo P(max consecutive run >= {max_run_len}) = {p_run:.4f}")

results["tests"]["T7_consecutive_runs"] = {
    "runs": [{"positions": [ALL_CRIB_POS[i] for i in r],
              "value": keystream_chars[r[0]],
              "length": len(r)} for r in runs],
    "max_run_length": max_run_len,
    "p_value": p_run,
}

# ── Summary ──────────────────────────────────────────────────────────────────

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)

print(f"""
Test 1 (AP significance):
  {6,10,14} (G,K,O) gets {gko_hits}/24 hits, rank {gko_rank}/{total_aps} among all 3-element APs
  P(max AP >= {gko_hits} in random 24-draw) = {p_max_ge_observed:.4f}
  P(this specific AP >= {gko_hits}) = {p_gko_ge_observed:.4f}
  Even AZ indices: {even_count}/24 (expected 12)
  -> {'SIGNIFICANT' if p_gko_ge_observed < 0.05 else 'NOT SIGNIFICANT'} for specific AP
  -> {'SIGNIFICANT' if p_max_ge_observed < 0.05 else 'NOT SIGNIFICANT'} after multiple-testing correction

Test 2 (AP ranking):
  {aps_with_same_or_more} APs achieve >= {gko_hits} hits ({100*aps_with_same_or_more/total_aps:.1f}% of all APs)

Test 3 (K dominance):
  K=10 appears {len(k_positions)}x. CT at K-positions in GKO: {ct_gko_count}/{len(k_positions)}
  Self-reinforcement: {gko_ct_at_gko_ks}/{len(gko_ks_indices)} GKO-keystream positions have GKO CT
  (expected: {expected_ct_gko:.1f})

Test 4 (Parity):
  Same-parity CT+PT: {same_parity}/24 ({100*same_parity/24:.0f}%)
  Binomial p = {p_ge:.4f} -> {'enriched' if same_parity > 12 else 'depleted' if same_parity < 12 else 'exactly expected'}

Test 5 (Beaufort KA sources):
  See table above for per-key GKO source analysis

Test 6 (Position-dependent key):
  KA Beaufort keystream: {''.join(all_ka_ks)}
  GKO positions dominated by KA key letters: {dict(Counter(ka_ks_at_gko).most_common())}

Test 7 (Consecutive runs):
  Max consecutive same-value run: {max_run_len}
  P(>= {max_run_len} in random) = {p_run:.4f} -> {'SIGNIFICANT' if p_run < 0.05 else 'NOT SIGNIFICANT'}
""")

# ── Save results ─────────────────────────────────────────────────────────────

output_path = os.path.join(_ROOT, 'results', 'gko_ap_analysis.json')
with open(output_path, 'w') as f:
    json.dump(results, f, indent=2, default=str)

print(f"Results saved to: {output_path}")
