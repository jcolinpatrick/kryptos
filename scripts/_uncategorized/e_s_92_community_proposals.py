#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-92: Community Proposals + Creative Models

Tests specific community-proposed solutions and creative cipher models:

  P1: Naughton/Grok3 — reverse, Vig(KRYPTOS), reverse
  P2: Nash — pure transposition (IC check = instant disproof)
  P3: Double-key Vigenère — key1(period 7) + key2(period p2) + w7 columnar
  P4: Row-shifted columnar — standard w7 columnar + per-row cyclic shift
  P5: Keyed alphabet Vigenère — KRYPTOS-alphabet tableau + various keys + w7
  P6: Bifid-like with 6×5 grid (26 letters in 30 cells)
"""

import json, os, time
from itertools import permutations, product
from collections import defaultdict, Counter
from math import gcd

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
I2N = {c: i for i, c in enumerate(AZ)}
CT_N = [I2N[c] for c in CT]

CRIBS = {
    21:'E',22:'A',23:'S',24:'T',25:'N',26:'O',27:'R',28:'T',29:'H',30:'E',31:'A',32:'S',33:'T',
    63:'B',64:'E',65:'R',66:'L',67:'I',68:'N',69:'C',70:'L',71:'O',72:'C',73:'K'}
PT_N = {p: I2N[c] for p, c in CRIBS.items()}
CPOS = sorted(CRIBS.keys())
W = 7

print("=" * 70)
print("E-S-92: Community Proposals + Creative Models")
print("=" * 70)

t0 = time.time()
R = {}


# ━━━ Phase 1: Naughton/Grok3 — Reverse + Vig(KRYPTOS) + Reverse ━━━━
print("\n--- P1: Naughton proposal (reverse + Vig + reverse) ---")

# Method: CT -> reverse -> Vigenere decrypt with KRYPTOS -> reverse -> PT
ct_rev = CT[::-1]
ct_rev_n = [I2N[c] for c in ct_rev]

kryptos_key = [I2N[c] for c in "KRYPTOS"]

# Decrypt reversed CT with Vig key KRYPTOS
intermediate = []
for j in range(N):
    v = (ct_rev_n[j] - kryptos_key[j % 7]) % 26
    intermediate.append(v)

# Reverse back
pt_naughton_n = intermediate[::-1]
pt_naughton = ''.join(AZ[v] for v in pt_naughton_n)

# Check cribs
crib_matches = sum(1 for p in CPOS if pt_naughton_n[p] == PT_N[p])

print(f"  Proposed plaintext: {pt_naughton}")
print(f"  Crib matches: {crib_matches}/24")

# Also test Beaufort variant
intermediate_b = [(kryptos_key[j % 7] - ct_rev_n[j]) % 26 for j in range(N)]
pt_b = ''.join(AZ[v] for v in intermediate_b[::-1])
crib_b = sum(1 for p in CPOS if intermediate_b[::-1][p] == PT_N[p])
print(f"  Beaufort variant: {crib_b}/24")

# Variant Beaufort
intermediate_vb = [(ct_rev_n[j] + kryptos_key[j % 7]) % 26 for j in range(N)]
pt_vb = ''.join(AZ[v] for v in intermediate_vb[::-1])
crib_vb = sum(1 for p in CPOS if intermediate_vb[::-1][p] == PT_N[p])
print(f"  VarBeau variant: {crib_vb}/24")

best_naughton = max(crib_matches, crib_b, crib_vb)
print(f"  Best: {best_naughton}/24 — {'NOISE' if best_naughton < 10 else 'INVESTIGATE'}")
R['P1_naughton'] = {'best': best_naughton, 'verdict': 'NOISE' if best_naughton < 10 else 'INVESTIGATE'}


# ━━━ Phase 2: Nash — Pure transposition check ━━━━━━━━━━━━━━━━━━━━━━
print("\n--- P2: Nash pure transposition check ---")

# If K4 is pure transposition, CT and PT have same letter frequencies
# IC should be ~0.066 (English), not 0.0361
ct_freq = Counter(CT_N)
ic = sum(f * (f - 1) for f in ct_freq.values()) / (N * (N - 1))
print(f"  CT IC: {ic:.4f}")
print(f"  English IC: ~0.066, Random IC: ~0.0385")

if ic < 0.050:
    print(f"  IC = {ic:.4f} << 0.050 — PURE TRANSPOSITION DEFINITIVELY ELIMINATED")
    R['P2_nash'] = {'ic': ic, 'verdict': 'ELIMINATED (IC too low)'}
else:
    R['P2_nash'] = {'ic': ic, 'verdict': 'POSSIBLE'}

# Also check: do the crib letters appear in CT at the right positions?
# For pure transposition, CT[σ(p)] = PT[p] for some permutation σ
# So each crib letter must appear somewhere in CT
pt_letters = [CRIBS[p] for p in CPOS]
for ch in set(pt_letters):
    ct_count = CT.count(ch)
    pt_count = pt_letters.count(ch)
    if pt_count > ct_count:
        print(f"  IMPOSSIBLE: PT needs {pt_count}× '{ch}' but CT only has {ct_count}")

# Check if any standard grid readings produce the cribs
# Test 31×3, 32×3, 33×3 grids (Nash claims 31×3)
for w in [3, 31, 32, 33]:
    if w > N:
        continue
    nr = (N + w - 1) // w
    # Standard columnar reading
    for order in [list(range(w)), list(range(w-1, -1, -1))]:
        perm = []
        ns = nr * w - N
        for k in range(min(w, N)):
            c = order[k] if k < len(order) else k
            if c >= w:
                continue
            sz = nr - 1 if c >= w - ns else nr
            for r in range(sz):
                pos = r * w + c
                if pos < N:
                    perm.append(pos)
        if len(perm) == N and sorted(perm) == list(range(N)):
            # Check crib matches (pure transposition: PT[perm[j]] should be at pos j)
            matches = sum(1 for p in CPOS if perm[p] in PT_N and CT_N[perm[p]] == PT_N[perm[p]])
            # Wait, for pure transposition: CT = σ(PT), so PT[i] = CT[σ^{-1}(i)]
            # Actually: output[i] = input[perm[i]] for gather convention
            # So "CT is a transposition of PT" means CT[i] = PT[perm[i]]
            # At crib position p: CT[p] should equal PT[perm[p]]... no
            # Actually for pure transposition, PT is the unknown and CT is the scrambled PT
            # So PT[perm[p]] = CT[p]... hmm this is confusing.
            # Let me just check: does the reading produce the cribs?
            reading = ''.join(CT[perm[j]] for j in range(N))
            matches = sum(1 for p in CPOS if I2N.get(reading[p], -1) == PT_N[p])
            if matches > 3:
                print(f"  Grid {nr}×{w} order={order[:5]}: {matches}/24 crib matches")


# ━━━ Phase 3: Double-key Vigenère + w7 columnar ━━━━━━━━━━━━━━━━━━━━
# key[j] = key1[j%7] + key2[j%p2] mod 26
# Combined period = 7*p2 when gcd(7,p2)=1
# Test with w7 columnar transposition (Model B)
print("\n--- P3: Double-key Vigenère (period 7 + p2) + w7 columnar ---")

def build_perm(order, w=W):
    nr = (N + w - 1) // w
    ns = nr * w - N
    p = []
    for k in range(w):
        c = order[k]
        sz = nr - 1 if c >= w - ns else nr
        for r in range(sz):
            p.append(r * w + c)
    return p if len(p) == N else None

def inv_perm(perm):
    iv = [0] * N
    for i, p in enumerate(perm):
        iv[p] = i
    return iv

ORDERS7 = [list(o) for o in permutations(range(7))]
PERMS7 = [build_perm(o) for o in ORDERS7]
INVS7 = [inv_perm(p) for p in PERMS7]

best_p3 = (0, None)

for p2 in [2, 3, 4, 5, 8, 9, 11, 13]:
    combined_period = 7 * p2 // gcd(7, p2)
    if combined_period > 48:  # Too underdetermined
        continue

    for oi in range(len(ORDERS7)):
        iv = INVS7[oi]
        for vi in range(3):
            # Compute k_obs for each crib
            cd = []
            for p in CPOS:
                j = iv[p]
                if vi == 0: k = (CT_N[j] - PT_N[p]) % 26
                elif vi == 1: k = (CT_N[j] + PT_N[p]) % 26
                else: k = (PT_N[p] - CT_N[j]) % 26
                cd.append((j, k))

            # Group by combined residue (j%7, j%p2)
            residue_keys = {}
            consistent = True
            for j, k in cd:
                r = (j % 7, j % p2)
                if r in residue_keys:
                    if residue_keys[r] != k:
                        consistent = False
                        break
                else:
                    residue_keys[r] = k

            if consistent:
                m = len(cd)  # All 24 match
            else:
                # Count max matches
                residue_vals = defaultdict(list)
                for j, k in cd:
                    r = (j % 7, j % p2)
                    residue_vals[r].append(k)
                m = sum(max(Counter(vals).values()) for vals in residue_vals.values())

            if m > best_p3[0]:
                best_p3 = (m, (p2, ORDERS7[oi], ['V','B','X'][vi]))

            if m >= 20:
                print(f"  HIT: {m}/24 p2={p2} order={ORDERS7[oi]} {'VBX'[vi]}")

    el = time.time() - t0
    print(f"  p2={p2} (combined_period={combined_period}): best={best_p3[0]}/24 ({el:.0f}s)")

R['P3_double_key'] = {'best': best_p3[0], 'cfg': str(best_p3[1])}
print(f"\n  P3 best: {best_p3[0]}/24 {best_p3[1]}")


# ━━━ Phase 4: Row-shifted columnar ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Standard w7 columnar, but each row is cyclically shifted by s*row mod 7
# This creates a non-standard transposition preserving column structure
print("\n--- P4: Row-shifted columnar + period-7 Vig ---")

best_p4 = (0, None)

for oi, order in enumerate(ORDERS7):
    perm_base = build_perm(order)
    if perm_base is None:
        continue
    iv_base = inv_perm(perm_base)

    for shift in range(1, 7):  # Row shift amount per row
        # Build modified permutation: within each row of the PT grid,
        # shift positions by (shift * row) mod 7
        modified_perm = [0] * N
        for j in range(N):
            pt_pos = perm_base[j]
            pt_row = pt_pos // 7
            pt_col = pt_pos % 7
            # Apply row shift
            new_col = (pt_col + shift * pt_row) % 7
            new_pt_pos = pt_row * 7 + new_col
            if new_pt_pos < N:
                modified_perm[j] = new_pt_pos
            else:
                modified_perm[j] = pt_pos  # Keep original if out of bounds

        if sorted(modified_perm) != list(range(N)):
            continue  # Invalid permutation

        iv_mod = inv_perm(modified_perm)

        for vi in range(3):
            # Check period-7 consistency
            residue_keys = {}
            consistent = True
            for p in CPOS:
                j = iv_mod[p]
                if vi == 0: k = (CT_N[j] - PT_N[p]) % 26
                elif vi == 1: k = (CT_N[j] + PT_N[p]) % 26
                else: k = (PT_N[p] - CT_N[j]) % 26
                r = j % 7
                if r in residue_keys:
                    if residue_keys[r] != k:
                        consistent = False
                        break
                else:
                    residue_keys[r] = k

            m = 24 if consistent else 0
            if not consistent:
                rv = defaultdict(list)
                for p in CPOS:
                    j = iv_mod[p]
                    if vi == 0: k = (CT_N[j] - PT_N[p]) % 26
                    elif vi == 1: k = (CT_N[j] + PT_N[p]) % 26
                    else: k = (PT_N[p] - CT_N[j]) % 26
                    rv[j % 7].append(k)
                m = sum(max(Counter(v).values()) for v in rv.values())

            if m > best_p4[0]:
                best_p4 = (m, (order, shift, ['V','B','X'][vi]))

            if m >= 15:
                print(f"  HIT: {m}/24 order={order} shift={shift} {'VBX'[vi]}")

    if (oi + 1) % 1000 == 0:
        print(f"  {oi+1}/5040 ({time.time()-t0:.0f}s) best={best_p4[0]}")

R['P4_row_shifted'] = {'best': best_p4[0], 'cfg': str(best_p4[1])}
print(f"\n  P4 best: {best_p4[0]}/24 {best_p4[1]}")


# ━━━ Phase 5: Keyed-alphabet Vigenère with various keywords ━━━━━━━━
# Use KRYPTOS-derived mixed alphabet as the Vigenère tableau base
print("\n--- P5: KRYPTOS-alphabet Vigenère + various period-7 keys + w7 ---")

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}

# Build KA-based Vigenère encryption: CT[j] = KA[(KA_idx(PT[j]) + key[j]) % 26]
# Decryption: PT[j] = KA[(KA_idx(CT[j]) - key[j]) % 26]

best_p5 = (0, None)
CT_KA = [KA_IDX[c] for c in CT]
PT_KA = {p: KA_IDX[c] for p, c in CRIBS.items()}

for oi, order in enumerate(ORDERS7):
    perm = build_perm(order)
    iv = inv_perm(perm)

    for vi in range(2):  # Vig and Beau only
        residue_keys = {}
        consistent = True
        for p in CPOS:
            j = iv[p]
            if vi == 0:
                k = (CT_KA[j] - PT_KA[p]) % 26
            else:
                k = (CT_KA[j] + PT_KA[p]) % 26
            r = j % 7
            if r in residue_keys:
                if residue_keys[r] != k:
                    consistent = False
                    break
            else:
                residue_keys[r] = k

        m = 24 if consistent else 0
        if not consistent:
            rv = defaultdict(list)
            for p in CPOS:
                j = iv[p]
                if vi == 0:
                    k = (CT_KA[j] - PT_KA[p]) % 26
                else:
                    k = (CT_KA[j] + PT_KA[p]) % 26
                rv[j % 7].append(k)
            m = sum(max(Counter(v).values()) for v in rv.values())

        if m > best_p5[0]:
            best_p5 = (m, (order, ['V','B'][vi]))
        if m >= 15:
            print(f"  HIT: {m}/24 order={order} {'VB'[vi]}")

    if (oi + 1) % 1000 == 0:
        print(f"  {oi+1}/5040 ({time.time()-t0:.0f}s) best={best_p5[0]}")

R['P5_ka_vig'] = {'best': best_p5[0], 'cfg': str(best_p5[1])}
print(f"\n  P5 best: {best_p5[0]}/24 {best_p5[1]}")


# ━━━ Phase 6: Bifid-like with 6×5 grid ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 6 columns × 5 rows = 30 cells, 26 used + 4 empty
# Standard Bifid 5×5 is eliminated (25 letters). Test 6×5 variant.
# The grid arrangement uses keyword KRYPTOS to fill.
print("\n--- P6: Bifid 6×5 grid (26 letters) + period check ---")

# Build grid from KRYPTOS keyword
def build_grid_65(keyword):
    seen = set()
    grid = []
    for c in keyword.upper():
        if c not in seen and c in AZ:
            seen.add(c)
            grid.append(c)
    for c in AZ:
        if c not in seen:
            seen.add(c)
            grid.append(c)
    return grid[:26]  # 26 letters in order

grid = build_grid_65("KRYPTOS")
g2rc = {}  # letter -> (row, col)
rc2g = {}  # (row, col) -> letter
for i, c in enumerate(grid):
    r, co = i // 6, i % 6
    g2rc[c] = (r, co)
    rc2g[(r, co)] = c

# Check if grid covers all 26 letters
assert len(set(grid)) == 26

# Bifid encryption with period p:
# 1. Split plaintext into blocks of p
# 2. For each block, extract rows and cols via Polybius
# 3. Concatenate rows then cols: r1r2...rp c1c2...cp
# 4. Take pairs (r1,c1), (r2,c2), ... and look up in grid
# This should produce CT. Check if CT matches.

best_p6 = (0, None)

for period in range(2, 20):
    # Try Bifid encryption: does encrypting some PT produce CT?
    # We don't know PT, but we can check crib positions.
    # For crib positions, we know PT[p]. The Bifid encryption of a block
    # containing position p produces CT at that position.
    # The check is complex because Bifid is not position-independent.

    # Simplified check: for each period, check if the crib-derived
    # row/column structure is consistent.
    # At crib position p in block b = p // period, offset within block o = p % period:
    # The CT at position p comes from combining row[o] with col[o]
    # where the row/col sequences are the concatenated rows then cols of the block's PT.

    # This is too complex for a quick check. Let me just test a few small periods
    # by brute-forcing the unknown PT characters within crib-containing blocks.
    # Skip for now - mark as needing deeper analysis.
    pass

print(f"  Bifid 6×5 analysis: DEFERRED (complex, needs dedicated experiment)")
R['P6_bifid65'] = {'best': 0, 'verdict': 'DEFERRED'}


# ━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
total = time.time() - t0
overall = max(v.get('best', 0) for v in R.values())

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
for k, v in R.items():
    print(f"  {k}: {v}")
print(f"  Total: {total:.1f}s")

if overall >= 20:
    verdict = f"SIGNAL — {overall}/24"
elif overall >= 15:
    verdict = f"INTERESTING — {overall}/24"
else:
    verdict = f"NO SIGNAL — {overall}/24"

print(f"\n  Verdict: {verdict}")

out = {
    'experiment': 'E-S-92',
    'description': 'Community proposals + creative models',
    'results': {k: str(v) for k, v in R.items()},
    'elapsed_seconds': total,
    'verdict': verdict,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_92_community_proposals.json", "w") as f:
    json.dump(out, f, indent=2)
print(f"\n  Artifact: results/e_s_92_community_proposals.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_92_community_proposals.py")
