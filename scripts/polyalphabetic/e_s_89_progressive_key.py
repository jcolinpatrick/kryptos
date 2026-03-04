#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: polyalphabetic
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-89: Structured Non-Periodic Key + Width-7 Columnar (Model B)

Tests structured key generation models that produce non-periodic keystreams
from a compact parameterization. Each model has far fewer free parameters
than the 97 keystream values, making crib-based verification DECISIVE.

Models tested:
  P1: CT-coord vertical progressive, 8 params: key[j]=base[j%7]+s*(j//7)
  P2: PT-coord vertical progressive, 8 params: key[p]=base[p%7]+s*(p//7)
  P3: Column-specific slopes (CT-coord), 14 params
  P4: Bilinear (CT-coord), 3 params: key[j]=a*(j//7)+b*(j%7)+c
  P5: Diagonal, D params: key[j]=val[(j%7+j//7)%D]

All phases: 5040 orderings × 3 variants (Vig/Beau/VarBeau)
Expected false positives: ~0 for all phases (heavily overdetermined)

Motivation: K4's "coding charts" ($962,500) likely represent a grid-based
key lookup. Progressive keys are the natural "change in methodology"
from K3's periodic Vigenère — same column structure but row-dependent shifts.
"""

import json, os, time
from itertools import permutations
from collections import defaultdict

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
NC = len(CPOS)  # 24
W = 7
NR = (N + W - 1) // W  # 14

VNAMES = ['Vig', 'Beau', 'VBeau']

def kobs(j, pt, vi):
    """Observed keystream value at CT position j given PT value."""
    if vi == 0: return (CT_N[j] - pt) % 26       # Vigenere
    if vi == 1: return (CT_N[j] + pt) % 26        # Beaufort
    return (pt - CT_N[j]) % 26                     # Variant Beaufort

def decrypt_char(ct_val, key_val, vi):
    """Decrypt single char: return intermediate plaintext value."""
    if vi == 0: return (ct_val - key_val) % 26     # Vig: I = CT - K
    if vi == 1: return (key_val - ct_val) % 26     # Beau: I = K - CT
    return (ct_val + key_val) % 26                  # VBeau: I = CT + K

def build_perm(order):
    """Gather permutation for width-7 columnar: perm[ct_pos] = pt_pos."""
    ns = NR * W - N  # 1 short column
    p = []
    for k in range(W):
        c = order[k]
        sz = NR - 1 if c >= W - ns else NR
        for r in range(sz):
            p.append(r * W + c)
    return p

def inv_perm(perm):
    iv = [0] * N
    for i, p in enumerate(perm):
        iv[p] = i
    return iv


print("=" * 70)
print("E-S-89: Structured Non-Periodic Key + Width-7 Columnar")
print(f"  N={N}, W={W}, rows={NR}, cribs={NC}")
print("=" * 70)

t0 = time.time()
R = {}

# Precompute all permutations and their inverses
ORDERS = [list(o) for o in permutations(range(W))]
N_ORD = len(ORDERS)
PERMS = [build_perm(o) for o in ORDERS]
INVS = [inv_perm(p) for p in PERMS]

# PT grid coordinates (fixed)
PT_COL = {p: p % W for p in CPOS}
PT_ROW = {p: p // W for p in CPOS}


# ━━━ Phase 1: CT-coord vertical progressive ━━━━━━━━━━━━━━━━━━━━━━━━
# key[j] = base[j%7] + s*(j//7) mod 26   [8 unknowns, 16 excess]
# Expected FP: 5040*3*26 * 26^{-16} ≈ 0
print("\n--- P1: CT-coord vertical progressive [8 params, 16 excess] ---")

best1 = 0
best1_cfg = None

for oi in range(N_ORD):
    iv = INVS[oi]
    for vi in range(3):
        # Crib data: (k_obs, ct_col, ct_row)
        cd = []
        for p in CPOS:
            j = iv[p]
            cd.append((kobs(j, PT_N[p], vi), j % W, j // W))

        for s in range(26):
            col_vals = {}
            col_cnt = {}
            for k, c, r in cd:
                req = (k - s * r) % 26
                if c not in col_vals:
                    col_vals[c] = set()
                    col_cnt[c] = 0
                col_vals[c].add(req)
                col_cnt[c] += 1

            m = sum(col_cnt[c] for c in col_vals if len(col_vals[c]) == 1)

            if m > best1:
                best1 = m
                best1_cfg = (ORDERS[oi], VNAMES[vi], s)

            if m >= 20:
                # Determine base values
                bases = {}
                for c in col_vals:
                    if len(col_vals[c]) == 1:
                        bases[c] = list(col_vals[c])[0]

                # Decrypt full text
                pt_chars = ['?'] * N
                for j in range(N):
                    c = j % W
                    if c in bases:
                        kv = (bases[c] + s * (j // W)) % 26
                        pt_chars[PERMS[oi][j]] = AZ[decrypt_char(CT_N[j], kv, vi)]

                print(f"  *** P1 HIT: {m}/24 order={ORDERS[oi]} {VNAMES[vi]} slope={s}")
                print(f"      bases={bases}")
                print(f"      PT: {''.join(pt_chars[:50])}...")

    if (oi + 1) % 1000 == 0:
        print(f"  {oi+1}/{N_ORD} ({time.time()-t0:.0f}s) best={best1}")

t1 = time.time()
print(f"\n  P1 done: {t1-t0:.1f}s, best={best1}/24 cfg={best1_cfg}")
R['P1_ct_progressive'] = {'best': best1, 'cfg': str(best1_cfg)}


# ━━━ Phase 2: PT-coord vertical progressive ━━━━━━━━━━━━━━━━━━━━━━━━
# key[p] = base[p%7] + s*(p//7) mod 26   [8 unknowns, 16 excess]
# Same k_obs values, different grouping (by PT column/row)
print("\n--- P2: PT-coord vertical progressive [8 params, 16 excess] ---")

best2 = 0
best2_cfg = None

for oi in range(N_ORD):
    iv = INVS[oi]
    for vi in range(3):
        for s in range(26):
            col_vals = {}
            col_cnt = {}
            for p in CPOS:
                j = iv[p]
                k = kobs(j, PT_N[p], vi)
                pc, pr = PT_COL[p], PT_ROW[p]
                req = (k - s * pr) % 26
                if pc not in col_vals:
                    col_vals[pc] = set()
                    col_cnt[pc] = 0
                col_vals[pc].add(req)
                col_cnt[pc] += 1

            m = sum(col_cnt[c] for c in col_vals if len(col_vals[c]) == 1)

            if m > best2:
                best2 = m
                best2_cfg = (ORDERS[oi], VNAMES[vi], s)

            if m >= 20:
                print(f"  *** P2 HIT: {m}/24 order={ORDERS[oi]} {VNAMES[vi]} slope={s}")

    if (oi + 1) % 1000 == 0:
        print(f"  {oi+1}/{N_ORD} ({time.time()-t0:.0f}s) best={best2}")

t2 = time.time()
print(f"\n  P2 done: {t2-t1:.1f}s, best={best2}/24 cfg={best2_cfg}")
R['P2_pt_progressive'] = {'best': best2, 'cfg': str(best2_cfg)}


# ━━━ Phase 3: Column-specific slopes (CT-coord) ━━━━━━━━━━━━━━━━━━━━
# key[j] = base[j%7] + slope[j%7]*(j//7) mod 26   [14 unknowns, 10 excess]
# Each column independently picks its slope. Strict: all cribs in column agree.
print("\n--- P3: Column-specific slopes [14 params, 10 excess] ---")

best3 = 0
best3_cfg = None

for oi in range(N_ORD):
    iv = INVS[oi]
    for vi in range(3):
        # Group cribs by CT column
        cc = defaultdict(list)
        for p in CPOS:
            j = iv[p]
            k = kobs(j, PT_N[p], vi)
            cc[j % W].append((j // W, k))

        strict = 0
        for col, cribs in cc.items():
            n = len(cribs)
            if n <= 1:
                strict += n
                continue
            ok = False
            for s in range(26):
                bs = set((k - s * r) % 26 for r, k in cribs)
                if len(bs) == 1:
                    ok = True
                    break
            strict += n if ok else 0

        if strict > best3:
            best3 = strict
            best3_cfg = (ORDERS[oi], VNAMES[vi])

        if strict >= 20:
            print(f"  *** P3 HIT: {strict}/24 order={ORDERS[oi]} {VNAMES[vi]}")

    if (oi + 1) % 1000 == 0:
        print(f"  {oi+1}/{N_ORD} ({time.time()-t0:.0f}s) best={best3}")

t3 = time.time()
print(f"\n  P3 done: {t3-t2:.1f}s, best={best3}/24 cfg={best3_cfg}")
R['P3_column_slopes'] = {'best': best3, 'cfg': str(best3_cfg)}


# ━━━ Phase 4: Bilinear key ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# key[j] = a*(j//7) + b*(j%7) + c mod 26   [3 unknowns, 21 excess]
# Expected FP: 5040*3 * 26^{-21} ≈ 0
print("\n--- P4: Bilinear key [3 params, 21 excess] ---")

best4 = 0
best4_cfg = None

for oi in range(N_ORD):
    iv = INVS[oi]
    for vi in range(3):
        jd = []
        for p in CPOS:
            j = iv[p]
            jd.append((kobs(j, PT_N[p], vi), j // W, j % W))

        k0, r0, c0 = jd[0]
        k1, r1, c1 = jd[1]
        k2, r2, c2 = jd[2]

        best_local = 0
        for a in range(26):
            for b in range(26):
                c = (k0 - a * r0 - b * c0) % 26
                # Quick check crib 1
                if (a * r1 + b * c1 + c) % 26 != k1:
                    continue
                # Quick check crib 2
                if (a * r2 + b * c2 + c) % 26 != k2:
                    continue
                # Full check
                m = sum(1 for ki, ri, ci in jd if (a * ri + b * ci + c) % 26 == ki)
                if m > best_local:
                    best_local = m

        if best_local > best4:
            best4 = best_local
            best4_cfg = (ORDERS[oi], VNAMES[vi])

        if best_local >= 20:
            print(f"  *** P4 HIT: {best_local}/24 order={ORDERS[oi]} {VNAMES[vi]}")

    if (oi + 1) % 500 == 0:
        print(f"  {oi+1}/{N_ORD} ({time.time()-t0:.0f}s) best={best4}")

t4 = time.time()
print(f"\n  P4 done: {t4-t3:.1f}s, best={best4}/24 cfg={best4_cfg}")
R['P4_bilinear'] = {'best': best4, 'cfg': str(best4_cfg)}


# ━━━ Phase 5: Diagonal key ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# key[j] = val[(j%7 + j//7) % D]   [D unknowns]
# Also tests anti-diagonal: (j%7 - j//7) % D
print("\n--- P5: Diagonal key [D params, D in {5..14}] ---")

best5 = 0
best5_cfg = None

for D in [5, 6, 7, 8, 9, 10, 11, 13, 14]:
    for oi in range(N_ORD):
        iv = INVS[oi]
        for vi in range(3):
            # Forward diagonal
            dv = {}
            dc = {}
            for p in CPOS:
                j = iv[p]
                k = kobs(j, PT_N[p], vi)
                d = (j % W + j // W) % D
                if d not in dv:
                    dv[d] = set()
                    dc[d] = 0
                dv[d].add(k)
                dc[d] += 1

            m = sum(dc[d] for d in dv if len(dv[d]) == 1)
            if m > best5:
                best5 = m
                best5_cfg = (D, 'fwd', ORDERS[oi], VNAMES[vi])
            if m >= 20:
                print(f"  *** P5 HIT: {m}/24 D={D} fwd order={ORDERS[oi]} {VNAMES[vi]}")

            # Anti-diagonal
            dv2 = {}
            dc2 = {}
            for p in CPOS:
                j = iv[p]
                k = kobs(j, PT_N[p], vi)
                d = (j % W - j // W) % D
                if d not in dv2:
                    dv2[d] = set()
                    dc2[d] = 0
                dv2[d].add(k)
                dc2[d] += 1

            m2 = sum(dc2[d] for d in dv2 if len(dv2[d]) == 1)
            if m2 > best5:
                best5 = m2
                best5_cfg = (D, 'anti', ORDERS[oi], VNAMES[vi])
            if m2 >= 20:
                print(f"  *** P5 HIT: {m2}/24 D={D} anti order={ORDERS[oi]} {VNAMES[vi]}")

    print(f"  D={D}: best so far {best5}/24 ({time.time()-t0:.0f}s)")

t5 = time.time()
print(f"\n  P5 done: {t5-t4:.1f}s, best={best5}/24 cfg={best5_cfg}")
R['P5_diagonal'] = {'best': best5, 'cfg': str(best5_cfg)}


# ━━━ Phase 6: Horizontal progressive ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# key[j] = base[j//7] + s*(j%7) mod 26   [15 unknowns (14 bases + 1 slope)]
# Key progresses ACROSS columns for each row, with row-specific offset
print("\n--- P6: Horizontal progressive [15 params, 9 excess] ---")

best6 = 0
best6_cfg = None

for oi in range(N_ORD):
    iv = INVS[oi]
    for vi in range(3):
        cd = []
        for p in CPOS:
            j = iv[p]
            cd.append((kobs(j, PT_N[p], vi), j // W, j % W))

        for s in range(26):
            row_vals = {}
            row_cnt = {}
            for k, r, c in cd:
                req = (k - s * c) % 26
                if r not in row_vals:
                    row_vals[r] = set()
                    row_cnt[r] = 0
                row_vals[r].add(req)
                row_cnt[r] += 1

            m = sum(row_cnt[r] for r in row_vals if len(row_vals[r]) == 1)

            if m > best6:
                best6 = m
                best6_cfg = (ORDERS[oi], VNAMES[vi], s)

            if m >= 20:
                print(f"  *** P6 HIT: {m}/24 order={ORDERS[oi]} {VNAMES[vi]} slope={s}")

    if (oi + 1) % 1000 == 0:
        print(f"  {oi+1}/{N_ORD} ({time.time()-t0:.0f}s) best={best6}")

t6 = time.time()
print(f"\n  P6 done: {t6-t5:.1f}s, best={best6}/24 cfg={best6_cfg}")
R['P6_horizontal'] = {'best': best6, 'cfg': str(best6_cfg)}


# ━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
total = time.time() - t0
overall = max(v['best'] for v in R.values())

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
for k, v in R.items():
    print(f"  {k}: {v['best']}/24")
print(f"  Total: {total:.1f}s")

if overall >= 20:
    verdict = f"STRONG SIGNAL — {overall}/24"
elif overall >= 15:
    verdict = f"INTERESTING — {overall}/24"
elif overall >= 10:
    verdict = f"MARGINAL — {overall}/24"
else:
    verdict = f"NO SIGNAL — {overall}/24 at noise floor"

print(f"\n  Verdict: {verdict}")

# Expected noise analysis
print("\n  Expected noise floors:")
print("    P1 (8 params): score ~1-2/24 random, FP for 24/24: ~10^{-19}")
print("    P2 (8 params): same as P1")
print("    P3 (14 params): score ~4-6/24 (cols w/ 2 cribs often match)")
print("    P4 (3 params): score ~3/24 random")
print("    P5 (D params): score ~2-4/24 random")
print("    P6 (15 params): score ~2-4/24 random")

out = {
    'experiment': 'E-S-89',
    'description': 'Structured non-periodic key + width-7 columnar',
    'results': R,
    'elapsed_seconds': total,
    'verdict': verdict,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_89_progressive_key.json", "w") as f:
    json.dump(out, f, indent=2)
print(f"\n  Artifact: results/e_s_89_progressive_key.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_89_progressive_key.py")
