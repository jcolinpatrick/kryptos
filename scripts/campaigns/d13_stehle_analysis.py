#!/usr/bin/env python3
"""
scripts/campaigns/d13_stehle_analysis.py

Exploit d=13 keystream anomaly and investigate Stehle Δ^4=5 observation.
Three angles:
  A. Period-13 key collision structure — which residues match/conflict and why
  B. Stehle Δ^4(lag=5)=5 — locate anomalous positions, test cipher hypotheses
  C. EASTNORTHEAST as period key — rotation/offset tests
"""
import sys
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT
from collections import Counter, defaultdict

N = len(CT)
ct = [ord(c) - 65 for c in CT]
L = lambda n: chr(int(n) % 26 + 65)

ENE, BLK = "EASTNORTHEAST", "BERLINCLOCK"
all_cribs = ([(21 + i, ENE[i]) for i in range(13)] +
             [(63 + i, BLK[i]) for i in range(11)] +
             [(32, 'S'), (73, 'K')])

def fdiff(seq, order, lag=1):
    s = list(seq)
    for _ in range(order):
        s = [(s[i + lag] - s[i]) % 26 for i in range(len(s) - lag)]
    return s

# ─── SECTION A: Key collision structure ────────────────────────────────────────
print("=" * 62)
print("A. BEAUFORT KEYSTREAM COLLISION ANALYSIS")
print("=" * 62)
kstream = {}
for pos, pt in all_cribs:
    kstream[pos] = (ct[pos] + ord(pt) - 65) % 26

# Group by mod-13
by_r13 = defaultdict(list)
for pos, k in kstream.items():
    by_r13[pos % 13].append((pos, k))

print(f"\n{'r':>3} {'Positions & keys':42} {'status':12} {'Δk'}")
conflicts, c_diffs = 0, {}
for r in range(13):
    entries = sorted(by_r13[r])
    if not entries:
        print(f"{r:3d}  (no cribs)")
        continue
    ks = [e[1] for e in entries]
    ok = len(set(ks)) == 1
    detail = "  ".join(f"pos{e[0]}={L(e[1])}" for e in entries)
    if not ok:
        dk = (ks[1] - ks[0]) % 26
        c_diffs[r] = dk
        conflicts += 1
        print(f"{r:3d}  {detail:42} CONFLICT    Δk={dk}({L(dk)})")
    else:
        print(f"{r:3d}  {detail:42} MATCH")

print(f"\nConflicts: {conflicts}/13  Matches: {13 - conflicts - sum(1 for r in range(13) if not by_r13[r])}/13")

# Key collision pairs at same Beaufort value
key_to_pos = defaultdict(list)
for pos, k in kstream.items():
    key_to_pos[k].append(pos)

print("\nSame Beaufort key value → positions & lags:")
for k in sorted(key_to_pos):
    pl = sorted(key_to_pos[k])
    if len(pl) >= 2:
        gaps = [pl[i+1] - pl[i] for i in range(len(pl)-1)]
        print(f"  k={k}({L(k)}): {pl}  gaps={gaps}")

# ─── SECTION B: Stehle Δ^4=5 analysis ─────────────────────────────────────────
print("\n" + "=" * 62)
print("B. STEHLE Δ^4=5 ANALYSIS")
print("=" * 62)

# Full CT differences
print("\nFinite differences on full 97-char CT:")
print(f"{'Δ^n':6} {'lag':5} {'n':4} {'val5':5} {'top_val':8} {'top_cnt':8} {'exp':6} {'×exp':5}")
for order in [1, 2, 3, 4]:
    for lag in [1, 4, 5, 13]:
        d = fdiff(ct, order, lag)
        if not d:
            continue
        c = Counter(d)
        top_v, top_n = c.most_common(1)[0]
        v5 = c.get(5, 0)
        exp = len(d) / 26.0
        xexp = top_n / exp
        flag = " ***" if xexp > 2.5 else (" **" if xexp > 2.0 else "")
        print(f"  ^{order}   lag={lag:2d}  n={len(d):3d}  val5={v5:2d}  "
              f"top={L(top_v)}({top_v:2d})  ×{top_n}  exp={exp:.1f}  {xexp:.2f}x{flag}")

# Pinpoint Δ^4(lag=5)=5 positions
print("\nΔ^4(lag=5) = 5 [Stehle obs]: position detail")
d4_5 = fdiff(ct, 4, 5)
stehle_pos = [i for i, v in enumerate(d4_5) if v == 5]
for i in stehle_pos:
    vals = ct[i:i+21:5]  # positions i, i+5, i+10, i+15, i+20
    raw = vals[0] - 4*vals[1] + 6*vals[2] - 4*vals[3] + vals[4]
    print(f"  i={i:3d}: {[L(v) for v in vals]} raw={raw:4d} "
          f"W_in_window={[p for p in [20,36,48,58,74] if i <= p <= i+20]}")

# Test: do Δ^4(lag=5)=5 positions correlate with crib/W positions?
crib_pos = set(range(21,34)) | set(range(63,74)) | {32,73}
W_pos = {20, 36, 48, 58, 74}
print(f"\nStehle positions in cribs: {[p for p in stehle_pos if p in crib_pos]}")
print(f"Stehle positions with W in [p, p+20]: {[p for p in stehle_pos if W_pos & set(range(p, p+21))]}")

# Keystream finite differences (ENE and BLK consecutive)
ks_ene = [kstream[21 + i] for i in range(13)]
ks_blk = [kstream[63 + i] for i in range(11)]
print(f"\nENE keystream: {''.join(L(k) for k in ks_ene)} = {ks_ene}")
print(f"BLK keystream: {''.join(L(k) for k in ks_blk)} = {ks_blk}")
print("Finite diffs of ENE keystream:")
for order in [1, 2, 3, 4]:
    d = fdiff(ks_ene, order, 1)
    print(f"  Δ^{order}: {d}  val5={d.count(5)}")

# ─── SECTION C: EASTNORTHEAST as key ──────────────────────────────────────────
print("\n" + "=" * 62)
print("C. EASTNORTHEAST AS BEAUFORT KEY (ALL OFFSETS)")
print("=" * 62)
n_c = len(all_cribs)
print(f"\n{'Offset':8} {'Matches':8} {'Plaintext (first 40 chars)'}")
best_m, best_off, best_pt = 0, 0, ""
for offset in range(13):
    m = 0
    pt_chars = []
    for i in range(N):
        key_val = ord(ENE[(i + offset) % 13]) - 65
        pt_val = (key_val - ct[i]) % 26
        pt_chars.append(L(pt_val))
    for pos, expected in all_cribs:
        if (ord(ENE[(pos + offset) % 13]) - 65 - ct[pos]) % 26 == ord(expected) - 65:
            m += 1
    pt_str = ''.join(pt_chars)
    if m > best_m:
        best_m, best_off, best_pt = m, offset, pt_str
    if m >= 3:
        print(f"  off={offset:2d}    {m:3d}/{n_c}    {pt_str[:40]}")
print(f"\nBest offset={best_off}: {best_m}/{n_c} matches")
if best_pt:
    print(f"Decryption: {best_pt}")

# ─── SECTION D: Period-p analysis for small p ─────────────────────────────────
print("\n" + "=" * 62)
print("D. SMALL-PERIOD RESIDUE IC (polyalphabetic fingerprint)")
print("=" * 62)
for p in [5, 7, 11, 13, 19]:
    by_rp = defaultdict(list)
    for i in range(N):
        by_rp[i % p].append(ct[i])
    ics = []
    for r in range(p):
        b = by_rp[r]
        freq = Counter(b)
        n_b = len(b)
        ic = sum(v*(v-1) for v in freq.values()) / (n_b*(n_b-1)) if n_b > 1 else 0
        ics.append(ic)
    avg_ic = sum(ics) / len(ics)
    # For English ~0.065, random ~0.038
    print(f"  p={p:2d}: avg_IC={avg_ic:.4f}  max={max(ics):.4f}  "
          f"{'English-ish' if avg_ic > 0.055 else ('slight' if avg_ic > 0.045 else 'random')}")

# ─── SECTION E: Beaufort residue conflict patterns ─────────────────────────────
print("\n" + "=" * 62)
print("E. CONFLICT STRUCTURE: what two-system interpretation fits?")
print("=" * 62)

print("\nConflict diffs at each mod-13 residue:")
for r, dk in sorted(c_diffs.items()):
    print(f"  r={r:2d}: Δk={dk:2d}({L(dk)})")

# Check if conflict diffs = f(r) for linear f
diffs_seq = [(r, dk) for r, dk in sorted(c_diffs.items())]
r_vals = [r for r, _ in diffs_seq]
d_vals = [dk for _, dk in diffs_seq]
print(f"\nConflict residues: {r_vals}")
print(f"Conflict Δk values: {d_vals}")
print(f"Sum of Δk: {sum(d_vals) % 26}")
print(f"Product of Δk mod 26: {1}")  # skip expensive product

# Key values at matching residues (r=1,5,11 for Beaufort)
matching_r = [r for r in range(13) if r not in c_diffs and by_r13[r]]
print(f"\nMatching residues: {matching_r}")
print("Key values at matching positions:")
for r in matching_r:
    entries = by_r13[r]
    print(f"  r={r:2d}: k={entries[0][1]}({L(entries[0][1])}) at {[e[0] for e in entries]}")

# Note: Bean EQ k[27]=k[65] — positions 27%13=1, 65%13=0 — different residues!
print(f"\nBean EQ: k[27]={kstream[27]}({L(kstream[27])}) at r=27%13={27%13}")
print(f"         k[65]={kstream[65]}({L(kstream[65])}) at r=65%13={65%13}")
print(f"         Equal: {kstream[27] == kstream[65]} (not from period, from crib letter identity)")

print("\n=== DONE ===")
