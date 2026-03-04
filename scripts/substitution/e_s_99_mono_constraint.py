#!/usr/bin/env python3
"""
Cipher: monoalphabetic substitution
Family: substitution
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-99: Monoalphabetic + Arbitrary Transposition via Constraint Propagation

Key idea: If the cipher is monoalphabetic + transposition (Model B):
  1. Apply transposition σ to CT → intermediate I
  2. Apply monoalphabetic substitution α to I → PT
  Then α(I[j]) = PT[j] for all j.

At crib positions, we know PT[j]. So α(CT[σ(j)]) = CRIBS[j].

This means: for each crib position j, the letter CT[σ(j)] must map to CRIBS[j].
The mapping α must be:
  - Well-defined: each CT letter maps to at most one PT letter
  - Injective: each PT letter is the image of at most one CT letter

For a GIVEN σ, the crib constraints determine partial α. If the partial α has
contradictions (same CT letter maps to different PT letters, or same PT letter
comes from different CT letters), σ is eliminated.

This gives us a VERY strong filter: 24 crib equations with only 26 unknowns.
We don't need to enumerate all 97! permutations. Instead, we can:

Phase 1: Determine which (CT_letter, PT_letter) pairs are REQUIRED at each crib.
Phase 2: For width-7 columnar, test all 5040 orderings.
Phase 3: For width-5 through width-12, test all orderings.
Phase 4: For decimation (96 steps), test all.
Phase 5: For arbitrary transposition, use constraint propagation on positions.

Structural analysis:
  - ENE cribs (13 positions): 8 distinct PT letters (E,A,S,T,N,O,R,H)
  - BC cribs (11 positions): 8 distinct PT letters (B,E,R,L,I,N,C,K,O)
  - Combined: 11 distinct PT letters: A,B,C,E,H,I,K,L,N,O,R,S,T
  - Combined CT at crib positions: varies by σ
"""

import json, os, time
from itertools import permutations

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

# Distinct PT letters in cribs
PT_LETTERS = set(CRIBS.values())
print(f"Distinct PT letters: {sorted(PT_LETTERS)} ({len(PT_LETTERS)} letters)")

# CT letters at crib positions (under identity permutation)
CT_AT_CRIBS = {p: CT[p] for p in CPOS}
print(f"CT at ENE cribs: {''.join(CT[p] for p in range(21,34))}")
print(f"CT at BC cribs:  {''.join(CT[p] for p in range(63,74))}")


def check_mono_consistent(perm):
    """Check if a monoalphabetic substitution is consistent with cribs
    under the given transposition permutation.

    Returns: (is_consistent, n_determined, mapping) or (False, 0, None)
    """
    # Build required mapping: CT[perm[j]] → CRIBS[j]
    alpha = {}  # CT letter → PT letter
    alpha_inv = {}  # PT letter → CT letter

    for p in CPOS:
        ct_letter = CT_N[perm[p]]
        pt_letter = PT_FULL[p]

        if ct_letter in alpha:
            if alpha[ct_letter] != pt_letter:
                return False, 0, None  # Contradiction: same CT maps to different PT
        else:
            alpha[ct_letter] = pt_letter

        if pt_letter in alpha_inv:
            if alpha_inv[pt_letter] != ct_letter:
                return False, 0, None  # Contradiction: different CT maps to same PT
        else:
            alpha_inv[pt_letter] = ct_letter

    return True, len(alpha), alpha


print("=" * 70)
print("E-S-99: Monoalphabetic + Arbitrary Transposition via Constraint Propagation")
print(f"  N={N}, cribs={len(CPOS)}")
print("=" * 70)

t0 = time.time()
results = {}


# ── Phase 1: Width-7 columnar ────────────────────────────────────────
print("\n--- P1: Mono + width-7 columnar ---")

W = 7
def build_perm(order, w=W):
    nr = (N + w - 1) // w
    ns = nr * w - N
    p = []
    for k in range(w):
        c = order[k]
        sz = nr - 1 if c >= w - ns else nr
        for r in range(sz):
            p.append(r * w + c)
    return p

ORDERS_7 = [list(o) for o in permutations(range(W))]
survivors_7 = []

for oi, order in enumerate(ORDERS_7):
    perm = build_perm(order)
    ok, n_det, alpha = check_mono_consistent(perm)
    if ok:
        survivors_7.append((order, n_det, alpha))

print(f"  Width-7 columnar survivors: {len(survivors_7)}/5040")

if survivors_7:
    for order, n_det, alpha in survivors_7[:10]:
        print(f"    order={order}, {n_det} letters determined")
        # Decrypt with this mono
        perm = build_perm(order)
        pt = [0] * N
        for j in range(N):
            ct_letter = CT_N[perm[j]]
            if ct_letter in alpha:
                pt[j] = alpha[ct_letter]
            else:
                pt[j] = ct_letter  # unmapped letters pass through
        pt_text = ''.join(AZ[x] for x in pt)
        print(f"    PT: {pt_text}")

        # IC of plaintext
        from collections import Counter
        freq = Counter(pt)
        ic = sum(f*(f-1) for f in freq.values()) / (N*(N-1))
        print(f"    IC: {ic:.4f} (English≈0.066, random≈0.038)")

results['P1_w7'] = {'survivors': len(survivors_7)}
print(f"\n  P1 done: {time.time()-t0:.1f}s")


# ── Phase 2: Other widths (5-12) ─────────────────────────────────────
print("\n--- P2: Mono + other columnar widths ---")

for w in range(5, 13):
    if w == 7:
        continue  # Already tested

    all_orders = list(permutations(range(w)))
    survivors = 0

    for order in all_orders:
        nr = (N + w - 1) // w
        ns = nr * w - N
        perm = []
        for k in range(w):
            c = order[k]
            sz = nr - 1 if c >= w - ns else nr
            for r in range(sz):
                perm.append(r * w + c)

        ok, n_det, alpha = check_mono_consistent(perm)
        if ok:
            survivors += 1

    total = len(all_orders)
    pct = survivors / total * 100 if total > 0 else 0
    print(f"  Width {w}: {survivors}/{total} ({pct:.1f}%)")
    results[f'P2_w{w}'] = {'survivors': survivors, 'total': total}

print(f"\n  P2 done: {time.time()-t0:.1f}s")


# ── Phase 3: Decimation ──────────────────────────────────────────────
print("\n--- P3: Mono + decimation ---")

dec_survivors = 0
for d in range(1, N):
    perm = [(j * d) % N for j in range(N)]
    ok, n_det, alpha = check_mono_consistent(perm)
    if ok:
        dec_survivors += 1
        print(f"  d={d}: consistent, {n_det} letters determined")
        # Decrypt
        pt = [0] * N
        for j in range(N):
            ct_letter = CT_N[perm[j]]
            if ct_letter in alpha:
                pt[j] = alpha[ct_letter]
            else:
                pt[j] = ct_letter
        pt_text = ''.join(AZ[x] for x in pt)
        print(f"    PT: {pt_text}")
        freq = Counter(pt)
        ic = sum(f*(f-1) for f in freq.values()) / (N*(N-1))
        print(f"    IC: {ic:.4f}")

print(f"  Decimation survivors: {dec_survivors}/96")
results['P3_decimation'] = {'survivors': dec_survivors}
print(f"\n  P3 done: {time.time()-t0:.1f}s")


# ── Phase 4: Identity (no transposition) ──────────────────────────────
print("\n--- P4: Mono + identity (no transposition) ---")

perm = list(range(N))
ok, n_det, alpha = check_mono_consistent(perm)
print(f"  Identity: consistent={ok}")
if ok:
    print(f"  {n_det} letters determined: {alpha}")
    pt = [0] * N
    for j in range(N):
        ct_letter = CT_N[j]
        if ct_letter in alpha:
            pt[j] = alpha[ct_letter]
        else:
            pt[j] = ct_letter
    pt_text = ''.join(AZ[x] for x in pt)
    print(f"  PT: {pt_text}")
results['P4_identity'] = {'consistent': ok}


# ── Phase 5: Structural analysis ─────────────────────────────────────
print("\n--- P5: Structural analysis of mono constraints ---")

# For identity permutation, what are the required mappings?
print(f"\n  CT at ENE positions (21-33): {''.join(CT[p] for p in range(21,34))}")
print(f"  PT at ENE positions:          EASTNORTHEAST")
print(f"\n  CT at BC positions (63-73):   {''.join(CT[p] for p in range(63,74))}")
print(f"  PT at BC positions:            BERLINCLOCK")

# Required mono mappings under identity:
print(f"\n  Required mappings (identity permutation):")
for p in CPOS:
    print(f"    CT[{p}]={CT[p]} → PT[{p}]={CRIBS[p]}")

# Check for contradictions
alpha_id = {}
contradictions = []
for p in CPOS:
    ct = CT[p]
    pt = CRIBS[p]
    if ct in alpha_id:
        if alpha_id[ct] != pt:
            contradictions.append((p, ct, pt, alpha_id[ct]))
    else:
        alpha_id[ct] = pt

if contradictions:
    print(f"\n  CONTRADICTIONS under identity:")
    for p, ct, pt, existing in contradictions:
        print(f"    pos {p}: {ct}→{pt} conflicts with prior {ct}→{existing}")
    print(f"  Monoalphabetic + identity: IMPOSSIBLE")
else:
    print(f"\n  No contradictions. Mapping: {alpha_id}")


# ── Summary ───────────────────────────────────────────────────────────
total_elapsed = time.time() - t0

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
for phase, data in sorted(results.items()):
    print(f"  {phase}: {data}")
print(f"  Total: {total_elapsed:.1f}s")

os.makedirs("results", exist_ok=True)
out = {
    'experiment': 'E-S-99',
    'description': 'Monoalphabetic + arbitrary transposition constraint propagation',
    'results': {k: str(v) for k, v in results.items()},
    'elapsed_seconds': total_elapsed,
}
with open("results/e_s_99_mono_constraint.json", "w") as f:
    json.dump(out, f, indent=2, default=str)
print(f"\n  Artifact: results/e_s_99_mono_constraint.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_99_mono_constraint.py")
