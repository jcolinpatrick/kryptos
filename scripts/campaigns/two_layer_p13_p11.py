#!/usr/bin/env python3
"""
Two-layer cipher: CT = sub2(sub1(PT)) where
  sub1 = any poly-sub with period p1
  sub2 = any poly-sub with period p2

For each position i:
  T[i] = sub1(PT[i], key1[i%p1])   ← intermediate text
  CT[i] = sub2(T[i], key2[i%p2])

The 24 cribs give 24 equations: sub2(sub1(PT[i]), key1[i%p1], key2[i%p2]) = CT[i]

KEY INSIGHT: With p1=13, p2=11:
  13+11 = 24 = number of crib positions!
  ENE covers ALL 13 residues mod 13 AND all 11 residues mod 11.
  → The 24 cribs FULLY CONSTRAIN key1[0:13] + key2[0:11] as a linear system.

For Beaufort×Beaufort:
  T[i] = (key1[i%p1] - PT[i]) % 26
  CT[i] = (key2[i%p2] - T[i]) % 26 = (key2[i%p2] - key1[i%p1] + PT[i]) % 26

So: key2[i%p2] - key1[i%p1] = (CT[i] - PT[i]) % 26 = Vig_key(i)

For Vigenère×Beaufort or other combos, similarly.

We solve for all (key1, key2) pairs consistent with the 24 cribs,
then decrypt full CT and score.
"""
import sys, itertools
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT as CT_STR, CRIB_DICT, KRYPTOS_ALPHABET as KA

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CT = [ord(c)-65 for c in CT_STR]
N = len(CT)

ENE = "EASTNORTHEAST"   # 13 chars at positions 21-33
BLK = "BERLINCLOCK"     # 11 chars at positions 63-73

def beau(a, b):    return (a + b) % 26  # Beaufort: key = CT+PT
def vig_key(c, p): return (c - p) % 26  # Vigenère: key = CT-PT
def vb_key(c, p):  return (p - c) % 26  # VBeau: key = PT-CT

# Derived key values at crib positions (Beaufort AZ)
# beau_key[i] = (CT[i] + PT[i]) % 26
crib_beau_key = {}
for pos, pt_ch in CRIB_DICT.items():
    crib_beau_key[pos] = (CT[pos] + (ord(pt_ch)-65)) % 26

print("Crib Beaufort AZ key stream:")
for pos in sorted(crib_beau_key):
    print(f"  pos {pos}: CT={CT_STR[pos]} PT={CRIB_DICT[pos]} key={AZ[crib_beau_key[pos]]}")

# ── Model: CT[i] = (key2[i%p2] - key1[i%p1] + PT[i]) % 26
# i.e., effective Vigenère key = key2 - key1 at each position
# This means the COMBINATION cipher is EQUIVALENT to Vigenère with
# key k_eff[i] = (key2[i%p2] - key1[i%p1]) % 26
# → k_eff has period lcm(p1,p2)

# For p1=13, p2=11: lcm=143. The effective key has period 143.
# From 24 cribs: k_eff[i] = Vig_key at each position.
# The structure: k_eff[i] = K2[i%11] - K1[i%13]
# This is a constrained version of a period-143 Vigenère.

# Let's SOLVE: find K1[0:13] and K2[0:11] such that:
# K2[i%11] - K1[i%13] = vig_key(CT[pos], PT[pos]) for each crib pos

# Build the constraint matrix
# Unknowns: x[0:13] = K1[0:13], x[13:24] = K2[0:11]
# Equation for crib at position i:
#   x[13 + i%11] - x[i%13] = vig_key(CT[i], PT[i]) (mod 26)

print("\n\n=== SOLVING: CT[i] = Vig(K2-K1, PT)[i] with p1=13, p2=11 ===")
print("(All 6 variant combos)")

def solve_two_layer(alpha, crib_key_fn, combine, p1, p2, verify_fn):
    """
    Find K1[0:p1], K2[0:p2] such that for each crib pos:
      combine(K1[pos%p1], K2[pos%p2]) ≡ crib_key_fn(CT[pos], PT[pos]) mod 26

    Returns list of (K1, K2) solutions.
    """
    # Build equations: for each crib position pos,
    # f(K1[pos%p1], K2[pos%p2]) = target
    targets = {}  # (r1, r2) → target value
    conflicts = 0

    for pos, pt_ch in CRIB_DICT.items():
        r1 = pos % p1
        r2 = pos % p2
        target = crib_key_fn(alpha, CT_STR[pos], pt_ch)

        key = (r1, r2)
        if key in targets:
            if targets[key] != target:
                conflicts += 1
        else:
            targets[key] = target

    if conflicts > 0:
        return None, conflicts

    # Now solve the constraint system
    # For the (Beau-outer, Beau-inner) = (K2-K1): x[13+r2] - x[r1] = target
    # For Vig outer: x[13+r2] + x[r1] = target, etc.
    # Use a free variable approach: fix K1[0] = c (free param), solve rest

    solutions = []

    # Try all 26 values of K1[0]
    for k1_0 in range(26):
        K1 = [None] * p1
        K2 = [None] * p2
        K1[0] = k1_0

        # Propagate: for each constraint (r1, r2, target), if K1[r1] known, find K2[r2]
        # Or if K2[r2] known, find K1[r1]
        changed = True
        consistent = True

        while changed and consistent:
            changed = False
            for (r1, r2), target in targets.items():
                if K1[r1] is not None and K2[r2] is None:
                    # derive K2[r2] from K1[r1] and target
                    K2[r2] = combine(K1[r1], target)  # target = f(K1[r1], K2[r2]) → K2[r2] = g(K1[r1], target)
                    changed = True
                elif K2[r2] is not None and K1[r1] is None:
                    K1[r1] = combine(K2[r2], target)  # symmetrically
                    changed = True
                elif K1[r1] is not None and K2[r2] is not None:
                    # Verify
                    expected = crib_key_fn(alpha, CT_STR[
                        # find a crib pos with this (r1,r2)
                        next(p for p,c in CRIB_DICT.items() if p%p1==r1 and p%p2==r2)
                    ], CRIB_DICT[
                        next(p for p,c in CRIB_DICT.items() if p%p1==r1 and p%p2==r2)
                    ])
                    if verify_fn(K1[r1], K2[r2]) != expected:
                        consistent = False
                        break

        if consistent and None not in K1 and None not in K2:
            solutions.append((K1[:], K2[:]))

    return solutions, 0

# This approach is complex. Let's use a simpler method:
# For the "difference" model CT[i] = (PT[i] + K2[i%p2] - K1[i%p1]) % 26
# The effective key k_eff[i] = (K2[i%p2] - K1[i%p1]) % 26
# This is a Vigenère with period lcm(13,11)=143.
# From 24 cribs, the effective key at 24 positions is known.
# Question: can a key of the form K2[i%11] - K1[i%13] fit these 24 values?

print("\nEffective Vig key at crib positions (AZ Vigenère):")
eff_key = {}
for pos, pt_ch in CRIB_DICT.items():
    eff_key[pos] = vig_key(CT[pos], ord(pt_ch)-65)
    print(f"  pos {pos} (r13={pos%13}, r11={pos%11}): key={AZ[eff_key[pos]]}")

# Build the system: k_eff[pos] = K2[pos%11] - K1[pos%13] for all crib pos
# = K2[r2] - K1[r1] = target
# This is a system of linear equations over Z_26.
# 24 equations, 24 unknowns (K1[0:13], K2[0:11]).
# There's 1 degree of freedom (shift K1 by c, K2 by c).

# Let's fix K1[0] = 0 and solve:
print("\n\nSolving K2[r2] - K1[r1] = target mod 26 (Vig effective key)...")

# Build adjacency: each equation (r1, r2, target) connects K1[r1] to K2[r2]
# Start with K1[0]=0, propagate via equations

from collections import defaultdict, deque

def solve_z26_system(constraints, p1, p2):
    """
    Solve: K2[r2] - K1[r1] = target (mod 26) for all (r1, r2, target) in constraints.
    Returns all solutions (free param over K1[0]).
    """
    # BFS from K1[0]
    solutions = []

    for k1_0 in range(26):
        K1 = [None] * p1
        K2 = [None] * p2
        K1[0] = k1_0

        # BFS propagation
        queue = deque()
        # Find all constraints involving r1=0 (since K1[0] is known)
        for r1, r2, target in constraints:
            if r1 == 0 and K2[r2] is None:
                K2[r2] = (K1[0] + target) % 26
                queue.append(('K2', r2))

        changed = True
        consistent = True
        iterations = 0
        while changed and consistent:
            changed = False
            iterations += 1
            if iterations > 1000:
                break

            for r1, r2, target in constraints:
                if K1[r1] is not None and K2[r2] is None:
                    K2[r2] = (K1[r1] + target) % 26
                    changed = True
                elif K2[r2] is not None and K1[r1] is None:
                    K1[r1] = (K2[r2] - target) % 26
                    changed = True
                elif K1[r1] is not None and K2[r2] is not None:
                    expected = (K2[r2] - K1[r1]) % 26
                    if expected != target:
                        consistent = False
                        break

        if consistent:
            # Check if fully determined
            n_unknown_k1 = sum(1 for x in K1 if x is None)
            n_unknown_k2 = sum(1 for x in K2 if x is None)

            if n_unknown_k1 == 0 and n_unknown_k2 == 0:
                solutions.append((K1[:], K2[:]))
            elif consistent:  # partially determined
                k1_str = ''.join(AZ[x] if x is not None else '?' for x in K1)
                k2_str = ''.join(AZ[x] if x is not None else '?' for x in K2)
                print(f"  k1_0={AZ[k1_0]}: K1={k1_str} K2={k2_str} (partial)")

    return solutions

# Build constraints for (p1=13, p2=11) Vig effective key
constraints_13_11 = []
for pos, pt_ch in CRIB_DICT.items():
    r1 = pos % 13
    r2 = pos % 11
    target = vig_key(CT[pos], ord(pt_ch)-65)  # K2[r2] - K1[r1] = target
    constraints_13_11.append((r1, r2, target))

print(f"Constraints for (p1=13, p2=11):")
for r1, r2, tgt in sorted(constraints_13_11):
    print(f"  (r1={r1}, r2={r2}): K2[{r2}] - K1[{r1}] = {AZ[tgt]}")

solutions_13_11 = solve_z26_system(constraints_13_11, 13, 11)
print(f"\nSolutions for (p1=13, p2=11): {len(solutions_13_11)}")

for K1, K2 in solutions_13_11[:10]:
    k1_str = ''.join(AZ[x] if x is not None else '?' for x in K1)
    k2_str = ''.join(AZ[x] if x is not None else '?' for x in K2)
    print(f"  K1={k1_str}  K2={k2_str}")

    # Decrypt full CT: CT[i] = (PT[i] + K2[i%11] - K1[i%13]) % 26
    pt = [(CT[i] - K2[i%11] + K1[i%13]) % 26 for i in range(N)]
    pt_str = ''.join(AZ[x] for x in pt)
    crib_hits = sum(1 for pos, ch in CRIB_DICT.items() if AZ[pt[pos]] == ch)
    print(f"  PT: {pt_str[:50]}...")
    print(f"  Crib hits: {crib_hits}/24")

# Try other period combos
print("\n\n=== Testing other (p1, p2) combinations ===")
all_combos = []

for p1 in range(1, 27):
    for p2 in range(1, 27):
        if p1 == p2:
            continue

        # Check: do the 24 crib positions cover all r1=0..p1-1 AND r2=0..p2-1?
        r1_covered = set(pos%p1 for pos in CRIB_DICT)
        r2_covered = set(pos%p2 for pos in CRIB_DICT)
        r1_full = (r1_covered == set(range(p1)))
        r2_full = (r2_covered == set(range(p2)))

        # Solve
        c = [(pos%p1, pos%p2, vig_key(CT[pos], ord(ch)-65))
             for pos, ch in CRIB_DICT.items()]

        # Check for immediate conflicts (same r1,r2 → different target)
        seen = {}
        conflict = False
        for r1, r2, tgt in c:
            key = (r1, r2)
            if key in seen and seen[key] != tgt:
                conflict = True
                break
            seen[key] = tgt

        if conflict:
            continue

        solns = solve_z26_system(c, p1, p2)
        if solns:
            all_combos.append((p1, p2, len(solns), solns, r1_full, r2_full))

print(f"\nFound {len(all_combos)} (p1,p2) combos with solutions:")
print(f"{'p1':>4} {'p2':>4} {'#sol':>5} {'K1-full':>8} {'K2-full':>8}  {'K1 (first soln)':<26}  {'K2 (first soln)'}")
print("-" * 90)

for p1, p2, n_solns, solns, r1f, r2f in sorted(all_combos, key=lambda x: x[2]):
    K1, K2 = solns[0]
    k1_s = ''.join(AZ[x] if x is not None else '?' for x in K1)
    k2_s = ''.join(AZ[x] if x is not None else '?' for x in K2)
    flag = ' ◄' if r1f and r2f else ''
    print(f"{p1:>4} {p2:>4} {n_solns:>5} {'YES' if r1f else 'no':>8} {'YES' if r2f else 'no':>8}  {k1_s:<26}  {k2_s}{flag}")

# Decrypt for best solutions (fully constrained)
print("\n\n=== Full decryptions for best (p1=13, p2=11) solutions ===")
for K1, K2 in solutions_13_11[:5]:
    pt = [(CT[i] - K2[i%11] + K1[i%13]) % 26 for i in range(N)]
    pt_str = ''.join(AZ[x] for x in pt)
    crib_hits = sum(1 for pos, ch in CRIB_DICT.items() if AZ[pt[pos]] == ch)
    k1_s = ''.join(AZ[x] if x is not None else '?' for x in K1)
    k2_s = ''.join(AZ[x] if x is not None else '?' for x in K2)
    print(f"\nK1={k1_s} K2={k2_s}  Crib hits: {crib_hits}/24")
    print(f"PT: {pt_str}")
