"""
Cipher: Cardan grille
Family: grille
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_k3_grille_v4.py — CSP with YWT crib + correct K3-style formula search.

CRITICAL INSIGHTS FROM V1-V3:
1. K3 = PURE TRANSPOSITION confirmed
2. Y only appears at position 64 in K4_CARVED → if K4_PT[0]='Y', σ(0)=64
3. K3 formula: a=i//w1, b=i%w1, inter=h1*b+(h1-1)-a, pt=h2*d+(h2-1)-c
4. 97 is prime → exact K3-style formula needs divisors (only 1 and 97)
5. K3 and K4 are independent permutations

THIS SCRIPT:
1. CSP search for pure transposition with ALL known PT constraints
   (σ(0)=64 [YWT], ENE@21-33, BC@63-73, self-enc σ(32)∈S_pos, σ(73)∈K_pos)
2. K3-style formula search for N' divisible by multiple widths near 97
3. Physical-structure: the 4-row K4 layout with specific column counts

Run: PYTHONPATH=src python3 -u scripts/grille/blitz_k3_grille_v4.py
"""
from __future__ import annotations
import sys, math
from collections import defaultdict

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KEYWORDS = ["KRYPTOS","PALIMPSEST","ABSCISSA","SHADOW","SANBORN",
            "SCHEIDT","BERLIN","CLOCK","EAST","NORTH",
            "LIGHT","ANTIPODES","MEDUSA","ENIGMA"]

K4_CARVED = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(K4_CARVED) == 97

ENE = "EASTNORTHEAST"   # PT[21:34]
BC  = "BERLINCLOCK"     # PT[63:74]

# ─── Cipher functions ─────────────────────────────────────────────────────────
def vig_decrypt(ct, key, alpha=AZ):
    res = []
    for i, c in enumerate(ct):
        ci = alpha.index(c); ki = alpha.index(key[i%len(key)])
        res.append(alpha[(ci-ki)%26])
    return "".join(res)

def beau_decrypt(ct, key, alpha=AZ):
    res = []
    for i, c in enumerate(ct):
        ci = alpha.index(c); ki = alpha.index(key[i%len(key)])
        res.append(alpha[(ki-ci)%26])
    return "".join(res)

def check_all(sigma, tag=""):
    """Test sigma under pure transposition and all ciphers."""
    real_ct = "".join(K4_CARVED[sigma[j]] for j in range(97))
    # Pure transposition
    pt = real_ct
    if ENE in pt or BC in pt:
        print(f"*** PURE TRANSPOSITION HIT [{tag}]! ***")
        print(f"    PT: {pt}")
        return True
    if len(pt)>33 and pt[21:34]==ENE: return True
    if len(pt)>73 and pt[63:74]==BC: return True
    # All ciphers
    for kw in KEYWORDS:
        for aname, alpha in [("AZ",AZ),("KA",KA)]:
            for cname, cfn in [("vig",vig_decrypt),("beau",beau_decrypt)]:
                try:
                    pt2 = cfn(real_ct, kw, alpha)
                    if ENE in pt2 or BC in pt2:
                        print(f"*** CIPHER HIT [{tag}] {cname}/{kw}/{aname}! ***")
                        print(f"    PT: {pt2}")
                        return True
                    if len(pt2)>33 and pt2[21:34]==ENE: return True
                    if len(pt2)>73 and pt2[63:74]==BC: return True
                except: pass
    return False

# ─── 1. MAP: WHAT LETTERS ARE AT EACH CARVED POSITION? ──────────────────────
print("="*70)
print("1. K4_CARVED LETTER INDEX")
print("="*70)

letter_positions = defaultdict(list)
for i, c in enumerate(K4_CARVED):
    letter_positions[c].append(i)

print("Letter → positions in K4_CARVED:")
for c in sorted(letter_positions):
    print(f"  {c}: {letter_positions[c]}")

# ─── 2. CONSTRAINT SETUP FOR PURE TRANSPOSITION ──────────────────────────────
print("\n" + "="*70)
print("2. CONSTRAINTS FOR PURE TRANSPOSITION (K4 PT = permutation of K4_CARVED)")
print("="*70)

# Known PT positions:
# If K4 starts "YESWONDERFULTHINGS..." (answering K3's "CANYOUSEEANYTHINGQ"):
# PT[0]='Y' → σ(0)=letter_positions['Y'][0]=64 (ONLY ONE Y!)
# PT[1]='E' → σ(1)∈letter_positions['E']={44,92}
# PT[2]='S' → σ(2)∈letter_positions['S']={13,32,33,39,42,43}
# PT[3]='W' → σ(3)∈letter_positions['W']={20,36,48,58,74}

# ENE crib: PT[21:34] = EASTNORTHEAST
# BC crib:  PT[63:74] = BERLINCLOCK

# Self-encrypting: PT[32]='S' → σ(32)∈letter_positions['S']
#                  PT[73]='K' → σ(73)∈letter_positions['K']

# Note: PT[21]='E', PT[22]='A', ..., PT[33]='T'
# Note: BC BC BC... PT[63]='B', PT[64]='E', PT[65]='R', ...

# Build complete constraint set for pure transposition
pt_constraints = {}  # pt_pos → list of valid sigma(pt_pos) values

# YWT constraints (if K4 PT starts YES WONDERFUL THINGS)
YWT = "YESWONDERFULTHINGS"
for i, c in enumerate(YWT):
    if c in letter_positions:
        pt_constraints[i] = letter_positions[c][:]

# ENE crib
for i, c in enumerate(ENE):
    pt_constraints[21+i] = letter_positions[c][:]

# BC crib
for i, c in enumerate(BC):
    pt_constraints[63+i] = letter_positions[c][:]

# Self-encrypting
pt_constraints[32] = letter_positions['S'][:]
pt_constraints[73] = letter_positions['K'][:]

# Merge (intersection) where multiple sources constrain same position
# (e.g., PT[32]='S' from ENE and self-encrypting → same constraint)
print("Complete constraint set:")
total_combos = 1
for pos in sorted(pt_constraints):
    print(f"  PT[{pos:2d}]='{chr(65+AZ.index(K4_CARVED[pos])) if False else [ENE,BC,YWT][0][max(0,pos-21)] if 21<=pos<=33 else BC[pos-63] if 63<=pos<=73 else YWT[pos] if pos < len(YWT) else '?'}': σ({pos:2d}) ∈ {pt_constraints[pos]}")
    total_combos *= len(pt_constraints[pos])

print(f"\nTotal constraint combinations: {total_combos:,}")
print(f"Constrained positions: {len(pt_constraints)}")
print(f"Free positions: {97 - len(pt_constraints)}")

# ─── 3. VERIFY σ(0)=64 UNIQUENESS ─────────────────────────────────────────────
print("\n" + "="*70)
print("3. Y UNIQUENESS ANALYSIS")
print("="*70)
print(f"Y appears at: {letter_positions['Y']}")
print(f"If PT[0]='Y', σ(0) MUST = {letter_positions['Y'][0]}")
print(f"This is a HARD CONSTRAINT (only one Y in K4_CARVED)")

# ─── 4. K3-STYLE FORMULA FOR N' NEAR 97 ─────────────────────────────────────
print("\n" + "="*70)
print("4. K3-STYLE FORMULA FOR N' NEAR 97 (CORRECT IMPLEMENTATION)")
print("="*70)

def k3_style_perm_correct(N_prime, w1, w2):
    """Correct K3-style permutation: a=i//w1, b=i%w1, inter=h1*b+(h1-1)-a,
    c=inter//w2, d=inter%w2, pt=h2*d+(h2-1)-c.
    Returns None if not valid perm, else list of pt_pos for i=0..N'-1."""
    if N_prime % w1 != 0 or N_prime % w2 != 0:
        return None
    h1 = N_prime // w1
    h2 = N_prime // w2

    result = []
    for i in range(N_prime):
        a = i // w1; b = i % w1
        inter = h1 * b + (h1-1) - a
        c = inter // w2; d = inter % w2
        pt_pos = h2 * d + (h2-1) - c
        result.append(pt_pos)

    if len(set(result)) != N_prime:
        return None
    return result

# Verify K3: k3_style_perm_correct(336, 24, 8)[0] should be 250
k3_test = k3_style_perm_correct(336, 24, 8)
assert k3_test is not None and k3_test[0] == 250, f"K3 formula check failed: {k3_test[0] if k3_test else None}"
print("K3 formula verified: k3_style_perm_correct(336, 24, 8)[0] = 250 ✓")

# For K4: find N' near 97 such that k3-style formula gives first 97 outputs
# spanning {0..96} (no null/garbage in first 97 output positions).

# Strategy: N' = 97 + padding. Apply formula to i=0..96.
# If the result for i=0..96 is a permutation of {0..96}, we have a valid K4 perm.
# Note: result[i] < N' always. We need result[i] < 97 for i=0..96.

hits_formula = 0
best_pct = 0

for N_prime in range(97, 300):
    # Find all divisors of N_prime ≥ 2
    divs = [w for w in range(2, N_prime) if N_prime % w == 0]
    if not divs: continue  # prime → skip (unless N_prime=97 itself)

    for w1 in divs:
        h1 = N_prime // w1
        for w2 in divs:
            h2 = N_prime // w2
            if w1 == w2 and h1 == h2: continue

            # Compute perm for i=0..96 only
            result97 = []
            valid = True
            for i in range(97):
                a = i // w1; b = i % w1
                inter = h1 * b + (h1-1) - a
                if inter < 0 or inter >= N_prime:
                    valid = False; break
                c = inter // w2; d = inter % w2
                pt_pos = h2 * d + (h2-1) - c
                if pt_pos < 0 or pt_pos >= N_prime:
                    valid = False; break
                result97.append(pt_pos)

            if not valid: continue
            # Check if result97 is a permutation of 0..96
            if len(set(result97)) != 97 or set(result97) != set(range(97)):
                continue

            # Valid! Test this permutation
            sigma = result97
            pt_pure = "".join(K4_CARVED[sigma[i]] for i in range(97))

            # Quick check against constraints
            satisfies = True
            # σ(0) must be in Y positions [64]
            if 0 in pt_constraints and sigma[0] not in pt_constraints[0]:
                satisfies = False
            if satisfies:
                ene_count = sum(1 for i in range(13) if len(pt_pure)>21+i and pt_pure[21+i]==ENE[i])
                bc_count  = sum(1 for i in range(11) if len(pt_pure)>63+i and pt_pure[63+i]==BC[i])
                total = ene_count + bc_count

                if total > best_pct:
                    best_pct = total
                    print(f"  N'={N_prime}, w1={w1}, w2={w2}: ENE={ene_count}/13, BC={bc_count}/11")
                    print(f"    PT: {pt_pure[:60]}")

                if ENE in pt_pure or BC in pt_pure:
                    print(f"  *** PURE HIT: N'={N_prime}, w1={w1}, w2={w2}! ***")
                    print(f"    PT: {pt_pure}")
                    hits_formula += 1
                elif ene_count >= 13 or bc_count >= 11:
                    print(f"  *** CRIB HIT! N'={N_prime}, w1={w1}, w2={w2} ***")
                    check_all(sigma, f"K3style_N{N_prime}_w{w1}_w{w2}")
                    hits_formula += 1

print(f"Formula search: best crib count = {best_pct}/24, total hits = {hits_formula}")

# ─── 5. CSP BACKTRACKING FOR PURE TRANSPOSITION ──────────────────────────────
print("\n" + "="*70)
print("5. CSP BACKTRACKING: PURE TRANSPOSITION WITH ALL CONSTRAINTS")
print("="*70)

# We have hard constraints at 18 (YWT) + 13 (ENE) + 11 (BC) + 2 (self-enc) positions.
# But YWT and ENE overlap at positions... let's check.
# YWT = "YESWONDERFULTHINGS" (pos 0..17)
# ENE = "EASTNORTHEAST" (pos 21..33)
# BC = "BERLINCLOCK" (pos 63..73)
# Self-enc: pos 32, 73
# No overlaps! (YWT: 0-17, ENE: 21-33, BC: 63-73, self-enc: 32, 73)
# But pos 73 appears in both BC (63+10=73, BC[10]='K') and self-enc.
# BC[10] = 'K' = self-enc[73]='K' → consistent.

# We have constraints at up to 18+13+11+1 = 43 positions (pos 32 covered by ENE).
# Wait: ENE covers pos 21-33 (including 32). And self-enc pos 32 = 'S' = ENE[11]='S'. Consistent.
# So pos 32 covered by ENE. Pos 73 covered by BC. Self-enc adds no new positions.

# Only new constraint: YWT extends to pos 0..17 = 18 new positions.
# But YWT is speculative! Let's start with what we KNOW: ENE + BC = 24 crib positions.
# Then add YWT incrementally.

# For pure transposition: σ is a permutation of {0..96}.
# Constraint: σ(pos) ∈ valid_carved_positions_for_letter_at_pos.
# σ must be injective (no two PT positions map to the same carved position).

# Build constraint dict: pt_pos → {valid carved positions}
CRIB_CONSTRAINTS = {}
for i, c in enumerate(ENE):
    CRIB_CONSTRAINTS[21+i] = set(letter_positions[c])
for i, c in enumerate(BC):
    CRIB_CONSTRAINTS[63+i] = set(letter_positions[c])

print(f"Crib constraints: {len(CRIB_CONSTRAINTS)} positions")
for pos in sorted(CRIB_CONSTRAINTS):
    print(f"  PT[{pos:2d}] ∈ {sorted(CRIB_CONSTRAINTS[pos])}")

# Quick search: for each valid assignment of crib positions,
# check if it's consistent with any structured permutation.
# (Too slow for full 97! but fast for partial.)

# With σ(0)=64 (Y constraint) AND crib constraints:
# Extend CRIB_CONSTRAINTS with YWT:
ALL_CONSTRAINTS = dict(CRIB_CONSTRAINTS)

# Y uniqueness → fixed constraint
ALL_CONSTRAINTS[0] = {64}

# Other YWT positions (speculative but testable):
YWT_FULL = "YESWONDERFULTHINGS"
for i, c in enumerate(YWT_FULL):
    if i > 0 and i not in ALL_CONSTRAINTS:  # don't override existing
        if c in letter_positions and letter_positions[c]:
            ALL_CONSTRAINTS[i] = set(letter_positions[c])

print(f"\nAll constraints (incl YWT): {len(ALL_CONSTRAINTS)} positions")
# Count total search space
total_sp = 1
for pos in ALL_CONSTRAINTS:
    total_sp *= len(ALL_CONSTRAINTS[pos])
print(f"Search space (ignoring injectivity): {total_sp:,}")

# ─── 6. DIRECT CRIB SEARCH: FIND PERMUTATIONS SATISFYING ENE+BC+Y ────────────
print("\n" + "="*70)
print("6. DIRECT CRIB SEARCH: E-POSITION SCAN")
print("="*70)

# Key insight: Y is at position 64 only. ENE has 'E' at positions 21, 30.
# If σ(0)=64 (Y), then the carved positions 44 and 92 (the two E's)
# must go to σ(21) and σ(30) respectively (or vice versa).

# Let's enumerate all ways to assign the ENE+BC cribs.
# There are only a few valid assignments for the rarer letters:
# Y: 1 choice (pos 64)
# H: 2 choices (pos 9, 88) → assigned to PT[29] (ENE) only
# N: 3 choices for PT[25] and PT[63] (BC start B... wait BC[0]=B not N)

# Let me be more careful.
# ENE = E(21)A(22)S(23)T(24)N(25)O(26)R(27)T(28)H(29)E(30)A(31)S(32)T(33)
# BC  = B(63)E(64)R(65)L(66)I(67)N(68)C(69)L(70)O(71)C(72)K(73)

# The rarest letters in K4_CARVED for the crib:
# H: letter_positions['H'] = [9, 88] → 2 positions for PT[29] in ENE
# Y: not in ENE or BC
# B: letter_positions['B'] = ?

B_positions = letter_positions['B']
H_positions = letter_positions['H']
I_positions = letter_positions['I']
L_positions = letter_positions['L']

print(f"B (BC[0]): {B_positions}")
print(f"H (ENE[8]): {H_positions}")
print(f"I (BC[4]): {I_positions}")
print(f"L (BC[3],BC[5]): {L_positions}")

# The rarest crib letter is H (2 positions) and B (let me count)
print(f"\nH has {len(H_positions)} candidates → σ(29) fixed to small set")
print(f"B has {len(B_positions)} candidates → σ(63) fixed to small set")

# Since σ(0)=64 is FIXED (Y uniqueness), and σ(29)∈{9,88} (H, 2 choices),
# and σ(63)∈B_positions (B positions), we can enumerate.

# Count B in K4_CARVED:
print(f"\nLetters with fewest positions in K4_CARVED:")
for c in AZ:
    n = len(letter_positions.get(c, []))
    if n <= 4:
        print(f"  '{c}': {n} positions → {letter_positions.get(c, [])}")

# ─── 7. COMBINED ENE+BC+Y ENUMERATION ────────────────────────────────────────
print("\n" + "="*70)
print("7. BRUTE-FORCE ENUMERATION OF ENE+BC+Y PARTIAL ASSIGNMENTS")
print("="*70)

# Strategy: enumerate all valid (σ(21),...,σ(33)) × (σ(63),...,σ(73)) × σ(0)=64
# that use DISJOINT carved positions. Check consistency.

# Build ENE assignment iterator
from itertools import product

# ENE letters and their candidates
ene_letters = list(ENE)  # 13 chars
ene_candidates = [letter_positions[c][:] for c in ene_letters]

# BC letters and their candidates
bc_letters = list(BC)  # 11 chars
bc_candidates = [letter_positions[c][:] for c in bc_letters]

# σ(0) is FIXED to 64
fixed_positions = {64}  # already used

print(f"ENE candidates (before constraint): {[len(x) for x in ene_candidates]}")
print(f"BC candidates (before constraint): {[len(x) for x in bc_candidates]}")

# Total naïve combos
from functools import reduce
import operator
ene_combos = reduce(operator.mul, [len(x) for x in ene_candidates], 1)
bc_combos  = reduce(operator.mul, [len(x) for x in bc_candidates],  1)
print(f"ENE combos (without injectivity): {ene_combos:,}")
print(f"BC combos (without injectivity):  {bc_combos:,}")

# Backtracking search for ENE
def backtrack_ene(idx, used, partial):
    """Enumerate valid ENE assignments."""
    if idx == len(ene_letters):
        return [partial[:]]
    results = []
    for cand in ene_candidates[idx]:
        if cand not in used:
            used.add(cand)
            partial.append(cand)
            results.extend(backtrack_ene(idx+1, used, partial))
            partial.pop()
            used.remove(cand)
    return results

used_init = {64}  # σ(0)=64 already used
ene_assignments = backtrack_ene(0, used_init.copy(), [])
print(f"\nValid ENE assignments (with injectivity + σ(0)=64): {len(ene_assignments)}")

# For each ENE assignment, find valid BC assignments
total_valid = 0
total_hits = 0

for ene_assign in ene_assignments:
    # Used positions from σ(0) and ENE
    used_ene = {64} | set(ene_assign)

    def backtrack_bc(idx, used, partial):
        if idx == len(bc_letters):
            return [partial[:]]
        results = []
        for cand in bc_candidates[idx]:
            if cand not in used:
                used.add(cand)
                partial.append(cand)
                results.extend(backtrack_bc(idx+1, used, partial))
                partial.pop()
                used.remove(cand)
        return results

    bc_assigns = backtrack_bc(0, used_ene.copy(), [])
    total_valid += len(bc_assigns)

    for bc_assign in bc_assigns:
        # We now have constraints:
        # σ(0)=64, σ(21..33)=ene_assign, σ(63..73)=bc_assign
        # Verify against K4_CARVED
        crib_ok = True
        # ENE
        for i, pos in enumerate(ene_assign):
            if K4_CARVED[pos] != ENE[i]:
                crib_ok = False; break
        # BC
        if crib_ok:
            for i, pos in enumerate(bc_assign):
                if K4_CARVED[pos] != BC[i]:
                    crib_ok = False; break
        if not crib_ok:
            continue  # Shouldn't happen since candidates are correct by construction

        # This is a valid PARTIAL sigma.
        # Under PURE TRANSPOSITION: this partial assignment IS the partial PT.
        # The full sigma still needs 97-1-13-11 = 72 free positions.
        # We can check if this partial assignment is consistent with any
        # STRUCTURED permutation (K3-style, affine, etc.)

        # Quick quadgram test of partial PT (only 25 known chars out of 97):
        partial_pt = ['?']*97
        partial_pt[0] = 'Y'  # σ(0)=64=K4_CARVED[64]='Y' ✓ (assuming pure transposition)
        for i, pos in enumerate(ene_assign):
            partial_pt[21+i] = ENE[i]
        for i, pos in enumerate(bc_assign):
            partial_pt[63+i] = BC[i]

        # Check if partial is consistent with "YESWONDERFULTHINGS" start
        # (We have PT[0]='Y' from σ(0)=64=Y)
        # No other YWT positions constrained here.

total_valid_all = total_valid
print(f"Total valid (ENE+BC+Y) partial sigma assignments: {total_valid_all:,}")
print(f"Crib hits during search: {total_hits}")

# ─── 8. DIRECT PATTERN TEST — ENE AT CARVED POSITIONS ────────────────────────
print("\n" + "="*70)
print("8. DIRECT PATTERN: DOES K4_CARVED CONTAIN SCATTERED ENE+BC?")
print("="*70)

# Under pure transposition: K4_carved = permuted K4_PT.
# K4_PT contains EASTNORTHEAST at positions 21-33.
# So K4_carved must contain all 13 letters of ENE scattered around,
# at positions σ(21), σ(22), ..., σ(33).
# Similarly for BC.

# Count: how many of each letter in K4_CARVED?
print("K4_CARVED letter counts vs ENE+BC requirements:")
ene_needed = Counter(ENE)
bc_needed  = Counter(BC)

for c in sorted(set(ENE+BC)):
    have = len(letter_positions.get(c, []))
    need_ene = ene_needed.get(c, 0)
    need_bc  = bc_needed.get(c, 0)
    need_total = need_ene + need_bc
    ok = "✓" if have >= need_total else "✗"
    print(f"  '{c}': have={have}, need ENE={need_ene}+BC={need_bc}={need_total} {ok}")

# ─── 9. K4 READING THE 14×31 GRID VIA 31-COLUMN TRANSPOSITION ───────────────
print("\n" + "="*70)
print("9. K4 VIA 31-COLUMN TRANSPOSITION OF THE BOTTOM HALF")
print("="*70)

# K3 uses 24-column transposition. The MASTER GRID is 31-wide.
# What if K4 uses 31-column reading of its 97-char region?
# K4 in 31-wide grid: row 24 (4 chars at cols 27-30), rows 25-27 (31 each).
# 4 + 31 + 31 + 31 = 97.
# If we arrange K4 in a 31-wide block (4 partial + 3 full), we can try:
# - Read by columns of the 31-wide arrangement
# - Apply K3-style rotations on the padded 124=4*31 version

# Pad K4 to 124 chars (fill first 3*4=12 positions of col 0, then normal):
# Actually, let's think of K4 as fitting into a 4×31 grid with 4*31-97=27 "null" cells.
# The K4 chars fill the LAST 97 positions of a 4×31=124 grid.
# Null positions: (0,0)..(0,26) = 27 cells. K4 chars: (0,27)..(3,30).

# Try K3-style formula on 124=4×31:
for w1 in [4, 31]:
    if 124 % w1 != 0: continue
    for w2 in [4, 31]:
        if 124 % w2 != 0: continue
        if w1 == w2: continue

        perm = k3_style_perm_correct(124, w1, w2)
        if perm is None: continue

        # Map: input positions 27..123 → output positions
        # (K4 chars are at input positions 27..123 in the padded 4×31 grid)
        # Under the formula: carved[i] = PT[perm[i]]
        # K4 carved positions (in padded grid) are 27..123.
        # K4 PT positions (in padded grid) are also 27..123 (if the formula maps them).
        k4_output_indices = [i for i in range(27, 124) if perm[i] >= 27]  # outputs in K4 range
        if len(k4_output_indices) == 97 and set(k4_output_indices) == set(range(27, 124)):
            # Extract K4 perm: sigma[j] = perm[27+j] - 27 for j=0..96
            sigma_k4 = [perm[27+j]-27 for j in range(97)]
            if len(set(sigma_k4)) == 97 and set(sigma_k4) == set(range(97)):
                print(f"  Valid K4 sub-perm from 4×31 formula: w1={w1}, w2={w2}")
                pt = "".join(K4_CARVED[sigma_k4[j]] for j in range(97))
                ene_c = sum(1 for i in range(13) if len(pt)>21+i and pt[21+i]==ENE[i])
                bc_c  = sum(1 for i in range(11) if len(pt)>63+i and pt[63+i]==BC[i])
                print(f"    ENE={ene_c}/13, BC={bc_c}/11")
                if ene_c >= 10 or bc_c >= 8 or ENE in pt or BC in pt:
                    print(f"    *** NEAR-HIT! PT: {pt} ***")
                    check_all(sigma_k4, f"4x31_w{w1}_w{w2}")

# ─── 10. KEY INSIGHT: K3 FORMULA ON 434 WITH CORRECT OFFSETS ─────────────────
print("\n" + "="*70)
print("10. K3-STYLE FORMULA ON 434 (14×31 BOTTOM HALF) WITH CORRECT OFFSETS")
print("="*70)

# 434 = 14 × 31 = 2 × 7 × 31
# Divisors: 1, 2, 7, 14, 31, 62, 217, 434
# Try all pairs (w1, w2) for 434

K3_FWD = [None]*336
def k3_carved_to_pt(i):
    a = i//24; b = i%24
    inter = 14*b + 13 - a
    c = inter//8; d = inter%8
    return 42*d + 41 - c
for i in range(336): K3_FWD[i] = k3_carved_to_pt(i)

# Check 434 formula against K3 (K3 uses positions 0..335 of 434-space):
divs434 = [w for w in range(2, 434) if 434%w==0]
print(f"Divisors of 434 (>1, <434): {divs434}")

# For each (w1, w2) divisor pair of 434, check if the formula matches K3 for i=0..335
best_match = 0
best_params = None

for w1 in divs434:
    for w2 in divs434:
        if w1 == w2: continue
        h1 = 434//w1; h2 = 434//w2

        # Check how many K3 positions match
        match = 0
        for i in range(336):
            a = i//w1; b = i%w1
            inter = h1*b + (h1-1) - a
            if inter < 0 or inter >= 434: break
            c = inter//w2; d = inter%w2
            pt = h2*d + (h2-1) - c
            if pt == K3_FWD[i]: match += 1

        if match > best_match:
            best_match = match
            best_params = (w1, w2)

        if match >= 300:
            print(f"  w1={w1}, w2={w2}: {match}/336 match K3 formula")

        if match == 336:
            print(f"  *** PERFECT MATCH: w1={w1}, w2={w2}! ***")
            # Extract K4 portion (positions 337..433)
            k4_perm = []
            for i in range(337, 434):
                a = i//w1; b = i%w1
                inter = h1*b + (h1-1) - a
                if inter < 0 or inter >= 434: k4_perm.append(-1); continue
                c = inter//w2; d = inter%w2
                pt = h2*d + (h2-1) - c
                k4_perm.append(pt - 337)  # relative to K4 start
            print(f"  K4 perm: {k4_perm[:10]}...")
            if len(k4_perm) == 97 and len(set(k4_perm)) == 97 and set(k4_perm) == set(range(97)):
                print(f"  K4 perm is valid! Testing...")
                check_all(k4_perm, f"434formula_perfect_w{w1}_w{w2}")

print(f"\nBest match: {best_match}/336 with params {best_params}")

# ─── 11. SUMMARY ──────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("11. SUMMARY")
print("="*70)
print(f"σ(0) = 64 if K4_PT[0]='Y' (ONLY ONE Y IN K4_CARVED)")
print(f"Valid partial assignments (ENE+BC+Y): {total_valid_all:,}")
print(f"K3-style formula matches for 434: best {best_match}/336")
print(f"No crib hits found in this session")
print()

from collections import Counter
Counter = Counter  # already imported
