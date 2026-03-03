#!/usr/bin/env python3
"""
E-UNSCRAMBLE-03: Crib-constraint + strip-cipher brute force.

Key insight from analysis:
  Under KRYPTOS-Vigenère, ENE@21 requires real_CT[29]=Y.
  K4 has Y at ONLY position 64. So carved pos 64 MUST go to real CT pos 29.
  This is a FORCED constraint, regardless of which permutation we use.

  The 24 crib positions give 24 equations: real_CT[crib_pos] = specific K4 char.
  → Each such char must come from a specific set of K4 positions.
  → This severely constrains the permutation.

Approach:
  1. Crib constraint analysis: list ALL valid K4-position assignments for each crib position
  2. Strip cipher attack: enumerate all strip orderings (W=8..16), check for cribs
  3. Rotation attack: all 97 rotations of K4, apply all keys
  4. Guided permutation: fix forced assignments, optimize rest with hill-climbing
"""

import sys, json, math, os, itertools
from collections import defaultdict

sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT

K4 = CT  # 97 chars carved K4
assert len(K4) == 97

GRILLE_EXTRACT = 'HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD'
KA  = 'KRYPTOSABCDEFGHIJLMNQUVWXZ'
AZ  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
CRIB1 = 'EASTNORTHEAST'
CRIB2 = 'BERLINCLOCK'
KEYWORDS = ['KRYPTOS','PALIMPSEST','ABSCISSA','SHADOW','BERLIN','CLOCK',
            'NORTH','EAST','IQLUSION','ILLUSION','EQUINOX']

# ── Quadgrams ──────────────────────────────────────────────────────────────
_QUAD = json.load(open('data/english_quadgrams.json'))
_FLOOR = min(_QUAD.values()) - 1.0
def quad_score(text):
    if len(text) < 4: return _FLOOR
    s = sum(_QUAD.get(text[i:i+4], _FLOOR) for i in range(len(text)-3))
    return s / max(len(text)-3, 1)

# ── Cipher engines ─────────────────────────────────────────────────────────
def vig_dec(ct, key, alpha=AZ):
    kv = [alpha.index(k) for k in key if k in alpha]; n=len(alpha)
    if not kv: return ''
    out=[]; ki=0
    for c in ct:
        if c in alpha: out.append(alpha[(alpha.index(c)-kv[ki%len(kv)])%n]); ki+=1
        else: out.append(c)
    return ''.join(out)

def beau_dec(ct, key, alpha=AZ):
    kv = [alpha.index(k) for k in key if k in alpha]; n=len(alpha)
    if not kv: return ''
    out=[]; ki=0
    for c in ct:
        if c in alpha: out.append(alpha[(kv[ki%len(kv)]-alpha.index(c))%n]); ki+=1
        else: out.append(c)
    return ''.join(out)

def vig_enc(pt, key, alpha=AZ):
    kv = [alpha.index(k) for k in key if k in alpha]; n=len(alpha)
    out=[]; ki=0
    for c in pt:
        if c in alpha: out.append(alpha[(alpha.index(c)+kv[ki%len(kv)])%n]); ki+=1
        else: out.append(c)
    return ''.join(out)

def apply_perm(seq, perm):
    return ''.join(seq[perm[i]] for i in range(len(perm)))

# ── K4 character positions lookup ──────────────────────────────────────────
char_positions = defaultdict(list)
for i, c in enumerate(K4):
    char_positions[c].append(i)

print("K4 character counts:")
for c in sorted(char_positions.keys()):
    print(f"  {c}: {len(char_positions[c])} at {char_positions[c]}")

# ══════════════════════════════════════════════════════════════════════════
# PART 1: CRIB CONSTRAINT ANALYSIS
# For KRYPTOS-Vigenère, compute expected real CT chars at crib positions
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("PART 1: CRIB CONSTRAINT ANALYSIS (KRYPTOS-vig)")
print("="*70)

KRYPTOS = 'KRYPTOS'
KRYPTOS_vals = [AZ.index(k) for k in KRYPTOS]

def compute_expected_ct(plaintext, key_vals, start_pos):
    """Compute expected real CT chars if PT starts at real CT position start_pos."""
    result = []
    for i, pt_char in enumerate(plaintext):
        pt_val = AZ.index(pt_char)
        key_val = key_vals[(start_pos + i) % len(key_vals)]
        result.append(AZ[(pt_val + key_val) % 26])
    return ''.join(result)

# For each possible ENE start position (0..84) and BC start position (0..86)
# compute expected real CT and check multiset feasibility

best_combos = []

for ene_start in range(85):
    ene_ct = compute_expected_ct(CRIB1, KRYPTOS_vals, ene_start)
    ene_multiset = defaultdict(int)
    for c in ene_ct: ene_multiset[c] += 1
    # Check ENE feasibility
    ene_ok = all(ene_multiset[c] <= len(char_positions[c]) for c in ene_multiset)
    if not ene_ok: continue

    for bc_start in range(87):
        # No overlap
        if ene_start <= bc_start <= ene_start + 12: continue
        if bc_start <= ene_start <= bc_start + 10: continue

        bc_ct = compute_expected_ct(CRIB2, KRYPTOS_vals, bc_start)
        # Combined multiset
        combined = defaultdict(int)
        for c in ene_ct: combined[c] += 1
        for c in bc_ct: combined[c] += 1
        # Check feasibility
        ok = all(combined[c] <= len(char_positions[c]) for c in combined)
        if ok:
            # Score: prefer positions matching known hints (21, 63)
            ene_score = abs(ene_start - 21)
            bc_score = abs(bc_start - 63)
            best_combos.append((ene_score + bc_score, ene_start, bc_start, ene_ct, bc_ct))

best_combos.sort(key=lambda x: x[0])
print(f"Feasible (ENE_start, BC_start) pairs under KRYPTOS-vig: {len(best_combos)}")
print("Top 10 closest to (21, 63):")
for score, es, bs, ect, bct in best_combos[:10]:
    print(f"  ENE@{es:2d} BC@{bs:2d}  ENE_ct={ect}  BC_ct={bct}")

# Also try KRYPTOS-Beaufort
print("\n\nKRYPTOS-Beaufort feasibility:")
best_combos_beau = []
for ene_start in range(85):
    ene_ct_b = ''.join(AZ[(KRYPTOS_vals[(ene_start+i)%7] - AZ.index(CRIB1[i])) % 26]
                        for i in range(len(CRIB1)))
    ec_ms = defaultdict(int)
    for c in ene_ct_b: ec_ms[c] += 1
    if not all(ec_ms[c] <= len(char_positions[c]) for c in ec_ms): continue
    for bc_start in range(87):
        if ene_start <= bc_start <= ene_start+12: continue
        if bc_start <= ene_start <= bc_start+10: continue
        bc_ct_b = ''.join(AZ[(KRYPTOS_vals[(bc_start+i)%7] - AZ.index(CRIB2[i])) % 26]
                           for i in range(len(CRIB2)))
        comb = defaultdict(int)
        for c in ene_ct_b+bc_ct_b: comb[c] += 1
        if all(comb[c] <= len(char_positions[c]) for c in comb):
            best_combos_beau.append((abs(ene_start-21)+abs(bc_start-63), ene_start, bc_start, ene_ct_b, bc_ct_b))

best_combos_beau.sort()
print(f"Feasible pairs (Beaufort): {len(best_combos_beau)}")
for score, es, bs, ect, bct in best_combos_beau[:5]:
    print(f"  ENE@{es:2d} BC@{bs:2d}  ENE_ct={ect}  BC_ct={bct}")

# ══════════════════════════════════════════════════════════════════════════
# PART 2: FORCED CONSTRAINTS
# Find characters with count=1 in K4 → their real CT position is FORCED
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("PART 2: FORCED CONSTRAINTS (unique characters)")
print("="*70)

# Characters appearing exactly once in K4
unique_chars = {c: pos[0] for c, pos in char_positions.items() if len(pos) == 1}
print(f"Unique characters in K4: {unique_chars}")

# For the top feasible combo (ENE@21, BC@63 under KRYPTOS-vig):
if best_combos:
    _, ene_s, bc_s, ene_expected, bc_expected = best_combos[0]
    print(f"\nBest combo: ENE@{ene_s} BC@{bc_s}")
    print(f"ENE expected CT: {ene_expected}")
    print(f"BC expected CT:  {bc_expected}")

    forced = {}  # real_CT_position → carved_K4_position (FORCED, unique char)
    print("\nForced assignments (unique chars in expected CT):")
    for i, c in enumerate(ene_expected):
        if c in unique_chars:
            real_pos = ene_s + i
            k4_pos = unique_chars[c]
            print(f"  real_CT[{real_pos}] = {c} → carved K4 position {k4_pos} (FORCED)")
            forced[real_pos] = k4_pos
    for i, c in enumerate(bc_expected):
        if c in unique_chars:
            real_pos = bc_s + i
            k4_pos = unique_chars[c]
            print(f"  real_CT[{real_pos}] = {c} → carved K4 position {k4_pos} (FORCED)")
            forced[real_pos] = k4_pos

# ══════════════════════════════════════════════════════════════════════════
# PART 3: ROTATION ATTACK
# Try all 97 rotations of K4, apply all keywords/ciphers
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("PART 3: Rotation attack (97 rotations × keywords)")
print("="*70)

rotation_hits = []
rotation_scores = []
for offset in range(97):
    rotated = K4[offset:] + K4[:offset]
    for kw in KEYWORDS:
        for alpha_name, alpha in [('AZ', AZ), ('KA', KA)]:
            for fname, fn in [('vig', vig_dec), ('beau', beau_dec)]:
                pt = fn(rotated, kw, alpha)
                has1 = CRIB1 in pt; has2 = CRIB2 in pt
                if has1 or has2:
                    print(f"  CRIB HIT: rotation {offset}, {kw}/{fname}/{alpha_name}")
                    print(f"  PT: {pt}")
                    rotation_hits.append({'offset': offset, 'kw': kw, 'cipher': fname,
                                         'alpha': alpha_name, 'pt': pt,
                                         'has1': has1, 'has2': has2})
                sc = quad_score(pt)
                rotation_scores.append((sc, offset, kw, fname, alpha_name, pt))

rotation_scores.sort(reverse=True)
print(f"Total rotation candidates: {len(rotation_scores)}")
print(f"CRIB HITS: {len(rotation_hits)}")
print("Top 5 rotation scores:")
for sc, off, kw, fn, an, pt in rotation_scores[:5]:
    print(f"  offset={off:2d} {kw}/{fn}/{an}: {sc:.4f} | {pt[:40]}...")

# ══════════════════════════════════════════════════════════════════════════
# PART 4: STRIP CIPHER BRUTE FORCE
# For widths where strip_count is small (factorial is manageable)
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("PART 4: Strip cipher brute force (W=13,14,15,16)")
print("="*70)

strip_hits = []
strip_best = []

def build_strips(text, W):
    """Split text into strips of width W."""
    strips = []
    i = 0
    while i < len(text):
        strips.append(text[i:i+W])
        i += W
    return strips

for W in [16, 15, 14, 13, 12]:
    strips = build_strips(K4, W)
    n = len(strips)
    total = math.factorial(n)
    print(f"  W={W}: {n} strips, {total} orderings")
    if total > 5_000_000:
        print(f"    Skipping (too many)")
        continue

    best_sc = -999.0
    best_perm = None
    best_pt = None
    best_info = None
    tested = 0

    for perm in itertools.permutations(range(n)):
        candidate = ''.join(strips[perm[i]] for i in range(n))
        # Fast crib check first (no decryption needed for raw check)
        for kw in ['KRYPTOS', 'ABSCISSA', 'PALIMPSEST']:
            for alpha_name, alpha in [('AZ', AZ)]:
                for fname, fn in [('vig', vig_dec), ('beau', beau_dec)]:
                    pt = fn(candidate, kw, alpha)
                    if CRIB1 in pt or CRIB2 in pt:
                        sc = quad_score(pt)
                        strip_hits.append({
                            'W': W, 'perm': list(perm), 'kw': kw,
                            'cipher': fname, 'alpha': alpha_name,
                            'ct': candidate, 'pt': pt, 'score': sc,
                            'has1': CRIB1 in pt, 'has2': CRIB2 in pt
                        })
                        print(f"    *** CRIB HIT *** W={W} perm={perm} {kw}/{fname}/{alpha_name}")
                        print(f"    PT: {pt}")
        tested += 1

    # Also track best quadgram score
    # (Too slow to do full quadgram for all perms at large W — do targeted)
    if W <= 14:
        for perm in itertools.permutations(range(n)):
            candidate = ''.join(strips[perm[i]] for i in range(n))
            pt = vig_dec(candidate, 'KRYPTOS')
            sc = quad_score(pt)
            if sc > best_sc:
                best_sc = sc; best_perm = perm; best_pt = pt
                best_info = ('KRYPTOS','vig','AZ')
            # Also Beaufort
            pt_b = beau_dec(candidate, 'KRYPTOS')
            sc_b = quad_score(pt_b)
            if sc_b > best_sc:
                best_sc = sc_b; best_perm = perm; best_pt = pt_b
                best_info = ('KRYPTOS','beau','AZ')

        print(f"  W={W}: Best score {best_sc:.4f} with perm {best_perm}")
        if best_pt: print(f"    PT: {best_pt[:60]}...")
        if best_perm:
            strip_best.append((best_sc, W, list(best_perm), best_info, best_pt))

print(f"\nStrip cipher CRIB HITS: {len(strip_hits)}")

# ══════════════════════════════════════════════════════════════════════════
# PART 5: TARGETED SEARCH using forced constraints
# For the best (ENE, BC) position combo, try to build a consistent permutation
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("PART 5: Constraint-driven permutation search")
print("="*70)

if best_combos:
    _, ene_s, bc_s, ene_ct_str, bc_ct_str = best_combos[0]

    # Build constraint: which K4 positions must go to which real CT positions
    crib_constraints = []
    for i, c in enumerate(ene_ct_str):
        crib_constraints.append((ene_s + i, c))
    for i, c in enumerate(bc_ct_str):
        crib_constraints.append((bc_s + i, c))

    print(f"Crib constraints for ENE@{ene_s} + BC@{bc_s} under KRYPTOS-vig:")
    for real_pos, expected_c in crib_constraints[:5]:
        k4_positions = char_positions[expected_c]
        print(f"  real_CT[{real_pos}] = {expected_c} → K4 has it at positions {k4_positions}")

    # Count valid assignments using bipartite matching intuition
    # For chars with only 1 K4 position → forced assignment
    # For chars with 2+ K4 positions → choice
    print(f"\n  Forced assignments:")
    forced_assignments = {}
    for real_pos, expected_c in crib_constraints:
        if len(char_positions[expected_c]) == 1:
            k4_pos = char_positions[expected_c][0]
            forced_assignments[real_pos] = k4_pos
            print(f"    real_CT[{real_pos}] = {expected_c} → K4[{k4_pos}] (FORCED)")

    print(f"\n  Found {len(forced_assignments)} forced assignments out of {len(crib_constraints)}")

    # Build a partial permutation: σ^{-1}(real_CT_pos) = K4_pos
    # Using greedy assignment for ambiguous positions
    # (This won't be exhaustive, just finds ONE valid assignment)

    # Try ABSCISSA-based combo as well
    for kw_name, kw_str in [('KRYPTOS', 'KRYPTOS'), ('ABSCISSA', 'ABSCISSA')]:
        kw_v = [AZ.index(k) for k in kw_str]

        for ene_s2 in [21, 0, 7, 14, 28, 35, 42]:
            ene_ct2 = compute_expected_ct(CRIB1, kw_v, ene_s2)
            ene_ms = defaultdict(int)
            for c in ene_ct2: ene_ms[c] += 1
            if not all(ene_ms[c] <= len(char_positions[c]) for c in ene_ms): continue

            for bc_s2 in [63, 44, 51, 58, 65, 70, 72, 79]:
                if ene_s2 <= bc_s2 <= ene_s2+12: continue
                if bc_s2 <= ene_s2 <= bc_s2+10: continue
                bc_ct2 = compute_expected_ct(CRIB2, kw_v, bc_s2)
                combined = defaultdict(int)
                for c in ene_ct2+bc_ct2: combined[c] += 1
                if not all(combined[c] <= len(char_positions[c]) for c in combined): continue

                # Build a candidate permutation
                # For each crib real_CT position, assign a K4 position
                assignment = {}  # real_CT_pos → K4_pos
                used = set()
                valid = True

                # First assign unique chars (forced)
                all_crib_chars = list(ene_ct2) + list(bc_ct2)
                crib_real_positions = [ene_s2+i for i in range(len(CRIB1))] + \
                                      [bc_s2+i for i in range(len(CRIB2))]

                for real_pos, expected_c in zip(crib_real_positions, all_crib_chars):
                    available = [p for p in char_positions[expected_c] if p not in used]
                    if not available:
                        valid = False; break
                    # Greedy: pick first available
                    chosen = available[0]
                    assignment[real_pos] = chosen
                    used.add(chosen)

                if not valid: continue

                # Build full permutation: remaining non-crib positions get remaining K4 positions
                all_k4_positions = list(range(97))
                remaining_k4 = [p for p in all_k4_positions if p not in used]
                crib_real_set = set(crib_real_positions)
                remaining_real = [p for p in range(97) if p not in crib_real_set]

                # Assign remaining K4 positions to remaining real CT positions in order
                for real_pos, k4_pos in zip(remaining_real, remaining_k4):
                    assignment[real_pos] = k4_pos

                # Build real CT from assignment
                real_ct = ''.join(K4[assignment[i]] for i in range(97))

                # Decrypt with the keyword
                for fname, fn in [('vig', vig_dec), ('beau', beau_dec)]:
                    pt = fn(real_ct, kw_str)
                    has1 = CRIB1 in pt; has2 = CRIB2 in pt
                    sc = quad_score(pt)
                    if has1 or has2:
                        print(f"\n  *** CRIB HIT *** {kw_name}/{fname} ENE@{ene_s2} BC@{bc_s2}")
                        print(f"  PT: {pt}")
                    if sc > -6.0:
                        print(f"  Good score {sc:.4f}: {kw_name}/{fname} ENE@{ene_s2} BC@{bc_s2}")
                        print(f"    PT: {pt[:60]}...")

# ══════════════════════════════════════════════════════════════════════════
# PART 6: HILL-CLIMBING on permutation to maximize quadgram score
# Start from identity or from constraint-based permutation
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("PART 6: Hill-climbing permutation optimization")
print("="*70)
import random

def hill_climb(initial_perm, key='KRYPTOS', alpha=AZ, fn=vig_dec, n_iter=10000, seed=42):
    """Optimize permutation to maximize quadgram score."""
    random.seed(seed)
    perm = list(initial_perm)
    best_perm = list(perm)

    real_ct = apply_perm(K4, perm)
    pt = fn(real_ct, key, alpha)
    best_score = quad_score(pt)
    best_pt = pt

    for iteration in range(n_iter):
        # Random swap of two positions
        i, j = random.sample(range(97), 2)
        perm[i], perm[j] = perm[j], perm[i]

        real_ct = apply_perm(K4, perm)
        pt = fn(real_ct, key, alpha)
        score = quad_score(pt)

        if score >= best_score:
            best_score = score
            best_perm = list(perm)
            best_pt = pt
        else:
            # Revert
            perm[i], perm[j] = perm[j], perm[i]

    return best_perm, best_score, best_pt

# Run hill climbing with different starting points and keys
hc_results = []
for seed in [42, 123, 456, 789, 1000]:
    initial = list(range(97))
    random.shuffle(initial)
    for kw in ['KRYPTOS', 'ABSCISSA', 'PALIMPSEST']:
        for fname, fn in [('vig', vig_dec), ('beau', beau_dec)]:
            perm, score, pt = hill_climb(initial, kw, AZ, fn, n_iter=5000, seed=seed)
            has1 = CRIB1 in pt; has2 = CRIB2 in pt
            if has1 or has2:
                print(f"*** CRIB HIT via hill climb! {kw}/{fname} seed={seed}")
                print(f"    PT: {pt}")
            hc_results.append((score, kw, fname, seed, pt, has1 or has2))

hc_results.sort(reverse=True)
print(f"\nHill climbing results ({len(hc_results)} runs):")
for sc, kw, fn, seed, pt, hit in hc_results[:10]:
    tag = " *** CRIB ***" if hit else ""
    print(f"  {sc:.4f} {kw}/{fn} seed={seed}{tag}: {pt[:50]}...")

# ══════════════════════════════════════════════════════════════════════════
# PART 7: Try Beaufort on grille extract-permuted K4
# The grille extract IS a sorted ordering key for K4
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("PART 7: Grille extract as Beaufort running key (direct)")
print("="*70)

# Check if the GRILLE EXTRACT can directly decrypt K4 to give ENE/BC
# at ANY position
for alpha_name, alpha in [('AZ', AZ), ('KA', KA)]:
    # Extend extract to 97 chars by repeating or truncating
    ext_key = GRILLE_EXTRACT[:97]
    for fname, fn in [('vig', vig_dec), ('beau', beau_dec)]:
        pt = fn(K4, ext_key, alpha)
        if CRIB1 in pt or CRIB2 in pt:
            print(f"*** CRIB HIT: grille extract direct key, {fname}/{alpha_name}")
            print(f"   PT: {pt}")
    # Try searching for ENE/BC at each window
    for window_start in range(50):
        ext_key2 = GRILLE_EXTRACT[window_start:window_start+97]
        if len(ext_key2) < 97: break
        for fname, fn in [('vig', vig_dec), ('beau', beau_dec)]:
            pt = fn(K4, ext_key2, alpha)
            if CRIB1 in pt or CRIB2 in pt:
                print(f"*** CRIB HIT: grille extract window={window_start}, {fname}/{alpha_name}")
                print(f"    PT: {pt}")

# ══════════════════════════════════════════════════════════════════════════
# PART 8: Special permutations suggested by grille geometry
# The 107 holes are distributed across 28 rows with varying counts.
# What if each hole POSITION encodes a K4 position via the KA tableau?
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("PART 8: Hole → tableau-letter → K4 positional mapping")
print("="*70)

# The grille extract (HJLVACINXZ...) read at hole positions
# These letters ARE the tableau letters. Now: use them to define K4 reading order.

# Interpretation: the extract letter at hole i tells us which K4 POSITION to read
# by finding where that letter appears in K4.
# If extract[i]=H, H appears in K4 at certain positions — this creates a mapping.

# Method: for each extract position i, find the i-th occurrence of that letter in K4
extract_107 = GRILLE_EXTRACT  # 106 chars (holes 0..105)
perm_by_occurrence = []
occurrence_counters = defaultdict(int)
valid = True

for c in extract_107:
    if c in char_positions:
        occ = occurrence_counters[c]
        positions = char_positions[c]
        if occ < len(positions):
            perm_by_occurrence.append(positions[occ])
            occurrence_counters[c] += 1
        else:
            valid = False; break
    else:
        valid = False; break

if valid and len(perm_by_occurrence) >= 97:
    p97 = perm_by_occurrence[:97]
    if len(set(p97)) == 97:
        real_ct = apply_perm(K4, p97)
        for kw in KEYWORDS:
            for alpha_name, alpha in [('AZ', AZ), ('KA', KA)]:
                for fname, fn in [('vig', vig_dec), ('beau', beau_dec)]:
                    pt = fn(real_ct, kw, alpha)
                    if CRIB1 in pt or CRIB2 in pt:
                        print(f"*** CRIB HIT: extract-occurrence perm, {kw}/{fname}/{alpha_name}")
                        print(f"    PT: {pt}")
        sc = quad_score(vig_dec(real_ct, 'KRYPTOS'))
        print(f"  Extract-occurrence perm (KRYPTOS-vig): score={sc:.4f}")
    else:
        # Not all 97 unique — there are repeats in first 97 of extract mapping
        print(f"  Extract-occurrence perm: {len(set(p97))} unique out of 97 (has repeats)")

# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("FINAL SUMMARY")
print("="*70)
all_hits = rotation_hits + strip_hits
print(f"Total CRIB HITS: {len(all_hits)}")
if all_hits:
    for h in all_hits:
        print(f"  {h}")

print(f"\nBest hill-climbing score: {hc_results[0][0]:.4f} via {hc_results[0][1]}/{hc_results[0][2]}")
print(f"Best rotation score: {rotation_scores[0][0]:.4f} at offset {rotation_scores[0][1]}")
if strip_best:
    print(f"Best strip score: {strip_best[0][0]:.4f} at W={strip_best[0][1]} perm={strip_best[0][2]}")

# Save
os.makedirs('kbot_results', exist_ok=True)
output = {
    'experiment': 'E-UNSCRAMBLE-03',
    'date': '2026-03-02',
    'total_hits': len(all_hits),
    'any_crib_found': len(all_hits) > 0,
    'crib_hits': all_hits,
    'feasible_ene_bc_combos_kryptos_vig': len(best_combos),
    'forced_constraints': len(forced_assignments) if best_combos else 0,
    'hill_climb_best': {'score': hc_results[0][0], 'kw': hc_results[0][1],
                         'pt': hc_results[0][4][:80]} if hc_results else None,
    'top_rotation': {'offset': rotation_scores[0][1], 'score': rotation_scores[0][0],
                      'pt': rotation_scores[0][5][:80]} if rotation_scores else None,
}
with open('kbot_results/unscramble_analysis.json', 'w') as f:
    json.dump(output, f, indent=2)
print("\nResults saved → kbot_results/unscramble_analysis.json")
