#!/usr/bin/env python3
"""E-S-94: Keystream Structure Analysis for Width-7 Orderings

For every width-7 columnar ordering (5040), extract the observed keystream
at all 24 crib positions under Vig/Beau/VBeau. Analyze each for:
  1. Autokey patterns (correlation with shifted CT/intermediate)
  2. Arithmetic/polynomial structure
  3. Readable key fragments (letter frequency)
  4. Difference patterns (key deltas)
  5. Period-p consistency for small p (already done, but check p=2,3,4,5)
  6. Grid-position correlations (row, column, diagonal dependencies)

Goal: find ANY ordering where the keystream reveals recognizable structure
that could guide identification of the substitution method.
"""

import json, os, time
from itertools import permutations
from collections import Counter

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
PT_VALS = [PT_FULL[p] for p in CPOS]

W = 7

def build_perm(order):
    nr = (N + W - 1) // W
    ns = nr * W - N
    p = []
    for k in range(W):
        c = order[k]
        sz = nr - 1 if c >= W - ns else nr
        for r in range(sz):
            p.append(r * W + c)
    return p

ORDERS = [list(o) for o in permutations(range(W))]
PERMS = [build_perm(o) for o in ORDERS]

# Precompute intermediates for each ordering
# Model B: CT → columnar read → intermediate I
# Then substitution: I[j] → PT[j] via key[j]
# Key observation: I[j] = CT[perm[j]]
# So for Vig: K_obs[j] = (I[j] - PT[j]) % 26


def extract_keystream(oi, variant):
    """Extract observed keystream at crib positions for given ordering and variant.

    Returns list of (grid_pos_j, key_value) where grid_pos_j is the position
    in the intermediate sequence that maps to PT position p.

    Model B: intermediate I = permuted CT, then I → PT via substitution
    For crib at PT position p:
      The intermediate position that maps to PT[p] is inv_perm[p]
      So j = inv_perm[p], I[j] = CT[perm[j]]
      Wait — need to be more careful.

    Model B pipeline:
      1. Write CT into rows of W=7 → grid[r][c] = CT[r*7+c]
      2. Read columns in 'order' → intermediate I
         I[j] = CT[perm[j]] where perm = columnar reading order
      3. Apply substitution: PT[j] = decrypt(I[j], key[j])
         For Vig: PT[j] = (I[j] - key[j]) % 26
         For Beau: PT[j] = (key[j] - I[j]) % 26

    So at plaintext position j, we need PT[j] to match cribs.
    Since cribs specify PT[p] for p in CPOS, we need:
      key[p] = (I[p] - PT[p]) % 26  for Vig
      key[p] = (I[p] + PT[p]) % 26  for Beau

    Wait, I need to think about this more carefully.

    After columnar transposition, position j in the output corresponds to
    position perm[j] in the input (CT). So:
      I[j] = CT[perm[j]]

    Then substitution maps I[j] → PT[j] using key[j]:
      For Vig: PT[j] = (I[j] - key[j]) % 26
      So key[j] = (I[j] - PT[j]) % 26

    The cribs tell us PT[p] for certain positions p.
    So key[p] = (I[p] - PT[p]) % 26 = (CT[perm[p]] - PT[p]) % 26

    This is the KEY at position p in the PLAINTEXT/OUTPUT sequence.
    """
    perm = PERMS[oi]
    result = []
    for p in CPOS:
        i_val = CT_N[perm[p]]  # intermediate value at position p
        pt_val = PT_FULL[p]

        if variant == 0:  # Vig: P = I - K
            k = (i_val - pt_val) % 26
        elif variant == 1:  # Beau: P = K - I
            k = (i_val + pt_val) % 26
        else:  # VBeau: P = I + K
            k = (pt_val - i_val) % 26

        result.append((p, k))

    return result


def check_autokey_ct(oi, keystream, variant):
    """Check if keystream could be CT-autokey: key[j] should equal I[j-p] for some p."""
    perm = PERMS[oi]
    intermed = [CT_N[perm[j]] for j in range(N)]

    best_shift = 0
    best_shift_matches = 0

    for shift in range(1, 30):
        matches = 0
        for pos, kval in keystream:
            if pos - shift >= 0:
                if intermed[pos - shift] == kval:
                    matches += 1
        if matches > best_shift_matches:
            best_shift_matches = matches
            best_shift = shift

    return best_shift, best_shift_matches


def check_autokey_pt(keystream):
    """Check if keystream could be PT-autokey: key[j] should equal PT[j-p].
    We only know PT at crib positions, so check those."""
    best_shift = 0
    best_matches = 0

    pt_known = {p: PT_FULL[p] for p in CPOS}

    for shift in range(1, 30):
        matches = 0
        total = 0
        for pos, kval in keystream:
            src = pos - shift
            if src in pt_known:
                total += 1
                if pt_known[src] == kval:
                    matches += 1
        if total > 0 and matches > best_matches:
            best_matches = matches
            best_shift = shift

    return best_shift, best_matches


def check_arithmetic(keystream):
    """Check for arithmetic progression in keystream values at consecutive positions."""
    # Sort by position
    ks = sorted(keystream, key=lambda x: x[0])

    # Check deltas between consecutive crib positions
    deltas = []
    for i in range(len(ks) - 1):
        pos_diff = ks[i + 1][0] - ks[i][0]
        val_diff = (ks[i + 1][1] - ks[i][1]) % 26
        deltas.append((pos_diff, val_diff))

    # Check for constant delta within each crib block
    # ENE block: positions 21-33 (consecutive)
    ene_keys = [k for p, k in ks if 21 <= p <= 33]
    ene_deltas = [(ene_keys[i + 1] - ene_keys[i]) % 26 for i in range(len(ene_keys) - 1)]

    # BC block: positions 63-73 (consecutive)
    bc_keys = [k for p, k in ks if 63 <= p <= 73]
    bc_deltas = [(bc_keys[i + 1] - bc_keys[i]) % 26 for i in range(len(bc_keys) - 1)]

    # Count most common delta
    ene_counter = Counter(ene_deltas)
    bc_counter = Counter(bc_deltas)

    return ene_deltas, bc_deltas, ene_counter, bc_counter


def check_grid_pattern(keystream):
    """Check if key values correlate with grid position (row, col)."""
    # Position p in output → grid row = p // 7, col = p % 7
    row_groups = {}
    col_groups = {}

    for pos, kval in keystream:
        r = pos // W
        c = pos % W
        row_groups.setdefault(r, []).append(kval)
        col_groups.setdefault(c, []).append(kval)

    # Check if same-column positions have consistent key mod something
    col_consistency = {}
    for c, vals in col_groups.items():
        if len(vals) >= 2:
            diffs = [(vals[i + 1] - vals[i]) % 26 for i in range(len(vals) - 1)]
            col_consistency[c] = Counter(diffs).most_common(1)[0] if diffs else None

    return col_consistency


def check_period(keystream, p):
    """Check period-p consistency."""
    residue_vals = {}
    for pos, kval in keystream:
        r = pos % p
        if r in residue_vals:
            if residue_vals[r] != kval:
                return False
        else:
            residue_vals[r] = kval
    return True


print("=" * 70)
print("E-S-94: Keystream Structure Analysis for Width-7 Orderings")
print(f"  N={N}, W={W}, orderings={len(ORDERS)}, cribs={len(CPOS)}")
print("=" * 70)

t0 = time.time()

# ── Phase 1: Autokey correlation scan ─────────────────────────────────
print("\n--- P1: CT-autokey correlation scan ---")

ct_autokey_results = []
for oi in range(len(ORDERS)):
    for vi in range(3):
        ks = extract_keystream(oi, vi)
        shift, matches = check_autokey_ct(oi, ks, vi)
        if matches >= 5:
            ct_autokey_results.append((matches, shift, oi, vi, ks))

ct_autokey_results.sort(reverse=True)
print(f"  Configs with ≥5 CT-autokey matches: {len(ct_autokey_results)}")
for matches, shift, oi, vi, ks in ct_autokey_results[:10]:
    VNAMES = ['Vig', 'Beau', 'VBeau']
    print(f"    {matches}/24 matches at shift={shift}, order={ORDERS[oi]}, {VNAMES[vi]}")

print(f"\n  P1 done: {time.time()-t0:.1f}s")


# ── Phase 2: PT-autokey correlation scan ──────────────────────────────
print("\n--- P2: PT-autokey correlation scan ---")

pt_autokey_results = []
VNAMES = ['Vig', 'Beau', 'VBeau']

for oi in range(len(ORDERS)):
    for vi in range(3):
        ks = extract_keystream(oi, vi)
        shift, matches = check_autokey_pt(ks)
        if matches >= 2:
            pt_autokey_results.append((matches, shift, oi, vi))

pt_autokey_results.sort(reverse=True)
print(f"  Configs with ≥2 PT-autokey matches: {len(pt_autokey_results)}")
for matches, shift, oi, vi in pt_autokey_results[:10]:
    print(f"    {matches} matches at shift={shift}, order={ORDERS[oi]}, {VNAMES[vi]}")

print(f"\n  P2 done: {time.time()-t0:.1f}s")


# ── Phase 3: Period consistency for small p ───────────────────────────
print("\n--- P3: Period consistency check (p=2..14) ---")

period_counts = {}
for p in range(2, 15):
    count = 0
    for oi in range(len(ORDERS)):
        for vi in range(3):
            ks = extract_keystream(oi, vi)
            if check_period(ks, p):
                count += 1
    period_counts[p] = count
    pct = count / 15120 * 100
    print(f"  period {p}: {count}/15120 ({pct:.2f}%) consistent")

print(f"\n  P3 done: {time.time()-t0:.1f}s")


# ── Phase 4: Arithmetic structure in keystream ────────────────────────
print("\n--- P4: Arithmetic structure scan ---")

# For each ordering, check if the keystream within each crib block
# shows constant deltas (arithmetic progression)
arith_results = []

for oi in range(len(ORDERS)):
    for vi in range(3):
        ks = extract_keystream(oi, vi)
        ene_d, bc_d, ene_c, bc_c = check_arithmetic(ks)

        # Score: how many deltas are the same?
        if ene_c and bc_c:
            ene_top = ene_c.most_common(1)[0]
            bc_top = bc_c.most_common(1)[0]
            ene_score = ene_top[1]
            bc_score = bc_top[1]
            total_score = ene_score + bc_score

            if total_score >= 15:  # Strong arithmetic pattern
                arith_results.append((total_score, ene_top, bc_top, oi, vi))

arith_results.sort(reverse=True)
print(f"  Configs with arithmetic score ≥15: {len(arith_results)}")
for total, ene_top, bc_top, oi, vi in arith_results[:10]:
    print(f"    score={total}, ENE delta={ene_top[0]} ({ene_top[1]}×), "
          f"BC delta={bc_top[0]} ({bc_top[1]}×), order={ORDERS[oi]}, {VNAMES[vi]}")

# Expected: for 12 ENE deltas and 10 BC deltas, random constant delta
# would give max ~12*1/26 + 10*1/26 ≈ 0.85. Score 15+ would be very rare.
print(f"  Expected random max score: ~4-5")
print(f"\n  P4 done: {time.time()-t0:.1f}s")


# ── Phase 5: Grid-position correlation ────────────────────────────────
print("\n--- P5: Grid-position key correlation ---")

# Check if key[j] = f(row(j), col(j)) for simple functions
# E.g., key[j] = a * row(j) + b * col(j) + c (mod 26)
# With 24 equations and 3 unknowns, this is heavily overdetermined

grid_results = []

for oi in range(len(ORDERS)):
    for vi in range(3):
        ks = extract_keystream(oi, vi)

        # Try key = a*row + b*col + c (mod 26)
        # Use first 3 cribs to solve for a, b, c, then check rest
        if len(ks) < 3:
            continue

        best_match = 0
        best_abc = None

        # Brute force a, b, c
        for a in range(26):
            for b in range(26):
                # Determine c from first crib
                pos0, k0 = ks[0]
                r0, c0 = pos0 // W, pos0 % W
                c_val = (k0 - a * r0 - b * c0) % 26

                # Check all cribs
                matches = 0
                for pos, kval in ks:
                    r, cc = pos // W, pos % W
                    predicted = (a * r + b * cc + c_val) % 26
                    if predicted == kval:
                        matches += 1

                if matches > best_match:
                    best_match = matches
                    best_abc = (a, b, c_val)

        if best_match >= 18:
            grid_results.append((best_match, best_abc, oi, vi))

grid_results.sort(reverse=True)
print(f"  Configs with grid-linear score ≥18: {len(grid_results)}")
for score, abc, oi, vi in grid_results[:10]:
    print(f"    {score}/24, a={abc[0]} b={abc[1]} c={abc[2]}, order={ORDERS[oi]}, {VNAMES[vi]}")

print(f"\n  P5 done: {time.time()-t0:.1f}s")


# ── Phase 6: Key readable as letters ─────────────────────────────────
print("\n--- P6: Key readability analysis ---")

# For each ordering/variant, concatenate key values as letters and check
# if they contain common English digrams/trigrams

COMMON_DIGRAMS = {'TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ON', 'AT', 'EN', 'ND',
                  'ST', 'ES', 'OR', 'TE', 'OF', 'ED', 'IS', 'IT', 'AL', 'AR'}

best_readable = 0
best_readable_cfg = None

for oi in range(len(ORDERS)):
    for vi in range(3):
        ks = extract_keystream(oi, vi)
        # Sort by position and extract key letters
        ks_sorted = sorted(ks, key=lambda x: x[0])

        # ENE block key (consecutive)
        ene_key = ''.join(AZ[k] for _, k in ks_sorted if 21 <= _  <= 33)

        # BC block key (consecutive)
        bc_key = ''.join(AZ[k] for _, k in ks_sorted if 63 <= _ <= 73)

        # Count digram hits
        digram_hits = 0
        for block in [ene_key, bc_key]:
            for i in range(len(block) - 1):
                if block[i:i+2] in COMMON_DIGRAMS:
                    digram_hits += 1

        if digram_hits > best_readable:
            best_readable = digram_hits
            best_readable_cfg = (ORDERS[oi], VNAMES[vi], ene_key, bc_key)

print(f"  Best digram score: {best_readable}")
if best_readable_cfg:
    print(f"    order={best_readable_cfg[0]}, {best_readable_cfg[1]}")
    print(f"    ENE key: {best_readable_cfg[2]}")
    print(f"    BC  key: {best_readable_cfg[3]}")

# Expected: ~24 * (20/676) ≈ 0.71 digram hits random
print(f"  Expected random digram hits: ~0.7")
print(f"\n  P6 done: {time.time()-t0:.1f}s")


# ── Phase 7: Key difference analysis ─────────────────────────────────
print("\n--- P7: Key second differences (curvature) ---")

# Check if key values follow a second-order pattern (constant second differences)
# Within each consecutive crib block

best_2nd = 0
best_2nd_cfg = None

for oi in range(len(ORDERS)):
    for vi in range(3):
        ks = extract_keystream(oi, vi)
        ks_sorted = sorted(ks, key=lambda x: x[0])

        ene_keys = [k for p, k in ks_sorted if 21 <= p <= 33]
        bc_keys = [k for p, k in ks_sorted if 63 <= p <= 73]

        for block_name, block in [('ENE', ene_keys), ('BC', bc_keys)]:
            if len(block) < 3:
                continue
            # First differences
            d1 = [(block[i+1] - block[i]) % 26 for i in range(len(block)-1)]
            # Second differences
            d2 = [(d1[i+1] - d1[i]) % 26 for i in range(len(d1)-1)]

            # Count zeros in d2 (constant first diff = linear)
            zeros = sum(1 for x in d2 if x == 0)
            # Count constant d2 (quadratic)
            d2_counter = Counter(d2)
            max_const = d2_counter.most_common(1)[0][1] if d2_counter else 0

            score = zeros + max_const
            if score > best_2nd:
                best_2nd = score
                best_2nd_cfg = (block_name, ORDERS[oi], VNAMES[vi],
                               d1[:5], d2[:5], zeros, max_const)

print(f"  Best 2nd-diff score: {best_2nd}")
if best_2nd_cfg:
    print(f"    block={best_2nd_cfg[0]}, order={best_2nd_cfg[1]}, {best_2nd_cfg[2]}")
    print(f"    d1 (first 5): {best_2nd_cfg[3]}")
    print(f"    d2 (first 5): {best_2nd_cfg[4]}")
    print(f"    d2 zeros={best_2nd_cfg[5]}, max_const={best_2nd_cfg[6]}")


# ── Summary ───────────────────────────────────────────────────────────
total_elapsed = time.time() - t0

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  P1 CT-autokey: top={ct_autokey_results[0][0] if ct_autokey_results else 0}/24 matches")
print(f"  P2 PT-autokey: top={pt_autokey_results[0][0] if pt_autokey_results else 0} matches")
print(f"  P3 Period consistency: {period_counts}")
print(f"  P4 Arithmetic: top={arith_results[0][0] if arith_results else 0}")
print(f"  P5 Grid-linear: top={grid_results[0][0] if grid_results else 0}/24")
print(f"  P6 Key readability: {best_readable} digram hits")
print(f"  P7 2nd-diff: {best_2nd}")
print(f"  Total: {total_elapsed:.1f}s")

os.makedirs("results", exist_ok=True)
out = {
    'experiment': 'E-S-94',
    'description': 'Keystream structure analysis for width-7 orderings',
    'ct_autokey_top': ct_autokey_results[:5] if ct_autokey_results else [],
    'pt_autokey_top': pt_autokey_results[:5] if pt_autokey_results else [],
    'period_consistency': period_counts,
    'arithmetic_top': [(s, str(e), str(b), ORDERS[oi], VNAMES[vi])
                       for s, e, b, oi, vi in arith_results[:5]] if arith_results else [],
    'grid_linear_top': [(s, abc, ORDERS[oi], VNAMES[vi])
                        for s, abc, oi, vi in grid_results[:5]] if grid_results else [],
    'key_readability': best_readable,
    'elapsed_seconds': total_elapsed,
}
with open("results/e_s_94_keystream_structure.json", "w") as f:
    json.dump(out, f, indent=2, default=str)
print(f"\n  Artifact: results/e_s_94_keystream_structure.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_94_keystream_structure.py")
