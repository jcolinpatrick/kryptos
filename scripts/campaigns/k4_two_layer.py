"""
Cipher: multi-vector campaign
Family: campaigns
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
Two-layer cipher tests for K4.

Scheidt stated there is a "change in methodology" from K3→K4 and rated difficulty 9/10.
This suggests multiple cipher layers or a non-standard combination.

Strategy: If K4 has TWO layers, the outer layer must be "unpeeled" first.
The inner layer produces the cribs. We test systematic outer layers:

1. Monoalphabetic substitution + Vigenère
2. Keyword-mixed alphabet (KA) as substitution layer
3. Nibble swap / letter-pair manipulation
4. Columnar transposition as outer layer (pre-Vig reorder)
5. Caesar shift varying by row in a grid
6. Additive mask from K1/K2/K3 ciphertext or plaintext
"""
import sys, itertools
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

CT = 'OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR'
CT_NUM = [ord(c) - ord('A') for c in CT]
N = 97

ENE_POS, ENE_PT = 21, 'EASTNORTHEAST'
BC_POS, BC_PT = 63, 'BERLINCLOCK'

def c2n(c): return ord(c) - ord('A')
def n2c(n): return chr(n % 26 + ord('A'))

# Known Vig key values
known_vig = {}
for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]:
    for i, ch in enumerate(pt):
        pos = start + i
        known_vig[pos] = (CT_NUM[pos] - c2n(ch)) % 26

def score_key(key_slice):
    matches = 0
    for pos, expected in known_vig.items():
        if pos < len(key_slice):
            if key_slice[pos] == expected:
                matches += 1
    return matches

def score_ct_mod(ct_mod_nums):
    """Score modified CT against cribs assuming Vig with periodic key."""
    # Try all periods 1-24 and keyword-starts
    best = 0
    for period in range(1, 25):
        # At crib positions, derive what key must be
        key_vals = {}
        consistent = True
        for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]:
            for i, ch in enumerate(pt):
                pos = start + i
                if pos < len(ct_mod_nums):
                    needed = (ct_mod_nums[pos] - c2n(ch)) % 26
                    residue = pos % period
                    if residue in key_vals:
                        if key_vals[residue] != needed:
                            consistent = False
                            break
                    else:
                        key_vals[residue] = needed
            if not consistent:
                break

        if consistent:
            # Count how many crib positions are explained
            matches = 0
            for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]:
                for i, ch in enumerate(pt):
                    pos = start + i
                    if pos < len(ct_mod_nums):
                        residue = pos % period
                        if residue in key_vals:
                            expected_pt = (ct_mod_nums[pos] - key_vals[residue]) % 26
                            if expected_pt == c2n(ch):
                                matches += 1
            best = max(best, matches)
    return best

print("=" * 70)
print("K4 TWO-LAYER CIPHER ANALYSIS")
print("=" * 70)

# ============================================================
# 1. MONOALPHABETIC OUTER LAYER
# ============================================================
print("\n1. MONOALPHABETIC SUBSTITUTION + VIGENÈRE")
print("-" * 70)
print("  If CT was mono-substituted BEFORE Vig encryption:")
print("  True_CT[i] = mono(visible_CT[i]), then PT[i] = True_CT[i] - key[i]")
print("  So: key[i] = mono(CT[i]) - PT[i] mod 26")
print()

# At crib positions, the relationship is:
# key[pos] = (mono(CT[pos]) - PT[pos]) mod 26
# If the Vig key has period p, then key[pos] depends only on pos mod p.
# So: mono(CT[pos]) = PT[pos] + key[pos%p] mod 26
# For two crib positions pos1, pos2 with pos1 ≡ pos2 mod p:
#   mono(CT[pos1]) - PT[pos1] = mono(CT[pos2]) - PT[pos2] mod 26
# This constrains the mono mapping.

# For period p, collect constraints
for period in range(2, 14):
    # Group crib positions by residue
    residue_groups = {}
    for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]:
        for i, ch in enumerate(pt):
            pos = start + i
            r = pos % period
            if r not in residue_groups:
                residue_groups[r] = []
            residue_groups[r].append((pos, CT[pos], ch))

    # Check consistency: for each residue class, mono(CT_letter) - PT_letter must be constant
    consistent = True
    constraints = {}  # mono(A) - mono(B) constraints
    for r, group in residue_groups.items():
        if len(group) < 2:
            continue
        ref_pos, ref_ct, ref_pt = group[0]
        for pos, ct_ch, pt_ch in group[1:]:
            # mono(ct_ch) - c2n(pt_ch) = mono(ref_ct) - c2n(ref_pt) mod 26
            # i.e., mono(ct_ch) - mono(ref_ct) = c2n(pt_ch) - c2n(ref_pt) mod 26
            diff = (c2n(pt_ch) - c2n(ref_pt)) % 26
            pair = (ct_ch, ref_ct)
            if pair in constraints:
                if constraints[pair] != diff:
                    consistent = False
                    break
            else:
                constraints[pair] = diff
                # Also reverse
                constraints[(ref_ct, ct_ch)] = (26 - diff) % 26
        if not consistent:
            break

    if consistent and constraints:
        # Count unique constraints
        n_constraints = len(set(frozenset(k) for k in constraints.keys()))
        if n_constraints >= 3:
            print(f"  Period {period}: {n_constraints} mono constraints, CONSISTENT")
            for (a, b), diff in sorted(constraints.items()):
                if a <= b:  # avoid duplicates
                    print(f"    mono({a}) - mono({b}) ≡ {diff} mod 26")
    elif not consistent:
        pass  # print(f"  Period {period}: CONTRADICTION (eliminated)")

# ============================================================
# 2. KA ALPHABET AS SUBSTITUTION LAYER
# ============================================================
print("\n2. KRYPTOS ALPHABET AS SUBSTITUTION LAYER")
print("-" * 70)

# Method: replace each CT letter with its KA position, then Vig decrypt
KA = 'KRYPTOSABCDEFGHIJLMNQUVWXZ'
KA_MAP = {c: i for i, c in enumerate(KA)}
AZ_MAP = {c: i for i, c in enumerate('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}

# CT → KA positions → Vig decrypt with periodic key
ct_ka = [KA_MAP[c] for c in CT]
best_ka = (0, 0)
for period in range(1, 25):
    # Derive key from cribs
    key_vals = {}
    ok = True
    for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]:
        for i, ch in enumerate(pt):
            pos = start + i
            needed = (ct_ka[pos] - c2n(ch)) % 26
            r = pos % period
            if r in key_vals:
                if key_vals[r] != needed:
                    ok = False
                    break
            else:
                key_vals[r] = needed
        if not ok:
            break

    if ok:
        # Count matches
        matches = 0
        for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]:
            for i, ch in enumerate(pt):
                pos = start + i
                r = pos % period
                if r in key_vals:
                    if (ct_ka[pos] - key_vals[r]) % 26 == c2n(ch):
                        matches += 1
        if matches > best_ka[0]:
            best_ka = (matches, period)
        if matches == 24:
            # Full match! Show it
            key_full = [key_vals.get(i % period, -1) for i in range(N)]
            pt_text = ''.join(n2c((ct_ka[i] - key_full[i]) % 26) for i in range(N))
            print(f"  KA→AZ Vig period {period}: {matches}/24 FULL MATCH!")
            print(f"  PT: {pt_text}")
            print(f"  Key: {''.join(n2c(k) for k in key_full)}")
print(f"  Best KA substitution + Vig: {best_ka[0]}/24 (period {best_ka[1]})")

# Also test: AZ → KA (reverse mapping)
ct_rev = [AZ_MAP[KA[v]] if v < 26 else v for v in CT_NUM]
# Wait, that doesn't make sense. Let's try: interpret CT as KA-encoded,
# map back to AZ, then Vig
ct_ka_to_az = [c2n(KA[c2n(c)]) if c2n(c) < 26 else c2n(c) for c in CT]
best_ka2 = (0, 0)
for period in range(1, 25):
    key_vals = {}
    ok = True
    for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]:
        for i, ch in enumerate(pt):
            pos = start + i
            needed = (ct_ka_to_az[pos] - c2n(ch)) % 26
            r = pos % period
            if r in key_vals:
                if key_vals[r] != needed:
                    ok = False
                    break
            else:
                key_vals[r] = needed
        if not ok:
            break
    if ok:
        matches = sum(1 for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]
                     for i, ch in enumerate(pt)
                     if (ct_ka_to_az[start+i] - key_vals.get((start+i) % period, -99)) % 26 == c2n(ch))
        if matches > best_ka2[0]:
            best_ka2 = (matches, period)
        if matches == 24:
            key_full = [key_vals.get(i % period, -1) for i in range(N)]
            pt_text = ''.join(n2c((ct_ka_to_az[i] - key_full[i]) % 26) for i in range(N))
            print(f"  AZ→KA→Vig period {period}: {matches}/24")
            print(f"  PT: {pt_text}")
print(f"  Best AZ→KA + Vig: {best_ka2[0]}/24 (period {best_ka2[1]})")

# ============================================================
# 3. ADDITIVE MASK FROM K1/K2/K3
# ============================================================
print("\n3. ADDITIVE MASK FROM K1/K2/K3 CIPHER/PLAIN TEXTS")
print("-" * 70)

K1_CT = 'EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD'
K2_CT = 'VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKSQATQPMFGXIFLAIFQDMHRGWTKRQLXTFSLYEVQALNMFEWFGLFEAMKKSNLCPYSEPQWICETQFHQSVZJLNTIHLLKSQVNIWECQLQOQENMWVLNPEKLSRMSLKLDNQSRMPKHEQIEJFM'
K3_CT = 'ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNETPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOETFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLBTEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEBAECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHEECDMRIPFEIMEHNLSSTTRTVDOHW'
K1_PT = 'BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION'
K2_PT = 'ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISXTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONXONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTXLAYERTWO'
K3_PT = 'SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBABORSWEREDISCOVEREDALEADTOTHEDOORWAYWASONLYEXTENDEDLABORUNDERGOROUDLEADTOLAROKINGTUTSEPULCHURALSROOM'

masks = {
    'K1_CT': K1_CT,
    'K2_CT': K2_CT[:N],
    'K3_CT': K3_CT[:N],
    'K1_PT': K1_PT,
    'K2_PT': K2_PT[:N],
    'K3_PT': K3_PT[:N],
    'K2_CT_rev': K2_CT[::-1][:N],
    'K3_CT_rev': K3_CT[::-1][:N],
}

for mask_name, mask_text in masks.items():
    if len(mask_text) < N:
        # Pad with cycling
        while len(mask_text) < N:
            mask_text += mask_text
        mask_text = mask_text[:N]

    mask_nums = [c2n(c) for c in mask_text.upper() if c.isalpha()][:N]
    if len(mask_nums) < N:
        continue

    # Method A: subtract mask from CT, then check cribs (mask is additive outer layer)
    ct_unmasked = [(CT_NUM[i] - mask_nums[i]) % 26 for i in range(N)]
    s_a = score_ct_mod(ct_unmasked)

    # Method B: add mask to CT
    ct_added = [(CT_NUM[i] + mask_nums[i]) % 26 for i in range(N)]
    s_b = score_ct_mod(ct_added)

    # Method C: XOR-like (multiply)
    # Well, mod 26 multiply is not great. Skip.

    best = max(s_a, s_b)
    variant = "sub" if s_a >= s_b else "add"
    if best >= 6:
        print(f"  {mask_name} ({variant}): {best}/24")
    elif best >= 4:
        print(f"  {mask_name}: best {best}/24 (noise)")

# ============================================================
# 4. K1/K2 KEY AS MASK
# ============================================================
print("\n4. K1/K2 KEYSTREAM AS MASK")
print("-" * 70)

# K1 was encrypted with keyword PALIMPSEST using Vig with KA alphabet
# K2 was encrypted with keyword ABSCISSA using Vig with KA alphabet
# What if K4's CT has K1's or K2's keystream added/subtracted?

# Reconstruct K1 keystream (under KA-Vig)
K1_KW = 'PALIMPSEST'
K2_KW = 'ABSCISSA'

for kw_name, kw, ct_text, pt_text in [
    ('K1', K1_KW, K1_CT, K1_PT),
    ('K2', K2_KW, K2_CT, K2_PT),
]:
    # Standard AZ keystream
    kw_stream = [c2n(kw[i % len(kw)]) for i in range(len(ct_text))]

    # Use first N values as mask
    if len(kw_stream) >= N:
        mask = kw_stream[:N]
    else:
        mask = (kw_stream * ((N // len(kw_stream)) + 1))[:N]

    # Unmask CT
    for direction, label in [(-1, "sub"), (1, "add")]:
        ct_mod = [(CT_NUM[i] + direction * mask[i]) % 26 for i in range(N)]
        s = score_ct_mod(ct_mod)
        if s >= 4:
            print(f"  {kw_name} keystream ({label}): {s}/24")

    # Also try: just the keyword cycling
    kw_nums = [c2n(c) for c in kw]
    p = len(kw_nums)
    for direction, label in [(-1, "sub"), (1, "add")]:
        ct_mod = [(CT_NUM[i] + direction * kw_nums[i % p]) % 26 for i in range(N)]
        key = [(ct_mod[pos] - c2n(pt_ch)) % 26
               for start, pt_text_cr in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]
               for pos_i, pt_ch in enumerate(pt_text_cr)
               for pos in [start + pos_i]][:24]
        # Score: how many match periodic key
        s = score_ct_mod(ct_mod)
        if s >= 4:
            print(f"  {kw_name} keyword {kw} ({label}): {s}/24")

# ============================================================
# 5. REVERSED/SHUFFLED INNER CT
# ============================================================
print("\n5. PRE-TRANSPOSITION BEFORE VIG")
print("-" * 70)
print("  Testing: undo a columnar transposition FIRST, then check Vig cribs")

# For small widths, try all column orderings
from itertools import permutations

def columnar_decrypt(text, width, col_order):
    """Undo columnar transposition: given ciphertext written into columns, read by rows."""
    n = len(text)
    nrows = (n + width - 1) // width
    ncols = width
    # Number of long columns (nrows cells) vs short (nrows-1)
    n_long = n - (nrows - 1) * ncols  # cols that have nrows cells

    # Place text into columns in the given order
    grid = [[''] * ncols for _ in range(nrows)]
    pos = 0
    for col_idx in col_order:
        col_len = nrows if col_idx < n_long else nrows - 1
        for row in range(col_len):
            if pos < n:
                grid[row][col_idx] = text[pos]
                pos += 1

    # Read by rows
    result = ''
    for row in range(nrows):
        for col in range(ncols):
            if grid[row][col]:
                result += grid[row][col]
    return result

# Test widths 2-6 exhaustively (6! = 720 orderings max)
best_pre_trans = (0, 0, None)
for width in range(2, 7):
    for perm in permutations(range(width)):
        try:
            unscrambled = columnar_decrypt(CT, width, list(perm))
            if len(unscrambled) != N:
                continue
            un_nums = [c2n(c) for c in unscrambled]
            # Check if this + periodic Vig explains cribs
            for period in range(1, 15):
                key_vals = {}
                ok = True
                for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]:
                    for i, ch in enumerate(pt):
                        pos = start + i
                        needed = (un_nums[pos] - c2n(ch)) % 26
                        r = pos % period
                        if r in key_vals:
                            if key_vals[r] != needed:
                                ok = False
                                break
                        else:
                            key_vals[r] = needed
                    if not ok:
                        break
                if ok:
                    matches = 0
                    for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]:
                        for i, ch in enumerate(pt):
                            pos = start + i
                            r = pos % period
                            if r in key_vals:
                                if (un_nums[pos] - key_vals[r]) % 26 == c2n(ch):
                                    matches += 1
                    if matches > best_pre_trans[0]:
                        best_pre_trans = (matches, period, (width, perm))
                    if matches >= 20:
                        print(f"  W={width} perm={perm} period={period}: {matches}/24!")
        except:
            pass

print(f"  Best pre-transposition + Vig: {best_pre_trans[0]}/24 (period={best_pre_trans[1]}, grid={best_pre_trans[2]})")

# ============================================================
# 6. RAIL FENCE + VIGENÈRE
# ============================================================
print("\n6. RAIL FENCE + VIGENÈRE")
print("-" * 70)

def rail_fence_decrypt(text, rails):
    n = len(text)
    if rails <= 1 or rails >= n:
        return text
    # Build fence pattern
    pattern = list(range(rails)) + list(range(rails-2, 0, -1))
    cycle = len(pattern)
    assignments = [pattern[i % cycle] for i in range(n)]

    # Determine positions for each rail
    result = [''] * n
    idx = 0
    for rail in range(rails):
        for i in range(n):
            if assignments[i] == rail:
                result[i] = text[idx]
                idx += 1
    return ''.join(result)

best_rf = (0, 0, 0)
for rails in range(2, 20):
    unscrambled = rail_fence_decrypt(CT, rails)
    un_nums = [c2n(c) for c in unscrambled]
    for period in range(1, 25):
        key_vals = {}
        ok = True
        for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]:
            for i, ch in enumerate(pt):
                pos = start + i
                needed = (un_nums[pos] - c2n(ch)) % 26
                r = pos % period
                if r in key_vals:
                    if key_vals[r] != needed:
                        ok = False
                        break
                else:
                    key_vals[r] = needed
            if not ok:
                break
        if ok:
            matches = sum(1 for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]
                         for i, ch in enumerate(pt)
                         if (un_nums[start+i] - key_vals.get((start+i) % period, -99)) % 26 == c2n(ch))
            if matches > best_rf[0]:
                best_rf = (matches, rails, period)
            if matches >= 20:
                print(f"  Rails={rails} period={period}: {matches}/24!")

print(f"  Best rail fence + Vig: {best_rf[0]}/24 (rails={best_rf[1]}, period={best_rf[2]})")

print("\n" + "=" * 70)
print("TWO-LAYER ANALYSIS COMPLETE")
print("=" * 70)
