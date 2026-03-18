#!/usr/bin/env python3
"""
Cipher: Beaufort/Vigenere/VBeau (analytical)
Family: analysis
Status: active
Keyspace: N/A (analytical)
Last run: 2026-03-16
Best score: N/A
"""
"""MODEL B DEEP INVESTIGATION: Cipher operates on ALL 97 chars directly.

No null extraction, no col7 transposition. Cribs at their original positions
(21-33 = EASTNORTHEAST, 63-73 = BERLINCLOCK). 24 PT chars are garbage, 73 real.

Under Beaufort: K[i] = (CT[i] + PT[i]) mod 26
Under Vigenere: K[i] = (CT[i] - PT[i]) mod 26
Under VBeau:   K[i] = (PT[i] - CT[i]) mod 26

Steps:
  1. Compute all 24 raw keystream values (3 variants)
  2. Frequency analysis, IC, palette check
  3. Period search on raw 97 positions
  4. ENE key region analysis (13 consecutive key values)
  5. BCL key region analysis (11 consecutive key values)
  6. Cross-region comparison and d=13 exploitation
  7. Running key search against Carter text, K1-K3, tableau rows
  8. Tableau key derivation
  9. d=13 anomaly exploitation
 10. Model B decryption attempts with any discovered patterns
"""

import json, os, sys, time, math
from collections import Counter

# ── Constants ──────────────────────────────────────────────────────────
CT97 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
I2N = {c: i for i, c in enumerate(AZ)}
N2L = {i: c for i, c in enumerate(AZ)}
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_I2N = {c: i for i, c in enumerate(KA)}

ENE_START = 21
ENE_TEXT = "EASTNORTHEAST"
BCL_START = 63
BCL_TEXT = "BERLINCLOCK"

ENE_NUMS = [I2N[c] for c in ENE_TEXT]
BCL_NUMS = [I2N[c] for c in BCL_TEXT]

# All crib positions and their PT values
CRIB_DICT = {}
for i, ch in enumerate(ENE_TEXT):
    CRIB_DICT[ENE_START + i] = (ch, I2N[ch])
for i, ch in enumerate(BCL_TEXT):
    CRIB_DICT[BCL_START + i] = (ch, I2N[ch])

CRIB_POSITIONS = sorted(CRIB_DICT.keys())  # 24 positions
CT_NUMS = [I2N[c] for c in CT97]

# K1-K3 plaintexts
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTIDBYROWS"
K3_PT = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHINEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"

KEYWORDS = {
    'KRYPTOS': [I2N[c] for c in 'KRYPTOS'],
    'DEFECTOR': [I2N[c] for c in 'DEFECTOR'],
    'ABSCISSA': [I2N[c] for c in 'ABSCISSA'],
    'PALIMPSEST': [I2N[c] for c in 'PALIMPSEST'],
    'SEVEN': [I2N[c] for c in 'SEVEN'],
    'KOMPASS': [I2N[c] for c in 'KOMPASS'],
    'COLOPHON': [I2N[c] for c in 'COLOPHON'],
    'PARALLAX': [I2N[c] for c in 'PARALLAX'],
    'BERLIN': [I2N[c] for c in 'BERLIN'],
    'CLOCK': [I2N[c] for c in 'CLOCK'],
    'BERLINCLOCK': [I2N[c] for c in 'BERLINCLOCK'],
    'ENIGMA': [I2N[c] for c in 'ENIGMA'],
    'HOROLOGE': [I2N[c] for c in 'HOROLOGE'],
}

PALETTE = set('BGIKOWZ')

# Quadgrams if available
QUADGRAMS = None
try:
    qg_path = "/home/cpatrick/kryptos/data/english_quadgrams.json"
    if os.path.exists(qg_path):
        with open(qg_path) as f:
            QUADGRAMS = json.load(f)
        # Precompute total and floor
        QG_TOTAL = sum(10**v for v in QUADGRAMS.values())
        QG_FLOOR = min(QUADGRAMS.values()) - 1  # penalty for unseen
except Exception:
    pass

def quadgram_score(text):
    """Compute quadgram log-probability per character."""
    if QUADGRAMS is None:
        return None
    text = text.upper()
    total = 0.0
    count = 0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        if qg in QUADGRAMS:
            total += QUADGRAMS[qg]
        else:
            total += QG_FLOOR
        count += 1
    return total / count if count > 0 else None


# ════════════════════════════════════════════════════════════════════
# STEP 1: Compute the 24 raw keystream values
# ════════════════════════════════════════════════════════════════════
print("=" * 80)
print("MODEL B DEEP INVESTIGATION: Raw 97-char Keystream Analysis")
print("=" * 80)
print(f"\nCT97: {CT97}")
print(f"Length: {len(CT97)}")
print(f"\nModel B premise: Cipher operates on ALL 97 chars. No null extraction.")
print(f"Cribs: ENE at positions 21-33, BCL at positions 63-73.")
print(f"24 plaintext positions are garbage, 73 are the real message.")

print("\n" + "=" * 80)
print("STEP 1: ALL 24 RAW KEYSTREAM VALUES (3 variants)")
print("=" * 80)

beau_key = {}  # pos -> value
vig_key = {}
vbeau_key = {}

print(f"\n{'Pos':>4} {'CT':>3} {'PT':>3} {'Beau_K':>7} {'BLet':>5} {'Vig_K':>7} {'VLet':>5} {'VBeau_K':>8} {'VBLet':>6}")
for pos in CRIB_POSITIONS:
    ct_val = CT_NUMS[pos]
    pt_ch, pt_val = CRIB_DICT[pos]
    bk = (ct_val + pt_val) % 26
    vk = (ct_val - pt_val) % 26
    vbk = (pt_val - ct_val) % 26
    beau_key[pos] = bk
    vig_key[pos] = vk
    vbeau_key[pos] = vbk
    print(f"{pos:>4}   {CT97[pos]}  {pt_ch}  {bk:>5} {N2L[bk]:>5}  {vk:>5} {N2L[vk]:>5}   {vbk:>5} {N2L[vbk]:>6}")

beau_vals = [beau_key[p] for p in CRIB_POSITIONS]
vig_vals = [vig_key[p] for p in CRIB_POSITIONS]
vbeau_vals = [vbeau_key[p] for p in CRIB_POSITIONS]

beau_str = ''.join(N2L[v] for v in beau_vals)
vig_str = ''.join(N2L[v] for v in vig_vals)
vbeau_str = ''.join(N2L[v] for v in vbeau_vals)

print(f"\nBeau  key letters: {beau_str}")
print(f"Vig   key letters: {vig_str}")
print(f"VBeau key letters: {vbeau_str}")

# ════════════════════════════════════════════════════════════════════
# STEP 2: Analyze the 24 key values
# ════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("STEP 2: KEYSTREAM ANALYSIS")
print("=" * 80)

for name, vals, key_dict in [("Beaufort", beau_vals, beau_key),
                              ("Vigenere", vig_vals, vig_key),
                              ("VBeau", vbeau_vals, vbeau_key)]:
    print(f"\n--- {name} Keystream ---")

    # 2a. IC
    freq = Counter(vals)
    n_ks = len(vals)
    ic_num = sum(c * (c - 1) for c in freq.values())
    ic_den = n_ks * (n_ks - 1)
    ic = ic_num / ic_den if ic_den > 0 else 0
    print(f"  IC: {ic:.4f} (random={1/26:.4f}, English=0.0667, ratio={ic/(1/26):.2f}x)")

    # 2b. Letter frequency
    print(f"  Letter freq ({len(freq)} distinct):")
    for val, count in sorted(freq.items(), key=lambda x: -x[1]):
        bar = '#' * count
        print(f"    {N2L[val]}({val:>2}): {bar} {count}")

    # 2c. Palette check
    pal_count = sum(1 for v in vals if N2L[v] in PALETTE)
    print(f"  Palette {{B,G,I,K,O,W,Z}}: {pal_count}/24 ({pal_count/24*100:.1f}%)")

    # 2d. KA indices
    ka_indices = [KA_I2N[N2L[v]] for v in vals]
    print(f"  KA indices: {ka_indices}")

    # 2e. Mod patterns
    for m in [5, 7, 8, 13]:
        mod_vals = [v % m for v in vals]
        mod_freq = Counter(mod_vals)
        n_distinct = len(mod_freq)
        # Check if all same
        if n_distinct == 1:
            print(f"  mod {m}: ALL SAME = {mod_vals[0]}")
        elif n_distinct <= m // 2:
            print(f"  mod {m}: {n_distinct} distinct values: {dict(mod_freq)}")

    # 2f. Sorted values - arithmetic progressions
    sorted_vals = sorted(set(vals))
    if len(sorted_vals) >= 3:
        diffs = [sorted_vals[i+1] - sorted_vals[i] for i in range(len(sorted_vals)-1)]
        if len(set(diffs)) == 1:
            print(f"  ARITHMETIC PROGRESSION: step={diffs[0]}")

    # 2g. Bean's "same PT letter -> similar keys" clustering
    # Group by plaintext letter
    pt_letter_keys = {}
    for pos in CRIB_POSITIONS:
        _, pt_val = CRIB_DICT[pos]
        pt_letter = chr(65 + pt_val)
        if pt_letter not in pt_letter_keys:
            pt_letter_keys[pt_letter] = []
        pt_letter_keys[pt_letter].append(key_dict[pos])

    same_pt_pairs = []
    for letter, keys in pt_letter_keys.items():
        if len(keys) >= 2:
            for i in range(len(keys)):
                for j in range(i+1, len(keys)):
                    diff = min(abs(keys[i] - keys[j]), 26 - abs(keys[i] - keys[j]))
                    same_pt_pairs.append((letter, keys[i], keys[j], diff))

    if same_pt_pairs:
        print(f"  Same-PT-letter key clustering:")
        for letter, k1, k2, diff in same_pt_pairs:
            status = "EQUAL" if diff == 0 else f"diff={diff}"
            print(f"    PT='{letter}': keys {N2L[k1]}({k1}), {N2L[k2]}({k2}) -> {status}")

        # Compare to random expectation
        avg_diff = sum(d for _, _, _, d in same_pt_pairs) / len(same_pt_pairs)
        # Random expected: average minimum circular distance = 26/4 = 6.5
        print(f"    Average min-circular-diff: {avg_diff:.2f} (random expected ~6.5)")


# ════════════════════════════════════════════════════════════════════
# STEP 3: Period search on raw 97 keystream
# ════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("STEP 3: PERIOD SEARCH ON RAW 97 POSITIONS")
print("=" * 80)

for name, key_dict in [("Beaufort", beau_key), ("Vigenere", vig_key)]:
    print(f"\n--- {name} period consistency (raw 97 positions) ---")
    print(f"  24 known positions: {CRIB_POSITIONS}")

    for p in range(1, 49):
        residue_vals = {}
        conflicts = 0
        for pos in CRIB_POSITIONS:
            r = pos % p
            if r in residue_vals:
                if residue_vals[r] != key_dict[pos]:
                    conflicts += 1
            else:
                residue_vals[r] = key_dict[pos]
        n_residues = len(residue_vals)
        n_populated = sum(1 for r in residue_vals if sum(1 for pos2 in CRIB_POSITIONS if pos2 % p == r) >= 2)

        if conflicts == 0:
            marker = "*** 0 CONFLICTS ***"
            # Calculate how many constraints this actually tests
            n_checks = sum(max(0, sum(1 for pos2 in CRIB_POSITIONS if pos2 % p == r) - 1) for r in residue_vals)
            print(f"  period {p:>2}: {marker} ({n_residues} residues, {n_checks} pairwise checks, {n_populated} multi-value residues)")
        elif conflicts <= 2 and p <= 26:
            print(f"  period {p:>2}: {conflicts} conflicts ({n_residues} residues)")


# ════════════════════════════════════════════════════════════════════
# STEP 4: ENE key region (positions 21-33, 13 consecutive key values)
# ════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("STEP 4: ENE KEY REGION (positions 21-33, 13 consecutive values)")
print("=" * 80)

ene_positions = list(range(ENE_START, ENE_START + len(ENE_TEXT)))
ene_beau = [beau_key[p] for p in ene_positions]
ene_vig = [vig_key[p] for p in ene_positions]

print(f"\n  Positions:    {ene_positions}")
print(f"  CT:           {''.join(CT97[p] for p in ene_positions)}")
print(f"  PT:           {ENE_TEXT}")
print(f"  Beau keys:    {ene_beau}")
print(f"  Beau letters: {''.join(N2L[v] for v in ene_beau)}")
print(f"  Vig keys:     {ene_vig}")
print(f"  Vig letters:  {''.join(N2L[v] for v in ene_vig)}")

# 4a. Arithmetic progression
print(f"\n  --- 4a. Arithmetic progression check ---")
diffs_beau = [(ene_beau[i+1] - ene_beau[i]) % 26 for i in range(len(ene_beau)-1)]
print(f"  Beau consecutive diffs (mod 26): {diffs_beau}")
print(f"  Beau letters of diffs: {''.join(N2L[d] for d in diffs_beau)}")

diffs_vig = [(ene_vig[i+1] - ene_vig[i]) % 26 for i in range(len(ene_vig)-1)]
print(f"  Vig consecutive diffs (mod 26): {diffs_vig}")

# Check if diffs are constant
if len(set(diffs_beau)) == 1:
    print(f"  *** BEAU ARITHMETIC PROGRESSION: step={diffs_beau[0]} ***")
if len(set(diffs_vig)) == 1:
    print(f"  *** VIG ARITHMETIC PROGRESSION: step={diffs_vig[0]} ***")

# 4b. Recurrence: k[i+1] = f(k[i])
print(f"\n  --- 4b. Recurrence check (ENE region) ---")
# k[i+1] = (a*k[i] + b) mod 26
best_affine = (0, 0, 0)
for a in range(26):
    for b in range(26):
        matches = sum(1 for i in range(len(ene_beau)-1)
                      if (a * ene_beau[i] + b) % 26 == ene_beau[i+1])
        if matches > best_affine[0]:
            best_affine = (matches, a, b)
print(f"  Best k[i+1] = (a*k[i]+b)%26: {best_affine[0]}/12 at a={best_affine[1]}, b={best_affine[2]}")

# k[i+2] = f(k[i], k[i+1])
print(f"\n  --- 4c. 2-term recurrence (ENE): k[i+2] = (a*k[i] + b*k[i+1] + c) mod 26 ---")
best_2term = (0, 0, 0, 0)
for a in range(26):
    for b in range(26):
        # Derive c from first triple
        c = (ene_beau[2] - a * ene_beau[0] - b * ene_beau[1]) % 26
        matches = sum(1 for i in range(len(ene_beau)-2)
                      if (a * ene_beau[i] + b * ene_beau[i+1] + c) % 26 == ene_beau[i+2])
        if matches > best_2term[0]:
            best_2term = (matches, a, b, c)
print(f"  Best: {best_2term[0]}/11 at a={best_2term[1]}, b={best_2term[2]}, c={best_2term[3]}")

# 4d. Check if ENE key = shifted/rotated known sequence
print(f"\n  --- 4d. Match to known keywords (cyclic, any shift) ---")
for kw_name, kw_vals in KEYWORDS.items():
    L = len(kw_vals)
    for shift in range(L):
        # Check if ene_beau matches kw_vals starting at offset shift
        matches = sum(1 for i in range(13)
                      if kw_vals[(shift + i) % L] == ene_beau[i])
        if matches >= 5:
            print(f"  {kw_name}[{shift}:]: {matches}/13 match (Beau)")
    for shift in range(L):
        matches = sum(1 for i in range(13)
                      if kw_vals[(shift + i) % L] == ene_vig[i])
        if matches >= 5:
            print(f"  {kw_name}[{shift}:]: {matches}/13 match (Vig)")

# 4e. Position-based: k[pos] = f(pos)
print(f"\n  --- 4e. Position-based key (ENE) ---")
# k = (a*pos + b) mod 26
best_lin = (0, 0, 0)
for a in range(26):
    for b in range(26):
        matches = sum(1 for i, pos in enumerate(ene_positions)
                      if (a * pos + b) % 26 == ene_beau[i])
        if matches > best_lin[0]:
            best_lin = (matches, a, b)
print(f"  Linear (Beau): k=(a*pos+b)%26 best: {best_lin[0]}/13 at a={best_lin[1]}, b={best_lin[2]}")

# Check k = pos mod 26 (shifted)
for offset in range(26):
    matches = sum(1 for i, pos in enumerate(ene_positions)
                  if (pos + offset) % 26 == ene_beau[i])
    if matches >= 4:
        print(f"  k=(pos+{offset})%26: {matches}/13 (Beau)")

# 4f. Check reversed key
ene_beau_rev = list(reversed(ene_beau))
print(f"\n  --- 4f. Reversed ENE Beau key ---")
print(f"  Forward:  {ene_beau}")
print(f"  Reversed: {ene_beau_rev}")
# Is reversed a known keyword cycle?
for kw_name, kw_vals in KEYWORDS.items():
    L = len(kw_vals)
    for shift in range(L):
        matches = sum(1 for i in range(13)
                      if kw_vals[(shift + i) % L] == ene_beau_rev[i])
        if matches >= 5:
            print(f"  Reversed matches {kw_name}[{shift}:]: {matches}/13")


# ════════════════════════════════════════════════════════════════════
# STEP 5: BCL key region (positions 63-73, 11 consecutive key values)
# ════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("STEP 5: BCL KEY REGION (positions 63-73, 11 consecutive values)")
print("=" * 80)

bcl_positions = list(range(BCL_START, BCL_START + len(BCL_TEXT)))
bcl_beau = [beau_key[p] for p in bcl_positions]
bcl_vig = [vig_key[p] for p in bcl_positions]

print(f"\n  Positions:    {bcl_positions}")
print(f"  CT:           {''.join(CT97[p] for p in bcl_positions)}")
print(f"  PT:           {BCL_TEXT}")
print(f"  Beau keys:    {bcl_beau}")
print(f"  Beau letters: {''.join(N2L[v] for v in bcl_beau)}")
print(f"  Vig keys:     {bcl_vig}")
print(f"  Vig letters:  {''.join(N2L[v] for v in bcl_vig)}")

# 5a. Diffs
diffs_bcl_beau = [(bcl_beau[i+1] - bcl_beau[i]) % 26 for i in range(len(bcl_beau)-1)]
print(f"\n  Consecutive diffs (Beau, mod 26): {diffs_bcl_beau}")

# 5b. Comparison to ENE
print(f"\n  --- 5b. Cross-region comparison ---")
print(f"  ENE beau: {ene_beau} (len=13)")
print(f"  BCL beau: {bcl_beau} (len=11)")

# Are they the same sequence shifted?
# ENE starts at pos 21, BCL at pos 63. Gap = 42 positions.
print(f"  Position gap: {BCL_START - ENE_START} = 42")
print(f"  If period p divides 42, ENE and BCL residues should match")
print(f"  Factors of 42: 1, 2, 3, 6, 7, 14, 21, 42")

# For each potential period that divides 42, check alignment
for p in [1, 2, 3, 6, 7, 14, 21, 42]:
    # Under period p, pos 21 has residue 21%p, pos 63 has residue 63%p
    # If 21%p == 63%p, first elements should match
    r21 = 21 % p
    r63 = 63 % p
    if r21 == r63:
        # Elements at same residue should have same key
        matches = 0
        comparable = min(13, 11)
        for i in range(comparable):
            if ene_beau[i] == bcl_beau[i]:
                matches += 1
        print(f"  period {p}: residues align (21%{p}={r21}=63%{p}={r63}), direct match: {matches}/{comparable}")
    else:
        # Check shifted alignment
        shift_in_cycle = (63 - 21) % p  # = 0 if they align
        print(f"  period {p}: residues differ (21%{p}={r21}, 63%{p}={r63}), shift={shift_in_cycle}")

# 5c. Is BCL = ENE[offset:]?
print(f"\n  --- 5c. Is BCL a shifted version of ENE? ---")
for offset in range(-12, 13):
    matches = 0
    total = 0
    for i in range(11):
        src = i + offset
        if 0 <= src < 13:
            total += 1
            if ene_beau[src] == bcl_beau[i]:
                matches += 1
    if total >= 5 and matches >= 3:
        print(f"  offset {offset}: {matches}/{total} match")

# 5d. Constant difference between ENE and BCL keys?
print(f"\n  --- 5d. Constant difference ENE[i] - BCL[i] (first 11) ---")
region_diffs = [(ene_beau[i] - bcl_beau[i]) % 26 for i in range(11)]
print(f"  Diffs: {region_diffs}")
print(f"  Diff letters: {''.join(N2L[d] for d in region_diffs)}")
if len(set(region_diffs)) == 1:
    print(f"  *** CONSTANT DIFFERENCE: {region_diffs[0]} ({N2L[region_diffs[0]]}) ***")
else:
    diff_freq = Counter(region_diffs)
    print(f"  Distinct: {len(diff_freq)} values")
    for v, c in diff_freq.most_common(3):
        print(f"    {N2L[v]}({v}): {c}x")


# ════════════════════════════════════════════════════════════════════
# STEP 6: Does the key look like English?
# ════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("STEP 6: KEY AS ENGLISH TEXT")
print("=" * 80)

for name, vals, key_str in [("Beaufort", beau_vals, beau_str),
                              ("Vigenere", vig_vals, vig_str),
                              ("VBeau", vbeau_vals, vbeau_str)]:
    print(f"\n--- {name} key as text ---")
    # Full 24-char key
    print(f"  Full (24 chars): {key_str}")

    # ENE region (13 consecutive)
    ene_k = ''.join(N2L[v] for v in vals[:13])
    print(f"  ENE region (pos 21-33): {ene_k}")

    # BCL region (11 consecutive)
    bcl_k = ''.join(N2L[v] for v in vals[13:])
    print(f"  BCL region (pos 63-73): {bcl_k}")

    # Quadgram scores
    if QUADGRAMS:
        qg_ene = quadgram_score(ene_k)
        qg_bcl = quadgram_score(bcl_k)
        print(f"  ENE qg score: {qg_ene:.3f}" if qg_ene else "  ENE qg: N/A")
        print(f"  BCL qg score: {qg_bcl:.3f}" if qg_bcl else "  BCL qg: N/A")
        print(f"  (English text ~= -2.5 to -3.0, random ~= -4.5 to -5.0)")


# ════════════════════════════════════════════════════════════════════
# STEP 7: Running key search
# ════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("STEP 7: RUNNING KEY SEARCH (Model B specific)")
print("=" * 80)
print("\nUnder Model B, the key is a 97-letter text. Known key values:")
print(f"  Positions 21-33: {''.join(N2L[beau_key[p]] for p in ene_positions)} (Beau)")
print(f"  Positions 63-73: {''.join(N2L[beau_key[p]] for p in bcl_positions)} (Beau)")
print(f"  Gap: 30 positions between end of ENE (pos 33) and start of BCL (pos 63)")

# Load Carter text
carter_texts = []
for cpath in ["/home/cpatrick/kryptos/reference/carter_gutenberg.txt",
              "/home/cpatrick/kryptos/reference/carter_vol1.txt"]:
    if os.path.exists(cpath):
        with open(cpath, 'r', errors='ignore') as f:
            raw = f.read()
        # Sanitize: uppercase, remove non-alpha
        sanitized = ''.join(c for c in raw.upper() if 'A' <= c <= 'Z')
        carter_texts.append((os.path.basename(cpath), sanitized))

# Running key search function for ALL three variants
def running_key_search(key_positions, key_values, source_text, source_name, min_matches=5):
    """Search for offsets where source text matches key values at given positions."""
    source_nums = [I2N[c] for c in source_text]
    results = []

    # The key at position p = source_text[p + offset]
    # So source_nums[p + offset] should equal key_values[p] for crib positions p
    for offset in range(-len(source_text), 97 + len(source_text)):
        matches = 0
        total = 0
        for pos, kv in zip(key_positions, key_values):
            src_idx = pos + offset
            if 0 <= src_idx < len(source_nums):
                total += 1
                if source_nums[src_idx] == kv:
                    matches += 1
        if total >= 10 and matches >= min_matches:
            results.append((matches, total, offset))

    results.sort(key=lambda x: -x[0])
    return results[:5]

print(f"\n--- 7a. Running key search against Carter books ---")
for variant_name, key_dict in [("Beaufort", beau_key), ("Vigenere", vig_key), ("VBeau", vbeau_key)]:
    key_values = [key_dict[p] for p in CRIB_POSITIONS]
    for cname, ctext in carter_texts:
        hits = running_key_search(CRIB_POSITIONS, key_values, ctext, cname, min_matches=4)
        if hits:
            best = hits[0]
            print(f"  {variant_name} + {cname}: best {best[0]}/{best[1]} at offset {best[2]}")

print(f"\n--- 7b. Running key search against K1-K3 plaintext ---")
for variant_name, key_dict in [("Beaufort", beau_key), ("Vigenere", vig_key)]:
    key_values = [key_dict[p] for p in CRIB_POSITIONS]
    for name, text in [("K1", K1_PT), ("K2", K2_PT), ("K3", K3_PT), ("K1+K2+K3", K1_PT + K2_PT + K3_PT)]:
        hits = running_key_search(CRIB_POSITIONS, key_values, text, name, min_matches=3)
        if hits:
            best = hits[0]
            print(f"  {variant_name} + {name}: best {best[0]}/{best[1]} at offset {best[2]}")

print(f"\n--- 7c. Running key search: ENE region only (13 consecutive chars) ---")
ene_key_beau = [beau_key[p] for p in ene_positions]
for cname, ctext in carter_texts:
    # Search for the 13-char ENE key fragment anywhere in Carter
    ene_key_str = ''.join(N2L[v] for v in ene_key_beau)
    source_nums = [I2N[c] for c in ctext]
    best_m = 0
    best_pos = -1
    for start in range(len(source_nums) - 13):
        matches = sum(1 for i in range(13) if source_nums[start + i] == ene_key_beau[i])
        if matches > best_m:
            best_m = matches
            best_pos = start
    if best_m >= 5:
        # Show the matching region
        context = ctext[max(0, best_pos-5):best_pos+18]
        print(f"  ENE Beau key in {cname}: best {best_m}/13 at pos {best_pos}")
        print(f"    Context: ...{context}...")
        print(f"    Key:     {''.join(N2L[v] for v in ene_key_beau)}")
        print(f"    Source:  {ctext[best_pos:best_pos+13]}")

# 7d. Check if key is the KRYPTOS TABLEAU itself (read across rows or down columns)
print(f"\n--- 7d. Kryptos Tableau as running key ---")
# Build the tableau: 26 rows, each row is KA shifted by AZ key column
AZ_str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
# Tableau: row r = shift of KA by r positions (Vigenere style)
# Sanborn's tableau: key col = standard alphabet, body rows = KA shifted
tableau_rows = []
for r in range(26):
    row = ''.join(KA[(i + r) % 26] for i in range(26))
    tableau_rows.append(row)

# Read tableau in different ways and check as running key
# 1. Read across rows concatenated
tableau_text = ''.join(tableau_rows)
# 2. Read down columns
tableau_cols = ''
for c in range(26):
    for r in range(26):
        tableau_cols += tableau_rows[r][c]

for reading_name, text in [("rows", tableau_text), ("columns", tableau_cols)]:
    for variant_name, key_dict in [("Beaufort", beau_key), ("Vigenere", vig_key)]:
        key_values = [key_dict[p] for p in CRIB_POSITIONS]
        source_nums = [I2N[c] for c in text]
        best_m = 0
        best_off = 0
        for offset in range(-len(text), 100):
            matches = 0
            total = 0
            for pos in CRIB_POSITIONS:
                src_idx = pos + offset
                if 0 <= src_idx < len(source_nums):
                    total += 1
                    if source_nums[src_idx] == key_dict[pos]:
                        matches += 1
            if total >= 10 and matches > best_m:
                best_m = matches
                best_off = offset
        if best_m >= 4:
            print(f"  Tableau {reading_name} + {variant_name}: best {best_m}/24 at offset {best_off}")


# ════════════════════════════════════════════════════════════════════
# STEP 8: Tableau key derivation
# ════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("STEP 8: TABLEAU KEY DERIVATION")
print("=" * 80)

# For each row r of the tableau, check if reading positions 21-33 from that
# row matches the ENE key
print(f"\n--- 8a. Single tableau row as key source ---")
for r in range(26):
    row = tableau_rows[r]
    # The key would be row[pos % 26] at each crib position
    matches = 0
    for pos in CRIB_POSITIONS:
        row_val = KA_I2N[row[pos % 26]]  # Wait, this is KA-indexed
        # Actually tableau is just letters. Convert to AZ index.
        row_az_val = I2N[row[pos % 26]]
        if row_az_val == beau_key[pos]:
            matches += 1
    if matches >= 5:
        print(f"  Row {r:>2} ({AZ_str[r]}): {matches}/24 match (Beau)")

# Reading down a specific column at each position
print(f"\n--- 8b. Tableau column reading as key ---")
for c in range(26):
    # key[pos] = tableau[pos % 26][c]
    matches = 0
    for pos in CRIB_POSITIONS:
        tab_val = I2N[tableau_rows[pos % 26][c]]
        if tab_val == beau_key[pos]:
            matches += 1
    if matches >= 5:
        print(f"  Column {c:>2} ({AZ_str[c]}): {matches}/24 match (Beau)")


# ════════════════════════════════════════════════════════════════════
# STEP 9: d=13 anomaly exploitation under Model B
# ════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("STEP 9: d=13 ANOMALY EXPLOITATION (Model B)")
print("=" * 80)

print(f"\nENE crib: 13 chars at positions 21-33 cover ALL 13 residues mod 13 exactly once:")
for j, pos in enumerate(ene_positions):
    r = pos % 13
    print(f"  pos {pos}: residue {r} -> Beau key = {beau_key[pos]} ({N2L[beau_key[pos]]})")

print(f"\nBCL crib: 11 chars at positions 63-73 cover residues:")
bcl_residues = set()
for j, pos in enumerate(bcl_positions):
    r = pos % 13
    bcl_residues.add(r)
    print(f"  pos {pos}: residue {r} -> Beau key = {beau_key[pos]} ({N2L[beau_key[pos]]})")

missing_residues = set(range(13)) - bcl_residues
print(f"\nBCL covers residues: {sorted(bcl_residues)} ({len(bcl_residues)}/13)")
print(f"Missing residues: {sorted(missing_residues)}")

# For residues with both ENE and BCL values: do they match?
print(f"\n--- 9a. If key has period 13, ENE and BCL values at same residue MUST match ---")
n_match = 0
n_total = 0
conflicts = []
for j_bcl, pos_bcl in enumerate(bcl_positions):
    r = pos_bcl % 13
    # Find the ENE position with same residue
    for j_ene, pos_ene in enumerate(ene_positions):
        if pos_ene % 13 == r:
            n_total += 1
            ene_val = beau_key[pos_ene]
            bcl_val = beau_key[pos_bcl]
            match = (ene_val == bcl_val)
            if match:
                n_match += 1
            else:
                conflicts.append((r, pos_ene, ene_val, pos_bcl, bcl_val))
            status = "MATCH" if match else f"CONFLICT (delta={(ene_val-bcl_val)%26})"
            print(f"  residue {r:>2}: ENE[{pos_ene}]={N2L[ene_val]}({ene_val}), BCL[{pos_bcl}]={N2L[bcl_val]}({bcl_val}) -> {status}")
            break

print(f"\n  Period-13 consistency: {n_match}/{n_total} match")
if n_match == n_total:
    print(f"  *** PERIOD 13 IS FULLY CONSISTENT! ***")
    # Extract the period-13 key
    key13 = [None] * 13
    for pos in CRIB_POSITIONS:
        r = pos % 13
        key13[r] = beau_key[pos]
    print(f"  Period-13 key: {[N2L[v] if v is not None else '?' for v in key13]}")
    print(f"  Period-13 key string: {''.join(N2L[v] if v is not None else '?' for v in key13)}")

    # Decrypt ALL 97 with period-13 key
    pt_p13 = []
    for i in range(97):
        k = key13[i % 13]
        # Beaufort: PT = (K - CT) mod 26
        pt_val = (k - CT_NUMS[i]) % 26
        pt_p13.append(pt_val)
    pt_p13_str = ''.join(N2L[v] for v in pt_p13)
    print(f"\n  Decrypted PT (Beau period-13): {pt_p13_str}")

    # Verify cribs
    ene_check = pt_p13_str[21:34]
    bcl_check = pt_p13_str[63:74]
    print(f"  PT[21:34] = {ene_check} (expected: {ENE_TEXT}) -> {'MATCH' if ene_check == ENE_TEXT else 'FAIL'}")
    print(f"  PT[63:74] = {bcl_check} (expected: {BCL_TEXT}) -> {'MATCH' if bcl_check == BCL_TEXT else 'FAIL'}")

    # Quadgram quality
    qg = quadgram_score(pt_p13_str)
    if qg:
        print(f"  Quadgram score: {qg:.3f} per char")

    # IC
    pt_freq = Counter(pt_p13_str)
    ic_pt = sum(c*(c-1) for c in pt_freq.values()) / (97*96) if 97 > 1 else 0
    print(f"  PT IC: {ic_pt:.4f} (English=0.0667, random=0.0385)")

    # Does the key match any keyword?
    key13_str = ''.join(N2L[v] for v in key13)
    print(f"\n  --- Key identification ---")
    print(f"  Key: {key13_str}")
    for kw_name, kw_vals in KEYWORDS.items():
        if len(kw_vals) == 13:
            matches = sum(1 for i in range(13) if kw_vals[i] == key13[i])
            if matches >= 5:
                print(f"  vs {kw_name}: {matches}/13 match")

    # Check if key is a substring of K1-K3 PT
    for name, text in [("K1", K1_PT), ("K2", K2_PT), ("K3", K3_PT)]:
        if key13_str in text.upper():
            idx = text.upper().index(key13_str)
            print(f"  *** KEY FOUND IN {name} PT at position {idx}! ***")

    # Check key against KA alphabet
    ka_key = ''.join(KA[v] for v in key13)
    print(f"  Key in KA alphabet: {ka_key}")

elif n_match >= n_total - 2:
    print(f"  Near-period-13: {len(conflicts)} conflicts")
    for r, pe, ev, pb, bv in conflicts:
        delta = (ev - bv) % 26
        print(f"    residue {r}: delta = {delta} ({N2L[delta]})")

else:
    print(f"  Period 13 NOT consistent ({len(conflicts)} conflicts)")


# ════════════════════════════════════════════════════════════════════
# STEP 9b: Check ALL periods systematically for consistency
# ════════════════════════════════════════════════════════════════════
print(f"\n--- 9b. All consistent periods and their keys ---")
for p in range(1, 49):
    residue_map = {}
    conflicts = 0
    for pos in CRIB_POSITIONS:
        r = pos % p
        if r in residue_map:
            if residue_map[r] != beau_key[pos]:
                conflicts += 1
        else:
            residue_map[r] = beau_key[pos]

    if conflicts == 0:
        n_checks = sum(max(0, sum(1 for pos2 in CRIB_POSITIONS if pos2 % p == r) - 1) for r in residue_map)
        if n_checks >= 3:  # At least 3 pairwise constraints actually tested
            # Build the partial key
            key_p = ['?'] * p
            for r, v in residue_map.items():
                key_p[r] = N2L[v]
            key_str = ''.join(key_p)
            filled = sum(1 for c in key_str if c != '?')

            # Try to decrypt
            pt_chars = []
            for i in range(97):
                r = i % p
                if key_p[r] != '?':
                    k = I2N[key_p[r]]
                    pt_val = (k - CT_NUMS[i]) % 26
                    pt_chars.append(N2L[pt_val])
                else:
                    pt_chars.append('?')
            pt_str = ''.join(pt_chars)

            qg = None
            if QUADGRAMS and '?' not in pt_str:
                qg = quadgram_score(pt_str)

            print(f"  period {p:>2}: 0 conflicts, {n_checks} checks, key={key_str} ({filled}/{p} filled)"
                  + (f", qg={qg:.3f}" if qg else ""))


# ════════════════════════════════════════════════════════════════════
# STEP 10: Vigenere keystream analysis (same depth as Beaufort)
# ════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("STEP 10: VIGENERE d=13 CHECK")
print("=" * 80)

print(f"\n--- Vigenere period-13 consistency ---")
n_match_v = 0
n_total_v = 0
conflicts_v = []
for j_bcl, pos_bcl in enumerate(bcl_positions):
    r = pos_bcl % 13
    for j_ene, pos_ene in enumerate(ene_positions):
        if pos_ene % 13 == r:
            n_total_v += 1
            ene_val = vig_key[pos_ene]
            bcl_val = vig_key[pos_bcl]
            match = (ene_val == bcl_val)
            if match:
                n_match_v += 1
            else:
                conflicts_v.append((r, pos_ene, ene_val, pos_bcl, bcl_val))
            status = "MATCH" if match else f"CONFLICT"
            print(f"  residue {r:>2}: ENE[{pos_ene}]={N2L[ene_val]}({ene_val}), BCL[{pos_bcl}]={N2L[bcl_val]}({bcl_val}) -> {status}")
            break

print(f"\n  Period-13 consistency (Vig): {n_match_v}/{n_total_v}")

if n_match_v == n_total_v:
    # Extract and decrypt
    key13v = [None] * 13
    for pos in CRIB_POSITIONS:
        r = pos % 13
        key13v[r] = vig_key[pos]
    key13v_str = ''.join(N2L[v] if v is not None else '?' for v in key13v)
    print(f"  Period-13 Vig key: {key13v_str}")

    pt_v13 = []
    for i in range(97):
        k = key13v[i % 13]
        pt_val = (CT_NUMS[i] - k) % 26
        pt_v13.append(pt_val)
    pt_v13_str = ''.join(N2L[v] for v in pt_v13)
    print(f"  Decrypted PT (Vig period-13): {pt_v13_str}")

    ene_check = pt_v13_str[21:34]
    bcl_check = pt_v13_str[63:74]
    print(f"  PT[21:34] = {ene_check} (expected: {ENE_TEXT}) -> {'MATCH' if ene_check == ENE_TEXT else 'FAIL'}")
    print(f"  PT[63:74] = {bcl_check} (expected: {BCL_TEXT}) -> {'MATCH' if bcl_check == BCL_TEXT else 'FAIL'}")

    qg = quadgram_score(pt_v13_str)
    if qg:
        print(f"  Quadgram: {qg:.3f}")

    ic_pt = sum(c*(c-1) for c in Counter(pt_v13_str).values()) / (97*96)
    print(f"  PT IC: {ic_pt:.4f}")


# ════════════════════════════════════════════════════════════════════
# STEP 11: Bean constraint check under Model B
# ════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("STEP 11: BEAN CONSTRAINT CHECK (Model B)")
print("=" * 80)

# Bean EQ: k[27] = k[65]
# Positions 27 and 65 are BOTH crib positions
assert 27 in CRIB_DICT, "Position 27 should be a crib"
assert 65 in CRIB_DICT, "Position 65 should be a crib"

print(f"\n  Bean equality: k[27] = k[65]")
print(f"  CT[27] = {CT97[27]}, PT[27] = {CRIB_DICT[27][0]}")
print(f"  CT[65] = {CT97[65]}, PT[65] = {CRIB_DICT[65][0]}")

for name, key_dict in [("Beaufort", beau_key), ("Vigenere", vig_key), ("VBeau", vbeau_key)]:
    k27 = key_dict[27]
    k65 = key_dict[65]
    status = "SATISFIED" if k27 == k65 else f"VIOLATED (delta={(k27-k65)%26})"
    print(f"  {name}: k[27]={N2L[k27]}({k27}), k[65]={N2L[k65]}({k65}) -> {status}")

# Bean inequalities
from itertools import combinations
print(f"\n  Bean inequalities (should all hold):")
for name, key_dict in [("Beaufort", beau_key), ("Vigenere", vig_key), ("VBeau", vbeau_key)]:
    violations = 0
    total_ineq = 0
    for i, j in combinations(CRIB_POSITIONS, 2):
        if (i, j) == (27, 65) or (j, i) == (27, 65):
            continue  # Skip the equality pair
        # The inequality says k[i] != k[j] for variant-independent pairs
        # But we need to check if this is a VI inequality
        # A pair is VI inequality if the key values differ for ALL three variants
        ca, pa = CT_NUMS[i], CRIB_DICT[i][1]
        cb, pb = CT_NUMS[j], CRIB_DICT[j][1]
        vig_eq = (ca - pa) % 26 == (cb - pb) % 26
        beau_eq = (ca + pa) % 26 == (cb + pb) % 26
        vbeau_eq = (pa - ca) % 26 == (pb - cb) % 26
        if not vig_eq and not beau_eq and not vbeau_eq:
            total_ineq += 1
            if key_dict[i] == key_dict[j]:
                violations += 1
    print(f"  {name}: {violations} violations out of {total_ineq} VI inequalities")


# ════════════════════════════════════════════════════════════════════
# STEP 12: Keyword autokey under Model B (no transposition)
# ════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("STEP 12: AUTOKEY UNDER MODEL B (no transposition)")
print("=" * 80)

def beau_pt_autokey_decrypt(ct_nums, primer_nums):
    """Beaufort PT-autokey: K[i]=primer[i] if i<L, else K[i]=PT[i-L]. PT=(K-C)%26."""
    L = len(primer_nums)
    pt = []
    for i in range(len(ct_nums)):
        if i < L:
            k = primer_nums[i]
        else:
            k = pt[i - L]
        pt_val = (k - ct_nums[i]) % 26
        pt.append(pt_val)
    return pt

def vig_pt_autokey_decrypt(ct_nums, primer_nums):
    """Vigenere PT-autokey: K[i]=primer[i] if i<L, else K[i]=PT[i-L]. PT=(C-K)%26."""
    L = len(primer_nums)
    pt = []
    for i in range(len(ct_nums)):
        if i < L:
            k = primer_nums[i]
        else:
            k = pt[i - L]
        pt_val = (ct_nums[i] - k) % 26
        pt.append(pt_val)
    return pt

print(f"\n--- 12a. Known keyword autokeys on raw CT97 ---")
autokey_results = []
for kw_name, kw_vals in KEYWORDS.items():
    for cipher_name, decrypt_fn in [("beau_pt_autokey", beau_pt_autokey_decrypt),
                                      ("vig_pt_autokey", vig_pt_autokey_decrypt)]:
        for alph_name, alph_map in [("AZ", I2N), ("KA", KA_I2N)]:
            primer = [alph_map[c] for c in kw_name]
            pt = decrypt_fn(CT_NUMS, primer)

            # Score at crib positions
            ene_match = sum(1 for j in range(13) if pt[21+j] == ENE_NUMS[j])
            bcl_match = sum(1 for j in range(11) if pt[63+j] == BCL_NUMS[j])
            total = ene_match + bcl_match

            if total >= 8:
                pt_str = ''.join(N2L[v] for v in pt)
                qg = quadgram_score(pt_str)
                autokey_results.append((total, ene_match, bcl_match, kw_name, cipher_name, alph_name, pt_str, qg))

autokey_results.sort(reverse=True)
for total, ene_m, bcl_m, kw, ciph, alph, pt_str, qg in autokey_results[:20]:
    print(f"  {kw}:{alph}_{ciph}: {total}/24 (ene={ene_m}/13, bcl={bcl_m}/11)"
          + (f" qg={qg:.3f}" if qg else ""))
    if total >= 12:
        print(f"    PT: {pt_str}")

if not autokey_results:
    print(f"  No keyword autokey scored >= 8/24")


# ════════════════════════════════════════════════════════════════════
# STEP 13: Self-encrypting positions analysis
# ════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("STEP 13: SELF-ENCRYPTING POSITIONS")
print("=" * 80)

# CT[32] = PT[32] = S, CT[73] = PT[73] = K
# Under Model B, at self-encrypting positions, key[i] is special
for pos, letter in [(32, 'S'), (73, 'K')]:
    ct_val = I2N[letter]
    pt_val = I2N[letter]
    bk = (ct_val + pt_val) % 26
    vk = (ct_val - pt_val) % 26
    vbk = (pt_val - ct_val) % 26
    print(f"\n  Self-encrypting pos {pos}: CT=PT={letter}({ct_val})")
    print(f"    Beaufort key: ({ct_val}+{ct_val})%26 = {bk} ({N2L[bk]})")
    print(f"    Vigenere key: ({ct_val}-{ct_val})%26 = {vk} ({N2L[vk]}) = ALWAYS A")
    print(f"    VBeau key:    ({ct_val}-{ct_val})%26 = {vbk} ({N2L[vbk]}) = ALWAYS A")

    # Under Vigenere, self-encrypting always gives key=A(0)
    # Under Beaufort, gives key = 2*ct_val mod 26
    print(f"    NOTE: Under Vigenere, self-encrypting => key=A always")
    print(f"    Under Beaufort: key = 2*{ct_val} mod 26 = {bk}")


# ════════════════════════════════════════════════════════════════════
# STEP 14: Model B decryption with all consistent period keys
# ════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("STEP 14: MODEL B DECRYPTION ATTEMPTS")
print("=" * 80)

# Try every Beaufort-consistent period
best_decryptions = []
for p in range(1, 49):
    residue_map = {}
    conflicts = 0
    for pos in CRIB_POSITIONS:
        r = pos % p
        if r in residue_map:
            if residue_map[r] != beau_key[pos]:
                conflicts += 1
        else:
            residue_map[r] = beau_key[pos]

    if conflicts == 0 and len(residue_map) == p:  # All residues filled
        # Full key available - decrypt
        key_p = [residue_map[r] for r in range(p)]
        pt_chars = []
        for i in range(97):
            k = key_p[i % p]
            pt_val = (k - CT_NUMS[i]) % 26
            pt_chars.append(N2L[pt_val])
        pt_str = ''.join(pt_chars)

        # Score
        qg = quadgram_score(pt_str)
        ic_pt = sum(c*(c-1) for c in Counter(pt_str).values()) / (97*96)

        # Verify cribs
        ene_ok = pt_str[21:34] == ENE_TEXT
        bcl_ok = pt_str[63:74] == BCL_TEXT

        key_str = ''.join(N2L[v] for v in key_p)
        best_decryptions.append((p, key_str, pt_str, qg, ic_pt, ene_ok, bcl_ok))

for p, key_str, pt_str, qg, ic, ene_ok, bcl_ok in sorted(best_decryptions, key=lambda x: x[3] or -999, reverse=True):
    print(f"\n  Period {p}: key={key_str}")
    print(f"    PT: {pt_str}")
    print(f"    QG: {qg:.3f}" if qg else "    QG: N/A")
    print(f"    IC: {ic:.4f}")
    print(f"    ENE crib: {'MATCH' if ene_ok else 'FAIL'}, BCL crib: {'MATCH' if bcl_ok else 'FAIL'}")

    # Check if PT looks English
    if qg and qg > -4.0:
        print(f"    *** POSSIBLE ENGLISH (qg > -4.0) ***")

# Also try Vigenere
print(f"\n--- Vigenere period decryptions ---")
for p in range(1, 49):
    residue_map = {}
    conflicts = 0
    for pos in CRIB_POSITIONS:
        r = pos % p
        if r in residue_map:
            if residue_map[r] != vig_key[pos]:
                conflicts += 1
        else:
            residue_map[r] = vig_key[pos]

    if conflicts == 0 and len(residue_map) == p:
        key_p = [residue_map[r] for r in range(p)]
        pt_chars = []
        for i in range(97):
            k = key_p[i % p]
            pt_val = (CT_NUMS[i] - k) % 26
            pt_chars.append(N2L[pt_val])
        pt_str = ''.join(pt_chars)

        qg = quadgram_score(pt_str)
        ic_pt = sum(c*(c-1) for c in Counter(pt_str).values()) / (97*96)
        ene_ok = pt_str[21:34] == ENE_TEXT
        bcl_ok = pt_str[63:74] == BCL_TEXT
        key_str = ''.join(N2L[v] for v in key_p)

        if qg and qg > -5.0:
            print(f"  Period {p}: key={key_str}, QG={qg:.3f}, IC={ic_pt:.4f}")
            print(f"    PT: {pt_str}")


# ════════════════════════════════════════════════════════════════════
# STEP 15: Summary of all findings
# ════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("SUMMARY OF FINDINGS")
print("=" * 80)

print(f"\nModel B: Cipher on all 97 chars, no null extraction, no transposition")
print(f"\n1. Raw keystream values (Beaufort):")
print(f"   ENE region (pos 21-33): {ene_beau} -> {''.join(N2L[v] for v in ene_beau)}")
print(f"   BCL region (pos 63-73): {bcl_beau} -> {''.join(N2L[v] for v in bcl_beau)}")
print(f"   Full: {beau_str}")

print(f"\n2. Keystream IC (Beaufort): ", end='')
freq = Counter(beau_vals)
ic = sum(c*(c-1) for c in freq.values()) / (24*23) if 24 > 1 else 0
print(f"{ic:.4f} ({ic/(1/26):.2f}x random)")

print(f"\n3. Period consistency (Beaufort):")
for p in range(1, 49):
    residue_map = {}
    conflicts = 0
    for pos in CRIB_POSITIONS:
        r = pos % p
        if r in residue_map:
            if residue_map[r] != beau_key[pos]:
                conflicts += 1
        else:
            residue_map[r] = beau_key[pos]
    if conflicts == 0:
        n_checks = sum(max(0, sum(1 for pos2 in CRIB_POSITIONS if pos2 % p == r) - 1) for r in residue_map)
        if n_checks >= 3:
            print(f"   Period {p}: CONSISTENT ({n_checks} checks)")

print(f"\n4. Bean EQ k[27]=k[65]:")
for name, kd in [("Beau", beau_key), ("Vig", vig_key)]:
    eq = kd[27] == kd[65]
    print(f"   {name}: {N2L[kd[27]]}={N2L[kd[65]]} -> {'PASS' if eq else 'FAIL'}")

print(f"\n5. Self-encrypting: pos 32 (S), pos 73 (K)")
print(f"   Beaufort: k[32]={N2L[beau_key[32]]}({beau_key[32]}), k[73]={N2L[beau_key[73]]}({beau_key[73]})")
print(f"   Vigenere: k[32]=A(0) always, k[73]=A(0) always")

# Save results
results = {
    'experiment': 'MODEL-B-DEEP-INVESTIGATION',
    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
    'model': 'Model B: cipher on all 97, no null extraction, no transposition',
    'beaufort_keystream': {
        'positions': CRIB_POSITIONS,
        'values': beau_vals,
        'letters': beau_str,
        'ene_region': {'positions': ene_positions, 'values': ene_beau, 'letters': ''.join(N2L[v] for v in ene_beau)},
        'bcl_region': {'positions': bcl_positions, 'values': bcl_beau, 'letters': ''.join(N2L[v] for v in bcl_beau)},
    },
    'vigenere_keystream': {
        'positions': CRIB_POSITIONS,
        'values': vig_vals,
        'letters': vig_str,
    },
    'ic_beaufort': ic,
    'bean_eq': {
        'beaufort': beau_key[27] == beau_key[65],
        'vigenere': vig_key[27] == vig_key[65],
    },
    'period_13_beaufort': {
        'consistent': all(beau_key[ene_positions[j]] == beau_key[bcl_positions[i]]
                          for i, pos_bcl in enumerate(bcl_positions)
                          for j, pos_ene in enumerate(ene_positions)
                          if pos_ene % 13 == pos_bcl % 13),
        'ene_bcl_matches': n_match,
        'ene_bcl_total': n_total,
    },
    'self_encrypting': {
        'pos_32': {'beau_key': beau_key[32], 'vig_key': vig_key[32]},
        'pos_73': {'beau_key': beau_key[73], 'vig_key': vig_key[73]},
    },
}

os.makedirs("/home/cpatrick/kryptos/results", exist_ok=True)
outpath = "/home/cpatrick/kryptos/results/model_b_deep_investigation.json"
with open(outpath, 'w') as f:
    json.dump(results, f, indent=2, default=str)

print(f"\nArtifact: {outpath}")
print(f"Repro: PYTHONPATH=src python3 -u scripts/analysis/e_model_b_deep_investigation.py")
