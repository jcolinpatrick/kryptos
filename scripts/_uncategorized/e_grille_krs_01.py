#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-GRILLE-KRS-01: Test KRS Cardan grille hypothesis.

If the Cardan grille selects all K, R, S positions on the cipher panel (97 holes),
what do we read from the Vigenère tableau at those same (row, col) positions?

Tests:
1. Read tableau chars at K/R/S positions → score for English-like properties
2. Monte Carlo: compare against 1000 random 97-position selections
3. Also test PRS, and the KOT|PRS split model
4. Try decrypting the extracted text with known keywords
"""

import random
import math
from collections import Counter

# === CONSTANTS ===

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
K4_CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

# Full cipher panel (869 chars with 4 ?'s, one squeezed)
CIPHER_PANEL_RAW = (
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ"
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE"
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA"
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI"
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX"
    "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ"
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP"
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI"
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAE"
    "WMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR"
    "EIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI"
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT"
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR"
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO"
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP"
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
)

# Remove the squeezed ? (3rd one, in GGTEZ?FKZ)
# Find and remove just that specific one
def build_cipher_panel():
    """Build 868-char cipher panel by removing squeezed ?."""
    raw = CIPHER_PANEL_RAW
    # The 3rd ? is in "FLGGTEZ?FKZ" — find its position
    q_count = 0
    result = []
    for ch in raw:
        if ch == '?':
            q_count += 1
            if q_count == 3:
                continue  # skip the squeezed one
        result.append(ch)
    panel = ''.join(result)
    assert len(panel) == 868, f"Panel length {len(panel)}, expected 868"
    return panel

CIPHER_PANEL = build_cipher_panel()

# Kryptos Vigenère tableau (28 rows x 31 cols)
KRYPTOS_TABLEAU = [
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",
    "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",
    "BRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",
    "CYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",
    "DPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",
    "ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA",
    "FOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",
    "GSABCDEFGHIJLMNQUVWXZKRYPTOSABC",
    "HABCDEFGHIJLMNQUVWXZKRYPTOSABCD",
    "IBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",
    "JCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",
    "KDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",
    "LEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",
    "MFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",  # Row N: 32 chars (extra L)
    "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",
    "PIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",
    "QJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",
    "RLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",
    "SMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",
    "TNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",
    "UQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",
    "VUVWXZKRYPTOSABCDEFGHIJLMNQUVWX",
    "WVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",
    "XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",
    "YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",
]

def build_tableau_grid():
    """Build 28x31 tableau grid. Row N (index 14) has extra L — truncate to 31."""
    grid = []
    for row_str in KRYPTOS_TABLEAU:
        # Pad or truncate to exactly 31 chars
        row = row_str[:31]
        if len(row) < 31:
            row = row + ' ' * (31 - len(row))
        grid.append(row)
    assert len(grid) == 28
    return grid

TABLEAU_GRID = build_tableau_grid()

# Wrap cipher panel into 28x31 grid
def build_cipher_grid():
    """Wrap 868-char cipher panel into 28 rows of 31 columns."""
    grid = []
    for i in range(28):
        row = CIPHER_PANEL[i*31:(i+1)*31]
        grid.append(row)
    assert len(grid) == 28
    assert all(len(r) == 31 for r in grid), [len(r) for r in grid]
    return grid

CIPHER_GRID = build_cipher_grid()

# === IC CALCULATION ===

def ic(text):
    """Index of coincidence."""
    text = ''.join(c for c in text.upper() if c.isalpha())
    n = len(text)
    if n < 2:
        return 0.0
    freq = Counter(text)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

# === BIGRAM SCORE ===

# English bigram log-frequencies (simplified top bigrams)
COMMON_BIGRAMS = {
    'TH': 3.56, 'HE': 3.07, 'IN': 2.43, 'ER': 2.05, 'AN': 1.99,
    'RE': 1.85, 'ON': 1.76, 'AT': 1.49, 'EN': 1.45, 'ND': 1.35,
    'TI': 1.34, 'ES': 1.34, 'OR': 1.28, 'TE': 1.27, 'OF': 1.17,
    'ED': 1.17, 'IS': 1.13, 'IT': 1.12, 'AL': 1.09, 'AR': 1.07,
    'ST': 1.05, 'TO': 1.05, 'NT': 1.04, 'NG': 0.95, 'SE': 0.93,
    'HA': 0.93, 'AS': 0.87, 'OU': 0.87, 'IO': 0.83, 'LE': 0.83,
}

def bigram_score(text):
    """Count how many common English bigrams appear."""
    text = ''.join(c for c in text.upper() if c.isalpha())
    count = 0
    for i in range(len(text) - 1):
        bg = text[i:i+2]
        if bg in COMMON_BIGRAMS:
            count += 1
    return count

# === VIGENERE DECRYPT ===

def vig_decrypt(ct, key, alphabet=AZ):
    """Decrypt ciphertext with Vigenère using given alphabet."""
    pt = []
    for i, c in enumerate(ct):
        if not c.isalpha():
            pt.append(c)
            continue
        c_idx = alphabet.index(c) if c in alphabet else ord(c) - 65
        k_idx = alphabet.index(key[i % len(key)]) if key[i % len(key)] in alphabet else ord(key[i % len(key)]) - 65
        p_idx = (c_idx - k_idx) % len(alphabet)
        pt.append(alphabet[p_idx])
    return ''.join(pt)

def beaufort_decrypt(ct, key, alphabet=AZ):
    """Decrypt ciphertext with Beaufort using given alphabet."""
    pt = []
    for i, c in enumerate(ct):
        if not c.isalpha():
            pt.append(c)
            continue
        c_idx = alphabet.index(c) if c in alphabet else ord(c) - 65
        k_idx = alphabet.index(key[i % len(key)]) if key[i % len(key)] in alphabet else ord(key[i % len(key)]) - 65
        p_idx = (k_idx - c_idx) % len(alphabet)
        pt.append(alphabet[p_idx])
    return ''.join(pt)

# === FIND LETTER POSITIONS ===

def find_letter_positions(grid, letters):
    """Find all (row, col) positions where grid contains any of the given letters."""
    positions = []
    for r in range(len(grid)):
        for c in range(len(grid[r])):
            if grid[r][c] in letters:
                positions.append((r, c))
    return positions

# === EXTRACT FROM GRID ===

def extract_at_positions(grid, positions):
    """Read characters from grid at given positions."""
    chars = []
    for r, c in positions:
        if r < len(grid) and c < len(grid[r]):
            chars.append(grid[r][c])
        else:
            chars.append('?')
    return ''.join(chars)

# === MONTE CARLO ===

def random_positions(n, rows=28, cols=31):
    """Generate n random (row, col) positions."""
    all_pos = [(r, c) for r in range(rows) for c in range(cols)]
    return random.sample(all_pos, min(n, len(all_pos)))

# ================================================================
# MAIN EXPERIMENT
# ================================================================

print("=" * 75)
print("E-GRILLE-KRS-01: KRS Cardan Grille Hypothesis Test")
print("=" * 75)

# Part 1: Find K, R, S positions on cipher panel
print("\n--- PART 1: Locate K/R/S positions on 28x31 cipher grid ---")

for letter_set_name, letter_set in [
    ("KRS", set("KRS")),
    ("PRS", set("PRS")),
]:
    positions = find_letter_positions(CIPHER_GRID, letter_set)
    print(f"\n{letter_set_name}: {len(positions)} positions found")

    # Distribution by row
    row_counts = Counter(r for r, c in positions)
    print(f"  By row (upper/lower split at row 14):")
    upper = sum(row_counts.get(r, 0) for r in range(14))
    lower = sum(row_counts.get(r, 0) for r in range(14, 28))
    print(f"    Upper 14 rows: {upper}, Lower 14 rows: {lower}")

    # Extract from tableau
    tableau_text = extract_at_positions(TABLEAU_GRID, positions)
    tableau_alpha = ''.join(c for c in tableau_text if c.isalpha())
    print(f"  Tableau extraction ({len(tableau_alpha)} alpha chars): {tableau_alpha[:60]}...")
    print(f"  IC: {ic(tableau_alpha):.4f}")
    print(f"  Common bigrams: {bigram_score(tableau_alpha)}")
    print(f"  Letter distribution: {dict(sorted(Counter(tableau_alpha).items()))}")

    # Extract from cipher panel itself (should be all K/R/S)
    cipher_text = extract_at_positions(CIPHER_GRID, positions)
    print(f"  Cipher panel extraction: {cipher_text[:60]}...")
    print(f"  Unique letters in cipher extraction: {sorted(set(cipher_text))}")

    # Try decrypting tableau extraction with known keywords
    print(f"\n  --- Decryption attempts on tableau extraction ---")
    keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SANBORN", "BERLIN", "SHADOW"]
    for kw in keywords:
        for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
            try:
                vig_pt = vig_decrypt(tableau_alpha, kw, alph)
                beau_pt = beaufort_decrypt(tableau_alpha, kw, alph)
                vig_ic = ic(vig_pt)
                beau_ic = ic(beau_pt)
                vig_bg = bigram_score(vig_pt)
                beau_bg = bigram_score(beau_pt)
                if vig_ic > 0.050 or vig_bg > 15 or beau_ic > 0.050 or beau_bg > 15:
                    print(f"    *** SIGNAL: key={kw}, alph={alph_name}")
                    print(f"      Vig:  IC={vig_ic:.4f}, bigrams={vig_bg}, PT={vig_pt[:50]}...")
                    print(f"      Beau: IC={beau_ic:.4f}, bigrams={beau_bg}, PT={beau_pt[:50]}...")
            except (ValueError, IndexError):
                pass

    # Always print a few decryption results
    for kw in ["KRYPTOS", "PALIMPSEST"]:
        for alph_name, alph in [("KA", KA)]:
            vig_pt = vig_decrypt(tableau_alpha, kw, alph)
            beau_pt = beaufort_decrypt(tableau_alpha, kw, alph)
            print(f"    key={kw}/{alph_name}: Vig IC={ic(vig_pt):.4f} bg={bigram_score(vig_pt)} PT={vig_pt[:50]}")
            print(f"    key={kw}/{alph_name}: Beau IC={ic(beau_pt):.4f} bg={bigram_score(beau_pt)} PT={beau_pt[:50]}")

# Part 2: KOT|PRS split model
print("\n\n--- PART 2: Split Model — Upper(KOT) + Lower(PRS) ---")

upper_positions = find_letter_positions(CIPHER_GRID, set("KOT"))
upper_positions = [(r, c) for r, c in upper_positions if r < 14]

lower_positions = find_letter_positions(CIPHER_GRID, set("PRS"))
lower_positions = [(r, c) for r, c in lower_positions if r >= 14]

combined = upper_positions + lower_positions
print(f"Upper KOT: {len(upper_positions)}, Lower PRS: {len(lower_positions)}, Total: {len(combined)}")

if len(combined) > 0:
    tableau_text_split = extract_at_positions(TABLEAU_GRID, combined)
    tableau_alpha_split = ''.join(c for c in tableau_text_split if c.isalpha())
    print(f"Tableau extraction ({len(tableau_alpha_split)} chars): {tableau_alpha_split[:60]}...")
    print(f"IC: {ic(tableau_alpha_split):.4f}")
    print(f"Common bigrams: {bigram_score(tableau_alpha_split)}")

# Also try the reverse: Upper(PRS) + Lower(KOT)
print("\n--- Split Model — Upper(PRS) + Lower(KOT) ---")
upper_positions2 = find_letter_positions(CIPHER_GRID, set("PRS"))
upper_positions2 = [(r, c) for r, c in upper_positions2 if r < 14]
lower_positions2 = find_letter_positions(CIPHER_GRID, set("KOT"))
lower_positions2 = [(r, c) for r, c in lower_positions2 if r >= 14]
combined2 = upper_positions2 + lower_positions2
print(f"Upper PRS: {len(upper_positions2)}, Lower KOT: {len(lower_positions2)}, Total: {len(combined2)}")

# Part 3: Monte Carlo null distribution
print("\n\n--- PART 3: Monte Carlo Null Distribution (1000 trials) ---")

random.seed(42)
n_trials = 1000
mc_ics = []
mc_bigrams = []

for _ in range(n_trials):
    rand_pos = random_positions(97)
    rand_text = extract_at_positions(TABLEAU_GRID, rand_pos)
    rand_alpha = ''.join(c for c in rand_text if c.isalpha())
    if len(rand_alpha) >= 10:
        mc_ics.append(ic(rand_alpha))
        mc_bigrams.append(bigram_score(rand_alpha))

mc_ics.sort()
mc_bigrams.sort()

# KRS stats
krs_pos = find_letter_positions(CIPHER_GRID, set("KRS"))
krs_text = extract_at_positions(TABLEAU_GRID, krs_pos)
krs_alpha = ''.join(c for c in krs_text if c.isalpha())
krs_ic = ic(krs_alpha)
krs_bg = bigram_score(krs_alpha)

print(f"KRS extraction: IC={krs_ic:.4f}, bigrams={krs_bg}")
print(f"Monte Carlo IC:  mean={sum(mc_ics)/len(mc_ics):.4f}, "
      f"median={mc_ics[len(mc_ics)//2]:.4f}, "
      f"95th={mc_ics[int(0.95*len(mc_ics))]:.4f}, "
      f"99th={mc_ics[int(0.99*len(mc_ics))]:.4f}")
print(f"Monte Carlo bg:  mean={sum(mc_bigrams)/len(mc_bigrams):.1f}, "
      f"median={mc_bigrams[len(mc_bigrams)//2]}, "
      f"95th={mc_bigrams[int(0.95*len(mc_bigrams))]}, "
      f"99th={mc_bigrams[int(0.99*len(mc_bigrams))]}")

# Percentile rank
ic_rank = sum(1 for x in mc_ics if x <= krs_ic) / len(mc_ics)
bg_rank = sum(1 for x in mc_bigrams if x <= krs_bg) / len(mc_bigrams)
print(f"KRS IC percentile: {ic_rank*100:.1f}%")
print(f"KRS bigram percentile: {bg_rank*100:.1f}%")

if krs_ic > mc_ics[int(0.99*len(mc_ics))]:
    print("*** KRS IC exceeds 99th percentile — STATISTICALLY SIGNIFICANT")
elif krs_ic > mc_ics[int(0.95*len(mc_ics))]:
    print("** KRS IC exceeds 95th percentile — marginally significant")
else:
    print("KRS IC is within normal range — not significant")

# Part 4: Does KRS reading order match K4?
print("\n\n--- PART 4: KRS as Reading Order for K4 ---")
print("If K/R/S positions define the reading order for K4's 97 characters...")

# Read K4 chars from the cipher grid at K4's actual positions (rows 24-27)
k4_start = 24 * 31 + 27  # K4 starts at row 24, col 27 (after the ? at col 26)
# Actually, let's find K4 in the panel
k4_idx = CIPHER_PANEL.find('OBKR')
print(f"K4 starts at panel index {k4_idx} (row {k4_idx//31}, col {k4_idx%31})")

# The KRS positions, sorted reading order (top-to-bottom, left-to-right)
krs_pos_sorted = sorted(krs_pos, key=lambda p: (p[0], p[1]))

# If we map KRS position i → K4 character i, what permutation does that define?
if len(krs_pos_sorted) == 97:
    # Build the permuted K4: position i in the output gets K4[i]
    # This tests: "the i-th K/R/S position (reading order) corresponds to K4[i]"
    print(f"97 KRS positions (matches K4 length) — testing as reading order")

    # Place K4 chars at KRS positions
    k4_placed = list(CIPHER_PANEL)
    for i, (r, c) in enumerate(krs_pos_sorted):
        k4_placed[r * 31 + c] = K4_CT[i]

    # Read back just the K4 region
    # But more interestingly: the KRS positions define a permutation
    # If we READ the cipher panel at KRS positions, do we get K4?
    cipher_at_krs = extract_at_positions(CIPHER_GRID, krs_pos_sorted)
    print(f"Cipher panel at KRS positions: {cipher_at_krs}")
    print(f"K4 ciphertext:                 {K4_CT}")
    if cipher_at_krs == K4_CT:
        print("*** EXACT MATCH! KRS positions read K4 in order! ***")
    else:
        matches = sum(1 for a, b in zip(cipher_at_krs, K4_CT) if a == b)
        print(f"Character matches: {matches}/97")
        # Check if it's the same multiset
        if sorted(cipher_at_krs) == sorted(K4_CT):
            print("Same letter multiset — could be a different reading order!")
        else:
            print(f"Different multisets — cipher at KRS has letters not in K4")
else:
    print(f"WARNING: {len(krs_pos_sorted)} KRS positions (expected 97)")

print("\n\n--- EXPERIMENT COMPLETE ---")
print("Artifacts: stdout only (no file output)")
