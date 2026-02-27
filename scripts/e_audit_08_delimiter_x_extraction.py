#!/usr/bin/env python3
"""
E-AUDIT-08: X-Delimiter Extraction Experiment

Hypothesis: The X characters used as delimiters (sentence boundaries) in K1-K3
plaintext are structurally meaningful. They encrypt to specific CT letters that
may form a secondary message, or their removal from the CT stream reveals a
new cipher structure.

Key observations:
  - ? marks appear as LITERAL punctuation in CT (not enciphered)
  - X-as-period IS enciphered (goes through the Vigenère cipher)
  - Apostrophes are simply OMITTED (HOW'S -> HOWS)
  - K2 has 5 delimiter X (corrected) / 4 (original sculpture) + 2 content X
  - K3 has 1 delimiter X (before "CAN YOU SEE ANYTHING")
  - K1 has 0 delimiter X (single sentence, no periods needed)
  - This is INCONSISTENT if X is just formatting - it must serve a purpose

  Physical anomaly (Antipodes):
  - Row 22 has a SKINNY ? that doesn't consume a character space
  - Same row has W.W. with DOTS (unique to Antipodes)
  - Sanborn distorted the ? to fit the dots — dots were more important

Approach:
  1. Map all delimiter X positions in K2 CT (the only section with reliable alignment)
  2. Extract the CT letters at those positions
  3. Remove them from the CT stream and re-decrypt with various keys
  4. Check if the extracted letters or the residual stream reveal anything
  5. Cross-reference with K4 CT X positions (pos 6 and 79)

Uses only the ORIGINAL SCULPTURE CT (369 letters, pre-2006 correction).
"""

import sys
import os
import json
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT as K4_CT

# ═══════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KEY_ABSCISSA = "ABSCISSA"
KEY_KRYPTOS = "KRYPTOS"
KEY_PALIMPSEST = "PALIMPSEST"

K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"

# K2 SCULPTURE CT — the 369 cipher letters as they appear on Kryptos
# (WITHOUT question marks, WITHOUT the 2006 correction)
K2_CT_SCULPTURE = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)

# K2 PLAINTEXT — the CORRECTED intended plaintext (370 chars)
K2_PT_CORRECTED = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELD"
    "XTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATION"
    "XDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWS"
    "THEEXACTLOCATIONONLYWWTHISISHISTLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTY"
    "SEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTES"
    "FORTYFOURSECONDSWESTXLAYERTWO"
)

# K3 CT (336 chars)
K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)

# Full sculpture with ? marks (for position reference)
FULL_SCULPTURE = (
    K1_CT
    + "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKK?DQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVH?DWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
    + K3_CT
    + "?"
    + K4_CT
)


# ═══════════════════════════════════════════════════════════════════════
# Cipher functions
# ═══════════════════════════════════════════════════════════════════════

def ka_encrypt(pt, key):
    return KA[(KA.index(pt) + KA.index(key)) % 26]

def ka_decrypt(ct, key):
    return KA[(KA.index(ct) - KA.index(key)) % 26]

def decrypt_stream(ct_str, key_str, alphabet=KA):
    """Decrypt a CT stream with a repeating key."""
    pt = ""
    for i, c in enumerate(ct_str):
        k = key_str[i % len(key_str)]
        p_idx = (alphabet.index(c) - alphabet.index(k)) % 26
        pt += alphabet[p_idx]
    return pt

def encrypt_stream(pt_str, key_str, alphabet=KA):
    """Encrypt a PT stream with a repeating key."""
    ct = ""
    for i, c in enumerate(pt_str):
        k = key_str[i % len(key_str)]
        c_idx = (alphabet.index(c) + alphabet.index(k)) % 26
        ct += alphabet[c_idx]
    return ct


# ═══════════════════════════════════════════════════════════════════════
# Step 1: Decrypt original sculpture K2 CT and locate all X
# ═══════════════════════════════════════════════════════════════════════

print("=" * 70)
print("E-AUDIT-08: X-DELIMITER EXTRACTION EXPERIMENT")
print("=" * 70)
print()

# Decrypt the original sculpture K2 CT with ABSCISSA
k2_decrypted = decrypt_stream(K2_CT_SCULPTURE, KEY_ABSCISSA)
assert len(k2_decrypted) == 369

print(f"K2 CT (sculpture, no ?, no correction): {len(K2_CT_SCULPTURE)} chars")
print(f"Decrypted: {len(k2_decrypted)} chars")
print()

# The decryption of the original sculpture ends with IDBYROWS (not XLAYERTWO)
print(f"Tail: ...{k2_decrypted[-25:]}")
print()

# Find all X in the decrypted plaintext
all_x_positions = [i for i, c in enumerate(k2_decrypted) if c == 'X']
print(f"All X positions in decrypted K2: {all_x_positions}")
print()

# Classify each X
delimiter_x = []
content_x = []

for pos in all_x_positions:
    before = k2_decrypted[max(0, pos - 12):pos]
    after = k2_decrypted[pos + 1:min(len(k2_decrypted), pos + 13)]
    ct_letter = K2_CT_SCULPTURE[pos]
    key_letter = KEY_ABSCISSA[pos % 8]

    # Check if part of EXACT or SIX
    is_content = False
    # EXACT: X is at index 1 of the word
    exact_start = k2_decrypted.find("EXACT")
    if exact_start >= 0 and exact_start + 1 == pos:
        is_content = "EXACT"
    # SIX: X is at index 2 of the word
    six_start = k2_decrypted.find("SIX")
    if six_start >= 0 and six_start + 2 == pos:
        is_content = "SIX"

    role = f"CONTENT ({is_content})" if is_content else "DELIMITER"
    if is_content:
        content_x.append((pos, ct_letter, key_letter, is_content))
    else:
        delimiter_x.append((pos, ct_letter, key_letter))

    print(f"  [{pos:3d}] CT={ct_letter}  KEY={key_letter}  {role:18s}  ...{before}[X]{after}...")

print()
print(f"DELIMITER X: {len(delimiter_x)} positions: {[p for p, _, _ in delimiter_x]}")
print(f"CONTENT X:   {len(content_x)} positions: {[p for p, _, _, _ in content_x]}")

# ═══════════════════════════════════════════════════════════════════════
# Step 2: Extract delimiter CT letters
# ═══════════════════════════════════════════════════════════════════════

print()
print("=" * 70)
print("STEP 2: EXTRACTED DELIMITER CT LETTERS")
print("=" * 70)
print()

extracted_ct = "".join(ct for _, ct, _ in delimiter_x)
extracted_keys = "".join(k for _, _, k in delimiter_x)
print(f"Extracted CT letters: {extracted_ct}")
print(f"Key at those positions: {extracted_keys}")
print(f"KA-index values: {[KA.index(ct) for _, ct, _ in delimiter_x]}")
print()

# Try decrypting the extracted letters with various keys
print("Decrypted with various keys:")
for key_name, key in [("ABSCISSA (orig positions)", None),
                       ("ABSCISSA (contiguous)", KEY_ABSCISSA),
                       ("KRYPTOS (contiguous)", KEY_KRYPTOS),
                       ("PALIMPSEST (contiguous)", KEY_PALIMPSEST),
                       ("A (identity)", "A")]:
    if key is None:
        # Use original position keys
        result = "".join(ka_decrypt(ct, k) for _, ct, k in delimiter_x)
    else:
        result = "".join(ka_decrypt(ct, key[i % len(key)])
                         for i, (_, ct, _) in enumerate(delimiter_x))
    print(f"  {key_name:35s} -> {result}")

# Beaufort variant
print("\nBeaufort variants:")
for key_name, key in [("ABSCISSA (contiguous)", KEY_ABSCISSA),
                       ("KRYPTOS (contiguous)", KEY_KRYPTOS)]:
    result = "".join(KA[(KA.index(key[i % len(key)]) - KA.index(ct)) % 26]
                     for i, (_, ct, _) in enumerate(delimiter_x))
    print(f"  Beaufort {key_name:28s} -> {result}")

# ═══════════════════════════════════════════════════════════════════════
# Step 3: Remove delimiter CT letters and re-decrypt
# ═══════════════════════════════════════════════════════════════════════

print()
print("=" * 70)
print("STEP 3: CT STREAM WITH DELIMITERS REMOVED")
print("=" * 70)
print()

delim_pos_set = set(p for p, _, _ in delimiter_x)
residual_ct = "".join(c for i, c in enumerate(K2_CT_SCULPTURE) if i not in delim_pos_set)
print(f"Original CT: {len(K2_CT_SCULPTURE)} chars")
print(f"Residual CT: {len(residual_ct)} chars (removed {len(delimiter_x)})")
print()

# Option A: decrypt residual with ABSCISSA, preserving original key positions
pt_preserve_keys = ""
for i, c in enumerate(K2_CT_SCULPTURE):
    if i in delim_pos_set:
        continue
    pt_preserve_keys += ka_decrypt(c, KEY_ABSCISSA[i % 8])

print(f"A) Preserve original key positions:")
print(f"   {pt_preserve_keys[:80]}...")
print(f"   ...{pt_preserve_keys[-40:]}")
print(f"   (This is just K2 PT with delimiters removed - expected)")
print()

# Option B: decrypt residual with ABSCISSA, contiguous key
pt_rekey = decrypt_stream(residual_ct, KEY_ABSCISSA)
print(f"B) Contiguous re-keying with ABSCISSA:")
print(f"   {pt_rekey[:80]}...")
print(f"   ...{pt_rekey[-40:]}")
print()

# Option C: decrypt residual with KRYPTOS, contiguous key
pt_kryptos = decrypt_stream(residual_ct, KEY_KRYPTOS)
print(f"C) Contiguous re-keying with KRYPTOS:")
print(f"   {pt_kryptos[:80]}...")
print()

# Option D: decrypt residual with PALIMPSEST, contiguous key
pt_palimpsest = decrypt_stream(residual_ct, KEY_PALIMPSEST)
print(f"D) Contiguous re-keying with PALIMPSEST:")
print(f"   {pt_palimpsest[:80]}...")

# ═══════════════════════════════════════════════════════════════════════
# Step 4: K4 CT X analysis
# ═══════════════════════════════════════════════════════════════════════

print()
print("=" * 70)
print("STEP 4: K4 CIPHERTEXT X POSITIONS")
print("=" * 70)
print()

k4_x_positions = [i for i, c in enumerate(K4_CT) if c == 'X']
print(f"K4 CT: {K4_CT}")
print(f"K4 CT length: {len(K4_CT)}")
print(f"X positions in K4 CT: {k4_x_positions}")
print()

for pos in k4_x_positions:
    before = K4_CT[max(0, pos - 8):pos]
    after = K4_CT[pos + 1:min(len(K4_CT), pos + 9)]
    in_crib = "CRIB" if (21 <= pos <= 33 or 63 <= pos <= 73) else "unknown PT"
    print(f"  K4[{pos:2d}] = X  context: ...{before}[X]{after}...  ({in_crib})")

print()

# If K4 X positions are delimiters (like K2), removing them gives 95 chars
k4_no_x = "".join(c for i, c in enumerate(K4_CT) if c != 'X')
print(f"K4 without X: {len(k4_no_x)} chars")
print(f"Segments created by X: ", end="")
prev = 0
seg_lengths = []
for pos in k4_x_positions:
    seg = K4_CT[prev:pos]
    seg_lengths.append(len(seg))
    prev = pos + 1
seg_lengths.append(len(K4_CT) - prev)
print(f"{seg_lengths} (lengths)")
print()

# What if K4's X positions are structural like K2's?
# In K2, delimiter X appears every ~67 chars on average.
# K4 has X at position 6 and 79 — gap of 72 between them.
# That's a similar scale to K2's average gap.
print(f"K2 delimiter spacing: {[delimiter_x[i+1][0] - delimiter_x[i][0] for i in range(len(delimiter_x)-1)]}")
print(f"K4 X spacing: [{k4_x_positions[1] - k4_x_positions[0]}]")

# ═══════════════════════════════════════════════════════════════════════
# Step 5: Combined X extraction across K1-K3
# ═══════════════════════════════════════════════════════════════════════

print()
print("=" * 70)
print("STEP 5: ALL DELIMITER X ACROSS K1-K3")
print("=" * 70)
print()

# K1: 0 delimiter X
# K2: 4 delimiter X in sculpture version (67, 137, 198, 250)
# K2 (corrected): 5 delimiter X (add 361)
# K3: 1 delimiter X (position TBD - need full correct K3 decryption)

print("K1: 0 delimiter X")
print(f"K2 (sculpture): {len(delimiter_x)} delimiter X at CT positions {[p for p, _, _ in delimiter_x]}")
print(f"  CT letters: {extracted_ct}")
print(f"K3: 1+ delimiter X (MIST|X|CAN) — position in K3 CT: ~325 (near end)")
print()

# The K3 X is in the last ~11 chars of K3 PT: "FROMTHEMISTXCANYOUSEEANYTHINGQ"
# K3 is 336 chars. "CANYOUSEEANYTHINGQ" = 18 chars, so X is at ~336-18-1 = 317
# (This is approximate since K3 uses transposition and we need the actual mapping)
print("K3 delimiter X position estimate: ~317 in the 336-char K3 PT")
print("(Exact position requires proper K3 transposition decryption)")

# ═══════════════════════════════════════════════════════════════════════
# Step 6: Structural analysis of delimiter positions
# ═══════════════════════════════════════════════════════════════════════

print()
print("=" * 70)
print("STEP 6: STRUCTURAL PATTERNS IN DELIMITER POSITIONS")
print("=" * 70)
print()

delim_positions = [p for p, _, _ in delimiter_x]
print(f"K2 delimiter X positions: {delim_positions}")
print(f"Gaps between delimiters: {[delim_positions[i+1] - delim_positions[i] for i in range(len(delim_positions)-1)]}")
print(f"Modulo 8 (ABSCISSA period): {[p % 8 for p in delim_positions]}")
print(f"Key letters at positions: {[KEY_ABSCISSA[p % 8] for p in delim_positions]}")
print()

# Check if delimiter positions have a pattern mod various values
for mod in range(2, 27):
    residues = [p % mod for p in delim_positions]
    if len(set(residues)) == 1:
        print(f"  *** ALL delimiters ≡ {residues[0]} (mod {mod})")

# Check arithmetic progression
diffs = [delim_positions[i+1] - delim_positions[i] for i in range(len(delim_positions)-1)]
print(f"\nGaps: {diffs}")
print(f"Mean gap: {sum(diffs)/len(diffs):.1f}")
print(f"Are gaps constant? {len(set(diffs)) == 1}")

# K2 segment lengths (between delimiters)
print(f"\nSegment lengths (text between delimiters):")
prev = 0
for i, pos in enumerate(delim_positions):
    seg = k2_decrypted[prev:pos]
    print(f"  Seg {i+1}: {len(seg):3d} chars")
    prev = pos + 1
seg = k2_decrypted[prev:]
print(f"  Seg {len(delim_positions)+1}: {len(seg):3d} chars (final)")

# ═══════════════════════════════════════════════════════════════════════
# Step 7: Cross-reference — do K4's X positions reveal anything about cribs?
# ═══════════════════════════════════════════════════════════════════════

print()
print("=" * 70)
print("STEP 7: K4 X AS SENTENCE BOUNDARIES (hypothesis)")
print("=" * 70)
print()

# If K4 X positions mark sentence boundaries in the plaintext:
# Segment 1: positions 0-5 (6 chars) — unknown PT
# Segment 2: positions 7-78 (72 chars) — contains both cribs
# Segment 3: positions 80-96 (17 chars) — unknown PT
#
# The middle segment (72 chars) contains:
#   EASTNORTHEAST at positions 21-33
#   BERLINCLOCK at positions 63-73
# Both cribs are in the SAME segment.

print("If K4 X marks sentence boundaries:")
print(f"  Segment 1: pos 0-5   ( 6 chars) — all unknown")
print(f"  Segment 2: pos 7-78  (72 chars) — BOTH cribs here")
print(f"  Segment 3: pos 80-96 (17 chars) — all unknown")
print()
print("Both EASTNORTHEAST (21-33) and BERLINCLOCK (63-73) fall in Segment 2.")
print("If X is a period, the plaintext would be:")
print("  [6-char clause]. [72-char sentence containing compass + clock]. [17-char clause].")
print()

# What 6-letter words could start K4 plaintext?
# And what 17-letter fragments could end it?
# Given Sanborn's themes: Egypt trip (1986), Berlin Wall (1989)
print("Possible K4 plaintext structure:")
print("  [SHORT INTRO]. [...EAST NORTH EAST...BERLIN CLOCK...]. [SHORT ENDING].")
print()
print("6-char opening candidates: SLOWLY, BURIED, HIDDEN, SECRET, WITHIN, UNDER?")
print("17-char closing candidates: (room for 2-3 words)")

# ═══════════════════════════════════════════════════════════════════════
# Step 8: What if X in K4 CT encrypts X-as-delimiter in PT?
# ═══════════════════════════════════════════════════════════════════════

print()
print("=" * 70)
print("STEP 8: WHAT CIPHER MAPS PT 'X' TO CT 'X'? (self-encrypting)")
print("=" * 70)
print()

# In K2, PT X encrypts to various CT letters depending on the key.
# But in K4, if positions 6 and 79 are delimiter X in BOTH PT and CT,
# that means the key at those positions maps X -> X.
# Under Vigenere with KA: CT = KA[(KA.index(X) + KA.index(K)) % 26]
# For CT = PT = X: KA.index(X) = (KA.index(X) + KA.index(K)) % 26
# => KA.index(K) = 0 => K = KA[0] = 'K'
# Under standard AZ: X->X means key = A (identity)

x_idx_ka = KA.index('X')
print(f"X in KA alphabet: index {x_idx_ka}")
print(f"For Vigenère (KA): X encrypts to X when key letter = {KA[0]} (K)")
print(f"For Vigenère (AZ): X encrypts to X when key letter = A")
print()
print(f"So if K4[6] and K4[79] are delimiter X in plaintext:")
print(f"  Under KA Vigenère: key[6] = K, key[79] = K")
print(f"  Under AZ Vigenère: key[6] = A, key[79] = A")
print()

# Check: do any known keystream values exist at positions 6 or 79?
# Crib 1: positions 21-33, crib 2: positions 63-73
# Position 6 and 79 are NOT in crib regions.
print("Positions 6 and 79 are NOT in crib regions — no known keystream.")
print("But if key[6] = K and key[79] = K, that's a new constraint!")
print()

# Check Bean-like constraint: does k[6] = k[79]?
# k[6] = k[79] = K (or A under AZ)
# This is analogous to Bean's k[27] = k[65] constraint.
# Gap: 79 - 6 = 73. Bean gap: 65 - 27 = 38.
print(f"New constraint (if hypothesis true): k[6] = k[79]")
print(f"  Gap: 79 - 6 = 73")
print(f"  Bean constraint: k[27] = k[65], gap = 38")
print(f"  Both would need to be satisfied simultaneously.")

# ═══════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════

print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print()
print("FINDINGS:")
print("  1. K2 sculpture has 4 delimiter X at positions [67, 137, 198, 250]")
print(f"     Extracted CT letters: {extracted_ct}")
print(f"     KA indices: {[KA.index(ct) for _, ct, _ in delimiter_x]}")
print(f"     These decrypt to XXXX under ABSCISSA at original positions (trivially)")
print()
print("  2. K3 has at least 1 delimiter X (before CAN YOU SEE ANYTHING)")
print("     The repo K3 PT is garbled (226 chars vs 336 CT chars)")
print()
print("  3. K4 has CT letter X at positions 6 and 79 (both outside crib regions)")
print("     If these are delimiter X in plaintext, it implies:")
print("     - Key = K (KA) or A (AZ) at those positions")
print("     - New constraint: k[6] = k[79]")
print("     - K4 plaintext has 3 sentences of lengths 6, 72, 17")
print()
print("  4. Removing delimiter CT letters from K2 and re-keying produces")
print("     garbage — the key alignment is destroyed")
print("     This means delimiter X are INTEGRAL to the key cycling,")
print("     not separable overlay")
print()
print("OPEN QUESTIONS:")
print("  a. What is the correct full K3 plaintext? (repo version is garbled)")
print("  b. Are K4 CT X positions actually PT delimiters or coincidental?")
print("  c. If k[6]=k[79]=K (KA Vig), does this constrain the key model?")
print("  d. Does the k[6]=k[79] constraint combine with Bean k[27]=k[65]?")
print()
print("VERDICT: INCONCLUSIVE — the extracted CT letters (ASTT) show no")
print("obvious pattern, and removing delimiters destroys key alignment.")
print("However, the K4 self-encrypting X hypothesis (k[6]=k[79]) is a")
print("NEW constraint worth combining with Bean in further analysis.")

# Save results
results = {
    "experiment": "E-AUDIT-08",
    "description": "X-delimiter extraction from K2 ciphertext",
    "k2_delimiter_x_positions": [p for p, _, _ in delimiter_x],
    "k2_delimiter_ct_letters": extracted_ct,
    "k2_delimiter_ka_indices": [KA.index(ct) for _, ct, _ in delimiter_x],
    "k4_x_positions": k4_x_positions,
    "k4_segments_if_delimiters": [6, 72, 17],
    "self_encrypting_x_key_ka": "K",
    "self_encrypting_x_key_az": "A",
    "new_constraint": "k[6] = k[79] (if K4 X are delimiters)",
    "verdict": "INCONCLUSIVE - extraction destroys key alignment, but k[6]=k[79] is new",
}

os.makedirs("results", exist_ok=True)
with open("results/e_audit_08_delimiter_x.json", "w") as f:
    json.dump(results, f, indent=2)
print(f"\nResults saved to results/e_audit_08_delimiter_x.json")