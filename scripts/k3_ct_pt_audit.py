#!/usr/bin/env python3
"""K3 CT/PT Alignment Audit.

Rigorous verification of:
1. K3 ciphertext extraction and character count
2. K3 plaintext character count
3. Letter frequency comparison (must be IDENTICAL for pure transposition)
4. Q and X handling at boundaries

Usage: PYTHONPATH=src python3 -u scripts/k3_ct_pt_audit.py
"""
from collections import Counter

# ── Full sculpture ciphertext (from data/ct.txt and CLAUDE.md) ──────────
# This is the COMPLETE Kryptos sculpture cipher side, all rows concatenated,
# with ? marks exactly as they appear on the sculpture.

FULL_SCULPTURE = (
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ"   # Row 1
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"     # Row 2
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE"      # Row 3
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG"       # Row 4  (? = K2 question mark)
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA"       # Row 5
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"     # Row 6
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI"       # Row 7
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE"       # Row 8  (? = K2 question mark)
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX"      # Row 9
    "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF"       # Row 10 (? = K2 question mark)
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ"        # Row 11
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"       # Row 12
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP"       # Row 13
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"       # Row 14
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA"      # Row 15 (K3 starts)
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNE"        # Row 16
    "TPRNGATIHNRARPESLNNELEBLPIIACAE"        # Row 17
    "WMTWNDITEENRAHCTENEUDRETNHAEOE"         # Row 18
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR"      # Row 19
    "EIFTBRSPAMHHEWENATAMATEGYEERLB"         # Row 20
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI"      # Row 21
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"       # Row 22
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT"     # Row 23
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE"         # Row 24
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR"       # Row 25 (? = K3/K4 boundary, K4 starts after ?)
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO"       # Row 26
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP"       # Row 27
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"      # Row 28
)

print("=" * 72)
print("K3 CT/PT ALIGNMENT AUDIT")
print("=" * 72)

# ── Step 1: Count all characters ───────────────────────────────────────
total_chars = len(FULL_SCULPTURE)
letters_only = ''.join(c for c in FULL_SCULPTURE if c.isalpha())
q_marks = FULL_SCULPTURE.count('?')

print(f"\n--- Step 1: Full sculpture character counts ---")
print(f"Total characters (letters + ?): {total_chars}")
print(f"Total letters (A-Z only):       {len(letters_only)}")
print(f"Total ? marks:                   {q_marks}")
print(f"Letters + ? marks:               {len(letters_only) + q_marks}")

# ── Step 2: Extract sections ───────────────────────────────────────────
# K1 = first 63 letters
# K2 = next 369 letters + 3 ? marks (372 chars)
# K3 = from there until the 4th ? mark (the K3/K4 boundary ?)
# K4 = last 97 letters

# Known K4 ciphertext
K4_CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(K4_CT) == 97

# Find K4 in the full sculpture
k4_start_in_full = FULL_SCULPTURE.find(K4_CT)
assert k4_start_in_full > 0, "K4 not found in full sculpture"
print(f"\nK4 starts at character position {k4_start_in_full} in full sculpture")
print(f"Character just before K4: '{FULL_SCULPTURE[k4_start_in_full - 1]}'")

# The ? at K3/K4 boundary
assert FULL_SCULPTURE[k4_start_in_full - 1] == '?', "Expected ? before K4"

# K1: first 63 letters
k1_letters = []
k1_end_pos = 0
count = 0
for i, ch in enumerate(FULL_SCULPTURE):
    if ch.isalpha():
        k1_letters.append(ch)
        count += 1
        if count == 63:
            k1_end_pos = i + 1
            break
K1_CT = ''.join(k1_letters)

print(f"\n--- Step 2: Section extraction ---")
print(f"K1: {len(K1_CT)} letters, ends at char pos {k1_end_pos}")
print(f"K1: {K1_CT[:20]}...{K1_CT[-10:]}")

# K2: from k1_end_pos to start of K3
# K3 starts at "ENDYAHROHNLSR..." which is on row 15
# Find ENDYAHROHNLSR in the full sculpture
k3_start_str = "ENDYAHROHNLSR"
k3_start_pos = FULL_SCULPTURE.find(k3_start_str)
assert k3_start_pos > 0, "K3 start not found"

K2_SECTION = FULL_SCULPTURE[k1_end_pos:k3_start_pos]
k2_letters = ''.join(c for c in K2_SECTION if c.isalpha())
k2_qmarks = K2_SECTION.count('?')
print(f"K2 section: {len(K2_SECTION)} chars total")
print(f"K2: {len(k2_letters)} letters + {k2_qmarks} question marks = {len(k2_letters) + k2_qmarks} chars")

# K3: from k3_start_pos to the ? before K4
K3_SECTION = FULL_SCULPTURE[k3_start_pos:k4_start_in_full - 1]  # exclude the ?
k3_letters = ''.join(c for c in K3_SECTION if c.isalpha())
k3_qmarks = K3_SECTION.count('?')
K3_CT = k3_letters  # pure letters

# Also include the boundary ?
K3_SECTION_WITH_Q = FULL_SCULPTURE[k3_start_pos:k4_start_in_full]  # include the ?

print(f"\nK3 section (excluding boundary ?): {len(K3_SECTION)} chars")
print(f"K3: {len(k3_letters)} letters + {k3_qmarks} internal ? = {len(k3_letters) + k3_qmarks}")
print(f"K3 section (including boundary ?): {len(K3_SECTION_WITH_Q)} chars")
print(f"K3 letters: {K3_CT[:30]}...{K3_CT[-20:]}")

# K4
print(f"\nK4: {len(K4_CT)} letters")

# Verify: all sections sum to total
all_sections = K1_CT + K2_SECTION + K3_SECTION_WITH_Q + K4_CT
print(f"\nK1({len(K1_CT)}) + K2_section({len(K2_SECTION)}) + K3_section_with_?({len(K3_SECTION_WITH_Q)}) + K4({len(K4_CT)}) = {len(all_sections)}")

# Check letter sum
total_letters_check = len(K1_CT) + len(k2_letters) + len(k3_letters) + len(K4_CT)
print(f"Letter sum: {len(K1_CT)} + {len(k2_letters)} + {len(k3_letters)} + {len(K4_CT)} = {total_letters_check}")
print(f"Expected total letters: {len(letters_only)}")
assert total_letters_check == len(letters_only), f"Letter count mismatch: {total_letters_check} != {len(letters_only)}"
print("PASS: Letter counts sum correctly")

# ── Step 3: K3 CT from Antipodes (cross-check) ─────────────────────────
# Antipodes starts with K3 and has it verified independently
ANTIPODES_K3 = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACH"
    "TNREYULDSLLSLLNOHSNOSMRWXMNETPRNG"
    "ATIHNRARPESLNNELEBLPIIACAEWMTWNDITE"
    "ENRAHCTENEUDRETNHAEOETFOLSEDTIWENH"
    "AEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWE"
    "NATAMATEGYEERLBTEEFOASFIOTUETUAEOT"
    "OARMAEERTNRTIBSEDDNIAAHTTMSTEWPIER"
    "OAGRIEWFEBAECTDDHILCEIHSITEGOEAOSDD"
    "RYDLORITRKLMLEHAGTDHARDPNEOHMGFMF"
    "EUHEECDMRIPFEIMEHNLSSTTRTVDOHW"
)
# Note: Antipodes K3 ends at W before K4 starts with OBKR...
# The ? at the boundary on Kryptos replaced by nothing on Antipodes (K3 flows into K4)

print(f"\n--- Step 3: Cross-check K3 CT with Antipodes ---")
print(f"Kryptos K3 CT:   {len(K3_CT)} letters")
print(f"Antipodes K3 CT: {len(ANTIPODES_K3)} letters")

if K3_CT == ANTIPODES_K3:
    print("PASS: K3 CT matches between Kryptos and Antipodes EXACTLY")
else:
    print("MISMATCH!")
    # Find differences
    min_len = min(len(K3_CT), len(ANTIPODES_K3))
    diffs = [(i, K3_CT[i], ANTIPODES_K3[i]) for i in range(min_len) if K3_CT[i] != ANTIPODES_K3[i]]
    if diffs:
        for pos, k, a in diffs[:10]:
            print(f"  Position {pos}: Kryptos='{k}', Antipodes='{a}'")
    if len(K3_CT) != len(ANTIPODES_K3):
        print(f"  Length difference: Kryptos={len(K3_CT)}, Antipodes={len(ANTIPODES_K3)}")

# ── Step 4: K3 Plaintext (community consensus) ─────────────────────────
# Source: Jim Gillogly's 1999 solution, verified by multiple independent sources
# Sanborn's paraphrase of Howard Carter's Nov 26, 1922 journal
# Key differences from Carter original:
#   - "DESPARATLY" (deliberate misspelling of DESPERATELY)
#   - "WAS REMOVED" vs "WERE REMOVED" (Carter had "were")
#   - Abbreviated — omits many details
#   - Q represents ? ("Can you see anything?")
#   - X is delimiter (between "MIST" and "CAN")

# The canonical K3 plaintext (letters only, no spaces/punctuation):
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINS"
    "OFPASSAGEDEBRISTHATENCUMBEREDTHE"
    "LOWERPARTOFTHEDOORWAYWASREMOVED"
    "WITHTREMBLINGHANDSIMADEATINYBREACH"
    "INTHEUPPERLEFTHANDCORNERANDTHEN"
    "WIDENINGTHEHOLEALITTLEIINSERTEDTHE"
    "CANDLEANDPEABORINTHEHOTAIRESCAPING"
    "FROMTHECHAMBERCAUSEDTHEFLAMETO"
    "FLICKERBUTPRESENTLYDETAILSOFTHE"
    "ROOMWITHINEMERGEFROMTHEMISTX"
    "CANYOUSEEANYTHINGQ"
)

# Wait — I need to be very careful here. Let me construct the plaintext
# from the well-known word-by-word version and count precisely.

# Word-by-word version (from multiple community sources):
K3_PT_WORDS = (
    "SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS "
    "THAT ENCUMBERED THE LOWER PART OF THE DOORWAY WAS REMOVED "
    "WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER "
    "LEFT HAND CORNER AND THEN WIDENING THE HOLE A LITTLE "
    "I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING "
    "FROM THE CHAMBER CAUSED THE FLAME TO FLICKER BUT PRESENTLY "
    "DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST "
    "X CAN YOU SEE ANYTHING Q"
)

# Extract letters only
K3_PT = ''.join(c for c in K3_PT_WORDS.upper() if c.isalpha())

print(f"\n--- Step 4: K3 Plaintext ---")
print(f"K3 PT (letters only): {len(K3_PT)} letters")
print(f"K3 CT (letters only): {len(K3_CT)} letters")
print(f"Difference: {len(K3_CT) - len(K3_PT)}")
print()
print(f"K3 PT: {K3_PT[:40]}...{K3_PT[-30:]}")
print(f"K3 CT: {K3_CT[:40]}...{K3_CT[-30:]}")

if len(K3_PT) == len(K3_CT):
    print("\nPASS: K3 PT and CT have SAME length (consistent with pure transposition)")
else:
    print(f"\nFAIL: K3 PT ({len(K3_PT)}) != K3 CT ({len(K3_CT)})")
    print(f"  Difference = {abs(len(K3_CT) - len(K3_PT))} characters")
    print("  This means either:")
    print("  a) The plaintext transcription is wrong")
    print("  b) K3 is not purely transposition (has substitution component)")
    print("  c) The ? at the boundary is part of K3 (Q→?)")

# ── Step 5: Letter frequency comparison ─────────────────────────────────
print(f"\n--- Step 5: Letter frequency comparison ---")
ct_freq = Counter(K3_CT)
pt_freq = Counter(K3_PT)

# Check all 26 letters
all_letters = sorted(set(list(ct_freq.keys()) + list(pt_freq.keys())))
mismatches = []
print(f"{'Letter':>6} {'CT':>4} {'PT':>4} {'Diff':>5}")
print("-" * 25)
for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
    ct_count = ct_freq.get(letter, 0)
    pt_count = pt_freq.get(letter, 0)
    diff = ct_count - pt_count
    marker = " ***" if diff != 0 else ""
    print(f"{letter:>6} {ct_count:>4} {pt_count:>4} {diff:>+5}{marker}")
    if diff != 0:
        mismatches.append((letter, ct_count, pt_count, diff))

if not mismatches:
    print("\nPASS: ALL letter frequencies match (pure transposition confirmed)")
else:
    print(f"\nFAIL: {len(mismatches)} letter frequency mismatches found:")
    for letter, ct_c, pt_c, diff in mismatches:
        print(f"  {letter}: CT has {ct_c}, PT has {pt_c} (diff={diff:+d})")

    # Compute total excess/deficit
    excess = sum(d for _, _, _, d in mismatches if d > 0)
    deficit = sum(-d for _, _, _, d in mismatches if d < 0)
    print(f"  Total CT excess: {excess}, Total PT excess: {deficit}")

# ── Step 6: Investigate Q and X handling ────────────────────────────────
print(f"\n--- Step 6: Q and X in K3 ---")
print(f"K3 PT contains Q: {'Q' in K3_PT} (count: {K3_PT.count('Q')})")
print(f"K3 PT contains X: {'X' in K3_PT} (count: {K3_PT.count('X')})")
print(f"K3 CT contains Q: {'Q' in K3_CT} (count: {K3_CT.count('Q')})")
print(f"K3 CT contains X: {'X' in K3_CT} (count: {K3_CT.count('X')})")

# Where is Q in the plaintext?
for i, ch in enumerate(K3_PT):
    if ch == 'Q':
        print(f"  Q at PT position {i}: ...{K3_PT[max(0,i-5):i+6]}...")

# Where is X in the plaintext?
for i, ch in enumerate(K3_PT):
    if ch == 'X':
        print(f"  X at PT position {i}: ...{K3_PT[max(0,i-5):i+6]}...")

# On the sculpture, there IS a ? at the K3/K4 boundary
# Under transposition, the Q in the plaintext gets transposed to some CT position
# If that CT position is the LAST position of K3, then Q→? on the sculpture
print(f"\nThe ? on the sculpture sits between K3 CT and K4 CT.")
print(f"If K3 is pure transposition, then Q in PT gets permuted to some CT position.")
print(f"The ? on the sculpture represents this Q landing at position {len(K3_CT)} (end of K3).")
print(f"Under transposition: PT[some_pos]='Q' → CT[{len(K3_CT)}]='?' ")
print(f"This means the transposition maps the PT Q position to the last CT position.")

# ── Step 7: Alternate PT versions found in codebase ─────────────────────
print(f"\n--- Step 7: Alternate K3 PT versions in codebase ---")

# Version from e_s_11 (has WIDENIN not WIDENING, EMERGE not EMERGED)
K3_PT_V1 = ''.join(c for c in (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBERED"
    "THELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSI"
    "MADEATINYBREACHINTHEUPPER"
    "LEFTHANDCORNERANDTHENWIDENINTHEHOLEALITTLEIINSERTEDTHECANDLE"
    "ANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBER"
    "CAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOM"
    "WITHINEMERGEFROMTHEMISTXCANYOUSEEANYTHINGQ"
).upper() if c.isalpha())
print(f"V1 (e_s_11, WIDENIN/EMERGE):     {len(K3_PT_V1)} letters")

# Version from e_frac_39 (has WIDENING, IINSERTED, different ending)
K3_PT_V2 = ''.join(c for c in (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBERED"
    "THELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINY"
    "BREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLE"
    "IINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBER"
    "CAUSEDTHEFLAMETOFLICKERBUTSOONDETAILSOFTHEROOMWITHINEMERGED"
    "FROMTHEMISTXCANYOUSEEANYTHINGQ"
).upper() if c.isalpha())
print(f"V2 (e_frac_39, WIDENING/SOON):    {len(K3_PT_V2)} letters")

# Version from dragnet (community consensus with PRESENTLY)
K3_PT_V3 = ''.join(c for c in (
    "SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS "
    "THAT ENCUMBERED THE LOWER PART OF THE DOORWAY WAS REMOVED "
    "WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER "
    "LEFT HAND CORNER AND THEN WIDENING THE HOLE A LITTLE "
    "I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING "
    "FROM THE CHAMBER CAUSED THE FLAME TO FLICKER BUT PRESENTLY "
    "DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST "
    "X CAN YOU SEE ANYTHING Q"
).upper() if c.isalpha())
print(f"V3 (dragnet/community, PRESENTLY): {len(K3_PT_V3)} letters")

# Version with PRESENTLY but IINSERTED (double I)
K3_PT_V4 = ''.join(c for c in (
    "SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS "
    "THAT ENCUMBERED THE LOWER PART OF THE DOORWAY WAS REMOVED "
    "WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER "
    "LEFT HAND CORNER AND THEN WIDENING THE HOLE A LITTLE "
    "I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING "
    "FROM THE CHAMBER CAUSED THE FLAME TO FLICKER BUT PRESENTLY "
    "DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST "
    "X CAN YOU SEE ANYTHING Q"
).upper() if c.isalpha())
print(f"V4 (PRESENTLY, I INSERTED):        {len(K3_PT_V4)} letters")

# Try with double I (IINSERTED)
K3_PT_V5 = ''.join(c for c in (
    "SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS "
    "THAT ENCUMBERED THE LOWER PART OF THE DOORWAY WAS REMOVED "
    "WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER "
    "LEFT HAND CORNER AND THEN WIDENING THE HOLE A LITTLE "
    "IINSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING "
    "FROM THE CHAMBER CAUSED THE FLAME TO FLICKER BUT PRESENTLY "
    "DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST "
    "X CAN YOU SEE ANYTHING Q"
).upper() if c.isalpha())
print(f"V5 (PRESENTLY, IINSERTED):         {len(K3_PT_V5)} letters")

print(f"\nK3 CT length for comparison:       {len(K3_CT)} letters")

# Check which version matches CT length
for name, pt_ver in [("V1", K3_PT_V1), ("V2", K3_PT_V2), ("V3", K3_PT_V3), ("V4", K3_PT_V4), ("V5", K3_PT_V5)]:
    diff = len(pt_ver) - len(K3_CT)
    marker = " <<<< MATCH" if diff == 0 else ""
    print(f"  {name}: {len(pt_ver)} letters, diff from CT = {diff:+d}{marker}")

# ── Step 8: For each version that matches CT length, verify frequencies ──
print(f"\n--- Step 8: Frequency verification for matching versions ---")
for name, pt_ver in [("V1", K3_PT_V1), ("V2", K3_PT_V2), ("V3", K3_PT_V3), ("V4", K3_PT_V4), ("V5", K3_PT_V5)]:
    if len(pt_ver) != len(K3_CT):
        continue

    pt_f = Counter(pt_ver)
    ct_f = Counter(K3_CT)
    mismatches = []
    for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        if pt_f.get(letter, 0) != ct_f.get(letter, 0):
            mismatches.append((letter, ct_f.get(letter, 0), pt_f.get(letter, 0)))

    if not mismatches:
        print(f"\n  {name}: ALL frequencies match! Pure transposition CONFIRMED.")
    else:
        print(f"\n  {name}: {len(mismatches)} frequency mismatches:")
        for letter, ct_c, pt_c in mismatches:
            print(f"    {letter}: CT={ct_c}, PT={pt_c} (diff={ct_c - pt_c:+d})")

# Even for non-matching versions, show what the freq diff looks like
print(f"\n--- Step 8b: Frequency comparison for ALL versions ---")
for name, pt_ver in [("V1", K3_PT_V1), ("V2", K3_PT_V2), ("V3", K3_PT_V3), ("V4", K3_PT_V4), ("V5", K3_PT_V5)]:
    pt_f = Counter(pt_ver)
    ct_f = Counter(K3_CT)
    mismatches = []
    for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        if pt_f.get(letter, 0) != ct_f.get(letter, 0):
            mismatches.append((letter, ct_f.get(letter, 0), pt_f.get(letter, 0)))

    ct_excess = sum(ct_f.get(l, 0) - pt_f.get(l, 0) for l, _, _ in mismatches if ct_f.get(l, 0) > pt_f.get(l, 0))
    pt_excess = sum(pt_f.get(l, 0) - ct_f.get(l, 0) for l, _, _ in mismatches if pt_f.get(l, 0) > ct_f.get(l, 0))
    print(f"  {name} ({len(pt_ver)} letters): {len(mismatches)} freq mismatches, CT excess={ct_excess}, PT excess={pt_excess}")

# ── Step 9: Summary ────────────────────────────────────────────────────
print(f"\n{'=' * 72}")
print("SUMMARY")
print("=" * 72)
print(f"K1: {len(K1_CT)} cipher letters")
print(f"K2: {len(k2_letters)} cipher letters + {k2_qmarks} ? marks = {len(k2_letters) + k2_qmarks} chars")
print(f"K3: {len(K3_CT)} cipher letters (the boundary ? is the 4th ? mark)")
print(f"K4: {len(K4_CT)} cipher letters")
print(f"Total letters: {total_letters_check}")
print(f"Total chars (incl ?): {total_chars}")
print(f"  = {len(K1_CT)} + {len(k2_letters)} + {len(K3_CT)} + {len(K4_CT)} letters + {q_marks} ?")
print()
print(f"CRITICAL: K3 has {len(K3_CT)} CIPHER LETTERS + 1 boundary ? mark")
print(f"The boundary ? represents the Q at the END of K3 plaintext")
print(f"('CAN YOU SEE ANYTHING?' → ...CANYOUSEEANYTHINGQ → Q maps to ? on sculpture)")
print()
print(f"If K3 plaintext has {len(K3_CT)} letters (excluding Q/?):")
print(f"  Then K3 CT must also be {len(K3_CT)} letters (pure transposition)")
print(f"  And the ? is NOT a cipher letter but a punctuation mark added after encryption")
print()
print(f"If K3 plaintext has {len(K3_CT) + 1} letters (including Q for ?):")
print(f"  Then K3 has {len(K3_CT)} CT letters + 1 Q-as-? = {len(K3_CT) + 1} total")
print(f"  The Q participated in the transposition and happened to land at the end")
print()

# ── Step 10: Does the '?' follow the transposition pattern? ────────────
# If K3 uses keyed columnar with key KRYPTOS (0362514) on a grid,
# and the Q ends up at position 337 (the last position), we can check
# whether this is consistent with the transposition.
print(f"--- Step 10: The ? position question ---")
print(f"On the physical sculpture, the ? sits at the EXACT boundary between K3 and K4.")
print(f"Two interpretations:")
print(f"  A) The ? is the 337th character of K3 (Q encrypted via transposition to last pos)")
print(f"     → K3 = {len(K3_CT) + 1} characters total, CT must have {len(K3_CT) + 1} letters for freq match")
print(f"  B) The ? is a punctuation mark outside the cipher")
print(f"     → K3 = {len(K3_CT)} cipher letters, transposition operates on {len(K3_CT)} chars")
print(f"     → The Q is the LAST letter of K3 PT, becomes the LAST cipher letter (W at pos {len(K3_CT)-1})")
print(f"     → The ? is just Sanborn's way of showing where the question mark was")
print()
print(f"For pure transposition of {len(K3_CT)} letters:")
print(f"  K3 PT must have exactly {len(K3_CT)} letters")
print(f"  K3 PT must have identical letter frequencies to K3 CT")
print()
print(f"For pure transposition of {len(K3_CT) + 1} letters (including Q→?):")
print(f"  K3 PT must have exactly {len(K3_CT) + 1} letters (with a Q)")
print(f"  K3 CT+? must have identical letter frequencies to K3 PT")
print(f"  The ? on the sculpture = CT position of the plaintext Q")

# Check: if we ADD Q to K3 CT, does it match any PT version with Q?
K3_CT_WITH_Q = K3_CT + "Q"  # If Q is the last position
print(f"\n  K3 CT + Q = {len(K3_CT_WITH_Q)} letters")
ct_q_freq = Counter(K3_CT_WITH_Q)

for name, pt_ver in [("V1", K3_PT_V1), ("V2", K3_PT_V2), ("V3", K3_PT_V3), ("V4", K3_PT_V4), ("V5", K3_PT_V5)]:
    if 'Q' not in pt_ver:
        continue
    pt_f = Counter(pt_ver)
    mismatches = []
    for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        if pt_f.get(letter, 0) != ct_q_freq.get(letter, 0):
            mismatches.append((letter, ct_q_freq.get(letter, 0), pt_f.get(letter, 0)))

    if not mismatches and len(pt_ver) == len(K3_CT_WITH_Q):
        print(f"  {name} ({len(pt_ver)} letters) vs CT+Q ({len(K3_CT_WITH_Q)}): PERFECT MATCH!")
    else:
        print(f"  {name} ({len(pt_ver)} letters) vs CT+Q ({len(K3_CT_WITH_Q)}): {len(mismatches)} freq mismatches, len diff={len(pt_ver) - len(K3_CT_WITH_Q)}")
        if mismatches and len(pt_ver) == len(K3_CT_WITH_Q):
            for letter, ct_c, pt_c in mismatches[:5]:
                print(f"    {letter}: CT+Q={ct_c}, PT={pt_c}")

# ── Step 11: what is the "correct" K3 PT? ───────────────────────────────
# Let's try to figure out from the transposition itself.
# K3 uses route transposition with key KRYPTOS = 0362514
# Grid width = 7, then route read
# If we know the CT and the method, we should be able to get the PT

print(f"\n--- Step 11: Reconstruct K3 PT from known method ---")
print(f"K3 encryption method: Keyed columnar transposition")
print(f"Key: KRYPTOS → column order 0362514")
print(f"Grid width: 7 (key length)")

# KRYPTOS key → alphabetical ranking
keyword = "KRYPTOS"
indexed = [(ch, i) for i, ch in enumerate(keyword)]
ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
col_order = [0] * len(keyword)
for rank, (_, pos) in enumerate(ranked):
    col_order[pos] = rank
print(f"Column order: {col_order}")
# Expected: K=0, R=3, Y=6, P=2, T=5, O=1, S=4
# So columns are read in order: col_with_rank_0 first, col_with_rank_1 second, etc.

# Actually, the correct interpretation for K3 is:
# Plaintext is written into a grid of width 7, row by row.
# Columns are then read out in the order specified by the key.
# The key 0362514 means: read column 0 first, then column 3, then column 6, etc.

# To DECRYPT: we need to undo this.
# 1. Determine grid dimensions (n_chars / 7, with possible remainder)
# 2. Distribute CT back into columns in key order
# 3. Read off row by row

def k3_decrypt(ct_text, key_order):
    """Decrypt columnar transposition given CT and column read order."""
    n = len(ct_text)
    ncols = len(key_order)
    nrows = (n + ncols - 1) // ncols  # ceiling division
    remainder = n % ncols  # number of columns with nrows chars (if remainder > 0)
    # If remainder == 0, all columns have same length
    # If remainder > 0, only 'remainder' columns have nrows chars, rest have nrows-1

    # Actually for standard columnar:
    # n chars, ncols columns → some columns have ceil(n/ncols) chars, others have floor(n/ncols)
    full_rows = n // ncols
    extra = n % ncols  # number of columns that get an extra char

    # Column lengths: columns at positions 0..extra-1 in the ORIGINAL grid have full_rows+1 chars
    # columns at positions extra..ncols-1 have full_rows chars
    # But wait: which columns are "long" depends on convention.
    # For standard left-to-right fill: first 'extra' columns (by grid position) are long.

    # The key_order tells us the READ order (which column is read first)
    # key_order[col] = rank (when that column is read)
    # So column with rank 0 is read first, rank 1 second, etc.

    # rank_to_col: which original column has rank r?
    rank_to_col = [0] * ncols
    for col_idx, rank in enumerate(key_order):
        rank_to_col[rank] = col_idx

    # Determine length of each column (by original position)
    col_lengths = []
    for col in range(ncols):
        if extra == 0:
            col_lengths.append(full_rows)
        else:
            col_lengths.append(full_rows + 1 if col < extra else full_rows)

    # Distribute CT into columns in READ order
    columns = {}
    pos = 0
    for rank in range(ncols):
        col = rank_to_col[rank]
        length = col_lengths[col]
        columns[col] = ct_text[pos:pos + length]
        pos += length

    # Read off row by row
    plaintext = []
    for row in range(full_rows + (1 if extra > 0 else 0)):
        for col in range(ncols):
            if row < len(columns[col]):
                plaintext.append(columns[col][row])

    return ''.join(plaintext)

# Try decryption with the standard key
# Key KRYPTOS: K=0, R=3, Y=6, P=2, T=5, O=1, S=4
key_order = col_order  # [0, 3, 6, 2, 5, 1, 4]

# Try with just the 336 cipher letters
pt_attempt_336 = k3_decrypt(K3_CT, key_order)
print(f"\nDecryption attempt (336 letters, key order {key_order}):")
print(f"  First 80: {pt_attempt_336[:80]}")
print(f"  Last 30:  {pt_attempt_336[-30:]}")
starts_with_slowly = pt_attempt_336.startswith("SLOWLY")
print(f"  Starts with SLOWLY: {starts_with_slowly}")

# Try with CT + Q (337 letters)
pt_attempt_337 = k3_decrypt(K3_CT_WITH_Q, key_order)
print(f"\nDecryption attempt (337 letters = CT+Q, key order {key_order}):")
print(f"  First 80: {pt_attempt_337[:80]}")
print(f"  Last 30:  {pt_attempt_337[-30:]}")
starts_with_slowly_2 = pt_attempt_337.startswith("SLOWLY")
print(f"  Starts with SLOWLY: {starts_with_slowly_2}")

# Try alternate column read orders (maybe 0362514 means something different)
# 0362514 could mean: columns are read in order 0, 3, 6, 2, 5, 1, 4
alt_key = [0, 3, 6, 2, 5, 1, 4]
# Convert to the format our function expects (col → rank)
alt_key_order = [0] * 7
for rank, col in enumerate(alt_key):
    alt_key_order[col] = rank
print(f"\nAlternate key interpretation: read columns in order {alt_key}")
print(f"  → col_order = {alt_key_order}")

pt_attempt_alt = k3_decrypt(K3_CT, alt_key_order)
print(f"  First 80: {pt_attempt_alt[:80]}")
print(f"  Starts with SLOWLY: {pt_attempt_alt.startswith('SLOWLY')}")

pt_attempt_alt_q = k3_decrypt(K3_CT_WITH_Q, alt_key_order)
print(f"\nWith Q (337):")
print(f"  First 80: {pt_attempt_alt_q[:80]}")
print(f"  Starts with SLOWLY: {pt_attempt_alt_q.startswith('SLOWLY')}")

# Try also with the route transposition (not just columnar)
# K3 actually uses ROUTE + columnar combined
# Let's try multiple approaches

# Method described by Gillogly: write PT into 48×7 grid, reorder columns, read off
# 336/7 = 48 rows exactly, 337/7 = 48 rows + 1 extra char
print(f"\n--- Grid dimensions ---")
print(f"336 / 7 = {336/7} ({336//7} rows, remainder {336%7})")
print(f"337 / 7 = {337/7} ({337//7} rows, remainder {337%7})")

# Try every possible column read order for width 7 (7! = 5040 permutations)
# and see which one produces plaintext starting with "SLOWLY"
from itertools import permutations

print(f"\n--- Brute force: all 5040 column read orders, width 7 ---")
found_any = False

for perm in permutations(range(7)):
    # perm = the read order: read column perm[0] first, perm[1] second, etc.
    # Convert to col_order format
    co = [0] * 7
    for rank, col in enumerate(perm):
        co[col] = rank

    # Try 336 letters
    pt = k3_decrypt(K3_CT, co)
    if pt.startswith("SLOWLY"):
        print(f"  336 letters, read order {list(perm)}, col_order {co}:")
        print(f"    {pt[:100]}")
        print(f"    ...{pt[-40:]}")
        print(f"    Length: {len(pt)}")
        found_any = True

    # Try 337 letters
    pt_q = k3_decrypt(K3_CT_WITH_Q, co)
    if pt_q.startswith("SLOWLY"):
        print(f"  337 letters (with Q), read order {list(perm)}, col_order {co}:")
        print(f"    {pt_q[:100]}")
        print(f"    ...{pt_q[-40:]}")
        print(f"    Length: {len(pt_q)}")
        found_any = True

if not found_any:
    print("  No simple columnar transposition (width 7) produces SLOWLY...")
    print("  K3 likely uses a more complex route/rotation method.")

# Try route transposition: write into grid, read by column (various routes)
print(f"\n--- Route transposition attempts ---")
for n_chars, label, ct_input in [(336, "336", K3_CT), (337, "337", K3_CT_WITH_Q)]:
    for width in [7, 8, 42, 48, 14, 24]:
        if n_chars % width != 0 and width > n_chars:
            continue
        height = (n_chars + width - 1) // width
        remainder = n_chars % width

        # Write CT into grid (row-major)
        grid = []
        pos = 0
        for r in range(height):
            row = []
            for c in range(width):
                if pos < n_chars:
                    row.append(ct_input[pos])
                    pos += 1
                else:
                    row.append('')
            grid.append(row)

        # Read column-major (top to bottom, left to right)
        pt_col = ''
        for c in range(width):
            for r in range(height):
                if grid[r][c]:
                    pt_col += grid[r][c]

        if pt_col.startswith("SLOWLY"):
            print(f"  {label} chars, {height}x{width} grid, col-major read: STARTS WITH SLOWLY!")
            print(f"    {pt_col[:100]}")
            found_any = True

        # Also: read bottom to top
        pt_col_rev = ''
        for c in range(width):
            for r in range(height - 1, -1, -1):
                if grid[r][c]:
                    pt_col_rev += grid[r][c]

        if pt_col_rev.startswith("SLOWLY"):
            print(f"  {label} chars, {height}x{width} grid, col-major REVERSE read: STARTS WITH SLOWLY!")
            print(f"    {pt_col_rev[:100]}")
            found_any = True

print(f"\n{'=' * 72}")
print("DONE")
print("=" * 72)
