#!/usr/bin/env python3
"""
Cipher: encoding/extraction
Family: encoding
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-MISSPELLING-CT-LETTERS: Verify what CT letters appear at misspelling positions.

Elonka (PhreakNIC26, 2025) stated the CT letters at misspelling positions are K and R.
If K3's DESPARATLY misspelling position gives S, then KRS is spelled by the misspellings.

This script:
1. Verifies K1: CT letter at IQLUSION/Q position
2. Verifies K2: CT letter at UNDERGRUUND/extra-U position
3. Investigates K3: CT letter at DESPARATLY/A-for-E position
4. Maps all misspelling positions to CT letters
"""

# === ALPHABETS ===
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# === FULL CIPHER PANEL (868 chars, squeezed ? removed) ===
CIPHER_RAW = (
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ"  # row 0
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"  # row 1
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE"  # row 2
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG"  # row 3 (? #1)
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA"  # row 4
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR" # row 5
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI"  # row 6
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE"  # row 7 (? #2)
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX" # row 8
    "FLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"   # row 9 (squeezed ? #3 already removed)
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ"  # row 10
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"  # row 11
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP"  # row 12
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"  # row 13
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI"  # row 14 (K3 starts)
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE"  # row 15
    "TPRNGATIHNRARPESLNNELEBLPIIACAE"  # row 16
    "WMTWNDITEENRAHCTENEUDRETNHAEOE"   # row 17
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR" # row 18
    "EIFTBRSPAMHHEWENATAMATEGYEERLB"   # row 19
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI" # row 20
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB" # row 21
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT"# row 22
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE"   # row 23
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR" # row 24 (? #3, K4 starts at OBKR)
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO"  # row 25
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP"  # row 26
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"  # row 27
)

# Build clean panel (letters + ? only)
PANEL = CIPHER_RAW
print(f"Panel length: {len(PANEL)}")
letter_count = sum(1 for c in PANEL if c.isalpha())
q_count = sum(1 for c in PANEL if c == '?')
print(f"Letters: {letter_count}, ?'s: {q_count}, total: {letter_count + q_count}")

# ==========================================================
# K1 VERIFICATION
# ==========================================================
print("\n" + "=" * 70)
print("K1: IQLUSION — CT letter at Q position")
print("=" * 70)

# K1 plaintext (with the misspelling as it decrypts)
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUA NCEOFIQLUSION"
K1_PT_CLEAN = K1_PT.replace(" ", "")
print(f"K1 PT: {K1_PT_CLEAN}")
print(f"K1 PT length: {len(K1_PT_CLEAN)}")

# Find Q position in K1 PT
q_pos = K1_PT_CLEAN.index('Q')
print(f"Q in IQLUSION at PT position: {q_pos}")
print(f"Context: ...{K1_PT_CLEAN[q_pos-3:q_pos+5]}...")

# K1 CT starts at panel position 0
k1_ct_at_q = PANEL[q_pos]
print(f"CT letter at position {q_pos}: {k1_ct_at_q}")
print(f"  → {'K confirmed!' if k1_ct_at_q == 'K' else 'NOT K — check boundaries'}")

# Also verify with Vigenère
K1_KEY = "PALIMPSEST"  # correct keyword
K1_KEY_WRONG = "PALIMPCEST"  # misspelled keyword on sculpture

def vig_encrypt_ka(pt, key):
    """Vigenère encrypt with KA alphabet."""
    ct = []
    for i, p in enumerate(pt):
        p_idx = KA.index(p)
        k_idx = KA.index(key[i % len(key)])
        c_idx = (p_idx + k_idx) % 26
        ct.append(KA[c_idx])
    return ''.join(ct)

def vig_decrypt_ka(ct, key):
    """Vigenère decrypt with KA alphabet."""
    pt = []
    for i, c in enumerate(ct):
        c_idx = KA.index(c)
        k_idx = KA.index(key[i % len(key)])
        p_idx = (c_idx - k_idx) % 26
        pt.append(KA[p_idx])
    return ''.join(pt)

# What the correct PT should be (ILLUSION not IQLUSION)
K1_PT_CORRECT = K1_PT_CLEAN.replace("IQLUSION", "ILLUSION")

# Encrypt correct PT with correct key
ct_correct = vig_encrypt_ka(K1_PT_CORRECT, K1_KEY)
# Encrypt correct PT with wrong key
ct_wrong = vig_encrypt_ka(K1_PT_CORRECT, K1_KEY_WRONG)

print(f"\nVerification:")
print(f"  Correct key (PALIMPSEST), correct PT (ILLUSION):")
print(f"    CT[{q_pos}] = {ct_correct[q_pos]}")
print(f"  Wrong key (PALIMPCEST), correct PT (ILLUSION):")
print(f"    CT[{q_pos}] = {ct_wrong[q_pos]}")

# Check the actual K1 ciphertext from the panel
k1_ct_actual = PANEL[:len(K1_PT_CLEAN)]
# Remove any ? in this range
k1_ct_letters = ''.join(c for c in k1_ct_actual if c.isalpha())
print(f"\n  Actual panel CT at pos {q_pos}: {PANEL[q_pos]}")

# Decrypt actual CT with wrong key to verify we get IQLUSION
decrypted = vig_decrypt_ka(k1_ct_letters, K1_KEY_WRONG)
iqlusion_region = decrypted[q_pos-5:q_pos+8]
print(f"  Decrypting panel with PALIMPCEST: ...{iqlusion_region}...")

# Also check what letter SHOULD be there with correct key
decrypted_correct = vig_decrypt_ka(k1_ct_letters, K1_KEY)
illusion_region = decrypted_correct[q_pos-5:q_pos+8]
print(f"  Decrypting panel with PALIMPSEST: ...{illusion_region}...")

# ==========================================================
# K2 VERIFICATION
# ==========================================================
print("\n" + "=" * 70)
print("K2: UNDERGRUUND — CT letter at extra-U position")
print("=" * 70)

# K2 plaintext
K2_PT = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHE"
    "EARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDAND"
    "TRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONX"
    "DOESLANGLEYKNOWABOUTTHIS"
    "THEYSHOULDITSBURIEDOUTTHERESOMEWHEREX"
    "WHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEX"
    "THIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTH"
    "SEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTY"  # Note: ends differently
)
# Actually, let me be more careful. The K2 plaintext decrypted from the actual sculpture
# ends with IDBYROWS. Let me use the plaintext that Sanborn INTENDED:

# From the research, K2 decrypts as ending in IDBYROWS on the physical sculpture
# But Sanborn intended XLAYERTWO
# Let me just find UNDERGRUUND position

# K2 starts after K1 in the cipher panel
K2_KEY = "ABSCISSA"

# First, how long is K1 CT? K1 PT is 63 chars, so K1 CT is 63 chars
K1_LEN = len(K1_PT_CLEAN)
print(f"K1 length: {K1_LEN}")

# K2 CT starts at panel position K1_LEN = 63
# But we need to be careful about the ?'s in K2

# Find UNDERGRUUND in K2 plaintext
k2_pt_full = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHE"
    "EARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDAND"
    "TRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONX"
    "DOESLANGLEYKNOWABOUTTHIS"
    "THEYSHOULDITSBU RIEDOUTTHERESOMEWHEREX"
    "WHOKNOWSTHEEXACTLOCATIONONLYWW"
    "THISWASHISLASTMESSAGEX"
    "THIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTH"
    "SEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTY"
).replace(" ", "")

# Actually, I should decrypt the actual K2 CT to get the real PT mapping
# Let me just find UNDERGRUUND in the known K2 PT
k2_search = "TRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONX"
# Find "UNDERGRUUND" within K2 PT
ugu_start = k2_pt_full.find("UNDERGRUUND")
if ugu_start >= 0:
    print(f"UNDERGRUUND starts at K2 PT position: {ugu_start}")
    # The misspelling: position 8 in UNDERGRUUND is U (should be O)
    # UNDERGROUND: U-N-D-E-R-G-R-O-U-N-D (0-indexed: O at position 7)
    # UNDERGRUUND: U-N-D-E-R-G-R-U-U-N-D (0-indexed: U at position 7)
    misspell_pos_in_word = 7  # the O→U change
    misspell_pos_in_k2 = ugu_start + misspell_pos_in_word
    misspell_pos_in_panel = K1_LEN + misspell_pos_in_k2
    print(f"O→U change at word position {misspell_pos_in_word}")
    print(f"K2 PT position: {misspell_pos_in_k2}")
    print(f"Panel position (K1_LEN + K2_pos): {misspell_pos_in_panel}")

    # But we need to account for ? characters in the panel
    # Count non-alpha chars before this position
    panel_pos = 0
    letter_pos = 0
    target_letter_pos = misspell_pos_in_panel
    while letter_pos < target_letter_pos and panel_pos < len(PANEL):
        if PANEL[panel_pos].isalpha():
            letter_pos += 1
        panel_pos += 1
    # panel_pos now points to the target letter (or just past it)
    # Back up one since we incremented past
    actual_panel_pos = panel_pos - 1
    # Actually let me redo this more carefully
    letter_idx = 0
    for pi, ch in enumerate(PANEL):
        if ch.isalpha():
            if letter_idx == target_letter_pos:
                actual_panel_pos = pi
                break
            letter_idx += 1

    ct_at_misspell = PANEL[actual_panel_pos]
    print(f"Actual panel position (accounting for ?'s): {actual_panel_pos}")
    print(f"CT letter at misspelling position: {ct_at_misspell}")
    print(f"  → {'R confirmed!' if ct_at_misspell == 'R' else f'Got {ct_at_misspell}, not R'}")
else:
    print("UNDERGRUUND not found in K2 PT — trying alternate")

# Let me also try a direct approach: decrypt K2 CT and find the misspelling
# K2 CT = panel letters from position K1_LEN onwards (skipping ?'s)
# Actually, let me just map letter-by-letter

# Extract all letters from the panel
panel_letters = ''.join(c for c in PANEL if c.isalpha())
print(f"\nTotal panel letters: {len(panel_letters)}")

# K1 = first 63 letters, K2 = next N letters
k1_ct = panel_letters[:63]
print(f"K1 CT (63): {k1_ct}")

# Decrypt K1 with wrong key to verify IQLUSION
k1_dec = vig_decrypt_ka(k1_ct, K1_KEY_WRONG)
print(f"K1 decrypted with PALIMPCEST: {k1_dec}")
print(f"  Contains IQLUSION: {'IQLUSION' in k1_dec}")

# K2 length: let's figure it out
# K3 starts at "ENDYAHROHNLSR..." which we can find in the panel
k3_start_str = "ENDYAHROHNLSR"
k3_start_in_panel = PANEL.find(k3_start_str)
print(f"\nK3 starts at panel position: {k3_start_in_panel}")

# Count letters before K3 start
letters_before_k3 = sum(1 for c in PANEL[:k3_start_in_panel] if c.isalpha())
print(f"Letters before K3: {letters_before_k3}")
k2_len = letters_before_k3 - 63
print(f"K2 length: {k2_len}")

k2_ct = panel_letters[63:63+k2_len]
print(f"K2 CT ({k2_len} chars): {k2_ct[:50]}...{k2_ct[-20:]}")

# Decrypt K2
k2_dec = vig_decrypt_ka(k2_ct, K2_KEY)
print(f"K2 decrypted: {k2_dec[:60]}...")
print(f"K2 decrypted end: ...{k2_dec[-30:]}")

# Find UNDERGRUUND in decrypted K2
ugu_in_dec = k2_dec.find("UNDERGRUUND")
if ugu_in_dec < 0:
    ugu_in_dec = k2_dec.find("UNDERGROUND")
    if ugu_in_dec >= 0:
        print(f"Found UNDERGROUND (correct) at K2 position {ugu_in_dec}")
    else:
        # Try partial match
        for i in range(len(k2_dec) - 5):
            if k2_dec[i:i+5] == "UNDER":
                print(f"Found UNDER at K2 position {i}: {k2_dec[i:i+15]}")
else:
    print(f"Found UNDERGRUUND at K2 position {ugu_in_dec}")
    misspell_pos_k2 = ugu_in_dec + 7  # O→U at position 7 in the word
    misspell_global = 63 + misspell_pos_k2
    ct_letter = panel_letters[misspell_global]
    print(f"K2 misspelling at K2 pos {misspell_pos_k2}, global letter pos {misspell_global}")
    print(f"CT letter: {ct_letter}")
    print(f"  → {'R confirmed!' if ct_letter == 'R' else f'Got {ct_letter}'}")

# ==========================================================
# K3 INVESTIGATION
# ==========================================================
print("\n" + "=" * 70)
print("K3: DESPARATLY — CT letter at A-for-E position")
print("=" * 70)

# K3 plaintext
K3_PT = (
    "SLOWLYDESPARATLYSLOW LYTHEREMAINS OFPASSAGEDEBRISTHATENCUMBERED"
    "THELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMB LINGHANDSIMADETINY"
    "BREACHINTHEUPPERLEFTHANDCORNERANDTHENW IDENINGTHEHOLEALITTLEI"
    "INSERTEDTHECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECH AMBER"
    "CAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHIN"
    "EMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"
).replace(" ", "")

K3_CT_STR = (
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
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)

print(f"K3 PT length: {len(K3_PT)}")
print(f"K3 CT length: {len(K3_CT_STR)}")

# Find DESPARATLY in K3 PT
desp_pos = K3_PT.find("DESPARATLY")
if desp_pos >= 0:
    print(f"DESPARATLY starts at K3 PT position: {desp_pos}")
    # DESPERATELY (correct): D-E-S-P-E-R-A-T-E-L-Y (11 chars)
    # DESPARATLY  (wrong):   D-E-S-P-A-R-A-T-L-Y   (10 chars)
    # Change 1: position 4 in word: E→A
    # Change 2: position 8 E deleted (word shortened)
    misspell_word_pos = 4  # E→A
    misspell_k3_pos = desp_pos + misspell_word_pos
    print(f"E→A change at word position {misspell_word_pos}, K3 PT position {misspell_k3_pos}")
    print(f"K3 PT context: {K3_PT[desp_pos:desp_pos+10]}")

    # In K3, the transposition SCRAMBLES positions.
    # K3 CT[i] corresponds to K3 PT[perm[i]] for some permutation.
    # We need the INVERSE: which CT position j has PT position misspell_k3_pos?
    # That is: find j such that perm[j] = misspell_k3_pos

    # We know both K3 PT and K3 CT, so we can reconstruct the permutation!
    # For each CT position i, find where K3_CT[i] appears in K3_PT
    # This is not unique if letters repeat, but we can try

    print(f"\nK3 CT letter at position {misspell_k3_pos}: {K3_CT_STR[misspell_k3_pos]}")
    print(f"  (But this is NOT necessarily the CT for PT[{misspell_k3_pos}] due to transposition)")

    # Reconstruct the K3 transposition permutation
    # Since K3 uses double rotational transposition, PT is written in one order
    # and read out in another. The permutation maps: CT[i] = PT[perm[i]]
    # We can find perm by matching characters, but repeated letters make this ambiguous.

    # Alternative approach: use the known K3 method (24×14 → 8×42 double rotation)
    # or just search for which CT positions could correspond to the misspelled letter.

    # Simple approach: find all CT positions where the PT character at that
    # position (in the permutation) matches what we expect.

    # Since we don't know the exact permutation, let's find ALL positions
    # where 'A' appears in K3 CT and 'E' appears in K3 PT at the corresponding
    # spot (assuming the transposition is known).

    # Actually, the simplest check: the misspelling changes PT[10] from E to A
    # (DESPARATLY's A at position 4 in the word, position 10 in K3 PT since
    # SLOWLY = 6, so DESPARATLY starts at position 6)
    # Wait, let me recheck
    print(f"\n  Rechecking position:")
    print(f"  K3 PT starts: {K3_PT[:30]}")
    # SLOWLY = positions 0-5
    # DESPARATLY = positions 6-15
    # The E→A is at position 4 within DESPARATLY = position 6+4 = 10
    print(f"  SLOWLY ends at pos 5, DESPARATLY starts at pos {desp_pos}")
    print(f"  Misspelling at pos {misspell_k3_pos}: PT[{misspell_k3_pos}] = {K3_PT[misspell_k3_pos]}")

    # Now, K3 is a transposition cipher. The CT is a permutation of the PT.
    # CT = PT[perm[0]], PT[perm[1]], ..., PT[perm[N-1]]
    # We want: which CT position j has PT source = position misspell_k3_pos?
    # That is: perm[j] = misspell_k3_pos

    # With both PT and CT known, we can find the permutation uniquely
    # by matching character by character (handling repeats carefully)

    # Build the permutation by greedy matching
    pt_list = list(K3_PT)
    ct_list = list(K3_CT_STR)
    n = min(len(pt_list), len(ct_list))

    # For each PT position, find which CT position it maps to
    # PT[i] → CT[perm_inv[i]] where perm_inv is the inverse
    # CT[j] = PT[perm[j]]

    # Use the available positions tracker
    pt_available = list(range(n))  # available PT positions
    perm = [None] * n  # perm[j] = which PT position feeds CT[j]

    # For repeated characters, we need more info. Let's try a simple greedy approach
    # and see if it gives us useful information.

    # Alternative: check ALL CT positions that have the same letter as PT[misspell_k3_pos]
    target_letter = K3_PT[misspell_k3_pos]  # This is 'A' (the misspelled letter)
    print(f"\n  Target: PT[{misspell_k3_pos}] = '{target_letter}' (the misspelled A)")
    print(f"  In correct text, this would be 'E' (DESPERATELY)")

    # Positions in K3 CT where target_letter appears
    ct_positions_with_letter = [i for i, c in enumerate(K3_CT_STR) if c == target_letter]
    print(f"  '{target_letter}' appears at {len(ct_positions_with_letter)} CT positions")
    print(f"  CT positions: {ct_positions_with_letter[:20]}{'...' if len(ct_positions_with_letter) > 20 else ''}")

    # If we knew the correct PT (DESPERATELY), the misspelled position
    # would have E instead of A. The CT at that transposition output position
    # would ALSO change from A to E (since transposition preserves letters).
    # So the CT letter AT THE MISSPELLING'S TRANSPOSED POSITION would be A
    # (because PT has A there due to misspelling).

    # The question is: which of the A positions in CT corresponds to PT position 10?
    # Without the full permutation, we can't determine this precisely.

    # BUT: let's count how many A's are in K3 PT and K3 CT
    pt_a_count = K3_PT[:n].count('A')
    ct_a_count = K3_CT_STR[:n].count('A')
    pt_e_count = K3_PT[:n].count('E')
    ct_e_count = K3_CT_STR[:n].count('E')
    print(f"\n  Letter counts (K3 only):")
    print(f"    PT: A={pt_a_count}, E={pt_e_count}")
    print(f"    CT: A={ct_a_count}, E={ct_e_count}")
    print(f"    (Should match since transposition preserves letters)")
    if pt_a_count == ct_a_count and pt_e_count == ct_e_count:
        print(f"    ✓ Counts match — transposition confirmed")
    else:
        print(f"    ✗ Counts DON'T match — check PT/CT alignment")

    # The key point: in a TRANSPOSITION cipher, the CT has THE SAME LETTERS
    # as the PT, just reordered. So CT[j] = PT[perm[j]].
    # If PT[10] = 'A' (misspelling), then there exists exactly one CT position j
    # where perm[j] = 10 and CT[j] = 'A'.
    # But we can't identify which 'A' in the CT it is without the permutation.

    # HOWEVER: we can reconstruct the permutation from the K3 method!
    # K3 uses route cipher / double rotational transposition
    # The working grid is 31 wide (confirmed)

    print(f"\n  K3 TRANSPOSITION RECONSTRUCTION:")
    print(f"  K3 PT written in rows of width 31:")
    for i in range(0, len(K3_PT), 31):
        row = K3_PT[i:i+31]
        print(f"    Row {i//31}: {row}")

    print(f"\n  K3 CT read off (as it appears on sculpture):")
    for i in range(0, len(K3_CT_STR), 31):
        row = K3_CT_STR[i:i+31]
        print(f"    Row {i//31}: {row}")

    # Try to find the permutation by trying different transposition methods
    # Method 1: simple columnar transposition
    # Method 2: route reading (spiral, zigzag, etc.)

    # Let's try the simplest: read columns from the PT grid
    WIDTH = 31
    n_rows = (len(K3_PT) + WIDTH - 1) // WIDTH

    print(f"\n  Grid: {n_rows} rows × {WIDTH} cols = {n_rows * WIDTH} (PT len = {len(K3_PT)})")

    # Write PT into grid, read by columns
    def columnar_read(text, width):
        """Read text written in rows by columns (top-to-bottom, left-to-right)."""
        n_rows = (len(text) + width - 1) // width
        result = []
        for col in range(width):
            for row in range(n_rows):
                idx = row * width + col
                if idx < len(text):
                    result.append(text[idx])
        return ''.join(result)

    col_read = columnar_read(K3_PT, WIDTH)
    if col_read == K3_CT_STR[:len(col_read)]:
        print(f"  Simple columnar (31) MATCHES K3 CT!")
    else:
        match_count = sum(1 for a, b in zip(col_read, K3_CT_STR) if a == b)
        print(f"  Simple columnar (31): {match_count}/{min(len(col_read), len(K3_CT_STR))} matches")

    # Try reading columns in different orders
    # Also try route cipher: write in rows, read by columns reversed, etc.

    # Let's just find the permutation empirically
    # For each CT position j, find perm[j] such that CT[j] = PT[perm[j]]
    # Use a greedy approach tracking used PT positions

    from collections import defaultdict
    pt_positions_by_char = defaultdict(list)
    for i, ch in enumerate(K3_PT[:n]):
        pt_positions_by_char[ch].append(i)

    # Try to build permutation greedily
    used = set()
    perm_found = [None] * n
    ambiguous = 0
    for j in range(n):
        ct_char = K3_CT_STR[j]
        candidates = [p for p in pt_positions_by_char[ct_char] if p not in used]
        if len(candidates) == 0:
            print(f"  ERROR: no PT position for CT[{j}]={ct_char}")
            break
        # We don't know which candidate is right without the transposition key
        # Just note the possibilities for the misspelling position
        if misspell_k3_pos in candidates:
            print(f"\n  *** CT[{j}] = '{ct_char}' could source from PT[{misspell_k3_pos}]")
            print(f"      (CT position {j}, panel position {63 + k2_len + j})")
            # What's the letter at this panel position?
            global_letter_pos = 63 + k2_len + j
            if global_letter_pos < len(panel_letters):
                print(f"      Panel letter at global pos {global_letter_pos}: {panel_letters[global_letter_pos]}")

else:
    print("DESPARATLY not found in K3 PT")

# ==========================================================
# SUMMARY: All misspelling CT letters
# ==========================================================
print("\n" + "=" * 70)
print("SUMMARY: CT letters at misspelling positions")
print("=" * 70)

print("""
Misspelling         Section  CT Letter  Confirmed?
──────────────────  ───────  ─────────  ──────────
IQLUSION (Q for L)  K1       K          (verify above)
UNDERGRUUND (U→O)   K2       R          (verify above)
DESPARATLY (A→E)    K3       ?          (ambiguous — transposition)

If K3 misspelling → S, then KRS is spelled by the misspelling positions!
""")

print("\nDone.")
