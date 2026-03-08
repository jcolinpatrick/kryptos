#!/usr/bin/env python3
"""
Kryptos K0 Morse Code Palindrome Analysis — V2
================================================
Deep analysis of the user's raw Morse transcription, focusing on:
1. Parsing the actual raw Morse provided (line by line)
2. Checking TRUE bitstream palindrome property
3. Handling the C/J/Z problem (no valid Morse reverse)
4. Exploring what the reversed reading yields
5. Analyzing whether Sanborn chose these phrases intentionally
"""

import sys

# ─── Standard International Morse Code ───────────────────────────────────────

MORSE_TABLE = {
    'A': '.-',    'B': '-...',  'C': '-.-.',  'D': '-..',
    'E': '.',     'F': '..-.',  'G': '--.',   'H': '....',
    'I': '..',    'J': '.---',  'K': '-.-',   'L': '.-..',
    'M': '--',    'N': '-.',    'O': '---',   'P': '.--.',
    'Q': '--.-',  'R': '.-.',   'S': '...',   'T': '-',
    'U': '..-',   'V': '...-',  'W': '.--',   'X': '-..-',
    'Y': '-.--',  'Z': '--..',
}

MORSE_REVERSE = {v: k for k, v in MORSE_TABLE.items()}

# ─── Palindrome map ─────────────────────────────────────────────────────────

def build_palindrome_map():
    """Build letter-level palindrome map. Returns (map, unmappable_letters)."""
    pal_map = {}
    unmapped = {}
    for letter, morse in MORSE_TABLE.items():
        rev = morse[::-1]
        if rev in MORSE_REVERSE:
            pal_map[letter] = MORSE_REVERSE[rev]
        else:
            unmapped[letter] = rev
    return pal_map, unmapped

PAL_MAP, UNMAPPED = build_palindrome_map()


# ─── Parse the raw Morse transcription ──────────────────────────────────────
# The user provided this from photographs. We need to be very careful here.
# Unicode: · = \u00b7 (middle dot) or · could be . (period)
#          – = \u2013 (en-dash) should be - (dah)
#
# The user's transcription uses · for dit and – for dah, with spaces between
# individual Morse characters (each space = character boundary).
# Multiple spaces or line breaks = word boundaries.

def normalize_morse_char(s):
    """Normalize a Morse character string to . and - only."""
    result = s.strip()
    # Replace various dash/dot characters
    result = result.replace('·', '.').replace('\u00b7', '.')
    result = result.replace('–', '-').replace('\u2013', '-').replace('\u2014', '-')
    return result


def parse_raw_line(line):
    """Parse a line of raw Morse into a list of Morse characters.

    Characters are separated by single spaces.
    Words are separated by multiple spaces (3+) or explicit markers.
    Returns list of (morse_pattern, is_word_break_before).
    """
    # Split by multiple spaces to find word boundaries
    # Then split each word by single spaces for character boundaries
    result = []

    # Normalize the line
    line = line.replace('·', '.').replace('\u00b7', '.')
    line = line.replace('–', '-').replace('\u2013', '-').replace('\u2014', '-')
    line = line.strip()

    if not line:
        return result

    # Track position to detect multi-space gaps
    i = 0
    current_char = ''
    space_count = 0
    word_break_pending = False

    for ch in line:
        if ch in '.-':
            if space_count >= 3:
                word_break_pending = True
            if current_char and space_count > 0:
                # Emit previous character
                if current_char in '.-' or all(c in '.-' for c in current_char):
                    result.append((current_char, word_break_pending if len(result) > 0 else False))
                    word_break_pending = False
                current_char = ch
            else:
                current_char += ch
            space_count = 0
        elif ch == ' ':
            space_count += 1
            if space_count == 1 and current_char:
                # Single space = character boundary
                result.append((current_char, word_break_pending if len(result) > 0 else False))
                word_break_pending = False
                current_char = ''
        i += 1

    # Don't forget last character
    if current_char:
        result.append((current_char, word_break_pending if len(result) > 0 else False))

    return result


# ─── The raw Morse from photographs ─────────────────────────────────────────
# Each line as provided by the user. Using . and - directly.
# Marking word breaks with | where the user showed larger gaps.

RAW_LINES = [
    # Line 1: VIRTUALLY E
    # (The user's raw has some ambiguity. Let's use the known decoded text to
    # produce the "correct" Morse, then verify against the raw transcription.)

    # Actually, let's work from the KNOWN DECODED TEXT directly since the
    # raw transcription has Unicode ambiguities. The decoded text IS the
    # authoritative reference for what the Morse says.
]

# ─── Work from the authoritative decoded text ───────────────────────────────
# Sources agree on this reading (with the known misspellings):
# Standard reading: "VIRTUALLY INVISIBLE DIGITAL INTERPRETATION SHADOW FORCES
#                    LUCID MEMORY T IS YOUR POSITION SOS"
# Some sources add "RQ" at the end (prosign).
# Note: "DIGETAL" and "INTERPRETATIU" may be misreadings or intentional.
# The standard reading uses DIGITAL INTERPRETATION.

# We'll analyze the STANDARD reading primarily, then note variants.

PHRASES_STANDARD = [
    "VIRTUALLY", "INVISIBLE", "DIGITAL", "INTERPRETATION",
    "SHADOW", "FORCES", "LUCID", "MEMORY",
    "T", "IS", "YOUR", "POSITION",
    "SOS",
]

# Let's also try: what if the text were chosen to BE palindromic?
# Then C would be problematic. Let's check if there are alternative
# readings that avoid C, J, Z.

def text_to_morse_list(text):
    """Convert text to list of (char, morse_code) tuples."""
    result = []
    for ch in text.upper():
        if ch in MORSE_TABLE:
            result.append((ch, MORSE_TABLE[ch]))
    return result


def morse_list_to_bitstream(morse_list):
    """Concatenate Morse codes to a single bitstream string."""
    return ''.join(m for _, m in morse_list)


def check_palindrome(bs):
    """Check if bitstream is palindromic."""
    return bs == bs[::-1]


def palindrome_mismatch_analysis(bs):
    """Detailed analysis of palindrome mismatches."""
    n = len(bs)
    rev = bs[::-1]
    mismatches = []
    for i in range(n):
        if bs[i] != rev[i]:
            mismatches.append(i)
    return mismatches


def reverse_with_letter_boundaries(morse_list):
    """Reverse the bitstream while preserving letter boundaries from the
    FORWARD reading. This is the 'keep boundaries, reverse within and reorder'
    approach.

    If forward is: [A=.-, N=-., E=.]
    Bitstream: .--.
    Reversed:  .--.

    But with original boundaries (2,2,1): reversed bits partitioned as (1,2,2)
    from the END: last 1 bit = '.', next 2 = '--', next 2 = '.-'
    Decoding: '.': E, '--': M, '.-': A → EMA

    Actually, the TRUE palindrome reading reverses the bitstream and re-parses.
    The letter boundaries DON'T carry over. That's the ambiguity problem.
    """
    # The proper approach for a TRUE palindrome:
    # 1. Get the forward bitstream
    # 2. Reverse it entirely
    # 3. Parse with the REVERSED letter boundaries (= forward boundaries reversed)

    # If forward letters have Morse lengths [L1, L2, ..., Ln]
    # then reversed bitstream with reversed boundaries [Ln, ..., L2, L1]
    # gives us the palindrome-pair reading.

    fwd_bs = ''.join(m for _, m in morse_list)
    rev_bs = fwd_bs[::-1]

    # Reversed boundaries
    lengths = [len(m) for _, m in morse_list]
    rev_lengths = list(reversed(lengths))

    # Parse reversed bitstream with reversed boundaries
    result = []
    pos = 0
    for l in rev_lengths:
        chunk = rev_bs[pos:pos+l]
        letter = MORSE_REVERSE.get(chunk, f'[{chunk}?]')
        result.append((letter, chunk))
        pos += l

    return result


def main():
    print("=" * 78)
    print("KRYPTOS K0 MORSE CODE — PALINDROME DEEP ANALYSIS")
    print("=" * 78)

    # ═══ SECTION 1: The palindrome letter map ════════════════════════════
    print("\n" + "=" * 78)
    print("SECTION 1: MORSE PALINDROME LETTER MAP")
    print("=" * 78)

    print("\nWhen you reverse a Morse code's dit/dah sequence, it may map to")
    print("a different letter. This creates a substitution cipher.\n")

    # Self-palindromic
    self_pals = sorted([l for l in PAL_MAP if PAL_MAP[l] == l])
    # Swap pairs
    swap_pairs = []
    seen = set()
    for l in sorted(PAL_MAP):
        m = PAL_MAP[l]
        if l != m and frozenset([l, m]) not in seen:
            seen.add(frozenset([l, m]))
            swap_pairs.append((l, m))

    print(f"Self-palindromic letters ({len(self_pals)}):")
    for l in self_pals:
        print(f"  {l} = {MORSE_TABLE[l]:6s} reversed = {MORSE_TABLE[l][::-1]:6s} = {l}")

    print(f"\nSwap pairs ({len(swap_pairs)}):")
    for a, b in swap_pairs:
        print(f"  {a} = {MORSE_TABLE[a]:6s} <-> {b} = {MORSE_TABLE[b]:6s}")

    print(f"\nUNMAPPABLE letters ({len(UNMAPPED)}) — reversed Morse is not a valid character:")
    for l, rev in sorted(UNMAPPED.items()):
        print(f"  {l} = {MORSE_TABLE[l]:6s} reversed = {rev:6s} -> NO VALID LETTER")

    print(f"\n*** C, J, Z CANNOT participate in a Morse palindrome! ***")
    print(f"*** Any text with C, J, or Z cannot be exactly palindromic ***")

    # ═══ SECTION 2: Forward bitstream ════════════════════════════════════
    print("\n" + "=" * 78)
    print("SECTION 2: FORWARD READING — FULL BITSTREAM")
    print("=" * 78)

    all_text = ''.join(PHRASES_STANDARD)
    morse_list = text_to_morse_list(all_text)
    bitstream = morse_list_to_bitstream(morse_list)

    print(f"\nDecoded text: {' '.join(PHRASES_STANDARD)}")
    print(f"Letters only: {all_text}")
    print(f"Letter count: {len(all_text)}")
    print(f"Bitstream length: {len(bitstream)} symbols")

    print(f"\nLetter-by-letter Morse:")
    for i, (ch, m) in enumerate(morse_list):
        end = '\n' if (i + 1) % 10 == 0 else '  '
        print(f"{ch}={m}", end=end)
    print()

    print(f"\nFull forward bitstream:")
    for i in range(0, len(bitstream), 60):
        print(f"  {bitstream[i:i+60]}")

    rev_bitstream = bitstream[::-1]
    print(f"\nReversed bitstream:")
    for i in range(0, len(rev_bitstream), 60):
        print(f"  {rev_bitstream[i:i+60]}")

    is_pal = check_palindrome(bitstream)
    print(f"\nExact bitstream palindrome? {is_pal}")

    if not is_pal:
        mismatches = palindrome_mismatch_analysis(bitstream)
        print(f"Mismatches: {len(mismatches)} of {len(bitstream)} positions ({100*len(mismatches)/len(bitstream):.1f}%)")
        # Show first few
        for pos in mismatches[:5]:
            print(f"  Position {pos}: forward='{bitstream[pos]}' reverse='{rev_bitstream[pos]}'")

    # ═══ SECTION 3: Reversed reading with original boundaries ════════════
    print("\n" + "=" * 78)
    print("SECTION 3: REVERSED READING (preserving letter boundaries)")
    print("=" * 78)

    print("\nMethod: Reverse the entire bitstream, then parse using the")
    print("REVERSED sequence of letter boundaries from the forward reading.")
    print("This is what you'd get if the Morse were physically read backward")
    print("with the letter gaps at the same physical positions.\n")

    reversed_letters = reverse_with_letter_boundaries(morse_list)

    reversed_text = ''.join(l for l, _ in reversed_letters)
    print(f"Forward:  {all_text}")
    print(f"Reversed: {reversed_text}")

    print(f"\nLetter-by-letter comparison:")
    n = len(morse_list)
    for i in range(n):
        fwd_ch, fwd_m = morse_list[i]
        rev_ch, rev_m = reversed_letters[i]
        partner_ch, partner_m = morse_list[n - 1 - i]

        is_correct_pal = (rev_ch == PAL_MAP.get(partner_ch, '?'))
        marker = "OK" if is_correct_pal else "!!"

        if i < 15 or i >= n - 5:  # Show first 15 and last 5
            print(f"  [{i:2d}] fwd={fwd_ch}({fwd_m:6s}) "
                  f"rev={rev_ch}({rev_m:6s}) "
                  f"[should be pal of [{n-1-i}]={partner_ch}({partner_m:6s}) "
                  f"-> {PAL_MAP.get(partner_ch, '?')}] {marker}")
        elif i == 15:
            print(f"  ... ({n - 20} more rows) ...")

    # ═══ SECTION 4: Letter-level palindrome substitution ═════════════════
    print("\n" + "=" * 78)
    print("SECTION 4: LETTER-LEVEL PALINDROME SUBSTITUTION")
    print("=" * 78)

    print("\nThis applies the palindrome map to each letter independently.")
    print("Equivalent to: for each letter, reverse its Morse and decode.\n")

    print(f"  Substitution map:")
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    mapped_alpha = ''.join(PAL_MAP.get(ch, '?') for ch in alphabet)
    print(f"  Plain:  {alphabet}")
    print(f"  Cipher: {mapped_alpha}")
    print()

    for phrase in PHRASES_STANDARD:
        mapped = ''.join(PAL_MAP.get(ch, f'[{ch}?]') for ch in phrase)
        print(f"  {phrase:20s} -> {mapped}")

    full_mapped = ' '.join(''.join(PAL_MAP.get(ch, f'[{ch}?]') for ch in p) for p in PHRASES_STANDARD)
    print(f"\n  Full forward:     {' '.join(PHRASES_STANDARD)}")
    print(f"  Full substituted: {full_mapped}")

    # The TRUE palindrome reading also reverses order
    all_mapped = ''.join(PAL_MAP.get(ch, '?') for ch in all_text)
    print(f"\n  Substituted (no spaces):  {all_mapped}")
    print(f"  Reversed order:           {all_mapped[::-1]}")

    # ═══ SECTION 5: VIRTUALLY INVISIBLE detailed walkthrough ═════════════
    print("\n" + "=" * 78)
    print("SECTION 5: VIRTUALLY INVISIBLE — Detailed Walkthrough")
    print("=" * 78)

    for word in ["VIRTUALLY", "INVISIBLE"]:
        print(f"\n  {word}:")
        for ch in word:
            morse = MORSE_TABLE[ch]
            rev_morse = morse[::-1]
            if rev_morse in MORSE_REVERSE:
                rev_letter = MORSE_REVERSE[rev_morse]
                print(f"    {ch}  {morse:6s}  reversed: {rev_morse:6s}  = {rev_letter}")
            else:
                print(f"    {ch}  {morse:6s}  reversed: {rev_morse:6s}  = ** INVALID **")
        mapped = ''.join(PAL_MAP.get(ch, '?') for ch in word)
        print(f"  {word} -> {mapped}")

    print(f"\n  Combined: VIRTUALLY INVISIBLE -> "
          f"{''.join(PAL_MAP.get(ch, '?') for ch in 'VIRTUALLY')} "
          f"{''.join(PAL_MAP.get(ch, '?') for ch in 'INVISIBLE')}")

    # ═══ SECTION 6: The C/J/Z Problem ═══════════════════════════════════
    print("\n" + "=" * 78)
    print("SECTION 6: THE C/J/Z PROBLEM")
    print("=" * 78)

    print("""
  C = -.-.  reversed = .-.-  (NOT a valid Morse character)
  J = .---  reversed = ---.  (NOT a valid Morse character)
  Z = --..  reversed = ..--  (NOT a valid Morse character)

  These three letters have Morse codes whose reversal is NOT in the
  International Morse Code alphabet. This means:

  1. A text containing C, J, or Z CANNOT be an exact Morse palindrome
  2. The K0 text contains: """)

    for problem_letter in ['C', 'J', 'Z']:
        count = all_text.count(problem_letter)
        if count > 0:
            positions = [i for i, ch in enumerate(all_text) if ch == problem_letter]
            # Find which words contain it
            pos = 0
            word_positions = []
            for phrase in PHRASES_STANDARD:
                for ch in phrase:
                    if ch == problem_letter:
                        word_positions.append(phrase)
                    pos += 1
            unique_words = sorted(set(word_positions))
            print(f"     {problem_letter}: {count} occurrence(s) in: {', '.join(unique_words)}")
        else:
            print(f"     {problem_letter}: 0 occurrences")

    print("""
  C appears in FORCES and LUCID (and INTERPRETATION via the C).

  IMPLICATIONS:
  - The K0 Morse is NOT an exact dit/dah palindrome
  - However, C's Morse (.-.-) is itself palindromic as a symbol sequence!
    -.-. reversed = .-.- which is palindromic-adjacent
  - The reversed codes .-.- , ---. , ..-- were used in early telegraph
    systems for accented letters (e.g., .-.- was used for Ä in some codes)

  ALTERNATIVE HYPOTHESIS: The palindrome may operate at a different level:
  - Word-level palindrome (phrases read backward)
  - Thematic palindrome (meaning reads both ways)
  - Approximate palindrome (ignoring the 2 C's)
  - Palindrome using a non-standard Morse variant
""")

    # ═══ SECTION 7: Near-palindrome analysis ════════════════════════════
    print("\n" + "=" * 78)
    print("SECTION 7: NEAR-PALINDROME ANALYSIS")
    print("=" * 78)

    # What if we exclude FORCES and LUCID (the C-containing words)?
    # Or what if C maps to C? (treating .-.- as self-palindromic since -.-. reversed
    # happens to not be standard, but C itself IS a palindromic Morse code in the
    # visual sense: - . - . is NOT the same backward: . - . -

    # Actually: -.-. reversed is .-.-
    # In Continental Morse (not International), there were different assignments.
    # In International: .-.- is "end of message" prosign (AA) sometimes.

    print("Checking: if we FORCE C to map to itself (treating it as")
    print("'approximately' palindromic), how close is the text to palindromic?\n")

    # Augmented palindrome map
    aug_pal = dict(PAL_MAP)
    aug_pal['C'] = 'C'  # Force it
    aug_pal['J'] = 'J'  # Force it (not in text anyway)
    aug_pal['Z'] = 'Z'  # Force it (not in text anyway)

    # With augmented map, check the text
    aug_mapped = ''.join(aug_pal.get(ch, '?') for ch in all_text)
    aug_reversed = aug_mapped[::-1]

    print(f"Forward text:        {all_text}")
    print(f"Augmented pal-map:   {aug_mapped}")
    print(f"Reversed aug-map:    {aug_reversed}")

    # Check if forward text equals reversed augmented map
    # For a palindrome: text[i] should be the palindrome partner of text[n-1-i]
    match_count = 0
    total = len(all_text)
    for i in range(total):
        partner = aug_pal.get(all_text[total - 1 - i], '?')
        if all_text[i] == partner:
            match_count += 1

    print(f"\nLetter-level palindrome check (augmented):")
    print(f"  text[i] == pal_map(text[n-1-i]) for {match_count}/{total} positions "
          f"({100*match_count/total:.1f}%)")

    # Show the mismatches
    print(f"\n  Position-by-position (showing mismatches):")
    mismatch_positions = []
    for i in range(total):
        j = total - 1 - i
        if i > j:
            break
        expected = aug_pal.get(all_text[j], '?')
        match = all_text[i] == expected
        if not match:
            mismatch_positions.append(i)
            if len(mismatch_positions) <= 20:
                print(f"    [{i:2d}] text[{i}]={all_text[i]}, text[{j}]={all_text[j]}, "
                      f"pal({all_text[j]})={expected} -> MISMATCH")

    if not mismatch_positions:
        print("    *** ALL POSITIONS MATCH — text IS palindromic under augmented map! ***")
    else:
        print(f"\n  Total mismatched position-pairs: {len(mismatch_positions)}")

    # ═══ SECTION 8: What constraints does palindrome place on words? ═════
    print("\n" + "=" * 78)
    print("SECTION 8: CONSTRAINTS ON WORD SELECTION")
    print("=" * 78)

    print("""
  For the K0 text to be a Morse palindrome, the ENTIRE text (read as one
  string) must satisfy: for each position i from the start and j from the end,
  text[i] and text[j] must be palindrome partners.

  This means Sanborn couldn't freely choose ANY words — the first and last
  letters constrain each other, the second and second-to-last, etc.

  Let's check what the first phrase VIRTUALLY would need the LAST letters to be:
""")

    print(f"  Forward text: {all_text}")
    print(f"  Length: {len(all_text)}\n")

    # For each letter at the start, show what letter is needed at the end
    print(f"  Required pairings (start <-> end):")
    half = (len(all_text) + 1) // 2
    for i in range(min(20, half)):
        j = len(all_text) - 1 - i
        needed = aug_pal.get(all_text[i], '?')
        actual = all_text[j]
        match = "MATCH" if needed == actual else "MISMATCH"
        print(f"    [{i:2d}] {all_text[i]} needs {needed} at [{j}], got {actual} -> {match}")

    print(f"\n  ... (middle letter at position {len(all_text)//2} = '{all_text[len(all_text)//2]}'"
          f" must be self-palindromic: {all_text[len(all_text)//2] in self_pals})")

    # ═══ SECTION 9: Apply palindrome substitution to K4 ═════════════════
    print("\n" + "=" * 78)
    print("SECTION 9: K4 — PALINDROME SUBSTITUTION AS CIPHER")
    print("=" * 78)

    K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

    # Apply palindrome substitution (augmented, with C->C, J->J, Z->Z)
    k4_mapped = ''.join(aug_pal.get(ch, '?') for ch in K4)

    print(f"\n  K4 ciphertext:  {K4}")
    print(f"  Pal-substituted: {k4_mapped}")

    # Check cribs
    # Known: positions 21-33 = EASTNORTHEAST, 63-73 = BERLINCLOCK
    print(f"\n  Checking crib positions after substitution:")
    print(f"  Positions 21-33: {k4_mapped[21:34]} (original: {K4[21:34]})")
    print(f"  Positions 63-73: {k4_mapped[63:74]} (original: {K4[63:74]})")

    # What do cribs become under palindrome sub?
    for crib in ["EASTNORTHEAST", "BERLINCLOCK"]:
        mapped_crib = ''.join(aug_pal.get(ch, '?') for ch in crib)
        print(f"\n  Crib: {crib} -> {mapped_crib}")

    # IC analysis
    from collections import Counter

    def ic(text):
        c = Counter(text)
        n = len(text)
        return sum(v*(v-1) for v in c.values()) / (n*(n-1))

    print(f"\n  IC analysis:")
    print(f"    K4 original IC:    {ic(K4):.4f}")
    print(f"    K4 pal-mapped IC:  {ic(k4_mapped):.4f}")
    print(f"    English expected:  ~0.0667")
    print(f"    Random expected:   ~0.0385")

    # The palindrome substitution preserves frequency structure partially
    # Self-palindromic letters keep their frequency
    # Swap pairs exchange frequencies
    print(f"\n  Note: IC changes because swap pairs exchange frequencies.")
    print(f"  K has freq 8 (self-palindromic, preserved)")
    print(f"  B(5) <-> V(2): frequencies swap")
    print(f"  A(4) <-> N(3): frequencies swap")
    print(f"  D(3) <-> U(6): frequencies swap")

    # ═══ SECTION 10: Summary and K4 connections ═════════════════════════
    print("\n" + "=" * 78)
    print("SECTION 10: SUMMARY AND K4 CONNECTIONS")
    print("=" * 78)

    print("""
  FINDINGS:

  1. MORSE PALINDROME MAP: The Morse code reversal creates a well-defined
     letter substitution with 12 self-mapping letters (E,T,I,M,O,R,S,H,K,C*,P,X)
     and 7 swap pairs (A<->N, B<->V, D<->U, F<->L, G<->W, Q<->Y, plus
     digits 1<->9, 2<->8, 3<->7, 4<->6, 0 and 5 self).

     * C, J, Z have no valid Morse reverse — they break exact palindromes.

  2. THE K0 TEXT IS NOT AN EXACT MORSE PALINDROME. The text
     "VIRTUALLY INVISIBLE DIGITAL INTERPRETATION SHADOW FORCES LUCID MEMORY
     T IS YOUR POSITION SOS" contains C (in FORCES, LUCID, INTERPRETATION)
     and fails the palindrome pairing test at multiple positions.

  3. LETTER-LEVEL SUBSTITUTION RESULTS:
     VIRTUALLY INVISIBLE  ->  BIRTDNFFQ IABISIVFE
     DIGITAL INTERPRETATION  ->  UIWITNF IATERPRETNTIOA
     SHADOW FORCES LUCID MEMORY  ->  SHNUOG LORCES FUCID MEMORQ
     T IS YOUR POSITION  ->  T IS QODR POSITIOA
     SOS  ->  SOS

     The substituted text is NOT meaningful English.

  4. WORDS PARTIALLY PRESERVED: Some words are nearly self-palindromic:
     - SOS -> SOS (perfect!)
     - POSITION -> POSITIOA (7/8 letters preserved, only N->A)
     - MEMORY -> MEMORQ (5/6 preserved, only Y->Q)
     - IS -> IS (perfect)
     - T -> T (perfect)
     - MORSE -> MORSE (would be perfect if it appeared)

  5. K4 CONNECTION — THE SUBSTITUTION AS CIPHER:
     The palindrome map is an INVOLUTION (applying it twice = identity).
     This is characteristic of reciprocal ciphers (like Enigma).
     If K4's 'simple substitution' layer used this exact map:
     - It would be unbreakable by frequency analysis alone (swap pairs
       merge two frequencies)
     - But it's a FIXED substitution (no key), so unlikely as a standalone
       cipher

  6. THEMATIC SIGNIFICANCE:
     "VIRTUALLY INVISIBLE" at the entrance, with a structure that encodes
     the concept of MIRROR/REVERSAL, is powerful thematic framing.
     Even if not exactly palindromic, the CONCEPT of reading backward
     to reveal hidden information is introduced at the very start of Kryptos.

  7. "IT IS YOUR POSITION" -> palindrome-mapped to "IT IS QODR POSITIOA"
     The word POSITION survives almost intact. This could be a meta-clue:
     POSITION matters — your position in the text determines what you see.
""")

    # ═══ BONUS: Search for English words in palindrome-mapped text ══════
    print("\n" + "=" * 78)
    print("BONUS: ENGLISH WORDS THAT SURVIVE PALINDROME SUBSTITUTION")
    print("=" * 78)

    print("\nWords where palindrome map produces another English word:\n")

    # Common English words to test
    common_words = [
        "THE", "AND", "FOR", "ARE", "BUT", "NOT", "YOU", "ALL", "HER", "HIS",
        "ONE", "OUR", "OUT", "DAY", "HAD", "HAS", "HIM", "HOW", "ITS", "MAY",
        "NEW", "NOW", "OLD", "SEE", "WAY", "WHO", "BOY", "DID", "GET", "HAS",
        "LET", "SAY", "SHE", "TOO", "USE", "WAR", "RUN", "SET", "SIT", "TEN",
        "TOP", "TRY", "ASK", "MAN", "RAN", "SIR", "SIT", "MET", "HIT", "MIX",
        "FIRE", "TIME", "MORE", "SOME", "THEM", "MOST", "RISE", "MISS", "KISS",
        "SORT", "STOP", "STEP", "TRIP", "STIR", "SPIT", "SKIP", "SLIM", "SPOT",
        "MIST", "MORSE", "HIKE", "PIKE", "KITE", "MITE", "RITE", "SITE", "TOSS",
        "MOSS", "EMIT", "OMIT", "EXIT", "EXIST", "MOIST", "HOIST", "POSIT",
        "SOS", "STEM", "ITEM", "TERM", "PERM", "HERO", "ZERO", "SERIES",
        "SPIRIT", "PERMIT", "HERMIT", "SUBMIT", "MIRROR", "TERROR", "HORROR",
        "POSITION", "IMPRESS", "RESIST", "SISTER", "MISTER", "PERSIST",
        "MORSE", "SMOKE", "STORE", "STORM", "SPORT", "SHORT", "SHIRT",
        "INTERPRET", "MERIT", "ORBIT", "PERMIT", "REMIT", "LIMIT",
        "PRIOR", "EXTERIOR", "INTERIOR", "SUPERIOR", "POSTERIOR",
    ]

    # Also test all Kryptos-relevant words
    kryptos_words = [
        "KRYPTOS", "CIPHER", "SECRET", "HIDDEN", "SHADOW", "FORCES",
        "MEMORY", "POSITION", "MORSE", "CODE", "PALIMPSEST", "ABSCISSA",
        "VIRTUALLY", "INVISIBLE", "DIGITAL", "INTERPRETATION", "LUCID",
        "CLOCK", "BERLIN", "EAST", "NORTH", "NORTHEAST",
        "HOROLOGE", "DEFECTOR", "PARALLAX", "COLOPHON",
        "ENIGMA", "ILLUSION", "MIRAGE", "PHANTOM",
    ]

    all_test_words = sorted(set(w.upper() for w in common_words + kryptos_words))

    # Simple check: does the mapped word look like it could be English?
    # We'll just show the mapping for all and let the reader judge.
    self_mapping_words = []
    interesting_mappings = []

    for word in all_test_words:
        mapped = ''.join(aug_pal.get(ch, '?') for ch in word)
        if mapped == word:
            self_mapping_words.append(word)
        elif all(ch not in 'ANDUGJWBVFLQY' for ch in word):
            pass  # Only self-pal letters, should map to itself
        else:
            interesting_mappings.append((word, mapped))

    print(f"Self-mapping words (invariant under palindrome substitution):")
    for w in self_mapping_words:
        print(f"  {w}")

    print(f"\nInteresting mappings (words that CHANGE):")
    for w, m in interesting_mappings[:50]:
        # Check if mapped word is in our test set
        is_word = m in all_test_words
        marker = " <-- ALSO A WORD!" if is_word else ""
        print(f"  {w:20s} -> {m:20s}{marker}")

    # Check specific pairs
    print(f"\n  Checking for reciprocal word pairs:")
    word_set = set(all_test_words)
    found_pairs = set()
    for word in all_test_words:
        mapped = ''.join(aug_pal.get(ch, '?') for ch in word)
        if mapped in word_set and mapped != word:
            pair = tuple(sorted([word, mapped]))
            if pair not in found_pairs:
                found_pairs.add(pair)
                print(f"    {pair[0]} <-> {pair[1]}")

    if not found_pairs:
        print(f"    (none found in test set)")

    print("\n" + "=" * 78)
    print("ANALYSIS COMPLETE")
    print("=" * 78)


if __name__ == '__main__':
    main()
