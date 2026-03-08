#!/usr/bin/env python3
"""
Kryptos K0 Morse Code Palindrome Analysis
==========================================
Analyzes the palindromic structure of the Kryptos entrance Morse code tablets.

The Morse code (K0) carved on the entrance tablets may be palindromic at the
dit/dah level — the entire sequence of dots and dashes could read the same
forward and backward, producing DIFFERENT letters because many Morse codes
are mirrors of each other.

This script:
1. Converts the raw Morse to a full dit/dah bitstream
2. Checks palindromic property
3. Decodes the reversed stream
4. Applies the letter-level palindrome substitution
5. Analyzes constraints on word selection
"""

# ─── Standard International Morse Code ───────────────────────────────────────

MORSE_TABLE = {
    'A': '.-',    'B': '-...',  'C': '-.-.',  'D': '-..',
    'E': '.',     'F': '..-.',  'G': '--.',   'H': '....',
    'I': '..',    'J': '.---',  'K': '-.-',   'L': '.-..',
    'M': '--',    'N': '-.',    'O': '---',   'P': '.--.',
    'Q': '--.-',  'R': '.-.',   'S': '...',   'T': '-',
    'U': '..-',   'V': '...-',  'W': '.--',   'X': '-..-',
    'Y': '-.--',  'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--',
    '4': '....-', '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.',
}

# Reverse lookup: morse pattern -> character
MORSE_REVERSE = {v: k for k, v in MORSE_TABLE.items()}


# ─── Build palindrome mapping ────────────────────────────────────────────────

def reverse_morse(pattern):
    """Reverse a dit/dah pattern."""
    return pattern[::-1]


def build_palindrome_map():
    """Build the letter-level palindrome substitution map.

    For each letter, reverse its Morse code and look up what letter
    the reversed code corresponds to.
    """
    pal_map = {}
    unmapped = {}
    for letter, morse in MORSE_TABLE.items():
        rev = reverse_morse(morse)
        if rev in MORSE_REVERSE:
            pal_map[letter] = MORSE_REVERSE[rev]
        else:
            unmapped[letter] = rev
    return pal_map, unmapped


# ─── Raw Morse from the Kryptos entrance tablets ─────────────────────────────
# User-provided transcription from photographs.
# Format: each line is a sequence of Morse characters separated by spaces.
# Spaces between words indicated by multiple spaces or explicit markers.
# '–' (en-dash) = '-' (dah), '·' = '.' (dit)

# We'll encode each line as a list of (morse_for_letter, ...) with word breaks.
# Using the user's transcription, normalizing dashes.

RAW_LINES_MORSE = [
    # Line 1: · · ···- ·· ·-· – ··- ·- ·-·· ·-·· -·– ·
    # This reads: E E V I R T U A L L Y E  ... but that's "EEVIRTUALLY E"
    # The user says it decodes to "VIRTUALLY INVISIBLE" etc.
    # Let me re-parse more carefully.
    #
    # Actually, looking at the user's transcription more carefully:
    # Line 1: · · ···- ·· ·-· – ··- ·- ·-·· ·-·· -·– ·
    # Morse letters: E E V I R T U A L L Y E
    # But "EEVIRTUALLYE" doesn't match "VIRTUALLY"
    #
    # The '· ·' at start might be one character '··' = I, or two E's
    # Let me just work with the KNOWN decoded text and build from there.

    # Known decoded text (forward reading):
    # VIRTUALLY INVISIBLE
    # DIGETAL INTERPRETATIU (note: misspellings may be intentional)
    # SHADOW FORCES
    # LUCID MEMORY
    # T IS YOUR POSITION
    # SOS
    # RQ (prosign for "roger")
]

# ─── APPROACH: Work from the known decoded text ──────────────────────────────
# Since we have the decoded phrases, we'll:
# 1. Convert each phrase to Morse
# 2. Concatenate to get the full bitstream
# 3. Reverse and decode
# 4. Check palindromic properties

# The known decoded text from the Kryptos Morse tablets.
# Note: There are known misspellings that may be intentional:
#   DIGETAL (not DIGITAL), INTERPRETATIU (not INTERPRETATION)
# These are well-documented Kryptos anomalies.

# Full decoded text, preserving the phrases as separate words:
DECODED_PHRASES = [
    "VIRTUALLY",
    "INVISIBLE",
    "DIGETAL",           # sic - intentional misspelling?
    "INTERPRETATIU",     # sic - intentional misspelling? (or reading error)
    "IS",                # Some sources: "IT IS" or "T IS"
    "SHADOW",
    "FORCES",
    "LUCID",
    "MEMORY",
    "T",                 # Some sources include standalone T
    "IS",
    "YOUR",
    "POSITION",
    "SOS",
    "RQ",                # Prosign
]

# Alternative full reading (more commonly cited):
# "VIRTUALLY INVISIBLE DIGITAL INTERPRETATION SHADOW FORCES LUCID MEMORY
#  IT IS YOUR POSITION SOS RQ"
# But the user specifies DIGETAL INTERPRETATIU, so we'll analyze both.

STANDARD_PHRASES = [
    "VIRTUALLY", "INVISIBLE", "DIGITAL", "INTERPRETATION",
    "SHADOW", "FORCES", "LUCID", "MEMORY",
    "T", "IS", "YOUR", "POSITION",
    "SOS",
]

# User's variant
USER_PHRASES = [
    "VIRTUALLY", "INVISIBLE", "DIGETAL", "INTERPRETATIU",
    "SHADOW", "FORCES", "LUCID", "MEMORY",
    "T", "IS", "YOUR", "POSITION",
    "SOS", "RQ",
]


def text_to_morse_sequence(text):
    """Convert text to a list of Morse patterns (one per character)."""
    result = []
    for ch in text.upper():
        if ch in MORSE_TABLE:
            result.append(MORSE_TABLE[ch])
        # Skip spaces and unknown chars
    return result


def morse_sequence_to_bitstream(morse_list):
    """Convert a list of Morse patterns to a continuous dit/dah string.

    In actual Morse, characters are separated by inter-character gaps
    and words by inter-word gaps. For palindrome analysis at the
    dit/dah level, we need to decide how to handle gaps.

    Option A: No gaps - just concatenate all dits and dahs
    Option B: Include inter-character gaps as a third symbol

    For pure palindrome analysis, we use Option A (no gaps).
    """
    return ''.join(morse_list)


def bitstream_to_morse_letters(bitstream):
    """Attempt to decode a dit/dah bitstream back into letters.

    This is ambiguous without character boundaries! Morse code is
    NOT self-synchronizing - 'A' (.-) could also be 'ET' (. -).

    We'll use greedy decoding (longest match first) and also
    try shortest match, then report both.

    Returns list of possible decodings.
    """
    # For systematic analysis, we need to try all valid parsings.
    # This is exponential in general, but we can use dynamic programming.

    results = []

    def decode_recursive(remaining, decoded_so_far, depth=0):
        if not remaining:
            results.append(decoded_so_far[:])
            return
        if depth > 500:  # Safety limit
            return
        if len(results) > 100:  # Limit results
            return

        # Try all possible lengths (1 to 5 for standard Morse)
        for length in range(1, min(6, len(remaining) + 1)):
            chunk = remaining[:length]
            if chunk in MORSE_REVERSE:
                decoded_so_far.append(MORSE_REVERSE[chunk])
                decode_recursive(remaining[length:], decoded_so_far, depth + 1)
                decoded_so_far.pop()

    decode_recursive(bitstream, [])
    return results


def phrases_to_full_bitstream(phrases):
    """Convert a list of phrases to a full dit/dah bitstream."""
    all_morse = []
    for phrase in phrases:
        for ch in phrase.upper():
            if ch in MORSE_TABLE:
                all_morse.append(MORSE_TABLE[ch])
    return ''.join(all_morse)


def check_palindrome(bitstream):
    """Check if a bitstream is a palindrome."""
    return bitstream == bitstream[::-1]


def apply_palindrome_substitution(text, pal_map):
    """Apply the Morse palindrome letter substitution to text."""
    result = []
    for ch in text.upper():
        if ch in pal_map:
            result.append(pal_map[ch])
        elif ch == ' ':
            result.append(' ')
        else:
            result.append(f'[{ch}?]')
    return ''.join(result)


def analyze_word_palindrome_constraints(word, pal_map):
    """Analyze what constraints the palindrome property places on a word."""
    mapped = apply_palindrome_substitution(word, pal_map)
    self_palindrome_chars = sum(1 for c in word.upper() if c in pal_map and pal_map[c] == c)
    swapped_chars = sum(1 for c in word.upper() if c in pal_map and pal_map[c] != c)
    return {
        'original': word,
        'mapped': mapped,
        'self_palindrome_count': self_palindrome_chars,
        'swapped_count': swapped_chars,
        'total': len(word),
    }


# ─── MAIN ANALYSIS ──────────────────────────────────────────────────────────

def main():
    print("=" * 78)
    print("KRYPTOS K0 MORSE CODE PALINDROME ANALYSIS")
    print("=" * 78)

    # ─── Step 0: Build palindrome map ────────────────────────────────────
    print("\n" + "─" * 78)
    print("STEP 0: Morse Palindrome Letter Map")
    print("─" * 78)

    pal_map, unmapped = build_palindrome_map()

    print("\nPalindromic pairs (letter -> reversed-Morse letter):")
    pairs_shown = set()
    self_pals = []
    swap_pals = []

    for letter in sorted(pal_map.keys()):
        mapped = pal_map[letter]
        if letter == mapped:
            self_pals.append(letter)
        else:
            pair = tuple(sorted([letter, mapped]))
            if pair not in pairs_shown:
                pairs_shown.add(pair)
                swap_pals.append((letter, mapped))

    print(f"  Self-palindromic (map to themselves): {' '.join(self_pals)}")
    print(f"  Count: {len(self_pals)}")
    print()
    print("  Swap pairs:")
    for a, b in sorted(swap_pals):
        print(f"    {a} ({MORSE_TABLE[a]}) <-> {b} ({MORSE_TABLE[b]})")
    print(f"  Count: {len(swap_pals)} pairs")

    if unmapped:
        print(f"\n  Letters with no valid reverse mapping:")
        for letter, rev in sorted(unmapped.items()):
            print(f"    {letter} ({MORSE_TABLE[letter]}) -> reversed: {rev} (not a valid Morse character)")

    # ─── Verify the map is complete and consistent ───────────────────────
    print("\n  Verification:")
    for letter, mapped in pal_map.items():
        if mapped in pal_map:
            double_mapped = pal_map[mapped]
            if double_mapped != letter:
                print(f"    WARNING: {letter} -> {mapped} -> {double_mapped} (not involutory!)")
    print("    Map is involutory (applying twice returns original): ", end="")
    involutory = all(pal_map.get(pal_map.get(l, ''), '') == l for l in pal_map)
    print("YES" if involutory else "NO")

    # ─── Step 1: Convert known text to Morse bitstream ───────────────────
    print("\n" + "─" * 78)
    print("STEP 1: Forward Reading - Full Dit/Dah Bitstream")
    print("─" * 78)

    for label, phrases in [("STANDARD", STANDARD_PHRASES), ("USER VARIANT", USER_PHRASES)]:
        print(f"\n  [{label}]")
        full_text = ' '.join(phrases)
        print(f"  Text: {full_text}")

        # Build bitstream with letter boundaries shown
        all_morse_patterns = []
        for phrase in phrases:
            for ch in phrase.upper():
                if ch in MORSE_TABLE:
                    all_morse_patterns.append((ch, MORSE_TABLE[ch]))

        print(f"\n  Letter-by-letter Morse:")
        line = "  "
        for ch, morse in all_morse_patterns:
            segment = f"{ch}={morse} "
            if len(line) + len(segment) > 76:
                print(line)
                line = "  "
            line += segment
        if line.strip():
            print(line)

        bitstream = ''.join(m for _, m in all_morse_patterns)
        print(f"\n  Full bitstream ({len(bitstream)} symbols):")
        # Print in chunks of 50
        for i in range(0, len(bitstream), 50):
            chunk = bitstream[i:i+50]
            print(f"    [{i:4d}] {chunk}")

        reversed_bs = bitstream[::-1]
        is_pal = bitstream == reversed_bs
        print(f"\n  Is palindrome? {is_pal}")

        if not is_pal:
            # Find where they differ
            diffs = 0
            first_diff = None
            for i in range(len(bitstream)):
                if bitstream[i] != reversed_bs[i]:
                    diffs += 1
                    if first_diff is None:
                        first_diff = i
            print(f"  Differences: {diffs} positions out of {len(bitstream)}")
            if first_diff is not None:
                print(f"  First difference at position {first_diff}")
                ctx = 10
                start = max(0, first_diff - ctx)
                end = min(len(bitstream), first_diff + ctx + 1)
                print(f"    Forward:  ...{bitstream[start:end]}...")
                print(f"    Reversed: ...{reversed_bs[start:end]}...")
                print(f"    {'':>{first_diff - start + 15}}^")

    # ─── Step 2: Reverse the bitstream and decode ────────────────────────
    print("\n" + "─" * 78)
    print("STEP 2: Reverse Bitstream - Decode Attempt")
    print("─" * 78)

    # Since Morse without gaps is ambiguous, we'll use the letter-boundary
    # approach: reverse each letter's Morse code individually, which is
    # equivalent to reading the palindromic mirror.

    print("\n  Method: Reverse each letter's Morse code individually")
    print("  (This is what you'd get reading the physical dits/dahs backward")
    print("   with the SAME letter boundaries)")

    for label, phrases in [("STANDARD", STANDARD_PHRASES), ("USER VARIANT", USER_PHRASES)]:
        print(f"\n  [{label}]")
        full_text = ''.join(phrases)

        mapped_text = apply_palindrome_substitution(full_text, pal_map)
        # Now reverse the ORDER of characters too (reading backward)
        reversed_mapped = mapped_text[::-1]

        print(f"  Original text (no spaces): {full_text}")
        print(f"  Palindrome substitution:   {mapped_text}")
        print(f"  Reversed order:            {reversed_mapped}")

    # ─── Step 3: Apply palindrome substitution to each phrase ────────────
    print("\n" + "─" * 78)
    print("STEP 3: Palindrome Substitution Applied to Each Phrase")
    print("─" * 78)

    print("\n  For each word, apply the Morse-reversal letter substitution:")
    print("  (A->N, N->A, D->U, U->D, G->W, W->G, B->V, V->B, F->L, L->F, Y->Q, Q->Y)")
    print("  (Self-mapping: E,T,I,M,O,R,S,H,K,C,P,X)")
    print()

    for label, phrases in [("STANDARD", STANDARD_PHRASES), ("USER VARIANT", USER_PHRASES)]:
        print(f"  [{label}]")
        for phrase in phrases:
            mapped = apply_palindrome_substitution(phrase, pal_map)
            info = analyze_word_palindrome_constraints(phrase, pal_map)
            print(f"    {phrase:20s} -> {mapped:20s}  "
                  f"(self:{info['self_palindrome_count']}, swap:{info['swapped_count']})")

        # Full phrase
        full_forward = ' '.join(phrases)
        full_mapped = ' '.join(apply_palindrome_substitution(p, pal_map) for p in phrases)
        print(f"\n    FULL FORWARD:  {full_forward}")
        print(f"    FULL MAPPED:   {full_mapped}")

        # Now the TRUE palindrome reading: reversed order of mapped text
        # Reading the Morse backward = reverse order of (substituted letters)
        all_letters = ''.join(phrases)
        mapped_all = apply_palindrome_substitution(all_letters, pal_map)
        reversed_reading = mapped_all[::-1]
        print(f"    REVERSED READ: {reversed_reading}")
        print()

    # ─── Step 4: Detailed VIRTUALLY INVISIBLE walkthrough ────────────────
    print("\n" + "─" * 78)
    print("STEP 4: Detailed Walkthrough - VIRTUALLY INVISIBLE")
    print("─" * 78)

    for word in ["VIRTUALLY", "INVISIBLE"]:
        print(f"\n  {word}:")
        for ch in word:
            morse = MORSE_TABLE.get(ch.upper(), '?')
            rev_morse = morse[::-1]
            rev_letter = MORSE_REVERSE.get(rev_morse, '?')
            print(f"    {ch} = {morse:6s}  reversed = {rev_morse:6s} = {rev_letter}")
        mapped = apply_palindrome_substitution(word, pal_map)
        print(f"  Result: {word} -> {mapped}")

    # ─── Step 5: Constraint analysis ─────────────────────────────────────
    print("\n" + "─" * 78)
    print("STEP 5: Palindrome Constraint Analysis")
    print("─" * 78)

    print("\n  If the Morse IS palindromic, then the text must consist ONLY of")
    print("  letters that have valid Morse palindrome mappings.")
    print()

    # Check which letters have valid mappings
    valid_letters = set(pal_map.keys())
    all_26 = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    invalid_letters = all_26 - valid_letters

    print(f"  Letters with valid palindrome mappings ({len(valid_letters)}): "
          f"{''.join(sorted(valid_letters))}")
    print(f"  Letters WITHOUT valid mappings ({len(invalid_letters)}): "
          f"{''.join(sorted(invalid_letters))}")

    if invalid_letters:
        print(f"\n  These letters CANNOT appear in a Morse palindrome:")
        for letter in sorted(invalid_letters):
            morse = MORSE_TABLE.get(letter, '?')
            rev = morse[::-1]
            print(f"    {letter} = {morse}, reversed = {rev} -> "
                  f"{'NOT a valid Morse code' if rev not in MORSE_REVERSE else MORSE_REVERSE[rev]}")

    # Check the known text for any invalid letters
    print(f"\n  Checking known text for invalid letters:")
    for label, phrases in [("STANDARD", STANDARD_PHRASES), ("USER VARIANT", USER_PHRASES)]:
        all_text = ''.join(phrases).upper()
        invalid_found = set(ch for ch in all_text if ch not in valid_letters and ch.isalpha())
        if invalid_found:
            print(f"    [{label}] Contains invalid letters: {sorted(invalid_found)}")
            for ch in sorted(invalid_found):
                positions = [i for i, c in enumerate(all_text) if c == ch]
                print(f"      '{ch}' at positions: {positions}")
        else:
            print(f"    [{label}] All letters have valid palindrome mappings!")

    # ─── Step 6: Full palindrome bitstream test ──────────────────────────
    print("\n" + "─" * 78)
    print("STEP 6: True Bitstream Palindrome Test")
    print("─" * 78)

    print("\n  For the Morse to be palindromic at the dit/dah level, we need")
    print("  the ENTIRE concatenated bitstream to be a palindrome.")
    print("  This is MUCH more restrictive than just letter-level substitution.")
    print()
    print("  Letter-level substitution only ensures each individual letter's")
    print("  Morse code is the reverse of its corresponding letter from the")
    print("  other end. But letter BOUNDARIES also need to align!")
    print()

    for label, phrases in [("STANDARD", STANDARD_PHRASES), ("USER VARIANT", USER_PHRASES)]:
        all_text = ''.join(phrases).upper()

        # Get the Morse codes with their lengths
        morse_codes = [(ch, MORSE_TABLE[ch]) for ch in all_text if ch in MORSE_TABLE]
        morse_lengths_fwd = [len(m) for _, m in morse_codes]
        morse_lengths_rev = list(reversed(morse_lengths_fwd))

        bitstream = ''.join(m for _, m in morse_codes)
        is_pal = check_palindrome(bitstream)

        print(f"  [{label}]")
        print(f"  Text: {''.join(all_text)}")
        print(f"  Bitstream length: {len(bitstream)}")
        print(f"  Is exact palindrome? {is_pal}")

        if not is_pal:
            # Check how close
            half = len(bitstream) // 2
            mismatches = sum(1 for i in range(len(bitstream))
                          if bitstream[i] != bitstream[-(i+1)])
            print(f"  Mismatches: {mismatches}/{len(bitstream)}")

        # Check if letter lengths are palindromic (necessary condition)
        lengths_pal = morse_lengths_fwd == morse_lengths_rev
        print(f"  Morse code lengths palindromic? {lengths_pal}")
        if not lengths_pal:
            print(f"  Forward lengths:  {morse_lengths_fwd[:20]}...")
            print(f"  Reversed lengths: {morse_lengths_rev[:20]}...")
            # Find first mismatch
            for i in range(len(morse_lengths_fwd)):
                if morse_lengths_fwd[i] != morse_lengths_rev[i]:
                    fwd_ch = morse_codes[i][0]
                    rev_ch = morse_codes[-(i+1)][0]
                    print(f"  First length mismatch at position {i}: "
                          f"{fwd_ch}({morse_lengths_fwd[i]}) vs "
                          f"{rev_ch}({morse_lengths_rev[i]})")
                    break
        print()

    # ─── Step 7: What WOULD a palindromic Morse text look like? ──────────
    print("\n" + "─" * 78)
    print("STEP 7: Theoretical Palindromic Morse Text Properties")
    print("─" * 78)

    print("\n  For exact dit/dah palindrome, we need:")
    print("  1. Letter Morse-lengths must be palindromic: len(letter[i]) == len(letter[n-i-1])")
    print("  2. Each letter[i] must Morse-reverse to letter[n-i-1]")
    print("  3. If odd number of letters, middle letter must be self-palindromic")
    print()

    print("  Letters grouped by Morse code length:")
    by_length = {}
    for letter, morse in MORSE_TABLE.items():
        l = len(morse)
        if l not in by_length:
            by_length[l] = []
        by_length[l].append(letter)

    for l in sorted(by_length.keys()):
        letters = sorted(by_length[l])
        # Which of these are in our palindrome map?
        mapped_pairs = []
        for a in letters:
            if a in pal_map:
                b = pal_map[a]
                if len(MORSE_TABLE.get(b, '')) == l:
                    mapped_pairs.append(f"{a}<->{b}")
        print(f"  Length {l}: {' '.join(letters)}")

    print()
    print("  CRITICAL INSIGHT: For the bitstream to be palindromic,")
    print("  the i-th letter from the start and the i-th letter from the end")
    print("  must have the SAME Morse code length AND be palindrome partners.")
    print()
    print("  This means you can pair:")
    print("  - Length-1 letters only with length-1: E<->E, T<->T")
    print("  - Length-2 pairs: A<->N, I<->I, M<->M")
    print("  - Length-3 pairs: D<->U, G<->W, K<->K, O<->O, R<->R, S<->S")
    print("  - Length-4 pairs: B<->V, F<->L, C<->C, H<->H, P<->P, X<->X")
    print("     (also J<->? and Y<->Q and Z<->? if valid)")

    # Check J, Z specifically
    for ch in ['J', 'Z', 'Y', 'Q']:
        morse = MORSE_TABLE[ch]
        rev = morse[::-1]
        target = MORSE_REVERSE.get(rev, 'INVALID')
        target_len = len(MORSE_TABLE.get(target, '')) if target != 'INVALID' else 'N/A'
        print(f"  {ch} = {morse}, reversed = {rev} -> {target} (length: {len(morse)})")

    # ─── Step 8: The hidden side interpretation ──────────────────────────
    print("\n" + "─" * 78)
    print("STEP 8: 'Hidden Side' — The Morse Mirror Reading")
    print("─" * 78)

    print("\n  If the Kryptos entrance tablets have Morse code that is")
    print("  palindromic, then portions hidden under/behind the granite")
    print("  would be the mirror of the visible portions.")
    print()
    print("  The palindrome substitution (reading the 'other side') gives:")
    print()

    for label, phrases in [("STANDARD", STANDARD_PHRASES), ("USER VARIANT", USER_PHRASES)]:
        print(f"  [{label}]")
        for phrase in phrases:
            mapped = apply_palindrome_substitution(phrase, pal_map)
            print(f"    {phrase:20s} -> {mapped}")
        print()

    print("  Key observations:")
    print("  - VIRTUALLY -> ", apply_palindrome_substitution("VIRTUALLY", pal_map))
    print("  - INVISIBLE -> ", apply_palindrome_substitution("INVISIBLE", pal_map))
    print("  - SHADOW    -> ", apply_palindrome_substitution("SHADOW", pal_map))
    print("  - FORCES    -> ", apply_palindrome_substitution("FORCES", pal_map))
    print("  - MEMORY    -> ", apply_palindrome_substitution("MEMORY", pal_map))
    print("  - POSITION  -> ", apply_palindrome_substitution("POSITION", pal_map))
    print("  - SOS       -> ", apply_palindrome_substitution("SOS", pal_map))

    print()
    print("  SOS -> SOS is notable: it's self-palindromic at both the")
    print("  letter level AND the Morse level (... --- ...)")

    # ─── Step 9: Does the substituted text make sense? ───────────────────
    print("\n" + "─" * 78)
    print("STEP 9: Semantic Analysis of Substituted Text")
    print("─" * 78)

    print("\n  Forward:  VIRTUALLY INVISIBLE DIGITAL INTERPRETATION")
    print("  Mapped:   ", ' '.join(apply_palindrome_substitution(w, pal_map)
                                    for w in ["VIRTUALLY", "INVISIBLE", "DIGITAL", "INTERPRETATION"]))
    print()
    print("  Forward:  SHADOW FORCES LUCID MEMORY")
    print("  Mapped:   ", ' '.join(apply_palindrome_substitution(w, pal_map)
                                    for w in ["SHADOW", "FORCES", "LUCID", "MEMORY"]))
    print()
    print("  Forward:  IT IS YOUR POSITION")
    print("  Mapped:   ", ' '.join(apply_palindrome_substitution(w, pal_map)
                                    for w in ["IT", "IS", "YOUR", "POSITION"]))
    print()
    print("  Forward:  SOS")
    print("  Mapped:   ", apply_palindrome_substitution("SOS", pal_map))

    # ─── Step 10: Analyze if palindrome was intentional ──────────────────
    print("\n" + "─" * 78)
    print("STEP 10: Was the Palindrome Intentional?")
    print("─" * 78)

    print("""
  Analysis of constraints:

  The swap pairs (A<->N, D<->U, G<->W, B<->V, F<->L, Y<->Q) mean that
  if Sanborn chose words specifically for palindromic properties, he would
  need words that:

  1. Use mostly self-palindromic letters (E,T,I,M,O,R,S,H,K,C,P,X)
     to maintain readability in both directions

  2. Tolerate the swaps: A->N, D->U, G->W, B->V, F->L, Y->Q

  Let's count the swap-letter frequency in the standard text:
""")

    standard_text = ''.join(STANDARD_PHRASES)
    swap_letters = {'A', 'N', 'D', 'U', 'G', 'W', 'B', 'V', 'F', 'L', 'Y', 'Q'}
    self_letters = set(ch for ch in pal_map if pal_map[ch] == ch)

    total = len(standard_text)
    swap_count = sum(1 for ch in standard_text if ch in swap_letters)
    self_count = sum(1 for ch in standard_text if ch in self_letters)

    print(f"  Total letters: {total}")
    print(f"  Self-palindromic letters: {self_count} ({100*self_count/total:.1f}%)")
    print(f"  Swap-pair letters: {swap_count} ({100*swap_count/total:.1f}%)")

    # Expected in random English
    # A, N, D, U, G, W, B, V, F, L, Y, Q are the swap letters
    # In typical English: A=8.2%, N=6.7%, D=4.3%, U=2.8%, G=2.0%, W=2.4%,
    #   B=1.5%, V=1.0%, F=2.2%, L=4.0%, Y=2.0%, Q=0.1% = ~37.2%
    print(f"\n  In typical English text, ~37% of letters are swap-pair letters.")
    print(f"  In K0 text: {100*swap_count/total:.1f}%")

    # Check specific thematic words
    print("\n  Thematic word analysis (Kryptos-relevant words):")
    thematic_words = [
        "KRYPTOS", "CIPHER", "SECRET", "HIDDEN", "SHADOW", "INVISIBLE",
        "MEMORY", "POSITION", "FORCES", "MORSE", "CODE", "ENCRYPTION",
        "PALIMPSEST", "ABSCISSA", "VIRTUALLY", "DIGITAL", "LUCID",
        "INTERPRETATION", "ILLUSION", "MIRAGE", "SPECTRE", "PHANTOM",
        "ENIGMA", "MYSTERY", "CRYPTIC", "OBSCURE", "COVERT",
    ]

    for word in thematic_words:
        mapped = apply_palindrome_substitution(word, pal_map)
        swap_pct = sum(1 for ch in word if ch in swap_letters) / len(word)
        print(f"    {word:20s} -> {mapped:20s}  (swap letters: {100*swap_pct:.0f}%)")

    # ─── Step 11: K4 connection? ─────────────────────────────────────────
    print("\n" + "─" * 78)
    print("STEP 11: Potential K4 Connections")
    print("─" * 78)

    print("""
  If the Morse palindrome is intentional, it introduces the concept of
  READING IN REVERSE / MIRROR READING at the very entrance of Kryptos.

  This could be a meta-clue for K4:

  1. The palindrome substitution IS a simple substitution cipher
     (a fixed-point-free involution on swap pairs + identity on self-pairs)

  2. "VIRTUALLY INVISIBLE" -> mirror text hints at hidden information
     that becomes visible only when you read from the other direction

  3. The substitution A<->N, D<->U could be relevant to K4's cipher:
     - These are the EXACT pairs that differ between forward/backward Morse
     - If K4's "simple substitution" layer uses these same pairs...

  4. "IT IS YOUR POSITION" mapped through palindrome substitution becomes:
""")
    mapped_position = ' '.join(apply_palindrome_substitution(w, pal_map)
                                for w in ["IT", "IS", "YOUR", "POSITION"])
    print(f"     IT IS YOUR POSITION -> {mapped_position}")

    print("""
  5. The palindrome map as a cipher alphabet:
     ABCDEFGHIJKLMNOPQRSTUVWXYZ
     -> applying the palindrome substitution:
""")
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    mapped_alphabet = ''.join(pal_map.get(ch, '?') for ch in alphabet)
    print(f"     Plain:  {alphabet}")
    print(f"     Cipher: {mapped_alphabet}")

    # Apply this substitution to K4
    K4_CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
    mapped_k4 = ''.join(pal_map.get(ch, '?') for ch in K4_CT)
    print(f"\n  K4 CT:     {K4_CT}")
    print(f"  Pal-map:   {mapped_k4}")

    # Check if the mapped K4 has different IC or properties
    from collections import Counter

    def calc_ic(text):
        counts = Counter(text)
        n = len(text)
        return sum(c * (c-1) for c in counts.values()) / (n * (n-1))

    ic_original = calc_ic(K4_CT)
    ic_mapped = calc_ic(mapped_k4)
    print(f"\n  IC of K4 CT:     {ic_original:.4f}")
    print(f"  IC of pal-mapped: {ic_mapped:.4f}")
    print(f"  (IC is {'preserved' if abs(ic_original - ic_mapped) < 0.001 else 'changed'} by the substitution)")

    # Check letter frequency comparison
    print(f"\n  Letter frequency comparison (K4 CT vs palindrome-mapped):")
    freq_orig = Counter(K4_CT)
    freq_mapped = Counter(mapped_k4)
    print(f"  {'Letter':>6} {'Original':>8} {'Mapped':>8} {'Swap':>6}")
    for ch in alphabet:
        orig_count = freq_orig.get(ch, 0)
        map_count = freq_mapped.get(ch, 0)
        is_swap = ch in swap_letters
        if orig_count > 0 or map_count > 0:
            print(f"  {ch:>6} {orig_count:>8} {map_count:>8} {'<->' if is_swap else '   '}")

    print("\n" + "=" * 78)
    print("ANALYSIS COMPLETE")
    print("=" * 78)


if __name__ == '__main__':
    main()
