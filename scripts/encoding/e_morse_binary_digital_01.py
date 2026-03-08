#!/usr/bin/env python3
"""
Cipher: encoding/binary
Family: encoding
Status: active
Keyspace: ~500 configs
Last run: 2026-03-08
Best score: TBD

Hypothesis: "DIGETAL INTERPRETATIU" = "DIGITAL INTERPRETATION" = instruction to
reinterpret the Morse code as a binary digital signal. Test all sensible
binary encoding schemes (symbol-only, timed waveform, Baudot/ITA2, ASCII)
with multiple framings, polarities, and bit widths.

Two data sources:
  A) Message letters only (VIRTUALLY INVISIBLE DIGETAL INTERPRETATIU ...)
  B) Full token stream including extra E padding characters
"""

import sys
import os
import string
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

# ── MORSE CODE TABLE ─────────────────────────────────────────────────────────
MORSE = {
    'A': '.-',    'B': '-...',  'C': '-.-.',  'D': '-..',
    'E': '.',     'F': '..-.',  'G': '--.',   'H': '....',
    'I': '..',    'J': '.---',  'K': '-.-',   'L': '.-..',
    'M': '--',    'N': '-.',    'O': '---',   'P': '.--.',
    'Q': '--.-',  'R': '.-.',   'S': '...',   'T': '-',
    'U': '..-',   'V': '...-',  'W': '.--',   'X': '-..-',
    'Y': '-.--',  'Z': '--..',
}

# ── K0 DATA ──────────────────────────────────────────────────────────────────

# Misspelling-correct phrases from sculpture
PHRASES_MISSPELLED = [
    "VIRTUALLY INVISIBLE",
    "DIGETAL INTERPRETATIU",
    "SHADOW FORCES",
    "LUCID MEMORY",
    "T IS YOUR POSITION",
    "SOS",
    "RQ",
]

# Standard-spelling variant for comparison
PHRASES_STANDARD = [
    "VIRTUALLY INVISIBLE",
    "DIGITAL INTERPRETATION",
    "SHADOW FORCES",
    "LUCID MEMORY",
    "T IS YOUR POSITION",
    "SOS",
    "RQ",
]

# Full token stream from e01_morse_e_extraction.py (community consensus)
# uppercase = message letter, lowercase 'e' = extra E padding
MORSE_TOKENS = [
    'e', 'e',  # 2 E's before VIRTUALLY
    'V', 'I', 'R', 'T', 'U', 'A', 'L', 'L', 'Y',
    'e',  # 1 E after VIRTUALLY
    'e', 'e', 'e', 'e', 'e',  # 5 E's before INVISIBLE
    'I', 'N', 'V', 'I', 'S', 'I', 'B', 'L', 'E',
    'e',  # 1 E before DIGETAL
    'D', 'I', 'G', 'E', 'T', 'A', 'L',
    'e', 'e', 'e',  # 3 E's after DIGETAL
    'I', 'N', 'T', 'E', 'R', 'P', 'R', 'E', 'T', 'A', 'T', 'I', 'U',
    'e', 'e',  # 2 E's before SHADOW
    'S', 'H', 'A', 'D', 'O', 'W',
    'e', 'e',  # 2 E's after SHADOW
    'F', 'O', 'R', 'C', 'E', 'S',
    'e', 'e', 'e', 'e', 'e',  # 5 E's after FORCES
    'L', 'U', 'C', 'I', 'D',
    'e', 'e', 'e',  # 3 E's after LUCID
    'M', 'E', 'M', 'O', 'R', 'Y',
    'e',  # 1 E after MEMORY
    'T', 'I', 'S', 'Y', 'O', 'U', 'R',
    'P', 'O', 'S', 'I', 'T', 'I', 'O', 'N',
    'e',  # 1 E after POSITION
    'S', 'O', 'S',
    'R', 'Q',
]

# ── Baudot / ITA2 tables ─────────────────────────────────────────────────────
# 5-bit Baudot (Murray code / ITA2)
BAUDOT_LTRS = {
    0b00000: '\0', 0b00100: ' ', 0b00001: 'E', 0b00010: '\n',
    0b00011: 'A', 0b00101: 'S', 0b00110: 'I', 0b00111: 'U',
    0b01000: '\r', 0b01001: 'D', 0b01010: 'R', 0b01011: 'J',
    0b01100: 'N', 0b01101: 'F', 0b01110: 'C', 0b01111: 'K',
    0b10000: 'T', 0b10001: 'Z', 0b10010: 'L', 0b10011: 'W',
    0b10100: 'H', 0b10101: 'Y', 0b10110: 'P', 0b10111: 'Q',
    0b11000: 'O', 0b11001: 'B', 0b11010: 'G', 0b11011: 'FIGS',
    0b11100: 'M', 0b11101: 'X', 0b11110: 'V', 0b11111: 'LTRS',
}

BAUDOT_FIGS = {
    0b00000: '\0', 0b00100: ' ', 0b00001: '3', 0b00010: '\n',
    0b00011: '-', 0b00101: "'", 0b00110: '8', 0b00111: '7',
    0b01000: '\r', 0b01001: '$', 0b01010: '4', 0b01011: "'",
    0b01100: ',', 0b01101: '!', 0b01110: ':', 0b01111: '(',
    0b10000: '5', 0b10001: '"', 0b10010: ')', 0b10011: '2',
    0b10100: '#', 0b10101: '6', 0b10110: '0', 0b10111: '1',
    0b11000: '9', 0b11001: '?', 0b11010: '&', 0b11011: 'FIGS',
    0b11100: '.', 0b11101: '/', 0b11110: ';', 0b11111: 'LTRS',
}


# ── HELPER FUNCTIONS ─────────────────────────────────────────────────────────

def phrase_to_morse(phrase):
    """Convert a phrase to Morse, words separated by ' / '."""
    words = phrase.split()
    return " / ".join(" ".join(MORSE[ch] for ch in word if ch in MORSE) for word in words)


def all_phrases_to_morse(phrases):
    """Join all phrases with ' / ' separator."""
    return " / ".join(phrase_to_morse(p) for p in phrases)


def tokens_to_morse_no_gaps(tokens):
    """Convert token list to Morse patterns, no gap encoding."""
    parts = []
    for t in tokens:
        ch = t.upper()
        if ch in MORSE:
            parts.append(MORSE[ch])
    return parts


def symbol_stream(morse_text, dot='0', dash='1'):
    """Raw dot/dash -> binary, ignoring all gaps."""
    return ''.join(dot if c == '.' else dash for c in morse_text if c in '.-')


def timed_stream(morse_text, mark='1', space='0'):
    """ITU timed Morse waveform encoding."""
    words = morse_text.split(' / ')
    out = []
    for wi, word in enumerate(words):
        letters = word.split()
        for li, letter in enumerate(letters):
            for si, sym in enumerate(letter):
                out.append(mark * (1 if sym == '.' else 3))
                if si != len(letter) - 1:
                    out.append(space)           # intra-element gap
            if li != len(letters) - 1:
                out.append(space * 3)           # inter-letter gap
        if wi != len(words) - 1:
            out.append(space * 7)               # inter-word gap
    return ''.join(out)


def tokens_timed_stream(tokens, mark='1', space='0'):
    """ITU timed waveform from the full token list (preserving E pads as letters)."""
    out = []
    for ti, token in enumerate(tokens):
        ch = token.upper()
        if ch not in MORSE:
            continue
        morse = MORSE[ch]
        for si, sym in enumerate(morse):
            out.append(mark * (1 if sym == '.' else 3))
            if si != len(morse) - 1:
                out.append(space)               # intra-element
        # inter-letter gap (simplified: always 3 units between letters)
        if ti < len(tokens) - 1:
            out.append(space * 3)
    return ''.join(out)


def invert_bits(bits):
    return ''.join('1' if b == '0' else '0' for b in bits)


def decode_ascii(bits, width, offset=0):
    """Decode fixed-width binary to ASCII."""
    chars = []
    for i in range(offset, len(bits) - width + 1, width):
        val = int(bits[i:i + width], 2)
        if 32 <= val <= 126:
            chars.append(chr(val))
        else:
            chars.append('\x00')  # non-printable marker
    return ''.join(chars)


def decode_baudot(bits, offset=0):
    """Decode 5-bit Baudot/ITA2."""
    chars = []
    mode = BAUDOT_LTRS
    for i in range(offset, len(bits) - 4, 5):
        val = int(bits[i:i + 5], 2)
        if val in mode:
            ch = mode[val]
            if ch == 'FIGS':
                mode = BAUDOT_FIGS
            elif ch == 'LTRS':
                mode = BAUDOT_LTRS
            elif ch in ('\0', '\n', '\r'):
                chars.append(' ')
            else:
                chars.append(ch)
        else:
            chars.append('?')
    return ''.join(chars)


def score_text(s):
    """Score how 'readable' a decoded string is."""
    if not s:
        return {'printable_ratio': 0, 'alpha_ratio': 0, 'word_hits': 0,
                'digraph_hits': 0, 'preview': '', 'length': 0}

    clean = s.replace('\x00', '.')
    printable = sum(c in string.printable for c in s)
    alpha = sum(c.isalpha() for c in s)
    upper = s.upper()

    # Check for K4-related keywords
    keywords = [
        'BERLIN', 'CLOCK', 'NORTH', 'EAST', 'WEST', 'SOUTH',
        'POSITION', 'SHADOW', 'LUCID', 'MEMORY', 'INVISIBLE',
        'CIA', 'SECRET', 'KRYPTOS', 'PALIMPSEST', 'ABSCISSA',
        'AGENT', 'MORSE', 'CODE', 'KEY', 'THE', 'AND',
        'MAGNETIC', 'COMPASS', 'POINT', 'DIGITAL', 'BETWEEN',
        'LAYER', 'SUBTLE', 'SHADING', 'SOS', 'HELP',
        'LANGLEY', 'VIRGINIA', 'DEFECTOR', 'SPY',
    ]
    word_hits = sum(1 for kw in keywords if kw in upper)

    # Check for common English digraphs
    common_digraphs = ['TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ON', 'AT', 'EN', 'ND']
    digraph_hits = sum(upper.count(dg) for dg in common_digraphs)

    return {
        'printable_ratio': printable / len(s) if s else 0,
        'alpha_ratio': alpha / len(s) if s else 0,
        'word_hits': word_hits,
        'digraph_hits': digraph_hits,
        'preview': clean[:120],
        'length': len(s),
    }


# ── BUILD ALL BITSTREAMS ─────────────────────────────────────────────────────

def build_streams():
    """Generate all bitstream variants to test."""
    streams = {}

    # --- Source A: Message-only (misspelled) ---
    morse_mis = all_phrases_to_morse(PHRASES_MISSPELLED)
    streams['A_sym_d0'] = symbol_stream(morse_mis, '0', '1')
    streams['A_sym_d1'] = symbol_stream(morse_mis, '1', '0')
    streams['A_timed_m1'] = timed_stream(morse_mis, '1', '0')
    streams['A_timed_m0'] = timed_stream(morse_mis, '0', '1')

    # --- Source B: Message-only (standard spelling) ---
    morse_std = all_phrases_to_morse(PHRASES_STANDARD)
    streams['B_sym_d0'] = symbol_stream(morse_std, '0', '1')
    streams['B_sym_d1'] = symbol_stream(morse_std, '1', '0')
    streams['B_timed_m1'] = timed_stream(morse_std, '1', '0')
    streams['B_timed_m0'] = timed_stream(morse_std, '0', '1')

    # --- Source C: Full token stream with E padding ---
    tok_morse = tokens_to_morse_no_gaps(MORSE_TOKENS)
    tok_flat = ''.join(tok_morse)
    streams['C_sym_d0'] = ''.join('0' if c == '.' else '1' for c in tok_flat)
    streams['C_sym_d1'] = ''.join('1' if c == '.' else '0' for c in tok_flat)
    streams['C_timed_m1'] = tokens_timed_stream(MORSE_TOKENS, '1', '0')
    streams['C_timed_m0'] = tokens_timed_stream(MORSE_TOKENS, '0', '1')

    # --- Source D: Individual phrase testing (misspelled) ---
    for i, phrase in enumerate(PHRASES_MISSPELLED):
        pm = phrase_to_morse(phrase)
        tag = f'D{i}_{phrase.replace(" ", "_")[:15]}'
        streams[f'{tag}_sym_d0'] = symbol_stream(pm, '0', '1')
        streams[f'{tag}_timed_m1'] = timed_stream(pm, '1', '0')

    # --- Add reversed versions of main streams ---
    for name in list(streams.keys()):
        if name.startswith(('A_', 'B_', 'C_')):
            streams[name + '_REV'] = streams[name][::-1]

    # --- Add inverted versions of main streams ---
    for name in list(streams.keys()):
        if name.startswith(('A_', 'B_', 'C_')) and not name.endswith('_REV'):
            streams[name + '_INV'] = invert_bits(streams[name])

    return streams


# ── MAIN TEST ─────────────────────────────────────────────────────────────────

def main():
    print("=" * 80)
    print("K0 Morse → Binary Digital Interpretation Test")
    print("=" * 80)

    streams = build_streams()
    print(f"\nGenerated {len(streams)} bitstreams to test")

    # Show bitstream lengths
    print("\nBitstream lengths:")
    for name in sorted(streams.keys()):
        if not name.startswith('D'):
            print(f"  {name:30s}: {len(streams[name]):5d} bits")

    results = []

    for name, bits in streams.items():
        if len(bits) < 5:
            continue

        # ASCII 7-bit
        for offset in range(7):
            decoded = decode_ascii(bits, 7, offset)
            scored = score_text(decoded)
            scored['stream'] = name
            scored['encoding'] = f'ASCII-7 off={offset}'
            results.append(scored)

        # ASCII 8-bit
        for offset in range(8):
            decoded = decode_ascii(bits, 8, offset)
            scored = score_text(decoded)
            scored['stream'] = name
            scored['encoding'] = f'ASCII-8 off={offset}'
            results.append(scored)

        # Baudot 5-bit
        for offset in range(5):
            decoded = decode_baudot(bits, offset)
            scored = score_text(decoded)
            scored['stream'] = name
            scored['encoding'] = f'Baudot off={offset}'
            results.append(scored)

        # 6-bit (A=0, B=1, ..., Z=25, 26-63=other)
        for offset in range(6):
            chars = []
            for i in range(offset, len(bits) - 5, 6):
                val = int(bits[i:i + 6], 2)
                if 0 <= val <= 25:
                    chars.append(chr(ord('A') + val))
                elif val == 26:
                    chars.append(' ')
                else:
                    chars.append('\x00')
            decoded = ''.join(chars)
            scored = score_text(decoded)
            scored['stream'] = name
            scored['encoding'] = f'6bit-AZ off={offset}'
            results.append(scored)

        # 5-bit direct (A=1..Z=26, 0=space, 27-31=punct)
        for offset in range(5):
            chars = []
            for i in range(offset, len(bits) - 4, 5):
                val = int(bits[i:i + 5], 2)
                if 1 <= val <= 26:
                    chars.append(chr(ord('A') + val - 1))
                elif val == 0:
                    chars.append(' ')
                else:
                    chars.append('\x00')
            decoded = ''.join(chars)
            scored = score_text(decoded)
            scored['stream'] = name
            scored['encoding'] = f'5bit-AZ off={offset}'
            results.append(scored)

    # Sort by composite score
    for r in results:
        r['composite'] = (
            r['word_hits'] * 10 +
            r['digraph_hits'] * 2 +
            r['alpha_ratio'] * 5 +
            r['printable_ratio'] * 3
        )

    results.sort(key=lambda r: r['composite'], reverse=True)

    print(f"\nTotal configs tested: {len(results)}")

    # Show top results
    print("\n" + "=" * 80)
    print("TOP 50 RESULTS (sorted by composite score)")
    print("=" * 80)
    for i, r in enumerate(results[:50]):
        preview = r['preview'].replace('\x00', '.')
        print(
            f"{i+1:3d}. [{r['composite']:6.2f}] "
            f"{r['stream']:30s} {r['encoding']:18s} "
            f"pr={r['printable_ratio']:.3f} al={r['alpha_ratio']:.3f} "
            f"wh={r['word_hits']} dg={r['digraph_hits']} "
            f"len={r['length']:3d} | {preview}"
        )

    # Special check: look for anything with word_hits > 0
    word_matches = [r for r in results if r['word_hits'] > 0]
    if word_matches:
        print(f"\n{'=' * 80}")
        print(f"KEYWORD MATCHES ({len(word_matches)} configs)")
        print("=" * 80)
        for r in word_matches[:30]:
            preview = r['preview'].replace('\x00', '.')
            print(
                f"  {r['stream']:30s} {r['encoding']:18s} "
                f"words={r['word_hits']} | {preview}"
            )

    # Special check: anything with alpha_ratio > 0.7
    high_alpha = [r for r in results if r['alpha_ratio'] > 0.7]
    if high_alpha:
        print(f"\n{'=' * 80}")
        print(f"HIGH ALPHA RATIO >0.7 ({len(high_alpha)} configs)")
        print("=" * 80)
        for r in high_alpha[:30]:
            preview = r['preview'].replace('\x00', '.')
            print(
                f"  {r['stream']:30s} {r['encoding']:18s} "
                f"alpha={r['alpha_ratio']:.3f} | {preview}"
            )

    # ── ADDITIONAL TEST: Binary E/non-E encoding ─────────────────────────────
    # Hypothesis: extra E's = 0, other letters = 1 (or vice versa)
    print(f"\n{'=' * 80}")
    print("SPECIAL: E-padding as binary signal (E=0, other=1)")
    print("=" * 80)

    e_binary = ''.join('0' if t == 'e' else '1' for t in MORSE_TOKENS)
    e_binary_inv = invert_bits(e_binary)
    print(f"  E-binary stream ({len(e_binary)} bits): {e_binary}")
    print(f"  Inverted:                        {e_binary_inv}")

    for label, bits in [("E=0", e_binary), ("E=1", e_binary_inv)]:
        for width in (5, 6, 7, 8):
            for offset in range(width):
                if width <= 5:
                    decoded = decode_baudot(bits, offset) if width == 5 else None
                else:
                    decoded = decode_ascii(bits, width, offset)
                if decoded:
                    scored = score_text(decoded)
                    if scored['printable_ratio'] > 0.3 or scored['word_hits'] > 0:
                        preview = scored['preview'].replace('\x00', '.')
                        print(
                            f"  {label} width={width} off={offset}: "
                            f"pr={scored['printable_ratio']:.3f} wh={scored['word_hits']} | {preview}"
                        )

    # ── ADDITIONAL TEST: Start after DIGITAL marker ──────────────────────────
    print(f"\n{'=' * 80}")
    print("SPECIAL: Bitstream starting AFTER 'DIGETAL' (instruction = 'digital interpretation')")
    print("=" * 80)

    # Find where DIGETAL ends in the token stream
    digetal_end = None
    msg = ''.join(t.upper() for t in MORSE_TOKENS)
    idx = msg.find('DIGETAL')
    if idx >= 0:
        digetal_end = idx + len('DIGETAL')
        print(f"  DIGETAL found at token positions, ends at index {digetal_end}")

    # Post-DIGETAL tokens
    post_tokens = []
    count = 0
    past_digetal = False
    for t in MORSE_TOKENS:
        if not past_digetal:
            if t.upper() == 'L' and count >= 6:  # end of DIGETAL
                past_digetal = True
                continue
            if t.upper() in 'DIGETAL' and count < 7:
                count += 1 if t.upper() != 'e' else 0
            continue
        post_tokens.append(t)

    # Simpler: just take everything after the DIGETAL letters
    found_d = False
    post_idx = 0
    running = ''
    for i, t in enumerate(MORSE_TOKENS):
        running += t.upper()
        if 'DIGETAL' in running and not found_d:
            found_d = True
            post_idx = i + 1
            break

    if found_d:
        remaining_tokens = MORSE_TOKENS[post_idx:]
        remaining_morse = tokens_to_morse_no_gaps(remaining_tokens)
        remaining_flat = ''.join(remaining_morse)
        bits_post = ''.join('0' if c == '.' else '1' for c in remaining_flat)
        bits_post_inv = invert_bits(bits_post)

        print(f"  Post-DIGETAL tokens: {len(remaining_tokens)}, bits: {len(bits_post)}")
        print(f"  Post-DIGETAL text: {''.join(t.upper() for t in remaining_tokens)}")

        for label, bits in [("post_d0", bits_post), ("post_d1", bits_post_inv)]:
            for width in (5, 7, 8):
                for offset in range(min(width, 3)):  # just test first few offsets
                    if width == 5:
                        decoded = decode_baudot(bits, offset)
                    else:
                        decoded = decode_ascii(bits, width, offset)
                    scored = score_text(decoded)
                    preview = scored['preview'].replace('\x00', '.')
                    if scored['printable_ratio'] > 0.3 or scored['word_hits'] > 0:
                        print(
                            f"  {label} w={width} off={offset}: "
                            f"pr={scored['printable_ratio']:.3f} al={scored['alpha_ratio']:.3f} "
                            f"wh={scored['word_hits']} | {preview}"
                        )

    # ── ADDITIONAL: SOS as frame sync ────────────────────────────────────────
    print(f"\n{'=' * 80}")
    print("SPECIAL: SOS (...---...) as frame synchronization marker")
    print("=" * 80)

    # SOS in symbol encoding = ...---...
    morse_full = all_phrases_to_morse(PHRASES_MISSPELLED)
    sym_bits = symbol_stream(morse_full, '0', '1')
    sos_pattern_01 = '000111000'  # dot=0 dash=1
    sos_pattern_10 = '111000111'  # dot=1 dash=0

    for label, pattern in [("SOS_d0", sos_pattern_01), ("SOS_d1", sos_pattern_10)]:
        idx = sym_bits.find(pattern)
        if idx >= 0:
            # Start decoding right after SOS
            after_sos = sym_bits[idx + len(pattern):]
            print(f"  {label} found at bit {idx}, {len(after_sos)} bits remain after")
            for width in (5, 7, 8):
                decoded = decode_ascii(after_sos, width) if width >= 7 else decode_baudot(after_sos)
                scored = score_text(decoded)
                preview = scored['preview'].replace('\x00', '.')
                print(f"    w={width}: pr={scored['printable_ratio']:.3f} wh={scored['word_hits']} | {preview}")

    # ── Summary statistics ───────────────────────────────────────────────────
    print(f"\n{'=' * 80}")
    print("SUMMARY")
    print("=" * 80)
    max_word = max(r['word_hits'] for r in results)
    max_alpha = max(r['alpha_ratio'] for r in results)
    max_print = max(r['printable_ratio'] for r in results)
    print(f"  Total configs tested:     {len(results)}")
    print(f"  Max keyword hits:         {max_word}")
    print(f"  Max alpha ratio:          {max_alpha:.4f}")
    print(f"  Max printable ratio:      {max_print:.4f}")
    print(f"  Configs with word hits:   {len([r for r in results if r['word_hits'] > 0])}")
    print(f"  Configs with alpha > 0.5: {len([r for r in results if r['alpha_ratio'] > 0.5])}")

    if max_word == 0 and max_alpha < 0.5:
        print("\n  RESULT: No clean signal found in naive binary interpretations.")
        print("  The hypothesis is NOT disproven but requires non-trivial framing.")


if __name__ == '__main__':
    main()
