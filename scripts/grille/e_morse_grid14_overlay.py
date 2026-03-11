#!/usr/bin/env python3
"""Morse code overlay on width-14 grid for Kryptos K4.

Cipher:    Two-system (Morse-derived null mask on 14-wide grid + substitution)
Family:    grille
Status:    active
Keyspace:  ~10K framings x multiple binary encodings x cipher variants x keywords
Last run:  never
Best score: n/a

HYPOTHESIS:
  K4 (97 chars) is written into a 14-wide grid (7 rows).
  At width 14, both cribs start at column 7, and column 6 is the ONLY
  column with zero crib chars. This suggests width 14 is structurally special.

  The Morse code from K0 (sculpture entrance) generates a binary pattern
  that, when overlaid on the 14-wide grid, selects 73 "real" positions
  and masks 24 "null" positions.

  After extracting 73 chars, apply substitution cipher to recover plaintext.

APPROACH:
  1. Generate multiple binary encodings of K0 Morse data
  2. For each encoding, try all offsets/framings onto the 7x14 grid
  3. Filter: must mask exactly 24 positions AND all 24 crib positions must be "keep"
  4. For surviving masks: try Vig/Beau/VBeau with thematic keywords
  5. Score by crib matching and quadgrams
"""
from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS,
)
from kryptos.kernel.scoring.ngram import NgramScorer
from kryptos.kernel.scoring.free_crib import score_free_fast

# ── K0 Morse Data ────────────────────────────────────────────────────────

MORSE = {
    'A': '.-',    'B': '-...',  'C': '-.-.',  'D': '-..',
    'E': '.',     'F': '..-.',  'G': '--.',   'H': '....',
    'I': '..',    'J': '.---',  'K': '-.-',   'L': '.-..',
    'M': '--',    'N': '-.',    'O': '---',   'P': '.--.',
    'Q': '--.-',  'R': '.-.',   'S': '...',   'T': '-',
    'U': '..-',   'V': '...-',  'W': '.--',   'X': '-..-',
    'Y': '-.--',  'Z': '--..',
}

# K0 token sequence (uppercase = message letter, lowercase 'e' = extra E separator)
MORSE_TOKENS = [
    'e', 'e',
    'V', 'I', 'R', 'T', 'U', 'A', 'L', 'L', 'Y',
    'e',
    'e', 'e', 'e', 'e', 'e',
    'I', 'N', 'V', 'I', 'S', 'I', 'B', 'L', 'E',
    'e',
    'D', 'I', 'G', 'E', 'T', 'A', 'L',
    'e', 'e', 'e',
    'I', 'N', 'T', 'E', 'R', 'P', 'R', 'E', 'T', 'A', 'T', 'I', 'U',
    'e', 'e',
    'S', 'H', 'A', 'D', 'O', 'W',
    'e', 'e',
    'F', 'O', 'R', 'C', 'E', 'S',
    'e', 'e', 'e', 'e', 'e',
    'L', 'U', 'C', 'I', 'D',
    'e', 'e', 'e',
    'M', 'E', 'M', 'O', 'R', 'Y',
    'e',
    'T', 'I', 'S', 'Y', 'O', 'U', 'R',
    'P', 'O', 'S', 'I', 'T', 'I', 'O', 'N',
    'e',
    'S', 'O', 'S',
    'R', 'Q',
]

CRIB_SET = set(CRIB_POSITIONS)
GRID_W = 14

# ── Binary Encodings ─────────────────────────────────────────────────────

def gen_symbol_stream(tokens, dot_val=0, dash_val=1):
    """Convert token sequence to symbol stream (dot/dash → binary)."""
    bits = []
    for t in tokens:
        letter = t.upper()
        morse = MORSE[letter]
        for sym in morse:
            bits.append(dot_val if sym == '.' else dash_val)
    return bits

def gen_token_binary(tokens, e_val=0, msg_val=1):
    """Convert token sequence to binary: extra-E → e_val, message letter → msg_val."""
    bits = []
    for t in tokens:
        bits.append(e_val if t == 'e' else msg_val)
    return bits

def gen_morse_length_binary(tokens, threshold=2):
    """Each token → 0 if Morse length < threshold, 1 if >= threshold."""
    bits = []
    for t in tokens:
        ml = len(MORSE[t.upper()])
        bits.append(0 if ml < threshold else 1)
    return bits

def gen_timed_waveform(tokens, dot_units=1, dash_units=3,
                        intra_gap=1, inter_gap=3, word_gap=7):
    """ITU timed waveform: mark=1, space=0."""
    bits = []
    for i, t in enumerate(tokens):
        letter = t.upper()
        morse = MORSE[letter]
        for j, sym in enumerate(morse):
            if sym == '.':
                bits.extend([1] * dot_units)
            else:
                bits.extend([1] * dash_units)
            if j < len(morse) - 1:
                bits.extend([0] * intra_gap)
        # Inter-letter gap (simplified: always 3)
        if i < len(tokens) - 1:
            bits.extend([0] * inter_gap)
    return bits

def gen_row_reading(tokens, width):
    """Write symbol stream into grid, read by rows. Returns the grid as flat bits."""
    symbols = gen_symbol_stream(tokens)
    # Pad to fill grid
    grid_size = ((len(symbols) + width - 1) // width) * width
    padded = symbols + [0] * (grid_size - len(symbols))
    return padded

def gen_col_reading(tokens, width):
    """Write symbol stream into grid by rows, read by columns."""
    symbols = gen_symbol_stream(tokens)
    rows = (len(symbols) + width - 1) // width
    grid_size = rows * width
    padded = symbols + [0] * (grid_size - len(symbols))

    result = []
    for c in range(width):
        for r in range(rows):
            result.append(padded[r * width + c])
    return result

def gen_diagonal_reading(tokens, width):
    """Write symbols into grid, read by diagonals."""
    symbols = gen_symbol_stream(tokens)
    rows = (len(symbols) + width - 1) // width
    grid_size = rows * width
    padded = symbols + [0] * (grid_size - len(symbols))

    result = []
    for d in range(rows + width - 1):
        for r in range(rows):
            c = d - r
            if 0 <= c < width:
                result.append(padded[r * width + c])
    return result


# ── Grid overlay ─────────────────────────────────────────────────────────

def overlay_on_grid(binary_seq, offset, ct_len=97, keep_val=1):
    """Overlay binary sequence on positions 0..ct_len-1 starting at offset.

    keep_val: which binary value means "keep" (not null).
    Returns set of null positions, or None if constraints violated.
    """
    null_positions = set()
    for pos in range(ct_len):
        idx = offset + pos
        if idx < 0 or idx >= len(binary_seq):
            # Out of bounds — treat as null or keep based on position
            bit = 1 - keep_val  # null
        else:
            bit = binary_seq[idx]

        if bit != keep_val:
            null_positions.add(pos)

    return null_positions

def check_mask_valid(null_positions, n_nulls=24):
    """Check if mask has exactly n_nulls nulls and none are crib positions."""
    if len(null_positions) != n_nulls:
        return False
    if null_positions & CRIB_SET:
        return False
    return True

# ── Decryption ───────────────────────────────────────────────────────────

def extract_73(null_positions):
    """Extract 73 chars by removing null positions."""
    return "".join(CT[i] for i in range(CT_LEN) if i not in null_positions)

def decrypt_vig(ct_str, key_str):
    pt = []
    klen = len(key_str)
    for i, c in enumerate(ct_str):
        k = ALPH_IDX[key_str[i % klen]]
        pt.append(ALPH[(ALPH_IDX[c] - k) % MOD])
    return "".join(pt)

def decrypt_beau(ct_str, key_str):
    pt = []
    klen = len(key_str)
    for i, c in enumerate(ct_str):
        k = ALPH_IDX[key_str[i % klen]]
        pt.append(ALPH[(k - ALPH_IDX[c]) % MOD])
    return "".join(pt)

def decrypt_vbeau(ct_str, key_str):
    pt = []
    klen = len(key_str)
    for i, c in enumerate(ct_str):
        k = ALPH_IDX[key_str[i % klen]]
        pt.append(ALPH[(ALPH_IDX[c] + k) % MOD])
    return "".join(pt)

# ── Thematic keywords ───────────────────────────────────────────────────

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN",
    "SCHEIDT", "BERLIN", "CLOCK", "ENIGMA", "COMPASS",
    "KOMPASS", "DEFECTOR", "COLOPHON", "ABSCISSA", "LUCID",
    "MEMORY", "POSITION", "INVISIBLE", "DIGITAL", "FORCES",
    "VIRTUALLY", "INTERPRET", "DIGETAL", "FIVE", "POINT",
    "NORTHEAST", "EAST", "NORTH", "MERIDIAN", "MATRIX",
    "CIPHER", "SECRET", "QUAGMIRE", "VERDIGRIS", "GNOMON",
]

# ── 2D grid-specific patterns ───────────────────────────────────────────

def gen_checkerboard(width, height, phase=0):
    """Checkerboard pattern: alternating 0/1."""
    bits = []
    for r in range(height):
        for c in range(width):
            bits.append((r + c + phase) % 2)
    return bits

def gen_column_mask(width, height, null_cols):
    """Mask specific columns as null."""
    bits = []
    for r in range(height):
        for c in range(width):
            bits.append(0 if c in null_cols else 1)
    return bits

def gen_diagonal_stripe(width, height, stripe_width=1, phase=0):
    """Diagonal stripe pattern."""
    period = stripe_width * 2
    bits = []
    for r in range(height):
        for c in range(width):
            bits.append(1 if ((r + c + phase) % period) < stripe_width else 0)
    return bits

def gen_border_mask(width, height, border_width=1):
    """Keep interior, null border."""
    bits = []
    for r in range(height):
        for c in range(width):
            if r < border_width or r >= height - border_width or \
               c < border_width or c >= width - border_width:
                bits.append(0)  # null
            else:
                bits.append(1)  # keep
    return bits

# ── Main ─────────────────────────────────────────────────────────────────

def main():
    print("=" * 80)
    print("MORSE CODE OVERLAY ON WIDTH-14 GRID — KRYPTOS K4")
    print("=" * 80)
    print(f"CT: {CT}")
    print(f"Grid: {GRID_W} wide, {(CT_LEN + GRID_W - 1) // GRID_W} rows")
    print(f"Target: 24 nulls, 73 kept, all crib positions kept")
    print()

    # Load scorer
    scorer = NgramScorer.from_file(REPO / "data" / "english_quadgrams.json")
    print(f"Loaded {len(scorer.log_probs)} quadgrams")
    print()

    # Generate all binary encodings
    encodings = {}

    # Symbol streams (dot/dash → 0/1 and inverted)
    encodings["sym_dot0_dash1"] = gen_symbol_stream(MORSE_TOKENS, 0, 1)
    encodings["sym_dot1_dash0"] = gen_symbol_stream(MORSE_TOKENS, 1, 0)

    # Token binary (E vs message)
    encodings["tok_e0_msg1"] = gen_token_binary(MORSE_TOKENS, 0, 1)
    encodings["tok_e1_msg0"] = gen_token_binary(MORSE_TOKENS, 1, 0)

    # Morse length binary (various thresholds)
    for thresh in [2, 3]:
        encodings[f"morse_len_lt{thresh}"] = gen_morse_length_binary(MORSE_TOKENS, thresh)

    # Timed waveform
    encodings["timed_itu"] = gen_timed_waveform(MORSE_TOKENS)

    # Grid readings of symbol stream at various widths
    for gw in [7, 8, 9, 10, 13, 14, 24, 31]:
        encodings[f"sym_grid{gw}_col"] = gen_col_reading(MORSE_TOKENS, gw)
        encodings[f"sym_grid{gw}_diag"] = gen_diagonal_reading(MORSE_TOKENS, gw)

    # Message-only (skip E separators) symbol stream
    msg_only = [t for t in MORSE_TOKENS if t != 'e']
    encodings["msg_sym_dot0"] = gen_symbol_stream(msg_only, 0, 1)
    encodings["msg_sym_dot1"] = gen_symbol_stream(msg_only, 1, 0)

    # 2D geometric patterns on 14-wide grid
    rows_14 = (CT_LEN + 13) // 14  # = 7
    encodings["checker_phase0"] = gen_checkerboard(14, rows_14, 0)
    encodings["checker_phase1"] = gen_checkerboard(14, rows_14, 1)

    # Column-6-null variants
    for extra_col in range(14):
        if extra_col == 6:
            continue
        encodings[f"col6_{extra_col}_null"] = gen_column_mask(14, rows_14, {6, extra_col})

    # Diagonal stripes
    for sw in [1, 2, 3]:
        for ph in range(sw * 2):
            encodings[f"diag_w{sw}_p{ph}"] = gen_diagonal_stripe(14, rows_14, sw, ph)

    # Border masks
    encodings["border_1"] = gen_border_mask(14, rows_14, 1)

    print(f"Generated {len(encodings)} binary encodings")
    for name, bits in sorted(encodings.items()):
        ones = sum(bits)
        zeros = len(bits) - ones
        print(f"  {name:30s}: {len(bits):5d} bits ({ones} ones, {zeros} zeros)")
    print()

    # Phase 1: Find all valid masks
    valid_masks = []  # (encoding_name, offset, keep_val, null_positions)

    t0 = time.time()
    total_checked = 0

    for enc_name, bits in encodings.items():
        max_offset = len(bits) - CT_LEN + 50  # Allow some overshoot
        min_offset = -50

        for offset in range(min_offset, max_offset + 1):
            for keep_val in [0, 1]:
                total_checked += 1
                nulls = overlay_on_grid(bits, offset, CT_LEN, keep_val)
                if check_mask_valid(nulls):
                    valid_masks.append((enc_name, offset, keep_val, nulls))

    t1 = time.time()
    print(f"Phase 1: Checked {total_checked} overlay configurations in {t1-t0:.1f}s")
    print(f"Valid masks found: {len(valid_masks)}")
    print()

    if valid_masks:
        print("Valid mask details:")
        for enc_name, offset, keep_val, nulls in valid_masks:
            null_sorted = sorted(nulls)
            extract = extract_73(nulls)

            # Show grid
            print(f"\n  Encoding: {enc_name}, offset={offset}, keep={keep_val}")
            print(f"  Nulls: {null_sorted}")
            print(f"  Extract: {extract}")

            # Grid visualization
            print(f"  Grid (K=keep, N=null, C=crib):")
            for r in range((CT_LEN + GRID_W - 1) // GRID_W):
                row_str = "    "
                for c in range(GRID_W):
                    pos = r * GRID_W + c
                    if pos >= CT_LEN:
                        break
                    if pos in CRIB_SET:
                        row_str += "C"
                    elif pos in nulls:
                        row_str += "N"
                    else:
                        row_str += "K"
                print(row_str)

    # Phase 2: Try decryption on all valid masks
    if not valid_masks:
        print("No valid masks found. Trying relaxed search (22-26 nulls)...")
        for enc_name, bits in encodings.items():
            max_offset = len(bits) - CT_LEN + 50
            min_offset = -50
            for offset in range(min_offset, max_offset + 1):
                for keep_val in [0, 1]:
                    nulls = overlay_on_grid(bits, offset, CT_LEN, keep_val)
                    n_nulls = len(nulls)
                    if 22 <= n_nulls <= 26 and not (nulls & CRIB_SET):
                        valid_masks.append((enc_name, offset, keep_val, nulls))

        print(f"Relaxed search: {len(valid_masks)} masks with 22-26 nulls")
        # Show distribution
        null_counts = defaultdict(int)
        for _, _, _, nulls in valid_masks:
            null_counts[len(nulls)] += 1
        for nc in sorted(null_counts):
            print(f"  {nc} nulls: {null_counts[nc]} masks")
        print()

    if not valid_masks:
        print("ZERO valid masks even with relaxed search. Exiting.")
        return

    # Phase 2: Decrypt
    print(f"\nPhase 2: Testing {len(valid_masks)} masks × {len(KEYWORDS)} keywords × 3 variants")
    print("-" * 60)

    best_results = []
    crib_hits = []

    for mask_idx, (enc_name, offset, keep_val, nulls) in enumerate(valid_masks):
        extract = extract_73(nulls)
        n_extract = len(extract)

        for kw in KEYWORDS:
            for variant_name, decrypt_fn in [("vig", decrypt_vig), ("beau", decrypt_beau), ("vbeau", decrypt_vbeau)]:
                pt = decrypt_fn(extract, kw)
                qg = scorer.score_per_char(pt)
                fs = score_free_fast(pt)

                if fs >= 10 or qg > -5.0:
                    crib_hits.append((enc_name, offset, keep_val, kw, variant_name, pt, qg, fs))
                    if fs >= 10:
                        print(f"  *** CRIB HIT *** {enc_name} off={offset} {variant_name} key={kw} fs={fs} qg={qg:.3f}")
                        print(f"      PT: {pt}")

                best_results.append((qg, fs, enc_name, offset, keep_val, kw, variant_name, pt))

        if (mask_idx + 1) % 50 == 0:
            print(f"  Progress: {mask_idx+1}/{len(valid_masks)} masks")

    # Summary
    print()
    print("=" * 80)
    print("RESULTS")
    print("=" * 80)
    print(f"Total masks tested: {len(valid_masks)}")
    print(f"Total decryptions: {len(best_results)}")
    print(f"Crib hits (fs >= 10): {len([h for h in crib_hits if h[7] >= 10])}")
    print(f"Good quadgrams (> -5.0): {len([h for h in crib_hits if h[6] > -5.0])}")
    print()

    # Top 20 by quadgram
    best_results.sort(key=lambda x: x[0], reverse=True)
    print("Top 20 by quadgram score:")
    for rank, (qg, fs, enc, off, kv, kw, var, pt) in enumerate(best_results[:20], 1):
        print(f"  #{rank:2d} qg={qg:.3f} fs={fs} {enc} off={off} {var} key={kw}")
        print(f"      PT: {pt[:60]}...")
    print()

    # Top by free crib score
    if crib_hits:
        crib_hits.sort(key=lambda x: -x[7])
        print("Top by free crib score:")
        for enc, off, kv, kw, var, pt, qg, fs in crib_hits[:20]:
            print(f"  fs={fs} qg={qg:.3f} {enc} off={off} {var} key={kw}")
            print(f"    PT: {pt[:60]}...")

    print("\nDONE")


if __name__ == "__main__":
    main()
