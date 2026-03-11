#!/usr/bin/env python3
"""Columnar transposition THEN Morse mask overlay for K4.

Cipher:    Two-system (columnar transposition + Morse-derived null mask + substitution)
Family:    grille
Status:    active
Keyspace:  ~200 transposition keys × ~500 Morse framings × ~35 keywords × 3 variants
Last run:  never
Best score: n/a

MODEL (encryption direction):
  73-char PT → System 1 (substitution) → 73-char CT
  → insert 24 nulls at Morse-defined positions → 97 chars
  → System 2 (columnar transposition) → 97 carved chars

DECRYPTION:
  1. Undo columnar transposition on carved text → 97 chars (pre-transposition order)
  2. Apply Morse mask → extract 73 chars
  3. Undo substitution → 73-char plaintext
  4. Check for cribs ANYWHERE (free search, since positions shift)

K3 PARALLEL:
  K3 used double columnar transposition with keywords KRYPTOS and ABSCISSA.
  K4 may use a similar transposition as one of its two systems.
"""
from __future__ import annotations

import sys
import time
from collections import defaultdict
from itertools import permutations
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "src"))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD
from kryptos.kernel.scoring.ngram import NgramScorer
from kryptos.kernel.scoring.free_crib import score_free_fast

# ── Morse Data ───────────────────────────────────────────────────────────

MORSE = {
    'A': '.-',    'B': '-...',  'C': '-.-.',  'D': '-..',
    'E': '.',     'F': '..-.',  'G': '--.',   'H': '....',
    'I': '..',    'J': '.---',  'K': '-.-',   'L': '.-..',
    'M': '--',    'N': '-.',    'O': '---',   'P': '.--.',
    'Q': '--.-',  'R': '.-.',   'S': '...',   'T': '-',
    'U': '..-',   'V': '...-',  'W': '.--',   'X': '-..-',
    'Y': '-.--',  'Z': '--..',
}

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


def gen_symbol_stream(tokens, dot_val=0, dash_val=1):
    bits = []
    for t in tokens:
        morse = MORSE[t.upper()]
        for sym in morse:
            bits.append(dot_val if sym == '.' else dash_val)
    return bits


def gen_token_binary(tokens, e_val=0, msg_val=1):
    return [e_val if t == 'e' else msg_val for t in tokens]


def gen_timed_waveform(tokens):
    bits = []
    for i, t in enumerate(tokens):
        morse = MORSE[t.upper()]
        for j, sym in enumerate(morse):
            if sym == '.':
                bits.extend([1])
            else:
                bits.extend([1, 1, 1])
            if j < len(morse) - 1:
                bits.extend([0])
        if i < len(tokens) - 1:
            bits.extend([0, 0, 0])
    return bits


# ── Columnar Transposition ───────────────────────────────────────────────

def keyword_to_column_order(keyword):
    """Convert keyword to column reading order (alphabetical ranking)."""
    indexed = [(ch, i) for i, ch in enumerate(keyword)]
    indexed.sort(key=lambda x: (x[0], x[1]))
    order = [0] * len(keyword)
    for rank, (ch, orig_idx) in enumerate(indexed):
        order[orig_idx] = rank
    return order


def undo_columnar_transposition(ct_text, n_cols):
    """Undo columnar transposition: given ct_text was read column-by-column
    from a grid of n_cols columns, reconstruct the row-by-row reading.

    Write ct_text into columns (top-to-bottom, left-to-right in column order),
    then read row-by-row.
    """
    n = len(ct_text)
    n_rows = (n + n_cols - 1) // n_cols
    n_full = n % n_cols  # number of columns with n_rows chars
    if n_full == 0:
        n_full = n_cols

    # Fill grid column by column
    grid = [[''] * n_cols for _ in range(n_rows)]
    pos = 0
    for col in range(n_cols):
        col_len = n_rows if col < n_full else n_rows - 1
        for row in range(col_len):
            if pos < n:
                grid[row][col] = ct_text[pos]
                pos += 1

    # Read row by row
    return ''.join(grid[r][c] for r in range(n_rows) for c in range(n_cols) if grid[r][c])


def undo_columnar_with_key(ct_text, keyword):
    """Undo columnar transposition where columns were read in keyword order."""
    col_order = keyword_to_column_order(keyword)
    n_cols = len(keyword)
    n = len(ct_text)
    n_rows = (n + n_cols - 1) // n_cols
    n_full = n % n_cols
    if n_full == 0:
        n_full = n_cols

    # Determine which columns are "full" (have n_rows chars)
    # In standard columnar, shorter columns come last
    # The key order determines which LOGICAL columns are read first

    # inv_order[rank] = original_column_index
    inv_order = [0] * n_cols
    for orig, rank in enumerate(col_order):
        inv_order[rank] = orig

    # Fill the grid: read ct_text and assign to columns in key order
    grid = [[''] * n_cols for _ in range(n_rows)]
    pos = 0
    for rank in range(n_cols):
        orig_col = inv_order[rank]
        # Does this column have n_rows or n_rows-1 chars?
        col_len = n_rows if orig_col < n_full else n_rows - 1
        for row in range(col_len):
            if pos < n:
                grid[row][orig_col] = ct_text[pos]
                pos += 1

    # Read row by row
    result = ''
    for r in range(n_rows):
        for c in range(n_cols):
            if grid[r][c]:
                result += grid[r][c]
    return result


def do_columnar_with_key(pt_text, keyword):
    """Forward columnar transposition (for verification)."""
    col_order = keyword_to_column_order(keyword)
    n_cols = len(keyword)
    n = len(pt_text)
    n_rows = (n + n_cols - 1) // n_cols

    # Fill grid row by row
    grid = [[''] * n_cols for _ in range(n_rows)]
    pos = 0
    for r in range(n_rows):
        for c in range(n_cols):
            if pos < n:
                grid[r][c] = pt_text[pos]
                pos += 1

    # Read column by column in key order
    # inv: rank -> orig col
    inv_order = [0] * n_cols
    for orig, rank in enumerate(col_order):
        inv_order[rank] = orig

    result = ''
    for rank in range(n_cols):
        col = inv_order[rank]
        for r in range(n_rows):
            if grid[r][col]:
                result += grid[r][col]
    return result


# ── Mask application ─────────────────────────────────────────────────────

def apply_morse_mask(text, binary_seq, offset, keep_val=1):
    """Apply Morse mask: keep positions where binary == keep_val."""
    kept = []
    nulls = []
    for i, ch in enumerate(text):
        idx = offset + i
        if 0 <= idx < len(binary_seq) and binary_seq[idx] == keep_val:
            kept.append(ch)
        else:
            nulls.append(i)
    return ''.join(kept), nulls


# ── Decryption ───────────────────────────────────────────────────────────

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


# ── Keywords ─────────────────────────────────────────────────────────────

# Transposition keywords (column order)
TRANS_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN",
    "SCHEIDT", "ENIGMA", "COMPASS", "KOMPASS", "DEFECTOR",
    "COLOPHON", "BERLIN", "CLOCK", "FIVE", "POINT",
    "LUCID", "MEMORY", "FORCES", "DIGITAL", "INVISIBLE",
    "POSITION", "MATRIX", "CIPHER", "SECRET", "QUAGMIRE",
    "VIRTUALLY", "INTERPRET", "NORTHEAST", "EAST", "NORTH",
    "GNOMON", "VERDIGRIS", "MERIDIAN", "LODESTONE", "SCULPTURE",
    "OCULUS", "TRIPTYCH", "ARMATURE", "DOLMEN", "FILIGREE",
    "PARALLAX", "REVETEMENT", "CENOTAPH", "OUBLIETTE", "ESCUTCHEON",
]

# Substitution keywords
SUB_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN",
    "SCHEIDT", "ENIGMA", "COMPASS", "KOMPASS", "DEFECTOR",
    "COLOPHON", "BERLIN", "CLOCK", "FIVE", "POINT",
    "LUCID", "MEMORY", "FORCES", "DIGITAL", "INVISIBLE",
    "POSITION", "MATRIX", "CIPHER", "SECRET", "QUAGMIRE",
]


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    print("=" * 80)
    print("COLUMNAR TRANSPOSITION → MORSE MASK → SUBSTITUTION")
    print("=" * 80)
    print(f"CT: {CT}")
    print()

    scorer = NgramScorer.from_file(REPO / "data" / "english_quadgrams.json")
    print(f"Loaded {len(scorer.log_probs)} quadgrams")

    # Verify transposition roundtrip
    test = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for kw in ["KRYPTOS", "ABC"]:
        enc = do_columnar_with_key(test, kw)
        dec = undo_columnar_with_key(enc, kw)
        assert dec == test, f"Roundtrip failed for {kw}: {dec} != {test}"
    print("Transposition roundtrip verified")
    print()

    # Generate Morse binary encodings
    encodings = {}
    encodings["sym_d0"] = gen_symbol_stream(MORSE_TOKENS, 0, 1)
    encodings["sym_d1"] = gen_symbol_stream(MORSE_TOKENS, 1, 0)
    encodings["tok_e0"] = gen_token_binary(MORSE_TOKENS, 0, 1)
    encodings["tok_e1"] = gen_token_binary(MORSE_TOKENS, 1, 0)
    msg_only = [t for t in MORSE_TOKENS if t != 'e']
    encodings["msg_d0"] = gen_symbol_stream(msg_only, 0, 1)
    encodings["msg_d1"] = gen_symbol_stream(msg_only, 1, 0)
    encodings["timed"] = gen_timed_waveform(MORSE_TOKENS)

    for name, bits in encodings.items():
        ones = sum(bits)
        print(f"  {name:10s}: {len(bits)} bits ({ones} ones, {len(bits)-ones} zeros)")
    print()

    # Also include "no mask" option — just transposition alone
    # And column-6-null mask (from grid-14 analysis)

    t0 = time.time()
    total_configs = 0
    all_results = []
    crib_hits = []

    # For each transposition keyword
    for tkw in TRANS_KEYWORDS:
        # Undo the transposition
        untransposed = undo_columnar_with_key(CT, tkw)
        assert len(untransposed) == CT_LEN, f"Length mismatch for {tkw}"

        # Phase A: No mask — just try substitution on the untransposed text
        for skw in SUB_KEYWORDS:
            for vname, dfn in [("vig", decrypt_vig), ("beau", decrypt_beau), ("vbeau", decrypt_vbeau)]:
                pt = dfn(untransposed, skw)
                fs = score_free_fast(pt)
                qg = scorer.score_per_char(pt)
                total_configs += 1
                if fs >= 10 or qg > -4.5:
                    crib_hits.append(("notrans_nomask", tkw, "none", 0, skw, vname, pt, qg, fs))
                    if fs >= 11:
                        print(f"*** HIT *** trans={tkw} mask=none {vname} key={skw} fs={fs} qg={qg:.3f}")
                        print(f"    PT: {pt[:80]}")

        # Phase B: Apply each Morse encoding as mask
        for enc_name, bits in encodings.items():
            max_offset = min(len(bits) - 50, len(bits))
            min_offset = max(-50, -(len(bits)))

            for offset in range(min_offset, max_offset + 1):
                extracted, null_idx = apply_morse_mask(untransposed, bits, offset, keep_val=1)
                n_kept = len(extracted)

                # Accept 70-76 chars (flexible around 73)
                if n_kept < 70 or n_kept > 76:
                    continue

                # Try substitution on extracted text
                for skw in SUB_KEYWORDS:
                    for vname, dfn in [("vig", decrypt_vig), ("beau", decrypt_beau), ("vbeau", decrypt_vbeau)]:
                        pt = dfn(extracted, skw)
                        fs = score_free_fast(pt)
                        total_configs += 1

                        if fs >= 10:
                            qg = scorer.score_per_char(pt)
                            crib_hits.append((enc_name, tkw, enc_name, offset, skw, vname, pt, qg, fs))
                            if fs >= 11:
                                print(f"*** HIT *** trans={tkw} mask={enc_name} off={offset} {vname} key={skw} fs={fs} qg={qg:.3f}")
                                print(f"    PT({n_kept}): {pt[:80]}")

                # Also try with keep_val=0
                extracted0, _ = apply_morse_mask(untransposed, bits, offset, keep_val=0)
                n_kept0 = len(extracted0)
                if 70 <= n_kept0 <= 76:
                    for skw in SUB_KEYWORDS:
                        for vname, dfn in [("vig", decrypt_vig), ("beau", decrypt_beau), ("vbeau", decrypt_vbeau)]:
                            pt = dfn(extracted0, skw)
                            fs = score_free_fast(pt)
                            total_configs += 1

                            if fs >= 10:
                                qg = scorer.score_per_char(pt)
                                crib_hits.append((enc_name+"_inv", tkw, enc_name, offset, skw, vname, pt, qg, fs))
                                if fs >= 11:
                                    print(f"*** HIT *** trans={tkw} mask={enc_name}_inv off={offset} {vname} key={skw} fs={fs} qg={qg:.3f}")
                                    print(f"    PT({n_kept0}): {pt[:80]}")

        # Progress
        elapsed = time.time() - t0
        print(f"  trans_kw={tkw:15s} configs={total_configs:>10,d} hits={len(crib_hits)} ({elapsed:.0f}s)")

    # Also try double columnar (K3-style) with pairs of keywords
    print()
    print("Phase C: Double columnar transposition (K3-style)")
    print("-" * 60)

    # Limit to most promising keyword pairs
    K3_PAIRS = [
        ("KRYPTOS", "ABSCISSA"),
        ("ABSCISSA", "KRYPTOS"),
        ("PALIMPSEST", "KRYPTOS"),
        ("KRYPTOS", "PALIMPSEST"),
        ("KRYPTOS", "KRYPTOS"),
        ("ABSCISSA", "ABSCISSA"),
        ("KRYPTOS", "KOMPASS"),
        ("KOMPASS", "KRYPTOS"),
        ("KRYPTOS", "DEFECTOR"),
        ("DEFECTOR", "KRYPTOS"),
        ("KRYPTOS", "COLOPHON"),
        ("COLOPHON", "KRYPTOS"),
        ("KRYPTOS", "SHADOW"),
        ("SHADOW", "KRYPTOS"),
        ("PALIMPSEST", "ABSCISSA"),
        ("ABSCISSA", "PALIMPSEST"),
        ("KRYPTOS", "ENIGMA"),
        ("ENIGMA", "KRYPTOS"),
        ("KRYPTOS", "CIPHER"),
        ("KRYPTOS", "MATRIX"),
        ("KRYPTOS", "POINT"),
        ("KRYPTOS", "BERLIN"),
        ("BERLIN", "KRYPTOS"),
        ("KRYPTOS", "CLOCK"),
        ("CLOCK", "KRYPTOS"),
        ("KRYPTOS", "FIVE"),
        ("FIVE", "KRYPTOS"),
        ("KRYPTOS", "LUCID"),
        ("KRYPTOS", "MEMORY"),
        ("KRYPTOS", "FORCES"),
    ]

    for kw1, kw2 in K3_PAIRS:
        # Double columnar: undo second transposition, then undo first
        intermediate = undo_columnar_with_key(CT, kw2)
        untransposed = undo_columnar_with_key(intermediate, kw1)

        # Try without mask
        for skw in SUB_KEYWORDS:
            for vname, dfn in [("vig", decrypt_vig), ("beau", decrypt_beau), ("vbeau", decrypt_vbeau)]:
                pt = dfn(untransposed, skw)
                fs = score_free_fast(pt)
                total_configs += 1
                if fs >= 10:
                    qg = scorer.score_per_char(pt)
                    crib_hits.append(("double_col", f"{kw1}+{kw2}", "none", 0, skw, vname, pt, qg, fs))
                    if fs >= 11:
                        print(f"*** HIT *** double_col({kw1},{kw2}) {vname} key={skw} fs={fs} qg={qg:.3f}")
                        print(f"    PT: {pt[:80]}")

        # Try with best Morse masks
        for enc_name in ["sym_d0", "sym_d1", "tok_e0", "tok_e1", "msg_d0", "msg_d1"]:
            bits = encodings[enc_name]
            for offset in range(-20, min(len(bits) - 70, len(bits))):
                for keep_val in [0, 1]:
                    extracted, _ = apply_morse_mask(untransposed, bits, offset, keep_val)
                    if not (70 <= len(extracted) <= 76):
                        continue
                    for skw in SUB_KEYWORDS[:10]:  # Top 10 sub keywords
                        for vname, dfn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
                            pt = dfn(extracted, skw)
                            fs = score_free_fast(pt)
                            total_configs += 1
                            if fs >= 10:
                                qg = scorer.score_per_char(pt)
                                kv_str = "keep" if keep_val == 1 else "inv"
                                crib_hits.append((f"double_{enc_name}_{kv_str}", f"{kw1}+{kw2}", enc_name, offset, skw, vname, pt, qg, fs))
                                if fs >= 11:
                                    print(f"*** HIT *** double({kw1},{kw2}) mask={enc_name}_{kv_str} off={offset} {vname} key={skw} fs={fs}")

        print(f"  double({kw1:12s},{kw2:12s}) total={total_configs:>10,d} hits={len(crib_hits)}")

    # Summary
    elapsed = time.time() - t0
    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total configurations tested: {total_configs:,d}")
    print(f"Total crib hits (fs >= 10): {len(crib_hits)}")
    print(f"Runtime: {elapsed:.1f}s")
    print()

    if crib_hits:
        crib_hits.sort(key=lambda x: (-x[8], -x[7]))
        print("Top 20 crib hits:")
        for i, (src, tkw, enc, off, skw, var, pt, qg, fs) in enumerate(crib_hits[:20], 1):
            print(f"  #{i:2d} fs={fs} qg={qg:.3f} src={src} trans={tkw} mask={enc} off={off} {var} key={skw}")
            print(f"      PT: {pt[:80]}")
    else:
        print("ZERO crib hits.")

    print("\nDONE")


if __name__ == "__main__":
    main()
