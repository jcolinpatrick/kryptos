#!/usr/bin/env python3
"""
Cipher: Sanborn matrix method
Family: novel
Status: exhausted
Keyspace: ~6 keywords x 5 models x keyword combos = ~1000+ configs
Last run:
Best score:

Hypothesis: Sanborn mentioned using a "matrix" in his encryption process
(June 2005 interview, kryptos mailing list). Test five interpretations:

1. Custom tableau: 26x26 substitution tableau from keyword-mixed alphabets,
   periodic key selects row.
2. Keyed Polybius read-off: 6x5 grid (26 letters), encode as row/col pairs,
   apply transposition to coordinate pairs.
3. Double-substitution matrix: Two keyword-mixed alphabets define a mapping
   PT->(row in alph1, col in alph2)->CT.
4. Straddling checkerboard: VIC-style with thematic keyword row headers.
5. Bifid-like mod 26: Polybius encoding but mod 26 (no I/J merge), paired ops.
"""
import sys
import os
import time
import itertools
from collections import defaultdict

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CRIB_DICT, ALPH, ALPH_IDX, MOD
from kryptos.kernel.alphabet import keyword_mixed_alphabet, Alphabet
from kryptos.kernel.scoring.aggregate import score_candidate

# ── Configuration ──────────────────────────────────────────────────────────

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "SHADOW", "SCHEIDT"]
PERIODS = list(range(7, 11))  # 7, 8, 9, 10

CT_NUMS = [ALPH_IDX[c] for c in CT]
CT_LEN = len(CT)

best_results = []  # (score, plaintext, description)


def record(score, pt, desc):
    """Record a result if score >= 1; print if >= 10."""
    best_results.append((score, pt, desc))
    if score >= 10:
        print(f"  *** SCORE {score}: {desc}")
        print(f"      PT: {pt[:70]}")


# ── Model 1: Custom Tableau ───────────────────────────────────────────────

def model1_custom_tableau():
    """Build 26x26 tableau from two keyword-mixed alphabets. Row alphabet
    defines row headers, col alphabet shifted by row index. Periodic key
    selects which row to use for each position."""
    print("=" * 70)
    print("MODEL 1: Custom Tableau (keyword-mixed rows, periodic key)")
    print("=" * 70)
    configs = 0

    for row_kw in KEYWORDS:
        row_alph = keyword_mixed_alphabet(row_kw)
        for col_kw in KEYWORDS:
            col_alph = keyword_mixed_alphabet(col_kw)
            # Build tableau: row i = col_alph shifted by i positions
            # (like a Vigenere tableau but with keyword-mixed alphabets)
            tableau = []
            for i in range(26):
                tableau.append(col_alph[i:] + col_alph[:i])

            # Build inverse tableau for decryption
            inv_tableau = []
            for i in range(26):
                row = tableau[i]
                inv = [0] * 26
                for j, c in enumerate(row):
                    inv[ALPH_IDX[c]] = j
                inv_tableau.append(inv)

            for key_kw in KEYWORDS:
                for period in PERIODS:
                    key_str = key_kw[:period]
                    # Map key letters through row alphabet
                    key_nums = [row_alph.index(c) if c in row_alph else ALPH_IDX[c]
                                for c in key_str]

                    # Decrypt: for each CT char, find which PT letter maps to it
                    # in the row selected by the key
                    pt_chars = []
                    for pos, ct_c in enumerate(CT):
                        row_idx = key_nums[pos % len(key_nums)]
                        ct_idx = ALPH_IDX[ct_c]
                        pt_idx = inv_tableau[row_idx][ct_idx]
                        pt_chars.append(ALPH[pt_idx])

                    pt = "".join(pt_chars)
                    sb = score_candidate(pt)
                    configs += 1
                    if sb.crib_score >= 1:
                        record(sb.crib_score, pt,
                               f"M1 row={row_kw} col={col_kw} key={key_str} p={period}")

    print(f"  Tested {configs} configs")
    return configs


# ── Model 2: Keyed Polybius Read-off ─────────────────────────────────────

def model2_polybius_readoff():
    """6x5 grid (rows 0-5, cols 0-4, 26 cells used out of 30).
    Encode CT as (row, col) pairs, apply transposition to pairs, decode."""
    print("=" * 70)
    print("MODEL 2: Keyed Polybius 6x5 Read-off + Pair Transposition")
    print("=" * 70)
    configs = 0

    for kw in KEYWORDS:
        alph = keyword_mixed_alphabet(kw)
        # Build 6x5 grid
        grid = {}
        inv_grid = {}
        for idx, c in enumerate(alph):
            r, co = divmod(idx, 5)
            grid[(r, co)] = c
            inv_grid[c] = (r, co)

        # Extract coordinates from CT
        rows = []
        cols = []
        for c in CT:
            r, co = inv_grid[c]
            rows.append(r)
            cols.append(co)

        # Interleave coordinate pairs: [r0,c0,r1,c1,...] = 194 values
        coords = []
        for i in range(CT_LEN):
            coords.append(rows[i])
            coords.append(cols[i])

        # Try different transposition periods on the coordinate stream
        for period in PERIODS:
            # Columnar transposition on the coordinate stream
            for key_kw in KEYWORDS:
                key = key_kw[:period]
                # Create column order from key
                key_order = sorted(range(len(key)), key=lambda x: key[x])

                # Pad coordinates to fill grid
                n = len(coords)
                n_rows_grid = (n + period - 1) // period

                # Read off columns in key order (undo columnar transposition)
                # Assume coords were written into columns in key order
                col_lens = []
                for c_idx in range(period):
                    col_lens.append(n_rows_grid if c_idx < (n % period or period) else
                                    n_rows_grid - (1 if n % period != 0 else 0))

                # Try: coords were written row-by-row, read column-by-column in key order
                # Inverse: we have column-order data, need to reconstruct row order
                try:
                    # Distribute coords into columns (in key order)
                    col_data = []
                    pos = 0
                    actual_lens = []
                    for ci in range(period):
                        clen = n_rows_grid if ci < (n % period if n % period else period) else n_rows_grid - (1 if n % period else 0)
                        actual_lens.append(clen)

                    # Columns filled in key_order sequence
                    col_contents = [[] for _ in range(period)]
                    pos = 0
                    for ki in key_order:
                        clen = actual_lens[ki]
                        col_contents[ki] = coords[pos:pos+clen]
                        pos += clen

                    # Read row by row
                    new_coords = []
                    for r_idx in range(n_rows_grid):
                        for c_idx in range(period):
                            if r_idx < len(col_contents[c_idx]):
                                new_coords.append(col_contents[c_idx][r_idx])

                    # Decode back to text
                    if len(new_coords) >= CT_LEN * 2:
                        pt_chars = []
                        for i in range(CT_LEN):
                            r_val = new_coords[2*i] % 6
                            c_val = new_coords[2*i+1] % 5
                            if (r_val, c_val) in grid:
                                pt_chars.append(grid[(r_val, c_val)])
                            else:
                                pt_chars.append('X')
                        pt = "".join(pt_chars)
                        sb = score_candidate(pt)
                        configs += 1
                        if sb.crib_score >= 1:
                            record(sb.crib_score, pt,
                                   f"M2 grid={kw} trans_key={key} p={period}")
                except (IndexError, ValueError):
                    pass

        # Also try: just swap rows/cols streams
        # rows then cols, or cols then rows
        for label, stream in [("RC", rows + cols), ("CR", cols + rows)]:
            # Split back into pairs
            half = CT_LEN
            s1 = stream[:half]
            s2 = stream[half:]
            pt_chars = []
            for i in range(CT_LEN):
                r_val = s1[i] % 6
                c_val = s2[i] % 5
                if (r_val, c_val) in grid:
                    pt_chars.append(grid[(r_val, c_val)])
                else:
                    pt_chars.append('X')
            pt = "".join(pt_chars)
            sb = score_candidate(pt)
            configs += 1
            if sb.crib_score >= 1:
                record(sb.crib_score, pt, f"M2 grid={kw} split={label}")

    print(f"  Tested {configs} configs")
    return configs


# ── Model 3: Double-Substitution Matrix ──────────────────────────────────

def model3_double_sub():
    """Two keyword-mixed alphabets (A1, A2). Encryption: for PT char p,
    find index i = A1.index(p), then CT = A2[i]. This is just mono-sub,
    but we add a periodic key shift: CT = A2[(A1.index(p) + key[pos]) % 26].
    Essentially a Vigenere with non-standard alphabets for both PT and CT sides."""
    print("=" * 70)
    print("MODEL 3: Double-Substitution Matrix (two keyword alphabets + key)")
    print("=" * 70)
    configs = 0

    for pt_kw in KEYWORDS:
        pt_alph = keyword_mixed_alphabet(pt_kw)
        pt_idx = {c: i for i, c in enumerate(pt_alph)}
        for ct_kw in KEYWORDS:
            ct_alph = keyword_mixed_alphabet(ct_kw)
            ct_idx = {c: i for i, c in enumerate(ct_alph)}

            for key_kw in KEYWORDS:
                for period in PERIODS:
                    key_str = key_kw[:period]
                    key_nums = [ALPH_IDX[c] for c in key_str]

                    # Decrypt: CT[i] -> ct_idx -> subtract key -> pt_alph
                    pt_chars = []
                    for pos, ct_c in enumerate(CT):
                        ci = ct_idx[ct_c]
                        pi = (ci - key_nums[pos % len(key_nums)]) % 26
                        pt_chars.append(pt_alph[pi])
                    pt = "".join(pt_chars)
                    sb = score_candidate(pt)
                    configs += 1
                    if sb.crib_score >= 1:
                        record(sb.crib_score, pt,
                               f"M3 pt_alph={pt_kw} ct_alph={ct_kw} key={key_str} p={period}")

                    # Also try Beaufort variant: pi = (ci + key) % 26
                    pt_chars2 = []
                    for pos, ct_c in enumerate(CT):
                        ci = ct_idx[ct_c]
                        pi = (ci + key_nums[pos % len(key_nums)]) % 26
                        pt_chars2.append(pt_alph[pi])
                    pt2 = "".join(pt_chars2)
                    sb2 = score_candidate(pt2)
                    configs += 1
                    if sb2.crib_score >= 1:
                        record(sb2.crib_score, pt2,
                               f"M3B pt_alph={pt_kw} ct_alph={ct_kw} key={key_str} p={period}")

    print(f"  Tested {configs} configs")
    return configs


# ── Model 4: Straddling Checkerboard ─────────────────────────────────────

def model4_straddling():
    """Straddling checkerboard with keyword-derived letter assignments.
    Top row: 8 high-frequency letters (from keyword order).
    Two extended rows (digits as prefix) for remaining 18 letters.
    Since VIC family is eliminated for standard configs, we test with
    keyword-mixed letter orderings and different key overlays."""
    print("=" * 70)
    print("MODEL 4: Straddling Checkerboard (keyword-derived assignments)")
    print("=" * 70)
    configs = 0

    # High-frequency letters for top row (standard English)
    HIGH_FREQ = "ETAONIRSH"  # 9 most common (one will go to blank)
    # We'll try 8-letter top rows from different keyword orderings

    for kw in KEYWORDS:
        alph = keyword_mixed_alphabet(kw)

        # Top row: first 8 unique letters from keyword alphabet
        # that are also high-frequency
        top8 = []
        remaining = []
        for c in alph:
            if c in HIGH_FREQ and len(top8) < 8:
                top8.append(c)
            else:
                remaining.append(c)
        # Fill remaining if top8 < 8
        while len(top8) < 8:
            top8.append(remaining.pop(0))

        # Assign positions: top row gets single digits 0-9 (minus 2 prefix digits)
        # Prefix digits: positions of blanks in top row
        # For simplicity: top row positions 0-9, blanks at positions len(top8), len(top8)+1
        # Actually, let's just build a simple encode/decode table

        # Build encoding: top8 -> single digit, remaining -> two digits
        encode_table = {}
        decode_table = {}
        digit = 0
        prefix_digits = []
        for i in range(10):
            if i < len(top8):
                encode_table[top8[i]] = str(i)
                decode_table[str(i)] = top8[i]
            else:
                prefix_digits.append(str(i))

        # Remaining letters get two-digit codes
        ri = 0
        for prefix in prefix_digits:
            for suffix in range(10):
                code = prefix + str(suffix)
                if ri < len(remaining):
                    encode_table[remaining[ri]] = code
                    decode_table[code] = remaining[ri]
                    ri += 1

        # Encode CT as digit string, then try to decode with different
        # checkerboard layouts (this tests if CT was encoded this way)
        ct_digits = "".join(encode_table.get(c, "??") for c in CT)
        if "?" in ct_digits:
            continue

        # Now try decoding the digit string with different checkerboard configs
        for kw2 in KEYWORDS:
            alph2 = keyword_mixed_alphabet(kw2)
            top8_2 = []
            remaining_2 = []
            for c in alph2:
                if c in HIGH_FREQ and len(top8_2) < 8:
                    top8_2.append(c)
                else:
                    remaining_2.append(c)
            while len(top8_2) < 8:
                top8_2.append(remaining_2.pop(0))

            decode_table_2 = {}
            d2 = 0
            prefix_digits_2 = []
            for i in range(10):
                if i < len(top8_2):
                    decode_table_2[str(i)] = top8_2[i]
                else:
                    prefix_digits_2.append(str(i))

            ri2 = 0
            for prefix in prefix_digits_2:
                for suffix in range(10):
                    code = prefix + str(suffix)
                    if ri2 < len(remaining_2):
                        decode_table_2[code] = remaining_2[ri2]
                        ri2 += 1

            # Decode ct_digits with decode_table_2
            pt_chars = []
            pos = 0
            valid = True
            while pos < len(ct_digits):
                if ct_digits[pos] in decode_table_2 and ct_digits[pos] not in prefix_digits_2:
                    pt_chars.append(decode_table_2[ct_digits[pos]])
                    pos += 1
                elif pos + 1 < len(ct_digits):
                    code = ct_digits[pos:pos+2]
                    if code in decode_table_2:
                        pt_chars.append(decode_table_2[code])
                        pos += 2
                    else:
                        valid = False
                        break
                else:
                    valid = False
                    break

            if valid and len(pt_chars) >= 50:
                pt = "".join(pt_chars)
                # Pad or truncate to 97 if needed for scoring
                if len(pt) < 97:
                    pt = pt + "A" * (97 - len(pt))
                pt = pt[:97]
                sb = score_candidate(pt)
                configs += 1
                if sb.crib_score >= 1:
                    record(sb.crib_score, pt,
                           f"M4 enc={kw} dec={kw2} ptlen={len(pt_chars)}")

    print(f"  Tested {configs} configs")
    return configs


# ── Model 5: Bifid-like Mod 26 ──────────────────────────────────────────

def model5_bifid_mod26():
    """Bifid variant that works with all 26 letters (no I/J merge).
    Uses a keyword-mixed alphabet laid out in a conceptual grid.
    Two approaches:
    A) 26x1 with modular arithmetic (row = idx // period, col = idx % period)
    B) Paired coordinate extraction + recombination, all mod 26.
    """
    print("=" * 70)
    print("MODEL 5: Bifid-like Mod 26 (no I/J merge)")
    print("=" * 70)
    configs = 0

    for kw in KEYWORDS:
        alph = keyword_mixed_alphabet(kw)
        alph_idx = {c: i for i, c in enumerate(alph)}

        for period in PERIODS:
            # Approach A: Encode each CT char as (idx // N, idx % N) for various N
            for N in [5, 6, 7, 13, 26]:
                # Get coordinate pairs
                ct_coords = [(alph_idx[c] // N, alph_idx[c] % N) for c in CT]

                # Process in groups of 'period' chars (classic Bifid grouping)
                pt_chars = []
                for start in range(0, CT_LEN, period):
                    group = ct_coords[start:start+period]
                    glen = len(group)

                    # Extract rows and cols
                    rows = [g[0] for g in group]
                    cols = [g[1] for g in group]

                    # Recombine: take from concatenated stream
                    combined = rows + cols
                    for i in range(glen):
                        r_new = combined[i] % (26 // N + 1) if N < 26 else combined[i]
                        c_new = combined[i + glen] % N if i + glen < len(combined) else 0
                        idx = (r_new * N + c_new) % 26
                        pt_chars.append(alph[idx])

                if len(pt_chars) == CT_LEN:
                    pt = "".join(pt_chars)
                    sb = score_candidate(pt)
                    configs += 1
                    if sb.crib_score >= 1:
                        record(sb.crib_score, pt,
                               f"M5A kw={kw} N={N} period={period}")

            # Approach B: Simple paired mod-26 ops
            # For each pair (CT[i], CT[i+half]), compute PT via mod-26 ops
            half = CT_LEN // 2
            for key_kw in KEYWORDS:
                key_str = key_kw[:period]
                key_nums = [ALPH_IDX[c] for c in key_str]

                # Method: sum/difference of paired positions
                pt_chars = []
                for i in range(CT_LEN):
                    ci = alph_idx[CT[i]]
                    partner = (i + half) % CT_LEN
                    cj = alph_idx[CT[partner]]
                    k = key_nums[i % len(key_nums)]

                    # Try: PT[i] = (ci + cj - k) mod 26
                    pi = (ci + cj - k) % 26
                    pt_chars.append(alph[pi])

                pt = "".join(pt_chars)
                sb = score_candidate(pt)
                configs += 1
                if sb.crib_score >= 1:
                    record(sb.crib_score, pt,
                           f"M5B kw={kw} key={key_str} p={period} sum")

                # Try: PT[i] = (ci - cj + k) mod 26
                pt_chars2 = []
                for i in range(CT_LEN):
                    ci = alph_idx[CT[i]]
                    partner = (i + half) % CT_LEN
                    cj = alph_idx[CT[partner]]
                    k = key_nums[i % len(key_nums)]
                    pi = (ci - cj + k) % 26
                    pt_chars2.append(alph[pi])

                pt2 = "".join(pt_chars2)
                sb2 = score_candidate(pt2)
                configs += 1
                if sb2.crib_score >= 1:
                    record(sb2.crib_score, pt2,
                           f"M5B kw={kw} key={key_str} p={period} diff")

    print(f"  Tested {configs} configs")
    return configs


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    print("=" * 80)
    print("SANBORN 'MATRIX' METHOD — 5 MODELS")
    print("=" * 80)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Keywords: {KEYWORDS}")
    print(f"Periods: {PERIODS}")
    print()

    t0 = time.time()

    c1 = model1_custom_tableau()
    c2 = model2_polybius_readoff()
    c3 = model3_double_sub()
    c4 = model4_straddling()
    c5 = model5_bifid_mod26()

    total = c1 + c2 + c3 + c4 + c5
    elapsed = time.time() - t0

    print()
    print("=" * 80)
    print(f"RESULTS SUMMARY")
    print("=" * 80)
    print(f"Total configurations tested: {total}")
    print(f"Total time: {elapsed:.1f}s")
    print(f"Results with score >= 1: {len(best_results)}")
    print()

    if best_results:
        best_results.sort(key=lambda x: -x[0])
        best_score = best_results[0][0]
        print(f"Best score: {best_score}")
        print()
        print("TOP 20 RESULTS:")
        print("-" * 80)
        for i, (sc, pt, desc) in enumerate(best_results[:20]):
            sb = score_candidate(pt)
            print(f"  #{i+1:2d}  score={sc:2d}  {sb.summary}")
            print(f"       {desc}")
            print(f"       PT: {pt[:70]}{'...' if len(pt) > 70 else ''}")
            print()

        # Score distribution
        from collections import Counter
        dist = Counter(r[0] for r in best_results)
        print("SCORE DISTRIBUTION:")
        for sc in sorted(dist.keys(), reverse=True):
            print(f"  score={sc}: {dist[sc]} configs")
    else:
        print("No results with score >= 1 found.")

    print()
    print("CONCLUSION:")
    if any(r[0] >= 10 for r in best_results):
        print("  SIGNAL DETECTED (score >= 10) — investigate further!")
    elif any(r[0] >= 5 for r in best_results):
        print("  Weak partial matches found. Likely noise but worth noting.")
    else:
        print("  All models produced noise. 'Matrix' as tested here does not crack K4.")


if __name__ == "__main__":
    main()
