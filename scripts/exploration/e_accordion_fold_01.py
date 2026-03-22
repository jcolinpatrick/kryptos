#!/usr/bin/env python3
"""
E-ACCORDION-FOLD-01: Accordion fold on K1-K2 encoding chart

Cipher:      Beaufort / Vigenere / Variant Beaufort
Family:      exploration
Status:      active
Keyspace:    ~2,000 configurations
Last run:    never
Best score:  n/a

Hypothesis: The K1-K2 encoding chart has visible fold lines creating a
3-panel accordion (Lines 1-2 / Lines 3-6 / Lines 7-8). When folded,
PT/KEY/CT rows from different lines align. The combined (overlaid)
content at aligned positions produces K4's keystream.

Physical evidence: forensic photo analysis of NYT_Coding_Chart_HiRes.jpg
confirms fold creases at the ABSCISSA seam and between lines 6-7.

Chart structure (each "line" = 3 rows: PT, KEY, CT across 31 columns):
  Panel A: Lines 1-2 (K1, keyword PALIMPSEST)
  ──── FOLD #1 (ABSCISSA seam) ────
  Panel B: Lines 3-6 (K2 first portion, keyword ABSCISSA)
  ──── FOLD #2 (crease/tape between lines 6-7) ────
  Panel C: Lines 7-8 (K2 second portion, keyword ABSCISSA)
"""

import sys, os, json, time
from collections import defaultdict

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT
from kryptos.kernel.alphabet import AZ, KA

# ── Known texts ────────────────────────────────────────────────────────

K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"

K2_PT = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOS"
    "SIBLETHEYUSEDTHEEARTHSMAGNETICFI"
    "ELDXTHEINFORMATIONWASGATHEREDANDT"
    "RANSMITTEDUNDERGROUNDTOANUNKNOWNL"
    "OCATIONXWASTHATITSAIDIDINOTKNOWT"
    "HESECONDTHIRDORTOOMUCHBETTERWASC"
    "OMPLETELYBURIEDOUTTHEREFROMTHEDOO"
    "RWAYITWASOUTTHEREITSAIDIDDCUVHD"
    # Note: K2_PT may have minor variations at end
)
K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE"
    "GGWHKKDQMCPFQZDQMMIAGPFXHQRLGTI"
    "MVMZJANQLVKQEDAGDVFRPJUNGEUNAQZ"
    "GZLECGYUXUEENJTBJLBQCRTBJDFHRRY"
    "IZETKZEMVDUFKSJHKFWHKUWQLSZFTIH"
    "HDDDUVHDWKBFUFPWNTDFIYCUQZEREEV"
    "LDKFEZMOQQJLTTUGSYQPFEUNLAVIDXF"
    "LGGTEZFKZBSFDQVGOGIPUFXHHDRKFFH"
    "QNTGPUAECNUVPDJMQCLQUMUNEDFQELZ"
    "ZVRRGKFFVOEEXBDMVPNFQXEZLGREDNQ"
    "FMPNZGLFLPMRJQYALMGNUVPDXVKPDQU"
    "MEBEDMHDAFM"
)

K4_CT = CT

# Cribs
CRIBS = {}
for i, ch in enumerate("EASTNORTHEAST"): CRIBS[21+i] = ord(ch)-65
for i, ch in enumerate("BERLINCLOCK"): CRIBS[63+i] = ord(ch)-65

CT_NUMS = [ord(c)-65 for c in K4_CT]

# Known keystreams
KNOWN_KEY = {}
for variant in ('beaufort', 'vigenere', 'varbeau'):
    KNOWN_KEY[variant] = {}
    for pos, pt_val in CRIBS.items():
        ct_val = CT_NUMS[pos]
        if variant == 'beaufort':
            KNOWN_KEY[variant][pos] = (ct_val + pt_val) % 26
        elif variant == 'vigenere':
            KNOWN_KEY[variant][pos] = (ct_val - pt_val) % 26
        elif variant == 'varbeau':
            KNOWN_KEY[variant][pos] = (pt_val - ct_val) % 26


# ── Reconstruct chart content ──────────────────────────────────────────

def to_nums(text):
    return [ord(c) - 65 for c in text.upper()]

def compute_key_row_ka(pt_nums, ct_nums):
    """Compute KEY values using KA Vigenere: C_ka = (P_ka + K_ka) % 26
    So K_ka = (C_ka - P_ka) % 26 in KA indexing.
    Return values in STANDARD A=0 indexing."""
    ka_str = str(KA)
    std_to_ka = {ord(c)-65: i for i, c in enumerate(ka_str)}
    ka_to_std = {i: ord(c)-65 for i, c in enumerate(ka_str)}

    key_std = []
    for p, c in zip(pt_nums, ct_nums):
        p_ka = std_to_ka[p]
        c_ka = std_to_ka[c]
        k_ka = (c_ka - p_ka) % 26
        key_std.append(ka_to_std[k_ka])
    return key_std

def compute_key_row_az(pt_nums, ct_nums):
    """Compute KEY values using standard Vigenere: C = (P + K) % 26."""
    return [(c - p) % 26 for p, c in zip(pt_nums, ct_nums)]


# Build chart rows (PT, KEY, CT for each line, 31 columns each)
COLS = 31

k1_pt_nums = to_nums(K1_PT)
k1_ct_nums = to_nums(K1_CT)
k2_pt_nums = to_nums(K2_PT)
k2_ct_nums = to_nums(K2_CT)

# Compute KEY rows
k1_key_ka = compute_key_row_ka(k1_pt_nums, k1_ct_nums)
k1_key_az = compute_key_row_az(k1_pt_nums, k1_ct_nums)
k2_key_ka = compute_key_row_ka(k2_pt_nums[:len(k2_ct_nums)], k2_ct_nums)
k2_key_az = compute_key_row_az(k2_pt_nums[:len(k2_ct_nums)], k2_ct_nums)

# Split into 31-column lines
def split_lines(data, cols=31):
    lines = []
    for i in range(0, len(data), cols):
        lines.append(data[i:i+cols])
    return lines

k1_pt_lines = split_lines(k1_pt_nums)   # 2 lines (63 chars / 31 = ~2)
k1_ct_lines = split_lines(k1_ct_nums)
k1_key_ka_lines = split_lines(k1_key_ka)
k1_key_az_lines = split_lines(k1_key_az)

k2_pt_lines = split_lines(k2_pt_nums[:len(k2_ct_nums)])
k2_ct_lines = split_lines(k2_ct_nums)
k2_key_ka_lines = split_lines(k2_key_ka)
k2_key_az_lines = split_lines(k2_key_az)


def make_chart_rows(pt_lines, key_lines, ct_lines):
    """Build ordered list of (row_type, data) for chart rows.
    Each 'line' has 3 rows: PT, KEY, CT."""
    rows = []
    n = max(len(pt_lines), len(key_lines), len(ct_lines))
    for i in range(n):
        if i < len(pt_lines): rows.append(('PT', pt_lines[i]))
        else: rows.append(('PT', []))
        if i < len(key_lines): rows.append(('KEY', key_lines[i]))
        else: rows.append(('KEY', []))
        if i < len(ct_lines): rows.append(('CT', ct_lines[i]))
        else: rows.append(('CT', []))
    return rows


# ── Accordion fold simulation ──────────────────────────────────────────

def run_accordion_fold(results, alphabet_label, k1_key_lines, k2_key_lines):
    """Simulate accordion fold and test aligned content as K4 keystream."""

    # Build all chart rows for K1 (Panel A) and K2 (Panels B+C)
    k1_rows = make_chart_rows(k1_pt_lines, k1_key_lines, k1_ct_lines)
    k2_rows = make_chart_rows(k2_pt_lines, k2_key_lines, k2_ct_lines)

    n_k1 = len(k1_rows)  # Should be ~6 (2 lines × 3 rows)
    n_k2 = len(k2_rows)  # Should be ~36 (12 lines × 3 rows)

    print(f"\n  [{alphabet_label}] K1 chart rows: {n_k1}, K2 chart rows: {n_k2}")

    # Fold #1 at ABSCISSA: Panel A (K1, rows 0..n_k1-1) folds onto Panel B (K2, rows 0..)
    # When folded, K1 row (n_k1-1-k) aligns with K2 row k
    # This means the LAST K1 row aligns with the FIRST K2 row, etc.

    # Generate aligned row pairs from fold #1
    fold1_pairs = []
    for k in range(n_k1):
        k1_row_idx = n_k1 - 1 - k
        k2_row_idx = k
        if k2_row_idx < n_k2:
            k1_type, k1_data = k1_rows[k1_row_idx]
            k2_type, k2_data = k2_rows[k2_row_idx]
            fold1_pairs.append((k1_row_idx, k1_type, k1_data, k2_row_idx, k2_type, k2_data))

    print(f"  Fold #1 (ABSCISSA): {len(fold1_pairs)} row alignments")
    for k1i, k1t, k1d, k2i, k2t, k2d in fold1_pairs:
        k1_chars = ''.join(chr(v+65) for v in k1d[:10]) if k1d else '(empty)'
        k2_chars = ''.join(chr(v+65) for v in k2d[:10]) if k2d else '(empty)'
        print(f"    K1 row {k1i}({k1t}) aligns with K2 row {k2i}({k2t}): {k1_chars}... <-> {k2_chars}...")

    # Fold #2 between lines 6 and 7 of K2
    # K2 line 6 = K2 rows 9,10,11 (0-indexed from K2 start, lines are 0-indexed)
    # Actually, K2 has lines numbered from the chart as 3,4,5,6,7,8
    # In K2-local indexing: lines 0,1,2,3 (Panel B) and lines 4,5 (Panel C)
    # Panel B: K2 rows 0-11, Panel C: K2 rows 12-17
    # Fold between them: K2 row 11 (last of Panel B) aligns with K2 row 12 (first of Panel C)

    k2_panel_b_end = 12  # K2 local rows 0-11 (lines 3-6, 4 lines × 3 rows)
    fold2_pairs = []
    for k in range(min(k2_panel_b_end, n_k2 - k2_panel_b_end)):
        b_row_idx = k2_panel_b_end - 1 - k
        c_row_idx = k2_panel_b_end + k
        if c_row_idx < n_k2:
            b_type, b_data = k2_rows[b_row_idx]
            c_type, c_data = k2_rows[c_row_idx]
            fold2_pairs.append((b_row_idx, b_type, b_data, c_row_idx, c_type, c_data))

    print(f"\n  Fold #2 (Line 6/7): {len(fold2_pairs)} row alignments")
    for bi, bt, bd, ci, ct_, cd in fold2_pairs:
        b_chars = ''.join(chr(v+65) for v in bd[:10]) if bd else '(empty)'
        c_chars = ''.join(chr(v+65) for v in cd[:10]) if cd else '(empty)'
        print(f"    K2 row {bi}({bt}) aligns with K2 row {ci}({ct_}): {b_chars}... <-> {c_chars}...")

    # Now test: extract keystreams from aligned rows and score against K4 cribs
    # For each aligned pair of rows, combine values and use as running key for K4

    combination_models = {
        'direct_a': lambda a, b: a,   # Use row A value as key
        'direct_b': lambda a, b: b,   # Use row B value as key
        'add': lambda a, b: (a + b) % 26,
        'sub_ab': lambda a, b: (a - b) % 26,
        'sub_ba': lambda a, b: (b - a) % 26,
    }

    all_fold_pairs = [
        ('fold1', fold1_pairs),
        ('fold2', fold2_pairs),
    ]

    # Also: concatenate aligned row values to form longer keystreams
    for fold_name, pairs in all_fold_pairs:
        # Test individual row pairs
        for pair_idx, pair_data in enumerate(pairs):
            if fold_name == 'fold1':
                _, type_a, data_a, _, type_b, data_b = pair_data
            else:
                _, type_a, data_a, _, type_b, data_b = pair_data

            if not data_a or not data_b:
                continue

            min_len = min(len(data_a), len(data_b))

            for model_name, combine_fn in combination_models.items():
                # Build keystream from this row pair, repeating/cycling for K4's 97 chars
                row_key = [combine_fn(data_a[j], data_b[j]) for j in range(min_len)]
                if not row_key:
                    continue

                # Use this row as keystream (cycling if needed)
                for variant in ('beaufort', 'vigenere', 'varbeau'):
                    matches = 0
                    for pos in CRIBS:
                        key_val = row_key[pos % len(row_key)]
                        if key_val == KNOWN_KEY[variant][pos]:
                            matches += 1

                    if matches >= 6:
                        results.append({
                            'fold': fold_name,
                            'pair_idx': pair_idx,
                            'type_a': type_a, 'type_b': type_b,
                            'model': model_name,
                            'variant': variant,
                            'alphabet': alphabet_label,
                            'score': matches,
                            'key_len': len(row_key),
                        })

        # Test CONCATENATED aligned rows as a long keystream
        for model_name, combine_fn in combination_models.items():
            concat_key = []
            concat_types = []
            for pair_data in pairs:
                if fold_name == 'fold1':
                    _, type_a, data_a, _, type_b, data_b = pair_data
                else:
                    _, type_a, data_a, _, type_b, data_b = pair_data

                if not data_a or not data_b:
                    continue

                min_len = min(len(data_a), len(data_b))
                for j in range(min_len):
                    concat_key.append(combine_fn(data_a[j], data_b[j]))
                concat_types.append(f"{type_a}+{type_b}")

            if len(concat_key) < 24:
                continue

            # Test concatenated key at all offsets
            for offset in range(len(concat_key)):
                for variant in ('beaufort', 'vigenere', 'varbeau'):
                    matches = 0
                    for pos in CRIBS:
                        key_idx = (pos + offset) % len(concat_key)
                        if key_idx < len(concat_key):
                            key_val = concat_key[key_idx]
                            if key_val == KNOWN_KEY[variant][pos]:
                                matches += 1

                    if matches >= 6:
                        results.append({
                            'fold': fold_name,
                            'pair_idx': 'concat',
                            'type_a': 'mixed', 'type_b': 'mixed',
                            'model': model_name,
                            'variant': variant,
                            'alphabet': alphabet_label,
                            'score': matches,
                            'key_len': len(concat_key),
                            'offset': offset,
                        })

    # Also test: KEY-KEY pairs only (most interesting — two keyword streams combined)
    print(f"\n  Testing KEY-KEY aligned pairs specifically...")
    for fold_name, pairs in all_fold_pairs:
        key_key_pairs = []
        for pair_data in pairs:
            _, type_a, data_a, _, type_b, data_b = pair_data
            if type_a == 'KEY' and type_b == 'KEY' and data_a and data_b:
                key_key_pairs.append((data_a, data_b))

        if not key_key_pairs:
            continue

        # Concatenate all KEY-KEY values
        for model_name, combine_fn in combination_models.items():
            concat_key = []
            for data_a, data_b in key_key_pairs:
                min_len = min(len(data_a), len(data_b))
                for j in range(min_len):
                    concat_key.append(combine_fn(data_a[j], data_b[j]))

            if len(concat_key) < 10:
                continue

            for offset in range(len(concat_key)):
                for variant in ('beaufort', 'vigenere', 'varbeau'):
                    matches = 0
                    for pos in CRIBS:
                        key_idx = (pos + offset) % len(concat_key)
                        if key_idx < len(concat_key):
                            key_val = concat_key[key_idx]
                            if key_val == KNOWN_KEY[variant][pos]:
                                matches += 1

                    if matches >= 6:
                        results.append({
                            'fold': fold_name + '_KEY_KEY',
                            'pair_idx': 'concat_keys',
                            'type_a': 'KEY', 'type_b': 'KEY',
                            'model': model_name,
                            'variant': variant,
                            'alphabet': alphabet_label,
                            'score': matches,
                            'key_len': len(concat_key),
                            'offset': offset,
                        })


def main():
    print("=" * 70)
    print("E-ACCORDION-FOLD-01: Accordion Fold on K1-K2 Encoding Chart")
    print("=" * 70)
    print(f"K1: {len(K1_PT)} PT chars, {len(K1_CT)} CT chars")
    print(f"K2: {len(K2_PT)} PT chars (trimmed to {min(len(K2_PT),len(K2_CT))}), {len(K2_CT)} CT chars")
    print(f"Chart width: {COLS} columns")
    print(f"K1 lines: {len(k1_ct_lines)} ({len(K1_CT)} / {COLS})")
    print(f"K2 lines: {len(k2_ct_lines)} ({len(K2_CT)} / {COLS})")

    # Verify K1 keyword
    k1_key_chars = ''.join(chr(v+65) for v in k1_key_ka[:20])
    print(f"\nK1 KEY (KA, first 20): {k1_key_chars}")
    k1_key_chars_az = ''.join(chr(v+65) for v in k1_key_az[:20])
    print(f"K1 KEY (AZ, first 20): {k1_key_chars_az}")

    k2_key_chars = ''.join(chr(v+65) for v in k2_key_ka[:20])
    print(f"K2 KEY (KA, first 20): {k2_key_chars}")
    k2_key_chars_az = ''.join(chr(v+65) for v in k2_key_az[:20])
    print(f"K2 KEY (AZ, first 20): {k2_key_chars_az}")

    t0 = time.time()
    results = []

    print("\n--- Testing with KA alphabet ---")
    run_accordion_fold(results, 'KA', k1_key_ka_lines, k2_key_ka_lines)

    print("\n--- Testing with AZ alphabet ---")
    run_accordion_fold(results, 'AZ', k1_key_az_lines, k2_key_az_lines)

    elapsed = time.time() - t0

    print("\n" + "=" * 70)
    print(f"COMPLETE — {elapsed:.2f}s elapsed")
    print(f"Total results above threshold (6/24): {len(results)}")

    if results:
        results.sort(key=lambda r: r['score'], reverse=True)
        print(f"\nBest score: {results[0]['score']}/24")
        print(f"\nTop 20:")
        for r in results[:20]:
            offset_str = f" @{r.get('offset','?')}" if 'offset' in r else ""
            print(f"  {r['fold']:>20} {r['model']:>10} {r['variant']:>10} "
                  f"{r['alphabet']:>4} score={r['score']:>2}/24 "
                  f"keylen={r['key_len']}{offset_str} "
                  f"({r['type_a']}×{r['type_b']})")
    else:
        print("\nNo results above threshold. Accordion fold produces noise.")

    # Save
    output = {
        'experiment': 'E-ACCORDION-FOLD-01',
        'hypothesis': 'Accordion fold on K1-K2 encoding chart produces K4 keystream',
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'elapsed_seconds': elapsed,
        'total_results': len(results),
        'best_score': results[0]['score'] if results else 0,
        'results': results[:50],
    }

    os.makedirs(os.path.join(_ROOT, 'results'), exist_ok=True)
    out_path = os.path.join(_ROOT, 'results', 'e_accordion_fold_01.json')
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == '__main__':
    main()
