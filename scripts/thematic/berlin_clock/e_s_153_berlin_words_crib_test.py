#!/usr/bin/env python3
"""
Cipher: Berlin clock
Family: thematic/berlin_clock
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-139: Test Berlin-themed words as additional cribs.

For each candidate word, test all valid placements (no overlap with existing
cribs at positions 21-33 and 63-73). Compute Vigenere and Beaufort keystream,
check Bean constraints, and analyze keystream for periodicity and English-like
properties.

Run: PYTHONPATH=src python3 -u scripts/e_s_139_berlin_words_crib_test.py
"""
import json
import math
import os
import sys
from collections import Counter
from pathlib import Path

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)

# ── Known keystream at crib positions (Vigenere convention) ──────────────
KNOWN_VIG_KEY = {}
for i, k in enumerate(VIGENERE_KEY_ENE):
    KNOWN_VIG_KEY[21 + i] = k
for i, k in enumerate(VIGENERE_KEY_BC):
    KNOWN_VIG_KEY[63 + i] = k

KNOWN_BEA_KEY = {}
for i, k in enumerate(BEAUFORT_KEY_ENE):
    KNOWN_BEA_KEY[21 + i] = k
for i, k in enumerate(BEAUFORT_KEY_BC):
    KNOWN_BEA_KEY[63 + i] = k

# ── Candidate words ─────────────────────────────────────────────────────
CANDIDATES = [
    "CHECKPOINT",       # 10 chars — Berlin Wall crossing
    "BERLINWALL",       # 10 chars
    "THEWALL",          # 7 chars
    "REMEMBER",         # 8 chars
    "MEMORIAL",         # 8 chars
    "REMINDER",         # 8 chars
    "WHATSTHEPOINT",    # 13 chars
    "THEPOINT",         # 8 chars
    "POINT",            # 5 chars
    "SECRET",           # 6 chars
    "ASECRET",          # 7 chars
    "INVISIBLE",        # 9 chars
    "MESSAGE",          # 7 chars
    "WALL",             # 4 chars
    "DISCOVERED",       # 10 chars
    "FOUND",            # 5 chars
    "BURIED",           # 6 chars
    "FREEDOM",          # 7 chars
]

# ── English letter frequency (for running key detection) ────────────────
ENGLISH_FREQ = {
    'A': 0.0817, 'B': 0.0150, 'C': 0.0278, 'D': 0.0425, 'E': 0.1270,
    'F': 0.0223, 'G': 0.0202, 'H': 0.0609, 'I': 0.0697, 'J': 0.0015,
    'K': 0.0077, 'L': 0.0403, 'M': 0.0241, 'N': 0.0675, 'O': 0.0751,
    'P': 0.0193, 'Q': 0.0010, 'R': 0.0599, 'S': 0.0633, 'T': 0.0906,
    'U': 0.0276, 'V': 0.0098, 'W': 0.0236, 'X': 0.0015, 'Y': 0.0197,
    'Z': 0.0007,
}
ENG_FREQ_VEC = [ENGLISH_FREQ[chr(65 + i)] for i in range(26)]


def vig_key(ct_char, pt_char):
    """Vigenere keystream value: K = (CT - PT) mod 26."""
    return (ALPH_IDX[ct_char] - ALPH_IDX[pt_char]) % MOD


def bea_key(ct_char, pt_char):
    """Beaufort keystream value: K = (CT + PT) mod 26."""
    return (ALPH_IDX[ct_char] + ALPH_IDX[pt_char]) % MOD


def check_bean(all_crib_dict):
    """Check Bean EQ and INEQ constraints against a combined crib dict.

    Returns (eq_pass, ineq_pass, ineq_violations) where:
    - eq_pass: True if all equality constraints satisfied or not testable
    - ineq_pass: True if all inequality constraints satisfied or not testable
    - ineq_violations: list of violated (i, j) pairs
    """
    # Compute Vigenere keystream at all known positions
    key_at = {}
    for pos, pt_ch in all_crib_dict.items():
        key_at[pos] = vig_key(CT[pos], pt_ch)

    # Check equalities
    eq_pass = True
    for (i, j) in BEAN_EQ:
        if i in key_at and j in key_at:
            if key_at[i] != key_at[j]:
                eq_pass = False

    # Check inequalities
    ineq_violations = []
    for (i, j) in BEAN_INEQ:
        if i in key_at and j in key_at:
            if key_at[i] == key_at[j]:
                ineq_violations.append((i, j))

    ineq_pass = len(ineq_violations) == 0
    return eq_pass, ineq_pass, ineq_violations


def keystream_english_score(key_values):
    """Score how English-like a keystream fragment is.

    For a running key cipher, the keystream IS English text, so its letter
    frequencies should match English. Returns correlation coefficient with
    English frequency distribution.
    """
    if len(key_values) < 3:
        return 0.0

    counts = Counter(key_values)
    total = len(key_values)
    observed = [counts.get(i, 0) / total for i in range(26)]

    # Pearson correlation with English frequency
    mean_obs = sum(observed) / 26
    mean_eng = sum(ENG_FREQ_VEC) / 26

    num = sum((observed[i] - mean_obs) * (ENG_FREQ_VEC[i] - mean_eng) for i in range(26))
    den_obs = math.sqrt(sum((observed[i] - mean_obs) ** 2 for i in range(26)))
    den_eng = math.sqrt(sum((ENG_FREQ_VEC[i] - mean_eng) ** 2 for i in range(26)))

    if den_obs == 0 or den_eng == 0:
        return 0.0

    return num / (den_obs * den_eng)


def keystream_periodicity(key_at_positions):
    """Check if combined keystream shows periodicity at any period 2-26.

    Returns dict of period -> number of consistent residue classes.
    """
    results = {}
    positions = sorted(key_at_positions.keys())

    for period in range(2, 27):
        consistent = 0
        total_classes = 0
        for residue in range(period):
            class_positions = [p for p in positions if p % period == residue]
            if len(class_positions) >= 2:
                total_classes += 1
                vals = [key_at_positions[p] for p in class_positions]
                if len(set(vals)) == 1:
                    consistent += 1

        if total_classes > 0:
            results[period] = (consistent, total_classes, consistent / total_classes)

    return results


def keystream_readable(key_values):
    """Convert keystream values to letters (A=0, B=1, ..., Z=25)."""
    return ''.join(chr(65 + k) for k in key_values)


def valid_placements(word):
    """Return all valid start positions for a word (no overlap with existing cribs)."""
    word_len = len(word)
    placements = []
    for start in range(CT_LEN - word_len + 1):
        end = start + word_len - 1  # inclusive
        word_positions = set(range(start, start + word_len))
        if not word_positions.intersection(CRIB_POSITIONS):
            placements.append(start)
    return placements


def analyze_placement(word, start):
    """Analyze a word placement at a given start position.

    Returns a dict with analysis results.
    """
    # Build combined crib dict
    combined = dict(CRIB_DICT)
    for i, ch in enumerate(word):
        combined[start + i] = ch

    # Check Bean constraints
    eq_pass, ineq_pass, ineq_violations = check_bean(combined)

    # Compute keystream at new positions
    vig_keys = []
    bea_keys = []
    for i, ch in enumerate(word):
        pos = start + i
        vig_keys.append(vig_key(CT[pos], ch))
        bea_keys.append(bea_key(CT[pos], ch))

    # Build full keystream map (Vigenere)
    full_vig_key = dict(KNOWN_VIG_KEY)
    for i, ch in enumerate(word):
        pos = start + i
        full_vig_key[pos] = vig_key(CT[pos], ch)

    full_bea_key = dict(KNOWN_BEA_KEY)
    for i, ch in enumerate(word):
        pos = start + i
        full_bea_key[pos] = bea_key(CT[pos], ch)

    # Keystream as readable text
    vig_text = keystream_readable(vig_keys)
    bea_text = keystream_readable(bea_keys)

    # English-likeness of full keystream
    all_vig_values = list(full_vig_key.values())
    all_bea_values = list(full_bea_key.values())
    vig_eng_corr = keystream_english_score(all_vig_values)
    bea_eng_corr = keystream_english_score(all_bea_values)

    # Keystream overlap: how many new key values match existing crib key values
    existing_vig_set = set(KNOWN_VIG_KEY.values())
    vig_overlap = sum(1 for k in vig_keys if k in existing_vig_set)

    existing_bea_set = set(KNOWN_BEA_KEY.values())
    bea_overlap = sum(1 for k in bea_keys if k in existing_bea_set)

    # Periodicity check
    vig_periodicity = keystream_periodicity(full_vig_key)

    # Find best periodic fit
    best_period = None
    best_period_ratio = 0
    for p, (cons, total, ratio) in vig_periodicity.items():
        if total >= 3 and ratio > best_period_ratio:
            best_period_ratio = ratio
            best_period = p

    return {
        'word': word,
        'start': start,
        'end': start + len(word) - 1,
        'bean_eq_pass': eq_pass,
        'bean_ineq_pass': ineq_pass,
        'bean_violations': len(ineq_violations),
        'bean_violation_pairs': ineq_violations,
        'vig_keystream': vig_text,
        'bea_keystream': bea_text,
        'vig_keystream_nums': vig_keys,
        'bea_keystream_nums': bea_keys,
        'vig_eng_corr': vig_eng_corr,
        'bea_eng_corr': bea_eng_corr,
        'vig_overlap': vig_overlap,
        'bea_overlap': bea_overlap,
        'best_period': best_period,
        'best_period_ratio': best_period_ratio,
        'total_known': len(full_vig_key),
    }


def main():
    print("=" * 80)
    print("E-S-139: Berlin-themed words as additional cribs")
    print("=" * 80)
    print()
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Known cribs: {N_CRIBS} positions")
    print(f"Existing crib positions: 21-33 (ENE), 63-73 (BC)")
    print()

    all_results = {}
    summary_rows = []

    for word in CANDIDATES:
        placements = valid_placements(word)
        print(f"\n{'─' * 70}")
        print(f"Word: {word} ({len(word)} chars), {len(placements)} valid placements")
        print(f"{'─' * 70}")

        word_results = []
        bean_pass_count = 0

        for start in placements:
            result = analyze_placement(word, start)
            word_results.append(result)

            if result['bean_eq_pass'] and result['bean_ineq_pass']:
                bean_pass_count += 1

        # Sort by composite score: Bean pass, then English correlation
        word_results.sort(key=lambda r: (
            r['bean_eq_pass'] and r['bean_ineq_pass'],  # Bean pass first
            max(r['vig_eng_corr'], r['bea_eng_corr']),   # Then English-likeness
        ), reverse=True)

        print(f"Bean PASS: {bean_pass_count}/{len(placements)} placements")

        # Show top 5
        print(f"\nTop 5 placements (by Bean + English keystream correlation):")
        print(f"{'Start':>5} {'End':>3} {'Bean':>6} {'Vio':>3} "
              f"{'Vig Key':>15} {'Bea Key':>15} "
              f"{'Vig r':>6} {'Bea r':>6} {'Best p':>6}")

        for r in word_results[:5]:
            bean_str = "PASS" if (r['bean_eq_pass'] and r['bean_ineq_pass']) else "FAIL"
            print(f"{r['start']:>5} {r['end']:>3} {bean_str:>6} {r['bean_violations']:>3} "
                  f"{r['vig_keystream']:>15} {r['bea_keystream']:>15} "
                  f"{r['vig_eng_corr']:>6.3f} {r['bea_eng_corr']:>6.3f} "
                  f"{r['best_period'] or '-':>6}")

        # Also show Bean-failing placements with interesting keystreams
        bean_failing_interesting = [r for r in word_results
                                    if not (r['bean_eq_pass'] and r['bean_ineq_pass'])
                                    and max(r['vig_eng_corr'], r['bea_eng_corr']) > 0.3]
        if bean_failing_interesting:
            print(f"\nBean-failing but high English correlation (r > 0.3):")
            for r in bean_failing_interesting[:3]:
                print(f"  pos {r['start']}-{r['end']}: "
                      f"Vig={r['vig_keystream']} (r={r['vig_eng_corr']:.3f}), "
                      f"Bea={r['bea_keystream']} (r={r['bea_eng_corr']:.3f}), "
                      f"{r['bean_violations']} Bean violations")

        # Record summary
        best = word_results[0] if word_results else None
        if best:
            summary_rows.append({
                'word': word,
                'n_placements': len(placements),
                'n_bean_pass': bean_pass_count,
                'best_start': best['start'],
                'best_bean': best['bean_eq_pass'] and best['bean_ineq_pass'],
                'best_vig_r': best['vig_eng_corr'],
                'best_bea_r': best['bea_eng_corr'],
                'best_vig_key': best['vig_keystream'],
            })

        all_results[word] = word_results

    # ── Summary table ────────────────────────────────────────────────────
    print("\n\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"\n{'Word':<15} {'#Place':>6} {'#Bean':>5} {'Best@':>5} "
          f"{'Bean':>5} {'Vig r':>6} {'Bea r':>6} {'Vig Key'}")
    print("─" * 80)

    for row in summary_rows:
        bean_str = "PASS" if row['best_bean'] else "FAIL"
        print(f"{row['word']:<15} {row['n_placements']:>6} {row['n_bean_pass']:>5} "
              f"{row['best_start']:>5} {bean_str:>5} "
              f"{row['best_vig_r']:>6.3f} {row['best_bea_r']:>6.3f} "
              f"{row['best_vig_key']}")

    # ── Detailed analysis: POINT at specific positions ───────────────────
    print("\n\n" + "=" * 80)
    print("DETAILED: POINT at recommended positions (from clue analysis)")
    print("=" * 80)

    point_positions = [92, 87, 74, 34, 0, 5, 10, 15]
    for start in point_positions:
        if start + 5 > CT_LEN:
            continue
        word_positions = set(range(start, start + 5))
        if word_positions.intersection(CRIB_POSITIONS):
            print(f"\nPOINT@{start}: OVERLAPS with existing cribs — skipped")
            continue

        r = analyze_placement("POINT", start)
        bean_str = "PASS" if (r['bean_eq_pass'] and r['bean_ineq_pass']) else "FAIL"
        print(f"\nPOINT@{start}-{start+4}: Bean={bean_str} (violations={r['bean_violations']})")
        print(f"  Vig keystream: {r['vig_keystream']} = {r['vig_keystream_nums']}")
        print(f"  Bea keystream: {r['bea_keystream']} = {r['bea_keystream_nums']}")
        if r['bean_violation_pairs']:
            print(f"  Bean violations: {r['bean_violation_pairs']}")

    # ── Detailed analysis: THEPOINT and REMINDER at end ──────────────────
    print("\n\n" + "=" * 80)
    print("DETAILED: THEPOINT and REMINDER near end of plaintext")
    print("=" * 80)

    for word in ["THEPOINT", "REMINDER", "AREMINDER"]:
        # Try near the end
        for start in range(74, CT_LEN - len(word) + 1):
            word_positions = set(range(start, start + len(word)))
            if word_positions.intersection(CRIB_POSITIONS):
                continue
            r = analyze_placement(word, start)
            bean_str = "PASS" if (r['bean_eq_pass'] and r['bean_ineq_pass']) else "FAIL"
            print(f"\n{word}@{start}-{start+len(word)-1}: Bean={bean_str} (violations={r['bean_violations']})")
            print(f"  Vig keystream: {r['vig_keystream']} = {r['vig_keystream_nums']}")
            print(f"  Bea keystream: {r['bea_keystream']} = {r['bea_keystream_nums']}")

    # ── Detailed analysis: Combined cribs test ───────────────────────────
    print("\n\n" + "=" * 80)
    print("DETAILED: Compound crib test (POINT@92 + THEWALL at various positions)")
    print("=" * 80)

    # Test POINT at position 92 combined with THEWALL at various positions
    point_start = 92
    if point_start + 5 <= CT_LEN:
        for wall_start in range(0, 21 - 6):  # THEWALL in first segment (before ENE)
            combined = dict(CRIB_DICT)
            for i, ch in enumerate("POINT"):
                combined[point_start + i] = ch
            for i, ch in enumerate("THEWALL"):
                combined[wall_start + i] = ch

            eq_pass, ineq_pass, violations = check_bean(combined)
            if eq_pass and ineq_pass:
                # Compute full keystream
                full_key = {}
                for pos, pt_ch in combined.items():
                    full_key[pos] = vig_key(CT[pos], pt_ch)

                vig_text_point = keystream_readable([vig_key(CT[point_start+i], "POINT"[i]) for i in range(5)])
                vig_text_wall = keystream_readable([vig_key(CT[wall_start+i], "THEWALL"[i]) for i in range(7)])

                eng_corr = keystream_english_score(list(full_key.values()))
                print(f"  THEWALL@{wall_start} + POINT@{point_start}: Bean PASS, "
                      f"Vig keys: WALL={vig_text_wall} POINT={vig_text_point}, "
                      f"English r={eng_corr:.3f}")

    # Also test in middle segment
    for wall_start in range(34, 63 - 6):
        combined = dict(CRIB_DICT)
        for i, ch in enumerate("POINT"):
            combined[point_start + i] = ch
        for i, ch in enumerate("THEWALL"):
            combined[wall_start + i] = ch

        eq_pass, ineq_pass, violations = check_bean(combined)
        if eq_pass and ineq_pass:
            full_key = {}
            for pos, pt_ch in combined.items():
                full_key[pos] = vig_key(CT[pos], pt_ch)

            vig_text_point = keystream_readable([vig_key(CT[point_start+i], "POINT"[i]) for i in range(5)])
            vig_text_wall = keystream_readable([vig_key(CT[wall_start+i], "THEWALL"[i]) for i in range(7)])

            eng_corr = keystream_english_score(list(full_key.values()))
            print(f"  THEWALL@{wall_start} + POINT@{point_start}: Bean PASS, "
                  f"Vig keys: WALL={vig_text_wall} POINT={vig_text_point}, "
                  f"English r={eng_corr:.3f}")

    # ── Save results ─────────────────────────────────────────────────────
    outdir = Path("results/e_s_139")
    outdir.mkdir(parents=True, exist_ok=True)

    # Save summary
    summary_path = outdir / "summary.json"
    with open(summary_path, 'w') as f:
        json.dump(summary_rows, f, indent=2)

    # Save detailed results for top placements per word
    detail_path = outdir / "top_placements.json"
    top_details = {}
    for word, results in all_results.items():
        top_details[word] = [
            {k: v for k, v in r.items() if k != 'bean_violation_pairs'}
            for r in results[:10]
        ]
    with open(detail_path, 'w') as f:
        json.dump(top_details, f, indent=2)

    print(f"\n\nResults saved to {outdir}/")
    print("Done.")


if __name__ == "__main__":
    main()
