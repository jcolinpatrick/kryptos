#!/usr/bin/env python3
"""
# ── Metadata ──────────────────────────────────────────────────────────────
# Cipher:     Periodic Vigenere/Beaufort on null-extracted CT
# Family:     polyalphabetic
# Status:     active
# Keyspace:   ~50K keywords × 3 variants × 2 alphabets = ~300K configs
# Last run:   2026-03-24
# Best score: TBD
# ──────────────────────────────────────────────────────────────────────────
#
# Campaign V3 dead end #53: "Remove the 17 consensus nulls, apply standard
# Vigenere/Beaufort with ALL short keywords."
#
# The hypothesis: the cipher layer is simple periodic polyalphabetic
# (Vigenere or Beaufort) with a short keyword, applied to the REAL
# characters only. The null insertion layer was applied AFTER encryption.
# Prior exhaustive sweeps tested periodic ciphers on the full 97-char CT,
# which fails because null positions inject noise into the period.
# Removing nulls first changes which positions align with which key
# positions — a fundamentally different test.
#
# This script:
# 1. Removes 17 consensus null positions → 80-char extracted CT
# 2. Maps cribs from 97-char to 80-char positions
# 3. Tests ALL keywords from english.txt (length 2-15) + thematic keywords
# 4. Three cipher variants × two alphabets (AZ, KA)
# 5. Crib-only scoring for speed, full decrypt for top hits
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

from __future__ import annotations

import sys
import os
import time
import json

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    KRYPTOS_ALPHABET,
    BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD,
)
from kryptos.kernel.alphabet import AZ, KA


# ═══════════════════════════════════════════════════════════════════════════
# SETUP
# ═══════════════════════════════════════════════════════════════════════════

def extract_non_null(ct, null_positions):
    """Remove null positions, return (extracted_ct, position_map)."""
    chars, pos_map = [], []
    for i, c in enumerate(ct):
        if i not in null_positions:
            chars.append(c)
            pos_map.append(i)
    return ''.join(chars), pos_map


def map_cribs(crib_dict, pos_map):
    """Map crib positions to compressed indices.
    Returns list of (compressed_idx, expected_pt_num).
    """
    rev = {orig: comp for comp, orig in enumerate(pos_map)}
    mapped = []
    for orig_pos, letter in crib_dict.items():
        if orig_pos in rev:
            mapped.append((rev[orig_pos], ALPH_IDX[letter]))
    return mapped


def load_keywords():
    """Load keywords from both thematic and english wordlists."""
    keywords = set()

    # Thematic keywords
    thematic_path = os.path.join(_ROOT, "wordlists", "thematic_keywords.txt")
    if os.path.exists(thematic_path):
        with open(thematic_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                word = ''.join(c for c in line if c.isalpha()).upper()
                if 2 <= len(word) <= 15:
                    keywords.add(word)

    # English wordlist
    english_path = os.path.join(_ROOT, "wordlists", "english.txt")
    if os.path.exists(english_path):
        with open(english_path) as f:
            for line in f:
                word = line.strip().upper()
                if word.isascii() and word.isalpha() and 2 <= len(word) <= 15:
                    keywords.add(word)

    # Explicit Kryptos-related keywords
    for kw in [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "DEFECTOR",
        "BERLINCLOCK", "EASTNORTHEAST", "POINT", "SEVEN", "CIPHER",
        "SCHEIDT", "SANBORN", "ENIGMA", "VIGENERE", "BEAUFORT",
        "TABLEAU", "MATRIX", "GUILD", "WEBSTER", "LONGITUDE",
        "LATITUDE", "COMPASS", "LODESTONE", "IQLUSION", "UNDERGRUUND",
        "DESPARATLY", "LAYERTWO", "IDBYROWS", "LANGLEY", "BURIED",
        "MAGNETIC", "INVISIBLE", "NORTHWEST", "SOUTHEAST",
    ]:
        keywords.add(kw)

    return sorted(keywords)


# ═══════════════════════════════════════════════════════════════════════════
# CORE ATTACK
# ═══════════════════════════════════════════════════════════════════════════

def attack_sweep(ct_extracted, ct_nums, cribs, keywords, alphabet_name, alphabet_idx):
    """Sweep all keywords × 3 variants on the extracted CT.
    Only decrypts at crib positions for speed.
    Returns list of results above noise floor.
    """
    results = []
    best_score = 0
    tested = 0

    for kw in keywords:
        kw_nums = [alphabet_idx[c] for c in kw]
        kw_len = len(kw_nums)

        for variant in ('vig', 'beau', 'varbeau'):
            matches = 0
            for pos, expected in cribs:
                key_val = kw_nums[pos % kw_len]
                ct_val = ct_nums[pos]

                if variant == 'vig':
                    pt_val = (ct_val - key_val) % 26
                elif variant == 'beau':
                    pt_val = (key_val - ct_val) % 26
                else:  # varbeau
                    pt_val = (ct_val + key_val) % 26

                if pt_val == expected:
                    matches += 1

            tested += 1

            if matches > best_score:
                best_score = matches

            if matches >= NOISE_FLOOR:
                results.append({
                    'score': matches,
                    'keyword': kw,
                    'variant': variant,
                    'alphabet': alphabet_name,
                    'period': len(kw),
                })

    return results, tested, best_score


def check_bean(ct_nums, kw_nums, kw_len, variant, alphabet_idx, pos_map):
    """Check Bean constraints for a given keyword/variant on extracted text."""
    # Map original Bean positions to compressed positions
    rev = {orig: comp for comp, orig in enumerate(pos_map)}

    # Bean equality: k[27] == k[65]
    for a, b in BEAN_EQ:
        if a in rev and b in rev:
            ca, cb = rev[a], rev[b]
            ka = kw_nums[ca % kw_len]
            kb = kw_nums[cb % kw_len]
            if ka != kb:
                return False

    # Bean inequalities (sample — check first 50 for speed)
    checked = 0
    for a, b in BEAN_INEQ:
        if a in rev and b in rev:
            ca, cb = rev[a], rev[b]
            ka = kw_nums[ca % kw_len]
            kb = kw_nums[cb % kw_len]
            if ka == kb:
                # Derive actual keystream values and check
                ct_a = ct_nums[ca]
                ct_b = ct_nums[cb]
                if variant == 'vig':
                    k_a = (ct_a - ALPH_IDX[CRIB_DICT.get(a, 'A')]) % 26 if a in CRIB_DICT else ka
                    k_b = (ct_b - ALPH_IDX[CRIB_DICT.get(b, 'A')]) % 26 if b in CRIB_DICT else kb
                elif variant == 'beau':
                    k_a = (ct_a + ALPH_IDX[CRIB_DICT.get(a, 'A')]) % 26 if a in CRIB_DICT else ka
                    k_b = (ct_b + ALPH_IDX[CRIB_DICT.get(b, 'A')]) % 26 if b in CRIB_DICT else kb
                else:
                    k_a = (ALPH_IDX[CRIB_DICT.get(a, 'A')] - ct_a) % 26 if a in CRIB_DICT else ka
                    k_b = (ALPH_IDX[CRIB_DICT.get(b, 'A')] - ct_b) % 26 if b in CRIB_DICT else kb
                if k_a == k_b and a in CRIB_DICT and b in CRIB_DICT:
                    return False
            checked += 1

    return True


def full_decrypt(ct_nums, kw_nums, kw_len, variant):
    """Full decryption for display."""
    pt = []
    for i, ct_val in enumerate(ct_nums):
        key_val = kw_nums[i % kw_len]
        if variant == 'vig':
            p = (ct_val - key_val) % 26
        elif variant == 'beau':
            p = (key_val - ct_val) % 26
        else:
            p = (ct_val + key_val) % 26
        pt.append(ALPH[p])
    return ''.join(pt)


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 78)
    print("NULL-EXTRACTED KEYWORD SWEEP")
    print("Remove 17 consensus nulls → 80-char CT → periodic keyword attack")
    print("=" * 78)
    print()

    # Extract non-null CT
    ct_extracted, pos_map = extract_non_null(CT, CONSENSUS_NULL_POSITIONS)
    print(f"Original CT: {CT_LEN} chars")
    print(f"Consensus nulls removed: {len(CONSENSUS_NULL_POSITIONS)}")
    print(f"Extracted CT: {len(ct_extracted)} chars")
    print(f"Extracted: {ct_extracted}")
    print()

    # Map cribs
    cribs = map_cribs(CRIB_DICT, pos_map)
    print(f"Mapped cribs: {len(cribs)}/{N_CRIBS}")
    print()

    # Load keywords
    keywords = load_keywords()
    print(f"Keywords loaded: {len(keywords)}")
    by_len = {}
    for kw in keywords:
        l = len(kw)
        by_len[l] = by_len.get(l, 0) + 1
    print(f"By length: {dict(sorted(by_len.items()))}")
    print()

    # Prepare alphabets
    az_idx = {c: i for i, c in enumerate(ALPH)}
    ka_idx = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

    # Prepare CT nums for both alphabets
    ct_nums_az = [az_idx[c] for c in ct_extracted]
    ct_nums_ka = [ka_idx[c] for c in ct_extracted]

    # Map cribs for both alphabets
    cribs_az = [(pos, az_idx[ALPH[val]]) for pos, val in cribs]  # val is already AZ-indexed
    cribs_ka = [(pos, ka_idx[ALPH[val]]) for pos, val in cribs]  # convert to KA index

    total_configs = len(keywords) * 3 * 2  # keywords × variants × alphabets
    print(f"Total configs: {len(keywords)} × 3 variants × 2 alphabets = {total_configs:,}")
    print()

    # ── Run sweep ──
    t0 = time.time()
    all_results = []

    # AZ alphabet
    print("── Standard alphabet (AZ) ──")
    res_az, tested_az, best_az = attack_sweep(
        ct_extracted, ct_nums_az, cribs_az, keywords, "AZ", az_idx
    )
    all_results.extend(res_az)
    print(f"  Tested: {tested_az:,}, Best: {best_az}/{N_CRIBS}, "
          f"Hits >= {NOISE_FLOOR}: {len(res_az)}")

    # KA alphabet
    print("── Kryptos alphabet (KA) ──")
    res_ka, tested_ka, best_ka = attack_sweep(
        ct_extracted, ct_nums_ka, cribs_ka, keywords, "KA", ka_idx
    )
    all_results.extend(res_ka)
    print(f"  Tested: {tested_ka:,}, Best: {best_ka}/{N_CRIBS}, "
          f"Hits >= {NOISE_FLOOR}: {len(res_ka)}")

    elapsed = time.time() - t0
    total_tested = tested_az + tested_ka
    best_overall = max(best_az, best_ka)

    print()
    print("=" * 78)
    print(f"COMPLETE: {total_tested:,} configs in {elapsed:.1f}s "
          f"({total_tested/elapsed:,.0f}/s)")
    print(f"Best score: {best_overall}/{N_CRIBS}")
    print()

    # ── Report top results ──
    all_results.sort(key=lambda x: -x['score'])
    if all_results:
        print(f"Top results (score >= {NOISE_FLOOR}):")
        print("-" * 78)
        seen = set()
        for r in all_results[:30]:
            key = (r['keyword'], r['variant'], r['alphabet'])
            if key in seen:
                continue
            seen.add(key)

            # Full decrypt for display
            if r['alphabet'] == 'AZ':
                kw_nums = [az_idx[c] for c in r['keyword']]
                ct_n = ct_nums_az
            else:
                kw_nums = [ka_idx[c] for c in r['keyword']]
                ct_n = ct_nums_ka
            pt = full_decrypt(ct_n, kw_nums, len(kw_nums), r['variant'])

            # Bean check
            bean = check_bean(ct_n, kw_nums, len(kw_nums), r['variant'],
                              az_idx if r['alphabet'] == 'AZ' else ka_idx, pos_map)

            print(f"  {r['score']}/{N_CRIBS} | {r['alphabet']}/{r['variant']} "
                  f"period={r['period']} kw={r['keyword']} "
                  f"bean={'PASS' if bean else 'FAIL'}")
            print(f"    PT: {pt}")
            print()
    else:
        print("No results above noise floor.")

    # ── Save results ──
    result_path = os.path.join(_ROOT, "results", "null_extracted_keyword_sweep.json")
    os.makedirs(os.path.dirname(result_path), exist_ok=True)
    result_data = {
        'experiment': 'e_null_extracted_keyword_sweep',
        'hypothesis': 'Periodic cipher on null-extracted 80-char CT',
        'null_positions': sorted(CONSENSUS_NULL_POSITIONS),
        'extracted_length': len(ct_extracted),
        'configs_tested': total_tested,
        'elapsed_s': round(elapsed, 1),
        'best_score': best_overall,
        'n_cribs': N_CRIBS,
        'n_keywords': len(keywords),
        'alphabets': ['AZ', 'KA'],
        'variants': ['vig', 'beau', 'varbeau'],
        'top_results': all_results[:20],
        'verdict': 'TBD',
    }
    with open(result_path, 'w') as f:
        json.dump(result_data, f, indent=2)
    print(f"Results saved to {result_path}")

    # ── Verdict ──
    print()
    if best_overall >= SIGNAL_THRESHOLD:
        print(f"*** SIGNAL: {best_overall}/{N_CRIBS} — INVESTIGATE ***")
    elif best_overall >= STORE_THRESHOLD:
        print(f"INTERESTING: {best_overall}/{N_CRIBS} — worth investigating")
    else:
        print(f"NOISE: {best_overall}/{N_CRIBS} — periodic cipher on null-extracted "
              f"CT produces no signal with {len(keywords)} keywords")

    return best_overall


if __name__ == "__main__":
    main()
