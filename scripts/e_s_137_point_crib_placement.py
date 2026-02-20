#!/usr/bin/env python3
"""E-S-137: Algebraic placement analysis for POINT / THEPOINT / WHATSTHEPOINT.

Sanborn's August 2025 open letter contains: "(CLUE) what's the point?"
The explicit (CLUE) marker suggests POINT-related text appears in K4 plaintext.

This experiment tests all valid placements of candidate crib words and checks:
1. Bean constraint compatibility (EQ and all 21 INEQ)
2. Keystream patterns (repeated values suggesting periodicity, low entropy)
3. Keystream compatibility with structured key models
4. Overlap with known crib keystream values
5. English-plausible keystream (running key hypothesis)

Candidate cribs: POINT, THEPOINT, WHATSTHEPOINT, THEPOINTF (for adjacency testing)
All positions 0-indexed per project convention.

Output: results/e_s_137_point_placement.json
"""

import json
import math
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_ENTRIES, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]

# Existing crib data
EXISTING_CRIBS = {pos: ch for pos, ch in CRIB_ENTRIES}
EXISTING_CRIB_POS = set(EXISTING_CRIBS.keys())

# Known keystream values (Vigenere: K = CT - PT mod 26)
KNOWN_KEY_VIG = {}
for pos, ch in EXISTING_CRIBS.items():
    KNOWN_KEY_VIG[pos] = (CT_NUM[pos] - ALPH_IDX[ch]) % MOD

# Known keystream values (Beaufort: K = CT + PT mod 26)
KNOWN_KEY_BEAU = {}
for pos, ch in EXISTING_CRIBS.items():
    KNOWN_KEY_BEAU[pos] = (CT_NUM[pos] + ALPH_IDX[ch]) % MOD

# Bean constraints
BEAN_EQ_POS = BEAN_EQ[0]  # (27, 65) — k[27] = k[65]
BEAN_INEQ_PAIRS = BEAN_INEQ  # list of (i, j) where k[i] != k[j]


def compute_keystream(word, start_pos, variant='vigenere'):
    """Compute keystream values for word at start_pos."""
    keys = {}
    for i, ch in enumerate(word):
        pos = start_pos + i
        pt_num = ALPH_IDX[ch]
        ct_num = CT_NUM[pos]
        if variant == 'vigenere':
            keys[pos] = (ct_num - pt_num) % MOD
        elif variant == 'beaufort':
            keys[pos] = (ct_num + pt_num) % MOD
        elif variant == 'var_beaufort':
            keys[pos] = (pt_num - ct_num) % MOD
    return keys


def check_bean(combined_keys):
    """Check Bean EQ and INEQ constraints against combined keystream."""
    eq_a, eq_b = BEAN_EQ_POS
    # Check EQ
    if eq_a in combined_keys and eq_b in combined_keys:
        if combined_keys[eq_a] != combined_keys[eq_b]:
            return False, f"Bean EQ FAIL: k[{eq_a}]={combined_keys[eq_a]} != k[{eq_b}]={combined_keys[eq_b]}"
    # Check INEQ
    for ia, ib in BEAN_INEQ_PAIRS:
        if ia in combined_keys and ib in combined_keys:
            if combined_keys[ia] == combined_keys[ib]:
                return False, f"Bean INEQ FAIL: k[{ia}]=k[{ib}]={combined_keys[ia]}"
    return True, "Bean PASS"


def keystream_entropy(keys_dict):
    """Shannon entropy of keystream values (lower = more structured)."""
    if not keys_dict:
        return 0.0
    vals = list(keys_dict.values())
    counts = Counter(vals)
    n = len(vals)
    entropy = 0.0
    for c in counts.values():
        p = c / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def check_periodicity(combined_keys, max_period=26):
    """Check if keystream is consistent with any period p."""
    positions = sorted(combined_keys.keys())
    results = {}
    for p in range(2, max_period + 1):
        consistent = True
        # Group positions by residue mod p
        residue_groups = {}
        for pos in positions:
            r = pos % p
            if r not in residue_groups:
                residue_groups[r] = set()
            residue_groups[r].add(combined_keys[pos])
        # Check if any residue group has conflicting values
        for r, vals in residue_groups.items():
            if len(vals) > 1:
                consistent = False
                break
        results[p] = consistent
    return results


def count_key_repeats(combined_keys):
    """Count how many keystream values are repeated across positions."""
    vals = list(combined_keys.values())
    counts = Counter(vals)
    return sum(1 for v, c in counts.items() if c > 1)


def english_letter_score(keys_dict):
    """Score keystream values as if they were English letter frequencies."""
    # English letter frequencies (A=0, B=1, ..., Z=25)
    eng_freq = [0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020, 0.061,
                0.070, 0.002, 0.008, 0.040, 0.024, 0.067, 0.075, 0.019,
                0.001, 0.060, 0.063, 0.091, 0.028, 0.010, 0.023, 0.002,
                0.020, 0.001]
    vals = list(keys_dict.values())
    if not vals:
        return 0.0
    score = sum(math.log(eng_freq[v] + 1e-10) for v in vals)
    return score / len(vals)


def main():
    print("=" * 70)
    print("E-S-137: POINT Crib Placement Analysis")
    print("=" * 70)
    print()
    print("Source: Sanborn Aug 2025 open letter —")
    print('  "(CLUE) what\'s the point?"')
    print()
    print(f"CT: {CT}")
    print(f"Known cribs (0-indexed):")
    print(f"  21-33: EASTNORTHEAST (13 chars)")
    print(f"  63-73: BERLINCLOCK   (11 chars)")
    print(f"  Known key vals (Vig): k[27]={KNOWN_KEY_VIG[27]}, k[65]={KNOWN_KEY_VIG[65]}")
    print()

    # Candidate words to test
    candidates = {
        'POINT': 'POINT',
        'THEPOINT': 'THEPOINT',
        'WHATSTHEPOINT': 'WHATSTHEPOINT',
    }

    all_results = {}

    for word_name, word in candidates.items():
        word_len = len(word)
        print(f"\n{'='*60}")
        print(f"  Testing: {word_name} ({word_len} chars)")
        print(f"{'='*60}")

        valid_positions = []
        for p in range(CT_LEN - word_len + 1):
            # Check no overlap with existing cribs
            word_positions = set(range(p, p + word_len))
            if word_positions & EXISTING_CRIB_POS:
                continue
            valid_positions.append(p)

        print(f"  Valid start positions: {len(valid_positions)}")

        bean_pass = []
        bean_fail = []
        periodic_hits = {}
        best_entropy = (None, float('inf'))
        best_english = (None, float('-inf'))

        for p in valid_positions:
            for variant in ['vigenere', 'beaufort']:
                # Compute new keystream
                new_keys = compute_keystream(word, p, variant)

                # Combine with existing
                combined = dict(KNOWN_KEY_VIG if variant == 'vigenere' else KNOWN_KEY_BEAU)
                combined.update(new_keys)

                # Bean check
                bean_ok, bean_msg = check_bean(combined)

                # Keystream analysis
                entropy = keystream_entropy(combined)
                repeats = count_key_repeats(combined)
                eng_score = english_letter_score(new_keys)

                # Periodicity
                periods = check_periodicity(combined)
                consistent_periods = [p_val for p_val, ok in periods.items() if ok]

                record = {
                    'start': p,
                    'variant': variant,
                    'bean_pass': bean_ok,
                    'bean_msg': bean_msg,
                    'new_key_values': {str(k): v for k, v in sorted(new_keys.items())},
                    'new_key_letters': ''.join(ALPH[v] for v in [new_keys[p+i] for i in range(word_len)]),
                    'entropy': round(entropy, 3),
                    'repeats': repeats,
                    'eng_score': round(eng_score, 3),
                    'consistent_periods': consistent_periods,
                    'n_consistent_periods': len(consistent_periods),
                }

                if bean_ok:
                    bean_pass.append(record)
                else:
                    bean_fail.append(record)

                if entropy < best_entropy[1]:
                    best_entropy = (record, entropy)
                if eng_score > best_english[1]:
                    best_english = (record, eng_score)

                # Track periodic consistency
                for per in consistent_periods:
                    if per not in periodic_hits:
                        periodic_hits[per] = []
                    periodic_hits[per].append(record)

        print(f"\n  Bean results:")
        print(f"    PASS: {len(bean_pass)}  FAIL: {len(bean_fail)}")

        if bean_fail:
            print(f"\n  Bean FAILURES (positions that are ELIMINATED):")
            # Group failures by position
            fail_positions = {}
            for r in bean_fail:
                fp = r['start']
                if fp not in fail_positions:
                    fail_positions[fp] = []
                fail_positions[fp].append(f"{r['variant']}: {r['bean_msg']}")
            for fp in sorted(fail_positions.keys()):
                msgs = fail_positions[fp]
                if len(msgs) >= 2:  # Failed under BOTH variants
                    print(f"    pos {fp}: ELIMINATED (both variants) — {msgs[0]}")
                else:
                    print(f"    pos {fp}: {msgs[0]}")

        # Count positions eliminated under BOTH variants
        fail_by_pos = {}
        for r in bean_fail:
            fp = r['start']
            if fp not in fail_by_pos:
                fail_by_pos[fp] = set()
            fail_by_pos[fp].add(r['variant'])
        both_eliminated = [fp for fp, variants in fail_by_pos.items()
                          if 'vigenere' in variants and 'beaufort' in variants]
        vig_only_eliminated = [fp for fp, variants in fail_by_pos.items()
                              if 'vigenere' in variants and 'beaufort' not in variants]
        beau_only_eliminated = [fp for fp, variants in fail_by_pos.items()
                               if 'beaufort' in variants and 'vigenere' not in variants]

        print(f"\n  Elimination summary:")
        print(f"    Eliminated under BOTH variants: {len(both_eliminated)} positions")
        print(f"    Eliminated Vig only: {len(vig_only_eliminated)} positions")
        print(f"    Eliminated Beau only: {len(beau_only_eliminated)} positions")
        print(f"    Surviving (at least one variant): {len(valid_positions) - len(both_eliminated)} positions")

        # Show keystream for interesting positions
        print(f"\n  Top positions by lowest entropy (most structured keystream):")
        pass_by_entropy = sorted(bean_pass, key=lambda r: r['entropy'])[:10]
        for r in pass_by_entropy:
            print(f"    pos={r['start']:2d} ({r['variant'][:3]}) entropy={r['entropy']:.3f} "
                  f"repeats={r['repeats']} key_letters={r['new_key_letters']} "
                  f"consistent_periods={r['consistent_periods'][:5]}")

        print(f"\n  Top positions by English-plausible keystream:")
        pass_by_english = sorted(bean_pass, key=lambda r: -r['eng_score'])[:10]
        for r in pass_by_english:
            print(f"    pos={r['start']:2d} ({r['variant'][:3]}) eng_score={r['eng_score']:.3f} "
                  f"key_letters={r['new_key_letters']}")

        # Positions consistent with small periods
        print(f"\n  Positions consistent with period <= 7:")
        for per in range(2, 8):
            if per in periodic_hits:
                positions = [(r['start'], r['variant'][:3]) for r in periodic_hits[per]]
                if positions:
                    print(f"    period {per}: {len(positions)} configs — "
                          f"{positions[:8]}{'...' if len(positions) > 8 else ''}")
            else:
                print(f"    period {per}: 0 configs")

        # Check for keystream values that match Bean EQ
        print(f"\n  Positions where new keystream creates k[i]=k[j] (Bean-EQ-like patterns):")
        for r in bean_pass:
            new_keys = {int(k): v for k, v in r['new_key_values'].items()}
            combined = dict(KNOWN_KEY_VIG if r['variant'] == 'vigenere' else KNOWN_KEY_BEAU)
            combined.update(new_keys)
            # Find ALL pairs where k[i] = k[j]
            by_val = {}
            for pos, val in combined.items():
                if val not in by_val:
                    by_val[val] = []
                by_val[val].append(pos)
            for val, positions in by_val.items():
                if len(positions) > 1:
                    # Check if any of the new positions are involved
                    new_involved = [p for p in positions if p in new_keys]
                    if new_involved:
                        existing_involved = [p for p in positions if p not in new_keys]
                        if existing_involved:
                            # New position shares keystream value with existing crib position
                            pass  # tracked below

        # Detailed: positions where POINT keys match existing crib keys
        print(f"\n  Key value overlaps (new position shares k-value with existing crib):")
        overlap_count = {}
        for r in bean_pass:
            new_keys = {int(k): v for k, v in r['new_key_values'].items()}
            known = KNOWN_KEY_VIG if r['variant'] == 'vigenere' else KNOWN_KEY_BEAU
            overlaps = 0
            for npos, nval in new_keys.items():
                for kpos, kval in known.items():
                    if nval == kval:
                        overlaps += 1
                        break
            key = (r['start'], r['variant'])
            overlap_count[key] = overlaps

        top_overlaps = sorted(overlap_count.items(), key=lambda x: -x[1])[:10]
        for (pos, var), count in top_overlaps:
            matching_r = [r for r in bean_pass if r['start'] == pos and r['variant'] == var][0]
            print(f"    pos={pos:2d} ({var[:3]}) overlaps={count}/{word_len} "
                  f"key_letters={matching_r['new_key_letters']}")

        all_results[word_name] = {
            'word': word,
            'word_len': word_len,
            'valid_positions': len(valid_positions),
            'bean_pass': len(bean_pass),
            'bean_fail': len(bean_fail),
            'both_eliminated': sorted(both_eliminated),
            'n_eliminated': len(both_eliminated),
            'n_surviving': len(valid_positions) - len(both_eliminated),
        }

    # ── Adjacent placement test ────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("  ADJACENCY TEST: POINT immediately before EASTNORTHEAST")
    print(f"{'='*60}")
    # POINT at positions 16-20 (0-indexed) → POINTEASTNORTHEAST
    adj_pos = 16  # POINT ends at 20, ENE starts at 21
    print(f"  Testing POINT at position {adj_pos} → POINTEASTNORTHEAST (18 chars, pos 16-33)")
    for variant in ['vigenere', 'beaufort']:
        new_keys = compute_keystream('POINT', adj_pos, variant)
        combined = dict(KNOWN_KEY_VIG if variant == 'vigenere' else KNOWN_KEY_BEAU)
        combined.update(new_keys)
        bean_ok, bean_msg = check_bean(combined)
        key_letters = ''.join(ALPH[v] for v in [new_keys[adj_pos+i] for i in range(5)])

        # Full 18-char keystream for POINTEASTNORTHEAST
        full_keys = {}
        for i, ch in enumerate('POINTEASTNORTHEAST'):
            pos = 16 + i
            pt_num = ALPH_IDX[ch]
            ct_num = CT_NUM[pos]
            if variant == 'vigenere':
                full_keys[pos] = (ct_num - pt_num) % MOD
            else:
                full_keys[pos] = (ct_num + pt_num) % MOD
        full_key_str = ''.join(ALPH[full_keys[16+i]] for i in range(18))

        print(f"  {variant}: Bean={'PASS' if bean_ok else 'FAIL'} "
              f"key_for_POINT={key_letters} "
              f"full_18char_key={full_key_str}")
        if not bean_ok:
            print(f"    {bean_msg}")

    # Also test POINT right after EASTNORTHEAST
    adj_pos2 = 34  # POINT at 34-38
    if adj_pos2 + 5 <= CT_LEN:
        print(f"\n  Testing POINT at position {adj_pos2} → EASTNORTHEASTPOINT (pos 21-38)")
        for variant in ['vigenere', 'beaufort']:
            new_keys = compute_keystream('POINT', adj_pos2, variant)
            combined = dict(KNOWN_KEY_VIG if variant == 'vigenere' else KNOWN_KEY_BEAU)
            combined.update(new_keys)
            bean_ok, bean_msg = check_bean(combined)
            key_letters = ''.join(ALPH[v] for v in [new_keys[adj_pos2+i] for i in range(5)])
            print(f"  {variant}: Bean={'PASS' if bean_ok else 'FAIL'} "
                  f"key_for_POINT={key_letters}")

    # POINT right before BERLINCLOCK
    adj_pos3 = 58  # POINT at 58-62
    print(f"\n  Testing POINT at position {adj_pos3} → POINTBERLINCLOCK (pos 58-73)")
    for variant in ['vigenere', 'beaufort']:
        new_keys = compute_keystream('POINT', adj_pos3, variant)
        combined = dict(KNOWN_KEY_VIG if variant == 'vigenere' else KNOWN_KEY_BEAU)
        combined.update(new_keys)
        bean_ok, bean_msg = check_bean(combined)
        key_letters = ''.join(ALPH[v] for v in [new_keys[adj_pos3+i] for i in range(5)])

        full_keys = {}
        for i, ch in enumerate('POINTBERLINCLOCK'):
            pos = 58 + i
            pt_num = ALPH_IDX[ch]
            ct_num = CT_NUM[pos]
            if variant == 'vigenere':
                full_keys[pos] = (ct_num - pt_num) % MOD
            else:
                full_keys[pos] = (ct_num + pt_num) % MOD
        full_key_str = ''.join(ALPH[full_keys[58+i]] for i in range(16))

        print(f"  {variant}: Bean={'PASS' if bean_ok else 'FAIL'} "
              f"key_for_POINT={key_letters} "
              f"full_16char_key={full_key_str}")

    # ── Summary ────────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    for word_name, data in all_results.items():
        print(f"  {word_name:20s}: {data['valid_positions']} valid positions, "
              f"{data['n_eliminated']} Bean-eliminated (both variants), "
              f"{data['n_surviving']} surviving")

    print(f"\nKey insight: Bean constraints eliminate specific positions where")
    print(f"POINT would force k[i]=k[j] for a Bean INEQ pair, or k[27]!=k[65].")
    print(f"Surviving positions are algebraically compatible with all known constraints.")

    # Save
    os.makedirs("results", exist_ok=True)
    artifact = {
        "experiment_id": "e_s_137",
        "hypothesis": "POINT/THEPOINT/WHATSTHEPOINT appears in K4 plaintext",
        "source": "Sanborn Aug 2025 open letter: '(CLUE) what\\'s the point?'",
        "results": all_results,
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_s_137_point_crib_placement.py",
    }
    with open("results/e_s_137_point_placement.json", "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifact: results/e_s_137_point_placement.json")


if __name__ == "__main__":
    main()
