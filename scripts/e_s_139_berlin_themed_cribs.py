#!/usr/bin/env python3
"""E-S-139: Berlin-themed crib word analysis.

Tests CHECKPOINT, BERLINWALL, THEWALL, REMEMBER, MEMORIAL, REMINDER,
WHATSTHEPOINT, THEPOINT at all valid positions within K4 ciphertext.

For each valid placement:
1. Compute Vigenere and Beaufort keystream
2. Check Bean EQ and all 21 Bean INEQ constraints
3. Analyze keystream for periodicity (periods 2-26)
4. Score keystream for English-plausible letter frequencies (running key hypothesis)
5. Check for repeated key values suggesting structure

Output: results/e_s_139_berlin_themed_cribs.json
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
N = CT_LEN

# Existing cribs
EXISTING_CRIBS = {pos: ch for pos, ch in CRIB_ENTRIES}
EXISTING_CRIB_POS = set(EXISTING_CRIBS.keys())

# Known keystream values
KNOWN_KEY_VIG = {}
KNOWN_KEY_BEAU = {}
for pos, ch in EXISTING_CRIBS.items():
    KNOWN_KEY_VIG[pos] = (CT_NUM[pos] - ALPH_IDX[ch]) % MOD
    KNOWN_KEY_BEAU[pos] = (CT_NUM[pos] + ALPH_IDX[ch]) % MOD

BEAN_EQ_POS = BEAN_EQ[0]  # (27, 65)
BEAN_INEQ_PAIRS = list(BEAN_INEQ)

# English letter frequencies for scoring
ENG_FREQ = [0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020, 0.061,
            0.070, 0.002, 0.008, 0.040, 0.024, 0.067, 0.075, 0.019,
            0.001, 0.060, 0.063, 0.091, 0.028, 0.010, 0.023, 0.002,
            0.020, 0.001]

# Words to test
CANDIDATE_WORDS = [
    "CHECKPOINT",
    "BERLINWALL",
    "THEWALL",
    "REMEMBER",
    "MEMORIAL",
    "REMINDER",
    "WHATSTHEPOINT",
    "THEPOINT",
]


def compute_keystream(word, start_pos, variant):
    """Compute keystream values for word placed at start_pos."""
    keys = {}
    for i, ch in enumerate(word):
        pos = start_pos + i
        pt_num = ALPH_IDX[ch]
        ct_num = CT_NUM[pos]
        if variant == 'vigenere':
            keys[pos] = (ct_num - pt_num) % MOD
        elif variant == 'beaufort':
            keys[pos] = (ct_num + pt_num) % MOD
    return keys


def check_bean(combined_keys):
    """Check Bean EQ and all INEQ. Returns (pass, fail_reason)."""
    eq_a, eq_b = BEAN_EQ_POS
    # EQ check
    if eq_a in combined_keys and eq_b in combined_keys:
        if combined_keys[eq_a] != combined_keys[eq_b]:
            return False, f"EQ: k[{eq_a}]={combined_keys[eq_a]} != k[{eq_b}]={combined_keys[eq_b]}"
    # INEQ checks
    for ia, ib in BEAN_INEQ_PAIRS:
        if ia in combined_keys and ib in combined_keys:
            if combined_keys[ia] == combined_keys[ib]:
                return False, f"INEQ: k[{ia}]=k[{ib}]={combined_keys[ia]}"
    return True, "PASS"


def check_periodicity(combined_keys, max_period=26):
    """Find periods consistent with the combined keystream."""
    positions = sorted(combined_keys.keys())
    consistent = []
    for p in range(2, max_period + 1):
        ok = True
        residue_vals = {}
        for pos in positions:
            r = pos % p
            val = combined_keys[pos]
            if r in residue_vals:
                if residue_vals[r] != val:
                    ok = False
                    break
            else:
                residue_vals[r] = val
        if ok:
            consistent.append(p)
    return consistent


def keystream_entropy(keys_dict):
    """Shannon entropy of key values."""
    vals = list(keys_dict.values())
    if not vals:
        return 0.0
    counts = Counter(vals)
    n = len(vals)
    return -sum((c/n) * math.log2(c/n) for c in counts.values() if c > 0)


def english_key_score(keys_dict):
    """Average log-probability of key values as English letters."""
    vals = list(keys_dict.values())
    if not vals:
        return 0.0
    return sum(math.log(ENG_FREQ[v] + 1e-10) for v in vals) / len(vals)


def key_to_letters(keys_dict, positions):
    """Convert key values at specified positions to letter string."""
    return ''.join(ALPH[keys_dict[p]] for p in sorted(positions) if p in keys_dict)


def main():
    print("=" * 70)
    print("E-S-139: Berlin-Themed Crib Word Analysis")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"Known cribs: ENE@21-33, BC@63-73 (24 positions)")
    print(f"Testing: {', '.join(CANDIDATE_WORDS)}")
    print()

    all_results = {}

    for word in CANDIDATE_WORDS:
        word_len = len(word)
        print(f"\n{'='*60}")
        print(f"  {word} ({word_len} chars)")
        print(f"{'='*60}")

        # Find valid positions (no overlap OR consistent overlap with existing cribs)
        valid_positions = []
        for p in range(N - word_len + 1):
            word_positions = set(range(p, p + word_len))
            overlap = word_positions & EXISTING_CRIB_POS
            if overlap:
                # Check consistency
                consistent = True
                for op in overlap:
                    if EXISTING_CRIBS[op] != word[op - p]:
                        consistent = False
                        break
                if not consistent:
                    continue
            valid_positions.append(p)

        print(f"  Valid start positions: {len(valid_positions)} "
              f"(range {valid_positions[0]}-{valid_positions[-1]} if any)"
              if valid_positions else "  Valid start positions: 0")

        bean_pass_vig = []
        bean_pass_beau = []
        bean_fail_vig = []
        bean_fail_beau = []

        word_results = {
            'word': word,
            'length': word_len,
            'n_valid_positions': len(valid_positions),
            'vig_pass': [],
            'beau_pass': [],
            'vig_fail_count': 0,
            'beau_fail_count': 0,
            'best_english_vig': None,
            'best_english_beau': None,
            'periodic_hits': {},
        }

        for p in valid_positions:
            for variant in ['vigenere', 'beaufort']:
                new_keys = compute_keystream(word, p, variant)
                known = dict(KNOWN_KEY_VIG if variant == 'vigenere' else KNOWN_KEY_BEAU)
                combined = {**known, **new_keys}

                bean_ok, bean_msg = check_bean(combined)
                entropy = keystream_entropy(combined)
                eng_score = english_key_score(new_keys)
                consistent_periods = check_periodicity(combined)
                key_letters = key_to_letters(new_keys, range(p, p + word_len))
                repeats = sum(1 for v, c in Counter(combined.values()).items() if c > 1)

                record = {
                    'start': p,
                    'end': p + word_len - 1,
                    'bean_pass': bean_ok,
                    'bean_msg': bean_msg,
                    'key_letters': key_letters,
                    'entropy': round(entropy, 3),
                    'eng_score': round(eng_score, 3),
                    'consistent_periods': consistent_periods,
                    'repeats': repeats,
                }

                if variant == 'vigenere':
                    if bean_ok:
                        bean_pass_vig.append(record)
                    else:
                        bean_fail_vig.append(record)
                else:
                    if bean_ok:
                        bean_pass_beau.append(record)
                    else:
                        bean_fail_beau.append(record)

                # Track periodic hits
                for per in consistent_periods:
                    key = f"p{per}_{variant[:3]}"
                    if key not in word_results['periodic_hits']:
                        word_results['periodic_hits'][key] = []
                    word_results['periodic_hits'][key].append(p)

        word_results['vig_fail_count'] = len(bean_fail_vig)
        word_results['beau_fail_count'] = len(bean_fail_beau)

        # Report Bean results
        print(f"\n  Bean constraint results:")
        print(f"    Vigenere:  {len(bean_pass_vig)} PASS, {len(bean_fail_vig)} FAIL")
        print(f"    Beaufort:  {len(bean_pass_beau)} PASS, {len(bean_fail_beau)} FAIL")

        # Positions eliminated under BOTH variants
        fail_pos_vig = {r['start'] for r in bean_fail_vig}
        fail_pos_beau = {r['start'] for r in bean_fail_beau}
        both_eliminated = fail_pos_vig & fail_pos_beau
        surviving = set(valid_positions) - both_eliminated
        print(f"    Eliminated (both variants): {len(both_eliminated)}")
        print(f"    Surviving (at least 1 variant): {len(surviving)}")

        # Show Bean failures
        if bean_fail_vig:
            fail_reasons = Counter(r['bean_msg'] for r in bean_fail_vig)
            print(f"\n  Vig Bean failure reasons:")
            for reason, count in fail_reasons.most_common(5):
                print(f"    {reason}: {count} positions")

        if bean_fail_beau:
            fail_reasons = Counter(r['bean_msg'] for r in bean_fail_beau)
            print(f"\n  Beau Bean failure reasons:")
            for reason, count in fail_reasons.most_common(5):
                print(f"    {reason}: {count} positions")

        # Top positions by English key score (Vigenere)
        if bean_pass_vig:
            sorted_vig = sorted(bean_pass_vig, key=lambda r: -r['eng_score'])
            print(f"\n  Top 5 positions by English-plausible key (Vigenere, Bean-passing):")
            for r in sorted_vig[:5]:
                print(f"    pos {r['start']:2d}-{r['end']:2d}: key={r['key_letters']} "
                      f"eng={r['eng_score']:.3f} entropy={r['entropy']:.3f} "
                      f"periods={r['consistent_periods'][:5]}")
            word_results['best_english_vig'] = {
                'start': sorted_vig[0]['start'],
                'key_letters': sorted_vig[0]['key_letters'],
                'eng_score': sorted_vig[0]['eng_score'],
            }
            word_results['vig_pass'] = [{'start': r['start'], 'key': r['key_letters'],
                                          'eng': r['eng_score']}
                                         for r in sorted_vig[:10]]

        # Top positions by English key score (Beaufort)
        if bean_pass_beau:
            sorted_beau = sorted(bean_pass_beau, key=lambda r: -r['eng_score'])
            print(f"\n  Top 5 positions by English-plausible key (Beaufort, Bean-passing):")
            for r in sorted_beau[:5]:
                print(f"    pos {r['start']:2d}-{r['end']:2d}: key={r['key_letters']} "
                      f"eng={r['eng_score']:.3f} entropy={r['entropy']:.3f} "
                      f"periods={r['consistent_periods'][:5]}")
            word_results['best_english_beau'] = {
                'start': sorted_beau[0]['start'],
                'key_letters': sorted_beau[0]['key_letters'],
                'eng_score': sorted_beau[0]['eng_score'],
            }
            word_results['beau_pass'] = [{'start': r['start'], 'key': r['key_letters'],
                                           'eng': r['eng_score']}
                                          for r in sorted_beau[:10]]

        # Periodicity analysis
        all_pass = bean_pass_vig + bean_pass_beau
        small_period_hits = {}
        for r in all_pass:
            for per in r['consistent_periods']:
                if per <= 7:
                    if per not in small_period_hits:
                        small_period_hits[per] = []
                    small_period_hits[per].append(
                        f"pos={r['start']}"
                    )

        if small_period_hits:
            print(f"\n  Positions consistent with period <= 7 (Bean-passing):")
            for per in sorted(small_period_hits.keys()):
                hits = small_period_hits[per]
                print(f"    period {per}: {len(hits)} — {hits[:8]}{'...' if len(hits) > 8 else ''}")
        else:
            print(f"\n  No Bean-passing positions consistent with period <= 7")

        # Lowest entropy (most structured key)
        if all_pass:
            by_entropy = sorted(all_pass, key=lambda r: r['entropy'])[:3]
            print(f"\n  Most structured keystream (lowest entropy, Bean-passing):")
            for r in by_entropy:
                print(f"    pos {r['start']:2d}: entropy={r['entropy']:.3f} "
                      f"key={r['key_letters']} repeats={r['repeats']}")

        all_results[word] = word_results

    # ── Cross-word summary ───────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("CROSS-WORD SUMMARY")
    print(f"{'='*70}")
    print(f"{'Word':<16s} {'Len':>3s} {'Valid':>5s} {'VigPass':>7s} {'BeauPass':>8s} "
          f"{'Elim':>4s} {'BestEngV':>8s} {'BestEngB':>8s}")
    print("-" * 75)
    for word, data in all_results.items():
        vig_pass = len(data.get('vig_pass', []))
        beau_pass = len(data.get('beau_pass', []))
        total_valid = data['n_valid_positions']
        elim = data['vig_fail_count']  # approximate
        bev = data['best_english_vig']['eng_score'] if data['best_english_vig'] else -99
        beb = data['best_english_beau']['eng_score'] if data['best_english_beau'] else -99
        print(f"{word:<16s} {data['length']:>3d} {total_valid:>5d} {vig_pass:>7d} "
              f"{beau_pass:>8d} {elim:>4d} {bev:>8.3f} {beb:>8.3f}")

    # ── Key insight: which words produce English-like keys? ──────────────────
    print(f"\n{'='*70}")
    print("BEST ENGLISH-PLAUSIBLE KEY POSITIONS (across all words)")
    print(f"{'='*70}")

    all_english = []
    for word, data in all_results.items():
        for vpass in data.get('vig_pass', []):
            all_english.append({
                'word': word,
                'variant': 'vig',
                'start': vpass['start'],
                'key': vpass['key'],
                'eng': vpass['eng'],
            })
        for bpass in data.get('beau_pass', []):
            all_english.append({
                'word': word,
                'variant': 'beau',
                'start': bpass['start'],
                'key': bpass['key'],
                'eng': bpass['eng'],
            })

    all_english.sort(key=lambda r: -r['eng'])
    print(f"Top 20 (highest English letter frequency score):")
    for r in all_english[:20]:
        print(f"  {r['word']:<16s} @{r['start']:2d} ({r['variant']}) key={r['key']} "
              f"eng={r['eng']:.3f}")

    # ── Interpretation ───────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("INTERPRETATION")
    print(f"{'='*70}")
    print("English key score ranges:")
    print("  Strong English: > -3.5 (common letters like E,T,A,O,I,N,S)")
    print("  Moderate:       -3.5 to -4.5")
    print("  Weak/random:    < -4.5")
    print()
    print("Scores near -3.5 would support the running-key hypothesis")
    print("(key is English text). Scores near -4.5 suggest random key.")
    print()
    print("Bean eliminations reduce the search space but zero eliminations")
    print("means the word is unconstrained by Bean (most positions survive).")
    print()
    print("Periodic consistency at small periods (<=7) would be meaningful")
    print("but is algebraically impossible for periodic keys (E-FRAC-35).")
    print("It could indicate a non-periodic key with coincidental regularity.")

    # Save
    os.makedirs("results", exist_ok=True)
    artifact = {
        "experiment_id": "e_s_139",
        "description": "Berlin-themed crib word analysis: keystream, Bean, periodicity",
        "words_tested": CANDIDATE_WORDS,
        "results": all_results,
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_s_139_berlin_themed_cribs.py",
    }
    out_path = "results/e_s_139_berlin_themed_cribs.json"
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifact: {out_path}")


if __name__ == "__main__":
    main()
