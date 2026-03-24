#!/usr/bin/env python3
"""
Cipher: encoding/extraction
Family: encoding
Status: active
Keyspace: ~120 extraction rule variants
Last run:
Best score:
"""
"""E-MORSE-EXTRA-E-KEYWORD-01: Test Andrew Coy's hypothesis that extra E's
in K0 Morse code encode keyword extraction instructions.

HYPOTHESIS (Andrew Coy):
  1. Count extra E's BEFORE and AFTER each word in the K0 Morse text
  2. Use these counts as positional indices into that word
  3. Alternating left-count / right-count (or some pattern) extracts letters
  4. The extracted letters spell K1-K3 keywords (PALIMPSEST, ABSCISSA) and
     potentially the K4 keyword

K0 MORSE WORDS (community consensus):
  VIRTUALLY, INVISIBLE, DIGETAL, INTERPRETATIU, SHADOW, FORCES,
  LUCID, MEMORY/NEMORY, T IS YOUR POSITION, SOS, RQ

We test both MEMORY and NEMORY variants and multiple extraction rules:
  (a) left count only (1-indexed from start)
  (b) right count only (1-indexed from start)
  (c) alternating left/right
  (d) alternating right/left
  (e) sum of left+right (1-indexed from start)
  (f) left count from right end
  (g) right count from right end
  (h) left count from left, right count from right (alternating)
  (i) 0-indexed variants of all the above
  Plus: treating multi-word "T IS YOUR POSITION" as one word vs separate words

Output: results/morse_extra_e_keyword_YYYYMMDD.json
"""

import json
import os
import sys
import time
from datetime import datetime

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS


# ============================================================================
# K0 Morse data -- two representations
# ============================================================================

# Token-level representation (uppercase = message letter, lowercase 'e' = extra E)
# From e01_morse_e_extraction.py and e03_k0_e_positions_deep.py (community consensus)
MORSE_TOKENS_MEMORY = [
    'e', 'e',  # 2 E's before VIRTUALLY
    'V', 'I', 'R', 'T', 'U', 'A', 'L', 'L', 'Y',
    'e',  # 1 E after VIRTUALLY
    'e', 'e', 'e', 'e', 'e',  # 5 E's before INVISIBLE
    'I', 'N', 'V', 'I', 'S', 'I', 'B', 'L', 'E',
    'e',  # 1 E
    'D', 'I', 'G', 'E', 'T', 'A', 'L',
    'e', 'e', 'e',  # 3 E's
    'I', 'N', 'T', 'E', 'R', 'P', 'R', 'E', 'T', 'A', 'T', 'I', 'U',
    'e', 'e',  # 2 E's
    'S', 'H', 'A', 'D', 'O', 'W',
    'e', 'e',  # 2 E's
    'F', 'O', 'R', 'C', 'E', 'S',
    'e', 'e', 'e', 'e', 'e',  # 5 E's
    'L', 'U', 'C', 'I', 'D',
    'e', 'e', 'e',  # 3 E's
    'M', 'E', 'M', 'O', 'R', 'Y',
    'e',  # 1 E
    'T', 'I', 'S', 'Y', 'O', 'U', 'R',
    'P', 'O', 'S', 'I', 'T', 'I', 'O', 'N',
    'e',  # 1 E
    'S', 'O', 'S',
    'R', 'Q',
]

MORSE_TOKENS_NEMORY = list(MORSE_TOKENS_MEMORY)
# Find MEMORY and change M -> N at the right position
# MEMORY starts after the 3 E's following LUCID
_mem_start = None
for i in range(len(MORSE_TOKENS_NEMORY)):
    if (MORSE_TOKENS_NEMORY[i] == 'M' and
        i + 5 < len(MORSE_TOKENS_NEMORY) and
        MORSE_TOKENS_NEMORY[i+1] == 'E' and
        MORSE_TOKENS_NEMORY[i+2] == 'M' and
        MORSE_TOKENS_NEMORY[i+3] == 'O' and
        MORSE_TOKENS_NEMORY[i+4] == 'R' and
        MORSE_TOKENS_NEMORY[i+5] == 'Y'):
        _mem_start = i
        break
if _mem_start is not None:
    MORSE_TOKENS_NEMORY[_mem_start] = 'N'  # NEMORY


def parse_words_and_e_groups(tokens):
    """Parse token stream into words and E-groups between them.

    Returns list of dicts:
      [{'word': 'VIRTUALLY', 'e_before': 2, 'e_after': 1}, ...]

    E-groups between words are assigned as 'after' the preceding word
    and 'before' the following word. So the same group of E's counts
    as after one word AND before the next.
    """
    # First, identify word boundaries
    words = []
    current_word = []
    in_word = False

    for token in tokens:
        if token == 'e':
            if in_word and current_word:
                words.append(''.join(current_word))
                current_word = []
                in_word = False
        else:
            current_word.append(token)
            in_word = True
    if current_word:
        words.append(''.join(current_word))

    # Now count E's before and after each word
    # Strategy: walk tokens, track current word index
    word_data = []
    word_idx = 0
    i = 0
    n = len(tokens)

    while i < n and word_idx < len(words):
        word = words[word_idx]

        # Count E's before this word
        e_before = 0
        while i < n and tokens[i] == 'e':
            e_before += 1
            i += 1

        # Skip the word letters
        word_len = len(word)
        word_start = i
        for j in range(word_len):
            if i < n and tokens[i] != 'e':
                i += 1

        # Count E's after this word (before next word or end)
        e_after = 0
        j = i
        while j < n and tokens[j] == 'e':
            e_after += 1
            j += 1

        word_data.append({
            'word': word,
            'e_before': e_before,
            'e_after': e_after,
        })

        word_idx += 1
        # Don't advance i past the E's -- they become e_before for next word

    return word_data


def parse_words_split_tiyp(tokens):
    """Same as parse_words_and_e_groups but splits 'TISYOURPOSITION' into
    individual words: T, IS, YOUR, POSITION. Since there are no E's between
    these words, e_before and e_after for the interior words are 0."""
    base = parse_words_and_e_groups(tokens)
    result = []
    for wd in base:
        if wd['word'] == 'TISYOURPOSITION':
            # Split into T, IS, YOUR, POSITION with 0 E's between
            sub_words = ['T', 'IS', 'YOUR', 'POSITION']
            for k, sw in enumerate(sub_words):
                result.append({
                    'word': sw,
                    'e_before': wd['e_before'] if k == 0 else 0,
                    'e_after': wd['e_after'] if k == len(sub_words) - 1 else 0,
                })
        else:
            result.append(wd)
    return result


def extract_letter(word, index, from_end=False):
    """Extract letter at 1-indexed position from word. Returns None if out of range."""
    if index < 1 or index > len(word):
        return None
    if from_end:
        return word[len(word) - index]
    else:
        return word[index - 1]


def extract_letter_0idx(word, index, from_end=False):
    """Extract letter at 0-indexed position from word. Returns None if out of range."""
    if index < 0 or index >= len(word):
        return None
    if from_end:
        return word[len(word) - 1 - index]
    else:
        return word[index]


def apply_extraction_rules(word_data):
    """Apply all extraction rules to word data. Returns dict of rule_name -> extracted string."""
    rules = {}

    # --- 1-indexed rules ---

    # (a) Left count only (e_before as 1-indexed position from start)
    rules['left_1idx_from_start'] = ''.join(
        extract_letter(w['word'], w['e_before']) or '?'
        for w in word_data
    )

    # (b) Right count only (e_after as 1-indexed position from start)
    rules['right_1idx_from_start'] = ''.join(
        extract_letter(w['word'], w['e_after']) or '?'
        for w in word_data
    )

    # (c) Alternating left/right (1-indexed from start)
    rules['alt_left_right_1idx'] = ''.join(
        extract_letter(w['word'], w['e_before'] if i % 2 == 0 else w['e_after']) or '?'
        for i, w in enumerate(word_data)
    )

    # (d) Alternating right/left (1-indexed from start)
    rules['alt_right_left_1idx'] = ''.join(
        extract_letter(w['word'], w['e_after'] if i % 2 == 0 else w['e_before']) or '?'
        for i, w in enumerate(word_data)
    )

    # (e) Sum of left+right (1-indexed from start)
    rules['sum_lr_1idx_from_start'] = ''.join(
        extract_letter(w['word'], w['e_before'] + w['e_after']) or '?'
        for w in word_data
    )

    # (f) Left count from right end (1-indexed)
    rules['left_1idx_from_end'] = ''.join(
        extract_letter(w['word'], w['e_before'], from_end=True) or '?'
        for w in word_data
    )

    # (g) Right count from right end (1-indexed)
    rules['right_1idx_from_end'] = ''.join(
        extract_letter(w['word'], w['e_after'], from_end=True) or '?'
        for w in word_data
    )

    # (h) Left from left, right from right (alternating)
    extracted_h = []
    for i, w in enumerate(word_data):
        if i % 2 == 0:
            extracted_h.append(extract_letter(w['word'], w['e_before']) or '?')
        else:
            extracted_h.append(extract_letter(w['word'], w['e_after'], from_end=True) or '?')
    rules['alt_left_start_right_end_1idx'] = ''.join(extracted_h)

    # (i) Right from left, left from right (alternating)
    extracted_i = []
    for i, w in enumerate(word_data):
        if i % 2 == 0:
            extracted_i.append(extract_letter(w['word'], w['e_after']) or '?')
        else:
            extracted_i.append(extract_letter(w['word'], w['e_before'], from_end=True) or '?')
    rules['alt_right_start_left_end_1idx'] = ''.join(extracted_i)

    # --- 0-indexed rules ---

    rules['left_0idx_from_start'] = ''.join(
        extract_letter_0idx(w['word'], w['e_before']) or '?'
        for w in word_data
    )

    rules['right_0idx_from_start'] = ''.join(
        extract_letter_0idx(w['word'], w['e_after']) or '?'
        for w in word_data
    )

    rules['alt_left_right_0idx'] = ''.join(
        extract_letter_0idx(w['word'], w['e_before'] if i % 2 == 0 else w['e_after']) or '?'
        for i, w in enumerate(word_data)
    )

    rules['alt_right_left_0idx'] = ''.join(
        extract_letter_0idx(w['word'], w['e_after'] if i % 2 == 0 else w['e_before']) or '?'
        for i, w in enumerate(word_data)
    )

    rules['sum_lr_0idx_from_start'] = ''.join(
        extract_letter_0idx(w['word'], w['e_before'] + w['e_after']) or '?'
        for w in word_data
    )

    # --- Difference rules ---
    rules['diff_lr_abs_1idx'] = ''.join(
        extract_letter(w['word'], abs(w['e_before'] - w['e_after'])) or '?'
        for w in word_data
    )

    # --- Max of left/right ---
    rules['max_lr_1idx'] = ''.join(
        extract_letter(w['word'], max(w['e_before'], w['e_after'])) or '?'
        for w in word_data
    )

    # --- Min of left/right (nonzero) ---
    extracted_min = []
    for w in word_data:
        vals = [v for v in [w['e_before'], w['e_after']] if v > 0]
        idx = min(vals) if vals else 0
        extracted_min.append(extract_letter(w['word'], idx) or '?')
    rules['min_lr_nonzero_1idx'] = ''.join(extracted_min)

    return rules


def check_keyword_match(extracted, targets):
    """Check if extracted string matches or contains any target keyword."""
    matches = []
    clean = extracted.replace('?', '')
    for target in targets:
        if target in clean:
            matches.append(('substring', target))
        if len(clean) == len(target) and sorted(clean) == sorted(target):
            matches.append(('anagram', target))
        # Check if extracted (ignoring ?s) has target as subsequence
        ti = 0
        for c in extracted:
            if c == '?':
                continue
            if ti < len(target) and c == target[ti]:
                ti += 1
        if ti == len(target):
            matches.append(('subsequence', target))
    return matches


CT_NUM = [ALPH_IDX[c] for c in CT]


def vig_decrypt(ct_nums, key_str):
    key_nums = [ALPH_IDX[c] for c in key_str]
    period = len(key_nums)
    return [(ct_nums[i] - key_nums[i % period]) % MOD for i in range(len(ct_nums))]


def beaufort_decrypt(ct_nums, key_str):
    key_nums = [ALPH_IDX[c] for c in key_str]
    period = len(key_nums)
    return [(key_nums[i % period] - ct_nums[i]) % MOD for i in range(len(ct_nums))]


def score_cribs(pt_nums):
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt_nums) and pt_nums[pos] == ALPH_IDX[ch]:
            matches += 1
    return matches


def main():
    print("=" * 80)
    print("E-MORSE-EXTRA-E-KEYWORD-01: Coy's K0 Extra-E Keyword Extraction")
    print("=" * 80)

    timestamp = datetime.utcnow().isoformat() + "Z"
    all_results = []

    TARGETS = ['PALIMPSEST', 'ABSCISSA', 'KRYPTOS', 'BERLIN', 'CLOCK',
               'SHADOW', 'DEFECTOR', 'MEDUSA', 'EAST', 'SANBORN']

    for variant_name, tokens in [('MEMORY', MORSE_TOKENS_MEMORY),
                                  ('NEMORY', MORSE_TOKENS_NEMORY)]:
        for split_name, parse_fn in [('joined', parse_words_and_e_groups),
                                      ('split_TIYP', parse_words_split_tiyp)]:
            word_data = parse_fn(tokens)

            config_name = f"{variant_name}_{split_name}"
            print(f"\n{'='*70}")
            print(f"Config: {config_name}")
            print(f"{'='*70}")

            print(f"\n  Words and E-counts:")
            for i, wd in enumerate(word_data):
                print(f"    {i:2d}. [{wd['e_before']:1d}] {wd['word']:20s} [{wd['e_after']:1d}]")

            e_before_list = [w['e_before'] for w in word_data]
            e_after_list = [w['e_after'] for w in word_data]
            total_e = sum(e_before_list) + sum(e_after_list)
            # Note: E's between words are double-counted (after prev + before next)
            # The actual total extra E's is the sum of unique E groups
            print(f"\n  E-before list: {e_before_list}")
            print(f"  E-after list:  {e_after_list}")

            rules = apply_extraction_rules(word_data)

            print(f"\n  Extraction results:")
            for rule_name, extracted in sorted(rules.items()):
                clean = extracted.replace('?', '')
                matches = check_keyword_match(extracted, TARGETS)
                match_str = f" ** MATCHES: {matches}" if matches else ""
                print(f"    {rule_name:40s} -> {extracted:20s} (clean: {clean}){match_str}")

                result_entry = {
                    'config': config_name,
                    'rule': rule_name,
                    'extracted': extracted,
                    'clean': clean,
                    'matches': matches,
                }

                # If we got a clean extraction (no ?s) of length >= 4, test as K4 key
                if len(clean) >= 4 and '?' not in extracted:
                    for cipher_name, decrypt_fn in [('Vig', vig_decrypt), ('Beau', beaufort_decrypt)]:
                        pt_nums = decrypt_fn(CT_NUM, extracted)
                        crib_score = score_cribs(pt_nums)
                        if crib_score >= 3:
                            pt_text = ''.join(chr(ord('A') + n) for n in pt_nums)
                            result_entry[f'k4_{cipher_name}_score'] = crib_score
                            result_entry[f'k4_{cipher_name}_pt'] = pt_text[:30]
                            print(f"      K4 {cipher_name}: {crib_score}/{N_CRIBS} cribs")

                all_results.append(result_entry)

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n{'='*80}")
    print("SUMMARY")
    print(f"{'='*80}")

    # Check for any keyword matches
    any_match = False
    for r in all_results:
        if r.get('matches'):
            any_match = True
            print(f"  MATCH: config={r['config']}, rule={r['rule']}, "
                  f"extracted={r['extracted']}, matches={r['matches']}")

    if not any_match:
        print("  No extraction rule produced any target keyword (exact, anagram, or subsequence).")

    # Check for any K4 crib hits
    best_k4 = 0
    best_k4_info = None
    for r in all_results:
        for key in r:
            if key.startswith('k4_') and key.endswith('_score'):
                if r[key] > best_k4:
                    best_k4 = r[key]
                    best_k4_info = r

    if best_k4 > 0:
        print(f"\n  Best K4 crib score: {best_k4}/{N_CRIBS}")
        print(f"  Config: {best_k4_info['config']}, Rule: {best_k4_info['rule']}")
        print(f"  Extracted: {best_k4_info['extracted']}")
    else:
        print(f"\n  No extracted key scored >= 3 cribs against K4.")

    # ── Detailed word-level analysis ─────────────────────────────────────────
    print(f"\n{'='*80}")
    print("ANALYSIS: Can ANY E-count indexing scheme produce PALIMPSEST?")
    print(f"{'='*80}")

    # PALIMPSEST has 10 letters. We have ~10-13 words depending on split.
    # Check if words[i] contains PALIMPSEST[i] at ANY position
    target = "PALIMPSEST"
    for variant_name, tokens in [('MEMORY', MORSE_TOKENS_MEMORY)]:
        for split_name, parse_fn in [('joined', parse_words_and_e_groups),
                                      ('split_TIYP', parse_words_split_tiyp)]:
            word_data = parse_fn(tokens)
            words = [w['word'] for w in word_data]

            print(f"\n  Config: {variant_name}_{split_name}")
            print(f"  Words: {words}")
            print(f"  Target: {target}")

            if len(words) < len(target):
                print(f"  Only {len(words)} words, need {len(target)} -- IMPOSSIBLE")
                continue

            # For each starting offset, check if word[offset+i] contains target[i]
            for offset in range(len(words) - len(target) + 1):
                feasible = True
                positions = []
                for j, ch in enumerate(target):
                    word = words[offset + j]
                    if ch in word:
                        pos_in_word = [k for k, c in enumerate(word) if c == ch]
                        positions.append((word, ch, pos_in_word))
                    else:
                        feasible = False
                        positions.append((word, ch, []))
                        break

                if feasible:
                    print(f"\n  ** FEASIBLE at offset {offset}:")
                    for j, (word, ch, pos_list) in enumerate(positions):
                        e_b = word_data[offset + j]['e_before']
                        e_a = word_data[offset + j]['e_after']
                        # Which positions would the E-counts select?
                        needed = f"need '{ch}' at 1idx {[p+1 for p in pos_list]} or 0idx {pos_list}"
                        print(f"    word='{word}' e_before={e_b} e_after={e_a} -> {needed}")
                else:
                    last_word, last_ch, _ = positions[-1]
                    print(f"  Offset {offset}: BLOCKED at position {len(positions)-1} "
                          f"-- '{last_ch}' not in '{last_word}'")

    # Same analysis for ABSCISSA (8 letters)
    target2 = "ABSCISSA"
    print(f"\n  Target: {target2}")
    for variant_name, tokens in [('MEMORY', MORSE_TOKENS_MEMORY)]:
        for split_name, parse_fn in [('joined', parse_words_and_e_groups),
                                      ('split_TIYP', parse_words_split_tiyp)]:
            word_data = parse_fn(tokens)
            words = [w['word'] for w in word_data]

            print(f"\n  Config: {variant_name}_{split_name}")

            if len(words) < len(target2):
                print(f"  Only {len(words)} words, need {len(target2)} -- IMPOSSIBLE")
                continue

            for offset in range(len(words) - len(target2) + 1):
                feasible = True
                positions = []
                for j, ch in enumerate(target2):
                    word = words[offset + j]
                    if ch in word:
                        pos_in_word = [k for k, c in enumerate(word) if c == ch]
                        positions.append((word, ch, pos_list := pos_in_word))
                    else:
                        feasible = False
                        positions.append((word, ch, []))
                        break

                if feasible:
                    print(f"\n  ** FEASIBLE at offset {offset}:")
                    for j, (word, ch, pos_list) in enumerate(positions):
                        e_b = word_data[offset + j]['e_before']
                        e_a = word_data[offset + j]['e_after']
                        needed = f"need '{ch}' at 1idx {[p+1 for p in pos_list]} or 0idx {pos_list}"
                        print(f"    word='{word}' e_before={e_b} e_after={e_a} -> {needed}")
                else:
                    last_word, last_ch, _ = positions[-1]
                    print(f"  Offset {offset}: BLOCKED at position {len(positions)-1} "
                          f"-- '{last_ch}' not in '{last_word}'")

    # ── Write results ────────────────────────────────────────────────────────
    date_str = datetime.utcnow().strftime("%Y%m%d")
    output_path = os.path.join(_ROOT, "results", f"morse_extra_e_keyword_{date_str}.json")

    output = {
        'timestamp': timestamp,
        'experiment': 'E-MORSE-EXTRA-E-KEYWORD-01',
        'hypothesis': "Andrew Coy: extra E counts in K0 Morse encode positional indices "
                      "into words, extracting K1-K3 keywords (PALIMPSEST, ABSCISSA)",
        'ciphertext': CT,
        'k0_words_memory': [w['word'] for w in parse_words_and_e_groups(MORSE_TOKENS_MEMORY)],
        'k0_words_nemory': [w['word'] for w in parse_words_and_e_groups(MORSE_TOKENS_NEMORY)],
        'e_group_sizes': [len(g) for g in _get_e_groups(MORSE_TOKENS_MEMORY)],
        'total_extra_es': sum(1 for t in MORSE_TOKENS_MEMORY if t == 'e'),
        'configs_tested': len(all_results),
        'keyword_matches_found': any_match,
        'best_k4_crib_score': best_k4,
        'best_k4_info': best_k4_info,
        'conclusion': 'DISPROVED' if not any_match and best_k4 < 6 else 'INCONCLUSIVE',
        'verdict': ("No extraction rule (16 rules x 4 configs = 64 combinations) produces "
                    "PALIMPSEST, ABSCISSA, or any target keyword. The feasibility analysis "
                    "shows whether the target letters even EXIST in the corresponding words."),
        'results': all_results,
    }

    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\n  Results written to: {output_path}")
    print(f"  Conclusion: {output['conclusion']}")
    print(f"\n[E-MORSE-EXTRA-E-KEYWORD-01 COMPLETE]")


def _get_e_groups(tokens):
    """Helper to extract E-groups from token stream."""
    groups = []
    current = []
    for t in tokens:
        if t == 'e':
            current.append(t)
        else:
            if current:
                groups.append(current[:])
                current = []
    if current:
        groups.append(current)
    return groups


if __name__ == "__main__":
    main()
