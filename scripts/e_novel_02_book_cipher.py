#!/usr/bin/env python3
"""Novel Method B: Book Cipher Using Carter's Tomb Text.

Try treating K4 as a book cipher with various encoding schemes:
- CT letter values as word indices
- Pairs as word numbers
- CT letter values as character positions
"""
import json
import sys
import os
import re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed

RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results', 'novel_methods')
os.makedirs(RESULTS_DIR, exist_ok=True)

# Load Carter text
with open(os.path.join(os.path.dirname(__file__), '..', 'reference', 'carter_gutenberg.txt')) as f:
    carter_raw = f.read()

# Extract words (uppercase alpha only)
carter_words = re.findall(r'[A-Za-z]+', carter_raw)
carter_words_upper = [w.upper() for w in carter_words]
carter_alpha = re.sub(r'[^A-Za-z]', '', carter_raw).upper()

print(f"Carter text: {len(carter_words)} words, {len(carter_alpha)} alpha chars")

best_overall = {"score": 0, "method": "", "text": ""}
all_results = []


def check_candidate(text, method_name):
    global best_overall
    if not text or len(text) < CT_LEN:
        return 0
    text = text[:CT_LEN].upper()
    if not text.isalpha():
        return 0
    sc = score_cribs(text)
    if sc > best_overall["score"]:
        best_overall = {"score": sc, "method": method_name, "text": text}
    if sc > 2:
        detail = score_cribs_detailed(text)
        all_results.append({"method": method_name, "score": sc,
                           "ene": detail["ene_score"], "bc": detail["bc_score"],
                           "text": text[:50] + "..."})
        print(f"  [ABOVE NOISE] {method_name}: {sc}/24 (ENE={detail['ene_score']}, BC={detail['bc_score']})")
    return sc


print("=" * 60)
print("NOVEL METHOD B: Book Cipher with Carter Text")
print("=" * 60)

total_tested = 0

# Method 1: Each CT letter value (A=0..Z=25 or A=1..Z=26) -> word index, take first letter
print("\n--- Method 1: CT letter values as word indices ---")
for offset in range(50):
    for base in [0, 1]:  # 0-indexed vs 1-indexed
        pt_chars = []
        valid = True
        for ch in CT:
            idx = ALPH_IDX[ch] + base + offset
            if idx < len(carter_words_upper):
                pt_chars.append(carter_words_upper[idx][0])
            else:
                valid = False
                break
        if valid:
            pt = "".join(pt_chars)
            check_candidate(pt, f"letter_as_word_idx_base{base}_offset{offset}")
            total_tested += 1

# Method 2: Pairs of CT letters as word numbers (base-26 two-digit numbers)
print("\n--- Method 2: Pairs as word numbers ---")
for base in [0, 1]:
    for pair_size in [2, 3]:
        pt_chars = []
        valid = True
        i = 0
        while i + pair_size <= len(CT):
            num = 0
            for j in range(pair_size):
                num = num * 26 + ALPH_IDX[CT[i + j]] + base
            if num < len(carter_words_upper):
                pt_chars.append(carter_words_upper[num][0])
            else:
                valid = False
                break
            i += pair_size
        if valid and len(pt_chars) >= 10:
            pt = "".join(pt_chars)
            check_candidate(pt, f"pairs_{pair_size}_as_word_num_base{base}")
            total_tested += 1

# Method 3: CT letter values as character positions in the running text
print("\n--- Method 3: CT letters as char positions ---")
for stride in [1, 2, 3, 4, 5, 7, 10, 13, 26, 97]:
    for start_offset in range(min(stride, 50)):
        pt_chars = []
        valid = True
        for i, ch in enumerate(CT):
            pos = start_offset + i * stride + ALPH_IDX[ch]
            if pos < len(carter_alpha):
                pt_chars.append(carter_alpha[pos])
            else:
                valid = False
                break
        if valid:
            pt = "".join(pt_chars)
            check_candidate(pt, f"char_pos_stride{stride}_start{start_offset}")
            total_tested += 1

# Method 4: Cumulative sum of CT letter values as positions
print("\n--- Method 4: Cumulative letter values ---")
for offset in range(20):
    pt_chars = []
    cumsum = offset
    valid = True
    for ch in CT:
        cumsum += ALPH_IDX[ch] + 1
        if cumsum < len(carter_alpha):
            pt_chars.append(carter_alpha[cumsum])
        else:
            valid = False
            break
    if valid:
        pt = "".join(pt_chars)
        check_candidate(pt, f"cumsum_offset{offset}")
        total_tested += 1

# Method 5: CT letter as index into specific paragraph/sentence
# Try mapping CT to word-initial letters from various starting points
print("\n--- Method 5: Starting from various text positions ---")
for start_word in range(0, min(5000, len(carter_words_upper) - CT_LEN), 100):
    # Take first letters of consecutive words
    pt = "".join(carter_words_upper[start_word + i][0] for i in range(CT_LEN)
                 if start_word + i < len(carter_words_upper))
    if len(pt) >= CT_LEN:
        check_candidate(pt, f"first_letters_from_word{start_word}")
        total_tested += 1

# Method 6: Each CT letter selects the N-th word that starts with that letter
print("\n--- Method 6: Nth word starting with CT letter ---")
# Build index: letter -> list of words starting with that letter
letter_words = {chr(i + 65): [] for i in range(26)}
for w in carter_words_upper:
    if w:
        letter_words[w[0]].append(w)

for occurrence_offset in range(20):
    pt_chars = []
    valid = True
    for i, ch in enumerate(CT):
        words_for_letter = letter_words.get(ch, [])
        idx = i + occurrence_offset
        if idx < len(words_for_letter) and len(words_for_letter[idx]) > 1:
            pt_chars.append(words_for_letter[idx][1])  # Second letter of the word
        else:
            valid = False
            break
    if valid:
        pt = "".join(pt_chars)
        check_candidate(pt, f"nth_word_second_letter_offset{occurrence_offset}")
        total_tested += 1

# Method 7: Difference cipher - subtract Carter text from CT
print("\n--- Method 7: Difference with running Carter text ---")
for start in range(0, min(len(carter_alpha) - CT_LEN, 5000), 1):
    pt_chars = []
    for i, ch in enumerate(CT):
        ct_val = ALPH_IDX[ch]
        key_val = ALPH_IDX[carter_alpha[start + i]]
        pt_val = (ct_val - key_val) % 26
        pt_chars.append(chr(pt_val + 65))
    pt = "".join(pt_chars)
    sc = check_candidate(pt, f"vigenere_carter_start{start}")
    total_tested += 1

    # Also Beaufort variant
    pt_chars2 = []
    for i, ch in enumerate(CT):
        ct_val = ALPH_IDX[ch]
        key_val = ALPH_IDX[carter_alpha[start + i]]
        pt_val = (key_val - ct_val) % 26
        pt_chars2.append(chr(pt_val + 65))
    pt2 = "".join(pt_chars2)
    check_candidate(pt2, f"beaufort_carter_start{start}")
    total_tested += 1

    # And additive
    pt_chars3 = []
    for i, ch in enumerate(CT):
        ct_val = ALPH_IDX[ch]
        key_val = ALPH_IDX[carter_alpha[start + i]]
        pt_val = (ct_val + key_val) % 26
        pt_chars3.append(chr(pt_val + 65))
    pt3 = "".join(pt_chars3)
    check_candidate(pt3, f"additive_carter_start{start}")
    total_tested += 1

print(f"\nTotal book cipher configs tested: {total_tested}")
print(f"Best: {best_overall['method']} -> {best_overall['score']}/24")
if best_overall['score'] > 0:
    print(f"  Text: {best_overall['text'][:60]}...")

with open(os.path.join(RESULTS_DIR, "book_cipher.json"), "w") as f:
    json.dump({
        "method": "book_cipher_carter",
        "total_tested": total_tested,
        "best_score": best_overall["score"],
        "best_method": best_overall["method"],
        "best_text": best_overall["text"],
        "above_noise": all_results,
    }, f, indent=2)

print(f"\nResults saved to results/novel_methods/book_cipher.json")
