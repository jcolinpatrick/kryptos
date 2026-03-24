#!/usr/bin/env python3 -u
"""
Cipher: ITA-2 XOR with key-stepping
Family: novel
Status: active
Keyspace: 3 encodings x ~425 key sources x 26 starting offsets x 2 interpretations
Last run:
Best score:
"""
"""
e_ita2_xor_stepping_01.py -- ITA-2/Baudot XOR cipher with key-stepping for K4.

HYPOTHESIS: K4 uses a 5-bit binary cipher where PT and KEY letters are encoded
as 5-bit values, XORed together, and invalid results (>=26) cause the key to
advance without consuming a plaintext character. This produces "null" positions
in the CT where key stepped past, explaining why K4 is 97 chars but the message
may be shorter.

Two decryption interpretations are tested:
  Model A ("retry"): When CT XOR KEY >= 26, the CT position is a null.
      Advance key, retry same CT char with next key char.
  Model B ("skip"): When CT XOR KEY >= 26, mark position as null,
      advance BOTH CT and KEY pointers.

Three encodings: standard A=0, ITA-2 Baudot, KRYPTOS alphabet (K=0).
Key sources: KRYPTOS, PALIMPSEST, ABSCISSA, SHADOW, DEFECTOR, plus
  thematic keywords from wordlists/thematic_keywords.txt.
Starting offsets 0-25 into the key.

All positions 0-indexed. Results: results/ita2_xor_stepping_YYYYMMDD.json
"""

import sys
import os
import json
import datetime

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, MOD, ALPH, ALPH_IDX,
    CRIB_DICT, CRIB_POSITIONS, KRYPTOS_ALPHABET,
)
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free

# ============================================================================
# ENCODINGS
# ============================================================================

# 1. Standard A=0..Z=25
AZ_ENCODE = {c: i for i, c in enumerate(ALPH)}
AZ_DECODE = {i: c for c, i in AZ_ENCODE.items()}

# 2. KRYPTOS alphabet K=0, R=1, ...
KA_ENCODE = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
KA_DECODE = {i: c for c, i in KA_ENCODE.items()}

# 3. ITA-2 / Baudot Telegraph Code (letters only, 5-bit)
ITA2_ENCODE = {
    'A': 0b00011, 'B': 0b11001, 'C': 0b01110, 'D': 0b01001,
    'E': 0b00001, 'F': 0b01101, 'G': 0b11010, 'H': 0b10100,
    'I': 0b00110, 'J': 0b01011, 'K': 0b01111, 'L': 0b10010,
    'M': 0b11100, 'N': 0b01100, 'O': 0b11000, 'P': 0b10110,
    'Q': 0b10111, 'R': 0b01010, 'S': 0b00101, 'T': 0b10000,
    'U': 0b00111, 'V': 0b11110, 'W': 0b10011, 'X': 0b11101,
    'Y': 0b10101, 'Z': 0b10001,
}
# Build decode: value -> letter. Only values 0-25 are valid outputs.
# ITA2 values range 0-30 (5 bits), but we only decode values < 26.
ITA2_DECODE = {}
for ch, val in ITA2_ENCODE.items():
    if val < 26:
        ITA2_DECODE[val] = ch
# For values 0-25 not in ITA2_DECODE, map to standard alphabet position
for i in range(26):
    if i not in ITA2_DECODE:
        ITA2_DECODE[i] = ALPH[i]

ENCODINGS = {
    'AZ': (AZ_ENCODE, AZ_DECODE),
    'KA': (KA_ENCODE, KA_DECODE),
    'ITA2': (ITA2_ENCODE, ITA2_DECODE),
}

# ============================================================================
# DECRYPTION MODELS
# ============================================================================

def decrypt_model_a(ciphertext, key, ct_enc, key_enc, pt_dec, start_offset=0):
    """
    Model A ("retry"): XOR CT with KEY. If result >= 26, this CT position
    is a null -- advance key pointer, retry SAME CT char with next key char.
    If result < 26, output as PT letter, advance both.

    Returns (plaintext_str, null_positions_list, key_steps_used).
    """
    pt = []
    null_positions = []
    key_len = len(key)
    key_idx = start_offset
    max_key_steps = key_len * 20  # safety limit

    for ct_idx in range(len(ciphertext)):
        c = ciphertext[ct_idx]
        if c not in ct_enc:
            continue
        ct_val = ct_enc[c]
        found = False
        attempts = 0

        while attempts < max_key_steps:
            key_char = key[key_idx % key_len]
            if key_char not in key_enc:
                key_idx += 1
                attempts += 1
                continue
            key_val = key_enc[key_char]
            result = ct_val ^ key_val
            key_idx += 1
            attempts += 1

            if result < 26 and result in pt_dec:
                pt.append(pt_dec[result])
                found = True
                break
            else:
                null_positions.append(ct_idx)
                # Key stepped, retry same CT char

        if not found:
            # Exhausted key steps -- skip this CT char
            pt.append('?')

    return ''.join(pt), null_positions, key_idx - start_offset


def decrypt_model_b(ciphertext, key, ct_enc, key_enc, pt_dec, start_offset=0):
    """
    Model B ("skip"): XOR CT with KEY. If result >= 26, mark as null,
    advance BOTH pointers. If result < 26, output PT letter, advance both.

    Returns (plaintext_str, null_positions_list, key_steps_used).
    """
    pt = []
    null_positions = []
    key_len = len(key)
    key_idx = start_offset

    for ct_idx in range(len(ciphertext)):
        c = ciphertext[ct_idx]
        if c not in ct_enc:
            pt.append('?')
            key_idx += 1
            continue
        ct_val = ct_enc[c]
        key_char = key[key_idx % key_len]
        if key_char not in key_enc:
            pt.append('?')
            key_idx += 1
            continue
        key_val = key_enc[key_char]
        result = ct_val ^ key_val
        key_idx += 1

        if result < 26 and result in pt_dec:
            pt.append(pt_dec[result])
        else:
            null_positions.append(ct_idx)
            # Position is a null -- do not add to PT

    return ''.join(pt), null_positions, key_idx - start_offset


# ============================================================================
# KEY SOURCES
# ============================================================================

def load_keywords():
    """Load thematic keywords from wordlist."""
    kw_path = os.path.join(_ROOT, "wordlists", "thematic_keywords.txt")
    keywords = []
    if os.path.exists(kw_path):
        with open(kw_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                word = ''.join(c for c in line.upper() if c in ALPH)
                if 3 <= len(word) <= 30:
                    keywords.append(word)
    return keywords


PRIORITY_KEYS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "DEFECTOR",
    "SANBORN", "SCHEIDT", "MEDUSA", "LUCID", "EAST", "NORTH",
    "BERLIN", "CLOCK", "BERLINCLOCK", "EASTNORTHEAST",
    "WONDERFULTHINGS", "UNDERGROUND",
]


# ============================================================================
# SCORING WRAPPER
# ============================================================================

def evaluate(pt_str, method_desc):
    """Score a plaintext candidate. Returns dict with scores."""
    if len(pt_str) < 10:
        return None

    try:
        anchored = score_candidate(pt_str)
        free = score_candidate_free(pt_str)
    except Exception:
        return None

    result = {
        'plaintext': pt_str,
        'pt_len': len(pt_str),
        'method': method_desc,
        'crib_score_anchored': anchored.crib_score,
        'crib_score_free': free.crib_score,
        'crib_classification': anchored.crib_classification,
    }
    return result


# ============================================================================
# MAIN SWEEP
# ============================================================================

def run_sweep():
    print(f"K4 CT ({CT_LEN} chars): {CT}")
    print(f"Encodings: {list(ENCODINGS.keys())}")
    print()

    # Collect all keys
    all_keys = list(PRIORITY_KEYS)
    thematic = load_keywords()
    # Add thematic keywords not already in priority list
    priority_set = set(PRIORITY_KEYS)
    for kw in thematic:
        if kw not in priority_set:
            all_keys.append(kw)
            priority_set.add(kw)
    print(f"Total keys to test: {len(all_keys)}")

    # Encoding combinations: ct_enc, key_enc, pt_dec can differ
    # Test: same encoding for all three (3 combos)
    # Plus: mixed where ct/key use one encoding, pt uses another (6 more)
    encoding_configs = []
    for name in ENCODINGS:
        enc, dec = ENCODINGS[name]
        encoding_configs.append((name, name, name, enc, enc, dec))

    # Also test mixed: ITA2 for ct/key encoding, AZ for pt decoding, etc.
    for ct_name in ENCODINGS:
        for key_name in ENCODINGS:
            for pt_name in ENCODINGS:
                if ct_name == key_name == pt_name:
                    continue  # already covered
                ct_enc = ENCODINGS[ct_name][0]
                key_enc = ENCODINGS[key_name][0]
                pt_dec = ENCODINGS[pt_name][1]
                encoding_configs.append(
                    (ct_name, key_name, pt_name, ct_enc, key_enc, pt_dec)
                )

    print(f"Encoding configs: {len(encoding_configs)}")
    print(f"Models: A (retry), B (skip)")
    print(f"Offsets: 0-25")
    print()

    best_anchored = {'crib_score_anchored': -1}
    best_free = {'crib_score_free': -1}
    results_above_threshold = []
    total_tested = 0
    STORE_THRESHOLD = 6  # Store anything >= 6 for review

    for key_word in all_keys:
        for ct_enc_name, key_enc_name, pt_enc_name, ct_enc, key_enc, pt_dec in encoding_configs:
            for offset in range(min(26, len(key_word))):
                for model_name, decrypt_fn in [('A_retry', decrypt_model_a),
                                                ('B_skip', decrypt_model_b)]:
                    total_tested += 1

                    try:
                        pt_str, nulls, steps = decrypt_fn(
                            CT, key_word, ct_enc, key_enc, pt_dec, offset
                        )
                    except Exception:
                        continue

                    if len(pt_str) < 10:
                        continue

                    method = (
                        f"{model_name}|key={key_word}|off={offset}|"
                        f"ct={ct_enc_name}|key_enc={key_enc_name}|pt={pt_enc_name}"
                    )

                    result = evaluate(pt_str, method)
                    if result is None:
                        continue

                    result['null_count'] = len(nulls)
                    result['null_positions'] = nulls[:50]  # truncate for storage
                    result['key_steps'] = steps

                    # Track bests
                    if result['crib_score_anchored'] > best_anchored['crib_score_anchored']:
                        best_anchored = result
                        print(f"  NEW BEST ANCHORED: {result['crib_score_anchored']}/24 "
                              f"| {method} | PT[0:40]={pt_str[:40]}")

                    if result['crib_score_free'] > best_free['crib_score_free']:
                        best_free = result
                        print(f"  NEW BEST FREE: {result['crib_score_free']}/24 "
                              f"| {method} | PT[0:40]={pt_str[:40]}")

                    # Store if above threshold
                    max_score = max(result['crib_score_anchored'],
                                    result['crib_score_free'])
                    if max_score >= STORE_THRESHOLD:
                        results_above_threshold.append(result)

        # Progress reporting every 50 keys
        if total_tested % (50 * len(encoding_configs) * 26 * 2) < (
                len(encoding_configs) * 26 * 2):
            ki = all_keys.index(key_word) + 1 if key_word in all_keys else '?'
            print(f"  Progress: key {ki}/{len(all_keys)} ({key_word}), "
                  f"{total_tested} configs tested")

    # ========================================================================
    # SUMMARY
    # ========================================================================

    print("\n" + "=" * 72)
    print("SWEEP COMPLETE")
    print(f"Total configs tested: {total_tested}")
    print(f"Results >= {STORE_THRESHOLD}/24: {len(results_above_threshold)}")
    print()

    print("BEST ANCHORED SCORE:")
    if best_anchored.get('crib_score_anchored', -1) >= 0:
        print(f"  Score: {best_anchored['crib_score_anchored']}/24")
        print(f"  Method: {best_anchored.get('method', 'N/A')}")
        print(f"  PT: {best_anchored.get('plaintext', 'N/A')[:80]}")
        print(f"  Nulls: {best_anchored.get('null_count', 'N/A')}")
    else:
        print("  No valid results")

    print("\nBEST FREE SCORE:")
    if best_free.get('crib_score_free', -1) >= 0:
        print(f"  Score: {best_free['crib_score_free']}/24")
        print(f"  Method: {best_free.get('method', 'N/A')}")
        print(f"  PT: {best_free.get('plaintext', 'N/A')[:80]}")
        print(f"  Nulls: {best_free.get('null_count', 'N/A')}")
    else:
        print("  No valid results")

    # ========================================================================
    # SAVE RESULTS
    # ========================================================================

    timestamp = datetime.datetime.now().strftime("%Y%m%d")
    out_path = os.path.join(_ROOT, "results", f"ita2_xor_stepping_{timestamp}.json")

    output = {
        'timestamp': datetime.datetime.now().isoformat(),
        'hypothesis': 'ITA-2/Baudot XOR with key-stepping',
        'ciphertext': CT,
        'total_tested': total_tested,
        'store_threshold': STORE_THRESHOLD,
        'encodings_tested': list(ENCODINGS.keys()),
        'models_tested': ['A_retry', 'B_skip'],
        'num_keys': len(all_keys),
        'best_anchored': best_anchored if best_anchored.get('crib_score_anchored', -1) >= 0 else None,
        'best_free': best_free if best_free.get('crib_score_free', -1) >= 0 else None,
        'results_above_threshold': sorted(
            results_above_threshold,
            key=lambda x: max(x.get('crib_score_anchored', 0),
                              x.get('crib_score_free', 0)),
            reverse=True
        )[:100],  # Top 100 only
        'conclusion': None,  # filled below
    }

    # Determine conclusion
    max_anchored = best_anchored.get('crib_score_anchored', 0)
    max_free = best_free.get('crib_score_free', 0)
    best_overall = max(max_anchored, max_free)

    if best_overall >= 18:
        output['conclusion'] = 'SIGNAL -- investigate further'
    elif best_overall >= 10:
        output['conclusion'] = 'INTERESTING -- log for review'
    elif best_overall >= 6:
        output['conclusion'] = 'MARGINAL -- likely noise'
    else:
        output['conclusion'] = 'NOISE -- no crib matches above random expectation'

    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to: {out_path}")

    return output


if __name__ == '__main__':
    run_sweep()
