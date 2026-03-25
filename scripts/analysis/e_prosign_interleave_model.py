#!/usr/bin/env python3
"""
Cipher: prosign_interleave
Family: analysis
Status: active
Keyspace: ~56 cipher chars x keywords x variants x transpositions
Last run:
Best score:
"""
"""
E-PROSIGN-INTERLEAVE-MODEL: Test the hypothesis that K4 interleaves
plaintext operating signals (at "null" positions) with ciphertext.

Model:
  - Positions in CONSENSUS_NULL_POSITIONS → cleartext prosigns (W, K, Z, etc.)
  - Positions in CRIB_POSITIONS → cleartext English words (EASTNORTHEAST, BERLINCLOCK)
  - Positions 95-96 (AR) → cleartext "end of transmission" prosign
  - ALL REMAINING POSITIONS → the actual ciphertext to decrypt

Tests:
  1. Extract cipher-only characters and analyze statistics
  2. Periodic Beaufort/Vigenere with thematic keywords
  3. Columnar transposition + periodic substitution
  4. Score with score_candidate_free (free-position crib search on decrypted text)
     NOTE: Under this model, cribs are NOT in the ciphertext — they're plaintext.
     So we use quadgram scoring and English word detection instead.
  5. Also try: what if cribs ARE in the cipher but prosigns aren't?
     (Just remove prosign positions, keep cribs as ciphertext)

Output: results/prosign_interleave_model.json
Repro: PYTHONPATH=src python3 -u scripts/analysis/e_prosign_interleave_model.py
"""

import json
import sys
import os
import time
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CONSENSUS_NULL_POSITIONS,
    CRIB_POSITIONS, CRIB_DICT, KRYPTOS_ALPHABET
)
from kryptos.kernel.scoring.aggregate import score_candidate_free

# ── Model definitions ──

# Model A: Full prosign model — remove prosigns + cribs + AR
PROSIGN_POS = CONSENSUS_NULL_POSITIONS  # 17 positions
CRIB_POS = CRIB_POSITIONS              # 24 positions
AR_POS = {95, 96}                       # End of transmission

# Also consider: C at position 94 might be cleartext "Correct"
C_POS = {94}

CLEARTEXT_FULL = PROSIGN_POS | CRIB_POS | AR_POS | C_POS
CLEARTEXT_NO_C = PROSIGN_POS | CRIB_POS | AR_POS
CLEARTEXT_PROSIGN_ONLY = PROSIGN_POS | AR_POS  # Keep cribs as cipher

VARIANTS = ["beaufort", "vigenere", "var_beaufort"]

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "SHADOW", "BERLIN",
    "SCHEIDT", "SANBORN", "SEVEN", "CLOCK", "MORSE", "CIPHER", "SECRET",
    "TELEGRAPH", "SEMAPHORE", "CHAPPE", "POLYBIUS", "SIGNAL", "CHART",
    "TOWER", "ANTIPODES", "LUCID", "MATRIX", "ENIGMA", "MEDUSA",
    "INVISIBLE", "HIDDEN", "MARCONI", "OPTICAL", "CAMPO",
]

# Load quadgrams for English scoring
QUADGRAM_PATH = os.path.join(_ROOT, "data", "english_quadgrams.json")
QUADGRAMS = {}
QG_FLOOR = -10.0
if os.path.exists(QUADGRAM_PATH):
    with open(QUADGRAM_PATH) as f:
        QUADGRAMS = json.load(f)
    QG_FLOOR = min(QUADGRAMS.values()) - 1.0


def quadgram_score(text):
    """Score text by quadgram log-probability."""
    if len(text) < 4:
        return QG_FLOOR
    score = 0
    n = 0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        score += QUADGRAMS.get(qg, QG_FLOOR)
        n += 1
    return score / n if n > 0 else QG_FLOOR


def decrypt_periodic(ct_nums, key_text, variant, alphabet=ALPH):
    """Decrypt with periodic key."""
    key_nums = [alphabet.index(c) for c in key_text if c in alphabet]
    mod = len(alphabet)
    klen = len(key_nums)
    pt = []
    for i, c in enumerate(ct_nums):
        k = key_nums[i % klen]
        if variant == "beaufort":
            p = (k - c) % mod
        elif variant == "vigenere":
            p = (c - k) % mod
        elif variant == "var_beaufort":
            p = (c + k) % mod
        pt.append(alphabet[p])
    return ''.join(pt)


def columnar_untranspose(text, width):
    """Undo columnar transposition."""
    n = len(text)
    nrows = (n + width - 1) // width
    full_cols = n % width or width
    cols = []
    idx = 0
    for col in range(width):
        col_len = nrows if col < full_cols else nrows - 1
        cols.append(text[idx:idx + col_len])
        idx += col_len
    result = []
    for row in range(nrows):
        for col in range(width):
            if row < len(cols[col]):
                result.append(cols[col][row])
    return ''.join(result)


def compute_ic(text):
    n = len(text)
    if n < 2:
        return 0.0
    freq = Counter(text)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def english_word_count(text, min_len=3):
    """Count recognizable English words in text."""
    wordlist_path = os.path.join(_ROOT, "wordlists", "english.txt")
    if not os.path.exists(wordlist_path):
        return 0
    with open(wordlist_path) as f:
        words = set(w.strip().upper() for w in f if len(w.strip()) >= min_len)
    count = 0
    for length in range(min_len, min(len(text) + 1, 12)):
        for i in range(len(text) - length + 1):
            if text[i:i+length] in words:
                count += 1
    return count


print("=" * 70)
print("E-PROSIGN-INTERLEAVE-MODEL")
print("=" * 70)

t0 = time.time()
all_hits = []

# ══════════════════════════════════════════════════════════════════════════
# PHASE 1: Extract and characterize cipher-only strings
# ══════════════════════════════════════════════════════════════════════════
print("\n[Phase 1] Extract cipher-only characters under each model")
print("-" * 50)

models = {
    "A_full": CLEARTEXT_FULL,       # Remove prosigns + cribs + C + AR
    "B_no_c": CLEARTEXT_NO_C,       # Remove prosigns + cribs + AR (keep C)
    "C_prosign_ar": CLEARTEXT_PROSIGN_ONLY,  # Remove prosigns + AR only (keep cribs as cipher)
    "D_prosign_only": PROSIGN_POS,   # Remove only prosign positions (17)
}

cipher_strings = {}
for name, cleartext_pos in models.items():
    cipher = ''.join(CT[i] for i in range(CT_LEN) if i not in cleartext_pos)
    cipher_strings[name] = cipher
    ic = compute_ic(cipher)
    qg = quadgram_score(cipher)

    # Map of what's cleartext
    cleartext_chars = ''.join(CT[i] for i in sorted(cleartext_pos) if i < CT_LEN)

    print(f"\n  Model {name}:")
    print(f"    Cleartext positions: {len(cleartext_pos)}")
    print(f"    Cleartext chars: {cleartext_chars}")
    print(f"    Cipher length: {len(cipher)}")
    print(f"    Cipher: {cipher}")
    print(f"    IC: {ic:.4f}  (random=0.0385, English=0.065)")
    print(f"    Quadgram/char: {qg:.3f}  (English~-4.2, random~-5.3)")

    # Letter frequency
    freq = Counter(cipher)
    print(f"    Distinct letters: {len(freq)}")
    print(f"    Top 5: {freq.most_common(5)}")


# ══════════════════════════════════════════════════════════════════════════
# PHASE 2: Cipher attacks on Model A (full prosign removal = ~56 chars)
# ══════════════════════════════════════════════════════════════════════════
print(f"\n{'=' * 70}")
print("[Phase 2] Cipher attacks on Model A (full prosign + crib removal)")
print("-" * 50)

cipher_a = cipher_strings["A_full"]
cipher_a_nums = [ALPH_IDX[c] for c in cipher_a]
n_a = len(cipher_a)
print(f"  Cipher ({n_a} chars): {cipher_a}")

phase2_hits = []

# 2a: Periodic keywords (AZ and KA)
for kw in KEYWORDS:
    for variant in VARIANTS:
        for alpha_name, alpha in [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]:
            ct_in_alpha = [alpha.index(c) for c in cipher_a if c in alpha]
            if len(ct_in_alpha) != n_a:
                continue
            pt = decrypt_periodic(ct_in_alpha, kw, variant, alpha)
            qg = quadgram_score(pt)
            wc = english_word_count(pt)
            fsb = score_candidate_free(pt)

            score = max(fsb.crib_score, wc)
            if qg > -4.8 or score >= 4 or wc >= 3:
                hit = {"phase": 2, "model": "A_full", "method": "periodic",
                       "keyword": kw, "variant": variant, "alphabet": alpha_name,
                       "qg": round(qg, 3), "words": wc, "crib_free": fsb.crib_score,
                       "pt": pt[:60]}
                phase2_hits.append(hit)

print(f"  Periodic keywords: {len(KEYWORDS)} x 3 variants x 2 alphabets = {len(KEYWORDS)*6}")
print(f"  Hits (qg > -4.8 or words >= 3): {len(phase2_hits)}")
all_hits.extend(phase2_hits)

# 2b: All 26 single-letter keys
for k in range(26):
    for variant in VARIANTS:
        pt_nums = []
        for c in cipher_a_nums:
            if variant == "beaufort":
                pt_nums.append((k - c) % MOD)
            elif variant == "vigenere":
                pt_nums.append((c - k) % MOD)
            elif variant == "var_beaufort":
                pt_nums.append((c + k) % MOD)
        pt = ''.join(chr(p + 65) for p in pt_nums)
        qg = quadgram_score(pt)
        if qg > -4.8:
            hit = {"phase": 2, "model": "A_full", "method": "caesar",
                   "key": chr(k + 65), "variant": variant,
                   "qg": round(qg, 3), "pt": pt[:60]}
            all_hits.append(hit)

# 2c: Columnar transposition then periodic
print(f"  Testing columnar + periodic...")
for width in [7, 8, 9, 4, 6, 14]:
    ct_col = columnar_untranspose(cipher_a, width)
    ct_col_nums = [ALPH_IDX[c] for c in ct_col]
    for kw in ["KRYPTOS", "DEFECTOR", "SEMAPHORE", "SEVEN", "ABSCISSA", "SHADOW"]:
        for variant in VARIANTS:
            pt = decrypt_periodic(ct_col_nums, kw, variant)
            qg = quadgram_score(pt)
            if qg > -4.8:
                hit = {"phase": 2, "model": "A_full", "method": f"col{width}_periodic",
                       "keyword": kw, "variant": variant, "qg": round(qg, 3),
                       "pt": pt[:60]}
                all_hits.append(hit)


# ══════════════════════════════════════════════════════════════════════════
# PHASE 3: Cipher attacks on Model C (prosign removal only, cribs in cipher)
# ══════════════════════════════════════════════════════════════════════════
print(f"\n{'=' * 70}")
print("[Phase 3] Cipher attacks on Model C (prosign + AR removal, cribs remain)")
print("-" * 50)

cipher_c = cipher_strings["C_prosign_ar"]
cipher_c_nums = [ALPH_IDX[c] for c in cipher_c]
n_c = len(cipher_c)
print(f"  Cipher ({n_c} chars): {cipher_c[:60]}...")

phase3_hits = []

# Map crib positions from CT97 to the new cipher string
# Need to know where each CT97 position ends up after removing prosign+AR positions
ct97_to_cipher = {}
cipher_idx = 0
for i in range(CT_LEN):
    if i not in CLEARTEXT_PROSIGN_ONLY:
        ct97_to_cipher[i] = cipher_idx
        cipher_idx += 1

# Check which crib positions survive and where they map
crib_in_cipher = {}
for pos, ch in CRIB_DICT.items():
    if pos in ct97_to_cipher:
        new_pos = ct97_to_cipher[pos]
        crib_in_cipher[new_pos] = ch

print(f"  Cribs mapped to cipher positions: {len(crib_in_cipher)}/24")
print(f"  Crib positions in cipher: {sorted(crib_in_cipher.keys())}")

for kw in KEYWORDS:
    for variant in VARIANTS:
        pt = decrypt_periodic(cipher_c_nums, kw, variant)
        # Check cribs at mapped positions
        crib_match = 0
        for cp, expected_ch in crib_in_cipher.items():
            if cp < len(pt) and pt[cp] == expected_ch:
                crib_match += 1

        qg = quadgram_score(pt)
        if crib_match >= 5 or qg > -4.8:
            hit = {"phase": 3, "model": "C_prosign_ar", "method": "periodic",
                   "keyword": kw, "variant": variant,
                   "crib_match": crib_match, "max_crib": len(crib_in_cipher),
                   "qg": round(qg, 3), "pt": pt[:60]}
            phase3_hits.append(hit)

print(f"  Periodic keywords tested: {len(KEYWORDS) * 3}")
print(f"  Hits (crib >= 5 or qg > -4.8): {len(phase3_hits)}")

# Show best crib matches
if phase3_hits:
    phase3_hits.sort(key=lambda h: -h.get("crib_match", 0))
    print(f"  Best crib match: {phase3_hits[0]['crib_match']}/{phase3_hits[0]['max_crib']}")
    for h in phase3_hits[:5]:
        print(f"    {h['keyword']}/{h['variant']}: {h['crib_match']} cribs, qg={h['qg']}")

all_hits.extend(phase3_hits)

# Col7 + periodic on model C
print(f"  Testing col7 + periodic on Model C...")
ct_col7 = columnar_untranspose(cipher_c, 7)
ct_col7_nums = [ALPH_IDX[c] for c in ct_col7]

for kw in KEYWORDS:
    for variant in VARIANTS:
        pt = decrypt_periodic(ct_col7_nums, kw, variant)
        fsb = score_candidate_free(pt)
        qg = quadgram_score(pt)
        if fsb.crib_score >= 5 or qg > -4.8:
            hit = {"phase": 3, "model": "C_prosign_ar", "method": "col7_periodic",
                   "keyword": kw, "variant": variant,
                   "crib_free": fsb.crib_score, "qg": round(qg, 3), "pt": pt[:60]}
            all_hits.append(hit)


# ══════════════════════════════════════════════════════════════════════════
# PHASE 4: Model D — just remove 17 prosign positions (same as CT80 but reframed)
# ══════════════════════════════════════════════════════════════════════════
print(f"\n{'=' * 70}")
print("[Phase 4] Model D (remove 17 prosigns only = 80 chars)")
print("-" * 50)

cipher_d = cipher_strings["D_prosign_only"]
print(f"  Cipher ({len(cipher_d)} chars): {cipher_d[:60]}...")

# This is the same as CT80 but the conceptual framing is different
# Under this model, the 80 chars contain both ciphertext AND cleartext cribs
# The cribs at their new positions should match if the model is right

# Map crib positions
ct97_to_d = {}
d_idx = 0
for i in range(CT_LEN):
    if i not in PROSIGN_POS:
        ct97_to_d[i] = d_idx
        d_idx += 1

crib_in_d = {}
for pos, ch in CRIB_DICT.items():
    if pos in ct97_to_d:
        crib_in_d[ct97_to_d[pos]] = ch

print(f"  Cribs in 80-char string: {len(crib_in_d)}")

# Check if cribs are readable as-is (no decryption needed for crib positions)
cleartext_crib_match = sum(1 for cp, ch in crib_in_d.items()
                           if cp < len(cipher_d) and cipher_d[cp] == ch)
print(f"  Cribs readable as cleartext: {cleartext_crib_match}/{len(crib_in_d)}")
# If this is 0, the cribs are encrypted, not cleartext

# Under the interleave model, the cribs SHOULD be readable as-is
# If they're not, the model doesn't hold for this variant


# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════
elapsed = time.time() - t0

print(f"\n{'=' * 70}")
print("SUMMARY")
print("=" * 70)

print(f"\n  Model A (full cleartext removal): {len(cipher_strings['A_full'])} cipher chars")
print(f"  Model B (no C removal): {len(cipher_strings['B_no_c'])} cipher chars")
print(f"  Model C (prosigns+AR only): {len(cipher_strings['C_prosign_ar'])} cipher chars")
print(f"  Model D (prosigns only): {len(cipher_strings['D_prosign_only'])} cipher chars")

print(f"\n  Total hits across all phases: {len(all_hits)}")
if all_hits:
    all_hits.sort(key=lambda h: -h.get("qg", -10))
    print(f"  Best quadgram score: {all_hits[0]['qg']}")
    print(f"\n  Top 10:")
    for i, h in enumerate(all_hits[:10]):
        print(f"    #{i+1}: qg={h.get('qg', '?')} {h.get('method', '')} "
              f"{h.get('keyword', '')} {h.get('variant', '')} "
              f"model={h.get('model', '')} pt={h.get('pt', '')[:45]}")

# Key diagnostic: are cribs plaintext?
print(f"\n  CRITICAL TEST: Are cribs plaintext in the 80-char string?")
print(f"  Cribs matching as cleartext: {cleartext_crib_match}/{len(crib_in_d)}")
if cleartext_crib_match == len(crib_in_d):
    print(f"  >>> YES! All cribs are readable in the clear after prosign removal!")
    print(f"  >>> This CONFIRMS the interleaving model!")
elif cleartext_crib_match == 0:
    print(f"  >>> NO. Cribs are NOT plaintext — they are encrypted.")
    print(f"  >>> The interleaving model needs modification: cribs are cipher, not clear.")
else:
    print(f"  >>> PARTIAL match: {cleartext_crib_match} cribs match. Ambiguous.")

verdict = "SIGNAL" if any(h.get("qg", -10) > -4.5 for h in all_hits) else "NOISE"
print(f"\n  VERDICT: {verdict}")
print(f"  Elapsed: {elapsed:.1f}s")

# Save
os.makedirs(os.path.join(_ROOT, "results"), exist_ok=True)
artifact = {
    "experiment": "E-PROSIGN-INTERLEAVE-MODEL",
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "models": {name: {"length": len(cs), "cipher": cs, "ic": round(compute_ic(cs), 4)}
               for name, cs in cipher_strings.items()},
    "total_hits": len(all_hits),
    "top_20": all_hits[:20],
    "crib_cleartext_test": cleartext_crib_match,
    "verdict": verdict,
    "elapsed": round(elapsed, 1),
}
outpath = os.path.join(_ROOT, "results", "prosign_interleave_model.json")
with open(outpath, "w") as f:
    json.dump(artifact, f, indent=2, default=str)
print(f"\n  Artifact: {outpath}")
