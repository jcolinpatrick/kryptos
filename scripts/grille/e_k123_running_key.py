#!/usr/bin/env python3
"""
Cipher: running key / Vigenere
Family: grille
Status: active
Keyspace: ~50000 configs
Last run:
Best score:
"""
"""E-K123-RUNNING-KEY: K1/K2/K3 plaintexts and ciphertexts as running key for K4.

Comprehensive test of whether K1-K3 plaintext or ciphertext serves as key
material for K4 decryption. Tests:

1. Running-key Vigenere/Beaufort with K1/K2/K3 PT individually
2. Concatenated K1+K2+K3 PT at various offsets
3. Reversed plaintexts as running key
4. K1-K3 ciphertexts as running key
5. Cross-section double decryption (K1_CT then K2_CT, etc.)
6. Partial running key + periodic keyword hybrid
7. K3 permutation-derived keystream

Uses both AZ and KA alphabets, score_candidate() and score_candidate_free().

Usage: PYTHONPATH=src python3 -u scripts/grille/e_k123_running_key.py
"""

import sys
import os
import time
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, N_CRIBS, NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.scoring.aggregate import (
    score_candidate, score_candidate_free,
)

# ── Alphabets ──────────────────────────────────────────────────────────────

AZ = ALPH
AZ_IDX = ALPH_IDX
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

ALPHABETS = {
    "AZ": (AZ, AZ_IDX),
    "KA": (KA, KA_IDX),
}

# ── K1-K3 Plaintexts (canonical, from src/kryptos/novelty/generators.py) ──

K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSED"
    "THEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHERED"
    "ANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONX"
    "DOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUT"
    "THERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWW"
    "THISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTY"
    "SEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVEN"
    "DEGREESEIGHTMINUTESFORTYFOURSECONDSWESTIDBYROWS"
)
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRIS"
    "THATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVED"
    "WITHTREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFT"
    "HANDCORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTED"
    "THECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHE"
    "CHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILS"
    "OFTHEROOMWITHINEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"
)

# ── K1-K3 Ciphertexts (from sculpture) ────────────────────────────────────

K1_CT_TEXT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
K2_CT_TEXT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE"
    "GGWHKKDQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA"
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI"
    "HHDDDUVHDWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX"
    "FLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ"
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP"
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)
K3_CT_TEXT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA"
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAE"
    "WMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR"
    "EIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI"
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT"
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)

# Morse code (K0)
MORSE_PT = (
    "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHT"
    "LYINGVIRTUALLYINVISIBLEITISALMOSTSUPERNATURAL"
    "TISYOURPOSITION"
    "SHADOWFORCES"
    "DIGETALINTERPRETATION"
    "LUCIDMEMORY"
)

# ── Periodic keywords ─────────────────────────────────────────────────────

PERIODIC_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "HOROLOGE",
    "DEFECTOR", "PARALLAX", "COLOPHON",
]

# ── Helper functions ───────────────────────────────────────────────────────

def clean(s):
    """Strip to uppercase A-Z only."""
    return ''.join(c for c in s.upper() if c.isalpha())


def to_nums(text, idx_map):
    """Convert text to numeric list using given alphabet index."""
    return [idx_map[c] for c in text]


def to_text(nums, alphabet):
    """Convert numeric list back to text using given alphabet."""
    return ''.join(alphabet[n % len(alphabet)] for n in nums)


def vig_decrypt(ct_nums, key_nums):
    """Vigenere decrypt: PT = (CT - KEY) mod 26"""
    return [(c - k) % 26 for c, k in zip(ct_nums, key_nums)]


def beau_decrypt(ct_nums, key_nums):
    """Beaufort decrypt: PT = (KEY - CT) mod 26"""
    return [(k - c) % 26 for c, k in zip(ct_nums, key_nums)]


def vbeau_decrypt(ct_nums, key_nums):
    """Variant Beaufort decrypt: PT = (CT + KEY) mod 26"""
    return [(c + k) % 26 for c, k in zip(ct_nums, key_nums)]


VARIANTS = {
    "Vig": vig_decrypt,
    "Beau": beau_decrypt,
    "VBeau": vbeau_decrypt,
}


def extend_key(key_text, length):
    """Repeat key to fill 'length' characters."""
    if len(key_text) == 0:
        return ""
    reps = (length // len(key_text)) + 1
    return (key_text * reps)[:length]


def score_pt(pt_text):
    """Score plaintext with both anchored and free scoring. Return best."""
    anchored = score_candidate(pt_text)
    free = score_candidate_free(pt_text)
    return anchored, free


# ── Tracking ───────────────────────────────────────────────────────────────

results_log = []
best_overall_score = 0
best_overall_config = None


def record(test_name, alph_name, variant_name, offset, pt_text, anchored, free):
    """Record a result, print if above noise."""
    global best_overall_score, best_overall_config

    score_a = anchored.crib_score
    score_f = free.crib_score

    best_score = max(score_a, score_f)
    label = f"{test_name}/{alph_name}/{variant_name}/off={offset}"

    if best_score > best_overall_score:
        best_overall_score = best_score
        best_overall_config = label

    if best_score > NOISE_FLOOR:
        tag = "FREE" if score_f > score_a else "ANCHORED"
        print(f"  ** {tag} {best_score}/24: {label}")
        print(f"     PT: {pt_text[:60]}...")
        if free.ene_found:
            print(f"     ENE found at offsets: {free.free_crib.ene_offsets}")
        if free.bc_found:
            print(f"     BC found at offsets: {free.free_crib.bc_offsets}")
        print(f"     Anchored: {anchored.summary}")
        print(f"     Free:     {free.summary}")

    if best_score >= STORE_THRESHOLD:
        results_log.append({
            "test": test_name,
            "alphabet": alph_name,
            "variant": variant_name,
            "offset": offset,
            "anchored_score": score_a,
            "free_score": score_f,
            "ic": anchored.ic_value,
            "pt_sample": pt_text[:80],
        })

    return best_score


# ══════════════════════════════════════════════════════════════════════════
# TEST 1: Running-key Vigenere/Beaufort with individual K1/K2/K3 PT
# ══════════════════════════════════════════════════════════════════════════

print("=" * 78)
print("E-K123-RUNNING-KEY: K1-K3 as running key for K4")
print("=" * 78)
print(f"K4 CT: {CT_LEN} chars")
print(f"K1 PT: {len(K1_PT)} chars")
print(f"K2 PT: {len(K2_PT)} chars")
print(f"K3 PT: {len(K3_PT)} chars")
print(f"K1 CT: {len(K1_CT_TEXT)} chars")
print(f"K2 CT: {len(clean(K2_CT_TEXT))} chars")
print(f"K3 CT: {len(clean(K3_CT_TEXT))} chars")
print(f"Morse: {len(MORSE_PT)} chars")
print()

t0 = time.time()
total_configs = 0

# ── Test 1: Individual plaintexts as running key ──────────────────────────
print("--- TEST 1: Individual K1/K2/K3 plaintexts as running key ---")

SOURCES_PT = {
    "K1_PT": K1_PT,
    "K2_PT": K2_PT,
    "K3_PT": K3_PT,
    "Morse": MORSE_PT,
}

for src_name, src_text in SOURCES_PT.items():
    src_clean = clean(src_text)
    best_for_src = 0

    for alph_name, (alphabet, aidx) in ALPHABETS.items():
        ct_nums = to_nums(CT, aidx)

        # If source is shorter than CT, extend by cycling
        key_text = extend_key(src_clean, CT_LEN)
        key_nums = to_nums(key_text, aidx)

        for var_name, decrypt_fn in VARIANTS.items():
            pt_nums = decrypt_fn(ct_nums, key_nums)
            pt_text = to_text(pt_nums, alphabet)

            anchored, free = score_pt(pt_text)
            score = record(f"T1:{src_name}", alph_name, var_name, 0, pt_text, anchored, free)
            best_for_src = max(best_for_src, score)
            total_configs += 1

        # Also try at all offsets (for longer sources)
        if len(src_clean) > CT_LEN:
            max_off = len(src_clean) - CT_LEN
            for offset in range(1, max_off + 1):
                key_slice = src_clean[offset:offset + CT_LEN]
                key_nums = to_nums(key_slice, aidx)

                for var_name, decrypt_fn in VARIANTS.items():
                    pt_nums = decrypt_fn(ct_nums, key_nums)
                    pt_text = to_text(pt_nums, alphabet)

                    anchored, free = score_pt(pt_text)
                    score = record(f"T1:{src_name}", alph_name, var_name, offset, pt_text, anchored, free)
                    best_for_src = max(best_for_src, score)
                    total_configs += 1

    print(f"  {src_name}: best={best_for_src}/24")


# ══════════════════════════════════════════════════════════════════════════
# TEST 2: Concatenated K1+K2+K3 plaintext at various offsets
# ══════════════════════════════════════════════════════════════════════════

print("\n--- TEST 2: Concatenated K1+K2+K3 PT at section boundaries ---")

K123_PT = K1_PT + K2_PT + K3_PT
K321_PT = K3_PT + K2_PT + K1_PT

CONCAT_SOURCES = {
    "K123": K123_PT,
    "K321": K321_PT,
    "K1K3": K1_PT + K3_PT,
    "K2K3": K2_PT + K3_PT,
    "K3K1": K3_PT + K1_PT,
    "K1K2": K1_PT + K2_PT,
}

# Section boundaries for K1+K2+K3
BOUNDARY_OFFSETS = [0, len(K1_PT), len(K1_PT) + len(K2_PT)]
# Also test every offset for shorter combos
EXTRA_OFFSETS = list(range(0, 50))  # First 50 offsets

for src_name, src_text in CONCAT_SOURCES.items():
    src_clean = clean(src_text)
    best_for_src = 0
    max_off = max(0, len(src_clean) - CT_LEN)

    offsets_to_try = set(BOUNDARY_OFFSETS + EXTRA_OFFSETS)
    offsets_to_try = sorted([o for o in offsets_to_try if 0 <= o <= max_off])
    # For thoroughness, try ALL offsets
    offsets_to_try = list(range(max_off + 1))

    for alph_name, (alphabet, aidx) in ALPHABETS.items():
        ct_nums = to_nums(CT, aidx)

        for offset in offsets_to_try:
            key_slice = src_clean[offset:offset + CT_LEN]
            if len(key_slice) < CT_LEN:
                continue
            key_nums = to_nums(key_slice, aidx)

            for var_name, decrypt_fn in VARIANTS.items():
                pt_nums = decrypt_fn(ct_nums, key_nums)
                pt_text = to_text(pt_nums, alphabet)

                anchored, free = score_pt(pt_text)
                score = record(f"T2:{src_name}", alph_name, var_name, offset, pt_text, anchored, free)
                best_for_src = max(best_for_src, score)
                total_configs += 1

    print(f"  {src_name}: best={best_for_src}/24 ({len(offsets_to_try)} offsets x 2 alphs x 3 vars)")


# ══════════════════════════════════════════════════════════════════════════
# TEST 3: Reversed plaintexts as running key
# ══════════════════════════════════════════════════════════════════════════

print("\n--- TEST 3: Reversed plaintexts as running key ---")

REV_SOURCES = {
    "K1_rev": K1_PT[::-1],
    "K2_rev": K2_PT[::-1],
    "K3_rev": K3_PT[::-1],
    "K123_rev": (K1_PT + K2_PT + K3_PT)[::-1],
    "K321_rev": (K3_PT + K2_PT + K1_PT)[::-1],
    "Morse_rev": MORSE_PT[::-1],
}

for src_name, src_text in REV_SOURCES.items():
    src_clean = clean(src_text)
    best_for_src = 0
    max_off = max(0, len(src_clean) - CT_LEN)
    offsets_to_try = list(range(max_off + 1))

    for alph_name, (alphabet, aidx) in ALPHABETS.items():
        ct_nums = to_nums(CT, aidx)

        for offset in offsets_to_try:
            key_slice = src_clean[offset:offset + CT_LEN]
            if len(key_slice) < CT_LEN:
                # Extend by cycling
                key_slice = extend_key(src_clean, CT_LEN)
            key_nums = to_nums(key_slice, aidx)

            for var_name, decrypt_fn in VARIANTS.items():
                pt_nums = decrypt_fn(ct_nums, key_nums)
                pt_text = to_text(pt_nums, alphabet)

                anchored, free = score_pt(pt_text)
                score = record(f"T3:{src_name}", alph_name, var_name, offset, pt_text, anchored, free)
                best_for_src = max(best_for_src, score)
                total_configs += 1

    print(f"  {src_name}: best={best_for_src}/24")


# ══════════════════════════════════════════════════════════════════════════
# TEST 4: K1-K3 CIPHERTEXTS as running key
# ══════════════════════════════════════════════════════════════════════════

print("\n--- TEST 4: K1-K3 ciphertexts as running key ---")

CT_SOURCES = {
    "K1_CT": clean(K1_CT_TEXT),
    "K2_CT": clean(K2_CT_TEXT),
    "K3_CT": clean(K3_CT_TEXT),
    "K1K2K3_CT": clean(K1_CT_TEXT) + clean(K2_CT_TEXT) + clean(K3_CT_TEXT),
    "K1_CT_rev": clean(K1_CT_TEXT)[::-1],
    "K2_CT_rev": clean(K2_CT_TEXT)[::-1],
    "K3_CT_rev": clean(K3_CT_TEXT)[::-1],
}

for src_name, src_text in CT_SOURCES.items():
    best_for_src = 0
    max_off = max(0, len(src_text) - CT_LEN)
    offsets_to_try = list(range(max_off + 1))
    if not offsets_to_try:
        offsets_to_try = [0]

    for alph_name, (alphabet, aidx) in ALPHABETS.items():
        ct_nums = to_nums(CT, aidx)

        for offset in offsets_to_try:
            key_slice = src_text[offset:offset + CT_LEN]
            if len(key_slice) < CT_LEN:
                key_slice = extend_key(src_text, CT_LEN)
            key_nums = to_nums(key_slice, aidx)

            for var_name, decrypt_fn in VARIANTS.items():
                pt_nums = decrypt_fn(ct_nums, key_nums)
                pt_text = to_text(pt_nums, alphabet)

                anchored, free = score_pt(pt_text)
                score = record(f"T4:{src_name}", alph_name, var_name, offset, pt_text, anchored, free)
                best_for_src = max(best_for_src, score)
                total_configs += 1

    print(f"  {src_name}: best={best_for_src}/24")


# ══════════════════════════════════════════════════════════════════════════
# TEST 5: Cross-section double decryption
# ══════════════════════════════════════════════════════════════════════════

print("\n--- TEST 5: Cross-section double decryption ---")

CROSS_PAIRS = [
    ("K1_CT+K2_CT", clean(K1_CT_TEXT), clean(K2_CT_TEXT)),
    ("K2_CT+K3_CT", clean(K2_CT_TEXT), clean(K3_CT_TEXT)),
    ("K1_CT+K3_CT", clean(K1_CT_TEXT), clean(K3_CT_TEXT)),
    ("K3_CT+K1_CT", clean(K3_CT_TEXT), clean(K1_CT_TEXT)),
    ("K1_PT+K2_PT", K1_PT, K2_PT),
    ("K2_PT+K3_PT", K2_PT, K3_PT),
    ("K1_PT+K3_PT", K1_PT, K3_PT),
    ("K1_CT+K2_PT", clean(K1_CT_TEXT), K2_PT),
    ("K2_CT+K3_PT", clean(K2_CT_TEXT), K3_PT),
]

for pair_name, key1_text, key2_text in CROSS_PAIRS:
    best_for_pair = 0
    key1 = extend_key(key1_text, CT_LEN)
    key2 = extend_key(key2_text, CT_LEN)

    for alph_name, (alphabet, aidx) in ALPHABETS.items():
        ct_nums = to_nums(CT, aidx)
        key1_nums = to_nums(key1, aidx)
        key2_nums = to_nums(key2, aidx)

        # All 9 combinations of first-layer and second-layer variants
        for var1_name, decrypt1_fn in VARIANTS.items():
            intermediate = decrypt1_fn(ct_nums, key1_nums)

            for var2_name, decrypt2_fn in VARIANTS.items():
                pt_nums = decrypt2_fn(intermediate, key2_nums)
                pt_text = to_text(pt_nums, alphabet)

                anchored, free = score_pt(pt_text)
                combo_name = f"{var1_name}+{var2_name}"
                score = record(f"T5:{pair_name}", alph_name, combo_name, 0, pt_text, anchored, free)
                best_for_pair = max(best_for_pair, score)
                total_configs += 1

    print(f"  {pair_name}: best={best_for_pair}/24")


# ══════════════════════════════════════════════════════════════════════════
# TEST 6: Partial running key + periodic keyword hybrid
# ══════════════════════════════════════════════════════════════════════════

print("\n--- TEST 6: Partial running key + periodic keyword hybrid ---")

RUNNING_KEY_SOURCES = {
    "K1_PT": K1_PT,
    "K2_PT": K2_PT[:CT_LEN],
    "K3_PT": K3_PT[:CT_LEN],
    "K1_CT": clean(K1_CT_TEXT),
    "K2_CT": clean(K2_CT_TEXT)[:CT_LEN],
    "K3_CT": clean(K3_CT_TEXT)[:CT_LEN],
}

# Try split points: first N chars from running key, rest from periodic keyword
SPLIT_POINTS = [21, 33, 34, 63, 64, 73, 74, 48, 50, 13, 24]

best_t6 = 0
for src_name, src_text in RUNNING_KEY_SOURCES.items():
    src_clean = clean(src_text)

    for kw in PERIODIC_KEYWORDS:
        for split in SPLIT_POINTS:
            if split >= CT_LEN:
                continue

            # Build hybrid key: first 'split' chars from running key, rest from keyword
            rk_part = extend_key(src_clean, split)[:split]
            kw_part = extend_key(kw, CT_LEN - split)[:CT_LEN - split]
            hybrid_key = rk_part + kw_part

            for alph_name, (alphabet, aidx) in ALPHABETS.items():
                ct_nums = to_nums(CT, aidx)
                key_nums = to_nums(hybrid_key, aidx)

                for var_name, decrypt_fn in VARIANTS.items():
                    pt_nums = decrypt_fn(ct_nums, key_nums)
                    pt_text = to_text(pt_nums, alphabet)

                    anchored, free = score_pt(pt_text)
                    score = record(f"T6:{src_name}+{kw}@{split}",
                                   alph_name, var_name, split, pt_text, anchored, free)
                    best_t6 = max(best_t6, score)
                    total_configs += 1

            # Also try reverse: keyword first, running key after split
            kw_part2 = extend_key(kw, split)[:split]
            rk_part2 = extend_key(src_clean, CT_LEN - split)[:CT_LEN - split]
            hybrid_key2 = kw_part2 + rk_part2

            for alph_name, (alphabet, aidx) in ALPHABETS.items():
                ct_nums = to_nums(CT, aidx)
                key_nums = to_nums(hybrid_key2, aidx)

                for var_name, decrypt_fn in VARIANTS.items():
                    pt_nums = decrypt_fn(ct_nums, key_nums)
                    pt_text = to_text(pt_nums, alphabet)

                    anchored, free = score_pt(pt_text)
                    score = record(f"T6:{kw}+{src_name}@{split}",
                                   alph_name, var_name, split, pt_text, anchored, free)
                    best_t6 = max(best_t6, score)
                    total_configs += 1

print(f"  Test 6 overall best: {best_t6}/24")


# ══════════════════════════════════════════════════════════════════════════
# TEST 7: K3 permutation-derived keystream
# ══════════════════════════════════════════════════════════════════════════

print("\n--- TEST 7: K3 permutation-derived keystream ---")

# K3 uses double rotational transposition (24x14 -> 8x42).
# The K3 decryption permutation maps CT positions to PT positions.
# We can derive the K3 permutation by comparing K3_CT to K3_PT.

k3_ct_clean = clean(K3_CT_TEXT)
k3_pt_clean = clean(K3_PT)

print(f"  K3 CT length: {len(k3_ct_clean)}")
print(f"  K3 PT length: {len(k3_pt_clean)}")

# Build K3 permutation: for each CT position, find the matching PT position
# K3 is a transposition, so same letters but reordered.
# perm[i] = j means CT[i] came from PT[j]
# We need to find this permutation.

if len(k3_ct_clean) == len(k3_pt_clean):
    from collections import Counter
    ct_freq = Counter(k3_ct_clean)
    pt_freq = Counter(k3_pt_clean)

    if ct_freq == pt_freq:
        print("  K3 CT and PT have matching frequencies -- pure transposition confirmed")

        # Build permutation by matching letters
        # For each letter, list PT positions with that letter
        from collections import defaultdict
        pt_positions = defaultdict(list)
        for i, ch in enumerate(k3_pt_clean):
            pt_positions[ch].append(i)

        # Assign CT positions to PT positions in order for each letter
        pt_pos_idx = {ch: 0 for ch in pt_positions}
        k3_perm = [0] * len(k3_ct_clean)
        valid_perm = True

        for i, ch in enumerate(k3_ct_clean):
            if pt_pos_idx[ch] < len(pt_positions[ch]):
                k3_perm[i] = pt_positions[ch][pt_pos_idx[ch]]
                pt_pos_idx[ch] += 1
            else:
                valid_perm = False
                break

        if valid_perm:
            # Verify: applying perm to PT should give CT
            reconstructed = ''.join(k3_pt_clean[k3_perm[i]] for i in range(len(k3_ct_clean)))
            if reconstructed == k3_ct_clean:
                print("  K3 permutation verified: apply_perm(PT, perm) == CT")
            else:
                print("  WARNING: Naive permutation does not reconstruct CT exactly")
                print("  (Letter order ambiguity -- multiple permutations possible)")

            # Now use this K3 permutation to scramble keywords into keystreams
            # Take a keyword repeated to 97 chars, permute with K3 perm (mod 97)
            # Use result as Vigenere key for K4

            # We need to map the K3 perm (length ~336) to K4 length (97)
            # Method: take the first 97 elements of the K3 perm, mod 97
            k3_perm_97 = [p % CT_LEN for p in k3_perm[:CT_LEN]]

            best_t7 = 0
            for kw in PERIODIC_KEYWORDS:
                kw_extended = extend_key(kw, CT_LEN)

                # Apply K3 permutation (mod 97) to create scrambled keystream
                scrambled_key = ''.join(kw_extended[k3_perm_97[i]] for i in range(CT_LEN))

                for alph_name, (alphabet, aidx) in ALPHABETS.items():
                    ct_nums = to_nums(CT, aidx)
                    key_nums = to_nums(scrambled_key, aidx)

                    for var_name, decrypt_fn in VARIANTS.items():
                        pt_nums = decrypt_fn(ct_nums, key_nums)
                        pt_text = to_text(pt_nums, alphabet)

                        anchored, free = score_pt(pt_text)
                        score = record(f"T7:K3perm+{kw}", alph_name, var_name, 0,
                                       pt_text, anchored, free)
                        best_t7 = max(best_t7, score)
                        total_configs += 1

            # Also try: K3 perm applied to K1/K2/K3 plaintexts as keystream
            for pt_name, pt_text in [("K1_PT", K1_PT), ("K2_PT", K2_PT), ("K3_PT", K3_PT)]:
                pt_extended = extend_key(clean(pt_text), CT_LEN)
                scrambled_pt_key = ''.join(pt_extended[k3_perm_97[i]] for i in range(CT_LEN))

                for alph_name, (alphabet, aidx) in ALPHABETS.items():
                    ct_nums = to_nums(CT, aidx)
                    key_nums = to_nums(scrambled_pt_key, aidx)

                    for var_name, decrypt_fn in VARIANTS.items():
                        pt_nums = decrypt_fn(ct_nums, key_nums)
                        pt_text_out = to_text(pt_nums, alphabet)

                        anchored, free = score_pt(pt_text_out)
                        score = record(f"T7:K3perm+{pt_name}", alph_name, var_name, 0,
                                       pt_text_out, anchored, free)
                        best_t7 = max(best_t7, score)
                        total_configs += 1

            # Also try: use K3 perm directly as a numeric keystream
            # perm values as keystream (mod 26)
            k3_key_from_perm = [k3_perm[i % len(k3_perm)] % 26 for i in range(CT_LEN)]

            for alph_name, (alphabet, aidx) in ALPHABETS.items():
                ct_nums = to_nums(CT, aidx)

                for var_name, decrypt_fn in VARIANTS.items():
                    pt_nums = decrypt_fn(ct_nums, k3_key_from_perm)
                    pt_text_out = to_text(pt_nums, alphabet)

                    anchored, free = score_pt(pt_text_out)
                    score = record(f"T7:K3perm_direct", alph_name, var_name, 0,
                                   pt_text_out, anchored, free)
                    best_t7 = max(best_t7, score)
                    total_configs += 1

            # Try inverted permutation too
            from kryptos.kernel.transforms.transposition import invert_perm
            k3_inv_perm = invert_perm(k3_perm)
            k3_inv_97 = [p % CT_LEN for p in k3_inv_perm[:CT_LEN]]

            for kw in PERIODIC_KEYWORDS:
                kw_extended = extend_key(kw, CT_LEN)
                scrambled_key_inv = ''.join(kw_extended[k3_inv_97[i]] for i in range(CT_LEN))

                for alph_name, (alphabet, aidx) in ALPHABETS.items():
                    ct_nums = to_nums(CT, aidx)
                    key_nums = to_nums(scrambled_key_inv, aidx)

                    for var_name, decrypt_fn in VARIANTS.items():
                        pt_nums = decrypt_fn(ct_nums, key_nums)
                        pt_text_out = to_text(pt_nums, alphabet)

                        anchored, free = score_pt(pt_text_out)
                        score = record(f"T7:K3inv+{kw}", alph_name, var_name, 0,
                                       pt_text_out, anchored, free)
                        best_t7 = max(best_t7, score)
                        total_configs += 1

            print(f"  Test 7 overall best: {best_t7}/24")
        else:
            print("  Cannot build K3 perm: letter assignment failed")
    else:
        print("  K3 CT/PT frequency mismatch -- cannot derive permutation directly")
        diff_letters = set()
        for ch in set(list(ct_freq.keys()) + list(pt_freq.keys())):
            if ct_freq.get(ch, 0) != pt_freq.get(ch, 0):
                diff_letters.add(ch)
        print(f"  Mismatched letters: {diff_letters}")
        best_t7 = 0
        print(f"  Test 7 skipped due to frequency mismatch")
else:
    print(f"  K3 CT/PT length mismatch: {len(k3_ct_clean)} vs {len(k3_pt_clean)}")
    print(f"  Cannot derive K3 permutation")
    best_t7 = 0


# ══════════════════════════════════════════════════════════════════════════
# TEST 8 (BONUS): K4 CT XORed/added with K1-K3 character-by-character
# ══════════════════════════════════════════════════════════════════════════

print("\n--- TEST 8 (BONUS): Direct character addition/subtraction ---")

# What if K4[i] = K_other[i] + PT[i] mod 26, i.e. running key is literally the other section?
# This is algebraically identical to T1/T4 Vig, but let's also try CT+CT combinations
# (K4_CT[i] + K1_CT[i]) mod 26 as a potential plaintext

DIRECT_SOURCES = {
    "K1_CT": clean(K1_CT_TEXT),
    "K2_CT": clean(K2_CT_TEXT),
    "K3_CT": clean(K3_CT_TEXT),
    "K1_PT": K1_PT,
    "K2_PT": K2_PT,
    "K3_PT": K3_PT,
}

best_t8 = 0
for src_name, src_text in DIRECT_SOURCES.items():
    key_text = extend_key(clean(src_text), CT_LEN)

    for alph_name, (alphabet, aidx) in ALPHABETS.items():
        ct_nums = to_nums(CT, aidx)
        key_nums = to_nums(key_text, aidx)

        # Try: result = (K4 + source) mod 26  (plain addition)
        added = [(c + k) % 26 for c, k in zip(ct_nums, key_nums)]
        pt_text = to_text(added, alphabet)
        anchored, free = score_pt(pt_text)
        score = record(f"T8:add:{src_name}", alph_name, "add", 0, pt_text, anchored, free)
        best_t8 = max(best_t8, score)
        total_configs += 1

        # Try: result = (K4 - source) mod 26
        subbed = [(c - k) % 26 for c, k in zip(ct_nums, key_nums)]
        pt_text = to_text(subbed, alphabet)
        anchored, free = score_pt(pt_text)
        score = record(f"T8:sub:{src_name}", alph_name, "sub", 0, pt_text, anchored, free)
        best_t8 = max(best_t8, score)
        total_configs += 1

        # Try: result = (source - K4) mod 26
        subbed2 = [(k - c) % 26 for c, k in zip(ct_nums, key_nums)]
        pt_text = to_text(subbed2, alphabet)
        anchored, free = score_pt(pt_text)
        score = record(f"T8:rsub:{src_name}", alph_name, "rsub", 0, pt_text, anchored, free)
        best_t8 = max(best_t8, score)
        total_configs += 1

print(f"  Test 8 overall best: {best_t8}/24")


# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════

elapsed = time.time() - t0

print()
print("=" * 78)
print("SUMMARY")
print("=" * 78)
print(f"  Total configurations tested: {total_configs:,}")
print(f"  Elapsed: {elapsed:.1f}s")
print(f"  Best overall score: {best_overall_score}/24")
print(f"  Best config: {best_overall_config}")
print()

if results_log:
    print(f"  Results above store threshold ({STORE_THRESHOLD}):")
    for r in sorted(results_log, key=lambda x: -max(x['anchored_score'], x['free_score'])):
        best_s = max(r['anchored_score'], r['free_score'])
        print(f"    {best_s}/24: {r['test']}/{r['alphabet']}/{r['variant']} "
              f"off={r['offset']} IC={r['ic']:.4f}")
        print(f"           PT: {r['pt_sample'][:60]}...")
    print()

if best_overall_score >= 18:
    verdict = f"SIGNAL -- {best_overall_score}/24"
elif best_overall_score > NOISE_FLOOR:
    verdict = f"ABOVE NOISE -- {best_overall_score}/24 (investigate)"
else:
    verdict = f"NOISE -- {best_overall_score}/24"

print(f"  VERDICT: {verdict}")
print()

if best_overall_score <= NOISE_FLOOR:
    print("  CONCLUSION: K1-K3 plaintexts and ciphertexts are NOT the running key")
    print("  source for K4 under any single-layer or double-layer Vigenere/Beaufort")
    print("  with AZ or KA alphabets. This hypothesis is ELIMINATED.")
else:
    print("  CONCLUSION: Some configurations exceeded noise floor. See details above.")

# ── Save artifact ──────────────────────────────────────────────────────────

os.makedirs("/home/cpatrick/kryptos/results", exist_ok=True)
artifact = {
    "experiment": "E-K123-RUNNING-KEY",
    "description": "K1-K3 plaintext/ciphertext as running key for K4",
    "total_configs": total_configs,
    "elapsed_seconds": elapsed,
    "best_overall_score": best_overall_score,
    "best_overall_config": best_overall_config,
    "results_above_threshold": results_log,
    "verdict": verdict,
}
artifact_path = "/home/cpatrick/kryptos/results/e_k123_running_key.json"
with open(artifact_path, "w") as f:
    json.dump(artifact, f, indent=2)
print(f"  Artifact: {artifact_path}")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/grille/e_k123_running_key.py")
