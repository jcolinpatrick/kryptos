#!/usr/bin/env python3
"""
Cipher: running key
Family: running_key
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-RUNKEY-002: Running key from K1/K2/K3 plaintexts.

Tests whether K4's key is a substring of the concatenated K1+K2+K3
plaintexts (or transforms thereof) under Vigenère, Beaufort, and
Variant Beaufort, with both standard (AZ) and Kryptos-keyed (KA) alphabets.

Expected: FAIL (known keystream at crib positions is not English).
Purpose: Formal closure on a natural hypothesis.

Usage: PYTHONPATH=src python3 -u scripts/e_runkey_002_k123_plaintext.py
"""
import time

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, N_CRIBS, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

# ── K1/K2/K3 Plaintexts (spaces and punctuation stripped) ──────────

K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHEN UANCEOFIQLUSION"
K2_PT = ("ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSED"
         "THEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHERED"
         "ANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONX"
         "DOESLANGLEYKNOWABOUTTHIS THEYSHOULDITS BURIEDOUT"
         "THERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWW"
         "THISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTY"
         "SEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVEN"
         "DEGREESEIGHTMINUTESFORTYFOURSECONDSWES TIDBYROWS")
K3_PT = ("SLOWLYDESPARATLYSLOW LYTHEREMAINS OFPASSAGEDEBRIS"
         "THATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVED"
         "WITHTREMB LINGHANDSIMADETINYBREACHINTHEUPPERLEFT"
         "HANDCORNERANDTHENW IDENINGTHEHOLEALITTLEIINSERTED"
         "THECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHE"
         "CHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILS"
         "OFTHEROOMWITHIN EMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ")

# Clean: uppercase, letters only
def clean(s):
    return ''.join(c for c in s.upper() if c in ALPH)

K1 = clean(K1_PT)
K2 = clean(K2_PT)
K3 = clean(K3_PT)

# Build all source texts to test
SOURCES = {
    "K1+K2+K3": K1 + K2 + K3,
    "K3+K2+K1": K3 + K2 + K1,
    "K1": K1,
    "K2": K2,
    "K3": K3,
    "K1_rev": K1[::-1],
    "K2_rev": K2[::-1],
    "K3_rev": K3[::-1],
    "K1+K2+K3_rev": (K1 + K2 + K3)[::-1],
    "K2+K3": K2 + K3,
    "K3+K1": K3 + K1,
    "K1+K3": K1 + K3,
}

print("=" * 70)
print("E-RUNKEY-002: Running Key from K1/K2/K3 Plaintexts")
print("=" * 70)
for name, src in SOURCES.items():
    print(f"  {name}: {len(src)} chars")
print(f"  CT: {CT_LEN} chars, Cribs: {N_CRIBS}")
print()

# ── Cipher variants ────────────────────────────────────────────────

def make_alph_idx(alphabet):
    return {c: i for i, c in enumerate(alphabet)}

def vig_decrypt(ct_num, key_num, alph_size=26):
    """PT = (CT - KEY) mod 26"""
    return [(c - k) % alph_size for c, k in zip(ct_num, key_num)]

def beau_decrypt(ct_num, key_num, alph_size=26):
    """PT = (KEY - CT) mod 26"""
    return [(k - c) % alph_size for c, k in zip(ct_num, key_num)]

def vbeau_decrypt(ct_num, key_num, alph_size=26):
    """PT = (CT + KEY) mod 26"""
    return [(c + k) % alph_size for c, k in zip(ct_num, key_num)]

VARIANTS = {
    "Vigenere": vig_decrypt,
    "Beaufort": beau_decrypt,
    "VariantBeaufort": vbeau_decrypt,
}

ALPHABETS = {
    "AZ": (ALPH, ALPH_IDX),
    "KA": (KRYPTOS_ALPHABET, make_alph_idx(KRYPTOS_ALPHABET)),
}

# ── Scoring ────────────────────────────────────────────────────────

def score_cribs(pt_num, alph_idx_map):
    """Count how many crib positions match."""
    matches = 0
    for pos, ch in CRIB_DICT.items():
        expected = alph_idx_map[ch]
        if pos < len(pt_num) and pt_num[pos] == expected:
            matches += 1
    return matches

# ── Main sweep ─────────────────────────────────────────────────────

t0 = time.time()
best_overall = 0
best_config = None
total_tests = 0

for alph_name, (alphabet, aidx) in ALPHABETS.items():
    ct_in_alph = [aidx[c] for c in CT]

    for src_name, src_text in SOURCES.items():
        # Convert source to numeric in this alphabet
        try:
            src_num = [aidx[c] for c in src_text]
        except KeyError:
            continue  # skip if chars not in alphabet

        max_offset = len(src_num) - CT_LEN
        if max_offset < 0:
            continue

        for variant_name, decrypt_fn in VARIANTS.items():
            best_for_combo = 0

            for offset in range(max_offset + 1):
                key_num = src_num[offset:offset + CT_LEN]
                pt_num = decrypt_fn(ct_in_alph, key_num)
                score = score_cribs(pt_num, aidx)
                total_tests += 1

                if score > best_for_combo:
                    best_for_combo = score

                if score > best_overall:
                    best_overall = score
                    best_config = (alph_name, src_name, variant_name, offset, score)

                if score >= 14:
                    # Above noise — report immediately
                    pt_letters = ''.join(alphabet[x] for x in pt_num)
                    print(f"  ** SIGNAL: {alph_name}/{src_name}/{variant_name} "
                          f"offset={offset} score={score}/24")
                    print(f"     PT: {pt_letters[:40]}...")

            if best_for_combo >= 4:
                print(f"  {alph_name}/{src_name}/{variant_name}: best={best_for_combo}/24")

elapsed = time.time() - t0

# ── Summary ────────────────────────────────────────────────────────

print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Total configurations tested: {total_tests:,}")
print(f"  Elapsed: {elapsed:.3f}s")
print(f"  Best score: {best_overall}/24")
if best_config:
    alph_name, src_name, variant_name, offset, score = best_config
    print(f"  Best config: {alph_name}/{src_name}/{variant_name} offset={offset}")

if best_overall >= 20:
    print("\n  *** SIGNAL DETECTED — investigate immediately ***")
elif best_overall <= 6:
    print("\n  RESULT: NOISE. K1/K2/K3 plaintexts are NOT the running key source.")
    print("  K1-K3 running key under direct correspondence: ELIMINATED.")
else:
    print(f"\n  RESULT: Best {best_overall}/24 — above noise but below signal threshold.")
    print("  May warrant further investigation with transposition layer.")

print(f"\n  Repro: PYTHONPATH=src python3 -u scripts/e_runkey_002_k123_plaintext.py")
