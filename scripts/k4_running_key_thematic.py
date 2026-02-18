"""
Running key attack using thematic texts related to K4's stated themes:
1986 Egypt, 1989 Berlin Wall, CIA, delivering a message.
Tests all offsets with Vigenere, Beaufort, and Variant Beaufort.
"""
import sys, os, glob
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

CT = 'OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR'
CT_NUM = [ord(c) - ord('A') for c in CT]
N = 97

ENE_POS, ENE_PT = 21, 'EASTNORTHEAST'
BC_POS, BC_PT = 63, 'BERLINCLOCK'

def c2n(c): return ord(c) - ord('A')
def n2c(n): return chr(n % 26 + ord('A'))

# Known key values (Vigenere)
known_vig = {}
for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]:
    for i, ch in enumerate(pt):
        pos = start + i
        known_vig[pos] = (CT_NUM[pos] - c2n(ch)) % 26

# Known key values (Beaufort: key = CT + PT mod 26... no: Beaufort CT = (key - PT) mod 26 → key = (CT + PT) mod 26)
known_beau = {}
for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]:
    for i, ch in enumerate(pt):
        pos = start + i
        known_beau[pos] = (CT_NUM[pos] + c2n(ch)) % 26

print("=" * 70)
print("K4 THEMATIC RUNNING KEY ATTACK")
print("=" * 70)

# Load all text files
text_dir = '/home/cpatrick/kryptos/reference/running_key_texts/'
text_files = glob.glob(os.path.join(text_dir, '*.txt'))

# Also include Carter text and K1-K3 plaintexts
extra_texts = {
    'K1_plaintext': 'BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION',
    'K2_plaintext': 'ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISXTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONXONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTXLAYERTWO',
    'K3_plaintext': 'SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBABORSWEREDISCOVEREDALEADTOTHEDOORWAYWASONLYEXTENDEDLABORUNDERGOROUDLEADTOLAROKINGTUTSEPULCHURALSROOM',
    'K4_ciphertext': CT,  # self-referential
}

# Load Carter text
carter_files = glob.glob('/home/cpatrick/kryptos/reference/carter*.txt')
for cf in carter_files:
    try:
        with open(cf) as f:
            raw = f.read()
        clean = ''.join(c for c in raw.upper() if c.isalpha())
        if len(clean) > 200:
            extra_texts[os.path.basename(cf)] = clean
    except:
        pass

all_texts = {}

# Load from files
for fp in text_files:
    try:
        with open(fp) as f:
            raw = f.read()
        clean = ''.join(c for c in raw.upper() if c.isalpha())
        if len(clean) >= N:
            all_texts[os.path.basename(fp)] = clean
    except:
        pass

# Add extra texts
for name, text in extra_texts.items():
    clean = ''.join(c for c in text.upper() if c.isalpha())
    if len(clean) >= N:
        all_texts[name] = clean

print(f"Loaded {len(all_texts)} texts:")
for name, text in all_texts.items():
    print(f"  {name}: {len(text)} chars")

# Test each text at all offsets
NOISE_THRESHOLD = 6  # from scoring/crib_score.py

print(f"\nRunning key test (threshold: {NOISE_THRESHOLD}/24)...")
print("-" * 70)

best_overall = (0, '', 0, '')

for name, key_text in all_texts.items():
    key_nums = [c2n(c) for c in key_text]
    best_for_text = (0, 0, '')

    for offset in range(len(key_text) - N + 1):
        key_slice = key_nums[offset:offset + N]
        if len(key_slice) < N:
            continue

        # Vigenere: PT = (CT - key) mod 26
        vig_matches = sum(1 for pos, exp_k in known_vig.items()
                          if key_slice[pos] == exp_k)

        # Beaufort: PT = (key - CT) mod 26, key = (CT + PT) mod 26
        beau_matches = sum(1 for pos, exp_k in known_beau.items()
                           if key_slice[pos] == exp_k)

        # Variant Beaufort: PT = (CT + key) mod 26
        # Then at crib: c2n(pt_ch) = (CT[pos] + key[pos]) mod 26
        # So key[pos] = (c2n(pt_ch) - CT[pos]) mod 26 = -(known_vig[pos]) mod 26 = (26 - known_vig[pos]) % 26
        vbeau_matches = sum(1 for pos, exp_k in known_vig.items()
                            if key_slice[pos] == (26 - exp_k) % 26)

        best_match = max(vig_matches, beau_matches, vbeau_matches)
        variant = 'Vig' if best_match == vig_matches else ('Beau' if best_match == beau_matches else 'VBeau')

        if best_match > best_for_text[0]:
            best_for_text = (best_match, offset, variant)

        if best_match >= NOISE_THRESHOLD:
            # Show details
            key_at_ene = key_text[offset+ENE_POS:offset+ENE_POS+len(ENE_PT)]
            key_at_bc = key_text[offset+BC_POS:offset+BC_POS+len(BC_PT)]
            # Also show what the full plaintext would be
            if variant == 'Vig':
                pt_full = ''.join(n2c((CT_NUM[i] - key_slice[i]) % 26) for i in range(N))
            elif variant == 'Beau':
                pt_full = ''.join(n2c((key_slice[i] - CT_NUM[i]) % 26) for i in range(N))
            else:
                pt_full = ''.join(n2c((CT_NUM[i] + key_slice[i]) % 26) for i in range(N))

            print(f"\n  {name} offset={offset} {variant}: {best_match}/24")
            print(f"    Key@ENE: {key_at_ene}")
            print(f"    Key@BC:  {key_at_bc}")
            print(f"    PT: {pt_full}")

    if best_for_text[0] >= 4:
        print(f"  {name}: best={best_for_text[0]}/24 (offset={best_for_text[1]}, {best_for_text[2]})")

    if best_for_text[0] > best_overall[0]:
        best_overall = (best_for_text[0], name, best_for_text[1], best_for_text[2])

print(f"\n{'=' * 70}")
print(f"BEST OVERALL: {best_overall[0]}/24")
print(f"  Text: {best_overall[1]}")
print(f"  Offset: {best_overall[2]}")
print(f"  Variant: {best_overall[3]}")

if best_overall[0] >= NOISE_THRESHOLD:
    print("  STATUS: ABOVE NOISE — INVESTIGATE")
else:
    print("  STATUS: AT NOISE FLOOR — no signal")

# ============================================================
# CROSS-TEXT: try combining two texts as key
# ============================================================
print(f"\n{'=' * 70}")
print("CROSS-TEXT COMBINATION (text_a[:ENE] + text_b[ENE:BC] + text_c[BC:])")
print("=" * 70)

short_texts = {k: v for k, v in all_texts.items() if len(v) < 50000}
best_cross = (0, '', '', '')

for name_a, text_a in short_texts.items():
    for name_b, text_b in short_texts.items():
        if name_a == name_b:
            continue
        # Try text_a for positions 0-33, text_b for 34-96
        for off_a in range(0, min(100, len(text_a) - 34)):
            for off_b in range(0, min(100, len(text_b) - 63)):
                key_slice = ([c2n(text_a[off_a + i]) for i in range(34)] +
                             [c2n(text_b[off_b + i]) for i in range(63)])
                if len(key_slice) < N:
                    continue

                vig_matches = sum(1 for pos, exp_k in known_vig.items()
                                  if pos < len(key_slice) and key_slice[pos] == exp_k)

                if vig_matches > best_cross[0]:
                    best_cross = (vig_matches, name_a, name_b, f"off_a={off_a},off_b={off_b}")

                if vig_matches >= NOISE_THRESHOLD:
                    print(f"  {name_a}(off={off_a}) + {name_b}(off={off_b}): {vig_matches}/24 Vig")

print(f"\nBest cross-text: {best_cross[0]}/24 ({best_cross[1]} + {best_cross[2]}, {best_cross[3]})")

print(f"\n{'=' * 70}")
print("RUNNING KEY ATTACK COMPLETE")
print("=" * 70)
