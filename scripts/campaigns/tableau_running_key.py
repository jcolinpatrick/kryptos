#!/usr/bin/env python3
"""
Running key test: use the Kryptos TABLEAU as the key stream.

The physical Kryptos sculpture has the 28x31 Vigenère tableau engraved on it.
Scheidt could use the tableau itself as a running key — a meta-reference:
"decrypt using the same table you see in front of you."

Also tests:
- K4 CT reversed as running key (self-referential cipher)
- K1-K3 CIPHERTEXT as running key (NEVER tested before)
- K1-K3 keywords as running key (PALIMPSEST, ABSCISSA)
- The KRYPTOS sculpture coordinates in various forms
- The Berlin Clock encoding at specific times

For each candidate key text, test at various offsets and all 6 cipher variants.
Report any result with ≥10/24 crib hits.
"""
import sys
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT as CT_STR, CRIB_DICT, KRYPTOS_ALPHABET as KA

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CT = [ord(c)-65 for c in CT_STR]
N = len(CT)
ALL_CRIBS = list(CRIB_DICT.items())

def count_cribs(pt_str):
    return sum(1 for pos, ch in ALL_CRIBS if pos < len(pt_str) and pt_str[pos] == ch)

def apply_beau(key_seq, ct_seq, alpha):
    """Beaufort: PT = key - CT mod 26 (in alpha)"""
    return ''.join(alpha[(alpha.index(key_seq[i]) - alpha.index(ct_seq[i])) % 26]
                   for i in range(len(ct_seq)))

def apply_vig(key_seq, ct_seq, alpha):
    """Vigenère: PT = CT - key mod 26"""
    return ''.join(alpha[(alpha.index(ct_seq[i]) - alpha.index(key_seq[i])) % 26]
                   for i in range(len(ct_seq)))

def apply_vbeau(key_seq, ct_seq, alpha):
    """Variant Beaufort: PT = CT + key mod 26"""
    return ''.join(alpha[(alpha.index(ct_seq[i]) + alpha.index(key_seq[i])) % 26]
                   for i in range(len(ct_seq)))

VARIANTS = [
    ('AZ-Vig',   AZ, apply_vig),
    ('AZ-Beau',  AZ, apply_beau),
    ('AZ-VBeau', AZ, apply_vbeau),
    ('KA-Vig',   KA, apply_vig),
    ('KA-Beau',  KA, apply_beau),
    ('KA-VBeau', KA, apply_vbeau),
]

def test_running_key(key_text, key_name, min_hits=8):
    """Test a running key at all offsets, return best results."""
    best = []
    key_len = len(key_text)
    # Ensure key is all alpha
    key_clean = ''.join(c for c in key_text.upper() if c.isalpha())
    if len(key_clean) < N:
        # Repeat to fill
        key_clean = (key_clean * ((N // len(key_clean)) + 2))[:N+key_len]

    for offset in range(min(key_len, len(key_clean) - N + 1)):
        key_window = key_clean[offset:offset+N]
        if len(key_window) < N:
            continue

        for vname, alpha, apply_fn in VARIANTS:
            # Check key letters are in alphabet
            try:
                pt = apply_fn(key_window, CT_STR, alpha)
                hits = count_cribs(pt)
                if hits >= min_hits:
                    best.append((hits, offset, vname, pt))
            except ValueError:
                continue  # Letter not in alphabet

    return sorted(best, key=lambda x: -x[0])

# ── 1. KRYPTOS TABLEAU as running key ──────────────────────────────────────
print("=" * 65)
print("1. KRYPTOS TABLEAU (28x31) as running key")
print("=" * 65)

# The complete 28x31 Kryptos Vigenère tableau (engraved on the sculpture)
# This is the KA-keyed Vigenère tableau — 28 rows of 31 chars each
# Row i contains the Vigenère alphabet starting at KA[i]
TABLEAU_TEXT = ""
for i in range(28):
    start = i % 26  # wrap around for rows > 26
    row = ''.join(KA[(start + j) % 26] for j in range(31))
    TABLEAU_TEXT += row

print(f"Tableau length: {len(TABLEAU_TEXT)} chars")
print(f"Tableau start: {TABLEAU_TEXT[:60]}...")

results = test_running_key(TABLEAU_TEXT, "KA Tableau", min_hits=8)
if results:
    print(f"\nBest: {results[0][0]}/24 at offset={results[0][1]}, {results[0][2]}")
    for hits, offset, vname, pt in results[:5]:
        print(f"  hits={hits}/24 offset={offset} {vname}: {pt[:50]}")
else:
    print("No results ≥8/24")

# ── 2. K1-K3 CIPHERTEXT as running key ────────────────────────────────────
print("\n\n" + "=" * 65)
print("2. K1-K3 CIPHERTEXT as running key")
print("=" * 65)

# K1 CT (97 chars)
K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFDVFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWH"
# K2 CT (97 chars)
K2_CT = "KKQDQMCPFQZDQMMIAGPFXHQRLGTIMAFKAQJNAYSHMVDLRUHKVKJHNEQLKPJBZIQTBFQCVHBZPMHOQHWAQWTQMEBPCLBLMFPQB"
# K3 CT (336 chars)
K3_CT = "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNETPRNGATIHNRARPESLNNELEBLPIIACAEWMTWND"

K123_CT = K1_CT + K2_CT + K3_CT
print(f"K1+K2+K3 CT length: {len(K123_CT)} chars")

results = test_running_key(K123_CT, "K1-K3 CT", min_hits=8)
if results:
    for hits, offset, vname, pt in results[:5]:
        print(f"  hits={hits}/24 offset={offset} {vname}: {pt[:50]}")
else:
    print("No results ≥8/24")

# ── 3. K1-K3 KEYWORDS as running key ──────────────────────────────────────
print("\n\n" + "=" * 65)
print("3. K1-K3 KEYWORDS (PALIMPSEST, ABSCISSA) as running key")
print("=" * 65)

K13_KEYWORDS = "PALIMPSESTABSCISSAQUARTZ"  # the 3 known keywords
results = test_running_key(K13_KEYWORDS * 5, "K1-K3 keywords", min_hits=6)
if results:
    for hits, offset, vname, pt in results[:5]:
        print(f"  hits={hits}/24 offset={offset} {vname}: {pt[:50]}")
else:
    print("No results ≥6/24")

# ── 4. KRYPTOS as running key (from K2) ──────────────────────────────────
print("\n\n" + "=" * 65)
print("4. Various key sources (KRYPTOS, CT self-referential)")
print("=" * 65)

# K4 CT used as its own running key (autokey from start of CT)
# Different from autokey: use full CT as circular key
results = test_running_key(CT_STR * 2, "K4 CT circular", min_hits=6)
if results:
    for hits, offset, vname, pt in results[:5]:
        print(f"  K4 CT circular: hits={hits}/24 offset={offset} {vname}: {pt[:50]}")
else:
    print("K4 CT circular: No results ≥6/24")

# K2 plaintext as running key (the Sanborn/Scheidt message)
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHS" \
        "MAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDER" \
        "GROUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDX" \
        "ITSBURIED" \
        "OUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLAST" \
        "MESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENNINUTESSIXPOINTFIVESECONDS" \
        "NORTHSEVENTYSEVEN" \
        "DEGREESEIGHTMINUTESFORTYFOURSECONDSWESTXLAYERTWO"
results = test_running_key(K2_PT, "K2 plaintext", min_hits=8)
if results:
    for hits, offset, vname, pt in results[:5]:
        print(f"  K2 PT: hits={hits}/24 offset={offset} {vname}: {pt[:50]}")
else:
    print("K2 PT: No results ≥8/24")

# K3 plaintext as running key
K3_PT = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFDEBRISENCUMBEREDTHELOWERPART" \
        "OFTHEDOORWAYWASREMOVEDWITHTREMBLINGSHANDISMADEATINYBREACHINTHE" \
        "UPPERLEFTHANDCORNERANDTHENWIDENIBGTHEHOLEALITTLEIINSERTEDTHE" \
        "CANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBERCIUSEDTHEFLAME" \
        "TOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHINMERGEDFROMTHEMIST" \
        "XCANYOUSEEANYTHINGQ"
results = test_running_key(K3_PT, "K3 plaintext", min_hits=8)
if results:
    for hits, offset, vname, pt in results[:5]:
        print(f"  K3 PT: hits={hits}/24 offset={offset} {vname}: {pt[:50]}")
else:
    print("K3 PT: No results ≥8/24")

# ── 5. Antipodes text as running key ─────────────────────────────────────
print("\n\n" + "=" * 65)
print("5. ANTIPODES partial text as running key")
print("=" * 65)

# Antipodes is the text on the back of the Kryptos sculpture
# From the reference: 1584 letters. Let me use a known portion.
# K1/K2 appear on the back as the "Antipodes" reading (flipped tableau)
# For K4 area, the Antipodes section would be specific chars
ANTIPODES_START = "KRYPTOSABCDEFGHIJLMNQUVWXZKRYPTOSABCDEFGHIJLMNQUVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ"  # KA repeated (approximate)
results = test_running_key(ANTIPODES_START * 5, "Antipodes KA", min_hits=8)
if results:
    for hits, offset, vname, pt in results[:5]:
        print(f"  Antipodes KA: hits={hits}/24 offset={offset} {vname}: {pt[:50]}")
else:
    print("Antipodes KA: No results ≥8/24")

# ── 6. Beaufort keyword tableau applied to ITSELF ─────────────────────────
print("\n\n" + "=" * 65)
print("6. Key = alphabet extended by the CIPHER ITSELF (meta-key)")
print("=" * 65)

# What if the KEY for K4 is derived from K4 CT by some substitution?
# E.g., apply atbash to CT to get key, then apply Beaufort
CT_atbash = ''.join(AZ[25-AZ.index(c)] for c in CT_STR)
results = test_running_key(CT_atbash, "CT atbash as key", min_hits=6)
if results:
    for hits, offset, vname, pt in results[:5]:
        print(f"  CT atbash: hits={hits}/24 offset={offset} {vname}: {pt[:50]}")
else:
    print("CT atbash: No results ≥6/24")

# ROT13 of CT as key
CT_rot13 = ''.join(AZ[(AZ.index(c)+13)%26] for c in CT_STR)
results = test_running_key(CT_rot13, "CT ROT13 as key", min_hits=6)
if results:
    for hits, offset, vname, pt in results[:5]:
        print(f"  CT ROT13: hits={hits}/24 offset={offset} {vname}: {pt[:50]}")
else:
    print("CT ROT13: No results ≥6/24")

# ── 7. Berlin Clock key hypothesis ────────────────────────────────────────
print("\n\n" + "=" * 65)
print("7. BERLIN CLOCK encoding as cipher key")
print("=" * 65)

# The Berlin Clock has 5 rows: 1 second blinker, 4 five-hour, 4 one-hour, 11 five-min, 4 one-min
# If reading at time 23:59 (maximally lit): all lamps on
# Binary representation: 11110111011 11 (various configurations)
# For K4: what if the key IS derived from a Berlin Clock reading?

# Specific time hypothesis: midnight = 00:00
# At 00:00: all lamps OFF. Binary: 000000000000000000
# As key letters (A=0): AAAAAAAAAAAAAAAAAAA

# More interesting: time when Kryptos was installed (November 3, 1990, 9:00 AM)
# Berlin Clock at 9:00 AM local Berlin time (UTC+1) = 08:00 UTC
# 5-hour row: 1 lit (=5 hours). State: 1000.
# 1-hour row: 3 lit (= 8-5=3). State: 1110.
# 5-min row: 0 lit (= 0). State: 00000000000.
# 1-min row: 0 lit (= 0). State: 0000.
# Binary key at 8:00: 1000 1110 00000000000 0000
# As numbers: 5h=1×5=5, 1h=3×1=3, 5m=0, 1m=0. Time = 8 hours 0 mins.

# Key from binary digits: 1,0,0,0,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 = 23 chars
# Map 1→A, 0→B (or 1→B, 0→A, etc.)
berlin_clock_key = "ABBBAAABABBBAAAAAAAAAAAAA"  # 8:00, 1→A, 0→B

results = test_running_key(berlin_clock_key * 5, "Berlin Clock 8:00", min_hits=6)
if results:
    for hits, offset, vname, pt in results[:5]:
        print(f"  Berlin Clock 8:00: hits={hits}/24 offset={offset} {vname}: {pt[:50]}")
else:
    print("Berlin Clock 8:00: No results ≥6/24")

# The more direct: key = time digits = "0800" repeated...
# 0=A, 8=I, 0=A, 0=A → AIAA repeated
berlin_clock_time = "AIAA" * 25  # "0800" as A=0, I=8
results = test_running_key(berlin_clock_time, "Time 0800", min_hits=6)
if results:
    for hits, offset, vname, pt in results[:5]:
        print(f"  Time 0800: hits={hits}/24 offset={offset} {vname}: {pt[:50]}")
else:
    print("Time 0800: No results ≥6/24")

print("\n\nDone.")
