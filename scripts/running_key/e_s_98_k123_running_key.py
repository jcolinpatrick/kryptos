#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: running_key
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-98: K1-K3 Plaintext/Ciphertext as Running Key + Width-7 Columnar

Tests K1-K3 solutions as running key combined with width-7 columnar
transposition. Prior tests used direct correspondence (no transposition).
This tests Model B: transpose CT → intermediate I, then running key decrypt.

Also tests:
  - K3 plaintext (Carter quote about Tutankhamun's tomb)
  - K2 plaintext (coordinates, buried, Layer Two)
  - K1 plaintext (between subtle shading...)
  - K1-K3 ciphertext
  - Morse code translations
  - Concatenated K1+K2+K3 plaintext
  - K2 plaintext with coordinates expanded
"""

import json, os, time
from itertools import permutations

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
I2N = {c: i for i, c in enumerate(AZ)}
CT_N = [I2N[c] for c in CT]

CRIBS = {
    21:'E',22:'A',23:'S',24:'T',25:'N',26:'O',27:'R',28:'T',29:'H',30:'E',31:'A',32:'S',33:'T',
    63:'B',64:'E',65:'R',66:'L',67:'I',68:'N',69:'C',70:'L',71:'O',72:'C',73:'K'}
PT_FULL = {p: I2N[c] for p, c in CRIBS.items()}
CPOS = sorted(CRIBS.keys())

W = 7
VNAMES = ['Vig', 'Beau', 'VBeau']


def build_perm(order):
    nr = (N + W - 1) // W
    ns = nr * W - N
    p = []
    for k in range(W):
        c = order[k]
        sz = nr - 1 if c >= W - ns else nr
        for r in range(sz):
            p.append(r * W + c)
    return p


ORDERS = [list(o) for o in permutations(range(W))]
PERMS = [build_perm(o) for o in ORDERS]
INTERMEDIATES = [[CT_N[PERMS[oi][j]] for j in range(N)] for oi in range(len(ORDERS))]


def check_cribs(pt):
    return sum(1 for p in CPOS if pt[p] == PT_FULL[p])


def clean_text(text):
    """Clean text to uppercase letters only."""
    return ''.join(c for c in text.upper() if c in AZ)


# ── Define running key texts ─────────────────────────────────────────

# K3 plaintext (Howard Carter quote)
K3_PT = clean_text("""
SLOWLY DESPERATELY SLOWLY THE REMAINS OF PASSAGE DEBRIS THAT ENCUMBERED
THE LOWER PART OF THE DOORWAY WAS REMOVED WITH TREMBLING HANDS I MADE A TINY
BREACH IN THE UPPER LEFT HAND CORNER AND THEN WIDENING THE HOLE A LITTLE
I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING FROM THE CHAMBER
CAUSED THE FLAME TO FLICKER BUT PRESENTLY DETAILS OF THE ROOM WITHIN
EMERGED FROM THE MIST X CAN YOU SEE ANYTHING Q
""")

# Note: K3 has intentional misspellings. Try both versions.
K3_PT_MISSPELLED = clean_text("""
SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBERED
THELOWERPARTOFTHEDOORWAYWASEREMOVEDWITHTREMBLINGSHANDSI
MADEATINYBREACHINTHUPPERLEFTHANDCORNERANDTHENWIDENIENGTHE
HOLEALITTLEIINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRESCAPING
FROMTHECHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILS
OFTHEROOMWITHINMERGEDFROMTHEMISTXCANYOUSEEANYETHINGQ
""")

# K2 plaintext
K2_PT = clean_text("""
IT WAS TOTALLY INVISIBLE HOWS THAT POSSIBLE THEY USED THE EARTHS MAGNETIC FIELD
X THE INFORMATION WAS GATHERED AND TRANSMITTED UNDERGRUUND TO AN UNKNOWN LOCATION
X DOES LANGLEY KNOW ABOUT THIS THEY SHOULD ITS BURIED OUT THERE SOMEWHERE
X WHO KNOWS THE EXACT LOCATION ONLY WW THIS WAS HIS LAST MESSAGE
X THIRTY EIGHT DEGREES FIFTY SEVEN MINUTES SIX POINT FIVE SECONDS NORTH
SEVENTY SEVEN DEGREES EIGHT MINUTES FORTY FOUR SECONDS WEST
X LAYER TWO
""")

# K1 plaintext
K1_PT = clean_text("""
BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT LIES THE NUANCE OF IQLUSION
""")

# Morse code (K0)
MORSE_PT = clean_text("""
BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT
LYING VIRTUALLY INVISIBLE IT IS ALMOST SUPERNATURAL
T IS YOUR POSITION
SHADOW FORCES
DIGETAL INTERPRETATION
LUCID MEMORY
""")

# K1 ciphertext
K1_CT = clean_text("EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD")

# K2 ciphertext (approximate)
K2_CT = clean_text("""
VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKK
DQMCPFQZDQMMIAGPFXHQRLGTIMVMZJANQLVKQE
DAGAR QMCQAQVJQCDZAOHQCQAAGJQKMMFDAZQFHQQ
KDQMQPQABQKNQIDNQERTEAEZQVPQNNTQQMJQQ
SQJQWNSQVQIQQVJQCKAQKQMMFDAZQFHQQ
""")

# K3 ciphertext (approximate)
K3_CT_text = clean_text("""
ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLLSLKNQIORAATOYETW
QRXTQRSKSPTQUMWKFLRUQISASXDGMMJKJDMQICQTGLKZUGYSYQXQKOFYPJ
XZHQKTAYGCUEOGXIXEFGIUZEJTQHNZ
""")

# Concatenated K1+K2+K3 plaintext
K123_PT = K1_PT + K2_PT + K3_PT

# Additional text: repeat of K4's known plaintext (self-reference)
K4_KNOWN = clean_text("EASTNORTHEAST" + "X" * 29 + "BERLINCLOCK")

TEXTS = {
    'K3_PT': K3_PT,
    'K3_PT_misspelled': K3_PT_MISSPELLED,
    'K2_PT': K2_PT,
    'K1_PT': K1_PT,
    'Morse': MORSE_PT,
    'K1_CT': K1_CT,
    'K2_CT': K2_CT,
    'K3_CT': K3_CT_text,
    'K123_PT': K123_PT,
}

print("=" * 70)
print("E-S-98: K1-K3 Plaintext/Ciphertext as Running Key + Width-7 Columnar")
print(f"  N={N}, W={W}, orderings={len(ORDERS)}")
print("=" * 70)

for name, text in TEXTS.items():
    print(f"  {name}: {len(text)} chars")

t0 = time.time()
results = {}

for text_name, text in TEXTS.items():
    text_nums = [I2N[c] for c in text]
    text_len = len(text_nums)
    max_offset = max(0, text_len - N)

    if max_offset == 0 and text_len < N:
        # Text too short — pad with repeats
        while len(text_nums) < N * 2:
            text_nums = text_nums + text_nums
        max_offset = len(text_nums) - N

    best_score = 0
    best_cfg = None
    tested = 0

    for oi in range(len(ORDERS)):
        intermed = INTERMEDIATES[oi]

        for offset in range(max_offset + 1):
            key = text_nums[offset:offset + N]
            if len(key) < N:
                continue

            for vi in range(3):
                # Decrypt
                pt = [0] * N
                for j in range(N):
                    if vi == 0:  # Vig
                        pt[j] = (intermed[j] - key[j]) % 26
                    elif vi == 1:  # Beau
                        pt[j] = (key[j] - intermed[j]) % 26
                    else:  # VBeau
                        pt[j] = (intermed[j] + key[j]) % 26

                score = check_cribs(pt)
                tested += 1

                if score > best_score:
                    best_score = score
                    best_cfg = (ORDERS[oi], VNAMES[vi], offset)

                if score >= 18:
                    pt_text = ''.join(AZ[x] for x in pt)
                    print(f"  *** HIT {text_name}: {score}/24 order={ORDERS[oi]} "
                          f"{VNAMES[vi]} offset={offset}")
                    print(f"      PT: {pt_text}")
                    print(f"      Key: {text[offset:offset+40]}...")

                if score >= 24:
                    pt_text = ''.join(AZ[x] for x in pt)
                    print(f"\n  !!!!! BREAKTHROUGH with {text_name} !!!!!")
                    print(f"  PT: {pt_text}")

    elapsed = time.time() - t0
    print(f"  {text_name}: best={best_score}/24, {tested:,} tested, {elapsed:.0f}s, cfg={best_cfg}")
    results[text_name] = {'best': best_score, 'cfg': str(best_cfg)}


# ── Also test without transposition (direct running key) for completeness ──
print("\n--- Direct running key (no transposition) ---")

for text_name, text in TEXTS.items():
    text_nums = [I2N[c] for c in text]
    text_len = len(text_nums)
    max_offset = max(0, text_len - N)

    if max_offset == 0 and text_len < N:
        while len(text_nums) < N * 2:
            text_nums = text_nums + text_nums
        max_offset = len(text_nums) - N

    best_score = 0

    for offset in range(max_offset + 1):
        key = text_nums[offset:offset + N]
        if len(key) < N:
            continue

        for vi in range(3):
            pt = [0] * N
            for j in range(N):
                if vi == 0:
                    pt[j] = (CT_N[j] - key[j]) % 26
                elif vi == 1:
                    pt[j] = (key[j] - CT_N[j]) % 26
                else:
                    pt[j] = (CT_N[j] + key[j]) % 26

            score = check_cribs(pt)
            if score > best_score:
                best_score = score

            if score >= 12:
                pt_text = ''.join(AZ[x] for x in pt)
                print(f"  DIRECT {text_name}: {score}/24 {VNAMES[vi]} offset={offset}")
                if score >= 18:
                    print(f"    PT: {pt_text}")

    print(f"  {text_name} (direct): best={best_score}/24")


# ── Summary ───────────────────────────────────────────────────────────
total_elapsed = time.time() - t0

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
for name, data in sorted(results.items()):
    print(f"  {name}: {data['best']}/24")
print(f"  Total: {total_elapsed:.1f}s")

best = max(v['best'] for v in results.values())
if best >= 18:
    print(f"\n  Verdict: SIGNAL — {best}/24")
else:
    print(f"\n  Verdict: NOISE — {best}/24")

os.makedirs("results", exist_ok=True)
out = {
    'experiment': 'E-S-98',
    'description': 'K1-K3 running key + width-7 columnar',
    'results': results,
    'elapsed_seconds': total_elapsed,
}
with open("results/e_s_98_k123_running_key.json", "w") as f:
    json.dump(out, f, indent=2, default=str)
print(f"\n  Artifact: results/e_s_98_k123_running_key.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_98_k123_running_key.py")
