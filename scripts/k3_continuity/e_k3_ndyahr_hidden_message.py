#!/usr/bin/env python3
"""
Cipher: K3-hidden-message
Family: k3_continuity
Status: active
Keyspace: ~50K configs across 6 phases
Last run: 2026-03-15
Best score: TBD
"""
"""E-K3-NDYAHR-HIDDEN-MESSAGE: Test whether K3 CT contains a second hidden message.

Hypothesis: The NDYAHR displaced letters at the K3/K4 boundary are EDITING INSTRUCTIONS
telling you to modify the K3 ciphertext to produce a different cipher that decrypts to
a different plaintext — one that helps solve K4.

Key facts:
- K3 CT = 336 letters (pure transposition, keyword KRYPTOS, double columnar)
- NDYAHR = 6 physically displaced letters at K3/K4 boundary
- Sanborn: "I have left instructions in the earlier text that refer to later text"
- K1 misspelling (IQLUSION) and K3 misspelling (DESPARATLY) are deliberate

Phases:
  1. Count/analyze NDYAHR letters in K3 CT
  2. Remove NDYAHR letters and try decryption with various keywords
  3. Shift interpretation (displace positions according to NDYAHR directions)
  4. Check if removal produces K4-relevant lengths (e.g. 73)
  5. Include corrected C (XLAYERTWO → CLAYERTWO)
  6. Statistical analysis (are NDYAHR frequencies anomalous?)

Run: PYTHONPATH=src python3 -u scripts/k3_continuity/e_k3_ndyahr_hidden_message.py
"""

import sys
import os
import json
import math
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET
from kryptos.kernel.scoring.ngram import NgramScorer

# Load quadgram scorer
QG_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json')
scorer = NgramScorer.from_file(QG_PATH, n=4)

# ── K3 Ciphertext (verified against Kryptos sculpture and Antipodes) ──
K3_CT = (
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

K4_CT = CT  # from constants

# K3 Plaintext (community consensus, verified)
K3_PT_WORDS = (
    "SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS "
    "THAT ENCUMBERED THE LOWER PART OF THE DOORWAY WAS REMOVED "
    "WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER "
    "LEFT HAND CORNER AND THEN WIDENING THE HOLE A LITTLE "
    "I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING "
    "FROM THE CHAMBER CAUSED THE FLAME TO FLICKER BUT PRESENTLY "
    "DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST "
    "X CAN YOU SEE ANYTHING Q"
)
K3_PT = ''.join(c for c in K3_PT_WORDS.upper() if c.isalpha())

# NDYAHR letters
NDYAHR = set('NDYAHR')
NDYAHR_STR = 'NDYAHR'

# Displacement directions
DISPLACEMENTS = {
    'N': 'LEFT',    # West
    'D': 'RIGHT',   # East
    'Y': 'UP',      # North
    'A': 'UP',      # North
    'H': 'RIGHT',   # East
    'R': 'UP-LEFT', # Northwest
}

# Keywords to test
KEYWORDS = [
    'KRYPTOS', 'DEFECTOR', 'PALIMPSEST', 'ABSCISSA', 'KOMPASS',
    'COLOPHON', 'PARALLAX', 'SHADOW', 'MEDUSA', 'ENIGMA',
    'SANBORN', 'BERLINCLOCK', 'EASTNORTHEAST',
]

results = {
    'timestamp': datetime.now(timezone.utc).isoformat(),
    'script': 'e_k3_ndyahr_hidden_message.py',
    'hypothesis': 'K3 CT contains a second hidden message via NDYAHR letter removal/modification',
    'phases': {}
}

def vig_decrypt(ct, key, alphabet=ALPH):
    """Vigenere decryption: PT[i] = (CT[i] - KEY[i%len(key)]) mod 26"""
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    pt = []
    for i, c in enumerate(ct):
        ki = alph_idx.get(key[i % len(key)], 0)
        ci = alph_idx.get(c, 0)
        pi = (ci - ki) % 26
        pt.append(alphabet[pi])
    return ''.join(pt)

def beau_decrypt(ct, key, alphabet=ALPH):
    """Beaufort decryption: PT[i] = (KEY[i%len(key)] - CT[i]) mod 26"""
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    pt = []
    for i, c in enumerate(ct):
        ki = alph_idx.get(key[i % len(key)], 0)
        ci = alph_idx.get(c, 0)
        pi = (ki - ci) % 26
        pt.append(alphabet[pi])
    return ''.join(pt)

def vbeau_decrypt(ct, key, alphabet=ALPH):
    """Variant Beaufort decryption: PT[i] = (CT[i] + KEY[i%len(key)]) mod 26"""
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    pt = []
    for i, c in enumerate(ct):
        ki = alph_idx.get(key[i % len(key)], 0)
        ci = alph_idx.get(c, 0)
        pi = (ci + ki) % 26
        pt.append(alphabet[pi])
    return ''.join(pt)

def autokey_pt_decrypt(ct, primer, alphabet=ALPH):
    """PT-autokey Vigenere: key = primer + PT so far"""
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    pt = []
    key_stream = list(primer)
    for i, c in enumerate(ct):
        ki = alph_idx.get(key_stream[i], 0)
        ci = alph_idx.get(c, 0)
        pi = (ci - ki) % 26
        p = alphabet[pi]
        pt.append(p)
        key_stream.append(p)
    return ''.join(pt)

def autokey_ct_decrypt(ct, primer, alphabet=ALPH):
    """CT-autokey Vigenere: key = primer then CT"""
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    pt = []
    key_stream = list(primer) + list(ct)
    for i, c in enumerate(ct):
        ki = alph_idx.get(key_stream[i], 0)
        ci = alph_idx.get(c, 0)
        pi = (ci - ki) % 26
        pt.append(alphabet[pi])
    return ''.join(pt)

def ic(text):
    """Index of coincidence"""
    n = len(text)
    if n < 2:
        return 0.0
    freq = Counter(text)
    return sum(f * (f-1) for f in freq.values()) / (n * (n-1))

def find_english_fragments(text, min_len=4):
    """Look for common English words in text"""
    common = ['THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU', 'ALL',
              'CAN', 'HER', 'WAS', 'ONE', 'OUR', 'OUT', 'THAT', 'HAVE',
              'BEEN', 'THEY', 'THIS', 'WILL', 'EACH', 'MAKE', 'FROM',
              'THEM', 'THEN', 'WITH', 'WHICH', 'THEIR', 'THERE', 'THESE',
              'WOULD', 'COULD', 'SHOULD', 'ABOUT', 'CLOCK', 'BERLIN',
              'EAST', 'NORTH', 'LAYER', 'TWO', 'ROOM', 'DOOR', 'WALL',
              'LIGHT', 'TUNNEL', 'SECRET', 'HIDDEN', 'BENEATH',
              'SLOWLY', 'PASSAGE', 'CHAMBER', 'CANDLE', 'FLAME',
              'KRYPTOS', 'SHADOW', 'COMPASS', 'POINT']
    found = []
    text_upper = text.upper()
    for word in common:
        if len(word) >= min_len:
            idx = text_upper.find(word)
            if idx >= 0:
                found.append((word, idx))
    return found

print("=" * 80)
print("K3 NDYAHR HIDDEN MESSAGE INVESTIGATION")
print("=" * 80)
print(f"K3 CT length: {len(K3_CT)}")
print(f"K3 PT length: {len(K3_PT)}")
print(f"K4 CT length: {len(K4_CT)}")
print()

# ══════════════════════════════════════════════════════════════════════════
# PHASE 1: Basic analysis of NDYAHR in K3 CT
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 1: NDYAHR Letter Analysis in K3 CT")
print("=" * 80)

phase1 = {}

# Count each NDYAHR letter
ndyahr_counts = {}
ndyahr_positions = {}
for letter in NDYAHR_STR:
    positions = [i for i, c in enumerate(K3_CT) if c == letter]
    ndyahr_counts[letter] = len(positions)
    ndyahr_positions[letter] = positions
    print(f"  {letter}: {len(positions)} occurrences at positions {positions[:20]}{'...' if len(positions)>20 else ''}")

total_ndyahr = sum(ndyahr_counts.values())
pct_ndyahr = total_ndyahr / len(K3_CT) * 100
print(f"\nTotal NDYAHR letters in K3 CT: {total_ndyahr}/{len(K3_CT)} = {pct_ndyahr:.1f}%")

# Remove all NDYAHR letters
k3_no_ndyahr = ''.join(c for c in K3_CT if c not in NDYAHR)
print(f"After removing NDYAHR: {len(k3_no_ndyahr)} characters remain")
print(f"  Removed: {len(K3_CT) - len(k3_no_ndyahr)} characters")
print(f"  Remaining text: {k3_no_ndyahr[:80]}...")
print(f"  ...{k3_no_ndyahr[-40:]}")

# Check remaining letter distribution
remaining_freq = Counter(k3_no_ndyahr)
print(f"\n  Remaining letters ({len(remaining_freq)} distinct): {dict(sorted(remaining_freq.items()))}")
remaining_ic = ic(k3_no_ndyahr)
print(f"  IC of remaining: {remaining_ic:.6f} (English ~0.067, random ~0.038)")

phase1 = {
    'ndyahr_counts': ndyahr_counts,
    'total_ndyahr': total_ndyahr,
    'pct_ndyahr': pct_ndyahr,
    'remaining_length': len(k3_no_ndyahr),
    'remaining_ic': remaining_ic,
    'remaining_text': k3_no_ndyahr,
}
results['phases']['phase1'] = phase1

# Also do NDYAHR analysis on K3 PT for comparison
total_ndyahr_pt = sum(1 for c in K3_PT if c in NDYAHR)
pct_ndyahr_pt = total_ndyahr_pt / len(K3_PT) * 100
print(f"\nFor comparison - NDYAHR in K3 PT: {total_ndyahr_pt}/{len(K3_PT)} = {pct_ndyahr_pt:.1f}%")

# Also check K4 CT
total_ndyahr_k4 = sum(1 for c in K4_CT if c in NDYAHR)
pct_ndyahr_k4 = total_ndyahr_k4 / len(K4_CT) * 100
print(f"NDYAHR in K4 CT: {total_ndyahr_k4}/{len(K4_CT)} = {pct_ndyahr_k4:.1f}%")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 2: Remove NDYAHR letters and try decryption
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 2: Decrypt K3_CT minus NDYAHR with various keywords")
print("=" * 80)

phase2_results = []

# Texts to try: the reduced K3 CT
texts_to_try = [
    ('k3_no_ndyahr', k3_no_ndyahr),
]

# Also try keeping positions and replacing with X
k3_x_replace = ''.join('X' if c in NDYAHR else c for c in K3_CT)
texts_to_try.append(('k3_x_replace', k3_x_replace))

for text_name, text in texts_to_try:
    print(f"\n--- Testing: {text_name} (length {len(text)}) ---")

    best_for_text = {'score': -999, 'pt': '', 'method': ''}

    for kw in KEYWORDS:
        for alph_name, alph in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
            for cipher_name, cipher_fn in [('vig', vig_decrypt), ('beau', beau_decrypt), ('vbeau', vbeau_decrypt)]:
                pt = cipher_fn(text, kw, alph)
                qg = scorer.score_per_char(pt)
                pt_ic = ic(pt)
                frags = find_english_fragments(pt)

                entry = {
                    'text': text_name,
                    'keyword': kw,
                    'alphabet': alph_name,
                    'cipher': cipher_name,
                    'qg_per_char': round(qg, 4),
                    'ic': round(pt_ic, 6),
                    'plaintext_preview': pt[:60],
                    'english_fragments': frags,
                }
                phase2_results.append(entry)

                if qg > best_for_text['score']:
                    best_for_text = {'score': qg, 'pt': pt[:80], 'method': f'{kw}:{alph_name}_{cipher_name}'}

                # Only print interesting ones
                if qg > -6.0 or frags:
                    print(f"  {kw}:{alph_name}_{cipher_name}: qg={qg:.3f}, ic={pt_ic:.4f}, frags={frags}")
                    if qg > -5.5:
                        print(f"    PT: {pt[:80]}")

    # Also try autokey
    for kw in KEYWORDS[:8]:  # Top keywords only
        for alph_name, alph in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
            for ak_name, ak_fn in [('ptautokey', autokey_pt_decrypt), ('ctautokey', autokey_ct_decrypt)]:
                pt = ak_fn(text, kw, alph)
                qg = scorer.score_per_char(pt)
                frags = find_english_fragments(pt)

                entry = {
                    'text': text_name,
                    'keyword': kw,
                    'alphabet': alph_name,
                    'cipher': ak_name,
                    'qg_per_char': round(qg, 4),
                    'ic': round(ic(pt), 6),
                    'plaintext_preview': pt[:60],
                    'english_fragments': frags,
                }
                phase2_results.append(entry)

                if qg > best_for_text['score']:
                    best_for_text = {'score': qg, 'pt': pt[:80], 'method': f'{kw}:{alph_name}_{ak_name}'}

                if qg > -6.0 or frags:
                    print(f"  {kw}:{alph_name}_{ak_name}: qg={qg:.3f}, frags={frags}")
                    if qg > -5.5:
                        print(f"    PT: {pt[:80]}")

    print(f"\n  BEST for {text_name}: {best_for_text['method']} = {best_for_text['score']:.3f}")
    print(f"    PT: {best_for_text['pt']}")

# Sort results by score
phase2_results.sort(key=lambda x: x['qg_per_char'], reverse=True)
results['phases']['phase2'] = {
    'top_10': phase2_results[:10],
    'total_configs': len(phase2_results),
}

print(f"\nPhase 2 top 10:")
for r in phase2_results[:10]:
    print(f"  {r['text']}:{r['keyword']}:{r['alphabet']}_{r['cipher']}: qg={r['qg_per_char']:.3f}, ic={r['ic']:.4f}")
    if r['english_fragments']:
        print(f"    Fragments: {r['english_fragments']}")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 3: Shift interpretation on 28x31 grid
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 3: Grid-based displacement interpretation")
print("=" * 80)

# K3 occupies rows 15-24 on the 28x31 grid (approx)
# Let's work with just K3 on various grid widths
GRID_WIDTH = 31  # The master grid width

phase3_results = []

# Direction vectors (col_delta, row_delta)
DIR_VECTORS = {
    'LEFT': (-1, 0),
    'RIGHT': (1, 0),
    'UP': (0, -1),
    'UP-LEFT': (-1, -1),
    'DOWN': (0, 1),
    'DOWN-LEFT': (-1, 1),
    'DOWN-RIGHT': (1, 1),
    'UP-RIGHT': (1, -1),
}

# For each NDYAHR letter occurrence in K3 CT, shift its position
for width in [7, 31, 14, 24, 8]:
    height = (len(K3_CT) + width - 1) // width

    # Build grid
    grid = {}
    for i, c in enumerate(K3_CT):
        row = i // width
        col = i % width
        grid[(row, col)] = c

    # Apply shifts: for each NDYAHR letter, move it according to its direction
    shifted_text_list = list(K3_CT)
    shift_count = 0

    for i, c in enumerate(K3_CT):
        if c in DISPLACEMENTS:
            direction = DISPLACEMENTS[c]
            dc, dr = DIR_VECTORS[direction]
            row = i // width
            col = i % width
            new_row = row + dr
            new_col = col + dc
            new_pos = new_row * width + new_col

            if 0 <= new_row < height and 0 <= new_col < width and 0 <= new_pos < len(K3_CT):
                # Swap the letter with the one at the new position
                shifted_text_list[i], shifted_text_list[new_pos] = shifted_text_list[new_pos], shifted_text_list[i]
                shift_count += 1

    shifted_text = ''.join(shifted_text_list)

    # Try decrypting the shifted version
    for kw in ['KRYPTOS', 'DEFECTOR', 'PALIMPSEST', 'ABSCISSA']:
        for alph_name, alph in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
            for cipher_name, cipher_fn in [('vig', vig_decrypt), ('beau', beau_decrypt)]:
                pt = cipher_fn(shifted_text, kw, alph)
                qg = scorer.score_per_char(pt)
                frags = find_english_fragments(pt)

                entry = {
                    'grid_width': width,
                    'shifts_applied': shift_count,
                    'keyword': kw,
                    'alphabet': alph_name,
                    'cipher': cipher_name,
                    'qg_per_char': round(qg, 4),
                    'english_fragments': frags,
                    'pt_preview': pt[:60],
                }
                phase3_results.append(entry)

                if qg > -6.0 or frags:
                    print(f"  w{width} shift({shift_count}) {kw}:{alph_name}_{cipher_name}: qg={qg:.3f} frags={frags}")
                    if qg > -5.5:
                        print(f"    PT: {pt[:80]}")

phase3_results.sort(key=lambda x: x['qg_per_char'], reverse=True)
results['phases']['phase3'] = {
    'top_5': phase3_results[:5],
    'total_configs': len(phase3_results),
}
print(f"\nPhase 3 top 5:")
for r in phase3_results[:5]:
    print(f"  w{r['grid_width']} {r['keyword']}:{r['alphabet']}_{r['cipher']}: qg={r['qg_per_char']:.3f}")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 4: Check for K4-relevant lengths and use as key/running-key
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 4: K4-relevant analysis of reduced K3 CT")
print("=" * 80)

phase4 = {}

# Key length check
print(f"K3 CT minus NDYAHR = {len(k3_no_ndyahr)} chars")
print(f"  Is it 73? {'YES!' if len(k3_no_ndyahr) == 73 else 'No (' + str(len(k3_no_ndyahr)) + ')'}")
print(f"  Is it 97? {'YES!' if len(k3_no_ndyahr) == 97 else 'No (' + str(len(k3_no_ndyahr)) + ')'}")
print(f"  Is it 24? {'YES!' if len(k3_no_ndyahr) == 24 else 'No (' + str(len(k3_no_ndyahr)) + ')'}")

# How many of each NDYAHR letter?
for letter in NDYAHR_STR:
    ct = K3_CT.count(letter)
    print(f"  {letter}: appears {ct} times in K3 CT")

# What if we remove only SOME NDYAHR letters?
# E.g., remove only the first occurrence of each, or remove based on positions
print(f"\nTotal NDYAHR removals needed for length 73: {len(K3_CT) - 73} = {len(K3_CT) - 73}")
print(f"Total NDYAHR removals needed for length 97: {len(K3_CT) - 97} = {len(K3_CT) - 97}")

# Use reduced K3 CT as running key against K4
print(f"\n--- Using reduced K3 CT as running key against K4 ---")
phase4_rk_results = []

for text_name, text in [('k3_no_ndyahr', k3_no_ndyahr)]:
    # Truncate or cycle the key to match K4 length
    key_text = text
    while len(key_text) < len(K4_CT):
        key_text += text
    key_text = key_text[:len(K4_CT)]

    for alph_name, alph in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
        for cipher_name, cipher_fn in [('vig', vig_decrypt), ('beau', beau_decrypt), ('vbeau', vbeau_decrypt)]:
            pt = cipher_fn(K4_CT, key_text, alph)
            qg = scorer.score_per_char(pt)
            frags = find_english_fragments(pt)
            pt_ic = ic(pt)

            entry = {
                'key_source': text_name,
                'alphabet': alph_name,
                'cipher': cipher_name,
                'qg_per_char': round(qg, 4),
                'ic': round(pt_ic, 6),
                'english_fragments': frags,
                'pt_preview': pt[:80],
            }
            phase4_rk_results.append(entry)

            print(f"  {text_name}:{alph_name}_{cipher_name}: qg={qg:.3f}, ic={pt_ic:.4f} frags={frags}")
            if qg > -5.5 or frags:
                print(f"    PT: {pt[:80]}")

    # Also try only the NDYAHR positions (the REMOVED characters) as a key
    ndyahr_only = ''.join(c for c in K3_CT if c in NDYAHR)
    key_text2 = ndyahr_only
    while len(key_text2) < len(K4_CT):
        key_text2 += ndyahr_only
    key_text2 = key_text2[:len(K4_CT)]

    for alph_name, alph in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
        for cipher_name, cipher_fn in [('vig', vig_decrypt), ('beau', beau_decrypt)]:
            pt = cipher_fn(K4_CT, key_text2, alph)
            qg = scorer.score_per_char(pt)
            frags = find_english_fragments(pt)

            entry = {
                'key_source': 'ndyahr_only_cycled',
                'alphabet': alph_name,
                'cipher': cipher_name,
                'qg_per_char': round(qg, 4),
                'ic': round(ic(pt), 6),
                'english_fragments': frags,
                'pt_preview': pt[:80],
            }
            phase4_rk_results.append(entry)

            print(f"  ndyahr_only:{alph_name}_{cipher_name}: qg={qg:.3f} frags={frags}")

phase4_rk_results.sort(key=lambda x: x['qg_per_char'], reverse=True)
results['phases']['phase4'] = {
    'remaining_length': len(k3_no_ndyahr),
    'is_73': len(k3_no_ndyahr) == 73,
    'running_key_results': phase4_rk_results[:5],
}

# ══════════════════════════════════════════════════════════════════════════
# PHASE 5: Include the corrected C (XLAYERTWO -> CLAYERTWO)
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 5: Corrected C analysis")
print("=" * 80)

# Find where XLAYERTWO or MISTXCAN appears in K3 PT
x_pos_pt = K3_PT.find('X')
print(f"X in K3 PT at position: {x_pos_pt}")
print(f"Context: ...{K3_PT[max(0,x_pos_pt-10):x_pos_pt+15]}...")

# Replace X with C in the plaintext
k3_pt_c = K3_PT[:x_pos_pt] + 'C' + K3_PT[x_pos_pt+1:]
print(f"With C: ...{k3_pt_c[max(0,x_pos_pt-10):x_pos_pt+15]}...")

# The CT character at the position that encrypts to X (or C) in the transposition
# For transposition, the PT letter at a position maps 1:1 to a CT position
# So changing X->C in PT changes one letter in CT's inverse transposition
# Let's find what CT positions correspond to the X position

# K3 is a transposition cipher, so every CT letter = some PT letter at a different position
# If we know the transposition permutation, we can find which CT position holds the "X"

# For now, let's try removing NDYAHR from the C-corrected version
# Since K3 is a transposition, the CT won't change (just the PT mapping changes)
# The CT is what's on the sculpture, and we're modifying it

# Actually, the hypothesis is about modifying K3 CT, not K3 PT
# Let's try: what if the "dropped C" means a C should be ADDED to K3 CT?
k3_ct_plus_c = K3_CT + 'C'
print(f"\nK3 CT + C = {len(k3_ct_plus_c)} chars")

# Or inserted somewhere
# Try inserting C at position where X appears in relation to "LAYERTWO"
# Find LAYERTWO-like patterns in K3 CT
for i in range(len(K3_CT) - 8):
    snippet = K3_CT[i:i+9]
    # Check if any decryption of this snippet produces LAYERTWO
    # (this is speculative)

# More practically: try removing NDYAHR from K3 CT + C at various positions
phase5_results = []
for c_pos in [0, len(K3_CT), len(K3_CT)//2]:
    modified_ct = K3_CT[:c_pos] + 'C' + K3_CT[c_pos:]
    no_ndyahr = ''.join(c for c in modified_ct if c not in NDYAHR)

    for kw in ['KRYPTOS', 'DEFECTOR']:
        for alph_name, alph in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
            pt = vig_decrypt(no_ndyahr, kw, alph)
            qg = scorer.score_per_char(pt)
            frags = find_english_fragments(pt)

            if qg > -6.0 or frags:
                print(f"  C@{c_pos} no_ndyahr {kw}:{alph_name}_vig: qg={qg:.3f} frags={frags}")

results['phases']['phase5'] = {'note': 'C insertion variants tested, see console'}

# ══════════════════════════════════════════════════════════════════════════
# PHASE 6: Statistical analysis — is NDYAHR frequency anomalous?
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 6: Statistical Analysis")
print("=" * 80)

# Expected frequency of NDYAHR letters in English
english_freq = {
    'N': 0.0675, 'D': 0.0425, 'Y': 0.0197, 'A': 0.0817,
    'H': 0.0609, 'R': 0.0599
}
expected_ndyahr_pct = sum(english_freq.values()) * 100
print(f"Expected NDYAHR percentage in English: {expected_ndyahr_pct:.1f}%")
print(f"Observed NDYAHR percentage in K3 CT: {pct_ndyahr:.1f}%")
print(f"Observed NDYAHR percentage in K3 PT: {pct_ndyahr_pt:.1f}%")
print(f"Observed NDYAHR percentage in K4 CT: {pct_ndyahr_k4:.1f}%")

# For a Vigenere CT with keyword KRYPTOS, what's the expected NDYAHR frequency?
# Under Vigenere, each CT letter has a shifted distribution
# With keyword KRYPTOS (shifts K=10, R=17, Y=24, P=15, T=19, O=14, S=18)
# The CT distribution is a mixture of 7 shifted English distributions
# Expected frequency of letter L in CT = avg over key positions of P(PT_letter = L - shift_i)

kryptos_shifts = [ALPH_IDX[c] for c in 'KRYPTOS']
print(f"\nKRYPTOS shifts: {kryptos_shifts}")

# For each NDYAHR letter, compute expected CT frequency under Vig(KRYPTOS)
# P(CT=c) = (1/7) * sum_i P(PT = (c - shift_i) mod 26)
# Using English letter frequencies
eng_freq_full = {
    'A': 0.0817, 'B': 0.0149, 'C': 0.0278, 'D': 0.0425, 'E': 0.1270,
    'F': 0.0223, 'G': 0.0202, 'H': 0.0609, 'I': 0.0697, 'J': 0.0015,
    'K': 0.0077, 'L': 0.0403, 'M': 0.0241, 'N': 0.0675, 'O': 0.0751,
    'P': 0.0193, 'Q': 0.0010, 'R': 0.0599, 'S': 0.0633, 'T': 0.0906,
    'U': 0.0276, 'V': 0.0098, 'W': 0.0236, 'X': 0.0015, 'Y': 0.0197,
    'Z': 0.0007
}

print(f"\nExpected vs observed NDYAHR frequencies in K3 CT (Vig(KRYPTOS) model):")
expected_ndyahr_vig = {}
for target_letter in NDYAHR_STR:
    target_idx = ALPH_IDX[target_letter]
    expected_freq = 0
    for shift in kryptos_shifts:
        pt_idx = (target_idx - shift) % 26
        pt_letter = ALPH[pt_idx]
        expected_freq += eng_freq_full[pt_letter]
    expected_freq /= len(kryptos_shifts)
    expected_count = expected_freq * len(K3_CT)
    observed_count = ndyahr_counts[target_letter]
    ratio = observed_count / expected_count if expected_count > 0 else 0
    expected_ndyahr_vig[target_letter] = expected_freq
    print(f"  {target_letter}: expected={expected_count:.1f}, observed={observed_count}, ratio={ratio:.2f}")

total_expected_vig = sum(expected_ndyahr_vig.values()) * len(K3_CT)
print(f"\nTotal NDYAHR: expected={total_expected_vig:.1f}, observed={total_ndyahr}")
print(f"Ratio: {total_ndyahr / total_expected_vig:.3f}")

# K3 is actually a TRANSPOSITION cipher, not Vigenere
# For pure transposition, CT frequencies = PT frequencies
# So expected NDYAHR in K3 CT = NDYAHR in K3 PT
print(f"\nBUT K3 is a TRANSPOSITION cipher!")
print(f"So K3 CT letter frequencies = K3 PT letter frequencies (exactly)")
print(f"NDYAHR in K3 PT = {total_ndyahr_pt} ({pct_ndyahr_pt:.1f}%)")
print(f"NDYAHR in K3 CT = {total_ndyahr} ({pct_ndyahr:.1f}%)")
if total_ndyahr == total_ndyahr_pt:
    print(f"MATCH: frequencies are identical (as expected for transposition)")
else:
    print(f"MISMATCH: {total_ndyahr} != {total_ndyahr_pt} -- indicates transcription error or K3 is NOT pure transposition!")

# Check individual letter frequencies
print(f"\nPer-letter comparison (K3 CT vs K3 PT):")
ct_freq_full = Counter(K3_CT)
pt_freq_full = Counter(K3_PT)
for letter in NDYAHR_STR:
    ct_c = ct_freq_full.get(letter, 0)
    pt_c = pt_freq_full.get(letter, 0)
    match = "OK" if ct_c == pt_c else f"MISMATCH (diff={ct_c - pt_c:+d})"
    print(f"  {letter}: CT={ct_c}, PT={pt_c} -- {match}")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 6b: Monte Carlo — how often does random K3-like CT have this NDYAHR count?
# ══════════════════════════════════════════════════════════════════════════
print(f"\n--- Monte Carlo: NDYAHR count in random permutations of K3 ---")
import random
random.seed(42)

# Since K3 is a transposition, the CT is just a permutation of the PT
# So the NDYAHR count is FIXED by the plaintext
# There's no randomness — the count is what it is
# The question is: is the COUNT unusual for English text of this length?

# Compare with random 336-char English-frequency text
n_trials = 100000
ndyahr_counts_random = []
for _ in range(n_trials):
    # Generate random text with English frequencies
    text = ''.join(random.choices(ALPH, weights=[eng_freq_full[c] for c in ALPH], k=len(K3_CT)))
    count = sum(1 for c in text if c in NDYAHR)
    ndyahr_counts_random.append(count)

mean_random = sum(ndyahr_counts_random) / len(ndyahr_counts_random)
# What percentile is our observed count?
higher = sum(1 for c in ndyahr_counts_random if c >= total_ndyahr)
lower = sum(1 for c in ndyahr_counts_random if c <= total_ndyahr)
print(f"  Random English 336-char text: mean NDYAHR count = {mean_random:.1f}")
print(f"  Observed K3 CT NDYAHR count = {total_ndyahr}")
print(f"  P(count >= {total_ndyahr}) = {higher/n_trials:.4f}")
print(f"  P(count <= {total_ndyahr}) = {lower/n_trials:.4f}")

phase6 = {
    'ndyahr_pct_k3ct': pct_ndyahr,
    'ndyahr_pct_k3pt': pct_ndyahr_pt,
    'ndyahr_pct_k4ct': pct_ndyahr_k4,
    'expected_english_pct': expected_ndyahr_pct,
    'ct_pt_freq_match': total_ndyahr == total_ndyahr_pt,
    'mc_p_value_geq': higher / n_trials,
    'mc_p_value_leq': lower / n_trials,
}
results['phases']['phase6'] = phase6

# ══════════════════════════════════════════════════════════════════════════
# PHASE 7: Keep ONLY NDYAHR positions and analyze
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 7: NDYAHR-only positions analysis")
print("=" * 80)

# Extract only the NDYAHR letters from K3 CT, in order
ndyahr_extracted = ''.join(c for c in K3_CT if c in NDYAHR)
print(f"NDYAHR letters extracted from K3 CT: {len(ndyahr_extracted)} chars")
print(f"  Text: {ndyahr_extracted[:80]}")
print(f"  IC: {ic(ndyahr_extracted):.6f}")
print(f"  Frequency: {dict(Counter(ndyahr_extracted))}")

# Try as running key for K4 (already done in Phase 4 but let's also try direct)
# Also check if it anagrams to anything
from itertools import permutations as iter_perms

# Check distribution
ndyahr_dist = Counter(ndyahr_extracted)
print(f"\n  N={ndyahr_dist.get('N',0)}, D={ndyahr_dist.get('D',0)}, Y={ndyahr_dist.get('Y',0)}")
print(f"  A={ndyahr_dist.get('A',0)}, H={ndyahr_dist.get('H',0)}, R={ndyahr_dist.get('R',0)}")

# What percentage of each letter in K3 CT is NDYAHR?
# vs expected from K3 PT
for letter in NDYAHR_STR:
    ct_positions = [i for i, c in enumerate(K3_CT) if c == letter]
    pt_positions = [i for i, c in enumerate(K3_PT) if c == letter]
    print(f"  {letter} positions in CT: {ct_positions[:10]}{'...' if len(ct_positions)>10 else ''}")
    print(f"  {letter} positions in PT: {pt_positions[:10]}{'...' if len(pt_positions)>10 else ''}")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 8: Position-based removal (only remove NDYAHR at specific positions)
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 8: Selective NDYAHR removal (boundary region)")
print("=" * 80)

# The NDYAHR displaced letters are at the K3/K4 boundary (first 6 chars of K3 CT = ENDYAHR)
# What if we only remove occurrences near the boundary?
# Or: what if the instruction is "remove exactly 6 NDYAHR letters" (one of each) at specific positions?

# First: remove only the FIRST occurrence of each NDYAHR letter
first_occurrence = {}
k3_modified = list(K3_CT)
removed_indices = set()
for letter in NDYAHR_STR:
    for i, c in enumerate(K3_CT):
        if c == letter and i not in removed_indices:
            first_occurrence[letter] = i
            removed_indices.add(i)
            break

k3_first_removed = ''.join(c for i, c in enumerate(K3_CT) if i not in removed_indices)
print(f"Remove FIRST occurrence of each NDYAHR letter:")
print(f"  Removed at positions: {sorted(removed_indices)}")
print(f"  Remaining: {len(k3_first_removed)} chars (removed {len(removed_indices)})")

# Try decryption
for kw in ['KRYPTOS', 'DEFECTOR', 'PALIMPSEST']:
    for alph_name, alph in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
        pt = vig_decrypt(k3_first_removed, kw, alph)
        qg = scorer.score_per_char(pt)
        frags = find_english_fragments(pt)
        if qg > -6.5 or frags:
            print(f"  first_removed {kw}:{alph_name}_vig: qg={qg:.3f} frags={frags}")

# Remove only the ENDYAHR at position 0-5 (the literal displaced letters)
k3_skip6 = K3_CT[6:]  # Skip the displaced ENDYAHR
print(f"\nSkip first 6 chars (ENDYAH): remaining {len(k3_skip6)} chars")
# Actually it's ENDYAHROHNLSR... so first 6 are ENDYAH (but NDYAHR starts at pos 1)
# Let me be precise
print(f"First 10 chars of K3 CT: {K3_CT[:10]}")
print(f"NDYAHR are at positions 1-5 in K3 CT (the letters N,D,Y,A,H,R within ENDYAHR)")
# Actually ENDYAHR = E,N,D,Y,A,H,R so positions 1-6 are N,D,Y,A,H,R
k3_skip_boundary = K3_CT[0] + K3_CT[7:]  # Keep E, skip NDYAHR (pos 1-6), keep from pos 7
print(f"Skip boundary NDYAHR (positions 1-6): {len(k3_skip_boundary)} chars")
print(f"  Text starts: {k3_skip_boundary[:30]}")

for kw in ['KRYPTOS', 'DEFECTOR', 'PALIMPSEST', 'ABSCISSA']:
    for alph_name, alph in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
        for cipher_name, cipher_fn in [('vig', vig_decrypt), ('beau', beau_decrypt)]:
            pt = cipher_fn(k3_skip_boundary, kw, alph)
            qg = scorer.score_per_char(pt)
            frags = find_english_fragments(pt)
            if qg > -6.5 or frags:
                print(f"  skip_boundary {kw}:{alph_name}_{cipher_name}: qg={qg:.3f} frags={frags}")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 9: DESPARATLY misspelling analysis
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 9: DESPARATLY misspelling CT letter analysis")
print("=" * 80)

# In K3 PT: DESPARATLY has A where DESPERATELY would have E
# Under transposition, this A in PT maps to some specific CT position
# Find the A that should be E

# K3 PT = SLOWLY DESPARATLY SLOWLY THE...
# DESPERATELY = D,E,S,P,E,R,A,T,E,L,Y (11 chars)
# DESPARATLY  = D,E,S,P,A,R,A,T,L,Y (10 chars)
# Wait, DESPARATLY is 10 chars, DESPERATELY is 11
# Actually looking more carefully:
# DESPARATLY = D,E,S,P,A,R,A,T,L,Y
# This is a deliberate misspelling of DESPERATELY (missing the first E after D,
# and using A instead of E, and dropped one letter)
# The key difference: position 4 has A instead of E (DESP-A-RATLY vs DESP-E-RATELY)

desparatly_start = K3_PT.find('DESPARATLY')
print(f"DESPARATLY starts at K3 PT position: {desparatly_start}")
print(f"Context: {K3_PT[desparatly_start:desparatly_start+10]}")
print(f"The A at position {desparatly_start + 4} should be E")
print(f"The misspelling A is at K3 PT position {desparatly_start + 4}")

# Under K3's transposition, this PT position maps to some CT position
# We can find this if we know the transposition permutation
# For now, note the analysis

# Also check: if we correct DESPARATLY -> DESPERATELY in PT,
# what changes in the letter frequencies?
print(f"\nLetter frequency impact of correcting DESPARATLY:")
print(f"  -1 A, +1 E (changing A->E at the misspelling position)")
print(f"  K3 PT has {pt_freq_full['A']} A's and {pt_freq_full['E']} E's")
print(f"  K3 CT has {ct_freq_full['A']} A's and {ct_freq_full['E']} E's")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 10: Remove specific subsets of NDYAHR for target length 73
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 10: Target length analysis")
print("=" * 80)

target_73_removals = len(K3_CT) - 73  # 336 - 73 = 263
target_97_removals = len(K3_CT) - 97  # 336 - 97 = 239
print(f"To get length 73: need to remove {target_73_removals} chars (too many, impossible with just NDYAHR)")
print(f"To get length 97: need to remove {target_97_removals} chars (also too many)")
print(f"Actual NDYAHR removal gives: {len(k3_no_ndyahr)} chars")
print(f"  336 - {total_ndyahr} = {len(k3_no_ndyahr)}")
print()

# What length is k3_no_ndyahr?
remaining_len = len(k3_no_ndyahr)
# Is this a multiple of anything interesting?
for d in range(2, 30):
    if remaining_len % d == 0:
        print(f"  {remaining_len} = {d} x {remaining_len // d}")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 11: Try columnar transposition on the reduced text
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 11: Columnar transposition on reduced K3 CT")
print("=" * 80)

def columnar_decrypt(ct, key_order):
    """Decrypt columnar transposition"""
    n = len(ct)
    ncols = len(key_order)
    full_rows = n // ncols
    extra = n % ncols

    rank_to_col = [0] * ncols
    for col_idx, rank in enumerate(key_order):
        rank_to_col[rank] = col_idx

    col_lengths = []
    for col in range(ncols):
        col_lengths.append(full_rows + 1 if col < extra else full_rows)

    columns = {}
    pos = 0
    for rank in range(ncols):
        col = rank_to_col[rank]
        length = col_lengths[col]
        columns[col] = ct[pos:pos + length]
        pos += length

    plaintext = []
    for row in range(full_rows + (1 if extra > 0 else 0)):
        for col in range(ncols):
            if row < len(columns[col]):
                plaintext.append(columns[col][row])

    return ''.join(plaintext)

# KRYPTOS key -> column order
keyword = "KRYPTOS"
indexed = [(ch, i) for i, ch in enumerate(keyword)]
ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
kryptos_col_order = [0] * len(keyword)
for rank, (_, pos) in enumerate(ranked):
    kryptos_col_order[pos] = rank
print(f"KRYPTOS column order: {kryptos_col_order}")

# Try columnar decryption on reduced text
for text_name, text in [('k3_no_ndyahr', k3_no_ndyahr), ('k3_skip_boundary', k3_skip_boundary)]:
    print(f"\n--- {text_name} (len={len(text)}) ---")
    for width in [7, 6, 8, 14, 31]:
        # For width 7, use KRYPTOS key
        if width == 7:
            pt = columnar_decrypt(text, kryptos_col_order)
            qg = scorer.score_per_char(pt)
            frags = find_english_fragments(pt)
            print(f"  col7(KRYPTOS): qg={qg:.3f}, frags={frags}")
            if qg > -6.0:
                print(f"    PT: {pt[:80]}")

        # Generic (identity key)
        identity_key = list(range(width))
        pt = columnar_decrypt(text, identity_key)
        qg = scorer.score_per_char(pt)
        frags = find_english_fragments(pt)
        if qg > -6.5 or frags:
            print(f"  col{width}(identity): qg={qg:.3f}, frags={frags}")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 12: Double transposition (K3 method) on reduced text
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 12: K3 double-rotation method on reduced text")
print("=" * 80)

# K3 uses a double rotational transposition:
# 1. Write PT into 24x14 grid (row by row)
# 2. Read columns in KRYPTOS order (from 7-col mapping)
# 3. Write result into 8x42 grid
# 4. Read columns in some order
#
# For the REDUCED text, this exact method won't work (wrong dimensions)
# But let's try standard K3 decryption on K3 CT directly to verify we get the right PT

# Actually, the most interesting thing: if K3 has a SECOND plaintext,
# it would need a different key or different method
# The first thing to check: does a different keyword decrypt K3 CT to something meaningful?

print(f"\n--- Try decrypting full K3 CT ({len(K3_CT)} chars) with different Vig keywords ---")
# K3 is NOT a Vigenere cipher (it's transposition), but what if there's ALSO
# a substitution layer hidden in K3?
for kw in KEYWORDS:
    for alph_name, alph in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
        for cipher_name, cipher_fn in [('vig', vig_decrypt), ('beau', beau_decrypt)]:
            pt = cipher_fn(K3_CT, kw, alph)
            qg = scorer.score_per_char(pt)
            frags = find_english_fragments(pt, min_len=4)

            if qg > -6.0 or len(frags) >= 2:
                print(f"  {kw}:{alph_name}_{cipher_name}: qg={qg:.3f}, frags={frags}")
                if qg > -5.5:
                    print(f"    PT: {pt[:80]}")

# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)

print(f"""
K3 CT: {len(K3_CT)} characters
K3 PT: {len(K3_PT)} characters (freq match: {total_ndyahr == total_ndyahr_pt})

NDYAHR in K3 CT: {total_ndyahr} / {len(K3_CT)} = {pct_ndyahr:.1f}%
NDYAHR in K3 PT: {total_ndyahr_pt} / {len(K3_PT)} = {pct_ndyahr_pt:.1f}%
NDYAHR in K4 CT: {total_ndyahr_k4} / {len(K4_CT)} = {pct_ndyahr_k4:.1f}%

After removing ALL NDYAHR from K3 CT: {len(k3_no_ndyahr)} characters
  IC: {remaining_ic:.6f}
  Is 73? {len(k3_no_ndyahr) == 73}
  Is 97? {len(k3_no_ndyahr) == 97}

Best Phase 2 decryption (reduced text):
  {phase2_results[0]['text']}:{phase2_results[0]['keyword']}:{phase2_results[0]['alphabet']}_{phase2_results[0]['cipher']}
  Score: {phase2_results[0]['qg_per_char']:.3f} per char
  PT: {phase2_results[0]['plaintext_preview']}

Key findings:
1. K3 is a TRANSPOSITION cipher, so CT and PT have IDENTICAL letter frequencies
2. Removing NDYAHR from K3 CT removes {total_ndyahr} chars -> {len(k3_no_ndyahr)} remaining
3. This is NOT 73 or 97 or any K4-relevant length
4. K3 CT letter frequencies must match K3 PT exactly (transposition invariant)
""")

# Save results
results_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'results')
os.makedirs(results_dir, exist_ok=True)
results_file = os.path.join(results_dir, 'k3_ndyahr_hidden_message.json')
with open(results_file, 'w') as f:
    json.dump(results, f, indent=2, default=str)
print(f"Results saved to: {results_file}")
