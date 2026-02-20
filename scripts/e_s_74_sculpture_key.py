#!/usr/bin/env python3
"""
E-S-74: Sculpture-Derived Key Approaches

Explores the idea that the K4 key/method comes from the Kryptos sculpture itself.
Sanborn said "Who says it is even a math solution?" and the "coding charts" were
physical artifacts. This experiment tests various ways the sculpture text could
generate keys or substitutions.

Phase 1: K1-K3 CT/PT as substitution tables
  - K1-K3 combined give ~500+ characters of known CT↔PT pairs
  - These pairs define partial substitution alphabets at each position
  - Test: use K1-K3 as a running key source (position-aligned with K4)

Phase 2: K1-K3 as alphabet definition
  - K1-K3 plaintext written into grids → read out as mixed alphabets
  - Each K section could define one or more alphabets

Phase 3: Sculpture physical layout
  - The 4 sections are on a curved copper plate
  - K4 starts at a specific physical position after K3
  - What if the key wraps around from K1-K3?

Phase 4: K1-K3 keystream extraction
  - Extract the actual K1/K2/K3 Vigenère keys (PALIMPSEST, ABSCISSA, KRYPTOS)
  - Use combinations/repetitions of these as K4 key
"""

import json
import os
import random
import sys
import time

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
IDX = {c: i for i, c in enumerate(AZ)}
CT_IDX = [IDX[c] for c in CT]

CRIB_DICT = {
    21: 'E', 22: 'A', 23: 'S', 24: 'T', 25: 'N', 26: 'O', 27: 'R',
    28: 'T', 29: 'H', 30: 'E', 31: 'A', 32: 'S', 33: 'T',
    63: 'B', 64: 'E', 65: 'R', 66: 'L', 67: 'I', 68: 'N', 69: 'C',
    70: 'L', 71: 'O', 72: 'C', 73: 'K'
}
CRIB_POS = sorted(CRIB_DICT.keys())

print("=" * 70)
print("E-S-74: Sculpture-Derived Key Approaches")
print("=" * 70)

# ── K1-K3 Data ───────────────────────────────────────────────────────────
# K1 (Vigenère with key PALIMPSEST)
K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUABOROFINVISIBILITY"  # Sanborn's intended

# K2 (Vigenère with key ABSCISSA)
K2_CT = "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRRYIZETKZE"
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUABORUNDTHISWASNOTVISIBLE"

# K3 (transposition + Vigenère with key KRYPTOS, width 7)
K3_CT = "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNETPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOETFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLBTEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEBAECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLLEHAGTDHARDPNEOHMGFMFEUHEECDMRIPFEIMEHNLSSTTRTVDOHW"
K3_PT = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISUNDERTHECARTOSCOULDSTILLBESEENPARTOFWHATHADBEENAGREATMOVEMENTTODENYWHATTHEYHADFOUNDTHEYHADCOMETOTHEEDGEOFTHEIRCALCULATEDDESTICATIONFIFTEENCHARACTERSFROMTHEENDOFMASINTERPRETAWERECASTTHATHADBEENINTENDEDTOFOOLTHEMUPONTHEFLOOROFTHEARCHAEOLOGYHOUSEHADBEENREMOVEDSOTOEXPOSETHEENTIRE"

# K1-K3 keys
K1_KEY = "PALIMPSEST"
K2_KEY = "ABSCISSA"
K3_KEY = "KRYPTOS"

def score_cribs(key_vals, variant='vig'):
    """Score key against cribs."""
    matches = 0
    for p in CRIB_POS:
        pt_v = IDX[CRIB_DICT[p]]
        ct_v = CT_IDX[p]
        if variant == 'vig':
            expected_k = (ct_v - pt_v) % 26
        elif variant == 'beau':
            expected_k = (ct_v + pt_v) % 26
        else:
            expected_k = (pt_v - ct_v) % 26

        if p < len(key_vals) and key_vals[p] == expected_k:
            matches += 1
    return matches

# ── Phase 1: K1-K3 CT/PT as running key ─────────────────────────────────
print("\n" + "-" * 50)
print("Phase 1: K1-K3 as running key (various alignments)")
print("-" * 50)

# All K-section texts concatenated
all_k_ct = K1_CT + K2_CT + K3_CT
all_k_pt = K1_PT + K2_PT + K3_PT
all_k_keys = K1_KEY * 20 + K2_KEY * 20 + K3_KEY * 20  # repeated keys

# Also try the sculpture text as it appears (K1-K4 continuous)
# K4 starts at position after K3 on the sculpture
# The exact position depends on interpretation

running_sources = {
    'K1_CT': K1_CT,
    'K2_CT': K2_CT,
    'K3_CT': K3_CT,
    'K1_PT': K1_PT,
    'K2_PT': K2_PT,
    'K3_PT': K3_PT,
    'K1K2K3_CT': all_k_ct,
    'K1K2K3_PT': all_k_pt,
    'K1K2K3_KEYS': all_k_keys,
    'K1_KEY_rep': K1_KEY * 20,
    'K2_KEY_rep': K2_KEY * 20,
    'K3_KEY_rep': K3_KEY * 20,
    'PALIMPSESTABSCISSA': ('PALIMPSEST' + 'ABSCISSA') * 10,
    'PALIMPSESTABSCISSAKRYPTOS': ('PALIMPSEST' + 'ABSCISSA' + 'KRYPTOS') * 10,
    'KRYPTOSPALIMPSEST': ('KRYPTOS' + 'PALIMPSEST') * 10,
    'K3_PT_reversed': K3_PT[::-1],
    'K3_CT_reversed': K3_CT[::-1],
}

best_p1 = {'score': 0}
for name, source in running_sources.items():
    if len(source) < N:
        # Pad with repeated
        source = (source * ((N // len(source)) + 2))[:N]

    for offset in range(min(len(source) - N + 1, 300)):
        key_text = source[offset:offset+N]
        key_vals = [IDX[c] for c in key_text.upper() if c.upper() in IDX]
        if len(key_vals) < N:
            continue
        key_vals = key_vals[:N]

        for variant in ['vig', 'beau', 'vb']:
            score = score_cribs(key_vals, variant)
            if score > best_p1['score']:
                best_p1 = {'score': score, 'source': name, 'offset': offset,
                           'variant': variant}
                if score >= 6:
                    print(f"    {name} offset={offset} {variant}: {score}/24")

print(f"  Phase 1 best: {best_p1['score']}/24 — {best_p1}")

# ── Phase 2: K1-K3 PT as alphabet definition ────────────────────────────
print("\n" + "-" * 50)
print("Phase 2: K-section text → mixed alphabets")
print("-" * 50)

def text_to_mixed_alphabet(text):
    """Create a mixed alphabet from a keyword/text (standard construction)."""
    seen = set()
    alpha = []
    for c in text.upper():
        if c in IDX and c not in seen:
            seen.add(c)
            alpha.append(c)
    # Append remaining letters
    for c in AZ:
        if c not in seen:
            alpha.append(c)
    return ''.join(alpha)

# Generate mixed alphabets from various K-section keywords and phrases
alpha_sources = {
    'KRYPTOS': 'KRYPTOS',
    'PALIMPSEST': 'PALIMPSEST',
    'ABSCISSA': 'ABSCISSA',
    'INVISIBILITY': 'INVISIBILITY',
    'SHADOW': 'SHADOW',
    'BETWEENSUBTLESHADING': 'BETWEENSUBTLESHADING',
    'ITWASTOTALLYINVISIBLE': 'ITWASTOTALLYINVISIBLE',
    'BERLINCLOCK': 'BERLINCLOCK',
    'EASTNORTHEAST': 'EASTNORTHEAST',
    'K3_first7': K3_PT[:7],
    'K3_first10': K3_PT[:10],
    'K3_first14': K3_PT[:14],
    'K3_key_KRYPTOS': 'KRYPTOS',
    'K2_key_ABSCISSA': 'ABSCISSA',
}

best_p2 = {'score': 0}
for name, src in alpha_sources.items():
    mixed = text_to_mixed_alphabet(src)
    alpha_map = {c: i for i, c in enumerate(mixed)}

    for variant in ['vig', 'beau']:
        # Use the mixed alphabet to remap CT or PT
        # Interpretation 1: Use mixed alphabet as the tableau row/column headers
        # Vigenère with mixed plain alphabet: PT letter → mixed position, then shift
        for period in range(1, 15):
            for key_start in range(26):
                key_vals = [(key_start + (i % period)) % 26 for i in range(N)]  # Simple arithmetic key
                score = score_cribs(key_vals, variant)
                if score > best_p2['score']:
                    best_p2 = {'score': score, 'source': name, 'variant': variant,
                               'period': period, 'key_start': key_start}

print(f"  Phase 2 best: {best_p2['score']}/24 — {best_p2}")

# ── Phase 3: Combined K1-K3 keystream as K4 key ─────────────────────────
print("\n" + "-" * 50)
print("Phase 3: K1-K3 keystream values as K4 key")
print("-" * 50)

# Extract actual keystream values from K1, K2, K3
def extract_keystream(ct_text, pt_text, variant='vig'):
    """Extract the keystream from known CT/PT pair."""
    ks = []
    for ct_c, pt_c in zip(ct_text.upper(), pt_text.upper()):
        if ct_c in IDX and pt_c in IDX:
            ct_v, pt_v = IDX[ct_c], IDX[pt_c]
            if variant == 'vig':
                k = (ct_v - pt_v) % 26
            else:
                k = (ct_v + pt_v) % 26
            ks.append(k)
    return ks

k1_ks = extract_keystream(K1_CT, K1_PT, 'vig')
k2_ks = extract_keystream(K2_CT, K2_PT, 'vig')
k3_ks = extract_keystream(K3_CT, K3_PT, 'vig')  # Note: K3 uses transposition too, so this is the EFFECTIVE keystream

print(f"  K1 keystream: {len(k1_ks)} values")
print(f"  K2 keystream: {len(k2_ks)} values")
print(f"  K3 keystream: {len(k3_ks)} values")

# Try: concatenated keystreams as K4 key
ks_sources = {
    'K1_ks': k1_ks,
    'K2_ks': k2_ks,
    'K3_ks': k3_ks,
    'K1K2K3_ks': k1_ks + k2_ks + k3_ks,
    'K3K2K1_ks': k3_ks + k2_ks + k1_ks,
    'K1_ks_reversed': k1_ks[::-1],
    'K2_ks_reversed': k2_ks[::-1],
    'K3_ks_reversed': k3_ks[::-1],
}

best_p3 = {'score': 0}
for name, ks in ks_sources.items():
    if len(ks) < N:
        continue
    for offset in range(min(len(ks) - N + 1, 500)):
        key_vals = ks[offset:offset+N]
        for variant in ['vig', 'beau', 'vb']:
            score = score_cribs(key_vals, variant)
            if score > best_p3['score']:
                best_p3 = {'score': score, 'source': name, 'offset': offset,
                           'variant': variant}
                if score >= 6:
                    print(f"    {name} offset={offset} {variant}: {score}/24")

print(f"  Phase 3 best: {best_p3['score']}/24 — {best_p3}")

# ── Phase 4: Key derived from K1-K3 via XOR/addition of keystreams ──────
print("\n" + "-" * 50)
print("Phase 4: Derived keys (keystream arithmetic)")
print("-" * 50)

# Try combining keystreams arithmetically
best_p4 = {'score': 0}

# K1 key repeated + K2 key repeated + K3 key repeated
k1_key_vals = [IDX[c] for c in K1_KEY]
k2_key_vals = [IDX[c] for c in K2_KEY]
k3_key_vals = [IDX[c] for c in K3_KEY]

# Various arithmetic combinations of repeating keys
combos = []

# Simple concatenation of key values
for k1_reps in range(1, 4):
    for k2_reps in range(1, 4):
        for k3_reps in range(1, 4):
            combined = k1_key_vals * k1_reps + k2_key_vals * k2_reps + k3_key_vals * k3_reps
            if len(combined) >= N:
                combos.append(('concat_{}_{}_{}' .format(k1_reps, k2_reps, k3_reps), combined[:N]))

# Addition of repeating keys
for p1 in [len(K1_KEY), 7]:
    for p2 in [len(K2_KEY), 7]:
        key1 = [k1_key_vals[i % len(k1_key_vals)] for i in range(N)]
        key2 = [k2_key_vals[i % len(k2_key_vals)] for i in range(N)]
        combined = [(key1[i] + key2[i]) % 26 for i in range(N)]
        combos.append((f'add_p{p1}_p{p2}', combined))

# XOR of repeating keys
for p1 in [len(K1_KEY)]:
    for p2 in [len(K2_KEY)]:
        key1 = [k1_key_vals[i % len(k1_key_vals)] for i in range(N)]
        key2 = [k2_key_vals[i % len(k2_key_vals)] for i in range(N)]
        combined = [(key1[i] ^ key2[i]) % 26 for i in range(N)]
        combos.append((f'xor_p{p1}_p{p2}', combined))

# Progressive key: K3_KEY repeated but shifted by position
for shift in range(1, 26):
    key = [(k3_key_vals[i % len(k3_key_vals)] + (i // len(k3_key_vals)) * shift) % 26 for i in range(N)]
    combos.append((f'k3_prog_shift{shift}', key))

# Fibonacci-like from key values
for seed_key in [k1_key_vals, k2_key_vals, k3_key_vals]:
    for seed_len in [2, 3, 4]:
        if len(seed_key) >= seed_len:
            fib = list(seed_key[:seed_len])
            while len(fib) < N:
                fib.append((fib[-1] + fib[-2]) % 26)
            combos.append((f'fib_{seed_len}_{seed_key[:3]}', fib[:N]))

for name, key_vals in combos:
    for variant in ['vig', 'beau', 'vb']:
        score = score_cribs(key_vals, variant)
        if score > best_p4['score']:
            best_p4 = {'score': score, 'source': name, 'variant': variant}
            if score >= 6:
                print(f"    {name} {variant}: {score}/24")

print(f"  Phase 4 best: {best_p4['score']}/24 — {best_p4}")

# ── Phase 5: Width-7 columnar + K-derived running keys ──────────────────
print("\n" + "-" * 50)
print("Phase 5: Width-7 columnar + K-derived running keys (all orderings)")
print("-" * 50)

from itertools import permutations

WIDTH = 7
NROWS_FULL = N // WIDTH
NROWS_EXTRA = N % WIDTH

def build_col_perm(order):
    """Build columnar transposition permutation."""
    col_lengths = []
    for col_idx in range(WIDTH):
        if col_idx < NROWS_EXTRA:
            col_lengths.append(NROWS_FULL + 1)
        else:
            col_lengths.append(NROWS_FULL)

    perm = [0] * N
    j = 0
    for rank in range(WIDTH):
        c = order[rank]
        clen = col_lengths[c]
        for row in range(clen):
            pt_pos = row * WIDTH + c
            perm[j] = pt_pos
            j += 1

    inv_perm = [0] * N
    for j in range(N):
        inv_perm[perm[j]] = j
    return perm, inv_perm

# Best running key sources from earlier phases
best_rk_sources = {
    'K1K2K3_PT': all_k_pt,
    'K3_PT': K3_PT,
    'K3_CT': K3_CT,
    'K1K2K3_CT': all_k_ct,
    'K3_PT_reversed': K3_PT[::-1],
    'PALIMPSESTABSCISSAKRYPTOS_rep': ('PALIMPSEST' + 'ABSCISSA' + 'KRYPTOS') * 10,
}

best_p5 = {'score': 0}
t5_start = time.time()
all_orders = list(permutations(range(WIDTH)))

for name, source_text in best_rk_sources.items():
    source_upper = source_text.upper()
    source_vals = [IDX[c] for c in source_upper if c in IDX]
    if len(source_vals) < N:
        source_vals = (source_vals * ((N // len(source_vals)) + 2))

    for oi, order in enumerate(all_orders):
        order = list(order)
        _, inv_perm = build_col_perm(order)

        # Model B: CT[j] = sub(PT[perm[j]])
        # With running key: CT[j] = (PT[perm[j]] + key[j]) % 26
        # So: key[j] = (CT[j] - PT[perm[j]]) % 26

        for offset in [0]:  # Just offset 0 for speed
            key_slice = source_vals[offset:offset+N]
            if len(key_slice) < N:
                continue

            for variant in ['vig', 'beau']:
                matches = 0
                for p in CRIB_POS:
                    j = inv_perm[p]
                    pt_v = IDX[CRIB_DICT[p]]
                    ct_v = CT_IDX[j]
                    if variant == 'vig':
                        expected_k = (ct_v - pt_v) % 26
                    else:
                        expected_k = (ct_v + pt_v) % 26
                    if expected_k == key_slice[j]:
                        matches += 1

                if matches > best_p5['score']:
                    best_p5 = {'score': matches, 'source': name, 'order': order,
                               'variant': variant, 'offset': offset}
                    if matches >= 6:
                        print(f"    {name} order={order} {variant}: {matches}/24")

    elapsed = time.time() - t5_start
    print(f"  Source {name}: {elapsed:.0f}s, best so far = {best_p5['score']}/24")

print(f"\n  Phase 5 best: {best_p5['score']}/24 — {best_p5}")

# ── Summary ──────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Phase 1 (K-text running key): {best_p1['score']}/24")
print(f"  Phase 2 (mixed alphabets): {best_p2['score']}/24")
print(f"  Phase 3 (keystream values): {best_p3['score']}/24")
print(f"  Phase 4 (keystream arithmetic): {best_p4['score']}/24")
print(f"  Phase 5 (w7 + K-derived key): {best_p5['score']}/24")

best_all = max(best_p1['score'], best_p2['score'], best_p3['score'],
               best_p4['score'], best_p5['score'])
if best_all >= 10:
    verdict = f"SIGNAL — {best_all}/24"
else:
    verdict = f"NO SIGNAL — best {best_all}/24"

print(f"\n  Verdict: {verdict}")

output = {
    'experiment': 'E-S-74',
    'description': 'Sculpture-derived key approaches',
    'phase1_best': best_p1['score'],
    'phase2_best': best_p2['score'],
    'phase3_best': best_p3['score'],
    'phase4_best': best_p4['score'],
    'phase5_best': best_p5['score'],
    'verdict': verdict,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_74_sculpture_key.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_74_sculpture_key.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_74_sculpture_key.py")
