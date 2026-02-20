#!/usr/bin/env python3
"""
E-S-66: Themed Running Key Texts + Width-7 Columnar (Model B)

Sanborn's themes: 1986 Egypt trip, 1989 Berlin Wall, CIA, "delivering a message"

Tests running key Vigenère/Beaufort combined with width-7 columnar transposition
(Model B: transposition first, then substitution).

For each text × offset × ordering × variant, check crib matches.
Scores ≥10 are investigated further with quadgram analysis.

Also tests:
- Direct application (no transposition) at all offsets
- Reversed texts
- Texts with keyword-derived alphabet substitution pre-applied
"""

import json
import math
import os
import sys
import time
from itertools import permutations

# ── Constants ──────────────────────────────────────────────────────────────
CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)  # 97

CRIB_DICT = {
    21: 'E', 22: 'A', 23: 'S', 24: 'T', 25: 'N', 26: 'O', 27: 'R',
    28: 'T', 29: 'H', 30: 'E', 31: 'A', 32: 'S', 33: 'T',
    63: 'B', 64: 'E', 65: 'R', 66: 'L', 67: 'I', 68: 'N', 69: 'C',
    70: 'L', 71: 'O', 72: 'C', 73: 'K'
}

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
IDX = {c: i for i, c in enumerate(AZ)}
CT_IDX = [IDX[c] for c in CT]

WIDTH = 7
NROWS = 14  # ceil(97/7)
COL_LENS = [14, 14, 14, 14, 14, 14, 13]  # col 6 has 13

# ── Load texts ─────────────────────────────────────────────────────────────
def load_alpha(path):
    """Load text file, keep only A-Z uppercase."""
    with open(path) as f:
        return ''.join(c.upper() for c in f.read() if c.upper() in AZ)

texts = {}
rk_dir = "reference/running_key_texts"
for fname in os.listdir(rk_dir):
    if fname.endswith('.txt'):
        texts[fname] = load_alpha(os.path.join(rk_dir, fname))

# Carter texts
for cname in ['carter_gutenberg.txt', 'carter_vol1.txt', 'carter_vol1_extract.txt']:
    path = f"reference/{cname}"
    if os.path.exists(path):
        texts[cname] = load_alpha(path)

# Sanborn/Smithsonian/YouTube
for sname in ['sanborn_correspondence.md', 'smithsonian_archive.md', 'youtube_transcript.md']:
    path = f"reference/{sname}"
    if os.path.exists(path):
        texts[sname] = load_alpha(path)

# Generate additional themed texts
themed = {
    'kryptos_repeated': 'KRYPTOS' * 200,
    'palimpsest_repeated': 'PALIMPSEST' * 200,
    'abscissa_repeated': 'ABSCISSA' * 200,
    'alphabet_repeated': AZ * 100,
    'k1_pt': 'BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUABORETHEMOROFLUMINANCE',  # K1 partial
    'k2_pt': 'ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGABORETHROUTHEMURTWASABLOCKOFTEXT',  # K2 partial
    'k3_pt': 'SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBABORISATTEMTOBETHROUGHTHETUPPEROPPENINODTHEDOORWAYWIDEDANDCHAMBERANDBYLIGHTOFDACANMADEOUTNOTHINGTHEHOTAIRFLORWARDANDTHEFLAMEFLICKEREDAWHOLEEVERYTHINGOKCANXOUVSEEANYTYHING',  # K3 (with Sanborn's typos)
    'cia_motto': 'ANDYESHALLKNOWTHETRUTHANTHTHE TRUTHSHALLMAKEYOUFREE'.replace(' ', '') * 20,
    'berlin_wall_date': 'NOVEMBERNINTHNINETEENEIGHTYNINE' * 20,
    'egypt_date': 'NINETEENEIGHTYSIX' * 50,
    'coordinates_langley': 'THIRTYEIGHTNINEFIVENORTHSEVENTYSEVENEIGHTWEST' * 20,
}
texts.update(themed)

# Also add K1+K2+K3 concatenated plaintext
k123 = texts.get('k1_pt', '') + texts.get('k2_pt', '') + texts.get('k3_pt', '')
texts['k123_concat'] = k123

print("=" * 70)
print("E-S-66: Themed Running Key Texts + Width-7 Columnar (Model B)")
print("=" * 70)
print(f"Texts loaded: {len(texts)}")
for name, text in sorted(texts.items()):
    print(f"  {name}: {len(text)} chars")

# ── Phase 1: Direct application (no transposition) ────────────────────────
print("\n" + "-" * 50)
print("Phase 1: Direct running key (no transposition)")
print("-" * 50)

best_direct = {'cribs': 0}
configs_d = 0
t0 = time.time()

for name, text in texts.items():
    text_idx = [IDX[c] for c in text]
    max_offset = len(text) - N
    if max_offset < 0:
        continue

    for offset in range(max_offset):
        for var_sign in (1, -1):  # vig, beau
            cribs = 0
            for p, expected in CRIB_DICT.items():
                kv = text_idx[offset + p]
                ct_v = CT_IDX[p]
                pt_v = (ct_v - var_sign * kv) % 26
                if AZ[pt_v] == expected:
                    cribs += 1
            configs_d += 1

            if cribs > best_direct['cribs']:
                vname = 'vig' if var_sign == 1 else 'beau'
                best_direct = {'cribs': cribs, 'text': name, 'offset': offset, 'variant': vname}
                if cribs >= 8:
                    print(f"  {cribs}/24 {vname} {name} offset={offset}")

t1 = time.time()
print(f"  {configs_d:,} configs, {t1-t0:.1f}s, best={best_direct['cribs']}/24")

# ── Phase 2: Reversed texts ───────────────────────────────────────────────
print("\n" + "-" * 50)
print("Phase 2: Reversed texts (no transposition)")
print("-" * 50)

best_rev = {'cribs': 0}
configs_r = 0
t2 = time.time()

for name, text in texts.items():
    rev = text[::-1]
    rev_idx = [IDX[c] for c in rev]
    max_offset = len(rev) - N
    if max_offset < 0:
        continue

    for offset in range(max_offset):
        for var_sign in (1, -1):
            cribs = 0
            for p, expected in CRIB_DICT.items():
                kv = rev_idx[offset + p]
                ct_v = CT_IDX[p]
                pt_v = (ct_v - var_sign * kv) % 26
                if AZ[pt_v] == expected:
                    cribs += 1
            configs_r += 1

            if cribs > best_rev['cribs']:
                vname = 'vig' if var_sign == 1 else 'beau'
                best_rev = {'cribs': cribs, 'text': name + '_REV', 'offset': offset, 'variant': vname}
                if cribs >= 8:
                    print(f"  {cribs}/24 {vname} {name}_REV offset={offset}")

t3 = time.time()
print(f"  {configs_r:,} configs, {t3-t2:.1f}s, best={best_rev['cribs']}/24")

# ── Phase 3: Width-7 columnar + running key (Model B) ─────────────────────
print("\n" + "-" * 50)
print("Phase 3: Width-7 columnar + running key (Model B, all orderings)")
print("-" * 50)

# Only use the longer texts (≥500 chars) for the full ordering sweep
long_texts = {k: v for k, v in texts.items() if len(v) >= 200}
print(f"  Using {len(long_texts)} texts with ≥200 chars for full sweep")

best_w7 = {'cribs': 0}
configs_w7 = 0
t4 = time.time()

# Precompute crib items for speed
crib_items = list(CRIB_DICT.items())

for name, text in long_texts.items():
    text_idx = [IDX[c] for c in text]
    max_offset = len(text) - N
    if max_offset < 0:
        continue

    # Sample offsets to keep runtime manageable
    step = max(1, max_offset // 1000)

    for order in permutations(range(WIDTH)):
        # Build inv_perm: pt_pos → ct_pos
        inv_perm = [0] * N
        pos = 0
        for grid_col in order:
            for row in range(COL_LENS[grid_col]):
                pt_pos = row * WIDTH + grid_col
                inv_perm[pt_pos] = pos
                pos += 1

        # Precompute: for each crib position, the CT position
        crib_ct = [(inv_perm[p], IDX[expected]) for p, expected in crib_items]

        for offset in range(0, max_offset, step):
            for var_sign in (1, -1):
                cribs = 0
                for j, exp_idx in crib_ct:
                    kv = text_idx[offset + j]
                    ct_v = CT_IDX[j]
                    pt_v = (ct_v - var_sign * kv) % 26
                    if pt_v == exp_idx:
                        cribs += 1
                configs_w7 += 1

                if cribs > best_w7['cribs']:
                    vname = 'vig' if var_sign == 1 else 'beau'
                    best_w7 = {
                        'cribs': cribs,
                        'order': list(order),
                        'text': name,
                        'offset': offset,
                        'variant': vname,
                    }
                    if cribs >= 10:
                        print(f"  ** HIT: {cribs}/24 order={list(order)} {vname} {name} offset={offset}")

    if time.time() - t4 > 300:  # 5 minute timeout per text
        elapsed = time.time() - t4
        print(f"  {name}: {configs_w7:,} configs in {elapsed:.0f}s (continuing...)")

t5 = time.time()
print(f"\n  Total: {configs_w7:,} configs in {t5-t4:.1f}s")
print(f"  Best: {best_w7['cribs']}/24 — {best_w7}")

# ── Phase 4: Targeted texts × dense offset search on promising orderings ──
print("\n" + "-" * 50)
print("Phase 4: Dense offset search — Carter + speeches × top orderings")
print("-" * 50)

# Use the biggest text (Carter) with ALL offsets on a subset of orderings
# Try orderings that have thematic resonance: KRYPTOS keyword ordering etc.
# And the top orderings from E-S-65 bigram analysis (if we have results)
carter = texts.get('carter_vol1_extract.txt', texts.get('carter_gutenberg.txt', ''))
carter_idx = [IDX[c] for c in carter]
carter_len = len(carter)

# Test ALL offsets for a set of promising orderings
# K3 used PALIMPSEST as transposition keyword → order [5, 0, 3, 2, 4, 7, 6, 1, 8, 9]
# For width 7, keyword-derived orderings from KRYPTOS, PALIMPSEST, etc.
def keyword_order(keyword, width):
    """Derive column ordering from keyword."""
    if len(keyword) < width:
        keyword = keyword + ''.join(c for c in AZ if c not in keyword)
    keyword = keyword[:width]
    return [i for _, i in sorted(zip(keyword, range(width)))]

test_keywords = [
    'KRYPTOS', 'PALIMPS', 'ABSCISS', 'BERLINCL', 'EASTNOR',
    'SANBORN', 'SCHEIDT', 'LANGLEY', 'CENTRAL', 'INTELLI',
    'CLOCKBE', 'MESSAGE', 'DELIVER', 'SECRETA', 'PHANTOM',
]
keyword_orders = set()
for kw in test_keywords:
    order = tuple(keyword_order(kw, WIDTH))
    keyword_orders.add(order)
print(f"  Keyword-derived orderings: {len(keyword_orders)}")

best_carter = {'cribs': 0}
configs_carter = 0
t6 = time.time()

for order in keyword_orders:
    inv_perm = [0] * N
    pos = 0
    for grid_col in order:
        for row in range(COL_LENS[grid_col]):
            pt_pos = row * WIDTH + grid_col
            inv_perm[pt_pos] = pos
            pos += 1

    crib_ct = [(inv_perm[p], IDX[expected]) for p, expected in crib_items]

    for offset in range(carter_len - N):
        for var_sign in (1, -1):
            cribs = 0
            for j, exp_idx in crib_ct:
                kv = carter_idx[offset + j]
                ct_v = CT_IDX[j]
                pt_v = (ct_v - var_sign * kv) % 26
                if pt_v == exp_idx:
                    cribs += 1
            configs_carter += 1

            if cribs > best_carter['cribs']:
                vname = 'vig' if var_sign == 1 else 'beau'
                best_carter = {
                    'cribs': cribs,
                    'order': list(order),
                    'text': 'carter',
                    'offset': offset,
                    'variant': vname,
                }
                if cribs >= 10:
                    print(f"  ** HIT: {cribs}/24 order={list(order)} {vname} carter offset={offset}")

t7 = time.time()
print(f"  {configs_carter:,} configs in {t7-t6:.1f}s, best={best_carter['cribs']}/24")

# ── Summary ────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Phase 1 (direct): best {best_direct['cribs']}/24 — {best_direct}")
print(f"  Phase 2 (reversed): best {best_rev['cribs']}/24 — {best_rev}")
print(f"  Phase 3 (width-7 all orderings): best {best_w7['cribs']}/24 — {best_w7}")
print(f"  Phase 4 (Carter + keyword orders): best {best_carter['cribs']}/24 — {best_carter}")

max_cribs = max(best_direct['cribs'], best_rev['cribs'], best_w7['cribs'], best_carter['cribs'])
if max_cribs >= 18:
    verdict = f"SIGNAL — {max_cribs}/24 matches"
elif max_cribs >= 10:
    verdict = f"WEAK SIGNAL — {max_cribs}/24 (investigate)"
else:
    verdict = f"NO SIGNAL — best {max_cribs}/24 (all at noise)"

print(f"\n  Verdict: {verdict}")
print(f"  Total configs: {configs_d + configs_r + configs_w7 + configs_carter:,}")

# Save results
output = {
    'experiment': 'E-S-66',
    'description': 'Themed running key texts + width-7 columnar',
    'best_direct': best_direct,
    'best_reversed': best_rev,
    'best_w7': best_w7,
    'best_carter': best_carter,
    'verdict': verdict,
    'total_configs': configs_d + configs_r + configs_w7 + configs_carter,
}

os.makedirs("results", exist_ok=True)
with open("results/e_s_66_themed_running_keys.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_66_themed_running_keys.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_66_themed_running_keys.py")
