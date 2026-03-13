#!/usr/bin/env python3
"""
Cipher:   W-removal (5 W's→92 chars) + Autokey
Family:   campaigns
Status:   active
Keyspace: 304 keywords × 2 autokey modes × 3 ciphers × 2 alphabets = ~7K configs
Last run:
Best score:

W-REMOVAL + AUTOKEY (92-char)
------------------------------
Remove ONLY the 5 W positions [20,36,48,58,74] → 92-char CT.
Test PT-autokey and CT-autokey on the 92-char text.

KEY DISTINCTIONS:
- e_w_removal_hypothesis_01.py: tested PERIODIC on 92-char (no autokey)
- e_w_null_autokey_sa.py: tests autokey on 73-char (24 nulls, W+19 more)
- THIS SCRIPT: tests autokey on 92-char (only 5 W's removed)

Crib positions after W removal:
- W[20] before ENE (21-33): ENE shifts to positions 20-32 in 92-char
- W[20,36,48,58] before BC (63-73): BC shifts to positions 59-69 in 92-char

Also tests 92-char → then trying specific 73/74-char extractions.
"""

import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET, CRIB_DICT,
)

# ── W removal ─────────────────────────────────────────────────────────────

W_POSITIONS = frozenset(i for i, c in enumerate(CT) if c == 'W')
assert W_POSITIONS == frozenset([20, 36, 48, 58, 74]), f"Unexpected W positions: {sorted(W_POSITIONS)}"

CT92 = [c for i, c in enumerate(CT) if i not in W_POSITIONS]
assert len(CT92) == 92, f"Expected 92, got {len(CT92)}"

CT92_ORDS = [ord(c) - 65 for c in CT92]

# Build mapping from original positions to 92-char positions
ORIG_TO_92 = {}
idx = 0
for i in range(CT_LEN):
    if i not in W_POSITIONS:
        ORIG_TO_92[i] = idx
        idx += 1

# Crib positions in 92-char text
CRIB_92 = {ORIG_TO_92[pos]: ch for pos, ch in CRIB_DICT.items()}
CRIB_92_LIST = sorted(CRIB_92.items())

ENE_START_92 = ORIG_TO_92[21]   # should be 20 (W at 20 removed)
BC_START_92 = ORIG_TO_92[63]    # should be 59 (W at 20,36,48,58 removed = 4 removed before pos 63)

print(f"CT92 ({len(CT92)} chars): {''.join(CT92)}")
print(f"ENE starts at position {ENE_START_92} in 92-char (want 20)")
print(f"BC  starts at position {BC_START_92} in 92-char (want 59)")
print(f"ENE region in CT92: {''.join(CT92[ENE_START_92:ENE_START_92+13])}")
print(f"BC  region in CT92: {''.join(CT92[BC_START_92:BC_START_92+11])}")
print()

# ── Cipher variants ────────────────────────────────────────────────────────

ALPHABETS = {
    "AZ": (ALPH, {c: i for i, c in enumerate(ALPH)}),
    "KA": (KRYPTOS_ALPHABET, {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}),
}

def vig_dec(c, k): return (c - k) % 26
def beau_dec(c, k): return (k - c) % 26
def vbeau_dec(c, k): return (c + k) % 26
CIPHERS = [("Vig", vig_dec), ("Beau", beau_dec), ("VBeau", vbeau_dec)]

def count_cribs_92(pt_ords):
    return sum(1 for pos, ch in CRIB_92_LIST if pos < len(pt_ords) and pt_ords[pos] == ord(ch) - 65)

def count_cribs_92_free(pt_str):
    mapped = sum(1 for pos, ch in CRIB_92_LIST if pos < len(pt_str) and pt_str[pos] == ch)
    free = 13 if "EASTNORTHEAST" in pt_str else 0
    free += 11 if "BERLINCLOCK" in pt_str else 0
    return max(mapped, free)

def pt_autokey(ct_ords, kw_ords, dec_fn):
    L = len(kw_ords)
    key = list(kw_ords)
    pt = []
    for c in ct_ords:
        k = key[len(pt)] if len(pt) < L else pt[len(pt) - L]
        p = dec_fn(c, k)
        pt.append(p)
        key.append(p)
    return pt

def ct_autokey(ct_ords, kw_ords, dec_fn):
    L = len(kw_ords)
    return [dec_fn(ct_ords[i], kw_ords[i] if i < L else ct_ords[i - L])
            for i in range(len(ct_ords))]

# ── Keyword loading ────────────────────────────────────────────────────────

PRIORITY = [
    "KRYPTOS", "KOMPASS", "DEFECTOR", "COLOPHON", "ABSCISSA",
    "PARALLAX", "VERDIGRIS", "SHADOW", "KRYPTA", "PALIMPSEST",
    "CIPHER", "SECRET", "COMPASS", "ENIGMA", "BERLIN", "CLOCK",
    "SANBORN", "SCHEIDT", "LANGLEY", "LODESTONE", "MAGNETIC",
    "EAST", "NORTH", "BERLINCLOCK", "KRYPTEIA", "KLEPSYDRA", "KOLOPHON",
]

KW_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'wordlists', 'thematic_keywords.txt')
all_kws = set(PRIORITY)
if os.path.exists(KW_FILE):
    with open(KW_FILE) as f:
        for ln in f:
            w = ln.strip().upper()
            if w and not w.startswith('#') and 3 <= len(w) <= 20 and w.isalpha():
                all_kws.add(w)
KEYWORDS = sorted(all_kws)
print(f"Keywords: {len(KEYWORDS)}")

# ── Main search ────────────────────────────────────────────────────────────

t0 = time.time()
best = 0
best_configs = []
total = 0

for kw in KEYWORDS:
    for alph_name, (alph_str, c2i) in ALPHABETS.items():
        try:
            kw_ords = [c2i[c] for c in kw]
        except KeyError:
            continue
        for cn, dec_fn in CIPHERS:
            for mode_name, dec_wrapper in [("pt", pt_autokey), ("ct", ct_autokey)]:
                pt = dec_wrapper(CT92_ORDS, kw_ords, dec_fn)
                pt_str = ''.join(alph_str[p] for p in pt)
                hits = count_cribs_92_free(pt_str)
                total += 1
                if hits >= max(best, 6):
                    best = hits
                    cfg = dict(kw=kw, alph=alph_name, cipher=cn, mode=mode_name,
                               score=hits, pt=pt_str)
                    best_configs.append(cfg)
                    print(f"Score {hits}/24 | {kw}/{cn}/{alph_name}/{mode_name}_autokey")
                    print(f"  ENE: {pt_str[ENE_START_92:ENE_START_92+13]} (want EASTNORTHEAST)")
                    print(f"  BC:  {pt_str[BC_START_92:BC_START_92+11]} (want BERLINCLOCK)")
                    if hits >= 18:
                        print("  *** SIGNAL ***")
                        print(f"  FULL PT: {pt_str}")

elapsed = time.time() - t0
print(f"\n{'=' * 70}")
print(f"Configs: {total} | Elapsed: {elapsed:.2f}s | Best: {best}/24")
if best_configs:
    top = sorted(best_configs, key=lambda x: -x['score'])
    print(f"\nTop results:")
    for c in top[:5]:
        print(f"  {c['score']}/24 | {c['kw']}/{c['cipher']}/{c['alph']}/{c['mode']}")
        print(f"    ENE: {c['pt'][ENE_START_92:ENE_START_92+13]}")
        print(f"    BC:  {c['pt'][BC_START_92:BC_START_92+11]}")
print(f"{'=' * 70}")
if best >= 18:
    print("STATUS: SIGNAL")
elif best >= 6:
    print("STATUS: ABOVE NOISE — investigate further")
else:
    print("STATUS: NOISE — W-only removal + autokey: no signal")
