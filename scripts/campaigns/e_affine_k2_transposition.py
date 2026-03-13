#!/usr/bin/env python3
"""
Cipher:   Affine Transposition + Sub/Autokey
Family:   campaigns
Status:   active
Keyspace: affine T=(27x+21)%97 × 27kw × 3ciphers × 2alph × PT/CT-autokey = ~8K
Last run:
Best score:

K2 AFFINE TRANSPOSITION MODEL
------------------------------
K2 coordinates encode K4 constants. The affine map y = 27x+21 (mod 97)
connects K2 latitude values (38, 57) to longitude values (77, 8):
  27×38+21 ≡ 77 (mod 97)
  27×57+21 ≡ 8  (mod 97)
Parameters: 27 = K4 start column, 21 = ENE crib start.

Hypothesis: K4 uses an affine permutation as the transposition cipher:
  T(x) = (27x+21) mod 97  →  CT_perm[x] = CT[T(x)]

Then periodic/autokey is applied to CT_perm[0..96].
Cribs must appear at positions 21-33 (ENE) and 63-73 (BC) of PT.

NOTE: Affine SUBSTITUTION (letter mapping) was eliminated (9,312 keys).
This script tests affine TRANSPOSITION (position reordering) — genuinely new.
"""

import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET, CRIB_DICT,
)

# ── Constants ──────────────────────────────────────────────────────────────

CT_ORDS = [ord(c) - 65 for c in CT]
N = 97
A, B = 27, 21   # T(x) = (27x+21) mod 97

# Compute T and T^{-1}
T_FWD = [(A * x + B) % N for x in range(N)]   # T_FWD[x] → CT position for PT[x]

# Inverse: 27^{-1} mod 97 = 18 (since 27×18=486=5×97+1≡1)
A_INV = 18
assert (A * A_INV) % N == 1, "A_INV check failed"
T_INV = [(A_INV * (y - B)) % N for y in range(N)]   # T_INV[y] → PT position for CT[y]

# Permuted CT streams (two directions)
CT_PERM_FWD = [CT_ORDS[T_FWD[x]] for x in range(N)]  # read CT[T(x)] → gives PT[x]
CT_PERM_INV = [CT_ORDS[T_INV[y]] for y in range(N)]  # read CT[T^{-1}(y)] → different model

ALPHABETS = {
    "AZ": (ALPH, {c: i for i, c in enumerate(ALPH)}),
    "KA": (KRYPTOS_ALPHABET, {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}),
}

KEYWORDS = [
    "KRYPTOS", "KOMPASS", "DEFECTOR", "COLOPHON", "ABSCISSA",
    "PARALLAX", "VERDIGRIS", "SHADOW", "KRYPTA", "KOLOPHON",
    "PALIMPSEST", "CIPHER", "SECRET", "ENIGMA", "COMPASS",
    "BERLINCLOCK", "SANBORN", "SCHEIDT", "LANGLEY", "CLOCK",
    "EAST", "NORTH", "BERLIN", "POINT", "FIVE", "LODESTONE", "MAGNETIC",
]

# Cipher variants
def vig_dec(c, k): return (c - k) % 26
def beau_dec(c, k): return (k - c) % 26
def vbeau_dec(c, k): return (c + k) % 26
CIPHERS = [("Vig", vig_dec), ("Beau", beau_dec), ("VBeau", vbeau_dec)]

CRIB_LIST = sorted(CRIB_DICT.items())

def count_cribs(pt_ords):
    return sum(1 for pos, ch in CRIB_LIST if pos < len(pt_ords) and pt_ords[pos] == ord(ch) - 65)

def decrypt_periodic(ct_stream, kw_ords, dec_fn):
    klen = len(kw_ords)
    return [dec_fn(ct_stream[x], kw_ords[x % klen]) for x in range(N)]

def decrypt_pt_autokey(ct_stream, kw_ords, dec_fn):
    L = len(kw_ords)
    key = list(kw_ords)
    pt = []
    for x, c in enumerate(ct_stream):
        k = key[x] if x < L else pt[x - L]
        p = dec_fn(c, k)
        pt.append(p)
        key.append(p)
    return pt

def decrypt_ct_autokey(ct_stream, kw_ords, dec_fn):
    L = len(kw_ords)
    pt = []
    for x, c in enumerate(ct_stream):
        k = kw_ords[x] if x < L else ct_stream[x - L]
        p = dec_fn(c, k)
        pt.append(p)
    return pt

# ── Main ──────────────────────────────────────────────────────────────────

t0 = time.time()
best = 0
best_config = None
total = 0

print("=" * 70)
print("AFFINE K2 TRANSPOSITION: T(x)=(27x+21) mod 97")
print("=" * 70)
print(f"CT (97 chars): {CT}")
print(f"CT_PERM_FWD[0..9]: {''.join(chr(CT_PERM_FWD[x]+65) for x in range(10))}")
print(f"CT_PERM_INV[0..9]: {''.join(chr(CT_PERM_INV[x]+65) for x in range(10))}")
print(f"Cribs at positions 21-33 (ENE) and 63-73 (BC) of output PT")
print()

streams_to_test = [
    ("T_fwd", CT_PERM_FWD),   # PT[x] = sub(CT[T(x)])
    ("T_inv", CT_PERM_INV),   # PT[x] = sub(CT[T^{-1}(x)])
]

modes = [
    ("periodic",   decrypt_periodic),
    ("pt_autokey", decrypt_pt_autokey),
    ("ct_autokey", decrypt_ct_autokey),
]

for stream_name, ct_stream in streams_to_test:
    for mode_name, dec_fn_wrapper in modes:
        for kw in KEYWORDS:
            for alph_name, (alph_str, alph_idx) in ALPHABETS.items():
                try:
                    kw_ords = [alph_idx[c] for c in kw]
                except KeyError:
                    total += 1
                    continue
                for cipher_name, dec_fn in CIPHERS:
                    pt = dec_fn_wrapper(ct_stream, kw_ords, dec_fn)
                    hits = count_cribs(pt)
                    total += 1
                    if hits > best:
                        best = hits
                        pt_str = ''.join(chr(p + 65) for p in pt)
                        best_config = (stream_name, mode_name, kw, alph_name, cipher_name, pt_str)
                        print(f"NEW BEST: {hits}/24 | {stream_name}/{mode_name}/{kw}/{alph_name}/{cipher_name}")
                        print(f"  ENE: {pt_str[21:34]} (want EASTNORTHEAST)")
                        print(f"  BC:  {pt_str[63:74]} (want BERLINCLOCK)")
                        print(f"  PT: {pt_str}")
                        if hits >= 18:
                            print("*** SIGNAL — INVESTIGATE ***")

elapsed = time.time() - t0
print(f"\n{'=' * 70}")
print(f"Configs tested: {total}")
print(f"Elapsed: {elapsed:.2f}s")
print(f"Best: {best}/24")
if best_config:
    sn, mn, kw, an, cn, pt_str = best_config
    print(f"Config: stream={sn} mode={mn} kw={kw} alph={an} cipher={cn}")
    print(f"PT: {pt_str}")
    print(f"ENE: {pt_str[21:34]}")
    print(f"BC:  {pt_str[63:74]}")
print(f"{'=' * 70}")
if best >= 18:
    print("STATUS: SIGNAL")
elif best >= 6:
    print("STATUS: ABOVE NOISE")
else:
    print("STATUS: NOISE — Affine K2 transposition model: no signal")
