#!/usr/bin/env python3 -u
"""
Cipher:  Soviet three-step agent cipher analog
Family:  novel
Status:  exhausted
Keyspace: ~15 seeds x 50 chain lengths x 10 widths x 3 variants x 2 peel orders = ~45K configs
Last run:
Best score:

HYPOTHESIS (TICOM): Soviet-style three-step cipher:
  1. Chain addition key generation (lagged Fibonacci mod 10, converted to mod 26)
  2. Substitution (Vigenere/Beaufort/Variant Beaufort)
  3. Columnar transposition

This differs from periodic substitution because chain addition keys are
NON-PERIODIC and have IC near random — matching K4's observed keystream IC=0.029.

Chain addition: start with N-digit seed, compute d_new = (d[i] + d[i+1]) mod 10,
extend right indefinitely. Convert to mod 26 key by: k[i] = (2*d[2i] + d[2i+1]) mod 26
or k[i] = d[i] mod 26 (wrapping at 10).

Seeds derived from thematic keywords converted to digits via A=0..Z=25 mod 10.

Tests both peel orders:
  Model A: CT -> undo_trans -> chain_sub_decrypt -> PT
  Model B: CT -> chain_sub_decrypt -> undo_trans -> PT

All positions 0-indexed. Constants imported from kernel.
"""

import sys
import os
import json
import time
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, CRIB_DICT,
)
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free
from kryptos.kernel.transforms.transposition import (
    columnar_perm, invert_perm, apply_perm, keyword_to_order,
)

# ── Chain addition key generation ────────────────────────────────────────────

def chain_addition_digits(seed_digits, length):
    """Generate chain addition digit stream (lagged Fibonacci mod 10).

    Starting from seed, each new digit = (d[i] + d[i+1]) mod 10.
    """
    d = list(seed_digits)
    while len(d) < length + len(seed_digits):
        d.append((d[-len(seed_digits)] + d[-len(seed_digits)+1]) % 10)
    return d[:length]


def digits_to_key_mod26(digits, method="direct"):
    """Convert digit stream to mod-26 key values.

    Methods:
      direct: k[i] = digits[i] % 26 (only values 0-9)
      pair:   k[i] = (10*digits[2i] + digits[2i+1]) % 26
      triple: k[i] = (digits[i] + digits[i+1]*10) % 26
    """
    if method == "direct":
        return [d % 26 for d in digits]
    elif method == "pair":
        keys = []
        for i in range(0, len(digits) - 1, 2):
            keys.append((10 * digits[i] + digits[i+1]) % 26)
        return keys
    elif method == "triple":
        keys = []
        for i in range(len(digits) - 1):
            keys.append((digits[i] + digits[i+1] * 10) % 26)
        return keys
    return digits


def keyword_to_digits(keyword):
    """Convert keyword to digit sequence: letter -> (ord - 65) mod 10."""
    return [(ord(c) - 65) % 10 for c in keyword.upper() if c.isalpha()]


# ── Substitution ────────────────────────────────────────────────────────────

def decrypt_with_key(ct_str, key_values, variant="vigenere"):
    """Decrypt ciphertext with a numeric key sequence."""
    result = []
    klen = len(key_values)
    for i, c in enumerate(ct_str):
        ci = ALPH_IDX.get(c, -1)
        if ci < 0:
            result.append(c)
            continue
        k = key_values[i % klen]
        if variant == "vigenere":
            pi = (ci - k) % 26
        elif variant == "beaufort":
            pi = (k - ci) % 26
        else:  # var_beaufort
            pi = (ci + k) % 26
        result.append(ALPH[pi])
    return ''.join(result)


# ── Columnar transposition ──────────────────────────────────────────────────

def undo_columnar(ct_str, width, col_order):
    """Undo columnar transposition."""
    perm = columnar_perm(width, col_order, len(ct_str))
    inv = invert_perm(perm)
    return apply_perm(ct_str, inv)


# ── Scoring ─────────────────────────────────────────────────────────────────

ENE = "EASTNORTHEAST"
BCL = "BERLINCLOCK"

def quick_free_score(pt):
    s = 0
    if ENE in pt:
        s += 13
    if BCL in pt:
        s += 11
    return s


def quick_anchored_score(pt):
    s = 0
    if len(pt) >= 34:
        for i, ch in enumerate(ENE):
            if 21 + i < len(pt) and pt[21 + i] == ch:
                s += 1
    if len(pt) >= 74:
        for i, ch in enumerate(BCL):
            if 63 + i < len(pt) and pt[63 + i] == ch:
                s += 1
    return s


# ── Keywords / Seeds ────────────────────────────────────────────────────────

SEED_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "SHADOW",
    "BERLIN", "SCHEIDT", "SANBORN", "SEVEN", "CLOCK",
    "ENIGMA", "HAYDN", "NORMANDY", "ECLIPSE", "CARTER",
]

TRANS_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "SHADOW",
    "BERLIN", "SCHEIDT", "SANBORN",
]

WIDTHS = range(5, 15)
VARIANTS = ["vigenere", "beaufort", "var_beaufort"]
DIGIT_METHODS = ["direct", "pair", "triple"]


# ── Main attack ─────────────────────────────────────────────────────────────

def attack():
    start = time.time()
    results = []
    configs_tested = 0
    best_anchored = 0
    best_free = 0

    print("Soviet three-step agent cipher test")
    print(f"CT: {CT}")
    print(f"Seed keywords: {len(SEED_KEYWORDS)}")
    print(f"Trans keywords: {len(TRANS_KEYWORDS)}")
    print()

    for seed_kw in SEED_KEYWORDS:
        seed_digits = keyword_to_digits(seed_kw)
        if len(seed_digits) < 3:
            continue

        # Generate chain addition digits (enough for 200 key values)
        chain = chain_addition_digits(seed_digits, 400)

        for dm in DIGIT_METHODS:
            key_vals = digits_to_key_mod26(chain, method=dm)
            if len(key_vals) < CT_LEN:
                continue

            for variant in VARIANTS:
                # ── MODEL A: CT -> undo_trans -> chain_decrypt -> PT ──
                for trans_kw in TRANS_KEYWORDS:
                    for width in WIDTHS:
                        order = keyword_to_order(trans_kw, width)
                        if order is None:
                            continue

                        # Undo transposition first
                        inter = undo_columnar(CT, width, order)
                        # Then decrypt with chain key
                        pt = decrypt_with_key(inter, key_vals, variant)

                        configs_tested += 1
                        sa = quick_anchored_score(pt)
                        sf = quick_free_score(pt)

                        if sa > best_anchored:
                            best_anchored = sa
                            print(f"  BEST ANCHORED: {sa}/24 | A|seed={seed_kw}|dm={dm}|var={variant}|tw={trans_kw}|w={width}")
                            print(f"    PT: {pt[:60]}")

                        if sf > best_free:
                            best_free = sf
                            print(f"  BEST FREE: {sf}/24 | A|seed={seed_kw}|dm={dm}|var={variant}|tw={trans_kw}|w={width}")
                            print(f"    PT: {pt[:60]}")

                        if sa >= 10 or sf >= 11:
                            results.append({
                                'score_anchored': sa, 'score_free': sf,
                                'model': 'A', 'seed_kw': seed_kw,
                                'digit_method': dm, 'variant': variant,
                                'trans_kw': trans_kw, 'width': width,
                                'pt': pt,
                            })

                # ── MODEL B: CT -> chain_decrypt -> undo_trans -> PT ──
                # Decrypt first, then undo transposition
                inter_b = decrypt_with_key(CT, key_vals, variant)

                for trans_kw in TRANS_KEYWORDS:
                    for width in WIDTHS:
                        order = keyword_to_order(trans_kw, width)
                        if order is None:
                            continue

                        pt = undo_columnar(inter_b, width, order)
                        configs_tested += 1

                        sa = quick_anchored_score(pt)
                        sf = quick_free_score(pt)

                        if sa > best_anchored:
                            best_anchored = sa
                            print(f"  BEST ANCHORED: {sa}/24 | B|seed={seed_kw}|dm={dm}|var={variant}|tw={trans_kw}|w={width}")
                            print(f"    PT: {pt[:60]}")

                        if sf > best_free:
                            best_free = sf
                            print(f"  BEST FREE: {sf}/24 | B|seed={seed_kw}|dm={dm}|var={variant}|tw={trans_kw}|w={width}")
                            print(f"    PT: {pt[:60]}")

                        if sa >= 10 or sf >= 11:
                            results.append({
                                'score_anchored': sa, 'score_free': sf,
                                'model': 'B', 'seed_kw': seed_kw,
                                'digit_method': dm, 'variant': variant,
                                'trans_kw': trans_kw, 'width': width,
                                'pt': pt,
                            })

        print(f"  Seed {seed_kw} done, {configs_tested} configs, best_a={best_anchored} best_f={best_free}")

    elapsed = time.time() - start

    outpath = os.path.join(_ROOT, "results", f"soviet_threestep_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json")
    summary = {
        'script': 'e_soviet_threestep_01.py',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'configs_tested': configs_tested,
        'best_anchored': best_anchored,
        'best_free': best_free,
        'hits': len(results),
        'runtime_seconds': round(elapsed, 1),
        'results': results[:100],
    }
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"\n{'='*70}")
    print(f"SOVIET THREE-STEP AGENT CIPHER TEST COMPLETE")
    print(f"Configs tested: {configs_tested}")
    print(f"Best anchored: {best_anchored}/24")
    print(f"Best free: {best_free}/24")
    print(f"Hits: {len(results)}")
    print(f"Runtime: {elapsed:.1f}s")
    print(f"Results: {outpath}")
    if best_anchored < 10 and best_free < 11:
        print(f"Conclusion: NOISE — no signal detected")
    print(f"{'='*70}")


if __name__ == "__main__":
    attack()
