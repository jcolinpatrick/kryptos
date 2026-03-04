#!/usr/bin/env python3
"""
Cipher: K3-method extension
Family: k3_continuity
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-ANTIPODES-03: K3→K4 Method Continuity

HYPOTHESIS: K3→K4 is seamless on Antipodes (the ? is K3 prose content, not a
delimiter). This suggests they share an encryption method. K3 uses columnar
transposition + Vigenère with keyword KRYPTOS. K4 may use the SAME method
with the key continuing from where K3 ended.

WHY ANTIPODES: The seamless K3→K4 transition is NEW information. Prior work
tested columnar+Vig broadly, but NOT the specific hypothesis of K3-method
continuity with correct key offset logic.

METHOD:
1. K3's Vigenère key = KRYPTOS (length 7). After 336 K3 chars, offset = 336 mod 7 = 0.
   Test all 7 offsets in case of off-by-one.
2. Test K3's exact grid width + nearby widths (7-14) with all column orderings
3. Extended keywords: KRYPTOSPALIMPSEST, KRYPTOSABSCISSA, etc.
4. Also test K3 plaintext tail as running key for K4
5. Test 3 cipher variants (Vigenère/Beaufort/Variant Beaufort)

COST: ~5040 orderings × 7 offsets × 8 widths × 3 variants × 5 keywords ≈ 4.2M. ~2 min.
"""

import json
import os
import sys
import time
import itertools
from typing import List, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, N_CRIBS,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, invert_perm, apply_perm, keyword_to_order, validate_perm,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.constraints.bean import verify_bean_simple
from kryptos.kernel.alphabet import Alphabet, KA, AZ

# ── K3 known values ──────────────────────────────────────────────────────

# K3 plaintext (public fact)
K3_PLAINTEXT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHAT"
    "ENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITH"
    "TREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFT"
    "HANDCORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTED"
    "THECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHE"
    "CHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILS"
    "OFTHEROOMWITHINEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"
)

# K3 key = KRYPTOS, applied with KA alphabet Vigenère
K3_KEY_WORD = "KRYPTOS"
K3_KEY_LEN = len(K3_KEY_WORD)  # 7
K3_CT_LEN = 336

# Keywords to test (the key for K4's substitution layer)
KEYWORDS = [
    "KRYPTOS",
    "PALIMPSEST",
    "ABSCISSA",
    "KRYPTOSPALIMPSEST",
    "KRYPTOSABSCISSA",
    "PALIMPSESTKRYPTOS",
    "ABSCISSAKRYPTOS",
    "BERLIN",
    "SANBORN",
    "SCHEIDT",
    "SHADOW",
    "ENIGMA",
]

# K3 plaintext tail (last 97 chars) as potential running key
K3_PT_TAIL_RAW = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFJPASSAGEDEBABORETURNST"
    "OTHEEARLIESTTASKWASENTALANTSANDHOWTESIDWALLSITTWASFORCED"
    "HEWALLSLOWLYWERECAVINGINTHEYWEREONLYABLETONOTREADITVERYC"
    "LEARLYWASTHEREACHAROOMBEYONDTHECHAMBERQCANYOUSEEANYTHINGQ"
).upper()
# Use last 97+ characters
K3_PT_TAIL = K3_PT_TAIL_RAW[-120:] if len(K3_PT_TAIL_RAW) >= 120 else K3_PT_TAIL_RAW

# Carter book narrative text around the K3 passage
CARTER_TEXT = (
    "CANYOUSEEANYTHINGQ"  # Last part of K3
)


def generate_column_orderings(width: int, max_orderings: int = 5040):
    if width <= 7:
        yield from itertools.permutations(range(width))
    else:
        seen = set()
        for kw in KEYWORDS + ["EASTNORTHEAST", "BERLINCLOCK", "CARTER", "EGYPT",
                               "CIPHER", "HILL", "QUARTZ", "CLOCK", "MATRIX"]:
            order = keyword_to_order(kw, width)
            if order is not None and order not in seen:
                seen.add(order)
                yield order
        import random
        rng = random.Random(42)
        attempts = 0
        while len(seen) < max_orderings and attempts < max_orderings * 5:
            perm_list = list(range(width))
            rng.shuffle(perm_list)
            t = tuple(perm_list)
            if t not in seen:
                seen.add(t)
                yield t
            attempts += 1


def make_key_numeric(keyword: str, offset: int = 0) -> List[int]:
    """Convert keyword to numeric key starting at given offset.
    Uses standard A=0 numbering."""
    kw_nums = [ord(c) - 65 for c in keyword.upper()]
    klen = len(kw_nums)
    # Return 97 key values starting at offset
    return [kw_nums[(offset + i) % klen] for i in range(CT_LEN)]


def make_key_numeric_ka(keyword: str, offset: int = 0) -> List[int]:
    """Convert keyword to numeric key using KA alphabet numbering."""
    ka_idx = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
    kw_nums = [ka_idx[c] for c in keyword.upper()]
    klen = len(kw_nums)
    return [kw_nums[(offset + i) % klen] for i in range(CT_LEN)]


def text_to_key(text: str, start: int = 0) -> List[int]:
    """Convert text to numeric key (A=0)."""
    return [ord(c) - 65 for c in text[start:start+CT_LEN].upper()]


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-ANTIPODES-03: K3→K4 Method Continuity")
    print("=" * 70)

    best_score = 0
    best_result = None
    total_configs = 0
    above_noise = []

    variants = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

    # ── Phase 1: Columnar transposition + periodic key with offset ────────
    print("\n--- Phase 1: Columnar transposition + periodic key (K3 continuation) ---")

    for keyword in KEYWORDS:
        for width in range(6, 15):
            for col_order in generate_column_orderings(width):
                perm = columnar_perm(width, col_order, CT_LEN)
                if not validate_perm(perm, CT_LEN):
                    continue
                inv_p = invert_perm(perm)
                intermediate = apply_perm(CT, inv_p)

                for variant in variants:
                    for offset in range(len(keyword)):
                        total_configs += 1

                        # Try both AZ and KA numbering
                        for numbering, make_key in [("AZ", make_key_numeric),
                                                      ("KA", make_key_numeric_ka)]:
                            key = make_key(keyword, offset)
                            pt = decrypt_text(intermediate, key, variant)
                            sc = score_cribs(pt)

                            if sc > best_score:
                                best_score = sc
                                best_result = {
                                    "phase": 1,
                                    "keyword": keyword,
                                    "width": width,
                                    "col_order": list(col_order)[:10],
                                    "variant": variant.value,
                                    "offset": offset,
                                    "numbering": numbering,
                                    "plaintext": pt,
                                    "crib_score": sc,
                                }
                                if sc > NOISE_FLOOR:
                                    print(f"NEW BEST: {sc}/24, kw={keyword}, w={width}, "
                                          f"off={offset}, {variant.value}, {numbering}")
                                    if sc >= STORE_THRESHOLD:
                                        print(f"  PT: {pt}")

                            if sc > NOISE_FLOOR:
                                above_noise.append({
                                    "phase": 1,
                                    "keyword": keyword,
                                    "width": width,
                                    "variant": variant.value,
                                    "offset": offset,
                                    "numbering": numbering,
                                    "crib_score": sc,
                                })

        print(f"  Keyword '{keyword}': {total_configs:,} configs so far, best={best_score}")

    # ── Phase 2: Running key from K3 plaintext tail ──────────────────────
    print("\n--- Phase 2: K3 plaintext tail as running key ---")

    # Use various offsets into K3 plaintext
    k3_full = K3_PT_TAIL_RAW
    max_offset = max(0, len(k3_full) - CT_LEN)

    for start in range(max_offset + 1):
        if start + CT_LEN > len(k3_full):
            break
        key = text_to_key(k3_full, start)
        if len(key) < CT_LEN:
            key = key + [0] * (CT_LEN - len(key))

        for variant in variants:
            # Direct (no transposition)
            total_configs += 1
            pt = decrypt_text(CT, key, variant)
            sc = score_cribs(pt)
            if sc > best_score:
                best_score = sc
                best_result = {
                    "phase": 2,
                    "key_source": "K3_PT_tail",
                    "start_offset": start,
                    "variant": variant.value,
                    "plaintext": pt,
                    "crib_score": sc,
                }
                if sc > NOISE_FLOOR:
                    print(f"NEW BEST: {sc}/24, K3 tail offset={start}, {variant.value}")

            if sc > NOISE_FLOOR:
                above_noise.append({
                    "phase": 2,
                    "key_source": "K3_PT_tail",
                    "start_offset": start,
                    "variant": variant.value,
                    "crib_score": sc,
                })

            # With transposition
            for width in [7, 8, 9, 10, 11, 12]:
                for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                    order = keyword_to_order(kw, width)
                    if order is None:
                        continue
                    perm = columnar_perm(width, order, CT_LEN)
                    inv_p = invert_perm(perm)
                    intermediate = apply_perm(CT, inv_p)

                    total_configs += 1
                    pt = decrypt_text(intermediate, key, variant)
                    sc = score_cribs(pt)
                    if sc > best_score:
                        best_score = sc
                        best_result = {
                            "phase": 2,
                            "key_source": "K3_PT_tail",
                            "start_offset": start,
                            "width": width,
                            "trans_keyword": kw,
                            "variant": variant.value,
                            "plaintext": pt,
                            "crib_score": sc,
                        }
                        if sc > NOISE_FLOOR:
                            print(f"NEW BEST: {sc}/24, K3 tail+trans, off={start}, "
                                  f"w={width}, kw={kw}, {variant.value}")

    # ── Phase 3: Autokey from K3 tail ────────────────────────────────────
    print("\n--- Phase 3: Autokey from K3 plaintext tail ---")

    # PT-autokey: key[i] = PT[i-1] for i > seed_len
    seed_lengths = [1, 3, 5, 7, 13]
    for seed_len in seed_lengths:
        for seed_start in range(max(1, len(k3_full) - seed_len - 5),
                                 min(len(k3_full), len(k3_full) + 1)):
            if seed_start + seed_len > len(k3_full):
                continue
            seed = [ord(c) - 65 for c in k3_full[seed_start:seed_start+seed_len]]

            for variant in variants:
                total_configs += 1
                # PT-autokey decrypt
                key = list(seed)
                pt_chars = []
                decrypt_fn = {
                    CipherVariant.VIGENERE: lambda c, k: (c - k) % 26,
                    CipherVariant.BEAUFORT: lambda c, k: (k - c) % 26,
                    CipherVariant.VAR_BEAUFORT: lambda c, k: (c + k) % 26,
                }[variant]

                for i in range(CT_LEN):
                    c = ord(CT[i]) - 65
                    if i < len(key):
                        k = key[i]
                    else:
                        k = pt_chars[-1]  # PT-autokey: use previous PT char
                    p = decrypt_fn(c, k)
                    pt_chars.append(p)

                pt = "".join(chr(p + 65) for p in pt_chars)
                sc = score_cribs(pt)
                if sc > best_score:
                    best_score = sc
                    best_result = {
                        "phase": 3,
                        "key_source": "autokey_K3_tail",
                        "seed_start": seed_start,
                        "seed_len": seed_len,
                        "variant": variant.value,
                        "plaintext": pt,
                        "crib_score": sc,
                    }
                    if sc > NOISE_FLOOR:
                        print(f"NEW BEST: {sc}/24, autokey seed_start={seed_start}, "
                              f"seed_len={seed_len}, {variant.value}")

                if sc > NOISE_FLOOR:
                    above_noise.append({
                        "phase": 3,
                        "variant": variant.value,
                        "seed_start": seed_start,
                        "seed_len": seed_len,
                        "crib_score": sc,
                    })

    elapsed = time.time() - t0

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total configs tested: {total_configs:,}")
    print(f"Best crib score: {best_score}/24")
    if best_result:
        print(f"Best config: phase={best_result.get('phase')}")
        for k, v in best_result.items():
            if k not in ('plaintext',):
                print(f"  {k}: {v}")
        if best_score >= STORE_THRESHOLD:
            print(f"Best plaintext: {best_result.get('plaintext')}")
    print(f"Above-noise results: {len(above_noise)}")
    print(f"Elapsed: {elapsed:.1f}s")

    # ── Write results ─────────────────────────────────────────────────────
    outdir = os.path.join(os.path.dirname(__file__), '..', 'results', 'e_antipodes_03')
    os.makedirs(outdir, exist_ok=True)
    summary = {
        "experiment": "E-ANTIPODES-03",
        "hypothesis": "K3→K4 method continuity (columnar + Vigenère with key offset)",
        "total_configs": total_configs,
        "best_score": best_score,
        "best_result": best_result,
        "above_noise_count": len(above_noise),
        "elapsed_seconds": elapsed,
    }
    with open(os.path.join(outdir, 'summary.json'), 'w') as f:
        json.dump(summary, f, indent=2)
    if above_noise:
        above_noise.sort(key=lambda x: x["crib_score"], reverse=True)
        with open(os.path.join(outdir, 'above_noise.json'), 'w') as f:
            json.dump(above_noise[:100], f, indent=2)

    print(f"\nResults written to {outdir}/")
    if best_score <= NOISE_FLOOR:
        print("\nCONCLUSION: NOISE — K3→K4 continuity hypothesis not supported.")
    elif best_score < STORE_THRESHOLD:
        print(f"\nCONCLUSION: Low signal ({best_score}/24), likely noise.")
    else:
        print(f"\nCONCLUSION: SIGNAL detected ({best_score}/24) — investigate!")


if __name__ == "__main__":
    main()
