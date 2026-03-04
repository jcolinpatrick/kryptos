#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: transposition/columnar
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""Phase 3: Deep columnar search focusing on K3-derived approaches and
comprehensive small-width brute force with key alignment offsets.

Key insight: K3 is a known transposition cipher on the same sculpture.
If K3 and K4 share the same grid width (31), the K3 column order
(or a variation) might apply to K4.

Also: exhaustive width-9 through width-13 brute force (only keywords, not all perms).
And: all widths with all possible key alignment offsets.
"""
from __future__ import annotations

import itertools
import json
import math
import os
import sys
import time
from collections import defaultdict
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, N_CRIBS,
)
from kryptos.kernel.transforms.transposition import (
    invert_perm, apply_perm, validate_perm,
)
from kryptos.kernel.transforms.vigenere import CipherVariant

# ── Quadgrams ────────────────────────────────────────────────────────────
QUADGRAM_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
with open(QUADGRAM_PATH) as f:
    QUADGRAMS = json.load(f)
QUADGRAM_FLOOR = min(QUADGRAMS.values()) - 1.0

def qg_score(text: str) -> float:
    if len(text) < 4:
        return QUADGRAM_FLOOR
    total = sum(QUADGRAMS.get(text[i:i+4], QUADGRAM_FLOOR) for i in range(len(text)-3))
    return total / (len(text) - 3)

# ── Cribs ────────────────────────────────────────────────────────────────
CRIB_STRINGS = ["EASTNORTHEAST", "BERLINCLOCK"]

def check_cribs_anywhere(text: str) -> List[Tuple[str, int]]:
    found = []
    for crib in CRIB_STRINGS:
        idx = text.find(crib)
        while idx != -1:
            found.append((crib, idx))
            idx = text.find(crib, idx + 1)
    return found

def check_canonical_cribs(text: str) -> int:
    return sum(1 for pos, ch in CRIB_DICT.items() if pos < len(text) and text[pos] == ch)

# ── Decryption ──────────────────────────────────────────────────────────
def decrypt(ct_text: str, keyword: str, variant: CipherVariant, alphabet: str) -> str:
    idx = {c: i for i, c in enumerate(alphabet)}
    key = [idx[c] for c in keyword.upper()]
    klen = len(key)
    if variant == CipherVariant.VIGENERE:
        fn = lambda c, k: (c - k) % 26
    elif variant == CipherVariant.BEAUFORT:
        fn = lambda c, k: (k - c) % 26
    else:
        fn = lambda c, k: (c + k) % 26
    return "".join(alphabet[fn(idx[ch], key[i % klen])] for i, ch in enumerate(ct_text))

def decrypt_with_offset(ct_text: str, keyword: str, offset: int, variant: CipherVariant, alphabet: str) -> str:
    """Decrypt with key starting at given offset position."""
    idx = {c: i for i, c in enumerate(alphabet)}
    key = [idx[c] for c in keyword.upper()]
    klen = len(key)
    if variant == CipherVariant.VIGENERE:
        fn = lambda c, k: (c - k) % 26
    elif variant == CipherVariant.BEAUFORT:
        fn = lambda c, k: (k - c) % 26
    else:
        fn = lambda c, k: (c + k) % 26
    return "".join(alphabet[fn(idx[ch], key[(i + offset) % klen])] for i, ch in enumerate(ct_text))

# ── Columnar decrypt ───────────────────────────────────────────────────
def columnar_decrypt(ct_text: str, width: int, col_order: List[int]) -> str:
    length = len(ct_text)
    nrows = math.ceil(length / width)
    remainder = length % width
    col_lens = {}
    for c in range(width):
        col_lens[c] = nrows if (remainder == 0 or c < remainder) else nrows - 1
    grid = {}
    ct_idx = 0
    for rank in range(width):
        col_idx = col_order.index(rank)
        for r in range(col_lens[col_idx]):
            grid[(r, col_idx)] = ct_text[ct_idx]
            ct_idx += 1
    return "".join(grid[(r, c)] for r in range(nrows) for c in range(width) if (r, c) in grid)

def kw_to_order(keyword: str, width: int) -> List[int]:
    kw = keyword.upper()
    if len(kw) > width:
        kw = kw[:width]
    while len(kw) < width:
        used = set(kw)
        for c in ALPH:
            if c not in used:
                kw += c
                used.add(c)
                if len(kw) == width:
                    break
        if len(kw) < width:
            kw += ALPH[len(kw) % 26]
    indexed = [(ch, i) for i, ch in enumerate(kw)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * width
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return order

# ── Tracking ────────────────────────────────────────────────────────────
best_qg = -999.0
best_cribs = 0
crib_hits = []
interesting = []
total = 0

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]
ALPHABETS = {"AZ": ALPH, "KA": KRYPTOS_ALPHABET}
VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

def test(desc: str, text: str):
    global best_qg, best_cribs, total
    total += 1
    qg = qg_score(text)
    cribs_at = check_cribs_anywhere(text)
    canon = check_canonical_cribs(text)
    if qg > best_qg:
        best_qg = qg
    if canon > best_cribs:
        best_cribs = canon
    if cribs_at:
        crib_hits.append({"desc": desc, "text": text, "cribs": cribs_at, "qg": qg})
        print(f"*** CRIB HIT *** {desc}: {text[:60]}... cribs={cribs_at}")
    if qg > -6.0 or canon >= 10:
        interesting.append({"desc": desc, "text": text, "qg": qg, "canon": canon})


def test_with_all_decrypts(desc: str, text: str):
    """Test text + all keyword/variant/alphabet combos with all key offsets."""
    test(f"{desc}/identity", text)
    for kw in KEYWORDS:
        klen = len(kw)
        for variant in VARIANTS:
            for aname, alph in ALPHABETS.items():
                # Standard offset = 0
                dec = decrypt(text, kw, variant, alph)
                test(f"{desc}/{variant.value}/{kw}/{aname}", dec)
                # Try all key offsets
                for off in range(1, klen):
                    dec_off = decrypt_with_offset(text, kw, off, variant, alph)
                    test(f"{desc}/{variant.value}/{kw}/{aname}/off{off}", dec_off)


def main():
    global best_qg, best_cribs, total, crib_hits, interesting
    t0 = time.time()
    print("="*70)
    print("PHASE 3: DEEP COLUMNAR SEARCH WITH KEY OFFSETS")
    print(f"CT: {CT}")
    print("="*70)

    # ── A: Comprehensive width sweep with key offsets ─────────────────
    print("\n--- A: Width sweep with keyword column orders + key offsets ---")
    for width in range(4, 50):
        for kw in KEYWORDS:
            if len(kw) > width:
                kw_col = kw[:width]
            else:
                kw_col = kw
            order = kw_to_order(kw_col, width)
            unscr = columnar_decrypt(CT, width, order)
            test_with_all_decrypts(f"col{width}/{kw_col}", unscr)

    print(f"  After width sweep: {total} tested, best QG={best_qg:.4f}")

    # ── B: Brute force width 9-10 column permutations ─────────────────
    # 9! = 362880, 10! = 3628800 (too many for full decrypt)
    # For width 9: test all column perms with quick qg check, then full decrypt on promising ones
    print("\n--- B: Width 9 brute force (362,880 perms x quick check) ---")
    for col_perm in itertools.permutations(range(9)):
        col_order = list(col_perm)
        unscr = columnar_decrypt(CT, 9, col_order)
        total += 1
        qg = qg_score(unscr)
        cribs_at = check_cribs_anywhere(unscr)
        if cribs_at:
            print(f"  *** RAW CRIB HIT w9 {col_perm}: {unscr[:60]}...")
            crib_hits.append({"desc": f"brute_col9/{col_perm}/identity", "text": unscr})

        if qg > best_qg:
            best_qg = qg

        # Full decrypt only if raw text is promising
        if qg > -7.0 or cribs_at:
            test_with_all_decrypts(f"brute_col9/{col_perm}", unscr)

        # Also try as encryption perm (inverse)
        # Build the encryption perm
        nrows = math.ceil(CT_LEN / 9)
        remainder = CT_LEN % 9
        col_lens = {c: (nrows if (remainder == 0 or c < remainder) else nrows - 1) for c in range(9)}
        enc_positions = []
        for rank in range(9):
            col_idx = col_order.index(rank)
            for r in range(col_lens[col_idx]):
                pos = r * 9 + col_idx
                if pos < CT_LEN:
                    enc_positions.append(pos)
        if len(enc_positions) == CT_LEN and validate_perm(enc_positions, CT_LEN):
            inv = invert_perm(enc_positions)
            unscr_inv = apply_perm(CT, inv)
            total += 1
            qg_inv = qg_score(unscr_inv)
            cribs_inv = check_cribs_anywhere(unscr_inv)
            if qg_inv > best_qg:
                best_qg = qg_inv
            if cribs_inv:
                print(f"  *** RAW CRIB HIT w9_inv {col_perm}: {unscr_inv[:60]}...")
                crib_hits.append({"desc": f"brute_col9_inv/{col_perm}/identity", "text": unscr_inv})
            if qg_inv > -7.0 or cribs_inv:
                test_with_all_decrypts(f"brute_col9_inv/{col_perm}", unscr_inv)

    print(f"  After w9 brute: {total} tested, best QG={best_qg:.4f}")

    # ── C: Width 10 with PALIMPSEST keyword permutations ──────────────
    # PALIMPSEST has 10 letters. Instead of all 10!, try variations of PALIMPSEST ordering
    print("\n--- C: Width 10 PALIMPSEST variations ---")
    base_kw = "PALIMPSEST"
    base_order = kw_to_order(base_kw, 10)

    # Try all cyclic rotations of the base keyword
    for rot in range(10):
        rotated = base_kw[rot:] + base_kw[:rot]
        order = kw_to_order(rotated, 10)
        unscr = columnar_decrypt(CT, 10, order)
        test_with_all_decrypts(f"col10/PAL_rot{rot}", unscr)

    # Try reversals
    rev_kw = base_kw[::-1]
    order_rev = kw_to_order(rev_kw, 10)
    unscr_rev = columnar_decrypt(CT, 10, order_rev)
    test_with_all_decrypts("col10/PAL_rev", unscr_rev)

    # ── D: Width-31 with K3 connection ─────────────────────────────────
    print("\n--- D: Width-31 K3-inspired approaches ---")

    # K3 ciphertext (from the sculpture, positions 432-767)
    K3_CT = (
        "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA"
        "CHTNREYULDSLLSLLNOHSNOSMRWXMNE"
        "TPRNGATIHNRARPESLNNELEBLPIIACAE"
        "WMTWNDITEENRAHCTENEUDRETNHAEOE"
        "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR"
        "EIFTBRSPAMHHEWENATAMATEGYEERLB"
        "TEEFOASFIOTUETUAEOTOARMAEERTNRTI"
        "BSEDDNIAAHTTMSTEWPIEROAGRIEW"
        "FEBAECTDDHILCEIHSITEGOEAOSDDRYDL"
        "ORITRKLMLEHAGTDHARDPNEOHMGFMFEUHEECDMRIPFEIMEHNLKSTTRTVDOH"
    )
    # Clean up to just the ciphertext characters
    K3_CT = ''.join(c for c in K3_CT if c.isalpha())

    # K3 plaintext (known)
    K3_PT = (
        "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHE"
        "LOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINY"
        "BREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLE"
        "IINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBER"
        "CAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHIN"
        "EMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"
    )
    K3_PT = ''.join(c for c in K3_PT if c.isalpha()).upper()

    print(f"  K3 CT length: {len(K3_CT)}, K3 PT length: {len(K3_PT)}")

    # If K3 used columnar transposition on width-31, we could potentially
    # recover the column order from the known PT<->CT mapping
    # K3 length = 336, width 31: 336/31 = 10.84 -> 11 rows

    # Try to find if K3 CT -> PT is a pure columnar transposition at width 31
    if len(K3_CT) >= 336 and len(K3_PT) >= 336:
        k3_ct_use = K3_CT[:336]
        k3_pt_use = K3_PT[:336]

        # For each column permutation, check if columnar decrypt of K3_CT gives K3_PT
        # We can't brute force 31! but we can try to reverse-engineer the column order
        # from the known mapping

        # Build the position mapping: which CT position maps to which PT position?
        # If it's a columnar transposition, then the mapping follows a specific pattern

        # Actually, K3 uses Vigenere + transposition. Let's just see if any simple
        # columnar ordering of K4 combined with the K3 Vigenere key works.

        # K3 key is KRYPTOS for the Vigenere part
        # Let's try: apply K3's Vigenere decryption to K4 first, then columnar
        for variant in VARIANTS:
            for aname, alph in ALPHABETS.items():
                dec_first = decrypt(CT, "KRYPTOS", variant, alph)
                # Then try columnar on the decrypted text
                for width in [7, 8, 10, 13, 31]:
                    for kw in KEYWORDS:
                        order = kw_to_order(kw, width)
                        unscr = columnar_decrypt(dec_first, width, order)
                        total += 1
                        qg = qg_score(unscr)
                        ca = check_cribs_anywhere(unscr)
                        if qg > best_qg:
                            best_qg = qg
                        if ca:
                            crib_hits.append({"desc": f"vig_then_col/{variant.value}/{aname}/col{width}/{kw}", "text": unscr})
                            print(f"  *** CRIB HIT: vig_then_col {variant.value}/{aname} col{width}/{kw}")

    # ── E: Width-31, try all 31 cyclic shifts of column reading ────────
    print("\n--- E: Width-31 cyclic column shifts ---")
    for shift in range(31):
        # Column order: read columns starting at 'shift'
        order = [(i + shift) % 31 for i in range(31)]
        unscr = columnar_decrypt(CT, 31, order)
        test_with_all_decrypts(f"col31_cyclic/shift={shift}", unscr)

    # ── F: Mixed row/column approach on width-31 ──────────────────────
    print("\n--- F: Mixed approaches on width-31 ---")
    nrows_31 = math.ceil(CT_LEN / 31)  # 4 rows

    # Try all 4! = 24 row permutations combined with keyword column orders
    for row_perm in itertools.permutations(range(nrows_31)):
        # Build row-permuted text
        chunks = []
        for target_row in range(nrows_31):
            src_row = row_perm[target_row]
            start = src_row * 31
            end = min(start + 31, CT_LEN)
            chunks.append(CT[start:end])
        row_permuted = "".join(chunks)

        if len(row_permuted) != CT_LEN:
            continue

        # Then apply columnar with keywords
        for kw in KEYWORDS:
            order = kw_to_order(kw, 31)
            unscr = columnar_decrypt(row_permuted, 31, order)
            test_with_all_decrypts(f"rowperm31/{row_perm}/col/{kw}", unscr)

    elapsed = time.time() - t0

    # ── Summary ──────────────────────────────────────────────────────────
    print("\n" + "="*70)
    print("PHASE 3 SUMMARY")
    print("="*70)
    print(f"Total tested: {total}")
    print(f"Time: {elapsed:.1f}s")
    print(f"Best QG: {best_qg:.4f}")
    print(f"Best canonical cribs: {best_cribs}/24")
    print(f"Crib hits: {len(crib_hits)}")

    if crib_hits:
        print("\nCRIB HITS:")
        for h in crib_hits:
            print(f"  {h['desc']}: {h['text'][:70]}")

    if interesting:
        sorted_int = sorted(interesting, key=lambda x: x['qg'], reverse=True)
        print(f"\nTop 15 interesting (QG > -6.0 or canon >= 10):")
        for i, r in enumerate(sorted_int[:15]):
            print(f"  {i+1}. QG={r['qg']:.4f} canon={r['canon']}/24 | {r['desc']}")
            print(f"     {r['text'][:80]}")

    outfile = os.path.join(os.path.dirname(__file__), '..', 'kbot_results', 'grid31_columnar_phase3_results.json')
    os.makedirs(os.path.dirname(outfile), exist_ok=True)
    save_data = {
        "total_tested": total,
        "elapsed": elapsed,
        "best_qg": best_qg,
        "best_cribs": best_cribs,
        "crib_hits": crib_hits,
        "interesting": sorted(interesting, key=lambda x: x['qg'], reverse=True)[:30] if interesting else [],
    }
    with open(outfile, 'w') as f:
        json.dump(save_data, f, indent=2, default=str)
    print(f"\nSaved to {outfile}")


if __name__ == "__main__":
    main()
