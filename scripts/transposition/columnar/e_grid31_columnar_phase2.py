#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: transposition/columnar
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""Phase 2: Extended columnar transposition search for K4.

Phase 1 tested 2.6M configs with no crib hits. Phase 2 extends with:
1. Columnar with ALL keyword lengths extended to width-31 (padding with remaining alpha)
2. Combination: columnar unscramble + shifted key application
3. Wider brute-force on promising small widths with full decryption sweeps
4. Column-pair swaps on width-31
5. Route ciphers (column-major write, row-major read and vice versa)
6. K3-style transposition (if K3 uses width-31 columnar, what column order?)
"""
from __future__ import annotations

import itertools
import json
import math
import os
import sys
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_WORDS, CRIB_DICT, N_CRIBS, CRIB_POSITIONS,
)
from kryptos.kernel.transforms.transposition import (
    invert_perm, apply_perm, validate_perm,
    columnar_perm, keyword_to_order, myszkowski_perm,
)
from kryptos.kernel.transforms.vigenere import CipherVariant


# ── Load quadgrams ──────────────────────────────────────────────────────────
QUADGRAM_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
QUADGRAMS: Dict[str, float] = {}
QUADGRAM_FLOOR: float = -10.0

def load_quadgrams():
    global QUADGRAMS, QUADGRAM_FLOOR
    with open(QUADGRAM_PATH) as f:
        QUADGRAMS = json.load(f)
    if QUADGRAMS:
        QUADGRAM_FLOOR = min(QUADGRAMS.values()) - 1.0

load_quadgrams()


def quadgram_score(text: str) -> float:
    if len(text) < 4:
        return QUADGRAM_FLOOR
    total = 0.0
    count = 0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        total += QUADGRAMS.get(qg, QUADGRAM_FLOOR)
        count += 1
    return total / count if count > 0 else QUADGRAM_FLOOR


CRIB_STRINGS = ["EASTNORTHEAST", "BERLINCLOCK"]

def check_any_position_cribs(text: str) -> List[Tuple[str, int]]:
    found = []
    for crib in CRIB_STRINGS:
        for i in range(len(text) - len(crib) + 1):
            if text[i:i+len(crib)] == crib:
                found.append((crib, i))
    return found


def check_primary_cribs(text: str) -> int:
    count = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(text) and text[pos] == ch:
            count += 1
    return count


def generate_keyword_column_order(keyword: str, width: int) -> List[int]:
    kw = keyword.upper()
    if len(kw) > width:
        kw = kw[:width]
    if len(kw) < width:
        used = set(kw)
        for c in ALPH:
            if c not in used:
                kw += c
                used.add(c)
                if len(kw) == width:
                    break
    # If still short (keyword had repeats), add duplicates
    while len(kw) < width:
        kw += ALPH[len(kw) % 26]
    indexed = [(ch, i) for i, ch in enumerate(kw)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * width
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return order


def columnar_decrypt(ct_text: str, width: int, col_order: List[int]) -> str:
    length = len(ct_text)
    nrows = math.ceil(length / width)
    remainder = length % width
    if remainder == 0:
        col_lens = {c: nrows for c in range(width)}
    else:
        col_lens = {}
        for c in range(width):
            col_lens[c] = nrows if c < remainder else nrows - 1
    grid = {}
    ct_idx = 0
    for rank in range(width):
        col_idx = col_order.index(rank)
        clen = col_lens[col_idx]
        for r in range(clen):
            grid[(r, col_idx)] = ct_text[ct_idx]
            ct_idx += 1
    result = []
    for r in range(nrows):
        for c in range(width):
            if (r, c) in grid:
                result.append(grid[(r, c)])
    return "".join(result)


def decrypt_with_config(ct_text: str, keyword: str, variant: CipherVariant, alphabet: str) -> str:
    idx = {c: i for i, c in enumerate(alphabet)}
    key = [idx[c] for c in keyword.upper()]
    klen = len(key)
    if variant == CipherVariant.VIGENERE:
        fn = lambda c, k: (c - k) % 26
    elif variant == CipherVariant.BEAUFORT:
        fn = lambda c, k: (k - c) % 26
    else:
        fn = lambda c, k: (c + k) % 26
    result = []
    for i, ch in enumerate(ct_text):
        c_val = idx[ch]
        k_val = key[i % klen]
        p_val = fn(c_val, k_val)
        result.append(alphabet[p_val])
    return "".join(result)


KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]
ALPHABETS = {"AZ": ALPH, "KA": KRYPTOS_ALPHABET}
VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

# Results
best_qg = -999.0
best_cribs = 0
crib_hits = []
interesting = []
total_tested = 0


def test_candidate(desc: str, text: str):
    global best_qg, best_cribs, total_tested, crib_hits, interesting

    # Test identity
    total_tested += 1
    qg = quadgram_score(text)
    any_cribs = check_any_position_cribs(text)
    canon = check_primary_cribs(text)

    if qg > best_qg:
        best_qg = qg
    if canon > best_cribs:
        best_cribs = canon

    if any_cribs:
        crib_hits.append({"desc": desc, "decrypt": "identity", "text": text, "cribs": any_cribs, "qg": qg})
        print(f"*** CRIB HIT *** {desc} identity: {text[:60]}...")

    if qg > -6.0 or canon >= 10:
        interesting.append({"desc": desc, "decrypt": "identity", "text": text, "qg": qg, "canon": canon})

    # Decrypt with keywords
    for kw in KEYWORDS:
        for variant in VARIANTS:
            for aname, alph in ALPHABETS.items():
                total_tested += 1
                try:
                    dec = decrypt_with_config(text, kw, variant, alph)
                except Exception:
                    continue
                qg = quadgram_score(dec)
                any_cribs = check_any_position_cribs(dec)
                canon = check_primary_cribs(dec)

                if qg > best_qg:
                    best_qg = qg
                if canon > best_cribs:
                    best_cribs = canon

                ddesc = f"{variant.value}/{kw}/{aname}"
                if any_cribs:
                    crib_hits.append({"desc": desc, "decrypt": ddesc, "text": dec, "cribs": any_cribs, "qg": qg})
                    print(f"*** CRIB HIT *** {desc} {ddesc}: {dec[:60]}...")

                if qg > -6.0 or canon >= 10:
                    interesting.append({"desc": desc, "decrypt": ddesc, "text": dec, "qg": qg, "canon": canon})


def main():
    global total_tested
    t0 = time.time()

    print("="*70)
    print("PHASE 2: EXTENDED COLUMNAR TRANSPOSITION SEARCH FOR K4")
    print(f"CT: {CT}")
    print(f"Length: {CT_LEN}")
    print("="*70)

    # ── Strategy A: Width-31 with all keywords padded to 31 ────────────
    print("\n--- Strategy A: Width-31 padded keywords ---")
    kw_list_31 = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK",
                  "EASTNORTHEAST", "KRYPTOSABCDE", "PALIMPSESTAB",
                  "ABSCISSAKRYP", "LUCIFER", "ENIGMA", "CIPHER"]

    for kw in kw_list_31:
        order = generate_keyword_column_order(kw, 31)
        unscr = columnar_decrypt(CT, 31, order)
        test_candidate(f"col31/{kw}", unscr)

        # Inverse (apply the encryption perm)
        perm = []
        nrows = math.ceil(CT_LEN / 31)
        remainder = CT_LEN % 31
        if remainder == 0:
            col_lens = {c: nrows for c in range(31)}
        else:
            col_lens = {c: (nrows if c < remainder else nrows - 1) for c in range(31)}

        ct_idx = 0
        positions_by_rank = {}
        for rank in range(31):
            col_idx = order.index(rank)
            clen = col_lens[col_idx]
            positions_by_rank[rank] = []
            for r in range(clen):
                pos = r * 31 + col_idx
                if pos < CT_LEN:
                    positions_by_rank[rank].append(pos)
                ct_idx += 1

        # Build perm: the encryption perm maps original positions to CT positions
        enc_perm = []
        for rank in range(31):
            enc_perm.extend(positions_by_rank[rank])

        if len(enc_perm) == CT_LEN and validate_perm(enc_perm, CT_LEN):
            inv = invert_perm(enc_perm)
            unscr_inv = apply_perm(CT, inv)
            test_candidate(f"col31_inv/{kw}", unscr_inv)

    # ── Strategy B: Width-31 column-major with keyword-ordered column reading ─
    print("\n--- Strategy B: Write column-major on 31-wide, read with keyword ---")
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        order = generate_keyword_column_order(kw, 31)
        nrows = math.ceil(CT_LEN / 31)

        # Write K4 column-major into 31-wide grid, then read row-major
        grid = {}
        idx = 0
        for c in range(31):
            for r in range(nrows):
                pos = r * 31 + c
                if pos < CT_LEN and idx < CT_LEN:
                    grid[pos] = CT[idx]
                    idx += 1

        result = []
        for r in range(nrows):
            for c in range(31):
                pos = r * 31 + c
                if pos in grid:
                    result.append(grid[pos])
        if len(result) == CT_LEN:
            test_candidate(f"colmaj_write_rowread/{kw}", "".join(result))

        # Write row-major, read column-major in keyword order
        grid2 = {}
        for i, ch in enumerate(CT):
            r, c = divmod(i, 31)
            grid2[(r, c)] = ch

        result2 = []
        for rank in range(31):
            col_idx = order.index(rank)
            for r in range(nrows):
                if (r, col_idx) in grid2:
                    result2.append(grid2[(r, col_idx)])
        if len(result2) == CT_LEN:
            test_candidate(f"rowwrite_colkeyread/{kw}", "".join(result2))

    # ── Strategy C: Shifted key with columnar ────────────────────────────
    print("\n--- Strategy C: Columnar + shifted key application ---")
    for width in [7, 8, 10, 31]:
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            if len(kw) > width:
                kw_use = kw[:width]
            else:
                kw_use = kw
            order = generate_keyword_column_order(kw_use, width)
            unscr = columnar_decrypt(CT, width, order)

            # Try with shifted key offsets
            for shift in range(1, len(kw_use)):
                shifted_kw = kw_use[shift:] + kw_use[:shift]
                for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                    for aname, alph in ALPHABETS.items():
                        total_tested += 1
                        try:
                            dec = decrypt_with_config(unscr, shifted_kw, variant, alph)
                        except Exception:
                            continue
                        qg = quadgram_score(dec)
                        any_c = check_any_position_cribs(dec)
                        canon = check_primary_cribs(dec)
                        if qg > best_qg:
                            globals()['best_qg'] = qg
                        if any_c:
                            crib_hits.append({"desc": f"col{width}/{kw_use}_shift{shift}", "decrypt": f"{variant.value}/{shifted_kw}/{aname}", "text": dec})
                            print(f"*** CRIB HIT *** col{width}/{kw_use}_shift{shift}")

    # ── Strategy D: Reverse text + columnar ────────────────────────────
    print("\n--- Strategy D: Reverse K4 then columnar ---")
    CT_REV = CT[::-1]
    for width in [7, 8, 10, 13, 31]:
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            if len(kw) > width:
                kw_use = kw[:width]
            else:
                kw_use = kw
            order = generate_keyword_column_order(kw_use, width)
            unscr = columnar_decrypt(CT_REV, width, order)
            test_candidate(f"rev_col{width}/{kw_use}", unscr)

    # ── Strategy E: Column-pair and triple swaps on width-31 ────────────
    print("\n--- Strategy E: Column-pair swaps on width-31 ---")
    # Identity column order on width-31
    base_order = list(range(31))
    for i in range(31):
        for j in range(i+1, 31):
            swapped = list(base_order)
            swapped[i], swapped[j] = swapped[j], swapped[i]
            unscr = columnar_decrypt(CT, 31, swapped)
            # Quick qg check
            total_tested += 1
            qg = quadgram_score(unscr)
            if qg > -6.5:
                test_candidate(f"col31_swap/{i},{j}", unscr)

    # ── Strategy F: Route cipher variations on width-31 ─────────────────
    print("\n--- Strategy F: Route cipher on width-31 ---")
    nrows = math.ceil(CT_LEN / 31)
    # Write in rows, read in various routes
    grid_chars = {}
    for i, ch in enumerate(CT):
        r, c = divmod(i, 31)
        grid_chars[(r, c)] = ch

    # Route 1: column-major bottom-to-top
    route_result = []
    for c in range(31):
        for r in range(nrows-1, -1, -1):
            if (r, c) in grid_chars:
                route_result.append(grid_chars[(r, c)])
    if len(route_result) == CT_LEN:
        test_candidate("route31/col_btup", "".join(route_result))

    # Route 2: column-major with alternating direction
    route_result2 = []
    for c in range(31):
        if c % 2 == 0:
            for r in range(nrows):
                if (r, c) in grid_chars:
                    route_result2.append(grid_chars[(r, c)])
        else:
            for r in range(nrows-1, -1, -1):
                if (r, c) in grid_chars:
                    route_result2.append(grid_chars[(r, c)])
    if len(route_result2) == CT_LEN:
        test_candidate("route31/col_boustro", "".join(route_result2))

    # Route 3: Right-to-left column reading
    route_result3 = []
    for c in range(30, -1, -1):
        for r in range(nrows):
            if (r, c) in grid_chars:
                route_result3.append(grid_chars[(r, c)])
    if len(route_result3) == CT_LEN:
        test_candidate("route31/col_rtl", "".join(route_result3))

    # ── Strategy G: Disrupted columnar (null positions) ─────────────────
    print("\n--- Strategy G: Disrupted columnar ---")
    # Try disrupted columnar where certain cells are "null" (skipped)
    # Common disruption: triangle void in bottom-right
    for width in [8, 10, 13, 31]:
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            if len(kw) > width:
                kw_use = kw[:width]
            else:
                kw_use = kw
            order = generate_keyword_column_order(kw_use, width)
            nrows_w = math.ceil(CT_LEN / width)
            remainder_w = CT_LEN % width

            if remainder_w == 0:
                continue  # No disruption possible with even fill

            # Disrupted: void cells are at positions >= length in the last row
            # Try filling void cells in different columns
            # Standard disrupted: void columns are the LAST (width - remainder) columns
            # by rank order, last row

            # Already handled by standard columnar_decrypt (short columns).
            # Try DIFFERENT void placement: void the FIRST (width-remainder) columns instead
            if remainder_w > 0:
                voids = width - remainder_w
                # Swap: long columns become the LAST ones by rank, not first
                alt_col_lens = {}
                for c in range(width):
                    if c < voids:
                        alt_col_lens[c] = nrows_w - 1
                    else:
                        alt_col_lens[c] = nrows_w

                grid = {}
                ct_idx = 0
                for rank in range(width):
                    col_idx = order.index(rank)
                    clen = alt_col_lens[col_idx]
                    for r in range(clen):
                        if ct_idx < CT_LEN:
                            grid[(r, col_idx)] = CT[ct_idx]
                            ct_idx += 1

                result = []
                for r in range(nrows_w):
                    for c in range(width):
                        if (r, c) in grid:
                            result.append(grid[(r, c)])

                if len(result) == CT_LEN:
                    test_candidate(f"disrupted_col{width}/{kw_use}", "".join(result))

    # ── Strategy H: Interleaved halves and thirds ──────────────────────
    print("\n--- Strategy H: Interleaved halves/thirds ---")
    half = CT_LEN // 2
    # Interleave first and second half
    for offset in range(5):
        interleaved = []
        i, j = 0, half + offset
        while i < half + offset or j < CT_LEN:
            if i < half + offset:
                interleaved.append(CT[i])
                i += 1
            if j < CT_LEN:
                interleaved.append(CT[j])
                j += 1
        if len(interleaved) == CT_LEN:
            test_candidate(f"interleave_half/off={offset}", "".join(interleaved))

    # Thirds
    third = CT_LEN // 3
    for perm_order in itertools.permutations(range(3)):
        chunks = [CT[third*i:third*(i+1)] for i in range(3)]
        remainder_chunk = CT[third*3:]
        reordered = "".join(chunks[p] for p in perm_order) + remainder_chunk
        if len(reordered) == CT_LEN:
            test_candidate(f"thirds/{perm_order}", reordered)

    elapsed = time.time() - t0

    # ── Summary ──────────────────────────────────────────────────────────
    print("\n" + "="*70)
    print("PHASE 2 SUMMARY")
    print("="*70)
    print(f"Total tested: {total_tested}")
    print(f"Time: {elapsed:.1f}s")
    print(f"Best QG: {best_qg:.4f}")
    print(f"Best canonical cribs: {best_cribs}/24")
    print(f"Crib hits: {len(crib_hits)}")

    if crib_hits:
        print("\nCRIB HITS:")
        for h in crib_hits:
            print(f"  {h['desc']} | {h.get('decrypt','?')} | {h['text'][:60]}")

    if interesting:
        print(f"\nTop {min(20, len(interesting))} interesting results (QG > -6.0 or cribs >= 10):")
        sorted_int = sorted(interesting, key=lambda x: x['qg'], reverse=True)
        for i, r in enumerate(sorted_int[:20]):
            print(f"  {i+1}. QG={r['qg']:.4f} canon={r['canon']}/24 | {r['desc']} | {r['decrypt']}")
            print(f"     {r['text'][:80]}")

    # Save
    outdir = os.path.join(os.path.dirname(__file__), '..', 'kbot_results')
    os.makedirs(outdir, exist_ok=True)
    outfile = os.path.join(outdir, 'grid31_columnar_phase2_results.json')
    save_data = {
        "total_tested": total_tested,
        "elapsed": elapsed,
        "best_qg": best_qg,
        "best_cribs": best_cribs,
        "crib_hits": crib_hits,
        "interesting": sorted(interesting, key=lambda x: x['qg'], reverse=True)[:50] if interesting else [],
    }
    with open(outfile, 'w') as f:
        json.dump(save_data, f, indent=2, default=str)
    print(f"\nResults saved to {outfile}")


if __name__ == "__main__":
    main()
