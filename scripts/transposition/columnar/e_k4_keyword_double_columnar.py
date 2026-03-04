#!/usr/bin/env python3
from __future__ import annotations
"""
Cipher: columnar transposition
Family: transposition/columnar
Status: active
Keyspace: see implementation
Last run:
Best score:
"""
"""K4 keyword-ordered double columnar transposition search.

K3 uses double columnar with RTL reading (effectively a specific column order).
But K4 might use keyword-ordered column reading instead of simple RTL.
This script tests double columnar with KEYWORD column orders at various widths.

Also tests: columnar with keyword order on one pass + RTL on the other.

attack(ciphertext, **params) -> list[tuple[float, str, str]]
    Standard attack interface.
    params: trans_keywords (list[str]), sub_keywords (list[str]),
            qg_threshold (float, default -5.5), canon_threshold (int, default 12)
"""

import json
import math
import os
import sys
import time
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT,
)
from kryptos.kernel.transforms.transposition import invert_perm, apply_perm, validate_perm
from kryptos.kernel.transforms.vigenere import CipherVariant

# -- Quadgrams --
QUADGRAM_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
with open(QUADGRAM_PATH) as f:
    QUADGRAMS = json.load(f)
QUADGRAM_FLOOR = min(QUADGRAMS.values()) - 1.0

def qg_score(text: str) -> float:
    if len(text) < 4:
        return QUADGRAM_FLOOR
    total = sum(QUADGRAMS.get(text[i:i+4], QUADGRAM_FLOOR) for i in range(len(text)-3))
    return total / (len(text) - 3)

# -- Cribs --
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

# -- Decryption --
def decrypt_with_offset(ct_text: str, keyword: str, offset: int, variant: CipherVariant, alphabet: str) -> str:
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

# -- Columnar with keyword column order --
def keyword_to_col_order(keyword: str) -> List[int]:
    """Convert keyword to column reading order (alphabetical rank of each letter)."""
    kw = keyword.upper()
    indexed = [(ch, i) for i, ch in enumerate(kw)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * len(kw)
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return order

def columnar_keyword_encrypt(text: str, keyword: str) -> str:
    """Columnar transposition with keyword column order.
    Write in rows of len(keyword), read columns in alphabetical keyword order.
    """
    width = len(keyword)
    col_order = keyword_to_col_order(keyword)
    length = len(text)
    nrows = math.ceil(length / width)

    grid = {}
    for i, ch in enumerate(text):
        r, c = divmod(i, width)
        grid[(r, c)] = ch

    result = []
    for rank in range(width):
        col_idx = col_order.index(rank)
        for r in range(nrows):
            if (r, col_idx) in grid:
                result.append(grid[(r, col_idx)])

    return "".join(result)

def columnar_keyword_decrypt(ct_text: str, keyword: str) -> str:
    """Undo keyword columnar transposition."""
    width = len(keyword)
    col_order = keyword_to_col_order(keyword)
    length = len(ct_text)
    nrows = math.ceil(length / width)
    remainder = length % width

    if remainder == 0:
        col_lens = {c: nrows for c in range(width)}
    else:
        col_lens = {c: (nrows if c < remainder else nrows - 1) for c in range(width)}

    grid = {}
    ct_idx = 0
    for rank in range(width):
        col_idx = col_order.index(rank)
        for r in range(col_lens[col_idx]):
            if ct_idx < length:
                grid[(r, col_idx)] = ct_text[ct_idx]
                ct_idx += 1

    result = []
    for r in range(nrows):
        for c in range(width):
            if (r, c) in grid:
                result.append(grid[(r, c)])

    return "".join(result)

def columnar_rtl_decrypt(ct_text: str, width: int) -> str:
    """Undo columnar RTL (right-to-left column reading)."""
    length = len(ct_text)
    nrows = math.ceil(length / width)
    remainder = length % width
    if remainder == 0:
        col_lens = {c: nrows for c in range(width)}
    else:
        col_lens = {c: (nrows if c < remainder else nrows - 1) for c in range(width)}

    grid = {}
    ct_idx = 0
    for c in range(width - 1, -1, -1):
        for r in range(col_lens[c]):
            if ct_idx < length:
                grid[(r, c)] = ct_text[ct_idx]
                ct_idx += 1

    return "".join(grid[(r, c)] for r in range(nrows) for c in range(width) if (r, c) in grid)

def columnar_ltr_decrypt(ct_text: str, width: int) -> str:
    """Undo columnar LTR."""
    length = len(ct_text)
    nrows = math.ceil(length / width)
    remainder = length % width
    if remainder == 0:
        col_lens = {c: nrows for c in range(width)}
    else:
        col_lens = {c: (nrows if c < remainder else nrows - 1) for c in range(width)}

    grid = {}
    ct_idx = 0
    for c in range(width):
        for r in range(col_lens[c]):
            if ct_idx < length:
                grid[(r, c)] = ct_text[ct_idx]
                ct_idx += 1

    return "".join(grid[(r, c)] for r in range(nrows) for c in range(width) if (r, c) in grid)

# -- Default keyword lists --
DEFAULT_TRANS_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK", "EASTNORTHEAST",
    "ENIGMA", "LUCIFER", "CIPHER", "SECRET", "SHADOW", "LIGHT",
    "BURIED", "TUNNEL", "BURY", "CARTER", "HOWARD",
    "CANDLE", "SLOWLY", "DESPERATE", "PASSAGE",
]
DEFAULT_SUB_KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]
ALPHABETS = {"AZ": ALPH, "KA": KRYPTOS_ALPHABET}
VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]


# -- Standard attack interface --

def attack(ciphertext: str, **params) -> list[tuple[float, str, str]]:
    """Standard attack interface. Returns [(score, plaintext, method_description), ...]"""
    trans_keywords = params.get("trans_keywords", DEFAULT_TRANS_KEYWORDS)
    sub_keywords = params.get("sub_keywords", DEFAULT_SUB_KEYWORDS)
    qg_threshold = params.get("qg_threshold", -5.5)
    canon_threshold = params.get("canon_threshold", 12)

    results = []  # (score, plaintext, description)

    def evaluate(desc: str, text: str):
        qg = qg_score(text)
        cribs_at = check_cribs_anywhere(text)
        canon = check_canonical_cribs(text)
        # Use qg as score; also include anything with canonical crib hits or free crib hits
        if qg > qg_threshold or canon >= canon_threshold or cribs_at:
            score = qg
            if cribs_at:
                # Boost score for crib hits so they sort higher
                score = max(score, 0.0) + canon
            results.append((float(score), text, desc))

    def evaluate_with_sub(desc: str, text: str):
        evaluate(f"{desc}/identity", text)
        for kw in sub_keywords:
            klen = len(kw)
            for variant in VARIANTS:
                for aname, alph in ALPHABETS.items():
                    for off in range(klen):
                        dec = decrypt_with_offset(text, kw, off, variant, alph)
                        off_str = f"/off{off}" if off > 0 else ""
                        evaluate(f"{desc}/{variant.value}/{kw}/{aname}{off_str}", dec)

    # 1. Double keyword columnar: keyword1 + keyword2
    for kw1 in trans_keywords:
        for kw2 in trans_keywords:
            step1 = columnar_keyword_decrypt(ciphertext, kw2)
            step2 = columnar_keyword_decrypt(step1, kw1)
            evaluate_with_sub(f"dbl_kw/{kw1}+{kw2}", step2)

    # 2. Keyword columnar + RTL/LTR columnar (mixed)
    for kw in trans_keywords:
        for w2 in range(3, 50):
            # Order A: undo RTL(w2), then undo keyword(kw)
            step1_a = columnar_rtl_decrypt(ciphertext, w2)
            step2_a = columnar_keyword_decrypt(step1_a, kw)
            evaluate(f"kw_then_rtl/{kw}+rtl{w2}/identity", step2_a)

            qg_a = qg_score(step2_a)
            cribs_a = check_cribs_anywhere(step2_a)
            if qg_a > -7.0 or cribs_a:
                evaluate_with_sub(f"kw_then_rtl/{kw}+rtl{w2}", step2_a)

            # Order B: undo keyword(kw), then undo RTL(w2)
            step1_b = columnar_keyword_decrypt(ciphertext, kw)
            step2_b = columnar_rtl_decrypt(step1_b, w2)
            evaluate(f"rtl_then_kw/rtl{w2}+{kw}/identity", step2_b)

            qg_b = qg_score(step2_b)
            cribs_b = check_cribs_anywhere(step2_b)
            if qg_b > -7.0 or cribs_b:
                evaluate_with_sub(f"rtl_then_kw/rtl{w2}+{kw}", step2_b)

            # Same with LTR
            step1_c = columnar_ltr_decrypt(ciphertext, w2)
            step2_c = columnar_keyword_decrypt(step1_c, kw)
            evaluate(f"kw_then_ltr/{kw}+ltr{w2}/identity", step2_c)

            qg_c = qg_score(step2_c)
            cribs_c = check_cribs_anywhere(step2_c)
            if qg_c > -7.0 or cribs_c:
                evaluate_with_sub(f"kw_then_ltr/{kw}+ltr{w2}", step2_c)

            step1_d = columnar_keyword_decrypt(ciphertext, kw)
            step2_d = columnar_ltr_decrypt(step1_d, w2)
            evaluate(f"ltr_then_kw/ltr{w2}+{kw}/identity", step2_d)

            qg_d = qg_score(step2_d)
            cribs_d = check_cribs_anywhere(step2_d)
            if qg_d > -7.0 or cribs_d:
                evaluate_with_sub(f"ltr_then_kw/ltr{w2}+{kw}", step2_d)

    # 3. Single keyword columnar (comprehensive)
    for kw in trans_keywords:
        unscr = columnar_keyword_decrypt(ciphertext, kw)
        evaluate_with_sub(f"single_kw/{kw}", unscr)

    # 4. Reversed keyword columnar + reverse text experiments
    ct_rev = ciphertext[::-1]
    for kw in trans_keywords:
        kw_rev = kw[::-1]
        unscr = columnar_keyword_decrypt(ciphertext, kw_rev)
        evaluate_with_sub(f"single_kw_rev/{kw_rev}", unscr)

        unscr2 = columnar_keyword_decrypt(ct_rev, kw)
        evaluate_with_sub(f"rev_ct_kw/{kw}", unscr2)

        step1 = columnar_keyword_decrypt(ciphertext, kw)
        step2 = columnar_keyword_decrypt(step1, kw_rev)
        evaluate_with_sub(f"dbl_kw_rev/{kw}+{kw_rev}", step2)

    results.sort(key=lambda x: -x[0])
    return results


# -- Tracking (used by main for backwards-compatible output) --
best_qg = -999.0
best_cribs_canon = 0
crib_hits = []
interesting = []
total = 0


def test_text(desc: str, text: str):
    global best_qg, best_cribs_canon, total
    total += 1
    qg = qg_score(text)
    cribs_at = check_cribs_anywhere(text)
    canon = check_canonical_cribs(text)
    if qg > best_qg:
        best_qg = qg
    if canon > best_cribs_canon:
        best_cribs_canon = canon
    if cribs_at:
        crib_hits.append({"desc": desc, "text": text, "cribs": cribs_at, "qg": qg, "canon": canon})
        print(f"\n*** CRIB HIT *** {desc}")
        print(f"    Text: {text}")
        print(f"    Cribs: {cribs_at}, QG: {qg:.4f}")
    if qg > -5.5 or canon >= 12:
        interesting.append({"desc": desc, "text": text, "qg": qg, "canon": canon})


def test_with_sub(desc: str, text: str):
    """Test with identity + substitution decrypts."""
    test_text(f"{desc}/identity", text)
    for kw in DEFAULT_SUB_KEYWORDS:
        klen = len(kw)
        for variant in VARIANTS:
            for aname, alph in ALPHABETS.items():
                for off in range(klen):
                    dec = decrypt_with_offset(text, kw, off, variant, alph)
                    off_str = f"/off{off}" if off > 0 else ""
                    test_text(f"{desc}/{variant.value}/{kw}/{aname}{off_str}", dec)


def main():
    global total, best_qg, best_cribs_canon
    t0 = time.time()
    print("="*70)
    print("K4 KEYWORD DOUBLE COLUMNAR SEARCH")
    print(f"CT: {CT}, Length: {CT_LEN}")
    print(f"Transposition keywords: {len(DEFAULT_TRANS_KEYWORDS)}")
    print("="*70)

    # Verify roundtrip
    test_str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    enc = columnar_keyword_encrypt(test_str, "KRYPTOS")
    dec = columnar_keyword_decrypt(enc, "KRYPTOS")
    assert dec == test_str, f"Keyword columnar roundtrip failed: {dec}"
    print("Keyword columnar roundtrip verified OK")

    # 1. Double keyword columnar: all keyword pairs
    print("\n" + "="*70)
    print("1. Double keyword columnar: all keyword pairs")
    print("="*70)

    for kw1 in DEFAULT_TRANS_KEYWORDS:
        for kw2 in DEFAULT_TRANS_KEYWORDS:
            step1 = columnar_keyword_decrypt(CT, kw2)
            step2 = columnar_keyword_decrypt(step1, kw1)
            test_with_sub(f"dbl_kw/{kw1}+{kw2}", step2)

        if DEFAULT_TRANS_KEYWORDS.index(kw1) % 5 == 0:
            print(f"  kw1={kw1}: {total} tested, best QG={best_qg:.4f}")

    print(f"  After double keyword: {total} tested, best QG={best_qg:.4f}")

    # 2. Mixed: keyword columnar + RTL/LTR columnar
    print("\n" + "="*70)
    print("2. Mixed: keyword columnar + RTL/LTR columnar")
    print("="*70)

    for kw in DEFAULT_TRANS_KEYWORDS:
        kw_width = len(kw)
        for w2 in range(3, 50):
            step1_a = columnar_rtl_decrypt(CT, w2)
            step2_a = columnar_keyword_decrypt(step1_a, kw)
            test_text(f"kw_then_rtl/{kw}+rtl{w2}/identity", step2_a)

            qg_a = qg_score(step2_a)
            cribs_a = check_cribs_anywhere(step2_a)
            if qg_a > -7.0 or cribs_a:
                test_with_sub(f"kw_then_rtl/{kw}+rtl{w2}", step2_a)

            step1_b = columnar_keyword_decrypt(CT, kw)
            step2_b = columnar_rtl_decrypt(step1_b, w2)
            test_text(f"rtl_then_kw/rtl{w2}+{kw}/identity", step2_b)

            qg_b = qg_score(step2_b)
            cribs_b = check_cribs_anywhere(step2_b)
            if qg_b > -7.0 or cribs_b:
                test_with_sub(f"rtl_then_kw/rtl{w2}+{kw}", step2_b)

            step1_c = columnar_ltr_decrypt(CT, w2)
            step2_c = columnar_keyword_decrypt(step1_c, kw)
            test_text(f"kw_then_ltr/{kw}+ltr{w2}/identity", step2_c)

            qg_c = qg_score(step2_c)
            cribs_c = check_cribs_anywhere(step2_c)
            if qg_c > -7.0 or cribs_c:
                test_with_sub(f"kw_then_ltr/{kw}+ltr{w2}", step2_c)

            step1_d = columnar_keyword_decrypt(CT, kw)
            step2_d = columnar_ltr_decrypt(step1_d, w2)
            test_text(f"ltr_then_kw/ltr{w2}+{kw}/identity", step2_d)

            qg_d = qg_score(step2_d)
            cribs_d = check_cribs_anywhere(step2_d)
            if qg_d > -7.0 or cribs_d:
                test_with_sub(f"ltr_then_kw/ltr{w2}+{kw}", step2_d)

        print(f"  kw={kw}: {total} tested, best QG={best_qg:.4f}")

    # 3. Single keyword columnar with full sub decrypts
    print("\n" + "="*70)
    print("3. Single keyword columnar with full sub decrypts")
    print("="*70)

    for kw in DEFAULT_TRANS_KEYWORDS:
        unscr = columnar_keyword_decrypt(CT, kw)
        test_with_sub(f"single_kw/{kw}", unscr)

    print(f"  After single keyword: {total} tested, best QG={best_qg:.4f}")

    # 4. Reversed keyword + reverse text experiments
    print("\n" + "="*70)
    print("4. Reversed keyword + reverse text experiments")
    print("="*70)

    CT_REV = CT[::-1]
    for kw in DEFAULT_TRANS_KEYWORDS:
        kw_rev = kw[::-1]
        unscr = columnar_keyword_decrypt(CT, kw_rev)
        test_with_sub(f"single_kw_rev/{kw_rev}", unscr)

        unscr2 = columnar_keyword_decrypt(CT_REV, kw)
        test_with_sub(f"rev_ct_kw/{kw}", unscr2)

        step1 = columnar_keyword_decrypt(CT, kw)
        step2 = columnar_keyword_decrypt(step1, kw_rev)
        test_with_sub(f"dbl_kw_rev/{kw}+{kw_rev}", step2)

    print(f"  After reversed: {total} tested, best QG={best_qg:.4f}")

    elapsed = time.time() - t0

    # -- Summary --
    print("\n" + "="*70)
    print("FINAL SUMMARY")
    print("="*70)
    print(f"Total: {total:,} tested")
    print(f"Time: {elapsed:.1f}s")
    print(f"Best QG: {best_qg:.4f}")
    print(f"Best canonical cribs: {best_cribs_canon}/24")
    print(f"Crib hits: {len(crib_hits)}")

    if crib_hits:
        for h in crib_hits:
            print(f"  {h['desc']}: {h['text'][:70]}")

    if interesting:
        sorted_int = sorted(interesting, key=lambda x: x['qg'], reverse=True)
        print(f"\nTop {min(15, len(sorted_int))} interesting:")
        for i, r in enumerate(sorted_int[:15]):
            print(f"  {i+1}. QG={r['qg']:.4f} canon={r['canon']}/24 | {r['desc']}")
            print(f"     {r['text'][:80]}")

    outfile = os.path.join(os.path.dirname(__file__), '..', 'kbot_results', 'k4_keyword_double_columnar_results.json')
    os.makedirs(os.path.dirname(outfile), exist_ok=True)
    with open(outfile, 'w') as f:
        json.dump({"total": total, "elapsed": elapsed, "best_qg": best_qg,
                   "best_cribs": best_cribs_canon, "crib_hits": crib_hits,
                   "interesting": sorted(interesting, key=lambda x: x['qg'], reverse=True)[:30] if interesting else []
                   }, f, indent=2, default=str)
    print(f"\nSaved to {outfile}")


if __name__ == "__main__":
    main()
