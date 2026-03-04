#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: transposition/columnar
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""Double columnar RTL transposition search for K4.

K3 CONFIRMED METHOD: Double columnar transposition with RTL column reading.
  Step 1: Write PT in rows of 21, read columns right-to-left
  Step 2: Write step1 result in rows of 28, read columns right-to-left
  Result = K3 CT.

Key facts:
  - GCD(21, 28) = 7 = len("KRYPTOS")
  - 434 = 2 * 7 * 31
  - K3 and K4 use DIFFERENT transpositions
  - K4 may have substitution (Vig/Beaufort) BEFORE or AFTER transposition

Search strategy:
  1. All width pairs (w1, w2) for double columnar RTL on K4 (97 chars)
     - Focus on multiples of 7: 7,14,21,28,35,49
     - Also try all pairs from 3-49
  2. Try both directions: apply perm and inverse perm
  3. Try Vig/Beaufort decrypt BEFORE transposition (cipher-then-transpose)
  4. Try Vig/Beaufort decrypt AFTER transposition (transpose-then-cipher)
  5. Also try LTR column reading (standard) and mixed RTL/LTR
"""
from __future__ import annotations

import json
import math
import os
import sys
import time
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

def check_short_cribs(text: str) -> List[str]:
    """Check for shorter crib fragments."""
    shorts = ["EAST", "NORTH", "NORTHEAST", "BERLIN", "CLOCK",
              "SLOWLY", "DESPER", "ATELY", "UNDER", "GROUND"]
    return [s for s in shorts if s in text]

def check_canonical_cribs(text: str) -> int:
    return sum(1 for pos, ch in CRIB_DICT.items() if pos < len(text) and text[pos] == ch)


# ── Decryption ──────────────────────────────────────────────────────────
def decrypt_vig(ct_text: str, keyword: str, variant: CipherVariant, alphabet: str) -> str:
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


# ── Columnar transposition (RTL and LTR) ──────────────────────────────
def columnar_rtl_encrypt(text: str, width: int) -> str:
    """Columnar transposition: write in rows of width, read columns RIGHT-TO-LEFT.

    This is the ENCRYPTION direction (what Sanborn did to create the ciphertext).
    """
    length = len(text)
    nrows = math.ceil(length / width)

    # Write text in rows
    grid = {}
    for i, ch in enumerate(text):
        r, c = divmod(i, width)
        grid[(r, c)] = ch

    # Read columns right-to-left (col width-1, width-2, ..., 0)
    result = []
    for c in range(width - 1, -1, -1):
        for r in range(nrows):
            if (r, c) in grid:
                result.append(grid[(r, c)])

    return "".join(result)


def columnar_rtl_decrypt(ct_text: str, width: int) -> str:
    """Undo columnar RTL encryption.

    During encryption: write in rows, read columns RTL.
    To decrypt: write into columns RTL, read rows.
    """
    length = len(ct_text)
    nrows = math.ceil(length / width)
    remainder = length % width

    # Calculate how many chars each column gets
    # When reading RTL during encryption, the rightmost column (width-1) is read first
    # Columns with more chars: if remainder > 0, the first 'remainder' columns (0..remainder-1)
    # have nrows chars, the rest have nrows-1
    if remainder == 0:
        col_lens = {c: nrows for c in range(width)}
    else:
        col_lens = {c: (nrows if c < remainder else nrows - 1) for c in range(width)}

    # Write CT into columns in RTL order (rightmost column first)
    grid = {}
    ct_idx = 0
    for c in range(width - 1, -1, -1):
        for r in range(col_lens[c]):
            if ct_idx < length:
                grid[(r, c)] = ct_text[ct_idx]
                ct_idx += 1

    # Read rows
    result = []
    for r in range(nrows):
        for c in range(width):
            if (r, c) in grid:
                result.append(grid[(r, c)])

    return "".join(result)


def columnar_ltr_encrypt(text: str, width: int) -> str:
    """Standard columnar: write rows, read columns left-to-right."""
    length = len(text)
    nrows = math.ceil(length / width)
    grid = {}
    for i, ch in enumerate(text):
        r, c = divmod(i, width)
        grid[(r, c)] = ch
    result = []
    for c in range(width):
        for r in range(nrows):
            if (r, c) in grid:
                result.append(grid[(r, c)])
    return "".join(result)


def columnar_ltr_decrypt(ct_text: str, width: int) -> str:
    """Undo standard columnar LTR encryption."""
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
    result = []
    for r in range(nrows):
        for c in range(width):
            if (r, c) in grid:
                result.append(grid[(r, c)])
    return "".join(result)


def double_columnar_decrypt(ct_text: str, w1: int, w2: int,
                             dir1: str = "rtl", dir2: str = "rtl") -> str:
    """Double columnar transposition decryption.

    Encryption was: PT -> col(w1,dir1) -> col(w2,dir2) -> CT
    Decryption is:  CT -> inv_col(w2,dir2) -> inv_col(w1,dir1) -> PT
    """
    decrypt_fn = {
        "rtl": columnar_rtl_decrypt,
        "ltr": columnar_ltr_decrypt,
    }

    # Undo step 2 first
    intermediate = decrypt_fn[dir2](ct_text, w2)
    # Then undo step 1
    result = decrypt_fn[dir1](intermediate, w1)
    return result


# ── Tracking ────────────────────────────────────────────────────────────
best_qg = -999.0
best_cribs_canon = 0
crib_hits = []
interesting = []
total = 0

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]
EXTRA_KEYWORDS = ["BERLINCLOCK", "EASTNORTHEAST", "ENIGMA", "LUCIFER", "CIPHER"]
ALL_KEYWORDS = KEYWORDS + EXTRA_KEYWORDS
ALPHABETS = {"AZ": ALPH, "KA": KRYPTOS_ALPHABET}
VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]


def test_text(desc: str, text: str):
    """Test a single text for cribs and quality."""
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
        if not cribs_at:
            short_cribs = check_short_cribs(text)
            if short_cribs:
                print(f"  Interesting: {desc} QG={qg:.4f} canon={canon} words={short_cribs}")


def test_with_decrypts(desc: str, text: str, keywords=None):
    """Test text + all substitution decryptions."""
    if keywords is None:
        keywords = KEYWORDS

    test_text(f"{desc}/identity", text)

    for kw in keywords:
        klen = len(kw)
        for variant in VARIANTS:
            for aname, alph in ALPHABETS.items():
                # All key offsets
                for off in range(klen):
                    dec = decrypt_with_offset(text, kw, off, variant, alph)
                    off_str = f"/off{off}" if off > 0 else ""
                    test_text(f"{desc}/{variant.value}/{kw}/{aname}{off_str}", dec)


def main():
    global total, best_qg, best_cribs_canon
    t0 = time.time()

    print("="*70)
    print("K4 DOUBLE COLUMNAR RTL SEARCH")
    print(f"CT: {CT}")
    print(f"Length: {CT_LEN}")
    print("K3 method: double columnar RTL, widths 21+28, GCD=7")
    print("="*70)

    # First verify K3's method works
    print("\n--- Verifying K3 method (sanity check) ---")
    test_text_k3 = "ABCDEFGHIJKLMNOP"  # simple test
    enc1 = columnar_rtl_encrypt(test_text_k3, 4)
    dec1 = columnar_rtl_decrypt(enc1, 4)
    print(f"  RTL encrypt '{test_text_k3}' width=4: '{enc1}'")
    print(f"  RTL decrypt back: '{dec1}'")
    assert dec1 == test_text_k3, f"RTL roundtrip failed: {dec1}"
    print("  Roundtrip OK")

    # Test double roundtrip
    enc2 = columnar_rtl_encrypt(columnar_rtl_encrypt(test_text_k3, 4), 5)
    dec2 = double_columnar_decrypt(enc2, 4, 5, "rtl", "rtl")
    print(f"  Double RTL encrypt w=4,5: '{enc2}'")
    print(f"  Double RTL decrypt back: '{dec2}'")
    assert dec2 == test_text_k3, f"Double RTL roundtrip failed: {dec2}"
    print("  Double roundtrip OK")

    # ══════════════════════════════════════════════════════════════════
    # STRATEGY 1: Double columnar RTL — all width pairs
    # ══════════════════════════════════════════════════════════════════
    print("\n" + "="*70)
    print("STRATEGY 1: Double columnar RTL — all width pairs (3-49)")
    print("="*70)

    # Prioritize multiples of 7 and factors related to 434 = 2*7*31
    priority_widths = [7, 14, 21, 28, 31, 35, 49]
    all_widths = list(range(3, 50))

    # Phase 1a: Priority width pairs with full decryption
    print("\n  Phase 1a: Priority width pairs with full keyword decrypts...")
    for w1 in priority_widths:
        for w2 in priority_widths:
            desc = f"dbl_rtl/{w1}x{w2}"
            unscr = double_columnar_decrypt(CT, w1, w2, "rtl", "rtl")
            test_with_decrypts(desc, unscr)

    print(f"    After priority pairs: {total} tested, best QG={best_qg:.4f}")

    # Phase 1b: All width pairs with quick check, full decrypt on promising
    print("\n  Phase 1b: All width pairs (3-49) x (3-49) with quick check...")
    for w1 in all_widths:
        for w2 in all_widths:
            unscr = double_columnar_decrypt(CT, w1, w2, "rtl", "rtl")
            total += 1
            qg = qg_score(unscr)
            cribs_at = check_cribs_anywhere(unscr)

            if qg > best_qg:
                best_qg = qg

            if cribs_at:
                crib_hits.append({"desc": f"dbl_rtl/{w1}x{w2}/identity", "text": unscr,
                                 "cribs": cribs_at, "qg": qg})
                print(f"\n*** CRIB HIT *** dbl_rtl/{w1}x{w2}: {unscr[:60]}...")
                # Full decrypt sweep
                test_with_decrypts(f"dbl_rtl/{w1}x{w2}", unscr)
            elif qg > -7.0:
                # Promising — try full decrypts
                test_with_decrypts(f"dbl_rtl/{w1}x{w2}", unscr, keywords=KEYWORDS)

        if w1 % 10 == 0:
            print(f"    w1={w1}: {total} tested, best QG={best_qg:.4f}")

    print(f"  After all RTL pairs: {total} tested, best QG={best_qg:.4f}")

    # ══════════════════════════════════════════════════════════════════
    # STRATEGY 2: Double columnar LTR — all width pairs
    # ══════════════════════════════════════════════════════════════════
    print("\n" + "="*70)
    print("STRATEGY 2: Double columnar LTR — all width pairs (3-49)")
    print("="*70)

    for w1 in all_widths:
        for w2 in all_widths:
            unscr = double_columnar_decrypt(CT, w1, w2, "ltr", "ltr")
            total += 1
            qg = qg_score(unscr)
            cribs_at = check_cribs_anywhere(unscr)

            if qg > best_qg:
                best_qg = qg

            if cribs_at:
                crib_hits.append({"desc": f"dbl_ltr/{w1}x{w2}/identity", "text": unscr,
                                 "cribs": cribs_at, "qg": qg})
                print(f"\n*** CRIB HIT *** dbl_ltr/{w1}x{w2}: {unscr[:60]}...")
                test_with_decrypts(f"dbl_ltr/{w1}x{w2}", unscr)
            elif qg > -7.0:
                test_with_decrypts(f"dbl_ltr/{w1}x{w2}", unscr, keywords=KEYWORDS)

        if w1 % 10 == 0:
            print(f"    w1={w1}: {total} tested, best QG={best_qg:.4f}")

    print(f"  After all LTR pairs: {total} tested, best QG={best_qg:.4f}")

    # ══════════════════════════════════════════════════════════════════
    # STRATEGY 3: Mixed direction — RTL+LTR and LTR+RTL
    # ══════════════════════════════════════════════════════════════════
    print("\n" + "="*70)
    print("STRATEGY 3: Mixed direction double columnar (RTL+LTR, LTR+RTL)")
    print("="*70)

    for dir1, dir2 in [("rtl", "ltr"), ("ltr", "rtl")]:
        for w1 in all_widths:
            for w2 in all_widths:
                unscr = double_columnar_decrypt(CT, w1, w2, dir1, dir2)
                total += 1
                qg = qg_score(unscr)
                cribs_at = check_cribs_anywhere(unscr)

                if qg > best_qg:
                    best_qg = qg

                if cribs_at:
                    crib_hits.append({"desc": f"dbl_{dir1}_{dir2}/{w1}x{w2}/identity",
                                     "text": unscr, "cribs": cribs_at, "qg": qg})
                    print(f"\n*** CRIB HIT *** dbl_{dir1}_{dir2}/{w1}x{w2}: {unscr[:60]}...")
                    test_with_decrypts(f"dbl_{dir1}_{dir2}/{w1}x{w2}", unscr)
                elif qg > -7.0:
                    test_with_decrypts(f"dbl_{dir1}_{dir2}/{w1}x{w2}", unscr, keywords=KEYWORDS)

            if w1 % 15 == 0:
                print(f"    {dir1}+{dir2} w1={w1}: {total} tested, best QG={best_qg:.4f}")

    print(f"  After mixed pairs: {total} tested, best QG={best_qg:.4f}")

    # ══════════════════════════════════════════════════════════════════
    # STRATEGY 4: Single columnar RTL/LTR with substitution
    # ══════════════════════════════════════════════════════════════════
    print("\n" + "="*70)
    print("STRATEGY 4: Single columnar RTL/LTR + Vig/Beaufort (all widths)")
    print("="*70)

    for direction in ["rtl", "ltr"]:
        decrypt_fn = columnar_rtl_decrypt if direction == "rtl" else columnar_ltr_decrypt
        for w in all_widths:
            unscr = decrypt_fn(CT, w)
            test_with_decrypts(f"single_{direction}/{w}", unscr, keywords=ALL_KEYWORDS)

    print(f"  After single columnar: {total} tested, best QG={best_qg:.4f}")

    # ══════════════════════════════════════════════════════════════════
    # STRATEGY 5: Substitution FIRST, then double columnar
    # ══════════════════════════════════════════════════════════════════
    print("\n" + "="*70)
    print("STRATEGY 5: Vig/Beaufort decrypt first, then double columnar RTL")
    print("="*70)

    # If encryption was: PT -> Vig_encrypt -> double_columnar -> CT
    # Then decryption is: CT -> inv_double_columnar -> Vig_decrypt -> PT
    # But if encryption was: PT -> double_columnar -> Vig_encrypt -> CT
    # Then decryption is: CT -> Vig_decrypt -> inv_double_columnar -> PT

    for kw in KEYWORDS:
        klen = len(kw)
        for variant in VARIANTS:
            for aname, alph in ALPHABETS.items():
                for off in range(klen):
                    # Decrypt substitution first
                    dec_sub = decrypt_with_offset(CT, kw, off, variant, alph)
                    off_str = f"_off{off}" if off > 0 else ""

                    # Then try double columnar on the result (priority widths)
                    for w1 in priority_widths:
                        for w2 in priority_widths:
                            for dir1, dir2 in [("rtl", "rtl"), ("ltr", "ltr"), ("rtl", "ltr"), ("ltr", "rtl")]:
                                unscr = double_columnar_decrypt(dec_sub, w1, w2, dir1, dir2)
                                total += 1
                                qg = qg_score(unscr)
                                cribs_at = check_cribs_anywhere(unscr)

                                if qg > best_qg:
                                    best_qg = qg

                                if cribs_at:
                                    desc = f"sub_first/{variant.value}/{kw}/{aname}{off_str}/dbl_{dir1}_{dir2}/{w1}x{w2}"
                                    crib_hits.append({"desc": desc, "text": unscr,
                                                     "cribs": cribs_at, "qg": qg})
                                    print(f"\n*** CRIB HIT *** {desc}")
                                    print(f"    {unscr[:60]}...")

    print(f"  After sub-first: {total} tested, best QG={best_qg:.4f}")

    # ══════════════════════════════════════════════════════════════════
    # STRATEGY 6: Triple columnar (K3 widths + one more)
    # ══════════════════════════════════════════════════════════════════
    print("\n" + "="*70)
    print("STRATEGY 6: Triple columnar RTL (three passes)")
    print("="*70)

    # If K4 used K3's widths (21, 28) PLUS a third pass
    for w3 in range(3, 32):
        for dir_combo in [("rtl", "rtl", "rtl"), ("rtl", "rtl", "ltr")]:
            # Undo: inv(w3) -> inv(w2=28) -> inv(w1=21)
            d3 = columnar_rtl_decrypt if dir_combo[2] == "rtl" else columnar_ltr_decrypt
            d2 = columnar_rtl_decrypt if dir_combo[1] == "rtl" else columnar_ltr_decrypt
            d1 = columnar_rtl_decrypt if dir_combo[0] == "rtl" else columnar_ltr_decrypt

            step1 = d3(CT, w3)
            step2 = d2(step1, 28)
            step3 = d1(step2, 21)

            total += 1
            qg = qg_score(step3)
            cribs_at = check_cribs_anywhere(step3)

            if qg > best_qg:
                best_qg = qg

            if cribs_at:
                desc = f"triple_{dir_combo}/21x28x{w3}"
                crib_hits.append({"desc": desc, "text": step3, "cribs": cribs_at, "qg": qg})
                print(f"\n*** CRIB HIT *** {desc}: {step3[:60]}...")
                test_with_decrypts(desc, step3)

            # Also try: inv(w3) -> inv(w1=21) -> inv(w2=28) (different order)
            step2b = d1(step1, 21)
            step3b = d2(step2b, 28)

            total += 1
            qg2 = qg_score(step3b)
            cribs_at2 = check_cribs_anywhere(step3b)

            if qg2 > best_qg:
                best_qg = qg2

            if cribs_at2:
                desc = f"triple_{dir_combo}/28x21x{w3}"
                crib_hits.append({"desc": desc, "text": step3b, "cribs": cribs_at2, "qg": qg2})
                print(f"\n*** CRIB HIT *** {desc}: {step3b[:60]}...")

    print(f"  After triple: {total} tested, best QG={best_qg:.4f}")

    elapsed = time.time() - t0

    # ══════════════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════════════
    print("\n" + "="*70)
    print("FINAL SUMMARY")
    print("="*70)
    print(f"Total configurations tested: {total:,}")
    print(f"Time: {elapsed:.1f}s")
    print(f"Best quadgram score: {best_qg:.4f}")
    print(f"Best canonical crib count: {best_cribs_canon}/24")
    print(f"Crib hits (EASTNORTHEAST/BERLINCLOCK at any position): {len(crib_hits)}")

    if crib_hits:
        print("\n  CRIB HITS:")
        for h in crib_hits:
            print(f"    {h['desc']}")
            print(f"      Text: {h['text'][:80]}")
            print(f"      Cribs: {h.get('cribs', '?')}, QG: {h.get('qg', '?')}")

    if interesting:
        sorted_int = sorted(interesting, key=lambda x: x['qg'], reverse=True)
        print(f"\n  Top {min(20, len(sorted_int))} interesting results:")
        for i, r in enumerate(sorted_int[:20]):
            print(f"    {i+1}. QG={r['qg']:.4f} canon={r['canon']}/24 | {r['desc']}")
            print(f"       {r['text'][:80]}")

    # Save results
    outfile = os.path.join(os.path.dirname(__file__), '..', 'kbot_results', 'k4_double_columnar_rtl_results.json')
    os.makedirs(os.path.dirname(outfile), exist_ok=True)
    save_data = {
        "total_tested": total,
        "elapsed": elapsed,
        "best_qg": best_qg,
        "best_cribs_canon": best_cribs_canon,
        "crib_hits": crib_hits,
        "interesting": sorted(interesting, key=lambda x: x['qg'], reverse=True)[:50] if interesting else [],
    }
    with open(outfile, 'w') as f:
        json.dump(save_data, f, indent=2, default=str)
    print(f"\nResults saved to {outfile}")


if __name__ == "__main__":
    main()
