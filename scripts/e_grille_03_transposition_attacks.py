#!/usr/bin/env python3
"""
E-GRILLE-03: Comprehensive transposition & pattern attacks on YAR grille CT.

CT extracted via Cardan grille from Kryptos tableau: 106 characters.
Tries columnar transposition, rail fence, route cipher, skip reads,
reversals, combined substitution attacks, and crib dragging.

Usage: PYTHONPATH=src python3 -u scripts/e_grille_03_transposition_attacks.py
"""
from __future__ import annotations

import json
import math
import os
import sys
from itertools import permutations
from collections import defaultdict
from typing import List, Tuple, Optional, Dict

# ── Constants ────────────────────────────────────────────────────────────────

GRILLE_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
CT_LEN = len(GRILLE_CT)  # 106

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPH_IDX = {c: i for i, c in enumerate(ALPH)}
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}

# ── Load scoring data ────────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)

# Quadgrams
QUADGRAMS: Dict[str, float] = {}
qg_path = os.path.join(PROJECT_DIR, "data", "english_quadgrams.json")
if os.path.exists(qg_path):
    with open(qg_path) as f:
        QUADGRAMS = json.load(f)
    print(f"[+] Loaded {len(QUADGRAMS)} quadgrams")
else:
    print("[!] Quadgram file not found, using trigram fallback only")

# English words (3+ letters)
ENGLISH_WORDS = set()
wl_path = os.path.join(PROJECT_DIR, "wordlists", "english.txt")
if os.path.exists(wl_path):
    with open(wl_path) as f:
        for line in f:
            w = line.strip().upper()
            if len(w) >= 3:
                ENGLISH_WORDS.add(w)
    print(f"[+] Loaded {len(ENGLISH_WORDS)} English words (3+ letters)")

# Common trigrams for quick scoring
COMMON_TRIGRAMS = {
    "THE", "AND", "ING", "ENT", "ION", "HER", "FOR", "THA", "NTH", "INT",
    "ERE", "TIO", "VER", "EST", "ARE", "ATE", "ALL", "EVE", "ITH", "WIT",
    "HIS", "OUR", "NOT", "BUT", "OUT", "HAS", "WAS", "ONE", "HAD", "HEN",
    "ERS", "HAN", "OFT", "STH", "ORT", "OUN", "RED", "TER", "RES", "COM",
}

# ── Scoring functions ────────────────────────────────────────────────────────

def quadgram_score(text: str) -> float:
    """Log-probability score using quadgrams. Higher = more English-like."""
    if not QUADGRAMS or len(text) < 4:
        return -999.0
    floor = -10.0  # penalty for unseen quadgrams
    score = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        score += QUADGRAMS.get(qg, floor)
    return score / max(1, len(text) - 3)  # normalize per quadgram


def count_english_words(text: str) -> Tuple[int, List[str]]:
    """Count English words (3+ letters) found in text. Greedy longest-first."""
    found = []
    text_len = len(text)
    # Check for words of length 3 to min(15, text_len)
    for length in range(min(15, text_len), 2, -1):
        for i in range(text_len - length + 1):
            word = text[i:i+length]
            if word in ENGLISH_WORDS:
                found.append(word)
    # Deduplicate overlapping but keep all unique words
    seen = set()
    unique = []
    for w in found:
        if w not in seen:
            seen.add(w)
            unique.append(w)
    return len(unique), unique


def trigram_count(text: str) -> int:
    """Count common English trigrams in text."""
    count = 0
    for i in range(len(text) - 2):
        if text[i:i+3] in COMMON_TRIGRAMS:
            count += 1
    return count


def composite_score(text: str) -> float:
    """Composite English-likeness score."""
    qg = quadgram_score(text)
    nwords, words = count_english_words(text)
    tris = trigram_count(text)
    # Weight: quadgram score (normalized), word count, trigram count
    # quadgram typically ranges from -10 (random) to -4 (English)
    # Scale so that qg=-4 contributes ~60, nwords*5, tris*2
    return (qg + 10.0) * 10.0 + nwords * 5.0 + tris * 2.0


# ── Cipher primitives ────────────────────────────────────────────────────────

def vigenere_decrypt(ct: str, key: str) -> str:
    """Vigenère decrypt: PT[i] = (CT[i] - KEY[i]) mod 26"""
    pt = []
    klen = len(key)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = ALPH_IDX[key[i % klen]]
        pt.append(ALPH[(ci - ki) % 26])
    return "".join(pt)


def beaufort_decrypt(ct: str, key: str) -> str:
    """Beaufort decrypt: PT[i] = (KEY[i] - CT[i]) mod 26"""
    pt = []
    klen = len(key)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = ALPH_IDX[key[i % klen]]
        pt.append(ALPH[(ki - ci) % 26])
    return "".join(pt)


def caesar_shift(text: str, shift: int) -> str:
    return "".join(ALPH[(ALPH_IDX[c] + shift) % 26] for c in text)


# ── Transposition attacks ────────────────────────────────────────────────────

def columnar_decrypt(ct: str, col_order: List[int]) -> str:
    """Reverse columnar transposition given column read order.

    Encryption: write PT into rows of width=ncols, read columns in col_order.
    Decryption: distribute CT chars back into columns in col_order, read rows.
    """
    ncols = len(col_order)
    nrows = math.ceil(len(ct) / ncols)
    total = nrows * ncols
    short_cols = total - len(ct)  # number of columns with nrows-1 chars

    # Determine how many chars each column gets
    # Last 'short_cols' columns (in natural order) are short
    col_lengths = []
    for col_natural in range(ncols):
        if col_natural >= ncols - short_cols:
            col_lengths.append(nrows - 1)
        else:
            col_lengths.append(nrows)

    # Distribute CT into columns in the given order
    grid = [[] for _ in range(ncols)]
    pos = 0
    for order_idx in range(ncols):
        col_idx = col_order[order_idx]
        length = col_lengths[col_idx]
        grid[col_idx] = list(ct[pos:pos+length])
        pos += length

    # Read rows
    result = []
    for row in range(nrows):
        for col in range(ncols):
            if row < len(grid[col]):
                result.append(grid[col][row])
    return "".join(result)


def rail_fence_decrypt(ct: str, rails: int) -> str:
    """Decrypt rail fence cipher."""
    n = len(ct)
    if rails <= 1 or rails >= n:
        return ct

    # Build the fence pattern to know character positions
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    for i in range(n):
        fence[rail].append(i)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction

    # Fill in characters
    result = [''] * n
    pos = 0
    for r in range(rails):
        for idx in fence[r]:
            result[idx] = ct[pos]
            pos += 1
    return "".join(result)


def route_cipher_spiral(ct: str, nrows: int, ncols: int) -> str:
    """Read CT into grid, extract via clockwise spiral from top-left."""
    total = nrows * ncols
    padded = ct + "X" * (total - len(ct)) if len(ct) < total else ct[:total]

    # Fill grid row by row
    grid = []
    for r in range(nrows):
        grid.append(list(padded[r*ncols:(r+1)*ncols]))

    # Spiral read
    result = []
    top, bottom, left, right = 0, nrows - 1, 0, ncols - 1
    while top <= bottom and left <= right:
        for c in range(left, right + 1):
            result.append(grid[top][c])
        top += 1
        for r in range(top, bottom + 1):
            result.append(grid[r][right])
        right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                result.append(grid[bottom][c])
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                result.append(grid[r][left])
            left += 1
    return "".join(result)[:len(ct)]


def route_cipher_snake(ct: str, nrows: int, ncols: int) -> str:
    """Read CT into grid, extract via snake (alternating L-R, R-L rows)."""
    total = nrows * ncols
    padded = ct + "X" * (total - len(ct)) if len(ct) < total else ct[:total]

    grid = []
    for r in range(nrows):
        grid.append(list(padded[r*ncols:(r+1)*ncols]))

    result = []
    for r in range(nrows):
        if r % 2 == 0:
            result.extend(grid[r])
        else:
            result.extend(reversed(grid[r]))
    return "".join(result)[:len(ct)]


def route_cipher_diagonal(ct: str, nrows: int, ncols: int) -> str:
    """Read CT into grid, extract via diagonal reads (top-right to bottom-left)."""
    total = nrows * ncols
    padded = ct + "X" * (total - len(ct)) if len(ct) < total else ct[:total]

    grid = []
    for r in range(nrows):
        grid.append(list(padded[r*ncols:(r+1)*ncols]))

    result = []
    for d in range(nrows + ncols - 1):
        for r in range(max(0, d - ncols + 1), min(nrows, d + 1)):
            c = d - r
            if 0 <= c < ncols:
                result.append(grid[r][c])
    return "".join(result)[:len(ct)]


def route_cipher_columns(ct: str, nrows: int, ncols: int) -> str:
    """Read CT into grid row-by-row, extract column-by-column."""
    total = nrows * ncols
    padded = ct + "X" * (total - len(ct)) if len(ct) < total else ct[:total]

    grid = []
    for r in range(nrows):
        grid.append(list(padded[r*ncols:(r+1)*ncols]))

    result = []
    for c in range(ncols):
        for r in range(nrows):
            result.append(grid[r][c])
    return "".join(result)[:len(ct)]


def skip_read(ct: str, skip: int, offset: int) -> str:
    """Read every skip-th character starting at offset."""
    result = []
    idx = offset
    visited = set()
    while len(result) < len(ct):
        actual = idx % len(ct)
        if actual in visited:
            # Find next unvisited
            found = False
            for j in range(len(ct)):
                if j not in visited:
                    actual = j
                    found = True
                    break
            if not found:
                break
        visited.add(actual)
        result.append(ct[actual])
        idx += skip
    return "".join(result)


# ── Crib dragging ────────────────────────────────────────────────────────────

CRIBS = [
    "KRYPTOS", "BERLIN", "CLOCK", "EAST", "NORTH", "SHADOW", "LIGHT",
    "UNDERGROUND", "PALIMPSEST", "ABSCISSA", "BETWEEN", "SUBTLE",
    "SHADING", "ABSENCE", "IQLUSION", "VIRTUALLY", "INVISIBLE",
    "BERLINCLOCK", "EASTNORTHEAST", "NORTHEAST", "SOUTHEAST",
    "EQUINOX", "SOLSTICE", "MERIDIAN", "CIPHER", "SECRET",
    "HIDDEN", "REVEAL", "TRUTH", "ANSWER", "MATRIX", "LUCID",
]


def derive_vig_key_segment(ct_segment: str, pt_segment: str) -> str:
    """Derive Vigenère key: K[i] = (CT[i] - PT[i]) mod 26"""
    key = []
    for c, p in zip(ct_segment, pt_segment):
        key.append(ALPH[(ALPH_IDX[c] - ALPH_IDX[p]) % 26])
    return "".join(key)


def derive_beaufort_key_segment(ct_segment: str, pt_segment: str) -> str:
    """Derive Beaufort key: K[i] = (CT[i] + PT[i]) mod 26"""
    key = []
    for c, p in zip(ct_segment, pt_segment):
        key.append(ALPH[(ALPH_IDX[c] + ALPH_IDX[p]) % 26])
    return "".join(key)


def check_key_pattern(key: str) -> Optional[str]:
    """Check if a key segment shows a recognizable pattern."""
    patterns = []

    # Check if it's a repeated short key
    for period in range(1, len(key) // 2 + 1):
        base = key[:period]
        if all(key[i] == base[i % period] for i in range(len(key))):
            patterns.append(f"periodic({period}): {base}")
            break

    # Check if it's alphabetical sequence
    diffs = [ALPH_IDX[key[i+1]] - ALPH_IDX[key[i]] for i in range(len(key)-1)]
    if len(set(diffs)) == 1:
        patterns.append(f"arithmetic(step={diffs[0]})")

    # Check if it's all one letter
    if len(set(key)) == 1:
        patterns.append(f"caesar({key[0]}={ALPH_IDX[key[0]]})")

    # Check if it matches KRYPTOS or KA
    for kw in ["KRYPTOS", KA, "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK"]:
        for start in range(len(kw)):
            seg = kw[start:start+len(key)]
            if len(seg) == len(key) and seg == key:
                patterns.append(f"keyword_match({kw}[{start}:{start+len(key)}])")

    # Check if key segment is a recognizable English word
    if key in ENGLISH_WORDS:
        patterns.append(f"english_word({key})")

    # Check if key segment appears in KA alphabet
    if key in KA:
        pos = KA.index(key)
        patterns.append(f"in_KA_at_{pos}")

    if patterns:
        return "; ".join(patterns)
    return None


# ── Main attack runner ───────────────────────────────────────────────────────

class Result:
    def __init__(self, method: str, text: str, score: float, details: str = ""):
        self.method = method
        self.text = text
        self.score = score
        self.details = details

    def __repr__(self):
        return f"[{self.score:.2f}] {self.method}: {self.text[:80]}..."


def run_attacks():
    results: List[Result] = []
    ct = GRILLE_CT
    ct_rev = ct[::-1]

    print(f"\n{'='*80}")
    print(f"E-GRILLE-03: Transposition & Pattern Attacks on YAR Grille CT")
    print(f"CT length: {CT_LEN}")
    print(f"CT: {ct}")
    print(f"{'='*80}\n")

    # ── 1. Columnar transposition ────────────────────────────────────────────
    print("[1] Columnar transposition (widths 2-15)...")

    # KRYPTOS key order: K=0,R=1,Y=2,P=3,T=4,O=5,S=6 → alphabetic rank
    kryptos_key = "KRYPTOS"
    kryptos_order = sorted(range(len(kryptos_key)), key=lambda i: kryptos_key[i])
    # kryptos_order gives column read order based on alphabetical sort of KRYPTOS
    # K=10, R=17, Y=24, P=15, T=19, O=14, S=18 → sorted indices: K(0),O(5),P(3),R(1),S(6),T(4),Y(2)

    col_configs_tested = 0
    for width in range(2, 16):
        if width <= 8:
            # For small widths, try all permutations
            for perm in permutations(range(width)):
                text = columnar_decrypt(ct, list(perm))
                sc = composite_score(text)
                if sc > 30:
                    results.append(Result(f"columnar(w={width},order={perm})", text, sc))
                col_configs_tested += 1

                # Also try on reversed CT
                text_r = columnar_decrypt(ct_rev, list(perm))
                sc_r = composite_score(text_r)
                if sc_r > 30:
                    results.append(Result(f"columnar(w={width},order={perm},rev)", text_r, sc_r))
                col_configs_tested += 1
        else:
            # For larger widths, try key-based orders
            # Natural order
            text = columnar_decrypt(ct, list(range(width)))
            sc = composite_score(text)
            if sc > 30:
                results.append(Result(f"columnar(w={width},natural)", text, sc))
            col_configs_tested += 1

            # Reverse order
            text = columnar_decrypt(ct, list(range(width-1, -1, -1)))
            sc = composite_score(text)
            if sc > 30:
                results.append(Result(f"columnar(w={width},reverse)", text, sc))
            col_configs_tested += 1

            # KRYPTOS-based key (truncated or extended)
            if width <= 7:
                key_str = kryptos_key[:width]
            else:
                key_str = (kryptos_key * ((width // 7) + 1))[:width]
            key_order = sorted(range(width), key=lambda i: key_str[i])
            text = columnar_decrypt(ct, key_order)
            sc = composite_score(text)
            if sc > 30:
                results.append(Result(f"columnar(w={width},kryptos_key)", text, sc))
            col_configs_tested += 1

            # Also reverse of kryptos key order
            text = columnar_decrypt(ct, key_order[::-1])
            sc = composite_score(text)
            if sc > 30:
                results.append(Result(f"columnar(w={width},kryptos_key_rev)", text, sc))
            col_configs_tested += 1

            # KA-alphabet based key for this width
            ka_key_str = KA[:width]
            ka_order = sorted(range(width), key=lambda i: ka_key_str[i])
            text = columnar_decrypt(ct, ka_order)
            sc = composite_score(text)
            if sc > 30:
                results.append(Result(f"columnar(w={width},ka_key)", text, sc))
            col_configs_tested += 1

            # All above on reversed CT
            for order, label in [(list(range(width)), "natural"),
                                  (list(range(width-1, -1, -1)), "reverse"),
                                  (key_order, "kryptos_key"),
                                  (key_order[::-1], "kryptos_key_rev"),
                                  (ka_order, "ka_key")]:
                text_r = columnar_decrypt(ct_rev, order)
                sc_r = composite_score(text_r)
                if sc_r > 30:
                    results.append(Result(f"columnar(w={width},{label},rev)", text_r, sc_r))
                col_configs_tested += 1

    print(f"  Tested {col_configs_tested} columnar configurations")

    # ── 2. Rail fence ────────────────────────────────────────────────────────
    print("[2] Rail fence (rails 2-10)...")
    rail_tested = 0
    for rails in range(2, 11):
        for source, label in [(ct, ""), (ct_rev, ",rev")]:
            text = rail_fence_decrypt(source, rails)
            sc = composite_score(text)
            if sc > 30:
                results.append(Result(f"railfence(r={rails}{label})", text, sc))
            rail_tested += 1
    print(f"  Tested {rail_tested} rail fence configurations")

    # ── 3. Route cipher ─────────────────────────────────────────────────────
    print("[3] Route cipher (various grid dimensions)...")
    route_tested = 0
    # Exact and near-fit dimensions
    grid_dims = []
    for r in range(2, 54):
        for c in range(2, 54):
            if r * c == CT_LEN or (r * c >= CT_LEN and r * c <= CT_LEN + 4):
                grid_dims.append((r, c))

    # Add some specific ones
    grid_dims.extend([(2, 53), (53, 2), (10, 11), (11, 10), (7, 16), (16, 7),
                       (8, 14), (14, 8), (9, 12), (12, 9), (6, 18), (18, 6)])
    grid_dims = list(set(grid_dims))

    for nrows, ncols in grid_dims:
        for source, slabel in [(ct, ""), (ct_rev, ",rev")]:
            for route_fn, rlabel in [(route_cipher_spiral, "spiral"),
                                      (route_cipher_snake, "snake"),
                                      (route_cipher_diagonal, "diag"),
                                      (route_cipher_columns, "cols")]:
                text = route_fn(source, nrows, ncols)
                sc = composite_score(text)
                if sc > 30:
                    results.append(Result(f"route({nrows}x{ncols},{rlabel}{slabel})", text, sc))
                route_tested += 1
    print(f"  Tested {route_tested} route cipher configurations")

    # ── 4. Skip/interval reads ──────────────────────────────────────────────
    print("[4] Skip/interval reads (n=2..20, all offsets)...")
    skip_tested = 0
    for skip in range(2, 21):
        for offset in range(skip):
            for source, label in [(ct, ""), (ct_rev, ",rev")]:
                text = skip_read(source, skip, offset)
                sc = composite_score(text)
                if sc > 30:
                    results.append(Result(f"skip(n={skip},off={offset}{label})", text, sc))
                skip_tested += 1
    print(f"  Tested {skip_tested} skip read configurations")

    # ── 5. Simple reversal ──────────────────────────────────────────────────
    print("[5] Simple reversal...")
    sc = composite_score(ct_rev)
    results.append(Result("reverse", ct_rev, sc))

    # ── 6. Combined attacks (transposition + substitution) ──────────────────
    print("[6] Combined attacks (transposition + Vig/Beau/ROT13)...")

    # Collect best transposition outputs to try substitution on
    # First, gather ALL transposition outputs above a low threshold
    trans_candidates = []

    # Re-run key transpositions and collect outputs
    # Columnar width 7 (KRYPTOS length) with all permutations
    for perm in permutations(range(7)):
        text = columnar_decrypt(ct, list(perm))
        trans_candidates.append((f"col7({perm})", text))

    # Key specific columnar widths
    for width in [2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14]:
        text = columnar_decrypt(ct, list(range(width)))
        trans_candidates.append((f"col{width}(nat)", text))
        text = columnar_decrypt(ct, list(range(width-1, -1, -1)))
        trans_candidates.append((f"col{width}(rev)", text))

    # Rail fence
    for rails in range(2, 11):
        text = rail_fence_decrypt(ct, rails)
        trans_candidates.append((f"rail{rails}", text))

    # Skip reads
    for skip in range(2, 11):
        for offset in range(min(skip, 3)):
            text = skip_read(ct, skip, offset)
            trans_candidates.append((f"skip{skip}o{offset}", text))

    # Identity (no transposition)
    trans_candidates.append(("identity", ct))
    trans_candidates.append(("identity_rev", ct_rev))

    combined_tested = 0
    keys = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK"]
    for tlabel, ttext in trans_candidates:
        for key in keys:
            # Vigenère
            pt = vigenere_decrypt(ttext, key)
            sc = composite_score(pt)
            if sc > 30:
                results.append(Result(f"combined({tlabel}+vig({key}))", pt, sc))
            combined_tested += 1

            # Beaufort
            pt = beaufort_decrypt(ttext, key)
            sc = composite_score(pt)
            if sc > 30:
                results.append(Result(f"combined({tlabel}+beau({key}))", pt, sc))
            combined_tested += 1

        # ROT13
        pt = caesar_shift(ttext, 13)
        sc = composite_score(pt)
        if sc > 30:
            results.append(Result(f"combined({tlabel}+rot13)", pt, sc))
        combined_tested += 1

        # All 26 Caesar shifts
        for shift in range(1, 26):
            if shift == 13:
                continue  # already done
            pt = caesar_shift(ttext, shift)
            sc = composite_score(pt)
            if sc > 30:
                results.append(Result(f"combined({tlabel}+caesar({shift}))", pt, sc))
            combined_tested += 1

    print(f"  Tested {combined_tested} combined configurations")

    # ── 7. Crib dragging ────────────────────────────────────────────────────
    print("[7] Crib dragging...")
    crib_results = []

    for crib in CRIBS:
        crib_len = len(crib)
        if crib_len > CT_LEN:
            continue

        for pos in range(CT_LEN - crib_len + 1):
            ct_seg = ct[pos:pos+crib_len]

            # Vigenère key derivation
            vig_key = derive_vig_key_segment(ct_seg, crib)
            pattern = check_key_pattern(vig_key)
            if pattern:
                crib_results.append({
                    "crib": crib,
                    "pos": pos,
                    "variant": "vigenere",
                    "key": vig_key,
                    "pattern": pattern,
                })

            # Beaufort key derivation
            beau_key = derive_beaufort_key_segment(ct_seg, crib)
            pattern = check_key_pattern(beau_key)
            if pattern:
                crib_results.append({
                    "crib": crib,
                    "pos": pos,
                    "variant": "beaufort",
                    "key": beau_key,
                    "pattern": pattern,
                })

    print(f"  Found {len(crib_results)} crib placements with key patterns")

    # ── 8. Additional: Anagram fragments ─────────────────────────────────────
    print("[8] Checking for Kryptos-relevant words in CT...")
    words_in_ct = []
    for length in range(15, 2, -1):
        for i in range(CT_LEN - length + 1):
            frag = ct[i:i+length]
            if frag in ENGLISH_WORDS:
                words_in_ct.append((i, frag))

    if words_in_ct:
        print(f"  Found {len(words_in_ct)} English words directly in CT:")
        for pos, word in words_in_ct[:30]:
            print(f"    pos {pos}: {word}")

    # ── 9. Double transposition ──────────────────────────────────────────────
    print("[9] Double transposition (columnar w=7 KRYPTOS key, then w=7 again)...")
    double_tested = 0
    # First undo one columnar, then undo another
    kryptos_order_7 = sorted(range(7), key=lambda i: "KRYPTOS"[i])

    for perm1 in [kryptos_order_7, list(range(7)), list(range(6, -1, -1))]:
        text1 = columnar_decrypt(ct, perm1)
        for perm2 in permutations(range(7)):
            text2 = columnar_decrypt(text1, list(perm2))
            sc = composite_score(text2)
            if sc > 35:
                results.append(Result(f"double_col(7:{perm1}+7:{perm2})", text2, sc))
            double_tested += 1
    print(f"  Tested {double_tested} double transposition configurations")

    # ── 10. KA-alphabet substitution ─────────────────────────────────────────
    print("[10] KA-alphabet based substitution...")
    # Map each letter through KA → AZ position (KA[i] → ALPH[i])
    ka_to_az = {}
    for i in range(26):
        ka_to_az[KA[i]] = ALPH[i]

    az_to_ka = {}
    for i in range(26):
        az_to_ka[ALPH[i]] = KA[i]

    # Apply KA→AZ substitution
    ka_sub = "".join(ka_to_az[c] for c in ct)
    sc = composite_score(ka_sub)
    results.append(Result("ka_to_az_sub", ka_sub, sc))

    # Apply AZ→KA substitution
    az_sub = "".join(az_to_ka[c] for c in ct)
    sc = composite_score(az_sub)
    results.append(Result("az_to_ka_sub", az_sub, sc))

    # KA sub + columnar w7 KRYPTOS
    for sub_text, sub_label in [(ka_sub, "ka2az"), (az_sub, "az2ka")]:
        for perm in permutations(range(7)):
            text = columnar_decrypt(sub_text, list(perm))
            sc = composite_score(text)
            if sc > 30:
                results.append(Result(f"combined({sub_label}+col7({perm}))", text, sc))

    # ── Results ──────────────────────────────────────────────────────────────
    print(f"\n{'='*80}")
    print(f"RESULTS SUMMARY")
    print(f"{'='*80}\n")

    # Sort by score
    results.sort(key=lambda r: r.score, reverse=True)

    total_tested = col_configs_tested + rail_tested + route_tested + skip_tested + combined_tested + double_tested
    print(f"Total configurations tested: {total_tested:,}")
    print(f"Results above threshold: {len(results)}")

    print(f"\n--- TOP 20 RESULTS ---\n")
    for i, r in enumerate(results[:20]):
        nw, words = count_english_words(r.text)
        qg = quadgram_score(r.text)
        tris = trigram_count(r.text)
        print(f"#{i+1} [{r.score:.2f}] {r.method}")
        print(f"  Text: {r.text}")
        print(f"  Quadgram: {qg:.4f}/char | Words: {nw} | Trigrams: {tris}")
        if words:
            print(f"  Words found: {', '.join(words[:15])}")
        print()

    # Crib results
    if crib_results:
        print(f"\n--- CRIB DRAG RESULTS ({len(crib_results)} pattern matches) ---\n")
        for cr in crib_results[:30]:
            print(f"  Crib={cr['crib']} at pos {cr['pos']} ({cr['variant']})")
            print(f"    Key: {cr['key']} → {cr['pattern']}")
        if len(crib_results) > 30:
            print(f"  ... and {len(crib_results) - 30} more")

    # Words found directly
    if words_in_ct:
        print(f"\n--- ENGLISH WORDS FOUND DIRECTLY IN CT ---")
        for pos, word in words_in_ct:
            print(f"  pos {pos}: {word}")

    print(f"\n{'='*80}")
    print(f"E-GRILLE-03 COMPLETE")
    print(f"{'='*80}")

    return results, crib_results


if __name__ == "__main__":
    results, crib_results = run_attacks()
