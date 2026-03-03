#!/usr/bin/env python3
"""E-VIC-01: VIC-style chain addition key derivation from Cardan grille extract.

Hypothesis: The 106-char grille extract is VIC-cipher-style key material that
requires chain addition (lagged Fibonacci digit expansion) to produce the
transposition key(s) that unscramble K4's carved text into real CT.

Phases:
  1. Digit extraction (5 methods)
  2. Chain addition expansion (6 variants)
  3. Transposition key derivation (sequentialization, disrupted columnar, double columnar)
  4. Permutation application & scoring (free crib search + quadgrams)
  5. T-position exploitation
  6. Keyword-derived seed modification (VIC-style non-carrying subtraction)

Ed Scheidt was CIA Chairman of Crypto Center (1963-1989) — VIC was the most
complex hand cipher of the Cold War. Gillogly says K4's method is bespoke.
"""
from __future__ import annotations

import json
import math
import os
import sys
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    ALPH, ALPH_IDX, CT, CT_LEN, KRYPTOS_ALPHABET, MOD,
)
from kryptos.kernel.transforms.transposition import (
    apply_perm, invert_perm, validate_perm,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
)

# ── Constants ────────────────────────────────────────────────────────────

GRILLE_EXTRACT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
assert len(GRILLE_EXTRACT) == 106

KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]
ALPHABETS = [("AZ", ALPH, ALPH_IDX), ("KA", KRYPTOS_ALPHABET, KA_IDX)]
VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

WIDTHS = [7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
DOUBLE_PAIRS = [(7, 7), (7, 10), (8, 10), (10, 10), (7, 14), (8, 12)]
MAX_OFFSET = 20

# ── Quadgram scorer ─────────────────────────────────────────────────────

QUADGRAMS: Dict[str, float] = {}
QG_FLOOR = -10.0


def load_quadgrams():
    global QUADGRAMS, QG_FLOOR
    qpath = os.path.join(os.path.dirname(__file__), "..", "data", "english_quadgrams.json")
    with open(qpath) as f:
        QUADGRAMS = json.load(f)
    QG_FLOOR = min(QUADGRAMS.values()) - 1.0


def qscore(text: str) -> float:
    if len(text) < 4:
        return QG_FLOOR
    total = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i + 4]
        total += QUADGRAMS.get(qg, QG_FLOOR)
    return total / (len(text) - 3)


# ── Phase 1: Digit extraction ───────────────────────────────────────────

def extract_digits_m1(extract: str) -> List[int]:
    """M1: ord(c) - ord('A') mod 10."""
    return [(ord(c) - 65) % 10 for c in extract]


def extract_digits_m2(extract: str) -> List[int]:
    """M2: KA.index(c) mod 10."""
    return [KA_IDX[c] % 10 for c in extract]


def extract_digits_m3(extract: str) -> List[int]:
    """M3: ord(c) - ord('A') (full 0-25 values, mod 26)."""
    return [ord(c) - 65 for c in extract]


def extract_digits_m4(extract: str) -> List[int]:
    """M4: pair-based (v[2i]*26 + v[2i+1]) mod 10."""
    vals = [ord(c) - 65 for c in extract]
    result = []
    for i in range(0, len(vals) - 1, 2):
        result.append((vals[i] * 26 + vals[i + 1]) % 10)
    return result


def extract_digits_m5(extract: str) -> List[int]:
    """M5: adjacent sum (v[i] + v[i+1]) mod 10."""
    vals = [ord(c) - 65 for c in extract]
    return [(vals[i] + vals[i + 1]) % 10 for i in range(len(vals) - 1)]


DIGIT_METHODS = [
    ("M1_ord_mod10", extract_digits_m1, 10),
    ("M2_ka_mod10", extract_digits_m2, 10),
    ("M3_ord_full", extract_digits_m3, 26),
    ("M4_pair_mod10", extract_digits_m4, 10),
    ("M5_adjsum_mod10", extract_digits_m5, 10),
]

# ── Phase 2: Chain addition ─────────────────────────────────────────────

def chain_add(digits: List[int], modulus: int = 10) -> List[int]:
    """VIC-style chain addition: d_new = (d[-1] + d[-2]) mod M."""
    extended = list(digits)
    n = len(digits)
    for _ in range(n):
        extended.append((extended[-1] + extended[-2]) % modulus)
    return extended


def chain_add_triple(digits: List[int], modulus: int = 10) -> List[int]:
    """Triple chain addition: d_new = (d[-1] + d[-2] + d[-3]) mod M."""
    if len(digits) < 3:
        return list(digits)
    extended = list(digits)
    n = len(digits)
    for _ in range(n):
        extended.append((extended[-1] + extended[-2] + extended[-3]) % modulus)
    return extended


def expand_chain(digits: List[int], rounds: int, modulus: int, triple: bool = False) -> List[int]:
    """Apply chain addition for the given number of rounds."""
    result = list(digits)
    fn = chain_add_triple if triple else chain_add
    for _ in range(rounds):
        result = fn(result, modulus)
    return result


# Chain addition variants: (label, rounds, triple)
CHAIN_VARIANTS = [
    ("1round", 1, False),
    ("2round", 2, False),
    ("3round", 3, False),
    ("1round_triple", 1, True),
    ("2round_triple", 2, True),
    ("3round_triple", 3, True),
]

# ── Phase 3: Transposition key derivation ────────────────────────────────

def sequentialize(digits: List[int]) -> List[int]:
    """Rank digits to produce a permutation (ties broken left-to-right)."""
    indexed = [(d, i) for i, d in enumerate(digits)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    perm = [0] * len(digits)
    for rank, (_, pos) in enumerate(ranked):
        perm[pos] = rank
    return perm


def columnar_from_key(col_order: List[int], width: int, length: int = 97) -> List[int]:
    """Build columnar transposition permutation from column ordering."""
    cols: dict[int, list[int]] = defaultdict(list)
    for pos in range(length):
        _, c = divmod(pos, width)
        cols[c].append(pos)
    perm: list[int] = []
    for rank in range(width):
        col_idx = col_order.index(rank)
        perm.extend(cols[col_idx])
    return perm


def disrupted_columnar_perm(col_order: List[int], width: int, length: int = 97) -> List[int]:
    """VIC-style disrupted columnar transposition.

    Fill: write into grid but 'disrupt' by filling a triangle first,
    starting at the column with the highest key digit.
    Then fill the remainder normally. Read columns in key order.
    """
    nrows = math.ceil(length / width)
    grid = [[-1] * width for _ in range(nrows)]

    disrupt_col = col_order.index(max(col_order))

    pos = 0
    triangle_done_row = nrows  # default: no triangle phase

    for row in range(nrows):
        end_col = min(disrupt_col + row + 1, width)
        for col in range(end_col):
            if pos < length:
                grid[row][col] = pos
                pos += 1
        if end_col >= width:
            triangle_done_row = row + 1
            break

    # Phase 2: Fill remaining cells left-to-right, top-to-bottom
    for row in range(nrows):
        for col in range(width):
            if grid[row][col] == -1 and pos < length:
                grid[row][col] = pos
                pos += 1

    # Read by column order
    perm = []
    for rank in range(width):
        col_idx = col_order.index(rank)
        for row in range(nrows):
            val = grid[row][col_idx]
            if val != -1 and val < length:
                perm.append(val)
    return perm


def noncary_subtract(digits: List[int], keyword_digits: List[int], modulus: int = 10) -> List[int]:
    """VIC-style non-carrying subtraction."""
    klen = len(keyword_digits)
    return [(digits[i] - keyword_digits[i % klen]) % modulus for i in range(len(digits))]


def keyword_to_digits(keyword: str, use_ka: bool = False) -> List[int]:
    """Convert keyword to digits via alphabet index mod 10."""
    idx = KA_IDX if use_ka else ALPH_IDX
    return [idx[c] % 10 for c in keyword.upper()]


# ── Phase 4: Scoring ────────────────────────────────────────────────────

def try_decrypt_and_score(
    real_ct: str,
    perm_label: str,
    hits: list,
    top_n: list,
    configs_tested: list,  # mutable counter [count]
) -> None:
    """Try all keyword × alphabet × variant combinations, score each."""
    for kw_name in KEYWORDS:
        for alph_name, alph_str, alph_idx in ALPHABETS:
            key_ints = [alph_idx[kw_name[i % len(kw_name)]] for i in range(CT_LEN)]
            for variant in VARIANTS:
                pt = decrypt_text(real_ct, key_ints, variant)
                configs_tested[0] += 1

                # Free crib search
                ene_pos = pt.find("EASTNORTHEAST")
                bc_pos = pt.find("BERLINCLOCK")

                qg = qscore(pt)

                if ene_pos >= 0 or bc_pos >= 0:
                    hit = {
                        "perm": perm_label,
                        "keyword": kw_name,
                        "alphabet": alph_name,
                        "variant": variant.value,
                        "pt": pt,
                        "ene_pos": ene_pos,
                        "bc_pos": bc_pos,
                        "qg": qg,
                    }
                    hits.append(hit)
                    print(f"\n*** HIT *** {hit}")

                # Track top-N by quadgram
                if len(top_n) < 20 or qg > top_n[-1][0]:
                    entry = (qg, perm_label, kw_name, alph_name, variant.value, pt[:40])
                    top_n.append(entry)
                    top_n.sort(key=lambda x: x[0], reverse=True)
                    if len(top_n) > 20:
                        top_n.pop()


def process_perm(
    perm: List[int],
    label: str,
    hits: list,
    top_n: list,
    configs_tested: list,
) -> None:
    """Apply permutation (both directions) and score."""
    for direction, p in [("fwd", perm), ("inv", invert_perm(perm))]:
        if not validate_perm(p, CT_LEN):
            continue
        real_ct = apply_perm(CT, p)
        dir_label = f"{label}|{direction}"
        try_decrypt_and_score(real_ct, dir_label, hits, top_n, configs_tested)


# ── Phase 5: T-position exploitation ────────────────────────────────────

def t_gap_digits(extract: str) -> List[int]:
    """Encode T-absence as digit stream: distances between positions where T 'should' appear."""
    # T has ~6.5% frequency in English. In 106 chars, expect ~7 T's.
    # Positions where T is absent but expected (every ~15 chars)
    t_ord = ord('T') - 65  # = 19
    # Use positions of letters nearest to T (S=18, U=20) as markers
    markers = []
    for i, c in enumerate(extract):
        v = ord(c) - 65
        if v in (18, 20):  # S or U adjacent to T
            markers.append(i)
    if len(markers) < 2:
        return []
    # Gaps between markers
    gaps = [markers[i + 1] - markers[i] for i in range(len(markers) - 1)]
    return [g % 10 for g in gaps]


def t_position_digits(extract: str) -> List[int]:
    """Positions where T would alphabetically fall, encoded as digits."""
    # T=19 in A-Z. Find chars with value >= 19 vs < 19 transitions
    result = []
    for i, c in enumerate(extract):
        v = ord(c) - 65
        if v >= 19:  # At or past T
            result.append(i % 10)
    return result


# ── Main execution ──────────────────────────────────────────────────────

def main():
    t0 = time.time()
    print("=" * 72)
    print("E-VIC-01: VIC-Style Chain Addition Key Derivation")
    print("=" * 72)
    print(f"Grille extract: {GRILLE_EXTRACT} ({len(GRILLE_EXTRACT)} chars)")
    print(f"K4 CT: {CT} ({CT_LEN} chars)")
    print()

    load_quadgrams()
    print(f"Loaded {len(QUADGRAMS)} quadgrams")

    hits: list = []
    top_n: list = []
    configs_tested = [0]
    perms_tested = 0

    # ── Phase 1+2+3: Digit extraction → chain addition → key derivation ──

    # Collect all digit streams (Phase 1 + Phase 5 T-methods)
    digit_streams: List[Tuple[str, List[int], int]] = []

    for method_name, method_fn, modulus in DIGIT_METHODS:
        digits = method_fn(GRILLE_EXTRACT)
        digit_streams.append((method_name, digits, modulus))

    # Phase 5: T-position digit streams
    t_gap = t_gap_digits(GRILLE_EXTRACT)
    if len(t_gap) >= 4:
        digit_streams.append(("T_gap", t_gap, 10))
    t_pos = t_position_digits(GRILLE_EXTRACT)
    if len(t_pos) >= 4:
        digit_streams.append(("T_pos", t_pos, 10))

    print(f"\nPhase 1/5: {len(digit_streams)} digit streams generated")
    for name, digits, mod in digit_streams:
        print(f"  {name}: {len(digits)} digits (mod {mod}), first 20: {digits[:20]}")

    # Phase 2: Expand each stream via chain addition
    expanded_streams: List[Tuple[str, List[int], int]] = []

    for stream_name, digits, modulus in digit_streams:
        # Also include raw (no chain addition)
        expanded_streams.append((f"{stream_name}|raw", digits, modulus))

        for chain_label, rounds, triple in CHAIN_VARIANTS:
            # For mod-26 streams, use mod 26; for mod-10, use mod 10
            expanded = expand_chain(digits, rounds, modulus, triple)
            expanded_streams.append((f"{stream_name}|{chain_label}", expanded, modulus))

    print(f"\nPhase 2: {len(expanded_streams)} expanded streams")

    # Phase 3+4: Derive transposition keys and test

    # 3A: Single columnar (sequentialized segments)
    print("\nPhase 3A: Single columnar (normal + disrupted)...")
    phase3a_perms = 0
    for stream_name, stream, modulus in expanded_streams:
        for width in WIDTHS:
            if len(stream) < width:
                continue
            max_off = min(MAX_OFFSET, len(stream) - width)
            for offset in range(max_off + 1):
                segment = stream[offset:offset + width]
                col_order = sequentialize(segment)

                # Normal columnar
                perm = columnar_from_key(col_order, width, CT_LEN)
                if len(perm) == CT_LEN:
                    label = f"{stream_name}|w{width}|off{offset}|col"
                    process_perm(perm, label, hits, top_n, configs_tested)
                    phase3a_perms += 1

                # Disrupted columnar
                perm_d = disrupted_columnar_perm(col_order, width, CT_LEN)
                if len(perm_d) == CT_LEN and validate_perm(perm_d, CT_LEN):
                    label = f"{stream_name}|w{width}|off{offset}|disrupt"
                    process_perm(perm_d, label, hits, top_n, configs_tested)
                    phase3a_perms += 1

    print(f"  Tested {phase3a_perms} permutations ({configs_tested[0]} decrypt configs)")

    # 3B: Double columnar
    print("\nPhase 3B: Double columnar...")
    phase3b_perms = 0
    for stream_name, stream, modulus in expanded_streams:
        for w1, w2 in DOUBLE_PAIRS:
            if len(stream) < w1 + w2:
                continue
            seg1 = stream[:w1]
            seg2 = stream[w1:w1 + w2]
            co1 = sequentialize(seg1)
            co2 = sequentialize(seg2)

            p1 = columnar_from_key(co1, w1, CT_LEN)
            p2 = columnar_from_key(co2, w2, CT_LEN)

            if len(p1) == CT_LEN and len(p2) == CT_LEN:
                # Apply p1 then p2
                combined_12 = [p1[p2[i]] for i in range(CT_LEN)]
                if validate_perm(combined_12, CT_LEN):
                    label = f"{stream_name}|dbl_w{w1}x{w2}|12"
                    process_perm(combined_12, label, hits, top_n, configs_tested)
                    phase3b_perms += 1

                # Apply p2 then p1
                combined_21 = [p2[p1[i]] for i in range(CT_LEN)]
                if validate_perm(combined_21, CT_LEN):
                    label = f"{stream_name}|dbl_w{w1}x{w2}|21"
                    process_perm(combined_21, label, hits, top_n, configs_tested)
                    phase3b_perms += 1

    print(f"  Tested {phase3b_perms} permutations ({configs_tested[0]} decrypt configs)")

    # Phase 6: Keyword-derived seed modification (VIC-style non-carrying subtraction)
    print("\nPhase 6: Keyword-derived seed modification...")
    phase6_perms = 0
    for stream_name, stream, modulus in expanded_streams:
        for kw in KEYWORDS:
            kw_digits_az = keyword_to_digits(kw, use_ka=False)
            kw_digits_ka = keyword_to_digits(kw, use_ka=True)

            for kd_label, kw_d in [("AZ", kw_digits_az), ("KA", kw_digits_ka)]:
                modified = noncary_subtract(stream, kw_d, modulus)

                for width in WIDTHS:
                    if len(modified) < width:
                        continue
                    # Only test offset 0 for keyword-modified to limit explosion
                    max_off_kw = min(5, len(modified) - width)
                    for offset in range(max_off_kw + 1):
                        segment = modified[offset:offset + width]
                        col_order = sequentialize(segment)

                        perm = columnar_from_key(col_order, width, CT_LEN)
                        if len(perm) == CT_LEN:
                            label = f"{stream_name}|kw_{kw}_{kd_label}|w{width}|off{offset}"
                            process_perm(perm, label, hits, top_n, configs_tested)
                            phase6_perms += 1

    print(f"  Tested {phase6_perms} permutations ({configs_tested[0]} decrypt configs)")

    # ── Summary ──────────────────────────────────────────────────────────

    elapsed = time.time() - t0
    total_perms = phase3a_perms + phase3b_perms + phase6_perms

    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"Total permutations tested: {total_perms}")
    print(f"Total decrypt configs tested: {configs_tested[0]}")
    print(f"Elapsed: {elapsed:.1f}s ({configs_tested[0] / max(elapsed, 0.1):.0f} configs/sec)")
    print(f"\nCrib hits: {len(hits)}")

    if hits:
        print("\n*** CRIB HITS ***")
        for h in hits:
            print(f"  ENE@{h['ene_pos']} BC@{h['bc_pos']} | {h['perm']} "
                  f"| {h['keyword']}/{h['alphabet']}/{h['variant']} "
                  f"| qg={h['qg']:.3f}")
            print(f"    PT: {h['pt']}")
    else:
        print("  (none)")

    print(f"\nTop 20 by quadgram score:")
    for i, (qg, label, kw, alph, var, pt_prefix) in enumerate(top_n):
        print(f"  {i + 1:2d}. qg={qg:.4f} | {kw}/{alph}/{var} | {label}")
        print(f"      PT: {pt_prefix}...")

    # Save results
    out_path = os.path.join(os.path.dirname(__file__), "..", "kbot_results", "e_vic_01_chain_addition.json")
    result = {
        "experiment": "E-VIC-01",
        "description": "VIC-style chain addition key derivation from Cardan grille extract",
        "total_permutations": total_perms,
        "total_configs": configs_tested[0],
        "elapsed_seconds": round(elapsed, 1),
        "crib_hits": hits,
        "top_20_quadgram": [
            {"qg": qg, "label": label, "keyword": kw, "alphabet": alph,
             "variant": var, "pt_prefix": pt_prefix}
            for qg, label, kw, alph, var, pt_prefix in top_n
        ],
    }
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nResults saved to {out_path}")

    if hits:
        print("\n*** INVESTIGATE HITS IMMEDIATELY ***")
        return 0
    else:
        print("\nNo crib hits. Chain addition alone does not produce the permutation.")
        print("This eliminates VIC-style derivation from the grille extract.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
