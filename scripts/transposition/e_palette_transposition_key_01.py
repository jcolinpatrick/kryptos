#!/usr/bin/env python3
"""
Cipher: columnar transposition + substitution
Family: transposition
Status: active
Keyspace: ~30K (5040 perms × targets × cipher combos)
Last run: 2026-03-23
Best score: TBD

Test the null palette letters {B,G,I,K,O,W,Z} as a columnar transposition key.
The 7 palette letters define column reading order for width-7 grids.

Tests:
1. All 5040 orderings on CT97 → score_cribs (fixed positions)
2. All 5040 orderings on CT73 (after null extraction) → score_free (floating cribs)
3. Combined transposition + Beaufort/Vigenere with KRYPTOS key on transposed CT97
4. Specific KA-ranked permutation [3,5,4,1,0,2,6] (K=1st,O=2nd,B=3rd,G=4th,I=5th,W=6th,Z=7th)
"""

import sys
import os
import json
import itertools
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    KRYPTOS_ALPHABET, CRIB_DICT, N_CRIBS,
    BEAUFORT_KEYSTREAM_AT_CRIBS,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.scoring.free_crib import score_free


PALETTE_LETTERS = sorted(NULL_PALETTE)  # ['B', 'G', 'I', 'K', 'O', 'W', 'Z']
WIDTH = len(PALETTE_LETTERS)  # 7

# KA ordering for palette letters
KA = KRYPTOS_ALPHABET
KA_INDICES = {ch: KA.index(ch) for ch in PALETTE_LETTERS}
# K=0, R=1, Y=2, P=3, T=4, O=5, S=6, A=7, B=8, C=9, D=10, E=11, F=12, G=13, H=14, I=15, J=16, L=17, M=18, N=19, Q=20, U=21, V=22, W=23, X=24, Z=25
# KA rank: K(0), O(5), B(8), G(13), I(15), W(23), Z(25)
# sorted by KA index: K,O,B,G,I,W,Z → rank in alphabetical palette: K=3, O=4, B=0, G=1, I=2, W=5, Z=6
# Column read order when using KA ranking: read column of the letter with smallest KA index first

# Build the CT73 by removing consensus null positions
CT73_CHARS = [CT[i] for i in range(CT_LEN) if i not in CONSENSUS_NULL_POSITIONS]
CT73 = "".join(CT73_CHARS)


def columnar_read(text, width, col_order):
    """Write text into rows of given width, read columns in col_order.

    text is written left-to-right into rows.
    col_order[i] = which column to read as the i-th output block.
    """
    nrows = (len(text) + width - 1) // width
    # Pad with a sentinel that won't appear in real text
    padded = text + "\x00" * (nrows * width - len(text))

    # Write into grid (row-major)
    grid = []
    for r in range(nrows):
        grid.append(padded[r * width:(r + 1) * width])

    # Read columns in specified order
    result = []
    for col in col_order:
        for r in range(nrows):
            ch = grid[r][col]
            if ch != "\x00":
                result.append(ch)
    return "".join(result)


def columnar_unread(text, width, col_order):
    """Inverse of columnar_read: given text that was produced by columnar_read,
    reconstruct the original row-major text.

    This UNDOES a columnar transposition, i.e., if someone wrote into columns
    in col_order and read row-by-row, this recovers row-by-row text.
    """
    total = len(text)
    nrows = (total + width - 1) // width
    full_cols = total % width if total % width != 0 else width
    # Actually: columns that have nrows chars vs nrows-1 chars
    # If total = nrows*width, all cols have nrows chars
    # If total < nrows*width, only some cols have nrows chars

    # Number of full-height columns
    n_full = total - (nrows - 1) * width  # = total mod width, or width if exact
    if total % width == 0:
        n_full = width

    # Determine which columns (in read order) are full vs short
    # The first n_full columns in the ORIGINAL grid order have nrows chars
    # But we read them in col_order, so:
    col_lengths = {}
    for c in range(width):
        if c < n_full:
            col_lengths[c] = nrows
        else:
            col_lengths[c] = nrows - 1

    # Split text into columns according to col_order
    columns = {}
    pos = 0
    for col in col_order:
        clen = col_lengths[col]
        columns[col] = text[pos:pos + clen]
        pos += clen

    # Reconstruct row-major
    result = []
    for r in range(nrows):
        for c in range(width):
            if r < len(columns.get(c, "")):
                result.append(columns[c][r])
    return "".join(result)


def beaufort_decrypt(ct_char, key_char):
    """Beaufort decrypt: PT = (KEY - CT) mod 26, A=0."""
    return chr((ord(key_char) - ord(ct_char)) % 26 + ord('A'))


def vigenere_decrypt(ct_char, key_char):
    """Vigenere decrypt: PT = (CT - KEY) mod 26, A=0."""
    return chr((ord(ct_char) - ord(key_char)) % 26 + ord('A'))


def apply_periodic_key(text, key, decrypt_fn):
    """Apply periodic key to text using given decrypt function."""
    result = []
    klen = len(key)
    for i, ch in enumerate(text):
        result.append(decrypt_fn(ch, key[i % klen]))
    return "".join(result)


def perm_to_label(perm):
    """Convert permutation to readable label using palette letters."""
    return "".join(PALETTE_LETTERS[i] for i in perm)


def run_test1():
    """Test 1: All 5040 orderings on CT97, score with fixed-position cribs."""
    print(f"\n{'='*60}")
    print("TEST 1: Palette columnar transposition on CT97 (fixed cribs)")
    print(f"{'='*60}")
    print(f"CT97: {CT} (len={CT_LEN})")
    print(f"Width: {WIDTH}, Rows: {(CT_LEN + WIDTH - 1) // WIDTH}")
    print(f"Palette letters (alphabetical): {PALETTE_LETTERS}")

    best_results = []

    for perm in itertools.permutations(range(WIDTH)):
        # Forward: write CT97 row-by-row, read columns in perm order
        transposed = columnar_read(CT, WIDTH, perm)
        s1 = score_cribs(transposed)
        if s1 >= 4:
            best_results.append(("read", perm, s1, transposed))

        # Inverse: undo columnar transposition (CT97 was produced BY columnar, undo it)
        untransposed = columnar_unread(CT, WIDTH, perm)
        s2 = score_cribs(untransposed)
        if s2 >= 4:
            best_results.append(("unread", perm, s2, untransposed))

    best_results.sort(key=lambda x: -x[2])
    print(f"\nTotal permutations tested: 5040 × 2 directions = 10080")
    print(f"Results with score >= 4: {len(best_results)}")

    for direction, perm, score, text in best_results[:20]:
        label = perm_to_label(perm)
        print(f"  {direction} perm={list(perm)} ({label}) score={score}/24 text={text[:40]}...")

    return best_results


def run_test2():
    """Test 2: All 5040 orderings on CT73, score with free-floating cribs."""
    print(f"\n{'='*60}")
    print("TEST 2: Palette columnar transposition on CT73 (free cribs)")
    print(f"{'='*60}")
    print(f"CT73: {CT73} (len={len(CT73)})")
    print(f"Width: {WIDTH}, Rows: {(len(CT73) + WIDTH - 1) // WIDTH}")

    best_results = []

    for perm in itertools.permutations(range(WIDTH)):
        # Forward
        transposed = columnar_read(CT73, WIDTH, perm)
        fr = score_free(transposed)
        if fr.score > 0 or (fr.ene_fragments and len(fr.ene_fragments) > 0) or (fr.bc_fragments and len(fr.bc_fragments) > 0):
            n_frags = (len(fr.ene_fragments) if fr.ene_fragments else 0) + (len(fr.bc_fragments) if fr.bc_fragments else 0)
            best_frag_len = 0
            if fr.ene_fragments:
                best_frag_len = max(best_frag_len, max(len(f[0]) for f in fr.ene_fragments))
            if fr.bc_fragments:
                best_frag_len = max(best_frag_len, max(len(f[0]) for f in fr.bc_fragments))
            if best_frag_len >= 6:
                best_results.append(("read", perm, fr.score, best_frag_len, n_frags, fr.summary, transposed))

        # Inverse
        untransposed = columnar_unread(CT73, WIDTH, perm)
        fr2 = score_free(untransposed)
        if fr2.score > 0 or (fr2.ene_fragments and len(fr2.ene_fragments) > 0) or (fr2.bc_fragments and len(fr2.bc_fragments) > 0):
            n_frags = (len(fr2.ene_fragments) if fr2.ene_fragments else 0) + (len(fr2.bc_fragments) if fr2.bc_fragments else 0)
            best_frag_len = 0
            if fr2.ene_fragments:
                best_frag_len = max(best_frag_len, max(len(f[0]) for f in fr2.ene_fragments))
            if fr2.bc_fragments:
                best_frag_len = max(best_frag_len, max(len(f[0]) for f in fr2.bc_fragments))
            if best_frag_len >= 6:
                best_results.append(("unread", perm, fr2.score, best_frag_len, n_frags, fr2.summary, untransposed))

    best_results.sort(key=lambda x: (-x[2], -x[3]))
    print(f"\nTotal permutations tested: 5040 × 2 directions = 10080")
    print(f"Results with fragment >= 6 chars: {len(best_results)}")

    for direction, perm, score, bfl, nf, summary, text in best_results[:20]:
        label = perm_to_label(perm)
        print(f"  {direction} perm={list(perm)} ({label}) score={score} best_frag={bfl} frags={nf} | {summary}")
        print(f"    text={text[:50]}...")

    return best_results


def run_test3():
    """Test 3: Combined transposition + substitution on CT97."""
    print(f"\n{'='*60}")
    print("TEST 3: Transposition + substitution on CT97")
    print(f"{'='*60}")

    key_kryptos = "KRYPTOS"
    best_results = []

    for perm in itertools.permutations(range(WIDTH)):
        for direction_fn, direction_name in [(columnar_read, "read"), (columnar_unread, "unread")]:
            transposed = direction_fn(CT, WIDTH, perm)

            # Beaufort with KRYPTOS key
            pt_beau = apply_periodic_key(transposed, key_kryptos, beaufort_decrypt)
            s_beau = score_cribs(pt_beau)
            fr_beau = score_free(pt_beau)

            if s_beau >= 4 or fr_beau.score >= 11:
                best_results.append((direction_name, perm, "beau_KRYPTOS", s_beau, fr_beau.score, pt_beau))

            # Vigenere with KRYPTOS key
            pt_vig = apply_periodic_key(transposed, key_kryptos, vigenere_decrypt)
            s_vig = score_cribs(pt_vig)
            fr_vig = score_free(pt_vig)

            if s_vig >= 4 or fr_vig.score >= 11:
                best_results.append((direction_name, perm, "vig_KRYPTOS", s_vig, fr_vig.score, pt_vig))

            # Also try KRYPTOS as key on KA alphabet (period 7 Beaufort in KA)
            # KA Beaufort: PT = KA[(KA.index(KEY) - KA.index(CT)) % 26]
            pt_ka_beau = []
            for i, ch in enumerate(transposed):
                ki = KA.index(key_kryptos[i % len(key_kryptos)])
                ci = KA.index(ch)
                pt_ka_beau.append(KA[(ki - ci) % 26])
            pt_ka_beau_str = "".join(pt_ka_beau)
            s_ka = score_cribs(pt_ka_beau_str)
            fr_ka = score_free(pt_ka_beau_str)

            if s_ka >= 4 or fr_ka.score >= 11:
                best_results.append((direction_name, perm, "beau_KRYPTOS_KA", s_ka, fr_ka.score, pt_ka_beau_str))

    best_results.sort(key=lambda x: (-x[3], -x[4]))
    print(f"\nTotal configs: 5040 perms × 2 dirs × 3 cipher variants = {5040*2*3}")
    print(f"Results with anchored >= 4 or free >= 11: {len(best_results)}")

    for direction, perm, cipher, s_anch, s_free, pt in best_results[:20]:
        label = perm_to_label(perm)
        print(f"  {direction} perm={list(perm)} ({label}) {cipher}: anchored={s_anch}/24 free={s_free}/24")
        print(f"    PT={pt[:50]}...")

    return best_results


def run_test4():
    """Test 4: Specific KA-ranked permutation."""
    print(f"\n{'='*60}")
    print("TEST 4: Specific KA-ranked permutation")
    print(f"{'='*60}")

    # Palette in KA order: K(0), O(5), B(8), G(13), I(15), W(23), Z(25)
    # When letters BGIKOWZ are used as keyword:
    # Alphabetical: B=0, G=1, I=2, K=3, O=4, W=5, Z=6
    # KA order:     K=0, O=1, B=2, G=3, I=4, W=5, Z=6 (rank by KA index)
    # So KA-ranked column read order: column 3 first (K), then 4 (O), then 0 (B), then 1 (G), then 2 (I), then 5 (W), then 6 (Z)
    ka_perm = [3, 4, 0, 1, 2, 5, 6]  # read columns in KA rank order

    # Also try: standard alphabetical order (identity) — trivial but let's confirm
    alpha_perm = [0, 1, 2, 3, 4, 5, 6]  # B,G,I,K,O,W,Z alphabetical

    # Also try reverse alphabetical
    rev_alpha_perm = [6, 5, 4, 3, 2, 1, 0]

    # Also try reverse KA
    rev_ka_perm = [6, 5, 2, 1, 0, 4, 3]

    named_perms = [
        ("KA_rank", ka_perm),
        ("alphabetical", alpha_perm),
        ("reverse_alpha", rev_alpha_perm),
        ("reverse_KA", rev_ka_perm),
    ]

    key_kryptos = "KRYPTOS"

    for name, perm in named_perms:
        print(f"\n--- Permutation: {name} = {perm} ---")

        for direction_fn, direction_name in [(columnar_read, "read"), (columnar_unread, "unread")]:
            for target_name, target in [("CT97", CT), ("CT73", CT73)]:
                transposed = direction_fn(target, WIDTH, perm)

                # Raw transposition scores
                s_anch = score_cribs(transposed) if target_name == "CT97" else 0
                fr = score_free(transposed)

                print(f"  {direction_name} {target_name}: anchored={s_anch}/24 free_score={fr.score}/24 | {fr.summary}")
                print(f"    text={transposed[:50]}...")

                # Beaufort + KRYPTOS
                pt_beau = apply_periodic_key(transposed, key_kryptos, beaufort_decrypt)
                s_b = score_cribs(pt_beau) if target_name == "CT97" else 0
                fr_b = score_free(pt_beau)
                print(f"    +beau_KRYPTOS: anchored={s_b}/24 free={fr_b.score}/24 | {fr_b.summary}")

                # Vigenere + KRYPTOS
                pt_vig = apply_periodic_key(transposed, key_kryptos, vigenere_decrypt)
                s_v = score_cribs(pt_vig) if target_name == "CT97" else 0
                fr_v = score_free(pt_vig)
                print(f"    +vig_KRYPTOS:  anchored={s_v}/24 free={fr_v.score}/24 | {fr_v.summary}")

    return named_perms


def main():
    print("=" * 60)
    print("PALETTE TRANSPOSITION KEY EXPERIMENT")
    print(f"Palette: {PALETTE_LETTERS} (width {WIDTH})")
    print(f"KA: {KA}")
    print(f"KA indices of palette: {KA_INDICES}")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    # Run all tests
    t1_results = run_test1()
    t2_results = run_test2()
    t3_results = run_test3()
    t4_results = run_test4()

    # Compile summary
    t1_best = t1_results[0] if t1_results else None
    t2_best = t2_results[0] if t2_results else None
    t3_best = t3_results[0] if t3_results else None

    # Determine overall best
    all_anchored = [(r[2], r) for r in t1_results] if t1_results else []
    all_anchored += [(r[3], r) for r in t3_results] if t3_results else []

    overall_best_anchored = max(all_anchored, key=lambda x: x[0])[0] if all_anchored else 0

    summary = {
        "experiment": "e_palette_transposition_key_01",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "description": "Null palette letters {B,G,I,K,O,W,Z} as columnar transposition key",
        "parameters": {
            "palette": PALETTE_LETTERS,
            "width": WIDTH,
            "ct97_len": CT_LEN,
            "ct73_len": len(CT73),
            "total_perms": 5040,
            "total_configs": "~30K (5040 perms x 2 dirs x targets x cipher combos)",
        },
        "test1_ct97_fixed_cribs": {
            "total_tested": 10080,
            "hits_ge4": len(t1_results),
            "best_score": t1_results[0][2] if t1_results else 0,
            "best_perm": list(t1_results[0][1]) if t1_results else None,
            "best_direction": t1_results[0][0] if t1_results else None,
            "best_text_prefix": t1_results[0][3][:50] if t1_results else None,
            "top5": [
                {"direction": r[0], "perm": list(r[1]), "label": perm_to_label(r[1]), "score": r[2]}
                for r in t1_results[:5]
            ],
        },
        "test2_ct73_free_cribs": {
            "total_tested": 10080,
            "hits_with_frag_ge6": len(t2_results),
            "best_score": t2_results[0][2] if t2_results else 0,
            "best_frag_len": t2_results[0][3] if t2_results else 0,
            "top5": [
                {"direction": r[0], "perm": list(r[1]), "label": perm_to_label(r[1]),
                 "score": r[2], "best_frag": r[3], "summary": r[5]}
                for r in t2_results[:5]
            ],
        },
        "test3_transposition_plus_cipher": {
            "total_tested": 5040 * 2 * 3,
            "hits": len(t3_results),
            "best_anchored": t3_results[0][3] if t3_results else 0,
            "best_free": max((r[4] for r in t3_results), default=0) if t3_results else 0,
            "top5": [
                {"direction": r[0], "perm": list(r[1]), "label": perm_to_label(r[1]),
                 "cipher": r[2], "anchored": r[3], "free": r[4]}
                for r in t3_results[:5]
            ],
        },
        "overall_best_anchored_score": overall_best_anchored,
        "verdict": "NOISE" if overall_best_anchored <= 6 else ("INTERESTING" if overall_best_anchored <= 9 else "SIGNAL"),
        "conclusion": "",
    }

    # Set conclusion
    if overall_best_anchored <= 6:
        summary["conclusion"] = (
            f"All 5040 permutations of palette letters as width-7 columnar transposition key "
            f"produce max {overall_best_anchored}/24 crib matches. This is within noise "
            f"(expected ~1/24 by chance). Palette letters do NOT define a useful columnar "
            f"transposition key for K4 under any tested model."
        )
    else:
        summary["conclusion"] = (
            f"Best score: {overall_best_anchored}/24. Investigate further."
        )

    # Write results
    results_path = os.path.join(_ROOT, "results", "e_palette_transposition_key.json")
    with open(results_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n{'='*60}")
    print(f"RESULTS WRITTEN: {results_path}")
    print(f"OVERALL BEST ANCHORED: {overall_best_anchored}/24")
    print(f"VERDICT: {summary['verdict']}")
    print(f"{'='*60}")

    return summary


if __name__ == "__main__":
    main()
