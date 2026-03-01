#!/usr/bin/env python3
"""
E-REF-01: Carter Chapter X Running Key Hypothesis

The K3 plaintext contains a single "X" delimiter: "FROM THE MIST X CAN YOU SEE
ANYTHING Q". In K2, X serves as a period/sentence separator. But in K3 there
is only ONE X, and it may be a meta-clue pointing to Chapter X of Carter's
"The Tomb of Tut.ankh.Amen" — titled "Work in the Laboratory."

Chapter X contains the famous bead-work passage, which is an uncanny metaphor
for cryptanalysis: reconstructing the original order of scattered elements
(beads/characters) whose connecting threads (key) have rotted away.

This script:
1. Extracts Chapter X text from both OCR sources (carter_vol1.txt, carter_gutenberg.txt)
2. Tests Chapter X as running key under Vig/Beau/VarBeau with identity transposition
3. Tests Chapter X with columnar transposition (widths 5-13)
4. Tests the specific bead-work passage as running key
5. Uses EAST constraint filter + Bean-EQ for fast elimination
6. Also tests nearby chapters (IX, XI) and the K3 source passage

Output: results/e_ref_01_carter_chapterX.json
"""

import json
import sys
import os
import time
import re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD

CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

# EAST constraint: positions 21-24 and 30-33 both spell EAST
# Under Vig/Beau, source[off+30]-source[off+21] ≡ 1,
# source[off+31]-source[off+22] ≡ 25, etc. (mod 26)
EAST_DIFFS_VIG = [1, 25, 1, 23]  # Also works for Beaufort
EAST_DIFFS_VARBEAU = [25, 1, 25, 3]

BEAN_EQ_POSITIONS = (27, 65)  # k[27] == k[65], gap of 38


def extract_alpha(text):
    """Convert text to list of uppercase letter indices."""
    return [ord(c) - ord('A') for c in text.upper() if c.isalpha()]


def load_chapter_x_vol1():
    """Extract Chapter X from carter_vol1.txt (OCR version)."""
    path = "reference/carter_vol1.txt"
    if not os.path.exists(path):
        return None, "file not found"

    with open(path) as f:
        lines = f.readlines()

    # Find chapter X start and end
    start_line = None
    end_line = None
    for i, line in enumerate(lines):
        stripped = re.sub(r'\s+', ' ', line.strip())
        if re.match(r'^CHAPTER\s+X\s*$', stripped):
            start_line = i
        elif start_line is not None and re.match(r'^CHAPTER\s+XI\s*$', stripped):
            end_line = i
            break

    if start_line is None:
        return None, "Chapter X not found"

    if end_line is None:
        end_line = len(lines)

    chapter_text = ''.join(lines[start_line:end_line])
    return chapter_text, f"lines {start_line}-{end_line}"


def load_chapter_x_gutenberg():
    """Extract Chapter X from carter_gutenberg.txt."""
    path = "reference/carter_gutenberg.txt"
    if not os.path.exists(path):
        return None, "file not found"

    with open(path) as f:
        text = f.read()

    # Find chapter boundaries
    chapters = list(re.finditer(r'CHAPTER\s+(X|IX|XI|VIII|XII)\b', text))
    ch_x_start = None
    ch_x_end = None

    for i, m in enumerate(chapters):
        num = m.group(1).strip()
        if num == 'X':
            ch_x_start = m.start()
        elif ch_x_start is not None and num in ('XI', 'XII'):
            ch_x_end = m.start()
            break

    if ch_x_start is None:
        return None, "Chapter X not found"

    return text[ch_x_start:ch_x_end], f"chars {ch_x_start}-{ch_x_end}"


def load_k3_source_passage():
    """The specific Carter passage used in K3."""
    # This is the passage Sanborn used (with his modifications)
    passage = (
        "SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS THAT "
        "ENCUMBERED THE LOWER PART OF THE DOORWAY WAS REMOVED WITH "
        "TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER LEFT HAND "
        "CORNER AND THEN WIDENING THE HOLE A LITTLE I INSERTED THE "
        "CANDLE AND PEERED IN THE HOT AIR ESCAPING FROM THE CHAMBER "
        "CAUSED THE FLAME TO FLICKER BUT PRESENTLY DETAILS OF THE ROOM "
        "WITHIN EMERGED FROM THE MIST CAN YOU SEE ANYTHING"
    )
    return passage


def check_east_constraint(text_nums, offset, diffs):
    """Check if EAST gap-9 differential holds at given offset."""
    for i, expected_diff in enumerate(diffs):
        pos1 = 21 + i + offset
        pos2 = 30 + i + offset
        if pos2 >= len(text_nums):
            return False
        actual_diff = (text_nums[pos2] - text_nums[pos1]) % MOD
        if actual_diff != expected_diff:
            return False
    return True


def check_bean_eq(text_nums, offset):
    """Check if text[offset+27] == text[offset+65] (Bean equality under identity trans)."""
    p1 = offset + BEAN_EQ_POSITIONS[0]
    p2 = offset + BEAN_EQ_POSITIONS[1]
    if p2 >= len(text_nums):
        return False
    return text_nums[p1] == text_nums[p2]


def score_running_key(text_nums, offset, variant="vig"):
    """Score a running key at given offset under identity transposition.

    For each crib position j, compute key = text[offset+j]
    Then check: does (CT[j] - key) mod 26 == PT[j]  (Vigenere)
    or: does (key - CT[j]) mod 26 == PT[j]  (Beaufort)
    """
    score = 0
    for j in CRIB_POS:
        text_pos = offset + j
        if text_pos >= len(text_nums):
            break
        key_val = text_nums[text_pos]

        if variant == "vig":
            pt_val = (CT_NUM[j] - key_val) % MOD
        elif variant == "beau":
            pt_val = (key_val - CT_NUM[j]) % MOD
        else:  # varbeau
            pt_val = (CT_NUM[j] + key_val) % MOD

        if pt_val == CRIB_PT[j]:
            score += 1

    return score


def columnar_decrypt_perm(width, n, col_order):
    """Return permutation mapping CT position -> PT position for columnar decryption."""
    rows = (n + width - 1) // width
    n_long = n % width
    if n_long == 0:
        n_long = width

    ct_to_pt = [0] * n
    ct_pos = 0
    for col in col_order:
        col_len = rows if col < n_long else rows - 1
        for row in range(col_len):
            pt_pos = row * width + col
            if pt_pos < n:
                ct_to_pt[ct_pos] = pt_pos
                ct_pos += 1

    return ct_to_pt


def score_with_transposition(text_nums, offset, ct_to_pt, variant="vig"):
    """Score running key with transposition.

    After undoing transposition, PT position j has CT value from CT[perm_inv[j]].
    Key at position j: text[offset + j]
    """
    # Build inverse: pt_to_ct[j] = CT position that maps to PT position j
    pt_to_ct = [0] * N
    for ct_pos in range(N):
        pt_to_ct[ct_to_pt[ct_pos]] = ct_pos

    score = 0
    bean_keys = {}
    for j in CRIB_POS:
        text_pos = offset + j
        if text_pos >= len(text_nums):
            break

        key_val = text_nums[text_pos]
        ct_val = CT_NUM[pt_to_ct[j]]

        if variant == "vig":
            pt_val = (ct_val - key_val) % MOD
        elif variant == "beau":
            pt_val = (key_val - ct_val) % MOD
        else:
            pt_val = (ct_val + key_val) % MOD

        if pt_val == CRIB_PT[j]:
            score += 1

        # Store key for Bean check
        if variant == "vig":
            bean_keys[j] = (ct_val - CRIB_PT[j]) % MOD
        elif variant == "beau":
            bean_keys[j] = (ct_val + CRIB_PT[j]) % MOD
        else:
            bean_keys[j] = (CRIB_PT[j] - ct_val) % MOD

    bean_eq = bean_keys.get(27) == bean_keys.get(65)
    return score, bean_eq


def main():
    print("=" * 60)
    print("E-REF-01: Carter Chapter X Running Key Hypothesis")
    print("=" * 60)
    print("  Hypothesis: K3's X delimiter points to Carter Chapter X")
    print()

    t0 = time.time()
    all_results = []
    total_configs = 0

    # Load texts
    texts = {}

    ch_x_v1, info_v1 = load_chapter_x_vol1()
    if ch_x_v1:
        texts["chapter_x_vol1"] = extract_alpha(ch_x_v1)
        print(f"  Chapter X (vol1): {len(texts['chapter_x_vol1'])} chars ({info_v1})")

    ch_x_gut, info_gut = load_chapter_x_gutenberg()
    if ch_x_gut:
        texts["chapter_x_gutenberg"] = extract_alpha(ch_x_gut)
        print(f"  Chapter X (gutenberg): {len(texts['chapter_x_gutenberg'])} chars ({info_gut})")

    # Also load full Carter texts for comparison
    if os.path.exists("reference/carter_vol1.txt"):
        with open("reference/carter_vol1.txt") as f:
            texts["carter_full_vol1"] = extract_alpha(f.read())
        print(f"  Full Carter vol1: {len(texts['carter_full_vol1'])} chars")

    if os.path.exists("reference/carter_gutenberg.txt"):
        with open("reference/carter_gutenberg.txt") as f:
            texts["carter_full_gutenberg"] = extract_alpha(f.read())
        print(f"  Full Carter gutenberg: {len(texts['carter_full_gutenberg'])} chars")

    # K3 source passage
    k3_passage = load_k3_source_passage()
    texts["k3_source_passage"] = extract_alpha(k3_passage)
    print(f"  K3 source passage: {len(texts['k3_source_passage'])} chars")

    # Also extract bead-work specific passage
    if ch_x_v1:
        bead_match = re.search(r'[Bb]ead.?work\s+is\s+in\s+itself', ch_x_v1)
        if bead_match:
            bead_text = ch_x_v1[bead_match.start():bead_match.start() + 5000]
            texts["beadwork_passage"] = extract_alpha(bead_text)
            print(f"  Beadwork passage: {len(texts['beadwork_passage'])} chars")

    print()

    # Phase 1: Identity transposition (running key scan)
    print("PHASE 1: Identity transposition — EAST + Bean filter")
    print("-" * 60)

    for text_name, text_nums in texts.items():
        max_offset = len(text_nums) - 74  # Need at least up to position 73
        if max_offset < 0:
            print(f"  {text_name}: too short ({len(text_nums)} chars), skipping")
            continue

        east_hits = 0
        bean_hits = 0
        full_hits = 0

        for variant, diffs in [("vig", EAST_DIFFS_VIG), ("beau", EAST_DIFFS_VIG),
                                ("varbeau", EAST_DIFFS_VARBEAU)]:
            for off in range(max_offset):
                total_configs += 1

                if not check_east_constraint(text_nums, off, diffs):
                    continue
                east_hits += 1

                if not check_bean_eq(text_nums, off):
                    continue
                bean_hits += 1

                # Full crib check
                score = score_running_key(text_nums, off, variant)
                if score >= 15:
                    full_hits += 1
                    result = {
                        "text": text_name,
                        "variant": variant,
                        "offset": off,
                        "score": score,
                        "model": "identity",
                    }
                    all_results.append(result)
                    print(f"    HIT: {text_name} {variant} off={off} score={score}/24")

                if score == 24:
                    # Try to recover plaintext
                    pt_chars = []
                    for j in range(N):
                        key_val = text_nums[off + j] if off + j < len(text_nums) else 0
                        if variant == "vig":
                            pt_val = (CT_NUM[j] - key_val) % MOD
                        elif variant == "beau":
                            pt_val = (key_val - CT_NUM[j]) % MOD
                        else:
                            pt_val = (CT_NUM[j] + key_val) % MOD
                        pt_chars.append(chr(pt_val + ord('A')))
                    print(f"    *** BREAKTHROUGH: PT = {''.join(pt_chars)}")

        print(f"  {text_name}: EAST={east_hits} Bean-EQ={bean_hits} "
              f"Full≥15={full_hits} ({max_offset} offsets × 3 variants)")

    # Phase 2: Columnar transposition widths 8-13 (matches 8-row grid hypothesis)
    print(f"\nPHASE 2: Columnar transposition (widths 5-13)")
    print("-" * 60)

    from itertools import permutations as perms

    for width in [8, 13, 7, 9, 10, 11, 5, 6, 12]:
        n_orderings = 1
        for i in range(2, width + 1):
            n_orderings *= i

        if n_orderings > 1_000_000:
            print(f"  Width {width}: {n_orderings:,} orderings — SKIPPING (too large)")
            continue

        print(f"  Width {width}: {n_orderings} orderings")

        for text_name in ["chapter_x_vol1", "chapter_x_gutenberg", "beadwork_passage"]:
            if text_name not in texts:
                continue
            text_nums = texts[text_name]
            max_offset = len(text_nums) - N
            if max_offset < 0:
                continue

            best_score = 0
            hits = 0

            for col_order in perms(range(width)):
                ct_to_pt = columnar_decrypt_perm(width, N, list(col_order))

                for off in range(0, max_offset, 1):
                    for variant in ["vig", "beau", "varbeau"]:
                        total_configs += 1
                        score, bean_eq = score_with_transposition(
                            text_nums, off, ct_to_pt, variant)

                        if score > best_score:
                            best_score = score

                        if score >= 18 and bean_eq:
                            hits += 1
                            result = {
                                "text": text_name,
                                "width": width,
                                "col_order": list(col_order),
                                "variant": variant,
                                "offset": off,
                                "score": score,
                                "bean_eq": bean_eq,
                                "model": "columnar",
                            }
                            all_results.append(result)
                            print(f"    HIT: {text_name} w={width} {variant} "
                                  f"off={off} score={score}/24 Bean=PASS")

            print(f"    {text_name} w={width}: best={best_score}/24, hits≥18+Bean={hits}")

        elapsed = time.time() - t0
        print(f"    [{elapsed:.0f}s] {total_configs:,} total configs", flush=True)

    elapsed = time.time() - t0

    print(f"\n{'=' * 60}")
    print(f"SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Total configs: {total_configs:,}")
    print(f"  Time: {elapsed:.1f}s")
    print(f"  Hits (Phase 1 ≥15 | Phase 2 ≥18+Bean): {len(all_results)}")

    if all_results:
        all_results.sort(key=lambda r: -r['score'])
        for r in all_results[:10]:
            print(f"    {r['text']} {r['variant']} "
                  f"{'w=' + str(r.get('width', '-')) + ' ' if 'width' in r else ''}"
                  f"off={r['offset']} score={r['score']}/24")

    verdict = "SIGNAL" if any(r['score'] >= 18 for r in all_results) else "NOISE"
    print(f"\n  Verdict: {verdict}")

    os.makedirs("results", exist_ok=True)
    artifact = {
        "experiment": "E-REF-01",
        "description": "Carter Chapter X as running key (X delimiter hypothesis)",
        "hypothesis": "K3 X delimiter points to Carter Ch.X; beadwork = transposition metaphor",
        "texts_tested": list(texts.keys()),
        "text_sizes": {k: len(v) for k, v in texts.items()},
        "total_configs": total_configs,
        "hits": len(all_results),
        "verdict": verdict,
        "top_results": all_results[:20],
        "elapsed_seconds": round(elapsed, 1),
    }
    with open("results/e_ref_01_carter_chapterX.json", "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"\n  Artifact: results/e_ref_01_carter_chapterX.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_ref_01_carter_chapterX.py")


if __name__ == "__main__":
    main()
