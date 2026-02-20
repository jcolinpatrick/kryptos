#!/usr/bin/env python3
"""E-EXPLORER-01: Sanborn manuscript + grid rotation + dual mono hypotheses.

Three hypotheses tested:
  H3: Sanborn's unpublished manuscript "KRYPTOS: From The Source" as running key
      (direct, no transposition) — Vigenere, Beaufort, Variant Beaufort at all offsets.
  H1: K3-style grid rotation (widths 7-11, 4 rotation directions) as transposition,
      then running key from Sanborn manuscript at all offsets.
  H2: Dual monoalphabetic substitution (even/odd partition) + grid rotation,
      checking if recovered alphabets are keyword-structured.

Source text: reference/smithsonian_archive.md (Sanborn's own words, never tested).

All constants imported from kryptos.kernel.constants.
Scoring via score_candidate() from kryptos.kernel.scoring.aggregate.
"""
from __future__ import annotations

import json
import math
import os
import re
import sys
import time
from collections import Counter
from itertools import permutations
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ, VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constraints.bean import verify_bean, verify_bean_simple, BeanResult
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text, recover_key_at_positions,
    vig_decrypt, beau_decrypt, varbeau_decrypt, vig_recover_key,
    beau_recover_key, varbeau_recover_key,
)

# ── Config ──────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
SMITHSONIAN_PATH = REPO_ROOT / "reference" / "smithsonian_archive.md"
ARTIFACTS_DIR = REPO_ROOT / "artifacts"
ARTIFACTS_DIR.mkdir(exist_ok=True)

SEED = 42
GRID_WIDTHS = [7, 8, 9, 10, 11]
ROTATION_DIRS = [90, 180, 270]  # degrees clockwise; 0 = identity (skip)

CT_NUMS = [ALPH_IDX[c] for c in CT]

DECRYPT_FNS = {
    "vigenere": vig_decrypt,
    "beaufort": beau_decrypt,
    "var_beaufort": varbeau_decrypt,
}

KEY_RECOVER_FNS = {
    "vigenere": vig_recover_key,
    "beaufort": beau_recover_key,
    "var_beaufort": varbeau_recover_key,
}


# ── Text extraction ─────────────────────────────────────────────────────────

def extract_alpha_text(path: Path) -> str:
    """Extract alphabetic characters from a file, uppercased."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    return re.sub(r"[^A-Z]", "", raw.upper())


def extract_clean_text(path: Path) -> str:
    """Extract readable English from the Smithsonian manuscript.

    Strips page markers, file metadata, UAN lines, etc.
    """
    raw = path.read_text(encoding="utf-8", errors="replace")
    lines = raw.split("\n")
    clean_lines = []
    for line in lines:
        # Skip metadata lines
        if any(skip in line for skip in [
            "UAN:", "File Name:", "Copyright:", "Usage conditions",
            "Page ", "Image ", "AAA_sanbojim", "AAA-AAA",
        ]):
            continue
        # Skip markdown headers that are just section markers
        if line.strip().startswith("#"):
            continue
        clean_lines.append(line)
    text = " ".join(clean_lines)
    return re.sub(r"[^A-Z]", "", text.upper())


# ── Grid rotation transpositions ─────────────────────────────────────────────

def grid_rotation_perm(width: int, length: int, degrees: int) -> List[int]:
    """Generate permutation for grid rotation.

    Text is written into a grid of given width, row by row.
    Then the grid is rotated by `degrees` clockwise.
    Then read out row by row from the rotated grid.

    Returns perm where output[i] = input[perm[i]] (gather convention).
    """
    rows = math.ceil(length / width)
    # Pad conceptually

    if degrees == 90:
        # 90 CW: new grid is rows_new=width, cols_new=rows
        # Position (r,c) in original -> (c, rows-1-r) in rotated
        perm = []
        for new_r in range(width):
            for new_c in range(rows):
                # new_r = old_c, new_c = rows-1-old_r
                # So old_r = rows-1-new_c, old_c = new_r
                old_r = rows - 1 - new_c
                old_c = new_r
                old_idx = old_r * width + old_c
                if old_idx < length:
                    perm.append(old_idx)
        return perm[:length]

    elif degrees == 180:
        # 180: Position (r,c) -> (rows-1-r, width-1-c)
        perm = []
        for new_r in range(rows):
            for new_c in range(width):
                old_r = rows - 1 - new_r
                old_c = width - 1 - new_c
                old_idx = old_r * width + old_c
                if old_idx < length:
                    perm.append(old_idx)
        return perm[:length]

    elif degrees == 270:
        # 270 CW (= 90 CCW): new grid is rows_new=width, cols_new=rows
        # Position (r,c) in original -> (width-1-c, r) in rotated
        perm = []
        for new_r in range(width):
            for new_c in range(rows):
                # new_r = width-1-old_c, new_c = old_r
                # So old_r = new_c, old_c = width-1-new_r
                old_r = new_c
                old_c = width - 1 - new_r
                old_idx = old_r * width + old_c
                if old_idx < length:
                    perm.append(old_idx)
        return perm[:length]

    else:
        return list(range(length))  # identity


def invert_perm(perm: List[int]) -> List[int]:
    """Invert a permutation: if output[i] = input[perm[i]],
    then input[j] = output[inv[j]]."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        if p < len(inv):
            inv[p] = i
    return inv


def apply_perm(text: str, perm: List[int]) -> str:
    """Apply gather permutation: output[i] = text[perm[i]]."""
    return "".join(text[p] for p in perm if p < len(text))


# ── Running key test ─────────────────────────────────────────────────────────

def running_key_crib_score(
    ct_text: str,
    key_text: str,
    key_offset: int,
    variant: str,
    crib_dict: Dict[int, str],
) -> int:
    """Fast crib score for running key at given offset. Returns match count."""
    decrypt_fn = DECRYPT_FNS[variant]
    ct_nums_local = [ord(c) - 65 for c in ct_text]
    score = 0
    for pos, expected_ch in crib_dict.items():
        if pos >= len(ct_text):
            continue
        key_pos = key_offset + pos
        if key_pos >= len(key_text):
            break
        k = ord(key_text[key_pos]) - 65
        p = decrypt_fn(ct_nums_local[pos], k)
        if chr(p + 65) == expected_ch:
            score += 1
    return score


def running_key_decrypt(
    ct_text: str,
    key_text: str,
    key_offset: int,
    variant: str,
) -> str:
    """Decrypt ct_text using running key starting at key_offset."""
    decrypt_fn = DECRYPT_FNS[variant]
    result = []
    for i, c in enumerate(ct_text):
        kp = key_offset + i
        if kp >= len(key_text):
            break
        k = ord(key_text[kp]) - 65
        p = decrypt_fn(ord(c) - 65, k)
        result.append(chr(p + 65))
    return "".join(result)


def recover_running_key_at_cribs(
    ct_text: str,
    crib_dict: Dict[int, str],
    variant: str,
) -> Dict[int, int]:
    """Recover key values at crib positions."""
    recover_fn = KEY_RECOVER_FNS[variant]
    result = {}
    for pos, pt_ch in crib_dict.items():
        if pos < len(ct_text):
            c = ord(ct_text[pos]) - 65
            p = ord(pt_ch) - 65
            result[pos] = recover_fn(c, p)
    return result


# ── Hypothesis 3: Direct running key ────────────────────────────────────────

def test_h3_direct_running_key(source_text: str) -> List[Dict]:
    """Test Sanborn manuscript as direct running key (no transposition)."""
    print("\n" + "=" * 70)
    print("HYPOTHESIS 3: Sanborn manuscript as direct running key")
    print("=" * 70)
    print(f"Source text length: {len(source_text)} chars")

    max_offset = len(source_text) - CT_LEN
    if max_offset <= 0:
        print("ERROR: Source text too short for running key test")
        return []

    print(f"Testing {max_offset} offsets x 3 variants = {max_offset * 3} checks")

    results = []
    best_score = 0
    best_config = None

    for variant in ["vigenere", "beaufort", "var_beaufort"]:
        for offset in range(max_offset):
            score = running_key_crib_score(CT, source_text, offset, variant, CRIB_DICT)

            if score > best_score:
                best_score = score
                best_config = {"variant": variant, "offset": offset, "score": score}

            if score >= 7:  # Above noise floor
                pt = running_key_decrypt(CT, source_text, offset, variant)
                key_frag = source_text[offset:offset + 20]
                results.append({
                    "variant": variant,
                    "offset": offset,
                    "crib_score": score,
                    "plaintext_preview": pt[:40],
                    "key_fragment": key_frag,
                })

    print(f"\nBest score: {best_score}/24")
    if best_config:
        print(f"  Variant: {best_config['variant']}, Offset: {best_config['offset']}")
    print(f"Scores >= 7: {len(results)}")

    if results:
        print("\nTop results:")
        for r in sorted(results, key=lambda x: -x["crib_score"])[:5]:
            print(f"  {r['variant']} offset={r['offset']}: {r['crib_score']}/24")
            print(f"    PT: {r['plaintext_preview']}...")
            print(f"    Key: {r['key_fragment']}...")

    return results


# ── Hypothesis 1: Grid rotation + running key ───────────────────────────────

def test_h1_rotation_running_key(source_text: str) -> List[Dict]:
    """Test K3-style grid rotation + running key from Sanborn manuscript."""
    print("\n" + "=" * 70)
    print("HYPOTHESIS 1: Grid rotation transposition + running key")
    print("=" * 70)

    max_offset = len(source_text) - CT_LEN
    if max_offset <= 0:
        print("ERROR: Source text too short")
        return []

    results = []
    best_score = 0
    best_config = None
    total_checks = 0

    for width in GRID_WIDTHS:
        for degrees in ROTATION_DIRS:
            # Generate rotation permutation
            perm = grid_rotation_perm(width, CT_LEN, degrees)
            if len(perm) != CT_LEN:
                # Skip if permutation doesn't cover all positions
                continue

            # Verify perm is valid (bijective on 0..96)
            if sorted(perm) != list(range(CT_LEN)):
                # Rotation with padding may not produce bijection; skip
                continue

            # Apply inverse transposition to CT
            inv = invert_perm(perm)
            ct_after_inv_trans = apply_perm(CT, inv)

            # Build crib dict for the transposed positions
            # If encryption is: CT = Trans(Sub(PT, key))
            # Then: inv_trans(CT) = Sub(PT, key)
            # But cribs are on PT, so we need: inv_trans(CT)[i] = Sub(PT[i], key[i])
            # Wait -- the cribs say PT[pos] = char.
            # The model is: intermediate = Sub(PT, key), CT = Trans(intermediate)
            # So intermediate = inv_Trans(CT)
            # And intermediate[i] = Sub(PT[i], key[i]) = Enc(PT[i], key[i])
            # For Vigenere: intermediate[i] = (PT[i] + key[i]) mod 26
            # So key[i] = (intermediate[i] - PT[i]) mod 26
            # The cribs tell us PT at specific positions, so we can recover key at those positions.

            # But wait -- the transposition acts on the intermediate, not on positions.
            # Let me think more carefully.
            #
            # Encryption: PT -> substitution with key -> intermediate -> transposition -> CT
            # So: CT[j] = intermediate[perm_inv[j]]  (scatter: perm maps intermediate positions to CT positions)
            # Actually let's use: CT[i] = intermediate[perm[i]] (gather)
            # Then: intermediate = inv_perm(CT), meaning intermediate[perm[i]] = CT[i]
            # So intermediate[j] = CT[inv_perm[j]]
            #
            # intermediate[j] = Enc(PT[j], key[j])
            # cribs: PT[pos] = ch
            # So: Enc(ch, key[pos]) = intermediate[pos] = CT[inv_perm[pos]]
            # key[pos] = Recover(CT[inv_perm[pos]], ch)
            #
            # For running key: key[pos] = source_text[offset + pos]
            # So: Recover(CT[inv_perm[pos]], crib_ch) should equal source_text[offset + pos]

            # Precompute intermediate values at crib positions
            crib_intermediate = {}
            for pos, ch in CRIB_DICT.items():
                inter_char = ct_after_inv_trans[pos]  # This is intermediate[pos]
                crib_intermediate[pos] = inter_char

            for variant in ["vigenere", "beaufort", "var_beaufort"]:
                recover_fn = KEY_RECOVER_FNS[variant]

                # Recover key values at crib positions
                required_key = {}
                for pos, pt_ch in CRIB_DICT.items():
                    c = ord(crib_intermediate[pos]) - 65
                    p = ord(pt_ch) - 65
                    required_key[pos] = recover_fn(c, p)

                # Now check each offset: does source_text[offset+pos] == required_key[pos]?
                for offset in range(max_offset):
                    score = 0
                    for pos, k_val in required_key.items():
                        key_pos = offset + pos
                        if key_pos >= len(source_text):
                            break
                        if ord(source_text[key_pos]) - 65 == k_val:
                            score += 1

                    total_checks += 1

                    if score > best_score:
                        best_score = score
                        best_config = {
                            "width": width, "degrees": degrees,
                            "variant": variant, "offset": offset,
                            "score": score,
                        }

                    if score >= 7:
                        # Decrypt full text
                        decrypt_fn = DECRYPT_FNS[variant]
                        pt_chars = []
                        for i in range(CT_LEN):
                            kp = offset + i
                            if kp >= len(source_text):
                                break
                            k = ord(source_text[kp]) - 65
                            p = decrypt_fn(ord(ct_after_inv_trans[i]) - 65, k)
                            pt_chars.append(chr(p + 65))
                        pt = "".join(pt_chars)

                        results.append({
                            "width": width,
                            "degrees": degrees,
                            "variant": variant,
                            "offset": offset,
                            "crib_score": score,
                            "plaintext_preview": pt[:40],
                            "key_fragment": source_text[offset:offset + 20],
                        })

    print(f"Total checks: {total_checks:,}")
    print(f"Best score: {best_score}/24")
    if best_config:
        print(f"  Width: {best_config['width']}, Rotation: {best_config['degrees']}deg")
        print(f"  Variant: {best_config['variant']}, Offset: {best_config['offset']}")
    print(f"Scores >= 7: {len(results)}")

    if results:
        print("\nTop results:")
        for r in sorted(results, key=lambda x: -x["crib_score"])[:5]:
            print(f"  w={r['width']} rot={r['degrees']} {r['variant']} off={r['offset']}: {r['crib_score']}/24")
            print(f"    PT: {r['plaintext_preview']}...")

    return results


# ── Hypothesis 2: Dual monoalphabetic + grid rotation ───────────────────────

def keyword_distance(alphabet: List[int]) -> int:
    """Measure how 'keyword-like' a partial alphabet mapping is.

    Returns the number of consecutive pairs where the difference is constant
    (characteristic of keyword alphabets where the non-keyword tail is alphabetical).
    """
    diffs = []
    for i in range(len(alphabet) - 1):
        if alphabet[i] is not None and alphabet[i+1] is not None:
            diffs.append((alphabet[i+1] - alphabet[i]) % 26)
    if not diffs:
        return 0
    # Count most common diff (keyword alphabets have long runs of diff=1)
    counter = Counter(diffs)
    return counter.most_common(1)[0][1] if counter else 0


def test_h2_dual_mono_rotation() -> List[Dict]:
    """Test dual monoalphabetic substitution + grid rotation."""
    print("\n" + "=" * 70)
    print("HYPOTHESIS 2: Dual monoalphabetic + grid rotation")
    print("=" * 70)

    results = []
    best_score = 0
    best_config = None

    # Partition schemes to test
    partitions = {
        "even_odd": lambda pos: pos % 2,
        "first_half": lambda pos: 0 if pos < 49 else 1,
        "thirds": lambda pos: pos % 3,  # 3 alphabets
        "mod4": lambda pos: pos % 4,     # 4 alphabets
    }

    for width in GRID_WIDTHS:
        for degrees in ROTATION_DIRS:
            perm = grid_rotation_perm(width, CT_LEN, degrees)
            if len(perm) != CT_LEN or sorted(perm) != list(range(CT_LEN)):
                continue

            inv = invert_perm(perm)
            ct_after_inv_trans = apply_perm(CT, inv)

            for part_name, part_fn in partitions.items():
                # For each partition, recover the substitution at crib positions
                # Group crib positions by partition
                groups: Dict[int, List[Tuple[int, str, str]]] = {}
                for pos, pt_ch in CRIB_DICT.items():
                    group = part_fn(pos)
                    inter_ch = ct_after_inv_trans[pos]
                    if group not in groups:
                        groups[group] = []
                    groups[group].append((pos, pt_ch, inter_ch))

                # For each group, check consistency of monoalphabetic substitution
                # mono: PT_ch -> inter_ch should be a function (each PT_ch maps to exactly one inter_ch)
                consistent = True
                mono_maps: Dict[int, Dict[str, str]] = {}

                for group, entries in groups.items():
                    mapping: Dict[str, str] = {}
                    for pos, pt_ch, inter_ch in entries:
                        if pt_ch in mapping:
                            if mapping[pt_ch] != inter_ch:
                                consistent = False
                                break
                        else:
                            mapping[pt_ch] = inter_ch
                    if not consistent:
                        break

                    # Also check injectivity: each inter_ch maps to at most one pt_ch
                    reverse_map: Dict[str, str] = {}
                    for pt_ch, inter_ch in mapping.items():
                        if inter_ch in reverse_map:
                            if reverse_map[inter_ch] != pt_ch:
                                consistent = False
                                break
                        else:
                            reverse_map[inter_ch] = pt_ch
                    if not consistent:
                        break

                    mono_maps[group] = mapping

                if consistent and len(mono_maps) > 0:
                    # Count how many crib positions are explained
                    explained = sum(len(entries) for entries in groups.values())

                    # Check if mappings look keyword-structured
                    # Convert to numeric for analysis
                    total_mapped = sum(len(m) for m in mono_maps.values())

                    # Score: try to extend and decrypt
                    # For unmapped positions, we can't decrypt, so score is just the cribs
                    # But we need to check if the mono maps are reasonable

                    if total_mapped >= 8:  # Need enough constraints
                        result = {
                            "width": width,
                            "degrees": degrees,
                            "partition": part_name,
                            "consistent": True,
                            "explained_cribs": explained,
                            "total_mapped_chars": total_mapped,
                            "mono_maps": {
                                str(g): {k: v for k, v in m.items()}
                                for g, m in mono_maps.items()
                            },
                        }
                        results.append(result)

                        if explained > best_score:
                            best_score = explained
                            best_config = result

    print(f"Consistent configurations found: {len(results)}")
    print(f"Best explained cribs: {best_score}/24")

    if best_config:
        print(f"\nBest config:")
        print(f"  Width: {best_config['width']}, Rotation: {best_config['degrees']}deg")
        print(f"  Partition: {best_config['partition']}")
        print(f"  Mapped chars: {best_config['total_mapped_chars']}")
        for g, m in best_config['mono_maps'].items():
            print(f"  Group {g}: {m}")

    if results:
        # Show distribution
        print(f"\nDistribution of explained cribs:")
        counts = Counter(r["explained_cribs"] for r in results)
        for score in sorted(counts.keys(), reverse=True):
            print(f"  {score}/24: {counts[score]} configs")

    return results


# ── Additional running key sources ───────────────────────────────────────────

def test_additional_sources() -> List[Dict]:
    """Also test YouTube transcript as running key source (contains Sanborn quotes)."""
    print("\n" + "=" * 70)
    print("BONUS: YouTube transcript as running key source")
    print("=" * 70)

    yt_path = REPO_ROOT / "reference" / "youtube_transcript.md"
    if not yt_path.exists():
        print("YouTube transcript not found, skipping")
        return []

    source_text = extract_clean_text(yt_path)
    print(f"Source text length: {len(source_text)} chars")

    max_offset = len(source_text) - CT_LEN
    if max_offset <= 0:
        print("Source text too short")
        return []

    print(f"Testing {max_offset} offsets x 3 variants")

    results = []
    best_score = 0
    best_config = None

    for variant in ["vigenere", "beaufort", "var_beaufort"]:
        for offset in range(max_offset):
            score = running_key_crib_score(CT, source_text, offset, variant, CRIB_DICT)

            if score > best_score:
                best_score = score
                best_config = {"variant": variant, "offset": offset, "score": score}

            if score >= 7:
                pt = running_key_decrypt(CT, source_text, offset, variant)
                results.append({
                    "source": "youtube_transcript",
                    "variant": variant,
                    "offset": offset,
                    "crib_score": score,
                    "plaintext_preview": pt[:40],
                })

    print(f"Best score: {best_score}/24")
    if best_config:
        print(f"  Variant: {best_config['variant']}, Offset: {best_config['offset']}")
    print(f"Scores >= 7: {len(results)}")

    return results


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("E-EXPLORER-01: Sanborn Manuscript Hypothesis Testing")
    print(f"CT: {CT[:20]}...{CT[-10:]}")
    print(f"CT length: {CT_LEN}")
    print(f"Cribs: {N_CRIBS} positions")
    print(f"Seed: {SEED}")

    t0 = time.time()

    # Extract source text
    print(f"\nExtracting text from: {SMITHSONIAN_PATH}")
    source_text = extract_clean_text(SMITHSONIAN_PATH)
    print(f"Clean text length: {len(source_text)} chars")
    print(f"First 100 chars: {source_text[:100]}")

    all_results = {}

    # H3: Direct running key (cheapest)
    h3_results = test_h3_direct_running_key(source_text)
    all_results["h3_direct_running_key"] = {
        "source": "smithsonian_archive",
        "source_length": len(source_text),
        "results_above_7": len(h3_results),
        "best_score": max((r["crib_score"] for r in h3_results), default=0),
        "top_results": sorted(h3_results, key=lambda x: -x["crib_score"])[:10],
    }

    # H1: Grid rotation + running key
    h1_results = test_h1_rotation_running_key(source_text)
    all_results["h1_rotation_running_key"] = {
        "source": "smithsonian_archive",
        "widths_tested": GRID_WIDTHS,
        "rotations_tested": ROTATION_DIRS,
        "results_above_7": len(h1_results),
        "best_score": max((r["crib_score"] for r in h1_results), default=0),
        "top_results": sorted(h1_results, key=lambda x: -x["crib_score"])[:10],
    }

    # H2: Dual mono + rotation
    h2_results = test_h2_dual_mono_rotation()
    all_results["h2_dual_mono_rotation"] = {
        "widths_tested": GRID_WIDTHS,
        "rotations_tested": ROTATION_DIRS,
        "consistent_configs": len(h2_results),
        "best_explained": max((r["explained_cribs"] for r in h2_results), default=0),
        "top_results": sorted(h2_results, key=lambda x: -x["explained_cribs"])[:10],
    }

    # Bonus: YouTube transcript
    yt_results = test_additional_sources()
    all_results["bonus_youtube_transcript"] = {
        "results_above_7": len(yt_results),
        "best_score": max((r["crib_score"] for r in yt_results), default=0),
        "top_results": sorted(yt_results, key=lambda x: -x["crib_score"])[:10],
    }

    elapsed = time.time() - t0

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total time: {elapsed:.1f}s")
    print(f"H3 (direct running key): best={all_results['h3_direct_running_key']['best_score']}/24, above_7={all_results['h3_direct_running_key']['results_above_7']}")
    print(f"H1 (rotation+running key): best={all_results['h1_rotation_running_key']['best_score']}/24, above_7={all_results['h1_rotation_running_key']['results_above_7']}")
    print(f"H2 (dual mono+rotation): consistent={all_results['h2_dual_mono_rotation']['consistent_configs']}, best_explained={all_results['h2_dual_mono_rotation']['best_explained']}/24")
    print(f"Bonus (YouTube transcript): best={all_results['bonus_youtube_transcript']['best_score']}/24, above_7={all_results['bonus_youtube_transcript']['results_above_7']}")

    # Interpretation
    print("\n--- INTERPRETATION ---")

    h3_best = all_results['h3_direct_running_key']['best_score']
    h1_best = all_results['h1_rotation_running_key']['best_score']

    for label, best in [("H3", h3_best), ("H1", h1_best)]:
        if best >= 18:
            print(f"{label}: SIGNAL — score {best}/24 warrants investigation")
        elif best >= 10:
            print(f"{label}: INTERESTING — score {best}/24, likely noise but worth logging")
        else:
            print(f"{label}: NOISE — best score {best}/24 is within random expectation (~6)")

    # Expected random score for running key:
    # Each crib position has 1/26 chance of matching, so expected = 24/26 ≈ 0.92
    # But running key from English text has biased letter frequencies.
    # Empirically, E-FRAC-49 found best scores of ~6-7 from known texts.
    # Scores of 7+ are worth logging but 10+ would be unusual.

    # Save results
    out_path = ARTIFACTS_DIR / "explorer_01_results.json"
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\nResults saved to: {out_path}")


if __name__ == "__main__":
    main()
