#!/usr/bin/env python3
"""
Cipher: running key
Family: exploration
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-EXPLORER-02: Expanded grid rotation + running key search.

Building on E-EXPLORER-01 finding: 9/24 at w=8 rot=90.
This script:
1. Establishes Monte Carlo baseline: expected crib score for rotation+running_key
   with random English text of the same length.
2. Tests ALL available reference texts (Carter, Reagan, JFK, UDHR, CIA Charter,
   NSA Act) through ALL grid rotations.
3. Tests Sanborn manuscript through COLUMNAR transpositions (not just rotation)
   at Bean-compatible widths.

Determines whether 9/24 is significant or within noise.
"""
from __future__ import annotations

import json
import math
import os
import random
import re
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constraints.bean import verify_bean_simple
from kryptos.kernel.transforms.vigenere import (
    vig_decrypt, beau_decrypt, varbeau_decrypt,
    vig_recover_key, beau_recover_key, varbeau_recover_key,
)

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
ARTIFACTS_DIR = REPO_ROOT / "artifacts"
ARTIFACTS_DIR.mkdir(exist_ok=True)

SEED = 42
random.seed(SEED)

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

GRID_WIDTHS = [7, 8, 9, 10, 11]
ROTATION_DIRS = [90, 180, 270]


# ── Text extraction ──────────────────────────────────────────────────────────

def extract_clean_text(path: Path) -> str:
    """Extract clean alphabetic text from a file."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    lines = raw.split("\n")
    clean_lines = []
    for line in lines:
        if any(skip in line for skip in [
            "UAN:", "File Name:", "Copyright:", "Usage conditions",
            "AAA_sanbojim", "AAA-AAA",
        ]):
            continue
        if line.strip().startswith("#"):
            continue
        clean_lines.append(line)
    text = " ".join(clean_lines)
    return re.sub(r"[^A-Z]", "", text.upper())


def extract_alpha(path: Path) -> str:
    """Simple alpha extraction."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    return re.sub(r"[^A-Z]", "", raw.upper())


# ── Grid rotation ────────────────────────────────────────────────────────────

def grid_rotation_perm(width: int, length: int, degrees: int) -> Optional[List[int]]:
    """Generate rotation permutation. Returns None if not bijective."""
    rows = math.ceil(length / width)

    if degrees == 90:
        perm = []
        for new_r in range(width):
            for new_c in range(rows):
                old_r = rows - 1 - new_c
                old_c = new_r
                old_idx = old_r * width + old_c
                if old_idx < length:
                    perm.append(old_idx)
        perm = perm[:length]
    elif degrees == 180:
        perm = []
        for new_r in range(rows):
            for new_c in range(width):
                old_r = rows - 1 - new_r
                old_c = width - 1 - new_c
                old_idx = old_r * width + old_c
                if old_idx < length:
                    perm.append(old_idx)
        perm = perm[:length]
    elif degrees == 270:
        perm = []
        for new_r in range(width):
            for new_c in range(rows):
                old_r = new_c
                old_c = width - 1 - new_r
                old_idx = old_r * width + old_c
                if old_idx < length:
                    perm.append(old_idx)
        perm = perm[:length]
    else:
        return list(range(length))

    if len(perm) != length or sorted(perm) != list(range(length)):
        return None
    return perm


def invert_perm(perm: List[int]) -> List[int]:
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def apply_perm(text: str, perm: List[int]) -> str:
    return "".join(text[p] for p in perm)


# ── Columnar transposition ───────────────────────────────────────────────────

def columnar_perm(width: int, col_order: List[int], length: int) -> List[int]:
    """Generate columnar transposition permutation.

    Text is written into rows of given width, then columns are read out
    in col_order.

    Returns gather permutation or None if invalid.
    """
    rows = math.ceil(length / width)
    # How many positions in the last (possibly incomplete) row
    last_row_len = length - (rows - 1) * width

    perm = []
    for col in col_order:
        for row in range(rows):
            idx = row * width + col
            if idx < length:
                perm.append(idx)

    if len(perm) != length:
        return None
    return perm


# ── Fast running key scoring ─────────────────────────────────────────────────

def fast_rk_max_score(
    ct_text: str,
    source_text: str,
    perm: Optional[List[int]],
    variants: List[str] = ["vigenere", "beaufort", "var_beaufort"],
) -> Tuple[int, Dict]:
    """Find best crib score across all offsets and variants for a given transposition.

    If perm is None, uses identity (no transposition).
    Returns (best_score, best_config_dict).
    """
    if perm is not None:
        inv = invert_perm(perm)
        ct_work = apply_perm(ct_text, inv)
    else:
        ct_work = ct_text

    max_offset = len(source_text) - CT_LEN
    if max_offset <= 0:
        return (0, {})

    best_score = 0
    best_cfg = {}

    # Precompute intermediate values at crib positions
    ct_work_nums = [ord(c) - 65 for c in ct_work]

    for variant in variants:
        recover_fn = KEY_RECOVER_FNS[variant]

        # Required key values at crib positions
        required = {}
        for pos, pt_ch in CRIB_DICT.items():
            c = ct_work_nums[pos]
            p = ord(pt_ch) - 65
            required[pos] = recover_fn(c, p)

        # Convert to list for fast access
        req_positions = sorted(required.keys())
        req_values = [required[p] for p in req_positions]

        for offset in range(max_offset):
            score = 0
            valid = True
            for i, pos in enumerate(req_positions):
                kp = offset + pos
                if kp >= len(source_text):
                    valid = False
                    break
                if ord(source_text[kp]) - 65 == req_values[i]:
                    score += 1

            if score > best_score:
                best_score = score
                best_cfg = {"variant": variant, "offset": offset}

    return (best_score, best_cfg)


# ── Monte Carlo baseline ────────────────────────────────────────────────────

def generate_random_english(length: int) -> str:
    """Generate random text with English-like letter frequencies."""
    # English letter frequencies (approximate)
    freq = {
        'A': 0.0817, 'B': 0.0149, 'C': 0.0278, 'D': 0.0425, 'E': 0.1270,
        'F': 0.0223, 'G': 0.0202, 'H': 0.0609, 'I': 0.0697, 'J': 0.0015,
        'K': 0.0077, 'L': 0.0403, 'M': 0.0241, 'N': 0.0675, 'O': 0.0751,
        'P': 0.0193, 'Q': 0.0010, 'R': 0.0599, 'S': 0.0633, 'T': 0.0906,
        'U': 0.0276, 'V': 0.0098, 'W': 0.0236, 'X': 0.0015, 'Y': 0.0197,
        'Z': 0.0007,
    }
    letters = list(freq.keys())
    weights = [freq[l] for l in letters]
    return "".join(random.choices(letters, weights=weights, k=length))


def monte_carlo_baseline(n_trials: int = 200) -> Dict:
    """Establish baseline: best crib score for rotation + random English running key."""
    print("\n" + "=" * 70)
    print(f"MONTE CARLO BASELINE: {n_trials} trials")
    print("=" * 70)

    # Generate valid rotation perms
    valid_perms = []
    for w in GRID_WIDTHS:
        for d in ROTATION_DIRS:
            p = grid_rotation_perm(w, CT_LEN, d)
            if p is not None:
                valid_perms.append((w, d, p))

    print(f"Valid rotation permutations: {len(valid_perms)}")

    all_scores = []
    for trial in range(n_trials):
        # Generate random English-like source text
        source = generate_random_english(500)  # 500 chars, enough for offset variation

        trial_best = 0
        # Test identity + all rotations
        for perm_info in [(0, 0, None)] + [(w, d, p) for w, d, p in valid_perms]:
            if perm_info[2] is None:
                perm = None
            else:
                perm = perm_info[2]
            score, _ = fast_rk_max_score(CT, source, perm)
            if score > trial_best:
                trial_best = score

        all_scores.append(trial_best)

    scores_counter = Counter(all_scores)
    mean_score = sum(all_scores) / len(all_scores)
    max_score = max(all_scores)
    p95 = sorted(all_scores)[int(0.95 * len(all_scores))]
    p99 = sorted(all_scores)[int(0.99 * len(all_scores))]

    print(f"Mean best score: {mean_score:.2f}")
    print(f"Max score: {max_score}")
    print(f"95th percentile: {p95}")
    print(f"99th percentile: {p99}")
    print(f"Distribution: {dict(sorted(scores_counter.items()))}")

    return {
        "n_trials": n_trials,
        "mean": mean_score,
        "max": max_score,
        "p95": p95,
        "p99": p99,
        "distribution": dict(sorted(scores_counter.items())),
    }


# ── Comprehensive reference text search ──────────────────────────────────────

def test_all_reference_texts() -> Dict:
    """Test all available reference texts with all rotation transpositions."""
    print("\n" + "=" * 70)
    print("COMPREHENSIVE: All reference texts x all rotations")
    print("=" * 70)

    ref_dir = REPO_ROOT / "reference"
    text_files = {
        "smithsonian": ref_dir / "smithsonian_archive.md",
        "youtube": ref_dir / "youtube_transcript.md",
        "carter_gutenberg": ref_dir / "carter_gutenberg.txt",
        "carter_vol1": ref_dir / "carter_vol1.txt",
        "carter_extract": ref_dir / "carter_vol1_extract.txt",
        "reagan_berlin": ref_dir / "running_key_texts" / "reagan_berlin.txt",
        "jfk_berlin": ref_dir / "running_key_texts" / "jfk_berlin.txt",
        "udhr": ref_dir / "running_key_texts" / "udhr.txt",
        "nsa_act": ref_dir / "running_key_texts" / "nsa_act_1947.txt",
        "cia_charter": ref_dir / "running_key_texts" / "cia_charter.txt",
    }

    # Generate valid rotation perms
    valid_perms = []
    for w in GRID_WIDTHS:
        for d in ROTATION_DIRS:
            p = grid_rotation_perm(w, CT_LEN, d)
            if p is not None:
                valid_perms.append((w, d, p))

    results = {}
    overall_best = 0
    overall_best_cfg = None

    for name, path in text_files.items():
        if not path.exists():
            print(f"  {name}: NOT FOUND, skipping")
            continue

        if "smithsonian" in name or "youtube" in name:
            source = extract_clean_text(path)
        else:
            source = extract_alpha(path)

        if len(source) < CT_LEN + 10:
            print(f"  {name}: too short ({len(source)} chars), skipping")
            continue

        text_best = 0
        text_best_cfg = {}

        # Test identity (no transposition)
        score, cfg = fast_rk_max_score(CT, source, None)
        if score > text_best:
            text_best = score
            text_best_cfg = {"transposition": "identity", **cfg}

        # Test all rotations
        for w, d, perm in valid_perms:
            score, cfg = fast_rk_max_score(CT, source, perm)
            if score > text_best:
                text_best = score
                text_best_cfg = {"transposition": f"rot_w{w}_d{d}", **cfg}

        results[name] = {
            "length": len(source),
            "best_score": text_best,
            "best_config": text_best_cfg,
        }

        if text_best > overall_best:
            overall_best = text_best
            overall_best_cfg = {"source": name, **text_best_cfg}

        print(f"  {name} ({len(source):,} chars): best={text_best}/24 [{text_best_cfg.get('transposition', '?')} {text_best_cfg.get('variant', '?')}]")

    print(f"\nOverall best: {overall_best}/24")
    if overall_best_cfg:
        print(f"  Config: {overall_best_cfg}")

    return {
        "per_text": results,
        "overall_best": overall_best,
        "overall_best_config": overall_best_cfg,
    }


# ── Test columnar transpositions with Sanborn text ───────────────────────────

def test_columnar_with_sanborn() -> Dict:
    """Test sampled columnar transpositions + Sanborn running key.

    Only at Bean-compatible widths: {8, 9} (from Bean-surviving periods).
    Width 6 also tested as it has moderate Bean pass rate.
    """
    print("\n" + "=" * 70)
    print("COLUMNAR TRANSPOSITION + SANBORN RUNNING KEY")
    print("=" * 70)

    source = extract_clean_text(REPO_ROOT / "reference" / "smithsonian_archive.md")
    print(f"Source length: {len(source):,} chars")

    # Test a sample of columnar orderings at widths 6, 8, 9
    widths_to_test = [6, 8, 9]
    n_samples = 500  # per width

    results = {}
    overall_best = 0
    overall_best_cfg = None

    for width in widths_to_test:
        n_cols = width
        all_orderings = list(range(n_cols))

        best_for_width = 0
        best_cfg_for_width = {}

        for trial in range(n_samples):
            # Random column ordering
            ordering = list(range(n_cols))
            random.shuffle(ordering)

            perm = columnar_perm(width, ordering, CT_LEN)
            if perm is None or len(perm) != CT_LEN:
                continue

            score, cfg = fast_rk_max_score(CT, source, perm)

            if score > best_for_width:
                best_for_width = score
                best_cfg_for_width = {"width": width, "ordering": ordering, **cfg}

        results[f"width_{width}"] = {
            "samples": n_samples,
            "best_score": best_for_width,
            "best_config": best_cfg_for_width,
        }

        if best_for_width > overall_best:
            overall_best = best_for_width
            overall_best_cfg = best_cfg_for_width

        print(f"  Width {width}: {n_samples} samples, best={best_for_width}/24")

    print(f"\nOverall best: {overall_best}/24")

    return {
        "per_width": results,
        "overall_best": overall_best,
        "overall_best_config": overall_best_cfg,
    }


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("E-EXPLORER-02: Expanded Grid Rotation + Running Key Search")
    print(f"CT: {CT[:20]}...{CT[-10:]}")
    print(f"Seed: {SEED}")

    t0 = time.time()

    all_results = {}

    # 1. Monte Carlo baseline
    baseline = monte_carlo_baseline(n_trials=500)
    all_results["monte_carlo_baseline"] = baseline

    # 2. All reference texts x all rotations
    ref_results = test_all_reference_texts()
    all_results["reference_texts"] = ref_results

    # 3. Columnar + Sanborn
    col_results = test_columnar_with_sanborn()
    all_results["columnar_sanborn"] = col_results

    elapsed = time.time() - t0

    # Summary
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"Total time: {elapsed:.1f}s")
    print(f"\nMonte Carlo baseline (rotation + random English running key):")
    print(f"  Mean: {baseline['mean']:.2f}, P95: {baseline['p95']}, P99: {baseline['p99']}, Max: {baseline['max']}")
    print(f"\nReference texts (rotation):")
    print(f"  Overall best: {ref_results['overall_best']}/24")
    if ref_results['overall_best_config']:
        print(f"  Config: {ref_results['overall_best_config']}")
    print(f"\nColumnar + Sanborn:")
    print(f"  Overall best: {col_results['overall_best']}/24")

    # Significance assessment
    p99 = baseline['p99']
    ref_best = ref_results['overall_best']
    print(f"\n--- SIGNIFICANCE ---")
    print(f"99th percentile of random: {p99}")
    print(f"Best from reference texts: {ref_best}")
    if ref_best > p99:
        print(f"ABOVE 99th percentile — warrants investigation!")
    else:
        print(f"WITHIN NOISE — reference texts show no signal above random baseline")

    # Save
    out_path = ARTIFACTS_DIR / "explorer_02_results.json"
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\nResults saved to: {out_path}")


if __name__ == "__main__":
    main()
