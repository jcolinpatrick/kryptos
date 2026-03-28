#!/usr/bin/env python3
"""Running-key English discriminator across all palette-consistent 24-null masks.

Cipher:   Running key + columnar transposition (73-char extract)
Family:   analysis
Status:   active
Keyspace: 3432 masks × 5925 orderings × 3 variants = ~61M checks
Last run: 2026-03-27
Best score: TBD

PURPOSE: For each (mask, columnar transposition, variant), determine whether
the Beaufort/Vigenère keystream at crib positions — when mapped through the
transposition to key-space positions — forms English-like fragments.

MODEL: CT73 = Trans(Sub(PT73, K)) where K is a running key (English text).
The 24 known keystream values are FIXED by (CT, cribs, variant). The mask
and transposition only change WHERE these values land in key space. If the
correct transposition groups crib positions into consecutive key positions,
those fragments should spell English.

SEARCH:
- 3,432 palette-consistent 24-null masks (consensus 17 + 7 of 14 extras)
- Widths 2-7: ALL column orderings (5,912 total)
- Widths 8-20: identity + KRYPTOS/PALIMPSEST/ABSCISSA orderings
- 3 cipher variants (Beaufort, Vigenère, Variant Beaufort)
"""

import sys
import os
import time
import json
from collections import defaultdict
from itertools import combinations, permutations

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    CRIB_DICT, CRIB_POSITIONS,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)
from kryptos.kernel.scoring.ngram import get_default_scorer
from kryptos.kernel.transforms.transposition import (
    columnar_perm, keyword_to_order, invert_perm,
)

# ═══════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

# Keystream letters at crib positions for each variant
KEYSTREAM = {
    'beau': [ALPH[v] for v in BEAUFORT_KEY_ENE + BEAUFORT_KEY_BC],
    'vig': [ALPH[v] for v in VIGENERE_KEY_ENE + VIGENERE_KEY_BC],
}
# Variant Beaufort: K = (PT - CT) mod 26
vbeau_ene = [(ALPH_IDX[CRIB_DICT[p]] - ALPH_IDX[CT[p]]) % MOD for p in range(21, 34)]
vbeau_bc = [(ALPH_IDX[CRIB_DICT[p]] - ALPH_IDX[CT[p]]) % MOD for p in range(63, 74)]
KEYSTREAM['vbeau'] = [ALPH[v] for v in vbeau_ene + vbeau_bc]

# Original crib positions (0-indexed in CT97)
ORIG_CRIB_POS = list(range(21, 34)) + list(range(63, 74))  # 24 positions

# Candidate null positions (palette letters, non-crib)
CANDIDATE_NULLS = sorted(
    set(i for i, c in enumerate(CT) if c in NULL_PALETTE) - CRIB_POSITIONS
)

# Extra candidates beyond consensus 17
EXTRA_CANDIDATES = sorted(set(CANDIDATE_NULLS) - CONSENSUS_NULL_POSITIONS)

# ═══════════════════════════════════════════════════════════════════════════
# MASK GENERATION
# ═══════════════════════════════════════════════════════════════════════════

def generate_masks():
    """Generate all 3432 palette-consistent 24-null masks."""
    masks = []
    for extra in combinations(EXTRA_CANDIDATES, 7):
        mask = CONSENSUS_NULL_POSITIONS | frozenset(extra)
        masks.append(mask)
    return masks


def compute_shifted_cribs(mask):
    """Map original crib positions to positions in 73-char extract.
    Returns list of 24 shifted positions in order of ORIG_CRIB_POS.
    """
    null_set = mask
    shifted = []
    for orig_pos in ORIG_CRIB_POS:
        # Count nulls before this position
        new_pos = orig_pos - sum(1 for n in null_set if n < orig_pos)
        shifted.append(new_pos)
    return shifted


# ═══════════════════════════════════════════════════════════════════════════
# TRANSPOSITION GENERATION
# ═══════════════════════════════════════════════════════════════════════════

def generate_orderings(width):
    """Generate column orderings for a given width.
    Width 2-7: all permutations. Width 8+: identity + keyword orderings.
    """
    if width <= 7:
        return list(permutations(range(width)))
    else:
        orderings = [tuple(range(width))]  # identity
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "DEFECTOR",
                    "KOMPASS", "HOROLOGE", "EQUINOX"]:
            order = keyword_to_order(kw, width)
            if order is not None and order not in orderings:
                orderings.append(order)
        return orderings


# ═══════════════════════════════════════════════════════════════════════════
# FRAGMENT SCORING
# ═══════════════════════════════════════════════════════════════════════════

def find_fragments(key_positions, key_values, key_len=73):
    """Given known (position, value) pairs in key space, find maximal
    contiguous runs of consecutive positions.

    Returns list of (start_pos, fragment_string) tuples.
    """
    if not key_positions:
        return []

    # Build position->value map
    pos_map = {}
    for pos, val in zip(key_positions, key_values):
        pos_map[pos] = val

    # Find contiguous runs
    fragments = []
    sorted_positions = sorted(pos_map.keys())

    current_start = sorted_positions[0]
    current_chars = [pos_map[sorted_positions[0]]]

    for i in range(1, len(sorted_positions)):
        if sorted_positions[i] == sorted_positions[i-1] + 1:
            current_chars.append(pos_map[sorted_positions[i]])
        else:
            if len(current_chars) >= 4:  # Only score fragments of length >= 4
                fragments.append((current_start, "".join(current_chars)))
            current_start = sorted_positions[i]
            current_chars = [pos_map[sorted_positions[i]]]

    if len(current_chars) >= 4:
        fragments.append((current_start, "".join(current_chars)))

    return fragments


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 78)
    print("RUNNING-KEY ENGLISH DISCRIMINATOR")
    print("3432 masks × columnar transpositions × 3 variants")
    print("=" * 78)

    # Load quadgram scorer
    scorer = get_default_scorer()
    print(f"Quadgram scorer loaded (floor={scorer._floor:.3f})")

    # English reference: good English scores about -2.5 to -3.5 per quadgram
    # Random text scores about -4.5 to -5.5 per quadgram
    # Threshold for "interesting": score_per_char > -4.0
    ENGLISH_THRESHOLD = -4.0
    SIGNAL_THRESHOLD = -3.5

    # Generate masks
    masks = generate_masks()
    print(f"Generated {len(masks)} palette-consistent 24-null masks")

    # Precompute shifted cribs for each mask
    print("Precomputing shifted crib positions...")
    mask_shifted = []
    for mask in masks:
        shifted = compute_shifted_cribs(mask)
        mask_shifted.append(shifted)

    # Count total orderings
    total_orderings = 0
    width_orderings = {}
    for w in range(2, 21):
        ords = generate_orderings(w)
        width_orderings[w] = ords
        total_orderings += len(ords)

    total_checks = len(masks) * total_orderings * 3
    print(f"Widths 2-20: {total_orderings} total orderings")
    print(f"Total checks: {len(masks)} × {total_orderings} × 3 = {total_checks:,}")
    print()

    # Precompute all permutations
    print("Precomputing columnar permutations...")
    perms_by_width = {}
    for w in range(2, 21):
        perms_by_width[w] = []
        for ordering in width_orderings[w]:
            perm = columnar_perm(w, ordering, length=73)
            perms_by_width[w].append(perm)

    # ── Main sweep ──
    t0 = time.time()
    checks_done = 0
    results = []

    # Track fragment statistics
    n_with_fragments = 0  # checks where >=1 fragment of length >=4 exists
    n_above_threshold = 0
    best_overall = (-999, None)

    for mi, (mask, shifted) in enumerate(zip(masks, mask_shifted)):
        if mi % 500 == 0 and mi > 0:
            elapsed = time.time() - t0
            rate = checks_done / elapsed
            eta = (total_checks - checks_done) / rate if rate > 0 else 0
            print(f"  Mask {mi}/{len(masks)}, "
                  f"{checks_done:,} checks, "
                  f"{rate:.0f}/s, "
                  f"ETA {eta:.0f}s, "
                  f"fragments_found={n_with_fragments}, "
                  f"above_threshold={n_above_threshold}")

        for w in range(2, 21):
            for pi, perm in enumerate(perms_by_width[w]):
                for variant in ['beau', 'vig', 'vbeau']:
                    ks_letters = KEYSTREAM[variant]

                    # Map shifted crib positions through transposition
                    # key_pos = perm[shifted_crib_pos]
                    key_positions = [perm[s] for s in shifted]
                    key_values = ks_letters

                    # Find contiguous fragments in key space
                    fragments = find_fragments(key_positions, key_values, 73)

                    checks_done += 1

                    if not fragments:
                        continue

                    n_with_fragments += 1

                    # Score best fragment
                    best_frag_score = -999
                    best_frag = None
                    for start, frag_str in fragments:
                        sc = scorer.score_per_char(frag_str)
                        if sc > best_frag_score:
                            best_frag_score = sc
                            best_frag = (start, frag_str)

                    if best_frag_score > ENGLISH_THRESHOLD:
                        n_above_threshold += 1
                        ordering_str = str(width_orderings[w][pi]) if w <= 7 else "kw"
                        extra = sorted(mask - CONSENSUS_NULL_POSITIONS)
                        results.append({
                            'score': round(best_frag_score, 4),
                            'variant': variant,
                            'width': w,
                            'ordering_idx': pi,
                            'mask_extra': extra,
                            'fragments': [(s, f) for s, f in fragments],
                            'best_fragment': best_frag,
                            'key_positions': sorted(set(key_positions)),
                        })

                    if best_frag_score > best_overall[0]:
                        extra = sorted(mask - CONSENSUS_NULL_POSITIONS)
                        best_overall = (best_frag_score, {
                            'variant': variant,
                            'width': w,
                            'ordering_idx': pi,
                            'mask_extra': extra,
                            'best_fragment': best_frag,
                            'all_fragments': fragments,
                        })

    elapsed = time.time() - t0

    # ── Results ──
    print()
    print("=" * 78)
    print("RESULTS")
    print("=" * 78)
    print(f"Total checks: {checks_done:,} in {elapsed:.1f}s ({checks_done/elapsed:.0f}/s)")
    print(f"Checks with ≥1 fragment (len≥4): {n_with_fragments:,} "
          f"({n_with_fragments/checks_done*100:.2f}%)")
    print(f"Checks above English threshold ({ENGLISH_THRESHOLD}): {n_above_threshold}")
    print()

    # Best overall
    print(f"BEST OVERALL SCORE: {best_overall[0]:.4f}")
    if best_overall[1]:
        b = best_overall[1]
        print(f"  Variant: {b['variant']}")
        print(f"  Width: {b['width']}, ordering #{b['ordering_idx']}")
        print(f"  Mask extra: {b['mask_extra']}")
        print(f"  Best fragment: '{b['best_fragment'][1]}' at key pos {b['best_fragment'][0]}")
        print(f"  All fragments: {b['all_fragments']}")

    # Sort results by score
    results.sort(key=lambda x: -x['score'])

    if results:
        print(f"\nTOP {min(30, len(results))} RESULTS (above {ENGLISH_THRESHOLD}):")
        print(f"{'Rank':>5} {'Score':>8} {'Variant':>6} {'Width':>5} "
              f"{'Fragment':>20} {'Frag_len':>8}")
        print("-" * 60)
        for i, r in enumerate(results[:30]):
            frag = r['best_fragment'][1]
            if len(frag) > 18:
                frag = frag[:15] + "..."
            print(f"{i+1:5d} {r['score']:8.4f} {r['variant']:>6} {r['width']:5d} "
                  f"{frag:>20} {len(r['best_fragment'][1]):8d}")

    # ── Fragment length distribution ──
    print()
    print("=" * 78)
    print("FRAGMENT LENGTH DISTRIBUTION (across all checks)")
    print("=" * 78)

    # Re-scan for fragment statistics (cheaper scan)
    frag_lengths = defaultdict(int)
    max_frag_by_width = defaultdict(int)

    for w in range(2, 21):
        for perm in perms_by_width[w]:
            # Use first mask (representative since fragment structure
            # depends mainly on width and crib spacing)
            shifted = mask_shifted[0]
            key_positions = [perm[s] for s in shifted]

            # Find max contiguous run
            pos_set = set(key_positions)
            sorted_kp = sorted(pos_set)
            if not sorted_kp:
                continue
            run = 1
            max_run = 1
            for i in range(1, len(sorted_kp)):
                if sorted_kp[i] == sorted_kp[i-1] + 1:
                    run += 1
                    max_run = max(max_run, run)
                else:
                    run = 1
            max_frag_by_width[w] = max(max_frag_by_width[w], max_run)
            frag_lengths[max_run] += 1

    print(f"\nMax contiguous fragment by width (using first mask, first ordering):")
    for w in sorted(max_frag_by_width):
        print(f"  Width {w:2d}: max fragment = {max_frag_by_width[w]}")

    print(f"\nMax fragment length distribution (across all widths × orderings):")
    for length in sorted(frag_lengths):
        print(f"  Length {length:2d}: {frag_lengths[length]} orderings")

    # ── Statistical context ──
    print()
    print("=" * 78)
    print("STATISTICAL CONTEXT")
    print("=" * 78)

    # Keystream letter frequency analysis
    for variant in ['beau', 'vig', 'vbeau']:
        ks = KEYSTREAM[variant]
        ks_str = "".join(ks)
        freq = defaultdict(int)
        for c in ks:
            freq[c] += 1

        # English expected frequencies for comparison
        ENGLISH_FREQ = {
            'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0,
            'N': 6.7, 'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3,
            'L': 4.0, 'C': 2.8, 'U': 2.8, 'M': 2.4, 'W': 2.4,
            'F': 2.2, 'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.5,
            'V': 1.0, 'K': 0.8, 'J': 0.2, 'X': 0.2, 'Q': 0.1,
            'Z': 0.1,
        }

        print(f"\n{variant.upper()} keystream: {ks_str}")
        print(f"  Letter frequencies vs English expectation:")
        for c in sorted(freq.keys(), key=lambda x: -freq[x]):
            observed_pct = freq[c] / 24 * 100
            expected_pct = ENGLISH_FREQ.get(c, 0.1)
            ratio = observed_pct / expected_pct if expected_pct > 0 else 999
            flag = " *** ANOMALOUS" if ratio > 5 else ""
            print(f"    {c}: {freq[c]:2d}/24 ({observed_pct:5.1f}%) "
                  f"vs English {expected_pct:4.1f}% "
                  f"(ratio={ratio:.1f}x){flag}")

    # ── Verdict ──
    print()
    print("=" * 78)
    print("VERDICT")
    print("=" * 78)

    if n_above_threshold == 0:
        print(f"\nZERO configurations produce English-like key fragments")
        print(f"(threshold: quadgram score > {ENGLISH_THRESHOLD}/char)")
        print(f"\nThis ELIMINATES: Running key + columnar transposition on")
        print(f"ALL {len(masks)} palette-consistent 73-char extracts,")
        print(f"at widths 2-7 (exhaustive orderings) and 8-20 (keyword orderings).")
        print(f"\nNote: the 24 known keystream values have non-English frequency")
        print(f"distributions (e.g., Beaufort has K at 20.8%, English expects 0.8%).")
        print(f"No transposition can fix the LETTER DISTRIBUTION of fragments —")
        print(f"it can only change which letters appear consecutively.")
    elif n_above_threshold < 10:
        print(f"\n{n_above_threshold} configurations show marginally English-like fragments.")
        print(f"Best score: {best_overall[0]:.4f}")
        print(f"INVESTIGATE these individually before drawing conclusions.")
    else:
        print(f"\n{n_above_threshold} configurations above threshold.")
        print(f"This may indicate underdetermination (many false positives).")

    # Save results
    result_path = os.path.join(_ROOT, "results", "mask_runkey_discriminator_01.json")
    result_data = {
        'experiment': 'e_mask_runkey_discriminator_01',
        'total_checks': checks_done,
        'elapsed_s': round(elapsed, 2),
        'n_masks': len(masks),
        'n_orderings': total_orderings,
        'n_with_fragments': n_with_fragments,
        'n_above_threshold': n_above_threshold,
        'english_threshold': ENGLISH_THRESHOLD,
        'best_score': round(best_overall[0], 4),
        'best_config': best_overall[1],
        'top_results': results[:50] if results else [],
    }
    with open(result_path, 'w') as f:
        json.dump(result_data, f, indent=2, default=str)
    print(f"\nResults saved to {result_path}")


if __name__ == "__main__":
    main()
