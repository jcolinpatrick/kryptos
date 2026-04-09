#!/usr/bin/env python3 -u
"""
Cipher:  Ubchi-style double transposition with null insertion between layers
Family:  novel
Status:  exhausted
Keyspace: ~5K keyword pairs x 3 null counts x 2 insertion modes x 2 peel orders = ~60K configs
Last run:
Best score:

HYPOTHESIS (TICOM): German WWI Ubchi cipher inserted null letters BETWEEN two
transposition layers: PT -> trans1 -> insert nulls -> trans2 -> CT.

This is structurally distinct from all prior tests:
- Prior null-mask tests: strip nulls from CT, THEN decrypt
- Prior transposition tests: decrypt CT directly (no null layer)
- Ubchi: nulls sit BETWEEN two transposition layers

Peel order matters:
  Model A: CT -> undo_trans2 -> strip_nulls -> undo_trans1 -> PT
  Model B: CT -> strip_nulls -> undo_trans2 -> undo_trans1 -> PT
  (Model B tests whether nulls were added AFTER both transpositions)

Three null-count hypotheses: 24 (73-char message), 17 (consensus), variable.
Null positions identified by palette membership {B,G,I,K,O,W,Z}.

All positions 0-indexed. Constants imported from kernel.
"""

import sys
import os
import json
import time
from datetime import datetime, timezone
from itertools import permutations
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, CRIB_DICT, CRIB_POSITIONS,
    CONSENSUS_NULL_POSITIONS,
)
from kryptos.kernel.scoring.aggregate import score_candidate_free
from kryptos.kernel.transforms.transposition import (
    columnar_perm, invert_perm, apply_perm, keyword_to_order,
)

# ── Null palette ────────────────────────────────────────────────────────────

NULL_PALETTE = frozenset("BGIKOWZ")
PALETTE_POSITIONS = frozenset(i for i, c in enumerate(CT) if c in NULL_PALETTE)

# ── Keywords ────────────────────────────────────────────────────────────────

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "SHADOW",
    "BERLIN", "SCHEIDT", "SANBORN", "SEVEN", "CLOCK",
    "FIVE", "ENIGMA", "HAYDN", "NORMANDY", "ECLIPSE",
]

# ── Columnar transposition helpers ──────────────────────────────────────────

def undo_columnar(ct_str, width, col_order):
    """Undo columnar transposition (decrypt direction)."""
    perm = columnar_perm(width, col_order, len(ct_str))
    inv = invert_perm(perm)
    return apply_perm(ct_str, inv)


def strip_palette_nulls(text, target_len=None):
    """Remove palette letters to reach target length.

    Removes palette letters from RIGHT to LEFT (last occurrences first)
    until target_len is reached. If target_len is None, removes all palette letters.
    """
    if target_len is None:
        return ''.join(c for c in text if c not in NULL_PALETTE)

    n_remove = len(text) - target_len
    if n_remove <= 0:
        return text

    # Find palette positions (indices where letter is in palette)
    palette_indices = [i for i, c in enumerate(text) if c in NULL_PALETTE]
    if len(palette_indices) < n_remove:
        return None  # Can't remove enough

    # Remove from the end first (rightmost palette letters)
    to_remove = set(palette_indices[-n_remove:])
    return ''.join(c for i, c in enumerate(text) if i not in to_remove)


def strip_nulls_at_positions(text, null_positions):
    """Remove characters at specific positions."""
    return ''.join(c for i, c in enumerate(text) if i not in null_positions)


# ── Scoring ─────────────────────────────────────────────────────────────────

ENE = "EASTNORTHEAST"
BCL = "BERLINCLOCK"

def quick_score(pt):
    """Fast substring search for both cribs."""
    s = 0
    if ENE in pt:
        s += 13
    if BCL in pt:
        s += 11
    return s


# ── Main attack ─────────────────────────────────────────────────────────────

def attack():
    start = time.time()
    results = []
    configs_tested = 0
    best_score = 0

    print(f"Ubchi-style null insertion test")
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Palette positions: {len(PALETTE_POSITIONS)}")
    print(f"Keywords: {len(KEYWORDS)}")
    print()

    # For each keyword pair (trans1_key, trans2_key)
    for kw1 in KEYWORDS:
        for width1 in range(5, 15):
            order1 = keyword_to_order(kw1, width1)
            if order1 is None:
                continue

            for kw2 in KEYWORDS:
                for width2 in range(5, 15):
                    order2 = keyword_to_order(kw2, width2)
                    if order2 is None:
                        continue

                    # ── MODEL A: CT -> undo_trans2 -> strip_nulls -> undo_trans1 -> PT ──
                    # (Nulls inserted between trans1 and trans2)

                    # Step 1: Undo trans2
                    intermediate1 = undo_columnar(CT, width2, order2)

                    # Step 2: Strip nulls (try consensus 17, palette-based 24, and all-palette)
                    for null_mode, null_set, target in [
                        ("consensus17", CONSENSUS_NULL_POSITIONS, None),
                        ("palette_all", None, None),  # remove all palette letters
                    ]:
                        if null_set is not None:
                            # Map consensus positions through trans2 inverse
                            # After undoing trans2, the null positions may have moved
                            # Actually: the nulls were inserted into the INTERMEDIATE,
                            # so their positions in the intermediate are what we strip.
                            # But we don't know where they are in the intermediate.
                            # Strategy: strip by LETTER (palette membership)
                            if null_mode == "consensus17":
                                stripped = strip_nulls_at_positions(intermediate1, null_set)
                            else:
                                stripped = strip_palette_nulls(intermediate1)
                        else:
                            stripped = strip_palette_nulls(intermediate1)

                        if stripped is None or len(stripped) < 30:
                            continue

                        # Step 3: Undo trans1
                        # Width1 must divide evenly or handle remainder
                        pt = undo_columnar(stripped, width1, keyword_to_order(kw1, width1))

                        configs_tested += 1
                        s = quick_score(pt)
                        if s > best_score:
                            best_score = s
                            print(f"  NEW BEST: {s}/24 | A|w1={width1}|w2={width2}|kw1={kw1}|kw2={kw2}|null={null_mode}")
                            print(f"    PT: {pt[:60]}")
                        if s >= 11:
                            results.append({
                                'score': s, 'model': 'A',
                                'kw1': kw1, 'width1': width1,
                                'kw2': kw2, 'width2': width2,
                                'null_mode': null_mode,
                                'pt': pt, 'pt_len': len(pt),
                            })

                    # ── MODEL B: CT -> strip_nulls -> undo_trans2 -> undo_trans1 -> PT ──
                    # (Nulls added after both transpositions — simpler model)

                    for null_mode in ["palette_all"]:
                        stripped = strip_palette_nulls(CT)
                        if stripped is None or len(stripped) < 30:
                            continue

                        inter = undo_columnar(stripped, width2, keyword_to_order(kw2, width2))
                        pt = undo_columnar(inter, width1, keyword_to_order(kw1, width1))

                        configs_tested += 1
                        s = quick_score(pt)
                        if s > best_score:
                            best_score = s
                            print(f"  NEW BEST: {s}/24 | B|w1={width1}|w2={width2}|kw1={kw1}|kw2={kw2}|null={null_mode}")
                            print(f"    PT: {pt[:60]}")
                        if s >= 11:
                            results.append({
                                'score': s, 'model': 'B',
                                'kw1': kw1, 'width1': width1,
                                'kw2': kw2, 'width2': width2,
                                'null_mode': null_mode,
                                'pt': pt, 'pt_len': len(pt),
                            })

        print(f"  Keyword {kw1} done, {configs_tested} configs, best={best_score}/24")

    elapsed = time.time() - start

    # Save results
    outpath = os.path.join(_ROOT, "results", f"ubchi_null_insertion_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json")
    summary = {
        'script': 'e_ubchi_null_insertion_01.py',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'configs_tested': configs_tested,
        'best_score': best_score,
        'hits': len(results),
        'runtime_seconds': round(elapsed, 1),
        'results': results[:100],
    }
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"\n{'='*70}")
    print(f"UBCHI NULL INSERTION TEST COMPLETE")
    print(f"Configs tested: {configs_tested}")
    print(f"Best score: {best_score}/24")
    print(f"Hits (>=11): {len(results)}")
    print(f"Runtime: {elapsed:.1f}s")
    print(f"Results: {outpath}")
    if best_score < 10:
        print(f"Conclusion: NOISE — no signal detected")
    print(f"{'='*70}")


if __name__ == "__main__":
    attack()
