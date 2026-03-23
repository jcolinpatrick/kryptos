#!/usr/bin/env python3
"""
Phase 3: 7x5 Table Generation Mechanism (OQ-1)

Tests whether CHART, TOWER, LAYER, or other thematic words generate
the N/R pattern in the (pos%7, pos%5) classification table via
Cipher(KRYPTOS[pos%7], WORD[pos%5]).

Also tests: keystream-derived table generation (crib positions mapped
to 7×5 cells predict N/R assignment).

Output: results/table_generation_deep.json
"""
import sys, os, json
from collections import defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    CRIB_POSITIONS, CRIB_DICT, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, BEAUFORT_KEYSTREAM_AT_CRIBS,
)

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

# ── Build target table ───────────────────────────────────────────────────
PALETTE_POSITIONS = sorted(p for p in range(CT_LEN) if CT[p] in NULL_PALETTE)

cell_data = defaultdict(list)
for p in PALETTE_POSITIONS:
    cell_data[(p % 7, p % 5)].append((p, p in CONSENSUS_NULL_POSITIONS))

target = {}  # (r,c) -> True=null, False=real, 'mixed', None=empty
for r in range(7):
    for c in range(5):
        entries = cell_data.get((r, c), [])
        if not entries:
            target[(r, c)] = None
        else:
            nulls = [e for e in entries if e[1]]
            reals = [e for e in entries if not e[1]]
            if nulls and not reals:
                target[(r, c)] = True
            elif reals and not nulls:
                target[(r, c)] = False
            else:
                target[(r, c)] = 'mixed'

# For scoring: occupied cells that are pure N or pure R (23 cells)
occupied_pure = {(r, c): v for (r, c), v in target.items() if v in (True, False)}

results = {
    "experiment": "e_table_generation_deep",
    "date": datetime.now(timezone.utc).isoformat(),
}

# ── TG-1: Cipher word test ───────────────────────────────────────────────
def test_cipher_words():
    """Test thematic 5-letter words as table generators via Cipher(KRYPTOS[r], WORD[c])."""
    KRYPTOS_WORD = "KRYPTOS"

    # Previously found matching words (from mod35_table_derivation.json)
    # + thematic candidates
    test_words = [
        "CHART", "TOWER", "LAYER", "SEVEN", "CLOCK",
        "NORTH", "GHOST", "LIGHT", "SHIFT", "GRILLE",
        "SHADE", "PHASE", "STEGO", "MASKT",  # 5-letter
        "CODES", "CYPHA", "SCREN", "REDTR",
    ]
    # Filter to exactly 5 letters
    test_words = [w for w in test_words if len(w) == 5 and w.isalpha()]

    word_results = {}
    for word in test_words:
        for cipher in ["beaufort_az", "vigenere_az", "beaufort_ka", "vigenere_ka"]:
            # Compute cipher output for each (r,c) cell
            cell_outputs = {}
            for r in range(7):
                for c in range(5):
                    kr = ALPH_IDX[KRYPTOS_WORD[r]] if "az" in cipher else KA_IDX[KRYPTOS_WORD[r]]
                    wc = ALPH_IDX[word[c]] if "az" in cipher else KA_IDX[word[c]]
                    if "beaufort" in cipher:
                        out = (kr - wc) % MOD
                    else:  # vigenere
                        out = (kr + wc) % MOD
                    cell_outputs[(r, c)] = out

            # Find the partition that maximizes classification
            # The "null set" = values that map to null cells
            null_values = set()
            for (r, c), is_null in occupied_pure.items():
                if is_null:
                    null_values.add(cell_outputs[(r, c)])

            # Score: how many occupied pure cells are correctly classified?
            correct = 0
            for (r, c), is_null in occupied_pure.items():
                predicted_null = cell_outputs[(r, c)] in null_values
                if predicted_null == is_null:
                    correct += 1

            key = f"{word}:{cipher}"
            word_results[key] = {
                "word": word, "cipher": cipher,
                "correct": correct, "total": len(occupied_pure),
                "null_values": sorted(null_values),
                "null_letters": sorted(ALPH[v] for v in null_values),
            }

    # Find best
    best_key = max(word_results, key=lambda k: word_results[k]["correct"])
    best = word_results[best_key]

    # Also report all perfect matches
    perfect = {k: v for k, v in word_results.items() if v["correct"] == len(occupied_pure)}

    return {
        "test": "TG-1", "name": "Cipher word table generation",
        "words_tested": len(test_words), "cipher_variants": 4,
        "total_configs": len(word_results),
        "best": {**best, "key": best_key},
        "perfect_matches": perfect,
        "verdict": "MATCH" if perfect else "NO_PERFECT_MATCH",
    }


# ── TG-5: Keystream derivation ──────────────────────────────────────────
def test_keystream_derivation():
    """Do keystream values at crib positions predict the N/R pattern in the 7×5 table?"""
    ks_nums = [ALPH_IDX[c] for c in BEAUFORT_KEYSTREAM_AT_CRIBS]
    crib_pos_sorted = sorted(CRIB_POSITIONS)

    # Map each crib position to its (pos%7, pos%5) cell
    crib_cell_ks = {}
    for i, cp in enumerate(crib_pos_sorted):
        cell = (cp % 7, cp % 5)
        crib_cell_ks[cell] = ks_nums[i]

    # How many of the 23 occupied-pure cells have a crib mapping?
    cells_with_ks = {cell for cell in occupied_pure if cell in crib_cell_ks}

    # For cells with keystream data, check: are null-cell ks values in palette?
    null_cell_ks_in_palette = 0
    real_cell_ks_in_palette = 0
    palette_nums = {ALPH_IDX[c] for c in NULL_PALETTE}

    for cell in cells_with_ks:
        ks_val = crib_cell_ks[cell]
        is_null = occupied_pure[cell]
        in_palette = ks_val in palette_nums
        if is_null and in_palette:
            null_cell_ks_in_palette += 1
        elif not is_null and in_palette:
            real_cell_ks_in_palette += 1

    null_cells_with_ks = sum(1 for cell in cells_with_ks if occupied_pure[cell])
    real_cells_with_ks = sum(1 for cell in cells_with_ks if not occupied_pure[cell])

    return {
        "test": "TG-5", "name": "Keystream -> table derivation",
        "cells_with_crib_mapping": len(cells_with_ks),
        "null_cells_with_ks": null_cells_with_ks,
        "real_cells_with_ks": real_cells_with_ks,
        "null_cell_ks_in_palette": null_cell_ks_in_palette,
        "real_cell_ks_in_palette": real_cell_ks_in_palette,
        "crib_cell_map": {f"({c[0]},{c[1]})": {"ks": v, "letter": ALPH[v], "in_palette": v in palette_nums,
                                                  "cell_is_null": occupied_pure.get(c, "N/A")}
                           for c, v in crib_cell_ks.items()},
        "verdict": "CORRELATED" if null_cell_ks_in_palette > real_cell_ks_in_palette else "NO_CORRELATION",
    }


if __name__ == "__main__":
    print("=" * 72)
    print("Phase 3: Table Generation Mechanism (OQ-1)")
    print("=" * 72)

    for test_func in [test_cipher_words, test_keystream_derivation]:
        result = test_func()
        results[result["test"]] = result
        print(f"\n{'─' * 60}")
        print(f"  {result['test']}: {result['name']}")
        print(f"    Verdict: {result['verdict']}")
        if "best" in result:
            b = result["best"]
            print(f"    Best: {b.get('key', 'N/A')} -> {b.get('correct', 'N/A')}/{b.get('total', 'N/A')}")
        if "perfect_matches" in result and result["perfect_matches"]:
            print(f"    Perfect matches: {list(result['perfect_matches'].keys())}")

    out_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'table_generation_deep.json')
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n  Results: {out_path}")
