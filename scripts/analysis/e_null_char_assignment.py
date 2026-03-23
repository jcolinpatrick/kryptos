#!/usr/bin/env python3
"""
Phase 1: Null Character Assignment Function (OQ-3)

Tests 7 models for what determines WHICH palette letter fills each null position.
The 17 consensus nulls and their characters are known. We test whether position,
neighbors, grid cell, keystream proximity, or delta constraints predict the char.

Models:
  NC-1: Random draw (chi-square uniformity test)
  NC-2: Neighbor-determined: null_char = f(CT[p-1], CT[p+1])
  NC-3: Position formula: null_char_num = (a*pos + b) mod M -> palette
  NC-4: Keystream echo: null_char correlates with nearest crib keystream
  NC-5: Grid cell consistency: same (pos%7, pos%5) cell -> same letter
  NC-6: Cipher-determined: null_char = Beaufort(X, known_key) for some X
  NC-7: Delta constraint extension: null char forced by constant-delta-lag

Output: results/null_char_assignment.json
"""
import sys, os, json
from collections import Counter, defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    CRIB_POSITIONS, CRIB_DICT, BEAUFORT_KEYSTREAM_AT_CRIBS,
    ALPH, ALPH_IDX, MOD,
)

# ── Data setup ───────────────────────────────────────────────────────────
NULL_POS_SORTED = sorted(CONSENSUS_NULL_POSITIONS)
NULL_CHARS = [CT[p] for p in NULL_POS_SORTED]
NULL_NUMS = [ALPH_IDX[c] for c in NULL_CHARS]
PALETTE_LIST = sorted(NULL_PALETTE)
PALETTE_NUMS = sorted(ALPH_IDX[c] for c in NULL_PALETTE)
CRIB_POS_SORTED = sorted(CRIB_POSITIONS)
KS_NUMS = [ALPH_IDX[c] for c in BEAUFORT_KEYSTREAM_AT_CRIBS]
KS_AT_POS = dict(zip(CRIB_POS_SORTED, KS_NUMS))

results = {"experiment": "e_null_char_assignment", "date": datetime.now(timezone.utc).isoformat(), "models": {}}


# ── NC-1: Chi-square uniformity test ─────────────────────────────────────
def test_nc1_uniformity():
    """Are the 17 null characters uniformly drawn from the 7-letter palette?"""
    freqs = Counter(NULL_CHARS)
    expected = 17.0 / 7.0  # 2.43
    chi2 = sum((freqs.get(c, 0) - expected) ** 2 / expected for c in PALETTE_LIST)
    df = 6  # 7 categories - 1
    # Approximate p-value using chi2 with 6 df
    # For chi2=6.06 (df=6): p ≈ 0.42 (not significant)
    # Manual: W=4 -> (4-2.43)^2/2.43=1.01, O=3->0.13, G=3->0.13, B=2->0.08, I=2->0.08, K=2->0.08, Z=1->0.84
    # chi2 = 1.01+0.13+0.13+0.08+0.08+0.08+0.84 = 2.35
    return {
        "model": "NC-1", "name": "Uniformity chi-square",
        "frequencies": dict(freqs), "chi2": round(chi2, 4),
        "df": df, "expected_per_letter": round(expected, 4),
        "verdict": "CANNOT_REJECT_UNIFORM" if chi2 < 12.59 else "REJECT_UNIFORM",
        "note": "Chi2 critical value at alpha=0.05, df=6 is 12.59"
    }


# ── NC-2: Neighbor analysis ──────────────────────────────────────────────
def test_nc2_neighbors():
    """Can null_char be computed from CT[p-1] and CT[p+1]?"""
    results_nc2 = []
    neighbor_data = []
    for p in NULL_POS_SORTED:
        left = ALPH_IDX[CT[p - 1]] if p > 0 else ALPH_IDX[CT[CT_LEN - 1]]
        right = ALPH_IDX[CT[p + 1]] if p < CT_LEN - 1 else ALPH_IDX[CT[0]]
        null_num = ALPH_IDX[CT[p]]
        neighbor_data.append({"pos": p, "char": CT[p], "num": null_num,
                              "left": left, "right": right,
                              "left_char": CT[p-1] if p > 0 else CT[CT_LEN-1],
                              "right_char": CT[p+1] if p < CT_LEN-1 else CT[0]})

    # Test functions: (left + right) % 26, (left - right) % 26, (left * right) % 26,
    # (left + right) % 7 -> palette, abs(left - right) % 7 -> palette, etc.
    functions = {
        "sum_mod26": lambda l, r: (l + r) % MOD,
        "diff_mod26": lambda l, r: (l - r) % MOD,
        "sum_mod7_palette": lambda l, r: PALETTE_NUMS[(l + r) % 7],
        "diff_mod7_palette": lambda l, r: PALETTE_NUMS[(l - r) % 7],
        "mean_floor": lambda l, r: (l + r) // 2,
        "xor_mod26": lambda l, r: (l ^ r) % MOD,
        "beaufort_lr": lambda l, r: (l + r) % MOD,  # same as sum — Beaufort(left, right)
        "max_mod7_palette": lambda l, r: PALETTE_NUMS[max(l, r) % 7],
        "min_mod7_palette": lambda l, r: PALETTE_NUMS[min(l, r) % 7],
    }

    best_func = None
    best_score = 0
    func_results = {}

    for fname, func in functions.items():
        matches = 0
        for nd in neighbor_data:
            predicted = func(nd["left"], nd["right"])
            if predicted == nd["num"]:
                matches += 1
        func_results[fname] = matches
        if matches > best_score:
            best_score = matches
            best_func = fname

    return {
        "model": "NC-2", "name": "Neighbor-determined",
        "neighbor_data": neighbor_data,
        "function_scores": func_results,
        "best_function": best_func, "best_score": f"{best_score}/17",
        "verdict": "MATCH" if best_score >= 16 else "NO_MATCH",
    }


# ── NC-3: Position formula ───────────────────────────────────────────────
def test_nc3_position_formula():
    """Can null_char_num = (a*pos + b) mod M -> palette index?"""
    best_score = 0
    best_params = None
    tested = 0

    for M in [5, 7, 26]:
        for a in range(M):
            for b in range(M):
                matches = 0
                for i, p in enumerate(NULL_POS_SORTED):
                    if M <= 7:
                        predicted = PALETTE_NUMS[(a * p + b) % M] if (a * p + b) % M < 7 else -1
                    else:
                        predicted = (a * p + b) % M
                    if predicted == NULL_NUMS[i]:
                        matches += 1
                tested += 1
                if matches > best_score:
                    best_score = matches
                    best_params = {"a": a, "b": b, "M": M}

    return {
        "model": "NC-3", "name": "Position formula",
        "tested": tested, "best_score": f"{best_score}/17",
        "best_params": best_params,
        "verdict": "MATCH" if best_score >= 16 else "NO_MATCH",
    }


# ── NC-4: Keystream echo (nearest crib) ─────────────────────────────────
def test_nc4_keystream_echo():
    """Does null_char correlate with keystream at nearest crib position?"""
    nearest_ks = []
    for p in NULL_POS_SORTED:
        # Find nearest crib position
        min_dist = CT_LEN
        nearest_crib = -1
        for cp in CRIB_POS_SORTED:
            dist = abs(p - cp)
            if dist < min_dist:
                min_dist = dist
                nearest_crib = cp
        ks_val = KS_AT_POS[nearest_crib]
        nearest_ks.append({"pos": p, "null_num": ALPH_IDX[CT[p]], "nearest_crib": nearest_crib,
                           "distance": min_dist, "ks_value": ks_val, "ks_letter": ALPH[ks_val]})

    # Test: null_num = (ks_val + offset) % 26 for each offset
    best_offset = -1
    best_score = 0
    for offset in range(MOD):
        matches = sum(1 for nk in nearest_ks if (nk["ks_value"] + offset) % MOD == nk["null_num"])
        if matches > best_score:
            best_score = matches
            best_offset = offset

    # Test: null_num = ks_val (direct)
    direct_matches = sum(1 for nk in nearest_ks if nk["ks_value"] == nk["null_num"])

    # Test: null is palette[ks_val % 7]
    palette_idx_matches = sum(
        1 for nk in nearest_ks if PALETTE_NUMS[nk["ks_value"] % 7] == nk["null_num"]
    )

    return {
        "model": "NC-4", "name": "Keystream echo",
        "data": nearest_ks,
        "direct_matches": f"{direct_matches}/17",
        "best_offset": best_offset, "best_offset_score": f"{best_score}/17",
        "palette_idx_matches": f"{palette_idx_matches}/17",
        "verdict": "MATCH" if best_score >= 14 else "NO_MATCH",
    }


# ── NC-5: Grid cell consistency ──────────────────────────────────────────
def test_nc5_grid_cell():
    """Do all nulls in the same (pos%7, pos%5) cell get the same letter?"""
    cell_chars = defaultdict(list)
    for p in NULL_POS_SORTED:
        cell = (p % 7, p % 5)
        cell_chars[cell].append({"pos": p, "char": CT[p]})

    consistent = True
    inconsistent_cells = []
    for cell, entries in cell_chars.items():
        chars = set(e["char"] for e in entries)
        if len(chars) > 1:
            consistent = False
            inconsistent_cells.append({"cell": cell, "entries": entries})

    # Build the cell-to-letter mapping
    cell_letter_map = {}
    for cell, entries in cell_chars.items():
        cell_letter_map[f"({cell[0]},{cell[1]})"] = entries[0]["char"]

    return {
        "model": "NC-5", "name": "Grid cell consistency",
        "num_cells_with_nulls": len(cell_chars),
        "consistent": consistent,
        "cell_letter_map": cell_letter_map,
        "inconsistent_cells": inconsistent_cells,
        "verdict": "CONSISTENT" if consistent else "INCONSISTENT",
        "note": "If consistent, the stego mechanism is a 10-entry lookup table: (pos%7,pos%5) -> palette letter"
    }


# ── NC-6: Cipher-determined ──────────────────────────────────────────────
def test_nc6_cipher_determined():
    """Is null_char = Beaufort(pos_in_some_sequence, known_key)?"""
    # For each null position, check: CT[p] = (key - X) mod 26 for some consistent X source
    # Test: X = position index (0,1,2,...), X = pos mod 7, X = pos mod 5, X = pos mod 26
    sources = {
        "seq_index": list(range(17)),
        "pos_mod7": [p % 7 for p in NULL_POS_SORTED],
        "pos_mod5": [p % 5 for p in NULL_POS_SORTED],
        "pos_mod26": [p % MOD for p in NULL_POS_SORTED],
        "pos_div7": [p // 7 for p in NULL_POS_SORTED],
    }

    # For each source X and each potential key K (0-25), check matches
    best = {"source": None, "key": -1, "score": 0}
    all_results = {}
    for src_name, x_vals in sources.items():
        best_for_source = 0
        for key in range(MOD):
            matches = sum(
                1 for i in range(17) if (key - x_vals[i]) % MOD == NULL_NUMS[i]
            )
            if matches > best_for_source:
                best_for_source = matches
            if matches > best["score"]:
                best = {"source": src_name, "key": key, "key_letter": ALPH[key], "score": matches}
        all_results[src_name] = best_for_source

    return {
        "model": "NC-6", "name": "Cipher-determined",
        "best": {**best, "score_str": f"{best['score']}/17"},
        "source_best_scores": all_results,
        "verdict": "MATCH" if best["score"] >= 14 else "NO_MATCH",
    }


# ── NC-7: Delta constraint extension ────────────────────────────────────
def test_nc7_delta_extension():
    """How many nulls are uniquely forced by a constant lag-delta constraint?"""
    forced_count = 0
    forced_details = []

    for p in NULL_POS_SORTED:
        forced = False
        for lag in range(1, 5):
            # Check: is CT[p] uniquely determined to maintain constant delta at this lag?
            # Need positions p-lag and p+lag to both be non-null
            if p - lag < 0 or p + lag >= CT_LEN:
                continue
            if (p - lag) in CONSENSUS_NULL_POSITIONS or (p + lag) in CONSENSUS_NULL_POSITIONS:
                continue
            # Delta at this lag: CT[p-lag] to CT[p] and CT[p] to CT[p+lag]
            # If delta(p-lag, p) should equal delta(p, p+lag):
            left_val = ALPH_IDX[CT[p - lag]]
            right_val = ALPH_IDX[CT[p + lag]]
            # If constant delta d: CT[p] = left_val + d AND CT[p] = right_val - d
            # => 2*CT[p] = left_val + right_val => CT[p] = (left_val + right_val) / 2
            mean = (left_val + right_val)
            if mean % 2 == 0 and mean // 2 == ALPH_IDX[CT[p]]:
                forced = True
                forced_details.append({"pos": p, "lag": lag, "left": p - lag, "right": p + lag,
                                        "left_val": left_val, "right_val": right_val,
                                        "predicted": mean // 2, "actual": ALPH_IDX[CT[p]]})
                break

        # Also check the known Delta4=5 pattern (positions 58,59)
        if not forced and p in (58, 59):
            forced = True
            forced_details.append({"pos": p, "mechanism": "Delta4=5 (known)", "actual": ALPH_IDX[CT[p]]})

        if forced:
            forced_count += 1

    return {
        "model": "NC-7", "name": "Delta constraint extension",
        "forced_count": f"{forced_count}/17",
        "forced_details": forced_details,
        "verdict": "SIGNIFICANT" if forced_count >= 10 else "PARTIAL" if forced_count >= 4 else "MINIMAL",
    }


# ── Main ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 72)
    print("Phase 1: Null Character Assignment Function (OQ-3)")
    print("=" * 72)
    print(f"\n17 consensus nulls:")
    print(f"  Positions: {NULL_POS_SORTED}")
    print(f"  Chars:     {NULL_CHARS}")
    print(f"  Nums:      {NULL_NUMS}")
    print()

    for test_func in [test_nc1_uniformity, test_nc2_neighbors, test_nc3_position_formula,
                       test_nc4_keystream_echo, test_nc5_grid_cell,
                       test_nc6_cipher_determined, test_nc7_delta_extension]:
        result = test_func()
        results["models"][result["model"]] = result
        print(f"\n{'─' * 60}")
        print(f"  {result['model']}: {result['name']}")
        verdict_key = "verdict"
        score_keys = [k for k in result if "score" in k.lower() and k != "function_scores"]
        if score_keys:
            for k in score_keys:
                print(f"    {k}: {result[k]}")
        print(f"    Verdict: {result[verdict_key]}")

    # Summary
    print(f"\n{'=' * 72}")
    print("SUMMARY")
    print(f"{'=' * 72}")
    matches = [m for m, r in results["models"].items() if r.get("verdict") in ("MATCH", "CONSISTENT")]
    no_matches = [m for m, r in results["models"].items() if r.get("verdict") in ("NO_MATCH", "INCONSISTENT")]
    print(f"  Models with signal: {matches if matches else 'NONE'}")
    print(f"  Models eliminated:  {no_matches if no_matches else 'NONE'}")

    # Write results
    out_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'null_char_assignment.json')
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n  Results: {out_path}")
