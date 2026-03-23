# Stego Layer Solve — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute four research phases that characterize the K4 steganographic mechanism and constrain the cipher layer.

**Architecture:** Each phase is a standalone experiment script in `scripts/analysis/` that imports from `kryptos.kernel.constants`, runs targeted tests against the 17 consensus null positions, and writes structured JSON results to `results/`. No new kernel modules needed — all infrastructure exists. Phase 1 tests null character assignment (7 models). Phase 2 resolves varying null positions via the false-positive connection. Phase 3 investigates CHART as a table generation keyword. Phase 4 tests Polybius grid reading orders as keystream source.

**Tech Stack:** Python 3.12, stdlib only, `PYTHONPATH=src`, pytest

**Spec:** `docs/superpowers/specs/2026-03-23-stego-layer-research-plan.md`

---

## File Structure

```
scripts/analysis/
  e_null_char_assignment.py     — Phase 1: 7 models for which palette letter fills each null position
  e_varying_null_resolution.py  — Phase 2: false-positive connection + C(13,7) mask enumeration
  e_table_generation_deep.py    — Phase 3: CHART keyword + keystream derivation of 7×5 table
  e_grid_key_generation.py      — Phase 4: Polybius grid reading orders as running key source

results/
  null_char_assignment.json     — Phase 1 output
  varying_null_resolution.json  — Phase 2 output
  table_generation_deep.json    — Phase 3 output
  grid_key_generation.json      — Phase 4 output

tests/
  test_stego_solve.py           — Regression tests for data integrity and known invariants
```

Each script is independent (no cross-phase dependencies) and follows the standard `attack()` contract where applicable.

---

## Task 1: Phase 1 — Null Character Assignment (OQ-3)

**Question:** Given that position P is a null, what determines which palette letter {B,G,I,K,O,W,Z} fills it?

**Files:**
- Create: `scripts/analysis/e_null_char_assignment.py`
- Create: `tests/test_stego_solve.py`
- Output: `results/null_char_assignment.json`

### Step 1: Write regression test for null data integrity

- [ ] Create `tests/test_stego_solve.py` with tests that lock in the 17 consensus null positions and their characters:

```python
"""Regression tests for stego layer solve pipeline."""
import pytest
from kryptos.kernel.constants import (
    CT, CT_LEN, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    CRIB_POSITIONS, BEAUFORT_KEYSTREAM_AT_CRIBS, ALPH,
)

# The 17 consensus null characters in position order
CONSENSUS_NULL_CHARS = tuple(CT[p] for p in sorted(CONSENSUS_NULL_POSITIONS))
CONSENSUS_NULL_NUMS = tuple(ALPH.index(c) for c in CONSENSUS_NULL_CHARS)


class TestNullDataIntegrity:
    """Lock in the exact null characters for all downstream experiments."""

    def test_17_consensus_nulls(self):
        assert len(CONSENSUS_NULL_POSITIONS) == 17

    def test_all_null_chars_in_palette(self):
        for p in CONSENSUS_NULL_POSITIONS:
            assert CT[p] in NULL_PALETTE, f"CT[{p}]={CT[p]} not in palette"

    def test_exact_null_characters(self):
        """The exact character at each null position — regression anchor."""
        expected = {
            0: 'O', 1: 'B', 2: 'K', 5: 'O', 8: 'G', 12: 'B', 14: 'O',
            20: 'W', 36: 'W', 52: 'K', 58: 'W', 59: 'I', 74: 'W',
            75: 'G', 78: 'Z', 84: 'I', 85: 'G',
        }
        for pos, char in expected.items():
            assert CT[pos] == char, f"CT[{pos}] expected {char}, got {CT[pos]}"

    def test_null_letter_frequencies(self):
        """W=4, O=3, G=3, B=2, I=2, K=2, Z=1."""
        from collections import Counter
        freqs = Counter(CT[p] for p in CONSENSUS_NULL_POSITIONS)
        assert freqs == {'W': 4, 'O': 3, 'G': 3, 'B': 2, 'I': 2, 'K': 2, 'Z': 1}

    def test_no_nulls_in_crib_ranges(self):
        assert not CONSENSUS_NULL_POSITIONS & CRIB_POSITIONS

    def test_keystream_length_matches_cribs(self):
        assert len(BEAUFORT_KEYSTREAM_AT_CRIBS) == 24


class TestPalettePositions:
    """Verify palette position structure used by Phase 2."""

    def test_35_palette_positions_in_ct97(self):
        palette_positions = [p for p in range(CT_LEN) if CT[p] in NULL_PALETTE]
        assert len(palette_positions) == 35

    def test_17_nulls_plus_18_reals_equals_35(self):
        palette_positions = {p for p in range(CT_LEN) if CT[p] in NULL_PALETTE}
        null_palette_positions = palette_positions & CONSENSUS_NULL_POSITIONS
        real_palette_positions = palette_positions - CONSENSUS_NULL_POSITIONS
        assert len(null_palette_positions) == 17
        assert len(real_palette_positions) == 18
```

- [ ] Run: `PYTHONPATH=src pytest tests/test_stego_solve.py -v`
- [ ] Expected: ALL PASS

### Step 2: Write Phase 1 experiment script

- [ ] Create `scripts/analysis/e_null_char_assignment.py`:

```python
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
        for key in range(MOD):
            matches = sum(
                1 for i in range(17) if (key - x_vals[i]) % MOD == NULL_NUMS[i]
            )
            if matches > best["score"]:
                best = {"source": src_name, "key": key, "key_letter": ALPH[key], "score": matches}
        all_results[src_name] = best["score"] if best["source"] == src_name else 0

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
```

- [ ] Run: `PYTHONPATH=src python3 -u scripts/analysis/e_null_char_assignment.py`
- [ ] Expected: Each model reports its score and verdict. NC-5 (grid cell consistency) is the most likely to return CONSISTENT.

### Step 3: Commit Phase 1

- [ ] `git add tests/test_stego_solve.py scripts/analysis/e_null_char_assignment.py`
- [ ] `git commit -m "feat: Phase 1 stego solve — null character assignment (OQ-3)"`

---

## Task 2: Phase 2 — Varying Null Resolution (OQ-2)

**Question:** Which 7 positions complete the 24-null mask? Tests the false-positive connection: the 7×5 table predicts 16 non-palette "null" positions — do the 7 varying nulls come from these?

**Files:**
- Create: `scripts/analysis/e_varying_null_resolution.py`
- Output: `results/varying_null_resolution.json`

### Step 1: Write Phase 2 experiment script

- [ ] Create `scripts/analysis/e_varying_null_resolution.py`:

```python
#!/usr/bin/env python3
"""
Phase 2: Resolving the 7 Varying Null Positions (OQ-2)

The (pos%7, pos%5) table classifies 35 palette positions perfectly.
When applied to ALL 97 positions, 16 non-palette positions also fall in "null" cells.
Hypothesis VP-1: The 7 varying nulls are drawn from these 16 false-positive positions.

After excluding crib-range positions, only C(13,7)=1,716 candidate masks remain.
Test each against cipher models to see if any break the 15/24 ceiling.

Output: results/varying_null_resolution.json
"""
import sys, os, json
from collections import defaultdict
from itertools import combinations
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    CRIB_POSITIONS, CRIB_DICT, ALPH, ALPH_IDX, MOD,
    BEAUFORT_KEYSTREAM_AT_CRIBS,
)

# ── Build the 7×5 classification table ───────────────────────────────────
PALETTE_POSITIONS = sorted(p for p in range(CT_LEN) if CT[p] in NULL_PALETTE)

cell_labels = {}  # (r,c) -> 'N', 'R', 'M', or None
cell_positions = defaultdict(list)
for p in PALETTE_POSITIONS:
    cell_positions[(p % 7, p % 5)].append(p)

for r in range(7):
    for c in range(5):
        positions = cell_positions.get((r, c), [])
        if not positions:
            cell_labels[(r, c)] = None
        else:
            null_count = sum(1 for p in positions if p in CONSENSUS_NULL_POSITIONS)
            real_count = len(positions) - null_count
            if null_count > 0 and real_count == 0:
                cell_labels[(r, c)] = 'N'
            elif real_count > 0 and null_count == 0:
                cell_labels[(r, c)] = 'R'
            else:
                cell_labels[(r, c)] = 'M'

NULL_CELLS = {(r, c) for (r, c), v in cell_labels.items() if v in ('N', 'M')}

# ── Find false-positive positions ────────────────────────────────────────
# Non-palette positions that fall in null/mixed cells
false_positive_positions = sorted(
    p for p in range(CT_LEN)
    if CT[p] not in NULL_PALETTE
    and (p % 7, p % 5) in NULL_CELLS
)

# Exclude crib-range positions
crib_range = set()
for start, word in [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]:
    for i in range(len(word)):
        crib_range.add(start + i)

fp_no_cribs = sorted(p for p in false_positive_positions if p not in crib_range)

# Known varying null ranges from memory
KNOWN_VARYING_RANGES = [{38,39,40,41,42,43,44,45}, {54,55,56}, {87,88}, {93,94,95,96}]
known_varying_union = set()
for r in KNOWN_VARYING_RANGES:
    known_varying_union |= r

results = {
    "experiment": "e_varying_null_resolution",
    "date": datetime.now(timezone.utc).isoformat(),
}


def score_mask(null_positions):
    """Score a 24-position null mask against cribs using Beaufort A=0.

    Returns crib score (0-24): how many crib positions have consistent keystream.
    A 'consistent' position means the Beaufort keystream value at that position
    matches the known keystream JLJODEGKUKKKLOCGGBGOKTRU.
    """
    ks_expected = [ALPH_IDX[c] for c in BEAUFORT_KEYSTREAM_AT_CRIBS]
    crib_pos_sorted = sorted(CRIB_POSITIONS)

    score = 0
    for i, cp in enumerate(crib_pos_sorted):
        if cp in null_positions:
            continue  # null at crib position = invalid, but shouldn't happen per S6
        ct_val = ALPH_IDX[CT[cp]]
        pt_val = ALPH_IDX[CRIB_DICT[cp]]
        ks_val = (ct_val + pt_val) % MOD  # Beaufort: K = (C + P) mod 26
        if ks_val == ks_expected[i]:
            score += 1
    return score


if __name__ == "__main__":
    print("=" * 72)
    print("Phase 2: Varying Null Resolution (OQ-2)")
    print("=" * 72)

    # Step 1: Report false-positive positions
    print(f"\n16 non-palette positions in null cells: {false_positive_positions}")
    print(f"  After removing crib positions: {fp_no_cribs} ({len(fp_no_cribs)} positions)")

    # Step 2: Check overlap with known varying ranges
    overlap = sorted(p for p in fp_no_cribs if p in known_varying_union)
    print(f"\n  Overlap with known varying ranges: {overlap} ({len(overlap)}/{len(fp_no_cribs)})")

    results["false_positive_positions"] = false_positive_positions
    results["fp_after_crib_exclusion"] = fp_no_cribs
    results["overlap_with_varying_ranges"] = overlap
    results["overlap_count"] = len(overlap)

    # Step 3: VP-1 test — if >=6 overlap, hypothesis is supported
    vp1_supported = len(overlap) >= 6
    print(f"\n  VP-1 hypothesis (≥6/7 from false positives): {'SUPPORTED' if vp1_supported else 'FAILED'}")
    results["vp1_supported"] = vp1_supported

    if vp1_supported and len(fp_no_cribs) >= 7:
        # Step 4: Enumerate C(N,7) masks and score each
        n_candidates = len(fp_no_cribs)
        n_masks = 1
        for i in range(7):
            n_masks = n_masks * (n_candidates - i) // (i + 1)
        print(f"\n  Candidate pool: {n_candidates} positions -> C({n_candidates},7) = {n_masks} masks")

        best_score = 0
        best_masks = []
        score_distribution = defaultdict(int)

        for varying_7 in combinations(fp_no_cribs, 7):
            full_mask = CONSENSUS_NULL_POSITIONS | set(varying_7)
            # Verify: 24 nulls, no overlap with cribs
            if len(full_mask) != 24:
                continue
            if full_mask & CRIB_POSITIONS:
                continue

            score = score_mask(full_mask)
            score_distribution[score] += 1

            if score > best_score:
                best_score = score
                best_masks = [sorted(varying_7)]
            elif score == best_score:
                best_masks.append(sorted(varying_7))

        print(f"\n  Masks tested: {sum(score_distribution.values())}")
        print(f"  Best score: {best_score}/24")
        print(f"  Masks at best: {len(best_masks)}")
        print(f"  Score distribution: {dict(sorted(score_distribution.items()))}")

        results["masks_tested"] = sum(score_distribution.values())
        results["best_score"] = best_score
        results["best_masks_count"] = len(best_masks)
        results["best_masks_sample"] = best_masks[:20]  # first 20
        results["score_distribution"] = dict(sorted(score_distribution.items()))

        # The known keystream is FIXED — all masks should score 24/24 at crib positions
        # because nulls don't overlap cribs (S6). Score variation comes from the mask
        # not affecting crib positions at all. So we expect ALL masks to score 24/24.
        # The real discriminator is the cipher mechanism, not the crib score.
        # Let's also compute a different metric: how many of the 7 varying positions
        # have CT letters that fall in a restricted set (second palette test).
        print(f"\n  --- Second Palette Analysis (VM-1) ---")
        varying_letters_all = set()
        for combo in best_masks[:100]:
            for p in combo:
                varying_letters_all.add(CT[p])
        print(f"  Distinct letters at varying positions (across top masks): {sorted(varying_letters_all)}")
        print(f"  Count: {len(varying_letters_all)}/26")
        results["varying_letters_pool"] = sorted(varying_letters_all)
    else:
        print("\n  VP-1 not supported — skipping mask enumeration")
        results["masks_tested"] = 0

    # Write results
    out_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'varying_null_resolution.json')
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n  Results: {out_path}")
```

- [ ] Run: `PYTHONPATH=src python3 -u scripts/analysis/e_varying_null_resolution.py`
- [ ] Expected: VP-1 overlap count ≥6/7, then C(13,7)=1716 masks enumerated. All masks likely score 24/24 at crib positions (because nulls don't touch cribs). The discriminator is the letter-diversity and structural coherence.

### Step 2: Commit Phase 2

- [ ] `git add scripts/analysis/e_varying_null_resolution.py`
- [ ] `git commit -m "feat: Phase 2 stego solve — varying null resolution via false-positive connection (OQ-2)"`

---

## Task 3: Phase 3 — Table Generation Mechanism (OQ-1)

**Question:** Does CHART (or another thematic word) generate the 7×5 table's N/R pattern?

**Files:**
- Create: `scripts/analysis/e_table_generation_deep.py`
- Output: `results/table_generation_deep.json`

### Step 1: Write Phase 3 experiment script

- [ ] Create `scripts/analysis/e_table_generation_deep.py`:

```python
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
        "test": "TG-5", "name": "Keystream → table derivation",
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
```

- [ ] Run: `PYTHONPATH=src python3 -u scripts/analysis/e_table_generation_deep.py`
- [ ] Expected: CHART may score perfect on AZ Beaufort (previously found). Report whether its null letter set connects to the palette.

### Step 2: Commit Phase 3

- [ ] `git add scripts/analysis/e_table_generation_deep.py`
- [ ] `git commit -m "feat: Phase 3 stego solve — table generation mechanism (OQ-1)"`

---

## Task 4: Phase 4 — Grid Key Generation / Backward Propagation (OQ-5)

**Question:** Can the 5-wide KA Polybius grid serve as the keystream source?

**Files:**
- Create: `scripts/analysis/e_grid_key_generation.py`
- Output: `results/grid_key_generation.json`

### Step 1: Write Phase 4 experiment script

- [ ] Create `scripts/analysis/e_grid_key_generation.py`:

```python
#!/usr/bin/env python3
"""
Phase 4: Grid Key Generation / Backward Propagation (OQ-5)

Tests whether the 5-wide KA Polybius grid generates the keystream.
If key values come from reading the grid in some order, the keystream
would naturally be biased toward palette columns (explaining C×S-1).

Tests:
  1. Grid reading orders as running key (L→R, T→B, column-major, etc.)
  2. f(row, col) mod 26 key functions on CT letter grid coordinates
  3. Mechanism family survival analysis

Output: results/grid_key_generation.json
"""
import sys, os, json
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_POSITIONS, CRIB_DICT, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, BEAUFORT_KEYSTREAM_AT_CRIBS, NULL_PALETTE,
)

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
GRID_WIDTH = 5
GRID_HEIGHT = 6  # ceil(26/5) = 6, last row has 1 letter (Z)

# Build 5-wide KA Polybius grid
KA_GRID = []
for row in range(GRID_HEIGHT):
    row_letters = []
    for col in range(GRID_WIDTH):
        idx = row * GRID_WIDTH + col
        if idx < 26:
            row_letters.append(KA[idx])
        else:
            row_letters.append(None)
    KA_GRID.append(row_letters)

# Letter -> (row, col) in the grid
KA_GRID_POS = {}
for row in range(GRID_HEIGHT):
    for col in range(GRID_WIDTH):
        idx = row * GRID_WIDTH + col
        if idx < 26:
            KA_GRID_POS[KA[idx]] = (row, col)

# Target keystream
KS_EXPECTED = [ALPH_IDX[c] for c in BEAUFORT_KEYSTREAM_AT_CRIBS]
CRIB_POS_SORTED = sorted(CRIB_POSITIONS)

results = {
    "experiment": "e_grid_key_generation",
    "date": datetime.now(timezone.utc).isoformat(),
}


# ── Test 1: Grid reading orders as running key ───────────────────────────
def test_grid_reading_orders():
    """Generate key sequences by reading the KA grid in various orders, apply as Beaufort running key."""
    # Generate reading orders
    orders = {}

    # Left-to-right, top-to-bottom (standard)
    orders["ltr_ttb"] = [KA[i] for i in range(26)]

    # Right-to-left, top-to-bottom
    orders["rtl_ttb"] = []
    for row in range(GRID_HEIGHT):
        for col in range(GRID_WIDTH - 1, -1, -1):
            idx = row * GRID_WIDTH + col
            if idx < 26:
                orders["rtl_ttb"].append(KA[idx])

    # Top-to-bottom, left-to-right (column-major)
    orders["col_major"] = []
    for col in range(GRID_WIDTH):
        for row in range(GRID_HEIGHT):
            idx = row * GRID_WIDTH + col
            if idx < 26:
                orders["col_major"].append(KA[idx])

    # Bottom-to-top, left-to-right
    orders["col_major_rev"] = []
    for col in range(GRID_WIDTH):
        for row in range(GRID_HEIGHT - 1, -1, -1):
            idx = row * GRID_WIDTH + col
            if idx < 26:
                orders["col_major_rev"].append(KA[idx])

    # Serpentine (row boustrophedon)
    orders["serpentine_row"] = []
    for row in range(GRID_HEIGHT):
        cols = range(GRID_WIDTH) if row % 2 == 0 else range(GRID_WIDTH - 1, -1, -1)
        for col in cols:
            idx = row * GRID_WIDTH + col
            if idx < 26:
                orders["serpentine_row"].append(KA[idx])

    # Diagonal (NW→SE)
    orders["diagonal_nw_se"] = []
    for d in range(GRID_HEIGHT + GRID_WIDTH - 1):
        for row in range(min(d, GRID_HEIGHT - 1), max(-1, d - GRID_WIDTH), -1):
            col = d - row
            if 0 <= col < GRID_WIDTH:
                idx = row * GRID_WIDTH + col
                if idx < 26:
                    orders["diagonal_nw_se"].append(KA[idx])

    # Spiral clockwise from top-left
    orders["spiral_cw"] = []
    visited = set()
    r, c, dr, dc = 0, 0, 0, 1
    for _ in range(26):
        idx = r * GRID_WIDTH + c
        if idx < 26:
            orders["spiral_cw"].append(KA[idx])
        visited.add((r, c))
        nr, nc = r + dr, c + dc
        if not (0 <= nr < GRID_HEIGHT and 0 <= nc < GRID_WIDTH and (nr, nc) not in visited):
            dr, dc = dc, -dr  # turn right
            nr, nc = r + dr, c + dc
        r, c = nr, nc

    # Reversed versions
    for name in list(orders.keys()):
        orders[name + "_rev"] = list(reversed(orders[name]))

    # Test each reading order at each offset as a Beaufort running key
    best_overall = {"order": None, "offset": -1, "score": 0}
    order_results = {}

    for order_name, key_seq in orders.items():
        if len(key_seq) < 26:
            continue  # skip incomplete orders
        best_for_order = {"offset": -1, "score": 0}

        for offset in range(len(key_seq)):
            # Generate running key for all 97 positions
            key_at = [(ALPH_IDX[key_seq[(offset + p) % len(key_seq)]]) for p in range(CT_LEN)]

            # Beaufort decrypt at crib positions and check
            score = 0
            for i, cp in enumerate(CRIB_POS_SORTED):
                ks_val = (ALPH_IDX[CT[cp]] + ALPH_IDX[CRIB_DICT[cp]]) % MOD  # Beaufort keystream
                if key_at[cp] == ks_val:
                    score += 1

            if score > best_for_order["score"]:
                best_for_order = {"offset": offset, "score": score}
            if score > best_overall["score"]:
                best_overall = {"order": order_name, "offset": offset, "score": score}

        order_results[order_name] = best_for_order

    return {
        "test": "grid_reading_orders",
        "orders_tested": len(orders),
        "offsets_per_order": 26,
        "total_configs": len(orders) * 26,
        "best_overall": {**best_overall, "score_str": f"{best_overall['score']}/24"},
        "top_orders": sorted(
            [{"order": k, **v} for k, v in order_results.items()],
            key=lambda x: -x["score"]
        )[:10],
        "verdict": "MATCH" if best_overall["score"] >= 20 else "NO_MATCH",
    }


# ── Test 2: f(row, col) mod 26 key functions ────────────────────────────
def test_grid_coordinate_functions():
    """Test key = f(grid_row, grid_col) of CT letter at each position."""
    # For each CT position, map CT letter to its (row, col) in the KA grid
    ct_grid_coords = []
    for p in range(CT_LEN):
        r, c = KA_GRID_POS[CT[p]]
        ct_grid_coords.append((r, c))

    best = {"a": 0, "b": 0, "c_val": 0, "score": 0}
    tested = 0

    # Test: key[p] = (a * row_of_CT[p] + b * col_of_CT[p] + c) mod 26
    for a in range(MOD):
        for b in range(MOD):
            for c_val in range(MOD):
                score = 0
                for i, cp in enumerate(CRIB_POS_SORTED):
                    r, c_coord = ct_grid_coords[cp]
                    predicted_key = (a * r + b * c_coord + c_val) % MOD
                    if predicted_key == KS_EXPECTED[i]:
                        score += 1
                tested += 1
                if score > best["score"]:
                    best = {"a": a, "b": b, "c_val": c_val, "score": score}

    # Also test: key[p] = Polybius_value (row*5 + col)
    polybius_score = 0
    for i, cp in enumerate(CRIB_POS_SORTED):
        r, c_coord = ct_grid_coords[cp]
        pv = (r * GRID_WIDTH + c_coord) % MOD
        if pv == KS_EXPECTED[i]:
            polybius_score += 1

    return {
        "test": "grid_coordinate_functions",
        "formula": "key = (a * row + b * col + c) mod 26",
        "configs_tested": tested,
        "best": {**best, "score_str": f"{best['score']}/24"},
        "polybius_value_score": f"{polybius_score}/24",
        "verdict": "MATCH" if best["score"] >= 20 else "NO_MATCH",
    }


# ── Test 3: Mechanism survival analysis ──────────────────────────────────
def test_mechanism_survival():
    """Which mechanism families can produce palette-biased keystream?"""
    palette_nums = {ALPH_IDX[c] for c in NULL_PALETTE}
    ks_palette_count = sum(1 for v in KS_EXPECTED if v in palette_nums)
    ap_set = {ALPH_IDX['G'], ALPH_IDX['K'], ALPH_IDX['O']}
    ks_ap_count = sum(1 for v in KS_EXPECTED if v in ap_set)

    families = {
        "periodic_polyalphabetic": {
            "can_produce_palette_bias": False,
            "reason": "Periodic keys produce uniform output; also eliminated by HC-4",
            "status": "ELIMINATED"
        },
        "pt_autokey": {
            "can_produce_palette_bias": False,
            "reason": "Structurally impossible (crib-to-crib proof)",
            "status": "ELIMINATED"
        },
        "ct_autokey": {
            "can_produce_palette_bias": False,
            "reason": "All configs produce 0/24",
            "status": "ELIMINATED"
        },
        "running_key_english": {
            "can_produce_palette_bias": False,
            "reason": "English+English cannot produce palette-biased sum; 60K texts tested",
            "status": "ELIMINATED"
        },
        "running_key_non_english": {
            "can_produce_palette_bias": True,
            "reason": "Non-English source could have any distribution",
            "status": "OPEN (untestable without source)"
        },
        "polybius_grid_lookup": {
            "can_produce_palette_bias": True,
            "reason": "Reading from 5-wide grid naturally biases toward certain columns",
            "status": "OPEN"
        },
        "otp_manual_key": {
            "can_produce_palette_bias": True,
            "reason": "Hand-selected from grid could naturally produce palette bias",
            "status": "OPEN (non-computational)"
        },
        "bespoke_grid_based": {
            "can_produce_palette_bias": True,
            "reason": "Any grid-reading process on 5-wide KA grid could produce palette bias",
            "status": "OPEN"
        },
    }

    return {
        "test": "mechanism_survival",
        "keystream_palette_count": f"{ks_palette_count}/24",
        "keystream_ap_count": f"{ks_ap_count}/24",
        "families": families,
        "surviving": [k for k, v in families.items() if v["status"].startswith("OPEN")],
        "eliminated": [k for k, v in families.items() if v["status"] == "ELIMINATED"],
    }


if __name__ == "__main__":
    print("=" * 72)
    print("Phase 4: Grid Key Generation / Backward Propagation (OQ-5)")
    print("=" * 72)

    print("\nKA Polybius Grid (5-wide):")
    for row in KA_GRID:
        print("  ", " ".join(c if c else '.' for c in row))

    for test_func in [test_grid_reading_orders, test_grid_coordinate_functions, test_mechanism_survival]:
        result = test_func()
        results[result["test"]] = result
        print(f"\n{'─' * 60}")
        print(f"  {result['test']}")
        print(f"    Verdict: {result.get('verdict', 'N/A')}")
        if "best_overall" in result:
            print(f"    Best: {result['best_overall']}")
        if "best" in result and isinstance(result["best"], dict):
            print(f"    Best: {result['best']}")
        if "surviving" in result:
            print(f"    Surviving families: {result['surviving']}")

    out_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'grid_key_generation.json')
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n  Results: {out_path}")
```

- [ ] Run: `PYTHONPATH=src python3 -u scripts/analysis/e_grid_key_generation.py`
- [ ] Expected: Grid reading orders likely score low (~4-6/24 = noise). The f(row,col) mod 26 sweep (17,576 triples) may find isolated high scores but is expected to be below 13/24 (the palette enrichment baseline). Mechanism survival analysis catalogs what's left.

**Note:** Test 2 (grid coordinate functions) sweeps 26^3 = 17,576 configs. At ~24 crib checks each, this is ~422K comparisons — runs in seconds.

### Step 2: Commit Phase 4

- [ ] `git add scripts/analysis/e_grid_key_generation.py`
- [ ] `git commit -m "feat: Phase 4 stego solve — grid key generation / backward propagation (OQ-5)"`

---

## Task 5: Run All Phases and Analyze Results

### Step 1: Run all 4 phases

- [ ] `PYTHONPATH=src pytest tests/test_stego_solve.py -v` (verify data integrity first)
- [ ] `PYTHONPATH=src python3 -u scripts/analysis/e_null_char_assignment.py`
- [ ] `PYTHONPATH=src python3 -u scripts/analysis/e_varying_null_resolution.py`
- [ ] `PYTHONPATH=src python3 -u scripts/analysis/e_table_generation_deep.py`
- [ ] `PYTHONPATH=src python3 -u scripts/analysis/e_grid_key_generation.py`

### Step 2: Analyze and report

- [ ] Review all 4 JSON result files in `results/`
- [ ] For any model scoring MATCH or SIGNIFICANT: validate with perturbation and convention robustness
- [ ] For any model scoring NO_MATCH: record as elimination in memory
- [ ] Update `memory/MEMORY.md` with findings
- [ ] Commit results: `git add results/*.json && git commit -m "results: stego layer solve phases 1-4"`

---

## Dependencies

- Task 1, 2, 3, 4 are fully independent and can run in parallel
- Task 5 depends on all of Tasks 1-4

## Estimated Time

| Task | Script | Compute | Total |
|------|--------|---------|-------|
| 1 | Phase 1: 7 models | < 2 min | ~5 min |
| 2 | Phase 2: C(13,7) masks | < 1 min | ~5 min |
| 3 | Phase 3: CHART + keystream | < 2 min | ~5 min |
| 4 | Phase 4: Grid reading + f(r,c) | < 5 min | ~10 min |
| 5 | Analysis | 0 | ~10 min |
| **Total** | | | **~35 min** |
