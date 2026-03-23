#!/usr/bin/env python3
"""
Phase B4: Mixed Cells and Varying Null Resolution

B4.1: Formalize the "first occurrence = null" tiebreaker for 3 mixed cells.
B4.2: False-positive model — which non-palette positions fall in null cells?
B4.3: Position-only rule produces ~39 nulls; identify secondary filter.
B4.4: Validate predicted varying nulls against Bean constraints.

Output: results/stego_mechanism/mixed_cell_varying.json
"""
import sys, os, json
from collections import defaultdict
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    CRIB_POSITIONS, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    BEAN_EQ, BEAN_INEQ,
)

KA = KRYPTOS_ALPHABET

# ── Build table structures ──────────────────────────────────────────
PALETTE_POSITIONS = sorted(p for p in range(CT_LEN) if CT[p] in NULL_PALETTE)
ALL_POSITIONS = list(range(CT_LEN))

cell_data = defaultdict(list)
for p in PALETTE_POSITIONS:
    cell_data[(p % 7, p % 5)].append((p, p in CONSENSUS_NULL_POSITIONS))

# Full table classification
table = {}
for r in range(7):
    for c in range(5):
        entries = cell_data.get((r, c), [])
        if not entries:
            table[(r, c)] = {"type": "empty", "positions": []}
        else:
            nulls = [e for e in entries if e[1]]
            reals = [e for e in entries if not e[1]]
            if nulls and not reals:
                table[(r, c)] = {"type": "null", "positions": entries}
            elif reals and not nulls:
                table[(r, c)] = {"type": "real", "positions": entries}
            else:
                table[(r, c)] = {"type": "mixed", "positions": entries}

# Identify null cells (pure null + mixed)
null_cells = {rc for rc, v in table.items() if v["type"] in ("null", "mixed")}


def run_b4():
    results = {
        "experiment": "e_mixed_cell_varying",
        "date": datetime.now(timezone.utc).isoformat(),
    }

    print("=" * 80)
    print("PHASE B4: MIXED CELLS AND VARYING NULLS")
    print("=" * 80)

    # ── B4.1: Tiebreaker formalization ──────────────────────────────
    print("\n── B4.1: Mixed Cell Tiebreaker ──")
    mixed_cells = {rc: v for rc, v in table.items() if v["type"] == "mixed"}
    b4_1 = {"mixed_cells": {}}

    for rc, data in sorted(mixed_cells.items()):
        positions = data["positions"]
        null_pos = [p for p, is_null in positions if is_null]
        real_pos = [p for p, is_null in positions if not is_null]
        first_is_null = min(null_pos) < min(real_pos)

        cell_info = {
            "cell": list(rc),
            "null_positions": null_pos,
            "real_positions": real_pos,
            "null_chars": [CT[p] for p in null_pos],
            "real_chars": [CT[p] for p in real_pos],
            "first_is_null": first_is_null,
        }
        b4_1["mixed_cells"][str(rc)] = cell_info

        print(f"  Cell {rc}: null@{null_pos}({[CT[p] for p in null_pos]}) "
              f"vs real@{real_pos}({[CT[p] for p in real_pos]}) "
              f"→ first_is_null={first_is_null}")

    all_first_null = all(v["first_is_null"] for v in b4_1["mixed_cells"].values())
    b4_1["tiebreaker_rule"] = "first_occurrence_is_null" if all_first_null else "INCONSISTENT"
    results["B4_1_tiebreaker"] = b4_1
    print(f"  → Rule: {b4_1['tiebreaker_rule']}")

    # Test alternative: if BOTH positions in mixed cells are null
    both_null_count = 17 + sum(len(v["real_positions"]) for v in b4_1["mixed_cells"].values())
    print(f"  If both-null in mixed cells: {both_null_count} consensus nulls "
          f"(need {24 - both_null_count} varying)")

    # ── B4.2: False-positive model ──────────────────────────────────
    print("\n── B4.2: False-Positive Model ──")

    # Find ALL positions (palette and non-palette) in null cells
    positions_in_null_cells = []
    for p in range(CT_LEN):
        cell = (p % 7, p % 5)
        if cell in null_cells:
            positions_in_null_cells.append(p)

    # Split by palette membership
    palette_in_null = [p for p in positions_in_null_cells if CT[p] in NULL_PALETTE]
    non_palette_in_null = [p for p in positions_in_null_cells if CT[p] not in NULL_PALETTE]

    b4_2 = {
        "total_positions_in_null_cells": len(positions_in_null_cells),
        "palette_in_null_cells": len(palette_in_null),
        "non_palette_in_null_cells": len(non_palette_in_null),
        "non_palette_positions": non_palette_in_null,
        "non_palette_chars": [CT[p] for p in non_palette_in_null],
    }

    print(f"  Positions in null cells: {len(positions_in_null_cells)}")
    print(f"  Palette positions in null cells: {len(palette_in_null)} "
          f"(these include the 17 consensus nulls)")
    print(f"  Non-palette positions in null cells: {len(non_palette_in_null)}")
    print(f"    Positions: {non_palette_in_null}")
    print(f"    Characters: {[CT[p] for p in non_palette_in_null]}")

    # Which of these are in crib ranges?
    in_crib = [p for p in non_palette_in_null if p in CRIB_POSITIONS]
    not_in_crib = [p for p in non_palette_in_null if p not in CRIB_POSITIONS]

    b4_2["in_crib_ranges"] = in_crib
    b4_2["outside_crib_ranges"] = not_in_crib
    print(f"  In crib ranges: {in_crib} (cannot be nulls)")
    print(f"  Outside crib ranges: {not_in_crib} (varying null candidates)")

    # Compare to prior VP-1 candidates
    prior_vp1_candidates = {39, 40, 43, 55, 87, 94}
    overlap = set(not_in_crib) & prior_vp1_candidates
    b4_2["vp1_overlap"] = sorted(overlap)
    b4_2["vp1_overlap_fraction"] = f"{len(overlap)}/{len(prior_vp1_candidates)}"
    print(f"  VP-1 overlap: {sorted(overlap)} ({len(overlap)}/{len(prior_vp1_candidates)})")

    results["B4_2_false_positive"] = b4_2

    # ── B4.3: Secondary filter ──────────────────────────────────────
    print("\n── B4.3: Secondary Filter Candidates ──")

    # We need exactly 7 varying nulls from the non-crib, non-palette null-cell positions
    candidates = not_in_crib
    need = 7
    b4_3 = {
        "candidate_count": len(candidates),
        "need": need,
        "candidates": candidates,
    }

    if len(candidates) == need:
        print(f"  EXACTLY {need} candidates — no secondary filter needed!")
        b4_3["filter_needed"] = False
        b4_3["predicted_varying_nulls"] = candidates
    elif len(candidates) > need:
        print(f"  {len(candidates)} candidates for {need} slots — secondary filter needed")
        b4_3["filter_needed"] = True
        # Test: first N by position order
        first_n = sorted(candidates)[:need]
        b4_3["first_n_by_position"] = first_n
        print(f"    First {need} by position: {first_n}")

        # Test: character-based grouping
        char_groups = defaultdict(list)
        for p in candidates:
            char_groups[CT[p]].append(p)
        b4_3["char_groups"] = {k: v for k, v in sorted(char_groups.items())}
        print(f"    Character groups: {dict(char_groups)}")
    else:
        print(f"  Only {len(candidates)} candidates for {need} slots — model incomplete")
        b4_3["filter_needed"] = True
        b4_3["deficit"] = need - len(candidates)

    results["B4_3_secondary_filter"] = b4_3

    # ── B4.4: Validation ────────────────────────────────────────────
    print("\n── B4.4: Validation ──")

    # If we have a predicted mask, validate it
    predicted_nulls = set(CONSENSUS_NULL_POSITIONS)
    if not b4_3.get("filter_needed", True) and "predicted_varying_nulls" in b4_3:
        predicted_nulls |= set(b4_3["predicted_varying_nulls"])
    elif "first_n_by_position" in b4_3:
        predicted_nulls |= set(b4_3["first_n_by_position"])

    b4_4 = {"predicted_null_count": len(predicted_nulls)}

    if len(predicted_nulls) == 24:
        predicted_real = sorted(set(range(CT_LEN)) - predicted_nulls)
        real_text = "".join(CT[p] for p in predicted_real)
        b4_4["real_positions"] = predicted_real
        b4_4["real_text_length"] = len(real_text)

        # Bean EQ check
        eq_pos_a, eq_pos_b = BEAN_EQ[0]
        if eq_pos_a in predicted_nulls or eq_pos_b in predicted_nulls:
            b4_4["bean_eq"] = "N/A (one of EQ positions is null)"
        else:
            # Both are real — check if they're at the same keystream index
            b4_4["bean_eq"] = "POSITIONS_REAL"

        # Check crib coverage
        crib_in_real = sum(1 for p in CRIB_POSITIONS if p not in predicted_nulls)
        b4_4["crib_coverage"] = f"{crib_in_real}/{len(CRIB_POSITIONS)}"

        print(f"  Predicted mask: {len(predicted_nulls)} nulls")
        print(f"  Real text length: {len(real_text)}")
        print(f"  Crib coverage: {b4_4['crib_coverage']}")
    else:
        print(f"  Predicted mask has {len(predicted_nulls)} nulls (target: 24)")

    results["B4_4_validation"] = b4_4

    # ── Verdict ─────────────────────────────────────────────────────
    print(f"\n{'=' * 80}")
    if not b4_3.get("filter_needed", True):
        results["verdict"] = "COMPLETE_MASK_PREDICTED"
        print("VERDICT: COMPLETE — mechanism predicts all 24 null positions")
    elif len(candidates) >= need:
        results["verdict"] = "PARTIAL_NEEDS_FILTER"
        print(f"VERDICT: PARTIAL — {len(candidates)} candidates for {need} slots, "
              f"secondary filter needed")
    else:
        results["verdict"] = "INCOMPLETE"
        print(f"VERDICT: INCOMPLETE — only {len(candidates)} candidates for {need} slots")
    print(f"{'=' * 80}")

    out_path = os.path.join(_ROOT, "results", "stego_mechanism", "mixed_cell_varying.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults written to {out_path}")

    return results


if __name__ == "__main__":
    run_b4()
