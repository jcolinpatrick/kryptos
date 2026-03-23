#!/usr/bin/env python3
"""
e_bifid_5x6_ka.py — Modified Bifid on 5×6 KA Polybius grid.

MOTIVATION: Three independent signals converge on a 5-wide KA Polybius grid:
  1. Null palette {B,G,I,K,O,W,Z} in columns 0,3 (p=6.3e-5)
  2. Bean's mod-5 keystream signal (p≈1/1470)
  3. Keystream palette enrichment 13/24 (p=0.0043)

Standard 5×5 Bifid was correctly dismissed (26 letters in K4 CT, needs 25).
But the 5×6 KA grid accommodates ALL 26 letters. This has NEVER been tested.

The 5×6 grid:
     0    1    2    3    4
  0: K    R    Y    P    T
  1: O    S    A    B    C
  2: D    E    F    G    H
  3: I    J    L    M    N
  4: Q    U    V    W    X
  5: Z

PHASES:
  Phase 1: Standard 5×6 KA Bifid, periods 2-97, encrypt+decrypt, CT97+CT73
  Phase 2: Conjugated Bifid (two 5×6 grids), selected keywords × periods
  Phase 3: 2D grid shift (Nihilist variant) with known key sources

ASYMMETRY HANDLING: In a 5×6 grid, rows ∈ {0..5}, cols ∈ {0..4}. After
Bifid fractionation, row values can land in column positions. Value 5
(from Z, row 5) is invalid as a column. We test multiple wrapping modes:
  - wrap5: 5 → 0 (mod 5)
  - clip5: 5 → 4 (clamp)
  - skip:  skip the block if 5 appears in a column slot

This wrapping bias toward column 0 could explain palette enrichment.
"""

import sys
import os
import json
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    CONSENSUS_NULL_POSITIONS, KRYPTOS_ALPHABET, ALPH, ALPH_IDX,
)
from kryptos.kernel.alphabet import keyword_mixed_alphabet


# ── Grid construction ──────────────────────────────────────────────────────

GRID_ROWS = 6
GRID_COLS = 5


def build_5x6_grid(alphabet: str) -> dict:
    """Build a 5×6 Polybius grid from a 26-letter alphabet.

    Returns dict with:
      - grid[row][col] -> letter
      - letter_to_rc[letter] -> (row, col)
    """
    grid = {}
    letter_to_rc = {}
    for i, ch in enumerate(alphabet):
        r, c = divmod(i, GRID_COLS)
        grid[(r, c)] = ch
        letter_to_rc[ch] = (r, c)
    return {"grid": grid, "letter_to_rc": letter_to_rc, "alphabet": alphabet}


def grid_lookup(g: dict, r: int, c: int) -> str:
    """Look up (row, col) on the grid, handling out-of-range and empty cells.

    The 5×6 grid has 30 cells but only 26 letters. Cells (5,1)-(5,4) are empty.
    For empty cells, convert to linear index and wrap mod 26.
    """
    r = r % GRID_ROWS
    c = c % GRID_COLS
    key = (r, c)
    if key in g["grid"]:
        return g["grid"][key]
    # Empty cell — wrap linearly
    linear = (r * GRID_COLS + c) % 26
    return g["alphabet"][linear]


# ── Bifid encrypt / decrypt ───────────────────────────────────────────────

def bifid_process(text: str, period: int, g: dict, decrypt: bool = False,
                  overflow_mode: str = "wrap5") -> str:
    """Apply Bifid encryption or decryption on 5×6 grid.

    For 5×6 asymmetry, when a row value (0-5) lands in a column slot:
      overflow_mode="wrap5":  val → val % 5  (biases toward col 0)
      overflow_mode="clip5":  val → min(val, 4)  (biases toward col 4)
      overflow_mode="skip":   return None for this block (error)
    """
    ltr = g["letter_to_rc"]
    result = []

    for start in range(0, len(text), period):
        block = text[start:start + period]
        p = len(block)

        # Convert block to coordinates
        rows = [ltr[ch][0] for ch in block]
        cols = [ltr[ch][1] for ch in block]

        if decrypt:
            # DECRYPTION: CT coords → intermediate → PT coords
            # CT[i] has row=R_i, col=C_i
            # Intermediate = R_0, C_0, R_1, C_1, ..., R_{p-1}, C_{p-1}
            intermediate = []
            for i in range(p):
                intermediate.append(rows[i])
                intermediate.append(cols[i])
            # First p values of intermediate = PT rows
            # Next p values = PT cols
            pt_rows = intermediate[:p]
            pt_cols = intermediate[p:]
        else:
            # ENCRYPTION: PT coords → intermediate → CT coords
            # Intermediate = row_0, row_1, ..., row_{p-1}, col_0, ..., col_{p-1}
            intermediate = rows + cols
            # Take consecutive pairs as (row, col) for CT
            pt_rows = [intermediate[2 * i] for i in range(p)]
            pt_cols = [intermediate[2 * i + 1] for i in range(p)]

        # Convert coordinates back to letters
        for i in range(p):
            r_val = pt_rows[i]
            c_val = pt_cols[i]

            # Handle 5×6 asymmetry
            if c_val >= GRID_COLS:
                if overflow_mode == "wrap5":
                    c_val = c_val % GRID_COLS
                elif overflow_mode == "clip5":
                    c_val = GRID_COLS - 1
                elif overflow_mode == "skip":
                    result.append("?")
                    continue
            if r_val >= GRID_ROWS:
                r_val = r_val % GRID_ROWS

            result.append(grid_lookup(g, r_val, c_val))

    return "".join(result)


def bifid_conjugated(text: str, period: int, g_in: dict, g_out: dict,
                     decrypt: bool = False, overflow_mode: str = "wrap5") -> str:
    """Conjugated Bifid: use g_in to get coordinates, g_out to look up result.

    In conjugated matrix Bifid, the 'reading' grid differs from the 'writing' grid.
    """
    ltr_in = g_in["letter_to_rc"]
    result = []

    for start in range(0, len(text), period):
        block = text[start:start + period]
        p = len(block)

        # Convert using input grid
        rows = [ltr_in[ch][0] for ch in block]
        cols = [ltr_in[ch][1] for ch in block]

        if decrypt:
            intermediate = []
            for i in range(p):
                intermediate.append(rows[i])
                intermediate.append(cols[i])
            out_rows = intermediate[:p]
            out_cols = intermediate[p:]
        else:
            intermediate = rows + cols
            out_rows = [intermediate[2 * i] for i in range(p)]
            out_cols = [intermediate[2 * i + 1] for i in range(p)]

        for i in range(p):
            r_val = out_rows[i]
            c_val = out_cols[i]
            if c_val >= GRID_COLS:
                if overflow_mode == "wrap5":
                    c_val = c_val % GRID_COLS
                elif overflow_mode == "clip5":
                    c_val = GRID_COLS - 1
                else:
                    result.append("?")
                    continue
            if r_val >= GRID_ROWS:
                r_val = r_val % GRID_ROWS
            result.append(grid_lookup(g_out, r_val, c_val))

    return "".join(result)


# ── 2D Grid Shift (Nihilist variant) ──────────────────────────────────────

def grid_shift_decrypt(ct: str, key: str, g: dict, variant: str = "beaufort") -> str:
    """2D grid shift: independent mod-6 row and mod-5 column operations.

    variant="beaufort":  PT_row = (Key_row - CT_row) % 6, PT_col = (Key_col - CT_col) % 5
    variant="vigenere":  PT_row = (CT_row - Key_row) % 6, PT_col = (CT_col - Key_col) % 5
    variant="nihilist":  PT_row = (CT_row + Key_row) % 6, PT_col = (CT_col + Key_col) % 5
    """
    ltr = g["letter_to_rc"]
    result = []
    for i, ch in enumerate(ct):
        k_ch = key[i % len(key)]
        ct_r, ct_c = ltr[ch]
        k_r, k_c = ltr[k_ch]
        if variant == "beaufort":
            pt_r = (k_r - ct_r) % GRID_ROWS
            pt_c = (k_c - ct_c) % GRID_COLS
        elif variant == "vigenere":
            pt_r = (ct_r - k_r) % GRID_ROWS
            pt_c = (ct_c - k_c) % GRID_COLS
        elif variant == "nihilist":
            pt_r = (ct_r + k_r) % GRID_ROWS
            pt_c = (ct_c + k_c) % GRID_COLS
        else:
            raise ValueError(f"Unknown variant: {variant}")
        result.append(grid_lookup(g, pt_r, pt_c))
    return "".join(result)


# ── Scoring ───────────────────────────────────────────────────────────────

def score_cribs(candidate: str, crib_dict: dict = None, offset: int = 0) -> int:
    """Count how many crib positions match."""
    if crib_dict is None:
        crib_dict = CRIB_DICT
    hits = 0
    for pos, expected_ch in crib_dict.items():
        adj_pos = pos - offset
        if 0 <= adj_pos < len(candidate) and candidate[adj_pos] == expected_ch:
            hits += 1
    return hits


def extract_null_removed(ct: str, null_positions: set) -> str:
    """Remove null positions from ciphertext."""
    return "".join(ch for i, ch in enumerate(ct) if i not in null_positions)


# ── Main experiment ───────────────────────────────────────────────────────

def run_phase1(results: dict):
    """Phase 1: Standard 5×6 KA Bifid, all periods."""
    print("\n" + "=" * 70)
    print("PHASE 1: Standard 5×6 KA Bifid")
    print("=" * 70)

    g_ka = build_5x6_grid(KRYPTOS_ALPHABET)

    # Extract CT73 using consensus nulls
    ct73 = extract_null_removed(CT, CONSENSUS_NULL_POSITIONS)
    # Build adjusted crib dict for CT73 (positions shift when nulls removed)
    null_sorted = sorted(CONSENSUS_NULL_POSITIONS)
    pos_map_73 = {}
    new_idx = 0
    for old_idx in range(CT_LEN):
        if old_idx not in CONSENSUS_NULL_POSITIONS:
            if old_idx in CRIB_DICT:
                pos_map_73[new_idx] = CRIB_DICT[old_idx]
            new_idx += 1
    ct73_crib_dict = pos_map_73

    targets = [
        ("CT97", CT, CRIB_DICT),
        ("CT73", ct73, ct73_crib_dict),
    ]

    best_overall = {"score": 0, "detail": "none"}
    phase1_results = []

    for target_name, target_ct, crib_d in targets:
        for direction in ["decrypt", "encrypt"]:
            for overflow in ["wrap5", "clip5"]:
                for period in range(2, len(target_ct) + 1):
                    try:
                        is_decrypt = (direction == "decrypt")
                        candidate = bifid_process(
                            target_ct, period, g_ka,
                            decrypt=is_decrypt,
                            overflow_mode=overflow,
                        )
                        score = score_cribs(candidate, crib_d)
                    except Exception:
                        score = 0
                        candidate = ""

                    if score > best_overall["score"]:
                        best_overall = {
                            "score": score,
                            "period": period,
                            "target": target_name,
                            "direction": direction,
                            "overflow": overflow,
                            "candidate_at_cribs": "".join(
                                candidate[p] if p < len(candidate) else "?"
                                for p in sorted(crib_d.keys())
                            ),
                        }

                    if score >= 4:  # Log anything non-trivial
                        phase1_results.append({
                            "score": score,
                            "period": period,
                            "target": target_name,
                            "direction": direction,
                            "overflow": overflow,
                        })

    total_configs = sum(
        2 * 2 * (len(t[1]) - 1) for t in targets
    )
    print(f"  Configs tested: {total_configs}")
    print(f"  Best score: {best_overall['score']}/24")
    print(f"  Best config: {best_overall}")
    print(f"  Scores >= 4: {len(phase1_results)}")

    results["phase1"] = {
        "total_configs": total_configs,
        "best": best_overall,
        "above_threshold": phase1_results,
    }


def run_phase2(results: dict):
    """Phase 2: Conjugated Bifid (two grids)."""
    print("\n" + "=" * 70)
    print("PHASE 2: Conjugated 5×6 Bifid")
    print("=" * 70)

    keywords = [
        "KRYPTOS", "SEVEN", "CHART", "ABSCISSA", "PALIMPSEST",
        "DEFECTOR", "KOMPASS", "BERLIN", "CLOCK", "TOWER", "LAYER",
        "ENIGMA", "CIPHER", "SECRET", "SHADOW",
    ]

    grids = {}
    for kw in keywords:
        alpha = keyword_mixed_alphabet(kw)
        grids[kw] = build_5x6_grid(alpha)

    g_ka = build_5x6_grid(KRYPTOS_ALPHABET)
    ct73 = extract_null_removed(CT, CONSENSUS_NULL_POSITIONS)

    # Build CT73 crib dict
    null_sorted = sorted(CONSENSUS_NULL_POSITIONS)
    pos_map_73 = {}
    new_idx = 0
    for old_idx in range(CT_LEN):
        if old_idx not in CONSENSUS_NULL_POSITIONS:
            if old_idx in CRIB_DICT:
                pos_map_73[new_idx] = CRIB_DICT[old_idx]
            new_idx += 1
    ct73_crib_dict = pos_map_73

    best_overall = {"score": 0, "detail": "none"}
    phase2_results = []
    configs_tested = 0

    targets = [("CT97", CT, CRIB_DICT), ("CT73", ct73, ct73_crib_dict)]

    for target_name, target_ct, crib_d in targets:
        for kw_in_name, g_in in [("KA", g_ka)] + list(grids.items()):
            for kw_out_name, g_out in [("KA", g_ka)] + list(grids.items()):
                if kw_in_name == kw_out_name:
                    continue  # Same grid = standard Bifid, covered in Phase 1
                for direction in ["decrypt", "encrypt"]:
                    for period in [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                                   14, 17, 21, 24, 31, 48, 49]:
                        if period >= len(target_ct):
                            continue
                        try:
                            candidate = bifid_conjugated(
                                target_ct, period, g_in, g_out,
                                decrypt=(direction == "decrypt"),
                            )
                            score = score_cribs(candidate, crib_d)
                        except Exception:
                            score = 0

                        configs_tested += 1

                        if score > best_overall["score"]:
                            best_overall = {
                                "score": score,
                                "period": period,
                                "grid_in": kw_in_name,
                                "grid_out": kw_out_name,
                                "target": target_name,
                                "direction": direction,
                            }

                        if score >= 4:
                            phase2_results.append({
                                "score": score,
                                "period": period,
                                "grid_in": kw_in_name,
                                "grid_out": kw_out_name,
                                "target": target_name,
                                "direction": direction,
                            })

    print(f"  Configs tested: {configs_tested}")
    print(f"  Best score: {best_overall['score']}/24")
    print(f"  Best config: {best_overall}")
    print(f"  Scores >= 4: {len(phase2_results)}")

    results["phase2"] = {
        "total_configs": configs_tested,
        "best": best_overall,
        "above_threshold": phase2_results,
    }


def run_phase3(results: dict):
    """Phase 3: 2D Grid Shift (Nihilist variant) with key sources."""
    print("\n" + "=" * 70)
    print("PHASE 3: 2D Grid Shift (Nihilist variant)")
    print("=" * 70)

    g_ka = build_5x6_grid(KRYPTOS_ALPHABET)

    # Known key sources — publicly available texts
    key_sources = {
        "KRYPTOS": "KRYPTOS",
        "SEVEN": "SEVEN",
        "CHART": "CHART",
        "PALIMPSEST": "PALIMPSEST",
        "ABSCISSA": "ABSCISSA",
        "KRYPTOSPALIMPSESTABSCISSA": "KRYPTOSPALIMPSESTABSCISSA",
        # K1 plaintext
        "K1_PT": "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUABOROFSIDYAHR"
                 "IQLUSION",
        # K2 plaintext
        "K2_PT": "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETIC"
                 "FIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWN"
                 "LOCATIONXDOESLANGABORLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOM"
                 "EWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYE"
                 "IGHTTDEGREESFIFORTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTY"
                 "SEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWET",
        # K3 plaintext
        "K3_PT": "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBERED"
                 "THELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINY"
                 "BREACHINTHEURPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLE"
                 "IINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRSCAPINGFROMTHECHAMBER"
                 "CAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHIN"
                 "EMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ",
        # The KA alphabet itself
        "KA": KRYPTOS_ALPHABET,
        # KRYPTOS reversed
        "KRYPTOS_REV": "KRYPTOS"[::-1],
        # BERLINCLOCK
        "BERLINCLOCK": "BERLINCLOCK",
        # EASTNORTHEAST
        "EASTNORTHEAST": "EASTNORTHEAST",
    }

    # Also build grids for selected keywords (for 2D shift on different alphabets)
    grid_variants = {
        "KA": g_ka,
        "AZ": build_5x6_grid(ALPH),
    }

    ct73 = extract_null_removed(CT, CONSENSUS_NULL_POSITIONS)
    null_sorted = sorted(CONSENSUS_NULL_POSITIONS)
    pos_map_73 = {}
    new_idx = 0
    for old_idx in range(CT_LEN):
        if old_idx not in CONSENSUS_NULL_POSITIONS:
            if old_idx in CRIB_DICT:
                pos_map_73[new_idx] = CRIB_DICT[old_idx]
            new_idx += 1
    ct73_crib_dict = pos_map_73

    best_overall = {"score": 0, "detail": "none"}
    phase3_results = []
    configs_tested = 0

    targets = [("CT97", CT, CRIB_DICT), ("CT73", ct73, ct73_crib_dict)]

    for target_name, target_ct, crib_d in targets:
        for grid_name, g in grid_variants.items():
            for key_name, key_text in key_sources.items():
                key_clean = "".join(ch for ch in key_text.upper() if ch.isalpha())
                if len(key_clean) == 0:
                    continue
                for variant in ["beaufort", "vigenere", "nihilist"]:
                    try:
                        candidate = grid_shift_decrypt(
                            target_ct, key_clean, g, variant=variant,
                        )
                        score = score_cribs(candidate, crib_d)
                    except Exception:
                        score = 0

                    configs_tested += 1

                    if score > best_overall["score"]:
                        best_overall = {
                            "score": score,
                            "key_source": key_name,
                            "grid": grid_name,
                            "variant": variant,
                            "target": target_name,
                        }

                    if score >= 4:
                        phase3_results.append({
                            "score": score,
                            "key_source": key_name,
                            "grid": grid_name,
                            "variant": variant,
                            "target": target_name,
                        })

    print(f"  Configs tested: {configs_tested}")
    print(f"  Best score: {best_overall['score']}/24")
    print(f"  Best config: {best_overall}")
    print(f"  Scores >= 4: {len(phase3_results)}")

    results["phase3"] = {
        "total_configs": configs_tested,
        "best": best_overall,
        "above_threshold": phase3_results,
    }


def main():
    print("=" * 70)
    print("EXPERIMENT: Modified Bifid on 5×6 KA Polybius Grid")
    print("=" * 70)
    print(f"CT97: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Grid: 5×6 KA ({KRYPTOS_ALPHABET})")
    print(f"Consensus nulls: {sorted(CONSENSUS_NULL_POSITIONS)}")
    print(f"Crib positions: {sorted(CRIB_POSITIONS)}")

    # Verify grid
    g = build_5x6_grid(KRYPTOS_ALPHABET)
    print("\n5×6 KA Grid:")
    for r in range(GRID_ROWS):
        row_str = "  " + "  ".join(
            g["grid"].get((r, c), ".") for c in range(GRID_COLS)
        )
        print(f"  Row {r}: {row_str}")

    # Quick sanity check: Bifid period=2 roundtrip
    test_text = "KRYPTOS"
    enc = bifid_process(test_text, 2, g, decrypt=False)
    dec = bifid_process(enc, 2, g, decrypt=True)
    assert dec == test_text, f"Roundtrip failed: {test_text} → {enc} → {dec}"
    print(f"\n  Roundtrip check: {test_text} → {enc} → {dec} ✓")

    # Second roundtrip at period 5
    enc5 = bifid_process(test_text, 5, g, decrypt=False)
    dec5 = bifid_process(enc5, 5, g, decrypt=True)
    assert dec5 == test_text, f"Roundtrip p=5 failed: {test_text} → {enc5} → {dec5}"
    print(f"  Roundtrip p=5:   {test_text} → {enc5} → {dec5} ✓")

    results = {"experiment": "e_bifid_5x6_ka", "timestamp": time.strftime("%Y%m%d_%H%M%S")}

    t0 = time.time()
    run_phase1(results)
    run_phase2(results)
    run_phase3(results)
    elapsed = time.time() - t0

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    overall_best = 0
    for phase_key in ["phase1", "phase2", "phase3"]:
        phase = results[phase_key]
        best = phase["best"]["score"] if isinstance(phase["best"].get("score"), int) else 0
        overall_best = max(overall_best, best)
        print(f"  {phase_key}: {phase['total_configs']} configs, best {best}/24")

    results["overall_best"] = overall_best
    results["elapsed_seconds"] = round(elapsed, 1)
    results["verdict"] = (
        "BREAKTHROUGH" if overall_best >= 24 else
        "SIGNAL" if overall_best >= 18 else
        "INTERESTING" if overall_best >= 10 else
        "NOISE"
    )

    print(f"\n  Overall best: {overall_best}/24 → {results['verdict']}")
    print(f"  Elapsed: {elapsed:.1f}s")

    # Write results
    out_path = os.path.join(_ROOT, "results", "e_bifid_5x6_ka.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Results written to: {out_path}")


if __name__ == "__main__":
    main()
