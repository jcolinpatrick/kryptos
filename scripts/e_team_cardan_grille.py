#!/usr/bin/env python3
"""E-TEAM-CARDAN-GRILLE: Aperture mask / Cardan grille experiments on K4 CT.

Tests systematic aperture patterns (checkerboard, diagonal, row/column selection),
random aperture sampling with statistical baseline, and full Kryptos panel grilles.

Uses score_candidate_free() for variable-length extractions.
"""
import sys, os, json, math, random
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
)
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free
from kryptos.kernel.scoring.free_crib import score_free_fast


def score_extraction(text, label):
    """Score extracted text and return result dict."""
    result = {"label": label, "text": text, "length": len(text)}
    if len(text) < 5:
        result["scorer"] = "too_short"
        result["crib_score"] = 0
        return result
    if len(text) == CT_LEN:
        sc = score_candidate(text)
        result["scorer"] = "anchored"
        result["crib_score"] = sc.crib_score
        result["ic"] = round(sc.ic_value, 4)
        result["classification"] = sc.crib_classification
    else:
        sc = score_candidate_free(text)
        result["scorer"] = "free"
        result["crib_score"] = sc.crib_score
        result["ene_found"] = sc.ene_found
        result["bc_found"] = sc.bc_found
        result["ic"] = round(sc.ic_value, 4)
        result["classification"] = sc.crib_classification
    return result


def load_full_kryptos():
    """Try to load full Kryptos CT (K1-K4, 865 chars) from data/ct.txt."""
    ct_path = os.path.join(os.path.dirname(__file__), "..", "data", "ct.txt")
    try:
        with open(ct_path) as f:
            text = f.read().strip().upper()
        text = "".join(c for c in text if c.isalpha())
        if len(text) >= 865:
            return text[:865]
        elif len(text) >= 97:
            return text
    except FileNotFoundError:
        pass
    return None


def main():
    random.seed(42)
    all_results = {}
    best_overall = {"label": "none", "crib_score": 0}

    def track(category, result):
        if category not in all_results:
            all_results[category] = []
        all_results[category].append(result)
        if result.get("crib_score", 0) > best_overall.get("crib_score", 0):
            best_overall.update(result)

    print("=" * 70)
    print("E-TEAM-CARDAN-GRILLE: Aperture mask experiments")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"CT_LEN: {CT_LEN}")
    print()

    # ── 1. Structured grid apertures (widths 7-13) ────────────────────────
    print("--- 1. Structured grid apertures ---")

    for width in range(7, 14):
        nrows = math.ceil(CT_LEN / width)
        padded = CT + "X" * (nrows * width - CT_LEN)

        # a) Checkerboard: (row+col) % 2 == 0
        checker_pos = []
        checker_pos_inv = []
        for row in range(nrows):
            for col in range(width):
                idx = row * width + col
                if idx >= CT_LEN:
                    continue
                if (row + col) % 2 == 0:
                    checker_pos.append(idx)
                else:
                    checker_pos_inv.append(idx)

        for positions, suffix in [(checker_pos, "even"), (checker_pos_inv, "odd")]:
            text = "".join(CT[p] for p in positions)
            r = score_extraction(text, f"checker_w{width}_{suffix}")
            track("checkerboard", r)

        # b) Diagonal: row == col (and anti-diagonal)
        diag_pos = []
        anti_diag_pos = []
        for row in range(nrows):
            for col in range(width):
                idx = row * width + col
                if idx >= CT_LEN:
                    continue
                if row == col:
                    diag_pos.append(idx)
                if row + col == width - 1:
                    anti_diag_pos.append(idx)

        for positions, suffix in [(diag_pos, "diag"), (anti_diag_pos, "anti_diag")]:
            if len(positions) >= 3:
                text = "".join(CT[p] for p in positions)
                r = score_extraction(text, f"diag_w{width}_{suffix}")
                track("diagonal", r)

        # c) Every-Nth-row
        for row_stride in range(2, nrows):
            for row_start in range(row_stride):
                positions = []
                for row in range(row_start, nrows, row_stride):
                    for col in range(width):
                        idx = row * width + col
                        if idx < CT_LEN:
                            positions.append(idx)
                if len(positions) >= 5:
                    text = "".join(CT[p] for p in positions)
                    r = score_extraction(text, f"row_stride{row_stride}_start{row_start}_w{width}")
                    track("row_stride", r)

        # d) Every-Nth-column
        for col_stride in range(2, width):
            for col_start in range(col_stride):
                positions = []
                for row in range(nrows):
                    for col in range(col_start, width, col_stride):
                        idx = row * width + col
                        if idx < CT_LEN:
                            positions.append(idx)
                if len(positions) >= 5:
                    text = "".join(CT[p] for p in positions)
                    r = score_extraction(text, f"col_stride{col_stride}_start{col_start}_w{width}")
                    track("col_stride", r)

        # e) Single column extraction
        for col in range(width):
            positions = []
            for row in range(nrows):
                idx = row * width + col
                if idx < CT_LEN:
                    positions.append(idx)
            if len(positions) >= 3:
                text = "".join(CT[p] for p in positions)
                r = score_extraction(text, f"single_col{col}_w{width}")
                track("single_col", r)

    for cat in ["checkerboard", "diagonal", "row_stride", "col_stride", "single_col"]:
        if cat in all_results:
            cat_best = max(all_results[cat], key=lambda x: x.get("crib_score", 0))
            print(f"  {cat:20s}: best={cat_best.get('crib_score', 0):3d} ({cat_best.get('label', 'none')}), configs={len(all_results[cat])}")
    print()

    # ── 2. Turning grille patterns ────────────────────────────────────────
    print("--- 2. Turning grille (quarter-turn) patterns ---")
    # For grids that are square-ish, try 90-degree rotation masks
    for side in [8, 10]:
        if side * side < CT_LEN:
            continue
        padded = CT + "X" * (side * side - CT_LEN)

        # Quarter mask: top-left quadrant positions, rotated 4 times
        half = side // 2
        quarter_positions = []
        for rot in range(4):
            for row in range(half):
                for col in range(half):
                    if rot == 0:
                        r, c = row, col
                    elif rot == 1:
                        r, c = col, side - 1 - row
                    elif rot == 2:
                        r, c = side - 1 - row, side - 1 - col
                    else:
                        r, c = side - 1 - col, row
                    idx = r * side + c
                    if idx < CT_LEN and idx not in quarter_positions:
                        quarter_positions.append(idx)

        if quarter_positions:
            text = "".join(CT[p] for p in quarter_positions if p < CT_LEN)
            r = score_extraction(text, f"turning_grille_{side}x{side}")
            track("turning_grille", r)

    tg_best = max(all_results.get("turning_grille", [{"crib_score": 0}]), key=lambda x: x.get("crib_score", 0))
    print(f"  Turning grille best: score={tg_best.get('crib_score', 0)}")
    print()

    # ── 3. Random aperture sampling (statistical baseline) ───────────────
    print("--- 3. Random aperture sampling (statistical baseline) ---")
    NUM_SAMPLES = 10000

    for k in [30, 40, 50, 60, 70]:
        scores = []
        best_sample = {"crib_score": 0}

        for trial in range(NUM_SAMPLES):
            positions = sorted(random.sample(range(CT_LEN), k))
            text = "".join(CT[p] for p in positions)
            # Use fast scorer for speed
            sc = score_free_fast(text)
            scores.append(sc)
            if sc > best_sample.get("crib_score", 0):
                best_sample = {"crib_score": sc, "positions": positions, "text": text}

        avg_score = sum(scores) / len(scores)
        max_score = max(scores)
        above_11 = sum(1 for s in scores if s >= 11)
        above_13 = sum(1 for s in scores if s >= 13)

        result = {
            "label": f"random_k{k}",
            "k": k,
            "num_samples": NUM_SAMPLES,
            "avg_score": round(avg_score, 4),
            "max_score": max_score,
            "above_11": above_11,
            "above_13": above_13,
            "best_text": best_sample.get("text", "")[:60],
            "crib_score": max_score,
        }
        track("random_sampling", result)

        print(f"  k={k}: avg={avg_score:.4f}, max={max_score}, "
              f"above_11={above_11}/{NUM_SAMPLES}, above_13={above_13}/{NUM_SAMPLES}")

    print()

    # ── 4. Thematic aperture patterns ────────────────────────────────────
    print("--- 4. Thematic aperture patterns ---")

    # a) Prime-indexed positions
    def is_prime(n):
        if n < 2:
            return False
        for i in range(2, int(n**0.5) + 1):
            if n % i == 0:
                return False
        return True

    prime_pos = [i for i in range(CT_LEN) if is_prime(i)]
    if prime_pos:
        text = "".join(CT[p] for p in prime_pos)
        r = score_extraction(text, "prime_positions")
        track("thematic", r)

    non_prime_pos = [i for i in range(CT_LEN) if not is_prime(i)]
    text = "".join(CT[p] for p in non_prime_pos)
    r = score_extraction(text, "non_prime_positions")
    track("thematic", r)

    # b) Fibonacci-indexed positions
    fib_pos = []
    a, b = 0, 1
    while a < CT_LEN:
        fib_pos.append(a)
        a, b = b, a + b
    text = "".join(CT[p] for p in fib_pos)
    r = score_extraction(text, "fibonacci_positions")
    track("thematic", r)

    # c) Powers of 2
    pow2_pos = [2**i for i in range(7) if 2**i < CT_LEN]  # 1,2,4,8,16,32,64
    pow2_pos = [0] + pow2_pos
    pow2_pos = sorted(set(p for p in pow2_pos if p < CT_LEN))
    text = "".join(CT[p] for p in pow2_pos)
    r = score_extraction(text, "power_of_2_positions")
    track("thematic", r)

    # d) Triangular numbers
    tri_pos = []
    n = 0
    while n * (n + 1) // 2 < CT_LEN:
        tri_pos.append(n * (n + 1) // 2)
        n += 1
    text = "".join(CT[p] for p in tri_pos)
    r = score_extraction(text, "triangular_positions")
    track("thematic", r)

    # e) Kryptos alphabet position: K=0, R=1, Y=2, P=3, T=4, O=5, S=6, ...
    ka = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
    ka_idx = {c: i for i, c in enumerate(ka)}
    ka_vals = [ka_idx[c] for c in CT]
    # Select positions where KA value < 13 (first half of KA alphabet)
    ka_low = [i for i, v in enumerate(ka_vals) if v < 13]
    ka_high = [i for i, v in enumerate(ka_vals) if v >= 13]
    for positions, suffix in [(ka_low, "KA_low"), (ka_high, "KA_high")]:
        if len(positions) >= 5:
            text = "".join(CT[p] for p in positions)
            r = score_extraction(text, f"thematic_{suffix}")
            track("thematic", r)

    # f) Binary representation of position: select where bit 0/1/2/3 is set
    for bit in range(7):
        bit_set = [i for i in range(CT_LEN) if (i >> bit) & 1]
        bit_clear = [i for i in range(CT_LEN) if not ((i >> bit) & 1)]
        for positions, suffix in [(bit_set, f"bit{bit}_set"), (bit_clear, f"bit{bit}_clear")]:
            if len(positions) >= 5:
                text = "".join(CT[p] for p in positions)
                r = score_extraction(text, f"thematic_{suffix}")
                track("thematic", r)

    thematic_best = max(all_results.get("thematic", [{"crib_score": 0}]), key=lambda x: x.get("crib_score", 0))
    print(f"  Thematic best: score={thematic_best.get('crib_score', 0)} ({thematic_best.get('label', 'none')})")
    print()

    # ── 5. Full Kryptos panel grille (if available) ──────────────────────
    print("--- 5. Full Kryptos panel grille ---")
    full_ct = load_full_kryptos()
    if full_ct and len(full_ct) >= 865:
        print(f"  Full Kryptos CT loaded: {len(full_ct)} chars")

        # Apply grid reads to full panel
        for width in [29, 30, 31, 32, 33, 86, 87]:
            nrows = math.ceil(len(full_ct) / width)
            padded = full_ct + "X" * (nrows * width - len(full_ct))

            # Column read
            col_read = ""
            for col in range(width):
                for row in range(nrows):
                    idx = row * width + col
                    if idx < len(full_ct):
                        col_read += full_ct[idx]
            r = score_extraction(col_read, f"full_panel_col_w{width}")
            track("full_panel", r)

            # Checkerboard on full panel
            checker = []
            for row in range(nrows):
                for col in range(width):
                    idx = row * width + col
                    if idx < len(full_ct) and (row + col) % 2 == 0:
                        checker.append(full_ct[idx])
            checker_text = "".join(checker)
            r = score_extraction(checker_text, f"full_panel_checker_w{width}")
            track("full_panel", r)

        fp_best = max(all_results.get("full_panel", [{"crib_score": 0}]), key=lambda x: x.get("crib_score", 0))
        print(f"  Full panel best: score={fp_best.get('crib_score', 0)} ({fp_best.get('label', 'none')})")
    else:
        print(f"  Full Kryptos CT: {'loaded ' + str(len(full_ct)) + ' chars (K4 only)' if full_ct else 'not available'}")
        if full_ct and len(full_ct) == 97:
            print("  (Skipping full panel grilles — only K4 CT available)")
    print()

    # ── 6. Double extraction: apply two masks sequentially ───────────────
    print("--- 6. Double extraction (two masks) ---")
    # Grid column read then every-other-char
    for width in [7, 8, 9, 10, 11]:
        nrows = math.ceil(CT_LEN / width)
        padded = CT + "X" * (nrows * width - CT_LEN)
        col_read = ""
        for col in range(width):
            for row in range(nrows):
                idx = row * width + col
                if idx < CT_LEN:
                    col_read += CT[idx]
        # Now apply even/odd split on the column-read result
        evens = "".join(col_read[i] for i in range(0, len(col_read), 2))
        odds = "".join(col_read[i] for i in range(1, len(col_read), 2))
        for text, suffix in [(evens, "evens"), (odds, "odds")]:
            r = score_extraction(text, f"double_colread_w{width}_{suffix}")
            track("double_extraction", r)

    double_best = max(all_results.get("double_extraction", [{"crib_score": 0}]), key=lambda x: x.get("crib_score", 0))
    print(f"  Double extraction best: score={double_best.get('crib_score', 0)} ({double_best.get('label', 'none')})")
    print()

    # ── Summary ──────────────────────────────────────────────────────────
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)

    total_configs = sum(len(v) for v in all_results.values())
    print(f"Total configurations tested: {total_configs}")
    print()

    for cat, results in sorted(all_results.items()):
        if not results:
            continue
        cat_best = max(results, key=lambda x: x.get("crib_score", 0))
        print(f"  {cat:25s}: best={cat_best.get('crib_score', 0):3d}  configs={len(results):6d}  ({cat_best.get('label', 'none')})")

    print()
    print(f"OVERALL BEST: score={best_overall.get('crib_score', 0)}")
    print(f"  Label: {best_overall.get('label', 'none')}")
    if best_overall.get("text"):
        print(f"  Text: {str(best_overall.get('text', ''))[:60]}...")
    print()

    signal_found = best_overall.get("crib_score", 0) >= 18
    if signal_found:
        print("*** SIGNAL DETECTED ***")
    else:
        print("VERDICT: ALL NOISE — no Cardan grille pattern produces meaningful crib alignment")

    # ── Save results ─────────────────────────────────────────────────────
    output = {
        "experiment_id": "e_team_cardan_grille",
        "description": "Aperture mask / Cardan grille experiments on K4 CT",
        "total_configs": total_configs,
        "best_overall": {
            "label": best_overall.get("label", "none"),
            "crib_score": best_overall.get("crib_score", 0),
        },
        "category_bests": {},
        "random_baseline": {},
        "verdict": "NOISE" if not signal_found else "SIGNAL",
    }

    for cat, results in sorted(all_results.items()):
        if not results:
            continue
        cat_best = max(results, key=lambda x: x.get("crib_score", 0))
        output["category_bests"][cat] = {
            "best_score": cat_best.get("crib_score", 0),
            "best_label": cat_best.get("label", "none"),
            "num_configs": len(results),
        }

    # Extract random sampling stats
    for r in all_results.get("random_sampling", []):
        output["random_baseline"][r["label"]] = {
            "k": r.get("k"),
            "avg_score": r.get("avg_score"),
            "max_score": r.get("max_score"),
            "above_11": r.get("above_11"),
            "above_13": r.get("above_13"),
            "num_samples": r.get("num_samples"),
        }

    results_path = os.path.join(os.path.dirname(__file__), "..", "results", "e_team_cardan_grille.json")
    os.makedirs(os.path.dirname(results_path), exist_ok=True)
    with open(results_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to: {results_path}")


if __name__ == "__main__":
    main()
