#!/usr/bin/env python3
"""E-TEAM-ANOMALY-EXTRACTION: Physically-motivated extraction masks on K4 CT.

Tests anomaly-derived reading patterns: YAR strides, DESPARATLY multiples,
self-encrypting anchors, ID BY ROWS grid reads, LAYER TWO even/odd splits,
letter masks, reversals/rotations, and HILL 2x2 matrix decryption.

Uses score_candidate() for 97-char results, score_candidate_free() for
variable-length extractions.
"""
import sys, os, json, itertools, math
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, N_CRIBS,
    CRIB_DICT, CRIB_POSITIONS,
)
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free


def score_text(text, label):
    """Score a text and return a result dict. Uses free scorer for non-97-char."""
    result = {"label": label, "text": text, "length": len(text)}
    if len(text) == CT_LEN:
        sc = score_candidate(text)
        result["scorer"] = "anchored"
        result["crib_score"] = sc.crib_score
        result["ene_score"] = sc.ene_score
        result["bc_score"] = sc.bc_score
        result["ic"] = round(sc.ic_value, 4)
        result["classification"] = sc.crib_classification
    elif len(text) >= 5:
        sc = score_candidate_free(text)
        result["scorer"] = "free"
        result["crib_score"] = sc.crib_score
        result["ene_found"] = sc.ene_found
        result["bc_found"] = sc.bc_found
        result["ic"] = round(sc.ic_value, 4)
        result["classification"] = sc.crib_classification
    else:
        result["scorer"] = "too_short"
        result["crib_score"] = 0
    return result


def mod_inverse(a, m):
    """Extended GCD to find modular inverse."""
    if math.gcd(a, m) != 1:
        return None
    g, x, _ = extended_gcd(a, m)
    return x % m


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def hill_invert_2x2(matrix):
    """Invert a 2x2 matrix mod 26. Returns None if not invertible."""
    a, b = matrix[0]
    c, d = matrix[1]
    det = (a * d - b * c) % MOD
    det_inv = mod_inverse(det, MOD)
    if det_inv is None:
        return None
    return [
        [(d * det_inv) % MOD, ((-b) * det_inv) % MOD],
        [((-c) * det_inv) % MOD, (a * det_inv) % MOD],
    ]


def hill_decrypt_2x2(ct_str, matrix_inv):
    """Decrypt using 2x2 Hill cipher."""
    result = []
    for i in range(0, len(ct_str) - 1, 2):
        c1 = ALPH_IDX[ct_str[i]]
        c2 = ALPH_IDX[ct_str[i + 1]]
        p1 = (matrix_inv[0][0] * c1 + matrix_inv[0][1] * c2) % MOD
        p2 = (matrix_inv[1][0] * c1 + matrix_inv[1][1] * c2) % MOD
        result.append(ALPH[p1])
        result.append(ALPH[p2])
    if len(ct_str) % 2 == 1:
        result.append(ct_str[-1])
    return "".join(result)


def main():
    all_results = {}
    best_overall = {"label": "none", "crib_score": 0}

    def track(category, result):
        if category not in all_results:
            all_results[category] = []
        all_results[category].append(result)
        if result.get("crib_score", 0) > best_overall.get("crib_score", 0):
            best_overall.update(result)

    print("=" * 70)
    print("E-TEAM-ANOMALY-EXTRACTION: Physically-motivated extraction masks")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"CT_LEN: {CT_LEN}")
    print()

    # ── 1. YAR-derived extractions ────────────────────────────────────────
    print("--- 1. YAR-derived (Y=24, A=0, R=17) ---")
    yar_values = {"Y": 24, "A": 0, "R": 17}

    # Stride extractions
    for name, stride in [("Y=24", 24), ("R=17", 17), ("Y+R=41", 41)]:
        for start in range(min(stride, CT_LEN)):
            positions = list(range(start, CT_LEN, stride))
            if len(positions) < 3:
                continue
            extracted = "".join(CT[p] for p in positions)
            r = score_text(extracted, f"YAR_stride_{name}_start{start}")
            track("yar_stride", r)
            if r["crib_score"] > 0:
                print(f"  stride {name} start={start}: {extracted[:40]}... score={r['crib_score']}")

    # Modular selections
    for mod_val in [17, 24, 41]:
        for rem in range(mod_val):
            positions = [p for p in range(CT_LEN) if p % mod_val == rem]
            if len(positions) < 3:
                continue
            extracted = "".join(CT[p] for p in positions)
            r = score_text(extracted, f"YAR_mod{mod_val}_rem{rem}")
            track("yar_mod", r)

    yar_best = max(
        all_results.get("yar_stride", [{}]) + all_results.get("yar_mod", [{}]),
        key=lambda x: x.get("crib_score", 0)
    )
    print(f"  YAR best: score={yar_best.get('crib_score', 0)} ({yar_best.get('label', 'none')})")
    print()

    # ── 2. DESPARATLY-derived ─────────────────────────────────────────────
    print("--- 2. DESPARATLY-derived (multiples of 5, 8) ---")
    for stride in [5, 8, 10, 13]:
        for start in range(stride):
            positions = list(range(start, CT_LEN, stride))
            if len(positions) < 3:
                continue
            extracted = "".join(CT[p] for p in positions)
            r = score_text(extracted, f"DESP_stride{stride}_start{start}")
            track("desparatly", r)

    # Also: positions of letters in DESPARATLY
    desp_letters = set("DESPARATLY")
    desp_positions = [i for i, c in enumerate(CT) if c in desp_letters]
    not_desp = [i for i, c in enumerate(CT) if c not in desp_letters]
    if desp_positions:
        r = score_text("".join(CT[p] for p in desp_positions), "DESP_letter_select")
        track("desparatly", r)
    if not_desp:
        r = score_text("".join(CT[p] for p in not_desp), "DESP_letter_reject")
        track("desparatly", r)

    desp_best = max(all_results.get("desparatly", [{}]), key=lambda x: x.get("crib_score", 0))
    print(f"  DESPARATLY best: score={desp_best.get('crib_score', 0)} ({desp_best.get('label', 'none')})")
    print()

    # ── 3. Self-encrypting anchors (pos 32=S, 73=K) ──────────────────────
    print("--- 3. Self-encrypting anchors (pos 32=S, 73=K) ---")
    anchors = [32, 73]

    # Partition CT at anchor points, try different segment orderings
    segments = [CT[:32], CT[32:73], CT[73:]]
    seg_names = ["pre32", "mid32_73", "post73"]
    for perm in itertools.permutations(range(3)):
        reordered = "".join(segments[i] for i in perm)
        perm_name = "_".join(seg_names[i] for i in perm)
        r = score_text(reordered, f"anchor_perm_{perm_name}")
        track("self_encrypt_anchor", r)

    # Segments including the anchor chars
    segments2 = [CT[:33], CT[33:74], CT[74:]]
    seg_names2 = ["pre33", "mid33_74", "post74"]
    for perm in itertools.permutations(range(3)):
        reordered = "".join(segments2[i] for i in perm)
        perm_name = "_".join(seg_names2[i] for i in perm)
        r = score_text(reordered, f"anchor_incl_perm_{perm_name}")
        track("self_encrypt_anchor", r)

    anchor_best = max(all_results.get("self_encrypt_anchor", [{}]), key=lambda x: x.get("crib_score", 0))
    print(f"  Anchor best: score={anchor_best.get('crib_score', 0)} ({anchor_best.get('label', 'none')})")
    print()

    # ── 4. "ID BY ROWS": grid reads, columns instead of rows ─────────────
    print("--- 4. ID BY ROWS: grid reads (widths 7-13) ---")
    for width in range(7, 14):
        nrows = math.ceil(CT_LEN / width)
        # Pad CT for grid
        padded = CT + "X" * (nrows * width - CT_LEN)

        # Read by columns (top to bottom, left to right)
        col_read = ""
        for col in range(width):
            for row in range(nrows):
                col_read += padded[row * width + col]
        col_read = col_read[:CT_LEN]
        r = score_text(col_read, f"grid_w{width}_col_LR_TB")
        track("id_by_rows", r)

        # Read by columns (bottom to top, left to right)
        col_read_bt = ""
        for col in range(width):
            for row in range(nrows - 1, -1, -1):
                col_read_bt += padded[row * width + col]
        col_read_bt = col_read_bt[:CT_LEN]
        r = score_text(col_read_bt, f"grid_w{width}_col_LR_BT")
        track("id_by_rows", r)

        # Read by columns (right to left, top to bottom)
        col_read_rl = ""
        for col in range(width - 1, -1, -1):
            for row in range(nrows):
                col_read_rl += padded[row * width + col]
        col_read_rl = col_read_rl[:CT_LEN]
        r = score_text(col_read_rl, f"grid_w{width}_col_RL_TB")
        track("id_by_rows", r)

        # Spiral read (clockwise from top-left)
        grid = []
        for row in range(nrows):
            grid.append(list(padded[row * width : (row + 1) * width]))
        spiral = []
        top, bottom, left, right = 0, nrows - 1, 0, width - 1
        while top <= bottom and left <= right:
            for c in range(left, right + 1):
                spiral.append(grid[top][c])
            top += 1
            for r_idx in range(top, bottom + 1):
                spiral.append(grid[r_idx][right])
            right -= 1
            if top <= bottom:
                for c in range(right, left - 1, -1):
                    spiral.append(grid[bottom][c])
                bottom -= 1
            if left <= right:
                for r_idx in range(bottom, top - 1, -1):
                    spiral.append(grid[r_idx][left])
                left += 1
        spiral_text = "".join(spiral)[:CT_LEN]
        r = score_text(spiral_text, f"grid_w{width}_spiral_CW")
        track("id_by_rows", r)

        # Diagonal read
        diag = []
        for d in range(nrows + width - 1):
            for row in range(max(0, d - width + 1), min(nrows, d + 1)):
                col = d - row
                if col < width:
                    diag.append(padded[row * width + col])
        diag_text = "".join(diag)[:CT_LEN]
        r = score_text(diag_text, f"grid_w{width}_diag")
        track("id_by_rows", r)

        # Boustrophedon (alternating row direction)
        bous = ""
        for row in range(nrows):
            row_chars = padded[row * width : (row + 1) * width]
            if row % 2 == 1:
                row_chars = row_chars[::-1]
            bous += row_chars
        bous = bous[:CT_LEN]
        r = score_text(bous, f"grid_w{width}_boustrophedon")
        track("id_by_rows", r)

    grid_best = max(all_results.get("id_by_rows", [{}]), key=lambda x: x.get("crib_score", 0))
    print(f"  Grid best: score={grid_best.get('crib_score', 0)} ({grid_best.get('label', 'none')})")
    print()

    # ── 5. "LAYER TWO": even/odd splits and interleaves ──────────────────
    print("--- 5. LAYER TWO: even/odd splits ---")
    evens = "".join(CT[i] for i in range(0, CT_LEN, 2))  # 49 chars
    odds = "".join(CT[i] for i in range(1, CT_LEN, 2))   # 48 chars

    # Score each half
    for text, label in [
        (evens, "evens"), (odds, "odds"),
        (evens[::-1], "evens_rev"), (odds[::-1], "odds_rev"),
    ]:
        r = score_text(text, f"layer2_{label}")
        track("layer_two", r)

    # Interleave in different orders
    interleaves = {
        "odds_then_evens": odds + evens,
        "evens_then_odds": evens + odds,
        "rev_odds_then_evens": odds[::-1] + evens,
        "evens_then_rev_odds": evens + odds[::-1],
        "rev_evens_then_odds": evens[::-1] + odds,
        "odds_then_rev_evens": odds + evens[::-1],
    }
    for label, text in interleaves.items():
        r = score_text(text, f"layer2_{label}")
        track("layer_two", r)

    # Re-interleave: zip odds into evens and vice versa
    def interleave(a, b):
        result = []
        for i in range(max(len(a), len(b))):
            if i < len(a):
                result.append(a[i])
            if i < len(b):
                result.append(b[i])
        return "".join(result)

    r = score_text(interleave(odds, evens), "layer2_interleave_odds_evens")
    track("layer_two", r)
    r = score_text(interleave(evens[::-1], odds), "layer2_interleave_rev_evens_odds")
    track("layer_two", r)
    r = score_text(interleave(odds[::-1], evens), "layer2_interleave_rev_odds_evens")
    track("layer_two", r)

    # Thirds split
    third = CT_LEN // 3  # 32
    t1, t2, t3 = CT[:third], CT[third:2*third], CT[2*third:]
    for perm in itertools.permutations(range(3)):
        parts = [t1, t2, t3]
        reordered = "".join(parts[i] for i in perm)
        r = score_text(reordered, f"layer2_thirds_{''.join(str(i) for i in perm)}")
        track("layer_two", r)

    layer2_best = max(all_results.get("layer_two", [{}]), key=lambda x: x.get("crib_score", 0))
    print(f"  LAYER TWO best: score={layer2_best.get('crib_score', 0)} ({layer2_best.get('label', 'none')})")
    print()

    # ── 6. Letter masks (single-letter selection) ─────────────────────────
    print("--- 6. Letter masks (26 letters) ---")
    letter_best = {"crib_score": 0}
    for letter in ALPH:
        # Select positions with this letter
        selected = [i for i, c in enumerate(CT) if c == letter]
        rejected = [i for i, c in enumerate(CT) if c != letter]

        if len(selected) >= 3:
            sel_text = "".join(CT[p] for p in selected)
            r = score_text(sel_text, f"letter_select_{letter}")
            track("letter_mask", r)
            if r["crib_score"] > letter_best.get("crib_score", 0):
                letter_best = r

        if len(rejected) >= 3:
            rej_text = "".join(CT[p] for p in rejected)
            r = score_text(rej_text, f"letter_reject_{letter}")
            track("letter_mask", r)
            if r["crib_score"] > letter_best.get("crib_score", 0):
                letter_best = r

    print(f"  Letter mask best: score={letter_best.get('crib_score', 0)} ({letter_best.get('label', 'none')})")
    print()

    # ── 7. Reverse and mirror ─────────────────────────────────────────────
    print("--- 7. Reverse, mirror, and rotations ---")
    # Reversed CT
    r = score_text(CT[::-1], "reverse")
    track("reverse_mirror", r)

    # Mirror: CT[96-i]
    mirror = "".join(CT[CT_LEN - 1 - i] for i in range(CT_LEN))
    r = score_text(mirror, "mirror_96-i")
    track("reverse_mirror", r)

    # All rotations
    rot_best = {"crib_score": 0}
    for rot in range(1, CT_LEN):
        rotated = CT[rot:] + CT[:rot]
        r = score_text(rotated, f"rotation_{rot}")
        track("rotations", r)
        if r["crib_score"] > rot_best.get("crib_score", 0):
            rot_best = r

    print(f"  Reverse score: {all_results['reverse_mirror'][0].get('crib_score', 0)}")
    print(f"  Mirror score: {all_results['reverse_mirror'][1].get('crib_score', 0)}")
    print(f"  Rotation best: score={rot_best.get('crib_score', 0)} ({rot_best.get('label', 'none')})")
    print()

    # ── 8. HILL cipher (2x2 matrix) ──────────────────────────────────────
    print("--- 8. HILL cipher (H=7,I=8,L=11,L=11) ---")
    hill_matrix = [[7, 8], [11, 11]]
    det = (7 * 11 - 8 * 11) % MOD  # = -11 mod 26 = 15
    print(f"  det = {det}, gcd(det,26) = {math.gcd(det, MOD)}")

    hill_inv = hill_invert_2x2(hill_matrix)
    if hill_inv is not None:
        print(f"  Inverse matrix: {hill_inv}")
        pt_hill = hill_decrypt_2x2(CT, hill_inv)
        r = score_text(pt_hill, "hill_HILL_decrypt")
        track("hill", r)
        print(f"  HILL decrypt: {pt_hill[:50]}... score={r['crib_score']}")

        # Also try the inverse direction (encrypting = decrypting with original)
        pt_hill_enc = hill_decrypt_2x2(CT, hill_matrix)
        r2 = score_text(pt_hill_enc, "hill_HILL_encrypt_dir")
        track("hill", r2)
        print(f"  HILL encrypt dir: {pt_hill_enc[:50]}... score={r2['crib_score']}")
    else:
        print("  HILL matrix not invertible mod 26")

    # Try other thematic 2x2 matrices
    thematic_matrices = {
        "KR_YP": [[10, 17], [24, 15]],   # K=10, R=17, Y=24, P=15
        "TO_SA": [[19, 14], [18, 0]],     # T=19, O=14, S=18, A=0
        "CI_AH": [[2, 8], [0, 7]],        # C=2, I=8, A=0, H=7 (CIA HQ)
        "EA_ST": [[4, 0], [18, 19]],      # EAST
        "BE_RL": [[1, 4], [17, 11]],       # BERL(in)
    }
    for name, matrix in thematic_matrices.items():
        det_val = (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % MOD
        if math.gcd(det_val, MOD) != 1:
            r = {"label": f"hill_{name}", "crib_score": 0, "text": "", "note": f"det={det_val} not invertible"}
            track("hill", r)
            continue
        inv = hill_invert_2x2(matrix)
        if inv is None:
            continue
        pt = hill_decrypt_2x2(CT, inv)
        r = score_text(pt, f"hill_{name}_decrypt")
        track("hill", r)
        if r["crib_score"] > 0:
            print(f"  {name} decrypt: {pt[:40]}... score={r['crib_score']}")

    hill_best = max(all_results.get("hill", [{}]), key=lambda x: x.get("crib_score", 0))
    print(f"  Hill best: score={hill_best.get('crib_score', 0)} ({hill_best.get('label', 'none')})")
    print()

    # ── 9. Morse E (positions where CT == 'E') ───────────────────────────
    print("--- 9. Morse E positions ---")
    e_positions = [i for i, c in enumerate(CT) if c == "E"]
    print(f"  E positions ({len(e_positions)}): {e_positions}")

    # Use E positions as selection mask
    if e_positions:
        e_selected = "".join(CT[p] for p in e_positions)
        r = score_text(e_selected, "morse_E_select")
        track("morse_e", r)

    # Use non-E positions
    non_e = [i for i, c in enumerate(CT) if c != "E"]
    non_e_text = "".join(CT[p] for p in non_e)
    r = score_text(non_e_text, "morse_E_reject")
    track("morse_e", r)

    # E positions as bit mask: use the count of chars between E's
    e_gaps = []
    for i in range(len(e_positions) - 1):
        e_gaps.append(e_positions[i + 1] - e_positions[i] - 1)
    print(f"  E gaps: {e_gaps}")
    # Try interpreting gaps as letter indices
    if all(0 <= g < 26 for g in e_gaps):
        gap_text = "".join(ALPH[g] for g in e_gaps)
        r = score_text(gap_text, "morse_E_gaps_as_letters")
        track("morse_e", r)
        print(f"  E gaps as letters: {gap_text}")

    morse_best = max(all_results.get("morse_e", [{}]), key=lambda x: x.get("crib_score", 0))
    print(f"  Morse E best: score={morse_best.get('crib_score', 0)}")
    print()

    # ── 10. Alphabet position value extraction ───────────────────────────
    print("--- 10. Numeric value extractions ---")
    # CT letter values (A=0..Z=25), try mod operations
    ct_vals = [ALPH_IDX[c] for c in CT]

    # Pairwise differences mod 26
    diffs = [(ct_vals[i + 1] - ct_vals[i]) % MOD for i in range(CT_LEN - 1)]
    diff_text = "".join(ALPH[d] for d in diffs)
    r = score_text(diff_text, "pairwise_diff_mod26")
    track("numeric", r)
    print(f"  Pairwise diffs: {diff_text[:50]}... score={r['crib_score']}")

    # Pairwise sums mod 26
    sums = [(ct_vals[i + 1] + ct_vals[i]) % MOD for i in range(CT_LEN - 1)]
    sum_text = "".join(ALPH[s] for s in sums)
    r = score_text(sum_text, "pairwise_sum_mod26")
    track("numeric", r)
    print(f"  Pairwise sums: {sum_text[:50]}... score={r['crib_score']}")

    # XOR-like: (a ^ b) mod 26
    xor_vals = [(ct_vals[i] ^ ct_vals[i + 1]) % MOD for i in range(CT_LEN - 1)]
    xor_text = "".join(ALPH[v] for v in xor_vals)
    r = score_text(xor_text, "pairwise_xor_mod26")
    track("numeric", r)

    # Running total mod 26
    running = []
    total = 0
    for v in ct_vals:
        total = (total + v) % MOD
        running.append(ALPH[total])
    r = score_text("".join(running), "running_total_mod26")
    track("numeric", r)

    numeric_best = max(all_results.get("numeric", [{}]), key=lambda x: x.get("crib_score", 0))
    print(f"  Numeric best: score={numeric_best.get('crib_score', 0)} ({numeric_best.get('label', 'none')})")
    print()

    # ── Summary ──────────────────────────────────────────────────────────
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)

    total_configs = sum(len(v) for v in all_results.values())
    print(f"Total configurations tested: {total_configs}")
    print()

    # Best per category
    for cat, results in sorted(all_results.items()):
        if not results:
            continue
        cat_best = max(results, key=lambda x: x.get("crib_score", 0))
        print(f"  {cat:25s}: best={cat_best.get('crib_score', 0):3d}  ({cat_best.get('label', 'none')})")

    print()
    print(f"OVERALL BEST: score={best_overall.get('crib_score', 0)}")
    print(f"  Label: {best_overall.get('label', 'none')}")
    if best_overall.get("text"):
        print(f"  Text: {best_overall['text'][:60]}...")
    print()

    # Check for any signal
    signal_found = best_overall.get("crib_score", 0) >= 18
    if signal_found:
        print("*** SIGNAL DETECTED — investigate immediately ***")
    else:
        print("VERDICT: ALL NOISE — no extraction mask produces meaningful crib alignment")

    # ── Save results ─────────────────────────────────────────────────────
    output = {
        "experiment_id": "e_team_anomaly_extraction",
        "description": "Physically-motivated extraction masks on K4 CT",
        "total_configs": total_configs,
        "best_overall": {
            "label": best_overall.get("label", "none"),
            "crib_score": best_overall.get("crib_score", 0),
            "text_preview": best_overall.get("text", "")[:60],
        },
        "category_bests": {},
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

    results_path = os.path.join(os.path.dirname(__file__), "..", "results", "e_team_anomaly_extraction.json")
    os.makedirs(os.path.dirname(results_path), exist_ok=True)
    with open(results_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to: {results_path}")


if __name__ == "__main__":
    main()
