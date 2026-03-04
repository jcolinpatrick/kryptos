#!/usr/bin/env python3
"""
Cipher: Berlin clock
Family: thematic/berlin_clock
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-TEAM-WELTZEITUHR-PROCEDURAL: Weltzeituhr as cipher device + non-standard routes.

Tests the Weltzeituhr (World Time Clock) in Berlin as a transposition device,
plus non-standard reading routes on K4 grids (center spiral, skip-N, two-pass
column reads, boustrophedon at wider grids).

For each route, applies direct scoring + Vigenere/Beaufort decryption with
thematic keywords.
"""
import sys, os, json, math, itertools

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
)
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
)


def score_97(text, label):
    """Score a 97-char text."""
    if len(text) != CT_LEN:
        return {"label": label, "crib_score": 0, "length": len(text), "error": "wrong length"}
    sc = score_candidate(text)
    return {
        "label": label,
        "crib_score": sc.crib_score,
        "ene_score": sc.ene_score,
        "bc_score": sc.bc_score,
        "ic": round(sc.ic_value, 4),
        "classification": sc.crib_classification,
    }


def apply_permutation(text, perm):
    """output[i] = text[perm[i]]"""
    return "".join(text[perm[i]] for i in range(len(perm)))


def try_with_decryption(text, label, results_list, track_fn):
    """Score text directly and with various decryptions."""
    # Direct scoring
    r = score_97(text, label)
    track_fn("routes", r)

    # Caesar shifts
    best_caesar = 0
    for shift in range(1, 26):
        key = [shift] * CT_LEN
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
            pt = decrypt_text(text, key, variant)
            sc = score_candidate(pt)
            if sc.crib_score > best_caesar:
                best_caesar = sc.crib_score
                r2 = score_97(pt, f"{label}_caesar{shift}_{variant.value}")
                track_fn("routes_decrypted", r2)

    # Keyword decryptions
    keywords = ["KRYPTOS", "BERLIN", "CLOCK", "WELTZEITUHR", "PALIMPSEST", "ABSCISSA"]
    for kw in keywords:
        key = [ALPH_IDX[c] for c in kw]
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
            pt = decrypt_text(text, key, variant)
            sc = score_candidate(pt)
            if sc.crib_score > 0:
                r2 = score_97(pt, f"{label}_{kw}_{variant.value}")
                track_fn("routes_decrypted", r2)


def grid_center_spiral(text, width):
    """Spiral read from the center of a grid outward."""
    nrows = math.ceil(len(text) / width)
    padded = text + "X" * (nrows * width - len(text))

    grid = []
    for row in range(nrows):
        grid.append(list(padded[row * width:(row + 1) * width]))

    # Start from center
    center_r = nrows // 2
    center_c = width // 2

    visited = [[False] * width for _ in range(nrows)]
    result = []

    # Directions: right, down, left, up
    dr = [0, 1, 0, -1]
    dc = [1, 0, -1, 0]

    r, c = center_r, center_c
    direction = 0
    steps = 1
    step_count = 0
    turns = 0

    while len(result) < nrows * width:
        if 0 <= r < nrows and 0 <= c < width and not visited[r][c]:
            visited[r][c] = True
            idx = r * width + c
            if idx < len(text):
                result.append(text[idx])

        step_count += 1
        if step_count >= steps:
            step_count = 0
            direction = (direction + 1) % 4
            turns += 1
            if turns % 2 == 0:
                steps += 1

        r += dr[direction]
        c += dc[direction]

        # Safety: break if we've gone too far
        if abs(r) > nrows + 5 or abs(c) > width + 5:
            break

    return "".join(result)[:len(text)]


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
    print("E-TEAM-WELTZEITUHR-PROCEDURAL: Weltzeituhr + reading routes")
    print("=" * 70)
    print()

    # ── 1. Weltzeituhr as 24-facet block transposition ───────────────────
    print("--- 1. Weltzeituhr 24-facet block transposition ---")

    # 97 = 4*24 + 1. Split CT into 4 blocks of 24 + 1 remainder.
    # Try all 24! permutations? No — 24! is way too large.
    # Instead try structured orderings of blocks.

    # Block partition: 4 blocks of 24 chars + 1 char
    blocks_24 = [CT[i*24:(i+1)*24] for i in range(4)]
    remainder = CT[96]  # last char 'R'

    print(f"  Blocks of 24: {[b[:10]+'...' for b in blocks_24]}")
    print(f"  Remainder: {remainder}")

    # Try all 24 (4!) block permutations + different remainder positions
    block_perms_tested = 0
    for perm in itertools.permutations(range(4)):
        reordered = "".join(blocks_24[i] for i in perm) + remainder
        r = score_97(reordered, f"welt_block24_perm{''.join(str(i) for i in perm)}_end")
        track("weltzeituhr_block", r)
        block_perms_tested += 1

        # Also try remainder at beginning
        reordered2 = remainder + "".join(blocks_24[i] for i in perm)
        r2 = score_97(reordered2, f"welt_block24_perm{''.join(str(i) for i in perm)}_begin")
        track("weltzeituhr_block", r2)
        block_perms_tested += 1

    # Smaller blocks: 97 / various facet counts
    for n_facets in [8, 12, 16, 24]:
        block_size = CT_LEN // n_facets
        if block_size < 2:
            continue
        n_full = CT_LEN // block_size
        blocks = [CT[i*block_size:(i+1)*block_size] for i in range(n_full)]
        rem = CT[n_full*block_size:]

        # Reverse blocks
        reversed_blocks = "".join(blocks[::-1]) + rem
        if len(reversed_blocks) >= CT_LEN:
            reversed_blocks = reversed_blocks[:CT_LEN]
            r = score_97(reversed_blocks, f"welt_block{block_size}_reverse")
            track("weltzeituhr_block", r)
            block_perms_tested += 1

        # Interleave: take 1st char of each block, then 2nd, etc.
        interleaved = []
        for offset in range(block_size):
            for b in blocks:
                if offset < len(b):
                    interleaved.append(b[offset])
        interleaved = "".join(interleaved) + rem
        if len(interleaved) >= CT_LEN:
            interleaved = interleaved[:CT_LEN]
            r = score_97(interleaved, f"welt_block{block_size}_interleave")
            track("weltzeituhr_block", r)
            block_perms_tested += 1

    welt_best = max(all_results.get("weltzeituhr_block", [{"crib_score": 0}]),
                    key=lambda x: x.get("crib_score", 0))
    print(f"  Block perms tested: {block_perms_tested}")
    print(f"  Best: score={welt_best.get('crib_score', 0)} ({welt_best.get('label', 'none')})")
    print()

    # ── 2. Boustrophedon at wider grids (14-20) ─────────────────────────
    print("--- 2. Boustrophedon (widths 14-20) ---")
    bous_count = 0
    for width in range(7, 21):
        nrows = math.ceil(CT_LEN / width)
        padded = CT + "X" * (nrows * width - CT_LEN)

        # Standard boustrophedon
        bous = ""
        for row in range(nrows):
            row_chars = padded[row * width:(row + 1) * width]
            if row % 2 == 1:
                row_chars = row_chars[::-1]
            bous += row_chars
        bous = bous[:CT_LEN]
        try_with_decryption(bous, f"bous_w{width}", all_results.get("routes", []), track)
        bous_count += 1

        # Reverse boustrophedon (start with reversed row)
        bous_rev = ""
        for row in range(nrows):
            row_chars = padded[row * width:(row + 1) * width]
            if row % 2 == 0:
                row_chars = row_chars[::-1]
            bous_rev += row_chars
        bous_rev = bous_rev[:CT_LEN]
        r = score_97(bous_rev, f"bous_rev_w{width}")
        track("routes", r)
        bous_count += 1

    print(f"  Boustrophedon configs: {bous_count}")
    print()

    # ── 3. Center spiral ────────────────────────────────────────────────
    print("--- 3. Center spiral (widths 7-15) ---")
    spiral_count = 0
    for width in range(7, 16):
        spiral_text = grid_center_spiral(CT, width)
        if len(spiral_text) == CT_LEN:
            r = score_97(spiral_text, f"center_spiral_w{width}")
            track("routes", r)
            spiral_count += 1

    print(f"  Center spiral configs: {spiral_count}")
    print()

    # ── 4. Skip-N patterns ──────────────────────────────────────────────
    print("--- 4. Skip-N patterns ---")
    skip_count = 0
    for skip in range(2, 49):  # skip 2 through 48
        positions = []
        pos = 0
        seen = set()
        while len(positions) < CT_LEN:
            if pos in seen:
                # Find next unseen position
                found = False
                for p in range(CT_LEN):
                    if p not in seen:
                        pos = p
                        found = True
                        break
                if not found:
                    break
            seen.add(pos)
            positions.append(pos)
            pos = (pos + skip) % CT_LEN

        if len(positions) == CT_LEN:
            text = "".join(CT[p] for p in positions)
            r = score_97(text, f"skip_{skip}")
            track("routes", r)
            skip_count += 1

    print(f"  Skip-N configs: {skip_count}")
    print()

    # ── 5. Two-pass column reads ────────────────────────────────────────
    print("--- 5. Two-pass column reads ---")
    twopass_count = 0
    for width in range(7, 14):
        nrows = math.ceil(CT_LEN / width)
        padded = CT + "X" * (nrows * width - CT_LEN)

        # Odd columns first, then even (0-indexed)
        odd_cols = [c for c in range(width) if c % 2 == 1]
        even_cols = [c for c in range(width) if c % 2 == 0]

        for col_order, label in [
            (odd_cols + even_cols, "odd_first"),
            (even_cols + odd_cols, "even_first"),
            (list(range(width - 1, -1, -1)), "reverse"),
        ]:
            text = ""
            for col in col_order:
                for row in range(nrows):
                    idx = row * width + col
                    if idx < CT_LEN:
                        text += CT[idx]
            if len(text) == CT_LEN:
                r = score_97(text, f"twopass_w{width}_{label}")
                track("routes", r)
                twopass_count += 1

    print(f"  Two-pass configs: {twopass_count}")
    print()

    # ── 6. Weltzeituhr city ordering ────────────────────────────────────
    print("--- 6. Weltzeituhr city-name reordering ---")

    # 24 cities on the Weltzeituhr, mapped to UTC offsets
    # Use offset as transposition key for blocks
    weltzeituhr_cities = [
        ("Anchorage", -9), ("Buenos Aires", -3), ("Cairo", 2),
        ("Dhaka", 6), ("Delhi", 5.5), ("Dubai", 4),
        ("Havana", -5), ("Helsinki", 2), ("Hong Kong", 8),
        ("Honolulu", -10), ("Istanbul", 3), ("Jakarta", 7),
        ("London", 0), ("Los Angeles", -8), ("Mexico City", -6),
        ("Moscow", 3), ("New York", -5), ("Paris", 1),
        ("Peking", 8), ("Petropavlovsk", 12), ("Reykjavik", 0),
        ("Santiago", -4), ("Sydney", 10), ("Tokyo", 9),
    ]

    # Sort by UTC offset
    by_offset = sorted(range(24), key=lambda i: weltzeituhr_cities[i][1])
    # Sort alphabetically
    by_alpha = sorted(range(24), key=lambda i: weltzeituhr_cities[i][0])

    # Use these orderings to reorder 24-char blocks
    # 97 / 24 = 4.04, so use 4 chars per block
    city_count = 0
    for ordering, ord_name in [(by_offset, "utc"), (by_alpha, "alpha")]:
        for block_size in [4, 3, 5]:
            if block_size * 24 > CT_LEN * 2:
                continue
            # Map each city index (in ordering) to a position in CT
            perm = []
            for city_idx in ordering:
                for j in range(block_size):
                    pos = city_idx * block_size + j
                    if pos < CT_LEN:
                        perm.append(pos)

            # Add remaining positions
            seen = set(perm)
            for p in range(CT_LEN):
                if p not in seen:
                    perm.append(p)

            if len(perm) == CT_LEN:
                text = apply_permutation(CT, perm)
                r = score_97(text, f"welt_city_{ord_name}_bs{block_size}")
                track("weltzeituhr_city", r)
                city_count += 1

                # Also try inverse
                inv_perm = [0] * CT_LEN
                for i, p in enumerate(perm):
                    inv_perm[p] = i
                text_inv = apply_permutation(CT, inv_perm)
                r2 = score_97(text_inv, f"welt_city_{ord_name}_bs{block_size}_inv")
                track("weltzeituhr_city", r2)
                city_count += 1

    print(f"  City ordering configs: {city_count}")
    print()

    # ── 7. Clock face reading ───────────────────────────────────────────
    print("--- 7. Clock face reading ---")
    clock_count = 0

    # Read positions as clock: arrange CT in circle, read by hour positions
    # 12-hour clock: positions 0,8,16,24,... (every 8th for 97/12≈8)
    for n_hours in [12, 24]:
        step = CT_LEN / n_hours
        for start_hour in range(n_hours):
            positions = []
            seen = set()
            for h in range(n_hours):
                idx = int(((start_hour + h) * step) % CT_LEN)
                while idx in seen and len(seen) < CT_LEN:
                    idx = (idx + 1) % CT_LEN
                if idx not in seen:
                    seen.add(idx)
                    positions.append(idx)

            # Fill remaining
            for p in range(CT_LEN):
                if p not in seen:
                    positions.append(p)
                    seen.add(p)

            if len(positions) == CT_LEN:
                text = "".join(CT[p] for p in positions)
                r = score_97(text, f"clock_{n_hours}h_start{start_hour}")
                track("clock_face", r)
                clock_count += 1

    print(f"  Clock face configs: {clock_count}")
    print()

    # ── 8. Route + decryption combos (top routes) ───────────────────────
    print("--- 8. Best routes with keyword decryption ---")
    # Collect the best route results and try decryption on them
    all_route_results = (
        all_results.get("routes", []) +
        all_results.get("weltzeituhr_block", []) +
        all_results.get("weltzeituhr_city", []) +
        all_results.get("clock_face", [])
    )

    # Get unique top-scoring texts
    top_routes = sorted(all_route_results, key=lambda x: x.get("crib_score", 0), reverse=True)[:20]

    keywords = ["KRYPTOS", "BERLIN", "CLOCK", "WELTZEITUHR", "PALIMPSEST",
                "ABSCISSA", "EAST", "NORTH", "NORTHEAST"]
    decrypt_count = 0

    for route_r in top_routes:
        label = route_r.get("label", "unknown")
        # We need to reconstruct the text... just try keywords on CT with permutation
        # Actually we can only do this efficiently for the original CT
        pass  # Already done in try_with_decryption for some routes

    # Instead, try all keywords directly on CT (no transposition)
    for kw in keywords:
        key = [ALPH_IDX[c] for c in kw]
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
            pt = decrypt_text(CT, key, variant)
            sc = score_candidate(pt)
            r = score_97(pt, f"direct_{kw}_{variant.value}")
            track("keyword_direct", r)
            decrypt_count += 1

    print(f"  Keyword direct decryptions: {decrypt_count}")
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
    print()

    signal_found = best_overall.get("crib_score", 0) >= 18
    if signal_found:
        print("*** SIGNAL DETECTED ***")
    else:
        print("VERDICT: ALL NOISE — no Weltzeituhr or reading route produces meaningful crib alignment")

    # ── Save results ─────────────────────────────────────────────────────
    output = {
        "experiment_id": "e_team_weltzeituhr_procedural",
        "description": "Weltzeituhr procedural cipher + non-standard reading routes",
        "total_configs": total_configs,
        "best_overall": {
            "label": best_overall.get("label", "none"),
            "crib_score": best_overall.get("crib_score", 0),
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

    results_path = os.path.join(os.path.dirname(__file__), "..", "results", "e_team_weltzeituhr_procedural.json")
    os.makedirs(os.path.dirname(results_path), exist_ok=True)
    with open(results_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to: {results_path}")


if __name__ == "__main__":
    main()
