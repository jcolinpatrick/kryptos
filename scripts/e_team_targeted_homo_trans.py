#!/usr/bin/env python3
"""E-TEAM-TARGETED-HOMO-TRANS: Targeted search for transpositions that resolve
all homophonic contradictions at K4 crib positions.

Under identity transposition, 9 CT letters at crib positions map to 2+ PT letters,
making homophonic substitution impossible. Random transpositions resolve all 9
with P < 1e-5 (from E-TEAM-HOMOPHONIC-TRANS). This script systematically tests
structured transpositions to find any that achieve 0 contradictions.

Streaming approach: test each permutation immediately, don't store all in memory.
"""
import sys, os, json, math, random, time, itertools
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS,
)

# Pre-compute for fast contradiction checking
CRIB_POS_LIST = sorted(CRIB_POSITIONS)
CRIB_PT_LIST = [CRIB_DICT[p] for p in CRIB_POS_LIST]


def count_contradictions(perm):
    """Count homophonic contradictions under a given transposition. Fast version."""
    letter_to_pt = {}
    contradictions = 0
    seen_contradiction = set()
    for i, pos in enumerate(CRIB_POS_LIST):
        intermediate_char = CT[perm[pos]]
        pt_char = CRIB_PT_LIST[i]
        if intermediate_char in letter_to_pt:
            if letter_to_pt[intermediate_char] != pt_char:
                if intermediate_char not in seen_contradiction:
                    # First time seeing this letter as contradiction
                    # But it might map to multiple — just count the letter once
                    pass
        else:
            letter_to_pt[intermediate_char] = pt_char

    # Recount properly: build full mapping
    letter_to_pts = defaultdict(set)
    for i, pos in enumerate(CRIB_POS_LIST):
        intermediate_char = CT[perm[pos]]
        pt_char = CRIB_PT_LIST[i]
        letter_to_pts[intermediate_char].add(pt_char)

    return sum(1 for pts in letter_to_pts.values() if len(pts) > 1)


def get_contradiction_detail(perm):
    """Get detailed contradiction mapping."""
    letter_to_pt = defaultdict(set)
    letter_to_positions = defaultdict(list)
    for i, pos in enumerate(CRIB_POS_LIST):
        intermediate_char = CT[perm[pos]]
        pt_char = CRIB_PT_LIST[i]
        letter_to_pt[intermediate_char].add(pt_char)
        letter_to_positions[intermediate_char].append((pos, pt_char))

    contradictions = {}
    clean = {}
    for letter in sorted(letter_to_pt.keys()):
        pts = letter_to_pt[letter]
        if len(pts) > 1:
            contradictions[letter] = {
                "maps_to": sorted(pts),
                "positions": letter_to_positions[letter],
            }
        else:
            clean[letter] = list(pts)[0]
    return contradictions, clean


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def compose_perms(perm1, perm2):
    return [perm1[perm2[i]] for i in range(len(perm1))]


# ── Transposition generators (yield permutations one at a time) ─────────

def columnar_perm(width, col_order):
    nrows = math.ceil(CT_LEN / width)
    perm = []
    for col in col_order:
        for row in range(nrows):
            idx = row * width + col
            if idx < CT_LEN:
                perm.append(idx)
    return perm


def keyword_to_col_order(keyword):
    indexed = sorted(range(len(keyword)), key=lambda i: (keyword[i], i))
    order = [0] * len(keyword)
    for rank, idx in enumerate(indexed):
        order[idx] = rank
    return [i for i in sorted(range(len(keyword)), key=lambda i: order[i])]


def rail_fence_perm(n_rails):
    if n_rails < 2 or n_rails >= CT_LEN:
        return None
    rails = [[] for _ in range(n_rails)]
    rail = 0
    direction = 1
    for i in range(CT_LEN):
        rails[rail].append(i)
        rail += direction
        if rail == n_rails - 1 or rail == 0:
            direction = -direction
    perm = []
    for r in rails:
        perm.extend(r)
    return perm


def boustrophedon_perm(width):
    nrows = math.ceil(CT_LEN / width)
    perm = []
    for row in range(nrows):
        row_positions = []
        for col in range(width):
            idx = row * width + col
            if idx < CT_LEN:
                row_positions.append(idx)
        if row % 2 == 1:
            row_positions.reverse()
        perm.extend(row_positions)
    return perm


def skip_perm(skip_val):
    positions = []
    pos = 0
    seen = set()
    while len(positions) < CT_LEN:
        if pos in seen:
            for p in range(CT_LEN):
                if p not in seen:
                    pos = p
                    break
            else:
                break
        seen.add(pos)
        positions.append(pos)
        pos = (pos + skip_val) % CT_LEN
    return positions if len(positions) == CT_LEN else None


def diagonal_perm(width):
    nrows = math.ceil(CT_LEN / width)
    perm = []
    for d in range(nrows + width - 1):
        for row in range(max(0, d - width + 1), min(nrows, d + 1)):
            col = d - row
            if col < width:
                idx = row * width + col
                if idx < CT_LEN:
                    perm.append(idx)
    return perm if len(perm) == CT_LEN else None


def anti_diagonal_perm(width):
    nrows = math.ceil(CT_LEN / width)
    perm = []
    for d in range(nrows + width - 1):
        for row in range(max(0, d - width + 1), min(nrows, d + 1)):
            col = width - 1 - (d - row)
            if 0 <= col < width:
                idx = row * width + col
                if idx < CT_LEN:
                    perm.append(idx)
    return perm if len(perm) == CT_LEN else None


def main():
    random.seed(42)
    t_start = time.time()

    print("=" * 70)
    print("E-TEAM-TARGETED-HOMO-TRANS: Targeted contradiction resolver search")
    print("=" * 70)
    print()

    # ── Step 0: Document the 9 contradictions under identity ─────────────
    print("--- Step 0: Identity contradictions ---")
    identity = list(range(CT_LEN))
    contras, clean = get_contradiction_detail(identity)
    print(f"  {len(contras)} contradictions under identity:")
    for letter, info in sorted(contras.items()):
        print(f"    {letter} → {info['maps_to']}  (positions: {[(p, pt) for p, pt in info['positions']]})")
    print(f"  {len(clean)} clean mappings: {clean}")
    print()

    # ── Step 1-2: Stream test all structured transpositions ──────────────
    print("--- Steps 1-2: Streaming test of structured transpositions ---")

    total_tested = 0
    min_contra = 99
    contra_dist = defaultdict(int)
    zero_results = []
    best_results = []  # Store results with <= 2 contradictions
    low_contra_perms = []  # For double composition (store only <= 2)

    def test_perm(label, perm):
        nonlocal total_tested, min_contra
        if perm is None or len(perm) != CT_LEN:
            return
        nc = count_contradictions(perm)
        total_tested += 1
        contra_dist[nc] += 1
        if nc < min_contra:
            min_contra = nc
            print(f"  New minimum: {nc} contradictions ({label})")
        if nc == 0:
            zero_results.append({"label": label, "perm": perm[:]})
            print(f"  *** ZERO CONTRADICTIONS: {label} ***")
        if nc <= 2:
            best_results.append({"label": label, "contradictions": nc})
            low_contra_perms.append((label, perm[:]))

    # 1a. Columnar widths 7-9: enumerate ALL column orderings
    for width in range(7, 10):
        n_perms = math.factorial(width)
        print(f"  Columnar w={width}: {n_perms} orderings...")
        for col_order in itertools.permutations(range(width)):
            perm = columnar_perm(width, list(col_order))
            label = f"col_w{width}_{''.join(str(c) for c in col_order)}"
            test_perm(label, perm)
            test_perm(label + "_inv", invert_perm(perm))

    # 1b. Columnar widths 10-13: keyword orderings + random sample
    for width in range(10, 14):
        # Standard and reverse
        for col_order, suffix in [
            (list(range(width)), "std"),
            (list(range(width - 1, -1, -1)), "rev"),
        ]:
            perm = columnar_perm(width, col_order)
            test_perm(f"col_w{width}_{suffix}", perm)
            test_perm(f"col_w{width}_{suffix}_inv", invert_perm(perm))

        # Random column orderings for wider grids (10K samples)
        for trial in range(10000):
            col_order = list(range(width))
            random.shuffle(col_order)
            perm = columnar_perm(width, col_order)
            test_perm(f"col_w{width}_rand{trial}", perm)
            test_perm(f"col_w{width}_rand{trial}_inv", invert_perm(perm))

    print(f"  After columnar: {total_tested} tested, min={min_contra}")

    # 1c. Keyword-based columnar
    keywords = [
        "KRYPTOS", "BERLIN", "CLOCK", "PALIMPSEST", "ABSCISSA",
        "SHADOW", "FORCES", "UNDERGRUUND", "VIRTUALLY", "INVISIBLE",
        "DIGETAL", "INTERPRETATU", "DESPARATLY", "LAYERTWO",
        "NORTHEAST", "WELTZEITUHR", "SANBORN", "SCHEIDT",
        "WEBSTER", "DRUSILLA", "LANGLEY", "EAST", "NORTH",
        "EGYPT", "CAIRO", "THEPOINT", "IQLUSION", "SLOWLYDESPARATLY",
    ]
    for kw in keywords:
        if len(kw) < 3 or len(kw) > 20:
            continue
        col_order = keyword_to_col_order(kw)
        width = len(kw)
        perm = columnar_perm(width, col_order)
        test_perm(f"kw_{kw}", perm)
        test_perm(f"kw_{kw}_inv", invert_perm(perm))
    print(f"  After keywords: {total_tested} tested")

    # 1d. Rail fence
    for rails in range(2, 20):
        perm = rail_fence_perm(rails)
        if perm:
            test_perm(f"railfence_{rails}", perm)
            test_perm(f"railfence_{rails}_inv", invert_perm(perm))
    print(f"  After rail fence: {total_tested} tested")

    # 1e. Boustrophedon
    for width in range(5, 25):
        perm = boustrophedon_perm(width)
        test_perm(f"bous_w{width}", perm)
        test_perm(f"bous_w{width}_inv", invert_perm(perm))

    # 1f. Skip-N
    for skip_val in range(2, 96):
        perm = skip_perm(skip_val)
        if perm:
            test_perm(f"skip_{skip_val}", perm)
            test_perm(f"skip_{skip_val}_inv", invert_perm(perm))

    # 1g. Diagonal / anti-diagonal
    for width in range(5, 20):
        perm = diagonal_perm(width)
        if perm:
            test_perm(f"diag_w{width}", perm)
            test_perm(f"diag_w{width}_inv", invert_perm(perm))
        perm = anti_diagonal_perm(width)
        if perm:
            test_perm(f"anti_diag_w{width}", perm)
            test_perm(f"anti_diag_w{width}_inv", invert_perm(perm))

    # 1h. Reverse, rotations
    test_perm("reverse", list(range(CT_LEN - 1, -1, -1)))
    for rot in range(1, CT_LEN):
        perm = [(i + rot) % CT_LEN for i in range(CT_LEN)]
        test_perm(f"rotation_{rot}", perm)

    t_single = time.time()
    print(f"\n  Total single transpositions: {total_tested} in {t_single - t_start:.1f}s")
    print(f"  Minimum contradictions: {min_contra}")
    print(f"  Results with <= 2 contradictions: {len(best_results)}")
    print()

    # ── Step 3: Double transposition (compose pairs) ─────────────────────
    print("--- Step 3: Double transposition ---")

    # Base perms for composition
    base_perms = []
    for width in range(7, 14):
        for col_order in [list(range(width)), list(range(width - 1, -1, -1))]:
            perm = columnar_perm(width, col_order)
            if len(perm) == CT_LEN:
                base_perms.append((f"col_w{width}", perm))
                base_perms.append((f"col_w{width}_inv", invert_perm(perm)))
    for rails in range(2, 10):
        perm = rail_fence_perm(rails)
        if perm and len(perm) == CT_LEN:
            base_perms.append((f"rf_{rails}", perm))
            base_perms.append((f"rf_{rails}_inv", invert_perm(perm)))
    for sv in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
        perm = skip_perm(sv)
        if perm:
            base_perms.append((f"sk_{sv}", perm))
    for width in range(7, 14):
        perm = boustrophedon_perm(width)
        if len(perm) == CT_LEN:
            base_perms.append((f"bous_w{width}", perm))

    print(f"  Low-contradiction perms for composition: {len(low_contra_perms)}")
    print(f"  Base perms: {len(base_perms)}")

    double_tested = 0
    double_min = 99
    double_zero = []

    for label1, perm1 in low_contra_perms:
        for label2, perm2 in base_perms:
            # perm1 then perm2
            composed = compose_perms(perm1, perm2)
            nc = count_contradictions(composed)
            double_tested += 1
            if nc < double_min:
                double_min = nc
            if nc == 0:
                double_zero.append(f"{label1}+{label2}")
                print(f"  *** ZERO (double): {label1} + {label2} ***")

            # perm2 then perm1
            composed2 = compose_perms(perm2, perm1)
            nc2 = count_contradictions(composed2)
            double_tested += 1
            if nc2 < double_min:
                double_min = nc2
            if nc2 == 0:
                double_zero.append(f"{label2}+{label1}")
                print(f"  *** ZERO (double): {label2} + {label1} ***")

    t_double = time.time()
    print(f"  Double compositions tested: {double_tested} in {t_double - t_single:.1f}s")
    print(f"  Double minimum: {double_min}")
    print(f"  Double zeros: {len(double_zero)}")
    print()

    # ── Step 4: Perturbation search near best singles ────────────────────
    print("--- Step 4: Perturbation search ---")

    perturb_tested = 0
    perturb_min = 99
    perturb_zero = []

    # Take up to 100 best singles
    for label, perm in low_contra_perms[:100]:
        for trial in range(2000):
            mutant = perm[:]
            n_swaps = random.randint(1, 5)
            for _ in range(n_swaps):
                i, j = random.sample(range(CT_LEN), 2)
                mutant[i], mutant[j] = mutant[j], mutant[i]
            nc = count_contradictions(mutant)
            perturb_tested += 1
            if nc < perturb_min:
                perturb_min = nc
            if nc == 0:
                perturb_zero.append(f"perturb_{label}_t{trial}")
                print(f"  *** ZERO (perturb): base={label}, trial {trial} ***")

    t_perturb = time.time()
    print(f"  Perturbations tested: {perturb_tested} in {t_perturb - t_double:.1f}s")
    print(f"  Perturbation minimum: {perturb_min}")
    print(f"  Perturbation zeros: {len(perturb_zero)}")
    print()

    # ── Step 5: Analysis ─────────────────────────────────────────────────
    print("--- Step 5: Analysis ---")
    all_zeros = zero_results + [{"label": z} for z in double_zero] + [{"label": z} for z in perturb_zero]

    if all_zeros:
        print(f"  TOTAL ZERO-CONTRADICTION TRANSPOSITIONS: {len(all_zeros)}")
        for z in all_zeros[:20]:
            print(f"    {z['label']}")
            if 'perm' in z:
                contras, clean_map = get_contradiction_detail(z['perm'])
                print(f"    Clean mapping ({len(clean_map)} letters): {clean_map}")
    else:
        print(f"  NO zero-contradiction transpositions found.")
        print(f"  Best results (min contradictions):")
        sorted_best = sorted(best_results, key=lambda x: x['contradictions'])
        for r in sorted_best[:15]:
            print(f"    {r['contradictions']}: {r['label']}")
    print()

    # ── Summary ──────────────────────────────────────────────────────────
    grand_total = total_tested + double_tested + perturb_tested
    elapsed = time.time() - t_start

    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Total configurations: {grand_total:,d}")
    print(f"  Elapsed: {elapsed:.1f}s")
    print(f"  Single: {total_tested:,d} (min {min_contra})")
    print(f"  Double: {double_tested:,d} (min {double_min})")
    print(f"  Perturbation: {perturb_tested:,d} (min {perturb_min})")
    print(f"  Zero-contradiction: {len(all_zeros)}")
    print()

    print(f"  Single contradiction distribution:")
    for nc in sorted(contra_dist.keys()):
        pct = contra_dist[nc] * 100 / total_tested
        bar = "#" * max(1, int(pct / 2))
        print(f"    {nc:2d}: {contra_dist[nc]:8d} ({pct:5.2f}%) {bar}")
    print()

    overall_min = min(min_contra, double_min, perturb_min)
    if all_zeros:
        verdict = "SIGNAL"
        print("*** SIGNAL: Zero-contradiction transpositions found! ***")
    elif overall_min <= 1:
        verdict = "NEAR_MISS"
        print(f"Near-miss: {overall_min} contradiction(s). Homophonic + trans not eliminated.")
    else:
        verdict = "CONSTRAINED"
        print(f"Minimum {overall_min} contradictions across all tests.")

    print(f"\nVERDICT: {verdict}")

    # ── Save ─────────────────────────────────────────────────────────────
    output = {
        "experiment_id": "e_team_targeted_homo_trans",
        "description": "Targeted search for transpositions resolving homophonic contradictions",
        "total_tested": grand_total,
        "elapsed_s": round(elapsed, 1),
        "single_tested": total_tested,
        "single_min": min_contra,
        "single_distribution": {str(k): v for k, v in sorted(contra_dist.items())},
        "double_tested": double_tested,
        "double_min": double_min,
        "perturb_tested": perturb_tested,
        "perturb_min": perturb_min,
        "zero_count": len(all_zeros),
        "zero_labels": [z.get("label", z) for z in all_zeros[:50]],
        "best_singles": sorted(best_results, key=lambda x: x['contradictions'])[:30],
        "verdict": verdict,
    }

    results_path = os.path.join(os.path.dirname(__file__), "..", "results", "e_team_targeted_homo_trans.json")
    os.makedirs(os.path.dirname(results_path), exist_ok=True)
    with open(results_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to: {results_path}")


if __name__ == "__main__":
    main()
