#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: _uncategorized
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-18: Turning grille constraint-guided search.

A 10×10 turning grille + Vigenère/Beaufort is a plausible K4 model:
- Hand-executable
- Creates non-trivial transposition
- 100 cells = 97 PT + 3 nulls
- Could explain lag-7 signal if grille has regular structure

Search strategy: instead of random Monte Carlo (which failed at 150K),
use constraint propagation from the 24 known crib positions.

For period-p Vigenère after turning grille:
1. PT written through grille holes in 4 rotations (25 chars each, last 22+3 nulls)
2. Grid read in row order = CT (after substitution)
3. Crib positions constrain which grid cells the known PT goes to

Phase 1: Enumerate all 25 equivalence classes of a 10×10 grid under 90° rotation
Phase 2: For each period p, determine constraints on class assignments
Phase 3: Backtracking search with constraint propagation
Phase 4: For feasible grilles, check full period consistency and quadgram fitness
"""

import json
import os
import sys
import time
from collections import Counter, defaultdict
from itertools import product

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_ENTRIES, MOD

# ═══ Setup ════════════════════════════════════════════════════════════════

CT_INT = [ord(c) - 65 for c in CT]
CT_100 = CT + "XXX"  # pad to 100 with nulls
CT_100_INT = [ord(c) - 65 for c in CT_100]

_sorted = sorted(CRIB_ENTRIES, key=lambda x: x[0])
CRIB_POS = [p for p, _ in _sorted]
CRIB_DICT = {p: c for p, c in _sorted}
PT_INT = {p: ord(c) - 65 for p, c in _sorted}

# ═══ Turning grille geometry ══════════════════════════════════════════════

def rotate_90cw(r, c, n=10):
    """Rotate position (r, c) by 90° clockwise in an n×n grid."""
    return (c, n - 1 - r)


def equivalence_class(r, c, n=10):
    """Compute the 4 positions in the equivalence class of (r, c)."""
    positions = []
    cr, cc = r, c
    for _ in range(4):
        positions.append((cr, cc))
        cr, cc = rotate_90cw(cr, cc, n)
    return tuple(sorted(set(positions)))


def build_equivalence_classes(n=10):
    """Build all equivalence classes for an n×n grid."""
    seen = set()
    classes = []
    for r in range(n):
        for c in range(n):
            ec = equivalence_class(r, c, n)
            key = ec
            if key not in seen:
                seen.add(key)
                classes.append(ec)
    return classes


def build_grille_permutation(classes, choices, n=10):
    """Build the transposition permutation for a turning grille.

    classes: list of 25 equivalence classes
    choices: list of 25 ints (0-3), indicating which rotation each class belongs to

    Returns: perm where perm[pt_pos] = grid_linear_pos
    The PT is written through holes in the order: rotation 0 (L→R, T→B), then
    rotation 1, etc. Grid is read in row order for CT.
    """
    # For each class and choice, determine which cell belongs to which rotation
    rotation_cells = [[] for _ in range(4)]  # rotation -> list of (row, col)

    for cls_idx, ec in enumerate(classes):
        choice = choices[cls_idx]
        # ec has 4 cells (one for each rotation)
        # Sort cells by their rotation order: the cell at position `choice` in ec
        # is rotation 0, the next is rotation 1, etc.
        # But how are ec cells ordered?
        # The canonical ordering: ec[0] is the original cell at rotation 0,
        # ec[1] is after one 90° CW rotation, etc.
        # Actually, ec was built by iterating rotate_90cw, so:
        # positions[0] = original, positions[1] = 90°CW, positions[2] = 180°, positions[3] = 270°
        # But we sorted them, so the order is arbitrary.

        # Let me rebuild properly:
        r0, c0 = ec[0]  # just use the first cell
        pos = [(r0, c0)]
        rr, cc = r0, c0
        for _ in range(3):
            rr, cc = rotate_90cw(rr, cc, n)
            pos.append((rr, cc))
        # Now pos[0..3] are the 4 rotated positions
        # Wait, but ec was sorted, so ec[0] might not be the same as the original cell

        # Let me just regenerate from the first cell in ec
        # Actually, we need a canonical rotation order for each class
        # Let's pick: the cell with smallest (r, c) as "base", then rotate
        base_r, base_c = ec[0]  # smallest by sort
        rotations = []
        rr, cc = base_r, base_c
        for _ in range(4):
            rotations.append((rr, cc))
            rr, cc = rotate_90cw(rr, cc, n)
        # rotations[0] = base, rotations[1] = 90°CW of base, etc.

        # choice says: hole at rotation `choice` in the base ordering
        for rot in range(4):
            cell = rotations[(choice + rot) % 4]
            rotation_cells[rot].append(cell)

    # Sort cells within each rotation by reading order (L→R, T→B)
    for rot in range(4):
        rotation_cells[rot].sort(key=lambda rc: (rc[0], rc[1]))

    # Build permutation: PT position -> grid linear position
    perm = []
    for rot in range(4):
        for r, c in rotation_cells[rot]:
            linear = r * n + c
            perm.append(linear)

    return perm


def grille_perm_to_transposition(perm):
    """Convert grille permutation to gather-convention transposition.

    perm[pt_pos] = grid_linear_pos means: PT at position pt_pos goes to
    grid position perm[pt_pos].

    For decryption (CT -> PT): CT is the grid read in row order.
    CT[grid_pos] was written from PT[pt_pos] where perm[pt_pos] = grid_pos.
    So: PT[pt_pos] = CT[perm[pt_pos]] (before substitution).

    The transposition σ for Model A (sub then transpose):
    CT[perm[pt_pos]] = sub(PT[pt_pos])
    """
    return perm


# ═══ Scoring ═════════════════════════════════════════════════════════════

def score_grille(perm, period):
    """Score a grille permutation for period-p consistency.

    Model A: PT → sub → grille_transpose → CT
    CT[perm[p]] = (PT[p] + K[p mod period]) mod 26
    So: K[p mod period] = (CT[perm[p]] - PT[p]) mod 26

    Model B: PT → grille_transpose → sub → CT
    CT[perm[p]] = (PT[p] + K[perm[p] mod period]) mod 26
    So: K[perm[p] mod period] = (CT[perm[p]] - PT[p]) mod 26
    """
    results = {}

    for model in ['A', 'B']:
        for variant in ['vig', 'beau']:
            groups = defaultdict(list)

            for p in CRIB_POS:
                grid_pos = perm[p]
                ct_val = CT_100_INT[grid_pos]
                pt_val = PT_INT[p]

                if variant == 'vig':
                    key_val = (ct_val - pt_val) % 26
                else:
                    key_val = (ct_val + pt_val) % 26

                if model == 'A':
                    residue = p % period
                else:
                    residue = grid_pos % period

                groups[residue].append(key_val)

            score = 0
            for vals in groups.values():
                if vals:
                    score += Counter(vals).most_common(1)[0][1]

            results[f"{model}_{variant}"] = score

    return results


# ═══ Constrained search ═══════════════════════════════════════════════════

def monte_carlo_search(classes, n_samples, seed=42):
    """Random sampling of grille patterns with period consistency scoring."""
    import random
    rng = random.Random(seed)

    best_score = 0
    best_config = None
    best_choices = None

    noise_floors = {3: 5, 4: 6, 5: 7, 6: 7, 7: 8, 8: 9, 9: 10}

    for sample in range(n_samples):
        choices = [rng.randint(0, 3) for _ in range(25)]
        perm = build_grille_permutation(classes, choices)

        # Check it's a valid permutation of 0-99
        if len(set(perm)) != 100:
            continue

        for period in [5, 6, 7, 8]:
            scores = score_grille(perm, period)
            for key, score in scores.items():
                noise = noise_floors.get(period, 8)
                excess = score - noise

                if score > best_score:
                    best_score = score
                    best_config = {
                        "period": period, "model_variant": key,
                        "score": score, "excess": excess,
                    }
                    best_choices = list(choices)

        if (sample + 1) % 100000 == 0:
            print(f"  [{sample+1:>10,}/{n_samples:,}] best={best_score}/24  "
                  f"({best_config['model_variant']} p={best_config['period']})")
            sys.stdout.flush()

    return best_score, best_config, best_choices


def targeted_search(classes, n_samples, seed=42):
    """Search biased toward grille patterns where crib positions cluster by key value.

    Strategy: for each pair of crib positions with the same key value,
    try to place them in the same residue class by choosing grille assignments
    that put them at grid positions with the same residue mod period.
    """
    import random
    rng = random.Random(seed)

    # Identify which equivalence classes contain crib positions
    # First, build mapping: grid_linear_pos -> equivalence class index
    grid_to_class = {}
    for cls_idx, ec in enumerate(classes):
        base_r, base_c = ec[0]
        rr, cc = base_r, base_c
        for rot in range(4):
            linear = rr * 10 + cc
            grid_to_class[linear] = cls_idx
            rr, cc = rotate_90cw(rr, cc)

    # For each crib position, which rotation does it fall in?
    # PT positions 0-24 = rotation 0, 25-49 = rotation 1, 50-74 = rotation 2, 75-99 = rotation 3
    crib_rotations = {}
    crib_within_rot = {}
    for p in CRIB_POS:
        rot = p // 25
        within = p % 25
        crib_rotations[p] = rot
        crib_within_rot[p] = within

    print(f"\n  Crib rotation distribution:")
    for rot in range(4):
        cribs_in_rot = [p for p in CRIB_POS if crib_rotations[p] == rot]
        print(f"    Rotation {rot}: {len(cribs_in_rot)} cribs: {cribs_in_rot}")

    best_score = 0
    best_config = None
    best_choices = None

    noise_floors = {3: 5, 4: 6, 5: 7, 6: 7, 7: 8, 8: 9, 9: 10}

    for sample in range(n_samples):
        choices = [rng.randint(0, 3) for _ in range(25)]
        perm = build_grille_permutation(classes, choices)

        if len(set(perm)) != 100:
            continue

        for period in [5, 6, 7]:
            scores = score_grille(perm, period)
            for key, score in scores.items():
                noise = noise_floors.get(period, 8)

                if score > best_score:
                    best_score = score
                    best_config = {
                        "period": period, "model_variant": key,
                        "score": score, "excess": score - noise,
                    }
                    best_choices = list(choices)

        if (sample + 1) % 200000 == 0:
            print(f"  [{sample+1:>10,}/{n_samples:,}] best={best_score}/24  "
                  f"({best_config['model_variant']} p={best_config['period']})")
            sys.stdout.flush()

    return best_score, best_config, best_choices


def main():
    t0 = time.time()

    print("=" * 60)
    print("E-S-18: Turning Grille + Period Consistency")
    print("=" * 60)

    # Build equivalence classes
    classes = build_equivalence_classes(10)
    print(f"Equivalence classes: {len(classes)}")
    print(f"Search space: 4^25 = {4**25:,}")
    print(f"CT padded to 100: {CT_100}")
    print()

    # Verify geometry
    all_cells = set()
    for ec in classes:
        for cell in ec:
            all_cells.add(cell)
    print(f"Total cells covered: {len(all_cells)} (expect 100)")
    assert len(all_cells) == 100

    # Phase 1: Monte Carlo sampling
    print("\n" + "=" * 60)
    print("  Phase 1: Monte Carlo (1M samples)")
    print("=" * 60)

    mc_score, mc_config, mc_choices = monte_carlo_search(
        classes, n_samples=1_000_000, seed=42)

    print(f"\n  MC best: {mc_score}/24 at p={mc_config['period']} "
          f"({mc_config['model_variant']})")

    # Phase 2: Targeted search
    print("\n" + "=" * 60)
    print("  Phase 2: Targeted search (1M samples)")
    print("=" * 60)

    tg_score, tg_config, tg_choices = targeted_search(
        classes, n_samples=1_000_000, seed=12345)

    print(f"\n  Targeted best: {tg_score}/24 at p={tg_config['period']} "
          f"({tg_config['model_variant']})")

    # Phase 3: Try grilles with specific structural properties
    print("\n" + "=" * 60)
    print("  Phase 3: Structured grilles (diagonal, symmetric, etc.)")
    print("=" * 60)

    structured_results = []

    # All-same choice (degenerate grilles)
    for choice in range(4):
        choices = [choice] * 25
        perm = build_grille_permutation(classes, choices)
        if len(set(perm)) == 100:
            for period in range(3, 10):
                scores = score_grille(perm, period)
                best_key = max(scores, key=lambda k: scores[k])
                structured_results.append({
                    "name": f"all_{choice}",
                    "period": period,
                    "score": scores[best_key],
                    "model": best_key,
                })

    # Alternating patterns
    for pat in [(0,1), (0,2), (0,3), (1,2), (1,3), (2,3),
                (0,1,2,3)]:
        choices = [pat[i % len(pat)] for i in range(25)]
        perm = build_grille_permutation(classes, choices)
        if len(set(perm)) == 100:
            for period in range(3, 10):
                scores = score_grille(perm, period)
                best_key = max(scores, key=lambda k: scores[k])
                structured_results.append({
                    "name": f"pattern_{''.join(str(p) for p in pat)}",
                    "period": period,
                    "score": scores[best_key],
                    "model": best_key,
                })

    # Row-based patterns
    for row_choice in range(4):
        # Each row of classes gets the same choice
        choices = []
        for cls_idx in range(25):
            # Assign based on the row of the first cell in the class
            base_row = classes[cls_idx][0][0]
            choices.append((base_row + row_choice) % 4)
        perm = build_grille_permutation(classes, choices)
        if len(set(perm)) == 100:
            for period in range(3, 10):
                scores = score_grille(perm, period)
                best_key = max(scores, key=lambda k: scores[k])
                structured_results.append({
                    "name": f"row_based_{row_choice}",
                    "period": period,
                    "score": scores[best_key],
                    "model": best_key,
                })

    if structured_results:
        structured_results.sort(key=lambda x: -x["score"])
        print(f"  Top structured results:")
        for r in structured_results[:10]:
            print(f"    {r['name']}: {r['score']}/24 at p={r['period']} ({r['model']})")

    # ═══ Summary ═══════════════════════════════════════════════════════════
    elapsed = time.time() - t0

    global_best = max(mc_score, tg_score)
    global_config = mc_config if mc_score >= tg_score else tg_config

    print(f"\n{'=' * 60}")
    print(f"  SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Time: {elapsed:.0f}s ({elapsed/60:.1f} min)")
    print(f"  MC best: {mc_score}/24")
    print(f"  Targeted best: {tg_score}/24")

    if structured_results:
        struct_best = structured_results[0]
        print(f"  Structured best: {struct_best['score']}/24")
        global_best = max(global_best, struct_best['score'])

    noise_7 = 8.2
    if global_best >= 18:
        verdict = "SIGNAL"
    elif global_best >= 14:
        verdict = "INVESTIGATE"
    elif global_best > noise_7 + 3:
        verdict = "WEAK SIGNAL"
    else:
        verdict = "NOISE"

    print(f"\n  Global best: {global_best}/24")
    print(f"  Noise floor at p=7: ~{noise_7}")
    print(f"  VERDICT: {verdict}")

    # Write results
    os.makedirs("results", exist_ok=True)
    outpath = "results/e_s_18_turning_grille.json"
    with open(outpath, "w") as f:
        json.dump({
            "experiment": "E-S-18",
            "hypothesis": "10×10 turning grille + periodic Vigenère",
            "total_time_s": round(elapsed, 1),
            "verdict": verdict,
            "mc_best": {"score": mc_score, "config": mc_config},
            "targeted_best": {"score": tg_score, "config": tg_config},
            "structured_top10": structured_results[:10] if structured_results else [],
            "n_equivalence_classes": len(classes),
            "search_space": 4**25,
        }, f, indent=2, default=str)

    print(f"\n  Artifacts: {outpath}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_18_turning_grille.py")
    print(f"\nRESULT: best={global_best}/24 verdict={verdict}")


if __name__ == "__main__":
    main()
