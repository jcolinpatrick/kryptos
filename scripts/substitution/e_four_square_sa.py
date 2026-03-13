#!/usr/bin/env python3
"""
Four-Square cipher simulated annealing attack on K4.

Cipher:  Four-Square (digraphic substitution)
Family:  substitution
Status:  active
Keyspace: 4 × 25! (mixed Four-Square, all grids keyword-mixed, I/J merged)
Last run: never
Best score: N/A

Strategy: Simulated annealing on all four 5×5 matrices simultaneously.
Uses quadgram scoring + crib matching bonus.
Tests start=0 alignment (proven consistent with cribs; start=1 eliminated).
"""

import json
import math
import random
import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from kryptos.kernel.constants import CT, CRIB_DICT

# ── Alphabet (I/J merged, 25 letters) ──────────────────────────────────────
ALPHA25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # no J
assert len(ALPHA25) == 25
assert len(set(ALPHA25)) == 25

CHAR_TO_IDX25 = {c: i for i, c in enumerate(ALPHA25)}

def merge_ij(ch):
    """Merge J→I for 25-letter alphabet."""
    return 'I' if ch == 'J' else ch

# ── Load quadgrams ──────────────────────────────────────────────────────────
QG_PATH = Path(__file__).resolve().parents[2] / "data" / "english_quadgrams.json"
with open(QG_PATH) as f:
    _raw_qg = json.load(f)

# Convert to log probabilities indexed by 4-char tuples for speed
# Pre-compute floor for missing quadgrams
_qg_total = sum(10**v for v in _raw_qg.values())  # approximate
QG_FLOOR = min(_raw_qg.values()) - 1.0  # worse than worst known

def quadgram_score(text: str) -> float:
    """Score text by sum of log10 quadgram probabilities."""
    score = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        score += _raw_qg.get(qg, QG_FLOOR)
    return score

def quadgram_per_char(text: str) -> float:
    n = len(text) - 3
    if n <= 0:
        return QG_FLOOR
    return quadgram_score(text) / n


# ── Four-Square cipher operations ──────────────────────────────────────────

def make_grid(letters: str) -> list:
    """Convert 25-char string to 5×5 grid (list of lists)."""
    assert len(letters) == 25
    return [list(letters[i*5:(i+1)*5]) for i in range(5)]

def find_in_grid(grid: list, ch: str) -> tuple:
    """Find (row, col) of character in 5×5 grid."""
    for r in range(5):
        for c in range(5):
            if grid[r][c] == ch:
                return (r, c)
    raise ValueError(f"{ch} not found in grid")

def make_lookup(grid: list) -> dict:
    """Create char→(row,col) lookup from grid."""
    return {grid[r][c]: (r, c) for r in range(5) for c in range(5)}

def four_square_decrypt(ct_text: str, p1: list, p2: list, c1: list, c2: list, start: int = 0) -> str:
    """Decrypt ciphertext using Four-Square with given alignment."""
    ct = [merge_ij(ch) for ch in ct_text]
    c1_lookup = make_lookup(c1)
    c2_lookup = make_lookup(c2)

    pt = []
    i = start
    while i + 1 < len(ct):
        ct1, ct2 = ct[i], ct[i+1]
        r1, j1 = c1_lookup[ct1]
        r2, j2 = c2_lookup[ct2]
        pt1 = p1[r1][j2]
        pt2 = p2[r2][j1]
        pt.append(pt1)
        pt.append(pt2)
        i += 2

    # Handle odd remaining character
    if i < len(ct):
        pt.append(ct[i])  # pass through

    return ''.join(pt)

def four_square_encrypt(pt_text: str, p1: list, p2: list, c1: list, c2: list, start: int = 0) -> str:
    """Encrypt plaintext using Four-Square."""
    pt = [merge_ij(ch) for ch in pt_text]
    p1_lookup = make_lookup(p1)
    p2_lookup = make_lookup(p2)

    ct = []
    i = start
    while i + 1 < len(pt):
        pt1, pt2 = pt[i], pt[i+1]
        r1, k1 = p1_lookup[pt1]
        r2, k2 = p2_lookup[pt2]
        ct1 = c1[r1][k2]
        ct2 = c2[r2][k1]
        ct.append(ct1)
        ct.append(ct2)
        i += 2

    if i < len(pt):
        ct.append(pt[i])

    return ''.join(ct)


# ── Crib scoring ───────────────────────────────────────────────────────────

def crib_score(plaintext: str) -> int:
    """Count how many crib positions match."""
    matches = 0
    for pos, expected in CRIB_DICT.items():
        if pos < len(plaintext):
            actual = plaintext[pos]
            # J→I merge for comparison
            if merge_ij(actual) == merge_ij(expected):
                matches += 1
    return matches


# ── Simulated Annealing ───────────────────────────────────────────────────

def random_perm25() -> str:
    """Random permutation of 25-letter alphabet."""
    letters = list(ALPHA25)
    random.shuffle(letters)
    return ''.join(letters)

def swap_in_grid(grid_str: str) -> str:
    """Swap two random positions in a 25-char grid string."""
    lst = list(grid_str)
    i, j = random.sample(range(25), 2)
    lst[i], lst[j] = lst[j], lst[i]
    return ''.join(lst)

def keyword_square(keyword: str, omit_j: bool = True) -> str:
    """Generate keyword-mixed 5×5 square."""
    seen = set()
    result = []
    kw = keyword.upper().replace('J', 'I') if omit_j else keyword.upper()
    for ch in kw:
        if ch in ALPHA25 and ch not in seen:
            result.append(ch)
            seen.add(ch)
    for ch in ALPHA25:
        if ch not in seen:
            result.append(ch)
            seen.add(ch)
    return ''.join(result)


def sa_attack(ct_text: str = CT, start: int = 0,
              n_restarts: int = 50, steps_per_restart: int = 50000,
              t_start: float = 1.0, t_end: float = 0.01,
              crib_weight: float = 5.0,
              seed: int = None, verbose: bool = True):
    """
    Simulated annealing attack on Four-Square cipher.

    Optimizes all four 5×5 grids to maximize quadgram score + crib matches.
    """
    if seed is not None:
        random.seed(seed)

    best_global_score = -float('inf')
    best_global_pt = ""
    best_global_grids = None
    best_global_crib = 0

    ct_merged = ''.join(merge_ij(ch) for ch in ct_text)

    for restart in range(n_restarts):
        # Initialize with random grids
        grids = [random_perm25() for _ in range(4)]  # p1, c1, c2, p2

        p1 = make_grid(grids[0])
        c1 = make_grid(grids[1])
        c2 = make_grid(grids[2])
        p2 = make_grid(grids[3])

        pt = four_square_decrypt(ct_merged, p1, p2, c1, c2, start)
        qg = quadgram_score(pt)
        cs = crib_score(pt)
        current_score = qg + cs * crib_weight

        best_score = current_score
        best_pt = pt
        best_grids = list(grids)
        best_crib = cs

        for step in range(steps_per_restart):
            # Temperature schedule (exponential decay)
            t = t_start * (t_end / t_start) ** (step / max(steps_per_restart - 1, 1))

            # Mutate: pick a random grid and swap two letters
            grid_idx = random.randint(0, 3)
            new_grids = list(grids)
            new_grids[grid_idx] = swap_in_grid(grids[grid_idx])

            np1 = make_grid(new_grids[0])
            nc1 = make_grid(new_grids[1])
            nc2 = make_grid(new_grids[2])
            np2 = make_grid(new_grids[3])

            npt = four_square_decrypt(ct_merged, np1, np2, nc1, nc2, start)
            nqg = quadgram_score(npt)
            ncs = crib_score(npt)
            new_score = nqg + ncs * crib_weight

            delta = new_score - current_score
            if delta > 0 or random.random() < math.exp(delta / t):
                grids = new_grids
                current_score = new_score
                pt = npt
                cs = ncs

                if new_score > best_score:
                    best_score = new_score
                    best_pt = npt
                    best_grids = list(new_grids)
                    best_crib = ncs

        if verbose and (restart % 5 == 0 or best_crib >= 3):
            print(f"  Restart {restart:3d}: best_qg={quadgram_per_char(best_pt):.3f} "
                  f"crib={best_crib}/24 | {best_pt[:40]}...")

        if best_score > best_global_score:
            best_global_score = best_score
            best_global_pt = best_pt
            best_global_grids = list(best_grids)
            best_global_crib = best_crib

            if verbose and best_global_crib >= 5:
                print(f"\n*** NEW GLOBAL BEST: crib={best_global_crib}/24 "
                      f"qg={quadgram_per_char(best_global_pt):.3f}")
                print(f"    PT: {best_global_pt}")
                print(f"    p1: {best_global_grids[0]}")
                print(f"    c1: {best_global_grids[1]}")
                print(f"    c2: {best_global_grids[2]}")
                print(f"    p2: {best_global_grids[3]}")
                print()

    return best_global_pt, best_global_grids, best_global_crib, best_global_score


def attack(ciphertext: str = CT, **params) -> list:
    """Standard attack interface. Returns [(score, plaintext, method), ...]."""
    results = []

    # Test start=0 (the consistent alignment)
    for alignment in [0]:
        print(f"\n{'='*70}")
        print(f"Four-Square SA Attack — alignment={alignment}")
        print(f"{'='*70}")

        # Phase 1: Wide search with many restarts
        print("\nPhase 1: Wide search (50 restarts × 50K steps)")
        pt, grids, cs, score = sa_attack(
            ciphertext, start=alignment,
            n_restarts=50, steps_per_restart=50000,
            t_start=2.0, t_end=0.005,
            crib_weight=8.0,
            verbose=True
        )

        qg_pc = quadgram_per_char(pt)
        print(f"\nPhase 1 best: crib={cs}/24, qg/c={qg_pc:.3f}")
        print(f"  PT: {pt}")
        results.append((cs + qg_pc * 3, pt,
                        f"FourSquare-SA align={alignment} crib={cs}/24 qg={qg_pc:.3f}"))

        # Phase 2: Deep search from best starting point
        if cs >= 3:
            print(f"\nPhase 2: Deep refinement (20 restarts × 200K steps)")
            pt2, grids2, cs2, score2 = sa_attack(
                ciphertext, start=alignment,
                n_restarts=20, steps_per_restart=200000,
                t_start=0.5, t_end=0.001,
                crib_weight=15.0,
                verbose=True
            )
            qg_pc2 = quadgram_per_char(pt2)
            print(f"\nPhase 2 best: crib={cs2}/24, qg/c={qg_pc2:.3f}")
            print(f"  PT: {pt2}")
            results.append((cs2 + qg_pc2 * 3, pt2,
                           f"FourSquare-SA-deep align={alignment} crib={cs2}/24 qg={qg_pc2:.3f}"))

    results.sort(key=lambda x: -x[0])
    return results


if __name__ == "__main__":
    print("Four-Square SA Attack on K4")
    print(f"CT: {CT}")
    print(f"CT len: {len(CT)}")
    print(f"Cribs: {len(CRIB_DICT)} positions")
    print(f"Alignment: start=0 (proven consistent)")
    print()

    t0 = time.time()
    results = attack()
    elapsed = time.time() - t0

    print(f"\n{'='*70}")
    print(f"RESULTS (elapsed: {elapsed:.1f}s)")
    print(f"{'='*70}")
    for score, pt, method in results[:5]:
        print(f"  [{score:.1f}] {method}")
        print(f"         {pt}")

    # Also test: what's the quadgram score of random Four-Square decryption?
    print(f"\n--- Random baseline ---")
    random.seed(12345)
    baseline_scores = []
    baseline_cribs = []
    for _ in range(100):
        g = [random_perm25() for _ in range(4)]
        p = four_square_decrypt(
            ''.join(merge_ij(ch) for ch in CT),
            make_grid(g[0]), make_grid(g[3]), make_grid(g[1]), make_grid(g[2]), 0
        )
        baseline_scores.append(quadgram_per_char(p))
        baseline_cribs.append(crib_score(p))

    avg_qg = sum(baseline_scores) / len(baseline_scores)
    max_qg = max(baseline_scores)
    avg_cs = sum(baseline_cribs) / len(baseline_cribs)
    max_cs = max(baseline_cribs)
    print(f"  Random qg/c: avg={avg_qg:.3f}, max={max_qg:.3f}")
    print(f"  Random crib: avg={avg_cs:.1f}, max={max_cs}")
