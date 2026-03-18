#!/usr/bin/env python3
"""
E-FOUR-SQUARE-NULL-MASK: Four-Square cipher on 72/73-char extracts after null removal.

Tests the two-system model: K4 = Four-Square encrypt on 72/73 plaintext digraphs,
then insert 24/25 nulls to get the 97 carved characters.

Model A (72 chars): 72 PT -> Four-Square (36 digraphs) -> 72 CT -> insert 25 nulls -> 97
Model B (73 chars): 73 PT -> Four-Square (36 digraphs + 1 extra) -> 73 CT -> insert 24 nulls -> 97

Algorithm:
  1. SA over null mask (which 24/25 of 97 positions are nulls)
  2. Extract non-null characters -> 72/73 chars
  3. Four-Square decrypt using two keyword-mixed 5x5 alphabets
  4. Score against cribs (mapped through null mask)
  5. Track best score, mask, keywords

For the 5x5 grid: all 26 letters appear in CT. Removing 25 nulls may leave <=25
distinct letters (perfect for 5x5 with I/J merge). Removing 24 nulls (73 chars)
with I/J merge also works.

Cipher: four-square-null-mask
Family: substitution
Status: active
Keyspace: ~C(97,24) * |keywords|^2 * 2 parities (SA-sampled)
Last run: never
Best score: N/A
"""

import json
import math
import random
import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from kryptos.kernel.constants import CT, CRIB_DICT, CT_LEN

# ── Constants ────────────────────────────────────────────────────────────────

ALPHA25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # no J, I/J merged
assert len(ALPHA25) == 25 and len(set(ALPHA25)) == 25

CRIB_POSITIONS = sorted(CRIB_DICT.keys())
ENE_POSITIONS = [p for p in CRIB_POSITIONS if 21 <= p <= 33]
BCL_POSITIONS = [p for p in CRIB_POSITIONS if 63 <= p <= 73]

# Keywords to test for the two CT squares (c1, c2)
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "KOMPASS",
    "COLOPHON", "PARALLAX", "SHADOW", "LODESTONE", "QUAGMIRE",
    "BERLINCLOCK", "EASTNORTHEAST", "YELLOW",
]

# ── Load quadgrams ──────────────────────────────────────────────────────────

QG_PATH = Path(__file__).resolve().parents[2] / "data" / "english_quadgrams.json"
with open(QG_PATH) as f:
    _raw_qg = json.load(f)
QG_FLOOR = min(_raw_qg.values()) - 1.0


def quadgram_score(text: str) -> float:
    """Sum of log10 quadgram probabilities."""
    return sum(_raw_qg.get(text[i:i+4], QG_FLOOR) for i in range(len(text) - 3))


def quadgram_per_char(text: str) -> float:
    n = len(text) - 3
    return quadgram_score(text) / n if n > 0 else QG_FLOOR


# ── I/J merge ────────────────────────────────────────────────────────────────

def merge_ij(ch: str) -> str:
    return "I" if ch == "J" else ch


# ── Four-Square operations ───────────────────────────────────────────────────

def make_grid(letters: str) -> list:
    """Convert 25-char string to 5x5 grid."""
    assert len(letters) == 25
    return [list(letters[i*5:(i+1)*5]) for i in range(5)]


def make_lookup(grid: list) -> dict:
    """Create char -> (row, col) lookup from 5x5 grid."""
    return {grid[r][c]: (r, c) for r in range(5) for c in range(5)}


def keyword_square(keyword: str) -> str:
    """Generate keyword-mixed 25-letter square (I/J merged)."""
    seen = set()
    result = []
    kw = keyword.upper().replace("J", "I")
    for ch in kw:
        if ch in set(ALPHA25) and ch not in seen:
            result.append(ch)
            seen.add(ch)
    for ch in ALPHA25:
        if ch not in seen:
            result.append(ch)
            seen.add(ch)
    return "".join(result)


def four_square_decrypt(ct_text: str, p1: list, p2: list,
                        c1: list, c2: list, start: int = 0) -> str:
    """
    Decrypt ciphertext using Four-Square.

    Standard Four-Square layout:
      p1 (top-left, PT)     c1 (top-right, CT)
      c2 (bottom-left, CT)  p2 (bottom-right, PT)

    To decrypt digraph (a, b):
      Find a in c1 -> (r1, j1)
      Find b in c2 -> (r2, j2)
      PT1 = p1[r1][j2]
      PT2 = p2[r2][j1]
    """
    c1_lk = make_lookup(c1)
    c2_lk = make_lookup(c2)
    pt = []
    i = start
    while i + 1 < len(ct_text):
        a, b = ct_text[i], ct_text[i+1]
        r1, j1 = c1_lk[a]
        r2, j2 = c2_lk[b]
        pt.append(p1[r1][j2])
        pt.append(p2[r2][j1])
        i += 2
    # Handle odd remaining char (pass through)
    if i < len(ct_text):
        pt.append(ct_text[i])
    return "".join(pt)


# ── Null mask operations ────────────────────────────────────────────────────

def map_positions(null_set: set) -> dict:
    """
    Map 97-char positions to extracted-text positions after null removal.

    Returns dict: {pos_97: pos_extracted} for non-null positions.
    """
    mapping = {}
    extracted_idx = 0
    for pos in range(CT_LEN):
        if pos not in null_set:
            mapping[pos] = extracted_idx
            extracted_idx += 1
    return mapping


def build_shifted_cribs(null_set: set) -> dict:
    """
    Build crib dict with positions shifted for the extracted text.

    Crib positions that fall on null positions are dropped.
    Returns {extracted_pos: expected_char}.
    """
    pos_map = map_positions(null_set)
    shifted = {}
    for pos, ch in CRIB_DICT.items():
        if pos in pos_map:
            shifted[pos_map[pos]] = ch
    return shifted


def extract_text(null_set: set) -> str:
    """Extract non-null chars from CT."""
    return "".join(CT[i] for i in range(CT_LEN) if i not in null_set)


def crib_score_shifted(plaintext: str, shifted_cribs: dict) -> tuple:
    """
    Score plaintext against shifted cribs. Returns (total, ene, bcl).

    We track ENE and BCL separately using the original 97-pos crib boundaries.
    """
    pos_map_inv = {}  # We need to know which original positions these came from
    total = 0
    for pos, expected in shifted_cribs.items():
        if pos < len(plaintext):
            if merge_ij(plaintext[pos]) == merge_ij(expected):
                total += 1
    return total


def crib_score_detailed(plaintext: str, null_set: set) -> tuple:
    """
    Score plaintext against cribs, returning (total, ene_score, bcl_score).

    Maps original crib positions through the null mask.
    """
    pos_map = map_positions(null_set)
    ene = 0
    bcl = 0
    for pos, expected in CRIB_DICT.items():
        if pos not in pos_map:
            continue  # crib position is a null -- skip
        mapped = pos_map[pos]
        if mapped < len(plaintext):
            if merge_ij(plaintext[mapped]) == merge_ij(expected):
                if pos in range(21, 34):
                    ene += 1
                elif pos in range(63, 74):
                    bcl += 1
    return ene + bcl, ene, bcl


# ── Random null mask generation ─────────────────────────────────────────────

def random_null_mask(n_nulls: int) -> set:
    """Generate a random null mask selecting n_nulls positions from 0..96."""
    return set(random.sample(range(CT_LEN), n_nulls))


def mutate_mask(mask: set, n_nulls: int) -> set:
    """Swap one null position with one non-null position."""
    null_list = list(mask)
    non_null_list = [i for i in range(CT_LEN) if i not in mask]
    to_remove = random.choice(null_list)
    to_add = random.choice(non_null_list)
    new_mask = set(mask)
    new_mask.discard(to_remove)
    new_mask.add(to_add)
    return new_mask


# ── SA over null mask + keyword Four-Square ──────────────────────────────────

def sa_null_mask_keyword(
    n_nulls: int,
    c1_kw: str, c2_kw: str,
    parity: int = 0,
    n_restarts: int = 50,
    steps: int = 5000,
    t_start: float = 2.0,
    t_end: float = 0.01,
) -> tuple:
    """
    SA over null masks with fixed keyword squares.

    PT squares (p1, p2) = standard ALPHA25.
    CT squares (c1, c2) = keyword-mixed from c1_kw, c2_kw.

    Returns (best_score, best_ene, best_bcl, best_mask, best_pt, desc).
    """
    # Build fixed grids
    p1 = make_grid(ALPHA25)
    p2 = make_grid(ALPHA25)
    c1_str = keyword_square(c1_kw)
    c2_str = keyword_square(c2_kw)
    c1 = make_grid(c1_str)
    c2 = make_grid(c2_str)

    best_global = (0, 0, 0, set(), "", "")

    for restart in range(n_restarts):
        mask = random_null_mask(n_nulls)

        # Extract and decrypt
        extracted = "".join(merge_ij(ch) for ch in extract_text(mask))
        pt = four_square_decrypt(extracted, p1, p2, c1, c2, parity)
        total, ene, bcl = crib_score_detailed(pt, mask)

        current_score = total
        current_mask = mask
        best_score = total
        best_mask = set(mask)
        best_ene = ene
        best_bcl = bcl
        best_pt = pt

        for step in range(steps):
            t = t_start * (t_end / t_start) ** (step / max(steps - 1, 1))

            new_mask = mutate_mask(current_mask, n_nulls)
            new_extracted = "".join(merge_ij(ch) for ch in extract_text(new_mask))
            new_pt = four_square_decrypt(new_extracted, p1, p2, c1, c2, parity)
            new_total, new_ene, new_bcl = crib_score_detailed(new_pt, new_mask)

            delta = new_total - current_score
            if delta > 0 or (t > 0 and random.random() < math.exp(delta / t)):
                current_mask = new_mask
                current_score = new_total

                if new_total > best_score:
                    best_score = new_total
                    best_mask = set(new_mask)
                    best_ene = new_ene
                    best_bcl = new_bcl
                    best_pt = new_pt

        if best_score > best_global[0]:
            desc = f"c1={c1_kw}|c2={c2_kw}|par={parity}|nulls={n_nulls}"
            best_global = (best_score, best_ene, best_bcl, best_mask, best_pt, desc)

    return best_global


def sa_null_mask_full_sa(
    n_nulls: int,
    parity: int = 0,
    n_restarts: int = 20,
    steps: int = 10000,
    t_start: float = 2.0,
    t_end: float = 0.005,
    crib_weight: float = 20.0,
) -> tuple:
    """
    Full SA over null masks AND four 5x5 grids simultaneously.

    This is the most flexible mode: optimizes both which positions are nulls
    and all four grids. Uses quadgram + crib scoring.

    Returns (best_crib, best_ene, best_bcl, best_mask, best_pt, best_grids, desc).
    """
    best_global = (0, 0, 0, set(), "", None, "")

    for restart in range(n_restarts):
        # Initialize random mask and random grids
        mask = random_null_mask(n_nulls)
        grids = []
        for _ in range(4):
            letters = list(ALPHA25)
            random.shuffle(letters)
            grids.append("".join(letters))

        # Decrypt
        extracted = "".join(merge_ij(ch) for ch in extract_text(mask))
        p1, c1, c2, p2 = [make_grid(g) for g in grids]
        pt = four_square_decrypt(extracted, p1, p2, c1, c2, parity)
        total, ene, bcl = crib_score_detailed(pt, mask)
        qg = quadgram_score(pt)
        current_score = qg + total * crib_weight

        best_score = current_score
        best_mask = set(mask)
        best_grids = list(grids)
        best_pt = pt
        best_crib = total
        best_ene = ene
        best_bcl = bcl

        for step in range(steps):
            t = t_start * (t_end / t_start) ** (step / max(steps - 1, 1))

            # Randomly choose: mutate mask (30%) or mutate a grid (70%)
            if random.random() < 0.3:
                new_mask = mutate_mask(mask, n_nulls)
                new_grids = list(grids)
            else:
                new_mask = set(mask)
                new_grids = list(grids)
                grid_idx = random.randint(0, 3)
                lst = list(grids[grid_idx])
                i, j = random.sample(range(25), 2)
                lst[i], lst[j] = lst[j], lst[i]
                new_grids[grid_idx] = "".join(lst)

            new_extracted = "".join(merge_ij(ch) for ch in extract_text(new_mask))
            np1, nc1, nc2, np2 = [make_grid(g) for g in new_grids]
            new_pt = four_square_decrypt(new_extracted, np1, np2, nc1, nc2, parity)
            new_total, new_ene, new_bcl = crib_score_detailed(new_pt, new_mask)
            new_qg = quadgram_score(new_pt)
            new_score = new_qg + new_total * crib_weight

            delta = new_score - current_score
            if delta > 0 or (t > 0 and random.random() < math.exp(delta / t)):
                mask = new_mask
                grids = new_grids
                current_score = new_score

                if new_score > best_score:
                    best_score = new_score
                    best_mask = set(new_mask)
                    best_grids = list(new_grids)
                    best_pt = new_pt
                    best_crib = new_total
                    best_ene = new_ene
                    best_bcl = new_bcl

        if best_crib > best_global[0] or (
            best_crib == best_global[0]
            and quadgram_per_char(best_pt) > quadgram_per_char(best_global[4])
        ):
            desc = f"full_SA|par={parity}|nulls={n_nulls}"
            best_global = (best_crib, best_ene, best_bcl, best_mask, best_pt,
                           best_grids, desc)

    return best_global


# ── Main ────────────────────────────────────────────────────────────────────

def attack(ciphertext: str = CT, **params) -> list:
    """Standard attack interface. Returns [(score, plaintext, method), ...]."""
    results = []
    t0 = time.time()
    last_report = t0

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 1: Keyword sweep with SA over null masks
    # ═══════════════════════════════════════════════════════════════════
    print("=" * 70)
    print("PHASE 1: Keyword-pair sweep with SA over null masks")
    print("=" * 70)

    configs_tested = 0
    phase1_results = []

    for n_nulls in [24, 25]:
        n_extract = CT_LEN - n_nulls
        print(f"\n--- {n_nulls} nulls ({n_extract}-char extract) ---")

        for parity in [0, 1]:
            for i, kw1 in enumerate(KEYWORDS):
                for j, kw2 in enumerate(KEYWORDS):
                    # Skip duplicate pairs (order matters for Four-Square)
                    # but test both orderings
                    score, ene, bcl, mask, pt, desc = sa_null_mask_keyword(
                        n_nulls=n_nulls,
                        c1_kw=kw1,
                        c2_kw=kw2,
                        parity=parity,
                        n_restarts=10,
                        steps=2000,
                    )
                    configs_tested += 1

                    if score >= 5:
                        phase1_results.append(
                            (score, ene, bcl, mask, pt, desc,
                             kw1, kw2, parity, n_nulls)
                        )

                    now = time.time()
                    if now - last_report >= 10.0:
                        elapsed = now - t0
                        print(f"  [{elapsed:.0f}s] {configs_tested} configs tested, "
                              f"{len(phase1_results)} hits >= 5/24, "
                              f"best={max((r[0] for r in phase1_results), default=0)}/24")
                        last_report = now

    phase1_results.sort(key=lambda x: (-x[0], -x[1]))

    print(f"\nPhase 1 complete: {configs_tested} configs, "
          f"{len(phase1_results)} hits >= 5/24")
    print(f"Elapsed: {time.time() - t0:.1f}s")

    if phase1_results:
        print("\n  Top 15 keyword-pair results:")
        print("  " + "-" * 68)
        for idx, (sc, ene, bcl, mask, pt, desc, kw1, kw2, par, nn) in enumerate(
            phase1_results[:15]
        ):
            print(f"  {sc:2d}/24 (ene={ene:2d}/13 bcl={bcl:2d}/11) "
                  f"c1={kw1} c2={kw2} par={par} nulls={nn}")
            print(f"      PT: {pt[:60]}...")
            if idx < 3:
                print(f"      Nulls: {sorted(mask)}")
        print("  " + "-" * 68)

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 2: Deep SA refinement on top keyword pairs
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("PHASE 2: Deep SA refinement on top keyword pairs")
    print("=" * 70)

    # Collect unique top keyword pairs (up to 10)
    seen_pairs = set()
    top_pairs = []
    for sc, ene, bcl, mask, pt, desc, kw1, kw2, par, nn in phase1_results:
        key = (kw1, kw2, par, nn)
        if key not in seen_pairs and len(top_pairs) < 10:
            seen_pairs.add(key)
            top_pairs.append((kw1, kw2, par, nn, sc))

    phase2_results = []
    for kw1, kw2, par, nn, prev_score in top_pairs:
        print(f"\n  Deep SA: c1={kw1} c2={kw2} par={par} nulls={nn} "
              f"(phase1 best: {prev_score}/24)")
        score, ene, bcl, mask, pt, desc = sa_null_mask_keyword(
            n_nulls=nn,
            c1_kw=kw1,
            c2_kw=kw2,
            parity=par,
            n_restarts=50,
            steps=8000,
        )
        print(f"    => {score:2d}/24 (ene={ene:2d}/13 bcl={bcl:2d}/11)")
        print(f"       PT: {pt[:60]}...")
        if score >= 7:
            print(f"       Nulls: {sorted(mask)}")
        phase2_results.append(
            (score, ene, bcl, mask, pt, desc, kw1, kw2, par, nn)
        )
        results.append(
            (score, pt,
             f"FourSquare-NullMask c1={kw1} c2={kw2} par={par} "
             f"nulls={nn} ene={ene}/13 bcl={bcl}/11")
        )

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 3: Full SA (mask + grids simultaneously)
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("PHASE 3: Full SA (null mask + all four grids)")
    print("=" * 70)

    for n_nulls in [24, 25]:
        for parity in [0]:
            print(f"\n  Full SA: nulls={n_nulls}, parity={parity}, "
                  f"20 restarts x 10K steps")
            cs, ene, bcl, mask, pt, grids, desc = sa_null_mask_full_sa(
                n_nulls=n_nulls,
                parity=parity,
                n_restarts=20,
                steps=10000,
                crib_weight=20.0,
            )
            qg = quadgram_per_char(pt)
            print(f"    => {cs:2d}/24 (ene={ene:2d}/13 bcl={bcl:2d}/11) "
                  f"qg/c={qg:.3f}")
            print(f"       PT: {pt[:60]}...")
            if cs >= 5:
                print(f"       Nulls: {sorted(mask)}")
                if grids:
                    print(f"       p1: {grids[0]}")
                    print(f"       c1: {grids[1]}")
                    print(f"       c2: {grids[2]}")
                    print(f"       p2: {grids[3]}")
            results.append(
                (cs, pt,
                 f"FourSquare-FullSA par={parity} nulls={n_nulls} "
                 f"ene={ene}/13 bcl={bcl}/11 qg={qg:.3f}")
            )

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 4: Crib positions as constraints on null mask
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("PHASE 4: Constrained null masks (cribs never null)")
    print("=" * 70)
    print("  Constraint: all 24 crib positions are NOT nulls")

    for n_nulls in [24, 25]:
        n_extract = CT_LEN - n_nulls
        non_crib = [i for i in range(CT_LEN) if i not in CRIB_POSITIONS]
        if n_nulls > len(non_crib):
            print(f"  Skipping nulls={n_nulls}: not enough non-crib positions")
            continue

        print(f"\n  --- {n_nulls} nulls ({n_extract}-char extract), "
              f"cribs protected ---")

        # Test top keyword pairs with constrained masks
        constrained_results = []
        for kw1, kw2, par, nn, _ in top_pairs[:5]:
            if nn != n_nulls:
                continue

            # Build fixed grids
            p1 = make_grid(ALPHA25)
            p2 = make_grid(ALPHA25)
            c1 = make_grid(keyword_square(kw1))
            c2 = make_grid(keyword_square(kw2))

            best_sc = 0
            best_result = None

            for restart in range(30):
                # Random mask from non-crib positions only
                mask = set(random.sample(non_crib, n_nulls))

                # SA on constrained mask
                current_mask = mask
                extracted = "".join(merge_ij(ch) for ch in extract_text(mask))
                pt = four_square_decrypt(extracted, p1, p2, c1, c2, par)
                total, ene, bcl = crib_score_detailed(pt, mask)
                current_score = total

                for step in range(3000):
                    t = 1.5 * (0.01 / 1.5) ** (step / max(2999, 1))

                    # Swap: pick a null from non-crib, pick a non-null from non-crib
                    null_list = [n for n in current_mask if n not in CRIB_POSITIONS]
                    non_null_non_crib = [
                        i for i in non_crib if i not in current_mask
                    ]
                    if not null_list or not non_null_non_crib:
                        break
                    to_remove = random.choice(null_list)
                    to_add = random.choice(non_null_non_crib)
                    new_mask = set(current_mask)
                    new_mask.discard(to_remove)
                    new_mask.add(to_add)

                    new_extracted = "".join(
                        merge_ij(ch) for ch in extract_text(new_mask)
                    )
                    new_pt = four_square_decrypt(
                        new_extracted, p1, p2, c1, c2, par
                    )
                    new_total, new_ene, new_bcl = crib_score_detailed(
                        new_pt, new_mask
                    )

                    delta = new_total - current_score
                    if delta > 0 or (t > 0 and random.random() < math.exp(delta / t)):
                        current_mask = new_mask
                        current_score = new_total

                        if new_total > best_sc:
                            best_sc = new_total
                            best_result = (
                                new_total, new_ene, new_bcl,
                                set(new_mask), new_pt
                            )

            if best_result:
                sc, ene, bcl, mask, pt = best_result
                print(f"  {sc:2d}/24 (ene={ene:2d}/13 bcl={bcl:2d}/11) "
                      f"c1={kw1} c2={kw2} par={par}")
                print(f"      PT: {pt[:60]}...")
                constrained_results.append(
                    (sc, ene, bcl, mask, pt, kw1, kw2, par, n_nulls)
                )
                results.append(
                    (sc, pt,
                     f"FourSquare-Constrained c1={kw1} c2={kw2} par={par} "
                     f"nulls={n_nulls} ene={ene}/13 bcl={bcl}/11")
                )

    # ═══════════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════════
    elapsed = time.time() - t0
    results.sort(key=lambda x: -x[0])

    print("\n" + "=" * 70)
    print(f"FINAL SUMMARY (elapsed: {elapsed:.1f}s)")
    print("=" * 70)

    if results:
        print("\nTop 20 results:")
        print("-" * 70)
        for idx, (sc, pt, method) in enumerate(results[:20]):
            print(f"  {sc:2d}/24 | {method}")
            print(f"         PT: {pt[:60]}...")
        print("-" * 70)

        best = results[0]
        if best[0] >= 18:
            print(f"\n*** SIGNAL: {best[0]}/24 — INVESTIGATE IMMEDIATELY ***")
        elif best[0] >= 13:
            print(f"\n*** MATCHES CURRENT CEILING ({best[0]}/24) — INVESTIGATE ***")
        elif best[0] >= 10:
            print(f"\n*** ABOVE NOISE ({best[0]}/24) — worth investigating ***")
        elif best[0] >= 7:
            print(f"\nBest: {best[0]}/24 — slightly above random. Marginal.")
        else:
            print(f"\nBest: {best[0]}/24 — noise floor. Four-Square + null mask "
                  f"shows no signal.")
    else:
        print("\nNo results collected.")

    return results


if __name__ == "__main__":
    print("Four-Square + Null Mask Attack on K4")
    print(f"CT: {CT}")
    print(f"CT len: {len(CT)}")
    print(f"Crib positions: {len(CRIB_DICT)} (ENE: 21-33, BCL: 63-73)")
    print(f"Keywords: {len(KEYWORDS)}")
    print(f"Keyword pairs: {len(KEYWORDS)**2}")
    print(f"Models: 24 nulls (73-char) + 25 nulls (72-char)")
    print(f"Parities: 0 (standard) and 1 (shifted)")
    print()

    random.seed(42)
    results = attack()
