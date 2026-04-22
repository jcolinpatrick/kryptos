#!/usr/bin/env python3
"""Serpentine × anomaly-derived grid × additive-inner standalone sweep.

Tests the hypothesis (user-proposed 2026-04-22):

    K4 plaintext = inner_decrypt(inverse_serpentine(CT, grid, path))

where the serpentine GRID dimensions and PATH variant are *derived from
K0-K3 anomalies* rather than enumerated blindly, and the inner cipher is
a standard additive family (Vigenere / Beaufort / Variant Beaufort) over
either the AZ or KA alphabet with keywords from the Oranchak QIII pool.

Motivation:
    Sanborn's own writing in the Archives of American Art (page 17,
    UAN AAA-AAA_sanbojim_4129080) describes Kryptos as "a serpentine
    copper screen perforated with encoded text and Blaise De Vigenère's
    Tableaux". Pairing those two technical terms in one sentence is a
    hypothesis seed. The plain serpentine × Vigenère / Beaufort shape
    has been community-tested to exhaustion at standard grid shapes
    (10×10, 4×25, etc.) — if it were trivially solvable, it would have
    been solved. What has NOT been tested is using K0-K3 anomalies to
    *parameterize* the grid or path specification: the project's
    procedural paradigm (anomalies as instructions, not decorations)
    treats this as a distinct class of test.

    The Tier-1 transposition eliminations in the session briefing all
    assume "direct positional correspondence CT[i] → PT[i]" — an outer
    serpentine transposition BREAKS that assumption, so this hypothesis
    lives in the carve-out scope, not inside the eliminated space.

Scope:
    Exhaustive sweep over (outer_perm × inner_family × alphabet ×
    keyword) where outer_perm is derived from K2 coordinates, NDYAHR,
    W positions, and K0 Morse extras. All parameter provenance traced
    in the output so signal findings can be attributed to a specific
    anomaly source.

Usage:
    PYTHONPATH=src python3 -u scripts/exploration/e_serpentine_anomaly_sweep.py
    PYTHONPATH=src python3 -u scripts/exploration/e_serpentine_anomaly_sweep.py \\
        --top-keywords 500 --report-path results/serpentine_sweep.json
"""
# Family: exploration
# Status: active
# Created: 2026-04-22 (user-proposed hypothesis; brief in session transcript)

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

from kryptos.kernel.alphabet import Alphabet, AZ, KA
from kryptos.kernel.constants import CT, CT_LEN
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.constraints.bean import verify_bean
from kryptos.kernel.transforms.transposition import (
    apply_perm, invert_perm, serpentine_perm, spiral_perm,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
)


# ─── Anomaly-derived parameter enumeration ──────────────────────────────────


@dataclass(frozen=True)
class GridCandidate:
    """One (grid, path) proposal with provenance back to an anomaly.

    ``padding`` controls the grid-fit strategy:
      "none"     — 97-cell perm (grid-positions beyond 97 skipped;
                   plaintext stays length-97).
      "tail_w"   — pad CT to rows*cols with W's appended at the tail,
                   apply full permutation, then trim output back to 97.
                   Motivated by the project's W-delimiter anomaly: the
                   5 carved W's at positions 20, 36, 48, 58, 74 are
                   candidate padding/marker characters.
      "tail_x"   — same as tail_w but with X (a common cipher pad).
    """
    source: str              # "k2_coords", "ndyahr", "w_positions", "k0_morse"
    description: str         # human-readable parameter derivation
    rows: int
    cols: int
    variant: str             # "serpentine_h", "serpentine_v", "spiral_cw", "spiral_ccw", "ndyahr_path"
    vertical: bool = False   # for serpentine
    clockwise: bool = True   # for spiral
    padding: str = "none"    # "none" | "tail_w" | "tail_x"


def _derive_from_k2_coords() -> list[GridCandidate]:
    """K2 coordinate digits as grid dimensions.

    K2 decrypted coordinates: 38°57'6.5" N, 77°8'44" W
    Small natural numbers from the coord components:
      degrees: 38, 77
      minutes: 57, 8
      seconds: 6.5 (→ 6 or 7), 44
      sums/diffs: 45 (77-32?), 14 (7*2), etc.

    Enumerate rows×cols where each dim is in the set of small numbers
    appearing anywhere in the coord spec, plus their doublings (the
    coords give halves like 6.5→13 under doubling).
    """
    # Natural small-integer readings of the coordinates.
    coord_nums = {
        6, 7, 8, 13, 14, 38, 44, 57, 65, 77,  # direct appearances
        # loose readings: double-up the half-seconds (6.5 → 13)
        # and doubled/halved single digits from the pairs
        3, 4, 5,  # singletons from "38", "57", "77", "8", "44"
    }
    # Reasonable factor pairs covering 97 ≤ r*c ≤ 200.
    candidates = []
    for rows in sorted(coord_nums):
        for cols in sorted(coord_nums):
            if rows < 2 or cols < 2:
                continue
            if rows * cols < CT_LEN or rows * cols > 200:
                continue
            desc = f"k2 coordinate small-integer reading {rows}x{cols}"
            for variant, vertical in (("serpentine_h", False), ("serpentine_h_vert", True)):
                candidates.append(GridCandidate(
                    "k2_coords", desc, rows, cols, variant, vertical, True,
                ))
            candidates.append(GridCandidate(
                "k2_coords", desc + " (spiral cw)", rows, cols, "spiral_cw", False, True,
            ))
    return candidates


def _derive_from_ndyahr() -> list[GridCandidate]:
    """NDYAHR as path-indicator (NOT as key — that's been exhausted).

    NDYAHR letters: N=13, D=3, Y=24, A=0, H=7, R=17.
    Interpretations:
      - Grid dims: pick any 2 ordered (rows, cols) from the letter positions
        where rows*cols >= 97. Only small values qualify.
      - Path indicator: the 6 letters could select 6 serpentine variants
        (N/D/Y/A/H/R = 6 paths on the same grid).
    """
    letter_vals = {"N": 13, "D": 3, "Y": 24, "A": 0, "H": 7, "R": 17}
    ordered = [("N", 13), ("D", 3), ("Y", 24), ("A", 0), ("H", 7), ("R", 17)]
    candidates = []
    # Grid dims from pairs of NDYAHR letter positions
    for i, (l1, r) in enumerate(ordered):
        for j, (l2, c) in enumerate(ordered):
            if r < 2 or c < 2:
                continue
            if r * c < CT_LEN or r * c > 160:
                continue
            desc = f"NDYAHR letters {l1}={r} × {l2}={c}"
            for variant, vertical in (("serpentine_h", False), ("serpentine_h_vert", True)):
                candidates.append(GridCandidate("ndyahr", desc, r, c, variant, vertical, True))
            candidates.append(GridCandidate("ndyahr", desc + " (spiral cw)", r, c, "spiral_cw", False, True))
            candidates.append(GridCandidate("ndyahr", desc + " (spiral ccw)", r, c, "spiral_ccw", False, False))
    return candidates


def _derive_from_w_positions() -> list[GridCandidate]:
    """W-position gaps as grid dimensions.

    W's at 20, 36, 48, 58, 74. Gaps: 20, 16, 12, 10, 16 (and 23 tail).
    Segments: 20, 15, 11, 9, 15, 22 (per w_delimiter_segments anomaly).
    """
    candidates = []
    # Pairs of segment lengths that fit around 100
    segments = [20, 15, 11, 9, 15, 22]
    gaps = [20, 16, 12, 10, 16, 23]
    for r in set(segments + gaps):
        for c in set(segments + gaps):
            if r < 2 or c < 2:
                continue
            if r * c < CT_LEN or r * c > 160:
                continue
            desc = f"W-segment {r}x{c}"
            for variant, vertical in (("serpentine_h", False), ("serpentine_h_vert", True)):
                candidates.append(GridCandidate("w_positions", desc, r, c, variant, vertical, True))
    return candidates


def _derive_from_k0_morse() -> list[GridCandidate]:
    """K0 Morse extra-E count (25-26 extras) and dependents.

    The Morse on the entrance slabs has ~25-26 extra E's. As grid param:
      - 26 x 4 = 104 (pad 7)
      - 13 x 8 = 104 (pad 7)
      - 5 x 26 = 130 (too large)
    """
    candidates = []
    for rows, cols in [(26, 4), (4, 26), (13, 8), (8, 13), (5, 20), (20, 5)]:
        if rows * cols < CT_LEN:
            continue
        desc = f"K0 Morse extra-E count {rows}x{cols}"
        for variant, vertical in (("serpentine_h", False), ("serpentine_h_vert", True)):
            candidates.append(GridCandidate("k0_morse", desc, rows, cols, variant, vertical, True))
    return candidates


def _enumerate_outer_candidates() -> list[GridCandidate]:
    """All anomaly-derived outer candidates, with padding variants.

    For each base (rows, cols, variant) we emit three candidates:
      - padding="none"      — grid-positions beyond 97 skipped
      - padding="tail_w"    — CT padded to rows*cols with W's at tail
      - padding="tail_x"    — same with X's (neutral cipher pad control)

    Plus: NDYAHR-path-indexed variants of the same base grids — the
    user's hypothesis about NDYAHR as path-indicator rather than key.
    """
    seen: set[tuple] = set()
    all_cands: list[GridCandidate] = []
    # Collect base grids (rows, cols, source, description) across sources.
    base_grids: list[tuple[int, int, str, str]] = []
    for src_fn in (
        _derive_from_k2_coords,
        _derive_from_ndyahr,
        _derive_from_w_positions,
        _derive_from_k0_morse,
    ):
        for c in src_fn():
            base_grids.append((c.rows, c.cols, c.source, c.description))

    # Dedup base grids on (rows, cols, source).
    base_seen: set[tuple[int, int, str]] = set()
    base_unique: list[tuple[int, int, str, str]] = []
    for r, cc, s, d in base_grids:
        if (r, cc, s) in base_seen:
            continue
        base_seen.add((r, cc, s))
        base_unique.append((r, cc, s, d))

    # Cross-product: base grids × path variants × padding.
    path_variants = [
        ("serpentine_h", False, True),
        ("serpentine_h_vert", True, True),
        ("spiral_cw", False, True),
        ("spiral_ccw", False, False),
        ("ndyahr_path", False, True),  # user-hypothesis anomaly-path
    ]
    paddings = ("none", "tail_w", "tail_x")

    for r, cc, s, d in base_unique:
        for variant, vertical, clockwise in path_variants:
            for pad in paddings:
                # Skip tail-padding when grid exactly fits 97 (no actual pad).
                if pad != "none" and r * cc <= CT_LEN:
                    continue
                k = (r, cc, variant, vertical, clockwise, pad)
                if k in seen:
                    continue
                seen.add(k)
                all_cands.append(GridCandidate(
                    source=s, description=d,
                    rows=r, cols=cc,
                    variant=variant, vertical=vertical, clockwise=clockwise,
                    padding=pad,
                ))
    return all_cands


_NDYAHR_POSITIONAL = [13, 3, 24, 0, 7, 17]  # N=13, D=3, Y=24, A=0, H=7, R=17


def _build_outer_perm(c: GridCandidate) -> list[int]:
    """Build the position permutation for the candidate grid+path.

    For ``padding == "none"``, returns a 97-elem perm. For tail-padded
    variants, returns a ``rows*cols``-elem perm — the caller must pad
    the CT before applying it and trim the output back to 97.
    """
    if c.padding == "none":
        length = CT_LEN
    else:
        length = c.rows * c.cols
    if c.variant.startswith("serpentine"):
        return serpentine_perm(c.rows, c.cols, length, vertical=c.vertical)
    if c.variant == "spiral_cw":
        return spiral_perm(c.rows, c.cols, length, clockwise=True)
    if c.variant == "spiral_ccw":
        return spiral_perm(c.rows, c.cols, length, clockwise=False)
    if c.variant == "ndyahr_path":
        # NDYAHR-indexed walk: start at position _NDYAHR_POSITIONAL[0]
        # modulo grid size, step by successive NDYAHR letter values.
        # Deterministic walk that visits every cell exactly once via
        # a linear-congruential traversal seeded by NDYAHR letters.
        return _ndyahr_walk_perm(c.rows, c.cols, length)
    raise ValueError(f"unknown variant {c.variant!r}")


def _ndyahr_walk_perm(rows: int, cols: int, length: int) -> list[int]:
    """NDYAHR-indexed walk through the grid.

    Uses the 6 NDYAHR letter values as a cyclic step sequence modulo
    grid size. Stepping starts at position N=13 mod cells, takes steps
    +D=3, +Y=24, +A=0, +H=7, +R=17 cyclically modulo cells, skipping
    already-visited cells until all cells are visited. Then trims
    positions beyond ``length``.

    This is a deterministic, anomaly-parameterized walk — distinct from
    serpentine/spiral and not a trivial shuffle. If NDYAHR is indeed a
    path-indicator clue, this shape exercises that reading.

    Termination: when every cell has been visited. The previous version
    used ``len(perm) < cells`` as the termination condition, but
    ``perm`` only grows when ``pos < length``; for padded grids where
    cells > length, the perm could never reach ``cells`` entries and
    the loop ran forever. Fixed 2026-04-22 to terminate on full-grid
    visitation regardless of how many positions land inside ``length``.
    """
    cells = rows * cols
    perm: list[int] = []
    visited = [False] * cells
    visited_count = 0
    pos = _NDYAHR_POSITIONAL[0] % cells
    step_idx = 0
    # Safety bound — at most cells * 20 iterations before we bail to
    # the linear fallback. Prevents runaway if the step cycle has a
    # pathological period modulo cells.
    max_iters = cells * 20
    iters = 0
    while visited_count < cells and iters < max_iters:
        if not visited[pos]:
            visited[pos] = True
            visited_count += 1
            if pos < length:
                perm.append(pos)
        # Advance by next NDYAHR step (cycle through the six values).
        step = _NDYAHR_POSITIONAL[step_idx % len(_NDYAHR_POSITIONAL)]
        pos = (pos + max(1, step)) % cells  # step 0 (A) replaced with 1 to avoid fixed-point loop
        step_idx += 1
        iters += 1
    # Fallback: linear sweep for any cells the step-cycle missed.
    if visited_count < cells:
        for i in range(cells):
            if not visited[i]:
                visited[i] = True
                if i < length:
                    perm.append(i)
    return perm[:length]


# ─── Inner layer: Vig / Beau / VarBeau on AZ or KA ──────────────────────────


_INNER_VARIANTS = [
    ("vigenere", CipherVariant.VIGENERE),
    ("beaufort", CipherVariant.BEAUFORT),
    ("variant_beaufort", CipherVariant.VAR_BEAUFORT),
]


def _load_inner_keywords(top_q3: int, top_q4: int = 0) -> list[str]:
    """Curated keyword pool from multiple sources, priority-ordered.

    Merge order (earlier sources take precedence; dedup keeps first occurrence):
      1. K1-K3 + project provenance keywords (always)
      2. ``wordlists/thematic_keywords_v2.txt`` — project-curated categories
         (Kryptos proper nouns, cryptography terms, tradecraft, Berlin,
         Carter/Egyptology, Sanborn vocabulary, navigation, etc.)
      3. ``wordlists/thematic_keywords.txt`` — legacy curated list
      4. ``wordlists/quagmire3_keywords_oranchak.txt`` — top ``top_q3``
         by Reddit-frequency from doranchak/kryptos (mirrored 2026-04-21)
      5. ``wordlists/quagmire4_keywords_oranchak.txt`` — top ``top_q4``

    Per user direction 2026-04-22: curated keywords take precedence; the
    Oranchak frequency-tail provides breadth.
    """
    seen: set[str] = set()
    keywords: list[str] = []

    def _add(w: str) -> None:
        u = w.strip().upper()
        if 3 <= len(u) <= 15 and u.isalpha() and u not in seen:
            seen.add(u)
            keywords.append(u)

    # 1. Provenance anchors (K1-K3 solved keywords + Sanborn/Scheidt +
    #    project-specific seeds tested elsewhere in the codebase).
    for w in [
        "PALIMPSEST", "ABSCISSA", "KRYPTOS", "YARD",
        "SANBORN", "SCHEIDT", "LANGLEY", "ANTIPODES",
        "IQLUSION", "UNDERGRUUND", "DIGETAL",
        "BERLINCLOCK", "WELTZEITUHR", "MENGENLEHREUHR",
        "ALEXANDERPLATZ", "EASTNORTHEAST",
        "SERPENTINE", "VIGENERE",  # user's hypothesis-seed anchors
        "NDYAHR", "ENDYAHR", "DYAHR", "YAHROH",  # K3 boundary anomaly
        "LODESTONE", "COMPASS", "KOMPASS",
    ]:
        _add(w)

    # 2-3. Thematic curated lists (v2 first — broader, more categories).
    for path_name in ("thematic_keywords_v2.txt", "thematic_keywords.txt"):
        path = _ROOT / "wordlists" / path_name
        if not path.exists():
            continue
        with path.open() as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                _add(line)

    # 4. Oranchak QIII top-N (frequency-ordered English words).
    q3_path = _ROOT / "wordlists" / "quagmire3_keywords_oranchak.txt"
    if q3_path.exists():
        q3_added = 0
        with q3_path.open() as f:
            for line in f:
                if q3_added >= top_q3:
                    break
                before = len(seen)
                _add(line)
                if len(seen) > before:
                    q3_added += 1

    # 5. Oranchak QIV top-M (smaller, different distribution).
    if top_q4 > 0:
        q4_path = _ROOT / "wordlists" / "quagmire4_keywords_oranchak.txt"
        if q4_path.exists():
            q4_added = 0
            with q4_path.open() as f:
                for line in f:
                    if q4_added >= top_q4:
                        break
                    before = len(seen)
                    _add(line)
                    if len(seen) > before:
                        q4_added += 1

    return keywords


def _keyword_to_key_ints(keyword: str, alphabet: Alphabet) -> list[int]:
    """Encode keyword as indices in the given alphabet."""
    if alphabet is AZ:
        return [ord(c) - 65 for c in keyword]
    # KA-style keyword-mixed
    idx = alphabet.index_table
    return [idx[ord(c) - 65] for c in keyword]


# ─── Scoring ────────────────────────────────────────────────────────────────


def _score_plaintext(pt: str) -> tuple[int, bool]:
    """Return (crib_score, bean_passed). Fast path, no ngram."""
    crib = score_cribs(pt)
    # Bean check needs the keystream at crib positions. Derive it from
    # pt + CT assuming Vigenère — but since we're testing three variants,
    # only report bean_passed for Vigenère convention; the other two
    # variants have their own key derivations. For this sweep, bean is
    # advisory (crib is the hard filter).
    bean_ok = False
    try:
        # Vigenère: k = (CT - PT) mod 26
        keystream = []
        from kryptos.kernel.constants import CRIB_DICT
        ct_at = {p: ord(CT[p]) - 65 for p in CRIB_DICT}
        for p in sorted(CRIB_DICT):
            ks = (ct_at[p] - (ord(pt[p]) - 65)) % 26
            keystream.append((p, ks))
        bean_ok = verify_bean(keystream)
    except Exception:
        pass
    return crib, bean_ok


# ─── Worker ─────────────────────────────────────────────────────────────────


@dataclass
class SweepResult:
    source: str
    grid: str             # "RxC"
    variant: str
    family: str
    alphabet: str
    keyword: str
    crib_score: int
    bean_passed: bool
    plaintext: str
    derivation: str       # human-readable anomaly trace


def _pad_ct_for_grid(candidate: GridCandidate) -> str:
    """Return the CT padded to the grid size according to ``padding``."""
    if candidate.padding == "none":
        return CT
    target = candidate.rows * candidate.cols
    if target <= CT_LEN:
        return CT  # no padding needed
    pad_char = "W" if candidate.padding == "tail_w" else "X"
    return CT + pad_char * (target - CT_LEN)


def _worker_sweep_one_outer(args):
    """Evaluate one outer candidate across all inner parameters.
    Returns top-K SweepResults (crib_score >= threshold)."""
    (candidate, keywords, threshold) = args
    perm = _build_outer_perm(candidate)
    inv = invert_perm(perm)
    ct_in = _pad_ct_for_grid(candidate)
    # Apply outer-inverse to padded CT once. Any inner decrypt operates on this.
    intermediate = apply_perm(ct_in, inv)

    results: list[SweepResult] = []
    for alphabet_name, alphabet in (("AZ", AZ), ("KA", KA)):
        alph_arg = None if alphabet is AZ else alphabet
        for family_name, variant in _INNER_VARIANTS:
            for kw in keywords:
                key = _keyword_to_key_ints(kw, alphabet)
                try:
                    pt = decrypt_text(intermediate, key, variant, alph_arg)
                except Exception:
                    continue
                # For padded grids, trim back to CT_LEN so crib-scoring
                # operates on positions 21-33 and 63-73 of the 97-char
                # plaintext, not on positions in the padded extension.
                if len(pt) > CT_LEN:
                    pt_scoring = pt[:CT_LEN]
                else:
                    pt_scoring = pt
                crib, bean = _score_plaintext(pt_scoring)
                if crib >= threshold:
                    results.append(SweepResult(
                        source=candidate.source,
                        grid=f"{candidate.rows}x{candidate.cols}",
                        variant=f"{candidate.variant}+{candidate.padding}"
                                if candidate.padding != "none"
                                else candidate.variant,
                        family=family_name,
                        alphabet=alphabet_name,
                        keyword=kw,
                        crib_score=crib,
                        bean_passed=bean,
                        plaintext=pt_scoring,
                        derivation=candidate.description,
                    ))
    return results


# ─── Driver ─────────────────────────────────────────────────────────────────


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--top-q3", type=int, default=3000,
                    help="Oranchak QIII keywords to sweep (top-N by frequency)")
    ap.add_argument("--top-q4", type=int, default=1500,
                    help="Oranchak QIV keywords to sweep (0 to skip)")
    ap.add_argument("--crib-threshold", type=int, default=8,
                    help="Report sweep results with crib_score >= this threshold")
    ap.add_argument("--workers", type=int, default=0,
                    help="Parallel workers (0 = cpu_count - 2)")
    ap.add_argument("--report-path", type=str,
                    default="results/serpentine_anomaly_sweep.json")
    args = ap.parse_args(argv)

    n_workers = args.workers if args.workers > 0 else max(1, mp.cpu_count() - 2)

    candidates = _enumerate_outer_candidates()
    keywords = _load_inner_keywords(args.top_q3, args.top_q4)

    print(f"Serpentine × anomaly-derived grid × inner-additive sweep")
    print(f"  CT_LEN:            {CT_LEN}")
    print(f"  Outer candidates:  {len(candidates)}")
    print(f"  Inner keywords:    {len(keywords)}")
    print(f"  Inner families:    {len(_INNER_VARIANTS)} (Vig, Beau, VarBeau)")
    print(f"  Inner alphabets:   2 (AZ, KA)")
    total = len(candidates) * len(keywords) * 3 * 2
    print(f"  Total combinations: {total:,}")
    print(f"  Workers:           {n_workers}")
    print(f"  Crib threshold:    >= {args.crib_threshold}")
    print(f"  Report:            {args.report_path}")
    print()

    sources_count: dict[str, int] = {}
    for c in candidates:
        sources_count[c.source] = sources_count.get(c.source, 0) + 1
    print("  Anomaly-source breakdown:")
    for s, n in sorted(sources_count.items()):
        print(f"    {s:15s} {n} outer candidates")
    print()

    t0 = time.monotonic()
    work = [(c, keywords, args.crib_threshold) for c in candidates]

    all_results: list[SweepResult] = []
    with mp.Pool(n_workers) as pool:
        for i, batch in enumerate(pool.imap_unordered(_worker_sweep_one_outer, work), 1):
            all_results.extend(batch)
            if i % 10 == 0 or i == len(work):
                elapsed = time.monotonic() - t0
                print(f"  [{i}/{len(work)}] outer done, "
                      f"{len(all_results)} results >= threshold, "
                      f"{elapsed:.1f}s elapsed", flush=True)

    wall = time.monotonic() - t0
    print(f"\nSweep complete in {wall:.1f}s")

    # Rank by crib, then bean
    all_results.sort(key=lambda r: (-r.crib_score, -int(r.bean_passed), r.keyword))

    print(f"Top 20 results (crib >= {args.crib_threshold}):")
    for r in all_results[:20]:
        bean_flag = "B✓" if r.bean_passed else "  "
        print(f"  crib={r.crib_score:2d} {bean_flag}  "
              f"{r.source:12s} {r.grid:7s} {r.variant:18s} "
              f"{r.family:17s} {r.alphabet}  {r.keyword}")

    # Persist full result set
    report = {
        "run_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "wall_seconds": round(wall, 2),
        "n_outer_candidates": len(candidates),
        "n_inner_keywords": len(keywords),
        "n_total_combinations": total,
        "crib_threshold": args.crib_threshold,
        "sources_count": sources_count,
        "n_results_at_threshold": len(all_results),
        "top_results": [asdict(r) for r in all_results[:100]],
    }
    Path(args.report_path).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report_path).write_text(json.dumps(report, indent=2))
    print(f"\nFull report written to {args.report_path}")

    max_crib = max((r.crib_score for r in all_results), default=0)
    if max_crib >= 18:
        print(f"\n⚠  SIGNAL ALERT: max crib_score = {max_crib} (>= 18 SIGNAL threshold)")
        print("   Verify independently before acting.")
    else:
        print(f"\nMax crib_score: {max_crib}")
        print(f"Verdict: no signal above SIGNAL threshold (18) from anomaly-derived "
              f"serpentine × additive-inner hypothesis.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
