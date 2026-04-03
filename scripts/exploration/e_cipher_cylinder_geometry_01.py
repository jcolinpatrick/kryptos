#!/usr/bin/env python3
"""
Cipher: exploration/cipher_cylinder
Family: exploration
Status: active
Keyspace: ~50K configs
Last run:
Best score:

E-CYLINDER-GEOM-01: Cipher Cylinder Geometry — Pool as Mandrel

Hypothesis: Sanborn designed the pool diameter (66") so the tableau wraps
at the pool circumference. The physical geometry creates a cipher cylinder
where the rotational/width relationship between cipher panel and tableau
encodes the key progression.

Three sub-hypotheses tested:

H1: ROW-WIDTH MISMATCH PROGRESSIVE KEY
  If cipher rows and tableau rows have different character counts,
  wrapping both around the same cylinder creates a cumulative offset
  that increases each row. This is equivalent to a Vigenère/Beaufort
  where the key shifts by a constant delta per row.
  Test: all width mismatches -5 to +5, all starting offsets 0-25,
  all 3 cipher variants.

H2: DUAL-RADIUS PROGRESSIVE KEY
  If cipher panel curves at radius R1 and tableau at R2 (pool radius=33"),
  overlaying creates differential rotation. Each row advances by
  (row_height * tan(angle_diff)) characters.
  Test: radius ratios from 0.8 to 1.5, all starting offsets.

H3: CYLINDRICAL COLUMN-WRAP TRANSPOSITION
  Writing K4 into a grid where the row width matches the cylinder
  circumference in characters, then reading in column order determined
  by the KRYPTOS keyword position on the cylinder.
  Test: row widths 26-36 (plausible cylinder circumferences in chars),
  KRYPTOS-keyed column order, all 3 variants.

Output: results/cipher_cylinder_geometry.json
"""
import json
import os
import sys
import time
import itertools
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS,
    CONSENSUS_NULL_POSITIONS, KRYPTOS_ALPHABET,
)
from kryptos.kernel.scoring.aggregate import score_candidate

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

# ── Vigenère tableau operations ──────────────────────────────────────────

def decrypt_beaufort_with_offset(ct, key_row, offset):
    """Beaufort decrypt where tableau column = (position + offset) mod 26."""
    pt = []
    for i, c in enumerate(ct):
        ct_val = ALPH_IDX[c]
        k = key_row[(i + offset) % len(key_row)] if isinstance(key_row, list) else key_row
        pt.append(ALPH[(k - ct_val) % MOD])
    return "".join(pt)


def decrypt_with_progressive_offset(ct, variant, start_offset, delta_per_row, row_width):
    """Decrypt with a key that shifts by delta_per_row each row.

    This models the effect of wrapping cipher+tableau around a cylinder
    where their row widths differ by delta_per_row characters.
    """
    pt = []
    for i, c in enumerate(ct):
        row = i // row_width
        col = i % row_width
        # The effective tableau column shifts by (delta * row + start_offset)
        effective_col = (col + start_offset + int(delta_per_row * row)) % MOD
        ct_val = ALPH_IDX[c]

        if variant == "beaufort":
            pt_val = (effective_col - ct_val) % MOD
        elif variant == "vigenere":
            pt_val = (ct_val - effective_col) % MOD
        else:  # var_beaufort
            pt_val = (ct_val + effective_col) % MOD

        pt.append(ALPH[pt_val])
    return "".join(pt)


def keyword_column_order(keyword, width):
    """Generate column read order from keyword, cycling if needed."""
    extended = (keyword * ((width // len(keyword)) + 1))[:width]
    indexed = [(c, i) for i, c in enumerate(extended)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * width
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return order


def columnar_decrypt(ct_str, width, col_order):
    """Undo columnar transposition."""
    n = len(ct_str)
    nrows = (n + width - 1) // width
    full_cols = n % width if n % width != 0 else width

    col_lens = []
    for c in range(width):
        if c < full_cols or full_cols == width:
            col_lens.append(nrows)
        else:
            col_lens.append(nrows - 1)

    pos = 0
    columns = {}
    for read_idx in range(width):
        col_id = col_order[read_idx]
        clen = col_lens[col_id]
        columns[col_id] = list(ct_str[pos:pos + clen])
        pos += clen

    pt = []
    for r in range(nrows):
        for c in range(width):
            if r < len(columns.get(c, [])):
                pt.append(columns[c][r])
    return "".join(pt)


def score_pt(pt):
    return score_candidate(pt).crib_score


# ── H1: Row-width mismatch progressive key ───────────────────────────────

def h1_worker(args):
    """Test progressive offset from row-width mismatch."""
    delta, start_offset, variant, row_width = args
    pt = decrypt_with_progressive_offset(CT, variant, start_offset, delta, row_width)
    sc = score_pt(pt)
    if sc >= 6:
        return {"score": sc, "delta": delta, "offset": start_offset,
                "variant": variant, "row_width": row_width,
                "hypothesis": "H1_progressive", "pt_preview": pt[:50]}
    return None


# ── H2: Dual-radius progressive key ─────────────────────────────────────

def h2_worker(args):
    """Test progressive offset from radius mismatch."""
    radius_ratio, start_offset, variant, row_width = args
    # delta_per_row = difference in chars per row between the two radii
    # If tableau is at radius R (31 chars/row) and cipher at R*ratio,
    # cipher has 31*ratio chars/row. The mismatch per row = 31*(ratio-1)
    # But we express as fractional chars of offset per row
    delta = row_width * (radius_ratio - 1.0)
    pt = decrypt_with_progressive_offset(CT, variant, start_offset, delta, row_width)
    sc = score_pt(pt)
    if sc >= 6:
        return {"score": sc, "radius_ratio": radius_ratio, "offset": start_offset,
                "variant": variant, "delta_per_row": round(delta, 3),
                "hypothesis": "H2_dual_radius", "pt_preview": pt[:50]}
    return None


# ── H3: Cylindrical column-wrap transposition ────────────────────────────

def h3_worker(args):
    """Test columnar transposition at cylinder-width + substitution."""
    width, variant, keyword, use_nullmask = args

    ct = CT
    if use_nullmask:
        ct = "".join(CT[i] for i in range(CT_LEN) if i not in CONSENSUS_NULL_POSITIONS)

    col_order = keyword_column_order(keyword, width)

    try:
        pt_trans = columnar_decrypt(ct, width, col_order)
    except Exception:
        return None

    # Apply substitution layer
    pt = []
    for i, c in enumerate(pt_trans):
        ct_val = ALPH_IDX[c]
        if variant == "beaufort":
            pt.append(ALPH[(0 - ct_val) % MOD])  # key=0 (identity-ish)
        else:
            pt.append(c)  # no substitution for raw transposition test
    pt_str = "".join(pt)

    # Score the transposition output directly (no substitution)
    sc = score_pt(pt_trans)
    if sc >= 6:
        return {"score": sc, "width": width, "variant": variant,
                "keyword": keyword, "nullmask": use_nullmask,
                "hypothesis": "H3_cylinder_transposition", "pt_preview": pt_trans[:50]}

    # Also try Beaufort/Vig with each keyword after transposition
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        kw_vals = [ALPH_IDX[c] for c in kw]
        for v in ["beaufort", "vigenere"]:
            pt2 = []
            for i, c in enumerate(pt_trans):
                ct_val = ALPH_IDX[c]
                k = kw_vals[i % len(kw_vals)]
                if v == "beaufort":
                    pt2.append(ALPH[(k - ct_val) % MOD])
                else:
                    pt2.append(ALPH[(ct_val - k) % MOD])
            pt2_str = "".join(pt2)
            sc2 = score_pt(pt2_str)
            if sc2 >= 6:
                return {"score": sc2, "width": width, "variant": v,
                        "keyword": keyword, "sub_keyword": kw,
                        "nullmask": use_nullmask,
                        "hypothesis": "H3_cylinder_trans+sub", "pt_preview": pt2_str[:50]}
    return None


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-CYLINDER-GEOM-01: Cipher Cylinder Geometry")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"Pool diameter: 66\", radius: 33\"")
    print()

    all_results = []
    best_score = 0
    n_workers = max(1, cpu_count() - 2)

    # ── H1: Progressive offset from row-width mismatch ───────────────
    print("H1: Row-width mismatch progressive key")
    print("-" * 50)

    h1_jobs = []
    for row_width in [29, 30, 31, 32, 33]:
        for delta in [x * 0.5 for x in range(-10, 11)]:  # -5.0 to +5.0 in 0.5 steps
            if delta == 0:
                continue
            for start_offset in range(26):
                for variant in ["beaufort", "vigenere", "var_beaufort"]:
                    h1_jobs.append((delta, start_offset, variant, row_width))

    print(f"  Jobs: {len(h1_jobs):,}")

    with Pool(n_workers) as pool:
        for r in pool.imap_unordered(h1_worker, h1_jobs, chunksize=500):
            if r:
                all_results.append(r)
                if r["score"] > best_score:
                    best_score = r["score"]
                    print(f"  NEW BEST H1: {r['score']}/24 delta={r['delta']} "
                          f"off={r['offset']} var={r['variant']} w={r['row_width']}")

    t1 = time.time()
    print(f"  H1 done: {t1-t0:.1f}s, best={best_score}/24")

    # ── H2: Dual-radius progressive key ──────────────────────────────
    print("\nH2: Dual-radius progressive key")
    print("-" * 50)

    h2_jobs = []
    for ratio in [0.8, 0.85, 0.9, 0.95, 1.02, 1.05, 1.1, 1.15, 1.2, 1.3, 1.5]:
        for row_width in [30, 31, 32]:
            for start_offset in range(26):
                for variant in ["beaufort", "vigenere", "var_beaufort"]:
                    h2_jobs.append((ratio, start_offset, variant, row_width))

    print(f"  Jobs: {len(h2_jobs):,}")

    with Pool(n_workers) as pool:
        for r in pool.imap_unordered(h2_worker, h2_jobs, chunksize=500):
            if r:
                all_results.append(r)
                if r["score"] > best_score:
                    best_score = r["score"]
                    print(f"  NEW BEST H2: {r['score']}/24 ratio={r['radius_ratio']} "
                          f"off={r['offset']} var={r['variant']}")

    t2 = time.time()
    print(f"  H2 done: {t2-t1:.1f}s, best={best_score}/24")

    # ── H3: Cylindrical column-wrap transposition ────────────────────
    print("\nH3: Cylindrical column-wrap transposition")
    print("-" * 50)

    h3_jobs = []
    keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK"]
    for width in range(26, 37):
        for keyword in keywords:
            for variant in ["beaufort", "vigenere", "var_beaufort"]:
                for use_null in [False, True]:
                    h3_jobs.append((width, variant, keyword, use_null))

    print(f"  Jobs: {len(h3_jobs):,}")

    with Pool(n_workers) as pool:
        for r in pool.imap_unordered(h3_worker, h3_jobs, chunksize=10):
            if r:
                all_results.append(r)
                if r["score"] > best_score:
                    best_score = r["score"]
                    print(f"  NEW BEST H3: {r['score']}/24 w={r['width']} "
                          f"kw={r.get('keyword','')} var={r['variant']}")

    t3 = time.time()
    print(f"  H3 done: {t3-t2:.1f}s, best={best_score}/24")

    # ── Summary ──────────────────────────────────────────────────────
    elapsed = time.time() - t0
    all_results.sort(key=lambda x: x["score"], reverse=True)

    print(f"\n{'=' * 70}")
    print(f"RESULTS")
    print(f"{'=' * 70}")
    print(f"Total configs: {len(h1_jobs) + len(h2_jobs) + len(h3_jobs):,}")
    print(f"Results >= 6: {len(all_results)}")
    print(f"Best score: {best_score}/24")
    print(f"Runtime: {elapsed:.1f}s")

    if all_results:
        print(f"\nTOP 10:")
        for r in all_results[:10]:
            print(f"  {r['score']}/24 | {r['hypothesis']} | {r}")

    verdict = "SIGNAL" if best_score >= 18 else "INTERESTING" if best_score >= 10 else "NOISE"
    print(f"\nVERDICT: {verdict}")

    output = {
        "experiment": "E-CYLINDER-GEOM-01",
        "description": "Cipher cylinder geometry — pool as mandrel, progressive offset from width/radius mismatch",
        "pool_diameter_inches": 66,
        "total_configs": len(h1_jobs) + len(h2_jobs) + len(h3_jobs),
        "best_score": best_score,
        "verdict": verdict,
        "runtime_s": round(elapsed, 1),
        "top10": all_results[:10],
        "h1_jobs": len(h1_jobs),
        "h2_jobs": len(h2_jobs),
        "h3_jobs": len(h3_jobs),
    }

    out_path = os.path.join(_ROOT, "results", "cipher_cylinder_geometry.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nResults saved to: {out_path}")


if __name__ == "__main__":
    main()
