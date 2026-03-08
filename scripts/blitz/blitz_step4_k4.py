#!/usr/bin/env python3
"""
Cipher: multi-method blitz
Family: blitz
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_step4_k4.py
==========================================================================
Step-4 column reading order — extension from K3 to K4.

DISCOVERY (from blitz_tableau_structural.py BONUS section):
  K3's reading order uses step -4 (mod 31) within each row.
  Starting columns for rows 14–24 (the K3 region):
    row 14 → 30
    row 15 → 15  (diff +16)
    row 16 → 27  (diff +12)
    row 17 →  0  (diff  +4)
    row 18 → 16  (diff +16)
    row 19 → 28  (diff +12)
    row 20 →  5  (diff  +8)
    row 21 → 21  (diff +16)
    row 22 → 29  (diff  +8)
    row 23 →  6  (diff  +8)
    row 24 → 22  (diff +16)   ← last K3 row (cols 0-25)

HYPOTHESIS:
  The same step-4 column pattern continues for K4 rows 25–27.
  Row 24's K4 columns (27–30) appear interleaved in the step-4 sequence
  starting at col 22, at steps k=6,14,22,29 → cols 29,28,27,30 in that order
  → K4 positions [2, 1, 0, 3] (since K4 col_offset = col - 27 for row 24).

  Rows 25, 26, 27 each have an unknown starting column ∈ {0..30}.

SEARCH:
  MAIN:  31³ = 29,791 combinations of (s25, s26, s27).
  EXT1:  All 10 cyclic rotations of the K3 diff pattern.
  EXT2:  All 31² = 961 (s26, s27) for EACH predicted s25 from diff extrapolation.

Usage:
  PYTHONPATH=src python3 -u scripts/blitz/blitz_step4_k4.py
"""
from __future__ import annotations
import sys, time, json
sys.path.insert(0, "scripts")
from kbot_harness import K4_CARVED, test_perm

# ── K3 structural constants ────────────────────────────────────────────────────

# Starting columns for K3 rows 14–24 (derived from K3 permutation analysis)
K3_START_COLS = [30, 15, 27, 0, 16, 28, 5, 21, 29, 6, 22]
# Row-to-row diffs (mod 31)
K3_DIFFS = [(K3_START_COLS[i + 1] - K3_START_COLS[i]) % 31 for i in range(10)]
# K3_DIFFS = [16, 12, 4, 16, 12, 8, 16, 8, 8, 16]

# Row-24 K4 reading order (FIXED by step-4 starting at col 22):
# Full step-4 seq for row 24: k=0→22, k=1→18, k=2→14, k=3→10, k=4→6,
#   k=5→2, k=6→29(K4!), k=7→25, ... k=14→28(K4!), ... k=22→27(K4!),
#   ... k=29→30(K4!), k=30→26(?)
# K4 cols in order read: 29, 28, 27, 30 → K4 positions 2, 1, 0, 3
ROW24_K4_ORDER = [2, 1, 0, 3]


# ── Permutation builder ────────────────────────────────────────────────────────

def build_sigma(s25: int, s26: int, s27: int) -> list[int]:
    """Build 97-element K4 scramble permutation.

    Convention (matches kbot_harness.test_perm):
      real_CT[j] = K4_CARVED[sigma[j]]

    Layout:
      sigma[0..3]   = ROW24_K4_ORDER  (fixed)
      sigma[4+k]    = 4  + (s25 - 4k) % 31   k=0..30  (row 25)
      sigma[35+k]   = 35 + (s26 - 4k) % 31   k=0..30  (row 26)
      sigma[66+k]   = 66 + (s27 - 4k) % 31   k=0..30  (row 27)
    """
    sigma = list(ROW24_K4_ORDER)                       # slots 0..3
    for k in range(31):
        sigma.append(4  + (s25 - 4 * k) % 31)         # slots 4..34
    for k in range(31):
        sigma.append(35 + (s26 - 4 * k) % 31)         # slots 35..65
    for k in range(31):
        sigma.append(66 + (s27 - 4 * k) % 31)         # slots 66..96
    return sigma


# ── Helpers ────────────────────────────────────────────────────────────────────

def _fmt(res: dict | None) -> str:
    if res is None:
        return "None"
    sc = res.get("score_per_char", -999)
    flag = "🎯CRIB" if res.get("crib_hit") else ""
    return (f"score={sc:.4f}  key={res.get('key')}  "
            f"cipher={res.get('cipher')}  alpha={res.get('alpha')}  {flag}")


def _run(s25: int, s26: int, s27: int,
         crib_hits: list, best_tracker: list) -> tuple[float, bool]:
    """Evaluate one (s25, s26, s27) triple.  Returns (score_per_char, crib_hit)."""
    sigma = build_sigma(s25, s26, s27)
    res = test_perm(sigma)
    if res is None:
        return -999.0, False
    sc = res.get("score_per_char", -999.0)
    hit = bool(res.get("crib_hit"))
    if hit:
        crib_hits.append((s25, s26, s27, res))
    if not best_tracker or sc > best_tracker[0][0]:
        best_tracker[:] = [(sc, s25, s26, s27, res)]
    return sc, hit


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    t0 = time.time()

    print("=" * 70)
    print("blitz_step4_k4.py — Step-4 column extension to K4")
    print(f"K4_CARVED  = {K4_CARVED}")
    print(f"K3 start cols (rows 14-24): {K3_START_COLS}")
    print(f"K3 diffs: {K3_DIFFS}")
    print(f"Row-24 K4 fixed order: {ROW24_K4_ORDER}")
    print("=" * 70)

    # Sanity: sigma must always be a permutation of 0..96
    _test = build_sigma(7, 13, 29)
    assert sorted(_test) == list(range(97)), "BUG: sigma not a permutation!"
    print("✓ sigma is always a valid permutation of 0..96")

    # Verify row-24 K4 interleaving by direct calculation
    row24_k4_direct = []
    seq24 = [(22 - 4 * k) % 31 for k in range(31)]
    for k, col in enumerate(seq24):
        if col in (27, 28, 29, 30):
            row24_k4_direct.append(col - 27)  # K4 position within row 24
    print(f"Row-24 K4 cols in step-4 order: {[c+27 for c in row24_k4_direct]}")
    print(f"Row-24 K4 positions in reading order: {row24_k4_direct}  (should be [2,1,0,3])")
    assert row24_k4_direct == [2, 1, 0, 3], f"Mismatch: {row24_k4_direct}"
    print()

    # ── Section 1: Full 31³ exhaustive search ─────────────────────────────────
    print("─" * 70)
    print(f"SECTION 1: Exhaustive search — 31³ = {31**3:,} (s25, s26, s27)")
    print("─" * 70)

    THRESHOLD = -5.2   # per-char score threshold for "notable" prints
    crib_hits: list = []
    best_tracker: list = []
    total = 31 ** 3
    checked = 0

    for s25 in range(31):
        for s26 in range(31):
            for s27 in range(31):
                sc, hit = _run(s25, s26, s27, crib_hits, best_tracker)
                checked += 1

                if hit:
                    res = crib_hits[-1][3]
                    print(f"\n{'='*60}")
                    print(f"🎯 CRIB HIT!  s25={s25}  s26={s26}  s27={s27}")
                    print(f"  real_CT : {res['real_ct']}")
                    print(f"  PT      : {res['pt']}")
                    print(f"  key={res['key']}  cipher={res['cipher']}  alpha={res['alpha']}")
                    print(f"  score/char = {sc:.4f}")
                    print(f"{'='*60}\n")
                    # Do NOT stop — keep searching for more hits

                elif sc > THRESHOLD and best_tracker and sc == best_tracker[0][0]:
                    res = best_tracker[0][4]
                    print(f"  Notable  s25={s25:2d} s26={s26:2d} s27={s27:2d}  "
                          f"score={sc:.4f}  key={res.get('key')}  "
                          f"cipher={res.get('cipher')}  alpha={res.get('alpha')}")
                    print(f"    PT: {res.get('pt', '')[:50]}...")

                if checked % 5000 == 0:
                    bs = best_tracker[0][0] if best_tracker else -999
                    print(f"  [{checked:5d}/{total}] best={bs:.4f}  "
                          f"elapsed={time.time()-t0:.1f}s")

    elapsed = time.time() - t0
    print(f"\nSection 1 done: {checked:,} combos in {elapsed:.1f}s")
    print(f"Crib hits: {len(crib_hits)}")
    if crib_hits:
        for s25, s26, s27, r in crib_hits:
            print(f"  s25={s25} s26={s26} s27={s27}  PT: {r.get('pt')}")
    if best_tracker:
        bs, s25b, s26b, s27b, rb = best_tracker[0]
        print(f"Best: s25={s25b} s26={s26b} s27={s27b}  score/char={bs:.4f}")
        print(f"  key={rb.get('key')}  cipher={rb.get('cipher')}  alpha={rb.get('alpha')}")
        print(f"  real_CT: {rb.get('real_ct')}")
        print(f"  PT     : {rb.get('pt')}")

    # ── Section 2: Cyclic diff-pattern extrapolation ──────────────────────────
    print()
    print("─" * 70)
    print("SECTION 2: Cyclic continuation of K3 diff pattern")
    print(f"K3 diffs: {K3_DIFFS}")
    print("─" * 70)
    ext_crib_hits: list = []
    ext_best: list = []

    for rot in range(10):
        d0 = K3_DIFFS[rot % 10]
        d1 = K3_DIFFS[(rot + 1) % 10]
        d2 = K3_DIFFS[(rot + 2) % 10]
        s25r = (22 + d0) % 31
        s26r = (s25r + d1) % 31
        s27r = (s26r + d2) % 31
        sc, hit = _run(s25r, s26r, s27r, ext_crib_hits, ext_best)
        res = build_sigma(s25r, s26r, s27r)
        res_d = test_perm(res)
        flag = "🎯 CRIB" if hit else ("⭐" if sc > -5.5 else "")
        key_str = res_d.get("key", "?") if res_d else "?"
        print(f"  rot={rot:2d}  s25={s25r:2d} s26={s26r:2d} s27={s27r:2d}  "
              f"score={sc:.4f}  key={key_str}  {flag}")
        if hit and res_d:
            print(f"    PT: {res_d.get('pt')}")

    print(f"Crib hits in ext: {len(ext_crib_hits)}")

    # ── Section 3: Arithmetic sequence extrapolation ──────────────────────────
    print()
    print("─" * 70)
    print("SECTION 3: Arithmetic extrapolation of starting-col sequence")
    print("─" * 70)
    # Starting cols: 30,15,27,0,16,28,5,21,29,6,22 (rows 14-24)
    # Try linear fit: start[n] = a + b*n (mod 31)
    # Two-point fit using last two known: rows 23→24: 6→22, diff=+16
    # Predict row 25: 22+16=38≡7, row26: 7+16=23, row27: 23+16=39≡8 (constant diff=16)
    # Also try using alternating diffs from the sequence end
    arith_preds: list[tuple] = []

    # Constant-diff extrapolations (try each of the observed diffs)
    print("  Constant-diff extrapolations from row-24 start=22:")
    for d in sorted(set(K3_DIFFS)):
        s25a = (22 + d) % 31
        s26a = (s25a + d) % 31
        s27a = (s26a + d) % 31
        sc, hit = _run(s25a, s26a, s27a, crib_hits, best_tracker)
        flag = "🎯 CRIB" if hit else ("⭐" if sc > -5.5 else "")
        print(f"    const diff={d:2d}  s25={s25a:2d} s26={s26a:2d} s27={s27a:2d}  "
              f"score={sc:.4f}  {flag}")
        arith_preds.append((d, s25a, s26a, s27a, sc, hit))
        if hit:
            print(f"      → PT: {crib_hits[-1][3].get('pt')}")

    # Also try reverse extrapolation (going backwards through the diff list)
    print("  Reverse-diff extrapolations (diffs in reverse order from end):")
    rev_diffs = K3_DIFFS[::-1]
    for rot in range(min(5, 10)):
        d0 = rev_diffs[rot % 10]
        d1 = rev_diffs[(rot + 1) % 10]
        d2 = rev_diffs[(rot + 2) % 10]
        s25r = (22 + d0) % 31
        s26r = (s25r + d1) % 31
        s27r = (s26r + d2) % 31
        sc, hit = _run(s25r, s26r, s27r, crib_hits, best_tracker)
        flag = "🎯 CRIB" if hit else ("⭐" if sc > -5.5 else "")
        print(f"    revrot={rot}  s25={s25r:2d} s26={s26r:2d} s27={s27r:2d}  "
              f"score={sc:.4f}  {flag}")
        if hit:
            print(f"      → PT: {crib_hits[-1][3].get('pt')}")

    # ── Section 4: Alternative row-24 K4 orders ───────────────────────────────
    print()
    print("─" * 70)
    print("SECTION 4: Alternative row-24 K4 reading orders (not interleaved)")
    print("─" * 70)
    # What if row-24 K4 is read in FORWARD col order (27,28,29,30) → positions 0,1,2,3?
    # Or REVERSE (30,29,28,27) → positions 3,2,1,0?
    # Or any of the 4! = 24 permutations of {0,1,2,3}?
    # We'll test all 24 × 31³ ... no, just a few plausible ones with best s25,s26,s27

    alt_orders = [
        ([0, 1, 2, 3], "forward 27,28,29,30"),
        ([3, 2, 1, 0], "reverse 30,29,28,27"),
        ([2, 1, 0, 3], "step-4 interleaved (canonical)"),
        ([1, 0, 3, 2], "paired swap"),
        ([0, 2, 1, 3], "inner swap"),
    ]

    alt_crib_hits: list = []

    if best_tracker:
        # Use the best s25,s26,s27 from main search
        _, bs25, bs26, bs27, _ = best_tracker[0]
        print(f"  Using best s25={bs25} s26={bs26} s27={bs27} from main search:")
        for order, label in alt_orders:
            # Build sigma with this row-24 order
            sigma_alt = list(order)
            for k in range(31):
                sigma_alt.append(4  + (bs25 - 4 * k) % 31)
            for k in range(31):
                sigma_alt.append(35 + (bs26 - 4 * k) % 31)
            for k in range(31):
                sigma_alt.append(66 + (bs27 - 4 * k) % 31)
            assert sorted(sigma_alt) == list(range(97))
            res_alt = test_perm(sigma_alt)
            if res_alt:
                sc_alt = res_alt.get("score_per_char", -999)
                flag = "🎯 CRIB" if res_alt.get("crib_hit") else ""
                print(f"    [{label}]  score={sc_alt:.4f}  {flag}")
                if res_alt.get("crib_hit"):
                    alt_crib_hits.append((order, label, bs25, bs26, bs27, res_alt))
                    print(f"      PT: {res_alt.get('pt')}")
    else:
        print("  (no best result from main search — skipping)")

    # Also try forward/reverse orders with full 31³ search but only report > -5.5
    print()
    print("  Checking forward order [0,1,2,3] and reverse [3,2,1,0] across 31³:")
    for alt_row24, alt_label in [([0,1,2,3], "forward"), ([3,2,1,0], "reverse")]:
        alt_best: list = []
        for s25 in range(31):
            for s26 in range(31):
                for s27 in range(31):
                    sigma_a = list(alt_row24)
                    for k in range(31): sigma_a.append(4  + (s25 - 4*k) % 31)
                    for k in range(31): sigma_a.append(35 + (s26 - 4*k) % 31)
                    for k in range(31): sigma_a.append(66 + (s27 - 4*k) % 31)
                    res_a = test_perm(sigma_a)
                    if res_a:
                        sc_a = res_a.get("score_per_char", -999)
                        if res_a.get("crib_hit"):
                            print(f"  🎯 CRIB [{alt_label}] s25={s25} s26={s26} s27={s27}  "
                                  f"PT: {res_a.get('pt')}")
                            alt_crib_hits.append((alt_row24, alt_label, s25, s26, s27, res_a))
                        if not alt_best or sc_a > alt_best[0][0]:
                            alt_best[:] = [(sc_a, s25, s26, s27, res_a)]
        if alt_best:
            bs2, s25b2, s26b2, s27b2, rb2 = alt_best[0]
            print(f"  [{alt_label}] best: s25={s25b2} s26={s26b2} s27={s27b2}  "
                  f"score={bs2:.4f}  key={rb2.get('key')}")

    # ── Final summary & verdict ────────────────────────────────────────────────
    total_crib_hits = len(crib_hits) + len(alt_crib_hits) + len(ext_crib_hits)
    elapsed_total = time.time() - t0

    print()
    print("=" * 70)
    print(f"TOTAL ELAPSED: {elapsed_total:.1f}s")
    print(f"TOTAL CRIB HITS (all sections): {total_crib_hits}")
    print()

    if best_tracker:
        bs, s25b, s26b, s27b, rb = best_tracker[0]
        print(f"OVERALL BEST (canonical step-4):")
        print(f"  s25={s25b}  s26={s26b}  s27={s27b}")
        print(f"  score/char = {bs:.4f}")
        print(f"  key={rb.get('key')}  cipher={rb.get('cipher')}  alpha={rb.get('alpha')}")
        print(f"  real_CT: {rb.get('real_ct')}")
        print(f"  PT     : {rb.get('pt')}")
    else:
        print("No results above threshold.")

    print()
    print("VERDICT JSON:")
    verdict = {
        "script": "blitz_step4_k4.py",
        "hypothesis": "K4 grille uses step-4 (mod 31) column reading order per row, same as K3",
        "k3_start_cols": K3_START_COLS,
        "k3_diffs": K3_DIFFS,
        "row24_k4_order_fixed": ROW24_K4_ORDER,
        "search_space_main": 31 ** 3,
        "total_crib_hits": total_crib_hits,
    }
    if best_tracker:
        bs, s25b, s26b, s27b, rb = best_tracker[0]
        verdict.update({
            "best_score_per_char": round(bs, 4),
            "best_s25": s25b,
            "best_s26": s26b,
            "best_s27": s27b,
            "best_key": rb.get("key"),
            "best_cipher": rb.get("cipher"),
            "best_alpha": rb.get("alpha"),
            "best_pt": rb.get("pt"),
        })
    verdict["verdict_text"] = (
        "SOLVED" if total_crib_hits > 0 else
        "null result — step-4 column hypothesis does not yield cribs; "
        "best score suggests noise-level only"
    )
    print(json.dumps(verdict, indent=2))


if __name__ == "__main__":
    main()
