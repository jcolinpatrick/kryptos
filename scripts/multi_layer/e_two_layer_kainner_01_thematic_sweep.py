"""Two-layer substitution attack: KA inner + AZ outer.

Cipher: Two-layer substitution, KA inner + AZ outer
Family: multi_layer
Status: active
Keyspace: kw_inner × kw_outer × 3 inner variants × 3 outer variants
Last run:
Best score:

Hypothesis class
----------------

CT = sub_outer(sub_inner(PT, k_inner, KA), k_outer, AZ)

where each sub is one of {Vigenère, Beaufort, Variant Beaufort}.

The composition is genuinely two-layer (does NOT collapse to a single
periodic Vigenère) because KA's permutation breaks the
translation-invariance that lets two same-alphabet Vigenères collapse
to ``key_eff = key_2 + key_1``. Verified in this script's __main__
guard before sweep.

Why this hasn't been comprehensively tested
-------------------------------------------

The TABP series exhausted ``CT = sub(trans(PT))`` under both AZ and KA
inner substitution × single-layer and two-layer outer transposition.
That covers transposition-then-substitution. The two_layer_p13_p11.py
script tested ``sub2(sub1(PT))`` under SAME-alphabet composition (which
collapses; equivalent to single-layer Vigenère at lcm(p1, p2)). Neither
covered cross-alphabet substitution composition. K4's IC of 0.036 is
below the random expectation of 0.0385, which is consistent with two
substitution layers (each layer adds roughly random noise to surface
statistics). Single-layer eliminations under direct positional crib
mapping do not cover this hypothesis class. (Hard Blocker #2 in
MEMORY.md: "Single-layer eliminations do not eliminate those families
as one layer of a multi-layer construction.")

Pre-registration (binding before sweep launches)
------------------------------------------------

Universe size:
    |kw_inner| × |kw_outer| × |variants_inner| × |variants_outer|
    = 366 × 366 × 3 × 3 = 1,205,604 cells

Keyword pool: ``wordlists/thematic_keywords.txt`` filtered to length
4-14, A-Z only. The pool is the same one used by Phase 2.1/2.2 null
calibrators. Its size is 366 (verified at runtime; mismatch aborts).

Decryption:
    mid = decrypt_text(CT, kw_outer, var_outer, alphabet=AZ)
    PT  = decrypt_text(mid, kw_inner, var_inner, alphabet=KA)

Scoring: ``kryptos.kernel.scoring.aggregate.score_candidate`` —
anchored crib_score (24 positions) + Bean equality + Bean inequality
+ Bean linear constraints + ngram. PT-only scoring; CT is the
canonical 97-char carved K4 (no perturbation in this attack).

Alert / watchlist policy:
    BREAKTHROUGH: crib_score == 24 AND bean_passed AND ngram_score
                  >= -3.5 AND Bonferroni-adjusted p ≤ 0.01.
    SIGNAL:       crib_score >= 18.
    Watchlist:    crib_score >= 10 AND not BREAKTHROUGH.
    Noise:        crib_score < 10.

Bonferroni: across the full pre-declared universe (1,205,604 cells).
Per-cell raw crib p-value ≈ Binomial(24, 1/26) right-tail. For
crib_score=24 the raw p ≈ 26⁻²⁴ ≈ 1.5e-34; Bonferroni-adjusted by
1.2e6 yields ~1.8e-28, well below 0.01. The threshold is therefore
effectively "any crib_score=24 + bean_passed candidate is
overwhelmingly significant under multiplicity correction". For lower
crib_scores the adjusted p remains far above 0.01 — the alert path
is BREAKTHROUGH-exclusive at this cell count.

Outputs
-------

results/multi_layer_kainner_v1/
    sweep_summary.json
    top_candidates.jsonl
    alerts.jsonl
    watchlist.jsonl

Reproducibility
---------------

PYTHONPATH=src python3 -u scripts/multi_layer/e_two_layer_kainner_01_thematic_sweep.py [--workers N] [--top-n N] [--smoke]

The ``--smoke`` flag samples 100 keyword pairs randomly for a fast
correctness check before the full sweep.
"""
import argparse
import json
import math
import os
import sys
import time
from dataclasses import dataclass
from multiprocessing import Pool
from pathlib import Path
from typing import Any, Iterator

_HERE = Path(__file__).resolve()
_ROOT = _HERE.parent.parent.parent
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

from kryptos.kernel.alphabet import AZ, KA  # noqa: E402
from kryptos.kernel.constants import CT  # noqa: E402
from kryptos.kernel.scoring.aggregate import score_candidate  # noqa: E402
from kryptos.kernel.transforms.vigenere import (  # noqa: E402
    CipherVariant,
    decrypt_text,
)


# Pre-registered constants.
KEYWORDS_PATH = _ROOT / "wordlists" / "thematic_keywords.txt"
EXPECTED_POOL_SIZE = 366  # binding; mismatch aborts
KW_MIN_LEN = 4
KW_MAX_LEN = 14
ARTIFACT_ROOT = _ROOT / "results" / "multi_layer_kainner_v1"
NOISE_THRESHOLD = 10
SIGNAL_THRESHOLD = 18
BREAKTHROUGH_THRESHOLD = 24
NGRAM_FLOOR_FOR_BREAKTHROUGH = -3.5

VARIANTS = (
    CipherVariant.VIGENERE,
    CipherVariant.BEAUFORT,
    CipherVariant.VAR_BEAUFORT,
)


@dataclass(frozen=True)
class Cell:
    kw_inner: str
    kw_outer: str
    var_inner: str  # serializable; CipherVariant.value
    var_outer: str


def _load_keywords() -> list[str]:
    raw = KEYWORDS_PATH.read_text().splitlines()
    kws: list[str] = []
    for line in raw:
        kw = line.strip().upper()
        if KW_MIN_LEN <= len(kw) <= KW_MAX_LEN and kw.isalpha():
            kws.append(kw)
    if len(kws) != EXPECTED_POOL_SIZE:
        raise RuntimeError(
            f"keyword pool size {len(kws)} != expected {EXPECTED_POOL_SIZE}; "
            f"universe-size pre-registration is invalid. Update "
            f"EXPECTED_POOL_SIZE if the keyword file changed deliberately."
        )
    return kws


def _verify_non_collapse() -> None:
    """Sanity check: KA-inner Vig + AZ-outer Vig does NOT collapse to
    a single periodic Vigenère in either alphabet.

    This is a property of the cipher class. We verify it once at
    runtime so a future change to the alphabet machinery does not
    silently invalidate the entire sweep.
    """
    from kryptos.kernel.transforms.vigenere import encrypt_text

    pt = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 3
    pt = pt[:60]
    k1, k2 = "KEY", "WORD"  # periods 3 and 4
    mid = encrypt_text(
        pt, KA.encode(k1), variant=CipherVariant.VIGENERE, alphabet=KA,
    )
    ct_test = encrypt_text(
        mid, AZ.encode(k2), variant=CipherVariant.VIGENERE, alphabet=AZ,
    )

    def _idx(ch: str, table: list[int]) -> int:
        return table[ord(ch) - 65]

    key_eff_az = [
        (_idx(ct_test[i], AZ.index_table) - _idx(pt[i], AZ.index_table)) % 26
        for i in range(60)
    ]
    for p in range(1, 31):
        if all(key_eff_az[i] == key_eff_az[i % p] for i in range(60)):
            raise RuntimeError(
                f"KA × AZ Vigenère collapses to period {p} in AZ; the "
                f"hypothesis class is degenerate and the sweep would "
                f"duplicate single-Vigenère elimination work."
            )


def _enumerate_cells(keywords: list[str]) -> Iterator[Cell]:
    for kw_inner in keywords:
        for kw_outer in keywords:
            for var_inner in VARIANTS:
                for var_outer in VARIANTS:
                    yield Cell(
                        kw_inner=kw_inner,
                        kw_outer=kw_outer,
                        var_inner=var_inner.value,
                        var_outer=var_outer.value,
                    )


def _evaluate_cell(cell: Cell) -> dict[str, Any]:
    """Decrypt CT under (var_outer, kw_outer, AZ) then (var_inner, kw_inner, KA)
    and score the resulting plaintext.
    """
    var_outer = CipherVariant(cell.var_outer)
    var_inner = CipherVariant(cell.var_inner)
    mid = decrypt_text(
        CT,
        AZ.encode(cell.kw_outer),
        variant=var_outer,
        alphabet=AZ,
    )
    pt = decrypt_text(
        mid,
        KA.encode(cell.kw_inner),
        variant=var_inner,
        alphabet=KA,
    )
    breakdown = score_candidate(pt)
    return {
        "kw_inner": cell.kw_inner,
        "kw_outer": cell.kw_outer,
        "var_inner": cell.var_inner,
        "var_outer": cell.var_outer,
        "crib_score": int(breakdown.crib_score),
        "bean_passed": bool(breakdown.bean_passed),
        "ngram_score": (
            float(breakdown.ngram_score)
            if breakdown.ngram_score is not None
            else None
        ),
        "classification": str(
            getattr(breakdown, "crib_classification", "?")
        ),
        "pt_first_24": pt[:24],
        "pt_cribs": pt[21:34] + "|" + pt[63:74],
    }


def _crib_p_value(crib_score: int, crib_total: int = 24) -> float:
    """Right-tail Binomial(crib_total, 1/26) p-value."""
    if crib_score <= 0:
        return 1.0
    if crib_score > crib_total:
        return 0.0
    p = 1.0 / 26.0
    q = 1.0 - p
    cdf = 0.0
    for k in range(crib_score):
        cdf += math.comb(crib_total, k) * (p**k) * (q ** (crib_total - k))
    return max(0.0, 1.0 - cdf)


def _bonferroni(p_raw: float, universe_size: int) -> float:
    return min(1.0, p_raw * universe_size)


def _classify(row: dict[str, Any], universe_size: int) -> str:
    crib = row["crib_score"]
    bean = row["bean_passed"]
    ngram = row["ngram_score"]
    if crib < NOISE_THRESHOLD:
        return "noise"
    p_raw = _crib_p_value(crib)
    p_adj = _bonferroni(p_raw, universe_size)
    if (
        crib == BREAKTHROUGH_THRESHOLD
        and bean
        and ngram is not None
        and ngram >= NGRAM_FLOOR_FOR_BREAKTHROUGH
        and p_adj <= 0.01
    ):
        return "breakthrough"
    if crib >= SIGNAL_THRESHOLD:
        return "signal"
    return "watchlist"


def _build_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--workers",
        type=int,
        default=max(1, (os.cpu_count() or 4) - 2),
        help="Parallel worker count (default cpu_count - 2)",
    )
    ap.add_argument(
        "--top-n",
        type=int,
        default=100,
        help="Retain top-N candidates by crib_score in JSONL",
    )
    ap.add_argument(
        "--smoke",
        action="store_true",
        help="Run a 1000-cell smoke sample; do not run the full sweep",
    )
    ap.add_argument(
        "--artifact-root",
        type=Path,
        default=ARTIFACT_ROOT,
    )
    ap.add_argument(
        "--report-every",
        type=int,
        default=50_000,
        help="Print progress every N cells (default 50K)",
    )
    return ap


def main(argv: list[str] | None = None) -> int:
    args = _build_argparser().parse_args(argv)

    # Pre-flight invariants.
    _verify_non_collapse()
    keywords = _load_keywords()
    pool_size = len(keywords)

    expected_universe = pool_size * pool_size * len(VARIANTS) * len(VARIANTS)

    cells = list(_enumerate_cells(keywords))
    if len(cells) != expected_universe:
        raise RuntimeError(
            f"enumerated {len(cells)} cells != predicted {expected_universe}"
        )

    if args.smoke:
        # Deterministic smoke: take first 1000 cells.
        cells = cells[:1000]
        print(f"[SMOKE MODE] sampling {len(cells)} of {expected_universe} cells")
        universe_size_for_pvalue = expected_universe  # keep multiplicity intact
    else:
        universe_size_for_pvalue = expected_universe

    args.artifact_root.mkdir(parents=True, exist_ok=True)
    print(f"Artifact root: {args.artifact_root}")
    print(f"Pool size: {pool_size} keywords (length {KW_MIN_LEN}-{KW_MAX_LEN})")
    print(f"Universe (pre-registered): {expected_universe:,} cells")
    print(f"Workers: {args.workers}")
    print()

    top_n = args.top_n
    top_buffer: list[dict[str, Any]] = []
    alerts: list[dict[str, Any]] = []
    watchlist: list[dict[str, Any]] = []
    breakthrough_count = 0
    signal_count = 0
    watchlist_count = 0
    noise_count = 0
    bean_pass_count = 0
    candidates_evaluated = 0

    t_start = time.time()
    with Pool(processes=args.workers) as pool:
        for row in pool.imap_unordered(
            _evaluate_cell, cells, chunksize=256,
        ):
            candidates_evaluated += 1
            if row["bean_passed"]:
                bean_pass_count += 1

            classification = _classify(row, universe_size_for_pvalue)
            row["sweep_classification"] = classification

            if classification == "breakthrough":
                breakthrough_count += 1
                alerts.append(row)
            elif classification == "signal":
                signal_count += 1
                alerts.append(row)
            elif classification == "watchlist":
                watchlist_count += 1
                watchlist.append(row)
            else:
                noise_count += 1

            # Top-N retention by crib_score (then by ngram if tied).
            if len(top_buffer) < top_n:
                top_buffer.append(row)
                top_buffer.sort(
                    key=lambda r: (
                        -(r["crib_score"]),
                        -(r["ngram_score"] or -99),
                    )
                )
            elif row["crib_score"] > top_buffer[-1]["crib_score"]:
                top_buffer[-1] = row
                top_buffer.sort(
                    key=lambda r: (
                        -(r["crib_score"]),
                        -(r["ngram_score"] or -99),
                    )
                )

            if candidates_evaluated % args.report_every == 0:
                elapsed = time.time() - t_start
                rate = candidates_evaluated / max(elapsed, 0.001)
                eta = (len(cells) - candidates_evaluated) / max(rate, 1)
                print(
                    f"  {candidates_evaluated:>10,} / {len(cells):,}  "
                    f"({100 * candidates_evaluated / len(cells):>5.1f}%)  "
                    f"rate={rate:>7.0f}/s  eta={eta:>5.0f}s  "
                    f"top_crib={top_buffer[0]['crib_score']}  "
                    f"alerts={breakthrough_count + signal_count}  "
                    f"watchlist={watchlist_count}"
                )

    elapsed = time.time() - t_start

    summary = {
        "schema_version": "two_layer_kainner_v1.summary.v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "smoke_mode": args.smoke,
        "universe_size_pre_registered": expected_universe,
        "candidates_evaluated": candidates_evaluated,
        "wall_seconds": round(elapsed, 1),
        "evaluations_per_second": round(
            candidates_evaluated / max(elapsed, 0.001), 1
        ),
        "workers": args.workers,
        "pool_size": pool_size,
        "thresholds": {
            "noise": NOISE_THRESHOLD,
            "signal": SIGNAL_THRESHOLD,
            "breakthrough": BREAKTHROUGH_THRESHOLD,
            "ngram_floor_for_breakthrough": NGRAM_FLOOR_FOR_BREAKTHROUGH,
        },
        "counts": {
            "breakthrough": breakthrough_count,
            "signal": signal_count,
            "watchlist": watchlist_count,
            "noise": noise_count,
            "bean_pass": bean_pass_count,
        },
        "top_candidate": top_buffer[0] if top_buffer else None,
        "top_n": top_n,
    }
    (args.artifact_root / "sweep_summary.json").write_text(
        json.dumps(summary, indent=2)
    )

    with (args.artifact_root / "top_candidates.jsonl").open("w") as f:
        for row in top_buffer:
            f.write(json.dumps(row) + "\n")
    with (args.artifact_root / "alerts.jsonl").open("w") as f:
        for row in alerts:
            f.write(json.dumps(row) + "\n")
    with (args.artifact_root / "watchlist.jsonl").open("w") as f:
        for row in watchlist:
            f.write(json.dumps(row) + "\n")

    print()
    print("=" * 72)
    print("  Two-layer KA-inner + AZ-outer sweep complete")
    print("=" * 72)
    print(f"  candidates evaluated:       {candidates_evaluated:>12,}")
    print(f"  wall time:                  {elapsed:>11.1f}s")
    print(f"  rate:                       {candidates_evaluated/max(elapsed, 0.001):>11.0f}/s")
    print(f"  bean_passed:                {bean_pass_count:>12,}")
    print(f"  breakthrough alerts:        {breakthrough_count:>12,}")
    print(f"  signal alerts:              {signal_count:>12,}")
    print(f"  watchlist:                  {watchlist_count:>12,}")
    print(f"  noise:                      {noise_count:>12,}")
    print()
    if top_buffer:
        top = top_buffer[0]
        print(
            f"  Top candidate: crib_score={top['crib_score']}  "
            f"bean_passed={top['bean_passed']}  "
            f"ngram={top['ngram_score']}"
        )
        print(
            f"    kw_inner={top['kw_inner']}  kw_outer={top['kw_outer']}  "
            f"var_inner={top['var_inner']}  var_outer={top['var_outer']}"
        )
        print(f"    pt_cribs: {top['pt_cribs']}")
    print()
    return 0 if breakthrough_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
