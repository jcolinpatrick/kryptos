"""
Hamming-1 cipher-agnostic statistical sweep over canonical K4 CT.

For each of 97 * 25 = 2425 single-character substitutions of the canonical
K4 ciphertext, compute pure CT-statistical metrics and rank the perturbations
without invoking any cipher attack. The intent is to ask whether a single
hypothetical carving error would meaningfully shift the intrinsic statistical
fingerprint of the CT toward (or away from) English / random structure.

Metrics:
  1. IC (index of coincidence) over full CT.
  2. Repeat-bigram count at full CT and at width-21 (vertical bigrams across
     21-column rows; the project's known anomaly p ~ 1/6750).
  3. Friedman best-period kappa (max IC among periods 1..26 by per-column IC).
  4. Autocorrelation max coincidence rate at offsets 1..50.
  5. Letter-frequency chi-square vs English monogram distribution.
  6. Number of unique letters present (baseline 26).

Output:
  - JSON dump of full per-perturbation metrics
  - Markdown summary
  - Cross-metric overall rank (rank-sum aggregation)

Stdlib only. Multiprocessing with cpu_count() - 2.
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from multiprocessing import Pool, cpu_count
from pathlib import Path
from time import time

# --- ensure src on path ---
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if os.path.join(_ROOT, "src") not in sys.path:
    sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT  # noqa: E402

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# English letter relative frequencies (Norvig / Beker-Piper consensus).
ENGLISH_FREQ = {
    "A": 0.0817, "B": 0.0149, "C": 0.0278, "D": 0.0425, "E": 0.1270,
    "F": 0.0223, "G": 0.0202, "H": 0.0609, "I": 0.0697, "J": 0.0015,
    "K": 0.0077, "L": 0.0403, "M": 0.0241, "N": 0.0675, "O": 0.0751,
    "P": 0.0193, "Q": 0.0010, "R": 0.0599, "S": 0.0633, "T": 0.0906,
    "U": 0.0276, "V": 0.0098, "W": 0.0236, "X": 0.0015, "Y": 0.0197,
    "Z": 0.0007,
}

# Out path for results.
OUT_DIR = Path("/home/cpatrick/kryptos/analysis_runs/hamming1_statistical_sweep_2026_05_06")


# ---------------- Metrics ----------------


def index_of_coincidence(text: str) -> float:
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    s = sum(c * (c - 1) for c in counts.values())
    return s / (n * (n - 1))


def repeat_bigram_count(text: str) -> int:
    """Count bigram occurrences beyond the first (sum over duplicates)."""
    bigrams = [text[i : i + 2] for i in range(len(text) - 1)]
    counts = Counter(bigrams)
    return sum(c - 1 for c in counts.values() if c > 1)


def width21_vertical_bigram_repeats(text: str, width: int = 21) -> int:
    """
    Lay text out in `width` columns, then form vertical bigrams (column-wise
    pairs of adjacent rows). Count repeats among those vertical bigrams.

    This corresponds to the project's known anomaly: at width 21 over the
    97-char CT there are 11 repeat vertical bigrams.
    """
    n = len(text)
    rows = [text[i : i + width] for i in range(0, n, width)]
    # full rows only for paired access
    full_rows = [r for r in rows if len(r) == width]
    if len(full_rows) < 2:
        return 0
    pairs: list[str] = []
    for r1, r2 in zip(full_rows, full_rows[1:]):
        for c in range(width):
            pairs.append(r1[c] + r2[c])
    counts = Counter(pairs)
    return sum(c - 1 for c in counts.values() if c > 1)


def friedman_best_period(text: str, max_period: int = 26) -> tuple[int, float]:
    """
    For each candidate period p in 1..max_period, average IC over the p
    columns. Return (period, kappa) maximizing average IC. A higher kappa
    suggests a periodic mono-substitution structure; English-like text on
    its true period gives kappa close to English IC (~0.067).
    """
    best_p = 1
    best_k = 0.0
    n = len(text)
    for p in range(1, max_period + 1):
        cols = [text[i::p] for i in range(p)]
        # weighted by column length (each col has ~ n/p chars)
        ics = []
        weights = []
        for c in cols:
            if len(c) >= 2:
                ics.append(index_of_coincidence(c))
                weights.append(len(c))
        if not weights:
            continue
        kappa = sum(i * w for i, w in zip(ics, weights)) / sum(weights)
        if kappa > best_k:
            best_k = kappa
            best_p = p
    return best_p, best_k


def autocorrelation_max(text: str, max_offset: int = 50) -> tuple[int, float]:
    """
    For each offset d in 1..max_offset, compute coincidence rate
    (# i where text[i] == text[i+d]) / (len(text) - d). Return
    (offset, rate) maximizing rate.
    """
    best_d = 1
    best_r = 0.0
    n = len(text)
    for d in range(1, min(max_offset, n - 1) + 1):
        m = n - d
        coinc = sum(1 for i in range(m) if text[i] == text[i + d])
        rate = coinc / m if m > 0 else 0.0
        if rate > best_r:
            best_r = rate
            best_d = d
    return best_d, best_r


def chi_square_english(text: str) -> float:
    """Chi-square distance of letter frequencies vs English."""
    n = len(text)
    counts = Counter(text)
    chi2 = 0.0
    for letter in ALPHABET:
        observed = counts.get(letter, 0)
        expected = ENGLISH_FREQ[letter] * n
        if expected > 0:
            chi2 += (observed - expected) ** 2 / expected
    return chi2


def unique_letters(text: str) -> int:
    return len(set(text))


# ---------------- Sweep ----------------


def perturb(ct: str, pos: int, new_char: str) -> str:
    return ct[:pos] + new_char + ct[pos + 1:]


def evaluate(args: tuple[int, str]) -> dict:
    """Evaluate one (pos, new_char) perturbation."""
    pos, new_char = args
    text = perturb(CT, pos, new_char)
    ic_full = index_of_coincidence(text)
    rep_full = repeat_bigram_count(text)
    rep21 = width21_vertical_bigram_repeats(text, 21)
    fri_p, fri_k = friedman_best_period(text, 26)
    ac_d, ac_r = autocorrelation_max(text, 50)
    chi2 = chi_square_english(text)
    uniq = unique_letters(text)
    return {
        "pos": pos,
        "orig": CT[pos],
        "new": new_char,
        "ic_full": ic_full,
        "rep_bigram_full": rep_full,
        "rep_bigram_w21": rep21,
        "friedman_period": fri_p,
        "friedman_kappa": fri_k,
        "autocorr_offset": ac_d,
        "autocorr_rate": ac_r,
        "chi2_english": chi2,
        "unique_letters": uniq,
    }


def baseline_metrics() -> dict:
    return {
        "ic_full": index_of_coincidence(CT),
        "rep_bigram_full": repeat_bigram_count(CT),
        "rep_bigram_w21": width21_vertical_bigram_repeats(CT, 21),
        "friedman_period": friedman_best_period(CT, 26)[0],
        "friedman_kappa": friedman_best_period(CT, 26)[1],
        "autocorr_offset": autocorrelation_max(CT, 50)[0],
        "autocorr_rate": autocorrelation_max(CT, 50)[1],
        "chi2_english": chi_square_english(CT),
        "unique_letters": unique_letters(CT),
    }


def make_jobs() -> list[tuple[int, str]]:
    jobs = []
    for pos in range(len(CT)):
        original = CT[pos]
        for new in ALPHABET:
            if new == original:
                continue
            jobs.append((pos, new))
    return jobs


def rank_results(results: list[dict]) -> dict[str, list[int]]:
    """
    Compute per-metric rank arrays. Each rank list is parallel to `results`.

    Direction convention (1 = "most English-improvement / least anomalous"):
      - ic_full: higher is more English-like (toward 0.067). Rank descending.
      - rep_bigram_full: lower is less anomalous. Rank ascending.
      - rep_bigram_w21: lower is less anomalous. Rank ascending.
      - friedman_kappa: higher means cleaner periodic structure (could go
        either way). We rank ABS-deviation from CT baseline, treating both
        directions as informative; we'll capture max-up and max-down lists
        separately. For rank-sum we use higher-is-better (reveals stronger
        periodic structure).
      - autocorr_rate: higher = stronger periodic/repetition structure.
        Rank descending.
      - chi2_english: lower = closer to English distribution. Rank ascending.
      - unique_letters: lower than 26 is informative (collapses alphabet).
        Rank ascending (lower first).
    """
    n = len(results)
    idx = list(range(n))
    out: dict[str, list[int]] = {}

    # ic_full: descending
    order = sorted(idx, key=lambda i: -results[i]["ic_full"])
    rank = [0] * n
    for r, i in enumerate(order):
        rank[i] = r + 1
    out["ic_full"] = rank

    # rep_bigram_full: ascending
    order = sorted(idx, key=lambda i: results[i]["rep_bigram_full"])
    rank = [0] * n
    for r, i in enumerate(order):
        rank[i] = r + 1
    out["rep_bigram_full"] = rank

    # rep_bigram_w21: ascending
    order = sorted(idx, key=lambda i: results[i]["rep_bigram_w21"])
    rank = [0] * n
    for r, i in enumerate(order):
        rank[i] = r + 1
    out["rep_bigram_w21"] = rank

    # friedman_kappa: descending
    order = sorted(idx, key=lambda i: -results[i]["friedman_kappa"])
    rank = [0] * n
    for r, i in enumerate(order):
        rank[i] = r + 1
    out["friedman_kappa"] = rank

    # autocorr_rate: descending
    order = sorted(idx, key=lambda i: -results[i]["autocorr_rate"])
    rank = [0] * n
    for r, i in enumerate(order):
        rank[i] = r + 1
    out["autocorr_rate"] = rank

    # chi2_english: ascending
    order = sorted(idx, key=lambda i: results[i]["chi2_english"])
    rank = [0] * n
    for r, i in enumerate(order):
        rank[i] = r + 1
    out["chi2_english"] = rank

    # unique_letters: ascending (lower means more collapse, possibly more interesting)
    order = sorted(idx, key=lambda i: results[i]["unique_letters"])
    rank = [0] * n
    for r, i in enumerate(order):
        rank[i] = r + 1
    out["unique_letters"] = rank

    return out


def empirical_null(results: list[dict]) -> dict:
    """Mean / variance / min / max of each metric across all perturbations."""
    keys = [
        "ic_full",
        "rep_bigram_full",
        "rep_bigram_w21",
        "friedman_kappa",
        "autocorr_rate",
        "chi2_english",
        "unique_letters",
    ]
    out = {}
    n = len(results)
    for k in keys:
        vals = [r[k] for r in results]
        mean = sum(vals) / n
        var = sum((v - mean) ** 2 for v in vals) / n
        out[k] = {
            "mean": mean,
            "stdev": var ** 0.5,
            "min": min(vals),
            "max": max(vals),
        }
    return out


# ---------------- Main ----------------


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    base = baseline_metrics()
    print(f"Baseline K4 CT metrics:")
    for k, v in base.items():
        print(f"  {k}: {v}")
    print()

    jobs = make_jobs()
    print(f"Sweep: {len(jobs)} perturbations")

    workers = max(1, cpu_count() - 2)
    print(f"Workers: {workers}")

    t0 = time()
    with Pool(workers) as pool:
        results = pool.map(evaluate, jobs, chunksize=32)
    dt = time() - t0
    print(f"Sweep complete in {dt:.2f}s")

    # Rankings
    ranks = rank_results(results)
    metric_keys = list(ranks.keys())

    # Rank-sum cross-metric aggregate
    rank_sum = []
    for i in range(len(results)):
        s = sum(ranks[k][i] for k in metric_keys)
        rank_sum.append((s, i))
    rank_sum.sort()

    # Per-metric top 20 + bottom 5
    per_metric_top = {}
    for k in metric_keys:
        order = sorted(range(len(results)), key=lambda i: ranks[k][i])
        top20 = order[:20]
        bot5 = order[-5:]
        per_metric_top[k] = {
            "top20": [
                {"pos": results[i]["pos"], "orig": results[i]["orig"],
                 "new": results[i]["new"], "value": results[i][k]}
                for i in top20
            ],
            "bottom5": [
                {"pos": results[i]["pos"], "orig": results[i]["orig"],
                 "new": results[i]["new"], "value": results[i][k]}
                for i in bot5
            ],
        }

    # Cross-metric top 30 by rank-sum
    cross_top30 = []
    for s, i in rank_sum[:30]:
        r = results[i]
        per_metric = {k: ranks[k][i] for k in metric_keys}
        cross_top30.append({
            "rank_sum": s,
            "pos": r["pos"],
            "orig": r["orig"],
            "new": r["new"],
            "metrics": {k: r[k] for k in metric_keys},
            "per_metric_rank": per_metric,
        })

    # Multi-signal triple-hits: in top 100 on >= 3 metrics
    triple_hits = []
    for i, r in enumerate(results):
        top100_metrics = [k for k in metric_keys if ranks[k][i] <= 100]
        if len(top100_metrics) >= 3:
            triple_hits.append({
                "pos": r["pos"],
                "orig": r["orig"],
                "new": r["new"],
                "top100_metrics": top100_metrics,
                "metrics": {k: r[k] for k in metric_keys},
                "per_metric_rank": {k: ranks[k][i] for k in metric_keys},
            })
    triple_hits.sort(key=lambda d: -len(d["top100_metrics"]))

    # Empirical null
    null = empirical_null(results)

    # Persist
    out_json = {
        "ct": CT,
        "baseline": base,
        "empirical_null": null,
        "n_perturbations": len(results),
        "runtime_seconds": dt,
        "cross_metric_top30": cross_top30,
        "triple_hits": triple_hits,
        "per_metric_top": per_metric_top,
        "all_results": results,
        "all_ranks": ranks,
    }
    json_path = OUT_DIR / "results.json"
    with open(json_path, "w") as f:
        json.dump(out_json, f, indent=2)
    print(f"Wrote {json_path}")

    # Markdown summary
    md_lines = []
    md_lines.append("# Hamming-1 cipher-agnostic statistical sweep")
    md_lines.append("")
    md_lines.append("Date: 2026-05-06  |  Runtime: %.2fs  |  N=%d perturbations" %
                    (dt, len(results)))
    md_lines.append("")
    md_lines.append("## Baseline metrics (canonical K4 CT)")
    md_lines.append("")
    md_lines.append("| metric | value |")
    md_lines.append("|---|---|")
    for k, v in base.items():
        md_lines.append(f"| {k} | {v} |")
    md_lines.append("")
    md_lines.append("## Empirical null (mean / stdev / min / max over 2425 perturbations)")
    md_lines.append("")
    md_lines.append("| metric | mean | stdev | min | max |")
    md_lines.append("|---|---|---|---|---|")
    for k, v in null.items():
        md_lines.append(f"| {k} | {v['mean']:.6f} | {v['stdev']:.6f} | {v['min']} | {v['max']} |")
    md_lines.append("")
    md_lines.append("## Cross-metric top 30 by rank-sum")
    md_lines.append("")
    md_lines.append("| rank | rank_sum | pos | orig→new | ic_full | rep_bg_full | rep_bg_w21 | fri_κ | ac_rate | χ² | uniq |")
    md_lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for idx, c in enumerate(cross_top30, 1):
        m = c["metrics"]
        md_lines.append(
            f"| {idx} | {c['rank_sum']} | {c['pos']} | {c['orig']}→{c['new']} | "
            f"{m['ic_full']:.4f} | {m['rep_bigram_full']} | {m['rep_bigram_w21']} | "
            f"{m['friedman_kappa']:.4f} | {m['autocorr_rate']:.4f} | "
            f"{m['chi2_english']:.2f} | {m['unique_letters']} |"
        )
    md_lines.append("")
    md_lines.append("## Multi-signal triple-hits (top-100 on >= 3 metrics)")
    md_lines.append("")
    if triple_hits:
        md_lines.append(f"Found {len(triple_hits)} triple-hits.")
        md_lines.append("")
        md_lines.append("| pos | orig→new | n_metrics | metrics |")
        md_lines.append("|---|---|---|---|")
        for h in triple_hits[:30]:
            md_lines.append(
                f"| {h['pos']} | {h['orig']}→{h['new']} | "
                f"{len(h['top100_metrics'])} | {','.join(h['top100_metrics'])} |"
            )
    else:
        md_lines.append("No triple-hits found.")
    md_lines.append("")
    md_lines.append("## Per-metric top 20 / bottom 5")
    md_lines.append("")
    for k, v in per_metric_top.items():
        md_lines.append(f"### {k}")
        md_lines.append("")
        md_lines.append("Top 20:")
        md_lines.append("")
        md_lines.append("| pos | orig→new | value |")
        md_lines.append("|---|---|---|")
        for r in v["top20"]:
            md_lines.append(f"| {r['pos']} | {r['orig']}→{r['new']} | {r['value']} |")
        md_lines.append("")
        md_lines.append("Bottom 5 (sanity check):")
        md_lines.append("")
        md_lines.append("| pos | orig→new | value |")
        md_lines.append("|---|---|---|")
        for r in v["bottom5"]:
            md_lines.append(f"| {r['pos']} | {r['orig']}→{r['new']} | {r['value']} |")
        md_lines.append("")

    md_path = OUT_DIR / "summary.md"
    md_path.write_text("\n".join(md_lines))
    print(f"Wrote {md_path}")

    # stdout dump of top 30
    print()
    print("=" * 80)
    print("CROSS-METRIC TOP 30 (by rank-sum, lower = better)")
    print("=" * 80)
    print(f"{'rk':>3} {'sum':>5} {'pos':>3} {'o>n':>5} "
          f"{'ic':>7} {'rb':>3} {'r21':>3} {'fk':>7} {'ac':>7} {'chi2':>7} {'u':>3}")
    for idx, c in enumerate(cross_top30, 1):
        m = c["metrics"]
        print(f"{idx:>3} {c['rank_sum']:>5} {c['pos']:>3} {c['orig']}>{c['new']}   "
              f"{m['ic_full']:.4f} {m['rep_bigram_full']:>3} {m['rep_bigram_w21']:>3} "
              f"{m['friedman_kappa']:.4f} {m['autocorr_rate']:.4f} "
              f"{m['chi2_english']:>7.2f} {m['unique_letters']:>3}")

    if triple_hits:
        print()
        print(f"TRIPLE-HITS: {len(triple_hits)}")
        for h in triple_hits[:10]:
            print(f"  pos {h['pos']:>2} {h['orig']}>{h['new']}  metrics: "
                  f"{','.join(h['top100_metrics'])}")


if __name__ == "__main__":
    main()
