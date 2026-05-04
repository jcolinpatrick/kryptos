#!/usr/bin/env python3
"""Calibrate the admitted-theory conditional null distribution.

Phase 2 of the K4 Evidence Calibration and Reopening Plan. See
``docs/methodological_audits/admitted_theory_conditional_null_design.md``
for the full design contract.

The conditional null is the distribution of ``crib_score`` for theories
that satisfy the framework's admissibility shape but carry no
cryptographic signal — i.e., what does a *typical admitted theory*
score, given the parameter distributions personas actually use?

Phase 2 scope (this script): DSL-cipher families only — vigenere,
beaufort, var_beaufort × {AZ, KA} alphabet × curated thematic keywords.
Multi-layer, methodological-family (k2_coords, archive_evidence,
antipodes, etc.), and CT-perturbation conditional nulls are deferred
to Phase 2.1.

Usage:
    PYTHONPATH=src python3 -u scripts/_infra/calibrate_admitted_theory_null.py --quick
    PYTHONPATH=src python3 -u scripts/_infra/calibrate_admitted_theory_null.py \\
        --samples-per-stratum 10000 \\
        --ledger-comparison
"""
from __future__ import annotations

import argparse
import json
import logging
import random
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

# Standalone bootstrap (script lives 2 levels deep under repo root).
_HERE = Path(__file__).resolve()
_ROOT = _HERE.parent.parent.parent
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))


from kryptos.kernel.alphabet import AZ, KA, Alphabet  # noqa: E402
from kryptos.kernel.constants import CT  # noqa: E402
from kryptos.kernel.scoring.aggregate import score_candidate  # noqa: E402
from kryptos.kernel.transforms.vigenere import (  # noqa: E402
    CipherVariant,
    decrypt_text,
)


SCRIPT_VERSION = "v1.0"
DEFAULT_SAMPLES = 10_000
QUICK_SAMPLES = 200
DEFAULT_SEED = 42
DEFAULT_KEYWORDS = _ROOT / "wordlists" / "thematic_keywords.txt"
DEFAULT_OUTPUT_ROOT = _ROOT / "results" / "null_baselines" / "admitted_theory"
DEFAULT_MANIFEST = _ROOT / "null_baselines" / "admitted_theory_manifest.json"

# Stratification axes that we expect to meaningfully shift the score
# distribution. Phase 2 covers only the DSL-cipher subset.
_VARIANTS = [
    ("vigenere", CipherVariant.VIGENERE),
    ("beaufort", CipherVariant.BEAUFORT),
    ("var_beaufort", CipherVariant.VAR_BEAUFORT),
]
_ALPHABETS: list[tuple[str, Alphabet]] = [("AZ", AZ), ("KA", KA)]


@dataclass
class StratumSummary:
    name: str
    cipher_kind: str
    alphabet: str
    n_samples: int
    seed: int
    mean: float
    stdev: float
    max: int
    p50: int
    p90: int
    p95: int
    p99: int
    p999: float
    bean_pass_rate: float
    ngram_mean: float
    distribution_path: str


def _git_commit() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=_ROOT, stderr=subprocess.DEVNULL
        )
        return out.decode().strip()
    except Exception:
        return "unknown"


def _kernel_commit_from_manifest() -> str:
    """Read the kernel commit recorded in the existing null baselines manifest.

    The kernel itself doesn't change between most commits; the manifest
    records the commit at which the kernel scoring path was last
    calibrated. We pin against that for reproducibility.
    """
    base_manifest = _ROOT / "null_baselines" / "manifest.json"
    if not base_manifest.exists():
        return "unknown"
    try:
        m = json.loads(base_manifest.read_text())
        dists = m.get("distributions", {})
        if dists:
            return next(iter(dists.values())).get("kernel_commit", "unknown")
    except Exception:
        pass
    return "unknown"


def _load_keywords(path: Path) -> list[str]:
    """Load curated keyword pool. Filter to A-Z-only, length 4..20."""
    raw = path.read_text().splitlines()
    kws: list[str] = []
    for line in raw:
        kw = line.strip().upper()
        if 4 <= len(kw) <= 20 and kw.isalpha():
            kws.append(kw)
    if not kws:
        raise RuntimeError(f"no usable keywords loaded from {path}")
    return kws


def _encode_keyword(keyword: str, alphabet: Alphabet) -> list[int]:
    """Encode a keyword into the alphabet's index space.

    For AZ this is `ord(c) - 65`. For KA this routes through the
    KRYPTOS-mixed alphabet so the dispatcher's KA encoding semantics
    are preserved.
    """
    idx_table = alphabet.index_table
    return [idx_table[ord(c) - 65] for c in keyword]


def _sample_one(
    keyword: str,
    variant_name: str,
    variant: CipherVariant,
    alphabet_name: str,
    alphabet: Alphabet,
) -> dict[str, Any]:
    """Generate one synthetic-admitted-theory sample.

    Decrypts the canonical 97-char K4 CT under (keyword, variant, alphabet)
    and runs the canonical kernel scoring path. The keyword is drawn from
    the curated thematic pool — that's the conditional-null property.
    """
    key = _encode_keyword(keyword, alphabet)
    pt = decrypt_text(CT, key, variant=variant, alphabet=alphabet)
    breakdown = score_candidate(pt)
    return {
        "keyword": keyword,
        "variant": variant_name,
        "alphabet": alphabet_name,
        "crib_score": int(breakdown.crib_score),
        "bean_passed": bool(breakdown.bean_passed),
        "ngram_score": (
            float(breakdown.ngram_score)
            if breakdown.ngram_score is not None
            else None
        ),
        "ic_value": float(getattr(breakdown, "ic_value", 0.0) or 0.0),
        "classification": str(getattr(breakdown, "crib_classification", "?")),
    }


def _summarize_stratum(
    name: str,
    cipher_kind: str,
    alphabet_name: str,
    samples: list[dict[str, Any]],
    seed: int,
    distribution_path: Path,
) -> StratumSummary:
    n = len(samples)
    crib_scores = [s["crib_score"] for s in samples]
    crib_scores.sort()
    mean = sum(crib_scores) / n
    var = sum((x - mean) ** 2 for x in crib_scores) / max(n - 1, 1)
    stdev = var**0.5

    def pct(p: float) -> int | float:
        i = int(p * (n - 1))
        return crib_scores[i] if 0 <= i < n else float("nan")

    bean_passes = sum(1 for s in samples if s["bean_passed"])
    ngrams = [s["ngram_score"] for s in samples if s["ngram_score"] is not None]
    ngram_mean = sum(ngrams) / len(ngrams) if ngrams else 0.0

    return StratumSummary(
        name=name,
        cipher_kind=cipher_kind,
        alphabet=alphabet_name,
        n_samples=n,
        seed=seed,
        mean=mean,
        stdev=stdev,
        max=max(crib_scores),
        p50=int(pct(0.50)),
        p90=int(pct(0.90)),
        p95=int(pct(0.95)),
        p99=int(pct(0.99)),
        p999=pct(0.999),
        bean_pass_rate=bean_passes / n,
        ngram_mean=ngram_mean,
        distribution_path=str(distribution_path.relative_to(_ROOT)),
    )


def _calibrate_stratum(
    cipher_kind: str,
    variant: CipherVariant,
    alphabet_name: str,
    alphabet: Alphabet,
    keywords: list[str],
    n_samples: int,
    seed: int,
    output_root: Path,
) -> StratumSummary:
    name = f"{cipher_kind}_{alphabet_name}_anchored_direct_singlelayer"
    output_root.mkdir(parents=True, exist_ok=True)
    distribution_path = output_root / f"{name}__v1.jsonl"

    rng = random.Random(seed)
    samples: list[dict[str, Any]] = []

    t_start = time.time()
    with distribution_path.open("w", encoding="utf-8") as f:
        f.write(json.dumps({"_header": {
            "stratum": name,
            "cipher_kind": cipher_kind,
            "alphabet": alphabet_name,
            "n_samples_target": n_samples,
            "seed": seed,
            "script_version": SCRIPT_VERSION,
            "started_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }}) + "\n")
        for _ in range(n_samples):
            kw = rng.choice(keywords)
            sample = _sample_one(kw, cipher_kind, variant, alphabet_name, alphabet)
            samples.append(sample)
            f.write(json.dumps(sample) + "\n")
        f.write(json.dumps({"_trailer": {
            "stratum": name,
            "n_samples": len(samples),
            "elapsed_sec": round(time.time() - t_start, 2),
            "completed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }}) + "\n")

    return _summarize_stratum(
        name, cipher_kind, alphabet_name, samples, seed, distribution_path
    )


def _ledger_comparison(
    summaries: list[StratumSummary],
    output_root: Path,
) -> dict[str, Any]:
    """Compare ledger family means against this calibration's strata."""
    import sqlite3

    ledger = _ROOT / "db" / "theory_ledger.sqlite"
    if not ledger.exists():
        return {"error": "ledger not found", "ledger_path": str(ledger)}

    conn = sqlite3.connect(f"file:{ledger}?mode=ro", uri=True)
    rows = conn.execute(
        "SELECT family, COUNT(*), AVG(best_score), MAX(best_score) "
        "FROM theories WHERE status NOT IN ('proposed', 'criticized') "
        "GROUP BY family ORDER BY AVG(best_score) DESC"
    ).fetchall()
    conn.close()

    # Compute reference null means across the calibrated strata
    null_mean = sum(s.mean for s in summaries) / len(summaries) if summaries else 0.0
    null_max = max((s.max for s in summaries), default=0)

    comparison = []
    for family, n_ledger, ledger_mean, ledger_max in rows:
        if n_ledger < 10:
            continue
        delta = ledger_mean - null_mean
        # rough z (assumes pooled stdev across strata; honest approx)
        pooled_stdev = (
            sum(s.stdev for s in summaries) / len(summaries) if summaries else 1.0
        )
        delta_z = delta / max(pooled_stdev / (n_ledger ** 0.5), 1e-9)

        if abs(delta_z) < 2.0:
            interp = "indistinguishable_from_null"
        elif delta < 0:
            interp = "below_null_no_concern"
        elif n_ledger < 30:
            interp = "elevated_inconclusive_due_to_small_sample"
        else:
            interp = "elevated_warrants_phase_2_1_methodological_null"

        comparison.append({
            "family": family,
            "n_ledger": n_ledger,
            "ledger_mean": round(ledger_mean, 3),
            "ledger_max": int(ledger_max),
            "null_mean": round(null_mean, 3),
            "null_max_seen": null_max,
            "delta": round(delta, 3),
            "delta_z": round(delta_z, 2),
            "interpretation": interp,
        })

    report = {
        "schema_version": "admitted_theory_null.ledger_comparison.v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "phase_2_scope": "DSL-cipher families only (vigenere/beaufort/var_beaufort × AZ/KA)",
        "phase_2_1_deferred": [
            "methodological-family null (k2_coords, archive_evidence, antipodes, etc.)",
            "CT-perturbation conditional null",
            "multi-layer composition conditional null",
        ],
        "stratum_count": len(summaries),
        "comparison": comparison,
        "headline_question": (
            "Do the observed family-level score elevations survive a "
            "conditional admitted-theory null?"
        ),
        "headline_answer": _headline_answer(comparison),
    }

    output_path = output_root / "ledger_comparison.json"
    output_path.write_text(json.dumps(report, indent=2))
    return report


def _headline_answer(comparison: list[dict[str, Any]]) -> str:
    """Return the directive-required headline answer."""
    elevated = [
        c for c in comparison
        if c["interpretation"] in (
            "elevated_warrants_phase_2_1_methodological_null",
        )
    ]
    inconclusive_small = [
        c for c in comparison
        if c["interpretation"] == "elevated_inconclusive_due_to_small_sample"
    ]
    if elevated:
        # Phase 2 scope alone cannot answer for methodological families;
        # honest answer is "inconclusive due to insufficient sampling"
        # because the methodological-family null is deferred.
        return (
            "inconclusive due to insufficient sampling — Phase 2 "
            "DSL-cipher null does not reach the methodological families "
            f"({', '.join(c['family'] for c in elevated)}) showing the "
            "highest ledger means; Phase 2.1 methodological null required."
        )
    if inconclusive_small:
        return (
            "inconclusive due to insufficient sampling — small-N families "
            f"({', '.join(c['family'] for c in inconclusive_small)}) cannot "
            "be discriminated from null at current ledger size."
        )
    if comparison:
        return (
            "no — all families with N>=10 fall within the conditional "
            "DSL-cipher null distribution. Phase 2.1 methodological null "
            "still required for the high-mean families before declaring "
            "no cryptographic signal globally."
        )
    return "inconclusive due to insufficient sampling — no comparable strata"


def _build_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quick", action="store_true",
                    help=f"Use {QUICK_SAMPLES} samples per stratum (default {DEFAULT_SAMPLES})")
    ap.add_argument("--samples-per-stratum", type=int, default=None,
                    help="Override sample size per stratum")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED, help="Deterministic RNG seed")
    ap.add_argument("--keywords", type=Path, default=DEFAULT_KEYWORDS,
                    help="Path to curated keyword pool")
    ap.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT,
                    help="Distribution output directory")
    ap.add_argument("--manifest-path", type=Path, default=DEFAULT_MANIFEST,
                    help="Manifest JSON path")
    ap.add_argument("--ledger-comparison", action="store_true",
                    help="Produce ledger_comparison.json")
    ap.add_argument("--only-stratum", type=str, default=None,
                    help="Build only stratum whose name contains this substring")
    return ap


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    args = _build_argparser().parse_args(argv)

    n_samples = args.samples_per_stratum or (
        QUICK_SAMPLES if args.quick else DEFAULT_SAMPLES
    )

    keywords = _load_keywords(args.keywords)
    git_commit = _git_commit()
    kernel_commit = _kernel_commit_from_manifest()

    print(f"admitted-theory null calibration")
    print(f"  samples per stratum: {n_samples}")
    print(f"  seed:                {args.seed}")
    print(f"  keyword pool:        {args.keywords} (n={len(keywords)})")
    print(f"  git commit:          {git_commit[:12]}")
    print(f"  kernel commit:       {kernel_commit[:12]}")
    print(f"  output root:         {args.output_root.relative_to(_ROOT)}")
    print()

    summaries: list[StratumSummary] = []
    stratum_seed = args.seed
    for cipher_kind, variant in _VARIANTS:
        for alphabet_name, alphabet in _ALPHABETS:
            stratum_name = f"{cipher_kind}_{alphabet_name}_anchored_direct_singlelayer"
            if args.only_stratum and args.only_stratum not in stratum_name:
                continue
            print(f"  [{stratum_name}] sampling {n_samples}...")
            t0 = time.time()
            summary = _calibrate_stratum(
                cipher_kind, variant, alphabet_name, alphabet,
                keywords, n_samples, stratum_seed, args.output_root,
            )
            elapsed = time.time() - t0
            print(
                f"    mean={summary.mean:.3f}  stdev={summary.stdev:.3f}  "
                f"max={summary.max}  bean={summary.bean_pass_rate:.4f}  "
                f"ngram={summary.ngram_mean:.3f}  ({elapsed:.1f}s)"
            )
            summaries.append(summary)
            stratum_seed += 1

    # Manifest
    args.manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": "admitted_theory_null.manifest.v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_commit": git_commit,
        "kernel_commit": kernel_commit,
        "script_version": SCRIPT_VERSION,
        "default_seed": args.seed,
        "samples_per_stratum": n_samples,
        "keyword_pool_size": len(keywords),
        "phase_2_scope_note": (
            "DSL-cipher families only. Methodological-family conditional "
            "null deferred to Phase 2.1. See "
            "docs/methodological_audits/admitted_theory_conditional_null_design.md."
        ),
        "strata": [asdict(s) for s in summaries],
    }
    args.manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"\n  manifest:  {args.manifest_path.relative_to(_ROOT)}")

    if args.ledger_comparison:
        report = _ledger_comparison(summaries, args.output_root)
        comp_path = args.output_root / "ledger_comparison.json"
        print(f"  comparison: {comp_path.relative_to(_ROOT)}")
        print()
        print(f"  Headline question: {report['headline_question']}")
        print(f"  Answer:            {report['headline_answer']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
