#!/usr/bin/env python3
"""Calibrate the methodological-family admitted-theory conditional null.

Phase 2.1 of the K4 Evidence Calibration and Reopening Plan. Companion
to Phase 2 (`calibrate_admitted_theory_null.py`, DSL-cipher subset).
This script targets the **methodological** families whose ledger means
exceed the random_text null mean of 0.92:

    k3_continuity  (mean 2.135, max 24)
    k2_coords      (mean 2.032, max  6)
    archive_evidence (mean 1.824, max 24)
    key_tape       (mean 1.574, max 24)
    geometry       (mean 1.236, max 16)
    encoding       (mean 1.139, max  7)

The conditional null question this answers:

    "Given a random theory that has the SHAPE of a family-X admitted
    theory but does NOT condition on K4 plaintext signal, what is the
    distribution of best_score?"

If the synthetic null mean approximates the ledger mean for family X,
that family's elevation is admissibility-gating bias (no cryptographic
content). If the ledger mean substantially exceeds the synthetic null,
that family carries content worth investigating.

Synthetic generator contracts per family:

    k3_continuity:    random columnar perm (random width, random keyword)
                      composed with random Vigenere-AZ keyword inner.
                      Mirrors K3-grid-extension theories.

    k2_coords:        random 8-12 digit sequence used as Gronsfeld
                      keystream (digit-as-shift) over K4. Mirrors
                      coordinate-digit-as-key theories.

    archive_evidence: random Hamming-1 CT perturbation × random
                      Vigenere/Beaufort/VarBeau × random keyword.
                      Mirrors Stage-A-style CT-perturbation theories.

    key_tape:         random finite tape (length 4-30) × random
                      Vigenere/Beaufort/VarBeau via the key_tape DSL.
                      Mirrors M1-M5 finite-tape theories.

    geometry:         random width (7-21) × random route (serpentine/
                      spiral) on K4 → permuted CT → random Vigenere
                      keyword inner. Mirrors width-21/grid-route theories.

    encoding:         random outer permutation (columnar/myszkowski/
                      rail_fence/serpentine) × random
                      Vigenere/Beaufort inner. Mirrors multi-layer
                      transposition+substitution encoding theories.

Each generator runs N samples through the canonical kernel scoring
path (`score_candidate`), records crib_score / bean_passed / ngram /
classification, and computes an empirical distribution.

The decision question this script answers:

    "Do the methodological-family score elevations survive a
     random-admitted-methodological-theory null?"

Allowed answers:
    yes
    no
    inconclusive due to insufficient sampling or invalid synthetic model

Usage:
    PYTHONPATH=src python3 -u scripts/_infra/calibrate_methodological_null.py --quick
    PYTHONPATH=src python3 -u scripts/_infra/calibrate_methodological_null.py \\
        --samples-per-family 10000 \\
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
from typing import Any, Callable

# Standalone bootstrap.
_HERE = Path(__file__).resolve()
_ROOT = _HERE.parent.parent.parent
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))


from kryptos.kernel.alphabet import AZ, KA, Alphabet  # noqa: E402
from kryptos.kernel.constants import CT  # noqa: E402
from kryptos.kernel.scoring.aggregate import score_candidate  # noqa: E402
from kryptos.kernel.transforms.key_tape import apply_key_tape  # noqa: E402
from kryptos.kernel.transforms.transposition import (  # noqa: E402
    apply_perm,
    columnar_perm,
    invert_perm,
    keyword_to_order,
    myszkowski_perm,
    rail_fence_perm,
    serpentine_perm,
    spiral_perm,
)
from kryptos.kernel.transforms.vigenere import (  # noqa: E402
    CipherVariant,
    decrypt_text,
)


SCRIPT_VERSION = "v1.0"
DEFAULT_SAMPLES = 10_000
QUICK_SAMPLES = 200
DEFAULT_SEED = 42
DEFAULT_KEYWORDS = _ROOT / "wordlists" / "thematic_keywords.txt"
DEFAULT_OUTPUT_ROOT = _ROOT / "results" / "null_baselines" / "methodological_null"
DEFAULT_MANIFEST = _ROOT / "null_baselines" / "methodological_null_manifest.json"

CT_LEN = len(CT)
assert CT_LEN == 97, f"unexpected K4 CT length {CT_LEN}"

# ─── shared helpers ───────────────────────────────────────────────────────


def _git_commit() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=_ROOT, stderr=subprocess.DEVNULL
        )
        return out.decode().strip()
    except Exception:
        return "unknown"


def _kernel_commit_from_manifest() -> str:
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


def _load_keywords(path: Path, min_len: int = 4, max_len: int = 12) -> list[str]:
    """Load curated keyword pool, filtered to A-Z-only of bounded length."""
    raw = path.read_text().splitlines()
    kws: list[str] = []
    for line in raw:
        kw = line.strip().upper()
        if min_len <= len(kw) <= max_len and kw.isalpha():
            kws.append(kw)
    if not kws:
        raise RuntimeError(f"no usable keywords loaded from {path}")
    return kws


def _score_pt(pt: str) -> dict[str, Any]:
    """Score a plaintext candidate via the canonical kernel scoring path."""
    breakdown = score_candidate(pt)
    return {
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


def _encode_keyword(keyword: str, alphabet: Alphabet) -> list[int]:
    idx_table = alphabet.index_table
    return [idx_table[ord(c) - 65] for c in keyword]


# ─── per-family synthetic generators ─────────────────────────────────────
# Each gen_<family>(rng, keywords) -> dict with the scored sample plus
# its parameter dict (recorded for reproducibility / debugging).
# Generators must NOT condition on K4 cribs or known plaintext anywhere.
# They sample from the family's natural parameter distribution and score
# the resulting plaintext through the canonical scoring path.


_VARIANTS = [
    CipherVariant.VIGENERE,
    CipherVariant.BEAUFORT,
    CipherVariant.VAR_BEAUFORT,
]


def gen_k3_continuity(rng: random.Random, keywords: list[str]) -> dict[str, Any]:
    """K3-grid-extension synthetic theory.

    Random keyed columnar transposition (width drawn from {4..20}, column
    order from a random keyword) → permuted CT → random Vigenere/Beaufort
    keyword inner over AZ alphabet. The outer columnar mirrors the K3-grid-
    extension shape; the inner keyword is unconstrained.
    """
    width = rng.randint(4, 20)
    outer_kw = rng.choice([k for k in keywords if len(k) == width] or keywords)
    # Truncate / pad to match width
    outer_kw = outer_kw[:width].ljust(width, "X") if len(outer_kw) != width else outer_kw
    col_order = keyword_to_order(outer_kw, width)
    if col_order is None:
        # Fallback: sequential order
        col_order = tuple(range(width))
    perm = columnar_perm(width, list(col_order), CT_LEN)
    inv = invert_perm(perm)
    permuted_ct = apply_perm(CT, inv)

    inner_kw = rng.choice(keywords)
    variant = rng.choice(_VARIANTS)
    key = _encode_keyword(inner_kw, AZ)
    pt = decrypt_text(permuted_ct, key, variant=variant, alphabet=AZ)

    return {
        "family": "k3_continuity",
        "params": {
            "outer_width": width, "outer_keyword": outer_kw,
            "inner_keyword": inner_kw, "variant": variant.value,
        },
        **_score_pt(pt),
    }


def gen_k2_coords(rng: random.Random, keywords: list[str]) -> dict[str, Any]:
    """Coordinate-digit-as-Gronsfeld synthetic theory.

    Random sequence of 8-12 decimal digits (mirroring the carved K2
    coordinate digit count of ~11) used as a Gronsfeld keystream
    (digit value 0-9 → shift 0-9) over K4 CT, with random direction
    (Vig/Beau).
    """
    klen = rng.randint(8, 12)
    digit_key = [rng.randint(0, 9) for _ in range(klen)]
    variant = rng.choice([CipherVariant.VIGENERE, CipherVariant.BEAUFORT])
    pt = decrypt_text(CT, digit_key, variant=variant, alphabet=AZ)

    return {
        "family": "k2_coords",
        "params": {
            "digit_key": digit_key, "klen": klen, "variant": variant.value,
        },
        **_score_pt(pt),
    }


def gen_archive_evidence(
    rng: random.Random, keywords: list[str]
) -> dict[str, Any]:
    """CT-perturbation + standard cipher synthetic theory.

    Random Hamming-1 perturbation of K4 CT (random position, random new
    letter) → decrypt with random Vigenere/Beaufort/VarBeau keyword over
    AZ or KA. Mirrors Stage A's H1 sweep shape at the per-theory level.
    """
    pos = rng.randint(0, CT_LEN - 1)
    old_ch = CT[pos]
    new_ch = old_ch
    while new_ch == old_ch:
        new_ch = chr(rng.randint(0, 25) + ord("A"))
    perturbed_ct = CT[:pos] + new_ch + CT[pos + 1:]

    inner_kw = rng.choice(keywords)
    variant = rng.choice(_VARIANTS)
    alphabet = rng.choice([AZ, KA])
    key = _encode_keyword(inner_kw, alphabet)
    pt = decrypt_text(perturbed_ct, key, variant=variant, alphabet=alphabet)

    return {
        "family": "archive_evidence",
        "params": {
            "perturbation_pos": pos, "old_char": old_ch, "new_char": new_ch,
            "inner_keyword": inner_kw, "variant": variant.value,
            "alphabet": alphabet.label,
        },
        **_score_pt(pt),
    }


def gen_key_tape(rng: random.Random, keywords: list[str]) -> dict[str, Any]:
    """Finite-tape synthetic theory via the key_tape DSL kind.

    Random tape (length 4-30, values 0-25), random variant, random
    alphabet, no nulls (sets null_rule='skip' which is irrelevant when
    null_positions is empty). Tape length must be ≥ CT_LEN under SKIP
    with no nulls — so we pad the tape by repetition to CT_LEN.

    Mirrors the M1-M5 finite-tape theories from the keystream
    forensics research line.
    """
    tape_len = rng.randint(4, 30)
    base_tape = tuple(rng.randint(0, 25) for _ in range(tape_len))
    # Repeat tape to cover 97 positions (else SKIP exhausts).
    full_tape = (base_tape * ((CT_LEN // tape_len) + 1))[:CT_LEN]

    variant = rng.choice(_VARIANTS)
    alphabet = rng.choice([AZ, KA])
    pt = apply_key_tape(
        CT, tape=full_tape, variant=variant,
        direction="decrypt",
        null_positions=frozenset(),
        null_rule="skip",
        alphabet=alphabet,
    )

    return {
        "family": "key_tape",
        "params": {
            "base_tape_len": tape_len, "variant": variant.value,
            "alphabet": alphabet.label,
        },
        **_score_pt(pt),
    }


def gen_geometry(rng: random.Random, keywords: list[str]) -> dict[str, Any]:
    """Width-grid + route synthetic theory.

    Random width (7-21) × random route (serpentine horizontal /
    serpentine vertical / spiral CW / spiral CCW) on K4 → permuted
    CT → random Vigenere keyword inner. Mirrors width-21 vertical-bigram
    and grid-route geometry theories.
    """
    width = rng.randint(7, 21)
    rows = (CT_LEN + width - 1) // width  # ceil
    route_kind = rng.choice(["serp_h", "serp_v", "spiral_cw", "spiral_ccw"])

    if route_kind == "serp_h":
        perm = serpentine_perm(rows, width, CT_LEN, vertical=False)
    elif route_kind == "serp_v":
        perm = serpentine_perm(rows, width, CT_LEN, vertical=True)
    elif route_kind == "spiral_cw":
        perm = spiral_perm(rows, width, CT_LEN, clockwise=True)
    else:
        perm = spiral_perm(rows, width, CT_LEN, clockwise=False)

    inv = invert_perm(perm)
    permuted_ct = apply_perm(CT, inv)

    inner_kw = rng.choice(keywords)
    variant = rng.choice(_VARIANTS)
    key = _encode_keyword(inner_kw, AZ)
    pt = decrypt_text(permuted_ct, key, variant=variant, alphabet=AZ)

    return {
        "family": "geometry",
        "params": {
            "width": width, "rows": rows, "route": route_kind,
            "inner_keyword": inner_kw, "variant": variant.value,
        },
        **_score_pt(pt),
    }


def gen_encoding(rng: random.Random, keywords: list[str]) -> dict[str, Any]:
    """Multi-layer transposition + substitution synthetic theory.

    Random outer transposition (columnar / myszkowski / rail_fence /
    serpentine) with random parameter × random Vigenere/Beaufort/VarBeau
    inner over AZ or KA. Mirrors the dominant ledger family
    (encoding, N=291, mean 1.139).
    """
    outer = rng.choice(["columnar", "myszkowski", "rail_fence", "serp_h"])
    if outer == "columnar":
        width = rng.randint(4, 21)
        kw = rng.choice([k for k in keywords if len(k) == width] or keywords)
        kw = kw[:width].ljust(width, "X") if len(kw) != width else kw
        col_order = keyword_to_order(kw, width)
        if col_order is None:
            col_order = tuple(range(width))
        perm = columnar_perm(width, list(col_order), CT_LEN)
        outer_params = {"outer": "columnar", "width": width, "keyword": kw}
    elif outer == "myszkowski":
        kw = rng.choice(keywords)
        perm = myszkowski_perm(kw, CT_LEN)
        outer_params = {"outer": "myszkowski", "keyword": kw}
    elif outer == "rail_fence":
        depth = rng.randint(2, 14)
        perm = rail_fence_perm(CT_LEN, depth)
        outer_params = {"outer": "rail_fence", "depth": depth}
    else:  # serp_h
        width = rng.randint(7, 21)
        rows = (CT_LEN + width - 1) // width
        perm = serpentine_perm(rows, width, CT_LEN, vertical=False)
        outer_params = {"outer": "serp_h", "width": width, "rows": rows}

    inv = invert_perm(perm)
    permuted_ct = apply_perm(CT, inv)

    inner_kw = rng.choice(keywords)
    variant = rng.choice(_VARIANTS)
    alphabet = rng.choice([AZ, KA])
    key = _encode_keyword(inner_kw, alphabet)
    pt = decrypt_text(permuted_ct, key, variant=variant, alphabet=alphabet)

    return {
        "family": "encoding",
        "params": {
            **outer_params, "inner_keyword": inner_kw,
            "variant": variant.value, "alphabet": alphabet.label,
        },
        **_score_pt(pt),
    }


_GENERATORS: dict[str, Callable[[random.Random, list[str]], dict[str, Any]]] = {
    "k3_continuity": gen_k3_continuity,
    "k2_coords": gen_k2_coords,
    "archive_evidence": gen_archive_evidence,
    "key_tape": gen_key_tape,
    "geometry": gen_geometry,
    "encoding": gen_encoding,
}


# ─── orchestration ────────────────────────────────────────────────────────


@dataclass
class FamilySummary:
    family: str
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


def _summarize(
    family: str, samples: list[dict[str, Any]], seed: int, distribution_path: Path
) -> FamilySummary:
    n = len(samples)
    crib_scores = sorted(s["crib_score"] for s in samples)
    mean = sum(crib_scores) / n
    var = sum((x - mean) ** 2 for x in crib_scores) / max(n - 1, 1)
    stdev = var**0.5

    def pct(p: float) -> int | float:
        i = int(p * (n - 1))
        return crib_scores[i] if 0 <= i < n else float("nan")

    bean_passes = sum(1 for s in samples if s["bean_passed"])
    ngrams = [s["ngram_score"] for s in samples if s["ngram_score"] is not None]
    ngram_mean = sum(ngrams) / len(ngrams) if ngrams else 0.0

    return FamilySummary(
        family=family, n_samples=n, seed=seed,
        mean=mean, stdev=stdev, max=crib_scores[-1],
        p50=int(pct(0.50)), p90=int(pct(0.90)),
        p95=int(pct(0.95)), p99=int(pct(0.99)),
        p999=pct(0.999),
        bean_pass_rate=bean_passes / n,
        ngram_mean=ngram_mean,
        distribution_path=str(distribution_path.relative_to(_ROOT)),
    )


def _calibrate_family(
    family: str, gen_fn: Callable, keywords: list[str],
    n_samples: int, seed: int, output_root: Path,
) -> FamilySummary:
    output_root.mkdir(parents=True, exist_ok=True)
    distribution_path = output_root / f"{family}__v1.jsonl"

    rng = random.Random(seed)
    samples: list[dict[str, Any]] = []

    t_start = time.time()
    with distribution_path.open("w", encoding="utf-8") as f:
        f.write(json.dumps({"_header": {
            "family": family, "n_samples_target": n_samples,
            "seed": seed, "script_version": SCRIPT_VERSION,
            "started_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }}) + "\n")
        for _ in range(n_samples):
            try:
                sample = gen_fn(rng, keywords)
            except Exception as e:
                # Synthetic generator failure — log and skip
                logging.warning("generator %s failed: %s", family, e)
                continue
            samples.append(sample)
            f.write(json.dumps(sample) + "\n")
        f.write(json.dumps({"_trailer": {
            "family": family, "n_samples": len(samples),
            "elapsed_sec": round(time.time() - t_start, 2),
            "completed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }}) + "\n")

    return _summarize(family, samples, seed, distribution_path)


def _ledger_comparison(
    summaries: list[FamilySummary], output_root: Path,
) -> dict[str, Any]:
    """Compare ledger family means against this calibration's per-family null."""
    import sqlite3

    ledger = _ROOT / "db" / "theory_ledger.sqlite"
    if not ledger.exists():
        return {"error": "ledger not found", "ledger_path": str(ledger)}

    conn = sqlite3.connect(f"file:{ledger}?mode=ro", uri=True)
    rows = conn.execute(
        "SELECT family, COUNT(*), AVG(best_score), MAX(best_score) "
        "FROM theories WHERE status NOT IN ('proposed', 'criticized') "
        "AND family IN (?, ?, ?, ?, ?, ?) "
        "GROUP BY family",
        ("k3_continuity", "k2_coords", "archive_evidence", "key_tape",
         "geometry", "encoding"),
    ).fetchall()
    conn.close()

    ledger_by_family = {r[0]: {"n": r[1], "mean": r[2], "max": r[3]} for r in rows}
    null_by_family = {s.family: s for s in summaries}

    comparison = []
    decisions: list[str] = []
    for family in [
        "k3_continuity", "k2_coords", "archive_evidence",
        "key_tape", "geometry", "encoding",
    ]:
        ledger_data = ledger_by_family.get(family)
        null_data = null_by_family.get(family)
        if not ledger_data or not null_data:
            continue
        n_ledger = ledger_data["n"]
        ledger_mean = ledger_data["mean"]
        ledger_max = int(ledger_data["max"])
        null_mean = null_data.mean
        null_stdev = null_data.stdev
        null_max = null_data.max

        # Standard error of ledger mean (assuming pooled stdev from null
        # since null has more samples than ledger in most families)
        se = null_stdev / (n_ledger ** 0.5)
        delta = ledger_mean - null_mean
        delta_z = delta / max(se, 1e-9)

        # Multiplicity correction across 6 families: Bonferroni α=0.05/6 ≈ 0.0083
        # corresponds to z ≈ 2.64 for one-sided test
        if abs(delta_z) < 2.64:
            verdict = "no"  # ledger mean indistinguishable from null after Bonf
            interp = "indistinguishable_from_null_after_bonferroni"
        elif delta < 0:
            verdict = "no"
            interp = "ledger_below_null_no_concern"
        elif n_ledger < 20:
            verdict = "inconclusive"
            interp = "elevated_but_small_ledger_sample"
        elif null_data.n_samples < 1000:
            verdict = "inconclusive"
            interp = "elevated_but_small_null_sample_quick_mode"
        else:
            verdict = "yes"
            interp = "elevated_above_null_warrants_followup"
        decisions.append(verdict)

        # Also compare the maxes — a null whose max is well below the
        # ledger max is suspicious (synthetic generator may not be
        # reaching the same regime as ledger theories).
        max_ratio = null_max / max(ledger_max, 1)

        comparison.append({
            "family": family,
            "n_ledger": n_ledger,
            "ledger_mean": round(ledger_mean, 3),
            "ledger_max": ledger_max,
            "n_null_samples": null_data.n_samples,
            "null_mean": round(null_mean, 3),
            "null_stdev": round(null_stdev, 3),
            "null_max": null_max,
            "delta_mean": round(delta, 3),
            "delta_z": round(delta_z, 2),
            "max_ratio": round(max_ratio, 2),
            "interpretation": interp,
            "per_family_verdict": verdict,
        })

    # Roll up the headline answer across all 6 families.
    if "yes" in decisions:
        headline = "yes"
        explanation = (
            "At least one methodological family's ledger mean exceeds the "
            "synthetic conditional null after Bonferroni correction across "
            "6 families. Specific families: "
            + ", ".join(c["family"] for c in comparison
                        if c["per_family_verdict"] == "yes")
            + "."
        )
    elif all(d == "no" for d in decisions):
        headline = "no"
        explanation = (
            "All 6 methodological families' ledger means fall within the "
            "synthetic conditional null after Bonferroni correction. The "
            "elevations observed in the raw ledger are statistically "
            "indistinguishable from the random-admitted-methodological-"
            "theory null at 0.05 / 6 = 0.0083 alpha."
        )
    else:
        headline = "inconclusive due to insufficient sampling or invalid synthetic model"
        explanation = (
            "Verdicts: "
            + ", ".join(f"{c['family']}={c['per_family_verdict']}"
                        for c in comparison)
        )

    report = {
        "schema_version": "methodological_null.ledger_comparison.v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "phase_2_1_scope": (
            "Methodological-family conditional null over 6 families "
            "with synthetic generators that mirror admissibility shape "
            "without conditioning on K4 cribs."
        ),
        "per_family": comparison,
        "headline_question": (
            "Do the methodological-family score elevations survive a "
            "random-admitted-methodological-theory null?"
        ),
        "headline_answer": headline,
        "explanation": explanation,
    }

    output_path = output_root / "ledger_comparison.json"
    output_path.write_text(json.dumps(report, indent=2))
    return report


def _build_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quick", action="store_true",
                    help=f"Use {QUICK_SAMPLES} samples per family (default {DEFAULT_SAMPLES})")
    ap.add_argument("--samples-per-family", type=int, default=None,
                    help="Override sample size")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED, help="RNG seed")
    ap.add_argument("--keywords", type=Path, default=DEFAULT_KEYWORDS)
    ap.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    ap.add_argument("--manifest-path", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument("--ledger-comparison", action="store_true",
                    help="Produce ledger_comparison.json")
    ap.add_argument("--only-family", type=str, default=None,
                    help="Build only families containing this substring")
    return ap


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    args = _build_argparser().parse_args(argv)

    n_samples = args.samples_per_family or (
        QUICK_SAMPLES if args.quick else DEFAULT_SAMPLES
    )
    keywords = _load_keywords(args.keywords)
    git_commit = _git_commit()
    kernel_commit = _kernel_commit_from_manifest()

    print(f"methodological-family null calibration")
    print(f"  samples per family: {n_samples}")
    print(f"  seed:               {args.seed}")
    print(f"  keyword pool:       {args.keywords} (n={len(keywords)})")
    print(f"  git commit:         {git_commit[:12]}")
    print(f"  kernel commit:      {kernel_commit[:12]}")
    print(f"  output root:        {args.output_root.relative_to(_ROOT)}")
    print()

    summaries: list[FamilySummary] = []
    family_seed = args.seed
    for family, gen_fn in _GENERATORS.items():
        if args.only_family and args.only_family not in family:
            family_seed += 1
            continue
        print(f"  [{family}] sampling {n_samples}...")
        t0 = time.time()
        summary = _calibrate_family(
            family, gen_fn, keywords, n_samples, family_seed, args.output_root,
        )
        elapsed = time.time() - t0
        print(
            f"    mean={summary.mean:.3f}  stdev={summary.stdev:.3f}  "
            f"max={summary.max}  bean={summary.bean_pass_rate:.4f}  "
            f"ngram={summary.ngram_mean:.3f}  ({elapsed:.1f}s)"
        )
        summaries.append(summary)
        family_seed += 1

    # Manifest
    args.manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": "methodological_null.manifest.v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_commit": git_commit,
        "kernel_commit": kernel_commit,
        "script_version": SCRIPT_VERSION,
        "default_seed": args.seed,
        "samples_per_family": n_samples,
        "keyword_pool_size": len(keywords),
        "phase_2_1_scope_note": (
            "Methodological-family conditional null. Synthetic generators "
            "mirror admissibility shape but do not condition on K4 cribs."
        ),
        "families": [asdict(s) for s in summaries],
    }
    args.manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"\n  manifest:  {args.manifest_path.relative_to(_ROOT)}")

    if args.ledger_comparison:
        report = _ledger_comparison(summaries, args.output_root)
        print(f"  comparison: {(args.output_root / 'ledger_comparison.json').relative_to(_ROOT)}")
        print()
        print(f"  Headline question: {report['headline_question']}")
        print(f"  Headline answer:   {report['headline_answer']}")
        print(f"  Explanation:       {report['explanation']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
