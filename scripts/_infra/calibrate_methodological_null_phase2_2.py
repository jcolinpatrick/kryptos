#!/usr/bin/env python3
"""Phase 2.2 of the methodological-family conditional null calibration.

Predecessor: ``scripts/_infra/calibrate_methodological_null.py`` (Phase 2.1).
Design memo: ``docs/methodological_audits/methodological_null_phase2_2_design.md``.
Prior attempt (v1.0) red-teamed and superseded; see decision-memo history.

Phase 2.1 calibrated a uniform-parameter conditional null over 6 families.
For 4 of those families (k3_continuity, archive_evidence, key_tape,
geometry) the synthetic-null max-ratio fell below 0.40, because uniform
parameter sampling does not construct the algebraic-degeneracy /
structural-overfit regimes that produced ledger BREAKTHROUGH (score=24)
artifacts. Phase 2.2 builds **mechanism-aware** generators that sample
parameters from the documented degeneracy regimes for each of those
four families.

A key constraint surfaced by red-team review of the v1.0 attempt:
the synthetic generator must run the family's actual cipher mechanism
through the canonical kernel scoring path, NOT construct an
admissibility-passing PT directly. A generator that places canonical
cribs at canonical positions trivially produces ``crib_score=24`` and
``null_stdev=0``, which makes the Bonferroni z-test undefined and
silently violates the design memo's non-circularity acceptance
criterion for archive_evidence. The v2 generators in this script
sample parameters from family-typical regimes, run real cipher
operations, and produce variable crib_scores that allow the directive's
faithful-null comparison to be made.

Per-family mechanism (v2):

    k3_continuity:    historical-K3-width columnar/serpentine/spiral/
                      myszkowski transposition (one of four reflow types)
                      composed with random Vigenere/Beaufort/VarBeau
                      keyword inner. Real cipher operations.

    archive_evidence: random Hamming-1..4 perturbation of CT at
                      NON-CRIB positions only (preserves the design's
                      bean-invariance argument), composed with random
                      keyword/variant/alphabet decryption. Real cipher
                      operations.

    key_tape:         primer-extension finite tape (primer drawn from
                      a curated K-thematic + generic pool, repeated to
                      cover CT_LEN), applied via apply_key_tape with
                      random variant + alphabet + null_rule. NO
                      back-solving from canonical PT. Real cipher.

    geometry:         random width × route, with post-hoc search over
                      column orders for the columnar route (best-of-K
                      random permutations per sample). The post-hoc
                      element models the documented overfit mechanism:
                      a theorist searches column orders to maximize
                      crib match. Real cipher operations.

This script is **opt-in** and **separate** from the Phase 2.1 runner.
It does NOT mutate Phase 2.1 outputs (reproducibility regression). It
writes a fresh manifest, distribution JSONLs, and ledger comparison.

Allowed ledger-comparison answers (per design):

    yes
    no
    inconclusive due to insufficient sampling or invalid synthetic model

The acceptance criterion is per-family ``synthetic_max / ledger_max ≥
0.80``. If a family fails to reach that threshold under v2 mechanism-
aware sampling, the verdict for that family is
``inconclusive due to invalid synthetic model`` per the design memo's
option 2. The honest outcome may be that some families remain
inconclusive after Phase 2.2; the calibration records what it found
without inflating the verdict.

Usage::

    PYTHONPATH=src python3 -u scripts/_infra/calibrate_methodological_null_phase2_2.py --quick --ledger-comparison
    PYTHONPATH=src python3 -u scripts/_infra/calibrate_methodological_null_phase2_2.py --ledger-comparison
    PYTHONPATH=src python3 -u scripts/_infra/calibrate_methodological_null_phase2_2.py --only-family key_tape --ledger-comparison
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
from kryptos.kernel.constants import CRIB_DICT, CT  # noqa: E402
from kryptos.kernel.scoring.aggregate import score_candidate  # noqa: E402
from kryptos.kernel.transforms.key_tape import apply_key_tape  # noqa: E402
from kryptos.kernel.transforms.transposition import (  # noqa: E402
    apply_perm,
    columnar_perm,
    invert_perm,
    keyword_to_order,
    myszkowski_perm,
    serpentine_perm,
    spiral_perm,
)
from kryptos.kernel.transforms.vigenere import (  # noqa: E402
    CipherVariant,
    decrypt_text,
)


SCRIPT_VERSION = "v2.0"
DEFAULT_SAMPLES = 10_000
QUICK_SAMPLES = 200
DEFAULT_SEED = 42
DEFAULT_OUTPUT_ROOT = (
    _ROOT / "results" / "null_baselines" / "methodological_null_phase2_2"
)
DEFAULT_MANIFEST = (
    _ROOT / "null_baselines" / "methodological_null_phase2_2_manifest.json"
)
DEFAULT_KEYWORDS = _ROOT / "wordlists" / "thematic_keywords.txt"
PHASE_2_1_OUTPUT_ROOT = (
    _ROOT / "results" / "null_baselines" / "methodological_null"
)
PHASE_2_1_MANIFEST = _ROOT / "null_baselines" / "methodological_null_manifest.json"

CT_LEN = len(CT)
assert CT_LEN == 97, f"unexpected K4 CT length {CT_LEN}"
assert len(CRIB_DICT) == 24, f"unexpected crib count {len(CRIB_DICT)}"

# K3 historical column widths and reflow shapes (per design memo §k3_continuity).
# Reflow types map to actual transposition perms in _build_k3_reflow_perm:
#   staggered     → myszkowski columnar with random keyword
#   partial       → standard keyed columnar with random keyword
#   boustrophedon → serpentine (alternating direction)
#   wrap          → spiral
_K3_WIDTHS = (7, 8, 13, 14)
_K3_REFLOWS = ("staggered", "partial", "boustrophedon", "wrap")

# Archive-evidence terms: a curated subset that mirrors what theorists
# proposed in the ledger (attested in MEMORY/notes; not the full
# controller family rotation). Used as descriptive metadata only — the
# scored configuration is the perturbed-CT decryption, not a function
# of the term.
_ARCHIVE_TERMS = (
    "ABSCISSA", "ATBASH", "PALIMPSEST", "DEFECTOR", "CIA",
    "LANGLEY", "SHADOW", "FORCE", "LUCID", "MEMORY",
    "TRANSCRIPTION", "MISSPELLING", "INSCRIPTION",
)

# Primer pool for key_tape v2: K-thematic anchors plus generic fillers.
# Length spans the design memo's primer_length set {5, 7, 8, 10}.
_KEY_TAPE_PRIMERS = (
    "AGENT",        # 5
    "EAGLE",        # 5
    "QUILL",        # 5
    "BERLIN",       # 6 — close to {5,7,8,10}; included as historical anchor
    "KRYPTOS",      # 7
    "ABSCISSA",     # 8
    "PALIMPSEST",   # 10
    "MEMORY",       # 6
    "SHADOW",       # 6
    "RIDDLE",       # 6
)
_KEY_TAPE_NULL_RULES = ("skip", "consume")
_VARIANTS = (
    CipherVariant.VIGENERE,
    CipherVariant.BEAUFORT,
    CipherVariant.VAR_BEAUFORT,
)

# Geometry generator's grid widths / routes / post-hoc-search cap.
# Widths span the design memo's {5..14}; routes cover the documented
# overfit-prone shapes. Search cap of 50 mirrors typical worker depth.
_GEOM_WIDTHS = tuple(range(5, 15))
_GEOM_ROUTES = ("columnar", "spiral_cw", "spiral_ccw", "serpentine_h",
                "serpentine_v")
_GEOM_POSTHOC_SEARCH_CAP = 50


# ─── shared helpers ───────────────────────────────────────────────────────


def _git_commit() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=_ROOT, stderr=subprocess.DEVNULL
        )
        return out.decode().strip()
    except Exception:
        return "unknown"


def _display_path(path: Path) -> str:
    """Return path relative to repo root, or absolute if it escapes the root.

    Calibrator tests pass tmp_path values outside the repo for isolation;
    Path.relative_to raises in that case. Display falls back to the
    absolute path so logging never crashes.
    """
    try:
        return str(path.relative_to(_ROOT))
    except ValueError:
        return str(path)


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


def _load_keywords(
    path: Path = DEFAULT_KEYWORDS,
    min_len: int = 4,
    max_len: int = 14,
) -> list[str]:
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


def _encode_keyword(keyword: str, alphabet: Alphabet) -> list[int]:
    idx_table = alphabet.index_table
    return [idx_table[ord(c) - 65] for c in keyword]


def _build_k3_reflow_perm(
    width: int, reflow: str, keyword: str | None,
) -> tuple[int, ...]:
    """Build the transposition permutation for a K3-style reflow.

    Maps each of the four documented reflow shapes to a kernel
    transposition primitive:

      staggered     → myszkowski columnar (repeated-letter keys produce
                      tied/staggered columns)
      partial       → standard keyed columnar (last row may be partial)
      boustrophedon → serpentine horizontal (alternating row direction)
      wrap          → spiral clockwise (text wraps the grid edges)
    """
    rows = (CT_LEN + width - 1) // width
    if reflow == "boustrophedon":
        return tuple(serpentine_perm(rows, width, CT_LEN, vertical=False))
    if reflow == "wrap":
        return tuple(spiral_perm(rows, width, CT_LEN, clockwise=True))
    if reflow == "partial":
        kw = (keyword or "K")[:width].ljust(width, "X")
        col_order = keyword_to_order(kw, width) or tuple(range(width))
        return tuple(columnar_perm(width, list(col_order), CT_LEN))
    if reflow == "staggered":
        kw = (keyword or "AB")[:width].ljust(width, "X")
        return tuple(myszkowski_perm(kw, CT_LEN))
    raise ValueError(f"unknown reflow type: {reflow}")


# ─── per-family mechanism-aware generators (v2) ──────────────────────────
# Each generator runs the family's actual cipher mechanism through the
# kernel scoring path, with parameters drawn from the documented
# theorist-proposal regime. Variable crib_scores by design — null_stdev
# > 0 lets the Bonferroni z-test apply.


def gen_k3_continuity_phase2_2(
    rng: random.Random, keywords: list[str],
) -> dict[str, Any]:
    """K3-grid-extension synthetic theory (real cipher).

    Mechanism: theorist proposes the K3 columnar grid extends into K4
    via one of four reflow shapes at one of four K3 historical widths.
    The synthetic generator builds the actual transposition permutation,
    applies its inverse to CT, then decrypts with a random keyword
    Vigenere/Beaufort/VarBeau under the AZ alphabet.

    The score arises from the actual cipher operations, NOT from
    canonical-crib placement. Most samples will score in the random
    regime (0-6); the upper tail reflects the rate at which random
    width × reflow × keyword combinations accidentally produce
    crib-matching plaintext.
    """
    width = rng.choice(_K3_WIDTHS)
    rows = (CT_LEN + width - 1) // width
    reflow = rng.choice(_K3_REFLOWS)
    keyword = rng.choice(keywords)
    inner_kw = rng.choice(keywords)
    variant = rng.choice(_VARIANTS)

    perm = _build_k3_reflow_perm(width, reflow, keyword)
    inv = invert_perm(perm)
    permuted_ct = apply_perm(CT, inv)
    key = _encode_keyword(inner_kw, AZ)
    pt = decrypt_text(permuted_ct, key, variant=variant, alphabet=AZ)

    return {
        "family": "k3_continuity",
        "mechanism": "k3_grid_extension_with_reflow",
        "params": {
            "width": width,
            "rows": rows,
            "reflow": reflow,
            "outer_keyword": keyword,
            "inner_keyword": inner_kw,
            "variant": variant.value,
        },
        **_score_pt(pt),
    }


def gen_archive_evidence_phase2_2(
    rng: random.Random, keywords: list[str],
) -> dict[str, Any]:
    """Hamming-1..4 non-crib CT-perturbation synthetic theory (real cipher).

    Mechanism: theorist proposes that 1-4 CT positions are transcription
    errors and applies a corrected CT to a random Vigenere/Beaufort/
    VarBeau decryption. Edits are restricted to non-crib positions
    (the design memo's bean-invariance argument: Bean is invariant
    under non-crib edits, so the admissibility check is preserved
    regardless of the perturbation).

    The score arises from the actual perturbed-CT decryption, NOT from
    canonical-crib placement. The synthetic generator does not condition
    on canonical PT or the crib dictionary anywhere in the score path,
    satisfying the design memo's archive_evidence non-circularity
    acceptance criterion.
    """
    edit_count = rng.randint(1, 4)
    non_crib_positions = [i for i in range(CT_LEN) if i not in CRIB_DICT]
    edit_positions = sorted(rng.sample(non_crib_positions, edit_count))
    perturbed = list(CT)
    for pos in edit_positions:
        old_ch = perturbed[pos]
        new_ch = chr(rng.randint(0, 25) + 65)
        while new_ch == old_ch:
            new_ch = chr(rng.randint(0, 25) + 65)
        perturbed[pos] = new_ch
    perturbed_ct = "".join(perturbed)
    edit_values = [perturbed_ct[p] for p in edit_positions]

    inner_kw = rng.choice(keywords)
    variant = rng.choice(_VARIANTS)
    alphabet = rng.choice([AZ, KA])
    archive_term = rng.choice(_ARCHIVE_TERMS)
    key = _encode_keyword(inner_kw, alphabet)
    pt = decrypt_text(perturbed_ct, key, variant=variant, alphabet=alphabet)

    return {
        "family": "archive_evidence",
        "mechanism": "non_crib_hamming_perturbation_plus_real_cipher",
        "params": {
            "edit_count": edit_count,
            "edit_positions": edit_positions,
            "edit_values": edit_values,
            "archive_term": archive_term,
            "inner_keyword": inner_kw,
            "variant": variant.value,
            "alphabet": alphabet.label,
        },
        **_score_pt(pt),
    }


def gen_key_tape_phase2_2(
    rng: random.Random, keywords: list[str],
) -> dict[str, Any]:
    """Primer-extension finite-tape synthetic theory (real cipher).

    Mechanism: theorist proposes a finite key tape constructed from a
    primer (5-10 chars) extended by repetition to cover CT. The tape is
    NOT back-solved from canonical PT; it is purely a function of the
    chosen primer. The kernel ``apply_key_tape`` is invoked to compute
    the resulting plaintext, which is scored through the canonical
    scoring path.

    Variable crib_scores arise from the actual cipher operation: random
    primer + variant + alphabet rarely produces a crib-matching PT.
    """
    primer = rng.choice(_KEY_TAPE_PRIMERS)
    primer_length = len(primer)
    null_rule = rng.choice(_KEY_TAPE_NULL_RULES)
    variant = rng.choice(_VARIANTS)
    alphabet = rng.choice([AZ, KA])

    primer_indices = _encode_keyword(primer, alphabet)
    repeats = (CT_LEN + primer_length - 1) // primer_length
    full_tape = (primer_indices * repeats)[:CT_LEN]

    pt = apply_key_tape(
        CT,
        tape=tuple(full_tape),
        variant=variant,
        direction="decrypt",
        null_positions=frozenset(),
        null_rule=null_rule,
        alphabet=alphabet,
    )

    return {
        "family": "key_tape",
        "mechanism": "primer_extension_finite_tape",
        "params": {
            "primer": primer,
            "primer_length": primer_length,
            "null_rule": null_rule,
            "variant": variant.value,
            "alphabet": alphabet.label,
        },
        **_score_pt(pt),
    }


def gen_geometry_phase2_2(
    rng: random.Random, keywords: list[str],
) -> dict[str, Any]:
    """Grid-route synthetic theory with post-hoc column-order search.

    Mechanism: theorist picks a grid width × route. For columnar routes,
    the theorist searches a finite pool of column orderings to maximize
    crib match — this post-hoc selection IS the documented overfit
    mechanism. For spiral / serpentine routes (no column-order
    parameter), the route alone determines the perm.

    The post-hoc element inflates the upper tail of the synthetic null,
    mirroring the documented overfit-prone proposal pattern. The
    ``post_hoc=True`` flag in params distinguishes columnar samples
    (which used search) from spiral / serpentine samples (which did
    not).
    """
    grid_width = rng.choice(_GEOM_WIDTHS)
    rows = (CT_LEN + grid_width - 1) // grid_width
    grid_route = rng.choice(_GEOM_ROUTES)
    inner_kw = rng.choice(keywords)
    variant = rng.choice(_VARIANTS)
    key = _encode_keyword(inner_kw, AZ)

    if grid_route == "columnar":
        # Post-hoc search over column orderings: best of K random perms.
        best_pt: str | None = None
        best_score = -1
        best_order: list[int] | None = None
        for _ in range(_GEOM_POSTHOC_SEARCH_CAP):
            col_order = list(range(grid_width))
            rng.shuffle(col_order)
            perm = tuple(columnar_perm(grid_width, col_order, CT_LEN))
            inv = invert_perm(perm)
            permuted_ct = apply_perm(CT, inv)
            cand = decrypt_text(
                permuted_ct, key, variant=variant, alphabet=AZ
            )
            sc = score_candidate(cand).crib_score
            if sc > best_score:
                best_score = sc
                best_pt = cand
                best_order = col_order
        pt = best_pt or ""
        column_order = best_order or list(range(grid_width))
        post_hoc = True
        search_cap = _GEOM_POSTHOC_SEARCH_CAP
    else:
        if grid_route == "spiral_cw":
            perm = tuple(spiral_perm(rows, grid_width, CT_LEN, clockwise=True))
        elif grid_route == "spiral_ccw":
            perm = tuple(
                spiral_perm(rows, grid_width, CT_LEN, clockwise=False)
            )
        elif grid_route == "serpentine_h":
            perm = tuple(
                serpentine_perm(rows, grid_width, CT_LEN, vertical=False)
            )
        else:  # serpentine_v
            perm = tuple(
                serpentine_perm(rows, grid_width, CT_LEN, vertical=True)
            )
        inv = invert_perm(perm)
        permuted_ct = apply_perm(CT, inv)
        pt = decrypt_text(permuted_ct, key, variant=variant, alphabet=AZ)
        column_order = []
        post_hoc = False
        search_cap = 0

    return {
        "family": "geometry",
        "mechanism": "grid_route_with_post_hoc_search",
        "params": {
            "grid_width": grid_width,
            "rows": rows,
            "grid_route": grid_route,
            "column_order": column_order,
            "search_cap": search_cap,
            "post_hoc": post_hoc,
            "inner_keyword": inner_kw,
            "variant": variant.value,
        },
        **_score_pt(pt),
    }


_GENERATORS: dict[str, Callable[[random.Random, list[str]], dict[str, Any]]] = {
    "k3_continuity": gen_k3_continuity_phase2_2,
    "archive_evidence": gen_archive_evidence_phase2_2,
    "key_tape": gen_key_tape_phase2_2,
    "geometry": gen_geometry_phase2_2,
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
    breakthrough_rate: float
    ngram_mean: float
    ngram_max: float
    distribution_path: str


def _summarize(
    family: str,
    samples: list[dict[str, Any]],
    seed: int,
    distribution_path: Path,
) -> FamilySummary:
    n = len(samples)
    if n == 0:
        raise ValueError(f"family {family} produced zero samples")
    crib_scores = sorted(s["crib_score"] for s in samples)
    mean = sum(crib_scores) / n
    var = sum((x - mean) ** 2 for x in crib_scores) / max(n - 1, 1)
    stdev = var**0.5

    def pct(p: float) -> int | float:
        i = int(p * (n - 1))
        return crib_scores[i] if 0 <= i < n else float("nan")

    bean_passes = sum(1 for s in samples if s["bean_passed"])
    breakthroughs = sum(
        1 for s in samples if s.get("classification") == "breakthrough"
    )
    ngrams = [s["ngram_score"] for s in samples if s["ngram_score"] is not None]
    ngram_mean = sum(ngrams) / len(ngrams) if ngrams else 0.0
    ngram_max = max(ngrams) if ngrams else 0.0

    return FamilySummary(
        family=family,
        n_samples=n,
        seed=seed,
        mean=mean,
        stdev=stdev,
        max=crib_scores[-1],
        p50=int(pct(0.50)),
        p90=int(pct(0.90)),
        p95=int(pct(0.95)),
        p99=int(pct(0.99)),
        p999=pct(0.999),
        bean_pass_rate=bean_passes / n,
        breakthrough_rate=breakthroughs / n,
        ngram_mean=ngram_mean,
        ngram_max=ngram_max,
        distribution_path=_display_path(distribution_path),
    )


def _calibrate_family(
    family: str,
    gen_fn: Callable[[random.Random, list[str]], dict[str, Any]],
    keywords: list[str],
    n_samples: int,
    seed: int,
    output_root: Path,
) -> FamilySummary:
    output_root.mkdir(parents=True, exist_ok=True)
    distribution_path = output_root / f"{family}__v1.jsonl"

    rng = random.Random(seed)
    samples: list[dict[str, Any]] = []

    t_start = time.time()
    with distribution_path.open("w", encoding="utf-8") as f:
        f.write(
            json.dumps({
                "_header": {
                    "family": family,
                    "n_samples_target": n_samples,
                    "seed": seed,
                    "script_version": SCRIPT_VERSION,
                    "phase": "2.2",
                    "started_at_utc": time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
                    ),
                }
            })
            + "\n"
        )
        for _ in range(n_samples):
            try:
                sample = gen_fn(rng, keywords)
            except Exception as e:
                logging.warning("generator %s failed: %s", family, e)
                continue
            samples.append(sample)
            f.write(json.dumps(sample) + "\n")
        f.write(
            json.dumps({
                "_trailer": {
                    "family": family,
                    "n_samples": len(samples),
                    "elapsed_sec": round(time.time() - t_start, 2),
                    "completed_at_utc": time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
                    ),
                }
            })
            + "\n"
        )

    return _summarize(family, samples, seed, distribution_path)


def _binomial_p_value_at_least_k(n: int, k: int, p: float) -> float:
    """Compute P(X >= k) where X ~ Binomial(n, p), using stdlib math.

    Used for the Bernoulli/binomial rate test: under H0 that the
    synthetic null's rate is at most p, what is the probability of
    observing k or more events in n ledger entries?
    """
    import math

    if k <= 0:
        return 1.0
    if p <= 0.0:
        return 0.0 if k > 0 else 1.0
    if p >= 1.0:
        return 1.0
    # P(X >= k) = 1 - P(X < k) = 1 - sum_{i=0}^{k-1} C(n,i) p^i (1-p)^(n-i)
    cdf = 0.0
    for i in range(k):
        cdf += math.comb(n, i) * (p**i) * ((1 - p) ** (n - i))
    return max(0.0, 1.0 - cdf)


def _ledger_comparison(
    summaries: list[FamilySummary],
    output_root: Path,
) -> dict[str, Any]:
    """Compare ledger family means against Phase 2.2's mechanism-aware null.

    Combines Phase 2.2 results for the four mismatched families with
    Phase 2.1 results for k2_coords and encoding (loaded from the Phase
    2.1 manifest if present). Bonferroni correction is across all 6
    families per the design memo's multiplicity-correction rule.

    Two independent statistics per family:
      - delta_z: Bonferroni z-test on mean elevation (informative when
        null_stdev > 0).
      - bernoulli_p: probability of observing the ledger's score-24
        event count under a binomial null whose rate is the synthetic
        null's score-24 rate (or its upper 95% CI bound when that rate
        is zero). The Bernoulli test is the right framing for the
        ledger's BREAKTHROUGH-class outliers, which are not central-
        tendency phenomena.

    Cross-comparison against the project's ``random_text__AZ__n97``
    baseline (mean=0.924, stdev=0.942, max=7) is included per family.
    A v2 mechanism-aware null whose distribution matches the
    random_text baseline is informative: it says the family-specific
    parameter regime does not move the score distribution beyond what
    random A-Z plaintext already produces under kernel scoring.
    """
    import sqlite3

    # Cross-comparison anchor: random_text AZ n97 baseline.
    # Hard-coded from null_baselines/manifest.json snapshot 2026-05-05.
    # If the baseline manifest lookup fails, we still report the
    # comparison with these reference values so downstream consumers
    # see a stable anchor.
    random_text_baseline = {
        "label": "random_text__AZ__n97",
        "mean": 0.924,
        "stdev": 0.942,
        "max": 7,
        "n_samples": 100_000,
    }
    base_manifest = _ROOT / "null_baselines" / "manifest.json"
    if base_manifest.exists():
        try:
            bm = json.loads(base_manifest.read_text())
            for k, v in bm.get("distributions", {}).items():
                if (
                    "random_text" in k
                    and "__AZ__" in k
                    and "n97" in k
                    and "crib_score" in k
                ):
                    random_text_baseline = {
                        "label": k,
                        "mean": float(v.get("mean", 0.0)),
                        "stdev": float(v.get("stdev", 0.0)),
                        "max": int(v.get("max", 0)),
                        "n_samples": int(v.get("n_samples", 0)),
                    }
                    break
        except Exception as e:
            logging.warning("could not load random_text baseline: %s", e)

    ledger = _ROOT / "db" / "theory_ledger.sqlite"
    if not ledger.exists():
        return {"error": "ledger not found", "ledger_path": str(ledger)}

    conn = sqlite3.connect(f"file:{ledger}?mode=ro", uri=True)
    rows = conn.execute(
        "SELECT family, COUNT(*), AVG(best_score), MAX(best_score) "
        "FROM theories WHERE status NOT IN ('proposed', 'criticized') "
        "AND family IN (?, ?, ?, ?, ?, ?) "
        "GROUP BY family",
        (
            "k3_continuity",
            "k2_coords",
            "archive_evidence",
            "key_tape",
            "geometry",
            "encoding",
        ),
    ).fetchall()
    # Score-24 events per family for the Bernoulli rate test.
    rows24 = conn.execute(
        "SELECT family, COUNT(*) "
        "FROM theories WHERE status NOT IN ('proposed', 'criticized') "
        "AND best_score = 24 "
        "AND family IN (?, ?, ?, ?, ?, ?) "
        "GROUP BY family",
        (
            "k3_continuity",
            "k2_coords",
            "archive_evidence",
            "key_tape",
            "geometry",
            "encoding",
        ),
    ).fetchall()
    conn.close()

    ledger_by_family = {r[0]: {"n": r[1], "mean": r[2], "max": r[3]} for r in rows}
    ledger_24_by_family = {r[0]: int(r[1]) for r in rows24}
    null_by_family: dict[str, dict[str, Any]] = {
        s.family: {
            "n": s.n_samples,
            "mean": s.mean,
            "stdev": s.stdev,
            "max": s.max,
            "source": "phase_2_2",
        }
        for s in summaries
    }

    # Pull Phase 2.1 results for the two families NOT re-run in Phase 2.2.
    if PHASE_2_1_MANIFEST.exists():
        try:
            p21 = json.loads(PHASE_2_1_MANIFEST.read_text())
            for fam in p21.get("families", []):
                fname = fam["family"]
                if fname in null_by_family:
                    continue  # Phase 2.2 takes precedence
                null_by_family[fname] = {
                    "n": fam["n_samples"],
                    "mean": fam["mean"],
                    "stdev": fam["stdev"],
                    "max": fam["max"],
                    "source": "phase_2_1",
                }
        except Exception as e:
            logging.warning("could not load Phase 2.1 manifest: %s", e)

    family_order = [
        "k3_continuity",
        "k2_coords",
        "archive_evidence",
        "key_tape",
        "geometry",
        "encoding",
    ]
    # Build a quick lookup for synthetic score-24 rates per family.
    # For Phase 2.2 families, we need to count crib_score==24 events in
    # the JSONL distributions; for Phase 2.1 families inherited via
    # manifest, we use stdev-based estimation as a fallback (the
    # synthetic JSONLs are gitignored and may not be present).
    synthetic_24_counts: dict[str, int] = {}
    for s in summaries:
        # The summary's max field tells us if any sample reached 24.
        # If max == 24, count via the jsonl distribution. If max < 24,
        # count is 0.
        if s.max < 24:
            synthetic_24_counts[s.family] = 0
        else:
            jsonl = (
                _ROOT / s.distribution_path
                if not Path(s.distribution_path).is_absolute()
                else Path(s.distribution_path)
            )
            if jsonl.exists():
                count = 0
                for line in jsonl.read_text().splitlines():
                    if not line or line.startswith('{"_'):
                        continue
                    try:
                        obj = json.loads(line)
                        if int(obj.get("crib_score", 0)) == 24:
                            count += 1
                    except Exception:
                        continue
                synthetic_24_counts[s.family] = count
            else:
                # Conservative: if jsonl missing, assume the max value
                # came from a single event.
                synthetic_24_counts[s.family] = 1

    comparison = []
    decisions: list[str] = []
    for family in family_order:
        ledger_data = ledger_by_family.get(family)
        null_data = null_by_family.get(family)
        if not ledger_data or not null_data:
            continue
        n_ledger = ledger_data["n"]
        ledger_mean = ledger_data["mean"]
        ledger_max = int(ledger_data["max"])
        null_mean = null_data["mean"]
        null_stdev = null_data["stdev"]
        null_max = null_data["max"]
        source = null_data["source"]

        delta = ledger_mean - null_mean
        max_ratio = null_max / max(ledger_max, 1)

        # Bonferroni z-test across 6 families: α = 0.05/6 ≈ 0.0083,
        # one-sided z-threshold ≈ 2.64.
        if null_stdev > 0 and n_ledger > 0:
            se = null_stdev / (n_ledger**0.5)
            delta_z: float | None = delta / max(se, 1e-12)
        else:
            delta_z = None

        # Per-family verdict logic. The acceptance gate is max_ratio ≥
        # 0.80 (synthetic null reaches the ledger max regime); families
        # below that threshold cannot be interpreted under the directive
        # because the synthetic generator does not characterize the
        # ledger's upper tail. For families that meet the acceptance
        # gate, the Bonferroni z-test decides yes / no.
        if max_ratio < 0.80:
            verdict = "inconclusive"
            interp = "max_ratio_below_acceptance_0.80_invalid_synthetic_model"
        elif delta_z is None:
            # Pathological case: null_stdev = 0 with non-saturated max.
            # Should not arise under v2 mechanism-aware sampling, but
            # we record it explicitly rather than silently fall through.
            verdict = "inconclusive"
            interp = "null_stdev_zero_test_undefined"
        elif abs(delta_z) < 2.64:
            verdict = "no"
            interp = "indistinguishable_from_null_after_bonferroni"
        elif delta < 0:
            verdict = "no"
            interp = "ledger_below_null_no_concern"
        elif n_ledger < 20:
            verdict = "inconclusive"
            interp = "elevated_but_small_ledger_sample"
        elif null_data["n"] < 1000:
            verdict = "inconclusive"
            interp = "elevated_but_small_null_sample_quick_mode"
        else:
            verdict = "yes"
            interp = "elevated_above_null_warrants_followup"
        decisions.append(verdict)

        # Bernoulli rate test on score-24 events.
        # n_ledger_24 = ledger entries that scored exactly 24.
        # n_null_24 = synthetic samples that scored exactly 24.
        # Under H0 that the synthetic null's true rate is the observed
        # rate (or its upper 95% CI if observed = 0), what is P(observe
        # >= n_ledger_24 in n_ledger trials)?
        n_ledger_24 = ledger_24_by_family.get(family, 0)
        n_null = null_data["n"]
        n_null_24 = (
            synthetic_24_counts.get(family, 0)
            if source == "phase_2_2"
            else 0  # Phase 2.1 inheritance: max was below 24, 0 events
        )
        # Upper 95% CI bound on rate when observed = 0:
        # rule-of-three approximation, p_upper ≈ 3/n.
        if n_null_24 == 0:
            null_rate_upper = 3.0 / max(n_null, 1)
            null_rate_observed = 0.0
        else:
            null_rate_observed = n_null_24 / max(n_null, 1)
            null_rate_upper = null_rate_observed
        bernoulli_p = _binomial_p_value_at_least_k(
            n_ledger, n_ledger_24, null_rate_upper
        )
        # Bonferroni-corrected significance threshold across 6 families.
        bernoulli_significant = bernoulli_p < (0.05 / 6)

        # Cross-comparison vs random_text baseline. A v2 mechanism-aware
        # null whose mean/stdev/max match the random_text baseline
        # indicates the family-specific parameters do not move the
        # score distribution beyond what random A-Z plaintext produces
        # under kernel scoring.
        rt_mean_diff = abs(null_mean - random_text_baseline["mean"])
        rt_stdev_diff = abs(null_stdev - random_text_baseline["stdev"])
        rt_max_diff = null_max - random_text_baseline["max"]
        # Heuristic: distributions are "indistinguishable from random_text"
        # if mean and stdev are within 0.10 of baseline AND max is at
        # most baseline+1.
        rt_indistinguishable = (
            rt_mean_diff <= 0.10
            and rt_stdev_diff <= 0.10
            and rt_max_diff <= 1
        )

        comparison.append({
            "family": family,
            "null_source": source,
            "n_ledger": n_ledger,
            "ledger_mean": round(ledger_mean, 3),
            "ledger_max": ledger_max,
            "n_ledger_score_24": n_ledger_24,
            "n_null_samples": n_null,
            "n_null_score_24": n_null_24,
            "null_mean": round(null_mean, 3),
            "null_stdev": round(null_stdev, 3),
            "null_max": null_max,
            "delta_mean": round(delta, 3),
            "delta_mean_in_null_stdev_units": (
                round(delta / null_stdev, 2)
                if null_stdev > 0
                else None
            ),
            "delta_z": (
                round(delta_z, 2) if delta_z is not None else None
            ),
            "max_ratio": round(max_ratio, 2),
            "max_ratio_acceptance": round(max_ratio, 2) >= 0.80,
            "bernoulli_null_rate_upper_95ci": round(null_rate_upper, 6),
            "bernoulli_p_value_one_sided": round(bernoulli_p, 6),
            "bernoulli_significant_at_bonf6": bernoulli_significant,
            "vs_random_text_baseline": {
                "baseline_label": random_text_baseline["label"],
                "mean_diff": round(rt_mean_diff, 3),
                "stdev_diff": round(rt_stdev_diff, 3),
                "max_diff": int(rt_max_diff),
                "indistinguishable": rt_indistinguishable,
            },
            "interpretation": interp,
            "per_family_verdict": verdict,
        })

    # Single headline answer per the directive's allowed-answer set:
    # yes / no / inconclusive due to insufficient sampling or invalid
    # synthetic model.
    #
    # Aggregation rule, matching the Phase 2.1 decision memo's logic so
    # the same numerical situation produces the same headline:
    #
    #   - If ANY family has verdict "inconclusive" (max_ratio < 0.80
    #     or other invalid-synthetic-model cause), the headline is
    #     "inconclusive due to insufficient sampling or invalid
    #     synthetic model". The honest answer when the synthetic
    #     model is invalid for one or more families is that the
    #     overall question cannot be answered with this calibration.
    #
    #   - If all families have verdict "no", the headline is "no".
    #
    #   - If all families have verdict "yes" (or some yes + some no
    #     with no inconclusive), the headline is "yes".
    #
    # This is intentionally conservative: a partial-yes mixed with
    # invalid-synthetic-model cannot be promoted to "yes" because the
    # invalid families could change the conclusion under a faithful
    # null. This matches Phase 2.1's "with 4/6 invalid-synthetic-model,
    # the only honest answer is inconclusive" reasoning.
    if not decisions:
        headline = (
            "inconclusive due to insufficient sampling or invalid synthetic model"
        )
        explanation = "no per-family decisions produced"
    elif "inconclusive" in decisions:
        headline = (
            "inconclusive due to insufficient sampling or invalid synthetic model"
        )
        inconclusive_fams = [
            c["family"]
            for c in comparison
            if c["per_family_verdict"] == "inconclusive"
        ]
        yes_fams = [
            c["family"]
            for c in comparison
            if c["per_family_verdict"] == "yes"
        ]
        no_fams = [
            c["family"]
            for c in comparison
            if c["per_family_verdict"] == "no"
        ]
        parts = [f"Inconclusive families: {', '.join(inconclusive_fams)}."]
        if yes_fams:
            parts.append(
                f"Programmatically-yes families (small absolute "
                f"elevation per Phase 2.1 commentary): "
                f"{', '.join(yes_fams)}."
            )
        if no_fams:
            parts.append(
                f"Programmatically-no families: {', '.join(no_fams)}."
            )
        explanation = " ".join(parts)
    elif all(d == "no" for d in decisions):
        headline = "no"
        explanation = (
            "All 6 methodological families pass max_ratio ≥ 0.80 "
            "acceptance and have ledger means within Bonferroni-"
            "corrected null range."
        )
    else:
        # All "yes" or mix of "yes" and "no" (no inconclusive).
        headline = "yes"
        yes_fams = [
            c["family"]
            for c in comparison
            if c["per_family_verdict"] == "yes"
        ]
        explanation = (
            "Families with elevation surviving Bonferroni: "
            + ", ".join(yes_fams)
            + "."
        )

    report = {
        "schema_version": "methodological_null_phase2_2.ledger_comparison.v3",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "phase_2_2_scope": (
            "Mechanism-aware methodological-family conditional null over "
            "the four families whose Phase 2.1 max_ratio fell below 0.40. "
            "Generators run real cipher mechanisms (transposition, "
            "decryption, finite-tape application, post-hoc grid search) "
            "with parameters drawn from family-typical theorist-proposal "
            "regimes. The two families whose Phase 2.1 result was already "
            "faithful (k2_coords, encoding) are loaded from the Phase 2.1 "
            "manifest unchanged. Bonferroni multiplicity correction is "
            "across all 6 families. Headline aggregation rule matches "
            "Phase 2.1: any family with verdict 'inconclusive' makes the "
            "headline 'inconclusive'."
        ),
        "random_text_baseline_anchor": random_text_baseline,
        "per_family": comparison,
        "headline_question": (
            "Do the methodological-family score elevations survive a "
            "mechanism-aware random-admitted-methodological-theory null?"
        ),
        "headline_answer": headline,
        "explanation": explanation,
    }

    output_path = output_root / "ledger_comparison.json"
    output_path.write_text(json.dumps(report, indent=2))
    return report


def _build_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--quick",
        action="store_true",
        help=(
            f"Use {QUICK_SAMPLES} samples per family "
            f"(default {DEFAULT_SAMPLES})"
        ),
    )
    ap.add_argument(
        "--samples-per-family",
        type=int,
        default=None,
        help="Override sample size",
    )
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED, help="RNG seed")
    ap.add_argument(
        "--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT
    )
    ap.add_argument(
        "--manifest-path", type=Path, default=DEFAULT_MANIFEST
    )
    ap.add_argument(
        "--ledger-comparison",
        action="store_true",
        help="Produce ledger_comparison.json",
    )
    ap.add_argument(
        "--only-family",
        type=str,
        default=None,
        help="Build only families containing this substring",
    )
    ap.add_argument(
        "--keywords",
        type=Path,
        default=DEFAULT_KEYWORDS,
        help="Keyword pool path (default thematic_keywords.txt)",
    )
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

    print("methodological-family Phase 2.2 conditional null calibration")
    print(f"  samples per family: {n_samples}")
    print(f"  seed:               {args.seed}")
    print(f"  keyword pool:       {_display_path(args.keywords)} "
          f"(n={len(keywords)})")
    print(f"  git commit:         {git_commit[:12]}")
    print(f"  kernel commit:      {kernel_commit[:12]}")
    print(f"  output root:        {_display_path(args.output_root)}")
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
            family, gen_fn, keywords, n_samples, family_seed, args.output_root
        )
        elapsed = time.time() - t0
        print(
            f"    mean={summary.mean:.3f}  stdev={summary.stdev:.3f}  "
            f"max={summary.max}  bean={summary.bean_pass_rate:.4f}  "
            f"breakthrough={summary.breakthrough_rate:.4f}  "
            f"ngram_mean={summary.ngram_mean:.3f}  "
            f"ngram_max={summary.ngram_max:.3f}  "
            f"({elapsed:.1f}s)"
        )
        summaries.append(summary)
        family_seed += 1

    args.manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": "methodological_null_phase2_2.manifest.v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_commit": git_commit,
        "kernel_commit": kernel_commit,
        "script_version": SCRIPT_VERSION,
        "default_seed": args.seed,
        "samples_per_family": n_samples,
        "phase_2_2_scope_note": (
            "v2.0 mechanism-aware synthetic generators for the four "
            "families whose Phase 2.1 max_ratio fell below 0.40. Each "
            "generator runs the family's actual cipher mechanism through "
            "the canonical kernel scoring path with parameters drawn "
            "from family-typical regimes (k3_continuity: keyed "
            "transposition + decryption; archive_evidence: Hamming-1..4 "
            "non-crib perturbation + decryption; key_tape: primer-"
            "extension finite tape; geometry: width × route × post-hoc "
            "column-order search). v2 produces variable crib_scores "
            "with non-zero stdev. The earlier v1.0 attempt that placed "
            "canonical cribs at canonical positions was retired after "
            "red-team review identified it as a degenerate non-null."
        ),
        "families": [asdict(s) for s in summaries],
    }
    args.manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"\n  manifest:  {_display_path(args.manifest_path)}")

    if args.ledger_comparison:
        report = _ledger_comparison(summaries, args.output_root)
        comp_path = args.output_root / "ledger_comparison.json"
        print(f"  comparison: {_display_path(comp_path)}")
        print()
        print(f"  Headline question: {report['headline_question']}")
        print(f"  Headline answer:   {report['headline_answer']}")
        print(f"  Explanation:       {report['explanation']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
