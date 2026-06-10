"""Calibrated null-distribution module for K4 scoring.

Framework maturation Phase 6 (2026-04-21). The brief's §8 target: replace
raw-score reasoning with p-value reasoning across the framework.
A ``crib_score`` of 18 means nothing in isolation; what matters is
P(crib_score >= 18 | matched null on same n, same alphabet, same scoring
path). Until alerts gate on calibrated p-values, every high score on
n=97 is dominated by search-breadth artifacts (see
docs/methodological_audits.md AUDIT-3).

Module responsibilities:

    1. Build null distributions by Monte Carlo (stdlib-only; seeded for
       reproducibility).
    2. Cache distributions to disk (gitignored under ``results/null_baselines/``).
       A summary manifest at ``null_baselines/manifest.json`` IS committed
       to git for provenance; the full sorted-score lists are not.
    3. Compute right-tailed p-values. For the crib_score + random_text
       combo, use the exact Binomial tail (24 Bernoulli(1/26) trials)
       so the p-value is accurate far below the empirical 1/N floor.
       For ngram_score + random_text, fit a normal from the empirical
       mean/stdev and use the normal tail (CLT justification: ngram_score
       is a sum of ~94 quadgram log-probs). Other combos fall back to
       the empirical tail with an explicit ``p < 1/N`` upper bound.
    4. Detect staleness via the recorded ``kernel_commit`` — a calibration
       built against a different kernel head should be rebuilt.

Not done in this phase:
    - Per-family matched_variant_family for anything other than Vigenere.
      Other cipher families raise NotImplementedError; the infrastructure
      is ready but the training cost was deferred.
    - Integration with word-level scorer for a "word_score" null. Phase 7
      territory if the self-test needs it.

See docs/maturation/phase_06_report.md for the distribution summaries
and the verification against theoretical expectations.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import logging
import math
import os
import random
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger("kryptosbot.null_baselines")


# ─── Constants and paths ─────────────────────────────────────────────────────

_REPO_ROOT = Path(__file__).resolve().parent.parent

# Full distributions (multi-MB JSON) live here. Gitignored.
_FULL_CACHE_DIR = _REPO_ROOT / "results" / "null_baselines"

# Summary manifest (a few KB) is committed so anyone cloning the repo
# knows what calibration is available.
_MANIFEST_PATH = _REPO_ROOT / "null_baselines" / "manifest.json"

_DEFAULT_SAMPLES = 100_000
_DEFAULT_SEED = 42

_VALID_SCORERS = frozenset({"crib_score", "ngram_score", "composite"})
_VALID_METHODS = frozenset(
    {"random_text", "shuffled_ct", "matched_variant_family"}
)
_VALID_ALPHABETS = frozenset({"AZ", "KA"})
# R2-4 (2026-04-21): families the matched_variant_family method can
# sample from. "" is the legacy default (Phase 6 — Vigenère AZ). Adding
# a new family requires (a) extending _sample_one_matched_family and
# (b) adding the family name here. Columnar families produce distinct
# null distributions from additive families because the transposition
# is compositionally independent of the CT's letter distribution.
_VALID_FAMILIES = frozenset({
    "",                 # Phase 6 legacy (Vigenère AZ)
    "vigenere",         # explicit alias for the legacy case
    "beaufort",         # R2-4
    "variant_beaufort", # R2-4
    "columnar_single",  # R2-4
    "columnar_double",  # R2-4
    "rail_fence",       # 2026-05-26: dispatchable transposition families
    "myszkowski",       #   added so the real-K4 instrument campaign can
    "route",            #   score genuine hits vs their own family null.
})

# G-1 (2026-06-10): scoring-mode dimension. "anchored" is the historical
# default (score_cribs at the canonical positions); "free" matches the
# dispatcher's crib_alignment="free" path (score_candidate_free — cribs
# matched ANYWHERE, support {0, 11, 13, 24}). A free crib_score compared
# against an anchored null misstates the chance rate in both directions,
# so free results must consult free-built nulls only.
_VALID_SCORING_MODES = frozenset({"anchored", "free"})

# Families whose matched_variant_family sample is a PERMUTATION of the
# real CT (letter multiset preserved). Under these sources the free-crib
# tail uses the exact uniform-permutation window probability, and free
# 24 is EXACTLY impossible: [DERIVED FACT] CT has 2 E's while the two
# cribs jointly need 3 (computed, not hardcoded — see
# _free_crib_tail_params).
_PERMUTATION_FAMILIES = frozenset({
    "columnar_single", "columnar_double", "rail_fence", "myszkowski",
    "route",
})


def _compute_kernel_commit() -> str:
    """Return the git HEAD sha at module load time, or 'unknown'."""
    env_override = os.environ.get("KRYPTOSBOT_KERNEL_COMMIT")
    if env_override:
        return env_override
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=_REPO_ROOT, capture_output=True, text=True, timeout=2,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "unknown"


_KERNEL_COMMIT: str = _compute_kernel_commit()


# ─── NullDistribution dataclass ──────────────────────────────────────────────

@dataclass
class NullDistribution:
    """An empirical + parametric null distribution for one scorer × method × (n, alphabet).

    Fields:
        scorer_name:   "crib_score" | "ngram_score" | "composite"
        method:        "random_text" | "shuffled_ct" | "matched_variant_family"
        n_chars:       ciphertext / plaintext length (97 for K4)
        alphabet:      "AZ" | "KA"
        n_samples:     how many Monte Carlo samples backed this distribution
        seed:          RNG seed (deterministic rebuild)
        kernel_commit: git HEAD at build time (staleness detection)
        sorted_scores: full sorted list for empirical tail computation
                       (MAY be empty when loaded from manifest-only summary)
        mean:          empirical mean
        stdev:         empirical stdev
        parametric_model:
                       "binomial" | "normal" | None
                       — which analytic family to use for tail p-values
                       when the observation exceeds the empirical range.
                       Fitted at build time from the scorer+method combo.
        p_value_tail_method:
                       "exact" | "empirical" | "normal_approx"
                       — which method ``p_value()`` will actually use.
    """
    scorer_name: str
    method: str
    n_chars: int
    alphabet: str
    n_samples: int
    seed: int
    kernel_commit: str
    sorted_scores: list[float] = field(default_factory=list)
    mean: float = 0.0
    stdev: float = 0.0
    parametric_model: Optional[str] = None
    p_value_tail_method: str = "empirical"
    # R2-4 (2026-04-21): cipher family when method=matched_variant_family.
    # Empty string means "legacy Phase 6 Vigenère default"; the new
    # R2-4 entries carry explicit family names like "beaufort" or
    # "columnar_single". Other methods ignore this field.
    family: str = ""
    # G-1 (2026-06-10): which crib-scoring geometry this null was built
    # under. "anchored" = score_cribs at canonical positions (historical
    # default, legacy caches deserialize to this); "free" =
    # score_free/score_candidate_free (cribs matched anywhere).
    scoring_mode: str = "anchored"
    # G-1: analytic tail parameters for the free_crib_substring model
    # (p_ene_present / p_bc_present / p_both_present / letter_model).
    # None for anchored distributions.
    free_tail_params: Optional[dict] = None

    @property
    def cache_key(self) -> str:
        """Deterministic identifier for the manifest.

        R2-4: matched_variant_family entries include the ``family`` tag
        so ``beaufort`` and ``variant_beaufort`` get distinct cache slots
        rather than overwriting each other.

        G-1: free-mode entries carry a ``__free`` suffix so they never
        collide with (or silently substitute for) anchored entries.
        """
        base = f"{self.scorer_name}__{self.method}__{self.alphabet}__n{self.n_chars}"
        if self.method == "matched_variant_family" and self.family:
            base += f"__{self.family}"
        if self.scoring_mode == "free":
            base += "__free"
        return base

    # ── Computational interface ──────────────────────────────────────────────

    def p_value(self, observed_score: float) -> float:
        """Right-tailed p-value P(X >= observed_score) under the null.

        Returns a value in [0.0, 1.0]. When the observation exceeds the
        empirical range, falls back to the parametric model if one was
        fitted; otherwise returns 1/n_samples as a conservative upper bound.

        Never raises.
        """
        # Prefer the exact/parametric tail when available — it extrapolates
        # correctly into the tail where empirical resolution runs out.
        # G-1: free-mode distributions use the substring-presence tail;
        # the anchored Binomial branch must never catch them (different
        # event geometry entirely).
        if (
            self.parametric_model == "free_crib_substring"
            and self.free_tail_params
        ):
            return self._free_crib_tail(observed_score)
        if (
            self.scorer_name == "crib_score"
            and self.method == "random_text"
            and self.scoring_mode != "free"
        ):
            return _binomial_right_tail(
                observed=int(math.floor(observed_score)),
                n=24, p=1.0 / 26.0,
            )
        if self.parametric_model == "normal":
            return _normal_right_tail(observed_score, self.mean, self.stdev)
        # Empirical fallback.
        return self._empirical_p_value(observed_score)

    def _free_crib_tail(self, observed_score: float) -> float:
        """Right tail over the free crib-score support {0, 11, 13, 24}.

        X >= s maps exactly onto crib-presence events:
          s <= 0         → 1.0
          0  < s <= 11   → P(any crib present)  = p_ene + p_bc − p_both
          11 < s <= 13   → P(ENE present)       = p_ene
          13 < s <= 24   → P(both present)      = p_both
          s > 24         → 0.0 (above the support maximum)

        ``p_both == 0.0`` is exact for permutation-of-CT sources (letter
        multiset infeasibility, computed at build time); elsewhere it is
        an independence approximation blended with the empirical rate
        (never smaller than observed — see _free_crib_tail_params).
        """
        params = self.free_tail_params or {}
        p_ene = float(params.get("p_ene_present", 0.0))
        p_bc = float(params.get("p_bc_present", 0.0))
        p_both = float(params.get("p_both_present", 0.0))
        if observed_score <= 0:
            return 1.0
        if observed_score <= 11:
            return max(0.0, min(1.0, p_ene + p_bc - p_both))
        if observed_score <= 13:
            return max(0.0, min(1.0, p_ene))
        if observed_score <= 24:
            return max(0.0, min(1.0, p_both))
        return 0.0

    def _empirical_p_value(self, observed_score: float) -> float:
        if not self.sorted_scores:
            # No empirical data loaded; conservative floor.
            return 1.0 / max(1, self.n_samples)
        n = len(self.sorted_scores)
        idx = bisect.bisect_left(self.sorted_scores, observed_score)
        tail_count = n - idx
        if tail_count == 0:
            # More extreme than any sample — return the 1/N floor.
            return 1.0 / n
        return tail_count / n

    # ── Persistence ──────────────────────────────────────────────────────────

    def to_summary_dict(self) -> dict[str, Any]:
        """Lightweight dict for the manifest (safe to commit)."""
        pct_labels = [("p01", 0.01), ("p05", 0.05), ("p10", 0.10),
                      ("p25", 0.25), ("p50", 0.50), ("p75", 0.75),
                      ("p90", 0.90), ("p95", 0.95), ("p99", 0.99),
                      ("p999", 0.999)]
        percentiles: dict[str, float] = {}
        if self.sorted_scores:
            n = len(self.sorted_scores)
            for lbl, q in pct_labels:
                idx = min(n - 1, int(q * n))
                percentiles[lbl] = float(self.sorted_scores[idx])
        return {
            "scorer_name": self.scorer_name,
            "method": self.method,
            "n_chars": self.n_chars,
            "alphabet": self.alphabet,
            "family": self.family,
            "n_samples": self.n_samples,
            "seed": self.seed,
            "kernel_commit": self.kernel_commit,
            "mean": self.mean,
            "stdev": self.stdev,
            "min": self.sorted_scores[0] if self.sorted_scores else None,
            "max": self.sorted_scores[-1] if self.sorted_scores else None,
            "percentiles": percentiles,
            "parametric_model": self.parametric_model,
            "p_value_tail_method": self.p_value_tail_method,
            "scoring_mode": self.scoring_mode,
            "free_tail_params": self.free_tail_params,
        }

    def to_full_dict(self) -> dict[str, Any]:
        """Full dict including sorted_scores (for disk cache)."""
        d = asdict(self)
        # Force floats for JSON compatibility.
        d["sorted_scores"] = [float(s) for s in self.sorted_scores]
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "NullDistribution":
        return cls(
            scorer_name=str(d["scorer_name"]),
            method=str(d["method"]),
            n_chars=int(d["n_chars"]),
            alphabet=str(d["alphabet"]),
            n_samples=int(d["n_samples"]),
            seed=int(d["seed"]),
            kernel_commit=str(d.get("kernel_commit", "unknown")),
            sorted_scores=list(d.get("sorted_scores", [])),
            mean=float(d.get("mean", 0.0)),
            stdev=float(d.get("stdev", 0.0)),
            parametric_model=d.get("parametric_model"),
            p_value_tail_method=str(d.get("p_value_tail_method", "empirical")),
            family=str(d.get("family", "") or ""),
            # G-1: legacy (pre-scoring_mode) caches are anchored by
            # construction — they were built with the anchored scorer.
            scoring_mode=str(d.get("scoring_mode", "anchored") or "anchored"),
            free_tail_params=d.get("free_tail_params"),
        )


# ─── Scoring helpers ─────────────────────────────────────────────────────────

def _alphabet_chars(alphabet: str) -> str:
    if alphabet == "AZ":
        return "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if alphabet == "KA":
        # Lazy import to avoid circulars during module load.
        from kryptos.kernel.constants import KRYPTOS_ALPHABET
        return KRYPTOS_ALPHABET
    raise ValueError(f"unknown alphabet {alphabet!r}")


def _build_scorer_fn(
    scorer_name: str,
    scoring_mode: str = "anchored",
) -> Callable[[str], float]:
    """Return a callable that takes a plaintext and returns a float score.

    G-1: ``scoring_mode="free"`` is only meaningful for ``crib_score``
    (the free geometry changes the crib EVENT, not the language stats);
    callers must validate before reaching here.
    """
    if scorer_name == "crib_score" and scoring_mode == "free":
        from kryptos.kernel.scoring.free_crib import score_free
        return lambda text: float(score_free(text).score)
    if scorer_name == "crib_score":
        from kryptos.kernel.scoring.crib_score import score_cribs
        return lambda text: float(score_cribs(text))
    if scorer_name == "ngram_score":
        from kryptos.kernel.scoring.ngram import get_default_scorer
        ng = get_default_scorer()
        return lambda text: float(ng.score_per_char(text))
    if scorer_name == "composite":
        from kryptos.kernel.scoring.aggregate import score_candidate
        def _composite(text: str) -> float:
            br = score_candidate(text)
            # Combine crib_score + a sigmoid-ish bonus for bean pass; keep
            # it monotone in quality so larger is "better". Not a canonical
            # score but a consistent orderable stat for the null comparison.
            return float(br.crib_score) + (1.0 if br.bean_passed else 0.0)
        return _composite
    raise ValueError(f"unknown scorer_name {scorer_name!r}")


def _sample_one(
    method: str,
    alphabet_chars: str,
    n_chars: int,
    rng: random.Random,
    family: str = "",
) -> str:
    """Draw one plaintext-like sample from the null.

    The returned string is what the scorer sees — for random_text and
    shuffled_ct methods, this is the candidate directly. For
    matched_variant_family, this is the K4 CT decrypted under a randomly-
    drawn member of the named cipher family (per brief R2-4 §5.2).
    """
    if method == "random_text":
        return "".join(rng.choice(alphabet_chars) for _ in range(n_chars))
    if method == "shuffled_ct":
        from kryptos.kernel.constants import CT
        chars = list(CT)
        rng.shuffle(chars)
        return "".join(chars)
    if method == "matched_variant_family":
        return _sample_one_matched_family(family, n_chars, rng)
    raise ValueError(f"unknown method {method!r}")


def _sample_one_matched_family(
    family: str,
    n_chars: int,
    rng: random.Random,
) -> str:
    """Draw one candidate from the matched_variant_family null.

    For additive families (vigenere / beaufort / variant_beaufort):
      random keyword of length 5..11 drawn uniformly from A-Z; decrypt
      the real K4 CT under the resulting key. The candidate is what
      that decryption produces.

    For transposition families:
      random (width, col_order) — for columnar_single — or two of them
      composed — for columnar_double. Each width is drawn uniformly
      from [4, 14]; each order is a random permutation. Invert both
      and apply to the real K4 CT.

    The semantics deliberately match brief §5.2: we test "what does a
    randomly-drawn member of this family produce when applied to the
    actual carved CT?" — NOT the Phase-6 "random-PT-encrypted-with-
    random-key" baseline (which is effectively just the scorer's noise
    floor on random text).

    The empty family string "" falls through to the Phase-6 Vigenère
    semantic for backward compatibility with pre-R2-4 caches.
    """
    from kryptos.kernel.constants import ALPH, CT
    # Legacy path: preserve the Phase 6 Vigenère-AZ cache semantics.
    if family == "":
        from kryptos.kernel.transforms.vigenere import (
            encrypt_text, CipherVariant,
        )
        kw_len = rng.randint(5, 11)
        key = [rng.randint(0, 25) for _ in range(kw_len)]
        pt = "".join(rng.choice(ALPH) for _ in range(n_chars))
        return encrypt_text(pt, key, CipherVariant.VIGENERE)

    if family in ("vigenere", "beaufort", "variant_beaufort"):
        from kryptos.kernel.transforms.vigenere import (
            decrypt_text, CipherVariant,
        )
        variant_map = {
            "vigenere": CipherVariant.VIGENERE,
            "beaufort": CipherVariant.BEAUFORT,
            "variant_beaufort": CipherVariant.VAR_BEAUFORT,
        }
        kw_len = rng.randint(5, 11)
        key = [rng.randint(0, 25) for _ in range(kw_len)]
        return decrypt_text(CT[:n_chars], key, variant_map[family])

    if family in ("columnar_single", "columnar_double"):
        from kryptos.kernel.transforms.transposition import (
            columnar_perm, apply_perm, invert_perm,
        )
        def _random_layer(ct_len: int) -> tuple[int, list[int]]:
            w = rng.randint(4, 14)
            order = list(range(w))
            rng.shuffle(order)
            return w, order

        ct = CT[:n_chars]
        # Decrypt the OUTER layer first (as if it was applied LAST during
        # encryption). For columnar_single there's only one layer.
        w1, o1 = _random_layer(n_chars)
        inv1 = invert_perm(columnar_perm(w1, o1, n_chars))
        step1 = apply_perm(ct, inv1)
        if family == "columnar_single":
            return step1
        w2, o2 = _random_layer(n_chars)
        inv2 = invert_perm(columnar_perm(w2, o2, n_chars))
        return apply_perm(step1, inv2)

    if family in ("rail_fence", "myszkowski", "route"):
        # Mirror the dispatcher's transposition path (transposition_full,
        # direction="undo"): build a random member's perm from the same
        # kernel primitive the translator uses, invert it, and apply to the
        # real CT — exactly what the scorer sees when this family dispatches.
        from kryptos.kernel.transforms.transposition import (
            apply_perm, invert_perm,
        )
        ct = CT[:n_chars]
        perm = _random_transposition_perm(family, n_chars, rng)
        return apply_perm(ct, invert_perm(perm))

    raise ValueError(
        f"matched_variant_family: unknown family {family!r}. Valid: "
        f"{sorted(_VALID_FAMILIES)}"
    )


def _random_transposition_perm(
    family: str,
    n_chars: int,
    rng: random.Random,
) -> list[int]:
    """Draw a random member of ``family`` and return its kernel permutation.

    The parameter ranges mirror what the dispatcher's _translate_layer
    accepts for each kind (job_dispatcher.py): rail_fence depth, myszkowski
    keyword, route variant + grid. The resulting perm is length-preserving
    (== n_chars) by construction for every draw, so the caller can invert
    and apply it directly.
    """
    from kryptos.kernel.transforms.transposition import (
        rail_fence_perm,
        myszkowski_perm,
        serpentine_perm,
        spiral_perm,
        diagonal_perm,
        canonical_diagonal_perm,
    )
    if family == "rail_fence":
        depth = rng.randint(2, min(24, n_chars - 1))
        return rail_fence_perm(n_chars, depth)

    if family == "myszkowski":
        from kryptos.kernel.constants import ALPH
        kw_len = rng.randint(4, 14)
        keyword = "".join(rng.choice(ALPH) for _ in range(kw_len))
        return myszkowski_perm(keyword, n_chars)

    # family == "route": variant selects the read pattern over a grid.
    variant = rng.choice(["serpentine", "spiral", "diagonal", "diagonal_canonical"])
    if variant == "diagonal_canonical":
        width = rng.randint(2, n_chars // 2)
        return canonical_diagonal_perm(width, n_chars)
    # Row-major variants: pick cols, derive rows = ceil so rows*cols >= n_chars.
    cols = rng.randint(2, n_chars // 2)
    rows = -(-n_chars // cols)  # ceil division
    if variant == "serpentine":
        return serpentine_perm(rows, cols, n_chars, vertical=rng.random() < 0.5)
    if variant == "spiral":
        return spiral_perm(
            rows, cols, n_chars,
            clockwise=rng.random() < 0.5,
            start_corner=rng.choice(
                ["top_left", "top_right", "bottom_right", "bottom_left"]
            ),
        )
    # variant == "diagonal": start_edge is axis-constrained in the kernel.
    axis = rng.choice(["main", "anti"])
    start_edge = rng.choice(
        ["top_then_left", "left_then_top"] if axis == "main"
        else ["top_then_right", "right_then_top"]
    )
    return diagonal_perm(
        rows, cols, n_chars,
        axis=axis,
        order=rng.choice(["forward", "reverse"]),
        start_edge=start_edge,
    )


# ─── Parametric tail helpers ─────────────────────────────────────────────────

def _permutation_window_match_prob(
    ct_counts: dict[str, int], pattern: str, n: int,
) -> float:
    """P(a fixed length-L window of a uniform random permutation of the
    CT multiset spells ``pattern``).

    Exact for a uniform permutation: falling-factorial product over the
    pattern's letter needs divided by FallingFactorial(n, L). Returns 0.0
    when the multiset cannot supply the pattern. For the STRUCTURED
    family draws (rail fence / route / columnar members, not uniform
    permutations) this is an approximation — adequate because the tail
    is consulted at the 1e-6 alert gate with many orders of magnitude of
    headroom, and the empirical blend (see caller) dominates wherever
    the structured family deviates measurably.
    """
    from collections import Counter
    need = Counter(pattern)
    num = 1
    for ch, k in need.items():
        have = int(ct_counts.get(ch, 0))
        if have < k:
            return 0.0
        for i in range(k):
            num *= (have - i)
    den = 1
    for i in range(len(pattern)):
        den *= (n - i)
    return num / den


def _presence_prob(p_match: float, n_windows: int) -> float:
    """P(at least one of ``n_windows`` window positions matches).

    Independence approximation across windows; computed via
    -expm1(k·log1p(-p)) so sub-1e-16 per-window probabilities don't
    underflow to zero.
    """
    if p_match <= 0.0:
        return 0.0
    if p_match >= 1.0:
        return 1.0
    return -math.expm1(n_windows * math.log1p(-p_match))


def _free_crib_tail_params(
    method: str,
    family: str,
    n_chars: int,
    sorted_scores: list[float],
) -> dict[str, Any]:
    """Fit the free_crib_substring tail parameters at build time.

    Letter models:
      * "uniform" — random_text and additive matched families (a random
        additive key on the fixed CT yields ~uniform output letters).
      * "ct_permutation" — shuffled_ct and transposition matched
        families: the sample is a permutation of the carved CT, so the
        per-window probability is the exact uniform-permutation value
        and joint (both-cribs) feasibility is a multiset fact. With the
        real K4 CT the joint need (3 E's vs 2 available) is infeasible,
        making P(free 24) exactly 0 — computed from constants, never
        hardcoded.

    Both per-crib presence estimates are BLENDED with the empirical
    presence rates (max of analytic and observed): under additive
    matched families a periodic key can place a crib with probability
    far above the iid-uniform analytic value, and the Monte Carlo run
    is the instrument that sees it. The estimates never report less
    chance than what the sampler actually observed.
    """
    from collections import Counter
    from kryptos.kernel.constants import CT
    from kryptos.kernel.scoring.free_crib import CRIB_BC, CRIB_ENE

    permutation_source = method == "shuffled_ct" or (
        method == "matched_variant_family" and family in _PERMUTATION_FAMILIES
    )
    if permutation_source:
        # shuffled_ct and the transposition samplers permute the FULL CT
        # (see _sample_one), so the window count uses len(CT).
        n = len(CT)
        counts = dict(Counter(CT))
        p_ene_match = _permutation_window_match_prob(counts, CRIB_ENE, n)
        p_bc_match = _permutation_window_match_prob(counts, CRIB_BC, n)
        joint_need = Counter(CRIB_ENE) + Counter(CRIB_BC)
        joint_feasible = all(
            counts.get(ch, 0) >= k for ch, k in joint_need.items()
        )
        letter_model = "ct_permutation"
    else:
        n = n_chars
        p_ene_match = 26.0 ** -len(CRIB_ENE)
        p_bc_match = 26.0 ** -len(CRIB_BC)
        joint_feasible = True
        letter_model = "uniform"

    p_ene = _presence_prob(p_ene_match, max(0, n - len(CRIB_ENE) + 1))
    p_bc = _presence_prob(p_bc_match, max(0, n - len(CRIB_BC) + 1))

    n_samples = len(sorted_scores)
    if n_samples:
        emp_ene = sum(1 for s in sorted_scores if s in (13.0, 24.0)) / n_samples
        emp_bc = sum(1 for s in sorted_scores if s in (11.0, 24.0)) / n_samples
        p_ene = max(p_ene, emp_ene)
        p_bc = max(p_bc, emp_bc)

    if joint_feasible:
        p_both = p_ene * p_bc
        if n_samples:
            emp_both = sum(1 for s in sorted_scores if s == 24.0) / n_samples
            p_both = max(p_both, emp_both)
    else:
        p_both = 0.0

    return {
        "letter_model": letter_model,
        "p_ene_present": p_ene,
        "p_bc_present": p_bc,
        "p_both_present": p_both,
        "joint_multiset_feasible": joint_feasible,
    }


def _binomial_right_tail(observed: int, n: int, p: float) -> float:
    """Exact P(X >= observed) for X ~ Binomial(n, p)."""
    if observed <= 0:
        return 1.0
    if observed > n:
        return 0.0
    # Sum the upper tail. For n=24 this is trivially fast.
    q = 1.0 - p
    total = 0.0
    for k in range(observed, n + 1):
        total += math.comb(n, k) * (p ** k) * (q ** (n - k))
    return max(0.0, min(1.0, total))


def _normal_right_tail(x: float, mean: float, stdev: float) -> float:
    """Right-tailed normal p-value using the complementary error function."""
    if stdev <= 0:
        return 1.0 if x <= mean else 0.0
    z = (x - mean) / stdev
    # P(Z >= z) = 0.5 * erfc(z / sqrt(2))
    return 0.5 * math.erfc(z / math.sqrt(2.0))


# ─── Build API ───────────────────────────────────────────────────────────────

def build_null_distribution(
    scorer_name: str,
    method: str = "random_text",
    n_chars: int = 97,
    alphabet: str = "AZ",
    n_samples: int = _DEFAULT_SAMPLES,
    seed: int = _DEFAULT_SEED,
    family: str = "",
    scoring_mode: str = "anchored",
) -> NullDistribution:
    """Monte Carlo the null distribution for the given combo.

    Deterministic given (method, n_chars, alphabet, n_samples, seed,
    family, scoring_mode) + the kernel commit.

    R2-4 (2026-04-21): ``family`` is required for
    ``method='matched_variant_family'`` when the family is not the
    legacy Vigenère default. Must be one of ``_VALID_FAMILIES``.

    G-1 (2026-06-10): ``scoring_mode="free"`` builds the null for the
    dispatcher's crib_alignment="free" path: samples are scored with the
    kernel's position-free crib scorer and the tail is the analytic
    free_crib_substring model (empirically blended). Free mode is only
    valid with ``scorer_name="crib_score"``.

    Raises ValueError on unknown scorer / method / alphabet / family /
    scoring_mode.
    """
    if scorer_name not in _VALID_SCORERS:
        raise ValueError(
            f"scorer_name {scorer_name!r} not in {sorted(_VALID_SCORERS)}"
        )
    if method not in _VALID_METHODS:
        raise ValueError(
            f"method {method!r} not in {sorted(_VALID_METHODS)}"
        )
    if alphabet not in _VALID_ALPHABETS:
        raise ValueError(
            f"alphabet {alphabet!r} not in {sorted(_VALID_ALPHABETS)}"
        )
    if family not in _VALID_FAMILIES:
        raise ValueError(
            f"family {family!r} not in {sorted(_VALID_FAMILIES)}"
        )
    if scoring_mode not in _VALID_SCORING_MODES:
        raise ValueError(
            f"scoring_mode {scoring_mode!r} not in {sorted(_VALID_SCORING_MODES)}"
        )
    if scoring_mode == "free" and scorer_name != "crib_score":
        raise ValueError(
            "scoring_mode='free' is only defined for scorer_name="
            "'crib_score' (free alignment changes the crib event "
            f"geometry, not {scorer_name!r})"
        )
    if n_samples <= 0:
        raise ValueError("n_samples must be positive")

    rng = random.Random(seed)
    alpha = _alphabet_chars(alphabet)
    scorer = _build_scorer_fn(scorer_name, scoring_mode=scoring_mode)

    scores: list[float] = []
    for _ in range(n_samples):
        text = _sample_one(method, alpha, n_chars, rng, family=family)
        scores.append(scorer(text))
    scores.sort()

    n = len(scores)
    mean = sum(scores) / n
    variance = sum((s - mean) ** 2 for s in scores) / n
    stdev = math.sqrt(variance)

    # Fit a parametric family where it's applicable.
    parametric_model: Optional[str] = None
    p_value_tail_method = "empirical"
    free_tail_params: Optional[dict] = None
    if scoring_mode == "free":
        # G-1: analytic substring-presence tail. An empirical-only free
        # null is degenerate at 0 and its 1/N floor would SUPPRESS a
        # genuine free 24/24 at the 1e-6 alert gate.
        parametric_model = "free_crib_substring"
        p_value_tail_method = "exact"
        free_tail_params = _free_crib_tail_params(
            method, family, n_chars, scores,
        )
    elif scorer_name == "crib_score" and method == "random_text":
        parametric_model = "binomial"
        p_value_tail_method = "exact"
    elif scorer_name == "ngram_score" and method != "matched_variant_family":
        # R2-4: ngram_score on transposition nulls is empirical only —
        # the output is a permutation of the K4 CT and carries the
        # empirical letter-frequency structure of the carved text, not
        # a Gaussian-behaving noise process. The brief §5.4 documents
        # this 1/N floor explicitly; do not pretend normality.
        parametric_model = "normal"
        p_value_tail_method = "normal_approx"

    return NullDistribution(
        scorer_name=scorer_name,
        method=method,
        n_chars=n_chars,
        alphabet=alphabet,
        n_samples=n_samples,
        seed=seed,
        kernel_commit=_KERNEL_COMMIT,
        sorted_scores=scores,
        mean=mean,
        stdev=stdev,
        parametric_model=parametric_model,
        p_value_tail_method=p_value_tail_method,
        family=family,
        scoring_mode=scoring_mode,
        free_tail_params=free_tail_params,
    )


# ─── Cache interface ─────────────────────────────────────────────────────────

def _full_cache_path(
    scorer_name: str, method: str, alphabet: str, n_chars: int,
    family: str = "",
    scoring_mode: str = "anchored",
) -> Path:
    """Return the on-disk path for the full null-distribution JSON.

    R2-4: the ``family`` suffix distinguishes matched_variant_family
    caches by cipher family (columnar_single vs columnar_double vs
    beaufort vs ...). Empty family preserves the Phase-6 legacy filename
    for backward compatibility.

    G-1: free-mode entries get a ``__free`` filename suffix so anchored
    and free caches can never substitute for each other.
    """
    _FULL_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    fname = f"{scorer_name}__{method}__{alphabet}__n{n_chars}"
    if method == "matched_variant_family" and family:
        fname += f"__{family}"
    if scoring_mode == "free":
        fname += "__free"
    fname += "__v1.json"
    return _FULL_CACHE_DIR / fname


def save_to_cache(dist: NullDistribution) -> Path:
    """Write the full distribution to ``results/null_baselines/`` and
    update the manifest.

    The full file is gitignored. The manifest summary is committed.
    Returns the path to the full cache file.
    """
    full_path = _full_cache_path(
        dist.scorer_name, dist.method, dist.alphabet, dist.n_chars,
        family=dist.family,
        scoring_mode=dist.scoring_mode,
    )
    full_path.parent.mkdir(parents=True, exist_ok=True)
    full_path.write_text(json.dumps(dist.to_full_dict()))
    _update_manifest(dist)
    return full_path


def _update_manifest(dist: NullDistribution) -> None:
    manifest: dict[str, Any] = {}
    if _MANIFEST_PATH.exists():
        try:
            manifest = json.loads(_MANIFEST_PATH.read_text())
        except json.JSONDecodeError:
            logger.warning("Manifest unreadable; rewriting fresh")
    manifest.setdefault("distributions", {})
    manifest["distributions"][dist.cache_key] = dist.to_summary_dict()
    manifest["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    manifest["kernel_commit_at_latest_write"] = _KERNEL_COMMIT
    _MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    _MANIFEST_PATH.write_text(json.dumps(manifest, indent=2, sort_keys=True))


def get_cached(
    scorer_name: str,
    method: str = "random_text",
    n_chars: int = 97,
    alphabet: str = "AZ",
    family: str = "",
    scoring_mode: str = "anchored",
) -> Optional[NullDistribution]:
    """Load a cached null distribution from disk, or return None on miss.

    Does NOT rebuild on miss — caller decides whether to call
    ``build_null_distribution`` + ``save_to_cache``.

    R2-4: ``family`` identifies the matched_variant_family sub-cache.
    Empty family falls back to the Phase 6 legacy cache slot.

    G-1: ``scoring_mode="free"`` loads the free-built null only — an
    anchored cache is never a substitute for a free one (and vice
    versa).
    """
    full_path = _full_cache_path(
        scorer_name, method, alphabet, n_chars, family=family,
        scoring_mode=scoring_mode,
    )
    if not full_path.exists():
        return None
    try:
        d = json.loads(full_path.read_text())
        return NullDistribution.from_dict(d)
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        logger.warning("Null cache %s unreadable: %s", full_path, exc)
        return None


def get_or_build(
    scorer_name: str,
    method: str = "random_text",
    n_chars: int = 97,
    alphabet: str = "AZ",
    n_samples: int = _DEFAULT_SAMPLES,
    seed: int = _DEFAULT_SEED,
    family: str = "",
    scoring_mode: str = "anchored",
) -> NullDistribution:
    """Cache-first lookup; builds + caches on miss. Rebuilds on staleness."""
    cached = get_cached(
        scorer_name, method, n_chars, alphabet, family=family,
        scoring_mode=scoring_mode,
    )
    if cached is not None and not calibration_stale(cached):
        return cached
    dist = build_null_distribution(
        scorer_name, method, n_chars, alphabet, n_samples, seed, family=family,
        scoring_mode=scoring_mode,
    )
    save_to_cache(dist)
    return dist


def calibration_stale(
    dist: NullDistribution,
    current_commit: Optional[str] = None,
) -> bool:
    """True if the distribution was built against a different kernel commit.

    ``current_commit`` defaults to the module-cached kernel commit. The
    check is permissive: an 'unknown' build commit never invalidates
    (no git available at build time is not the user's fault).
    """
    if current_commit is None:
        current_commit = _KERNEL_COMMIT
    if dist.kernel_commit == "unknown" or current_commit == "unknown":
        return False
    return dist.kernel_commit != current_commit


# ─── p_value as a free function ──────────────────────────────────────────────

def p_value(score: float, dist: NullDistribution) -> float:
    """Right-tailed p-value of ``score`` under ``dist``."""
    return dist.p_value(score)


def family_wise_p_value(
    candidate_p_value: float,
    *,
    n_tests: int,
    universe_hash: str = "",
) -> dict[str, Any]:
    """Return simple family-wise corrections for a candidate-local p-value.

    The alert path deliberately gates on candidate-local p-values because
    it is a contradiction detector. Audit artifacts need the broader view:
    "given this many tested configurations, how surprising is at least one
    hit this good?" This helper records both conservative Bonferroni and
    Sidak independent-trial corrections without pretending either covers
    post-hoc garden-of-forking-paths risk outside the declared universe.
    """
    if not isinstance(n_tests, int) or isinstance(n_tests, bool) or n_tests < 1:
        raise ValueError(f"n_tests must be a positive int; got {n_tests!r}")
    p = float(candidate_p_value)
    if not math.isfinite(p) or p < 0.0 or p > 1.0:
        raise ValueError(f"candidate_p_value must be finite in [0, 1]; got {candidate_p_value!r}")
    bonferroni = min(1.0, p * n_tests)
    sidak = 1.0 - ((1.0 - p) ** n_tests)
    return {
        "candidate_p_value": p,
        "n_tests": n_tests,
        "universe_hash": universe_hash,
        "bonferroni_p_value": bonferroni,
        "sidak_p_value": sidak,
        "method": "candidate-local p corrected over dispatcher config universe",
        "caveat": (
            "Does not correct for post-hoc hypothesis generation, repeated "
            "controller cycles, or unlogged search families."
        ),
    }


# ─── Alert gate parameterization (brief: raise n_samples + parameterize) ────
#
# Invariant the project relies on: the configured p-value gate
# (``alerts.ALERT_P_VALUE_GATE``) must be reachable under each null cache's
# empirical support. If n_samples is too small for the gate, the gate is
# structurally unreachable and matched-family alerts get silently suppressed
# regardless of how strong the signal is. That failure mode was Campaign A's
# §7.2 finding (surfaced by the synthetic-signal harness).
#
# The floor here is ``10 / n_samples`` rather than ``1 / n_samples``. The
# 10-event convention is conservative: a one-event tail could happen from a
# single stray high sample, but a 10-event tail is a genuinely rare outcome
# under the empirical null. We widen the gate to the floor when the
# configured gate is tighter, and log a warning the first time this happens
# per (family, session) pair so postmortems can see the degradation.

_EMPIRICAL_FLOOR_EVENT_COUNT: int = 10
_warned_floor_mismatches: set[tuple[str, int]] = set()


def effective_gate(
    null: "NullDistribution",
    configured_gate: float,
) -> float:
    """Return the effective p-value gate for alerts consulting ``null``.

    Enforces ``gate >= 10 / null.n_samples`` for **empirical** nulls only.
    When the configured gate is below the empirical floor, return the
    floor and log a warning exactly once per (family, process) pair.
    Otherwise return the configured gate unchanged.

    Nulls with a parametric model (``random_text`` has an exact Binomial
    tail; ``ngram_score`` on additive nulls has a normal-approx tail)
    extrapolate past their empirical support — the 10-event floor is
    irrelevant to them. Always return the configured gate in that case.
    This is load-bearing: Phase 6 random_text alerts must not be
    affected by the matched-family parameterization (brief non-goal).

    Intentionally pure aside from logging. Safe to call from the alert
    path without affecting production code outside this module.
    """
    if null is None or null.n_samples <= 0:
        return configured_gate
    # Parametric nulls bypass the empirical-floor widening: their
    # p-values are computed analytically, not via tail-counting, so the
    # floor doesn't apply.
    if null.parametric_model:
        return configured_gate
    empirical_floor = float(_EMPIRICAL_FLOOR_EVENT_COUNT) / float(null.n_samples)
    if configured_gate >= empirical_floor:
        return configured_gate
    key = (null.family, os.getpid())
    if key not in _warned_floor_mismatches:
        _warned_floor_mismatches.add(key)
        logger.warning(
            "ALERT_P_VALUE_GATE=%.0e is below empirical floor %.0e for "
            "family=%r (n_samples=%d); widening gate to floor. Run "
            "scripts/_infra/calibrate_null_baselines_r2_4.py with a "
            "higher n_samples to reach the configured gate.",
            configured_gate, empirical_floor, null.family, null.n_samples,
        )
    return empirical_floor


# ─── Convenience: alert-path helper ──────────────────────────────────────────

def p_value_for_alert(
    plaintext: str,
    crib_score_value: int,
    family: str = "",
    scoring_mode: str = "anchored",
) -> tuple[Optional[float], str]:
    """Best-effort p-value for the alert path (Phase 6 §8.4).

    Returns ``(p_value, status)`` where status is one of:
        "ok"                    — p-value computed from cached distribution
        "ok_matched_family"     — R3-2: matched-family null consulted
                                  successfully (R2-4 cache hit for ``family``)
        "matched_null_miss"     — R3-2: caller requested a matched-family
                                  null but no cache exists for that family;
                                  p-value was computed from the random_text
                                  fallback and the alert is flagged
                                  uncalibrated-for-family
        "ok_free_matched"       — G-1: free-mode matched-family null hit
        "ok_free"               — G-1: free-mode random_text null hit
        "free_matched_null_miss" — G-1: free matched-family cache missing;
                                  p computed from the free random_text null
        "free_null_miss"        — G-1: free mode requested but NO free
                                  null cache exists; p-value is None.
                                  Anchored caches are NEVER consulted in
                                  free mode — that substitution is the
                                  exact miscalibration G-1 exists to
                                  prevent.
        "stale_cache"           — a requested null cache exists but was
                                  built against a different kernel commit;
                                  p-value is None
        "cache_miss"            — null cache not available at all,
                                  p-value is None
        "error"                 — unexpected failure, p-value is None

    R3-2 (2026-04-21): when ``family`` is non-empty, attempt a
    matched-family null lookup first (R2-4 calibration cache). If the
    matched-family cache is missing, fall back to the random_text null
    with status ``"matched_null_miss"`` so the alert path can log the
    degradation explicitly. Empty ``family`` preserves the Phase 6
    behaviour (random_text null only).

    Callers should fall back to legacy crib_score-only alert gating when
    status in {"cache_miss", "stale_cache", "free_null_miss", "error"}
    and emit a WARNING that the alert is uncalibrated. The helper
    deliberately refuses to consume stale p-values; a stale cache can
    describe old scoring semantics and must not be treated as calibrated
    evidence.
    """
    try:
        def _stale(dist: NullDistribution, label: str) -> bool:
            if not calibration_stale(dist):
                return False
            logger.warning(
                "Null baseline cache %s is stale for alert p-value "
                "(cache_key=%s, cache_commit=%s, current_commit=%s); "
                "refusing to consume stale calibration.",
                label, dist.cache_key, dist.kernel_commit, _KERNEL_COMMIT,
            )
            return True

        # G-1: free scoring mode consults ONLY free-built nulls.
        if scoring_mode == "free":
            if family:
                matched = get_cached(
                    "crib_score", "matched_variant_family", 97, "AZ",
                    family=family, scoring_mode="free",
                )
                if matched is not None:
                    if _stale(matched, "free_matched_family"):
                        return (None, "stale_cache")
                    p = matched.p_value(float(crib_score_value))
                    return (p, "ok_free_matched")
                logger.warning(
                    "Free matched-family null cache miss for family=%r; "
                    "falling back to the free random_text null",
                    family,
                )
            dist = get_cached(
                "crib_score", "random_text", 97, "AZ", scoring_mode="free",
            )
            if dist is None:
                logger.warning(
                    "No free-mode null cache available (family=%r); the "
                    "alert is UNCALIBRATED for free alignment. Run "
                    "scripts/_infra/calibrate_null_baselines_r2_4.py to "
                    "build the free-mode entries.",
                    family,
                )
                return (None, "free_null_miss")
            if _stale(dist, "free_random_text"):
                return (None, "stale_cache")
            p = dist.p_value(float(crib_score_value))
            return (p, "free_matched_null_miss" if family else "ok_free")

        # R3-2: try matched-family first when caller gave a family hint.
        if family:
            matched = get_cached(
                "crib_score", "matched_variant_family", 97, "AZ",
                family=family,
            )
            if matched is not None:
                if _stale(matched, "matched_family"):
                    return (None, "stale_cache")
                p = matched.p_value(float(crib_score_value))
                return (p, "ok_matched_family")
            logger.warning(
                "Matched-family null cache miss for family=%r; "
                "falling back to random_text null for alert p-value",
                family,
            )
            dist = get_cached("crib_score", "random_text", 97, "AZ")
            if dist is None:
                return (None, "cache_miss")
            if _stale(dist, "random_text_fallback"):
                return (None, "stale_cache")
            p = dist.p_value(float(crib_score_value))
            return (p, "matched_null_miss")

        dist = get_cached("crib_score", "random_text", 97, "AZ")
        if dist is None:
            return (None, "cache_miss")
        if _stale(dist, "random_text"):
            return (None, "stale_cache")
        p = dist.p_value(float(crib_score_value))
        return (p, "ok")
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("p_value_for_alert failed: %s", exc)
        return (None, "error")


__all__ = [
    "NullDistribution",
    "build_null_distribution",
    "get_cached",
    "get_or_build",
    "save_to_cache",
    "calibration_stale",
    "p_value",
    "family_wise_p_value",
    "p_value_for_alert",
    "effective_gate",
    "_KERNEL_COMMIT",
    "_FULL_CACHE_DIR",
    "_MANIFEST_PATH",
    "_VALID_SCORERS",
    "_VALID_METHODS",
    "_VALID_ALPHABETS",
    "_VALID_SCORING_MODES",
    "_EMPIRICAL_FLOOR_EVENT_COUNT",
]
