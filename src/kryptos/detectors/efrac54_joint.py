"""E-FRAC-54 Joint Two-Sided Detector for mono->trans->running-key.

This module implements the joint statistical detector specified by the
statistical-review for the cipher family

    C[i] = sigma(PT[i]) ⊕ K[pi(i)]

where ⊕ is one of {Vigenere +, Beaufort -, Variant Beaufort -}.

E-FRAC-54 showed that single-sided English scoring on the recovered PT
is *underdetermined* at K4's sample size: the 13 mono degrees of freedom
plus a free running key give the search enough flexibility to absorb the
quadgram-signal budget on 97 chars.  The insight here is to score BOTH
sides simultaneously: the implied running-key tape K_hat must ALSO look
English-like.  Mono DOF that improve PT necessarily damage K_hat (the
sum is invariant under additive shifts of sigma, modulo transposition),
so the joint statistic

    T = L_PT + L_K - Penalty

is much harder to make extreme under H_0 than either side alone.

CRITICAL — surrogate/real pipeline parity
-----------------------------------------
Per the spec: the Gumbel calibration absorbs ALL multiplicity correction.
If the search pipeline applied to the surrogates differs in ANY way from
the search pipeline applied to real K4 CT (different hill-climb restarts,
width set, sigma enumerator, seed policy, etc.) then tau is invalidated.

`calibrate_threshold` therefore takes `search_fn` as a callable and
applies it identically to each surrogate.  Callers MUST NOT pass a
"cheap" surrogate-only search pipeline.  The `search_fn_hash` field in
the pre-registration artifact is your traceability anchor.

K_hat direction (verified by round-trip test in tests/test_efrac54_detector.py)
-------------------------------------------------------------------------------
Vigenere    : C[i] = sigma(PT[i]) + K[pi(i)]   ->  K[j] = C[pi^-1(j)] - sigma(PT[pi^-1(j)])
Beaufort    : C[i] = K[pi(i)]    - sigma(PT[i]) ->  K[j] = C[pi^-1(j)] + sigma(PT[pi^-1(j)])
Var Beaufort: C[i] = sigma(PT[i]) - K[pi(i)]   ->  K[j] = sigma(PT[pi^-1(j)]) - C[pi^-1(j)]

Quadgram scale note
-------------------
`data/english_quadgrams.json` ships log10 probabilities.  After ln
conversion (multiply by ln 10), real English text scores roughly
-10.5 nats/char on this scorer and uniform random scores roughly
-15 nats/char.  The statistical-review's original design memo
assumed a normalized model producing ~-3.2 nats/char for English
(the text's true entropy rate).  The spec logic is still correct
because only the *gap* between English and random enters the Gumbel
calibration, and the gap (~4.5 nats/char) is preserved under a
scale shift.  But absolute thresholds in the original memo (tau ~
-6.52) do NOT apply to this implementation; the empirical Gumbel
fit produces scale-appropriate values automatically.  Callers
reading the auditor memo should be aware of the factor-of-ln(10)
offset when comparing numbers.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import math
import os
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

from kryptos.kernel.constants import (
    ALPH,
    ALPH_IDX,
    CRIB_DICT,
    CRIB_POSITIONS,
    CT,
    CT_LEN,
    MOD,
)
from kryptos.kernel.scoring.ngram import NgramScorer, get_default_scorer
from kryptos.kernel.transforms.transposition import columnar_perm, invert_perm
from kryptos.kernel.transforms.vigenere import CipherVariant


# ── Public dataclasses ────────────────────────────────────────────────────


@dataclass(frozen=True)
class CandidateTuple:
    """A candidate (sigma, width, kappa, non-crib PT) tuple.

    Attributes
    ----------
    sigma : tuple[int, ...]
        Length-26 permutation of [0..25].  sigma[p] = the substituted
        letter index for plaintext letter p.
    width : int
        Columnar transposition width (>= 2).
    kappa : tuple[int, ...]
        Column read-order, length == width.  Standard "rank" form
        (matches `kryptos.kernel.transforms.transposition.columnar_perm`).
    pt_nc : str
        The candidate plaintext at the n_free non-crib positions, in
        ascending position order.  Length must equal n - len(crib_positions).
    """

    sigma: tuple[int, ...]
    width: int
    kappa: tuple[int, ...]
    pt_nc: str


@dataclass(frozen=True)
class JointScore:
    """Joint score for a candidate tuple.

    `t = l_pt + l_k - penalty`.  Both `l_pt` and `l_k` are nats/char.
    `penalty` is 0 in this implementation (multiplicity is absorbed by
    the Gumbel calibration of `tau`).
    """

    l_pt: float
    l_k: float
    t: float
    bean_ok: bool
    cribs_ok: bool
    penalty: float = 0.0


# ── Helpers ───────────────────────────────────────────────────────────────


_LN10 = math.log(10.0)


def _scorer_to_nats(scorer: NgramScorer) -> NgramScorer:
    """No-op identity hook.  We convert log10 -> ln in `_score_nats` below
    so we can keep the same scorer instance everywhere."""
    return scorer


def _score_nats(scorer: NgramScorer, masked_text: str, mask: Sequence[bool]) -> float:
    """Quadgram score in nats/char, restricted to positions where mask is True.

    Quadgrams are evaluated only when ALL FOUR of their positions fall
    inside the mask.  This is the cleanest way to honour "score non-crib
    positions only" without splicing across removed regions.

    NOTE: english_quadgrams.json stores log10 probabilities (negative
    floats roughly in [-7, -3]).  We multiply by ln(10) to convert to
    nats so the spec's nats/char accounting is honoured.
    """
    n = len(masked_text)
    if n < 4:
        return 0.0
    floor = scorer._floor * _LN10  # nats
    total = 0.0
    count = 0
    for i in range(n - 3):
        if not (mask[i] and mask[i + 1] and mask[i + 2] and mask[i + 3]):
            continue
        gram = masked_text[i : i + 4]
        lp10 = scorer.log_probs.get(gram, scorer._floor)
        total += lp10 * _LN10
        count += 1
    if count == 0:
        return floor
    return total / count


def _build_full_pt(pt_nc: str, n: int = CT_LEN) -> Optional[str]:
    """Weave non-crib PT with canonical cribs into a full-length string."""
    n_free = n - len(CRIB_POSITIONS)
    if len(pt_nc) != n_free:
        return None
    out = [""] * n
    for pos, ch in CRIB_DICT.items():
        out[pos] = ch
    it = iter(pt_nc)
    for i in range(n):
        if not out[i]:
            try:
                out[i] = next(it)
            except StopIteration:
                return None
            if not out[i].isalpha():
                return None
    return "".join(out).upper()


def _apply_sigma(pt: str, sigma: Sequence[int]) -> List[int]:
    """Return [sigma[ALPH_IDX[c]] for c in pt] as ints."""
    return [sigma[ALPH_IDX[c]] for c in pt]


def _columnar_perm_or_identity(width: int, kappa: Sequence[int], n: int) -> List[int]:
    """Build a columnar permutation, or identity if width <= 1."""
    if width <= 1 or len(kappa) != width:
        return list(range(n))
    return columnar_perm(width, list(kappa), length=n)


def _khat_from_pt(
    ct: str,
    pt: str,
    sigma: Sequence[int],
    pi: Sequence[int],
    variant: CipherVariant,
) -> List[int]:
    """Compute the implied keystream tape K_hat (length n).

    Model: C[i] = sigma(PT[i]) ⊕ K[pi(i)]

    Therefore (with j = pi(i), so i = pi^-1(j)):
        K[j] = invert(⊕)(C[pi^-1(j)], sigma(PT[pi^-1(j)]))
    """
    n = len(ct)
    pi_inv = invert_perm(list(pi))
    s_pt = _apply_sigma(pt, sigma)
    out: List[int] = [0] * n
    for j in range(n):
        i = pi_inv[j]
        c = ALPH_IDX[ct[i]]
        s = s_pt[i]
        if variant == CipherVariant.VIGENERE:
            # C = s + K  ->  K = C - s
            out[j] = (c - s) % MOD
        elif variant == CipherVariant.BEAUFORT:
            # C = K - s  ->  K = C + s
            out[j] = (c + s) % MOD
        elif variant == CipherVariant.VAR_BEAUFORT:
            # C = s - K  ->  K = s - C
            out[j] = (s - c) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant!r}")
    return out


def _check_cribs(pt: str) -> bool:
    return all(pt[pos] == ch for pos, ch in CRIB_DICT.items())


def _check_bean(sigma: Sequence[int]) -> bool:
    """The BEAN equality k[27]=k[65] is variant-independent and is a
    cipher-side property of the keystream, not directly of sigma.  We
    return True here as a structural placeholder; full Bean checking
    requires the recovered K_hat and is performed downstream by the
    main scoring infrastructure if needed."""
    return True


# ── Public API ────────────────────────────────────────────────────────────


def score_joint(
    ct: str,
    cand: CandidateTuple,
    quadgram: Optional[NgramScorer] = None,
    variant: str | CipherVariant = "vigenere",
    mask: Optional[Iterable[int]] = None,
) -> JointScore:
    """Compute the joint two-sided score for a candidate.

    Parameters
    ----------
    ct : str
        Ciphertext, length 97 for K4.  May be a surrogate.
    cand : CandidateTuple
        (sigma, width, kappa, pt_nc).
    quadgram : NgramScorer, optional
        Quadgram scorer.  Defaults to the project default scorer.
    variant : str | CipherVariant
        "vigenere" | "beaufort" | "var_beaufort".
    mask : iterable[int], optional
        Positions to EXCLUDE from scoring (in addition to the canonical
        cribs).  Useful for crib_positions extensions or null-mask work.

    Returns
    -------
    JointScore
        l_pt, l_k in nats/char; t = l_pt + l_k - penalty.
    """
    if quadgram is None:
        quadgram = _scorer_to_nats(get_default_scorer())
    if isinstance(variant, str):
        variant = CipherVariant(variant)

    n = len(ct)
    excluded = set(CRIB_POSITIONS)
    if mask is not None:
        excluded |= set(int(p) for p in mask)

    full_pt = _build_full_pt(cand.pt_nc, n=n)
    if full_pt is None or not _check_cribs(full_pt):
        return JointScore(l_pt=-math.inf, l_k=-math.inf, t=-math.inf,
                          bean_ok=False, cribs_ok=False)

    pi = _columnar_perm_or_identity(cand.width, cand.kappa, n)
    if len(pi) != n or set(pi) != set(range(n)):
        return JointScore(l_pt=-math.inf, l_k=-math.inf, t=-math.inf,
                          bean_ok=False, cribs_ok=False)

    # K_hat side
    khat_nums = _khat_from_pt(ct, full_pt, cand.sigma, pi, variant)
    khat_text = "".join(ALPH[v] for v in khat_nums)

    # Build masks
    pt_mask = [i not in excluded for i in range(n)]
    # K_hat lives in "transposed" coordinates: index j corresponds to
    # source position i = pi_inv[j].  A position j is "non-crib" iff its
    # source position pi_inv[j] is non-crib.
    pi_inv = invert_perm(pi)
    k_mask = [pi_inv[j] not in excluded for j in range(n)]

    l_pt = _score_nats(quadgram, full_pt, pt_mask)
    l_k = _score_nats(quadgram, khat_text, k_mask)

    bean_ok = _check_bean(cand.sigma)
    return JointScore(l_pt=l_pt, l_k=l_k, t=l_pt + l_k, bean_ok=bean_ok, cribs_ok=True)


# ── Round-trip helper (used by tests) ─────────────────────────────────────


def encrypt_with_model(
    pt: str,
    sigma: Sequence[int],
    width: int,
    kappa: Sequence[int],
    key_nums: Sequence[int],
    variant: str | CipherVariant = "vigenere",
) -> str:
    """Encrypt PT under the cipher model `C[i] = sigma(PT[i]) ⊕ K[pi(i)]`.

    Used to construct synthetic plants for tests.  K must have length n.
    """
    if isinstance(variant, str):
        variant = CipherVariant(variant)
    n = len(pt)
    pi = _columnar_perm_or_identity(width, kappa, n)
    if len(key_nums) != n:
        raise ValueError(f"key length {len(key_nums)} != pt length {n}")
    s_pt = _apply_sigma(pt, sigma)
    out: List[str] = [""] * n
    for i in range(n):
        s = s_pt[i]
        k = key_nums[pi[i]]
        if variant == CipherVariant.VIGENERE:
            c = (s + k) % MOD
        elif variant == CipherVariant.BEAUFORT:
            c = (k - s) % MOD
        elif variant == CipherVariant.VAR_BEAUFORT:
            c = (s - k) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant!r}")
        out[i] = ALPH[c]
    return "".join(out)


# ── Surrogate generation ──────────────────────────────────────────────────


def generate_shuffled_surrogate(ct: str, rng: random.Random) -> str:
    """Shuffle non-crib CT positions; preserve crib positions exactly."""
    n = len(ct)
    free = [i for i in range(n) if i not in CRIB_POSITIONS]
    chars = [ct[i] for i in free]
    rng.shuffle(chars)
    out = list(ct)
    for idx, src in enumerate(free):
        out[src] = chars[idx]
    return "".join(out)


# ── Gumbel fit (method of moments) ────────────────────────────────────────


_EULER_GAMMA = 0.5772156649015329


def fit_gumbel_mom(samples: Sequence[float]) -> Tuple[float, float]:
    """Fit Gumbel(mu, beta) by method of moments.

    For Gumbel max:
        mean = mu + beta * gamma
        var  = (pi^2 / 6) * beta^2

    Returns (mu, beta).
    """
    if len(samples) < 2:
        raise ValueError("need at least 2 samples")
    m = sum(samples) / len(samples)
    v = sum((s - m) ** 2 for s in samples) / (len(samples) - 1)
    if v <= 0:
        return (m, 1e-9)
    beta = math.sqrt(6.0 * v) / math.pi
    mu = m - beta * _EULER_GAMMA
    return (mu, beta)


def gumbel_quantile(mu: float, beta: float, p: float) -> float:
    """Inverse CDF of Gumbel max: F^-1(p) = mu - beta*ln(-ln(p))."""
    if not (0.0 < p < 1.0):
        raise ValueError(f"p out of range: {p}")
    return mu - beta * math.log(-math.log(p))


# ── Calibration ───────────────────────────────────────────────────────────


def _hash_search_fn(search_fn: Callable) -> str:
    try:
        src = inspect.getsource(search_fn)
    except (OSError, TypeError):
        src = repr(search_fn)
    return hashlib.sha256(src.encode("utf-8")).hexdigest()[:16]


def calibrate_threshold(
    ct: str,
    search_fn: Callable[[str, NgramScorer, random.Random], JointScore],
    quadgram: Optional[NgramScorer] = None,
    n_surrogates: int = 10_000,
    alpha: float = 0.01,
    seed: int = 0xBEEF,
    prereg_dir: str | os.PathLike = "results",
    write_prereg: bool = True,
) -> Tuple[float, float, float]:
    """Calibrate the joint detector threshold via shuffled-CT Gumbel fit.

    `search_fn(ct_surrogate, quadgram, rng) -> JointScore` is the REAL
    search pipeline.  See module docstring for the parity warning.

    Returns
    -------
    (mu, beta, tau) : tuple[float, float, float]
        Gumbel parameters and the alpha-level threshold.

    Side effects
    ------------
    Writes a pre-registration JSON artifact to
    `<prereg_dir>/efrac54_prereg_<utc-iso>.json` containing all
    parameters needed for an audit trail.

    NOTE: This function NEVER scores `ct` directly — only its shuffled
    surrogates.  This enforces the "don't peek at the answer key"
    discipline in code, not just in docstring.
    """
    if quadgram is None:
        quadgram = _scorer_to_nats(get_default_scorer())

    rng = random.Random(seed)
    t_max_samples: List[float] = []
    pairs: List[Tuple[float, float]] = []
    for k in range(n_surrogates):
        sub_seed = rng.randrange(0, 2**63)
        sub_rng = random.Random(sub_seed)
        surrogate = generate_shuffled_surrogate(ct, sub_rng)
        score = search_fn(surrogate, quadgram, sub_rng)
        t_max_samples.append(score.t)
        pairs.append((score.l_pt, score.l_k))

    mu, beta = fit_gumbel_mom(t_max_samples)
    tau = gumbel_quantile(mu, beta, 1.0 - alpha)

    # Covariance audit
    n = len(pairs)
    if n >= 2:
        m_pt = sum(p[0] for p in pairs) / n
        m_k = sum(p[1] for p in pairs) / n
        var_pt = sum((p[0] - m_pt) ** 2 for p in pairs) / (n - 1)
        var_k = sum((p[1] - m_k) ** 2 for p in pairs) / (n - 1)
        cov_pk = sum((p[0] - m_pt) * (p[1] - m_k) for p in pairs) / (n - 1)
        if var_pt > 0 and var_k > 0:
            corr = cov_pk / math.sqrt(var_pt * var_k)
        else:
            corr = 0.0
    else:
        corr = 0.0

    artifact = {
        "schema": "efrac54_prereg_v1",
        "mu": mu,
        "beta": beta,
        "tau": tau,
        "alpha": alpha,
        "n_surrogates": n_surrogates,
        "seed": seed,
        "search_fn_hash": _hash_search_fn(search_fn),
        "covariance_corr_pt_k": corr,
        "covariance_fallback_active": corr > 0.7,
        "ct_len": len(ct),
        "ct_sha256": hashlib.sha256(ct.encode("utf-8")).hexdigest()[:16],
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if write_prereg:
        prereg_dir = Path(prereg_dir)
        prereg_dir.mkdir(parents=True, exist_ok=True)
        out_path = prereg_dir / f"efrac54_prereg_{int(time.time())}.json"
        with open(out_path, "w") as f:
            json.dump(artifact, f, indent=2)

    return (mu, beta, tau)


# ── Verdict ───────────────────────────────────────────────────────────────


def verdict(t_observed: float, mu: float, beta: float, alpha: float = 0.01) -> str:
    """Return a verdict string per the spec decision rule.

        T < tau              -> "noise"
        tau <= T < tau+0.5*b -> "weak_signal"
        T >= tau + 0.5*b     -> "strong_signal"
        T >= mu + 5*beta     -> "breakthrough"
    """
    tau = gumbel_quantile(mu, beta, 1.0 - alpha)
    if t_observed >= mu + 5 * beta:
        return "breakthrough"
    if t_observed >= tau + 0.5 * beta:
        return "strong_signal"
    if t_observed >= tau:
        return "weak_signal"
    return "noise"
