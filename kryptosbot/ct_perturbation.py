"""CT-parametric Hamming-1 perturbation harness for Kryptos K4.

Stage A of the CT perturbation campaign — see
``docs/campaigns/ct_perturbation_stage_a_prereg.md``.

Design contract:
    - Every CT-dependent computation in this module accepts a CT string
      as an explicit argument. Nothing in this module reads
      ``kryptos.kernel.constants.CT`` or sets ``KRYPTOS_CT_OVERRIDE``.
      No global mutation.
    - Bean equality / inequality / linear constraint sets are RE-DERIVED
      from the perturbed CT against the canonical crib dictionary on
      every variant. The kernel's frozen ``BEAN_EQ`` / ``BEAN_INEQ`` /
      ``BEAN_LINEAR`` are reference values for the canonical (Hamming-0)
      CT only and are used solely for the identity-reproduction check.
    - Crib scoring and ngram scoring inspect plaintext only; they are
      CT-independent and are reused unchanged from the kernel.
    - Running-key, autokey, non-English source text, and CorpusLicense
      paths are out of scope. This module imports nothing from those
      branches and exposes no parameters that select them.
"""
from __future__ import annotations

import hashlib
import heapq
import json
import logging
import math
from dataclasses import dataclass, field
from typing import (
    Any, Callable, Dict, FrozenSet, Iterable, Iterator, List, Optional,
    Sequence, Tuple,
)

from kryptos.kernel.alphabet import AZ, KA, Alphabet
from kryptos.kernel.constants import (
    ALPH,
    BEAN_EQ as CANONICAL_BEAN_EQ,
    BEAN_INEQ as CANONICAL_BEAN_INEQ,
    BEAN_LINEAR as CANONICAL_BEAN_LINEAR,
    CRIB_DICT as CANONICAL_CRIB_DICT,
    CT as CANONICAL_CT,
    CT_LEN,
    MOD,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant,
    KEY_RECOVERY,
    decrypt_text,
)

logger = logging.getLogger("kryptosbot.ct_perturbation")

# ── Module-level constants ───────────────────────────────────────────────

#: Standard A-Z alphabet for variant generation.
DEFAULT_VARIANT_ALPHABET: str = ALPH

#: Cipher families this Stage-A campaign tests. Running-key, autokey,
#: Quagmire-III, and stateful families are deliberately out of scope.
SUPPORTED_FAMILIES: Tuple[CipherVariant, ...] = (
    CipherVariant.VIGENERE,
    CipherVariant.BEAUFORT,
    CipherVariant.VAR_BEAUFORT,
)

#: Alphabet kinds. KA = KRYPTOS-keyed (the K1-K3 alphabet).
SUPPORTED_ALPHABET_KINDS: Tuple[str, ...] = ("AZ", "KA")

CAMPAIGN_ID = "ct_perturbation_stage_a"
ARTIFACT_SCHEMA_VERSION = 2
H1_VARIANT_COUNT = CT_LEN * (len(ALPH) - 1)
H0_VARIANT_COUNT = 1
CRIB_POSITION_H1_VARIANTS = len(CANONICAL_CRIB_DICT) * (len(ALPH) - 1)
NONCRIB_POSITION_H1_VARIANTS = (CT_LEN - len(CANONICAL_CRIB_DICT)) * (len(ALPH) - 1)


def _alphabet_by_kind(kind: str) -> Alphabet:
    if kind == "AZ":
        return AZ
    if kind == "KA":
        return KA
    raise ValueError(f"unknown alphabet kind {kind!r}; expected one of {SUPPORTED_ALPHABET_KINDS}")


def ct_position_class(pos: Optional[int], crib_dict: Optional[Dict[int, str]] = None) -> str:
    """Classify a CT variant position for Stage-A coverage accounting."""
    if pos is None:
        return "h0_baseline"
    cribs = CANONICAL_CRIB_DICT if crib_dict is None else crib_dict
    return "crib_position" if pos in cribs else "noncrib_position"


def ct_variant_position_class_counts(
    *,
    include_h0: bool,
    h1_variants: int = H1_VARIANT_COUNT,
    crib_dict: Optional[Dict[int, str]] = None,
    alphabet: str = DEFAULT_VARIANT_ALPHABET,
) -> Dict[str, int]:
    """Return exact H0/H1 position-class counts for deterministic H1 order.

    ``h1_variants`` is an H1-only count. For the full canonical universe
    the result is 600 crib-position substitutions and 1,825 non-crib
    substitutions, plus the optional H0 baseline.
    """
    cribs = CANONICAL_CRIB_DICT if crib_dict is None else crib_dict
    if h1_variants < 0 or h1_variants > CT_LEN * (len(alphabet) - 1):
        raise ValueError("h1_variants out of range")
    per_pos = len(alphabet) - 1
    crib = 0
    noncrib = 0
    remaining = h1_variants
    for pos in range(CT_LEN):
        take = min(per_pos, remaining)
        if take <= 0:
            break
        if pos in cribs:
            crib += take
        else:
            noncrib += take
        remaining -= take
    return {
        "h0_baseline": 1 if include_h0 else 0,
        "crib_position_h1_variants": crib,
        "noncrib_position_h1_variants": noncrib,
        "h1_variants": h1_variants,
        "total_ct_variants": h1_variants + (1 if include_h0 else 0),
    }


# ── CT variant data model ────────────────────────────────────────────────

@dataclass(frozen=True)
class CTVariant:
    """An immutable CT observation, possibly perturbed from the canonical
    carved K4 ciphertext.

    For ``distance == 0`` (canonical baseline) ``pos``, ``old_char``, and
    ``new_char`` are all None. For ``distance == 1`` they identify the
    single position substitution.
    """
    variant_id: str
    distance: int
    pos: Optional[int]
    old_char: Optional[str]
    new_char: Optional[str]
    ct: str
    ct_sha256: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "variant_id": self.variant_id,
            "distance": self.distance,
            "pos": self.pos,
            "old_char": self.old_char,
            "new_char": self.new_char,
            "ct": self.ct,
            "ct_sha256": self.ct_sha256,
        }


def _ct_sha256(ct: str) -> str:
    return hashlib.sha256(ct.encode("ascii")).hexdigest()


def _validate_ct(ct: str) -> None:
    if not isinstance(ct, str):
        raise TypeError(f"CT must be a str, got {type(ct).__name__}")
    if len(ct) != CT_LEN:
        raise ValueError(f"CT must be exactly {CT_LEN} chars, got {len(ct)}")
    if not ct.isupper() or not ct.isalpha():
        raise ValueError("CT must be uppercase A-Z only")


def canonical_variant(ct: str) -> CTVariant:
    """Build the Hamming-0 (canonical) baseline variant for ``ct``."""
    _validate_ct(ct)
    return CTVariant(
        variant_id="H0_canonical",
        distance=0,
        pos=None,
        old_char=None,
        new_char=None,
        ct=ct,
        ct_sha256=_ct_sha256(ct),
    )


def enumerate_hamming1_variants(
    ct: str,
    alphabet: str = DEFAULT_VARIANT_ALPHABET,
) -> Iterator[CTVariant]:
    """Yield every Hamming-1 perturbation of ``ct`` over ``alphabet``.

    Order is deterministic: position ascending, then replacement letter
    ascending in ``alphabet`` order, skipping the original character.

    For canonical 97-char K4 over the standard A-Z alphabet, this yields
    exactly 97 * 25 = 2425 variants.
    """
    _validate_ct(ct)
    if len(set(alphabet)) != len(alphabet):
        raise ValueError("variant alphabet must have no duplicates")
    if not all(c.isupper() and c.isalpha() for c in alphabet):
        raise ValueError("variant alphabet must be uppercase A-Z chars")

    for pos in range(len(ct)):
        old_char = ct[pos]
        for new_char in alphabet:
            if new_char == old_char:
                continue
            new_ct = ct[:pos] + new_char + ct[pos + 1:]
            variant_id = f"H1_p{pos:02d}_{old_char}->{new_char}"
            yield CTVariant(
                variant_id=variant_id,
                distance=1,
                pos=pos,
                old_char=old_char,
                new_char=new_char,
                ct=new_ct,
                ct_sha256=_ct_sha256(new_ct),
            )


# ── CT-parametric Bean derivation ────────────────────────────────────────

# Bean derivation now lives in the core kernel (single source of truth).
# Re-exported here so existing call sites keep their import path.
from kryptos.kernel.constraints.bean import derive_bean_constraints  # noqa: E402,F401


# ── Keystream recovery at crib positions (CT- and family-parametric) ────

def recover_keystream_at_cribs(
    ct: str,
    pt: str,
    family: CipherVariant,
    alphabet: Alphabet,
    crib_positions: Iterable[int],
) -> Dict[int, int]:
    """Recover the implied keystream value at each crib position.

    The recovery uses the supplied ``alphabet`` for both PT and CT index
    lookup — equivalent to the kernel's ``recover_key_at_positions``
    when ``pa == ca``. Returns a sparse dict ``{pos: key_index}``.
    """
    _validate_ct(ct)
    if len(pt) != CT_LEN:
        raise ValueError(f"pt must be exactly {CT_LEN} chars, got {len(pt)}")
    fn = KEY_RECOVERY[family]
    idx = alphabet.index_table
    out: Dict[int, int] = {}
    for pos in crib_positions:
        if pos < 0 or pos >= CT_LEN:
            raise ValueError(f"crib position {pos} out of range")
        c = idx[ord(ct[pos]) - 65]
        p = idx[ord(pt[pos]) - 65]
        out[pos] = fn(c, p)
    return out


def verify_bean_against_keystream(
    ks_at_cribs: Dict[int, int],
    eq: Sequence[Tuple[int, int]],
    ineq: Sequence[Tuple[int, int]],
    linear: Sequence[Tuple[int, int, int, int]],
) -> bool:
    """Pure verifier: returns True iff the sparse keystream satisfies all
    eq / ineq / linear constraints. Constraints whose positions are all
    present must hold; the keystream is assumed to cover at least the
    positions referenced by all supplied constraints (the caller passes
    constraint sets derived from the same crib position set).
    """
    for a, b in eq:
        if ks_at_cribs[a] != ks_at_cribs[b]:
            return False
    for a, b in ineq:
        if ks_at_cribs[a] == ks_at_cribs[b]:
            return False
    for a, b, c, d in linear:
        if (ks_at_cribs[a] - ks_at_cribs[b]
                - ks_at_cribs[c] + ks_at_cribs[d]) % MOD != 0:
            return False
    return True


# ── Decryption wrapper (CT explicit) ─────────────────────────────────────

def decrypt_with_keyword(
    ct: str,
    keyword: str,
    family: CipherVariant,
    alphabet_kind: str,
) -> str:
    """Decrypt ``ct`` under ``keyword`` using ``family`` arithmetic and
    ``alphabet_kind`` indexing. Period equals ``len(keyword)``.

    ``keyword`` is upper-cased and encoded through the chosen alphabet
    BEFORE being passed to the kernel — the kernel's ``decrypt_text``
    expects integer key indices in the alphabet's index space.
    """
    _validate_ct(ct)
    if not keyword or not keyword.isalpha():
        raise ValueError(f"keyword must be alphabetic, got {keyword!r}")
    kw = keyword.upper()
    alpha = _alphabet_by_kind(alphabet_kind)
    key = alpha.encode(kw)
    return decrypt_text(ct, key, variant=family, alphabet=alpha)


# ── Crib scoring (CT-independent — wraps kernel) ─────────────────────────

def crib_score_for_pt(
    pt: str,
    crib_dict: Optional[Dict[int, str]] = None,
) -> Tuple[int, int]:
    """Return ``(matched, total)`` against ``crib_dict`` (canonical when
    None). Pure plaintext function — CT-independent."""
    cribs = crib_dict if crib_dict is not None else CANONICAL_CRIB_DICT
    total = len(cribs)
    matched = sum(
        1 for pos, ch in cribs.items()
        if pos < len(pt) and pt[pos] == ch
    )
    return matched, total


# ── P-value helpers ──────────────────────────────────────────────────────

def crib_p_value_random(crib_score_value: int, crib_total: int) -> float:
    """Exact right-tail Binomial(crib_total, 1/26) p-value."""
    if crib_score_value <= 0:
        return 1.0
    if crib_score_value > crib_total:
        return 0.0
    p = 1.0 / 26.0
    q = 1.0 - p
    total = 0.0
    for k in range(crib_score_value, crib_total + 1):
        total += math.comb(crib_total, k) * (p ** k) * (q ** (crib_total - k))
    return max(0.0, min(1.0, total))


def fisher_combine(p_values: Sequence[float]) -> Optional[float]:
    """Conservative combined p-value via Fisher's method.

    Returns None if any input is None or non-positive (combination
    undefined). Uses the chi-square upper-tail with 2k degrees of
    freedom; the regularized upper-incomplete gamma is computed by
    series for k <= 10 (sufficient for two-input combinations here).
    """
    cleaned = []
    for p in p_values:
        if p is None or p <= 0.0:
            return None
        cleaned.append(min(1.0, p))
    k = len(cleaned)
    if k == 0:
        return None
    chi2 = -2.0 * sum(math.log(p) for p in cleaned)
    df = 2 * k
    # Regularized upper-incomplete gamma Q(a, x) via series-then-tail.
    # Stdlib has math.lgamma but no incomplete gamma. We use a small
    # stdlib-only implementation suitable for df in [2, ~20].
    a = df / 2.0
    x = chi2 / 2.0
    return _gamma_q(a, x)


def _gamma_q(a: float, x: float) -> float:
    """Regularized upper-incomplete gamma Q(a, x). a > 0, x >= 0."""
    if x < 0 or a <= 0:
        return float("nan")
    if x == 0:
        return 1.0
    # Use series for x < a + 1, otherwise continued fraction.
    if x < a + 1.0:
        # Lower-incomplete series: P(a, x) = exp(-x) * x^a / a *
        #     sum_{n=0..inf} x^n / (a+1)(a+2)...(a+n)
        term = 1.0 / a
        s = term
        for n in range(1, 200):
            term *= x / (a + n)
            s += term
            if abs(term) < abs(s) * 1e-15:
                break
        p = math.exp(-x + a * math.log(x) - math.lgamma(a)) * s
        return max(0.0, min(1.0, 1.0 - p))
    # Continued fraction for Q(a, x).
    b0 = x + 1.0 - a
    c = 1e300
    d = 1.0 / b0
    h = d
    for n in range(1, 200):
        an = -n * (n - a)
        b0 += 2.0
        d = an * d + b0
        if abs(d) < 1e-300:
            d = 1e-300
        c = b0 + an / c
        if abs(c) < 1e-300:
            c = 1e-300
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-15:
            break
    q = math.exp(-x + a * math.log(x) - math.lgamma(a)) * h
    return max(0.0, min(1.0, q))


def bonferroni_adjust(p_raw: Optional[float], universe_size: int) -> Optional[float]:
    """Bonferroni correction: min(1, p_raw * universe_size)."""
    if p_raw is None or universe_size <= 0:
        return None
    return min(1.0, max(0.0, p_raw) * universe_size)


# ── Candidate score ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class CandidateScore:
    """Composite score of one (CT variant, family, alphabet, keyword) cell.

    Frozen so workers can ship them across process boundaries safely.
    """
    crib_score: int
    crib_total: int
    bean_passed: bool
    bean_variant: Optional[str]
    ngram_score: Optional[float]
    crib_p_raw: Optional[float]
    ngram_p_raw: Optional[float]
    ngram_null_available: bool
    p_combined_raw: Optional[float]
    p_adjusted: Optional[float]
    alert_class: str
    rejection_reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "crib_score": self.crib_score,
            "crib_total": self.crib_total,
            "bean_passed": self.bean_passed,
            "bean_variant": self.bean_variant,
            "ngram_score": self.ngram_score,
            "crib_p_raw": self.crib_p_raw,
            "ngram_p_raw": self.ngram_p_raw,
            "ngram_null_available": self.ngram_null_available,
            "p_combined_raw": self.p_combined_raw,
            "p_adjusted": self.p_adjusted,
            "alert_class": self.alert_class,
            "rejection_reason": self.rejection_reason,
        }


# ── Alert policy ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AlertPolicy:
    """Preregistered alert thresholds. Hamming-1 enforces strict bars;
    Hamming-0 relaxes the perturbation requirement only."""
    h1_require_full_cribs: bool = True            # crib_score == crib_total
    h1_require_bean_pass: bool = True
    h1_require_ngram_floor: bool = True
    h1_ngram_floor: float = -3.5                  # per-char ngram log-prob;
                                                  # English prose ≈ -3.0 to -3.2,
                                                  # random ≈ -6.4 (Phase 6 §6.4).
                                                  # -3.5 is the calibration alert
                                                  # bar from kryptosbot/alerts.py.
    h1_p_adjusted_threshold: float = 0.01
    h1_min_crib_score_watchlist: int = 18
    h0_require_bean_pass: bool = True             # H0 must satisfy Bean too
    h0_p_adjusted_threshold: float = 0.05         # H0 universe is tiny; bar more
                                                  # permissive for the canonical
                                                  # baseline reproduction check.
    require_null_for_alert: bool = True           # If null cache missing,
                                                  # downgrade alert to watchlist.

    def to_dict(self) -> Dict[str, Any]:
        return {
            "h1_require_full_cribs": self.h1_require_full_cribs,
            "h1_require_bean_pass": self.h1_require_bean_pass,
            "h1_require_ngram_floor": self.h1_require_ngram_floor,
            "h1_ngram_floor": self.h1_ngram_floor,
            "h1_p_adjusted_threshold": self.h1_p_adjusted_threshold,
            "h1_min_crib_score_watchlist": self.h1_min_crib_score_watchlist,
            "h0_require_bean_pass": self.h0_require_bean_pass,
            "h0_p_adjusted_threshold": self.h0_p_adjusted_threshold,
            "require_null_for_alert": self.require_null_for_alert,
        }


def classify_alert(
    *,
    crib_score: int,
    crib_total: int,
    bean_passed: bool,
    ngram_score: Optional[float],
    p_adjusted: Optional[float],
    null_available: bool,
    distance: int,
    policy: AlertPolicy,
) -> Tuple[str, str]:
    """Classify a candidate as alert / watchlist / none.

    Returns ``(alert_class, rejection_reason)``. ``rejection_reason`` is
    a short human-readable string for diagnostics; empty when the cell
    actually fires an alert.
    """
    # Watchlist when nulls unavailable but candidate looks suspicious.
    if not null_available and policy.require_null_for_alert:
        if crib_score >= policy.h1_min_crib_score_watchlist:
            return "watchlist_null_unavailable", "p-value gate uncalibrated"
        return "none", "below watchlist threshold"

    if distance == 0:
        # Hamming-0 path. We're verifying canonical-CT eligibility.
        if policy.h0_require_bean_pass and not bean_passed:
            return "none", "h0: bean failed"
        if (p_adjusted is not None
                and p_adjusted > policy.h0_p_adjusted_threshold):
            if crib_score >= policy.h1_min_crib_score_watchlist:
                return "watchlist", "h0: p_adjusted above threshold"
            return "none", "h0: p_adjusted above threshold"
        if crib_score >= policy.h1_min_crib_score_watchlist:
            return "alert", ""
        return "none", "h0: below watchlist threshold"

    # Hamming-1 path. Strict bar.
    fail_reasons: List[str] = []
    if policy.h1_require_full_cribs and crib_score != crib_total:
        fail_reasons.append(f"crib {crib_score}/{crib_total} (need full)")
    if policy.h1_require_bean_pass and not bean_passed:
        fail_reasons.append("bean failed")
    if policy.h1_require_ngram_floor:
        if ngram_score is None or ngram_score < policy.h1_ngram_floor:
            fail_reasons.append(
                f"ngram {ngram_score} below floor {policy.h1_ngram_floor}"
            )
    if (p_adjusted is None
            or p_adjusted > policy.h1_p_adjusted_threshold):
        fail_reasons.append(
            f"p_adjusted {p_adjusted} above {policy.h1_p_adjusted_threshold}"
        )

    if not fail_reasons:
        return "alert", ""

    if crib_score >= policy.h1_min_crib_score_watchlist:
        return "watchlist", "; ".join(fail_reasons)

    return "none", "; ".join(fail_reasons)


# ── Top-level CT-parametric scorer ───────────────────────────────────────

@dataclass
class ScorerContext:
    """Reusable state for one CT variant. Re-derives Bean once per
    variant; downstream candidates reuse those constraints for free."""
    variant: CTVariant
    crib_dict: Dict[int, str]
    bean_eq: Tuple[Tuple[int, int], ...]
    bean_ineq: Tuple[Tuple[int, int], ...]
    bean_linear: Tuple[Tuple[int, int, int, int], ...]
    crib_positions: Tuple[int, ...]
    ngram_dist: Any  # Optional[NullDistribution] — typed loosely to
                    # avoid forcing the kryptosbot.null_baselines import
                    # at module load.
    alphabet_kind: str = "AZ"

    @classmethod
    def build(
        cls,
        variant: CTVariant,
        crib_dict: Optional[Dict[int, str]] = None,
        ngram_dist: Any = None,
        alphabet_kind: str = "AZ",
    ) -> "ScorerContext":
        cribs = dict(crib_dict) if crib_dict is not None else dict(CANONICAL_CRIB_DICT)
        alpha = _alphabet_by_kind(alphabet_kind)
        eq, ineq, linear = derive_bean_constraints(variant.ct, cribs, alphabet=alpha)
        return cls(
            variant=variant,
            crib_dict=cribs,
            bean_eq=eq,
            bean_ineq=ineq,
            bean_linear=linear,
            crib_positions=tuple(sorted(cribs.keys())),
            ngram_dist=ngram_dist,
            alphabet_kind=alphabet_kind,
        )


def score_candidate_ct_parametric(
    ctx: ScorerContext,
    *,
    keyword: str,
    family: CipherVariant,
    alphabet_kind: str,
    universe_size: int,
    policy: AlertPolicy,
    ngram_scorer: Any = None,
) -> Tuple[CandidateScore, str]:
    """Score one (variant, family, alphabet, keyword) cell. Returns
    ``(CandidateScore, plaintext)``.

    The plaintext is returned alongside so the caller can attach it to
    stored candidates without recomputing.
    """
    if ctx.alphabet_kind != alphabet_kind:
        raise ValueError(
            "ScorerContext alphabet_kind does not match candidate "
            f"alphabet_kind: {ctx.alphabet_kind!r} != {alphabet_kind!r}"
        )
    pt = decrypt_with_keyword(
        ctx.variant.ct, keyword=keyword, family=family,
        alphabet_kind=alphabet_kind,
    )

    # Crib (PT-only).
    crib_score, crib_total = crib_score_for_pt(pt, ctx.crib_dict)

    # Bean (CT-parametric — uses ctx's re-derived constraints).
    alpha = _alphabet_by_kind(alphabet_kind)
    ks_at_cribs = recover_keystream_at_cribs(
        ctx.variant.ct, pt, family=family, alphabet=alpha,
        crib_positions=ctx.crib_positions,
    )
    bean_passed = verify_bean_against_keystream(
        ks_at_cribs, ctx.bean_eq, ctx.bean_ineq, ctx.bean_linear,
    )

    # Ngram (PT-only).
    ngram_score: Optional[float] = None
    ngram_p_raw: Optional[float] = None
    if ngram_scorer is not None:
        try:
            ngram_score = float(ngram_scorer.score_per_char(pt))
        except (ValueError, TypeError, IndexError, KeyError, AttributeError):
            ngram_score = None
        if ctx.ngram_dist is not None and ngram_score is not None:
            try:
                ngram_p_raw = float(ctx.ngram_dist.p_value(ngram_score))
            except Exception:  # pragma: no cover — defensive
                ngram_p_raw = None

    # Crib p-value: exact Binomial right tail, no cache needed.
    crib_p_raw = crib_p_value_random(crib_score, crib_total)
    p_combined = fisher_combine([crib_p_raw, ngram_p_raw])

    # Multiplicity correction: Bonferroni over the full preregistered
    # universe. We use the most informative raw p we have.
    p_to_adjust = p_combined if p_combined is not None else crib_p_raw
    p_adjusted = bonferroni_adjust(p_to_adjust, universe_size)

    ngram_null_available = ctx.ngram_dist is not None
    null_available = crib_p_raw is not None and (
        ngram_null_available or ngram_score is None
    )

    alert_class, rejection_reason = classify_alert(
        crib_score=crib_score,
        crib_total=crib_total,
        bean_passed=bean_passed,
        ngram_score=ngram_score,
        p_adjusted=p_adjusted,
        null_available=null_available,
        distance=ctx.variant.distance,
        policy=policy,
    )

    score = CandidateScore(
        crib_score=crib_score,
        crib_total=crib_total,
        bean_passed=bean_passed,
        bean_variant=family.value,
        ngram_score=ngram_score,
        crib_p_raw=crib_p_raw,
        ngram_p_raw=ngram_p_raw,
        ngram_null_available=ngram_null_available,
        p_combined_raw=p_combined,
        p_adjusted=p_adjusted,
        alert_class=alert_class,
        rejection_reason=rejection_reason,
    )
    return score, pt


# ── Top-N heap for memory-bounded ranking ────────────────────────────────

@dataclass
class TopNHeap:
    """Min-heap of (key, payload) pairs retaining the N largest by key."""
    capacity: int
    _heap: List[Tuple[float, str, Dict[str, Any]]] = field(default_factory=list)

    def push(self, key: float, payload: Dict[str, Any]) -> None:
        # Use a stable config id to break ties; multiprocessing merge
        # order is not semantic and must not perturb top-N output.
        config_id = str(payload.get("config_id", ""))
        item = (float(key), config_id, payload)
        if len(self._heap) < self.capacity:
            heapq.heappush(self._heap, item)
        elif item[:2] > self._heap[0][:2]:
            heapq.heapreplace(self._heap, item)

    def sorted_payloads(self) -> List[Dict[str, Any]]:
        return [p for _, _, p in sorted(self._heap, reverse=True)]


# ── Universe arithmetic (for honest preregistration) ─────────────────────

@dataclass(frozen=True)
class UniverseDimensions:
    """Cardinality of the preregistered Stage-A universe.

    ``period`` is intentionally NOT a dimension here. The kernel's
    additive families use ``period == len(keyword)`` — there is no
    independent period parameter, so distinct periods within the
    keyword pool are reflected by the keyword count alone.
    """
    families: int
    alphabet_kinds: int
    keywords: int
    ct_variants: int

    @property
    def per_ct_variant(self) -> int:
        return self.families * self.alphabet_kinds * self.keywords

    @property
    def total(self) -> int:
        return self.per_ct_variant * self.ct_variants

    def to_dict(self) -> Dict[str, Any]:
        return {
            "families": self.families,
            "alphabet_kinds": self.alphabet_kinds,
            "keywords": self.keywords,
            "ct_variants": self.ct_variants,
            "config_cardinality_per_ct_variant": self.per_ct_variant,
            "total_config_cardinality": self.total,
            "period_policy": "period_equals_keyword_length",
            "period_note": (
                "Kernel additive families have no independent period "
                "parameter; period is implicit in keyword length. The "
                "set of distinct periods present is determined by the "
                "lengths of the keywords in the curated pool."
            ),
        }


# ── Identity-reproduction guard (sanity check) ───────────────────────────

def assert_canonical_bean_reproduction() -> None:
    """Raises AssertionError if the local Bean derivation does not
    reproduce the kernel's canonical (BEAN_EQ, BEAN_INEQ, BEAN_LINEAR)
    on canonical CT and canonical cribs.

    This is the safety contract the CT-parametric harness stands on:
    the local re-derivation is bit-identical to the kernel for the
    canonical case, so any divergence on a perturbed CT is the
    perturbation itself, not a derivation drift.
    """
    eq, ineq, linear = derive_bean_constraints(CANONICAL_CT, dict(CANONICAL_CRIB_DICT))
    assert tuple(eq) == tuple(CANONICAL_BEAN_EQ), (
        f"local BEAN_EQ derivation diverged from kernel "
        f"(local={eq}, kernel={CANONICAL_BEAN_EQ})"
    )
    assert tuple(ineq) == tuple(CANONICAL_BEAN_INEQ), (
        f"local BEAN_INEQ derivation diverged from kernel "
        f"(|local|={len(ineq)}, |kernel|={len(CANONICAL_BEAN_INEQ)})"
    )
    assert tuple(linear) == tuple(CANONICAL_BEAN_LINEAR), (
        f"local BEAN_LINEAR derivation diverged from kernel "
        f"(|local|={len(linear)}, |kernel|={len(CANONICAL_BEAN_LINEAR)})"
    )


# ── Stage B: archive-anchored Hamming-2 framework ────────────────────────
#
# See docs/campaigns/ct_perturbation_stage_b_prereg.md for the binding
# specification. Stage B is constrained to position-pair perturbations
# where BOTH positions live in an operator-supplied predeclared
# ambiguous-position set A. The "second position only in A" reading was
# rejected because of cardinality (2,425 × |A| × 25 ≈ 60,625|A|, too
# large to defend under the same alert bar as Stage A). See prereg §3.4.
#
# This module exposes the framework primitives only:
#   - the AmbiguousPositionsManifest schema validator
#   - the H2 enumerator parameterized by A
#   - cardinality computation
#
# The full campaign runner is deferred until the operator supplies an
# A via --ambiguous-positions PATH plus a decision-gate document.

CAMPAIGN_ID_STAGE_B = "ct_perturbation_stage_b"
AMBIGUOUS_POSITIONS_SCHEMA_VERSION = "ct_perturbation_stage_b.ambiguous_positions.v1"
STAGE_B_K_MAX_DEFAULT = 20


@dataclass(frozen=True)
class CTVariantH2:
    """A Hamming-2 CT variant — two-position substitution.

    Both ``pos1`` and ``pos2`` live in the operator-supplied
    ambiguous-position set, with ``pos1 < pos2``. The perturbations are
    applied independently to ``ct`` to produce ``new_ct``.
    """
    variant_id: str
    distance: int  # always 2
    pos1: int
    old1: str
    new1: str
    pos2: int
    old2: str
    new2: str
    ct: str
    ct_sha256: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "variant_id": self.variant_id,
            "distance": self.distance,
            "pos_pair": [self.pos1, self.pos2],
            "chars_pair": [self.old1, self.new1, self.old2, self.new2],
            "ct": self.ct,
            "ct_sha256": self.ct_sha256,
        }


@dataclass(frozen=True)
class AmbiguousPositionsManifest:
    """Operator-supplied predeclared ambiguous-position set for Stage B.

    Loaded from a JSON file by ``load_ambiguous_positions``; the loader
    enforces schema, range, uniqueness, and checksum invariants. The
    manifest is immutable once loaded and is copied verbatim into
    ``ambiguous_positions_manifest.json`` in the run artifact directory.
    """
    schema_version: str
    archive_provenance: Dict[str, Any]
    positions: FrozenSet[int]
    rationale_per_position: Dict[int, str]
    checksum_sha256: str

    @property
    def k(self) -> int:
        return len(self.positions)

    def position_pairs(self) -> Iterator[Tuple[int, int]]:
        """Yield (i, j) pairs with i < j over the manifest positions."""
        sorted_positions = sorted(self.positions)
        for i_idx in range(len(sorted_positions)):
            for j_idx in range(i_idx + 1, len(sorted_positions)):
                yield (sorted_positions[i_idx], sorted_positions[j_idx])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "archive_provenance": self.archive_provenance,
            "positions": sorted(self.positions),
            "rationale_per_position": {
                str(p): self.rationale_per_position[p]
                for p in sorted(self.positions)
            },
            "checksum": {"sha256_of_positions_sorted": self.checksum_sha256},
        }


def _sha256_of_positions(positions: Iterable[int]) -> str:
    """Canonical checksum for a position set: sha256 of sorted CSV."""
    payload = ",".join(str(p) for p in sorted(positions)).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def load_ambiguous_positions(
    path: str,
    *,
    k_max: int = STAGE_B_K_MAX_DEFAULT,
    allow_large: bool = False,
) -> AmbiguousPositionsManifest:
    """Load and validate a Stage B ambiguous-positions JSON file.

    Raises:
        FileNotFoundError: if ``path`` does not exist.
        ValueError: on any schema, range, uniqueness, checksum, or
            ``k > k_max`` violation. ``allow_large=True`` permits
            ``k > k_max`` but does not skip the other checks.
    """
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)

    if not isinstance(raw, dict):
        raise ValueError("manifest must be a JSON object")

    schema = raw.get("schema_version")
    if schema != AMBIGUOUS_POSITIONS_SCHEMA_VERSION:
        raise ValueError(
            f"schema_version must be {AMBIGUOUS_POSITIONS_SCHEMA_VERSION!r}; "
            f"got {schema!r}"
        )

    provenance = raw.get("archive_provenance")
    if not isinstance(provenance, dict) or not provenance:
        raise ValueError(
            "archive_provenance must be a non-empty object — Stage B "
            "requires explicit archive citation per prereg §3.2"
        )
    for required in ("primary_source", "evaluator", "evaluation_date", "method"):
        if not provenance.get(required):
            raise ValueError(
                f"archive_provenance.{required} must be set and non-empty"
            )

    positions_raw = raw.get("positions")
    if not isinstance(positions_raw, list) or not positions_raw:
        raise ValueError("positions must be a non-empty list of ints")
    positions: List[int] = []
    for p in positions_raw:
        if not isinstance(p, int) or isinstance(p, bool):
            raise ValueError(f"position {p!r} must be an int (0-indexed)")
        if p < 0 or p >= CT_LEN:
            raise ValueError(
                f"position {p} out of range [0, {CT_LEN}); positions are 0-indexed"
            )
        positions.append(p)
    if len(positions) != len(set(positions)):
        raise ValueError(f"positions must be unique; got duplicates in {positions}")

    k = len(positions)
    if k < 2:
        raise ValueError(
            f"Hamming-2 requires at least 2 ambiguous positions; got k={k}"
        )
    if k > k_max and not allow_large:
        raise ValueError(
            f"k={k} exceeds k_max={k_max}; pass allow_large=True with a "
            f"separate documented review to override (see prereg §3.3)"
        )

    rationale_raw = raw.get("rationale_per_position", {})
    if not isinstance(rationale_raw, dict):
        raise ValueError("rationale_per_position must be an object")
    rationale: Dict[int, str] = {}
    for key, value in rationale_raw.items():
        try:
            pos_int = int(key)
        except (TypeError, ValueError):
            raise ValueError(
                f"rationale_per_position keys must be int-convertible; got {key!r}"
            )
        if pos_int not in set(positions):
            raise ValueError(
                f"rationale_per_position has key {pos_int} not in positions"
            )
        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                f"rationale_per_position[{pos_int}] must be a non-empty string"
            )
        rationale[pos_int] = value
    missing = set(positions) - set(rationale.keys())
    if missing:
        raise ValueError(
            f"rationale_per_position missing entries for positions {sorted(missing)}"
        )

    checksum = raw.get("checksum", {}).get("sha256_of_positions_sorted")
    expected = _sha256_of_positions(positions)
    if checksum != expected:
        raise ValueError(
            f"checksum mismatch: file claims {checksum!r}, "
            f"computed {expected!r} from positions"
        )

    return AmbiguousPositionsManifest(
        schema_version=schema,
        archive_provenance=dict(provenance),
        positions=frozenset(positions),
        rationale_per_position=rationale,
        checksum_sha256=expected,
    )


def stage_b_universe_size(
    manifest: AmbiguousPositionsManifest,
    n_keywords: int,
    *,
    n_families: int = len(SUPPORTED_FAMILIES),
    n_alphabets: int = len(SUPPORTED_ALPHABET_KINDS),
    alphabet_size: int = MOD,
) -> Dict[str, int]:
    """Compute Stage B Hamming-2 universe cardinality from manifest size.

    Returns a dict with ``k``, ``position_pairs``, ``substitution_pairs``,
    ``h2_variants``, ``configs_per_variant``, and ``total_configs``.
    """
    k = manifest.k
    position_pairs = (k * (k - 1)) // 2
    substitution_pairs = (alphabet_size - 1) ** 2
    h2_variants = position_pairs * substitution_pairs
    configs_per_variant = n_families * n_alphabets * n_keywords
    return {
        "k": k,
        "position_pairs": position_pairs,
        "substitution_pairs": substitution_pairs,
        "h2_variants": h2_variants,
        "configs_per_variant": configs_per_variant,
        "total_configs": h2_variants * configs_per_variant,
    }


def enumerate_hamming2_variants_constrained(
    ct: str,
    manifest: AmbiguousPositionsManifest,
    alphabet: str = DEFAULT_VARIANT_ALPHABET,
) -> Iterator[CTVariantH2]:
    """Yield every Hamming-2 perturbation of ``ct`` with both positions
    in ``manifest.positions``.

    Order is deterministic: position pair ascending (i<j), then new1
    ascending, then new2 ascending, skipping replacements equal to the
    original character. For ``k = |manifest.positions|`` and the
    standard 26-letter alphabet, yields exactly ``C(k,2) * 25 * 25`` =
    ``625 * k(k-1)/2`` variants.
    """
    _validate_ct(ct)
    if len(set(alphabet)) != len(alphabet):
        raise ValueError("variant alphabet must have no duplicates")
    if not all(c.isupper() and c.isalpha() for c in alphabet):
        raise ValueError("variant alphabet must be uppercase A-Z chars")

    for pos1, pos2 in manifest.position_pairs():
        old1 = ct[pos1]
        old2 = ct[pos2]
        for new1 in alphabet:
            if new1 == old1:
                continue
            for new2 in alphabet:
                if new2 == old2:
                    continue
                # Apply both substitutions (pos1 < pos2 guaranteed).
                new_ct = (
                    ct[:pos1] + new1 + ct[pos1 + 1:pos2] + new2 + ct[pos2 + 1:]
                )
                variant_id = (
                    f"H2_p{pos1:02d}_{old1}->{new1}"
                    f"_p{pos2:02d}_{old2}->{new2}"
                )
                yield CTVariantH2(
                    variant_id=variant_id,
                    distance=2,
                    pos1=pos1,
                    old1=old1,
                    new1=new1,
                    pos2=pos2,
                    old2=old2,
                    new2=new2,
                    ct=new_ct,
                    ct_sha256=_ct_sha256(new_ct),
                )


__all__ = [
    "AlertPolicy",
    "AMBIGUOUS_POSITIONS_SCHEMA_VERSION",
    "ARTIFACT_SCHEMA_VERSION",
    "AmbiguousPositionsManifest",
    "CAMPAIGN_ID",
    "CAMPAIGN_ID_STAGE_B",
    "CTVariant",
    "CTVariantH2",
    "CandidateScore",
    "CRIB_POSITION_H1_VARIANTS",
    "H0_VARIANT_COUNT",
    "H1_VARIANT_COUNT",
    "NONCRIB_POSITION_H1_VARIANTS",
    "STAGE_B_K_MAX_DEFAULT",
    "ScorerContext",
    "SUPPORTED_ALPHABET_KINDS",
    "SUPPORTED_FAMILIES",
    "TopNHeap",
    "UniverseDimensions",
    "assert_canonical_bean_reproduction",
    "bonferroni_adjust",
    "canonical_variant",
    "classify_alert",
    "crib_p_value_random",
    "crib_score_for_pt",
    "ct_position_class",
    "ct_variant_position_class_counts",
    "decrypt_with_keyword",
    "derive_bean_constraints",
    "enumerate_hamming1_variants",
    "enumerate_hamming2_variants_constrained",
    "fisher_combine",
    "load_ambiguous_positions",
    "recover_keystream_at_cribs",
    "score_candidate_ct_parametric",
    "stage_b_universe_size",
    "verify_bean_against_keystream",
]
