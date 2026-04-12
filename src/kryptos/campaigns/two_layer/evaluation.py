"""Blind evaluation framework for two-layer compositions.

Every metric here is computed AFTER candidate construction. Generation
parameters and evaluation metrics are disjoint sets — a candidate can
never be selected by sweeping over an evaluation metric.
"""
from __future__ import annotations

import math
import random
from typing import Dict, List, Optional

from kryptos.campaigns.two_layer.families import (
    CompositionProfile,
    EvaluationResult,
    ProvenanceClass,
)
from kryptos.campaigns.two_layer.multiplicity import (
    compute_multiplicity_penalty,
    is_cherry_picked_width,
)
from kryptos.kernel.constants import ALPH_IDX, CRIB_DICT, CT_LEN, MOD
from kryptos.kernel.scoring.aggregate import score_candidate


WIDTH_SPECTRUM_WIDTHS = (7, 10, 14, 17, 19, 21, 23, 28)

# Stehle canonical window (reported delta-5 lag-4 signature)
_STEHLE_START = 55
_STEHLE_LEN = 5  # positions 55,59,63 (lag 4, delta 5, chain length 5 letters)


def _width_bigram_repeat_count(text: str, width: int) -> int:
    """Write `text` into rows of `width` and count repeated vertical bigrams
    (column[r], column[r+1]) across all columns."""
    if width < 2 or len(text) < 2 * width:
        return 0
    rows = [text[i:i + width] for i in range(0, len(text), width)]
    # We need pairs of rows; last row may be shorter.
    full_rows = [r for r in rows if len(r) == width]
    if len(full_rows) < 2:
        return 0
    from collections import Counter
    bigrams = Counter()
    for r in range(len(full_rows) - 1):
        for c in range(width):
            bigrams[(full_rows[r][c], full_rows[r + 1][c])] += 1
    return sum(v for v in bigrams.values() if v >= 2)


def _width21_zscore(
    text: str,
    repeat_count: int,
    n_trials: int = 200,
    seed: int = 20260411,
) -> float:
    rng = random.Random(seed ^ hash(text) & 0xFFFFFFFF)
    chars = list(text)
    samples: List[int] = []
    for _ in range(n_trials):
        rng.shuffle(chars)
        samples.append(_width_bigram_repeat_count("".join(chars), 21))
    if not samples:
        return 0.0
    mean = sum(samples) / len(samples)
    var = sum((s - mean) ** 2 for s in samples) / max(1, len(samples) - 1)
    sd = math.sqrt(var) or 1.0
    return (repeat_count - mean) / sd


def _stehle_delta5_count(text: str) -> int:
    """Count starting positions i where text[i], text[i+4], text[i+8], text[i+12], text[i+16]
    form an arithmetic chain with delta 5 (mod 26)."""
    count = 0
    nums = [ALPH_IDX[c] for c in text]
    for i in range(len(nums) - 16):
        base = nums[i]
        if all((nums[i + 4 * k] - base) % MOD == (5 * k) % MOD for k in range(1, 5)):
            count += 1
    return count


def _stehle_window_match(text: str) -> bool:
    """Canonical Stehle window at 55..71 w/ lag 4, delta 5."""
    if len(text) < 72:
        return False
    nums = [ALPH_IDX[c] for c in text]
    base = nums[_STEHLE_START]
    for k in range(1, 5):
        idx = _STEHLE_START + 4 * k
        if (nums[idx] - base) % MOD != (5 * k) % MOD:
            return False
    return True


def _weak_identity_preservation(text: str) -> float:
    """Mean (1 - normalized_distance) at the 24 crib positions."""
    if len(text) < CT_LEN:
        return 0.0
    total = 0.0
    n = 0
    for pos, expected in CRIB_DICT.items():
        if pos >= len(text):
            continue
        d = abs(ALPH_IDX[text[pos]] - ALPH_IDX[expected])
        d = min(d, MOD - d)
        total += 1.0 - (d / 13.0)
        n += 1
    return total / n if n else 0.0


def _english_likeness(breakdown) -> float:
    """Normalize ngram_per_char into [0,1]-ish. Fallback on 0 if unavailable."""
    if breakdown.ngram_per_char is None:
        return 0.0
    # Typical English ngram_per_char is around -2.0 to -3.0 (log10 base),
    # random ~ -4.5. Map [-5, -2] -> [0, 1].
    x = breakdown.ngram_per_char
    v = (x + 5.0) / 3.0
    return max(0.0, min(1.0, v))


# ── Pad / align candidate to full 97-char frame ────────────────────────

def pad_candidate_to_ct(candidate_fragment: str, profile: CompositionProfile) -> str:
    """Place a candidate fragment back into a 97-char frame when the outer
    layer reduced the stream length (masks, partial projections).

    For non-length-preserving outer layers we pad with '.' placeholders,
    but evaluation metrics that depend on position alignment (Bean, cribs)
    can only be trusted when len(candidate_fragment) == CT_LEN AND the
    outer layer did NOT break positional alignment.
    """
    if len(candidate_fragment) >= CT_LEN:
        return candidate_fragment[:CT_LEN]
    return candidate_fragment + "A" * (CT_LEN - len(candidate_fragment))


# ── Known-elimination ledger (local) ────────────────────────────────────

_LOCAL_ELIMINATED: set = set()


def mark_eliminated(outer_family_id: str, inner_family_id: str) -> None:
    _LOCAL_ELIMINATED.add((outer_family_id, inner_family_id))


def is_novel(outer_family_id: str, inner_family_id: str) -> bool:
    return (outer_family_id, inner_family_id) not in _LOCAL_ELIMINATED


# ── Main evaluation ─────────────────────────────────────────────────────

def evaluate_composition(
    profile: CompositionProfile,
    candidate_text: str,
    ngram_scorer=None,
) -> EvaluationResult:
    """Pure evaluation — no parameter selection, no side effects.

    `candidate_text` is the candidate plaintext after applying outer
    extraction and inner inverse. It may be shorter than CT_LEN if the
    outer layer dropped characters; the evaluator pads before position-
    dependent metrics and flags the scope limitation.
    """
    flags: List[str] = []

    # Pad to 97 for crib alignment if needed; note the scope implication.
    original_len = len(candidate_text)
    aligned = pad_candidate_to_ct(candidate_text, profile)
    if original_len != CT_LEN:
        flags.append(f"length_mismatch_{original_len}_padded_to_{CT_LEN}")

    # Crib compatibility — always H1_CONDITIONAL (requires direct alignment).
    sb = score_candidate(aligned, ngram_scorer=ngram_scorer)
    crib_sc = sb.crib_score

    # Bean compatibility: only valid when outer preserves positional alignment.
    bean_note = ""
    if profile.outer.breaks_direct_positional_alignment:
        bean_compat: Optional[bool] = None
        bean_note = "H1 disabled — outer layer rearranges carved CT positions"
    else:
        # We can only check Bean on the keystream, which requires the inner
        # configuration. For this campaign we use crib_compatibility as a
        # weak proxy and leave bean_compatibility structural: PASS iff at
        # least 24/24 cribs match (sufficient condition). Otherwise False.
        bean_compat = crib_sc >= 24
        bean_note = "structural proxy: passes iff full crib alignment"

    # Width spectrum on the full aligned text.
    width_spectrum: Dict[int, int] = {}
    for w in WIDTH_SPECTRUM_WIDTHS:
        width_spectrum[w] = _width_bigram_repeat_count(aligned, w)
    width21_count = width_spectrum.get(21, 0)
    width21_z = _width21_zscore(aligned, width21_count)

    # Cherry-picked width?
    cand_w = profile.outer.parameters.get("width")
    cherry = False
    if cand_w is not None:
        cherry = is_cherry_picked_width(width_spectrum, cand_w) and profile.outer.selection_pool_size > 1
    if cherry:
        flags.append("cherry_picked_width")
    if profile.outer.is_post_hoc_selected:
        flags.append("post_hoc_outer_selection")

    # Stehle metrics (advisory only, never a hard filter).
    stehle_count = _stehle_delta5_count(aligned)
    stehle_match = _stehle_window_match(aligned)

    preservation = _weak_identity_preservation(aligned)
    engl = _english_likeness(sb)

    novelty = is_novel(profile.outer.family_id, profile.inner.family_id)
    mult_pen = compute_multiplicity_penalty(profile)

    # STRICT joint success
    joint = (
        crib_sc >= 18
        and (bean_compat is True or bean_compat is None)
        and width21_z >= 3.0
        and not cherry
        and (stehle_count > 0 or stehle_match)
        and preservation >= 0.4
        and engl >= 0.3  # noise floor proxy
        and len(flags) == 0
    )

    # Provenance: H1_CONDITIONAL if we relied on anchored cribs/alignment
    prov = ProvenanceClass.H1_CONDITIONAL
    if not profile.outer.breaks_direct_positional_alignment and crib_sc == 0:
        prov = ProvenanceClass.STRUCTURAL

    return EvaluationResult(
        profile_id=profile.profile_id,
        candidate_text=aligned,
        crib_compatibility_score=crib_sc,
        bean_compatibility=bean_compat,
        bean_compatibility_scope_note=bean_note,
        width21_repeat_count=width21_count,
        width21_zscore=width21_z,
        width_spectrum=width_spectrum,
        cherry_picked_width=cherry,
        stehle_local_delta5_count=stehle_count,
        stehle_position_55_63_match=stehle_match,
        weak_identity_preservation=preservation,
        english_likeness=engl,
        novelty_against_known_eliminations=novelty,
        is_joint_anomaly_success=joint,
        multiplicity_penalty=mult_pen,
        provenance=prov,
        flags=flags,
    )


# ── Summary rendering ──────────────────────────────────────────────────

def render_summary(results_dict: dict, coverage=None) -> str:
    """Render a short text summary from a results dict.

    Accepts optional CoverageReport to emit mode-aware null language.
    MUST NOT use overclaim language unless joint_anomaly_successes is
    non-empty OR the coverage report warrants the stronger claim.
    """
    n = results_dict.get("total_profiles_tested", 0)
    successes = results_dict.get("joint_anomaly_successes", []) or []
    if successes:
        return (
            f"Tested {n} two-layer profiles. {len(successes)} candidate(s) met "
            f"the joint anomaly success criterion and are flagged for audit."
        )

    # Mode-aware null language.
    if coverage is None:
        return (
            f"Tested {n} two-layer profiles. Zero candidates met the joint "
            f"anomaly success criterion. The two-layer hypothesis has not "
            f"been falsified, but no constrained low-complexity instance "
            f"shows materially better tradeoffs than single-layer baselines."
        )

    mode = getattr(coverage, "sampling_mode", "exploratory_stride")
    if mode == "exploratory_stride":
        return (
            f"EXPLORATORY null over {n} stride-sampled profiles. "
            f"Coverage is approximate; this is not a definitive negative result."
        )
    if mode == "stratified_family_cover" and coverage.qualifies_as_family_cover_complete:
        n_fams = len(coverage.inner_family_class_coverage) or 1
        return (
            f"FAMILY-COVER null across {coverage.distinct_outer_instances} outer "
            f"instances x {n_fams} inner family classes ({n} evaluations). "
            f"Every eligible outer instance was tested against every inner family "
            f"class with no joint anomaly success."
        )
    if mode == "stratified_low_complexity_bias" and coverage.qualifies_as_low_complexity_emphasized:
        return (
            f"LOW-COMPLEXITY-EMPHASIZED null over {n} profiles "
            f"({coverage.low_complexity_eval_count} in the low-complexity band, "
            f"total complexity <= band threshold). The simplest end of the "
            f"constrained search space was probed deeply with no joint anomaly success."
        )
    if mode == "full_cartesian" and coverage.qualifies_as_full_cartesian_complete:
        return (
            f"FULL-CARTESIAN null over {n} profiles within the parameterized "
            f"two-layer search space. Every outer x inner pair the framework "
            f"expresses was scored under blind evaluation with no joint "
            f"anomaly success. SCOPE: applies only to the parameterized "
            f"outer/inner generators; not a proof that no two-layer mechanism "
            f"can solve K4."
        )
    return (
        f"PARTIAL null over {n} profiles in mode {mode}. Coverage shape did "
        f"not meet the strong-claim invariant; treat as exploratory."
    )
