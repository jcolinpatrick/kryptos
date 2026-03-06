"""Post-selection validator for benchmark candidates.

Computes plaintext plausibility from quadgram scores and wordlist hit
rate, then derives a confidence level.  When plausibility is low or the
margin between top candidates is small, the result is flagged
``validated=False`` and confidence is reduced.

All logic is deterministic and score-based — no LLM calls, no
randomness.

See ``docs/bench/VALIDATION.md`` for threshold rationale and tuning
knobs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Tunable thresholds ───────────────────────────────────────────────────

# Quadgram score per char — calibrated from get_default_scorer() baselines:
#   Strong English  ≈ -4.2  (WEAREDISCOVEREDSAVEYOURSELF)
#   Moderate English ≈ -5.0  (THEQUICKBROWNFOXJUMPS…)
#   Random           ≈ -6.4
QUADGRAM_HIGH: float = -4.8   # above this → strong English signal
QUADGRAM_LOW: float = -5.5    # below this → weak English signal
QUADGRAM_FLOOR: float = -6.5  # below this → almost certainly not English

# Wordlist hit rate (fraction of greedy-segmented characters covered)
WORDLIST_HIGH: float = 0.60   # above this → plausible English
WORDLIST_LOW: float = 0.35    # below this → implausible
WORDLIST_MIN_WORD: int = 3    # shortest word to count during segmentation

# Score margin between rank-1 and rank-2 candidates
MARGIN_SMALL: float = 1.0     # absolute score difference considered "small"

# Minimum plaintext length for reliable quadgram scoring
MIN_SCORABLE_LEN: int = 8     # texts shorter than this get reduced confidence

# ── Confidence levels ────────────────────────────────────────────────────

CONFIDENCE_HIGH: str = "high"
CONFIDENCE_MEDIUM: str = "medium"
CONFIDENCE_LOW: str = "low"
CONFIDENCE_NONE: str = "none"


# ── Wordlist loader (lazy singleton) ─────────────────────────────────────

_wordlist: Optional[set] = None
_WORDLIST_PATHS = [
    Path("wordlists/english.txt"),
    Path(__file__).resolve().parent.parent / "wordlists" / "english.txt",
]


def _load_wordlist() -> set:
    global _wordlist
    if _wordlist is not None:
        return _wordlist
    for p in _WORDLIST_PATHS:
        if p.exists():
            words = set()
            with open(p) as f:
                for line in f:
                    w = line.strip().upper()
                    if len(w) >= WORDLIST_MIN_WORD:
                        words.add(w)
            _wordlist = words
            return _wordlist
    _wordlist = set()
    return _wordlist


def _reset_wordlist() -> None:
    """Reset cached wordlist (for testing)."""
    global _wordlist
    _wordlist = None


# ── Quadgram scorer loader (lazy singleton) ──────────────────────────────

_qg_scorer = None


def _get_qg_scorer():
    global _qg_scorer
    if _qg_scorer is not None:
        return _qg_scorer
    try:
        from kryptos.kernel.scoring.ngram import get_default_scorer
        _qg_scorer = get_default_scorer()
    except (ImportError, FileNotFoundError):
        _qg_scorer = None
    return _qg_scorer


def _reset_qg_scorer() -> None:
    """Reset cached scorer (for testing)."""
    global _qg_scorer
    _qg_scorer = None


# ── Plausibility computation ─────────────────────────────────────────────

def quadgram_score(text: str) -> Optional[float]:
    """Return per-char quadgram log-probability, or None if unavailable."""
    scorer = _get_qg_scorer()
    if scorer is None:
        return None
    text = re.sub(r"[^A-Z]", "", text.upper())
    if len(text) < 4:
        return None
    return scorer.score_per_char(text)


def wordlist_hit_rate(text: str) -> float:
    """Greedy longest-match segmentation, return fraction of chars covered.

    Uses a simple left-to-right greedy approach: at each position, find
    the longest dictionary word starting there.  Characters not covered
    by any word are "misses".  Returns covered_chars / total_chars.

    This is intentionally a rough heuristic — it doesn't need to be a
    perfect segmenter, just a plausibility signal.
    """
    words = _load_wordlist()
    if not words:
        return 0.0
    text = re.sub(r"[^A-Z]", "", text.upper())
    if not text:
        return 0.0

    n = len(text)
    # Precompute max word length to bound inner loop
    max_wlen = min(max((len(w) for w in words), default=0), n)

    covered = [False] * n
    i = 0
    while i < n:
        best_len = 0
        for length in range(min(max_wlen, n - i), WORDLIST_MIN_WORD - 1, -1):
            candidate = text[i:i + length]
            if candidate in words:
                best_len = length
                break
        if best_len > 0:
            for j in range(i, i + best_len):
                covered[j] = True
            i += best_len
        else:
            i += 1

    return sum(covered) / n


@dataclass
class PlausibilityResult:
    """Plausibility assessment for a single plaintext candidate."""

    quadgram_per_char: Optional[float] = None
    wordlist_coverage: float = 0.0
    plausibility: float = 0.0       # 0.0–1.0 composite score
    confidence: str = CONFIDENCE_NONE
    validated: bool = False
    margin: Optional[float] = None  # score gap to runner-up (if computed)

    def to_dict(self) -> Dict:
        d: Dict = {
            "plausibility": round(self.plausibility, 4),
            "confidence": self.confidence,
            "validated": self.validated,
            "wordlist_coverage": round(self.wordlist_coverage, 4),
        }
        if self.quadgram_per_char is not None:
            d["quadgram_per_char"] = round(self.quadgram_per_char, 4)
        if self.margin is not None:
            d["margin"] = round(self.margin, 4)
        return d


def _compute_plausibility(qg: Optional[float], wl: float) -> float:
    """Combine quadgram and wordlist signals into a 0–1 score.

    Weighting: 60% quadgram (when available), 40% wordlist.
    Each component is normalized to 0–1 within its range.
    """
    # Normalize quadgram: FLOOR→0.0, HIGH→1.0, clamp
    if qg is not None:
        qg_norm = (qg - QUADGRAM_FLOOR) / (QUADGRAM_HIGH - QUADGRAM_FLOOR)
        qg_norm = max(0.0, min(1.0, qg_norm))
    else:
        qg_norm = None

    # Normalize wordlist: 0→0.0, HIGH→1.0, clamp
    wl_norm = min(wl / WORDLIST_HIGH, 1.0) if WORDLIST_HIGH > 0 else 0.0

    if qg_norm is not None:
        return 0.6 * qg_norm + 0.4 * wl_norm
    else:
        return wl_norm


def _derive_confidence(
    plausibility: float,
    qg: Optional[float],
    wl: float,
    text_len: int,
    margin: Optional[float],
) -> Tuple[str, bool]:
    """Derive confidence level and validated flag.

    Returns (confidence, validated).
    """
    # Very short texts → never high confidence
    if text_len < MIN_SCORABLE_LEN:
        if plausibility >= 0.7:
            return CONFIDENCE_MEDIUM, True
        return CONFIDENCE_LOW, False

    # Check hard-fail conditions
    if qg is not None and qg < QUADGRAM_FLOOR:
        return CONFIDENCE_NONE, False
    if qg is not None and qg < QUADGRAM_LOW and wl < WORDLIST_LOW:
        return CONFIDENCE_LOW, False

    # Small margin between top candidates → reduce confidence
    if margin is not None and margin < MARGIN_SMALL:
        if plausibility >= 0.7:
            return CONFIDENCE_MEDIUM, True
        return CONFIDENCE_LOW, False

    # Main confidence tiers
    if plausibility >= 0.7:
        return CONFIDENCE_HIGH, True
    if plausibility >= 0.4:
        return CONFIDENCE_MEDIUM, True
    if plausibility >= 0.2:
        return CONFIDENCE_LOW, False
    return CONFIDENCE_NONE, False


# ── Public API ───────────────────────────────────────────────────────────

def validate_candidate(
    text: str,
    *,
    runner_up_score: Optional[float] = None,
    best_score: Optional[float] = None,
) -> PlausibilityResult:
    """Validate a single plaintext candidate.

    Args:
        text: The candidate plaintext (A-Z).
        runner_up_score: Score of the second-best candidate (for margin).
        best_score: Score of the best candidate (for margin).

    Returns:
        PlausibilityResult with scores, confidence, and validated flag.
    """
    clean = re.sub(r"[^A-Z]", "", text.upper())

    qg = quadgram_score(clean)
    wl = wordlist_hit_rate(clean)
    plausibility = _compute_plausibility(qg, wl)

    margin = None
    if best_score is not None and runner_up_score is not None:
        margin = abs(best_score - runner_up_score)

    confidence, validated = _derive_confidence(
        plausibility, qg, wl, len(clean), margin,
    )

    return PlausibilityResult(
        quadgram_per_char=qg,
        wordlist_coverage=wl,
        plausibility=plausibility,
        confidence=confidence,
        validated=validated,
        margin=margin,
    )


def validate_result(
    result_dict: Dict,
) -> Dict:
    """Validate a benchmark result dict in-place, adding validation fields.

    Operates on the raw dict (as produced by ``_run_one`` in runner.py).
    Adds ``validation`` key with PlausibilityResult data.

    When ``validated=False``, confidence is forced low and the result is
    flagged.  When margin is small, returns top-K instead of just top-1.
    """
    predicted = result_dict.get("predicted_plaintext", "")
    if not predicted or result_dict.get("status") != "success":
        result_dict["validation"] = PlausibilityResult(
            confidence=CONFIDENCE_NONE, validated=False,
        ).to_dict()
        return result_dict

    # Compute margin from top candidates
    candidates = result_dict.get("top_candidates", [])
    best_score = None
    runner_up_score = None
    if len(candidates) >= 1:
        best_score = candidates[0].get("score") if isinstance(candidates[0], dict) else None
    if len(candidates) >= 2:
        runner_up_score = candidates[1].get("score") if isinstance(candidates[1], dict) else None

    vr = validate_candidate(
        predicted,
        runner_up_score=runner_up_score,
        best_score=best_score,
    )

    # If segmentation detected mixed structure, cap confidence
    seg = result_dict.get("segmentation", {})
    if seg.get("is_mixed", False):
        vr_dict = vr.to_dict()
        vr_dict["mixed_input"] = True
        if vr.confidence == CONFIDENCE_HIGH:
            vr_dict["confidence"] = CONFIDENCE_MEDIUM
        if not any(s.get("label") == "cipher" for s in seg.get("segments", [])):
            # No cipher segments at all → no validation possible
            vr_dict["confidence"] = CONFIDENCE_NONE
            vr_dict["validated"] = False
        result_dict["validation"] = vr_dict
    else:
        result_dict["validation"] = vr.to_dict()

    return result_dict
