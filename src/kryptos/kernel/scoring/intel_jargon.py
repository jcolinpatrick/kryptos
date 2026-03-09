"""Intelligence community jargon scoring for candidate plaintexts.

Scores candidate plaintext for intelligence community jargon, acronyms,
and abbreviations. Thematically relevant to Kryptos since it is a
sculpture at CIA headquarters about intelligence gathering.

Scoring:
  score_intel_jargon()   — scan text for IC terms, return (score, found_terms)
  score_intel_combined() — weighted combination of crib, jargon, and quadgram scores
"""
from __future__ import annotations

from typing import Dict, List, Tuple


# ── Term dictionaries by weight tier ─────────────────────────────────────

# HIGH weight (3 points): Agency acronyms and core espionage terms
# These are 4+ chars or very specific 3-char acronyms unlikely to appear by chance.
_HIGH_TERMS: List[str] = [
    # Agency acronyms (4+ chars or very distinctive)
    "GCHQ",
    # Core espionage terms (5+ chars — low false-positive risk)
    "DEADDROP", "ASSET", "AGENT", "DEFECT", "DEFECTOR", "CIPHER",
    "COVERT", "CLASSIFIED", "SECRET", "BURIED", "HIDDEN", "MARKER",
    "SIGNAL", "INTERCEPT",
]

# MEDIUM weight (2 points): INT disciplines, tradecraft, locations, Cold War
_MEDIUM_TERMS: List[str] = [
    # Intelligence disciplines (5+ chars)
    "SIGINT", "HUMINT", "COMINT", "ELINT", "MASINT", "OSINT", "IMINT",
    # Tradecraft (4+ chars)
    "OPSEC", "COMSEC", "INTEL", "RECON", "EXFIL", "INFIL",
    # Cold War terms
    "DDR", "STASI", "CHECKPOINT", "SECTOR", "CURTAIN",
    # Locations (5+ chars — won't match noise)
    "LANGLEY", "MOSCOW", "BERLIN", "KREMLIN", "ALEXANDERPLATZ",
    # Agency acronyms (3-char — slightly higher false-positive risk, but distinctive)
    "CIA", "KGB", "NSA", "FBI", "DCI", "NRO", "DIA", "SVR", "FSB",
    "GRU", "BND", "SIS",
    # Kryptos-specific terms
    "KRYPTOS", "SANBORN", "SCHEIDT", "PALIMPSEST", "ABSCISSA",
    "ANTIPODES", "LODESTONE", "COMPASS", "GRILLE", "TABLEAU",
    "HOROLOGE", "WELTZEITUHR",
]

# LOW weight (1 point): Contextual words — ONLY 4+ chars to avoid noise
# Removed short common words (THE, AND, NOT, FOR, FROM) that match random text.
_LOW_TERMS: List[str] = [
    "NEAR", "STOP", "KNOW", "DOES", "ONLY", "THIS", "WHAT",
    "WHERE", "FIVE", "CLOCK", "POINT", "PACES", "LOCATION",
    "EXACTLY", "BETWEEN", "NORTH", "SOUTH", "EAST", "WEST",
]

# REMOVED: _THEMATIC_TERMS merged into MEDIUM above for simplicity


# ── Build unified lookup ─────────────────────────────────────────────────

TERM_WEIGHTS: Dict[str, int] = {}
for _term in _HIGH_TERMS:
    TERM_WEIGHTS[_term] = 3
for _term in _MEDIUM_TERMS:
    TERM_WEIGHTS[_term] = 2
for _term in _LOW_TERMS:
    TERM_WEIGHTS[_term] = 1

# Precompute sorted by length descending for greedy longest-match
_TERMS_BY_LENGTH: List[Tuple[str, int]] = sorted(
    TERM_WEIGHTS.items(), key=lambda t: len(t[0]), reverse=True
)


def score_intel_jargon(text: str) -> Tuple[float, List[str]]:
    """Score candidate plaintext for intelligence community jargon.

    Scans the text for all known IC terms using greedy longest-match-first.
    Overlapping matches are resolved by taking the highest-scoring one.

    Args:
        text: Candidate plaintext (any case, only A-Z characters are matched).

    Returns:
        (total_score, list_of_found_terms) where total_score is the sum of
        weights for all matched terms, and found_terms lists each match as
        "TERM@pos" for traceability.
    """
    text = text.upper()
    n = len(text)
    if n == 0:
        return 0.0, []

    # Track which character positions have been claimed by a match.
    # Each entry: (weight, term, start_pos) or None if unclaimed.
    claimed: List[Tuple[int, str, int] | None] = [None] * n

    # Greedy scan: longest terms first, highest weight wins ties at same pos.
    for term, weight in _TERMS_BY_LENGTH:
        tlen = len(term)
        start = 0
        while start <= n - tlen:
            idx = text.find(term, start)
            if idx == -1:
                break

            # Check if this match overlaps with a higher-weight claim.
            # Find the max weight already claimed in this span.
            max_existing = 0
            for p in range(idx, idx + tlen):
                if claimed[p] is not None:
                    max_existing = max(max_existing, claimed[p][0])

            if weight > max_existing:
                # This term wins: clear any lower-weight claims in the span
                # and claim these positions.
                for p in range(idx, idx + tlen):
                    if claimed[p] is not None and claimed[p][0] < weight:
                        # Un-claim positions from the displaced term
                        old_w, old_term, old_start = claimed[p]
                        # Clear all positions of the displaced term
                        for q in range(old_start, old_start + len(old_term)):
                            if q < n and claimed[q] is not None and claimed[q][2] == old_start:
                                claimed[q] = None
                    claimed[p] = (weight, term, idx)

            start = idx + 1

    # Collect unique matches (deduplicate by start position)
    seen_starts: set[int] = set()
    found_terms: List[str] = []
    total_score = 0.0

    for p in range(n):
        if claimed[p] is not None:
            weight, term, start_pos = claimed[p]
            if start_pos not in seen_starts:
                seen_starts.add(start_pos)
                found_terms.append(f"{term}@{start_pos}")
                total_score += weight

    return total_score, found_terms


def score_intel_combined(
    text: str,
    crib_score: int,
    quadgram_per_char: float,
) -> float:
    """Combine crib score, intel jargon, and quadgram quality into one metric.

    Weighting rationale:
      - crib_score * 10  — dominant factor (cryptographic constraint satisfaction)
      - intel_jargon * 3 — thematic relevance bonus
      - quadgram * 5     — reduced vs normal (noisy for short texts / jargon)

    Args:
        text: Candidate plaintext.
        crib_score: Crib match score (0-24 typical range).
        quadgram_per_char: Average quadgram log-probability per character
                           (typically -4.0 to -2.5 for English-like text).

    Returns:
        Weighted combined score (higher is better).
    """
    jargon_score, _ = score_intel_jargon(text)
    return (crib_score * 10) + (jargon_score * 3) + (quadgram_per_char * 5)
