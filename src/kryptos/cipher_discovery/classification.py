"""Classification and scoring for discovered cipher systems.

Implements the K4 relevance scoring rubric and cipher taxonomy.
[POLICY] All scores are heuristic estimates, not proofs.
"""
from __future__ import annotations

from .schema import (
    CipherRecord, CipherType, Taxonomy, K4RelevanceScore,
)


# =============================================================================
# K4 Relevance Scoring
# =============================================================================

def score_k4_relevance(record: CipherRecord) -> K4RelevanceScore:
    """Score a cipher's relevance to K4 using the defined rubric.

    Returns a K4RelevanceScore with per-factor scores (0-10) and weighted total.
    This is a heuristic classification, not a proof.
    """
    score = K4RelevanceScore()

    # --- manual_executability (weight 2.0) ---
    # Can one person do this with paper/pencil/simple aids?
    if record.cipher_type in (CipherType.SUBSTITUTION, CipherType.TRANSPOSITION):
        score.manual_executability = 9.0
    elif record.cipher_type == CipherType.MIXED:
        score.manual_executability = 8.0
    elif record.cipher_type in (CipherType.FRACTIONATION, CipherType.SPATIAL):
        score.manual_executability = 7.0
    elif record.cipher_type == CipherType.MECHANICAL:
        score.manual_executability = 4.0  # needs a device
    elif record.cipher_type == CipherType.SIGNALING:
        score.manual_executability = 6.0
    else:
        score.manual_executability = 5.0

    # Boost for explicit paper/pencil
    if any(t in record.manual_execution_type.lower()
           for t in ["paper", "pencil", "tabula", "grid", "table"]):
        score.manual_executability = min(10.0, score.manual_executability + 1.0)

    # --- artist_feasibility (weight 1.5) ---
    # Would a sculptor/artist learn and use this?
    if record.pedagogical_amateur:
        score.artist_feasibility = 8.0
    elif record.historically_attested:
        score.artist_feasibility = 7.0
    elif record.bespoke:
        score.artist_feasibility = 9.0  # bespoke = artist-designed
    else:
        score.artist_feasibility = 5.0

    if record.cipher_type == CipherType.SPATIAL:
        score.artist_feasibility = min(10.0, score.artist_feasibility + 2.0)

    # --- spatial_geometric (weight 1.5) ---
    spatial_keywords = [
        "grid", "spiral", "route", "path", "compass", "direction",
        "geometric", "spatial", "coordinate", "bearing", "azimuth",
        "dial", "wheel", "overlay", "stencil", "template", "mask",
        "clock", "sundial", "map",
    ]
    spatial_count = sum(
        1 for kw in spatial_keywords
        if kw in record.description.lower()
        or kw in record.operational_mechanics.lower()
        or kw in record.canonical_name.lower()
    )
    score.spatial_geometric = min(10.0, spatial_count * 2.0)

    if record.cipher_type == CipherType.SPATIAL:
        score.spatial_geometric = max(score.spatial_geometric, 8.0)

    # --- compass_bearing_relation (weight 2.0) ---
    compass_keywords = [
        "compass", "bearing", "north", "south", "east", "west",
        "cardinal", "azimuth", "heading", "direction", "navigation",
        "clock", "position",
    ]
    compass_count = sum(
        1 for kw in compass_keywords
        if kw in record.description.lower()
        or kw in record.canonical_name.lower()
        or any(kw in alias.lower() for alias in record.alias_names)
    )
    score.compass_bearing_relation = min(10.0, compass_count * 2.5)

    # --- morse_signaling_relation (weight 1.5) ---
    morse_keywords = [
        "morse", "signal", "semaphore", "flag", "heliograph",
        "telegraph", "tap", "dot", "dash", "dit", "dah",
        "pollux", "morbit", "fractionation morse",
    ]
    morse_count = sum(
        1 for kw in morse_keywords
        if kw in record.description.lower()
        or kw in record.canonical_name.lower()
    )
    score.morse_signaling_relation = min(10.0, morse_count * 2.5)

    # --- bespoke_hybrid (weight 1.5) ---
    if record.bespoke:
        score.bespoke_hybrid = 9.0
    elif record.taxonomy == Taxonomy.ARTISTIC_BESPOKE:
        score.bespoke_hybrid = 8.0
    elif "hybrid" in record.description.lower() or "combined" in record.description.lower():
        score.bespoke_hybrid = 6.0
    elif record.cipher_type == CipherType.MIXED:
        score.bespoke_hybrid = 5.0
    else:
        score.bespoke_hybrid = 2.0

    # --- physical_aid_use (weight 1.0) ---
    aid_keywords = [
        "dial", "wheel", "stencil", "overlay", "grid", "grille",
        "mask", "template", "ruler", "protractor", "compass tool",
        "strip", "slide", "cylinder", "disk", "card",
    ]
    aid_count = sum(
        1 for kw in aid_keywords
        if kw in record.description.lower()
        or kw in record.operational_mechanics.lower()
        or any(kw in t.lower() for t in record.tools_required)
    )
    score.physical_aid_use = min(10.0, aid_count * 2.0)

    # --- short_text_plausibility (weight 1.0) ---
    # Does this cipher work on ~97 character texts?
    # Most classical ciphers work fine. Some need longer texts.
    score.short_text_plausibility = 7.0  # default: most work

    if record.cipher_type == CipherType.TRANSPOSITION:
        score.short_text_plausibility = 8.0  # transpositions work on any length
    if "running key" in record.canonical_name.lower():
        score.short_text_plausibility = 6.0  # needs key text >= CT length
    if "book" in record.canonical_name.lower():
        score.short_text_plausibility = 7.0

    # --- sanborn_theme_compatibility (weight 1.5) ---
    theme_keywords = [
        "cia", "espionage", "spy", "intelligence", "archaeology",
        "navigation", "concealment", "berlin", "cold war", "secret",
        "invisible", "hidden", "underground", "tunnel", "coordinates",
        "sculpture", "art", "petrification", "ancient", "egypt",
        "kryptos", "palimpsest", "vigenere", "beaufort",
    ]
    theme_count = sum(
        1 for kw in theme_keywords
        if kw in record.description.lower()
        or kw in record.claimed_origin.lower()
    )
    score.sanborn_theme_compatibility = min(10.0, theme_count * 2.0)

    # Boost for systems actually used by intelligence agencies
    if record.category in ("military", "espionage") or \
       any("military" in t.lower() or "intelligence" in t.lower()
           for t in [record.claimed_origin, record.description]):
        score.sanborn_theme_compatibility = max(
            score.sanborn_theme_compatibility, 6.0
        )

    return score


def classify_taxonomy(record: CipherRecord) -> Taxonomy:
    """Classify a cipher record into the taxonomy.

    [POLICY] Conservative classification. When in doubt, return NEEDS_REVIEW.
    """
    name_lower = record.canonical_name.lower()

    # Well-known systems
    well_known = {
        "caesar", "rot13", "atbash", "vigenere", "beaufort",
        "playfair", "hill", "enigma", "adfgvx", "adfgx",
        "bifid", "trifid", "four-square", "rail fence",
        "columnar transposition", "nihilist",
    }
    for wk in well_known:
        if wk in name_lower:
            return Taxonomy.CONFIRMED_NAMED

    if record.confidence_real_system >= 0.8 and record.historically_attested:
        return Taxonomy.CONFIRMED_NAMED

    if record.confidence_real_system >= 0.5:
        return Taxonomy.PROBABLE_POORLY_EVIDENCED

    if record.confidence_distinct_from_known < 0.3:
        return Taxonomy.ALIAS_OF_KNOWN

    if record.bespoke:
        return Taxonomy.ARTISTIC_BESPOKE

    if record.cipher_type == CipherType.SIGNALING:
        return Taxonomy.SIGNALING_REPURPOSABLE

    return Taxonomy.NEEDS_REVIEW


def compute_obscurity_score(record: CipherRecord) -> float:
    """Estimate how obscure a cipher system is.

    0.0 = universally known (Caesar, Vigenere)
    1.0 = extremely obscure, barely documented

    [POLICY] This is a heuristic. Higher obscurity = more interesting for K4.
    """
    well_known_terms = {
        "caesar", "vigenere", "beaufort", "playfair", "enigma",
        "atbash", "rot13", "one-time pad", "morse code",
        "rail fence", "columnar transposition", "aes", "des", "rsa",
    }
    moderately_known = {
        "adfgvx", "bifid", "trifid", "nihilist", "hill",
        "four-square", "book cipher", "null cipher", "gronsfeld",
        "pigpen", "scytale", "polybius",
    }
    somewhat_known = {
        "vic", "gromark", "porta", "chaocipher", "myszkowski",
        "double transposition", "straddling checkerboard",
        "turning grille", "fleissner", "wheatstone",
    }

    name_lower = record.canonical_name.lower()

    for term in well_known_terms:
        if term in name_lower:
            return 0.1

    for term in moderately_known:
        if term in name_lower:
            return 0.3

    for term in somewhat_known:
        if term in name_lower:
            return 0.5

    # Default: if we don't recognize it, it's somewhat obscure
    if record.historically_attested:
        return 0.6
    if record.bespoke:
        return 0.9
    return 0.7


def score_and_classify(record: CipherRecord) -> CipherRecord:
    """Apply all scoring and classification to a CipherRecord. Returns modified record."""
    # Taxonomy
    record.taxonomy = classify_taxonomy(record)

    # Obscurity
    record.obscurity_score = compute_obscurity_score(record)

    # K4 relevance
    k4_score = score_k4_relevance(record)
    record.k4_relevance_score = k4_score.compute_total()
    record.k4_score_breakdown = k4_score.to_dict()

    # Confidence estimates
    if record.taxonomy == Taxonomy.CONFIRMED_NAMED:
        record.confidence_real_system = max(record.confidence_real_system, 0.9)
    elif record.taxonomy == Taxonomy.PROBABLE_POORLY_EVIDENCED:
        record.confidence_real_system = max(record.confidence_real_system, 0.5)

    return record
