"""Curated namespace bridge between cipher-discovery KB strings and ledger family ids.

Stdlib only. No I/O. No side effects.

Every value in KB_TO_LEDGER_FAMILY MUST be in
``valid_ledger_family_universe()`` (KNOWN_FAMILIES.family_id ∪
historical ledger.theories.family). Task 3's test enforces this.

Every value in KB_TO_DSL_KIND MUST be in
``kryptosbot.job_dispatcher._SUPPORTED_KINDS``. Task 5's test enforces this.

Unmapped KB ``cipher_family`` strings produce ``None`` from
``map_kb_family_to_ledger_families()`` — the calling code routes these
to ``verdict="defer_needs_mapping"`` rather than silently allowing them
through.

See docs/specs/2026-05-16-yield-feedback-phase2-design.md §4.1.
"""
from __future__ import annotations

import re
from typing import Mapping, Optional


# Lowercase, whitespace-collapsed KB cipher_family strings → ledger family ids.
# Values must each be in the bootstrapped family universe.
KB_TO_LEDGER_FAMILY: Mapping[str, frozenset[str]] = {
    "columnar":               frozenset({"columnar_single", "double_columnar", "route_cipher"}),
    "polybius transposition": frozenset({"fractionation", "multi_layer"}),
    "positional":             frozenset({"route_cipher", "geometry", "procedural"}),
    "steganographic":         frozenset({"stego_layer", "physical_overlay", "procedural"}),
    "running key":            frozenset({"running_key", "key_tape"}),
    "substitution":           frozenset({"vigenere", "beaufort", "variant_beaufort", "novel"}),
    "polyalphabetic":         frozenset({"vigenere", "beaufort", "variant_beaufort", "polyalphabetic"}),
    "fractionation":          frozenset({"fractionation", "multi_layer"}),
    "route transposition":    frozenset({"route_cipher", "transposition"}),
    "monoalphabetic":         frozenset({"caesar", "atbash", "affine", "novel"}),
    "delastelle":             frozenset({"four_square", "multi_layer"}),
    "playfair family":        frozenset({"four_square", "multi_layer"}),
}


# Lowercase, whitespace-collapsed KB cipher_family strings → dispatcher kind.
# Values must each be in job_dispatcher._SUPPORTED_KINDS.
KB_TO_DSL_KIND: Mapping[str, str] = {
    "columnar":               "columnar",
    "polybius transposition": "polybius",
    "route":                  "route",
    "route transposition":    "route",
    "myszkowski":             "myszkowski",
    "rail fence":             "rail_fence",
    "quagmire":               "quagmire",
    "grille":                 "grille",
    "procedural":             "procedural",
}


_WHITESPACE_RE = re.compile(r"\s+")


def normalize_kb_family(name: Optional[str]) -> str:
    """Lowercase, collapse internal whitespace, strip edges.

    None and pathological inputs collapse to "". Calling code treats ""
    as "no KB family declared" which maps to None (defer_needs_mapping).
    """
    if not name or not isinstance(name, str):
        return ""
    s = _WHITESPACE_RE.sub(" ", name).strip().lower()
    return s


def map_kb_family_to_ledger_families(kb_family: Optional[str]) -> Optional[frozenset[str]]:
    """Return mapped ledger families for a KB cipher_family string.

    Returns None when the KB family is empty, missing, or unmapped.
    Callers route None to verdict="defer_needs_mapping" — they do NOT
    silently allow.
    """
    key = normalize_kb_family(kb_family)
    if not key:
        return None
    return KB_TO_LEDGER_FAMILY.get(key)


# Historical ledger families that are NOT yet in KNOWN_FAMILIES but are
# legitimate empirical labels observed in production ledger snapshots.
# Adding here keeps the universe stable across ledger churn without
# forcing a KNOWN_FAMILIES entry for every transient ledger string.
# Audit by re-running:
#   SELECT DISTINCT family FROM theories WHERE family <> ''
# and reconciling. Spec §4.1 — Task 3 acceptance.
_HISTORICAL_LEDGER_FAMILIES: frozenset[str] = frozenset({
    "admissibility",
    "antipodes",
    "archive_evidence",
    "campaigns_final_checklist",
    "crib_analysis",
    "encoding",
    "fractionation",
    "geodetic",
    "geometry",
    "k2_coords",
    "k3_continuity",
    "mirror_ka",
    "overlay",
    "polyalphabetic",
    "transposition",
})


def valid_ledger_family_universe() -> frozenset[str]:
    """Union of KNOWN_FAMILIES.family_id and historical ledger families.

    Authoritative validity check for KB_TO_LEDGER_FAMILY values. Grows
    as new families are added to either source. Pure function; no I/O.
    """
    # Local import — registries imports kryptos kernel which is heavy.
    from kryptosbot.registries import KNOWN_FAMILIES
    registry_ids = frozenset(f["family_id"] for f in KNOWN_FAMILIES)
    return registry_ids | _HISTORICAL_LEDGER_FAMILIES
