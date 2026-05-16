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
