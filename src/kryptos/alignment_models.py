"""Canonical K4 crib-alignment model taxonomy (single source of truth).

The six alignment models describe what positional assumption a hypothesis
makes about how the carved ciphertext maps to plaintext. Consumed by the
session briefing (assumption-boundary audit) and the controller's frontier
map. Moved here from scripts/_infra/session_briefing.py so both surfaces
read one definition.
"""
from __future__ import annotations

ALIGNMENT_MODELS: tuple[tuple[str, str], ...] = (
    ("direct_ct_pt",
     "Direct CT[i] -> PT[i] crib mapping (each carved char decrypts in place)."),
    ("fixed_len_97",
     "Fixed CT_LEN=97 / fixed public crib positions 21-33, 63-73 (no nulls)."),
    ("ct73_null_extracted",
     "Specific null-extracted CT73-style models (a fixed 24-position extraction)."),
    ("arbitrary_null_mask",
     "Arbitrary null-mask / variable-PT-length models (mask positions unknown)."),
    ("non_direct_alignment",
     "Non-direct crib-alignment models (outer layer reorders CT before decrypt)."),
    ("joint_mask_mechanism",
     "Joint mask x mechanism inference (mask and cipher solved together)."),
)

ALIGNMENT_MODEL_KEYS: frozenset[str] = frozenset(k for k, _ in ALIGNMENT_MODELS)

# The two sub-assumptions that constitute the "direct carving" default that
# nearly all historical K4 work implicitly made.
DIRECT_CARVING_MODELS: frozenset[str] = frozenset({"direct_ct_pt", "fixed_len_97"})

# The under-explored frontier columns.
NON_DIRECT_MODELS: frozenset[str] = ALIGNMENT_MODEL_KEYS - DIRECT_CARVING_MODELS
