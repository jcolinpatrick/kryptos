"""Constrained grammar-prior scoring for K4 anchor-centered phrases.

This module is a SOFT PRIOR. It does not decode, identify plaintext, or
promote candidates to crib status. It ranks short candidate phrases around
the known K4 anchors (EASTNORTHEAST, BERLINCLOCK) using hand-curated POS
inventories, phrase templates, and communique-register models.
"""
from .communique_models import (
    CommuniqueRegister, RegisterStyle, POS_TAGS,
    directive_register, status_report_register,
    telegraphic_register, hybrid_register,
    all_registers, register_by_style,
)
from .inventories import (
    WordEntry, all_entries, entries_by_length, entries_by_pos,
    entries_by_length_and_pos, entries_by_register, find_word,
)
from .templates import (
    Slot, PhraseTemplate, all_templates, templates_by_register,
    template_by_id,
)
from .grammar_prior import (
    ScoreBreakdown, CandidateFill, DEFAULT_WEIGHTS,
    score_candidate, rank_candidates,
    left_context_candidates, right_context_candidates,
    compare_anchor_phrases, score_sequence,
    KNOWN_ANCHORS, ANCHOR_CONTEXT_PRIORS,
)

__all__ = [
    "CommuniqueRegister", "RegisterStyle", "POS_TAGS",
    "directive_register", "status_report_register",
    "telegraphic_register", "hybrid_register",
    "all_registers", "register_by_style",
    "WordEntry", "all_entries", "entries_by_length", "entries_by_pos",
    "entries_by_length_and_pos", "entries_by_register", "find_word",
    "Slot", "PhraseTemplate", "all_templates", "templates_by_register",
    "template_by_id",
    "ScoreBreakdown", "CandidateFill", "DEFAULT_WEIGHTS",
    "score_candidate", "rank_candidates",
    "left_context_candidates", "right_context_candidates",
    "compare_anchor_phrases", "score_sequence",
    "KNOWN_ANCHORS", "ANCHOR_CONTEXT_PRIORS",
]
