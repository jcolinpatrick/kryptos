"""Admissibility-first layer for K4 hypothesis filtering.

This package formalizes what it means for a hypothesis family to be
admissible BEFORE expensive search runs.  It distinguishes three layers:

    Layer 1 — Structural legitimacy:   Does this family deserve attention?
    Layer 2 — Exact admissibility:     Can it satisfy known constraints?
    Layer 3 — Enumerative search:      Only after Layers 1 and 2 pass.

The existing repo provides strong Layer 3 machinery.  This package adds
Layer 2 (solver-backed exact admissibility via CP-SAT) and Layer 1 (corpus
admissibility policy) while leaving Layer 3 untouched.

Design principles (see docs/admissibility_architecture.md):
    - Certificates, not heuristics: every elimination carries a structured
      reason and explicit assumption list.
    - Exact vs. empirical: `is_exact=True` means formal UNSAT; `False` means
      "search found nothing under a bounded budget" — these are never
      conflated.
    - No meta-framework: flat modules, plain dataclasses, opt-in imports.
"""
from __future__ import annotations

from kryptos.admissibility.certificate import (
    AdmissibilityCertificate,
    EliminationCertificate,
    EliminationReason,
    certificate_from_json,
    certificate_to_json,
)
from kryptos.admissibility.corpus_policy import (
    CORPUS_ALLOWLIST,
    CorpusJustification,
    CorpusLicense,
    CorpusPolicyError,
    check_corpus_source,
    get_license,
    load_allowlist_override,
    resolve_license_path,
)
from kryptos.admissibility.procedure_policy import (
    PROCEDURE_ALLOWLIST,
    ProcedureJustification,
    ProcedureLicense,
    ProcedurePolicyError,
    check_cipher_procedure,
    get_procedure_license,
    load_procedure_allowlist_override,
)
from kryptos.admissibility.periodic_admissibility import (
    check_periodic_additive,
    sweep_periodic_additive,
)

__all__ = [
    "AdmissibilityCertificate",
    "EliminationCertificate",
    "EliminationReason",
    "certificate_from_json",
    "certificate_to_json",
    "CORPUS_ALLOWLIST",
    "CorpusJustification",
    "CorpusLicense",
    "CorpusPolicyError",
    "check_corpus_source",
    "get_license",
    "load_allowlist_override",
    "resolve_license_path",
    "PROCEDURE_ALLOWLIST",
    "ProcedureJustification",
    "ProcedureLicense",
    "ProcedurePolicyError",
    "check_cipher_procedure",
    "get_procedure_license",
    "load_procedure_allowlist_override",
    "check_periodic_additive",
    "sweep_periodic_additive",
]
