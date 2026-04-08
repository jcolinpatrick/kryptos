"""Structured certificates for admissibility and elimination.

A certificate is the atomic unit of admissibility reasoning.  Every time
a hypothesis family is ruled in or out, the outcome is a certificate that
records:

    - What family / parameterisation was checked
    - Which assumptions were in force (A1 crib positions, A2 crib content,
      A3 additive key model, etc.)
    - Which solver or procedure was used
    - Whether the result is EXACT (formal UNSAT proof) or EMPIRICAL
      (bounded search turned up nothing)
    - A machine-readable reason code from a closed enum
    - Structured evidence suitable for audit

Certificates are JSON-roundtrippable and backward compatible with the
existing `Hypothesis.elimination_reason` string column: when a reader is
certificate-aware it parses JSON, otherwise it sees a one-line `summary`.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union


CERTIFICATE_SCHEMA_VERSION = "1.0"


class EliminationReason(str, Enum):
    """Closed taxonomy of elimination reasons.

    Any new reason code requires a test update — this is intentional:
    the set of distinct reasons is the contract of the admissibility
    layer.  Free-text explanation goes in `EliminationCertificate.summary`.
    """

    # --- Exact (solver-backed) proofs of infeasibility ---
    BEAN_UNSAT = "bean_unsat"
    """CP-SAT / Z3 proved that Bean equality + inequality constraints are
    unsatisfiable under this family's parameterisation."""

    CRIB_POSITION_CONTRADICTION = "crib_position_contradiction"
    """Two crib positions force incompatible key values under the family's
    key-derivation rule (e.g. same residue class in a periodic key)."""

    INSUFFICIENT_KEY_DOF = "insufficient_key_dof"
    """The family's parameter space has strictly fewer degrees of freedom
    than the minimum required to satisfy known constraints (pigeonhole)."""

    EMPTY_PARAMETER_SPACE = "empty_parameter_space"
    """The family's parameter domain is empty after constraint propagation."""

    TOPOLOGY_CONTRADICTION = "topology_contradiction"
    """The family's structural topology (grid shape, route, null mask)
    contradicts fixed-position requirements."""

    # --- Policy / structural rejections (not solver-derived) ---
    CORPUS_POLICY_VIOLATION = "corpus_policy_violation"
    """A running-key or text-derived hypothesis references a corpus source
    that is not on the public-provenance allowlist."""

    ASSUMPTION_UNMET = "assumption_unmet"
    """The hypothesis relies on a prerequisite that has not been established
    (e.g. needs mask inference but no model is specified)."""

    # --- Empirical (bounded-search) results ---
    NO_HITS_AT_FULL_ENUMERATION = "no_hits_full_enum"
    """Exhaustive enumeration of the family's finite parameter space
    produced no hits above the signal threshold.  This IS a proof for
    that finite space but only w.r.t. the scoring function used."""

    NO_HITS_UNDER_BUDGET = "no_hits_under_budget"
    """Bounded search (SA, sampling, truncated enumeration) produced no
    hits.  This is NOT a proof of infeasibility — only of empirical
    negative under the stated budget."""

    RUNTIME_EXHAUSTED = "runtime_exhausted"
    """The check timed out or hit a resource ceiling before reaching a
    verdict.  Recorded to prevent silent omission."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class EliminationCertificate:
    """A structured record that a hypothesis family has been ruled out.

    `is_exact=True` means the result is a formal proof of infeasibility
    given `assumptions`.  `is_exact=False` means it is empirical evidence
    (bounded search, no hits).

    `evidence` is an open dict — keep keys stable across runs of the same
    check so that downstream tools can aggregate.  Typical keys:

        - "variant": "beaufort" | "vigenere" | "var_beaufort"
        - "period": int
        - "conflict_positions": list of positions that collided
        - "solver_stats": {"wall_ms": float, ...}
        - "source_id": str               # for corpus policy
        - "license_required": bool       # for corpus policy
    """

    family: str
    reason: EliminationReason
    summary: str
    assumptions: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    solver: Optional[str] = None          # "cp_sat" | "z3" | "manual"
    is_exact: bool = False
    produced_at: str = field(default_factory=_now_iso)
    schema_version: str = CERTIFICATE_SCHEMA_VERSION

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["reason"] = self.reason.value
        d["kind"] = "elimination"
        return d


@dataclass(frozen=True)
class AdmissibilityCertificate:
    """A structured record that a hypothesis family CANNOT be trivially
    ruled out — i.e. it survives cheap checks and deserves search.

    This is deliberately weaker than 'feasible': it means 'the cheap
    checks did not produce a contradiction'.  It does NOT claim there
    exists a concrete parameter that will decrypt K4.
    """

    family: str
    summary: str
    assumptions: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    solver: Optional[str] = None
    produced_at: str = field(default_factory=_now_iso)
    schema_version: str = CERTIFICATE_SCHEMA_VERSION

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["kind"] = "admissibility"
        return d


Certificate = Union[EliminationCertificate, AdmissibilityCertificate]


def certificate_to_json(cert: Certificate) -> str:
    """Serialise a certificate to a compact JSON string suitable for
    storage in the existing `elimination_reason` TEXT column.
    """
    return json.dumps(cert.as_dict(), separators=(",", ":"), sort_keys=True)


def certificate_from_json(payload: str) -> Optional[Certificate]:
    """Parse a JSON certificate.  Returns None if `payload` is not a
    JSON-encoded certificate (e.g. a legacy free-text elimination reason).

    Backward compatibility: old `elimination_reason` values are plain
    strings; this function must never raise on them.
    """
    if not payload:
        return None
    try:
        data = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    kind = data.get("kind")
    if kind == "elimination":
        try:
            return EliminationCertificate(
                family=data["family"],
                reason=EliminationReason(data["reason"]),
                summary=data["summary"],
                assumptions=list(data.get("assumptions", [])),
                evidence=dict(data.get("evidence", {})),
                solver=data.get("solver"),
                is_exact=bool(data.get("is_exact", False)),
                produced_at=data.get("produced_at", ""),
                schema_version=data.get("schema_version", CERTIFICATE_SCHEMA_VERSION),
            )
        except (KeyError, ValueError):
            return None
    if kind == "admissibility":
        try:
            return AdmissibilityCertificate(
                family=data["family"],
                summary=data["summary"],
                assumptions=list(data.get("assumptions", [])),
                evidence=dict(data.get("evidence", {})),
                solver=data.get("solver"),
                produced_at=data.get("produced_at", ""),
                schema_version=data.get("schema_version", CERTIFICATE_SCHEMA_VERSION),
            )
        except (KeyError, ValueError):
            return None
    return None
