"""Hypothesis DSL — structured specification of a bounded cryptanalytic experiment.

Framework maturation Phase 4 (2026-04-21). Theorists emit JSON matching
``HypothesisSpec`` schema; the controller hands the spec to
``kryptosbot.job_dispatcher`` which admissibility-checks, enumerates,
dispatches to multiprocessing, and kernel-verifies every candidate above
the store threshold.

Before this DSL, worker agents wrote ad-hoc Python that re-implemented
cipher primitives in their scratch directory. The LLM's per-worker
throughput is orders of magnitude below the kernel's 28-core campaign
infrastructure, and the scratch code could silently drift from kernel
semantics. The DSL fixes both problems: LLM specifies, kernel computes.

Design principles (same posture as kryptosbot.contracts):
- Fail closed. Validation errors surface as ``ParseResult`` with explicit
  reasons, never silently-defaulted values.
- No free-text control flow. Every field is typed. Unknown cipher kinds
  are rejected; free-form prose lives in the optional ``notes`` field and
  is never parsed.
- No hidden state. A fully populated ``HypothesisSpec`` + the current
  kernel commit hash uniquely determines the work that will be executed.
  The ``spec_hash`` property on the spec is the deduplication key.

See ``docs/maturation/phase_04_report.md`` for worked examples.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Literal, Optional

from .contracts import ParseResult


# ─── Type aliases ────────────────────────────────────────────────────────────

# Cipher kinds the DSL understands. Must have a translation path in
# kryptosbot.job_dispatcher. New kinds require both a dispatcher
# translation AND an entry here; adding one without the other is a
# validation error.
CipherKind = Literal[
    "identity",             # pass-through; used for trivial end-to-end tests
    "vigenere",
    "beaufort",
    "variant_beaufort",
    "columnar",
    "rail_fence",
    "route",
    "myszkowski",
    "polybius",
    "quagmire",
    "atbash",
    "procedural",           # maps to a recipe_id in procedural_anomaly_recipes.md
]

_VALID_CIPHER_KINDS: frozenset[str] = frozenset(
    # Keep in lock-step with CipherKind Literal above. The Literal is for
    # static type-checkers; this frozenset is for runtime validation.
    [
        "identity",
        "vigenere", "beaufort", "variant_beaufort",
        "columnar", "rail_fence", "route", "myszkowski",
        "polybius", "quagmire", "atbash",
        "procedural",
    ]
)

AlphabetKind = Literal["AZ", "KA", "keyword_mixed"]
_VALID_ALPHABET_KINDS: frozenset[str] = frozenset(["AZ", "KA", "keyword_mixed"])

CribAlignment = Literal["direct_positional", "post_transposition", "free"]
_VALID_CRIB_ALIGNMENTS: frozenset[str] = frozenset(
    ["direct_positional", "post_transposition", "free"]
)

ScoringMode = Literal["crib_only", "crib_plus_bean", "ngram_vs_null", "composite"]
_VALID_SCORING_MODES: frozenset[str] = frozenset(
    ["crib_only", "crib_plus_bean", "ngram_vs_null", "composite"]
)

NullBaselineMethod = Literal[
    "random_text", "shuffled_ct", "matched_variant_family", "monte_carlo_cached",
]
_VALID_NULL_BASELINE_METHODS: frozenset[str] = frozenset(
    ["random_text", "shuffled_ct", "matched_variant_family", "monte_carlo_cached"]
)


# ─── Dataclasses ─────────────────────────────────────────────────────────────

@dataclass
class ParamRange:
    """Enumerable parameter range for one layer's parameter.

    Exactly one of two modes:
    - Explicit enumeration: set ``values`` (list). ``start`` and ``stop`` must be None.
    - Integer range [start, stop): set both. ``values`` must be empty.

    Hard cap on cardinality (default 10_000) prevents accidental denial-of-service
    specifications. The dispatcher multiplies cardinalities across layers and
    rejects any spec whose product exceeds ``compute_budget_cpu_minutes * per_minute_cap``.
    """
    name: str
    values: list[Any] = field(default_factory=list)
    start: Optional[int] = None
    stop: Optional[int] = None
    source_corpus: Optional[str] = None
    cardinality_cap: int = 10_000

    def cardinality(self) -> int:
        """Number of values this range enumerates. 0 if ill-defined."""
        if self.values:
            return len(self.values)
        if self.start is not None and self.stop is not None:
            return max(0, self.stop - self.start)
        return 0

    def enumerate(self) -> list[Any]:
        """Materialize the range as a list. Fails closed on ill-defined ranges."""
        if self.values and (self.start is not None or self.stop is not None):
            raise ValueError(
                f"ParamRange {self.name!r}: cannot set both values and start/stop"
            )
        if self.values:
            return list(self.values)
        if self.start is not None and self.stop is not None:
            return list(range(self.start, self.stop))
        raise ValueError(
            f"ParamRange {self.name!r}: must set either values or start+stop"
        )

    def validate(self) -> list[str]:
        """Return a list of validation errors (empty list = valid)."""
        errors: list[str] = []
        if not self.name or not isinstance(self.name, str):
            errors.append("ParamRange.name must be a non-empty string")
        has_enum = bool(self.values)
        has_range = self.start is not None and self.stop is not None
        if has_enum and has_range:
            errors.append(
                f"ParamRange {self.name!r}: cannot set both values and start/stop"
            )
        if not has_enum and not has_range:
            errors.append(
                f"ParamRange {self.name!r}: must set either values or start+stop"
            )
        if has_range:
            assert self.start is not None and self.stop is not None  # for type-checker
            if self.stop <= self.start:
                errors.append(
                    f"ParamRange {self.name!r}: stop ({self.stop}) "
                    f"must exceed start ({self.start})"
                )
        card = self.cardinality()
        if card > self.cardinality_cap:
            errors.append(
                f"ParamRange {self.name!r}: cardinality {card} "
                f"exceeds cardinality_cap {self.cardinality_cap}"
            )
        return errors

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ParamRange":
        allowed = {k for k in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in allowed})


@dataclass
class CipherLayer:
    """One layer of a composed cipher pipeline.

    Layers are applied in the order listed on ``HypothesisSpec.pipeline``.
    The pipeline runs in decrypt direction (CT → PT), so ``pipeline[0]``
    is the outermost / first-applied layer during decryption.
    """
    kind: str                                    # must be in _VALID_CIPHER_KINDS
    alphabet: str = "AZ"                         # must be in _VALID_ALPHABET_KINDS
    params: list[ParamRange] = field(default_factory=list)
    recipe_id: Optional[str] = None              # procedural only; e.g. "P-042"

    def cardinality(self) -> int:
        """Product of parameter cardinalities on this layer. 1 for a
        no-params layer (identity, atbash, pure-transposition with fixed
        width-set enumerated separately)."""
        total = 1
        for p in self.params:
            total *= max(1, p.cardinality())
        return total

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.kind not in _VALID_CIPHER_KINDS:
            errors.append(
                f"CipherLayer.kind {self.kind!r} is not a recognized CipherKind; "
                f"valid: {sorted(_VALID_CIPHER_KINDS)}"
            )
        if self.alphabet not in _VALID_ALPHABET_KINDS:
            errors.append(
                f"CipherLayer.alphabet {self.alphabet!r} is not recognized; "
                f"valid: {sorted(_VALID_ALPHABET_KINDS)}"
            )
        if self.kind == "procedural" and not self.recipe_id:
            errors.append(
                "CipherLayer.kind=='procedural' requires recipe_id (e.g. 'P-042')"
            )
        if self.kind != "procedural" and self.recipe_id:
            errors.append(
                f"CipherLayer.recipe_id={self.recipe_id!r} only valid when "
                f"kind=='procedural'; got kind={self.kind!r}"
            )
        seen_names = set()
        for p in self.params:
            if not isinstance(p, ParamRange):
                errors.append(f"CipherLayer.params entries must be ParamRange; got {type(p).__name__}")
                continue
            if p.name in seen_names:
                errors.append(f"CipherLayer.params has duplicate name {p.name!r}")
            seen_names.add(p.name)
            errors.extend(p.validate())
        return errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "alphabet": self.alphabet,
            "params": [p.to_dict() for p in self.params],
            "recipe_id": self.recipe_id,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CipherLayer":
        params_raw = d.get("params", []) or []
        return cls(
            kind=d.get("kind", ""),
            alphabet=d.get("alphabet", "AZ"),
            params=[ParamRange.from_dict(p) for p in params_raw],
            recipe_id=d.get("recipe_id"),
        )


@dataclass
class NullBaselineSpec:
    """How to build / look up the null distribution this job is compared against.

    Phase 4 emits this field on the spec for forward compatibility with
    Phase 6 (calibrated null baselines). The dispatcher accepts a spec
    with ``null_baseline=None`` and skips percentile reporting; when the
    Phase 6 infrastructure lands, the dispatcher starts honouring this
    field without DSL changes.
    """
    method: str = "random_text"                  # must be in _VALID_NULL_BASELINE_METHODS
    n_samples: int = 10_000
    cache_key: Optional[str] = None

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.method not in _VALID_NULL_BASELINE_METHODS:
            errors.append(
                f"NullBaselineSpec.method {self.method!r} not recognized; "
                f"valid: {sorted(_VALID_NULL_BASELINE_METHODS)}"
            )
        if self.n_samples <= 0:
            errors.append(
                f"NullBaselineSpec.n_samples must be positive; got {self.n_samples}"
            )
        return errors

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "NullBaselineSpec":
        allowed = {k for k in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in allowed})


@dataclass
class HypothesisSpec:
    """Complete specification of a computable hypothesis.

    The theorist produces this (optionally — Phase 4 does not require it);
    the dispatcher executes it; the kernel verifies every candidate
    above STORE_THRESHOLD.

    Fields:
        hypothesis_id:          Inherits from the TheoryRecord that spawned
                                this spec. Used for ledger linkage.
        pipeline:               Cipher layers applied left-to-right (outermost
                                first) during decryption.
        crib_alignment:         How to align plaintext against cribs.
        scoring:                Which canonical scoring path to use.
        null_baseline:          Optional Phase-6 null comparison config.
        information_gain_bits_estimate:
                                Theorist's a-priori guess at how much the
                                job eliminates. Dispatcher validates that
                                the guess is plausible (not strictly
                                enforced in Phase 4; just logged).
        success_criteria:       Dict describing what counts as a
                                "found something" outcome. Interpreted by
                                the dispatcher against JobResult.
        kill_criteria:          Dict describing what counts as a definitive
                                elimination. Used to populate
                                JobResult.eliminated_claim.
        compute_budget_cpu_minutes:
                                Hard ceiling. Dispatcher rejects specs
                                exceeding this × per-minute cap.
        checkpoint_every_sec:   Minimum checkpoint interval when dispatching.
        assumption_bundle:      List of assumption tags (e.g.
                                ["H1_direct_positional"]). Used for
                                exhaustion-log overlap checks.
        notes:                  Free-form narrative, never parsed.
    """
    hypothesis_id: str
    pipeline: list[CipherLayer] = field(default_factory=list)
    crib_alignment: str = "direct_positional"
    scoring: str = "composite"
    null_baseline: Optional[NullBaselineSpec] = None
    information_gain_bits_estimate: float = 0.0
    success_criteria: dict[str, Any] = field(default_factory=dict)
    kill_criteria: dict[str, Any] = field(default_factory=dict)
    compute_budget_cpu_minutes: int = 30
    checkpoint_every_sec: int = 60
    assumption_bundle: list[str] = field(default_factory=list)
    notes: str = ""
    # R2-3 (2026-04-21): exhaustion-overlap override.
    #
    # The dispatcher's admissibility check rejects specs whose assumption-
    # bundle + cipher family overlap a prior exhaustion-log entry. That
    # heuristic uses a substring match — Phase 8 observed it rejecting
    # one-third of legitimate procedural proposals where the
    # exhaustion-log coverage didn't actually subsume the new assumption
    # bundle.
    #
    # When override_exhaustion=True, the dispatcher demotes exhaustion
    # overlap from rejection to warning. The justification field is
    # mandatory: empty-string justification raises a validation error,
    # and the critic rejects theories whose justification duplicates
    # (Jaccard ≥ 0.7 on first 100 chars) an already-tested theory's
    # justification (see critic._check_override_duplicate).
    override_exhaustion: bool = False
    override_justification: str = ""

    def expected_cardinality(self) -> int:
        """Product of parameter cardinalities across all layers.

        Empty pipeline returns 1 (the single identity evaluation). An
        empty-params layer also contributes 1 (the layer itself is a
        single config). The dispatcher's admissibility check compares
        this against ``compute_budget_cpu_minutes * cap``.
        """
        total = 1
        for layer in self.pipeline:
            total *= max(1, layer.cardinality())
        return total

    @property
    def spec_hash(self) -> str:
        """Deterministic sha256-16 hash over the canonical serialization.

        Used as the universe_hash input for exhaustion-log matching and
        as the deduplication key for JobResult artifacts. Stable across
        equivalent specs regardless of field ordering in source JSON.
        """
        payload = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def validate(self) -> list[str]:
        """Return all validation errors; empty list means valid."""
        errors: list[str] = []
        if not self.hypothesis_id or not isinstance(self.hypothesis_id, str):
            errors.append("HypothesisSpec.hypothesis_id must be a non-empty string")
        if self.crib_alignment not in _VALID_CRIB_ALIGNMENTS:
            errors.append(
                f"HypothesisSpec.crib_alignment {self.crib_alignment!r} not recognized; "
                f"valid: {sorted(_VALID_CRIB_ALIGNMENTS)}"
            )
        if self.scoring not in _VALID_SCORING_MODES:
            errors.append(
                f"HypothesisSpec.scoring {self.scoring!r} not recognized; "
                f"valid: {sorted(_VALID_SCORING_MODES)}"
            )
        if self.compute_budget_cpu_minutes <= 0:
            errors.append(
                f"HypothesisSpec.compute_budget_cpu_minutes must be positive; "
                f"got {self.compute_budget_cpu_minutes}"
            )
        if self.checkpoint_every_sec <= 0:
            errors.append(
                f"HypothesisSpec.checkpoint_every_sec must be positive; "
                f"got {self.checkpoint_every_sec}"
            )
        if self.information_gain_bits_estimate < 0:
            errors.append(
                f"HypothesisSpec.information_gain_bits_estimate must be >= 0; "
                f"got {self.information_gain_bits_estimate}"
            )
        for i, layer in enumerate(self.pipeline):
            if not isinstance(layer, CipherLayer):
                errors.append(
                    f"HypothesisSpec.pipeline[{i}]: must be CipherLayer, "
                    f"got {type(layer).__name__}"
                )
                continue
            for err in layer.validate():
                errors.append(f"pipeline[{i}]: {err}")
        if self.null_baseline is not None:
            if not isinstance(self.null_baseline, NullBaselineSpec):
                errors.append(
                    f"HypothesisSpec.null_baseline: must be NullBaselineSpec or None, "
                    f"got {type(self.null_baseline).__name__}"
                )
            else:
                for err in self.null_baseline.validate():
                    errors.append(f"null_baseline: {err}")
        # R2-3: override_exhaustion requires a non-empty justification.
        # Allow justification without override (harmless — records
        # rationale); reject override without justification (the whole
        # point of the mechanism is to force a written reason).
        if self.override_exhaustion and not (self.override_justification or "").strip():
            errors.append(
                "HypothesisSpec.override_exhaustion=True requires a "
                "non-empty override_justification string (R2-3)"
            )
        return errors

    def is_valid(self) -> bool:
        return not self.validate()

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "hypothesis_id": self.hypothesis_id,
            "pipeline": [layer.to_dict() for layer in self.pipeline],
            "crib_alignment": self.crib_alignment,
            "scoring": self.scoring,
            "null_baseline": self.null_baseline.to_dict() if self.null_baseline else None,
            "information_gain_bits_estimate": self.information_gain_bits_estimate,
            "success_criteria": self.success_criteria,
            "kill_criteria": self.kill_criteria,
            "compute_budget_cpu_minutes": self.compute_budget_cpu_minutes,
            "checkpoint_every_sec": self.checkpoint_every_sec,
            "assumption_bundle": list(self.assumption_bundle),
            "notes": self.notes,
            "override_exhaustion": self.override_exhaustion,
            "override_justification": self.override_justification,
        }
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "HypothesisSpec":
        """Lenient deserialization (for round-trip).

        Does NOT validate — call .validate() separately, or use
        validate_hypothesis_spec() for boundary parsing.

        Uses `.get(key, default)` for field defaults. Critically: does NOT
        use `value or default` fallbacks on numeric fields — a literal 0
        is falsy but semantically meaningful, and an ``or``-based fallback
        would silently substitute the default and bypass validation
        (which rejects 0 as out-of-range for compute_budget and
        checkpoint intervals).
        """
        pipeline_raw = d.get("pipeline", []) or []
        nb_raw = d.get("null_baseline")

        def _coerce_int(key: str, default: int) -> int:
            v = d.get(key, default)
            try:
                return int(v) if v is not None else default
            except (TypeError, ValueError):
                return default

        def _coerce_float(key: str, default: float) -> float:
            v = d.get(key, default)
            try:
                return float(v) if v is not None else default
            except (TypeError, ValueError):
                return default

        return cls(
            hypothesis_id=d.get("hypothesis_id", ""),
            pipeline=[CipherLayer.from_dict(lr) for lr in pipeline_raw],
            crib_alignment=d.get("crib_alignment", "direct_positional"),
            scoring=d.get("scoring", "composite"),
            null_baseline=NullBaselineSpec.from_dict(nb_raw) if nb_raw else None,
            information_gain_bits_estimate=_coerce_float("information_gain_bits_estimate", 0.0),
            success_criteria=d.get("success_criteria", {}) or {},
            kill_criteria=d.get("kill_criteria", {}) or {},
            compute_budget_cpu_minutes=_coerce_int("compute_budget_cpu_minutes", 30),
            checkpoint_every_sec=_coerce_int("checkpoint_every_sec", 60),
            assumption_bundle=list(d.get("assumption_bundle", []) or []),
            notes=str(d.get("notes", "") or ""),
            override_exhaustion=bool(d.get("override_exhaustion", False)),
            override_justification=str(d.get("override_justification", "") or ""),
        )

    @classmethod
    def from_json(cls, raw: str) -> "HypothesisSpec":
        return cls.from_dict(json.loads(raw))


# ─── Boundary validation ─────────────────────────────────────────────────────

def validate_hypothesis_spec(raw: str | dict[str, Any]) -> ParseResult[HypothesisSpec]:
    """Parse and validate a HypothesisSpec from raw JSON or dict.

    Steps:
      1. Parse JSON if raw is a string.
      2. Attempt dataclass construction via from_dict.
      3. Run spec.validate() and surface every error.

    Any failure returns ``ParseResult.fail`` with explicit reasons and
    the raw input preserved for audit. Never silently repairs malformed
    input — that was the failure mode that led to the Day-4 fabrication
    incident documented in MEMORY.md.
    """
    raw_str: str
    if isinstance(raw, str):
        raw_str = raw
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            return ParseResult.fail(errors=[f"JSON parse error: {exc}"], raw=raw_str)
    elif isinstance(raw, dict):
        raw_str = json.dumps(raw, sort_keys=True, separators=(",", ":"))
        data = raw
    else:
        return ParseResult.fail(
            errors=[f"Expected str or dict, got {type(raw).__name__}"],
            raw=str(raw)[:500],
        )

    if not isinstance(data, dict):
        return ParseResult.fail(
            errors=[f"Expected JSON object at top level, got {type(data).__name__}"],
            raw=raw_str,
        )

    try:
        spec = HypothesisSpec.from_dict(data)
    except Exception as exc:
        return ParseResult.fail(
            errors=[f"HypothesisSpec construction raised: {exc}"],
            raw=raw_str,
        )

    errors = spec.validate()
    if errors:
        return ParseResult.fail(errors=errors, raw=raw_str)
    return ParseResult.ok(value=spec, raw=raw_str)


__all__ = [
    # Enums / literal groupings (runtime validation sets)
    "_VALID_CIPHER_KINDS",
    "_VALID_ALPHABET_KINDS",
    "_VALID_CRIB_ALIGNMENTS",
    "_VALID_SCORING_MODES",
    "_VALID_NULL_BASELINE_METHODS",
    # Dataclasses
    "ParamRange",
    "CipherLayer",
    "NullBaselineSpec",
    "HypothesisSpec",
    # Boundary validator
    "validate_hypothesis_spec",
]
