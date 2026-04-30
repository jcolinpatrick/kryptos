"""Real-K4 LLM↔HCC bridge: pseudo-clue pack schema.

A *pseudo-clue pack* is a structured, provenance-linked role hypothesis
about how real K4 might decode. It is the bridge between the LLM
theorist (which has access to evidence sources but cannot emit DSL
directly) and the HandCipherCore deterministic compiler (which needs
structured roles, not natural-language clue text).

A pack does NOT contain plaintext, candidate solutions, or DSL specs.
It contains:
  * keyword candidates with role hints (substitution / columnar /
    alphabet)
  * numeric role candidates with role hints (shift / width / depth /
    skip / ...)
  * operation hints (which cipher families are plausible)
  * composition templates (which layer combinations to enumerate)
  * bounds (cardinality caps so a pack cannot explode the universe)
  * provenance items (every role must cite a real-K4 evidence source)

The compiler in ``real_k4_pseudo_clue_compiler`` takes a pack and
emits a list of ``GeneratedSpec`` from the existing HCC family
generators. The bridge audit runner in ``real_k4_bridge_audit``
takes a pack registry, compiles all packs, dispatches the resulting
specs through the kernel, scores against real-K4 cribs, runs a null
baseline, and emits an audit artifact with full provenance.

Hard contract:
  * No K4Bench data may enter a pack.
  * No sealed-answer text may enter a pack.
  * Every role MUST cite at least one provenance item.
  * Empty packs (no roles) are invalid; the compiler refuses them.
  * Packs declare their bounds; the compiler enforces them; the
    audit runner enforces a global cap on top of per-pack bounds.

This module is import-safe in real-K4 mode and bench mode. It does
not reach into ``kryptos.kernel`` or ``kryptosbot.bench_*``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Literal, Mapping, Optional, Sequence


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


SOURCE_TYPES: frozenset[str] = frozenset({
    "crib",            # disclosed plaintext span (BERLIN, CLOCK, etc.)
    "anomaly",         # entry from the anomaly registry
    "sculpture",       # physical sculpture observation (panel, lodestone, ...)
    "public_comment",  # Sanborn / Scheidt / NSA published statement
    "registry",        # entry from kryptosbot.real_k4_clue_registry
    "human_note",      # operator-supplied research note (must reference
                       # an existing repo file)
})


KEYWORD_ROLE_HINTS: frozenset[str] = frozenset({
    "substitution", "columnar", "alphabet", "route", "unknown",
})


NUMERIC_ROLE_HINTS: frozenset[str] = frozenset({
    "shift", "width", "depth", "offset",
    "period", "position_anchor", "count", "unknown",
})


OPERATION_KINDS: frozenset[str] = frozenset({
    "caesar", "vigenere", "beaufort", "variant_beaufort",
    "columnar", "rail_fence",
    "route_boustrophedon", "route_diagonal",
    "route_diagonal_canonical",
    "row_reverse", "reverse_blocks", "skip_route",
    "atbash", "unknown",
})


OPERATION_REQUIREMENT: frozenset[str] = frozenset({
    "required", "optional", "speculative",
})


EVIDENCE_TIERS: frozenset[str] = frozenset({
    # Mirrors the project's truth taxonomy. Higher tier = stronger
    # evidence. A pack's evidence_tier is the WEAKEST tier of any
    # provenance item it cites.
    "tier_1_public_fact",       # disclosed cribs, public CT
    "tier_2_derived_fact",      # provable consequences
    "tier_3_creator_statement", # Sanborn/Scheidt published statements
    "tier_4_inference",         # plausible inference from registry
    "tier_5_speculation",       # explicitly speculative
})


# ---------------------------------------------------------------------------
# Provenance + role primitives
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProvenanceItem:
    """One evidence citation.

    ``source_id`` is a stable identifier the audit runner uses to
    cross-link packs and the evidence registry. ``quote_or_summary``
    is a short text excerpt (NOT the full source; the registry holds
    that). ``confidence`` is a 0..1 float reflecting how strongly the
    pack author commits to this citation supporting the claim.
    """
    source_id: str
    source_type: str
    quote_or_summary: str
    confidence: float
    url_or_registry_key: Optional[str] = None

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not isinstance(self.source_id, str) or not self.source_id.strip():
            errors.append("ProvenanceItem.source_id must be a non-empty string")
        if self.source_type not in SOURCE_TYPES:
            errors.append(
                f"ProvenanceItem.source_type {self.source_type!r} not in "
                f"{sorted(SOURCE_TYPES)}"
            )
        if not isinstance(self.quote_or_summary, str) or not self.quote_or_summary.strip():
            errors.append(
                "ProvenanceItem.quote_or_summary must be a non-empty string"
            )
        if not (0.0 <= float(self.confidence) <= 1.0):
            errors.append(
                f"ProvenanceItem.confidence {self.confidence} out of [0, 1]"
            )
        return errors


@dataclass(frozen=True)
class KeywordHint:
    """A candidate keyword with a role hint and provenance.

    ``token`` is normalised to upper-case A-Z (only). ``role_hint``
    suggests where the compiler should try this keyword; the
    compiler may try it in additional roles if other hints permit.
    """
    token: str
    role_hint: str
    source_ids: tuple[str, ...]
    confidence: float = 0.5

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not isinstance(self.token, str):
            errors.append("KeywordHint.token must be a string")
        else:
            up = self.token.upper().strip()
            if not up.isalpha() or len(up) < 2:
                errors.append(
                    f"KeywordHint.token {self.token!r} must be A-Z, "
                    "length >= 2"
                )
        if self.role_hint not in KEYWORD_ROLE_HINTS:
            errors.append(
                f"KeywordHint.role_hint {self.role_hint!r} not in "
                f"{sorted(KEYWORD_ROLE_HINTS)}"
            )
        if not self.source_ids:
            errors.append(
                "KeywordHint.source_ids must cite at least one provenance item"
            )
        if not (0.0 <= float(self.confidence) <= 1.0):
            errors.append(
                f"KeywordHint.confidence {self.confidence} out of [0, 1]"
            )
        return errors


@dataclass(frozen=True)
class NumericRoleHint:
    """A candidate integer with a role hint and provenance."""
    value: int
    token: str
    role_hint: str
    source_ids: tuple[str, ...]
    confidence: float = 0.5

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not isinstance(self.value, int):
            errors.append("NumericRoleHint.value must be int")
        elif not (0 <= self.value <= 99):
            errors.append(
                f"NumericRoleHint.value {self.value} out of plausible "
                "0..99 range for hand-cipher parameters"
            )
        if self.role_hint not in NUMERIC_ROLE_HINTS:
            errors.append(
                f"NumericRoleHint.role_hint {self.role_hint!r} not in "
                f"{sorted(NUMERIC_ROLE_HINTS)}"
            )
        if not self.source_ids:
            errors.append(
                "NumericRoleHint.source_ids must cite at least one provenance item"
            )
        if not (0.0 <= float(self.confidence) <= 1.0):
            errors.append(
                f"NumericRoleHint.confidence {self.confidence} out of [0, 1]"
            )
        return errors


@dataclass(frozen=True)
class OperationHint:
    """A cipher operation that the LLM thinks may participate.

    ``role`` controls how the compiler weights this operation when
    enumerating composition templates: ``required`` operations must
    appear in every emitted spec; ``optional`` may or may not;
    ``speculative`` only fire if the bounds explicitly allow them.
    """
    operation: str
    role: str
    source_ids: tuple[str, ...]
    confidence: float = 0.5

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.operation not in OPERATION_KINDS:
            errors.append(
                f"OperationHint.operation {self.operation!r} not in "
                f"{sorted(OPERATION_KINDS)}"
            )
        if self.role not in OPERATION_REQUIREMENT:
            errors.append(
                f"OperationHint.role {self.role!r} not in "
                f"{sorted(OPERATION_REQUIREMENT)}"
            )
        if not self.source_ids:
            errors.append(
                "OperationHint.source_ids must cite at least one provenance item"
            )
        if not (0.0 <= float(self.confidence) <= 1.0):
            errors.append(
                f"OperationHint.confidence {self.confidence} out of [0, 1]"
            )
        return errors


@dataclass(frozen=True)
class CompositionTemplate:
    """An ordered or unordered list of operation slots the compiler
    should enumerate as a single composition family.

    ``layer_kinds`` is a tuple of operation kinds (must be in
    ``OPERATION_KINDS``). ``ordered=True`` means emit the listed
    order only; ``ordered=False`` means emit all permutations.

    ``max_layers`` is a sanity cap (default 3). Layered hand ciphers
    above 3 layers are rare and explode the parameter space.
    """
    layer_kinds: tuple[str, ...]
    ordered: bool
    rationale: str
    confidence: float = 0.5
    max_layers: int = 3

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not isinstance(self.layer_kinds, (tuple, list)):
            errors.append("CompositionTemplate.layer_kinds must be a tuple")
        else:
            if len(self.layer_kinds) < 1 or len(self.layer_kinds) > self.max_layers:
                errors.append(
                    f"CompositionTemplate.layer_kinds length "
                    f"{len(self.layer_kinds)} out of [1, {self.max_layers}]"
                )
            for kind in self.layer_kinds:
                if kind not in OPERATION_KINDS:
                    errors.append(
                        f"CompositionTemplate.layer_kinds entry {kind!r} "
                        f"not in {sorted(OPERATION_KINDS)}"
                    )
        if not (0.0 <= float(self.confidence) <= 1.0):
            errors.append(
                f"CompositionTemplate.confidence {self.confidence} out of [0, 1]"
            )
        if not isinstance(self.rationale, str) or not self.rationale.strip():
            errors.append(
                "CompositionTemplate.rationale must be a non-empty string"
            )
        return errors


@dataclass(frozen=True)
class Bounds:
    """Per-pack cardinality and pool bounds.

    The audit runner enforces the global cap on top of these per-pack
    bounds; per-pack bounds only narrow the universe further. A pack
    can choose to disable the project-safe defaults entirely by
    setting ``allow_project_safe_defaults=False``, which forces the
    compiler to use only pack-supplied keywords/widths/depths/shifts.
    """
    max_specs: int = 200
    allowed_widths: tuple[int, ...] = ()
    allowed_depths: tuple[int, ...] = ()
    allowed_shifts: tuple[int, ...] = ()
    allowed_keywords: tuple[str, ...] = ()
    allow_project_safe_defaults: bool = True
    allow_default_widths: bool = True

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not isinstance(self.max_specs, int) or self.max_specs <= 0:
            errors.append(
                f"Bounds.max_specs must be positive int; got {self.max_specs!r}"
            )
        if self.max_specs > 5000:
            errors.append(
                f"Bounds.max_specs {self.max_specs} exceeds per-pack hard "
                "ceiling of 5000; tighten bounds or split into multiple packs"
            )
        for w in self.allowed_widths:
            if not isinstance(w, int) or w < 1 or w > 50:
                errors.append(f"Bounds.allowed_widths {w!r} out of [1, 50]")
        for d in self.allowed_depths:
            if not isinstance(d, int) or d < 2 or d > 20:
                errors.append(f"Bounds.allowed_depths {d!r} out of [2, 20]")
        for s in self.allowed_shifts:
            if not isinstance(s, int) or s < 0 or s > 25:
                errors.append(f"Bounds.allowed_shifts {s!r} out of [0, 25]")
        for kw in self.allowed_keywords:
            if not isinstance(kw, str):
                errors.append("Bounds.allowed_keywords entry must be string")
                continue
            up = kw.upper().strip()
            if not up.isalpha() or len(up) < 2:
                errors.append(
                    f"Bounds.allowed_keywords entry {kw!r} must be A-Z, "
                    "length >= 2"
                )
        return errors


# ---------------------------------------------------------------------------
# Pseudo-clue pack
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PseudoCluePack:
    """A structured role hypothesis about real K4.

    Every pack must:
      1. Carry a unique ``pack_id`` within an audit run.
      2. Include at least one provenance item.
      3. Include at least one keyword OR numeric role OR operation
         hint (an empty pack is rejected).
      4. Cite an existing provenance ``source_id`` from EVERY role
         entry's ``source_ids`` list.
      5. Declare bounds (defaults are conservative).
    """
    pack_id: str
    title: str
    hypothesis_summary: str
    provenance_items: tuple[ProvenanceItem, ...]
    evidence_tier: str
    keywords: tuple[KeywordHint, ...] = ()
    numeric_roles: tuple[NumericRoleHint, ...] = ()
    operation_hints: tuple[OperationHint, ...] = ()
    composition_templates: tuple[CompositionTemplate, ...] = ()
    constraints: tuple[str, ...] = ()
    bounds: Bounds = field(default_factory=Bounds)
    generated_by: str = "human_fixture"
    generation_run_id: str = ""
    excluded_reasons: tuple[str, ...] = ()
    caveats: tuple[str, ...] = ()

    def validate(self) -> list[str]:
        """Return a list of error strings; empty list means valid."""
        errors: list[str] = []

        # Identity / metadata
        if not isinstance(self.pack_id, str) or not self.pack_id.strip():
            errors.append("PseudoCluePack.pack_id must be a non-empty string")
        if not isinstance(self.title, str) or not self.title.strip():
            errors.append("PseudoCluePack.title must be a non-empty string")
        if not isinstance(self.hypothesis_summary, str) or not self.hypothesis_summary.strip():
            errors.append(
                "PseudoCluePack.hypothesis_summary must be a non-empty string"
            )
        if self.evidence_tier not in EVIDENCE_TIERS:
            errors.append(
                f"PseudoCluePack.evidence_tier {self.evidence_tier!r} not in "
                f"{sorted(EVIDENCE_TIERS)}"
            )

        # Provenance
        if not self.provenance_items:
            errors.append(
                "PseudoCluePack.provenance_items must contain at least one item"
            )
        seen_source_ids: set[str] = set()
        for prov in self.provenance_items:
            errors.extend(prov.validate())
            if prov.source_id in seen_source_ids:
                errors.append(
                    f"duplicate provenance source_id {prov.source_id!r}"
                )
            seen_source_ids.add(prov.source_id)

        # Roles must reference an existing provenance source_id
        def _check_source_refs(role_label: str, sids: Sequence[str]) -> None:
            for sid in sids:
                if sid not in seen_source_ids:
                    errors.append(
                        f"{role_label} cites unknown provenance source_id "
                        f"{sid!r}; declare it in provenance_items"
                    )

        # Keywords
        for i, kw in enumerate(self.keywords):
            errors.extend([f"keywords[{i}]: {e}" for e in kw.validate()])
            _check_source_refs(f"keywords[{i}]", kw.source_ids)

        # Numeric roles
        for i, n in enumerate(self.numeric_roles):
            errors.extend([f"numeric_roles[{i}]: {e}" for e in n.validate()])
            _check_source_refs(f"numeric_roles[{i}]", n.source_ids)

        # Operation hints
        for i, op in enumerate(self.operation_hints):
            errors.extend([f"operation_hints[{i}]: {e}" for e in op.validate()])
            _check_source_refs(f"operation_hints[{i}]", op.source_ids)

        # Composition templates (no source_ids — they're abstract
        # composition rules, not evidence claims; rationale field is
        # the human-readable evidence link).
        for i, ct in enumerate(self.composition_templates):
            errors.extend([f"composition_templates[{i}]: {e}" for e in ct.validate()])

        # Bounds
        errors.extend([f"bounds: {e}" for e in self.bounds.validate()])

        # Pack must have at least one role
        if (not self.keywords and not self.numeric_roles
                and not self.operation_hints):
            errors.append(
                "PseudoCluePack must contain at least one keyword, "
                "numeric_role, or operation_hint"
            )

        return errors

    def is_valid(self) -> bool:
        return not self.validate()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Convert frozen-dataclass tuples back to lists for JSON.
        for key in (
            "provenance_items", "keywords", "numeric_roles",
            "operation_hints", "composition_templates",
        ):
            d[key] = [_normalize_for_json(item) for item in getattr(self, key)]
        d["constraints"] = list(self.constraints)
        d["excluded_reasons"] = list(self.excluded_reasons)
        d["caveats"] = list(self.caveats)
        d["bounds"] = _normalize_for_json(self.bounds)
        return d

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "PseudoCluePack":
        prov = tuple(
            ProvenanceItem(
                source_id=str(p["source_id"]),
                source_type=str(p["source_type"]),
                quote_or_summary=str(p["quote_or_summary"]),
                confidence=float(p["confidence"]),
                url_or_registry_key=p.get("url_or_registry_key"),
            )
            for p in raw.get("provenance_items", [])
        )
        keywords = tuple(
            KeywordHint(
                token=str(k["token"]).upper().strip(),
                role_hint=str(k.get("role_hint", "unknown")),
                source_ids=tuple(k.get("source_ids", [])),
                confidence=float(k.get("confidence", 0.5)),
            )
            for k in raw.get("keywords", [])
        )
        numeric_roles = tuple(
            NumericRoleHint(
                value=int(n["value"]),
                token=str(n.get("token", "")),
                role_hint=str(n.get("role_hint", "unknown")),
                source_ids=tuple(n.get("source_ids", [])),
                confidence=float(n.get("confidence", 0.5)),
            )
            for n in raw.get("numeric_roles", [])
        )
        op_hints = tuple(
            OperationHint(
                operation=str(o["operation"]),
                role=str(o.get("role", "optional")),
                source_ids=tuple(o.get("source_ids", [])),
                confidence=float(o.get("confidence", 0.5)),
            )
            for o in raw.get("operation_hints", [])
        )
        comp_tpls = tuple(
            CompositionTemplate(
                layer_kinds=tuple(ct["layer_kinds"]),
                ordered=bool(ct.get("ordered", True)),
                rationale=str(ct.get("rationale", "")),
                confidence=float(ct.get("confidence", 0.5)),
                max_layers=int(ct.get("max_layers", 3)),
            )
            for ct in raw.get("composition_templates", [])
        )
        b = raw.get("bounds", {}) or {}
        bounds = Bounds(
            max_specs=int(b.get("max_specs", 200)),
            allowed_widths=tuple(b.get("allowed_widths", ()) or ()),
            allowed_depths=tuple(b.get("allowed_depths", ()) or ()),
            allowed_shifts=tuple(b.get("allowed_shifts", ()) or ()),
            allowed_keywords=tuple(
                str(kw).upper().strip()
                for kw in (b.get("allowed_keywords", ()) or ())
            ),
            allow_project_safe_defaults=bool(
                b.get("allow_project_safe_defaults", True)
            ),
            allow_default_widths=bool(
                b.get("allow_default_widths", True)
            ),
        )
        return cls(
            pack_id=str(raw["pack_id"]),
            title=str(raw.get("title", "")),
            hypothesis_summary=str(raw.get("hypothesis_summary", "")),
            provenance_items=prov,
            evidence_tier=str(raw.get("evidence_tier", "tier_5_speculation")),
            keywords=keywords,
            numeric_roles=numeric_roles,
            operation_hints=op_hints,
            composition_templates=comp_tpls,
            constraints=tuple(raw.get("constraints", ())),
            bounds=bounds,
            generated_by=str(raw.get("generated_by", "human_fixture")),
            generation_run_id=str(raw.get("generation_run_id", "")),
            excluded_reasons=tuple(raw.get("excluded_reasons", ())),
            caveats=tuple(raw.get("caveats", ())),
        )


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------


def _normalize_for_json(obj: Any) -> Any:
    """Recursively convert frozen dataclasses + tuples to JSON-friendly
    primitives."""
    if hasattr(obj, "__dataclass_fields__"):
        d = {}
        for k, v in asdict(obj).items():
            d[k] = _normalize_for_json(v)
        return d
    if isinstance(obj, tuple):
        return [_normalize_for_json(x) for x in obj]
    if isinstance(obj, list):
        return [_normalize_for_json(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _normalize_for_json(v) for k, v in obj.items()}
    return obj


def load_pack(path: str | Path) -> PseudoCluePack:
    """Load a single pack from a JSON file."""
    p = Path(path)
    with open(p, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return PseudoCluePack.from_dict(raw)


def load_pack_directory(path: str | Path) -> list[PseudoCluePack]:
    """Load every ``*.json`` file in a directory as a pack, sorted by
    filename for deterministic ordering."""
    p = Path(path)
    if not p.is_dir():
        raise ValueError(f"load_pack_directory: {path!r} is not a directory")
    packs: list[PseudoCluePack] = []
    for entry in sorted(p.glob("*.json")):
        packs.append(load_pack(entry))
    return packs


def utc_run_id() -> str:
    """Deterministic UTC-based run id helper."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")


__all__ = [
    "SOURCE_TYPES",
    "KEYWORD_ROLE_HINTS",
    "NUMERIC_ROLE_HINTS",
    "OPERATION_KINDS",
    "OPERATION_REQUIREMENT",
    "EVIDENCE_TIERS",
    "ProvenanceItem",
    "KeywordHint",
    "NumericRoleHint",
    "OperationHint",
    "CompositionTemplate",
    "Bounds",
    "PseudoCluePack",
    "load_pack",
    "load_pack_directory",
    "utc_run_id",
]
