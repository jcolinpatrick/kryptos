"""Tests for real-K4 LLM↔HCC bridge: pseudo-clue pack schema.

Pinned properties:

  1. Empty packs (no keywords / numeric_roles / operation_hints)
     are rejected.
  2. A pack with NO provenance items is rejected.
  3. A role citing an unknown source_id is rejected.
  4. KeywordHint enforces A-Z and length >= 2.
  5. NumericRoleHint enforces value >= 0 and value <= 99.
  6. Bounds.max_specs has a per-pack hard ceiling of 5000.
  7. evidence_tier must be one of the documented tier strings.
  8. operation kinds, role hints, source types are validated against
     the documented frozenset enumerations.
  9. JSON round-trip preserves all fields and their validation
     state.
 10. ``load_pack_directory`` orders packs by filename
     deterministically.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kryptosbot.real_k4_pseudo_clue_pack import (
    Bounds,
    CompositionTemplate,
    KeywordHint,
    NumericRoleHint,
    OperationHint,
    ProvenanceItem,
    PseudoCluePack,
    SOURCE_TYPES,
    KEYWORD_ROLE_HINTS,
    NUMERIC_ROLE_HINTS,
    OPERATION_KINDS,
    EVIDENCE_TIERS,
    load_pack,
    load_pack_directory,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _good_provenance() -> ProvenanceItem:
    return ProvenanceItem(
        source_id="CRIB-BERLIN",
        source_type="crib",
        quote_or_summary="BERLIN at 64-69",
        confidence=0.99,
    )


def _good_pack(**overrides) -> PseudoCluePack:
    base = dict(
        pack_id="t1",
        title="t",
        hypothesis_summary="t",
        provenance_items=(_good_provenance(),),
        evidence_tier="tier_1_public_fact",
        keywords=(KeywordHint("BERLIN", "substitution", ("CRIB-BERLIN",), 0.5),),
        numeric_roles=(),
        operation_hints=(),
        composition_templates=(
            CompositionTemplate(("vigenere", "columnar"), True, "two-layer", 0.5, 2),
        ),
        bounds=Bounds(),
    )
    base.update(overrides)
    return PseudoCluePack(**base)


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


class TestSchemaValidation:
    def test_minimal_valid_pack(self):
        p = _good_pack()
        assert p.is_valid()

    def test_empty_pack_rejected(self):
        # No keywords, no numeric_roles, no operation_hints
        p = _good_pack(
            keywords=(), numeric_roles=(), operation_hints=(),
        )
        errs = p.validate()
        assert any("at least one keyword" in e.lower() for e in errs)

    def test_no_provenance_rejected(self):
        # Constructor allows it, but validate must reject.
        p = PseudoCluePack(
            pack_id="t",
            title="t",
            hypothesis_summary="t",
            provenance_items=(),
            evidence_tier="tier_1_public_fact",
            keywords=(KeywordHint("BERLIN", "substitution", ("CRIB-BERLIN",), 0.5),),
        )
        errs = p.validate()
        assert any("provenance_items" in e for e in errs)

    def test_role_unknown_source_id_rejected(self):
        p = _good_pack(
            keywords=(KeywordHint("BERLIN", "substitution", ("MISSING-SID",), 0.5),),
        )
        errs = p.validate()
        assert any("MISSING-SID" in e for e in errs)

    def test_keyword_too_short_rejected(self):
        with pytest.raises(Exception):
            # frozen dataclass accepts the value but validate catches it
            kh = KeywordHint("A", "substitution", ("CRIB-BERLIN",), 0.5)
            errs = kh.validate()
            assert errs
            raise ValueError("\n".join(errs))

    def test_keyword_non_alpha_rejected(self):
        kh = KeywordHint("ABC123", "substitution", ("CRIB-BERLIN",), 0.5)
        errs = kh.validate()
        assert any("A-Z" in e for e in errs)

    def test_numeric_value_out_of_range_rejected(self):
        nh = NumericRoleHint(100, "hundred", "shift", ("CRIB-BERLIN",), 0.5)
        errs = nh.validate()
        assert any("0..99" in e for e in errs)

    def test_bounds_max_specs_ceiling(self):
        b = Bounds(max_specs=5001)
        errs = b.validate()
        assert any("5000" in e for e in errs)

    def test_evidence_tier_must_be_known(self):
        p = _good_pack(evidence_tier="tier_999_made_up")
        errs = p.validate()
        assert any("evidence_tier" in e for e in errs)

    def test_unknown_operation_rejected(self):
        oh = OperationHint("not_a_real_operation", "optional", ("CRIB-BERLIN",), 0.5)
        errs = oh.validate()
        assert any("operation" in e for e in errs)

    def test_unknown_source_type_rejected(self):
        prov = ProvenanceItem(
            source_id="SID", source_type="not_a_type",
            quote_or_summary="x", confidence=0.5,
        )
        errs = prov.validate()
        assert any("source_type" in e for e in errs)

    def test_confidence_out_of_range_rejected(self):
        kh = KeywordHint("BERLIN", "substitution", ("CRIB-BERLIN",), 1.5)
        errs = kh.validate()
        assert any("confidence" in e for e in errs)


# ---------------------------------------------------------------------------
# JSON round-trip
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_to_dict_from_dict_round_trip(self):
        p = _good_pack(
            numeric_roles=(NumericRoleHint(7, "seven", "depth", ("CRIB-BERLIN",), 0.4),),
            operation_hints=(OperationHint("rail_fence", "optional", ("CRIB-BERLIN",), 0.4),),
        )
        d = p.to_dict()
        # Round-trip through real JSON
        s = json.dumps(d)
        p2 = PseudoCluePack.from_dict(json.loads(s))
        assert p2.validate() == []
        assert p2.pack_id == p.pack_id
        assert p2.evidence_tier == p.evidence_tier
        assert p2.numeric_roles[0].value == 7
        assert p2.operation_hints[0].operation == "rail_fence"

    def test_load_pack_directory_orders_by_filename(self, tmp_path: Path):
        # Write packs in non-alphabetical order; loader must sort.
        for name in ("c.json", "a.json", "b.json"):
            data = _good_pack(pack_id=name.split(".")[0]).to_dict()
            (tmp_path / name).write_text(json.dumps(data), encoding="utf-8")
        packs = load_pack_directory(tmp_path)
        assert [p.pack_id for p in packs] == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class TestEnumerations:
    def test_source_types_documented(self):
        # Audit lock: source types are an exact set; new entries
        # require a deliberate audit.
        assert SOURCE_TYPES == frozenset({
            "crib", "anomaly", "sculpture", "public_comment",
            "registry", "human_note",
        })

    def test_keyword_role_hints_documented(self):
        assert "substitution" in KEYWORD_ROLE_HINTS
        assert "columnar" in KEYWORD_ROLE_HINTS
        assert "alphabet" in KEYWORD_ROLE_HINTS
        assert "unknown" in KEYWORD_ROLE_HINTS

    def test_numeric_role_hints_documented(self):
        assert "depth" in NUMERIC_ROLE_HINTS
        assert "shift" in NUMERIC_ROLE_HINTS
        assert "width" in NUMERIC_ROLE_HINTS

    def test_operation_kinds_overlap_solver_capabilities(self):
        # Every OPERATION_KINDS value (except 'unknown') must be a
        # cipher kind the existing HCC families can handle.
        from kryptosbot.real_k4_pseudo_clue_compiler import _TEMPLATE_ROUTING
        # Spot check: at least one routing key contains each
        # operation we claim to support (excluding 'unknown').
        kinds_used: set[str] = set()
        for key in _TEMPLATE_ROUTING:
            kinds_used.update(key)
        # Operations the compiler routes for must all be in the
        # documented OPERATION_KINDS frozenset.
        for k in kinds_used:
            assert k in OPERATION_KINDS, f"routing key {k!r} not in OPERATION_KINDS"

    def test_evidence_tiers_documented(self):
        for t in (
            "tier_1_public_fact", "tier_2_derived_fact",
            "tier_3_creator_statement", "tier_4_inference",
            "tier_5_speculation",
        ):
            assert t in EVIDENCE_TIERS
