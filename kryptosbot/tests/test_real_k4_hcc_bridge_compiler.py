"""Tests for real-K4 LLM↔HCC bridge: pack-to-HCC compiler.

Pinned properties:

  1. Sub+columnar template routes to LESSON-010 i3 family.
  2. Sub+columnar+rail_fence template routes to LESSON-022 i3
     rail_fence family.
  3. Caesar+route+columnar template routes to the LESSON-019
     numeric route columnar family.
  4. Caesar-alone template emits caesar specs from numeric shifts.
  5. Diagonal canonical template routes to LESSON-021 canonical
     family.
  6. Per-pack max_specs is enforced.
  7. Global max_specs is enforced across multiple packs.
  8. Every emitted spec carries pack_id + evidence_tier in its
     coverage extras.
  9. Required-operation gating: a template that doesn't include
     a required operation is skipped.
 10. Unknown template (no matching emitter) is skipped without error.
 11. Compilation is deterministic.
 12. Empty packs raise CompileError.
"""

from __future__ import annotations

import pytest

from kryptosbot.real_k4_pseudo_clue_pack import (
    Bounds, CompositionTemplate, KeywordHint, NumericRoleHint,
    OperationHint, ProvenanceItem, PseudoCluePack,
)
from kryptosbot.real_k4_pseudo_clue_compiler import (
    CompileError, compile_pack, compile_packs,
)


def _prov(sid: str = "SID-1") -> ProvenanceItem:
    return ProvenanceItem(sid, "crib", "summary", 0.99)


def _kw(token: str, role: str = "unknown") -> KeywordHint:
    return KeywordHint(token, role, ("SID-1",), 0.5)


def _num(value: int, role: str = "unknown") -> NumericRoleHint:
    return NumericRoleHint(value, str(value), role, ("SID-1",), 0.5)


def _op(op: str, role: str = "optional") -> OperationHint:
    return OperationHint(op, role, ("SID-1",), 0.5)


def _ct(layers: tuple[str, ...], ordered: bool = True, max_layers: int = 3) -> CompositionTemplate:
    return CompositionTemplate(layers, ordered, "rationale", 0.5, max_layers)


def _pack(**kw) -> PseudoCluePack:
    base = dict(
        pack_id="t",
        title="t",
        hypothesis_summary="t",
        provenance_items=(_prov(),),
        evidence_tier="tier_1_public_fact",
    )
    base.update(kw)
    return PseudoCluePack(**base)


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


class TestSubColumnar:
    def test_routes_to_i3_family(self):
        p = _pack(
            keywords=(_kw("BERLIN", "substitution"), _kw("CLOCK", "columnar")),
            composition_templates=(_ct(("vigenere", "columnar"), max_layers=2),),
        )
        specs = compile_pack(p)
        assert specs
        fams = {s.coverage.layer_family for s in specs}
        # LESSON-010 i3_columnar_<sub> families
        assert "i3_columnar_vigenere" in fams or "i3_columnar_beaufort" in fams or "i3_columnar_variant_beaufort" in fams


class TestSubColumnarRailFence:
    def test_routes_to_lesson_022_family(self):
        p = _pack(
            keywords=(
                _kw("OBSERVE", "substitution"), _kw("GARDEN", "columnar"),
            ),
            numeric_roles=(_num(3, "depth"),),
            composition_templates=(_ct(("vigenere", "columnar", "rail_fence")),),
        )
        specs = compile_pack(p)
        assert specs
        fams = {s.coverage.layer_family for s in specs}
        l022 = {
            "i3_columnar_vigenere_rail_fence",
            "i3_columnar_beaufort_rail_fence",
            "i3_columnar_variant_beaufort_rail_fence",
        }
        assert fams & l022, f"L022 family expected; got {fams}"

    def test_lesson_022_carries_full_telemetry(self):
        p = _pack(
            keywords=(_kw("OBSERVE", "substitution"), _kw("GARDEN", "columnar")),
            numeric_roles=(_num(3, "depth"),),
            composition_templates=(_ct(("vigenere", "columnar", "rail_fence")),),
        )
        specs = compile_pack(p)
        l022 = [s for s in specs if "rail_fence" in s.coverage.layer_family
                and s.coverage.layer_family.startswith("i3_columnar_")]
        assert l022
        for s in l022:
            assert s.coverage.transposition_keyword in ("OBSERVE", "GARDEN")
            assert s.coverage.role_assignment_mode == (
                "independent_two_keyword_rail_fence_three_role"
            )


class TestCaesarRouteColumnar:
    def test_routes_to_lesson_019_family(self):
        p = _pack(
            keywords=(_kw("KEYNAME", "columnar"),),
            numeric_roles=(_num(17, "shift"), _num(10, "width")),
            composition_templates=(_ct(("caesar", "columnar", "route_boustrophedon")),),
        )
        specs = compile_pack(p)
        assert specs
        fams = {s.coverage.layer_family for s in specs}
        assert any("caesar_route_boustrophedon_columnar" in f for f in fams), (
            f"L019 family expected; got {fams}"
        )

    def test_diagonal_partner_when_op_hint_signals(self):
        p = _pack(
            keywords=(_kw("KEYNAME", "columnar"),),
            numeric_roles=(_num(17, "shift"),),
            operation_hints=(_op("route_diagonal", "required"),),
            composition_templates=(_ct(("caesar", "columnar", "route_diagonal")),),
        )
        specs = compile_pack(p)
        fams = {s.coverage.layer_family for s in specs}
        assert any("caesar_route_diagonal_columnar" in f for f in fams), (
            f"L019 diagonal partner expected; got {fams}"
        )


class TestCaesarAlone:
    def test_routes_to_caesar_alone(self):
        p = _pack(
            keywords=(_kw("KEYNAME", "substitution"),),
            numeric_roles=(_num(17, "shift"),),
            composition_templates=(_ct(("caesar",), max_layers=1),),
        )
        specs = compile_pack(p)
        fams = {s.coverage.layer_family for s in specs}
        assert "caesar" in fams


class TestDiagonalCanonical:
    def test_routes_to_lesson_021_family(self):
        p = _pack(
            keywords=(_kw("KEYNAME", "substitution"),),
            numeric_roles=(_num(10, "width"),),
            composition_templates=(_ct(("route_diagonal_canonical",), max_layers=1),),
        )
        specs = compile_pack(p)
        fams = {s.coverage.layer_family for s in specs}
        assert "route_diagonal_canonical" in fams


class TestReverseBlocks:
    def test_routes_to_reverse_blocks_family(self):
        p = _pack(
            keywords=(_kw("BERLIN", "substitution"),),
            numeric_roles=(_num(5, "period"),),
            composition_templates=(_ct(("reverse_blocks", "vigenere"), max_layers=2),),
        )
        specs = compile_pack(p)
        fams = {s.coverage.layer_family for s in specs}
        assert any("reverse_blocks" in f for f in fams)

    def test_block_size_below_two_filtered(self):
        p = _pack(
            keywords=(_kw("BERLIN", "substitution"),),
            numeric_roles=(_num(1, "period"),),
            composition_templates=(_ct(("reverse_blocks", "vigenere"), max_layers=2),),
        )
        specs = compile_pack(p)
        assert specs == []


# ---------------------------------------------------------------------------
# Bounds + provenance
# ---------------------------------------------------------------------------


class TestBounds:
    def test_per_pack_max_specs_enforced(self):
        p = _pack(
            keywords=(_kw("BERLIN", "substitution"), _kw("CLOCK", "columnar")),
            composition_templates=(_ct(("vigenere", "columnar"), max_layers=2),),
            bounds=Bounds(max_specs=5),
        )
        specs = compile_pack(p)
        assert len(specs) <= 5

    def test_global_max_specs_enforced(self):
        # Two packs each emitting many specs; global cap < sum.
        p1 = _pack(
            pack_id="p1",
            keywords=(_kw("BERLIN", "substitution"), _kw("CLOCK", "columnar")),
            composition_templates=(_ct(("vigenere", "columnar"), max_layers=2),),
            bounds=Bounds(max_specs=200),
        )
        p2 = _pack(
            pack_id="p2",
            keywords=(_kw("OBSERVE", "substitution"), _kw("GARDEN", "columnar")),
            composition_templates=(_ct(("vigenere", "columnar"), max_layers=2),),
            bounds=Bounds(max_specs=200),
        )
        specs, _ = compile_packs([p1, p2], global_max_specs=20)
        assert len(specs) == 20


class TestProvenanceStamping:
    def test_pack_id_and_evidence_tier_in_extras(self):
        p = _pack(
            pack_id="audit-pack-X",
            evidence_tier="tier_2_derived_fact",
            keywords=(_kw("BERLIN", "substitution"), _kw("CLOCK", "columnar")),
            composition_templates=(_ct(("vigenere", "columnar"), max_layers=2),),
        )
        specs = compile_pack(p)
        assert specs
        for s in specs:
            extras = dict(s.coverage.extras)
            assert extras.get("pack_id") == "audit-pack-X"
            assert extras.get("evidence_tier") == "tier_2_derived_fact"


# ---------------------------------------------------------------------------
# Gating
# ---------------------------------------------------------------------------


class TestGating:
    def test_required_op_absent_from_template_skips_template(self):
        p = _pack(
            keywords=(_kw("BERLIN", "substitution"), _kw("CLOCK", "columnar")),
            operation_hints=(_op("rail_fence", "required"),),
            numeric_roles=(_num(3, "depth"),),
            # Template does NOT include rail_fence — must be skipped.
            composition_templates=(_ct(("vigenere", "columnar"), max_layers=2),),
        )
        specs = compile_pack(p)
        assert specs == []

    def test_unknown_template_layer_kinds_skipped(self):
        # 'unknown' is in OPERATION_KINDS but no routing exists for it
        p = _pack(
            keywords=(_kw("BERLIN", "substitution"),),
            composition_templates=(_ct(("unknown",), max_layers=1),),
        )
        specs = compile_pack(p)
        assert specs == []

    def test_no_template_means_no_specs(self):
        p = _pack(
            keywords=(_kw("BERLIN", "substitution"),),
            composition_templates=(),
        )
        specs = compile_pack(p)
        assert specs == []


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestValidation:
    def test_invalid_pack_raises_compile_error(self):
        # A pack with no roles fails validation; compile_pack must
        # raise.
        bad = PseudoCluePack(
            pack_id="bad",
            title="bad",
            hypothesis_summary="bad",
            provenance_items=(_prov(),),
            evidence_tier="tier_1_public_fact",
            keywords=(),
            numeric_roles=(),
            operation_hints=(),
        )
        with pytest.raises(CompileError):
            compile_pack(bad)

    def test_compile_packs_records_invalid_pack_in_summary(self):
        bad = PseudoCluePack(
            pack_id="bad",
            title="bad",
            hypothesis_summary="bad",
            provenance_items=(),
            evidence_tier="tier_1_public_fact",
            keywords=(_kw("BERLIN", "substitution"),),
        )
        good = _pack(
            keywords=(_kw("BERLIN", "substitution"), _kw("CLOCK", "columnar")),
            composition_templates=(_ct(("vigenere", "columnar"), max_layers=2),),
        )
        specs, summaries = compile_packs([bad, good], global_max_specs=200)
        assert any(s["pack_id"] == "bad" and s["validation_errors"] for s in summaries)
        assert any(s["pack_id"] == "t" and s["n_specs_retained"] > 0 for s in summaries)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_two_calls_identical(self):
        p = _pack(
            keywords=(_kw("BERLIN", "substitution"), _kw("CLOCK", "columnar")),
            numeric_roles=(_num(3, "depth"),),
            composition_templates=(
                _ct(("vigenere", "columnar"), max_layers=2),
                _ct(("vigenere", "columnar", "rail_fence")),
            ),
        )
        a = compile_pack(p)
        b = compile_pack(p)
        a_keys = [
            (s.coverage.layer_family,
             tuple(s.coverage.layer_order),
             s.coverage.substitution_keyword,
             s.coverage.transposition_keyword)
            for s in a
        ]
        b_keys = [
            (s.coverage.layer_family,
             tuple(s.coverage.layer_order),
             s.coverage.substitution_keyword,
             s.coverage.transposition_keyword)
            for s in b
        ]
        assert a_keys == b_keys
