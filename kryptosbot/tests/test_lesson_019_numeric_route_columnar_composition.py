"""LESSON-019: role-complete numeric-route-columnar three-layer
composition coverage tests.

Synthetic-clue tests only; no sealed-answer plaintext, no benchmark-
specific layer listings, no benchmark-specific keyword sets. The
clue strings are constructed to surface the role triple
(numeric Caesar candidate + route trigger + columnar keyword) using
generic vocabulary, not any specific bench challenge text.
"""

from __future__ import annotations

import pytest

from kryptosbot.hand_cipher_core import (
    GeneratedSpec,
    generate_layered_specs,
)
from kryptosbot.solver_capabilities import (
    LessonRegistry,
    _default_lessons,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


L019_FAMILIES = (
    "caesar_route_boustrophedon_columnar",
    "caesar_route_diagonal_columnar",
)


def _l019_specs(specs):
    return [
        s for s in specs
        if s.coverage.layer_family in L019_FAMILIES
    ]


def _gen(clue_words, clue_text, *, max_specs: int = 10000):
    return generate_layered_specs(
        clue_words,
        clue_text=clue_text,
        max_specs=max_specs,
        bench_slug="t",
    )


# Synthetic clues are deliberately generic — no benchmark-specific
# vocabulary. Each clue independently surfaces:
#   1. a numeric Caesar/ROT candidate (via tag/label/inscription
#      precursor + numeral),
#   2. a route trigger (boustrophedon: ragged grid + alternating
#      direction; diagonal: diagonal grid wording),
#   3. a columnar keyword (clue word with length >= 2).

DIAG_CLUE = (
    "A small tag says seventeen. A diagonal grid is crossed by "
    "alternating rows. The keyword KEYNAME is engraved nearby."
)
BOUSTRO_CLUE = (
    "A label says fifteen. A ragged eight-wide grid runs back and "
    "forth in a boustrophedon path. The keyword KEYNAME marks the "
    "edge."
)
ALL_TRIGGER_CLUE = (
    "A small tag says seventeen. A ragged grid runs back and forth "
    "in a boustrophedon path and a diagonal sweep crosses it. The "
    "keyword KEYNAME is inscribed."
)


# ---------------------------------------------------------------------------
# Role-gating: emit only when the full role triple is present
# ---------------------------------------------------------------------------


class TestRoleGating:
    def test_no_emission_without_numeric_role(self):
        # Diagonal trigger + columnar keyword present, but NO clue
        # numeral.
        clue = (
            "A diagonal grid is crossed by alternating rows. The "
            "keyword KEYNAME is engraved nearby."
        )
        specs = _gen(["KEYNAME", "ENGRAVED"], clue)
        l019 = _l019_specs(specs)
        assert l019 == [], (
            "LESSON-019 must not emit without a numeric Caesar "
            "candidate"
        )

    def test_no_emission_without_route_role(self):
        # Numeric tag + columnar keyword, NO route/grid trigger.
        clue = (
            "A small tag says seventeen. The keyword KEYNAME is "
            "engraved on the door."
        )
        specs = _gen(["KEYNAME", "TAG"], clue)
        l019 = _l019_specs(specs)
        assert l019 == [], (
            "LESSON-019 must not emit without a route/grid trigger"
        )

    def test_no_emission_without_columnar_keyword_role(self):
        # Single-character clue keyword (degenerate columnar). No
        # other usable keyword in the pool.
        clue = (
            "A small tag says seventeen. A diagonal grid is crossed "
            "by alternating rows."
        )
        specs = _gen(["A"], clue)
        l019 = _l019_specs(specs)
        assert l019 == [], (
            "LESSON-019 must not emit without a usable columnar "
            "keyword (length >= 2)"
        )

    def test_no_emission_when_explicit_caesar_trigger_fires(self):
        # Explicit Caesar trigger ("shift") suppresses the LESSON-018
        # numeric-promotion gate, which in turn suppresses LESSON-019.
        # The legacy explicit-Caesar path (LESSON-009) is responsible
        # for caesar+route compositions in this case.
        clue = (
            "Apply a shift of 17. A diagonal grid is crossed by "
            "alternating rows. The keyword KEYNAME is engraved."
        )
        specs = _gen(["KEYNAME", "TAG"], clue)
        l019 = _l019_specs(specs)
        assert l019 == [], (
            "LESSON-019 must not emit when the explicit Caesar "
            "trigger has already fired (LESSON-009 owns that path)"
        )


# ---------------------------------------------------------------------------
# Family emission: each route partner produces a populated family
# ---------------------------------------------------------------------------


class TestDiagonalFamilyEmission:
    def test_caesar_route_diagonal_columnar_emitted(self):
        specs = _gen(["KEYNAME", "TAG"], DIAG_CLUE)
        diag = [
            s for s in specs
            if s.coverage.layer_family == "caesar_route_diagonal_columnar"
        ]
        assert diag, "LESSON-019 diagonal family must emit"

    def test_diagonal_family_covers_all_six_layer_orders(self):
        specs = _gen(["KEYNAME", "TAG"], DIAG_CLUE)
        diag = [
            s for s in specs
            if s.coverage.layer_family == "caesar_route_diagonal_columnar"
        ]
        orders = {tuple(s.coverage.layer_order) for s in diag}
        expected = {
            ("caesar", "route_diagonal", "columnar"),
            ("caesar", "columnar", "route_diagonal"),
            ("route_diagonal", "caesar", "columnar"),
            ("route_diagonal", "columnar", "caesar"),
            ("columnar", "caesar", "route_diagonal"),
            ("columnar", "route_diagonal", "caesar"),
        }
        assert expected.issubset(orders), (
            f"LESSON-019 diagonal family missing layer orders: "
            f"{expected - orders}"
        )

    def test_diagonal_family_all_three_layers(self):
        specs = _gen(["KEYNAME", "TAG"], DIAG_CLUE)
        diag = [
            s for s in specs
            if s.coverage.layer_family == "caesar_route_diagonal_columnar"
        ]
        for s in diag:
            assert s.coverage.n_layers == 3
            assert len(s.coverage.layer_order) == 3
            assert {"caesar", "route_diagonal", "columnar"} == (
                set(s.coverage.layer_order)
            )


class TestBoustrophedonFamilyEmission:
    def test_caesar_route_boustrophedon_columnar_emitted(self):
        specs = _gen(["KEYNAME", "TAG"], BOUSTRO_CLUE)
        rb = [
            s for s in specs
            if s.coverage.layer_family ==
            "caesar_route_boustrophedon_columnar"
        ]
        assert rb, "LESSON-019 boustrophedon family must emit"

    def test_boustrophedon_family_covers_all_six_layer_orders(self):
        specs = _gen(["KEYNAME", "TAG"], BOUSTRO_CLUE)
        rb = [
            s for s in specs
            if s.coverage.layer_family ==
            "caesar_route_boustrophedon_columnar"
        ]
        orders = {tuple(s.coverage.layer_order) for s in rb}
        expected = {
            ("caesar", "route_boustrophedon", "columnar"),
            ("caesar", "columnar", "route_boustrophedon"),
            ("route_boustrophedon", "caesar", "columnar"),
            ("route_boustrophedon", "columnar", "caesar"),
            ("columnar", "caesar", "route_boustrophedon"),
            ("columnar", "route_boustrophedon", "caesar"),
        }
        assert expected.issubset(orders), (
            f"LESSON-019 boustrophedon family missing layer orders: "
            f"{expected - orders}"
        )


class TestBothPartnersEmitTogether:
    def test_dual_trigger_clue_emits_both_route_partners(self):
        specs = _gen(["KEYNAME", "TAG"], ALL_TRIGGER_CLUE)
        rb = [
            s for s in specs
            if s.coverage.layer_family ==
            "caesar_route_boustrophedon_columnar"
        ]
        diag = [
            s for s in specs
            if s.coverage.layer_family == "caesar_route_diagonal_columnar"
        ]
        assert rb and diag, (
            "Both LESSON-019 families must emit when both route "
            "triggers fire alongside numeric + columnar roles"
        )


# ---------------------------------------------------------------------------
# Parameter sources
# ---------------------------------------------------------------------------


class TestParameterSources:
    def test_shift_value_comes_from_lesson_018_promotion(self):
        # "tag says seventeen" → LESSON-018 promotes 17 (free_numeric_tag)
        # plus complement 9.
        specs = _gen(["KEYNAME", "TAG"], DIAG_CLUE)
        diag = [
            s for s in specs
            if s.coverage.layer_family == "caesar_route_diagonal_columnar"
        ]
        shift_values = {s.coverage.shift_value for s in diag}
        assert 17 in shift_values
        assert 9 in shift_values  # complement
        # No identity / self-complement entries.
        assert 0 not in shift_values
        assert 13 not in shift_values

    def test_shift_telemetry_carries_lesson_018_role(self):
        specs = _gen(["KEYNAME", "TAG"], DIAG_CLUE)
        diag = [
            s for s in specs
            if s.coverage.layer_family == "caesar_route_diagonal_columnar"
        ]
        for s in diag:
            assert s.coverage.shift_role in (
                "free_numeric_tag", "ambiguous_numeric",
                "explicit_caesar",
            )
            assert s.coverage.shift_source in (
                "clue_numeric_tag", "clue_numeric_free",
                "explicit_caesar_token",
            )
            assert s.coverage.shift_direction in (
                "as_given", "complement",
            )
            assert s.coverage.shift_token  # non-empty
            assert s.coverage.numeric_trigger_without_caesar_word is True

    def test_route_telemetry_present(self):
        specs = _gen(["KEYNAME", "TAG"], BOUSTRO_CLUE)
        rb = [
            s for s in specs
            if s.coverage.layer_family ==
            "caesar_route_boustrophedon_columnar"
        ]
        for s in rb:
            assert s.coverage.route_mode == "route_boustrophedon"
            assert isinstance(s.coverage.route_width, int)
            assert isinstance(s.coverage.route_rows, int)
            assert isinstance(s.coverage.route_cols, int)
            assert s.coverage.route_width_source in (
                "phrase_bound_route_width",
                "clue_keyword_length",
                "default_set",
            )

    def test_route_diagonal_telemetry_present(self):
        specs = _gen(["KEYNAME", "TAG"], DIAG_CLUE)
        diag = [
            s for s in specs
            if s.coverage.layer_family == "caesar_route_diagonal_columnar"
        ]
        for s in diag:
            assert s.coverage.route_mode == "route_diagonal"
            assert isinstance(s.coverage.route_width, int)
            assert isinstance(s.coverage.route_rows, int)
            assert isinstance(s.coverage.route_cols, int)
            assert s.coverage.diagonal_axis in ("main", "anti")
            assert s.coverage.diagonal_order in ("forward", "reverse")

    def test_columnar_keyword_comes_from_clue_pool(self):
        specs = _gen(["KEYNAME", "TAG"], DIAG_CLUE)
        diag = [
            s for s in specs
            if s.coverage.layer_family == "caesar_route_diagonal_columnar"
        ]
        kws = {s.coverage.transposition_keyword for s in diag}
        # Both clue keywords (length >= 2) should appear.
        assert "KEYNAME" in kws
        assert "TAG" in kws
        for s in diag:
            assert s.coverage.col_order_source == "clue_keyword"
            assert isinstance(s.coverage.col_order, tuple)
            assert len(s.coverage.col_order) >= 2


# ---------------------------------------------------------------------------
# CoverageVector telemetry
# ---------------------------------------------------------------------------


class TestCoverageTelemetry:
    REQUIRED_FIELDS = (
        "layer_family",
        "layer_order",
        "shift_value",
        "shift_source",
        "shift_role",
        "shift_token",
        "shift_direction",
        "route_mode",
        "route_width",
        "route_rows",
        "route_cols",
        "route_width_source",
        "transposition_keyword",
        "col_order",
        "col_order_source",
        "role_assignment",
        "role_assignment_mode",
        "operation_source",
        "scheduling_pass",
        "family_quota",
        "hcc_max_specs",
    )

    def test_all_required_telemetry_present(self):
        specs = _gen(["KEYNAME", "TAG"], DIAG_CLUE)
        for s in _l019_specs(specs):
            for field in self.REQUIRED_FIELDS:
                value = getattr(s.coverage, field, None)
                assert value not in (None, "", ()), (
                    f"LESSON-019 spec {s.hypothesis_id[:48]} missing "
                    f"required telemetry field {field!r}"
                )

    def test_role_assignment_mode_is_three_role(self):
        specs = _gen(["KEYNAME", "TAG"], ALL_TRIGGER_CLUE)
        for s in _l019_specs(specs):
            assert s.coverage.role_assignment_mode == (
                "numeric_route_columnar_three_role"
            )

    def test_operation_source_is_composition(self):
        specs = _gen(["KEYNAME", "TAG"], ALL_TRIGGER_CLUE)
        for s in _l019_specs(specs):
            assert s.coverage.operation_source == (
                "numeric_route_columnar_composition"
            )

    def test_role_assignment_carries_all_three_roles(self):
        specs = _gen(["KEYNAME", "TAG"], DIAG_CLUE)
        diag = [
            s for s in specs
            if s.coverage.layer_family == "caesar_route_diagonal_columnar"
        ]
        for s in diag:
            roles = dict(s.coverage.role_assignment)
            assert "caesar_shift" in roles
            assert "columnar" in roles
            assert "route_diagonal" in roles


# ---------------------------------------------------------------------------
# Structural-numeric blocking
# ---------------------------------------------------------------------------


class TestStructuralNumericBlocking:
    def test_object_count_does_not_become_caesar(self):
        # "five stones" — 5 is object_count; "tag says seventeen" —
        # 17 is free_numeric_tag (eligible). Only 17 (and complement)
        # should appear as shift_value.
        clue = (
            "Five stones line the path. A small tag says seventeen. "
            "A diagonal grid is crossed by alternating rows. The "
            "keyword KEYNAME is engraved."
        )
        specs = _gen(["KEYNAME", "TAG"], clue)
        diag = [
            s for s in specs
            if s.coverage.layer_family == "caesar_route_diagonal_columnar"
        ]
        shifts = {s.coverage.shift_value for s in diag}
        assert 5 not in shifts, (
            "object_count numeral 5 must not be promoted to a "
            "Caesar shift"
        )
        assert 17 in shifts

    def test_structural_route_width_does_not_become_caesar(self):
        # "ten-wide" — 10 binds to route_width (LESSON-018 hyphen-
        # suffix structural binding). "tag says seventeen" — 17 is
        # free_numeric_tag.
        clue = (
            "A ragged ten-wide grid runs back and forth in a "
            "boustrophedon path. A small tag says seventeen. The "
            "keyword KEYNAME is inscribed."
        )
        specs = _gen(["KEYNAME", "TAG"], clue)
        rb = [
            s for s in specs
            if s.coverage.layer_family ==
            "caesar_route_boustrophedon_columnar"
        ]
        shifts = {s.coverage.shift_value for s in rb}
        assert 10 not in shifts, (
            "route_width numeral 10 must not be promoted to a "
            "Caesar shift"
        )
        assert 17 in shifts


# ---------------------------------------------------------------------------
# Scheduler compatibility
# ---------------------------------------------------------------------------


class TestSchedulerCompatibility:
    def test_lesson_019_specs_carry_scheduling_telemetry(self):
        specs = _gen(["KEYNAME", "TAG"], DIAG_CLUE)
        for s in _l019_specs(specs):
            assert s.coverage.scheduling_pass in ("quota", "residual")
            assert s.coverage.family_quota == 40
            assert isinstance(s.coverage.family_quota_rank, int)
            assert s.coverage.hcc_max_specs == 10000

    def test_lesson_019_survives_constrained_cap(self):
        # Even at a tight cap, the role-complete composition must
        # land at least one spec per family. The LESSON-017
        # scheduler's quota pass walks emission order, so LESSON-019
        # must be emitted before the cap is exhausted by upstream
        # families.
        specs = _gen(["KEYNAME", "TAG"], DIAG_CLUE, max_specs=8000)
        l019 = _l019_specs(specs)
        assert l019, (
            "LESSON-019 specs must survive a constrained 8000-spec "
            "cap under K4B-009-shape multi-trigger clues"
        )

    def test_per_family_quota_caps_at_40(self):
        specs = _gen(["KEYNAME", "TAG"], ALL_TRIGGER_CLUE)
        rb = [
            s for s in specs
            if s.coverage.layer_family ==
            "caesar_route_boustrophedon_columnar"
        ]
        diag = [
            s for s in specs
            if s.coverage.layer_family == "caesar_route_diagonal_columnar"
        ]
        # Quota=40 per family in the quota pass. Residual fill may
        # add more, but quota-pass count per family is bounded.
        rb_quota = [s for s in rb if s.coverage.scheduling_pass == "quota"]
        diag_quota = [
            s for s in diag if s.coverage.scheduling_pass == "quota"
        ]
        assert len(rb_quota) <= 40
        assert len(diag_quota) <= 40


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_two_runs_produce_identical_lesson_019_specs(self):
        a = _gen(["KEYNAME", "TAG"], ALL_TRIGGER_CLUE)
        b = _gen(["KEYNAME", "TAG"], ALL_TRIGGER_CLUE)
        a_l019 = [
            (s.coverage.layer_family, tuple(s.coverage.layer_order),
             s.coverage.shift_value, s.coverage.transposition_keyword,
             s.coverage.route_width, s.coverage.shift_direction)
            for s in _l019_specs(a)
        ]
        b_l019 = [
            (s.coverage.layer_family, tuple(s.coverage.layer_order),
             s.coverage.shift_value, s.coverage.transposition_keyword,
             s.coverage.route_width, s.coverage.shift_direction)
            for s in _l019_specs(b)
        ]
        assert a_l019 == b_l019


# ---------------------------------------------------------------------------
# Lesson registry
# ---------------------------------------------------------------------------


class TestLessonRegistry:
    def test_lesson_019_in_default_set(self):
        ids = {l.lesson_id for l in _default_lessons()}
        assert "LESSON-019" in ids

    def test_lesson_019_metadata(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-019"]
        assert l.tactic_kind == (
            "numeric_route_columnar_three_layer_composition"
        )
        assert "caesar_route_boustrophedon_columnar" in (
            l.applies_to_families
        )
        assert "caesar_route_diagonal_columnar" in (
            l.applies_to_families
        )
        assert l.generates_specs is True
        params = l.tactic_parameters
        assert params["scheduler_quota_class"] == "three_layer_sandwich"
        assert params["no_new_primitive"] is True
        assert params["bench_only"] is True


# ---------------------------------------------------------------------------
# Real-K4 mode unaffected
# ---------------------------------------------------------------------------


class TestRealK4Unchanged:
    def test_real_k4_collect_hcc_seeds_returns_empty(self, tmp_path):
        # HCC is bench-mode only via the controller's
        # ``_collect_hcc_seeds`` path. Confirm the real-K4 path
        # returns no seeds even though LESSON-019 has been added —
        # the lesson is generalized capability for bench, not real-K4.
        from kryptosbot.controller import (
            ControllerConfig, ResearchController,
        )
        cfg = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "real_k4_ledger.sqlite",
            max_cycles=1, theories_per_cycle=5, dry_run=True,
        )
        controller = ResearchController(cfg)
        controller.state = controller.ledger.load_controller_state()
        controller._snapshot_session_baseline()
        assert controller._collect_hcc_seeds() == []
