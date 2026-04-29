"""LESSON-021: canonical width-only diagonal route alias tests.

Pinned properties:

  1. Kernel ``canonical_diagonal_perm(width, length)`` is length-
     preserving, bijective, and equivalent to a fixed
     ``diagonal_perm`` call (axis="anti", order="forward",
     start_edge="top_then_right", cell_order="forward").
  2. Dispatcher route variant="diagonal_canonical" accepts a
     width-only binding; rows/cols are inferred. Invalid width
     fails closed.
  3. HCC emits a standalone ``route_diagonal_canonical`` family
     when a diagonal trigger is present.
  4. HCC emits ``caesar_route_diagonal_canonical_columnar`` when
     the LESSON-019 role triple (numeric Caesar + diagonal route +
     columnar keyword) fires.
  5. CoverageVector telemetry: route_mode, diagonal_canonical
     pinned values, route_width_source preserved.
  6. Backward compatibility: existing route variant="diagonal"
     with explicit axis/order/start_edge/cell_order continues to
     dispatch unchanged.

No sealed-answer plaintext, no benchmark-specific layer listings,
no benchmark-specific keyword sets.
"""

from __future__ import annotations

import pytest

from kryptos.kernel.transforms.transposition import (
    apply_perm,
    canonical_diagonal_perm,
    diagonal_perm,
    invert_perm,
)
from kryptosbot.hand_cipher_core import (
    generate_layered_specs,
)
from kryptosbot.hypothesis_dsl import CipherLayer, ParamRange
from kryptosbot.job_dispatcher import (
    DispatcherError,
    _translate_layer,
)
from kryptosbot.solver_capabilities import _default_lessons


# ---------------------------------------------------------------------------
# 1. Kernel tests
# ---------------------------------------------------------------------------


class TestKernelCanonicalDiagonal:
    def test_canonical_equals_explicit_anti_forward_top_then_right(self):
        # The canonical convention pins anti/forward/top_then_right/forward.
        canon = canonical_diagonal_perm(10, 97)
        explicit = diagonal_perm(
            10, 10, 97,
            axis="anti", order="forward",
            start_edge="top_then_right",
            cell_order="forward",
        )
        assert canon == explicit

    def test_canonical_length_preserving(self):
        for w in (3, 7, 10, 12, 14, 16):
            p = canonical_diagonal_perm(w, 97)
            assert len(p) == 97, w

    def test_canonical_bijective(self):
        for w in (3, 7, 10, 12, 14, 16):
            p = canonical_diagonal_perm(w, 97)
            assert sorted(p) == list(range(97)), w

    def test_canonical_3x3_toy_grid(self):
        # 3x3 length=9 anti forward top_then_right forward:
        #   d=0 (0,0) -> [0]
        #   d=1 (0,1),(1,0) -> [1,3]
        #   d=2 (0,2),(1,1),(2,0) -> [2,4,6]
        #   d=3 (1,2),(2,1) -> [5,7]
        #   d=4 (2,2) -> [8]
        p = canonical_diagonal_perm(3, 9)
        assert p == [0, 1, 3, 2, 4, 6, 5, 7, 8]

    def test_canonical_round_trip(self):
        from string import ascii_uppercase
        text = (ascii_uppercase * 4)[:97]
        p = canonical_diagonal_perm(10, 97)
        permuted = apply_perm(text, p)
        recovered = apply_perm(permuted, invert_perm(p))
        assert recovered == text

    def test_canonical_invalid_width_raises(self):
        with pytest.raises(ValueError, match="width"):
            canonical_diagonal_perm(0, 97)
        with pytest.raises(ValueError, match="width"):
            canonical_diagonal_perm(-1, 97)
        with pytest.raises(ValueError, match="width"):
            canonical_diagonal_perm("ten", 97)  # type: ignore[arg-type]

    def test_canonical_handles_ragged_width_10(self):
        # rows = ceil(97/10) = 10, total cells 100, ragged 3.
        p = canonical_diagonal_perm(10, 97)
        assert len(p) == 97
        assert max(p) == 96
        assert sorted(p) == list(range(97))


# ---------------------------------------------------------------------------
# 2. Dispatcher tests
# ---------------------------------------------------------------------------


def _canonical_layer(width):
    cl = CipherLayer(kind="route", alphabet="AZ", params=[
        ParamRange(name="variant", values=["diagonal_canonical"]),
        ParamRange(name="width", values=[width]),
    ])
    return cl, {"variant": "diagonal_canonical", "width": width}


class TestDispatcherCanonicalDiagonal:
    def test_canonical_dispatches(self):
        layer, binding = _canonical_layer(10)
        step = _translate_layer(layer, binding)
        assert step["type"] == "transposition_full"
        perm = step["params"]["perm"]
        assert len(perm) == 97
        assert sorted(perm) == list(range(97))

    def test_canonical_matches_kernel_helper(self):
        layer, binding = _canonical_layer(10)
        step = _translate_layer(layer, binding)
        assert step["params"]["perm"] == canonical_diagonal_perm(10, 97)

    def test_canonical_invalid_width_rejects(self):
        layer, binding = _canonical_layer(0)
        with pytest.raises(DispatcherError, match="width"):
            _translate_layer(layer, binding)

    def test_canonical_negative_width_rejects(self):
        layer, binding = _canonical_layer(-1)
        with pytest.raises(DispatcherError, match="width"):
            _translate_layer(layer, binding)

    def test_unknown_variant_still_rejects(self):
        cl = CipherLayer(kind="route", alphabet="AZ", params=[
            ParamRange(name="variant", values=["zigzag"]),
            ParamRange(name="width", values=[10]),
        ])
        with pytest.raises(DispatcherError, match="variant"):
            _translate_layer(cl, {"variant": "zigzag", "width": 10})

    def test_existing_diagonal_variant_unaffected(self):
        # route variant="diagonal" with explicit axis/order/start_edge
        # must still dispatch correctly.
        cl = CipherLayer(kind="route", alphabet="AZ", params=[
            ParamRange(name="variant", values=["diagonal"]),
            ParamRange(name="rows", values=[10]),
            ParamRange(name="cols", values=[10]),
            ParamRange(name="diagonal_axis", values=["main"]),
            ParamRange(name="diagonal_order", values=["forward"]),
            ParamRange(name="diagonal_start_edge", values=["top_then_left"]),
        ])
        binding = {
            "variant": "diagonal", "rows": 10, "cols": 10,
            "diagonal_axis": "main", "diagonal_order": "forward",
            "diagonal_start_edge": "top_then_left",
        }
        step = _translate_layer(cl, binding)
        assert len(step["params"]["perm"]) == 97


# ---------------------------------------------------------------------------
# 3. HCC tests
# ---------------------------------------------------------------------------


def _gen(clue_words, clue_text, *, max_specs: int = 10000):
    return generate_layered_specs(
        clue_words,
        clue_text=clue_text,
        max_specs=max_specs,
        bench_slug="t",
    )


DIAG_CLUE = (
    "A diagonal grid is crossed by alternating rows. The keyword "
    "KEYNAME is engraved nearby."
)
DIAG_TEN_WIDE_CLUE = (
    "A small tag says seventeen. A ten-wide diagonal grid is "
    "crossed. The keyword KEYNAME is engraved."
)
ROLE_TRIPLE_CLUE = (
    "A small tag says seventeen. A diagonal grid is crossed by "
    "alternating rows. The keyword KEYNAME is engraved."
)
NO_DIAGONAL_CLUE = (
    "A small tag says seventeen. The keyword KEYNAME is engraved "
    "on the door."
)
NO_NUMERIC_CLUE = (
    "A diagonal grid is crossed. The keyword KEYNAME is engraved."
)


class TestHCCStandaloneCanonical:
    def test_diagonal_clue_emits_standalone_canonical(self):
        specs = _gen(["KEYNAME", "TAG"], DIAG_CLUE)
        canon = [
            s for s in specs
            if s.coverage.layer_family == "route_diagonal_canonical"
        ]
        assert canon, "diagonal clue must emit standalone canonical"

    def test_ten_wide_clue_emits_canonical_width_10(self):
        specs = _gen(["KEYNAME", "TAG"], DIAG_TEN_WIDE_CLUE)
        canon = [
            s for s in specs
            if s.coverage.layer_family == "route_diagonal_canonical"
        ]
        widths = {(s.coverage.route_width, s.coverage.route_width_source)
                  for s in canon}
        assert (10, "phrase_bound_route_width") in widths, (
            f"width=10 phrase-bound canonical must appear; got {widths}"
        )

    def test_canonical_carries_full_telemetry(self):
        specs = _gen(["KEYNAME", "TAG"], DIAG_TEN_WIDE_CLUE)
        canon = [
            s for s in specs
            if s.coverage.layer_family == "route_diagonal_canonical"
        ]
        assert canon
        for s in canon:
            cv = s.coverage
            assert cv.route_mode == "route_diagonal_canonical"
            assert isinstance(cv.route_width, int) and cv.route_width >= 3
            assert isinstance(cv.route_rows, int) and cv.route_rows >= 1
            assert isinstance(cv.route_cols, int) and cv.route_cols >= 1
            assert cv.route_width_source in (
                "phrase_bound_route_width", "default_set",
            )
            assert cv.diagonal_axis == "anti"
            assert cv.diagonal_order == "forward"
            assert cv.diagonal_start_edge == "top_then_right"
            assert cv.diagonal_cell_order == "forward"
            assert cv.operation_source == "canonical_diagonal_width"
            assert cv.scheduling_pass in ("quota", "residual")


class TestHCCLesson019Canonical:
    def test_role_triple_emits_canonical_three_layer(self):
        specs = _gen(["KEYNAME", "TAG"], ROLE_TRIPLE_CLUE)
        l021 = [
            s for s in specs
            if s.coverage.layer_family ==
            "caesar_route_diagonal_canonical_columnar"
        ]
        assert l021, "role triple must emit LESSON-021 canonical L019"

    def test_canonical_three_layer_covers_layer_orders(self):
        specs = _gen(["KEYNAME", "TAG"], ROLE_TRIPLE_CLUE)
        l021 = [
            s for s in specs
            if s.coverage.layer_family ==
            "caesar_route_diagonal_canonical_columnar"
        ]
        orders = {tuple(s.coverage.layer_order) for s in l021}
        # Same six layer-order permutations as LESSON-019 explicit
        # diagonal partner.
        expected = {
            ("caesar", "route_diagonal_canonical", "columnar"),
            ("caesar", "columnar", "route_diagonal_canonical"),
            ("route_diagonal_canonical", "caesar", "columnar"),
            ("route_diagonal_canonical", "columnar", "caesar"),
            ("columnar", "caesar", "route_diagonal_canonical"),
            ("columnar", "route_diagonal_canonical", "caesar"),
        }
        # At least four of the six must be retained under the
        # LESSON-017 quota=40 cap; the ten-wide variant typically
        # populates all six but cap pressure can drop one or two.
        intersect = expected & orders
        assert len(intersect) >= 4, (
            f"need >=4/6 layer orders, got {len(intersect)}: {orders}"
        )

    def test_canonical_three_layer_telemetry(self):
        specs = _gen(["KEYNAME", "TAG"], DIAG_TEN_WIDE_CLUE)
        l021 = [
            s for s in specs
            if s.coverage.layer_family ==
            "caesar_route_diagonal_canonical_columnar"
        ]
        assert l021
        for s in l021:
            cv = s.coverage
            assert cv.route_mode == "route_diagonal_canonical"
            assert cv.diagonal_axis == "anti"
            assert cv.diagonal_order == "forward"
            assert cv.diagonal_start_edge == "top_then_right"
            assert cv.diagonal_cell_order == "forward"
            assert cv.role_assignment_mode == (
                "numeric_route_columnar_three_role"
            )
            assert cv.operation_source == (
                "numeric_route_columnar_composition"
            )
            assert cv.shift_value in (17, 9)
            assert cv.shift_direction in ("as_given", "complement")
            assert cv.transposition_keyword
            assert cv.col_order_source == "clue_keyword"

    def test_canonical_three_layer_phrase_bound_width_dominates(self):
        # When a clue says "ten-wide diagonal" the canonical L019
        # cross-product should include width=10 with phrase_bound
        # provenance.
        specs = _gen(["KEYNAME", "TAG"], DIAG_TEN_WIDE_CLUE)
        l021 = [
            s for s in specs
            if s.coverage.layer_family ==
            "caesar_route_diagonal_canonical_columnar"
        ]
        widths = {(s.coverage.route_width, s.coverage.route_width_source)
                  for s in l021}
        assert (10, "phrase_bound_route_width") in widths

    def test_canonical_three_layer_survives_constrained_cap(self):
        specs = _gen(["KEYNAME", "TAG"], ROLE_TRIPLE_CLUE, max_specs=8000)
        l021 = [
            s for s in specs
            if s.coverage.layer_family ==
            "caesar_route_diagonal_canonical_columnar"
        ]
        assert l021, (
            "LESSON-021 canonical three-layer must survive "
            "constrained 8000-spec cap"
        )


# ---------------------------------------------------------------------------
# 4. Negative tests
# ---------------------------------------------------------------------------


class TestNegative:
    def test_no_canonical_when_no_diagonal_trigger(self):
        specs = _gen(["KEYNAME", "TAG"], NO_DIAGONAL_CLUE)
        canon = [
            s for s in specs
            if s.coverage.layer_family.startswith("route_diagonal_canonical")
            or s.coverage.layer_family ==
            "caesar_route_diagonal_canonical_columnar"
        ]
        assert canon == [], (
            "canonical diagonal must not emit without a diagonal "
            "trigger"
        )

    def test_no_l021_three_layer_without_numeric_role(self):
        specs = _gen(["KEYNAME", "TAG"], NO_NUMERIC_CLUE)
        l021 = [
            s for s in specs
            if s.coverage.layer_family ==
            "caesar_route_diagonal_canonical_columnar"
        ]
        assert l021 == [], (
            "no LESSON-021 three-layer family without numeric Caesar "
            "promotion"
        )

    def test_no_l021_three_layer_without_columnar_keyword(self):
        # A clue with single-character "keywords" only — degenerate
        # for a columnar layer (length < 2).
        clue = (
            "A small tag says seventeen. A diagonal grid is crossed "
            "by alternating rows."
        )
        specs = _gen(["A"], clue)
        l021 = [
            s for s in specs
            if s.coverage.layer_family ==
            "caesar_route_diagonal_canonical_columnar"
        ]
        assert l021 == [], (
            "no LESSON-021 three-layer family without a usable "
            "columnar keyword"
        )


# ---------------------------------------------------------------------------
# 5. Existing tests must still pass — sample regression
# ---------------------------------------------------------------------------


class TestExistingDiagonalUnchanged:
    def test_explicit_diagonal_still_emits(self):
        # LESSON-016/-020 explicit-axis diagonal families must still
        # emit alongside the canonical alias.
        specs = _gen(["KEYNAME", "TAG"], DIAG_CLUE)
        explicit = [
            s for s in specs
            if s.coverage.layer_family in (
                "route_diagonal",
                "route_diagonal_vigenere",
                "route_diagonal_beaufort",
                "route_diagonal_variant_beaufort",
                "route_diagonal_rail_fence",
            )
        ]
        assert explicit, "LESSON-016 explicit diagonal must still emit"

    def test_lesson_020_cell_order_telemetry_intact(self):
        specs = _gen(["KEYNAME", "TAG"], DIAG_CLUE)
        explicit = [
            s for s in specs
            if s.coverage.layer_family.startswith("route_diagonal_")
            and s.coverage.layer_family != "route_diagonal_canonical"
        ]
        cell_orders = {s.coverage.diagonal_cell_order for s in explicit}
        assert "forward" in cell_orders
        assert "reverse" in cell_orders


# ---------------------------------------------------------------------------
# 6. Lesson registry
# ---------------------------------------------------------------------------


class TestLessonRegistry:
    def test_lesson_021_in_default_set(self):
        ids = {l.lesson_id for l in _default_lessons()}
        assert "LESSON-021" in ids

    def test_lesson_021_metadata(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-021"]
        assert "canonical" in l.title.lower()
        params = l.tactic_parameters
        assert params["no_new_primitive"] is True
        assert params["bench_only"] is True
        assert params["canonical_axis"] == "anti"
        assert params["canonical_order"] == "forward"
        assert params["canonical_start_edge"] == "top_then_right"
        assert params["canonical_cell_order"] == "forward"


# ---------------------------------------------------------------------------
# 7. Real-K4 mode unchanged
# ---------------------------------------------------------------------------


class TestRealK4Unchanged:
    def test_real_k4_collect_hcc_seeds_returns_empty(self, tmp_path):
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
