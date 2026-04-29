"""LESSON-020: diagonal route semantic completeness tests.

Pinned properties:

  1. Kernel diagonal_perm: cell_order parameter accepts forward /
     reverse / alternate; forward (default) preserves pre-LESSON-020
     behavior bit-for-bit; reverse and alternate produce distinct
     bijections; ragged grids stay length-preserving.
  2. Dispatcher route variant=diagonal accepts diagonal_cell_order;
     omitted defaults to forward; invalid values fail closed.
  3. HCC LESSON-016 + LESSON-019 generators emit both forward and
     reverse cell-order variants under diagonal triggers.
  4. CoverageVector carries diagonal_cell_order on every diagonal
     spec.
  5. LESSON-019 caesar_route_diagonal_columnar specs survive the
     stratified scheduler under both cell orders.
  6. Existing route_boustrophedon / row_reverse / reverse_blocks /
     columnar / numeric Caesar promotion behavior is unchanged.

No sealed-answer plaintext, no benchmark-specific layer listings,
no benchmark-specific keyword sets.
"""

from __future__ import annotations

import pytest

from kryptos.kernel.transforms.transposition import (
    apply_perm,
    diagonal_perm,
    invert_perm,
)
from kryptosbot.hand_cipher_core import (
    generate_layered_specs,
)
from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
from kryptosbot.job_dispatcher import (
    DispatcherError,
    _translate_layer,
)
from kryptosbot.solver_capabilities import _default_lessons


# ---------------------------------------------------------------------------
# 1. Kernel primitive tests
# ---------------------------------------------------------------------------


class TestKernelDiagonalCellOrder:
    def test_forward_default_matches_explicit_forward(self):
        # Omitting cell_order must give identical output to passing
        # cell_order="forward" — backward compatibility contract.
        a = diagonal_perm(
            3, 3, 9, axis="main", order="forward",
            start_edge="top_then_left",
        )
        b = diagonal_perm(
            3, 3, 9, axis="main", order="forward",
            start_edge="top_then_left", cell_order="forward",
        )
        assert a == b

    def test_forward_3x3_main_top_then_left(self):
        # Pin the canonical 3x3 main-forward-top_then_left sequence
        # so any future kernel change has to update this assertion.
        p = diagonal_perm(
            3, 3, 9, axis="main", order="forward",
            start_edge="top_then_left", cell_order="forward",
        )
        assert p == [2, 1, 5, 0, 4, 8, 3, 7, 6]

    def test_reverse_differs_from_forward(self):
        fwd = diagonal_perm(
            3, 3, 9, axis="main", order="forward",
            start_edge="top_then_left", cell_order="forward",
        )
        rev = diagonal_perm(
            3, 3, 9, axis="main", order="forward",
            start_edge="top_then_left", cell_order="reverse",
        )
        assert fwd != rev
        # Both are bijections on [0, 9).
        assert sorted(fwd) == list(range(9))
        assert sorted(rev) == list(range(9))

    def test_reverse_reverses_cells_within_each_diagonal(self):
        # 3x3 main forward top_then_left:
        #   diagonals = [
        #     [(0,2)],          # cells already singleton
        #     [(0,1),(1,2)],
        #     [(0,0),(1,1),(2,2)],
        #     [(1,0),(2,1)],
        #     [(2,0)],
        #   ]
        # forward perm = [2,1,5,0,4,8,3,7,6]
        # reverse reverses each diagonal's cells (singletons unchanged):
        #   [2, 5,1, 8,4,0, 7,3, 6]
        rev = diagonal_perm(
            3, 3, 9, axis="main", order="forward",
            start_edge="top_then_left", cell_order="reverse",
        )
        assert rev == [2, 5, 1, 8, 4, 0, 7, 3, 6]

    def test_alternate_3x3(self):
        # alternate: even-index diagonals forward, odd-index reversed.
        # diag 0 [(0,2)] -> [2]
        # diag 1 [(0,1),(1,2)] reversed -> [5,1]
        # diag 2 [(0,0),(1,1),(2,2)] forward -> [0,4,8]
        # diag 3 [(1,0),(2,1)] reversed -> [7,3]
        # diag 4 [(2,0)] -> [6]
        alt = diagonal_perm(
            3, 3, 9, axis="main", order="forward",
            start_edge="top_then_left", cell_order="alternate",
        )
        assert alt == [2, 5, 1, 0, 4, 8, 7, 3, 6]

    def test_ragged_97_grid_remains_bijection(self):
        # 10x10 anti, both cell_orders, length=97 ragged.
        for cell_order in ("forward", "reverse", "alternate"):
            p = diagonal_perm(
                10, 10, 97, axis="anti", order="forward",
                start_edge="top_then_right", cell_order=cell_order,
            )
            assert len(p) == 97, cell_order
            assert len(set(p)) == 97, cell_order
            assert min(p) == 0, cell_order
            assert max(p) == 96, cell_order

    def test_round_trip_apply_invert(self):
        # apply_perm operates on text; use a 97-char A-Z string and
        # check round-trip recovery.
        from string import ascii_uppercase
        text = (ascii_uppercase * 4)[:97]
        p = diagonal_perm(
            10, 10, 97, axis="anti", order="reverse",
            start_edge="top_then_right", cell_order="reverse",
        )
        permuted = apply_perm(text, p)
        recovered = apply_perm(permuted, invert_perm(p))
        assert recovered == text

    def test_unknown_cell_order_raises(self):
        with pytest.raises(ValueError, match="cell_order"):
            diagonal_perm(
                3, 3, 9, axis="main", order="forward",
                start_edge="top_then_left", cell_order="zigzag",
            )

    def test_anti_axis_cell_order_distinct_permutations(self):
        a = diagonal_perm(
            10, 10, 97, axis="anti", order="forward",
            start_edge="top_then_right", cell_order="forward",
        )
        b = diagonal_perm(
            10, 10, 97, axis="anti", order="forward",
            start_edge="top_then_right", cell_order="reverse",
        )
        c = diagonal_perm(
            10, 10, 97, axis="anti", order="forward",
            start_edge="top_then_right", cell_order="alternate",
        )
        assert a != b
        assert a != c
        assert b != c


# ---------------------------------------------------------------------------
# 2. Dispatcher tests
# ---------------------------------------------------------------------------


def _make_route_layer(
    rows: int, cols: int, *,
    axis: str, order: str, start_edge: str,
    cell_order=None,
):
    """Build a route layer dict + minimal binding dict for
    ``_translate_layer`` smoke tests."""
    from kryptosbot.hypothesis_dsl import CipherLayer, ParamRange
    params = [
        ParamRange(name="variant", values=["diagonal"]),
        ParamRange(name="rows", values=[rows]),
        ParamRange(name="cols", values=[cols]),
        ParamRange(name="diagonal_axis", values=[axis]),
        ParamRange(name="diagonal_order", values=[order]),
        ParamRange(name="diagonal_start_edge", values=[start_edge]),
    ]
    binding: dict = {
        "variant": "diagonal",
        "rows": rows,
        "cols": cols,
        "diagonal_axis": axis,
        "diagonal_order": order,
        "diagonal_start_edge": start_edge,
    }
    if cell_order is not None:
        params.append(
            ParamRange(name="diagonal_cell_order", values=[cell_order])
        )
        binding["diagonal_cell_order"] = cell_order
    layer = CipherLayer(kind="route", alphabet="AZ", params=params)
    return layer, binding


class TestDispatcherDiagonalCellOrder:
    def test_forward_dispatches(self):
        layer, binding = _make_route_layer(
            10, 10, axis="anti", order="forward",
            start_edge="top_then_right", cell_order="forward",
        )
        step = _translate_layer(layer, binding)
        assert step["type"] == "transposition_full"
        assert len(step["params"]["perm"]) == 97

    def test_reverse_dispatches(self):
        layer, binding = _make_route_layer(
            10, 10, axis="anti", order="forward",
            start_edge="top_then_right", cell_order="reverse",
        )
        step = _translate_layer(layer, binding)
        perm = step["params"]["perm"]
        assert len(perm) == 97
        assert sorted(perm) == list(range(97))

    def test_alternate_dispatches(self):
        layer, binding = _make_route_layer(
            10, 10, axis="main", order="forward",
            start_edge="top_then_left", cell_order="alternate",
        )
        step = _translate_layer(layer, binding)
        perm = step["params"]["perm"]
        assert len(perm) == 97
        assert sorted(perm) == list(range(97))

    def test_omitted_cell_order_defaults_to_forward(self):
        # No diagonal_cell_order param → dispatcher must default to
        # "forward" and produce identical output to an explicit
        # forward binding.
        layer_implicit, binding_implicit = _make_route_layer(
            10, 10, axis="main", order="forward",
            start_edge="top_then_left", cell_order=None,
        )
        layer_explicit, binding_explicit = _make_route_layer(
            10, 10, axis="main", order="forward",
            start_edge="top_then_left", cell_order="forward",
        )
        a = _translate_layer(layer_implicit, binding_implicit)
        b = _translate_layer(layer_explicit, binding_explicit)
        assert a["params"]["perm"] == b["params"]["perm"]

    def test_invalid_cell_order_fails_closed(self):
        layer, binding = _make_route_layer(
            10, 10, axis="main", order="forward",
            start_edge="top_then_left", cell_order="zigzag",
        )
        with pytest.raises(DispatcherError, match="diagonal_cell_order"):
            _translate_layer(layer, binding)

    def test_rows_cols_below_ct_len_still_rejects(self):
        # Sanity: tightening cell_order validation must not weaken
        # the existing rows*cols >= CT_LEN gate.
        layer, binding = _make_route_layer(
            5, 5, axis="main", order="forward",
            start_edge="top_then_left", cell_order="forward",
        )
        with pytest.raises(DispatcherError, match="rows\\*cols"):
            _translate_layer(layer, binding)


# ---------------------------------------------------------------------------
# 3. HCC generation tests
# ---------------------------------------------------------------------------


DIAG_CLUE_BASIC = (
    "A diagonal grid is crossed by alternating rows. The keyword "
    "KEYNAME is engraved nearby."
)
DIAG_CLUE_ROLE_TRIPLE = (
    "A small tag says seventeen. A diagonal grid is crossed by "
    "alternating rows. The keyword KEYNAME is engraved."
)


def _gen(clue_words, clue_text, *, max_specs: int = 10000):
    return generate_layered_specs(
        clue_words,
        clue_text=clue_text,
        max_specs=max_specs,
        bench_slug="t",
    )


class TestHCCDiagonalCellOrder:
    def test_lesson_016_emits_both_cell_orders(self):
        specs = _gen(["KEYNAME", "TAG"], DIAG_CLUE_BASIC)
        diag = [
            s for s in specs
            if s.coverage.layer_family.startswith("route_diagonal")
        ]
        cell_orders = {s.coverage.diagonal_cell_order for s in diag}
        # Empty string would mean "no diagonal route"; we want both
        # forward and reverse populated.
        assert "forward" in cell_orders
        assert "reverse" in cell_orders

    def test_lesson_019_emits_both_cell_orders(self):
        specs = _gen(["KEYNAME", "TAG"], DIAG_CLUE_ROLE_TRIPLE)
        l019 = [
            s for s in specs
            if s.coverage.layer_family == "caesar_route_diagonal_columnar"
        ]
        cell_orders = {s.coverage.diagonal_cell_order for s in l019}
        assert "forward" in cell_orders
        assert "reverse" in cell_orders

    def test_coverage_vector_carries_cell_order(self):
        specs = _gen(["KEYNAME", "TAG"], DIAG_CLUE_ROLE_TRIPLE)
        diag = [
            s for s in specs
            if s.coverage.layer_family.startswith("route_diagonal")
            or s.coverage.layer_family == "caesar_route_diagonal_columnar"
        ]
        for s in diag:
            assert s.coverage.diagonal_cell_order in (
                "forward", "reverse", "alternate",
            )
            # All other diagonal telemetry must remain populated.
            assert s.coverage.diagonal_axis in ("main", "anti")
            assert s.coverage.diagonal_order in ("forward", "reverse")
            # LESSON-021 introduced an additional ``route_mode``
            # value for the canonical width-only alias; both modes
            # are valid diagonal-route surfaces.
            assert s.coverage.route_mode in (
                "route_diagonal",
                "route_diagonal_canonical",
            )

    def test_dict_round_trip_preserves_cell_order(self):
        specs = _gen(["KEYNAME", "TAG"], DIAG_CLUE_BASIC)
        diag = [
            s for s in specs
            if s.coverage.layer_family.startswith("route_diagonal")
            and s.coverage.diagonal_cell_order == "reverse"
        ]
        assert diag, "need at least one reverse-cell-order spec"
        s = diag[0]
        d = s.coverage.to_dict()
        from kryptosbot.hand_cipher_core import CoverageVector
        cov2 = CoverageVector.from_dict(d)
        assert cov2.diagonal_cell_order == "reverse"
        assert cov2.diagonal_axis == s.coverage.diagonal_axis

    def test_lesson_020_specs_survive_constrained_cap(self):
        specs = _gen(
            ["KEYNAME", "TAG"], DIAG_CLUE_ROLE_TRIPLE, max_specs=8000,
        )
        l019 = [
            s for s in specs
            if s.coverage.layer_family == "caesar_route_diagonal_columnar"
        ]
        cell_orders = {s.coverage.diagonal_cell_order for s in l019}
        assert "forward" in cell_orders
        assert "reverse" in cell_orders, (
            "reverse cell_order must survive the LESSON-017 quota "
            "pass on a constrained 8000-spec cap"
        )

    def test_emitted_specs_validate(self):
        # Every LESSON-020-affected spec must pass the dispatcher's
        # spec validation (validate_hypothesis_spec).
        specs = _gen(["KEYNAME", "TAG"], DIAG_CLUE_ROLE_TRIPLE)
        diag = [
            s for s in specs
            if s.coverage.diagonal_cell_order in ("forward", "reverse")
        ]
        for s in diag:
            parsed = validate_hypothesis_spec(s.raw_spec)
            assert parsed.is_valid, (
                f"LESSON-020 spec {s.hypothesis_id[:48]} failed "
                f"validation: {parsed.errors}"
            )


# ---------------------------------------------------------------------------
# 4. Regression tests — nothing else moves
# ---------------------------------------------------------------------------


BOUSTRO_CLUE = (
    "A ragged eight-wide grid runs back and forth in a "
    "boustrophedon path. The keyword KEYNAME marks the edge."
)
ROW_REVERSE_CLUE = (
    "Lay the message in rows of width nine and fold the strip "
    "back; alternate rows are reversed. The keyword KEYNAME is "
    "etched."
)
BLOCK_REVERSE_CLUE = (
    "Group the cipher into block size seven. Reverse each block. "
    "The keyword KEYNAME is engraved."
)


class TestRegressionBoustrophedonUnchanged:
    def test_no_diagonal_cell_order_on_boustrophedon_specs(self):
        specs = _gen(["KEYNAME", "TAG"], BOUSTRO_CLUE)
        rb = [
            s for s in specs
            if s.coverage.layer_family.startswith("route_boustrophedon")
        ]
        assert rb, "boustrophedon clue must emit boustrophedon specs"
        for s in rb:
            # diagonal_cell_order must remain empty on non-diagonal
            # specs.
            assert s.coverage.diagonal_cell_order == ""


class TestRegressionRowReverseUnchanged:
    def test_no_diagonal_cell_order_on_row_reverse_specs(self):
        specs = _gen(["KEYNAME", "TAG"], ROW_REVERSE_CLUE)
        rr = [
            s for s in specs
            if s.coverage.layer_family.startswith("row_reverse")
        ]
        assert rr, "row_reverse clue must emit row_reverse specs"
        for s in rr:
            assert s.coverage.diagonal_cell_order == ""


class TestRegressionReverseBlocksUnchanged:
    def test_no_diagonal_cell_order_on_reverse_blocks_specs(self):
        specs = _gen(["KEYNAME", "TAG"], BLOCK_REVERSE_CLUE)
        rb = [
            s for s in specs
            if s.coverage.layer_family.startswith("reverse_blocks")
        ]
        assert rb, "reverse_blocks clue must emit reverse_blocks specs"
        for s in rb:
            assert s.coverage.diagonal_cell_order == ""


class TestRegressionColumnarUnchanged:
    def test_columnar_specs_unaffected(self):
        # No diagonal/route trigger; a plain keyword-pair clue should
        # produce columnar specs with empty diagonal_cell_order.
        clue = "Two keywords mark the cipher: KEYNAME and TAG."
        specs = _gen(["KEYNAME", "TAG"], clue)
        col = [
            s for s in specs
            if s.coverage.layer_family.startswith("columnar_")
        ]
        assert col, "plain clue must still emit columnar specs"
        for s in col:
            assert s.coverage.diagonal_cell_order == ""


class TestRegressionNumericCaesarPromotionUnchanged:
    def test_lesson_018_promotion_still_works(self):
        # Tag-precursor numeric promotion must still emit caesar
        # specs and complement coverage; LESSON-020 must not perturb
        # LESSON-018.
        specs = _gen(
            ["KEYNAME"],
            "A small tag says seventeen. The keyword KEYNAME is engraved.",
        )
        caesar = [
            s for s in specs
            if s.coverage.layer_family == "caesar"
        ]
        shifts = {s.coverage.shift_value for s in caesar}
        assert 17 in shifts
        assert 9 in shifts  # complement


# ---------------------------------------------------------------------------
# 5. Lesson registry
# ---------------------------------------------------------------------------


class TestLessonRegistry:
    def test_lesson_020_in_default_set(self):
        ids = {l.lesson_id for l in _default_lessons()}
        assert "LESSON-020" in ids

    def test_lesson_020_metadata(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-020"]
        assert "diagonal" in l.title.lower()
        params = l.tactic_parameters
        assert "forward" in params["cell_order_values"]
        assert "reverse" in params["cell_order_values"]
        assert params["no_new_primitive"] is True
        assert params["bench_only"] is True


# ---------------------------------------------------------------------------
# 6. Real-K4 mode unchanged
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
