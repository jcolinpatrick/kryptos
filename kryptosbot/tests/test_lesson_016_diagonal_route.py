"""Tests for LESSON-016 — diagonal grid-route transposition.

Pinned properties:

  1. Kernel primitive ``diagonal_perm`` is length-preserving and
     produces a bijection on full and ragged grids for every
     (axis, order, start_edge) combination.
  2. The dispatcher accepts ``route(variant='diagonal')`` with
     explicit axis/order/start_edge params and rejects unknown
     values with DispatcherError. ``rows*cols < CT_LEN`` is also
     rejected.
  3. The DSL admits well-formed diagonal route specs; unsupported
     route variants still fail closed.
  4. HCC trigger detection fires on diagonal/oblique/slant/cross/
     lattice/stones/mason/etc., on multi-word phrases (nw-se,
     ne-sw, rising diagonal), and respects word boundaries.
  5. A clue containing "diagonal" produces at least one diagonal-
     route seed; a clue containing "mason diagonal stones"
     produces diagonal-route seeds AND keyword candidates from
     MASON / STONES (so diagonal terms are NOT treated only as
     keywords).
  6. ``coverage_vector`` carries diagonal_axis / diagonal_order /
     diagonal_start_edge plus the standard route_mode / rows /
     cols / width / ragged fields, with dict round-trip.
  7. Real-K4 normal mode is unchanged: ``_collect_hcc_seeds()``
     returns ``[]`` in real-K4 mode; LESSON-016 is visible in
     the registry as a generalized tactic.
  8. Existing route_boustrophedon / serpentine / spiral / row_reverse
     / columnar / rail_fence tests remain green (verified by the
     full-suite run, not in this file).
"""
from __future__ import annotations

from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[2]


# ===========================================================================
# (1) Kernel primitive
# ===========================================================================


class TestDiagonalPermPrimitive:
    def test_3x3_main_forward_top_then_left(self):
        from kryptos.kernel.transforms.transposition import diagonal_perm
        # Main diagonals indexed by a = r-c, range -2..2.
        # a=-2: [(0,2)] → pos 2
        # a=-1: [(0,1),(1,2)] → 1, 5
        # a=0: [(0,0),(1,1),(2,2)] → 0, 4, 8
        # a=1: [(1,0),(2,1)] → 3, 7
        # a=2: [(2,0)] → 6
        perm = diagonal_perm(3, 3, length=9, axis="main",
                             order="forward", start_edge="top_then_left")
        assert perm == [2, 1, 5, 0, 4, 8, 3, 7, 6]

    def test_3x3_main_reverse_top_then_left(self):
        from kryptos.kernel.transforms.transposition import diagonal_perm
        perm = diagonal_perm(3, 3, length=9, axis="main",
                             order="reverse", start_edge="top_then_left")
        assert perm == [6, 3, 7, 0, 4, 8, 1, 5, 2]

    def test_3x3_main_forward_left_then_top(self):
        from kryptos.kernel.transforms.transposition import diagonal_perm
        perm = diagonal_perm(3, 3, length=9, axis="main",
                             order="forward", start_edge="left_then_top")
        # Each diagonal reversed (bottom→top within diagonal).
        assert perm == [2, 5, 1, 8, 4, 0, 7, 3, 6]

    def test_3x3_anti_forward_top_then_right(self):
        from kryptos.kernel.transforms.transposition import diagonal_perm
        perm = diagonal_perm(3, 3, length=9, axis="anti",
                             order="forward", start_edge="top_then_right")
        # Anti-diagonals d=r+c, range 0..4.
        # d=0: [(0,0)] → 0
        # d=1: [(0,1),(1,0)] → 1, 3
        # d=2: [(0,2),(1,1),(2,0)] → 2, 4, 6
        # d=3: [(1,2),(2,1)] → 5, 7
        # d=4: [(2,2)] → 8
        assert perm == [0, 1, 3, 2, 4, 6, 5, 7, 8]

    def test_3x3_anti_reverse_right_then_top(self):
        from kryptos.kernel.transforms.transposition import diagonal_perm
        perm = diagonal_perm(3, 3, length=9, axis="anti",
                             order="reverse", start_edge="right_then_top")
        assert perm == [8, 7, 5, 6, 4, 2, 3, 1, 0]

    @pytest.mark.parametrize("rows,cols", [
        (13, 8), (8, 13), (10, 10), (7, 14), (14, 7),
        (12, 9), (9, 12), (11, 10), (10, 11),
    ])
    @pytest.mark.parametrize("axis", ["main", "anti"])
    @pytest.mark.parametrize("order", ["forward", "reverse"])
    def test_ragged_grid_is_length_preserving_bijection(
        self, rows, cols, axis, order,
    ):
        """For every supported grid + variant, the perm covers
        [0, CT_LEN) exactly once. Ragged grids (rows*cols > CT_LEN)
        are trimmed by the primitive.
        """
        from kryptos.kernel.transforms.transposition import diagonal_perm
        from kryptos.kernel.constants import CT_LEN
        valid_starts = {
            "main": ("top_then_left", "left_then_top"),
            "anti": ("top_then_right", "right_then_top"),
        }
        for start_edge in valid_starts[axis]:
            perm = diagonal_perm(
                rows, cols, length=CT_LEN,
                axis=axis, order=order, start_edge=start_edge,
            )
            assert len(perm) == CT_LEN, (axis, order, start_edge)
            assert sorted(perm) == list(range(CT_LEN)), (
                axis, order, start_edge,
            )
            assert max(perm) < CT_LEN

    def test_round_trip_via_invert_perm(self):
        """Applying the perm and then its inverse returns the
        original — proves the perm is a true bijection.
        """
        from kryptos.kernel.transforms.transposition import (
            diagonal_perm, invert_perm, apply_perm,
        )
        text = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRS"
        assert len(text) == 97
        perm = diagonal_perm(13, 8, length=97, axis="main",
                             order="forward", start_edge="top_then_left")
        inv = invert_perm(perm)
        out = apply_perm(text, perm)
        round_tripped = apply_perm(out, inv)
        assert round_tripped == text

    def test_invalid_axis_raises(self):
        from kryptos.kernel.transforms.transposition import diagonal_perm
        with pytest.raises(ValueError, match="axis"):
            diagonal_perm(3, 3, length=9, axis="zigzag")

    def test_invalid_order_raises(self):
        from kryptos.kernel.transforms.transposition import diagonal_perm
        with pytest.raises(ValueError, match="order"):
            diagonal_perm(3, 3, length=9, axis="main", order="random")

    def test_axis_constrained_start_edge(self):
        """``start_edge`` must match the axis: main accepts only
        top_then_left/left_then_top; anti accepts only top_then_right/
        right_then_top.
        """
        from kryptos.kernel.transforms.transposition import diagonal_perm
        with pytest.raises(ValueError, match="start_edge"):
            diagonal_perm(3, 3, length=9, axis="main",
                          start_edge="top_then_right")
        with pytest.raises(ValueError, match="start_edge"):
            diagonal_perm(3, 3, length=9, axis="anti",
                          start_edge="left_then_top")

    def test_zero_dimension_raises(self):
        from kryptos.kernel.transforms.transposition import diagonal_perm
        with pytest.raises(ValueError, match="rows="):
            diagonal_perm(0, 5, length=5)
        with pytest.raises(ValueError, match="cols="):
            diagonal_perm(5, 0, length=5)


# ===========================================================================
# (2) Dispatcher
# ===========================================================================


class TestDispatcherDiagonalRoute:
    def test_valid_diagonal_translates_to_transposition_full(self):
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer
        from kryptos.kernel.constants import CT_LEN
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "route", "alphabet": "AZ",
                "params": [
                    {"name": "variant", "values": ["diagonal"]},
                    {"name": "rows", "values": [13]},
                    {"name": "cols", "values": [8]},
                    {"name": "diagonal_axis", "values": ["main"]},
                    {"name": "diagonal_order", "values": ["forward"]},
                    {"name": "diagonal_start_edge",
                     "values": ["top_then_left"]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        assert parsed.is_valid, parsed.errors
        out = _translate_layer(parsed.value.pipeline[0], {
            "variant": "diagonal", "rows": 13, "cols": 8,
            "diagonal_axis": "main", "diagonal_order": "forward",
            "diagonal_start_edge": "top_then_left",
        })
        assert out["type"] == "transposition_full"
        assert out["params"]["direction"] == "undo"
        perm = out["params"]["perm"]
        assert len(perm) == CT_LEN
        assert sorted(perm) == list(range(CT_LEN))

    @pytest.mark.parametrize("axis,order,start_edge", [
        ("main", "forward", "top_then_left"),
        ("main", "reverse", "left_then_top"),
        ("anti", "forward", "top_then_right"),
        ("anti", "reverse", "right_then_top"),
    ])
    def test_dispatch_each_canonical_variant(
        self, axis, order, start_edge,
    ):
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer
        from kryptos.kernel.constants import CT_LEN
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "route", "alphabet": "AZ",
                "params": [
                    {"name": "variant", "values": ["diagonal"]},
                    {"name": "rows", "values": [10]},
                    {"name": "cols", "values": [10]},
                    {"name": "diagonal_axis", "values": [axis]},
                    {"name": "diagonal_order", "values": [order]},
                    {"name": "diagonal_start_edge",
                     "values": [start_edge]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        out = _translate_layer(parsed.value.pipeline[0], {
            "variant": "diagonal", "rows": 10, "cols": 10,
            "diagonal_axis": axis, "diagonal_order": order,
            "diagonal_start_edge": start_edge,
        })
        perm = out["params"]["perm"]
        assert len(perm) == CT_LEN
        assert sorted(perm) == list(range(CT_LEN))

    def test_invalid_diagonal_axis_rejects(self):
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import (
            _translate_layer, DispatcherError,
        )
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "route", "alphabet": "AZ",
                "params": [
                    {"name": "variant", "values": ["diagonal"]},
                    {"name": "rows", "values": [13]},
                    {"name": "cols", "values": [8]},
                    {"name": "diagonal_axis", "values": ["bogus"]},
                    {"name": "diagonal_order", "values": ["forward"]},
                    {"name": "diagonal_start_edge",
                     "values": ["top_then_left"]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        with pytest.raises(DispatcherError, match="diagonal_axis"):
            _translate_layer(parsed.value.pipeline[0], {
                "variant": "diagonal", "rows": 13, "cols": 8,
                "diagonal_axis": "bogus", "diagonal_order": "forward",
                "diagonal_start_edge": "top_then_left",
            })

    def test_invalid_diagonal_order_rejects(self):
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import (
            _translate_layer, DispatcherError,
        )
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "route", "alphabet": "AZ",
                "params": [
                    {"name": "variant", "values": ["diagonal"]},
                    {"name": "rows", "values": [13]},
                    {"name": "cols", "values": [8]},
                    {"name": "diagonal_axis", "values": ["main"]},
                    {"name": "diagonal_order", "values": ["random"]},
                    {"name": "diagonal_start_edge",
                     "values": ["top_then_left"]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        with pytest.raises(DispatcherError, match="diagonal_order"):
            _translate_layer(parsed.value.pipeline[0], {
                "variant": "diagonal", "rows": 13, "cols": 8,
                "diagonal_axis": "main", "diagonal_order": "random",
                "diagonal_start_edge": "top_then_left",
            })

    def test_cross_axis_start_edge_rejects(self):
        """``start_edge='top_then_right'`` is only valid for
        axis='anti'; combining it with axis='main' must reject."""
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import (
            _translate_layer, DispatcherError,
        )
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "route", "alphabet": "AZ",
                "params": [
                    {"name": "variant", "values": ["diagonal"]},
                    {"name": "rows", "values": [13]},
                    {"name": "cols", "values": [8]},
                    {"name": "diagonal_axis", "values": ["main"]},
                    {"name": "diagonal_order", "values": ["forward"]},
                    {"name": "diagonal_start_edge",
                     "values": ["top_then_right"]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        with pytest.raises(DispatcherError, match="diagonal_start_edge"):
            _translate_layer(parsed.value.pipeline[0], {
                "variant": "diagonal", "rows": 13, "cols": 8,
                "diagonal_axis": "main", "diagonal_order": "forward",
                "diagonal_start_edge": "top_then_right",
            })

    def test_small_grid_rejects(self):
        """``rows*cols < CT_LEN`` must reject (cannot cover every
        position).
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import (
            _translate_layer, DispatcherError,
        )
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "route", "alphabet": "AZ",
                "params": [
                    {"name": "variant", "values": ["diagonal"]},
                    {"name": "rows", "values": [5]},
                    {"name": "cols", "values": [5]},
                    {"name": "diagonal_axis", "values": ["main"]},
                    {"name": "diagonal_order", "values": ["forward"]},
                    {"name": "diagonal_start_edge",
                     "values": ["top_then_left"]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        with pytest.raises(DispatcherError, match="CT_LEN"):
            _translate_layer(parsed.value.pipeline[0], {
                "variant": "diagonal", "rows": 5, "cols": 5,
                "diagonal_axis": "main", "diagonal_order": "forward",
                "diagonal_start_edge": "top_then_left",
            })

    def test_unknown_route_variant_still_rejected(self):
        """Pre-existing variant guard still fires on values outside
        the canonical {serpentine, spiral, diagonal} set.
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import (
            _translate_layer, DispatcherError,
        )
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "route", "alphabet": "AZ",
                "params": [
                    {"name": "variant", "values": ["zigzag"]},
                    {"name": "rows", "values": [10]},
                    {"name": "cols", "values": [10]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        with pytest.raises(DispatcherError, match="variant"):
            _translate_layer(parsed.value.pipeline[0], {
                "variant": "zigzag", "rows": 10, "cols": 10,
            })


# ===========================================================================
# (3) Trigger detection
# ===========================================================================


class TestDiagonalTriggerDetection:
    @pytest.mark.parametrize("text,expected", [
        ("alternating diagonals on a grid", True),
        ("the diagonal route", True),
        ("oblique stripes", True),
        ("slant lines from corner", True),
        ("a slash and backslash pattern", True),
        ("crossed by lattice", True),
        ("rising diagonal sweep", True),
        ("falling diagonal sweep", True),
        ("MASON appears on five stones", True),
        ("masonry courses cross the wall", True),
        ("nw-se direction", True),
        ("ne to sw", True),
        ("plain caesar shift", False),
        ("ordinary substitution", False),
        ("", False),
    ])
    def test_detect_diagonal_trigger(self, text, expected):
        from kryptosbot.hand_cipher_core import _detect_diagonal_trigger
        assert _detect_diagonal_trigger(text) is expected

    def test_word_boundary_negative(self):
        """Generic words containing diagonal-like substrings should
        not falsely trigger.
        """
        from kryptosbot.hand_cipher_core import _detect_diagonal_trigger
        # "obliquely" contains "oblique" — does trigger (boundary ok)
        assert _detect_diagonal_trigger("obliquely tilted") is False
        # "stoned" contains "stone" — does NOT trigger
        assert _detect_diagonal_trigger("the stoned approach") is False


# ===========================================================================
# (4) HCC seed / coverage tests
# ===========================================================================


class TestHccDiagonalSeeds:
    def test_diagonal_clue_emits_diagonal_route_seeds(self):
        from kryptosbot.hand_cipher_core import generate_layered_specs
        specs = generate_layered_specs(
            ["ALPHA", "BRAVO"], bench_slug="t",
            clue_text="alternating diagonals on a ten-wide grid",
            max_specs=20000,
        )
        diag = [
            s for s in specs
            if s.coverage.layer_family.startswith("route_diagonal")
        ]
        assert diag, "diagonal trigger did not produce route_diagonal seeds"

    def test_mason_diagonal_stones_emits_diagonal_seeds(self):
        """The user-mandated synthetic clue: 'mason diagonal stones'
        must instantiate diagonal route operations, not only treat
        the words as keyword material.
        """
        from kryptosbot.hand_cipher_core import generate_layered_specs
        specs = generate_layered_specs(
            ["MASON", "STONES", "BERLIN"], bench_slug="t",
            clue_text=(
                "MASON appears on five stones. A ten-wide ragged "
                "grid is crossed by alternating diagonals."
            ),
            max_specs=30000,
        )
        diag = [
            s for s in specs
            if s.coverage.layer_family.startswith("route_diagonal")
        ]
        assert diag, "mason+diagonal+stones did not emit route_diagonal seeds"
        # axes / orders both represented.
        axes = {s.coverage.diagonal_axis for s in diag}
        orders = {s.coverage.diagonal_order for s in diag}
        assert "main" in axes and "anti" in axes
        assert "forward" in orders and "reverse" in orders

    def test_diagonal_terms_still_appear_as_keywords_too(self):
        """The diagonal trigger should ADD route operations without
        REMOVING the keyword-candidate path. MASON / STONES must
        still appear as substitution keywords in non-diagonal
        families.
        """
        from kryptosbot.hand_cipher_core import generate_layered_specs
        specs = generate_layered_specs(
            ["MASON", "STONES", "BERLIN"], bench_slug="t",
            clue_text=(
                "MASON appears on five stones. A ten-wide ragged "
                "grid is crossed by alternating diagonals."
            ),
            max_specs=30000,
        )
        # Look for non-diagonal families that USE MASON or STONES as
        # substitution keyword.
        keyword_users = [
            s for s in specs
            if not s.coverage.layer_family.startswith("route_diagonal")
            and s.coverage.substitution_keyword in ("MASON", "STONES")
        ]
        assert keyword_users, (
            "diagonal terms must remain available as keyword material "
            "in non-diagonal families; got zero such specs"
        )

    def test_diagonal_seeds_carry_full_coverage_telemetry(self):
        from kryptosbot.hand_cipher_core import generate_layered_specs
        specs = generate_layered_specs(
            ["ALPHA", "BRAVO"], bench_slug="t",
            clue_text="diagonal grid alternating diagonals ten-wide",
            max_specs=20000,
        )
        diag = [
            s for s in specs
            if s.coverage.layer_family.startswith("route_diagonal")
        ]
        assert diag
        for s in diag[:30]:
            cv = s.coverage
            assert cv.route_mode == "route_diagonal"
            assert cv.diagonal_axis in ("main", "anti")
            assert cv.diagonal_order in ("forward", "reverse")
            valid_starts = {
                "main": ("top_then_left", "left_then_top"),
                "anti": ("top_then_right", "right_then_top"),
            }
            assert (
                cv.diagonal_start_edge
                in valid_starts[cv.diagonal_axis]
            )
            assert isinstance(cv.route_rows, int)
            assert isinstance(cv.route_cols, int)
            assert cv.route_rows * cv.route_cols >= 97
            assert cv.operation_source in (
                "phrase_bound_diagonal_width",
                "clue_keyword_length",
                "default_set",
            )

    def test_no_diagonal_emission_without_trigger(self):
        from kryptosbot.hand_cipher_core import generate_layered_specs
        specs = generate_layered_specs(
            ["FOO", "BAR"], bench_slug="t",
            clue_text="just an ordinary cipher problem",
            max_specs=2000,
        )
        diag = [
            s for s in specs
            if s.coverage.layer_family.startswith("route_diagonal")
        ]
        assert diag == [], (
            "diagonal seeds emitted without a diagonal trigger token"
        )

    def test_paired_family_both_layer_orders(self):
        """sub + diagonal route is emitted in BOTH layer orders
        (LESSON-002 invariant)."""
        from kryptosbot.hand_cipher_core import generate_layered_specs
        specs = generate_layered_specs(
            ["ALPHA", "BRAVO"], bench_slug="t",
            clue_text="diagonal grid",
            max_specs=20000,
        )
        fam = [
            s for s in specs
            if s.coverage.layer_family == "route_diagonal_vigenere"
        ]
        assert fam
        orders = {s.coverage.layer_order for s in fam}
        assert ("vigenere", "route_diagonal") in orders
        assert ("route_diagonal", "vigenere") in orders


# ===========================================================================
# (5) CoverageVector round-trip
# ===========================================================================


class TestCoverageVectorRoundTrip:
    def test_diagonal_fields_round_trip(self):
        from kryptosbot.hand_cipher_core import CoverageVector
        cv = CoverageVector(
            layer_family="route_diagonal",
            layer_order=("route_diagonal",),
            role_assignment=(),
            alphabet="AZ", n_layers=1,
            route_mode="route_diagonal",
            route_rows=13, route_cols=8, route_width=8,
            route_ragged=True, route_direction="main",
            route_width_source="default_set",
            diagonal_axis="main", diagonal_order="forward",
            diagonal_start_edge="top_then_left",
            operation_source="default_set",
        )
        d = cv.to_dict()
        assert d["diagonal_axis"] == "main"
        assert d["diagonal_order"] == "forward"
        assert d["diagonal_start_edge"] == "top_then_left"
        assert d["route_mode"] == "route_diagonal"
        cv2 = CoverageVector.from_dict(d)
        assert cv2.diagonal_axis == "main"
        assert cv2.diagonal_order == "forward"
        assert cv2.diagonal_start_edge == "top_then_left"
        assert cv2.route_mode == "route_diagonal"

    def test_legacy_specs_have_empty_diagonal_fields(self):
        from kryptosbot.hand_cipher_core import generate_layered_specs
        specs = generate_layered_specs(
            ["FOO", "BAR"], bench_slug="t",
            clue_text="ordinary problem", max_specs=200,
            include_three_layer=False,
        )
        non_diag = [
            s for s in specs
            if not s.coverage.layer_family.startswith("route_diagonal")
        ]
        assert non_diag
        for s in non_diag:
            assert s.coverage.diagonal_axis == ""
            assert s.coverage.diagonal_order == ""
            assert s.coverage.diagonal_start_edge == ""


# ===========================================================================
# (6) Lesson registry
# ===========================================================================


class TestLessonRegistry:
    def test_lesson_016_present(self):
        from kryptosbot.solver_capabilities import _default_lessons
        lessons = {l.lesson_id: l for l in _default_lessons()}
        assert "LESSON-016" in lessons
        l = lessons["LESSON-016"]
        assert l.tactic_kind == "diagonal_grid_route_enumeration"
        assert l.generates_specs is True

    def test_lesson_016_trigger_vocabulary(self):
        from kryptosbot.solver_capabilities import _default_lessons
        lessons = {l.lesson_id: l for l in _default_lessons()}
        triggers = set(lessons["LESSON-016"].tactic_parameters["trigger_tokens"])
        for required in (
            "diagonal", "oblique", "slant", "slash", "backslash",
            "cross", "lattice", "stones", "mason", "courses",
        ):
            assert required in triggers, f"missing trigger: {required}"

    def test_lesson_016_axes_and_orders(self):
        from kryptosbot.solver_capabilities import _default_lessons
        lessons = {l.lesson_id: l for l in _default_lessons()}
        params = lessons["LESSON-016"].tactic_parameters
        assert set(params["axes"]) == {"main", "anti"}
        assert set(params["orders"]) == {"forward", "reverse"}
        assert set(params["start_edges_main"]) == {
            "top_then_left", "left_then_top",
        }
        assert set(params["start_edges_anti"]) == {
            "top_then_right", "right_then_top",
        }


# ===========================================================================
# (7) Real-K4 mode unchanged
# ===========================================================================


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
