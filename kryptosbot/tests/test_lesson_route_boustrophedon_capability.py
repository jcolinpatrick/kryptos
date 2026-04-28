"""Tests for LESSON-014 — width-only ragged boustrophedon route
transposition capability.

Pinned properties:

  1. ``LessonRegistry`` seeds LESSON-014 with the trigger
     vocabulary, default width set, and parameter knobs. Drift
     test: runtime constants in ``hand_cipher_core`` honor the
     lesson's parameters.
  2. The DSL accepts a ``route_boustrophedon`` cipher kind with
     ``width`` and ``vertical`` parameters; the dispatcher
     translates it to a ``transposition_full`` perm produced by
     ``serpentine_perm(ceil(CT_LEN / width), width, CT_LEN,
     vertical=...)``. The layer is length-preserving (perm is a
     bijection of [0, CT_LEN)) and the final row may be ragged.
  3. The CoverageVector dataclass exposes ``route_width``,
     ``route_rows``, ``route_cols``, ``route_ragged``,
     ``route_direction``, and ``route_width_source`` fields.
     Legacy specs leave them at safe empty defaults; dict round-
     trip preserves them.
  4. Trigger detection: a clue text containing any of the
     LESSON-014 trigger tokens flips
     ``_detect_route_boustrophedon_trigger``. Without a trigger
     the historical catalog is bit-identical (no
     route_boustrophedon specs emitted).
  5. The user-mandated synthetic toy clue
     ``"archive column walk, artifact count, ragged left edge"``
     causes HCC to emit vigenere(key=ARCHIVE) +
     route_boustrophedon(width derived from the 8-letter clue
     keyword 'ARTIFACT') before any LLM call.
  6. Width source priority is phrase-bound > clue keyword length
     > default. Bounded width range. Excluded source categories
     (rail_depth / shift_value / block_size / step / offset) do
     NOT pollute the route width list.
  7. Width-only route differs from a columnar transposition
     keyed on the same width — the two transformations are
     distinct permutations.
  8. All major two-layer orderings are present in the catalog
     (route_boustrophedon + sub in both orders; sub + rb +
     rail_fence in 4 orderings; sub + rb + columnar in 2
     orderings).
  9. Replayability: dispatching the same spec twice produces
     identical perms.
 10. Real-K4 mode unchanged: ``_collect_hcc_seeds`` returns
     ``[]`` in real-K4 mode, so the family generators never
     auto-emit; LESSON-014 entry IS in the registry as a
     generalized tactic.
"""
from __future__ import annotations

import math
from pathlib import Path

import pytest

from kryptosbot.solver_capabilities import _default_lessons, LessonRegistry
from kryptosbot.hand_cipher_core import (
    AlphabetMode,
    CoverageVector,
    _DEFAULT_ROUTE_BOUSTROPHEDON_WIDTHS,
    _ROUTE_BOUSTROPHEDON_TRIGGER_TOKENS,
    _ROUTE_BOUSTROPHEDON_VERTICAL_TOKENS,
    _ROUTE_BOUSTROPHEDON_HORIZONTAL_TOKENS,
    _ROUTE_BOUSTROPHEDON_MIN_WIDTH,
    _ROUTE_BOUSTROPHEDON_MAX_WIDTH,
    _ROUTE_BOUSTROPHEDON_MAX_KEYWORD_WIDTH,
    _detect_route_boustrophedon_trigger,
    _detect_route_vertical_priority,
    _extract_phrase_bound_route_widths,
    _gen_route_boustrophedon_alone_family,
    _gen_route_boustrophedon_atbash_family,
    _gen_route_boustrophedon_caesar_family,
    _gen_route_boustrophedon_rail_fence_family,
    _gen_route_boustrophedon_substitution_family,
    _gen_route_boustrophedon_three_layer_family,
    _route_boustrophedon_layer,
    _route_boustrophedon_widths_for_payload,
    generate_layered_specs,
)


_REPO_ROOT = Path(__file__).resolve().parents[2]
_K4B007_PATH = _REPO_ROOT / "bench" / "k4bench" / "challenges" / "K4B-007.json"

# Toy clue keyword set unrelated to any K4Bench challenge.
_ABC = ["ALPHA", "BRAVO", "CHARLIE"]


# ---------------------------------------------------------------------------
# (1) LessonRegistry
# ---------------------------------------------------------------------------


class TestLessonRegistry:
    def test_lesson_014_present(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        assert "LESSON-014" in lessons
        l = lessons["LESSON-014"]
        assert l.tactic_kind == "width_only_ragged_boustrophedon_route"
        assert l.generates_specs is True

    def test_lesson_014_has_required_trigger_vocabulary(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-014"]
        triggers = set(l.tactic_parameters.get("trigger_tokens", []))
        # The lesson's trigger vocabulary must cover the user-mandated
        # set: artifact / column / edge / walk / grid / archive /
        # route / path / count / ragged.
        required = {
            "archive", "artifact", "column", "columns",
            "grid", "walk", "route", "path", "edge",
            "count", "ragged",
        }
        missing = required - triggers
        assert not missing, f"LESSON-014 trigger_tokens missing: {missing}"

    def test_lesson_014_default_widths_bounded(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-014"]
        widths = list(l.tactic_parameters.get("default_widths", []))
        assert all(isinstance(w, int) and w >= 2 for w in widths)
        # Default set must include the K4B-007 expected width 8 so the
        # generator never depends on phrase-binding to find it.
        assert 8 in widths

    def test_lesson_014_excludes_unrelated_width_sources(self):
        """LESSON-014 contract: rail_depth / shift_value /
        block_size / step / offset bindings MUST NOT seed route
        widths. The lesson's tactic_parameters lists this exclusion
        explicitly so a future runtime change cannot quietly let
        them through.
        """
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-014"]
        excluded = set(
            l.tactic_parameters.get("excluded_width_sources", [])
        )
        for label in (
            "phrase_bound_rail_depth",
            "phrase_bound_shift_value",
            "phrase_bound_block_size",
            "phrase_bound_step",
            "phrase_bound_offset",
        ):
            assert label in excluded, (
                f"LESSON-014 must EXCLUDE {label} from width sources "
                "or the universe will explode with category-error "
                "values. Missing exclusion is a bug."
            )

    def test_lesson_014_runtime_drift(self):
        """Drift test: runtime trigger tokens, default widths, and
        bound constants match the registry entry.
        """
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-014"]
        assert set(l.tactic_parameters["trigger_tokens"]) == set(
            _ROUTE_BOUSTROPHEDON_TRIGGER_TOKENS
        )
        assert tuple(l.tactic_parameters["default_widths"]) == (
            _DEFAULT_ROUTE_BOUSTROPHEDON_WIDTHS
        )
        assert l.tactic_parameters["min_width"] == (
            _ROUTE_BOUSTROPHEDON_MIN_WIDTH
        )
        assert l.tactic_parameters["max_width"] == (
            _ROUTE_BOUSTROPHEDON_MAX_WIDTH
        )
        assert l.tactic_parameters["max_clue_keyword_width"] == (
            _ROUTE_BOUSTROPHEDON_MAX_KEYWORD_WIDTH
        )

    def test_lesson_registry_round_trip(self, tmp_path):
        path = tmp_path / "lessons.json"
        reg1 = LessonRegistry(path=path, seed_defaults=True)
        ids1 = {l.lesson_id for l in reg1.all()}
        assert "LESSON-014" in ids1
        reg2 = LessonRegistry(path=path, seed_defaults=True)
        ids2 = {l.lesson_id for l in reg2.all()}
        assert "LESSON-014" in ids2


# ---------------------------------------------------------------------------
# (2) DSL + dispatcher accept route_boustrophedon
# ---------------------------------------------------------------------------


class TestDslAndDispatcher:
    def test_dsl_validates_route_boustrophedon_layer(self):
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "route_boustrophedon", "alphabet": "AZ",
                "params": [
                    {"name": "width", "values": [8]},
                    {"name": "vertical", "values": [True]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        assert parsed.is_valid, parsed.errors

    def test_dispatcher_supported_kinds_includes_route_boustrophedon(self):
        from kryptosbot.job_dispatcher import (
            _SUPPORTED_KINDS, _kind_has_translation,
        )
        assert "route_boustrophedon" in _SUPPORTED_KINDS
        assert _kind_has_translation("route_boustrophedon")

    def test_translator_produces_serpentine_perm(self):
        """The translator emits perm = serpentine_perm(rows, width,
        CT_LEN, vertical) where rows = ceil(CT_LEN / width). The
        dispatcher returns it under direction='undo' which the kernel
        inverts before applying.
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer
        from kryptos.kernel.constants import CT_LEN
        from kryptos.kernel.transforms.transposition import serpentine_perm
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "route_boustrophedon", "alphabet": "AZ",
                "params": [
                    {"name": "width", "values": [8]},
                    {"name": "vertical", "values": [True]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        out = _translate_layer(
            parsed.value.pipeline[0],
            {"width": 8, "vertical": True},
        )
        assert out["type"] == "transposition_full"
        assert out["params"]["direction"] == "undo"
        rows = (CT_LEN + 8 - 1) // 8
        expected = list(serpentine_perm(rows, 8, CT_LEN, vertical=True))
        assert list(out["params"]["perm"]) == expected

    @pytest.mark.parametrize("width", [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16])
    @pytest.mark.parametrize("vertical", [False, True])
    def test_perm_is_valid_bijection(self, width, vertical):
        """Every (width, vertical) pair produces a perm that is a
        complete bijection of [0, CT_LEN) — even when CT_LEN is not
        a multiple of width (the ragged case). The kernel primitive
        trims out-of-bounds positions, so we test that the trimmed
        result still covers every input position exactly once.
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer
        from kryptos.kernel.constants import CT_LEN
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "route_boustrophedon", "alphabet": "AZ",
                "params": [
                    {"name": "width", "values": [width]},
                    {"name": "vertical", "values": [vertical]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        out = _translate_layer(
            parsed.value.pipeline[0],
            {"width": width, "vertical": vertical},
        )
        perm = out["params"]["perm"]
        assert len(perm) == CT_LEN, f"width={width}: perm length"
        assert sorted(perm) == list(range(CT_LEN)), (
            f"width={width} vertical={vertical}: perm not a bijection"
        )

    def test_translator_rejects_invalid_width(self):
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import (
            _translate_layer, DispatcherError,
        )
        from kryptos.kernel.constants import CT_LEN
        for bad_width in (1, 0, -1, CT_LEN, CT_LEN + 1):
            spec = {
                "hypothesis_id": "t",
                "pipeline": [{
                    "kind": "route_boustrophedon", "alphabet": "AZ",
                    "params": [
                        {"name": "width", "values": [bad_width]},
                        {"name": "vertical", "values": [False]},
                    ],
                }],
                "crib_alignment": "post_transposition",
                "scoring": "crib_plus_bean",
                "compute_budget_cpu_minutes": 1,
            }
            parsed = validate_hypothesis_spec(spec)
            with pytest.raises(DispatcherError, match="width"):
                _translate_layer(
                    parsed.value.pipeline[0],
                    {"width": bad_width, "vertical": False},
                )

    def test_perm_replayability_deterministic(self):
        """Translating the same spec twice produces the same perm.
        Foundational replayability invariant for attempt artifact
        reconstruction.
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "route_boustrophedon", "alphabet": "AZ",
                "params": [
                    {"name": "width", "values": [8]},
                    {"name": "vertical", "values": [True]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        out1 = _translate_layer(
            parsed.value.pipeline[0],
            {"width": 8, "vertical": True},
        )
        out2 = _translate_layer(
            parsed.value.pipeline[0],
            {"width": 8, "vertical": True},
        )
        assert out1["params"]["perm"] == out2["params"]["perm"]

    def test_route_boustrophedon_differs_from_columnar(self):
        """Width-only ragged boustrophedon is NOT equivalent to a
        columnar transposition keyed on the same width. The two
        produce different permutations even when widths match — this
        guards against future "simplifications" that collapse the
        kinds.
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer
        rb_spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "route_boustrophedon", "alphabet": "AZ",
                "params": [
                    {"name": "width", "values": [5]},
                    {"name": "vertical", "values": [False]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        col_spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "columnar", "alphabet": "AZ",
                "params": [
                    {"name": "width", "values": [5]},
                    {"name": "col_order", "values": [[0, 1, 2, 3, 4]]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        rb_parsed = validate_hypothesis_spec(rb_spec)
        col_parsed = validate_hypothesis_spec(col_spec)
        rb_out = _translate_layer(
            rb_parsed.value.pipeline[0],
            {"width": 5, "vertical": False},
        )
        col_out = _translate_layer(
            col_parsed.value.pipeline[0],
            {"width": 5, "col_order": [0, 1, 2, 3, 4]},
        )
        assert rb_out["params"]["perm"] != col_out["params"]["perm"], (
            "route_boustrophedon and columnar must produce distinct "
            "permutations"
        )


# ---------------------------------------------------------------------------
# (3) Trigger detection
# ---------------------------------------------------------------------------


class TestTriggerDetection:
    @pytest.mark.parametrize("text,expected", [
        ("the artifact says ARCHIVE and shows a ragged eight-column grid", True),
        ("walk every step through the route", True),
        ("read the column count", True),
        ("ragged left edge", True),
        ("a snake on a grid", True),
        ("boustrophedon read", True),
        ("plain caesar shift", False),
        ("ordinary substitution", False),
        ("", False),
    ])
    def test_detect_route_boustrophedon_trigger(self, text, expected):
        assert _detect_route_boustrophedon_trigger(text) is expected

    def test_word_boundary_negative(self):
        """``column`` inside ``columnist`` must NOT trigger; ``column``
        as a whole word must trigger.
        """
        # No trigger token spelled correctly here - "columnist" is
        # not a trigger; "edge" inside "edged" is not a trigger
        # because the next char is alphanumeric. We verify the
        # boundary by removing all whole-word triggers.
        assert _detect_route_boustrophedon_trigger("columnist") is False
        assert _detect_route_boustrophedon_trigger("a column here") is True

    @pytest.mark.parametrize("text,expected", [
        ("arrows down, up, down, up", True),
        ("the column reads vertically", True),
        ("read row by row left to right", False),
        ("plain text", False),
    ])
    def test_detect_vertical_priority(self, text, expected):
        assert _detect_route_vertical_priority(text) is expected


# ---------------------------------------------------------------------------
# (4) Width extraction + width source priority
# ---------------------------------------------------------------------------


class TestWidthExtraction:
    def test_phrase_bound_width_from_hyphen_compound(self):
        """``eight-column`` binds 8 to route_width."""
        assert 8 in _extract_phrase_bound_route_widths(
            "a ragged eight-column grid"
        )

    def test_phrase_bound_width_from_after_anchor(self):
        """``8 columns`` binds 8 to route_width."""
        assert 8 in _extract_phrase_bound_route_widths(
            "the grid has 8 columns"
        )

    def test_phrase_bound_width_from_before_anchor(self):
        """``width 8`` binds 8 to route_width."""
        assert 8 in _extract_phrase_bound_route_widths(
            "with grid of width 8"
        )

    def test_phrase_bound_width_via_cardinal_word(self):
        """Spelled cardinals are accepted (LESSON-012 number-word
        support inherited).
        """
        assert 8 in _extract_phrase_bound_route_widths(
            "a ragged eight-column grid"
        )
        assert 12 in _extract_phrase_bound_route_widths(
            "twelve-row layout"
        )

    def test_width_source_priority(self):
        """Phrase-bound > clue keyword length > default."""
        widths = _route_boustrophedon_widths_for_payload(
            "ragged eight-column grid", ["ARCHIVE"],
        )
        # First-appearing entry should be phrase-bound 8.
        assert widths[0] == (8, "phrase_bound_route_width")
        # ARCHIVE is 7 letters; it should appear with
        # clue_keyword_length provenance.
        kw_entries = [
            (w, src) for w, src in widths
            if src == "clue_keyword_length"
        ]
        assert (7, "clue_keyword_length") in kw_entries
        # Defaults still appear after the priority sources.
        default_entries = [src for _, src in widths if src == "default_set"]
        assert default_entries

    def test_width_bounds_enforced(self):
        """Widths < min or > max are dropped."""
        widths = _route_boustrophedon_widths_for_payload(
            "1-column grid", ["A", "B"],
        )
        for w, _ in widths:
            assert _ROUTE_BOUSTROPHEDON_MIN_WIDTH <= w <= (
                _ROUTE_BOUSTROPHEDON_MAX_WIDTH
            )

    def test_excluded_sources_do_not_pollute_route_width(self):
        """A clue with rail-depth / shift / block / step numerals
        but NO route-width anchor must NOT propagate those
        numerals into the route-boustrophedon width list. The
        excluded numerals can still appear — but only via
        (1) clue keyword length, or (2) the default set — never
        with provenance ``phrase_bound_*`` from another parameter.
        """
        widths = _route_boustrophedon_widths_for_payload(
            "shift 8 with depth four and rot 13", [],
        )
        # No phrase_bound_route_width entries because the clue
        # has no width-anchor phrase.
        for _, src in widths:
            assert src != "phrase_bound_route_width", (
                "rail_depth / shift_value / block_size numerals must "
                "NOT bind to route_width"
            )

    def test_ct_length_aware_extraction(self):
        """Widths are bounded to [min, max]; the ct_length
        parameter is kept for parity with LESSON-012 callers but
        does not currently relax the bounds.
        """
        widths = _extract_phrase_bound_route_widths(
            "10 columns wide", ct_length=97,
        )
        assert 10 in widths


# ---------------------------------------------------------------------------
# (5) User-mandated synthetic toy clue
# ---------------------------------------------------------------------------


class TestSyntheticToyClue:
    """The user-mandated synthetic clue:
    ``"archive column walk, artifact count, ragged left edge"``
    (phrase-bound width is implied by the 8-letter ARTIFACT clue
    keyword; combined with vigenere(ARCHIVE) the LESSON-014
    catalog must contain the matching spec before any LLM call).
    """

    _TOY_CLUE = (
        "archive column walk, artifact count, ragged left edge"
    )

    def test_route_boustrophedon_alone_emitted(self):
        specs = generate_layered_specs(
            ["ARCHIVE", "ARTIFACT", "EDGE"], bench_slug="toy",
            clue_text=self._TOY_CLUE, max_specs=20000,
        )
        match = [
            s for s in specs
            if s.coverage.layer_family == "route_boustrophedon"
        ]
        assert match, "route_boustrophedon alone NOT emitted from toy clue"
        # The width-source provenance is recorded on the coverage
        # vector so an attempt-artifact reader can audit "did we
        # test width=W with source=phrase-bound?" without re-parsing
        # the clue.
        sources = {s.coverage.route_width_source for s in match}
        assert sources, "no width sources emitted on alone family"

    @pytest.mark.parametrize("sub_kind,family", [
        ("vigenere", "route_boustrophedon_vigenere"),
        ("beaufort", "route_boustrophedon_beaufort"),
        ("variant_beaufort", "route_boustrophedon_variant_beaufort"),
    ])
    def test_substitution_paired_emits_archive(self, sub_kind, family):
        specs = generate_layered_specs(
            ["ARCHIVE", "ARTIFACT", "EDGE"], bench_slug="toy",
            clue_text=self._TOY_CLUE, max_specs=20000,
        )
        match = [
            s for s in specs
            if s.coverage.layer_family == family
            and s.coverage.substitution_keyword == "ARCHIVE"
        ]
        assert match, (
            f"{family}(key=ARCHIVE) NOT emitted from toy clue"
        )
        # Both layer orders present — LESSON-002 invariant.
        orders = {s.coverage.layer_order for s in match}
        assert (sub_kind, "route_boustrophedon") in orders
        assert ("route_boustrophedon", sub_kind) in orders

    def test_no_llm_required_for_emission(self):
        """``generate_layered_specs`` is pure-Python and invokes no
        SDK / LLM. This test simply confirms the function runs to
        completion with deterministic output for the toy clue and
        produces at least one route_boustrophedon-family spec.
        """
        specs = generate_layered_specs(
            ["ARCHIVE", "ARTIFACT", "EDGE"], bench_slug="toy",
            clue_text=self._TOY_CLUE, max_specs=20000,
        )
        rb_families = {
            s.coverage.layer_family for s in specs
            if s.coverage.layer_family.startswith("route_boustrophedon")
            or "_route_boustrophedon_" in s.coverage.layer_family
        }
        assert rb_families, "no route_boustrophedon family fired"

    def test_eight_letter_keyword_seeds_width_8(self):
        """ARTIFACT is 8 letters; the clue_keyword_length width source
        seeds width=8 even when the clue text has no phrase-bound
        anchor for route_width. This is the path that closes the
        K4B-007 gap: the clue says "eight-column" (phrase bound) AND
        an 8-letter clue word ARTIFACT exists.
        """
        widths = _route_boustrophedon_widths_for_payload(
            self._TOY_CLUE, ["ARCHIVE", "ARTIFACT", "EDGE"],
        )
        # ARTIFACT has length 8 — should appear via
        # clue_keyword_length provenance.
        kw_widths = [
            (w, src) for w, src in widths
            if src == "clue_keyword_length"
        ]
        assert (8, "clue_keyword_length") in kw_widths


# ---------------------------------------------------------------------------
# (6) Layer-order coverage
# ---------------------------------------------------------------------------


class TestLayerOrderCoverage:
    def _toy_specs(self):
        return generate_layered_specs(
            _ABC, bench_slug="t",
            clue_text=(
                "archive column walk through the ragged grid, "
                "every artifact count by route"
            ),
            max_specs=20000,
        )

    @pytest.mark.parametrize("partner,family", [
        ("vigenere", "route_boustrophedon_vigenere"),
        ("beaufort", "route_boustrophedon_beaufort"),
        ("variant_beaufort", "route_boustrophedon_variant_beaufort"),
    ])
    def test_two_layer_both_orders(self, partner, family):
        specs = self._toy_specs()
        fam = [s for s in specs if s.coverage.layer_family == family]
        assert fam
        orders = {s.coverage.layer_order for s in fam}
        assert (partner, "route_boustrophedon") in orders
        assert ("route_boustrophedon", partner) in orders

    def test_route_boustrophedon_atbash_both_orders(self):
        specs = self._toy_specs()
        fam = [
            s for s in specs
            if s.coverage.layer_family == "route_boustrophedon_atbash"
        ]
        assert fam
        orders = {s.coverage.layer_order for s in fam}
        assert ("atbash", "route_boustrophedon") in orders
        assert ("route_boustrophedon", "atbash") in orders

    def test_route_boustrophedon_rail_fence_both_orders(self):
        specs = self._toy_specs()
        fam = [
            s for s in specs
            if s.coverage.layer_family == "route_boustrophedon_rail_fence"
        ]
        assert fam
        orders = {s.coverage.layer_order for s in fam}
        assert ("rail_fence", "route_boustrophedon") in orders
        assert ("route_boustrophedon", "rail_fence") in orders

    def test_three_layer_rail_fence_four_orderings(self):
        specs = self._toy_specs()
        fam = [
            s for s in specs
            if s.coverage.layer_family
            == "vigenere_route_boustrophedon_rail_fence"
        ]
        assert fam
        orders = {s.coverage.layer_order for s in fam}
        assert ("vigenere", "route_boustrophedon", "rail_fence") in orders
        assert ("rail_fence", "route_boustrophedon", "vigenere") in orders
        assert ("route_boustrophedon", "vigenere", "rail_fence") in orders
        assert ("rail_fence", "vigenere", "route_boustrophedon") in orders

    def test_three_layer_columnar_two_orderings(self):
        specs = self._toy_specs()
        fam = [
            s for s in specs
            if s.coverage.layer_family
            == "vigenere_route_boustrophedon_columnar"
        ]
        assert fam, (
            "three-layer vigenere_route_boustrophedon_columnar family "
            "must be present in the catalog"
        )
        orders = {s.coverage.layer_order for s in fam}
        assert ("vigenere", "route_boustrophedon", "columnar") in orders
        assert ("columnar", "route_boustrophedon", "vigenere") in orders


# ---------------------------------------------------------------------------
# (7) Coverage vector new fields
# ---------------------------------------------------------------------------


class TestCoverageVectorRouteFields:
    def test_alone_family_carries_route_metadata(self):
        out = _gen_route_boustrophedon_alone_family(
            bench_slug="t",
            widths=[(8, "phrase_bound_route_width"),
                    (5, "default_set")],
        )
        for s in out:
            assert s.coverage.route_mode == "route_boustrophedon"
            assert s.coverage.route_width in (8, 5)
            assert s.coverage.route_cols == s.coverage.route_width
            # ceil(97 / W) for W in {8, 5}
            if s.coverage.route_width == 8:
                assert s.coverage.route_rows == 13
            else:
                assert s.coverage.route_rows == 20
            assert s.coverage.route_ragged is True  # 97 not divisible
            assert s.coverage.route_direction in ("horizontal", "vertical")
            assert s.coverage.route_width_source in (
                "phrase_bound_route_width", "default_set",
            )

    def test_legacy_specs_keep_empty_route_fields(self):
        specs = generate_layered_specs(
            ["FOO", "BAR"], bench_slug="t",
            clue_text="ordinary problem", max_specs=200,
            include_three_layer=False,
        )
        non_rb = [
            s for s in specs
            if "route_boustrophedon" not in s.coverage.layer_family
        ]
        assert non_rb
        for s in non_rb:
            assert s.coverage.route_mode == "" or (
                # LESSON-011 specs use route_mode="skip_route";
                # they're still non-LESSON-014.
                s.coverage.route_mode == "skip_route"
            )
            assert s.coverage.route_width is None
            assert s.coverage.route_rows is None
            assert s.coverage.route_cols is None
            assert s.coverage.route_ragged is None
            assert s.coverage.route_direction == ""
            assert s.coverage.route_width_source == ""

    def test_dict_round_trip(self):
        cv = CoverageVector(
            layer_family="route_boustrophedon",
            layer_order=("route_boustrophedon",),
            role_assignment=(),
            alphabet="AZ", n_layers=1,
            route_mode="route_boustrophedon",
            route_width=8, route_rows=13, route_cols=8,
            route_ragged=True, route_direction="vertical",
            route_width_source="phrase_bound_route_width",
            operation_source="phrase_bound_route_width",
        )
        d = cv.to_dict()
        assert d["route_mode"] == "route_boustrophedon"
        assert d["route_width"] == 8
        assert d["route_rows"] == 13
        assert d["route_cols"] == 8
        assert d["route_ragged"] is True
        assert d["route_direction"] == "vertical"
        assert d["route_width_source"] == "phrase_bound_route_width"
        cv2 = CoverageVector.from_dict(d)
        assert cv2.route_mode == "route_boustrophedon"
        assert cv2.route_width == 8
        assert cv2.route_rows == 13
        assert cv2.route_cols == 8
        assert cv2.route_ragged is True
        assert cv2.route_direction == "vertical"
        assert cv2.route_width_source == "phrase_bound_route_width"


# ---------------------------------------------------------------------------
# (8) Real-K4 mode unchanged
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
        seeds = controller._collect_hcc_seeds()
        assert seeds == []

    def test_lesson_014_in_registry_for_real_k4(self, tmp_path):
        reg = LessonRegistry(
            path=tmp_path / "lessons.json", seed_defaults=True,
        )
        ids = {l.lesson_id for l in reg.all()}
        assert "LESSON-014" in ids

    def test_no_route_boustrophedon_emission_without_trigger(self):
        """A clue without route_boustrophedon triggers MUST NOT emit
        route_boustrophedon specs (regression guard for 'historical
        catalog unchanged' contract).
        """
        specs = generate_layered_specs(
            ["FOO", "BAR"], bench_slug="t",
            clue_text="just an ordinary cipher problem",
            max_specs=2000,
        )
        rb_specs = [
            s for s in specs
            if "route_boustrophedon" in s.coverage.layer_family
        ]
        assert rb_specs == [], (
            f"unexpected route_boustrophedon specs without trigger: "
            f"{[s.coverage.layer_family for s in rb_specs[:3]]}"
        )


# ---------------------------------------------------------------------------
# (9) Internal helpers
# ---------------------------------------------------------------------------


class TestInternalHelpers:
    def test_layer_rejects_invalid_width(self):
        with pytest.raises(ValueError):
            _route_boustrophedon_layer(0)
        with pytest.raises(ValueError):
            _route_boustrophedon_layer(1)

    def test_default_widths_includes_eight(self):
        """Width 8 is in the default set so the LESSON-014 generator
        emits the K4B-007 width even without phrase-bound or
        clue-keyword sources.
        """
        assert 8 in _DEFAULT_ROUTE_BOUSTROPHEDON_WIDTHS


# ---------------------------------------------------------------------------
# (10) Replayability through dispatcher (end-to-end via execute)
# ---------------------------------------------------------------------------


class TestReplayability:
    def test_execute_emits_attempt_with_coverage_vector(self, tmp_path):
        """A LESSON-014 spec dispatched via the alone family produces
        a coverage_vector dict that round-trips back to a
        CoverageVector. This is the artifact-reader contract: the
        question "did we test vigenere(ARCHIVE) followed by ragged
        boustrophedon width 8?" must be answerable from the attempt
        artifact alone.
        """
        specs = _gen_route_boustrophedon_alone_family(
            bench_slug="t",
            widths=[(8, "phrase_bound_route_width")],
        )
        for s in specs:
            cv_dict = s.coverage.to_dict()
            assert cv_dict["route_mode"] == "route_boustrophedon"
            assert cv_dict["route_width"] == 8
            cv2 = CoverageVector.from_dict(cv_dict)
            # Check route-relevant fields preserve round-trip. The
            # ``extras`` tuple gets re-sorted by ``from_dict`` so a
            # strict equality on the whole CoverageVector is not
            # appropriate; the LESSON-014 telemetry is what matters
            # for the artifact-reader contract.
            assert cv2.route_mode == s.coverage.route_mode
            assert cv2.route_width == s.coverage.route_width
            assert cv2.route_rows == s.coverage.route_rows
            assert cv2.route_cols == s.coverage.route_cols
            assert cv2.route_ragged == s.coverage.route_ragged
            assert cv2.route_direction == s.coverage.route_direction
            assert cv2.route_width_source == s.coverage.route_width_source
            assert cv2.layer_family == s.coverage.layer_family
            assert cv2.layer_order == s.coverage.layer_order


# ---------------------------------------------------------------------------
# (11) K4B-007 canary
# ---------------------------------------------------------------------------


class TestK4B007Canary:
    """K4B-007 canary: confirms the LESSON-014 catalog produces an
    auditable vigenere(ARCHIVE) + route_boustrophedon(width=8,
    vertical=True) spec from the K4B-007 clue. The canary does NOT
    hard-code the K4B-007 plaintext; it only checks that the spec
    universe contains the required (sub_keyword, route_width,
    route_direction) candidate.
    """

    def test_k4b007_archive_width_8_in_catalog(self):
        if not _K4B007_PATH.exists():
            pytest.skip(f"K4B-007 fixture not on disk at {_K4B007_PATH}")
        from kryptosbot.bench_loader import load_k4bench_challenge
        from kryptosbot.bench_fallback import hand_cipher_core_fallback
        ch = load_k4bench_challenge(_K4B007_PATH)
        ch.install_kernel_overrides()
        seeds = hand_cipher_core_fallback(ch.canonical_facts(), n_target=5)
        # Look for vigenere(ARCHIVE) ∘ route_boustrophedon(width=8)
        match = [
            s for s in seeds
            if s.minimal_test_spec.get("coverage_vector", {}).get(
                "route_width"
            ) == 8
            and s.minimal_test_spec.get("coverage_vector", {}).get(
                "substitution_keyword"
            ) == "ARCHIVE"
            and s.minimal_test_spec.get("coverage_vector", {}).get(
                "route_mode"
            ) == "route_boustrophedon"
        ]
        assert match, (
            "K4B-007 HCC catalog must contain at least one "
            "vigenere(ARCHIVE) + route_boustrophedon(width=8) seed. "
            "If this fails, the LESSON-014 trigger / width-derivation "
            "path is broken."
        )

    def test_k4b007_seeds_carry_explicit_telemetry(self):
        if not _K4B007_PATH.exists():
            pytest.skip(f"K4B-007 fixture not on disk at {_K4B007_PATH}")
        from kryptosbot.bench_loader import load_k4bench_challenge
        from kryptosbot.bench_fallback import hand_cipher_core_fallback
        ch = load_k4bench_challenge(_K4B007_PATH)
        ch.install_kernel_overrides()
        seeds = hand_cipher_core_fallback(ch.canonical_facts(), n_target=5)
        rb_seeds = [
            s for s in seeds
            if "route_boustrophedon" in s.minimal_test_spec.get(
                "coverage_vector", {}
            ).get("layer_family", "")
        ]
        assert rb_seeds, "K4B-007 catalog has no route_boustrophedon seeds"
        for s in rb_seeds:
            cv = s.minimal_test_spec["coverage_vector"]
            assert cv.get("route_mode") == "route_boustrophedon", (
                f"missing route_mode in seed {s.hypothesis_id}"
            )
            assert isinstance(cv.get("route_width"), int)
            assert isinstance(cv.get("route_rows"), int)
            assert isinstance(cv.get("route_cols"), int)
            assert isinstance(cv.get("route_ragged"), bool)
            assert cv.get("route_direction") in ("horizontal", "vertical")
            assert cv.get("route_width_source") in (
                "phrase_bound_route_width",
                "clue_keyword_length",
                "default_set",
            )
