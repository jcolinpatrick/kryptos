"""Tests for LESSON-015 — alternate-row reversal / folded-strip route
transposition capability.

Pinned properties:

  1. ``LessonRegistry`` seeds LESSON-015 with the trigger
     vocabulary, default widths, and parity options. Drift test:
     runtime constants in ``hand_cipher_core`` match the lesson's
     parameters.
  2. The DSL accepts a ``row_reverse`` cipher kind with ``width``,
     ``parity``, and ``start_row`` parameters; the dispatcher
     translates it to a ``transposition_full`` perm that is both
     length-preserving (bijection of [0, CT_LEN)) and SELF-INVERSE
     (perm[perm[i]] == i for every i). The trailing partial row is
     reversed in place when its row-index is selected (ragged-
     aware).
  3. The CoverageVector dataclass exposes ``row_reverse_width``,
     ``row_reverse_parity``, ``row_reverse_source``,
     ``row_reverse_ragged``, ``row_reverse_start_row`` fields with
     dict round-trip.
  4. Trigger detection: a clue text containing any of the
     LESSON-015 trigger tokens or multi-word phrases flips
     ``_detect_row_reverse_trigger``. Without a trigger the
     historical catalog is bit-identical (no row_reverse specs
     emitted).
  5. The user-mandated synthetic toy clue
     ``"shadow strip on wall, reverse every other row, folded
     ten-wide panel"`` causes HCC to emit vigenere(SHADOW) +
     row_reverse(width=10, parity=odd) before any LLM call (and
     in the standard layer-order / parity matrix).
  6. Width source priority phrase-bound > clue keyword length >
     default. Bounded width range. Excluded source categories
     (rail_depth / shift_value / block_size / step / offset) do
     NOT pollute the row_reverse width list.
  7. ``row_reverse`` differs from a plain ``route`` (serpentine
     grid read) and from ``route_boustrophedon`` (single-perm
     serpentine). The two transformations produce different
     permutations.
  8. All major two-layer orderings present (row_reverse + sub in
     both orders; sub + route + row_reverse three-layer in 4
     orderings; sub + route_boustrophedon + row_reverse in 4
     orderings).
  9. Replayability: dispatching the same (width, parity,
     start_row) twice produces identical perms.
 10. Real-K4 mode unchanged: ``_collect_hcc_seeds`` returns ``[]``
     in real-K4 mode; LESSON-015 entry IS in the registry as a
     generalized tactic.
 11. K4B-008 canary: HCC catalog contains a vigenere(SHADOW) +
     mirrored_KA + row_reverse(width=97, parity=odd) candidate
     (the no-fold sentinel that lets the catalog reach
     substitution-alone-equivalent specs without a separate
     alone family).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from kryptosbot.solver_capabilities import _default_lessons, LessonRegistry
from kryptosbot.hand_cipher_core import (
    AlphabetMode,
    CoverageVector,
    _DEFAULT_ROW_REVERSE_WIDTHS,
    _DEFAULT_ROW_REVERSE_PARITIES,
    _ROW_REVERSE_TRIGGER_TOKENS,
    _ROW_REVERSE_TRIGGER_PHRASES,
    _ROW_REVERSE_MIN_WIDTH,
    _ROW_REVERSE_MAX_WIDTH,
    _ROW_REVERSE_MAX_KEYWORD_WIDTH,
    _detect_row_reverse_trigger,
    _extract_phrase_bound_row_reverse_widths,
    _gen_row_reverse_alone_family,
    _gen_row_reverse_atbash_family,
    _gen_row_reverse_caesar_family,
    _gen_row_reverse_rail_fence_family,
    _gen_row_reverse_route_three_layer_family,
    _gen_row_reverse_substitution_family,
    _row_reverse_layer,
    _row_reverse_widths_for_payload,
    generate_layered_specs,
)


_REPO_ROOT = Path(__file__).resolve().parents[2]
_K4B008_PATH = _REPO_ROOT / "bench" / "k4bench" / "challenges" / "K4B-008.json"

_ABC = ["ALPHA", "BRAVO", "CHARLIE"]


# ---------------------------------------------------------------------------
# (1) LessonRegistry
# ---------------------------------------------------------------------------


class TestLessonRegistry:
    def test_lesson_015_present(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        assert "LESSON-015" in lessons
        l = lessons["LESSON-015"]
        assert l.tactic_kind == "alternate_row_reversal_folded_strip"
        assert l.generates_specs is True

    def test_lesson_015_has_required_trigger_vocabulary(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-015"]
        triggers = set(l.tactic_parameters.get("trigger_tokens", []))
        # User-mandated set: fold/folded/unfold/unfolded/folding,
        # reverse/reversed/reversal, row/rows, line/lines, strip/
        # strips, wall, panel, boustrophedon, serpentine, zigzag,
        # alternate/alternating
        required = {
            "fold", "folded", "unfold", "unfolded", "folding",
            "reverse", "reversed", "reversal",
            "row", "rows", "line", "lines",
            "strip", "strips", "wall", "panel",
            "boustrophedon", "serpentine", "zigzag",
            "alternate", "alternating",
        }
        missing = required - triggers
        assert not missing, f"LESSON-015 trigger_tokens missing: {missing}"

    def test_lesson_015_has_required_phrase_triggers(self):
        """Multi-word phrases like 'every other' / 'left edge' must
        be recognized."""
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-015"]
        triggers = set(l.tactic_parameters.get("trigger_tokens", []))
        # The phrase triggers are stored in the same trigger_tokens
        # list (mirrors the runtime `_ROW_REVERSE_TRIGGER_PHRASES`).
        assert "every other" in triggers or any(
            "every other" in p for p in _ROW_REVERSE_TRIGGER_PHRASES
        )

    def test_lesson_015_default_widths_match_user_spec(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-015"]
        widths = list(l.tactic_parameters.get("default_widths", []))
        assert all(isinstance(w, int) and w >= 2 for w in widths)
        # User spec: "5, 7, 8, 10, 12, 14"
        for w in (5, 7, 8, 10, 12, 14):
            assert w in widths, f"default width {w} missing"

    def test_lesson_015_excludes_unrelated_width_sources(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-015"]
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
            assert label in excluded

    def test_lesson_015_runtime_drift(self):
        """Drift test: runtime trigger tokens, default widths, and
        bound constants match the registry entry.
        """
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-015"]
        assert set(l.tactic_parameters["trigger_tokens"]) == set(
            _ROW_REVERSE_TRIGGER_TOKENS
        ) | set(_ROW_REVERSE_TRIGGER_PHRASES)
        assert tuple(l.tactic_parameters["default_widths"]) == (
            _DEFAULT_ROW_REVERSE_WIDTHS
        )
        assert l.tactic_parameters["min_width"] == (
            _ROW_REVERSE_MIN_WIDTH
        )
        assert l.tactic_parameters["max_width"] == (
            _ROW_REVERSE_MAX_WIDTH
        )
        assert l.tactic_parameters["max_clue_keyword_width"] == (
            _ROW_REVERSE_MAX_KEYWORD_WIDTH
        )

    def test_lesson_015_records_self_inverse_contract(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-015"]
        assert l.tactic_parameters.get("self_inverse") is True
        assert l.tactic_parameters.get("length_preserving") is True

    def test_lesson_registry_round_trip(self, tmp_path):
        path = tmp_path / "lessons.json"
        reg1 = LessonRegistry(path=path, seed_defaults=True)
        ids1 = {l.lesson_id for l in reg1.all()}
        assert "LESSON-015" in ids1
        reg2 = LessonRegistry(path=path, seed_defaults=True)
        ids2 = {l.lesson_id for l in reg2.all()}
        assert "LESSON-015" in ids2


# ---------------------------------------------------------------------------
# (2) DSL + dispatcher accept row_reverse
# ---------------------------------------------------------------------------


class TestDslAndDispatcher:
    def test_dsl_validates_row_reverse_layer(self):
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "row_reverse", "alphabet": "AZ",
                "params": [
                    {"name": "width", "values": [10]},
                    {"name": "parity", "values": ["odd"]},
                    {"name": "start_row", "values": [0]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        assert parsed.is_valid, parsed.errors

    def test_dispatcher_supported_kinds_includes_row_reverse(self):
        from kryptosbot.job_dispatcher import (
            _SUPPORTED_KINDS, _kind_has_translation,
        )
        assert "row_reverse" in _SUPPORTED_KINDS
        assert _kind_has_translation("row_reverse")

    @pytest.mark.parametrize("width", [2, 5, 7, 8, 10, 12, 14, 16, 50, 97])
    @pytest.mark.parametrize("parity", ["odd", "even", "both"])
    def test_perm_is_length_preserving_bijection(self, width, parity):
        """Every (width, parity) pair produces a perm of length
        CT_LEN that is a complete bijection of [0, CT_LEN). The
        ragged final row is reversed in place when selected.
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer
        from kryptos.kernel.constants import CT_LEN
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "row_reverse", "alphabet": "AZ",
                "params": [
                    {"name": "width", "values": [width]},
                    {"name": "parity", "values": [parity]},
                    {"name": "start_row", "values": [0]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        out = _translate_layer(
            parsed.value.pipeline[0],
            {"width": width, "parity": parity, "start_row": 0},
        )
        perm = out["params"]["perm"]
        assert len(perm) == CT_LEN
        assert sorted(perm) == list(range(CT_LEN))

    @pytest.mark.parametrize("width", [3, 5, 7, 8, 10, 12, 14, 50, 97])
    @pytest.mark.parametrize("parity", ["odd", "even"])
    def test_perm_is_self_inverse(self, width, parity):
        """row_reverse is its own inverse: perm[perm[i]] == i for
        every position i. This is the SELF-INVERSE contract that
        makes the operation safe to apply in any direction.
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer
        from kryptos.kernel.constants import CT_LEN
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "row_reverse", "alphabet": "AZ",
                "params": [
                    {"name": "width", "values": [width]},
                    {"name": "parity", "values": [parity]},
                    {"name": "start_row", "values": [0]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        out = _translate_layer(
            parsed.value.pipeline[0],
            {"width": width, "parity": parity, "start_row": 0},
        )
        perm = out["params"]["perm"]
        for i in range(CT_LEN):
            assert perm[perm[i]] == i, (
                f"width={width} parity={parity}: perm not self-inverse "
                f"at i={i}"
            )

    def test_no_fold_sentinel_is_identity(self):
        """width=CT_LEN with parity=odd is the no-fold sentinel:
        only row 0 exists; row 0 is even; parity=odd selects no
        rows, so the perm is identity. This case is intentionally
        reachable and lets the catalog cover substitution-alone-
        equivalent specs.
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer
        from kryptos.kernel.constants import CT_LEN
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "row_reverse", "alphabet": "AZ",
                "params": [
                    {"name": "width", "values": [CT_LEN]},
                    {"name": "parity", "values": ["odd"]},
                    {"name": "start_row", "values": [0]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        out = _translate_layer(
            parsed.value.pipeline[0],
            {"width": CT_LEN, "parity": "odd", "start_row": 0},
        )
        assert out["params"]["perm"] == list(range(CT_LEN))

    def test_translator_rejects_invalid_width(self):
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import (
            _translate_layer, DispatcherError,
        )
        from kryptos.kernel.constants import CT_LEN
        for bad in (1, 0, -1, CT_LEN + 1):
            spec = {
                "hypothesis_id": "t",
                "pipeline": [{
                    "kind": "row_reverse", "alphabet": "AZ",
                    "params": [
                        {"name": "width", "values": [bad]},
                        {"name": "parity", "values": ["odd"]},
                        {"name": "start_row", "values": [0]},
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
                    {"width": bad, "parity": "odd", "start_row": 0},
                )

    def test_translator_rejects_invalid_parity(self):
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import (
            _translate_layer, DispatcherError,
        )
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "row_reverse", "alphabet": "AZ",
                "params": [
                    {"name": "width", "values": [10]},
                    {"name": "parity", "values": ["bogus"]},
                    {"name": "start_row", "values": [0]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        with pytest.raises(DispatcherError, match="parity"):
            _translate_layer(
                parsed.value.pipeline[0],
                {"width": 10, "parity": "bogus", "start_row": 0},
            )

    def test_perm_replayability_deterministic(self):
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "row_reverse", "alphabet": "AZ",
                "params": [
                    {"name": "width", "values": [10]},
                    {"name": "parity", "values": ["odd"]},
                    {"name": "start_row", "values": [0]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        out1 = _translate_layer(
            parsed.value.pipeline[0],
            {"width": 10, "parity": "odd", "start_row": 0},
        )
        out2 = _translate_layer(
            parsed.value.pipeline[0],
            {"width": 10, "parity": "odd", "start_row": 0},
        )
        assert out1["params"]["perm"] == out2["params"]["perm"]

    def test_ragged_final_row_reversed(self):
        """When the final row is partial (ragged) AND its row-index
        is selected by the parity, the final row IS reversed in
        place. CT_LEN=97 with width=10 leaves a final row of length
        7 at row index 9 (odd); parity=odd selects it.
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer
        from kryptos.kernel.constants import CT_LEN
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "row_reverse", "alphabet": "AZ",
                "params": [
                    {"name": "width", "values": [10]},
                    {"name": "parity", "values": ["odd"]},
                    {"name": "start_row", "values": [0]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        out = _translate_layer(
            parsed.value.pipeline[0],
            {"width": 10, "parity": "odd", "start_row": 0},
        )
        perm = out["params"]["perm"]
        # Final row covers positions 90..96 (length 7). Reversed
        # in place: pos 90 ← 96, pos 91 ← 95, ..., pos 96 ← 90.
        for k in range(7):
            assert perm[90 + k] == 90 + (7 - 1 - k)

    def test_row_reverse_parity_even_differs_from_route(self):
        """row_reverse(width=10, parity=EVEN) reverses rows 0, 2,
        4, ... — distinct from a serpentine route which always
        reverses rows 1, 3, 5, ... (parity=odd in our terms).
        This parity flip is the genuinely new capability LESSON-
        015 contributes over the existing route / route_boustro-
        phedon kinds.
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer
        rr_spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "row_reverse", "alphabet": "AZ",
                "params": [
                    {"name": "width", "values": [10]},
                    {"name": "parity", "values": ["even"]},
                    {"name": "start_row", "values": [0]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        rt_spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "route", "alphabet": "AZ",
                "params": [
                    {"name": "variant", "values": ["serpentine"]},
                    {"name": "rows", "values": [10]},
                    {"name": "cols", "values": [10]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        rr_parsed = validate_hypothesis_spec(rr_spec)
        rt_parsed = validate_hypothesis_spec(rt_spec)
        rr_out = _translate_layer(
            rr_parsed.value.pipeline[0],
            {"width": 10, "parity": "even", "start_row": 0},
        )
        rt_out = _translate_layer(
            rt_parsed.value.pipeline[0],
            {"variant": "serpentine", "rows": 10, "cols": 10},
        )
        assert rr_out["params"]["perm"] != rt_out["params"]["perm"]

    def test_row_reverse_parity_even_differs_from_route_boustrophedon(self):
        """row_reverse(parity=even) reverses the OPPOSITE rows
        from horizontal route_boustrophedon (which always reverses
        odd rows). This documents the parity-flip capability LESSON-
        015 brings over LESSON-014.

        Note: ``row_reverse(parity=odd)`` IS mathematically
        equivalent to horizontal ``route_boustrophedon`` for the
        same width. That equivalence is intentional and reflects
        cipher reality — LESSON-015's new capability is ``parity=
        even`` and ``parity=both``, not a redefinition of
        serpentine.
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer
        rr_spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "row_reverse", "alphabet": "AZ",
                "params": [
                    {"name": "width", "values": [10]},
                    {"name": "parity", "values": ["even"]},
                    {"name": "start_row", "values": [0]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        rb_spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "route_boustrophedon", "alphabet": "AZ",
                "params": [
                    {"name": "width", "values": [10]},
                    {"name": "vertical", "values": [False]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        rr_parsed = validate_hypothesis_spec(rr_spec)
        rb_parsed = validate_hypothesis_spec(rb_spec)
        rr_out = _translate_layer(
            rr_parsed.value.pipeline[0],
            {"width": 10, "parity": "even", "start_row": 0},
        )
        rb_out = _translate_layer(
            rb_parsed.value.pipeline[0],
            {"width": 10, "vertical": False},
        )
        assert rr_out["params"]["perm"] != rb_out["params"]["perm"]

    def test_row_reverse_odd_equals_horizontal_route_boustrophedon(self):
        """Documents the intentional mathematical equivalence:
        ``row_reverse(width=W, parity=odd, start_row=0)`` produces
        the SAME permutation as horizontal
        ``route_boustrophedon(width=W, vertical=False)`` for any
        width W. This is not a bug — both operations reverse rows
        1, 3, 5, ... in place. LESSON-015's new capability comes
        from parity=even and parity=both.
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer
        rr_spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "row_reverse", "alphabet": "AZ",
                "params": [
                    {"name": "width", "values": [8]},
                    {"name": "parity", "values": ["odd"]},
                    {"name": "start_row", "values": [0]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        rb_spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "route_boustrophedon", "alphabet": "AZ",
                "params": [
                    {"name": "width", "values": [8]},
                    {"name": "vertical", "values": [False]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        rr_out = _translate_layer(
            validate_hypothesis_spec(rr_spec).value.pipeline[0],
            {"width": 8, "parity": "odd", "start_row": 0},
        )
        rb_out = _translate_layer(
            validate_hypothesis_spec(rb_spec).value.pipeline[0],
            {"width": 8, "vertical": False},
        )
        assert rr_out["params"]["perm"] == rb_out["params"]["perm"]


# ---------------------------------------------------------------------------
# (3) Trigger detection
# ---------------------------------------------------------------------------


class TestTriggerDetection:
    @pytest.mark.parametrize("text,expected", [
        ("the strip is folded", True),
        ("reverse every other row", True),
        ("alternate the rows", True),
        ("a folded panel", True),
        ("read back the line", True),
        ("turn back the wall", True),
        ("plain caesar shift", False),
        ("ordinary substitution", False),
        ("", False),
    ])
    def test_detect_row_reverse_trigger(self, text, expected):
        assert _detect_row_reverse_trigger(text) is expected

    def test_word_boundary_negative(self):
        """``row`` inside ``arrow`` must NOT trigger (boundary is
        violated by the preceding alphabetic).
        """
        assert _detect_row_reverse_trigger("arrowhead") is False
        assert _detect_row_reverse_trigger("a single row of text") is True


# ---------------------------------------------------------------------------
# (4) Width extraction + width source priority
# ---------------------------------------------------------------------------


class TestWidthExtraction:
    def test_phrase_bound_width_from_hyphen_compound(self):
        assert 10 in _extract_phrase_bound_row_reverse_widths(
            "a folded ten-wide strip"
        )

    def test_phrase_bound_width_from_after_anchor(self):
        assert 10 in _extract_phrase_bound_row_reverse_widths(
            "the strip has 10 rows"
        )

    def test_phrase_bound_width_from_before_anchor(self):
        assert 8 in _extract_phrase_bound_row_reverse_widths(
            "with strip of width 8"
        )

    def test_phrase_bound_width_via_cardinal_word(self):
        assert 10 in _extract_phrase_bound_row_reverse_widths(
            "ten-wide folded panel"
        )

    def test_width_source_priority(self):
        widths = _row_reverse_widths_for_payload(
            "ten-wide folded strip", ["SHADOW", "KRYPTOS"],
        )
        # Phrase-bound 10 first
        assert widths[0] == (10, "phrase_bound_row_reverse_width")
        # SHADOW (6) and KRYPTOS (7) appear via clue_keyword_length
        kw_entries = [
            (w, s) for w, s in widths if s == "clue_keyword_length"
        ]
        assert (6, "clue_keyword_length") in kw_entries
        assert (7, "clue_keyword_length") in kw_entries
        # Defaults still appear
        defaults = [s for _, s in widths if s == "default_set"]
        assert defaults

    def test_no_fold_sentinel_appended(self):
        """The ct_length=97 sentinel is appended last so the
        catalog can express substitution-alone-equivalent specs
        via row_reverse(97, odd) = identity.
        """
        widths = _row_reverse_widths_for_payload(
            "folded strip", [], ct_length=97,
        )
        assert any(w == 97 for w, _ in widths)

    def test_excluded_sources_do_not_pollute_row_reverse_width(self):
        """Numerals attached to rail/shift/block/step/offset
        anchors must NOT propagate into the row_reverse width list
        as phrase_bound.
        """
        widths = _row_reverse_widths_for_payload(
            "shift 8 with depth four and rot 13", [],
        )
        for _, src in widths:
            assert src != "phrase_bound_row_reverse_width", (
                "rail/shift/block/step numerals must NOT bind to "
                "row_reverse_width"
            )


# ---------------------------------------------------------------------------
# (5) User-mandated synthetic toy clue
# ---------------------------------------------------------------------------


class TestSyntheticToyClue:
    """User-mandated clue:
    ``"shadow strip on wall, reverse every other row, folded
    ten-wide panel"``
    must cause HCC to emit vigenere(SHADOW) + row_reverse(width=10,
    parity=odd) before any LLM call.
    """

    _TOY_CLUE = (
        "shadow strip on wall, reverse every other row, "
        "folded ten-wide panel"
    )

    def test_row_reverse_alone_emitted(self):
        specs = generate_layered_specs(
            ["SHADOW", "STRIP", "WALL", "PANEL"], bench_slug="toy",
            clue_text=self._TOY_CLUE, max_specs=20000,
        )
        match = [
            s for s in specs
            if s.coverage.layer_family == "row_reverse"
        ]
        assert match, "row_reverse alone NOT emitted from toy clue"

    def test_vigenere_shadow_paired_emitted(self):
        specs = generate_layered_specs(
            ["SHADOW", "STRIP", "WALL", "PANEL"], bench_slug="toy",
            clue_text=self._TOY_CLUE, max_specs=20000,
        )
        match = [
            s for s in specs
            if s.coverage.layer_family == "row_reverse_vigenere"
            and s.coverage.substitution_keyword == "SHADOW"
            and s.coverage.row_reverse_width == 10
            and s.coverage.row_reverse_parity == "odd"
        ]
        assert match, (
            "vigenere(SHADOW) + row_reverse(width=10, parity=odd) "
            "NOT emitted from toy clue"
        )

    def test_no_llm_required_for_emission(self):
        specs = generate_layered_specs(
            ["SHADOW", "STRIP", "WALL", "PANEL"], bench_slug="toy",
            clue_text=self._TOY_CLUE, max_specs=20000,
        )
        rr_families = {
            s.coverage.layer_family for s in specs
            if s.coverage.layer_family.startswith("row_reverse")
            or "_row_reverse" in s.coverage.layer_family
        }
        assert rr_families, "no row_reverse family fired"


# ---------------------------------------------------------------------------
# (6) Layer-order coverage
# ---------------------------------------------------------------------------


class TestLayerOrderCoverage:
    def _toy_specs(self):
        return generate_layered_specs(
            _ABC, bench_slug="t",
            clue_text=(
                "a folded strip with reversed rows on the panel"
            ),
            max_specs=30000,
        )

    @pytest.mark.parametrize("partner,family", [
        ("vigenere", "row_reverse_vigenere"),
        ("beaufort", "row_reverse_beaufort"),
        ("variant_beaufort", "row_reverse_variant_beaufort"),
    ])
    def test_two_layer_both_orders(self, partner, family):
        specs = self._toy_specs()
        fam = [s for s in specs if s.coverage.layer_family == family]
        assert fam
        orders = {s.coverage.layer_order for s in fam}
        assert (partner, "row_reverse") in orders
        assert ("row_reverse", partner) in orders

    def test_row_reverse_atbash_both_orders(self):
        specs = self._toy_specs()
        fam = [
            s for s in specs
            if s.coverage.layer_family == "row_reverse_atbash"
        ]
        assert fam
        orders = {s.coverage.layer_order for s in fam}
        assert ("atbash", "row_reverse") in orders
        assert ("row_reverse", "atbash") in orders

    def test_row_reverse_rail_fence_both_orders(self):
        specs = self._toy_specs()
        fam = [
            s for s in specs
            if s.coverage.layer_family == "row_reverse_rail_fence"
        ]
        assert fam
        orders = {s.coverage.layer_order for s in fam}
        assert ("rail_fence", "row_reverse") in orders
        assert ("row_reverse", "rail_fence") in orders

    def test_three_layer_route_four_orderings(self):
        specs = self._toy_specs()
        fam = [
            s for s in specs
            if s.coverage.layer_family == "vigenere_route_row_reverse"
        ]
        assert fam
        orders = {s.coverage.layer_order for s in fam}
        # The four canonical orderings emitted by
        # _gen_row_reverse_route_three_layer_family.
        assert ("vigenere", "route", "row_reverse") in orders
        assert ("row_reverse", "route", "vigenere") in orders
        assert ("vigenere", "row_reverse", "route") in orders
        assert ("route", "row_reverse", "vigenere") in orders

    def test_three_layer_route_boustrophedon_four_orderings(self):
        specs = self._toy_specs()
        fam = [
            s for s in specs
            if s.coverage.layer_family
            == "vigenere_route_boustrophedon_row_reverse"
        ]
        assert fam, (
            "three-layer vigenere + route_boustrophedon + "
            "row_reverse family must be present"
        )
        orders = {s.coverage.layer_order for s in fam}
        assert (
            "vigenere", "route_boustrophedon", "row_reverse"
        ) in orders
        assert (
            "row_reverse", "route_boustrophedon", "vigenere"
        ) in orders
        assert (
            "vigenere", "row_reverse", "route_boustrophedon"
        ) in orders
        assert (
            "route_boustrophedon", "row_reverse", "vigenere"
        ) in orders


# ---------------------------------------------------------------------------
# (7) Coverage vector new fields
# ---------------------------------------------------------------------------


class TestCoverageVectorRowReverseFields:
    def test_alone_family_carries_metadata(self):
        out = _gen_row_reverse_alone_family(
            bench_slug="t",
            widths=[(10, "phrase_bound_row_reverse_width"),
                    (8, "clue_keyword_length"),
                    (97, "default_set")],
        )
        for s in out:
            assert s.coverage.layer_family == "row_reverse"
            assert s.coverage.row_reverse_width in (10, 8, 97)
            assert s.coverage.row_reverse_parity in ("odd", "even")
            assert s.coverage.row_reverse_source in (
                "phrase_bound_row_reverse_width",
                "clue_keyword_length",
                "default_set",
            )
            # ragged: 97%10 != 0 → True; 97%8 != 0 → True;
            # 97%97 == 0 → False
            if s.coverage.row_reverse_width in (10, 8):
                assert s.coverage.row_reverse_ragged is True
            elif s.coverage.row_reverse_width == 97:
                assert s.coverage.row_reverse_ragged is False
            assert s.coverage.row_reverse_start_row == 0

    def test_legacy_specs_keep_empty_row_reverse_fields(self):
        specs = generate_layered_specs(
            ["FOO", "BAR"], bench_slug="t",
            clue_text="ordinary problem", max_specs=200,
            include_three_layer=False,
        )
        non_rr = [
            s for s in specs
            if "row_reverse" not in s.coverage.layer_family
        ]
        assert non_rr
        for s in non_rr:
            assert s.coverage.row_reverse_width is None
            assert s.coverage.row_reverse_parity == ""
            assert s.coverage.row_reverse_source == ""
            assert s.coverage.row_reverse_ragged is None
            assert s.coverage.row_reverse_start_row is None

    def test_dict_round_trip(self):
        cv = CoverageVector(
            layer_family="row_reverse",
            layer_order=("row_reverse",),
            role_assignment=(),
            alphabet="AZ", n_layers=1,
            row_reverse_width=10,
            row_reverse_parity="odd",
            row_reverse_source="phrase_bound_row_reverse_width",
            row_reverse_ragged=True,
            row_reverse_start_row=0,
            operation_source="phrase_bound_row_reverse_width",
        )
        d = cv.to_dict()
        assert d["row_reverse_width"] == 10
        assert d["row_reverse_parity"] == "odd"
        assert d["row_reverse_source"] == "phrase_bound_row_reverse_width"
        assert d["row_reverse_ragged"] is True
        assert d["row_reverse_start_row"] == 0
        cv2 = CoverageVector.from_dict(d)
        assert cv2.row_reverse_width == 10
        assert cv2.row_reverse_parity == "odd"
        assert cv2.row_reverse_source == "phrase_bound_row_reverse_width"
        assert cv2.row_reverse_ragged is True
        assert cv2.row_reverse_start_row == 0


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

    def test_lesson_015_in_registry_for_real_k4(self, tmp_path):
        reg = LessonRegistry(
            path=tmp_path / "lessons.json", seed_defaults=True,
        )
        ids = {l.lesson_id for l in reg.all()}
        assert "LESSON-015" in ids

    def test_no_row_reverse_emission_without_trigger(self):
        specs = generate_layered_specs(
            ["FOO", "BAR"], bench_slug="t",
            clue_text="just an ordinary cipher problem",
            max_specs=2000,
        )
        rr_specs = [
            s for s in specs
            if "row_reverse" in s.coverage.layer_family
        ]
        assert rr_specs == [], (
            f"unexpected row_reverse specs without trigger: "
            f"{[s.coverage.layer_family for s in rr_specs[:3]]}"
        )


# ---------------------------------------------------------------------------
# (9) Internal helpers
# ---------------------------------------------------------------------------


class TestInternalHelpers:
    def test_layer_rejects_invalid_width(self):
        with pytest.raises(ValueError):
            _row_reverse_layer(0, "odd")
        with pytest.raises(ValueError):
            _row_reverse_layer(1, "odd")

    def test_layer_rejects_invalid_parity(self):
        with pytest.raises(ValueError):
            _row_reverse_layer(10, "bogus")

    def test_layer_rejects_invalid_start_row(self):
        with pytest.raises(ValueError):
            _row_reverse_layer(10, "odd", start_row=2)


# ---------------------------------------------------------------------------
# (10) K4B-008 canary
# ---------------------------------------------------------------------------


class TestK4B008Canary:
    """K4B-008 canary: the HCC catalog must contain a candidate that
    pairs ``vigenere(SHADOW)`` with ``mirrored_KA`` alphabet AND the
    no-fold sentinel ``row_reverse(width=97, parity=odd)``. That
    sentinel is identity, so this combination is equivalent to a
    single-layer Vigenere — which is the K4B-008 intended path.

    The canary does NOT hard-code the K4B-008 plaintext; it only
    checks that the spec universe contains the required candidate.
    """

    def test_k4b008_no_fold_sentinel_in_catalog(self):
        if not _K4B008_PATH.exists():
            pytest.skip(f"K4B-008 fixture not on disk at {_K4B008_PATH}")
        from kryptosbot.bench_loader import load_k4bench_challenge
        from kryptosbot.bench_fallback import hand_cipher_core_fallback
        ch = load_k4bench_challenge(_K4B008_PATH)
        ch.install_kernel_overrides()
        seeds = hand_cipher_core_fallback(ch.canonical_facts(), n_target=20)
        match = [
            s for s in seeds
            if s.minimal_test_spec.get("coverage_vector", {}).get(
                "row_reverse_width"
            ) == 97
            and s.minimal_test_spec.get("coverage_vector", {}).get(
                "row_reverse_parity"
            ) == "odd"
            and s.minimal_test_spec.get("coverage_vector", {}).get(
                "substitution_keyword"
            ) == "SHADOW"
            and s.minimal_test_spec.get("coverage_vector", {}).get(
                "alphabet_mode"
            ) == "mirrored_ka"
        ]
        assert match, (
            "K4B-008 HCC catalog must contain a vigenere(SHADOW) + "
            "mirrored_KA + row_reverse(width=97, parity=odd) seed. "
            "The no-fold sentinel is the path to substitution-alone-"
            "equivalent specs."
        )

    def test_k4b008_seeds_carry_explicit_row_reverse_telemetry(self):
        if not _K4B008_PATH.exists():
            pytest.skip(f"K4B-008 fixture not on disk at {_K4B008_PATH}")
        from kryptosbot.bench_loader import load_k4bench_challenge
        from kryptosbot.bench_fallback import hand_cipher_core_fallback
        ch = load_k4bench_challenge(_K4B008_PATH)
        ch.install_kernel_overrides()
        seeds = hand_cipher_core_fallback(ch.canonical_facts(), n_target=20)
        rr_seeds = [
            s for s in seeds
            if "row_reverse" in s.minimal_test_spec.get(
                "coverage_vector", {}
            ).get("layer_family", "")
        ]
        assert rr_seeds, "K4B-008 catalog has no row_reverse seeds"
        for s in rr_seeds[:50]:
            cv = s.minimal_test_spec["coverage_vector"]
            assert isinstance(cv.get("row_reverse_width"), int)
            assert cv.get("row_reverse_parity") in ("odd", "even", "both")
            assert cv.get("row_reverse_source") in (
                "phrase_bound_row_reverse_width",
                "clue_keyword_length",
                "default_set",
            )
            assert isinstance(cv.get("row_reverse_ragged"), bool)
            assert cv.get("row_reverse_start_row") in (0, 1)
