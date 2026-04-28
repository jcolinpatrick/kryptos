"""Tests for LESSON-013 — arbitrary columnar column-order enumeration
for small widths.

Pinned properties:

  1. ``LessonRegistry`` seeds LESSON-013 with the documented
     ``tactic_parameters`` (default_widths, max_enumerated_width,
     per_width_caps, width_sources, etc.). The runtime constants in
     ``hand_cipher_core`` match the registry entry (drift test).

  2. Width selection helper ``_columnar_widths_for_payload`` resolves
     widths from phrase_bound_step (LESSON-012) + safe defaults +
     clue_keyword_lengths in priority order, EXCLUDING rail_depth /
     shift_value / block_size / offset bindings.

  3. ``_enumerated_col_orders_for_width`` enumerates all W!
     permutations of ``range(W)`` in lexicographic order, capped at
     ``_PER_WIDTH_PERM_CAP[W]``, with the identity permutation
     ALWAYS skipped (K4B-001 root-cause regression guard) and
     optional dedup against a list of keyword-derived col_orders.

  4. ``_explicit_columnar_layer`` rejects malformed col_orders
     (non-permutations of range(W)) and emits a DSL-shaped layer
     dict matching the dispatcher contract.

  5. The enumerated family generators preserve the existing
     family_labels (``columnar_<sub>``, ``i3_columnar_<sub>``,
     ``caesar_columnar_atbash``) so coverage analysis treats the
     enumerated and keyword-derived specs as the same family.

  6. Per-family budget cap (``_LESSON_013_PER_FAMILY_CAP``) is
     respected — the cap fires after the highest-priority widths
     are filled, never starving phrase_bound_step.

  7. K4B-006 canary: clue ``step five`` resolves to W=5 via the
     phrase_bound_step path, the enumerated W=5 col_orders include
     (4, 1, 3, 0, 2) at lex index 106, and the columnar_<sub>
     family emits at least one spec at W=5 co=(4,1,3,0,2) for
     sub_kw=MIRROR + alpha=AZ in both layer orders.

  8. Real-K4 mode unchanged: ``_collect_hcc_seeds`` returns ``[]``
     in real-K4 mode, so LESSON-013 family generators never auto-
     emit on real K4. The LESSON-013 entry is still in the
     registry as a generalized tactic the LLM theorist can read.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from kryptosbot.solver_capabilities import _default_lessons
from kryptosbot.hand_cipher_core import (
    AlphabetMode,
    CoverageVector,
    _DEFAULT_COLUMNAR_WIDTHS,
    _MAX_ENUMERATED_WIDTH,
    _PER_WIDTH_PERM_CAP,
    _LESSON_013_PER_FAMILY_CAP,
    _LESSON_013_ALPHABET_MODES,
    _columnar_widths_for_payload,
    _enumerated_col_orders_for_width,
    _explicit_columnar_layer,
    _gen_enumerated_columnar_pair_family,
    _gen_enumerated_columnar_i3_family,
    _gen_enumerated_caesar_columnar_atbash_family,
    _keyword_to_col_order,
    generate_layered_specs,
)


_REPO_ROOT = Path(__file__).resolve().parents[2]
_K4B006_PATH = _REPO_ROOT / "bench" / "k4bench" / "challenges" / "K4B-006.json"
_K4B006_CLUE = (
    "The margins show four rails, the word MIRROR, and a route "
    "beginning three steps from the start with step five."
)
_K4B006_KEYWORDS = [
    "MIRROR", "MARGINS", "RAILS", "WORD", "ROUTE",
    "FENCE", "PATH",
]


# ---------------------------------------------------------------------------
# (1) LessonRegistry contains LESSON-013
# ---------------------------------------------------------------------------


class TestLessonRegistry:
    def test_lesson_013_present_in_defaults(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        assert "LESSON-013" in lessons
        l = lessons["LESSON-013"]
        assert l.tactic_kind == "arbitrary_columnar_order_enumeration"
        assert l.generates_specs is True

    def test_lesson_013_lists_required_tactic_params(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-013"]
        params = l.tactic_parameters
        assert params["default_widths"] == [3, 4, 5]
        assert params["max_enumerated_width"] == 7
        # Per-width caps are JSON-keyed strings in the registry; the
        # runtime constant uses int keys. Verify entries match.
        for w in (2, 3, 4, 5, 6, 7):
            assert str(w) in params["per_width_caps"]
        # Phrase-bound slots: ONLY ``step`` — never rail_depth /
        # shift_value (contamination guard).
        slots = set(params["phrase_bound_slots_for_width"])
        assert slots == {"step"}, (
            f"phrase_bound_slots_for_width must be {{'step'}} only; "
            f"got {slots}. rail_depth/shift_value would explode the "
            "universe with unrelated numerals."
        )

    def test_lesson_013_runtime_drift(self):
        """Drift: registry tactic_parameters must equal the runtime
        constants.
        """
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-013"]
        params = l.tactic_parameters
        assert tuple(params["default_widths"]) == _DEFAULT_COLUMNAR_WIDTHS
        assert params["max_enumerated_width"] == _MAX_ENUMERATED_WIDTH
        for w_str, cap in params["per_width_caps"].items():
            assert _PER_WIDTH_PERM_CAP[int(w_str)] == cap

    def test_lesson_013_alphabet_modes_az_ka_only(self):
        """Registry restricts enumerated path to AZ + KA."""
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-013"]
        modes = set(
            l.tactic_parameters["alphabet_modes_for_enumerated"]
        )
        assert modes == {"AZ", "KA"}
        runtime_labels = {m.mode_label for m in _LESSON_013_ALPHABET_MODES}
        assert runtime_labels == {"AZ", "KA"}


# ---------------------------------------------------------------------------
# (2) Width selection helper
# ---------------------------------------------------------------------------


class TestColumnarWidthsForPayload:
    def test_phrase_bound_step_is_first_priority(self):
        """``step five`` from the K4B-006 clue must yield W=5 from
        phrase_bound_step BEFORE the safe-default set.
        """
        widths = _columnar_widths_for_payload(
            _K4B006_CLUE, _K4B006_KEYWORDS,
        )
        # First two entries should be from phrase_bound_step
        assert widths[0][1] == "phrase_bound_step"
        # The K4B-006 clue binds step=5 (and step=3 from "three steps")
        sources_by_width = {w: src for w, src in widths}
        assert sources_by_width[5] == "phrase_bound_step"

    def test_rail_depth_does_not_pollute_widths(self):
        """``four rails`` in K4B-006 binds rail_depth=4 — that numeral
        must NOT appear as a transposition width source.
        """
        widths = _columnar_widths_for_payload(
            _K4B006_CLUE, _K4B006_KEYWORDS,
        )
        sources_by_width = {w: src for w, src in widths}
        # W=4 IS in the default set, so it appears, but its source
        # MUST be ``default_set`` or ``clue_keyword_length`` (WORD=4)
        # — never ``phrase_bound_rail_depth`` (which is not even a
        # valid source).
        assert sources_by_width.get(4) in {
            "default_set", "clue_keyword_length",
        }
        # No source label should reference rail_depth or shift_value.
        for _, src in widths:
            assert "rail_depth" not in src
            assert "shift_value" not in src
            assert "block_size" not in src

    def test_shift_value_does_not_pollute_widths(self):
        """A clue containing ``shift seven`` must NOT inject W=7 via
        any phrase_bound_shift_value path. (W=7 may appear via clue
        keyword length, but never via shift-value binding.)
        """
        clue = "Apply a Caesar shift seven over the columns."
        widths = _columnar_widths_for_payload(clue, ["ALPHA"])
        for w, src in widths:
            assert src != "phrase_bound_shift_value"
        # W=7 from clue keyword length only fires if a 7-letter
        # keyword is supplied; here ALPHA=5 letters, so no W=7.
        widths_set = {w for w, _ in widths}
        assert 7 not in widths_set

    def test_default_set_always_present(self):
        """When no phrase-bound or clue-keyword source produces a
        width, the default set fires.
        """
        widths = _columnar_widths_for_payload("", [])
        widths_set = {w for w, _ in widths}
        assert widths_set == set(_DEFAULT_COLUMNAR_WIDTHS)

    def test_widths_capped_at_max_enumerated(self):
        """Widths > _MAX_ENUMERATED_WIDTH must be filtered."""
        widths = _columnar_widths_for_payload(
            "step nine", ["LONGKEYWORD"],  # 11 chars
        )
        for w, _ in widths:
            assert 2 <= w <= _MAX_ENUMERATED_WIDTH


# ---------------------------------------------------------------------------
# (3) Col_order enumeration helper
# ---------------------------------------------------------------------------


class TestEnumeratedColOrders:
    def test_width_5_emits_119_perms_after_identity_skip(self):
        """W=5: 5! = 120, minus the identity permutation = 119."""
        co5 = _enumerated_col_orders_for_width(5)
        assert len(co5) == 119
        # The identity (0,1,2,3,4) MUST NOT appear.
        assert (0, 1, 2, 3, 4) not in {c[0] for c in co5}

    def test_width_3_full_enumeration(self):
        """W=3: 3! = 6, minus identity = 5."""
        co3 = _enumerated_col_orders_for_width(3)
        assert len(co3) == 5
        assert (0, 1, 2) not in {c[0] for c in co3}

    def test_width_2_handles_boundary(self):
        """W=2: 2! = 2, minus identity = 1."""
        co2 = _enumerated_col_orders_for_width(2)
        assert len(co2) == 1
        assert co2[0][0] == (1, 0)

    def test_width_below_minimum_returns_empty(self):
        """W < 2 is degenerate (W=1 is identity)."""
        assert _enumerated_col_orders_for_width(1) == []
        assert _enumerated_col_orders_for_width(0) == []

    def test_width_above_max_returns_empty(self):
        """W > _MAX_ENUMERATED_WIDTH (= 7) is out of scope; the
        keyword path still handles longer keywords.
        """
        assert _enumerated_col_orders_for_width(8) == []
        assert _enumerated_col_orders_for_width(20) == []

    def test_lexicographic_order_is_deterministic(self):
        """Two calls with the same width return identical lists."""
        a = _enumerated_col_orders_for_width(5)
        b = _enumerated_col_orders_for_width(5)
        assert a == b

    def test_dedup_against_keyword_col_orders(self):
        """A keyword-derived col_order in ``dedup_against`` must be
        absent from the returned enumeration. Used by the family
        generators to avoid duplicate specs vs the keyword path.
        """
        mirror_co = _keyword_to_col_order("MIRROR")  # W=6 stable rank
        assert len(mirror_co) == 6
        co6 = _enumerated_col_orders_for_width(6, dedup_against=[mirror_co])
        assert tuple(mirror_co) not in {c[0] for c in co6}
        # Identity also still skipped.
        assert (0, 1, 2, 3, 4, 5) not in {c[0] for c in co6}

    def test_per_width_cap_is_respected(self):
        """W=6 has 720 permutations but the cap truncates to 120."""
        cap = _PER_WIDTH_PERM_CAP[6]
        co6 = _enumerated_col_orders_for_width(6)
        assert len(co6) <= cap

    def test_k4b006_target_present_at_lex_index_106(self):
        """Cardinal evidence: K4B-006's empirically-derived winning
        col_order (4, 1, 3, 0, 2) is one of the 119 W=5 entries; it
        sits at lexicographic index 106 (0-indexed). The lesson
        emits this WITHOUT hard-coding — it falls out of the
        general permutation enumeration.
        """
        co5 = _enumerated_col_orders_for_width(5)
        target = (4, 1, 3, 0, 2)
        match = [(co, idx) for co, idx in co5 if co == target]
        assert len(match) == 1
        assert match[0][1] == 106


# ---------------------------------------------------------------------------
# (4) Explicit columnar layer dict
# ---------------------------------------------------------------------------


class TestExplicitColumnarLayer:
    def test_well_formed_layer(self):
        layer = _explicit_columnar_layer(5, [4, 1, 3, 0, 2])
        assert layer["kind"] == "columnar"
        assert layer["alphabet"] == "AZ"
        params = {p["name"]: p["values"][0] for p in layer["params"]}
        assert params["width"] == 5
        assert params["col_order"] == [4, 1, 3, 0, 2]

    def test_rejects_non_permutation(self):
        with pytest.raises(ValueError):
            _explicit_columnar_layer(5, [4, 1, 3, 0, 0])  # dup 0
        with pytest.raises(ValueError):
            _explicit_columnar_layer(5, [4, 1, 3, 0, 5])  # 5 out of range

    def test_rejects_width_below_two(self):
        with pytest.raises(ValueError):
            _explicit_columnar_layer(1, [0])


# ---------------------------------------------------------------------------
# (5) Enumerated columnar pair family
# ---------------------------------------------------------------------------


class TestEnumeratedColumnarPairFamily:
    def test_emits_all_three_sub_kinds(self):
        for sub_kind in ("vigenere", "beaufort", "variant_beaufort"):
            specs = _gen_enumerated_columnar_pair_family(
                bench_slug="t",
                sub_kind=sub_kind,
                keyword_a="ALPHA", keyword_b="BRAVO",
                clue_text="step five", clue_keywords=["ALPHA", "BRAVO"],
            )
            assert specs, f"sub_kind={sub_kind} produced no specs"
            for s in specs:
                assert s.coverage.layer_family == f"columnar_{sub_kind}"
                assert s.coverage.col_order_source == (
                    "enumerated_permutation"
                )
                assert s.coverage.transposition_width is not None
                assert s.coverage.col_order_index is not None
                assert s.coverage.width_source in {
                    "phrase_bound_step", "default_set",
                    "clue_keyword_length",
                }

    def test_per_family_cap_respected(self):
        """The per-family cap bounds the spec count."""
        specs = _gen_enumerated_columnar_pair_family(
            bench_slug="t",
            sub_kind="vigenere",
            keyword_a="ALPHA", keyword_b="BRAVO",
            clue_text=_K4B006_CLUE,
            clue_keywords=_K4B006_KEYWORDS,
        )
        assert len(specs) <= _LESSON_013_PER_FAMILY_CAP

    def test_layer_orders_balanced(self):
        """Both (sub, columnar) and (columnar, sub) layer orders
        appear for every (sub_kw, alpha, col_order) tuple.
        """
        specs = _gen_enumerated_columnar_pair_family(
            bench_slug="t",
            sub_kind="beaufort",
            keyword_a="ALPHA", keyword_b="BRAVO",
            clue_text="step three",
            clue_keywords=["ALPHA", "BRAVO"],
        )
        sub_first = sum(
            1 for s in specs
            if s.coverage.layer_order == ("beaufort", "columnar")
        )
        trans_first = sum(
            1 for s in specs
            if s.coverage.layer_order == ("columnar", "beaufort")
        )
        # At fixed cap the two orderings emit in alternating pairs;
        # difference at most 1.
        assert abs(sub_first - trans_first) <= 1

    def test_specs_pass_validation(self):
        """Every emitted spec must round-trip through the DSL
        validator and have a dispatcher translation.
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _kind_has_translation
        specs = _gen_enumerated_columnar_pair_family(
            bench_slug="t",
            sub_kind="beaufort",
            keyword_a="ALPHA", keyword_b="BRAVO",
            clue_text="step five",
            clue_keywords=["ALPHA", "BRAVO"],
        )
        for s in specs:
            parsed = validate_hypothesis_spec(s.raw_spec)
            assert parsed.is_valid, parsed.errors
            for layer in parsed.value.pipeline:
                assert _kind_has_translation(layer.kind)


# ---------------------------------------------------------------------------
# (6) Enumerated i3 columnar family
# ---------------------------------------------------------------------------


class TestEnumeratedI3ColumnarFamily:
    def test_family_label_unchanged(self):
        specs = _gen_enumerated_columnar_i3_family(
            bench_slug="t",
            sub_kind="vigenere",
            clue_keywords=["ALPHA", "BRAVO", "CHARLIE"],
            clue_text="step five",
        )
        assert specs
        for s in specs:
            assert s.coverage.layer_family == "i3_columnar_vigenere"
            assert s.coverage.role_assignment_mode == (
                "enumerated_columnar"
            )

    def test_at_least_two_clue_keywords_required(self):
        specs = _gen_enumerated_columnar_i3_family(
            bench_slug="t",
            sub_kind="vigenere",
            clue_keywords=["ALPHA"],
            clue_text="step five",
        )
        assert specs == []

    def test_cap_respected(self):
        specs = _gen_enumerated_columnar_i3_family(
            bench_slug="t",
            sub_kind="vigenere",
            clue_keywords=_K4B006_KEYWORDS,
            clue_text=_K4B006_CLUE,
        )
        assert len(specs) <= _LESSON_013_PER_FAMILY_CAP


# ---------------------------------------------------------------------------
# (7) Enumerated caesar+columnar+atbash sandwich
# ---------------------------------------------------------------------------


class TestEnumeratedCaesarColumnarAtbash:
    def test_emits_four_layer_orderings_per_combo(self):
        specs = _gen_enumerated_caesar_columnar_atbash_family(
            bench_slug="t",
            shifts=[(3, "default")],
            clue_text="step five",
            clue_keywords=["ALPHA", "BRAVO"],
        )
        assert specs
        observed_orderings = {s.coverage.layer_order for s in specs}
        # The 4 canonical orderings:
        expected = {
            ("caesar", "columnar", "atbash"),
            ("atbash", "columnar", "caesar"),
            ("columnar", "caesar", "atbash"),
            ("atbash", "caesar", "columnar"),
        }
        assert expected.issubset(observed_orderings)
        for s in specs:
            assert s.coverage.layer_family == "caesar_columnar_atbash"
            assert s.coverage.col_order_source == (
                "enumerated_permutation"
            )

    def test_cap_respected(self):
        specs = _gen_enumerated_caesar_columnar_atbash_family(
            bench_slug="t",
            shifts=[(s, "default") for s in (1, 3, 5, 7, 13)],
            clue_text=_K4B006_CLUE,
            clue_keywords=_K4B006_KEYWORDS,
        )
        assert len(specs) <= _LESSON_013_PER_FAMILY_CAP


# ---------------------------------------------------------------------------
# (8) Coverage-vector telemetry — full spec round-trip
# ---------------------------------------------------------------------------


class TestCoverageTelemetry:
    def test_new_fields_present_on_enumerated_specs(self):
        """All five new CoverageVector fields populated."""
        specs = _gen_enumerated_columnar_pair_family(
            bench_slug="t",
            sub_kind="beaufort",
            keyword_a="ALPHA", keyword_b="BRAVO",
            clue_text="step five",
            clue_keywords=["ALPHA", "BRAVO"],
        )
        s = specs[0]
        cv = s.coverage
        assert cv.transposition_width is not None
        assert cv.col_order
        assert cv.col_order_source == "enumerated_permutation"
        assert cv.col_order_index is not None
        assert cv.width_source != ""

    def test_legacy_keyword_specs_leave_new_fields_empty(self):
        """The keyword-derived columnar pair family must NOT touch
        the new LESSON-013 telemetry fields.
        """
        specs = generate_layered_specs(
            ["ALPHA", "BRAVO"], bench_slug="t",
            families={"columnar_vigenere"},
            alphabet_modes=(AlphabetMode("AZ", "AZ", None, "default"),),
            include_three_layer=False,
        )
        legacy = [
            s for s in specs
            if s.coverage.col_order_source != "enumerated_permutation"
        ]
        assert legacy
        for s in legacy:
            cv = s.coverage
            assert cv.transposition_width is None
            assert cv.col_order == ()
            assert cv.col_order_source == ""
            assert cv.col_order_index is None
            assert cv.width_source == ""

    def test_dict_round_trip_preserves_new_fields(self):
        cv = CoverageVector(
            layer_family="columnar_beaufort",
            layer_order=("beaufort", "columnar"),
            role_assignment=(
                ("beaufort", "MIRROR"),
                ("columnar", "W5_co106"),
            ),
            alphabet="AZ", n_layers=2,
            transposition_width=5,
            col_order=(4, 1, 3, 0, 2),
            col_order_source="enumerated_permutation",
            col_order_index=106,
            width_source="phrase_bound_step",
        )
        rt = CoverageVector.from_dict(cv.to_dict())
        assert rt.transposition_width == 5
        assert rt.col_order == (4, 1, 3, 0, 2)
        assert rt.col_order_source == "enumerated_permutation"
        assert rt.col_order_index == 106
        assert rt.width_source == "phrase_bound_step"


# ---------------------------------------------------------------------------
# (9) generate_layered_specs integration
# ---------------------------------------------------------------------------


class TestGenerateLayeredSpecsWithLesson013:
    def test_keyword_path_still_emits_4_role_order_combos(self):
        """The legacy 4-coord role/order invariant on the keyword
        path is preserved (LESSON-013 specs are on a separate axis).
        """
        specs = generate_layered_specs(
            ["ALPHA", "BRAVO"], bench_slug="t",
            include_three_layer=False,
        )
        legacy = [
            s for s in specs
            if s.coverage.layer_family == "columnar_vigenere"
            and s.coverage.col_order_source != "enumerated_permutation"
        ]
        coords = {
            (s.coverage.layer_order, s.coverage.role_assignment)
            for s in legacy
        }
        assert len(coords) == 4

    def test_enumerated_path_active_under_full_catalogue(self):
        """When ``families`` is None the catalogue includes enumerated
        columnar specs.
        """
        specs = generate_layered_specs(
            _K4B006_KEYWORDS, bench_slug="t",
            clue_text=_K4B006_CLUE,
        )
        enumerated = [
            s for s in specs
            if s.coverage.col_order_source == "enumerated_permutation"
        ]
        assert enumerated

    def test_k4b006_target_in_columnar_beaufort(self):
        """The K4B-006 winning composition is reachable: at least one
        spec has columnar(W=5, co=(4,1,3,0,2)) + beaufort(MIRROR | AZ)
        in BOTH layer orderings.
        """
        specs = generate_layered_specs(
            _K4B006_KEYWORDS, bench_slug="t",
            clue_text=_K4B006_CLUE,
        )
        target = (4, 1, 3, 0, 2)
        hits = [
            s for s in specs
            if s.coverage.layer_family == "columnar_beaufort"
            and s.coverage.transposition_width == 5
            and s.coverage.col_order == target
            and s.coverage.substitution_keyword == "MIRROR"
            and s.coverage.alphabet == "AZ"
        ]
        orders = {s.coverage.layer_order for s in hits}
        assert ("beaufort", "columnar") in orders
        assert ("columnar", "beaufort") in orders


# ---------------------------------------------------------------------------
# (10) Real-K4 mode unaffected
# ---------------------------------------------------------------------------


class TestRealK4ModeUnchanged:
    def test_real_k4_caller_can_invoke_generator_with_real_clue_words(self):
        """The generator works on any clue words — no bench dependency.
        LESSON-013 fires for real-K4 vocabulary IFF the caller invokes
        ``generate_layered_specs`` directly. The actual real-K4 gating
        happens at the controller level (``ProblemContext`` rejects
        bench-fallback in real-K4 mode); this test pins that the
        underlying generator does not have a hidden bench-mode flag.
        """
        specs = generate_layered_specs(
            ["BERLIN", "CLOCK"], bench_slug="real-k4",
        )
        assert len(specs) > 0
        # Real-K4 slug propagates without leaking bench-id vocabulary.
        for s in specs:
            assert "real-k4" in s.hypothesis_id
            assert "K4B" not in s.hypothesis_id

    def test_problem_context_separates_real_k4_from_bench(self):
        """The controller's ``ProblemContext`` carries the bench /
        real-K4 mode boundary that gates whether HCC + LESSON-013
        runs at all. This test pins the API the controller relies on.
        """
        from kryptosbot.problem_context import ProblemContext
        real = ProblemContext.real_k4()
        assert real.is_real_k4
        assert not real.is_bench


# ---------------------------------------------------------------------------
# (11) 3-layer columnar+sub+rail_fence sandwich
# ---------------------------------------------------------------------------


class TestEnumeratedColumnarSubRailFenceFamily:
    def test_family_emits_for_all_three_sub_kinds(self):
        from kryptosbot.hand_cipher_core import (
            _gen_enumerated_columnar_sub_rail_fence_family,
        )
        for sub_kind in ("vigenere", "beaufort", "variant_beaufort"):
            specs = _gen_enumerated_columnar_sub_rail_fence_family(
                bench_slug="t",
                sub_kind=sub_kind,
                keyword_a="ALPHA", keyword_b="BRAVO",
                rail_fence_depths=(3, 4),
                clue_text="step five",
                clue_keywords=["ALPHA", "BRAVO"],
            )
            assert specs, f"sub_kind={sub_kind} produced no specs"
            label = f"columnar_{sub_kind}_rail_fence"
            for s in specs:
                assert s.coverage.layer_family == label
                assert s.coverage.n_layers == 3
                assert s.coverage.col_order_source == (
                    "enumerated_permutation"
                )

    def test_emits_all_six_layer_orderings(self):
        from kryptosbot.hand_cipher_core import (
            _gen_enumerated_columnar_sub_rail_fence_family,
        )
        specs = _gen_enumerated_columnar_sub_rail_fence_family(
            bench_slug="t",
            sub_kind="beaufort",
            keyword_a="MIRROR", keyword_b="MARGINS",
            rail_fence_depths=(4,),
            clue_text="step five",
            clue_keywords=["MIRROR", "MARGINS"],
        )
        observed = {s.coverage.layer_order for s in specs}
        # All 6 permutations of (columnar, beaufort, rail_fence)
        expected = {
            ("columnar", "beaufort", "rail_fence"),
            ("columnar", "rail_fence", "beaufort"),
            ("beaufort", "columnar", "rail_fence"),
            ("beaufort", "rail_fence", "columnar"),
            ("rail_fence", "columnar", "beaufort"),
            ("rail_fence", "beaufort", "columnar"),
        }
        assert expected.issubset(observed)

    def test_dedup_against_keyword_col_orders(self):
        """A col_order produced by the legacy keyword path for a clue
        keyword of matching width must not appear in the enumerated
        path's output (avoids duplicate work).
        """
        from kryptosbot.hand_cipher_core import (
            _gen_enumerated_columnar_sub_rail_fence_family,
            _keyword_to_col_order,
        )
        # SHIFT is 5 letters; its stable rank is the width-5 col_order
        # the keyword path would emit.
        shift_co = tuple(_keyword_to_col_order("SHIFT"))
        specs = _gen_enumerated_columnar_sub_rail_fence_family(
            bench_slug="t",
            sub_kind="beaufort",
            keyword_a="SHIFT", keyword_b="ALPHA",
            rail_fence_depths=(3,),
            clue_text="step five",
            clue_keywords=["SHIFT", "ALPHA"],
        )
        # No spec at width=5 should carry the SHIFT-derived col_order.
        for s in specs:
            if s.coverage.transposition_width == 5:
                assert s.coverage.col_order != shift_co


# ---------------------------------------------------------------------------
# (12) K4B-006 kernel canary (24/24)
# ---------------------------------------------------------------------------


class TestK4B006Canary:
    """LESSON-013 must enable HCC to deterministically score 24/24 on
    K4B-006 via the ``columnar_<sub>_rail_fence`` 3-layer sandwich,
    using the empirical winning configuration:
        columnar(W=5, co=(4, 1, 3, 0, 2)) ∘
        beaufort(MIRROR | AZ) ∘
        rail_fence(4)
    in layer order ``(columnar, beaufort, rail_fence)``.

    Runs in a subprocess so the kernel constants module loads with
    the K4B-006 CT/cribs override.
    """

    def test_k4b006_columnar_beaufort_rail_fence_hits_24(self):
        if not _K4B006_PATH.exists():
            pytest.skip(f"K4B-006 fixture not on disk at {_K4B006_PATH}")
        import os, subprocess, sys
        env = {**os.environ}
        env["PYTHONPATH"] = (
            str(_REPO_ROOT / "src") + ":" + env.get("PYTHONPATH", "")
        )
        code = (
            "import json, sys\n"
            f"sys.path.insert(0, {str(_REPO_ROOT)!r})\n"
            "from kryptosbot.bench_loader import load_k4bench_challenge\n"
            f"ch = load_k4bench_challenge({str(_K4B006_PATH)!r})\n"
            "ch.install_kernel_overrides()\n"
            "from kryptosbot.bench_fallback import hand_cipher_core_fallback\n"
            "from kryptosbot.hypothesis_dsl import validate_hypothesis_spec\n"
            "from kryptosbot.job_dispatcher import execute\n"
            "seeds = hand_cipher_core_fallback(ch.canonical_facts(), n_target=5)\n"
            "target = (4, 1, 3, 0, 2)\n"
            "cands = [s for s in seeds\n"
            "         if s.minimal_test_spec.get('coverage_vector', {}).get('layer_family', '')\n"
            "            == 'columnar_beaufort_rail_fence'\n"
            "         and tuple(s.minimal_test_spec.get('coverage_vector', {}).get('col_order') or ()) == target\n"
            "         and s.minimal_test_spec.get('coverage_vector', {}).get('substitution_keyword') == 'MIRROR'\n"
            "         and s.minimal_test_spec.get('coverage_vector', {}).get('alphabet') == 'AZ']\n"
            "best = 0.0\n"
            "best_meta = None\n"
            "for s in cands:\n"
            "    parsed = validate_hypothesis_spec(s.dsl_spec)\n"
            "    if not parsed.is_valid:\n"
            "        continue\n"
            "    r = execute(parsed.value, workers=1, parallel=False, bench_mode=True)\n"
            "    if r.best_score > best:\n"
            "        best = r.best_score\n"
            "        cv = s.minimal_test_spec['coverage_vector']\n"
            "        best_meta = {\n"
            "            'layer_order': cv.get('layer_order'),\n"
            "            'col_order_index': cv.get('col_order_index'),\n"
            "            'transposition_width': cv.get('transposition_width'),\n"
            "            'width_source': cv.get('width_source'),\n"
            "            'col_order_source': cv.get('col_order_source'),\n"
            "        }\n"
            "print(json.dumps({'best': best, 'cand_count': len(cands), 'meta': best_meta}))\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            env=env, capture_output=True, text=True,
            cwd=str(_REPO_ROOT), timeout=600,
        )
        assert result.returncode == 0, (
            f"subprocess failed:\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
        import json
        last = next(
            (ln for ln in reversed(result.stdout.strip().splitlines())
             if ln.startswith("{")),
            "",
        )
        assert last
        payload = json.loads(last)
        assert payload["cand_count"] > 0, (
            "K4B-006 catalogue must contain at least one "
            "columnar_beaufort_rail_fence spec at "
            "(W=5, co=(4,1,3,0,2), MIRROR/AZ)"
        )
        assert payload["best"] == 24.0, (
            f"K4B-006 expected crib_score 24 from "
            f"columnar_beaufort_rail_fence; got {payload['best']}"
        )
        meta = payload["meta"]
        assert meta is not None
        # Telemetry surfacing — verifies the LESSON-013 fields are in
        # the attempt artifact.
        assert meta["transposition_width"] == 5
        assert meta["col_order_index"] == 106
        assert meta["col_order_source"] == "enumerated_permutation"
        assert meta["width_source"] == "phrase_bound_step"
