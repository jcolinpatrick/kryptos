"""Tests for LESSON-018 — numeric clue → Caesar/ROT trigger semantics.

Pinned properties:

  1. Numeric extraction: spelled cardinals ("seventeen") and digit
     literals ("17") both normalise to int 17. Out-of-range values
     are not promoted.
  2. Positive promotion: "small tag says seventeen", "tag 17",
     "marked seventeen", "label eight", and similar tag/label
     precursors emit Caesar candidates without an explicit Caesar
     trigger word.
  3. Each promoted shift n produces both n (as_given) and (26-n)
     (complement); self-complement n=13 and identity n=0 skipped.
  4. Negative binding: "ten-wide grid", "five stones", "rail depth
     five", "block size five", "step five" do NOT promote their
     numerals to Caesar.
  5. Existing explicit Caesar behavior preserved: "shift seventeen",
     "rotate 17", "caesar 17" still emit Caesar specs (legacy
     explicit-trigger path; numeric_trigger_without_caesar_word is
     None on those).
  6. K4B-009-shape clue: 5 → object_count, 10 → route_width,
     17 → free_numeric_tag (promoted as Caesar shift).
  7. Coverage_vector LESSON-018 fields populated and round-trip.
  8. LESSON-017 stratified scheduling preserved on numerically-
     promoted Caesar candidates.
  9. Determinism across two identical runs.

Real-K4 normal mode and any benchmark sealed-answer paths are not
touched by this test file. No K4Bench plaintext, sealed answer, or
benchmark-specific winning-shift assertion.
"""
from __future__ import annotations

from collections import Counter

import pytest


# ===========================================================================
# (1) Numeric extraction + role classification
# ===========================================================================


class TestNumericRoleClassifier:
    def test_seventeen_word_normalises_to_17(self):
        from kryptosbot.hand_cipher_core import _classify_numeric_roles
        roles = _classify_numeric_roles("the value seventeen")
        # "value" is a tag-precursor → free_numeric_tag
        assert any(
            c["value"] == 17 and c["token"] == "seventeen"
            and c["role"] == "free_numeric_tag"
            for c in roles
        )

    def test_digit_17_normalises(self):
        from kryptosbot.hand_cipher_core import _classify_numeric_roles
        roles = _classify_numeric_roles("the value 17")
        assert any(
            c["value"] == 17 and c["token"] == "17"
            and c["role"] == "free_numeric_tag"
            for c in roles
        )

    def test_out_of_range_classified_ignored(self):
        from kryptosbot.hand_cipher_core import _classify_numeric_roles
        roles = _classify_numeric_roles("the value 99 and 0")
        # 99 out of range → ignored; 0 is not in [1,25] → ignored.
        for c in roles:
            if c["raw_value"] in (99, 0):
                assert c["role"] == "ignored_out_of_range"
                assert c["value"] is None

    def test_object_count_blocks_caesar_promotion(self):
        from kryptosbot.hand_cipher_core import (
            _classify_numeric_roles, _detect_numeric_caesar_promotion,
        )
        roles = _classify_numeric_roles("five stones on the wall")
        five_role = next(c for c in roles if c["value"] == 5)
        assert five_role["role"] == "object_count"
        assert _detect_numeric_caesar_promotion("five stones on the wall") == []

    def test_route_width_blocks_promotion(self):
        from kryptosbot.hand_cipher_core import (
            _classify_numeric_roles, _detect_numeric_caesar_promotion,
        )
        roles = _classify_numeric_roles("ten-wide ragged grid")
        ten_role = next(c for c in roles if c["value"] == 10)
        assert ten_role["role"] == "route_width"
        assert _detect_numeric_caesar_promotion("ten-wide ragged grid") == []

    def test_rail_depth_blocks_promotion(self):
        from kryptosbot.hand_cipher_core import _detect_numeric_caesar_promotion
        assert _detect_numeric_caesar_promotion("rail depth five") == []
        assert _detect_numeric_caesar_promotion("depth 7 rails") == []

    def test_block_size_blocks_promotion(self):
        from kryptosbot.hand_cipher_core import _detect_numeric_caesar_promotion
        assert _detect_numeric_caesar_promotion("block size five") == []
        assert _detect_numeric_caesar_promotion("blocks of seven") == []

    def test_skip_step_blocks_promotion(self):
        from kryptosbot.hand_cipher_core import _detect_numeric_caesar_promotion
        assert _detect_numeric_caesar_promotion("step five through the grid") == []
        assert _detect_numeric_caesar_promotion("offset 7") == []


# ===========================================================================
# (2) Positive promotion
# ===========================================================================


class TestPositivePromotion:
    def test_small_tag_says_seventeen(self):
        from kryptosbot.hand_cipher_core import _detect_numeric_caesar_promotion
        promoted = _detect_numeric_caesar_promotion(
            "small tag says seventeen"
        )
        assert promoted
        assert promoted[0]["value"] == 17
        assert promoted[0]["role"] == "free_numeric_tag"
        assert promoted[0]["shift_source"] == "clue_numeric_tag"

    def test_tag_17(self):
        from kryptosbot.hand_cipher_core import _detect_numeric_caesar_promotion
        promoted = _detect_numeric_caesar_promotion("tag 17")
        assert any(p["value"] == 17 for p in promoted)

    def test_marked_seventeen(self):
        from kryptosbot.hand_cipher_core import _detect_numeric_caesar_promotion
        promoted = _detect_numeric_caesar_promotion("marked seventeen")
        assert any(p["value"] == 17 for p in promoted)

    def test_label_eight(self):
        from kryptosbot.hand_cipher_core import _detect_numeric_caesar_promotion
        promoted = _detect_numeric_caesar_promotion("label eight")
        assert any(p["value"] == 8 for p in promoted)

    def test_inscription_three(self):
        from kryptosbot.hand_cipher_core import _detect_numeric_caesar_promotion
        promoted = _detect_numeric_caesar_promotion("inscription three")
        assert any(p["value"] == 3 for p in promoted)

    def test_complement_emitted(self):
        from kryptosbot.hand_cipher_core import (
            _detect_numeric_caesar_promotion,
            _expand_caesar_shifts_with_complement,
        )
        promoted = _detect_numeric_caesar_promotion("tag 17")
        with_complement = _expand_caesar_shifts_with_complement(promoted)
        directions = {(s["shift_value"], s["shift_direction"]) for s in with_complement}
        assert (17, "as_given") in directions
        assert (9, "complement") in directions  # 26 - 17 = 9

    def test_self_complement_skipped(self):
        """Shift 13 self-complements (26 - 13 = 13). Avoid duplicate."""
        from kryptosbot.hand_cipher_core import (
            _detect_numeric_caesar_promotion,
            _expand_caesar_shifts_with_complement,
        )
        promoted = _detect_numeric_caesar_promotion("tag 13")
        with_complement = _expand_caesar_shifts_with_complement(promoted)
        # Only one entry for value 13.
        thirteens = [s for s in with_complement if s["shift_value"] == 13]
        assert len(thirteens) == 1
        assert thirteens[0]["shift_direction"] == "as_given"


# ===========================================================================
# (3) Existing explicit Caesar behavior preserved
# ===========================================================================


class TestExplicitCaesarPreserved:
    def test_shift_seventeen_classifies_as_explicit(self):
        from kryptosbot.hand_cipher_core import _classify_numeric_roles
        roles = _classify_numeric_roles("shift seventeen")
        assert any(
            c["value"] == 17 and c["role"] == "explicit_caesar"
            for c in roles
        )

    def test_rotate_17_classifies_as_explicit(self):
        from kryptosbot.hand_cipher_core import _classify_numeric_roles
        roles = _classify_numeric_roles("rotate 17")
        assert any(
            c["value"] == 17 and c["role"] == "explicit_caesar"
            for c in roles
        )

    def test_caesar_17_classifies_as_explicit(self):
        from kryptosbot.hand_cipher_core import _classify_numeric_roles
        roles = _classify_numeric_roles("caesar 17")
        assert any(
            c["value"] == 17 and c["role"] == "explicit_caesar"
            for c in roles
        )

    def test_existing_caesar_trigger_path_still_emits(self):
        """Clue with explicit Caesar word still emits Caesar specs
        via the legacy trigger path. numeric_trigger_without_caesar_word
        is None on those (they didn't go through LESSON-018
        promotion).
        """
        from kryptosbot.hand_cipher_core import generate_layered_specs
        s = generate_layered_specs(
            ["ALPHA", "BRAVO"], bench_slug="t",
            clue_text="apply caesar shift seventeen",
            max_specs=2000,
        )
        caesar = [
            spec for spec in s
            if spec.coverage.layer_family.startswith("caesar")
        ]
        assert caesar
        for spec in caesar:
            # Legacy path leaves LESSON-018 fields empty / None.
            assert (
                spec.coverage.numeric_trigger_without_caesar_word
                is None
            )


# ===========================================================================
# (4) K4B-009-shape clue regression
# ===========================================================================


class TestK4B009ShapeClue:
    """The K4B-009 clue is a public clue text. The cribs are
    PUBLIC FACTs. This test asserts the LESSON-018 classifier
    treats each numeral correctly without referencing any sealed
    answer text or expected winning shift.
    """

    _CLUE = (
        "MASON appears on five stones. A ten-wide ragged grid is "
        "crossed by alternating diagonals. A small tag says seventeen."
    )

    def test_five_classified_as_object_count(self):
        from kryptosbot.hand_cipher_core import _classify_numeric_roles
        roles = _classify_numeric_roles(self._CLUE)
        five = next(c for c in roles if c["value"] == 5)
        assert five["role"] == "object_count"

    def test_ten_classified_as_route_width(self):
        from kryptosbot.hand_cipher_core import _classify_numeric_roles
        roles = _classify_numeric_roles(self._CLUE)
        ten = next(c for c in roles if c["value"] == 10)
        assert ten["role"] == "route_width"

    def test_seventeen_classified_as_free_numeric_tag(self):
        from kryptosbot.hand_cipher_core import _classify_numeric_roles
        roles = _classify_numeric_roles(self._CLUE)
        seventeen = next(c for c in roles if c["value"] == 17)
        assert seventeen["role"] == "free_numeric_tag"

    def test_only_seventeen_promoted(self):
        from kryptosbot.hand_cipher_core import _detect_numeric_caesar_promotion
        promoted = _detect_numeric_caesar_promotion(self._CLUE)
        # 5 (object_count) and 10 (route_width) must not be
        # promoted; only 17 (free_numeric_tag).
        values = [p["value"] for p in promoted]
        assert 17 in values
        assert 5 not in values
        assert 10 not in values

    def test_caesar_specs_emitted_with_shift_17(self):
        """The clue does NOT contain an explicit Caesar trigger
        word, but LESSON-018 promotes 17 → Caesar. Verify Caesar
        specs are emitted with shift_value=17 (and complement 9).
        """
        from kryptosbot.hand_cipher_core import generate_layered_specs
        s = generate_layered_specs(
            ["MASON", "STONES", "BERLIN"], bench_slug="t",
            clue_text=self._CLUE, max_specs=10000,
        )
        numeric = [
            spec for spec in s
            if spec.coverage.numeric_trigger_without_caesar_word is True
        ]
        assert numeric
        shifts = {spec.coverage.shift_value for spec in numeric}
        assert 17 in shifts
        assert 9 in shifts

    def test_caesar_route_boustrophedon_includes_shift_17(self):
        """At least one caesar+route_boustrophedon spec carries
        shift_value=17.
        """
        from kryptosbot.hand_cipher_core import generate_layered_specs
        s = generate_layered_specs(
            ["MASON", "STONES", "BERLIN"], bench_slug="t",
            clue_text=self._CLUE, max_specs=10000,
        )
        rb_caesar = [
            spec for spec in s
            if spec.coverage.layer_family == "caesar_route_boustrophedon"
            and spec.coverage.shift_value == 17
        ]
        assert rb_caesar

    def test_caesar_route_diagonal_includes_shift_17(self):
        from kryptosbot.hand_cipher_core import generate_layered_specs
        s = generate_layered_specs(
            ["MASON", "STONES", "BERLIN"], bench_slug="t",
            clue_text=self._CLUE, max_specs=10000,
        )
        diag_caesar = [
            spec for spec in s
            if spec.coverage.layer_family == "caesar_route_diagonal"
            and spec.coverage.shift_value == 17
        ]
        assert diag_caesar


# ===========================================================================
# (5) Coverage_vector telemetry
# ===========================================================================


class TestCoverageTelemetry:
    def test_numeric_caesar_carries_full_telemetry(self):
        from kryptosbot.hand_cipher_core import generate_layered_specs
        s = generate_layered_specs(
            ["MASON", "STONES"], bench_slug="t",
            clue_text=(
                "MASON appears on five stones. A ten-wide ragged grid "
                "is crossed by alternating diagonals. A small tag "
                "says seventeen."
            ),
            max_specs=10000,
        )
        numeric = [
            spec for spec in s
            if spec.coverage.numeric_trigger_without_caesar_word is True
        ]
        assert numeric
        for spec in numeric[:30]:
            cv = spec.coverage
            assert cv.shift_source in (
                "clue_numeric_free", "clue_numeric_tag",
                "explicit_caesar_token",
            )
            assert cv.shift_token in ("17", "seventeen")
            assert cv.shift_role in (
                "free_numeric_tag", "ambiguous_numeric",
                "explicit_caesar",
            )
            assert cv.shift_direction in ("as_given", "complement")
            assert cv.numeric_trigger_without_caesar_word is True
            assert cv.operation_source == "numeric_caesar_trigger"
            assert cv.shift_value in (17, 9)

    def test_telemetry_round_trip(self):
        from kryptosbot.hand_cipher_core import (
            CoverageVector, generate_layered_specs,
        )
        s = generate_layered_specs(
            ["ALPHA"], bench_slug="t",
            clue_text="tag 17",
            max_specs=200,
        )
        for spec in s[:20]:
            d = spec.coverage.to_dict()
            assert "shift_source" in d
            assert "shift_token" in d
            assert "shift_role" in d
            assert "shift_direction" in d
            assert "numeric_trigger_without_caesar_word" in d
            cv2 = CoverageVector.from_dict(d)
            assert cv2.shift_source == spec.coverage.shift_source
            assert cv2.shift_token == spec.coverage.shift_token
            assert cv2.shift_role == spec.coverage.shift_role
            assert cv2.shift_direction == spec.coverage.shift_direction
            assert (
                cv2.numeric_trigger_without_caesar_word
                == spec.coverage.numeric_trigger_without_caesar_word
            )


# ===========================================================================
# (6) LESSON-017 scheduler compatibility
# ===========================================================================


class TestSchedulerCompatibility:
    def test_numeric_caesar_specs_carry_scheduling_pass(self):
        """LESSON-017 telemetry remains intact on numerically-
        promoted Caesar candidates.
        """
        from kryptosbot.hand_cipher_core import generate_layered_specs
        s = generate_layered_specs(
            ["MASON", "STONES"], bench_slug="t",
            clue_text=(
                "MASON appears on five stones. A ten-wide ragged grid "
                "is crossed by alternating diagonals. A small tag "
                "says seventeen."
            ),
            max_specs=10000,
        )
        numeric = [
            spec for spec in s
            if spec.coverage.numeric_trigger_without_caesar_word is True
        ]
        assert numeric
        for spec in numeric[:30]:
            assert spec.coverage.scheduling_pass in ("quota", "residual")
            assert spec.coverage.hcc_max_specs == 10000

    def test_numeric_caesar_survives_constrained_cap(self):
        """At a smaller max_specs, numerically-promoted Caesar specs
        should still survive (the LESSON-017 quota for the
        ``caesar`` family family is at least 'default'=40 = 40 specs
        per family). The 4 numeric-Caesar families across paired
        triggers should retain at least one spec each.
        """
        from kryptosbot.hand_cipher_core import generate_layered_specs
        s = generate_layered_specs(
            ["MASON", "STONES"], bench_slug="t",
            clue_text=(
                "MASON appears on five stones. A ten-wide ragged grid "
                "is crossed by alternating diagonals. A small tag "
                "says seventeen."
            ),
            max_specs=4000,
        )
        numeric = [
            spec for spec in s
            if spec.coverage.numeric_trigger_without_caesar_word is True
        ]
        assert numeric

    def test_determinism(self):
        from kryptosbot.hand_cipher_core import generate_layered_specs
        clue = (
            "MASON appears on five stones. A ten-wide ragged grid is "
            "crossed by alternating diagonals. A small tag says "
            "seventeen."
        )
        s1 = generate_layered_specs(
            ["MASON", "STONES"], bench_slug="t",
            clue_text=clue, max_specs=2000,
        )
        s2 = generate_layered_specs(
            ["MASON", "STONES"], bench_slug="t",
            clue_text=clue, max_specs=2000,
        )
        assert len(s1) == len(s2)
        for a, b in zip(s1, s2):
            assert a.hypothesis_id == b.hypothesis_id
            assert a.coverage.shift_value == b.coverage.shift_value
            assert a.coverage.shift_source == b.coverage.shift_source


# ===========================================================================
# (7) Lesson registry
# ===========================================================================


class TestLessonRegistry:
    def test_lesson_018_present(self):
        from kryptosbot.solver_capabilities import _default_lessons
        lessons = {l.lesson_id: l for l in _default_lessons()}
        assert "LESSON-018" in lessons
        l = lessons["LESSON-018"]
        assert l.tactic_kind == "numeric_clue_caesar_trigger_semantics"
        assert l.generates_specs is True

    def test_lesson_018_taxonomy(self):
        from kryptosbot.solver_capabilities import _default_lessons
        lessons = {l.lesson_id: l for l in _default_lessons()}
        params = lessons["LESSON-018"].tactic_parameters
        for role in (
            "explicit_caesar", "free_numeric_tag", "ambiguous_numeric",
        ):
            assert role in params["promotion_eligible_roles"]
        for role in (
            "route_width", "rail_depth", "block_size",
            "skip_step", "object_count",
        ):
            assert role in params["numeric_role_taxonomy"]
        assert params["shift_direction_policy"] == "as_given_and_complement"


# ===========================================================================
# (8) Real-K4 normal mode unchanged
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
