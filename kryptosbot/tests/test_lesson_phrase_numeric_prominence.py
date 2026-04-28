"""Tests for LESSON-012 — phrase-attached numeric prominence.

Pinned properties:

  1. ``LessonRegistry`` seeds LESSON-012 with the anchor-to-parameter
     taxonomy and operation_source labels the user mandated. Drift
     test: runtime ``_PHRASE_ANCHORS_BEFORE`` / ``_PHRASE_ANCHORS_AFTER``
     / ``_PHRASE_ANCHORS_PHRASES`` constants honor the lesson's
     ``anchor_to_parameter`` mapping.
  2. ``extract_phrase_bound_numerics`` parses anchor-attached
     numerals into per-parameter lists, supporting digit literals,
     cardinals, and ordinals.
  3. The user-mandated synthetic clue produces the exact bindings
     ``{rail_depth: [4], step: [5], offset: [3], shift_value: [8]}``
     without cross-contamination.
  4. Each numeric-parametrized lesson consumes its phrase-bound
     values FIRST (with provenance ``phrase_bound_*``), then falls
     back to legacy flat extraction and the default set.
  5. The skip_route pair list emits the phrase-bound (step, offset)
     pair within the cap budget regardless of competing numeric
     clues — closing the K4B-006 cap-12 starvation gap.
  6. Cross-contamination filter: numerals bound to one parameter
     are not promoted as another parameter from the legacy flat
     extractor (e.g. "four rails" does not contribute shift=4 to
     the Caesar shift list).
  7. Legacy flat fallback still works when no anchor phrase exists.
  8. Real-K4 mode unchanged — no auto-emit of HCC seeds.
"""
from __future__ import annotations

from pathlib import Path
import sys

import pytest

from kryptosbot.solver_capabilities import _default_lessons, LessonRegistry
from kryptosbot.hand_cipher_core import (
    _PHRASE_ANCHORS_AFTER,
    _PHRASE_ANCHORS_BEFORE,
    _PHRASE_ANCHORS_PHRASES,
    _block_sizes_for_payload,
    _caesar_shifts_for_payload,
    _rail_fence_depths_for_payload,
    _skip_route_offsets_for_payload,
    _skip_route_pairs_for_payload,
    _skip_route_steps_for_payload,
    extract_phrase_bound_numerics,
    generate_layered_specs,
)


_REPO_ROOT = Path(__file__).resolve().parents[2]


# User-mandated synthetic toy clue
_TOY_CLUE = (
    "take four rails, walk every fifth step through the tunnel, "
    "offset three, then shift eight"
)


# ---------------------------------------------------------------------------
# (1) LessonRegistry contains LESSON-012 with the right vocabulary
# ---------------------------------------------------------------------------


class TestLessonRegistry:
    def test_lesson_012_present(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        assert "LESSON-012" in lessons
        l = lessons["LESSON-012"]
        assert l.tactic_kind == "phrase_attached_numeric_prominence"

    def test_lesson_012_has_anchor_taxonomy(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-012"]
        anchor_map = l.tactic_parameters.get("anchor_to_parameter", {})
        # Required keys
        for k in ("step", "offset", "rail_depth",
                  "block_size", "shift_value"):
            assert k in anchor_map, f"missing parameter slot: {k}"

    def test_lesson_012_advertises_operation_source_labels(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-012"]
        labels = set(l.tactic_parameters.get("operation_source_labels", []))
        for need in (
            "phrase_bound_step",
            "phrase_bound_offset",
            "phrase_bound_rail_depth",
            "phrase_bound_block_size",
            "phrase_bound_shift_value",
        ):
            assert need in labels

    def test_lesson_012_supports_ordinals_and_cardinals(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-012"]
        params = l.tactic_parameters
        assert params.get("supports_digit_literals") is True
        assert params.get("supports_cardinals") is True
        assert params.get("supports_ordinals") is True

    def test_runtime_anchor_taxonomy_drift(self):
        """Runtime anchor constants must cover the lesson's taxonomy.
        We allow runtime to be a SUPERSET of the registry (the
        registry is the documentation surface; the runtime may carry
        synonyms). We require every registry-listed anchor to appear
        somewhere in the runtime constants for its parameter.
        """
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-012"]
        anchor_map = l.tactic_parameters["anchor_to_parameter"]
        for param, anchors in anchor_map.items():
            runtime_known = set()
            runtime_known |= set(_PHRASE_ANCHORS_BEFORE.get(param, ()))
            runtime_known |= set(_PHRASE_ANCHORS_AFTER.get(param, ()))
            for phrase in _PHRASE_ANCHORS_PHRASES.get(param, ()):
                runtime_known.add(phrase)
                # Also accept individual words inside phrases
                runtime_known |= set(phrase.split())
            for anchor in anchors:
                # Phrase form: present verbatim in PHRASE list, or
                # word form: present in BEFORE / AFTER lists
                if " " in anchor:
                    assert anchor in _PHRASE_ANCHORS_PHRASES.get(param, ()), (
                        f"runtime missing phrase '{anchor}' for {param}"
                    )
                else:
                    # Single-token anchor: BEFORE / AFTER. Plurals
                    # may live on the AFTER side (e.g. 'rails' on
                    # rail_depth's AFTER list).
                    assert anchor in runtime_known, (
                        f"runtime missing token '{anchor}' for {param} "
                        f"(known={sorted(runtime_known)})"
                    )

    def test_registry_round_trip(self, tmp_path):
        path = tmp_path / "lessons.json"
        reg1 = LessonRegistry(path=path, seed_defaults=True)
        ids1 = {l.lesson_id for l in reg1.all()}
        assert "LESSON-012" in ids1
        reg2 = LessonRegistry(path=path, seed_defaults=True)
        ids2 = {l.lesson_id for l in reg2.all()}
        assert "LESSON-012" in ids2


# ---------------------------------------------------------------------------
# (2) Parser correctness: anchor binding
# ---------------------------------------------------------------------------


class TestExtractPhraseBoundNumerics:
    def test_user_mandated_synthetic_clue(self):
        """Exact bindings the user specified for the toy clue."""
        b = extract_phrase_bound_numerics(_TOY_CLUE)
        assert b["rail_depth"] == [4]
        assert b["step"] == [5]
        assert b["offset"] == [3]
        assert b["shift_value"] == [8]
        # No cross-contamination: block_size MUST be empty because
        # the "every" before "fifth step" is disambiguated AWAY
        # from block_size by the "step" AFTER-anchor.
        assert b["block_size"] == []

    def test_step_anchor_binds_step(self):
        b = extract_phrase_bound_numerics("apply step five")
        assert b["step"] == [5]

    def test_stride_anchor_binds_step(self):
        b = extract_phrase_bound_numerics("stride seven through the route")
        assert b["step"] == [7]

    def test_offset_anchor_binds_offset(self):
        b = extract_phrase_bound_numerics("with offset three")
        assert b["offset"] == [3]

    def test_offset_of_phrase_binds_offset(self):
        b = extract_phrase_bound_numerics("starting offset of nine")
        assert b["offset"] == [9]

    def test_rails_after_anchor_binds_rail_depth(self):
        b = extract_phrase_bound_numerics("show four rails on the screen")
        assert b["rail_depth"] == [4]

    def test_depth_before_anchor_binds_rail_depth(self):
        b = extract_phrase_bound_numerics("use depth seven")
        assert b["rail_depth"] == [7]

    def test_blocks_of_phrase_binds_block_size(self):
        b = extract_phrase_bound_numerics("reverse blocks of seven")
        assert b["block_size"] == [7]

    def test_groups_after_anchor_binds_block_size(self):
        b = extract_phrase_bound_numerics("compass rose has five tick groups")
        assert b["block_size"] == [5]

    def test_shift_anchor_binds_shift_value(self):
        b = extract_phrase_bound_numerics("apply a shift eight on the disc")
        assert b["shift_value"] == [8]

    def test_shift_by_phrase_binds_shift_value(self):
        b = extract_phrase_bound_numerics("shift by three positions")
        assert b["shift_value"] == [3]

    def test_rotated_anchor_binds_shift_value(self):
        b = extract_phrase_bound_numerics("rotated five clockwise")
        assert b["shift_value"] == [5]

    @pytest.mark.parametrize("ordinal,n", [
        ("third", 3),
        ("fourth", 4),
        ("fifth", 5),
        ("seventh", 7),
        ("twelfth", 12),
    ])
    def test_ordinals_lift_to_cardinals(self, ordinal, n):
        b = extract_phrase_bound_numerics(f"step {ordinal} along the path")
        assert n in b["step"], (
            f"ordinal '{ordinal}' should bind to step={n}; got {b}"
        )

    def test_digit_literals_supported(self):
        b = extract_phrase_bound_numerics(
            "step 5, offset 3, depth 4, shift 8",
        )
        assert b["step"] == [5]
        assert b["offset"] == [3]
        assert b["rail_depth"] == [4]
        assert b["shift_value"] == [8]

    def test_no_anchor_returns_empty_lists(self):
        b = extract_phrase_bound_numerics(
            "ordinary cipher with twelve letters",
        )
        assert b["step"] == []
        assert b["offset"] == []
        assert b["rail_depth"] == []
        assert b["block_size"] == []
        assert b["shift_value"] == []

    def test_empty_clue_returns_empty_lists(self):
        b = extract_phrase_bound_numerics("")
        assert all(v == [] for v in b.values())

    def test_multiple_step_phrases_bind_all(self):
        """K4B-006-shaped: 'three steps from the start with step five'
        binds BOTH 3 and 5 to step (different anchor positions)."""
        b = extract_phrase_bound_numerics(
            "three steps from the start with step five",
        )
        assert set(b["step"]) == {3, 5}

    def test_intervening_numeric_blocks_after_anchor(self):
        """'blocks of seven four rails' must NOT bind seven to
        rail_depth via the lookahead — the intervening 'four' is its
        own numeric and OWNS the 'rails' anchor."""
        b = extract_phrase_bound_numerics(
            "blocks of seven four rails",
        )
        assert b["block_size"] == [7]
        assert b["rail_depth"] == [4]


# ---------------------------------------------------------------------------
# (3) Each numeric lesson consumes phrase-bound first
# ---------------------------------------------------------------------------


class TestRailFenceConsumesPhraseBindings:
    def test_four_rails_promotes_4_first(self):
        depths = _rail_fence_depths_for_payload(_TOY_CLUE)
        assert depths[0] == 4

    def test_no_phrase_falls_back_to_legacy(self):
        depths = _rail_fence_depths_for_payload(
            "use depth value of seven later"
        )
        # 7 is bound via "depth seven" → first; defaults follow
        assert depths[0] == 7


class TestBlockSizesConsumesPhraseBindings:
    def test_blocks_of_n_promotes_phrase_bound(self):
        sizes = _block_sizes_for_payload("reverse blocks of seven")
        assert sizes[0] == (7, "phrase_bound_block_size")

    def test_cross_contamination_filter(self):
        """'four rails' should NOT pollute block_size with 4 in the
        legacy fallback — 4 is bound to rail_depth, not block_size.
        """
        sizes = _block_sizes_for_payload("four rails, no block clue")
        # 4 must not appear as clue_numeral in block sizes
        clue_nums = [n for n, src in sizes if src == "clue_numeral"]
        assert 4 not in clue_nums


class TestCaesarShiftsConsumesPhraseBindings:
    def test_shift_anchor_promotes_phrase_bound(self):
        shifts = _caesar_shifts_for_payload("apply shift eight")
        assert shifts[0] == (8, "phrase_bound_shift_value")

    def test_cross_contamination_filter(self):
        """'four rails' must NOT contribute shift=4 from the legacy
        flat extractor — 4 is bound to rail_depth, not shift_value.
        """
        shifts = _caesar_shifts_for_payload(
            "four rails on the screen, no shift mentioned"
        )
        clue_nums = [s for s, src in shifts if src == "clue_numeral"]
        assert 4 not in clue_nums


class TestSkipRouteConsumesPhraseBindings:
    def test_step_anchor_promotes_phrase_bound(self):
        steps = _skip_route_steps_for_payload("step five through the path")
        assert steps[0] == (5, "phrase_bound_step")

    def test_offset_anchor_promotes_phrase_bound(self):
        offsets = _skip_route_offsets_for_payload(
            "offset three from the start", step=5,
        )
        assert offsets[0] == (3, "phrase_bound_offset")

    def test_pairs_phrase_bound_pair_lands_first(self):
        """The K4B-006 fix: cap-12 must include (step=5, offset=3)
        as a phrase-bound pair, regardless of competing numerals.
        """
        clue = (
            "The margins show four rails, the word MIRROR, and a "
            "route beginning three steps from the start with step five."
        )
        pairs = _skip_route_pairs_for_payload(clue, cap=12)
        # (5, 3) must appear within the first 12 pairs
        in_cap = any(p[0] == 5 and p[1] == 3 for p in pairs)
        assert in_cap, (
            f"step=5 offset=3 missing from cap=12 pair list; pairs={pairs}"
        )

    def test_pairs_phrase_bound_provenance_label(self):
        """The (5, 3) pair's provenance must be one of the LESSON-012
        phrase_bound_* labels when both are anchor-bound, OR
        phrase_bound_step / phrase_bound_offset when one is."""
        clue = (
            "step five, offset three, mirror then fence"
        )
        pairs = _skip_route_pairs_for_payload(clue, cap=8)
        match = [p for p in pairs if p[0] == 5 and p[1] == 3]
        assert match
        assert match[0][2] in (
            "phrase_bound", "phrase_bound_step", "phrase_bound_offset",
        )


# ---------------------------------------------------------------------------
# (4) Synthetic toy clue end-to-end
# ---------------------------------------------------------------------------


class TestSyntheticToyClue:
    """Exercises the full LESSON-012 path on the user-mandated clue:
    "take four rails, walk every fifth step through the tunnel,
     offset three, then shift eight"
    """

    def test_skip_route_substitution_includes_step_5_offset_3(self):
        specs = generate_layered_specs(
            ["TUNNEL", "ROUTE", "FENCE"], bench_slug="toy",
            clue_text=_TOY_CLUE, max_specs=20000,
        )
        # skip_route paired with substitution must include
        # (step=5, offset=3) with phrase-bound provenance
        match = [
            s for s in specs
            if s.coverage.layer_family.startswith("skip_route_")
            and not s.coverage.layer_family.endswith("_atbash")
            and not s.coverage.layer_family.endswith("_caesar")
            and not s.coverage.layer_family.endswith("_rail_fence")
            and s.coverage.step == 5 and s.coverage.offset == 3
        ]
        assert match, (
            "skip_route substitution-paired family missing "
            "(step=5, offset=3) for the toy clue"
        )

    def test_rail_fence_uses_4_from_phrase(self):
        depths = _rail_fence_depths_for_payload(_TOY_CLUE)
        # 4 must appear and must be FIRST (highest priority)
        assert depths[0] == 4

    def test_caesar_uses_8_from_phrase(self):
        shifts = _caesar_shifts_for_payload(_TOY_CLUE)
        # 8 must appear with phrase-bound provenance and be
        # the FIRST element
        assert shifts[0] == (8, "phrase_bound_shift_value")

    def test_block_size_does_not_consume_unrelated_numbers(self):
        """The toy clue has NO block / group / chunk anchor. The
        block_size list must NOT contain 4 (rail), 5 (step), 3
        (offset), or 8 (shift) under clue_numeral provenance —
        they all belong to other parameters.
        """
        sizes = _block_sizes_for_payload(_TOY_CLUE)
        clue_nums = [n for n, src in sizes if src == "clue_numeral"]
        for protected in (3, 4, 5, 8):
            assert protected not in clue_nums, (
                f"block_size clue_numeral list erroneously includes "
                f"{protected} (bound to a different parameter); "
                f"clue_numerals={clue_nums}"
            )


# ---------------------------------------------------------------------------
# (5) Determinism + bounded generation
# ---------------------------------------------------------------------------


class TestDeterminismAndBoundedness:
    def test_extract_deterministic(self):
        a = extract_phrase_bound_numerics(_TOY_CLUE)
        b = extract_phrase_bound_numerics(_TOY_CLUE)
        assert a == b

    def test_pairs_deterministic(self):
        clue = "step five, offset three"
        a = _skip_route_pairs_for_payload(clue, cap=8)
        b = _skip_route_pairs_for_payload(clue, cap=8)
        assert a == b

    def test_pairs_bounded_by_cap(self):
        pairs = _skip_route_pairs_for_payload(_TOY_CLUE, cap=4)
        assert len(pairs) <= 4


# ---------------------------------------------------------------------------
# (6) Legacy flat fallback when no anchor
# ---------------------------------------------------------------------------


class TestLegacyFallback:
    def test_no_anchor_falls_back_to_clue_numeral_then_default(self):
        """Clue text 'use seven and eleven' has no anchor for any
        parameter. The legacy flat extractor still picks up 7 and
        11 as clue_numeral provenance, falling back through to
        defaults. Caesar shift is the cleanest test surface
        because shift values 7 and 11 are both in the valid range
        and both will appear with clue_numeral provenance.
        """
        shifts = _caesar_shifts_for_payload("use seven and eleven")
        clue = [s for s, src in shifts if src == "clue_numeral"]
        # 7 and 11 are valid Caesar shifts and not phrase-bound
        # to any parameter, so they survive as clue_numeral
        assert 7 in clue or 11 in clue, (
            f"legacy clue_numeral fallback did not surface 7/11; "
            f"shifts={shifts}"
        )

    def test_no_anchor_no_phrase_bound_provenance(self):
        depths = _rail_fence_depths_for_payload("ordinary cipher")
        # No anchors → no phrase-bound depths → defaults only
        # (legacy depth list is just ints, no provenance)
        # We just confirm the default set is present
        for d in (3, 5):
            assert d in depths


# ---------------------------------------------------------------------------
# (7) Real-K4 mode unchanged
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

    def test_lesson_012_in_registry_for_real_k4(self, tmp_path):
        reg = LessonRegistry(
            path=tmp_path / "lessons.json", seed_defaults=True,
        )
        ids = {l.lesson_id for l in reg.all()}
        assert "LESSON-012" in ids
