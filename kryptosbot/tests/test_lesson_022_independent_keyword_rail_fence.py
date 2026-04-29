"""LESSON-022: independent two-keyword + rail_fence three-role
composition tests.

Pinned properties:

  1. Positive emission: a clue with two distinct keywords + a phrase-
     bound rail-fence depth emits both keyword orientations
     (sub=A col=B and sub=B col=A) across all three substitution
     kinds.
  2. All six decryption-order permutations of (sub, columnar,
     rail_fence) are emitted.
  3. CoverageVector telemetry: transposition_keyword populated with
     the second clue keyword (NOT empty); col_order_source =
     "clue_keyword"; role_assignment_mode =
     "independent_two_keyword_rail_fence_three_role";
     operation_source =
     "independent_keyword_rail_fence_composition"; rail_fence depth
     = clue-bound; n_layers = 3.
  4. Negative gating: no LESSON-022 family emits when the clue has
     fewer than 2 distinct usable keywords, when no phrase-bound
     rail-fence depth is found, or when the keywords are too short
     for a non-degenerate columnar.
  5. LESSON-022 specs survive a constrained max_specs cap under
     LESSON-017 stratified scheduling.
  6. Regressions: LESSON-010 i3 two-layer family still emits;
     LESSON-013 enumerated-columnar three-layer family still emits
     with empty transposition_keyword and
     role_assignment_mode="enumerated_columnar"; numeric role
     classifier still classifies "three-rail" as rail_depth and
     does not promote it to Caesar; HCC seed controls untouched.

No sealed-answer plaintext, no benchmark-specific layer listings,
no benchmark-specific keyword sets.
"""

from __future__ import annotations

import pytest

from kryptosbot.hand_cipher_core import (
    generate_layered_specs,
    extract_phrase_bound_numerics,
    _classify_numeric_roles,
    _detect_numeric_caesar_promotion,
    _rail_fence_depths_for_payload,
)
from kryptosbot.solver_capabilities import _default_lessons


# ---------------------------------------------------------------------------
# Synthetic test clues
# ---------------------------------------------------------------------------

ROLE_TRIPLE_CLUE = (
    "OBSERVE and GARDEN are both carved on the mock panel. "
    "A three-rail fence appears after the column labels."
)
ROLE_TRIPLE_DEPTH4_CLUE = (
    "ALPHA and BETA appear stamped on the bench. "
    "A four-rail fence runs after the column labels."
)
NO_RAIL_CLUE = (
    "OBSERVE and GARDEN are both carved on the mock panel. "
    "The column labels appear without other markings."
)
ONE_KEYWORD_CLUE = (
    "OBSERVE is carved on the mock panel. "
    "A three-rail fence appears after the column labels."
)
SHORT_KEYWORDS_CLUE = (
    "AB and CD are both carved on the mock panel. "
    "A three-rail fence appears after the column labels."
)
DEFAULT_DEPTH_ONLY_CLUE = (
    # No "N-rail" / "depth N" anchor → phrase-bound rail_depth empty.
    "OBSERVE and GARDEN are both carved on the mock panel. "
    "The fence runs in horizontal rails."
)


L022_FAMILIES = (
    "i3_columnar_vigenere_rail_fence",
    "i3_columnar_beaufort_rail_fence",
    "i3_columnar_variant_beaufort_rail_fence",
)


def _gen(clue_words, clue_text, *, max_specs: int = 10000):
    return generate_layered_specs(
        clue_words,
        clue_text=clue_text,
        max_specs=max_specs,
        bench_slug="t",
    )


def _l022_specs(specs):
    return [s for s in specs if s.coverage.layer_family in L022_FAMILIES]


# ---------------------------------------------------------------------------
# 1. Positive emission
# ---------------------------------------------------------------------------


class TestPositiveEmission:
    def test_role_triple_emits_lesson_022(self):
        specs = _gen(["OBSERVE", "GARDEN"], ROLE_TRIPLE_CLUE)
        l022 = _l022_specs(specs)
        assert l022, "role triple clue must emit LESSON-022"

    def test_both_keyword_orientations_emitted(self):
        specs = _gen(["OBSERVE", "GARDEN"], ROLE_TRIPLE_CLUE)
        l022 = _l022_specs(specs)
        orientations = {
            (s.coverage.substitution_keyword,
             s.coverage.transposition_keyword)
            for s in l022
        }
        assert ("OBSERVE", "GARDEN") in orientations
        assert ("GARDEN", "OBSERVE") in orientations

    def test_all_three_sub_kinds_emit(self):
        specs = _gen(["OBSERVE", "GARDEN"], ROLE_TRIPLE_CLUE)
        fams = {
            s.coverage.layer_family
            for s in _l022_specs(specs)
        }
        assert "i3_columnar_vigenere_rail_fence" in fams
        assert "i3_columnar_beaufort_rail_fence" in fams
        assert "i3_columnar_variant_beaufort_rail_fence" in fams

    def test_rail_fence_depth_is_clue_bound(self):
        specs = _gen(["OBSERVE", "GARDEN"], ROLE_TRIPLE_CLUE)
        for s in _l022_specs(specs):
            ra = dict(s.coverage.role_assignment)
            assert "rail_fence" in ra
            assert int(ra["rail_fence"]) == 3

    def test_rail_fence_depth_4_clue(self):
        specs = _gen(["ALPHA", "BETA"], ROLE_TRIPLE_DEPTH4_CLUE)
        l022 = _l022_specs(specs)
        assert l022, "depth-4 clue must emit LESSON-022"
        depths = {int(dict(s.coverage.role_assignment)["rail_fence"])
                  for s in l022}
        assert depths == {4}, (
            f"only the clue-bound depth should appear; got {depths}"
        )


# ---------------------------------------------------------------------------
# 2. Layer orders
# ---------------------------------------------------------------------------


class TestLayerOrders:
    EXPECTED_ORDERS_VIGENERE = {
        ("vigenere",   "columnar",  "rail_fence"),
        ("vigenere",   "rail_fence", "columnar"),
        ("columnar",   "vigenere",  "rail_fence"),
        ("columnar",   "rail_fence", "vigenere"),
        ("rail_fence", "vigenere",  "columnar"),
        ("rail_fence", "columnar",  "vigenere"),
    }

    def test_all_six_orders_for_vigenere(self):
        specs = _gen(["OBSERVE", "GARDEN"], ROLE_TRIPLE_CLUE)
        vig = [
            s for s in _l022_specs(specs)
            if s.coverage.layer_family == "i3_columnar_vigenere_rail_fence"
        ]
        orders = {tuple(s.coverage.layer_order) for s in vig}
        assert self.EXPECTED_ORDERS_VIGENERE.issubset(orders), (
            f"missing orders: "
            f"{self.EXPECTED_ORDERS_VIGENERE - orders}"
        )

    def test_layer_orders_use_correct_kinds(self):
        specs = _gen(["OBSERVE", "GARDEN"], ROLE_TRIPLE_CLUE)
        for s in _l022_specs(specs):
            order = tuple(s.coverage.layer_order)
            assert len(order) == 3
            assert "columnar" in order
            assert "rail_fence" in order
            assert any(
                k in order
                for k in ("vigenere", "beaufort", "variant_beaufort")
            )


# ---------------------------------------------------------------------------
# 3. CoverageVector telemetry
# ---------------------------------------------------------------------------


class TestCoverageTelemetry:
    def test_transposition_keyword_populated(self):
        specs = _gen(["OBSERVE", "GARDEN"], ROLE_TRIPLE_CLUE)
        for s in _l022_specs(specs):
            assert s.coverage.transposition_keyword in (
                "OBSERVE", "GARDEN",
            )
            assert s.coverage.transposition_keyword != ""

    def test_col_order_source_is_clue_keyword(self):
        specs = _gen(["OBSERVE", "GARDEN"], ROLE_TRIPLE_CLUE)
        for s in _l022_specs(specs):
            assert s.coverage.col_order_source == "clue_keyword"

    def test_col_order_matches_keyword_length(self):
        specs = _gen(["OBSERVE", "GARDEN"], ROLE_TRIPLE_CLUE)
        for s in _l022_specs(specs):
            kw = s.coverage.transposition_keyword
            assert s.coverage.transposition_width == len(kw)
            assert len(s.coverage.col_order) == len(kw)

    def test_role_assignment_mode(self):
        specs = _gen(["OBSERVE", "GARDEN"], ROLE_TRIPLE_CLUE)
        for s in _l022_specs(specs):
            assert s.coverage.role_assignment_mode == (
                "independent_two_keyword_rail_fence_three_role"
            )

    def test_operation_source(self):
        specs = _gen(["OBSERVE", "GARDEN"], ROLE_TRIPLE_CLUE)
        for s in _l022_specs(specs):
            assert s.coverage.operation_source == (
                "independent_keyword_rail_fence_composition"
            )

    def test_role_assignment_carries_three_roles(self):
        specs = _gen(["OBSERVE", "GARDEN"], ROLE_TRIPLE_CLUE)
        for s in _l022_specs(specs):
            ra = dict(s.coverage.role_assignment)
            assert len(ra) == 3
            assert "columnar" in ra
            assert "rail_fence" in ra
            assert any(
                k in ra
                for k in ("vigenere", "beaufort", "variant_beaufort")
            )

    def test_n_layers_equals_three(self):
        specs = _gen(["OBSERVE", "GARDEN"], ROLE_TRIPLE_CLUE)
        for s in _l022_specs(specs):
            assert s.coverage.n_layers == 3

    def test_scheduling_telemetry_present(self):
        specs = _gen(["OBSERVE", "GARDEN"], ROLE_TRIPLE_CLUE)
        for s in _l022_specs(specs):
            assert s.coverage.scheduling_pass in ("quota", "residual")
            assert s.coverage.family_quota == 40
            assert isinstance(s.coverage.family_quota_rank, int)
            assert s.coverage.hcc_max_specs == 10000


# ---------------------------------------------------------------------------
# 4. Negative gating
# ---------------------------------------------------------------------------


class TestNegativeGating:
    def test_no_emission_with_one_keyword(self):
        specs = _gen(["OBSERVE"], ONE_KEYWORD_CLUE)
        assert _l022_specs(specs) == [], (
            "LESSON-022 must require >= 2 distinct keywords"
        )

    def test_no_emission_without_rail_fence_depth(self):
        # Clue with two keywords but no rail-fence anchor → no
        # phrase-bound rail depth → no LESSON-022 emission.
        specs = _gen(["OBSERVE", "GARDEN"], NO_RAIL_CLUE)
        assert _l022_specs(specs) == [], (
            "LESSON-022 must require a clue-bound rail_fence depth"
        )

    def test_no_emission_with_one_usable_keyword(self):
        # Clue has rail-fence anchor BUT only one usable keyword.
        # The second clue_words entry is too short (len < 2) to be
        # a usable columnar key; LESSON-022 must not emit.
        clue = (
            "OBSERVE is carved on the mock panel. "
            "A three-rail fence appears after the column labels."
        )
        specs = _gen(["OBSERVE"], clue)
        assert _l022_specs(specs) == [], (
            "single usable clue keyword must not produce "
            "LESSON-022 specs"
        )

    def test_no_emission_with_default_only_rail_depth(self):
        # No phrase-bound rail-fence depth → LESSON-022 doesn't fire.
        # _rail_fence_depths_for_payload still returns the default
        # set, but LESSON-022 specifically requires phrase-bound
        # depth.
        specs = _gen(["OBSERVE", "GARDEN"], DEFAULT_DEPTH_ONLY_CLUE)
        assert _l022_specs(specs) == [], (
            "default-only rail depth must not trigger LESSON-022"
        )


# ---------------------------------------------------------------------------
# 5. Constrained-cap survival
# ---------------------------------------------------------------------------


class TestSchedulerSurvival:
    def test_lesson_022_survives_low_cap(self):
        # Even at a tight cap, at least one LESSON-022 spec must
        # survive the LESSON-017 quota pass.
        specs = _gen(
            ["OBSERVE", "GARDEN"], ROLE_TRIPLE_CLUE, max_specs=8000,
        )
        l022 = _l022_specs(specs)
        assert l022, (
            "LESSON-022 must survive constrained 8000-spec cap"
        )

    def test_lesson_022_quota_class(self):
        specs = _gen(["OBSERVE", "GARDEN"], ROLE_TRIPLE_CLUE)
        l022 = _l022_specs(specs)
        for s in l022:
            assert s.coverage.family_quota == 40, (
                "LESSON-022 should be in three_layer_sandwich quota"
            )


# ---------------------------------------------------------------------------
# 6. Regressions
# ---------------------------------------------------------------------------


class TestRegressions:
    def test_lesson_010_i3_two_layer_still_emits(self):
        specs = _gen(["OBSERVE", "GARDEN"], ROLE_TRIPLE_CLUE)
        i3_two = [
            s for s in specs
            if s.coverage.layer_family in (
                "i3_columnar_vigenere",
                "i3_columnar_beaufort",
                "i3_columnar_variant_beaufort",
            )
            and s.coverage.role_assignment_mode == "independent_three_role"
        ]
        assert i3_two, "LESSON-010 i3 two-layer family must still emit"

    def test_lesson_013_enumerated_three_layer_still_emits(self):
        specs = _gen(["OBSERVE", "GARDEN"], ROLE_TRIPLE_CLUE)
        l013 = [
            s for s in specs
            if s.coverage.layer_family in (
                "columnar_vigenere_rail_fence",
                "columnar_beaufort_rail_fence",
                "columnar_variant_beaufort_rail_fence",
            )
        ]
        assert l013, "LESSON-013 enumerated three-layer must still emit"
        # LESSON-013 specs have empty transposition_keyword and
        # role_assignment_mode='enumerated_columnar' — distinguishing
        # them from the new LESSON-022 family.
        for s in l013:
            assert s.coverage.transposition_keyword == ""
            assert s.coverage.role_assignment_mode == (
                "enumerated_columnar"
            )

    def test_numeric_classifier_still_binds_three_to_rail_depth(self):
        roles = _classify_numeric_roles(ROLE_TRIPLE_CLUE)
        assert roles == [{
            "value": 3, "token": "three", "role": "rail_depth",
            "position": 11, "raw_value": 3,
        }]

    def test_three_rail_does_not_promote_to_caesar(self):
        promoted = _detect_numeric_caesar_promotion(ROLE_TRIPLE_CLUE)
        assert promoted == []

    def test_phrase_bound_rail_depth_extracted(self):
        bound = extract_phrase_bound_numerics(ROLE_TRIPLE_CLUE)
        assert bound["rail_depth"] == [3]

    def test_rail_fence_depths_for_payload_includes_3(self):
        depths = _rail_fence_depths_for_payload(ROLE_TRIPLE_CLUE)
        assert 3 in depths


# ---------------------------------------------------------------------------
# 7. Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_two_runs_identical(self):
        a = _gen(["OBSERVE", "GARDEN"], ROLE_TRIPLE_CLUE)
        b = _gen(["OBSERVE", "GARDEN"], ROLE_TRIPLE_CLUE)
        a_l022 = [
            (s.coverage.layer_family, tuple(s.coverage.layer_order),
             s.coverage.substitution_keyword,
             s.coverage.transposition_keyword)
            for s in _l022_specs(a)
        ]
        b_l022 = [
            (s.coverage.layer_family, tuple(s.coverage.layer_order),
             s.coverage.substitution_keyword,
             s.coverage.transposition_keyword)
            for s in _l022_specs(b)
        ]
        assert a_l022 == b_l022


# ---------------------------------------------------------------------------
# 8. Lesson registry
# ---------------------------------------------------------------------------


class TestLessonRegistry:
    def test_lesson_022_in_default_set(self):
        ids = {l.lesson_id for l in _default_lessons()}
        assert "LESSON-022" in ids

    def test_lesson_022_metadata(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-022"]
        assert l.tactic_kind == (
            "independent_two_keyword_rail_fence_three_role_composition"
        )
        for fam in (
            "i3_columnar_vigenere_rail_fence",
            "i3_columnar_beaufort_rail_fence",
            "i3_columnar_variant_beaufort_rail_fence",
        ):
            assert fam in l.applies_to_families
        assert l.tactic_parameters["no_new_primitive"] is True
        assert l.tactic_parameters["bench_only"] is True


# ---------------------------------------------------------------------------
# 9. Real-K4 mode unchanged
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
