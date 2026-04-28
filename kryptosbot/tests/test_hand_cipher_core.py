"""Tests for kryptosbot/hand_cipher_core.py + solver_capabilities.py.

Covers the patch spec from 2026-04-27:

  1. Two clue words A,B over columnar+Vigenere produce all four
     role/order combinations (the K4B-001 failure pattern, expressed
     against synthetic clue words so the test does not require any
     bench fixture).
  2. Failed (partial-coverage) attempts produce a next-test
     recommendation for the missing inverse role assignment AND the
     missing layer order.
  3. The lesson registry refuses to store sealed-material fields
     (forbidden field names AND plaintext-shaped string values).
  4. Real-K4 mode can consume the generalized solver lessons without
     importing K4Bench plaintext or answer keys (lessons are pure
     tactics, not challenge-specific).
  5. Bench-mode catalog stays challenge-local (the generated specs
     reference clue keywords from the bench payload only; no real-K4
     vocabulary leak).
  6. Toy-cipher regression: A,B clue words, intended method =
     Vigenere(B) then Columnar(A). The solver must generate that
     EXACT candidate before any LLM call. Deterministic, no API.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from kryptosbot.hand_cipher_core import (
    CoverageVector,
    GeneratedSpec,
    coverage_class_key,
    coverage_gap_recommendations,
    coverage_vectors_from_theories,
    gap_analysis,
    generate_layered_specs,
    missing_combos_as_specs,
    _keyword_to_col_order,
)
from kryptosbot.solver_capabilities import (
    Lesson,
    LessonRegistry,
    LessonValidationError,
    _default_lessons,
)


# --- (1) Two clue words → four role/order combinations ----------------------


class TestTwoClueWordsFourCombos:
    def test_columnar_vigenere_emits_four_role_order_combos(self):
        """For two clue words A,B the columnar_vigenere family must
        emit all four (role × order) symmetry-class points.

        2026-04-27: with alphabet-mode enumeration, the same (role ×
        order) coord appears once per alphabet mode. The structural
        assertion is on the COORDINATE COUNT, not the spec count.

        2026-04-28 (LESSON-013): the family also emits enumerated
        col_order specs whose role_assignment uses synthetic
        identifiers (``W{w}_co{idx}``), creating ~120 additional
        coords per W=5 enumeration. The 4-coord invariant is on the
        KEYWORD-DERIVED specs only — filter them via
        ``col_order_source != "enumerated_permutation"``.
        """
        specs = generate_layered_specs(["ALPHA", "BRAVO"], bench_slug="t01")
        cv_specs = [
            gs for gs in specs
            if gs.family_label == "columnar_vigenere"
            and gs.coverage.col_order_source != "enumerated_permutation"
        ]
        coords = {
            (gs.coverage.layer_order, gs.coverage.role_assignment)
            for gs in cv_specs
        }
        assert len(coords) == 4, (
            f"expected 4 distinct (layer_order, role_assignment) coords "
            f"for columnar_vigenere keyword path; got {len(coords)} from "
            f"{len(cv_specs)} specs"
        )

    def test_all_four_combos_present_for_every_keyword_pair_family(self):
        """Same property as above for every keyword-pair two-layer
        family the generator supports. The 4-coord invariant is on
        the KEYWORD-DERIVED specs; LESSON-013's enumerated col_order
        specs are excluded by ``col_order_source`` filtering.
        """
        keyword_pair_families = (
            "columnar_vigenere", "columnar_beaufort",
            "columnar_variant_beaufort",
            "myszkowski_vigenere", "myszkowski_beaufort",
        )
        specs = generate_layered_specs(["ALPHA", "BRAVO"], bench_slug="t02")
        for family in keyword_pair_families:
            family_specs = [
                gs for gs in specs
                if gs.family_label == family
                and gs.coverage.col_order_source != "enumerated_permutation"
            ]
            coords = {
                (gs.coverage.layer_order, gs.coverage.role_assignment)
                for gs in family_specs
            }
            assert len(coords) == 4, (
                f"{family} expected 4 distinct (order, role) coords on "
                f"keyword path; got {len(coords)}"
            )

    def test_keywordless_transposition_collapses_role_swap(self):
        """rail_fence + substitution: rail_fence has no keyword role,
        so role-permutation collapses; only the layer-order flip
        remains. With 2 keywords × multiple depths × multiple alphabet
        modes the absolute spec count is large, but the role
        coordinate set has exactly ONE element per (keyword, depth)
        because the role-swap is unavailable.
        """
        # Override alphabet modes to AZ-only so the assertion is
        # easy to read; the alphabet dimension is covered separately.
        from kryptosbot.hand_cipher_core import AlphabetMode
        az_only = (AlphabetMode("AZ", "AZ", None, "default"),)
        specs = generate_layered_specs(
            ["ALPHA", "BRAVO"],
            bench_slug="t03",
            families={"rail_fence_vigenere"},
            alphabet_modes=az_only,
            rail_fence_depths=(3, 5),
        )
        rfv = [gs for gs in specs if gs.family_label == "rail_fence_vigenere"]
        # 2 keywords × 2 depths × 2 layer orders × 1 alphabet = 8
        assert len(rfv) == 8, f"expected 8 rail_fence_vigenere specs; got {len(rfv)}"
        # Role coordinate set has 2 entries (one per keyword); the
        # collapse-of-role-swap means role assignments are NOT
        # permuted on this side.
        roles = {gs.coverage.role_assignment for gs in rfv}
        assert len(roles) == 2

    def test_specs_validate_via_dispatcher(self):
        """Every emitted spec must pass validate_hypothesis_spec AND
        every layer kind must have a dispatcher translation. The
        generator already enforces this; this test pins the contract.
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _kind_has_translation
        specs = generate_layered_specs(["ALPHA", "BRAVO"], bench_slug="t04")
        for gs in specs:
            parsed = validate_hypothesis_spec(gs.raw_spec)
            assert parsed.is_valid, (
                f"spec {gs.hypothesis_id} failed validation: {parsed.errors}"
            )
            for layer in parsed.value.pipeline:
                assert _kind_has_translation(layer.kind), (
                    f"spec {gs.hypothesis_id} layer kind {layer.kind!r} "
                    "has no dispatcher translation"
                )

    def test_generator_is_deterministic(self):
        """Same inputs → same hypothesis_id ordering. Required for
        ledger deduplication."""
        a = generate_layered_specs(["ALPHA", "BRAVO"], bench_slug="t05")
        b = generate_layered_specs(["ALPHA", "BRAVO"], bench_slug="t05")
        assert [gs.hypothesis_id for gs in a] == [gs.hypothesis_id for gs in b]

    def test_columnar_uses_keyword_derived_col_order_not_identity(self):
        """The K4B-001 root cause: the prior generator emitted columnar
        with col_order=[0..width-1] (a no-op). The new generator must
        derive col_order from the keyword via _keyword_to_col_order.
        """
        specs = generate_layered_specs(["LANTERN", "CEDAR"], bench_slug="t06")
        cv_specs = [gs for gs in specs if gs.family_label == "columnar_vigenere"]
        for gs in cv_specs:
            for layer in gs.raw_spec["pipeline"]:
                if layer["kind"] != "columnar":
                    continue
                params = {p["name"]: p["values"][0] for p in layer["params"]}
                col_order = params["col_order"]
                width = params["width"]
                # A non-degenerate keyword (LANTERN, CEDAR — both have
                # non-monotonic letter sequences) MUST produce a
                # non-identity permutation.
                assert col_order != list(range(width)), (
                    f"spec {gs.hypothesis_id} columnar layer has identity "
                    f"col_order {col_order} — the K4B-001 bug regressed!"
                )


# --- (2) Failed run → next-test recommendation -------------------------------


class TestGapRecommendations:
    def test_partial_coverage_recommends_missing_inverse_assignment(self):
        """The K4B-001 failure mode: only A-as-Vigenere/B-as-columnar
        was tested. The recommendation must surface BOTH the inverse
        assignment and the missing layer order.
        """
        # Construct the "tested" coverage vector by hand: only one of
        # the four combos covered.
        tested_only = [CoverageVector(
            layer_family="columnar_vigenere",
            layer_order=("vigenere", "columnar"),
            role_assignment=tuple(sorted([
                ("vigenere", "ALPHA"),
                ("columnar", "BRAVO"),
            ])),
            alphabet="AZ",
            n_layers=2,
        )]
        recs = coverage_gap_recommendations(tested_only, bench_slug="t07")
        assert recs["n_classes_with_gaps"] == 1, (
            "should report exactly the one partially-covered class"
        )
        assert recs["n_recommended_specs"] == 3, (
            "should recommend exactly the 3 missing combos in that class"
        )
        # Inspect the recommended specs: confirm the role-swap is among them
        rec_class = recs["classes"][0]
        roles_recommended = [
            spec["role_assignment"] for spec in rec_class["next_specs"]
        ]
        # The role-swap (vigenere=BRAVO, columnar=ALPHA) must appear
        swap = {"vigenere": "BRAVO", "columnar": "ALPHA"}
        assert swap in roles_recommended, (
            f"role-swap recommendation missing; got {roles_recommended}"
        )
        # The order-flip (columnar, vigenere) for the original role must appear
        orders_for_original_role = [
            spec["layer_order"] for spec in rec_class["next_specs"]
            if spec["role_assignment"] == {"vigenere": "ALPHA", "columnar": "BRAVO"}
        ]
        assert ["columnar", "vigenere"] in orders_for_original_role, (
            f"order-flip for original role missing; got {orders_for_original_role}"
        )

    def test_full_coverage_yields_no_recommendations(self):
        """When all four combos in a class are tested, the class is
        NOT in the recommendations.

        2026-04-28 (LESSON-013): the family also emits enumerated
        col_order specs whose role_assignment uses synthetic
        identifiers. They share the family_label but are a separate
        coverage axis; the 4-combo gap invariant is on the keyword
        path only — filter via ``col_order_source``.
        """
        from kryptosbot.hand_cipher_core import AlphabetMode
        az_only = (AlphabetMode("AZ", "AZ", None, "default"),)
        full = [
            gs.coverage for gs in generate_layered_specs(
                ["ALPHA", "BRAVO"],
                bench_slug="t08",
                families={"columnar_vigenere"},
                alphabet_modes=az_only,
            )
            if gs.coverage.col_order_source != "enumerated_permutation"
        ]
        assert len(full) == 4
        recs = coverage_gap_recommendations(full, bench_slug="t08")
        assert recs["n_classes_with_gaps"] == 0, (
            f"fully-covered class should have no gaps; got {recs['classes']}"
        )

    def test_render_block_is_human_readable(self):
        """The render_block field must surface the gap as a prompt-
        ready text snippet referencing the actual missing combos."""
        tested = [CoverageVector(
            layer_family="columnar_vigenere",
            layer_order=("vigenere", "columnar"),
            role_assignment=tuple(sorted([
                ("vigenere", "ALPHA"), ("columnar", "BRAVO"),
            ])),
            alphabet="AZ", n_layers=2,
        )]
        recs = coverage_gap_recommendations(tested, bench_slug="t09")
        assert "columnar_vigenere" in recs["render_block"]
        assert "ALPHA" in recs["render_block"]
        assert "BRAVO" in recs["render_block"]
        assert "lesson 006" in recs["render_block"]


# --- (3) Lesson registry rejects sealed material -----------------------------


class TestLessonRegistryNoSealedMaterial:
    def test_default_lessons_pass_validation(self):
        """The seeded default lesson set must pass the forbidden-field
        scan. A regression here means the user spec violates its own
        registry contract.
        """
        for lesson in _default_lessons():
            # Constructing the dataclass runs __post_init__ which runs
            # the forbidden-field scan. If any seeded lesson tripped
            # the scan, this would raise.
            assert lesson.lesson_id.startswith("LESSON-")

    def test_registry_rejects_lesson_with_plaintext_field(self):
        """A lesson dict containing a `plaintext` key (anywhere) is
        rejected at construction time.
        """
        with pytest.raises(LessonValidationError):
            Lesson(
                lesson_id="LESSON-X", title="bad",
                description="ok", tactic_kind="role_permutation",
                coverage_floor={"plaintext_count": 1},
            )

    def test_registry_rejects_lesson_with_answer_field(self):
        with pytest.raises(LessonValidationError):
            Lesson(
                lesson_id="LESSON-X", title="bad",
                description="ok", tactic_kind="role_permutation",
                coverage_floor={"answer_hash": 1},
            )

    def test_registry_rejects_lesson_with_long_uppercase_value(self):
        """A 97-char A-Z string in any value position trips the
        sealed-string heuristic.
        """
        with pytest.raises(LessonValidationError):
            Lesson(
                lesson_id="LESSON-X", title="bad",
                description="X" * 97,  # plaintext-shaped
                tactic_kind="role_permutation",
            )

    def test_registry_file_round_trip(self, tmp_path: Path):
        """Default lesson set seeds, persists, reloads correctly.

        2026-04-27: lesson count is now governed by the
        ``_default_lessons()`` seed list, not a hard-coded constant —
        adding LESSON-007 (and any future lessons) auto-extends the
        round-trip without test churn.
        """
        from kryptosbot.solver_capabilities import _default_lessons
        expected_count = len(_default_lessons())
        assert expected_count >= 6  # the original lesson floor

        path = tmp_path / "lessons.json"
        reg = LessonRegistry(path=path)
        assert len(reg) == expected_count
        # Reload from file
        reg2 = LessonRegistry(path=path, seed_defaults=False)
        assert len(reg2) == expected_count
        for lesson in reg.all():
            loaded = reg2.get(lesson.lesson_id)
            assert loaded is not None
            assert loaded.title == lesson.title

    def test_registry_refuses_corrupt_file(self, tmp_path: Path):
        """A registry file whose contents include a forbidden token
        is rejected at load time.
        """
        path = tmp_path / "tampered.json"
        path.write_text(json.dumps({
            "schema_version": "solver_capabilities.lessons.v1",
            "lessons": [{
                "lesson_id": "LESSON-X", "title": "tampered",
                "description": "ok", "tactic_kind": "role_permutation",
                "coverage_floor": {"plaintext_blob": 1},
            }],
        }))
        with pytest.raises(LessonValidationError):
            LessonRegistry(path=path, seed_defaults=False)

    def test_lesson_applies_to_filter(self, tmp_path: Path):
        """``applicable_to`` returns lessons whose families match OR
        carry the wildcard.
        """
        reg = LessonRegistry(path=tmp_path / "lessons.json")
        # Layer-order inversion has wildcard "*"
        applicable = reg.applicable_to("columnar_vigenere")
        ids = {l.lesson_id for l in applicable}
        assert "LESSON-002" in ids  # wildcard
        assert "LESSON-001" in ids  # explicit family
        # Quagmire-only lesson present for quagmire family.
        quagmire_ids = {l.lesson_id for l in reg.applicable_to("quagmire")}
        assert "LESSON-003" in quagmire_ids
        # Quagmire-only lesson absent for an unrelated family.
        rfv_ids = {l.lesson_id for l in reg.applicable_to("rail_fence_vigenere")}
        assert "LESSON-003" not in rfv_ids


# --- (4) Real-K4 mode consumes lessons without K4Bench leakage --------------


class TestRealK4ConsumesLessons:
    def test_real_k4_caller_can_get_lessons_without_bench_payload(
        self, tmp_path: Path,
    ):
        """A real-K4 ProblemContext doesn't carry bench_payload; the
        lesson registry must still produce its lessons because they
        are challenge-agnostic.
        """
        from kryptosbot.problem_context import ProblemContext
        ctx = ProblemContext.real_k4()
        assert ctx.is_real_k4
        # Build the registry — no payload required
        reg = LessonRegistry(path=tmp_path / "lessons.json")
        lessons = reg.applicable_to("columnar_vigenere")
        assert len(lessons) > 0
        # Confirm none of the lessons reference bench-only material
        for lesson in lessons:
            assert "K4B-001" not in lesson.description
            assert "K4B-002" not in lesson.description
            # The source_origin field MAY mention "k4bench-derived" —
            # that's intended provenance, not sealed material
            assert "plaintext" not in lesson.description.lower()
            assert "answer" not in lesson.description.lower()

    def test_real_k4_caller_can_invoke_generator_with_real_clue_words(self):
        """The generator works on any clue words — no bench dependency."""
        # Real-K4-style words (e.g. from the BERLIN/CLOCK clues)
        specs = generate_layered_specs(
            ["BERLIN", "CLOCK"], bench_slug="real-k4",
        )
        assert len(specs) > 0
        # Confirm the bench_slug propagates without leaking K4B-001 vocab
        for gs in specs:
            assert "real-k4" in gs.hypothesis_id
            assert "K4B" not in gs.hypothesis_id
            assert "k4bench" not in gs.hypothesis_id.lower()


# --- (5) Bench-mode catalog stays challenge-local ----------------------------


class TestBenchModeChallengeLocal:
    def test_bench_specs_only_use_payload_clue_words(self):
        """The generator emits keywords drawn from its inputs only;
        nothing from real-K4 vocabulary unless the caller explicitly
        added it.

        2026-04-28 (LESSON-013): synthetic role identifiers of the
        form ``W{w}_co{idx}`` are emitted by the enumerated columnar
        path (they are NOT keywords — they encode (width, col_order_
        index) into the role tuple). Rail-fence depths in 3-layer
        sandwich families also appear as numeric strings ("3", "4",
        ...). Both are allowed in addition to the clue-derived
        keyword pool.
        """
        import re as _re
        l013_synthetic = _re.compile(r"^W\d+_co\d+$")
        rail_fence_depth = _re.compile(r"^\d+$")
        specs = generate_layered_specs(["WIDGET", "GIZMO"], bench_slug="b01")
        for gs in specs:
            roles = dict(gs.coverage.role_assignment)
            for keyword in roles.values():
                kw_str = str(keyword)
                # Allow placeholder kw_b == kw_a when only one supplied
                # (tested separately); here we passed two distinct words
                # so all role keywords MUST be in {WIDGET, GIZMO} or a
                # LESSON-013 synthetic ``W{w}_co{idx}`` identifier or
                # a rail-fence depth numeric string.
                if l013_synthetic.match(kw_str):
                    continue
                if rail_fence_depth.match(kw_str):
                    continue
                assert keyword in {"WIDGET", "GIZMO"}, (
                    f"unexpected keyword {keyword!r} in spec "
                    f"{gs.hypothesis_id} — should be from input pool only"
                )

    def test_bench_fallback_does_not_leak_real_k4_vocabulary(self):
        """The fallback wrapper uses the safe default keyword pool
        (KRYPTOS, PALIMPSEST, ABSCISSA, KEY) when the clue text yields
        nothing — these are project-wide-safe and don't contaminate
        a real-K4 prompt. Confirm bench mode doesn't sneak in real-K4
        anomaly anchors (BERLIN, CLOCK, CIA, ECLIPSE).
        """
        from kryptosbot.bench_fallback import hand_cipher_core_fallback
        payload = {
            "bench_id": "K4B-T99",
            "title": "Synthetic test",
            "clue_text": "WIDGET GIZMO appear in the margin.",
        }
        theories = hand_cipher_core_fallback(payload, n_target=5)
        for theory in theories:
            for forbidden in ("BERLIN", "CLOCK", "ECLIPSE", "EASTNORTHEAST"):
                # Forbidden tokens must not appear in the spec or coverage.
                spec_str = json.dumps(theory.dsl_spec)
                assert forbidden not in spec_str, (
                    f"theory {theory.hypothesis_id} leaked real-K4 token "
                    f"{forbidden!r}"
                )


# --- (6) Toy-cipher regression: known answer, deterministic generation -----


class TestToyCipherRegression:
    """Toy fixture modeled on K4B-001's failure pattern.

    A deliberately simple synthetic cipher with VISIBLE answer:
      - clue words: "PEACH" and "FIVE"
      - intended encryption: Columnar(PEACH) outermost,
        then Vigenere(FIVE) innermost
      - intended decryption pipeline: [Vigenere(FIVE), Columnar(PEACH)]
        (reverse order; outer-encryption is first-decrypted)

    The solver MUST produce that exact decryption pipeline as one of
    its candidates BEFORE any LLM call. That's the property the
    K4B-001 fallback failed to provide.
    """

    INTENDED_KW_VIGENERE = "FIVE"
    INTENDED_KW_COLUMNAR = "PEACH"

    def test_solver_generates_intended_decryption_pipeline_pre_llm(self):
        """Deterministic test — no SDK, no API. Calls the generator
        directly with the toy clue words and asserts the intended
        decryption pipeline is among the emitted specs.

        This is the K4B-001 failure pattern, expressed against
        synthetic clues so the test cannot accidentally inherit any
        bench-fixture context. The solver emitting the right
        candidate BEFORE the LLM is involved is the core property
        the patch ensures.
        """
        clues = [self.INTENDED_KW_VIGENERE, self.INTENDED_KW_COLUMNAR]
        specs = generate_layered_specs(clues, bench_slug="toy")

        # The intended decryption pipeline (decrypt-stack order =
        # reverse of encryption order):
        #   Encryption: Columnar(PEACH) ∘ Vigenere(FIVE)
        #   Decryption: Vigenere(FIVE) then Columnar(PEACH)
        intended_role = tuple(sorted([
            ("vigenere", self.INTENDED_KW_VIGENERE),
            ("columnar", self.INTENDED_KW_COLUMNAR),
        ]))
        intended_order = ("vigenere", "columnar")
        intended_family = "columnar_vigenere"

        match = [
            gs for gs in specs
            if gs.family_label == intended_family
            and gs.coverage.layer_order == intended_order
            and gs.coverage.role_assignment == intended_role
            # 2026-04-27: pin to the AZ alphabet mode so the structural
            # check picks the canonical decryption pipeline; alphabet
            # enumeration is verified separately.
            and gs.coverage.alphabet_mode == "AZ"
        ]
        assert len(match) == 1, (
            f"Solver did NOT generate the intended decryption pipeline "
            f"Vigenere({self.INTENDED_KW_VIGENERE}) ∘ "
            f"Columnar({self.INTENDED_KW_COLUMNAR}) for clues {clues}. "
            f"This is the K4B-001 failure pattern — the solver must "
            f"enumerate this assignment before any LLM call."
        )

        # Structural correctness: pull the actual layer dicts and
        # assert each layer carries the intended keyword.
        intended_spec = match[0].raw_spec
        layers = intended_spec["pipeline"]
        assert len(layers) == 2
        # Layer 0 (decrypt-first) must be Vigenere(FIVE)
        assert layers[0]["kind"] == "vigenere"
        vig_kw = next(
            p["values"][0] for p in layers[0]["params"] if p["name"] == "keyword"
        )
        assert vig_kw == self.INTENDED_KW_VIGENERE, (
            f"intended Vigenere keyword {self.INTENDED_KW_VIGENERE!r} "
            f"missing; got {vig_kw!r}"
        )
        # Layer 1 (decrypt-second) must be Columnar(PEACH) with
        # keyword-derived col_order, not the no-op identity that the
        # K4B-001 fallback used.
        assert layers[1]["kind"] == "columnar"
        col_params = {p["name"]: p["values"][0] for p in layers[1]["params"]}
        # The width should equal the columnar keyword's length.
        assert col_params["width"] == len(self.INTENDED_KW_COLUMNAR), (
            f"columnar width should equal len({self.INTENDED_KW_COLUMNAR})="
            f"{len(self.INTENDED_KW_COLUMNAR)}; got {col_params['width']}"
        )
        # And col_order must be the keyword-derived rank order, not identity.
        expected_col_order = _keyword_to_col_order(self.INTENDED_KW_COLUMNAR)
        assert col_params["col_order"] == expected_col_order, (
            f"col_order should be derived from keyword "
            f"{self.INTENDED_KW_COLUMNAR}; expected {expected_col_order}, "
            f"got {col_params['col_order']}"
        )
        assert col_params["col_order"] != list(range(col_params["width"])), (
            "col_order is identity — the K4B-001 bug regressed!"
        )

    def test_role_swap_is_also_generated(self):
        """The role-swap variant (Vigenere(PEACH) + Columnar(FIVE))
        must ALSO be present — it might be the right answer for a
        different toy cipher with the same clue pair.
        """
        clues = [self.INTENDED_KW_VIGENERE, self.INTENDED_KW_COLUMNAR]
        specs = generate_layered_specs(clues, bench_slug="toy")
        swapped_role = tuple(sorted([
            ("vigenere", self.INTENDED_KW_COLUMNAR),
            ("columnar", self.INTENDED_KW_VIGENERE),
        ]))
        match = [
            gs for gs in specs
            if gs.family_label == "columnar_vigenere"
            and gs.coverage.role_assignment == swapped_role
            and gs.coverage.alphabet_mode == "AZ"  # filter to canonical alphabet
        ]
        # Both layer orders should be present for the swapped role
        assert len(match) == 2, (
            f"Role-swap variant missing/incomplete; expected 2 layer "
            f"orders, got {len(match)}"
        )

    def test_solver_emits_no_identity_columnar_for_clued_pair(self):
        """The K4B-001 root cause: every columnar layer in a generated
        spec for a non-trivial clue pair has a non-identity col_order.

        This is the structural property that prevents the original
        bug from regressing — the prior fallback emitted col_order =
        [0, 1, 2, 3, 4, 5, 6] (identity) which is a no-op
        transposition. With keyword-derived col_order, even a single-
        configuration spec exercises the columnar layer meaningfully.
        """
        clues = [self.INTENDED_KW_VIGENERE, self.INTENDED_KW_COLUMNAR]
        specs = generate_layered_specs(clues, bench_slug="toy")
        for gs in specs:
            for layer in gs.raw_spec["pipeline"]:
                if layer["kind"] != "columnar":
                    continue
                params = {p["name"]: p["values"][0] for p in layer["params"]}
                assert params["col_order"] != list(range(params["width"])), (
                    f"spec {gs.hypothesis_id} has identity columnar "
                    f"order on width {params['width']} — K4B-001 bug "
                    "regressed."
                )


# --- Coverage vector serialization ------------------------------------------


class TestCoverageVectorSerialization:
    def test_round_trip(self):
        cv = CoverageVector(
            layer_family="columnar_vigenere",
            layer_order=("vigenere", "columnar"),
            role_assignment=tuple(sorted([
                ("vigenere", "ALPHA"),
                ("columnar", "BRAVO"),
            ])),
            alphabet="AZ", n_layers=2,
        )
        d = cv.to_dict()
        loaded = CoverageVector.from_dict(d)
        assert loaded == cv

    def test_clue_pair_property(self):
        cv = CoverageVector(
            layer_family="columnar_vigenere",
            layer_order=("vigenere", "columnar"),
            role_assignment=(("columnar", "ZULU"), ("vigenere", "ALPHA")),
            alphabet="AZ", n_layers=2,
        )
        # clue_pair is sorted set of values
        assert cv.clue_pair == ("ALPHA", "ZULU")

    def test_extract_from_theory_records(self):
        """coverage_vectors_from_theories ignores theories without a
        coverage_vector and parses the ones that have it.
        """
        from kryptosbot.models import TheoryRecord, TheoryStatus

        with_cv = TheoryRecord(
            hypothesis_id="t1", title="t",
            family="hcc", status=TheoryStatus.COMPLETED,
            minimal_test_spec={
                "coverage_vector": CoverageVector(
                    layer_family="columnar_vigenere",
                    layer_order=("vigenere", "columnar"),
                    role_assignment=(("columnar", "B"), ("vigenere", "A")),
                    alphabet="AZ", n_layers=2,
                ).to_dict(),
            },
        )
        without_cv = TheoryRecord(
            hypothesis_id="t2", title="legacy",
            family="legacy", status=TheoryStatus.COMPLETED,
            minimal_test_spec={"method": "legacy"},
        )
        vectors = coverage_vectors_from_theories([with_cv, without_cv])
        assert len(vectors) == 1
        assert vectors[0].layer_family == "columnar_vigenere"
