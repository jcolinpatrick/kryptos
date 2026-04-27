"""Tests for LESSON-007 — generalized trigger-driven alphabet/tableau
enumeration (2026-04-27, K4B-002 capability hardening).

Pinned properties:

  1. LESSON-007 is present in the default registry, has the correct
     tactic_kind (``alphabet_mode_enumeration``), and is enabled.
  2. The lesson is GENERALIZED: it carries no challenge-specific
     identifier, no plaintext, no ciphertext, no answer-derived
     parameter.
  3. The lesson's ``tactic_parameters`` match the runtime constants
     in ``kryptosbot.hand_cipher_core`` bit-for-bit (drift guard —
     the lesson is the audit-time source of truth).
  4. The forbidden-field scan rejects sealed-shape values placed in
     ``tactic_parameters``.
  5. K4Bench generation consumes the trigger language through the
     existing HCC path BEFORE any LLM call (no LessonRegistry
     runtime dependency required; the lesson documents what HCC
     does).
  6. Real-K4 mode can read the lesson as a tactical hint without
     importing K4Bench payloads, plaintexts, ciphertexts, or
     bench_id-keyed data.
  7. A synthetic mirror/alpha/strip clue produces substitution+
     transposition candidates over KA + mirrored alphabet modes
     before any LLM output is parsed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from kryptosbot.solver_capabilities import (
    Lesson,
    LessonRegistry,
    LessonValidationError,
)


_REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# (1) LESSON-007 exists and is correctly shaped
# ---------------------------------------------------------------------------


class TestLessonExists:
    def test_lesson_007_in_default_registry(self, tmp_path: Path):
        reg = LessonRegistry(path=tmp_path / "lessons.json")
        lesson = reg.get("LESSON-007")
        assert lesson is not None, (
            "LESSON-007 missing from default registry; the K4B-002 "
            "alphabet capability lesson is not persisted."
        )

    def test_lesson_007_tactic_kind(self, tmp_path: Path):
        reg = LessonRegistry(path=tmp_path / "lessons.json")
        lesson = reg.get("LESSON-007")
        assert lesson.tactic_kind == "alphabet_mode_enumeration"

    def test_lesson_007_is_enabled(self, tmp_path: Path):
        reg = LessonRegistry(path=tmp_path / "lessons.json")
        lesson = reg.get("LESSON-007")
        assert lesson.enabled is True

    def test_lesson_007_applies_to_substitution_and_paired_families(
        self, tmp_path: Path,
    ):
        reg = LessonRegistry(path=tmp_path / "lessons.json")
        lesson = reg.get("LESSON-007")
        # Must include all single-substitution kinds + paired families.
        for required in (
            "vigenere", "beaufort", "variant_beaufort",
            "quagmire",
            "columnar_vigenere", "columnar_beaufort",
            "rail_fence_vigenere", "rail_fence_beaufort",
            "route_vigenere", "route_beaufort",
            "myszkowski_vigenere",
        ):
            assert required in lesson.applies_to_families, (
                f"LESSON-007 missing applies_to_families entry "
                f"{required!r}; alphabet-mode enumeration must apply "
                "to every substitution + paired-transposition family"
            )


# ---------------------------------------------------------------------------
# (2) LESSON-007 is generalized (no challenge-specific or sealed material)
# ---------------------------------------------------------------------------


class TestLessonIsGeneralized:
    def test_lesson_007_does_not_reference_bench_ids(self, tmp_path: Path):
        """The lesson must not contain hard-coded challenge IDs,
        challenge-specific keywords (ORCHARD, etc.), challenge-specific
        depths, or any answer fact. The lesson is a TACTIC, not an
        answer recording.
        """
        reg = LessonRegistry(path=tmp_path / "lessons.json")
        lesson = reg.get("LESSON-007")
        as_json = json.dumps(lesson.to_dict()).upper()
        forbidden_in_lesson = [
            # Challenge IDs
            "K4B-001", "K4B-002", "K4B-003", "K4B-004", "K4B-005",
            "K4B-006", "K4B-007", "K4B-008", "K4B-009", "K4B-010",
            # Challenge-specific clue keywords
            "ORCHARD", "CEDAR", "LANTERN",
            # Challenge-specific depths and parameter values
            # (depth/width values are cipher-doctrine, but a SPECIFIC
            # depth tied to a specific challenge is answer-leakage)
        ]
        for token in forbidden_in_lesson:
            assert token not in as_json, (
                f"LESSON-007 contains challenge-specific token "
                f"{token!r}; lesson must be generalized, not "
                "answer-derived."
            )

    def test_lesson_007_tactic_parameters_have_no_sealed_keys(
        self, tmp_path: Path,
    ):
        reg = LessonRegistry(path=tmp_path / "lessons.json")
        lesson = reg.get("LESSON-007")
        params = lesson.tactic_parameters
        # The five expected keys exist; no plaintext/answer/ciphertext keys.
        expected_keys = {
            "trigger_tokens",
            "alphabet_mode_labels",
            "trigger_match",
            "applies_to_substitution_kinds",
            "applies_to_paired_transposition_kinds",
        }
        assert set(params.keys()) >= expected_keys
        forbidden_keys = (
            "plaintext", "ciphertext", "answer", "solution",
            "sealed_pt", "key_material", "decryption_key",
        )
        for k in params.keys():
            for tok in forbidden_keys:
                assert tok not in k.lower(), (
                    f"LESSON-007 tactic_parameters key {k!r} contains "
                    f"forbidden sealed-material token {tok!r}"
                )

    def test_no_lesson_in_default_set_carries_sealed_material(
        self, tmp_path: Path,
    ):
        """End-to-end: every lesson in the default set passes the
        forbidden-field scan AND has no challenge-ID reference.
        """
        reg = LessonRegistry(path=tmp_path / "lessons.json")
        for lesson in reg.all():
            # __post_init__ already ran the forbidden-field scan;
            # if any lesson tripped it, construction would have raised.
            # Check additionally for challenge IDs in the dict form.
            as_json = json.dumps(lesson.to_dict()).upper()
            for bench_id in ("K4B-001", "K4B-002", "K4B-003"):
                assert bench_id not in as_json, (
                    f"{lesson.lesson_id} references {bench_id} "
                    "— generalized lesson cannot point at a specific "
                    "bench challenge."
                )


# ---------------------------------------------------------------------------
# (3) Drift guard: lesson tactic_parameters match runtime constants
# ---------------------------------------------------------------------------


class TestLessonRuntimeDriftGuard:
    """The lesson is the audit-time source of truth. The runtime
    constants in ``kryptosbot.hand_cipher_core`` MUST match the
    lesson's ``tactic_parameters`` exactly. If they drift, this
    test fails loud and the operator either updates the lesson or
    fixes the runtime.
    """

    def test_trigger_tokens_match_runtime(self, tmp_path: Path):
        from kryptosbot.hand_cipher_core import _MIRROR_TRIGGER_TOKENS
        reg = LessonRegistry(path=tmp_path / "lessons.json")
        lesson = reg.get("LESSON-007")
        lesson_tokens = set(lesson.tactic_parameters["trigger_tokens"])
        assert lesson_tokens == set(_MIRROR_TRIGGER_TOKENS), (
            f"DRIFT: lesson trigger_tokens {lesson_tokens} != runtime "
            f"_MIRROR_TRIGGER_TOKENS {set(_MIRROR_TRIGGER_TOKENS)}. "
            "Update the lesson or the runtime — the lesson is the "
            "audit-time source of truth."
        )

    def test_alphabet_mode_labels_match_runtime_emission(
        self, tmp_path: Path,
    ):
        """The set of alphabet_mode_labels in the lesson must match
        the set of labels the runtime can emit (under trigger).
        """
        from kryptosbot.hand_cipher_core import (
            _alphabet_modes_for_payload,
        )
        reg = LessonRegistry(path=tmp_path / "lessons.json")
        lesson = reg.get("LESSON-007")
        lesson_labels = set(lesson.tactic_parameters["alphabet_mode_labels"])
        # Drive the runtime with a trigger clue + 1 keyword to
        # produce every emittable mode label exactly once.
        runtime_modes = _alphabet_modes_for_payload(
            "mirrored alphabet strip", ["WIDGET"],
        )
        runtime_labels = {m.mode_label for m in runtime_modes}
        assert lesson_labels == runtime_labels, (
            f"DRIFT: lesson alphabet_mode_labels {lesson_labels} != "
            f"runtime-emitted labels {runtime_labels}"
        )

    def test_substitution_kinds_match_runtime(self, tmp_path: Path):
        from kryptosbot.hand_cipher_core import (
            _SUBSTITUTION_KEYWORD_KINDS,
        )
        reg = LessonRegistry(path=tmp_path / "lessons.json")
        lesson = reg.get("LESSON-007")
        lesson_kinds = set(
            lesson.tactic_parameters["applies_to_substitution_kinds"]
        )
        assert lesson_kinds == set(_SUBSTITUTION_KEYWORD_KINDS)


# ---------------------------------------------------------------------------
# (4) Forbidden-field scan: tactic_parameters cannot smuggle sealed material
# ---------------------------------------------------------------------------


class TestTacticParametersLeakageGuard:
    def test_sealed_key_in_tactic_parameters_rejected(self):
        """A lesson with ``plaintext`` (or any forbidden token) inside
        tactic_parameters fails construction.
        """
        with pytest.raises(LessonValidationError):
            Lesson(
                lesson_id="LESSON-X", title="bad", description="ok",
                tactic_kind="alphabet_mode_enumeration",
                tactic_parameters={
                    "trigger_tokens": ["mirror"],
                    "plaintext_seed": "QQQ",
                },
            )

    def test_long_uppercase_value_in_tactic_parameters_rejected(self):
        """A 30+ char A-Z string anywhere in tactic_parameters trips
        the sealed-string heuristic.
        """
        long_plaintext_shape = "X" * 35
        with pytest.raises(LessonValidationError):
            Lesson(
                lesson_id="LESSON-X", title="bad", description="ok",
                tactic_kind="alphabet_mode_enumeration",
                tactic_parameters={
                    "trigger_tokens": ["mirror", long_plaintext_shape],
                },
            )

    def test_nested_sealed_field_in_tactic_parameters_rejected(self):
        """The forbidden-field scan walks nested dicts."""
        with pytest.raises(LessonValidationError):
            Lesson(
                lesson_id="LESSON-X", title="bad", description="ok",
                tactic_kind="alphabet_mode_enumeration",
                tactic_parameters={
                    "trigger_tokens": ["mirror"],
                    "metadata": {"answer_hash": "deadbeef"},
                },
            )


# ---------------------------------------------------------------------------
# (5) K4Bench generation consumes the trigger pre-LLM
# ---------------------------------------------------------------------------


class TestK4BenchConsumesLessonPreLLM:
    """The lesson documents WHAT hand_cipher_core does. This test
    proves the runtime emits the expected alphabet modes under a
    synthetic trigger BEFORE any LLM call is involved.
    """

    SYNTHETIC_CLUE = "the mirrored alphabet strip is folded"
    SYNTHETIC_CLUE_WORDS = ["WIDGET", "GIZMO"]

    def test_synthetic_trigger_emits_mirrored_modes(self):
        from kryptosbot.hand_cipher_core import generate_layered_specs
        specs = generate_layered_specs(
            self.SYNTHETIC_CLUE_WORDS,
            bench_slug="toy",
            clue_text=self.SYNTHETIC_CLUE,
        )
        modes = {s.coverage.alphabet_mode for s in specs}
        for required in ("AZ", "KA", "keyword_mixed",
                          "mirrored_az", "mirrored_ka"):
            assert required in modes, (
                f"runtime did not emit {required} under trigger "
                f"clue text — LESSON-007 contract violated"
            )

    def test_substitution_plus_transposition_with_ka_and_mirrored(self):
        """The user-mandated specific case: substitution+transposition
        candidates over KA AND mirrored alphabets, generated before
        any LLM call.
        """
        from kryptosbot.hand_cipher_core import generate_layered_specs
        specs = generate_layered_specs(
            self.SYNTHETIC_CLUE_WORDS,
            bench_slug="toy",
            clue_text=self.SYNTHETIC_CLUE,
        )
        # rail_fence_beaufort is the canonical substitution+transposition
        # family the user spec called out for the K4B-002-style scenario.
        bf_rf = [s for s in specs if s.family_label == "rail_fence_beaufort"]
        modes = {s.coverage.alphabet_mode for s in bf_rf}
        assert "KA" in modes
        assert "mirrored_az" in modes or "mirrored_ka" in modes


# ---------------------------------------------------------------------------
# (6) Real-K4 mode reads the lesson without bench imports
# ---------------------------------------------------------------------------


class TestRealK4ConsumesLessonAsHint:
    """The capability-hint API (``tactical_hints_for_real_k4``) must
    work without any K4Bench import, payload, or fixture. The hint
    is a plain dict; no controller config is required to fetch it.
    """

    def test_real_k4_caller_can_fetch_hints_with_no_bench_import(
        self, tmp_path: Path,
    ):
        # Construct registry alone — no controller, no bench loader,
        # no payload. This is exactly what a real-K4 caller would do.
        reg = LessonRegistry(path=tmp_path / "lessons.json")
        hints = reg.tactical_hints_for_real_k4()
        assert any(h["lesson_id"] == "LESSON-007" for h in hints)
        # And the K4 caller has no need to construct bench_payload to
        # read the hint — there's no challenge-specific data inside.
        h7 = next(h for h in hints if h["lesson_id"] == "LESSON-007")
        assert "tactic_parameters" in h7
        assert isinstance(h7["tactic_parameters"], dict)

    def test_render_block_is_human_readable_for_real_k4_prompts(
        self, tmp_path: Path,
    ):
        reg = LessonRegistry(path=tmp_path / "lessons.json")
        block = reg.hints_render_block()
        assert "LESSON-007" in block
        assert "alphabet" in block.lower() or "tableau" in block.lower()

    def test_hints_contain_no_challenge_specific_facts(
        self, tmp_path: Path,
    ):
        reg = LessonRegistry(path=tmp_path / "lessons.json")
        as_json = json.dumps(reg.tactical_hints_for_real_k4()).upper()
        for forbidden in (
            "K4B-001", "K4B-002", "K4B-003",
            "ORCHARD",
        ):
            assert forbidden not in as_json, (
                f"tactical_hints_for_real_k4 leaked challenge-specific "
                f"token {forbidden}"
            )


# ---------------------------------------------------------------------------
# (7) K4B-002 public-challenge regression (uses ONLY the public clue text;
#     does not assert sealed plaintext, ciphertext, or answer parameters)
# ---------------------------------------------------------------------------


class TestK4B002PublicClueRegression:
    """Regression-style check using ONLY the public K4B-002 challenge
    clue text. Asserts that mirror-trigger alphabet modes are
    generated from the public clue. Does NOT assert sealed answer
    facts (no plaintext / ciphertext / sealed depth / answer
    parameters).
    """

    K4B002_PATH = (
        _REPO_ROOT / "bench" / "k4bench" / "challenges" / "K4B-002.json"
    )

    @pytest.fixture
    def public_clue_text(self) -> str:
        if not self.K4B002_PATH.exists():
            pytest.skip(
                f"K4B-002 public challenge fixture not on disk at "
                f"{self.K4B002_PATH}"
            )
        with self.K4B002_PATH.open() as f:
            payload = json.load(f)
        return payload["public_clue_pack"]["clue_text"]

    def test_public_clue_text_triggers_mirror_enumeration(self, public_clue_text):
        from kryptosbot.hand_cipher_core import _detect_mirror_trigger
        # Public assertion: the clue text contains trigger language.
        # We do NOT assert what the right method is — only that the
        # LESSON-007 trigger fires from public material.
        assert _detect_mirror_trigger(public_clue_text), (
            "K4B-002 public clue text should trigger LESSON-007 "
            "alphabet enumeration"
        )

    def test_public_clue_text_yields_mirrored_modes(self, public_clue_text):
        """The set of alphabet modes derived from the K4B-002 public
        clue includes the mirrored variants. The test reads ONLY the
        public ``clue_text`` field — no sealed-answer file required.
        """
        from kryptosbot.hand_cipher_core import _alphabet_modes_for_payload
        # Use a synthetic clue-words pool so the test does not depend
        # on the bench's specific anchor words.
        modes = _alphabet_modes_for_payload(public_clue_text, ["WIDGET"])
        labels = {m.mode_label for m in modes}
        assert "mirrored_az" in labels
        assert "mirrored_ka" in labels


# ---------------------------------------------------------------------------
# (8) Self-check: this test file contains no sealed material
# ---------------------------------------------------------------------------


class TestNoSealedMaterialInTestFile:
    def test_no_sealed_tokens_or_plaintexts(self):
        """Reconstruct forbidden tokens at runtime so the literals
        never appear in the source file (avoids self-collision).
        """
        import re
        text = Path(__file__).read_text()
        forbidden_tokens = [
            "".join(chr(c) for c in toks) for toks in (
                # 13-char K4 crib
                (69, 65, 83, 84, 78, 79, 82, 84, 72, 69, 65, 83, 84),
                # 11-char K4 crib
                (66, 69, 82, 76, 73, 78, 67, 76, 79, 67, 75),
                # K4 ciphertext prefix
                (79, 66, 75, 82),
            )
        ]
        for token in forbidden_tokens:
            assert token not in text
        # No 30+ char A-Z run anywhere — that shape strongly suggests
        # a plaintext blob.
        for m in re.finditer(r"[A-Z]{30,}", text):
            chunk = m.group(0)
            # Reversed-AZ / reversed-KA are 26-char synthetic constants.
            # Anything 30+ should not exist in this file.
            raise AssertionError(
                f"test file contains a 30+ char A-Z run: {chunk[:60]}"
            )
