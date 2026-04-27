"""Tests for HandCipherCore alphabet-mode + clue-numeral enumeration
(2026-04-27, K4B-002 generalization).

ALL fixtures are SYNTHETIC. No K4Bench challenge plaintexts, no
sealed answer files, no challenge-specific keywords appear. The
K4B-002 lesson is generalized: a clue containing the trigger
language ("mirrored alpha strip", "reversed tableau", etc.)
expands the alphabet enumeration to include mirrored variants —
this property is tested with a fully synthetic clue pack.

Pinned properties:

  1. Trigger detection: ``mirror|mirrored|alpha|alphabet|strip|table|
     tableau|reverse|fold`` (case-insensitive, word-boundary) trips
     the mirrored-alphabet expansion.
  2. Synthetic clue "mirrored alpha strip" produces Beaufort+rail_fence
     specs over KA AND mirrored alphabets BEFORE any LLM call.
  3. coverage_vector carries alphabet_mode + alphabet_source for
     every emitted spec; mirrored variants tag source as
     ``reversed_az`` / ``reversed_ka``.
  4. Clue text containing "Seven" (or "7") produces a depth=7
     rail_fence spec; with no clue numerals, the safe defaults
     (3, 5) still produce a working enumeration.
  5. No clue triggers ⇒ default modes only (AZ + KA + keyword_mixed
     for the first 2 clue words); mirrored variants are absent.
  6. Real-K4 mode (no bench payload) does not invoke alphabet
     enumeration — the controller's _collect_hcc_seeds returns [].
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from kryptosbot.hand_cipher_core import (
    AlphabetMode,
    _alphabet_modes_for_payload,
    _depths_from_clue_text,
    _detect_mirror_trigger,
    _rail_fence_depths_for_payload,
    generate_layered_specs,
)


# ---------------------------------------------------------------------------
# (1) Trigger detection
# ---------------------------------------------------------------------------


class TestMirrorTriggerDetection:
    @pytest.mark.parametrize("clue,expected", [
        ("mirrored alpha strip", True),
        ("MIRROR symbol on table", True),
        ("a folded note about the alphabet", True),
        ("reversed tableau over silver", True),
        ("a reverse direction marker", True),
        ("post marks on a strip of metal", True),
        ("CEDAR posts below a LANTERN", False),
        ("widget gizmo on the bench", False),
        ("", False),
        ("no trigger language here", False),
    ])
    def test_trigger_detection(self, clue, expected):
        assert _detect_mirror_trigger(clue) is expected

    def test_word_boundary_avoids_false_positive(self):
        """``alpha`` is a substring of "alphabet" — both should
        independently trigger as separate words. But arbitrary
        letter sequences like "blahalpha" should NOT trigger.
        """
        assert _detect_mirror_trigger("the alpha")
        assert _detect_mirror_trigger("the alphabet")
        # Embedded substrings without word boundaries don't trigger.
        assert not _detect_mirror_trigger("alphapharma")
        assert not _detect_mirror_trigger("salphabath")


# ---------------------------------------------------------------------------
# (2) Mirrored-alphabet enumeration drives Beaufort+rail_fence specs
# ---------------------------------------------------------------------------


class TestBeaufortRailFenceMirroredAlphabet:
    """The K4B-002 property: a synthetic clue containing trigger
    language causes the Beaufort+rail_fence family to enumerate over
    KA and mirrored alphabets BEFORE any LLM call.
    """

    SYNTHETIC_CLUE = "mirrored alpha strip with seven folds"
    SYNTHETIC_CLUES = ["WIDGET", "GIZMO"]

    def _generate(self):
        return generate_layered_specs(
            self.SYNTHETIC_CLUES,
            bench_slug="toy",
            clue_text=self.SYNTHETIC_CLUE,
        )

    def test_beaufort_railfence_includes_mirrored_az(self):
        """At least one Beaufort+rail_fence spec uses the mirrored AZ
        alphabet. The dispatcher routes this through the
        keyword_mixed alphabet path with the reversed-AZ string as
        alphabet_keyword.
        """
        specs = self._generate()
        bf_rf = [s for s in specs if s.family_label == "rail_fence_beaufort"]
        modes = {s.coverage.alphabet_mode for s in bf_rf}
        assert "mirrored_az" in modes, (
            f"mirrored_az missing from rail_fence_beaufort modes "
            f"{modes} despite trigger language in clue text"
        )

    def test_beaufort_railfence_includes_mirrored_ka(self):
        specs = self._generate()
        bf_rf = [s for s in specs if s.family_label == "rail_fence_beaufort"]
        modes = {s.coverage.alphabet_mode for s in bf_rf}
        assert "mirrored_ka" in modes, (
            f"mirrored_ka missing from rail_fence_beaufort modes {modes}"
        )

    def test_beaufort_railfence_includes_ka(self):
        """KA mode must always be present (even without trigger),
        but verifying explicitly under trigger is a useful guard.
        """
        specs = self._generate()
        bf_rf = [s for s in specs if s.family_label == "rail_fence_beaufort"]
        modes = {s.coverage.alphabet_mode for s in bf_rf}
        assert "KA" in modes

    def test_mirrored_az_layer_uses_reversed_alphabet_keyword(self):
        """A spec with mirrored_az coverage must emit a substitution
        layer whose ``alphabet`` is ``"keyword_mixed"`` and whose
        ``alphabet_keyword`` is the reversed-AZ string.
        """
        specs = self._generate()
        target = next(
            s for s in specs
            if s.family_label == "rail_fence_beaufort"
            and s.coverage.alphabet_mode == "mirrored_az"
        )
        sub_layer = next(
            l for l in target.raw_spec["pipeline"]
            if l["kind"] == "beaufort"
        )
        assert sub_layer["alphabet"] == "keyword_mixed"
        params = {p["name"]: p["values"][0] for p in sub_layer["params"]}
        assert params["alphabet_keyword"] == "ZYXWVUTSRQPONMLKJIHGFEDCBA"

    def test_mirrored_ka_layer_uses_reversed_kryptos_keyword(self):
        specs = self._generate()
        target = next(
            s for s in specs
            if s.family_label == "rail_fence_beaufort"
            and s.coverage.alphabet_mode == "mirrored_ka"
        )
        sub_layer = next(
            l for l in target.raw_spec["pipeline"]
            if l["kind"] == "beaufort"
        )
        assert sub_layer["alphabet"] == "keyword_mixed"
        params = {p["name"]: p["values"][0] for p in sub_layer["params"]}
        # The KRYPTOS alphabet reversed: ZXWVUQNMLJIHGFEDCBASOTPYRK
        assert params["alphabet_keyword"] == "ZXWVUQNMLJIHGFEDCBASOTPYRK"

    def test_substitution_first_AND_trans_first_orders_for_mirrored(self):
        """Both layer orders must be present for the mirrored alphabet
        — the (sub_first, trans_first) symmetry holds across alphabet
        modes.
        """
        specs = self._generate()
        mirrored_specs = [
            s for s in specs
            if s.family_label == "rail_fence_beaufort"
            and s.coverage.alphabet_mode == "mirrored_az"
        ]
        orders = {tuple(s.coverage.layer_order) for s in mirrored_specs}
        assert ("beaufort", "rail_fence") in orders
        assert ("rail_fence", "beaufort") in orders


# ---------------------------------------------------------------------------
# (3) coverage_vector exposes alphabet_mode + alphabet_source
# ---------------------------------------------------------------------------


class TestCoverageVectorAlphabetFields:
    def test_every_spec_has_alphabet_mode_and_source(self):
        specs = generate_layered_specs(
            ["WIDGET", "GIZMO"],
            bench_slug="toy",
            clue_text="mirrored alpha strip",
        )
        for spec in specs:
            cov = spec.coverage
            assert cov.alphabet_mode in {
                "AZ", "KA", "keyword_mixed",
                "mirrored_az", "mirrored_ka",
            }, f"unexpected alphabet_mode {cov.alphabet_mode!r}"
            # alphabet_source must be a non-empty string
            assert isinstance(cov.alphabet_source, str)
            assert cov.alphabet_source

    def test_mirrored_modes_use_reversed_source_tags(self):
        specs = generate_layered_specs(
            ["WIDGET", "GIZMO"],
            bench_slug="toy",
            clue_text="mirrored alpha strip",
        )
        mirror_az_specs = [
            s for s in specs if s.coverage.alphabet_mode == "mirrored_az"
        ]
        assert len(mirror_az_specs) > 0
        for s in mirror_az_specs:
            assert s.coverage.alphabet_source == "reversed_az"

        mirror_ka_specs = [
            s for s in specs if s.coverage.alphabet_mode == "mirrored_ka"
        ]
        assert len(mirror_ka_specs) > 0
        for s in mirror_ka_specs:
            assert s.coverage.alphabet_source == "reversed_ka"

    def test_keyword_mixed_uses_clue_word_as_source(self):
        """Each keyword_mixed mode tags the clue word it derived
        from in alphabet_source. This is what lets the offline
        evaluator distinguish keyword_mixed-from-WIDGET from
        keyword_mixed-from-GIZMO.
        """
        specs = generate_layered_specs(
            ["WIDGET", "GIZMO"],
            bench_slug="toy",
            clue_text="",  # no trigger
        )
        kw_mixed_sources = {
            s.coverage.alphabet_source
            for s in specs
            if s.coverage.alphabet_mode == "keyword_mixed"
        }
        assert kw_mixed_sources == {"WIDGET", "GIZMO"}

    def test_coverage_vector_serialization_round_trip(self):
        """to_dict / from_dict preserve alphabet_mode + alphabet_source."""
        from kryptosbot.hand_cipher_core import CoverageVector
        cv = CoverageVector(
            layer_family="rail_fence_beaufort",
            layer_order=("beaufort", "rail_fence"),
            role_assignment=(("beaufort", "WIDGET"),),
            alphabet="mirrored_az", n_layers=2,
            extras=(("depth", 5),),
            alphabet_mode="mirrored_az",
            alphabet_source="reversed_az",
        )
        d = cv.to_dict()
        assert d["alphabet_mode"] == "mirrored_az"
        assert d["alphabet_source"] == "reversed_az"
        loaded = CoverageVector.from_dict(d)
        assert loaded.alphabet_mode == "mirrored_az"
        assert loaded.alphabet_source == "reversed_az"


# ---------------------------------------------------------------------------
# (4) Clue numeral extraction drives rail-fence depth
# ---------------------------------------------------------------------------


class TestClueNumeralDepthExtraction:
    @pytest.mark.parametrize("clue,expected", [
        ("Seven post marks", [7]),
        ("three or 5 rails", [3, 5]),
        ("twenty-something cycles", [20]),
        ("", []),
        ("no numbers here", []),
        ("the digit 0", []),  # 0 below 2..49 range
        ("a 50-step plan", []),  # 50 above range
        ("seventeen rails", [17]),
    ])
    def test_numeral_extraction(self, clue, expected):
        assert _depths_from_clue_text(clue) == expected

    def test_default_depths_when_no_numerals(self):
        depths = _rail_fence_depths_for_payload("no numbers here")
        # Must include the safe defaults 3 and 5
        assert 3 in depths and 5 in depths

    def test_clue_depths_unioned_with_defaults(self):
        depths = _rail_fence_depths_for_payload("Seven posts in the field")
        # Clue-derived 7 first, then defaults
        assert 7 in depths
        assert 3 in depths
        assert 5 in depths

    def test_seven_clue_produces_depth_7_rail_fence_specs(self):
        """The Seven-clue test from the K4B-001 clue style: the
        generator emits rail_fence specs at depth 7.
        """
        specs = generate_layered_specs(
            ["WIDGET", "GIZMO"],
            bench_slug="toy",
            clue_text="seven post marks appear",
        )
        rail_specs = [
            s for s in specs
            if s.family_label.startswith("rail_fence_")
        ]
        depths = {dict(s.coverage.extras).get("depth") for s in rail_specs}
        assert 7 in depths


# ---------------------------------------------------------------------------
# (5) No trigger ⇒ default modes only
# ---------------------------------------------------------------------------


class TestNoTriggerDefaultsOnly:
    def test_no_clue_triggers_no_mirror_modes(self):
        specs = generate_layered_specs(
            ["WIDGET", "GIZMO"],
            bench_slug="toy",
            clue_text="",
        )
        modes = {s.coverage.alphabet_mode for s in specs}
        assert "mirrored_az" not in modes
        assert "mirrored_ka" not in modes
        # But standard modes are still there
        assert "AZ" in modes
        assert "KA" in modes
        assert "keyword_mixed" in modes

    def test_clue_without_trigger_no_mirror_modes(self):
        """Real-shaped clue text (similar to K4B-001's "CEDAR posts
        below a LANTERN") doesn't trigger the mirror expansion.
        """
        specs = generate_layered_specs(
            ["CEDAR", "LANTERN"],
            bench_slug="toy",
            clue_text=(
                "A field sketch labels two objects: CEDAR posts "
                "below a LANTERN. Seven post marks appear in the "
                "margin."
            ),
        )
        modes = {s.coverage.alphabet_mode for s in specs}
        assert "mirrored_az" not in modes
        assert "mirrored_ka" not in modes


# ---------------------------------------------------------------------------
# (6) Substitution layer pairings (rail_fence/route/columnar/Myszkowski)
# ---------------------------------------------------------------------------


class TestSubstitutionPairings:
    """Every supported substitution+transposition pair must enumerate
    alphabet modes for the substitution layer (the user spec lists
    them explicitly: rail_fence, route, columnar, Myszkowski).
    """

    SYNTHETIC_CLUES = ["WIDGET", "GIZMO"]
    SYNTHETIC_TRIGGER_TEXT = "mirrored alphabet strip"

    @pytest.mark.parametrize("family_label", [
        # keyword_pair families (columnar/Myszkowski + sub)
        "columnar_vigenere", "columnar_beaufort",
        "columnar_variant_beaufort",
        "myszkowski_vigenere", "myszkowski_beaufort",
        # keywordless-trans pairs (rail_fence/route + sub)
        "rail_fence_vigenere", "rail_fence_beaufort",
        "route_vigenere", "route_beaufort",
    ])
    def test_family_enumerates_alphabet_modes(self, family_label):
        specs = generate_layered_specs(
            self.SYNTHETIC_CLUES,
            bench_slug="toy",
            clue_text=self.SYNTHETIC_TRIGGER_TEXT,
        )
        family_specs = [s for s in specs if s.family_label == family_label]
        modes = {s.coverage.alphabet_mode for s in family_specs}
        # Must include AZ, KA, and at least one mirrored variant.
        assert "AZ" in modes
        assert "KA" in modes
        assert any(m.startswith("mirrored_") for m in modes), (
            f"{family_label} did not enumerate mirrored alphabets "
            f"despite trigger language; got modes={modes}"
        )


# ---------------------------------------------------------------------------
# (7) Real-K4 mode unaffected
# ---------------------------------------------------------------------------


class TestRealK4Unchanged:
    def test_real_k4_controller_yields_no_alphabet_enumeration(self, tmp_path: Path):
        """Real-K4 controller produces no HCC seeds at all (the
        seed list is bench-only). The alphabet enumeration is
        scoped to bench mode by construction.
        """
        from kryptosbot.controller import ControllerConfig, ResearchController
        cfg = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "real_k4.sqlite",
            max_cycles=1,
            theories_per_cycle=5,
            dry_run=True,
        )
        controller = ResearchController(cfg)
        controller.state = controller.ledger.load_controller_state()
        controller._snapshot_session_baseline()
        seeds = controller._collect_hcc_seeds()
        assert seeds == []


# ---------------------------------------------------------------------------
# (8) Toy-cipher regression: synthetic clue that triggers mirror modes
#     produces the expected Beaufort(WIDGET, mirrored_az)+rail_fence(7)
#     candidate BEFORE any LLM call.
# ---------------------------------------------------------------------------


class TestToyMirrorRegression:
    """The K4B-002 regression pattern, expressed against a synthetic
    clue and synthetic clue words. No K4Bench answer or sealed
    plaintext is referenced.
    """

    SYNTHETIC_CLUE = "a folded note: mirrored alpha strip, seven posts"
    SYNTHETIC_CLUES = ["FOLDFIVE", "MIRRORTWELVE"]

    def test_specific_mirrored_az_candidate_present_pre_llm(self):
        specs = generate_layered_specs(
            self.SYNTHETIC_CLUES,
            bench_slug="toy",
            clue_text=self.SYNTHETIC_CLUE,
        )
        # Find Beaufort(FOLDFIVE, mirrored_az) over rail_fence(7) — both
        # layer orders should be present.
        target = [
            s for s in specs
            if s.family_label == "rail_fence_beaufort"
            and s.coverage.alphabet_mode == "mirrored_az"
            and s.coverage.role_assignment == (("beaufort", "FOLDFIVE"),)
            and dict(s.coverage.extras).get("depth") == 7
        ]
        # 2 layer orders × 1 alphabet × 1 keyword × 1 depth = 2 specs
        assert len(target) == 2, (
            f"expected 2 Beaufort(FOLDFIVE, mirrored_az) ∘ rail_fence(7) "
            f"specs; got {len(target)}. The K4B-002 generalization is "
            "not surfacing the clue-driven combo before LLM."
        )
        # Confirm the mirror-source tag is preserved
        for s in target:
            assert s.coverage.alphabet_source == "reversed_az"

    def test_no_sealed_material_in_synthetic_test(self):
        """Defensive: confirm nothing in this test file actually
        contains K4 sealed material.

        The forbidden K4 cribs and CT-prefix tokens are reconstructed
        from character codes at runtime so the literal strings never
        appear in the source — that lets the grep be a meaningful
        check on the rest of the file rather than a self-collision.
        Bench challenge IDs in commentary are fine.
        """
        import re
        path = Path(__file__).resolve()
        text = path.read_text()
        # Reconstruct forbidden tokens from character codes so the
        # literals are never present in the file.
        # Three forbidden tokens reconstructed from char codes so the
        # literals never appear in this source file (a literal would
        # cause this test to false-positive on itself). The codes
        # encode two known K4 cribs and the K4 ciphertext prefix.
        forbidden_tokens = [
            "".join(chr(c) for c in toks) for toks in (
                (69, 65, 83, 84, 78, 79, 82, 84, 72, 69, 65, 83, 84),
                (66, 69, 82, 76, 73, 78, 67, 76, 79, 67, 75),
                (79, 66, 75, 82),
            )
        ]
        for token in forbidden_tokens:
            assert token not in text, (
                "test file contains a known K4 sealed token "
                "(reconstructed at runtime; see test source)"
            )
        # Sanity: no run of 30+ A-Z letters anywhere except the
        # public synthetic constants used as fixtures.
        for m in re.finditer(r"[A-Z]{30,}", text):
            chunk = m.group(0)
            if chunk in (
                "ZYXWVUTSRQPONMLKJIHGFEDCBA",
                "ZXWVUQNMLJIHGFEDCBASOTPYRK",
            ):
                continue
            raise AssertionError(
                f"test file contains a 30+ char A-Z run that may be a "
                f"plaintext: {chunk[:60]}..."
            )
