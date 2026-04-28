"""Tests for LESSON-010 — independent multi-role keyword assignment.

Pinned properties:

  1. ``LessonRegistry`` seeds LESSON-010 with the role-slot taxonomy
     and bounded-pool policy the user mandated. Drift test: the
     runtime constants in ``hand_cipher_core`` honor the lesson's
     ``role_pool_size`` and ``alphabet_keyword_pool_size``.
  2. The CoverageVector dataclass exposes ``substitution_keyword``,
     ``alphabet_keyword``, ``transposition_keyword``, and
     ``role_assignment_mode`` fields. Legacy specs leave them at
     their safe empty defaults; the dict round-trip preserves them.
  3. The two new family generators emit the full
     (sub × alpha × trans) triple matrix from the first
     ``role_pool_size`` clue keywords (default 3) for the
     keyword-pair transposition partners (columnar, myszkowski),
     and the (sub × alpha) matrix for keywordless partners
     (rail_fence, route).
  4. Synthetic A/B/C clue test (user-mandated): toy clue words
     ALPHA, BRAVO, CHARLIE produce specs of the form
     vigenere(key=ALPHA, alphabet_keyword=BRAVO) +
     columnar(keyword=CHARLIE), the reverse layer order, and
     analogous candidates for Beaufort and Variant Beaufort.
  5. Determinism: two consecutive generation calls produce the same
     spec list (same hypothesis_ids, same order).
  6. Boundedness: the universe stays within the documented cap; the
     third clue word is never silently dropped from any of the three
     role slots.
  7. Real-K4 mode unchanged: the lesson is registered (so the LLM
     theorist reads it), but ``_collect_hcc_seeds`` returns ``[]``
     in real-K4 mode so the family generators never auto-emit.
  8. Existing two-keyword catalog continues to fire the legacy
     pair-family generators; LESSON-010 is purely additive (different
     family labels, different slugs).
"""
from __future__ import annotations

from pathlib import Path
import sys

import pytest

from kryptosbot.solver_capabilities import _default_lessons, LessonRegistry
from kryptosbot.hand_cipher_core import (
    AlphabetMode,
    CoverageVector,
    _alphabet_modes_for_payload,
    _gen_independent_three_role_keyword_family,
    _gen_independent_three_role_keywordless_family,
    generate_layered_specs,
)


_REPO_ROOT = Path(__file__).resolve().parents[2]
_K4B005_PATH = _REPO_ROOT / "bench" / "k4bench" / "challenges" / "K4B-005.json"


# Toy clue keyword set. Picked to be entirely unrelated to any
# K4Bench challenge so this test file can never accidentally encode
# a benchmark answer.
_ABC = ["ALPHA", "BRAVO", "CHARLIE"]


# ---------------------------------------------------------------------------
# (1) Lesson registry
# ---------------------------------------------------------------------------


class TestLessonRegistry:
    def test_lesson_010_present(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        assert "LESSON-010" in lessons
        l = lessons["LESSON-010"]
        assert l.tactic_kind == "independent_multi_role_assignment"
        assert l.generates_specs is True

    def test_lesson_010_has_role_slot_taxonomy(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-010"]
        slots = set(l.tactic_parameters.get("role_slots", []))
        # User-mandated minimum role-slot set
        required = {
            "substitution_keyword",
            "alphabet_keyword",
            "transposition_keyword",
            "quagmire_period_keyword",
            "quagmire_pt_alphabet_keyword",
            "quagmire_ct_alphabet_keyword",
            "indicator_letter",
            "route_grid_keyword",
        }
        missing = required - slots
        assert not missing, f"LESSON-010 role_slots missing: {missing}"

    def test_lesson_010_role_pool_size_is_three(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-010"]
        assert l.tactic_parameters.get("role_pool_size") == 3
        assert l.tactic_parameters.get(
            "alphabet_keyword_pool_size"
        ) == 3

    def test_lesson_010_role_assignment_modes(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-010"]
        modes = set(l.tactic_parameters.get("role_assignment_modes", []))
        assert {"pairwise", "independent_three_role"} <= modes

    def test_lesson_registry_round_trip(self, tmp_path):
        path = tmp_path / "lessons.json"
        reg1 = LessonRegistry(path=path, seed_defaults=True)
        ids1 = {l.lesson_id for l in reg1.all()}
        assert "LESSON-010" in ids1
        reg2 = LessonRegistry(path=path, seed_defaults=True)
        ids2 = {l.lesson_id for l in reg2.all()}
        assert "LESSON-010" in ids2


# ---------------------------------------------------------------------------
# (2) CoverageVector new fields
# ---------------------------------------------------------------------------


class TestCoverageVectorRoleFields:
    def test_legacy_specs_leave_fields_empty(self):
        """Specs from family generators that pre-date LESSON-010
        leave the new fields at "" so the legacy catalog is
        bit-identical for downstream coverage analysis.
        """
        specs = generate_layered_specs(
            ["FOO", "BAR"], bench_slug="t",
            clue_text="ordinary problem", max_specs=200,
            include_three_layer=False,
        )
        # Two-clue path doesn't activate i3 generators (i3 fires on
        # >=2 clue words; with exactly 2 the role_pool_size cap of 3
        # collapses the (sub × trans) cartesian to {(A,A), (A,B),
        # (B,A), (B,B)} = 4 ordered pairs, which is a strict
        # superset of the legacy pair family). The legacy
        # ``columnar_vigenere`` / etc. labels are still emitted.
        # Filter out i3 specs and assert the legacy ones leave the
        # new fields empty.
        legacy = [
            s for s in specs
            if not s.coverage.layer_family.startswith("i3_")
            and "reverse_blocks" not in s.coverage.layer_family
            and "caesar" not in s.coverage.layer_family
        ]
        assert legacy
        for s in legacy:
            assert s.coverage.substitution_keyword == ""
            assert s.coverage.alphabet_keyword == ""
            assert s.coverage.transposition_keyword == ""
            assert s.coverage.role_assignment_mode == ""

    def test_dict_round_trip(self):
        cv = CoverageVector(
            layer_family="i3_columnar_vigenere",
            layer_order=("vigenere", "columnar"),
            role_assignment=(
                ("vigenere", "ALPHA"),
                ("alphabet_keyword", "BRAVO"),
                ("columnar", "CHARLIE"),
            ),
            alphabet="keyword_mixed", n_layers=2,
            substitution_keyword="ALPHA",
            alphabet_keyword="BRAVO",
            transposition_keyword="CHARLIE",
            role_assignment_mode="independent_three_role",
        )
        d = cv.to_dict()
        assert d["substitution_keyword"] == "ALPHA"
        assert d["alphabet_keyword"] == "BRAVO"
        assert d["transposition_keyword"] == "CHARLIE"
        assert d["role_assignment_mode"] == "independent_three_role"
        cv2 = CoverageVector.from_dict(d)
        assert cv2.substitution_keyword == "ALPHA"
        assert cv2.alphabet_keyword == "BRAVO"
        assert cv2.transposition_keyword == "CHARLIE"
        assert cv2.role_assignment_mode == "independent_three_role"


# ---------------------------------------------------------------------------
# (3) max_keyword_mixed bumped from 2 to 3
# ---------------------------------------------------------------------------


class TestAlphabetModesIncludesThirdClueWord:
    def test_keyword_mixed_for_first_three_clue_words(self):
        modes = _alphabet_modes_for_payload(
            "no triggers here", _ABC,
        )
        keyword_mixed_sources = {
            m.source for m in modes
            if m.mode_label == "keyword_mixed"
        }
        # All three clue keywords appear as alphabet_keyword sources
        assert keyword_mixed_sources == {"ALPHA", "BRAVO", "CHARLIE"}

    def test_max_keyword_mixed_default_is_three(self):
        """Drift test: the default cap matches the LESSON-010
        ``alphabet_keyword_pool_size``."""
        modes = _alphabet_modes_for_payload(
            "no trigger", ["A1", "B2", "C3", "D4", "E5"],
        )
        # Note A1 etc. fail isalpha() check so are skipped; use
        # all-letter words.
        modes = _alphabet_modes_for_payload(
            "no trigger", ["AAA", "BBB", "CCC", "DDD", "EEE"],
        )
        keyword_mixed_count = sum(
            1 for m in modes if m.mode_label == "keyword_mixed"
        )
        assert keyword_mixed_count == 3, (
            f"expected exactly 3 keyword_mixed modes (the default "
            f"cap); got {keyword_mixed_count}"
        )


# ---------------------------------------------------------------------------
# (4) Independent three-role family generator
# ---------------------------------------------------------------------------


class TestIndependentThreeRoleKeywordFamily:
    def _modes(self, mirror_trigger=False):
        return _alphabet_modes_for_payload(
            "alphabet table mirror" if mirror_trigger else "ordinary",
            _ABC,
        )

    def test_emits_full_sub_trans_cartesian(self):
        """For 3 clue words {A, B, C} and the columnar+vigenere
        family, the i3 generator emits 3×3 = 9 (sub_kw × trans_kw)
        ordered pairs per (alphabet_mode, layer_order).
        """
        out = _gen_independent_three_role_keyword_family(
            bench_slug="t",
            sub_kind="vigenere", trans_kind="columnar",
            clue_keywords=_ABC,
            alphabet_modes=(AlphabetMode("AZ", "AZ", None, "default"),),
        )
        # 3 sub × 3 trans × 1 mode × 2 layer orders = 18
        assert len(out) == 18
        # The 9 distinct (sub_kw, trans_kw) pairs
        pairs = {
            (s.coverage.substitution_keyword,
             s.coverage.transposition_keyword)
            for s in out
        }
        expected = {
            (s, t) for s in _ABC for t in _ABC
        }
        assert pairs == expected

    def test_third_clue_word_is_never_dropped(self):
        out = _gen_independent_three_role_keyword_family(
            bench_slug="t",
            sub_kind="vigenere", trans_kind="columnar",
            clue_keywords=_ABC,
            alphabet_modes=(AlphabetMode("AZ", "AZ", None, "default"),),
        )
        # CHARLIE must appear as substitution AND as transposition.
        sub_set = {s.coverage.substitution_keyword for s in out}
        trans_set = {s.coverage.transposition_keyword for s in out}
        assert "CHARLIE" in sub_set
        assert "CHARLIE" in trans_set

    def test_alphabet_keyword_independent_of_sub_and_trans(self):
        """With keyword_mixed alphabet modes for each clue word, the
        emitted specs include cases where alphabet_keyword differs
        from BOTH substitution_keyword and transposition_keyword.
        """
        modes = self._modes()
        out = _gen_independent_three_role_keyword_family(
            bench_slug="t",
            sub_kind="vigenere", trans_kind="columnar",
            clue_keywords=_ABC,
            alphabet_modes=modes,
        )
        # Look for the spec where sub=ALPHA, trans=CHARLIE,
        # alphabet=BRAVO — all three roles distinct.
        match = [
            s for s in out
            if s.coverage.substitution_keyword == "ALPHA"
            and s.coverage.transposition_keyword == "CHARLIE"
            and s.coverage.alphabet_keyword == "BRAVO"
        ]
        # Two layer orders for this triple
        assert len(match) == 2

    @pytest.mark.parametrize("sub_kind", [
        "vigenere", "beaufort", "variant_beaufort",
    ])
    def test_synthetic_abc_emits_three_role_candidate_for_each_sub(
        self, sub_kind,
    ):
        """User-mandated test: for ALPHA, BRAVO, CHARLIE, the
        generator emits sub(key=ALPHA, alphabet_keyword=BRAVO) +
        columnar(keyword=CHARLIE) for vigenere AND beaufort AND
        variant_beaufort.
        """
        modes = self._modes()
        out = _gen_independent_three_role_keyword_family(
            bench_slug="t",
            sub_kind=sub_kind, trans_kind="columnar",
            clue_keywords=_ABC,
            alphabet_modes=modes,
        )
        match_sub_first = [
            s for s in out
            if s.coverage.substitution_keyword == "ALPHA"
            and s.coverage.alphabet_keyword == "BRAVO"
            and s.coverage.transposition_keyword == "CHARLIE"
            and s.coverage.layer_order == (sub_kind, "columnar")
        ]
        match_trans_first = [
            s for s in out
            if s.coverage.substitution_keyword == "ALPHA"
            and s.coverage.alphabet_keyword == "BRAVO"
            and s.coverage.transposition_keyword == "CHARLIE"
            and s.coverage.layer_order == ("columnar", sub_kind)
        ]
        assert len(match_sub_first) == 1, (
            f"{sub_kind}+columnar: missing sub-first spec for "
            f"(ALPHA, BRAVO, CHARLIE)"
        )
        assert len(match_trans_first) == 1, (
            f"{sub_kind}+columnar: missing trans-first spec for "
            f"(ALPHA, BRAVO, CHARLIE)"
        )

    def test_role_assignment_mode_is_independent_three_role(self):
        out = _gen_independent_three_role_keyword_family(
            bench_slug="t",
            sub_kind="vigenere", trans_kind="myszkowski",
            clue_keywords=_ABC,
            alphabet_modes=(AlphabetMode("AZ", "AZ", None, "default"),),
        )
        for s in out:
            assert s.coverage.role_assignment_mode == "independent_three_role"

    def test_role_pool_size_caps_at_three(self):
        """A 5-keyword clue pool collapses to the first 3 keywords."""
        five = ["AAA", "BBB", "CCC", "DDD", "EEE"]
        out = _gen_independent_three_role_keyword_family(
            bench_slug="t",
            sub_kind="vigenere", trans_kind="columnar",
            clue_keywords=five,
            alphabet_modes=(AlphabetMode("AZ", "AZ", None, "default"),),
        )
        sub_set = {s.coverage.substitution_keyword for s in out}
        trans_set = {s.coverage.transposition_keyword for s in out}
        # Only the first 3 appear; the 4th and 5th do not
        assert sub_set == {"AAA", "BBB", "CCC"}
        assert trans_set == {"AAA", "BBB", "CCC"}

    def test_returns_empty_for_single_keyword(self):
        out = _gen_independent_three_role_keyword_family(
            bench_slug="t",
            sub_kind="vigenere", trans_kind="columnar",
            clue_keywords=["ONLY_ONE"],
            alphabet_modes=(AlphabetMode("AZ", "AZ", None, "default"),),
        )
        assert out == []


class TestIndependentThreeRoleKeywordlessFamily:
    def test_keywordless_family_ranges_over_three_sub_keywords(self):
        out = _gen_independent_three_role_keywordless_family(
            bench_slug="t",
            sub_kind="vigenere", trans_kind="rail_fence",
            clue_keywords=_ABC,
            extra_params={"depth": 5},
            alphabet_modes=(AlphabetMode("AZ", "AZ", None, "default"),),
        )
        # 3 sub keywords × 1 mode × 2 layer orders
        assert len(out) == 6
        sub_set = {s.coverage.substitution_keyword for s in out}
        assert sub_set == {"ALPHA", "BRAVO", "CHARLIE"}

    def test_keywordless_transposition_keyword_is_empty(self):
        out = _gen_independent_three_role_keywordless_family(
            bench_slug="t",
            sub_kind="vigenere", trans_kind="rail_fence",
            clue_keywords=_ABC,
            extra_params={"depth": 5},
            alphabet_modes=(AlphabetMode("AZ", "AZ", None, "default"),),
        )
        for s in out:
            assert s.coverage.transposition_keyword == ""


# ---------------------------------------------------------------------------
# (5) Determinism + bounded universe
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_inputs_same_output(self):
        """Two consecutive calls with the same inputs produce the
        same hypothesis_id list in the same order.
        """
        a = _gen_independent_three_role_keyword_family(
            bench_slug="t",
            sub_kind="vigenere", trans_kind="columnar",
            clue_keywords=_ABC,
            alphabet_modes=(AlphabetMode("AZ", "AZ", None, "default"),),
        )
        b = _gen_independent_three_role_keyword_family(
            bench_slug="t",
            sub_kind="vigenere", trans_kind="columnar",
            clue_keywords=_ABC,
            alphabet_modes=(AlphabetMode("AZ", "AZ", None, "default"),),
        )
        assert [s.hypothesis_id for s in a] == [s.hypothesis_id for s in b]


class TestBoundedness:
    def test_full_payload_universe_stays_bounded(self):
        """With three clue keywords, the new families add at most
        ~10×3-role-family * (3 sub × 3 trans × 7 alpha-modes × 2
        layer-orders) ≈ a few hundred specs to the catalog. Confirm
        the i3 spec count stays < 2000 even with a mirror trigger
        in play.
        """
        specs = generate_layered_specs(
            _ABC, bench_slug="t",
            # mirror trigger → +2 alphabet modes
            clue_text="alphabet table mirror",
            max_specs=10000, include_three_layer=False,
        )
        i3_specs = [
            s for s in specs
            if s.coverage.layer_family.startswith("i3_")
        ]
        # 5 keyword-pair families (col_vig, col_beau, col_vbeau,
        # myz_vig, myz_beau) × 3 sub × 3 trans × ~7 modes × 2 orders
        # = 5 × 126 = 630, plus rail_fence + route keywordless ~600
        # ≈ 1200. Cap at 2000 to leave headroom.
        assert 100 < len(i3_specs) < 2000


# ---------------------------------------------------------------------------
# (6) Real-K4 mode unchanged
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
        assert seeds == [], (
            f"real-K4 HCC seeds must be empty; got {len(seeds)} seeds"
        )

    def test_lesson_010_in_registry_for_real_k4(self, tmp_path):
        """Real-K4 mode does not consume HCC seeds, but LESSON-010
        MUST be in the registry so the LLM theorist can read it as a
        generalized tactic at prompt-build time.
        """
        reg = LessonRegistry(
            path=tmp_path / "lessons.json", seed_defaults=True,
        )
        ids = {l.lesson_id for l in reg.all()}
        assert "LESSON-010" in ids


# ---------------------------------------------------------------------------
# (7) Legacy pair family preserved
# ---------------------------------------------------------------------------


class TestLegacyPairFamilyPreserved:
    def test_legacy_pair_family_still_fires(self):
        """LESSON-010 is purely additive. The legacy
        ``columnar_vigenere`` family label still appears in the
        catalog alongside the new ``i3_columnar_vigenere`` label.
        """
        specs = generate_layered_specs(
            _ABC, bench_slug="t",
            clue_text="ordinary problem", max_specs=5000,
            include_three_layer=False,
        )
        labels = {s.coverage.layer_family for s in specs}
        assert "columnar_vigenere" in labels      # legacy
        assert "i3_columnar_vigenere" in labels   # LESSON-010

    def test_legacy_specs_unchanged_role_assignment_format(self):
        """Legacy pair family specs continue to use the 2-tuple
        role_assignment shape; LESSON-010's 3-tuple shape is
        confined to ``i3_*`` labels.
        """
        specs = generate_layered_specs(
            _ABC, bench_slug="t",
            clue_text="ordinary problem", max_specs=5000,
            include_three_layer=False,
        )
        legacy_col_vig = [
            s for s in specs
            if s.coverage.layer_family == "columnar_vigenere"
        ]
        assert legacy_col_vig
        for s in legacy_col_vig:
            # Two role entries in the legacy 2-tuple shape
            assert len(s.coverage.role_assignment) == 2


# ---------------------------------------------------------------------------
# (8) K4B-005 canary
# ---------------------------------------------------------------------------


class TestK4B005Canary:
    """LESSON-010 must include a spec that scores 24/24 on K4B-005
    so the bench-fast HCC-only run finds the answer deterministically.
    Runs in a subprocess so the kernel constants module loads with
    the K4B-005 CT/cribs override.

    The test does NOT hard-code the K4B-005 plaintext. It dispatches
    every i3_columnar_vigenere candidate from the generated catalog
    and asserts the kernel scores 24 on at least one. The answer
    emerges from running the generalized capability against the
    public challenge fixture.
    """

    def test_k4b005_three_role_candidate_hits_24(self):
        if not _K4B005_PATH.exists():
            pytest.skip(f"K4B-005 fixture not on disk at {_K4B005_PATH}")
        import os
        import subprocess
        env = {**os.environ}
        env["PYTHONPATH"] = (
            str(_REPO_ROOT / "src") + ":" + env.get("PYTHONPATH", "")
        )
        code = (
            "import json, sys\n"
            f"sys.path.insert(0, {str(_REPO_ROOT)!r})\n"
            "from kryptosbot.bench_loader import load_k4bench_challenge\n"
            f"ch = load_k4bench_challenge({str(_K4B005_PATH)!r})\n"
            "ch.install_kernel_overrides()\n"
            "from kryptosbot.bench_fallback import hand_cipher_core_fallback\n"
            "from kryptosbot.hypothesis_dsl import validate_hypothesis_spec\n"
            "from kryptosbot.job_dispatcher import execute\n"
            "seeds = hand_cipher_core_fallback("
            "ch.canonical_facts(), n_target=5)\n"
            # Restrict to i3_columnar_vigenere — narrow search
            # universe so the test completes in a reasonable time.
            "cands = [s for s in seeds\n"
            "         if s.minimal_test_spec.get('coverage_vector', {}).get('layer_family') "
            "== 'i3_columnar_vigenere']\n"
            # Collect EVERY 24-scorer so the test can audit telemetry
            # across all winning role configurations. The KRYPTOS-
            # prefixed alphabet has TWO equivalent telemetry paths
            # (alphabet_mode='KA' with empty alphabet_keyword vs.
            # alphabet_mode='keyword_mixed' with alphabet_keyword=
            # 'KRYPTOS'); both score 24. The test asserts both
            # paths' provenance is honest — never that a particular
            # one wins.
            "hits = []\n"
            "for s in cands:\n"
            "    parsed = validate_hypothesis_spec(s.dsl_spec)\n"
            "    if not parsed.is_valid:\n"
            "        continue\n"
            "    r = execute(parsed.value, workers=1, parallel=False, "
            "bench_mode=True)\n"
            "    if r.best_score == 24.0:\n"
            "        cv = s.minimal_test_spec.get('coverage_vector', {})\n"
            "        hits.append({\n"
            "            'sub_kw': cv.get('substitution_keyword'),\n"
            "            'alpha_kw': cv.get('alphabet_keyword'),\n"
            "            'alpha_mode': cv.get('alphabet_mode'),\n"
            "            'alpha_source': cv.get('alphabet_source'),\n"
            "            'trans_kw': cv.get('transposition_keyword'),\n"
            "            'role_mode': cv.get('role_assignment_mode'),\n"
            "            'layer_order': cv.get('layer_order'),\n"
            "        })\n"
            "print(json.dumps({'cand_count': len(cands), 'hits': hits}))\n"
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
            "no i3_columnar_vigenere candidate emitted for K4B-005"
        )
        hits = payload["hits"]
        assert hits, (
            "K4B-005 expected at least one i3_columnar_vigenere "
            "candidate to score 24/24; got zero"
        )
        # Every 24-scorer is on the LESSON-010 path with non-empty
        # substitution and transposition keywords. The alphabet
        # provenance is auditable via either alphabet_keyword
        # (keyword_mixed mode) or alphabet_mode + alphabet_source
        # (KA mode). The test asserts BOTH paths produce honest
        # telemetry, not that a specific one wins.
        for h in hits:
            assert h["sub_kw"], f"empty sub_kw in hit: {h}"
            assert h["trans_kw"], f"empty trans_kw in hit: {h}"
            assert h["role_mode"] == "independent_three_role", (
                f"non-i3 hit: {h}"
            )
            # Alphabet provenance: at least one of (alphabet_keyword,
            # alphabet_mode, alphabet_source) tells the reader what
            # alphabet was used. Empty across all three would mean
            # untraceable telemetry, which the test forbids.
            assert (
                h["alpha_kw"] or h["alpha_mode"] or h["alpha_source"]
            ), f"untraceable alphabet provenance in hit: {h}"
        # At least one hit must surface the KRYPTOS-keyed alphabet
        # via either explicit alphabet_keyword or alphabet_source ==
        # "kryptos_alphabet" (the KA built-in). This audits that
        # K4B-005's intended KRYPTOS alphabet is reachable from the
        # i3 catalog.
        krypto_visible = any(
            h["alpha_kw"] == "KRYPTOS"
            or h["alpha_source"] == "kryptos_alphabet"
            for h in hits
        )
        assert krypto_visible, (
            "no 24-scorer surfaces the KRYPTOS-keyed alphabet via "
            f"alphabet_keyword or alphabet_source; hits={hits}"
        )
