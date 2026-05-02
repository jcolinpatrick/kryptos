"""Tests for the CT-perturbation Stage-A campaign.

Covers:
    1. Hamming-1 enumerator correctness, count, determinism, IDs
    2. Universe cardinality manifest matches enumerator
    3. CT-parametric scoring uses the variant CT, not canonical CT
    4. CLI dry-run / smoke-flag behaviour
    5. Synthetic recovery
    6. Scope exclusion (no running-key, no corpus, no out-of-scope CLI)
    7. Artifact validity (JSON parses, JSONL parses, required fields)
"""
from __future__ import annotations

import ast
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Set

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


from kryptos.kernel.constants import (
    CRIB_DICT as CANONICAL_CRIB_DICT,
    CT as CANONICAL_CT,
    BEAN_EQ as CANONICAL_BEAN_EQ,
    BEAN_INEQ as CANONICAL_BEAN_INEQ,
    BEAN_LINEAR as CANONICAL_BEAN_LINEAR,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, encrypt_text,
)
from kryptos.kernel.alphabet import AZ as _AZ_ALPHA, KA as _KA_ALPHA

from kryptosbot.ct_perturbation import (
    CRIB_POSITION_H1_VARIANTS,
    NONCRIB_POSITION_H1_VARIANTS,
    AlertPolicy,
    CTVariant,
    CandidateScore,
    ScorerContext,
    SUPPORTED_ALPHABET_KINDS,
    SUPPORTED_FAMILIES,
    UniverseDimensions,
    assert_canonical_bean_reproduction,
    bonferroni_adjust,
    canonical_variant,
    classify_alert,
    crib_p_value_random,
    crib_score_for_pt,
    ct_variant_position_class_counts,
    decrypt_with_keyword,
    derive_bean_constraints,
    enumerate_hamming1_variants,
    fisher_combine,
    recover_keystream_at_cribs,
    score_candidate_ct_parametric,
    verify_bean_against_keystream,
)


def load_stage_a_runner_module():
    path = REPO_ROOT / "scripts" / "campaigns" / "ct_perturbation_stage_a.py"
    spec = importlib.util.spec_from_file_location("ct_perturbation_stage_a_test_mod", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


# ── 1. Hamming-1 enumeration ────────────────────────────────────────────

class TestHamming1Enumeration:
    def test_count_is_2425_for_canonical_ct(self):
        variants = list(enumerate_hamming1_variants(CANONICAL_CT))
        assert len(variants) == 97 * 25
        assert len(variants) == 2425

    def test_every_variant_differs_in_exactly_one_position(self):
        for v in enumerate_hamming1_variants(CANONICAL_CT):
            diffs = sum(1 for a, b in zip(CANONICAL_CT, v.ct) if a != b)
            assert diffs == 1, f"variant {v.variant_id} has {diffs} diffs"
            assert v.distance == 1

    def test_no_replacement_equals_original(self):
        for v in enumerate_hamming1_variants(CANONICAL_CT):
            assert v.old_char != v.new_char
            assert CANONICAL_CT[v.pos] == v.old_char
            assert v.ct[v.pos] == v.new_char

    def test_deterministic_order(self):
        """Position ascending, replacement ascending excluding original."""
        variants = list(enumerate_hamming1_variants(CANONICAL_CT))
        # Check first chunk: position 0, replacement A,B,C... excluding O
        first_25 = variants[:25]
        assert all(v.pos == 0 for v in first_25)
        replacements = [v.new_char for v in first_25]
        # Original at position 0 is 'O'
        assert "O" not in replacements
        assert replacements == sorted(replacements)
        # Position 1 starts at index 25
        assert variants[25].pos == 1

    def test_stable_variant_ids(self):
        v0 = list(enumerate_hamming1_variants(CANONICAL_CT))[0]
        # H1_p00_O->A
        assert v0.variant_id.startswith("H1_p")
        assert "->" in v0.variant_id
        # SHA changes per variant.
        v1 = list(enumerate_hamming1_variants(CANONICAL_CT))[1]
        assert v0.ct_sha256 != v1.ct_sha256

    def test_canonical_baseline(self):
        v = canonical_variant(CANONICAL_CT)
        assert v.distance == 0
        assert v.pos is None
        assert v.old_char is None
        assert v.new_char is None
        assert v.ct == CANONICAL_CT
        assert v.variant_id == "H0_canonical"

    def test_position_class_counts_full_h1_plus_h0(self):
        counts = ct_variant_position_class_counts(include_h0=True, h1_variants=2425)
        assert counts["h0_baseline"] == 1
        assert counts["crib_position_h1_variants"] == 24 * 25
        assert counts["crib_position_h1_variants"] == CRIB_POSITION_H1_VARIANTS
        assert counts["noncrib_position_h1_variants"] == 73 * 25
        assert counts["noncrib_position_h1_variants"] == NONCRIB_POSITION_H1_VARIANTS
        assert counts["total_ct_variants"] == 2426

    def test_position_class_counts_respect_h1_only_cap(self):
        # Position 0 is non-crib, so the first two H1 variants are
        # non-crib perturbations. H0, if included, is counted separately.
        counts = ct_variant_position_class_counts(include_h0=True, h1_variants=2)
        assert counts["h0_baseline"] == 1
        assert counts["crib_position_h1_variants"] == 0
        assert counts["noncrib_position_h1_variants"] == 2
        assert counts["total_ct_variants"] == 3

    def test_validation_rejects_wrong_length(self):
        with pytest.raises(ValueError):
            list(enumerate_hamming1_variants("ABCDE"))
        with pytest.raises(ValueError):
            canonical_variant("ABCDE")

    def test_validation_rejects_lowercase(self):
        bad = ("abcdefghij" * 10)[:97]
        assert len(bad) == 97
        with pytest.raises(ValueError):
            canonical_variant(bad)


# ── 2. Cardinality manifest ─────────────────────────────────────────────

class TestUniverseCardinality:
    def test_arithmetic_matches_enumerator(self):
        keywords = 100  # arbitrary
        u = UniverseDimensions(
            families=len(SUPPORTED_FAMILIES),
            alphabet_kinds=len(SUPPORTED_ALPHABET_KINDS),
            keywords=keywords,
            ct_variants=2425,
        )
        # 3 × 2 × 100 = 600 per CT variant
        assert u.per_ct_variant == 600
        assert u.total == 600 * 2425

    def test_period_is_not_an_independent_dimension(self):
        u = UniverseDimensions(
            families=3, alphabet_kinds=2, keywords=719, ct_variants=2425,
        )
        d = u.to_dict()
        assert d["period_policy"] == "period_equals_keyword_length"
        assert "period_note" in d
        assert "no independent period" in d["period_note"].lower()

    def test_total_smaller_than_naive_378M(self):
        """If we naively claimed 26 independent periods, total would be
        ~378M. Actual without periods is 2425 × 3 × 2 × keywords."""
        u = UniverseDimensions(
            families=3, alphabet_kinds=2, keywords=1000, ct_variants=2425,
        )
        assert u.total == 14_550_000
        naive_with_period_dim = u.total * 26
        assert naive_with_period_dim != u.total
        assert naive_with_period_dim == 378_300_000


# ── 3. CT-parametric scoring ────────────────────────────────────────────

class TestCTParametricScoring:
    def test_canonical_bean_reproduction(self):
        eq, ineq, linear = derive_bean_constraints(
            CANONICAL_CT, dict(CANONICAL_CRIB_DICT),
        )
        assert tuple(eq) == tuple(CANONICAL_BEAN_EQ)
        assert tuple(ineq) == tuple(CANONICAL_BEAN_INEQ)
        assert tuple(linear) == tuple(CANONICAL_BEAN_LINEAR)

    def test_ka_bean_constraints_are_alphabet_parametric(self):
        az_constraints = derive_bean_constraints(
            CANONICAL_CT, dict(CANONICAL_CRIB_DICT), alphabet=_AZ_ALPHA,
        )
        ka_constraints = derive_bean_constraints(
            CANONICAL_CT, dict(CANONICAL_CRIB_DICT), alphabet=_KA_ALPHA,
        )
        assert az_constraints != ka_constraints
        assert [len(x) for x in az_constraints] == [1, 242, 101]
        assert [len(x) for x in ka_constraints] == [1, 254, 92]

    def test_assert_helper(self):
        # Should not raise.
        assert_canonical_bean_reproduction()

    def test_perturbation_at_non_crib_pos_preserves_bean(self):
        """A perturbation at a non-crib position MUST yield identical
        Bean constraints — because Bean only inspects (CT, PT) at crib
        positions. This is an important invariant of the campaign:
        most H1 variants share canonical Bean structure."""
        non_crib_pos = 0  # outside crib spans (21-33, 63-73)
        assert non_crib_pos not in CANONICAL_CRIB_DICT
        perturbed = "Z" + CANONICAL_CT[1:]
        assert perturbed != CANONICAL_CT
        eq, ineq, linear = derive_bean_constraints(
            perturbed, dict(CANONICAL_CRIB_DICT),
        )
        assert tuple(eq) == tuple(CANONICAL_BEAN_EQ)
        assert tuple(ineq) == tuple(CANONICAL_BEAN_INEQ)
        assert tuple(linear) == tuple(CANONICAL_BEAN_LINEAR)

    def test_perturbation_at_crib_pos_changes_bean(self):
        """A perturbation at a crib position MUST change Bean. This is
        the regression test: if scoring used canonical Bean by accident,
        the H1-at-crib-position variants would silently pass with wrong
        constraints."""
        crib_pos = 27  # k[27] = k[65] is the canonical equality
        assert crib_pos in CANONICAL_CRIB_DICT
        old = CANONICAL_CT[crib_pos]
        new = "A" if old != "A" else "B"
        perturbed = CANONICAL_CT[:crib_pos] + new + CANONICAL_CT[crib_pos + 1:]
        eq_canon, ineq_canon, _ = derive_bean_constraints(
            CANONICAL_CT, dict(CANONICAL_CRIB_DICT),
        )
        eq_pert, ineq_pert, _ = derive_bean_constraints(
            perturbed, dict(CANONICAL_CRIB_DICT),
        )
        # At least one of (eq, ineq) must differ for some pair touching pos 27.
        eq_changed = set(eq_canon) != set(eq_pert)
        ineq_changed = set(ineq_canon) != set(ineq_pert)
        assert eq_changed or ineq_changed, (
            "Bean derivation did not change after crib-position perturbation; "
            "scoring may be using canonical CT silently"
        )

    def test_score_candidate_uses_variant_ct(self):
        """The full scorer on a perturbed CT must produce different
        keystream / Bean than canonical CT."""
        # Build a synthetic case where a perturbation at a crib position
        # makes Bean PASS for a contrived keyword that fails on canonical.
        # We use a very direct construction: pick a keyword, encrypt a
        # known plaintext under it, then test that the original synthetic
        # CT (which by construction has Bean PASS) recovers correctly,
        # and that a Hamming-1 perturbation at a non-crib position
        # yields the same Bean-PASS state but at a crib position breaks
        # it.
        pt = ("X" * 21 + "EASTNORTHEAST" + "Y" * 29 + "BERLINCLOCK"
              + "Z" * (97 - 74))
        assert len(pt) == 97
        keyword = "PALIMPSEST"
        key = _AZ_ALPHA.encode(keyword)
        true_ct = encrypt_text(pt, key, variant=CipherVariant.VIGENERE,
                                alphabet=_AZ_ALPHA)
        v0 = canonical_variant(true_ct)
        ctx = ScorerContext.build(v0, dict(CANONICAL_CRIB_DICT))
        score, recovered_pt = score_candidate_ct_parametric(
            ctx, keyword=keyword, family=CipherVariant.VIGENERE,
            alphabet_kind="AZ", universe_size=1,
            policy=AlertPolicy(require_null_for_alert=False),
        )
        assert recovered_pt == pt
        assert score.crib_score == 24
        assert score.bean_passed

        # Now perturb at a crib position; cribs should miss exactly one,
        # which is the test that crib_score uses the recovered PT, and
        # the Bean derivation reflects the new CT.
        crib_pos = 21  # E in EASTNORTHEAST
        new_char = "Q" if true_ct[crib_pos] != "Q" else "R"
        bad_ct = true_ct[:crib_pos] + new_char + true_ct[crib_pos + 1:]
        v_bad = CTVariant(
            variant_id="test_bad", distance=1, pos=crib_pos,
            old_char=true_ct[crib_pos], new_char=new_char, ct=bad_ct,
            ct_sha256="test_sha",
        )
        ctx2 = ScorerContext.build(v_bad, dict(CANONICAL_CRIB_DICT))
        score2, recovered_pt2 = score_candidate_ct_parametric(
            ctx2, keyword=keyword, family=CipherVariant.VIGENERE,
            alphabet_kind="AZ", universe_size=1,
            policy=AlertPolicy(require_null_for_alert=False),
        )
        # Cribs must drop by 1.
        assert score2.crib_score == 23
        # The PT at crib_pos changes from 'E' to something else.
        assert recovered_pt2[crib_pos] != "E"

    def test_score_candidate_rejects_context_alphabet_mismatch(self):
        v = canonical_variant(CANONICAL_CT)
        ctx = ScorerContext.build(v, alphabet_kind="AZ")
        with pytest.raises(ValueError):
            score_candidate_ct_parametric(
                ctx, keyword="KRYPTOS", family=CipherVariant.VIGENERE,
                alphabet_kind="KA", universe_size=1,
                policy=AlertPolicy(require_null_for_alert=False),
            )

    def test_ka_candidate_uses_ka_bean_context(self):
        pt = ("X" * 21 + "EASTNORTHEAST" + "Y" * 29 + "BERLINCLOCK"
              + "Z" * (97 - 74))
        keyword = "PALIMPSEST"
        key = _KA_ALPHA.encode(keyword)
        true_ct = encrypt_text(pt, key, variant=CipherVariant.VIGENERE,
                               alphabet=_KA_ALPHA)
        v0 = canonical_variant(true_ct)
        ctx = ScorerContext.build(v0, dict(CANONICAL_CRIB_DICT), alphabet_kind="KA")
        score, recovered_pt = score_candidate_ct_parametric(
            ctx, keyword=keyword, family=CipherVariant.VIGENERE,
            alphabet_kind="KA", universe_size=1,
            policy=AlertPolicy(require_null_for_alert=False),
        )
        assert recovered_pt == pt
        assert score.crib_score == 24
        assert score.bean_passed

    def test_recover_keystream_uses_variant_ct(self):
        """recover_keystream_at_cribs must produce different keystream
        when CT changes at a crib position."""
        crib_pos = 21
        canonical_ct_local = CANONICAL_CT
        # Build a candidate PT that matches cribs (so PT[crib_pos] = 'E')
        candidate_pt = list("X" * 97)
        candidate_pt[21:34] = list("EASTNORTHEAST")
        candidate_pt[63:74] = list("BERLINCLOCK")
        pt = "".join(candidate_pt)

        ks_canonical = recover_keystream_at_cribs(
            canonical_ct_local, pt, family=CipherVariant.VIGENERE,
            alphabet=_AZ_ALPHA, crib_positions=sorted(CANONICAL_CRIB_DICT.keys()),
        )
        new_char = "A" if canonical_ct_local[crib_pos] != "A" else "B"
        perturbed_ct = (canonical_ct_local[:crib_pos] + new_char
                        + canonical_ct_local[crib_pos + 1:])
        ks_perturbed = recover_keystream_at_cribs(
            perturbed_ct, pt, family=CipherVariant.VIGENERE,
            alphabet=_AZ_ALPHA, crib_positions=sorted(CANONICAL_CRIB_DICT.keys()),
        )
        # The keystream value AT crib_pos differs.
        assert ks_canonical[crib_pos] != ks_perturbed[crib_pos]
        # All other crib positions are unchanged.
        for pos in CANONICAL_CRIB_DICT:
            if pos != crib_pos:
                assert ks_canonical[pos] == ks_perturbed[pos]

    def test_no_global_ct_mutation(self):
        """Running the full scorer must not mutate kryptos.kernel.constants.CT
        or BEAN_EQ/INEQ/LINEAR."""
        from kryptos.kernel import constants as kc
        ct_before = kc.CT
        eq_before = tuple(kc.BEAN_EQ)
        ineq_before = tuple(kc.BEAN_INEQ)
        linear_before = tuple(kc.BEAN_LINEAR)

        v = list(enumerate_hamming1_variants(CANONICAL_CT))[5]
        ctx = ScorerContext.build(v)
        _ = score_candidate_ct_parametric(
            ctx, keyword="KRYPTOS", family=CipherVariant.VIGENERE,
            alphabet_kind="AZ", universe_size=10,
            policy=AlertPolicy(require_null_for_alert=False),
        )

        assert kc.CT == ct_before
        assert tuple(kc.BEAN_EQ) == eq_before
        assert tuple(kc.BEAN_INEQ) == ineq_before
        assert tuple(kc.BEAN_LINEAR) == linear_before


# ── 4. Alert classification ─────────────────────────────────────────────

class TestAlertClassification:
    def test_h1_full_pass(self):
        klass, _ = classify_alert(
            crib_score=24, crib_total=24, bean_passed=True,
            ngram_score=-3.0, p_adjusted=1e-10, null_available=True,
            distance=1, policy=AlertPolicy(),
        )
        assert klass == "alert"

    def test_h1_partial_cribs_to_watchlist(self):
        klass, _ = classify_alert(
            crib_score=20, crib_total=24, bean_passed=True,
            ngram_score=-3.0, p_adjusted=1e-10, null_available=True,
            distance=1, policy=AlertPolicy(),
        )
        assert klass == "watchlist"

    def test_h1_no_null_downgrades(self):
        klass, _ = classify_alert(
            crib_score=24, crib_total=24, bean_passed=True,
            ngram_score=-3.0, p_adjusted=None, null_available=False,
            distance=1, policy=AlertPolicy(),
        )
        assert klass == "watchlist_null_unavailable"

    def test_h0_path(self):
        klass, _ = classify_alert(
            crib_score=24, crib_total=24, bean_passed=True,
            ngram_score=-3.0, p_adjusted=1e-3, null_available=True,
            distance=0, policy=AlertPolicy(),
        )
        assert klass == "alert"


# ── 5. P-value helpers ──────────────────────────────────────────────────

class TestPValueHelpers:
    def test_crib_p_value_at_zero(self):
        assert crib_p_value_random(0, 24) == 1.0

    def test_crib_p_value_decreases_with_score(self):
        p_low = crib_p_value_random(5, 24)
        p_mid = crib_p_value_random(10, 24)
        p_high = crib_p_value_random(18, 24)
        assert p_low > p_mid > p_high
        # 18/24 under p=1/26 is astronomically unlikely.
        assert p_high < 1e-15

    def test_fisher_combine_returns_none_on_bad_input(self):
        assert fisher_combine([0.5, 0.0]) is None
        assert fisher_combine([0.5, None]) is None
        assert fisher_combine([]) is None

    def test_fisher_combine_basic(self):
        # Two independent p-values both at 0.5: combined should be > 0.
        p = fisher_combine([0.5, 0.5])
        assert p is not None
        assert 0.0 < p < 1.0

    def test_bonferroni_adjust_clamps(self):
        assert bonferroni_adjust(0.001, 100) == 0.1
        # Clamps to 1.0 when product exceeds.
        assert bonferroni_adjust(0.5, 100) == 1.0
        assert bonferroni_adjust(None, 100) is None


class TestCipherFormulaMicrofixtures:
    @pytest.mark.parametrize("alphabet_kind,alphabet", [
        ("AZ", _AZ_ALPHA),
        ("KA", _KA_ALPHA),
    ])
    @pytest.mark.parametrize("family", [
        CipherVariant.VIGENERE,
        CipherVariant.BEAUFORT,
        CipherVariant.VAR_BEAUFORT,
    ])
    def test_decrypt_with_keyword_matches_kernel_encrypt_roundtrip(self, alphabet_kind, alphabet, family):
        pt = ("KRYPTOSABCXYZ" * 8)[:97]
        assert len(pt) == 97
        keyword = "PALIMPSEST"
        key = alphabet.encode(keyword)
        ct = encrypt_text(pt, key, variant=family, alphabet=alphabet)
        assert decrypt_with_keyword(ct, keyword, family, alphabet_kind) == pt

    def test_recovery_formulas_on_single_position_az(self):
        pt = "A" * 97
        key = _AZ_ALPHA.encode("D")
        expected_key_value = 3
        for family in (
            CipherVariant.VIGENERE,
            CipherVariant.BEAUFORT,
            CipherVariant.VAR_BEAUFORT,
        ):
            ct = encrypt_text(pt, key, variant=family, alphabet=_AZ_ALPHA)
            ks = recover_keystream_at_cribs(
                ct, pt, family=family, alphabet=_AZ_ALPHA, crib_positions=[0],
            )
            assert ks[0] == expected_key_value


# ── 6. Scope exclusion ──────────────────────────────────────────────────

class TestScopeExclusion:
    """Verify Stage A scope: no running-key, no corpus, no non-English."""

    @pytest.fixture
    def ct_perturbation_source(self) -> str:
        return (REPO_ROOT / "kryptosbot" / "ct_perturbation.py").read_text()

    @pytest.fixture
    def runner_source(self) -> str:
        return (REPO_ROOT / "scripts" / "campaigns"
                / "ct_perturbation_stage_a.py").read_text()

    def _imports_in(self, source: str) -> Set[str]:
        tree = ast.parse(source)
        imports: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    imports.add(n.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module)
        return imports

    def test_no_running_key_imports(self, ct_perturbation_source):
        imports = self._imports_in(ct_perturbation_source)
        bad = [i for i in imports if "running_key" in i.lower()]
        assert not bad, f"running-key imports leaked into ct_perturbation.py: {bad}"

    def test_no_running_key_imports_runner(self, runner_source):
        imports = self._imports_in(runner_source)
        bad = [i for i in imports if "running_key" in i.lower()]
        assert not bad, f"running-key imports leaked into runner: {bad}"

    def test_no_corpus_imports(self, ct_perturbation_source):
        imports = self._imports_in(ct_perturbation_source)
        bad = [i for i in imports if (
            "corpus" in i.lower()
            or "egyptian" in i.lower()
            or "hieratic" in i.lower()
            or "gutenberg" in i.lower()
        )]
        assert not bad, f"corpus imports leaked into ct_perturbation.py: {bad}"

    def test_no_corpus_imports_runner(self, runner_source):
        imports = self._imports_in(runner_source)
        bad = [i for i in imports if (
            "corpus" in i.lower()
            or "egyptian" in i.lower()
            or "hieratic" in i.lower()
            or "gutenberg" in i.lower()
        )]
        assert not bad, f"corpus imports leaked into runner: {bad}"

    def test_cli_exposes_no_running_key_options(self, runner_source):
        # No --running-key, --corpus, --non-english options.
        for forbidden in (
            "--running-key", "--running_key",
            "--corpus", "--corpus-license", "--non-english",
            "--source-text", "--language",
        ):
            assert forbidden not in runner_source, (
                f"Forbidden CLI option {forbidden!r} present in runner"
            )

    def test_no_autokey_or_quagmire_supported_families(self):
        # Stage A only does Vig / Beau / VarBeau.
        assert set(SUPPORTED_FAMILIES) == {
            CipherVariant.VIGENERE, CipherVariant.BEAUFORT,
            CipherVariant.VAR_BEAUFORT,
        }


class TestLoopAccounting:
    def test_worker_exception_fails_closed_without_formula_count(self, tmp_path, monkeypatch):
        runner = load_stage_a_runner_module()
        cfg = runner.SweepConfig(
            ct=CANONICAL_CT,
            keywords=["KRYPTOS"],
            universe_size=12,
            include_h0=False,
            max_ct_variants=2,
            policy=AlertPolicy(require_null_for_alert=False),
        )
        original = runner.evaluate_one_variant
        calls = {"n": 0}

        def flaky(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("controlled fault")
            return original(*args, **kwargs)

        monkeypatch.setattr(runner, "evaluate_one_variant", flaky)
        metadata = {
            "canonical_ct_sha256": "test",
            "h1_variants_executed": 2,
            "h0_variants_executed": 0,
            "total_ct_variants_executed": 2,
            "expected_total_config_cardinality": 12,
            "crib_position_h1_variants": 0,
            "noncrib_position_h1_variants": 2,
            "keyword_count": 1,
            "keyword_hash": "test",
            "period_values": [7],
            "null_status": {"ngram_AZ": "test", "ngram_KA": "test"},
        }
        with pytest.raises(RuntimeError, match="controlled fault"):
            runner.run_sweep(
                cfg, artifact_dir=tmp_path, run_id="fault",
                workers=1, run_metadata=metadata,
            )
        summary = json.loads((tmp_path / "summary.json").read_text())
        progress = json.loads((tmp_path / "progress.json").read_text())
        assert summary["status"] == "failed"
        assert progress["status"] == "failed"
        assert summary["candidates_evaluated"] < summary["expected_total_config_cardinality"]
        assert progress["candidates_evaluated"] < progress["expected_total_config_cardinality"]

    def test_workers_1_and_2_equivalent_on_tiny_universe(self, tmp_path):
        runner = REPO_ROOT / "scripts" / "campaigns" / "ct_perturbation_stage_a.py"
        kw_file = tmp_path / "kw.txt"
        kw_file.write_text("KRYPTOS\nBERLIN\n")
        import os
        env = {
            k: v for k, v in os.environ.items()
            if k not in (
                "KRYPTOS_CT_OVERRIDE",
                "KRYPTOS_CRIB_DICT_OVERRIDE",
                "KRYPTOS_BENCH_ID",
                "KRYPTOS_BENCH_SUITE",
            )
        }
        env["PYTHONPATH"] = str(SRC_DIR)
        for workers in ("1", "2"):
            cp = subprocess.run(
                [sys.executable, str(runner),
                 "--keywords", str(kw_file),
                 "--run-id", f"ut_w{workers}",
                 "--artifact-root", str(tmp_path),
                 "--max-ct-variants", "1",
                 "--include-h0-baseline",
                 "--workers", workers,
                 "--allow-null-unavailable",
                 ],
                capture_output=True, text=True, env=env, timeout=180,
            )
            assert cp.returncode == 0, cp.stderr
        s1 = json.loads((tmp_path / "ut_w1" / "summary.json").read_text())
        s2 = json.loads((tmp_path / "ut_w2" / "summary.json").read_text())
        comparable = (
            "expected_total_config_cardinality", "candidates_evaluated",
            "bean_pass_total", "watchlist_total", "alerts_total",
            "rejection_reason_counts",
        )
        for key in comparable:
            assert s1[key] == s2[key]
        assert (tmp_path / "ut_w1" / "top_candidates.jsonl").read_text() == (
            tmp_path / "ut_w2" / "top_candidates.jsonl"
        ).read_text()


# ── 7. CLI behaviour ────────────────────────────────────────────────────

class TestCLI:
    @staticmethod
    def _runner_path() -> Path:
        return REPO_ROOT / "scripts" / "campaigns" / "ct_perturbation_stage_a.py"

    def _run(self, *args: str, env_extra: dict | None = None) -> subprocess.CompletedProcess:
        env = {"PYTHONPATH": str(SRC_DIR)}
        if env_extra:
            env.update(env_extra)
        import os
        # Scrub any leaked KRYPTOS_*_OVERRIDE env vars from prior tests
        # (e.g. kryptosbot bench loader's install_kernel_overrides() in
        # test_lesson_block_reversal_capability.py is not torn down) —
        # the CT-perturbation campaign must run against the CANONICAL
        # carved K4 ciphertext, not a leaked synthetic override.
        full_env = {
            k: v for k, v in os.environ.items()
            if k not in (
                "KRYPTOS_CT_OVERRIDE",
                "KRYPTOS_CRIB_DICT_OVERRIDE",
                "KRYPTOS_BENCH_ID",
                "KRYPTOS_BENCH_SUITE",
            )
        }
        full_env.update(env)
        return subprocess.run(
            [sys.executable, str(self._runner_path()), *args],
            capture_output=True, text=True, env=full_env, timeout=180,
        )

    def test_help(self):
        cp = self._run("--help")
        assert cp.returncode == 0
        assert "Stage A" in cp.stdout

    def test_dry_run_writes_manifest(self, tmp_path):
        cp = self._run(
            "--dry-run", "--run-id", "ut_dry",
            "--artifact-root", str(tmp_path),
        )
        assert cp.returncode == 0, cp.stderr
        assert (tmp_path / "ut_dry" / "preregistration.json").exists()
        assert (tmp_path / "ut_dry" / "summary.json").exists()
        manifest = json.loads(
            (tmp_path / "ut_dry" / "preregistration.json").read_text()
        )
        assert manifest["campaign_id"] == "ct_perturbation_stage_a"
        assert manifest["cipher_families"] == ["vigenere", "beaufort", "var_beaufort"]
        assert manifest["alphabets"] == ["AZ", "KA"]
        assert manifest["exclusions"]["running_key"]
        assert manifest["exclusions"]["non_english_source_text"]

    def test_default_does_not_launch_full_sweep(self, tmp_path):
        # Without --execute-full and without --dry-run, default is a
        # tiny smoke: max-ct-variants <= 2.
        kw_file = tmp_path / "kw.txt"
        kw_file.write_text("KRYPTOS\nBERLIN\nCLOCK\n")
        cp = self._run(
            "--keywords", str(kw_file),
            "--run-id", "ut_smoke",
            "--artifact-root", str(tmp_path),
        )
        assert cp.returncode == 0, cp.stderr
        manifest = json.loads(
            (tmp_path / "ut_smoke" / "preregistration.json").read_text()
        )
        # number_of_ct_variants either equals 2 or is much less than 2425.
        assert manifest["number_of_ct_variants"] <= 2

    def test_max_ct_variants_smoke(self, tmp_path):
        kw_file = tmp_path / "kw.txt"
        kw_file.write_text("KRYPTOS\nBERLIN\nCLOCK\n")
        cp = self._run(
            "--keywords", str(kw_file),
            "--run-id", "ut_smoke2",
            "--artifact-root", str(tmp_path),
            "--max-ct-variants", "1",
            "--keyword-limit", "2",
        )
        assert cp.returncode == 0, cp.stderr
        manifest = json.loads(
            (tmp_path / "ut_smoke2" / "preregistration.json").read_text()
        )
        assert manifest["number_of_ct_variants"] == 1
        # 1 variant × 3 families × 2 alphabets × 2 keywords = 12.
        assert manifest["total_config_cardinality"] == 12

    def test_synthetic_recovery_flag(self, tmp_path):
        cp = self._run(
            "--synthetic-recovery-test", "--dry-run",
            "--run-id", "ut_recovery",
            "--artifact-root", str(tmp_path),
        )
        assert cp.returncode == 0, cp.stderr
        report_path = tmp_path / "ut_recovery" / "recovery_test_report.json"
        assert report_path.exists()
        report = json.loads(report_path.read_text())
        assert report["passed"] is True
        assert report["structural_recovery"]["passed"] is True
        assert report["selective_recovery"]["passed"] is True
        assert report["matching_alert_count"] >= 1

    def test_resume_fails_before_compute(self, tmp_path):
        cp = self._run(
            "--resume", str(tmp_path),
            "--dry-run",
            "--run-id", "ut_resume",
            "--artifact-root", str(tmp_path),
        )
        assert cp.returncode != 0
        assert "not implemented" in cp.stderr.lower()


# ── 8. Artifact validity ────────────────────────────────────────────────

class TestArtifactValidity:
    def test_smoke_run_produces_valid_artifacts(self, tmp_path):
        runner = REPO_ROOT / "scripts" / "campaigns" / "ct_perturbation_stage_a.py"
        kw_file = tmp_path / "kw.txt"
        kw_file.write_text("KRYPTOS\nBERLIN\n")
        import os
        # Scrub leaked overrides from prior tests (see TestCLI._run).
        env = {
            k: v for k, v in os.environ.items()
            if k not in (
                "KRYPTOS_CT_OVERRIDE",
                "KRYPTOS_CRIB_DICT_OVERRIDE",
                "KRYPTOS_BENCH_ID",
                "KRYPTOS_BENCH_SUITE",
            )
        }
        env["PYTHONPATH"] = str(SRC_DIR)
        cp = subprocess.run(
            [sys.executable, str(runner),
             "--keywords", str(kw_file),
             "--run-id", "ut_artifacts",
             "--artifact-root", str(tmp_path),
             "--max-ct-variants", "2",
             "--allow-null-unavailable",
             ],
            capture_output=True, text=True, env=env, timeout=180,
        )
        assert cp.returncode == 0, cp.stderr

        rdir = tmp_path / "ut_artifacts"
        # Required files.
        for name in ("preregistration.json", "universe_manifest.json",
                     "summary.json", "keyword_source_manifest.json",
                     "progress.json", "coverage_report.json",
                     "alerts.jsonl", "watchlist.jsonl", "top_candidates.jsonl"):
            assert (rdir / name).exists(), f"missing {name}"

        # JSON parsability.
        for name in ("preregistration.json", "universe_manifest.json",
                     "summary.json", "keyword_source_manifest.json",
                     "progress.json", "coverage_report.json"):
            json.loads((rdir / name).read_text())

        summary = json.loads((rdir / "summary.json").read_text())
        assert summary["campaign_id"] == "ct_perturbation_stage_a"
        assert summary["artifact_schema_version"] == 2
        assert summary["h1_variants_executed"] == 2
        assert summary["h0_variants_executed"] == 0
        assert summary["total_ct_variants_executed"] == 2
        assert summary["expected_total_config_cardinality"] == 24
        assert summary["candidates_evaluated"] == 24
        assert summary["period_policy"] == "keyword_length"

        # JSONL parsability for any present jsonl file.
        for jsonl_name in ("alerts.jsonl", "watchlist.jsonl", "top_candidates.jsonl"):
            p = rdir / jsonl_name
            for line in p.read_text().splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                assert "run_id" in row
                assert "variant_id" in row
                assert "distance" in row
                assert "ct_sha256" in row
                assert "family" in row
                assert "alphabet" in row
                assert "keyword" in row
                assert "score" in row
                # p-value fields exist (may be null).
                score = row["score"]
                assert "crib_p_raw" in score
                assert "p_adjusted" in score
                assert "alert_class" in score

    def test_trace_first_configs_records_actual_loop_visits(self, tmp_path):
        runner = REPO_ROOT / "scripts" / "campaigns" / "ct_perturbation_stage_a.py"
        kw_file = tmp_path / "kw.txt"
        kw_file.write_text("KRYPTOS\nBERLIN\n")
        import os
        env = {
            k: v for k, v in os.environ.items()
            if k not in (
                "KRYPTOS_CT_OVERRIDE",
                "KRYPTOS_CRIB_DICT_OVERRIDE",
                "KRYPTOS_BENCH_ID",
                "KRYPTOS_BENCH_SUITE",
            )
        }
        env["PYTHONPATH"] = str(SRC_DIR)
        cp = subprocess.run(
            [sys.executable, str(runner),
             "--keywords", str(kw_file),
             "--run-id", "ut_trace",
             "--artifact-root", str(tmp_path),
             "--max-ct-variants", "1",
             "--trace-first-configs", "3",
             "--allow-null-unavailable",
             ],
            capture_output=True, text=True, env=env, timeout=180,
        )
        assert cp.returncode == 0, cp.stderr
        trace_path = tmp_path / "ut_trace" / "trace_first_configs.jsonl"
        rows = [json.loads(line) for line in trace_path.read_text().splitlines()]
        assert len(rows) == 3
        assert rows[0]["variant_id"].startswith("H1_p00_")
        assert rows[0]["family"] == "vigenere"
        assert rows[0]["alphabet"] == "AZ"
        assert rows[0]["keyword"] == "KRYPTOS"
        assert rows[0]["crib_checked"] is True
        assert rows[0]["bean_checked"] is True

    def test_audit_run_passes_on_schema_v2_smoke(self, tmp_path):
        runner = REPO_ROOT / "scripts" / "campaigns" / "ct_perturbation_stage_a.py"
        kw_file = tmp_path / "kw.txt"
        kw_file.write_text("KRYPTOS\nBERLIN\n")
        import os
        env = {
            k: v for k, v in os.environ.items()
            if k not in (
                "KRYPTOS_CT_OVERRIDE",
                "KRYPTOS_CRIB_DICT_OVERRIDE",
                "KRYPTOS_BENCH_ID",
                "KRYPTOS_BENCH_SUITE",
            )
        }
        env["PYTHONPATH"] = str(SRC_DIR)
        cp = subprocess.run(
            [sys.executable, str(runner),
             "--keywords", str(kw_file),
             "--run-id", "ut_audit",
             "--artifact-root", str(tmp_path),
             "--max-ct-variants", "1",
             "--allow-null-unavailable",
             ],
            capture_output=True, text=True, env=env, timeout=180,
        )
        assert cp.returncode == 0, cp.stderr
        audit = subprocess.run(
            [sys.executable, str(runner),
             "--audit-run", str(tmp_path / "ut_audit")],
            capture_output=True, text=True, env=env, timeout=180,
        )
        assert audit.returncode == 0, audit.stderr + audit.stdout
        report = json.loads((tmp_path / "ut_audit" / "audit_report.json").read_text())
        assert report["passed"] is True
