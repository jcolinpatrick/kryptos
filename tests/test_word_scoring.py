"""Tests for word-level scoring and crib diagnostics."""
from __future__ import annotations

import pytest
from kryptos.kernel.scoring.words import WordScorer, WordResult
from kryptos.kernel.scoring.crib_diagnostic import diagnose_cribs, CribDiagnostic
from kryptos.kernel.constants import CT


class TestWordScorer:
    """Test word segmentation scoring."""

    @pytest.fixture
    def scorer(self):
        words = {
            "THE", "QUICK", "BROWN", "FOX", "JUMPED", "OVER",
            "LAZY", "SLOWLY", "REMAINS", "PASSAGE", "DEBRIS",
            "THAT", "DOOR", "REMOVED", "LOWER", "PART",
            "HANDS", "MADE", "TINY", "BREACH", "WITH",
        }
        return WordScorer(words, min_word_len=3)

    def test_full_coverage(self, scorer):
        r = scorer.score("THEQUICKBROWNFOX")
        assert r.coverage > 0.9
        assert "THE" in r.words
        assert "QUICK" in r.words

    def test_zero_coverage(self, scorer):
        r = scorer.score("XZQWPLFMKJ")
        assert r.coverage == 0.0
        assert r.word_count == 0

    def test_partial_coverage(self, scorer):
        r = scorer.score("THEXYZQUICK")
        assert 0.5 < r.coverage < 1.0

    def test_empty_string(self, scorer):
        r = scorer.score("")
        assert r.coverage == 0.0

    def test_longest_word(self, scorer):
        r = scorer.score("REMOVED")
        assert r.longest == 7

    def test_coverage_only(self, scorer):
        cov = scorer.score_coverage("THEQUICKBROWNFOX")
        assert cov > 0.9

    def test_k3_fragment(self, scorer):
        r = scorer.score("SLOWLYTHEREMAINSOFPASSAGEDEBRIS")
        assert r.coverage > 0.7
        assert "SLOWLY" in r.words

    def test_summary_format(self, scorer):
        r = scorer.score("THEQUICKBROWNFOX")
        s = r.summary
        assert "words=" in s
        assert "longest=" in s

    def test_to_dict(self, scorer):
        r = scorer.score("THEQUICKBROWNFOX")
        d = r.to_dict()
        assert "coverage" in d
        assert "words" in d
        assert isinstance(d["words"], list)


class TestCribDiagnostic:
    """Test spatial crib analysis."""

    def test_self_encrypting_positions(self):
        # CT[32]=S=PT[32] and CT[73]=K=PT[73] are self-encrypting
        diag = diagnose_cribs(CT)
        assert 32 in diag.matched_positions
        assert 73 in diag.matched_positions
        assert diag.total_score == 2

    def test_perfect_match(self):
        # Build a plaintext that matches all cribs
        text = list("A" * 97)
        from kryptos.kernel.constants import CRIB_DICT
        for pos, ch in CRIB_DICT.items():
            text[pos] = ch
        diag = diagnose_cribs("".join(text))
        assert diag.total_score == 24
        assert diag.longest_run == 13  # ENE is 13 contiguous
        assert diag.ene_contiguous == 13
        assert diag.bc_contiguous == 11

    def test_off_by_one_detection(self):
        # Create a near-miss at position 21 (expected E, give D or F)
        from kryptos.kernel.constants import CRIB_DICT
        text = list("A" * 97)
        for pos, ch in CRIB_DICT.items():
            text[pos] = ch
        text[21] = "D"  # one off from E
        diag = diagnose_cribs("".join(text))
        assert 21 in diag.off_by_one
        assert diag.total_score == 23

    def test_implied_key_chars(self):
        from kryptos.kernel.constants import CRIB_DICT
        text = list("A" * 97)
        for pos, ch in CRIB_DICT.items():
            text[pos] = ch
        diag = diagnose_cribs("".join(text))
        # All matched positions should have implied key chars
        assert len(diag.implied_key_chars) == 24

    def test_summary_format(self):
        diag = diagnose_cribs(CT)
        s = diag.summary
        assert "score=" in s
        assert "longest_run=" in s

    def test_to_dict(self):
        diag = diagnose_cribs(CT)
        d = diag.to_dict()
        assert "total_score" in d
        assert "matched_positions" in d
        assert "off_by_one" in d


class TestScoringIntegration:
    """Test that word scoring integrates with aggregate scorer."""

    def test_score_candidate_with_word_scorer(self):
        from kryptos.kernel.scoring.aggregate import score_candidate
        words = {"THE", "QUICK", "BROWN", "FOX", "TEST"}
        ws = WordScorer(words, min_word_len=3)
        sb = score_candidate("A" * 97, word_scorer=ws)
        assert sb.word_coverage is not None
        assert sb.word_coverage == 0.0

    def test_score_candidate_without_word_scorer(self):
        from kryptos.kernel.scoring.aggregate import score_candidate
        sb = score_candidate("A" * 97)
        assert sb.word_coverage is None

    def test_score_candidate_free_with_word_scorer(self):
        from kryptos.kernel.scoring.aggregate import score_candidate_free
        words = {"THE", "QUICK", "BROWN", "FOX", "TEST"}
        ws = WordScorer(words, min_word_len=3)
        fsb = score_candidate_free("A" * 97, word_scorer=ws)
        assert fsb.word_coverage is not None
