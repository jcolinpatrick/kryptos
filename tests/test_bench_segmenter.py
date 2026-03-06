"""Tests for bench.segmenter — sliding-window IOC analysis and mixed-input detection."""
from __future__ import annotations

import json

import pytest

from bench.segmenter import (
    DEFAULT_WINDOW,
    MIN_SEGMENT_LEN,
    Segment,
    SegmentationResult,
    _chi2_english,
    _find_alphabet_runs,
    _ioc,
    segment_ciphertext,
)


# ══════════════════════════════════════════════════════════════════════════
# Low-level statistics
# ══════════════════════════════════════════════════════════════════════════


class TestIOC:
    def test_english_text(self):
        ioc_val = _ioc("WEAREDISCOVEREDSAVEYOURSELF")
        assert ioc_val > 0.05  # English-like

    def test_sequential_alphabet_zero(self):
        """A–Z (each letter once) → IOC = 0.0."""
        assert _ioc("ABCDEFGHIJKLMNOPQRSTUVWXYZ") == 0.0

    def test_qwerty_alphabet_zero(self):
        assert _ioc("QWERTYUIOPASDFGHJKLZXCVBNM") == 0.0

    def test_empty(self):
        assert _ioc("") == 0.0

    def test_single_char(self):
        assert _ioc("A") == 0.0

    def test_all_same(self):
        # All same letter: IC = 1.0
        assert _ioc("AAAAAAAAAA") == pytest.approx(1.0)


class TestChi2:
    def test_english_low(self):
        # Short texts (26 chars) have higher chi2 due to sampling noise;
        # use a longer sample for a tighter bound.
        chi2 = _chi2_english("ITWASABRIGHTCOLDDAYINAPRILANDTHECLOCKSWERESTRIKINGTHIRTEEN")
        assert chi2 < 0.015  # close to English distribution

    def test_flat_distribution_higher(self):
        chi2 = _chi2_english("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        assert chi2 > 0.005  # further from English

    def test_empty(self):
        assert _chi2_english("") == 1.0


# ══════════════════════════════════════════════════════════════════════════
# Alphabet run detection
# ══════════════════════════════════════════════════════════════════════════


class TestAlphabetRuns:
    def test_az_forward(self):
        runs = _find_alphabet_runs("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        assert len(runs) >= 1
        assert runs[0][2] == "az_forward"
        assert runs[0][1] - runs[0][0] == 26

    def test_az_reverse(self):
        runs = _find_alphabet_runs("ZYXWVUTSRQPONMLKJIHGFEDCBA")
        assert len(runs) >= 1
        assert runs[0][2] == "az_reverse"

    def test_qwerty_full(self):
        runs = _find_alphabet_runs("QWERTYUIOPASDFGHJKLZXCVBNM")
        assert len(runs) >= 1
        assert "qwerty" in runs[0][2]

    def test_qwerty_row1(self):
        runs = _find_alphabet_runs("XXXXXQWERTYUIOPXXXXX")
        assert len(runs) >= 1
        r = runs[0]
        assert r[0] == 5
        assert r[1] == 15
        assert "qwerty" in r[2]

    def test_no_match_in_normal_text(self):
        runs = _find_alphabet_runs("WEAREDISCOVEREDSAVEYOURSELF")
        assert len(runs) == 0

    def test_partial_az_too_short(self):
        # 8 chars of A–Z: below _MIN_ALPHABET_RUN (10)
        runs = _find_alphabet_runs("ABCDEFGH")
        assert len(runs) == 0

    def test_embedded_in_larger_text(self):
        text = "HELLO" + "ABCDEFGHIJKLMNOP" + "WORLD"
        runs = _find_alphabet_runs(text)
        assert len(runs) >= 1
        r = runs[0]
        assert r[0] == 5
        assert r[1] == 21


# ══════════════════════════════════════════════════════════════════════════
# Full segmentation
# ══════════════════════════════════════════════════════════════════════════


class TestSegmentCiphertext:
    def test_pure_cipher_not_mixed(self):
        """Normal Vigenère ciphertext → single cipher segment, not mixed."""
        ct = "ZICVTWQNGRZGVTWAVZHCQYGLMGJ"
        result = segment_ciphertext(ct)
        assert result.is_mixed is False
        assert len(result.segments) >= 1
        assert result.segments[0].label == "cipher"
        assert result.global_ioc > 0

    def test_pure_alphabet_is_padding(self):
        """Full A–Z → padding."""
        ct = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        result = segment_ciphertext(ct)
        assert len(result.segments) >= 1
        assert result.segments[0].label == "padding"
        assert result.is_mixed is True

    def test_mixed_vig_plus_qwerty(self):
        """Vigenère block + QWERTY alphabet → mixed, at least 2 segments."""
        vig = "ZICVTWQNGRZGVTWAVZHCQYGLMGJ" * 2  # 54 chars
        qwerty = "QWERTYUIOPASDFGHJKLZXCVBNM"       # 26 chars
        ct = vig + qwerty
        result = segment_ciphertext(ct, window=20)
        assert result.is_mixed is True
        labels = [s.label for s in result.segments]
        assert "padding" in labels
        # Should have at least one cipher and one padding segment
        assert "cipher" in labels or "anomaly" in labels

    def test_vig_qwerty_vig_sandwich(self):
        """Cipher + QWERTY bait + cipher → mixed with 3+ segments."""
        vig1 = "ZICVTWQNGRZGVTWAVZHCQYGLMGJ"  # 27 chars
        bait = "QWERTYUIOPASDFGHJKLZXCVBNM"    # 26 chars
        vig2 = "ABIEKLMNOPQRSTUVWXYZABCDEFG"    # 27 chars
        ct = vig1 + bait + vig2
        result = segment_ciphertext(ct, window=20)
        assert result.is_mixed is True
        labels = [s.label for s in result.segments]
        assert "padding" in labels

    def test_empty_text(self):
        result = segment_ciphertext("")
        assert result.is_mixed is False
        assert len(result.segments) == 0

    def test_short_text_single_segment(self):
        result = segment_ciphertext("HELLO")
        assert len(result.segments) == 1
        assert result.segments[0].label == "cipher"

    def test_segments_cover_full_text(self):
        """Segments must span the entire ciphertext without gaps."""
        ct = "ZICVTWQNGRZGVTWAVZHCQYGLMGJ" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 2
        result = segment_ciphertext(ct, window=20)
        if result.segments:
            assert result.segments[0].start == 0
            assert result.segments[-1].end == len(ct)
            for i in range(len(result.segments) - 1):
                assert result.segments[i].end == result.segments[i + 1].start

    def test_segment_ioc_and_chi2_present(self):
        ct = "ZICVTWQNGRZGVTWAVZHCQYGLMGJ"
        result = segment_ciphertext(ct)
        for seg in result.segments:
            assert isinstance(seg.ioc, float)
            assert isinstance(seg.chi2, float)


# ══════════════════════════════════════════════════════════════════════════
# Regression: Vigenère blocks + QWERTY bait line
# ══════════════════════════════════════════════════════════════════════════


class TestMixedRegression:
    """The core regression test: Vigenère DECEPTIVE ciphertext with an
    embedded QWERTY alphabet line must be flagged as mixed, and must
    NOT yield high-confidence validation on a global solve.
    """

    @pytest.fixture
    def mixed_ct(self):
        """Build: Vig(DECEPTIVE) block + QWERTY bait + Vig(DECEPTIVE) block."""
        # Vigenère encrypt "WEAREDISCOVEREDSAVEYOURSELF" with key DECEPTIVE
        # Known result: ZICVTWQNGRZGVTWAVZHCQYGLMGJ
        vig_block = "ZICVTWQNGRZGVTWAVZHCQYGLMGJ"
        qwerty_bait = "QWERTYUIOPASDFGHJKLZXCVBNM"
        return vig_block + qwerty_bait + vig_block

    def test_detected_as_mixed(self, mixed_ct):
        result = segment_ciphertext(mixed_ct, window=20)
        assert result.is_mixed is True

    def test_has_padding_segment(self, mixed_ct):
        result = segment_ciphertext(mixed_ct, window=20)
        padding = [s for s in result.segments if s.label == "padding"]
        assert len(padding) >= 1
        # The padding segment should roughly cover the QWERTY region
        qwerty_start = 27
        qwerty_end = 53
        for p in padding:
            if p.start <= qwerty_start + 5 and p.end >= qwerty_end - 5:
                break
        else:
            pytest.fail("No padding segment covers the QWERTY bait region")

    def test_cipher_segments_present(self, mixed_ct):
        result = segment_ciphertext(mixed_ct, window=20)
        cipher = [s for s in result.segments if s.label == "cipher"]
        # At least one cipher segment should exist
        assert len(cipher) >= 1

    def test_validation_not_high_on_mixed(self, mixed_ct):
        """If the validator sees segmentation.is_mixed=True, confidence
        must not be 'high'.
        """
        from bench.validator import validate_result

        seg = segment_ciphertext(mixed_ct, window=20)
        result_dict = {
            "case_id": "regression_mixed",
            "status": "success",
            "predicted_plaintext": mixed_ct,  # the "solve" is the whole CT (garbage)
            "top_candidates": [
                {"score": 10.0, "plaintext": mixed_ct, "method": "guess"},
            ],
            "segmentation": seg.to_dict(),
        }
        validate_result(result_dict)
        v = result_dict["validation"]
        assert v["confidence"] != "high"
        assert v.get("mixed_input", False) is True


# ══════════════════════════════════════════════════════════════════════════
# Serialization
# ══════════════════════════════════════════════════════════════════════════


class TestSerialization:
    def test_segment_roundtrip(self):
        seg = Segment(start=0, end=26, label="padding",
                      ioc=0.0, chi2=0.01, notes="az_forward")
        d = seg.to_dict()
        seg2 = Segment.from_dict(d)
        assert seg2.start == 0
        assert seg2.end == 26
        assert seg2.label == "padding"
        assert seg2.notes == "az_forward"

    def test_result_roundtrip(self):
        sr = SegmentationResult(
            is_mixed=True,
            segments=[
                Segment(start=0, end=27, label="cipher", ioc=0.04, chi2=0.01),
                Segment(start=27, end=53, label="padding", ioc=0.0, chi2=0.02,
                        notes="qwerty"),
            ],
            global_ioc=0.03,
            window_size=20,
        )
        d = sr.to_dict()
        sr2 = SegmentationResult.from_dict(d)
        assert sr2.is_mixed is True
        assert len(sr2.segments) == 2
        assert sr2.segments[1].label == "padding"

    def test_json_serializable(self):
        ct = "ZICVTWQNGRZGVTWAVZHCQYGLMGJ" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        result = segment_ciphertext(ct, window=20)
        # Must not raise
        json_str = json.dumps(result.to_dict())
        parsed = json.loads(json_str)
        assert parsed["is_mixed"] is True


# ══════════════════════════════════════════════════════════════════════════
# Schema integration
# ══════════════════════════════════════════════════════════════════════════


class TestSchemaIntegration:
    def test_segmentation_in_benchmark_result(self):
        from bench.schema import BenchmarkResult

        seg_data = {
            "is_mixed": True,
            "global_ioc": 0.03,
            "window_size": 20,
            "n_segments": 2,
            "segments": [
                {"start": 0, "end": 27, "label": "cipher", "ioc": 0.04,
                 "chi2": 0.01, "validated": False},
                {"start": 27, "end": 53, "label": "padding", "ioc": 0.0,
                 "chi2": 0.02, "notes": "qwerty", "validated": False},
            ],
        }
        r = BenchmarkResult(
            case_id="test_seg",
            status="success",
            segmentation=seg_data,
        )
        d = r.to_dict()
        assert "segmentation" in d
        assert d["segmentation"]["is_mixed"] is True

        r2 = BenchmarkResult.from_dict(d)
        assert r2.segmentation["is_mixed"] is True

    def test_empty_segmentation_omitted(self):
        from bench.schema import BenchmarkResult

        r = BenchmarkResult(case_id="x", status="error")
        d = r.to_dict()
        assert "segmentation" not in d
