"""Tests for bench/scorer.py — edit distance, CER, and full scoring.

Uses a 5-case fixture where every metric value is hand-computed and
asserted exactly.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from bench.schema import BenchmarkCase, BenchmarkResult, CandidateResult
from bench.scorer import (
    _levenshtein,
    _percentile,
    character_error_rate,
    score,
    CaseScore,
    FamilyStats,
    ScoringReport,
)


# ── Levenshtein ──────────────────────────────────────────────────────────────


class TestLevenshtein:
    def test_identical(self):
        assert _levenshtein("HELLO", "HELLO") == 0

    def test_empty_both(self):
        assert _levenshtein("", "") == 0

    def test_empty_one(self):
        assert _levenshtein("ABC", "") == 3
        assert _levenshtein("", "XY") == 2

    def test_single_sub(self):
        assert _levenshtein("ABCDE", "ABCDF") == 1

    def test_single_insert(self):
        assert _levenshtein("ABC", "ABCD") == 1

    def test_single_delete(self):
        assert _levenshtein("ABCD", "ABC") == 1

    def test_completely_different(self):
        assert _levenshtein("AAA", "BBB") == 3

    def test_symmetric(self):
        assert _levenshtein("KITTEN", "SITTING") == _levenshtein("SITTING", "KITTEN")

    def test_classic_kitten_sitting(self):
        # kitten → sitten → sittin → sitting = 3
        assert _levenshtein("KITTEN", "SITTING") == 3


# ── Character Error Rate ─────────────────────────────────────────────────────


class TestCharacterErrorRate:
    def test_perfect_match(self):
        assert character_error_rate("HELLO", "HELLO") == 0.0

    def test_one_sub_of_five(self):
        assert character_error_rate("ABCDF", "ABCDE") == pytest.approx(0.2)

    def test_completely_wrong(self):
        assert character_error_rate("XXX", "ABC") == pytest.approx(1.0)

    def test_empty_prediction_nonempty_expected(self):
        # lev("", "XYZ") = 3, CER = 3/3 = 1.0
        assert character_error_rate("", "XYZ") == pytest.approx(1.0)

    def test_both_empty(self):
        assert character_error_rate("", "") == 0.0

    def test_empty_expected_nonempty_predicted(self):
        assert character_error_rate("ABC", "") == 1.0

    def test_longer_prediction(self):
        # lev("ABCDE", "ABC") = 2 (delete D, E), CER = 2/3
        assert character_error_rate("ABCDE", "ABC") == pytest.approx(2 / 3)


# ── Percentile ───────────────────────────────────────────────────────────────


class TestPercentile:
    def test_empty(self):
        assert _percentile([], 50) == 0.0

    def test_single(self):
        assert _percentile([5.0], 50) == 5.0
        assert _percentile([5.0], 90) == 5.0

    def test_two_values(self):
        assert _percentile([1.0, 3.0], 50) == pytest.approx(2.0)
        assert _percentile([1.0, 3.0], 0) == pytest.approx(1.0)
        assert _percentile([1.0, 3.0], 100) == pytest.approx(3.0)

    def test_five_values_p50(self):
        vals = [0.01, 0.05, 0.1, 0.2, 300.0]
        # k = 0.5 * 4 = 2.0 → index 2 exactly → 0.1
        assert _percentile(vals, 50) == pytest.approx(0.1)

    def test_five_values_p90(self):
        vals = [0.01, 0.05, 0.1, 0.2, 300.0]
        # k = 0.9 * 4 = 3.6 → 0.2 * 0.4 + 300.0 * 0.6 = 180.08
        assert _percentile(vals, 90) == pytest.approx(180.08)


# ── Full Scoring Fixture ─────────────────────────────────────────────────────
#
# 5 cases with hand-computed expected metrics:
#
#   1. "perfect"    — exact match at rank 1
#   2. "near_miss"  — wrong top-1, correct at rank 3, CER = 0.2
#   3. "error_case" — timeout error, CER = 1.0
#   4. "no_expected"— no expected PT (smoke test), metrics are None
#   5. "empty_out"  — no_results status, CER = 1.0


def _make_fixture():
    """Build deterministic (cases, results) for scoring tests."""
    cases = [
        BenchmarkCase(
            case_id="perfect",
            ciphertext="AAAAA",
            script="s.py",
            expected_plaintext="HELLO",
            expected_family="substitution",
        ),
        BenchmarkCase(
            case_id="near_miss",
            ciphertext="BBBBB",
            script="s.py",
            expected_plaintext="ABCDE",
            expected_family="substitution",
        ),
        BenchmarkCase(
            case_id="error_case",
            ciphertext="CCCCC",
            script="s.py",
            expected_plaintext="XYZ",
            expected_family="transposition",
        ),
        BenchmarkCase(
            case_id="no_expected",
            ciphertext="DDDDD",
            script="s.py",
        ),
        BenchmarkCase(
            case_id="empty_out",
            ciphertext="EEEEE",
            script="s.py",
            expected_plaintext="TEST",
            expected_family="substitution",
        ),
    ]

    results = [
        BenchmarkResult(
            case_id="perfect",
            status="success",
            elapsed_s=0.1,
            n_candidates=5,
            top_candidates=[
                CandidateResult(score=5.0, plaintext="HELLO", method="m1"),
                CandidateResult(score=3.0, plaintext="WORLD", method="m2"),
            ],
            predicted_plaintext="HELLO",
            predicted_family="substitution",
            match_plaintext=True,
            match_rank=1,
        ),
        BenchmarkResult(
            case_id="near_miss",
            status="success",
            elapsed_s=0.2,
            n_candidates=10,
            top_candidates=[
                CandidateResult(score=5.0, plaintext="ABCDF", method="m1"),
                CandidateResult(score=4.0, plaintext="ZZZZZ", method="m2"),
                CandidateResult(score=3.0, plaintext="ABCDE", method="m3"),
            ],
            predicted_plaintext="ABCDF",
            predicted_family="substitution",
            match_plaintext=True,
            match_rank=3,
        ),
        BenchmarkResult(
            case_id="error_case",
            status="error",
            elapsed_s=300.0,
            error="TimeoutError: exceeded 300s",
            predicted_family="",
        ),
        BenchmarkResult(
            case_id="no_expected",
            status="success",
            elapsed_s=0.05,
            n_candidates=2,
            top_candidates=[
                CandidateResult(score=1.0, plaintext="QWERTY", method="m1"),
            ],
            predicted_plaintext="QWERTY",
            predicted_family="",
        ),
        BenchmarkResult(
            case_id="empty_out",
            status="no_results",
            elapsed_s=0.01,
            predicted_family="",
        ),
    ]

    return cases, results


class TestScorer:
    """Full fixture tests with exact expected values."""

    @pytest.fixture()
    def report(self):
        cases, results = _make_fixture()
        return score(cases, results)

    # ── Counts ───────────────────────────────────────────────────────

    def test_total_cases(self, report):
        assert report.total_cases == 5

    def test_cases_with_expected_pt(self, report):
        # perfect, near_miss, error_case, empty_out = 4
        assert report.cases_with_expected_pt == 4

    def test_cases_with_expected_family(self, report):
        # perfect, near_miss, error_case, empty_out = 4
        assert report.cases_with_expected_family == 4

    # ── Status breakdown ─────────────────────────────────────────────

    def test_n_success(self, report):
        assert report.n_success == 3  # perfect, near_miss, no_expected

    def test_n_error(self, report):
        assert report.n_error == 1  # error_case

    def test_n_no_results(self, report):
        assert report.n_no_results == 1  # empty_out

    def test_n_timeout(self, report):
        assert report.n_timeout == 1  # error_case contains "TimeoutError"

    # ── Plaintext accuracy ───────────────────────────────────────────

    def test_pass_rate_top1(self, report):
        # Only "perfect" has top1_match = True → 1/4
        assert report.pass_rate_top1 == pytest.approx(0.25)

    def test_pass_rate_top5(self, report):
        # "perfect" (rank 1) + "near_miss" (rank 3) → 2/4
        assert report.pass_rate_top5 == pytest.approx(0.5)

    def test_exact_match_rate(self, report):
        # Only "perfect" exact → 1/4
        assert report.exact_match_rate == pytest.approx(0.25)

    def test_avg_cer(self, report):
        # CERs: perfect=0.0, near_miss=0.2, error_case=1.0, empty_out=1.0
        # avg = (0.0 + 0.2 + 1.0 + 1.0) / 4 = 0.55
        assert report.avg_cer == pytest.approx(0.55)

    # ── Family accuracy ──────────────────────────────────────────────

    def test_family_accuracy(self, report):
        # expected_family set on 4 cases (perfect, near_miss, error_case, empty_out)
        # correct: perfect (sub==sub), near_miss (sub==sub) = 2
        # incorrect: error_case (predicted=""), empty_out (predicted="") = 2
        # accuracy = 2/4 = 0.5
        assert report.family_accuracy == pytest.approx(0.5)

    # ── Timing ───────────────────────────────────────────────────────

    def test_avg_time(self, report):
        # times = [0.1, 0.2, 300.0, 0.05, 0.01]
        # avg = 300.36/5 = 60.072
        assert report.avg_time == pytest.approx(60.072)

    def test_p50_time(self, report):
        # sorted = [0.01, 0.05, 0.1, 0.2, 300.0]
        # p50: k = 2.0 → index 2 → 0.1
        assert report.p50_time == pytest.approx(0.1)

    def test_p90_time(self, report):
        # p90: k = 3.6 → 0.2*0.4 + 300.0*0.6 = 180.08
        assert report.p90_time == pytest.approx(180.08)

    # ── Per-case detail ──────────────────────────────────────────────

    def test_perfect_case(self, report):
        cs = next(c for c in report.cases if c.case_id == "perfect")
        assert cs.exact_match is True
        assert cs.cer == pytest.approx(0.0)
        assert cs.top1_match is True
        assert cs.top5_match is True
        assert cs.match_rank == 1
        assert cs.family_match is True

    def test_near_miss_case(self, report):
        cs = next(c for c in report.cases if c.case_id == "near_miss")
        assert cs.exact_match is False
        assert cs.cer == pytest.approx(0.2)
        assert cs.top1_match is False
        assert cs.top5_match is True
        assert cs.match_rank == 3
        assert cs.family_match is True

    def test_error_case(self, report):
        cs = next(c for c in report.cases if c.case_id == "error_case")
        assert cs.exact_match is False
        assert cs.cer == pytest.approx(1.0)
        assert cs.top1_match is False
        assert cs.top5_match is False
        assert cs.family_match is False
        assert "TimeoutError" in cs.error

    def test_no_expected_case(self, report):
        cs = next(c for c in report.cases if c.case_id == "no_expected")
        # No expected PT → all PT metrics are None
        assert cs.exact_match is None
        assert cs.cer is None
        assert cs.top1_match is None
        assert cs.top5_match is None
        # No expected family → family_match is None
        assert cs.family_match is None

    def test_empty_out_case(self, report):
        cs = next(c for c in report.cases if c.case_id == "empty_out")
        assert cs.status == "no_results"
        assert cs.exact_match is False
        assert cs.cer == pytest.approx(1.0)
        assert cs.top1_match is False
        assert cs.top5_match is False
        assert cs.family_match is False

    # ── By-family breakdown ──────────────────────────────────────────

    def test_by_family_substitution(self, report):
        fs = report.by_family["substitution"]
        assert fs.n_cases == 3  # perfect, near_miss, empty_out
        assert fs.n_with_expected_pt == 3
        assert fs.n_top1 == 1  # perfect
        assert fs.n_top5 == 2  # perfect, near_miss
        assert fs.avg_cer == pytest.approx((0.0 + 0.2 + 1.0) / 3)
        assert fs.pass_rate_top1 == pytest.approx(1 / 3)
        assert fs.pass_rate_top5 == pytest.approx(2 / 3)

    def test_by_family_transposition(self, report):
        fs = report.by_family["transposition"]
        assert fs.n_cases == 1  # error_case
        assert fs.n_with_expected_pt == 1
        assert fs.n_top1 == 0
        assert fs.n_top5 == 0
        assert fs.avg_cer == pytest.approx(1.0)

    def test_by_family_unknown(self, report):
        # no_expected: no expected_family, predicted_family="" → "(unknown)"
        fs = report.by_family["(unknown)"]
        assert fs.n_cases == 1
        assert fs.n_with_expected_pt == 0

    # ── Serialization ────────────────────────────────────────────────

    def test_to_dict_round_trip(self, report):
        d = report.to_dict()
        assert d["total_cases"] == 5
        assert d["pass_rate_top1"] == pytest.approx(0.25)
        assert len(d["cases"]) == 5
        assert len(d["by_family"]) == 3
        # Verify it's JSON-serializable
        json.dumps(d)

    def test_to_markdown_contains_sections(self, report):
        md = report.to_markdown()
        assert "# Benchmark Scoring Report" in md
        assert "## Summary" in md
        assert "## Timing" in md
        assert "## Failure Breakdown" in md
        assert "## By Family" in md
        assert "## Per-case Results" in md
        assert "perfect" in md
        assert "near_miss" in md
        assert "error_case" in md

    # ── Edge cases ───────────────────────────────────────────────────

    def test_missing_result_treated_as_error(self):
        """Case with no matching result should be an error with CER=1.0."""
        cases = [
            BenchmarkCase(
                case_id="orphan", ciphertext="A", script="s.py",
                expected_plaintext="HELLO",
            ),
        ]
        report = score(cases, [])
        assert report.total_cases == 1
        assert report.n_error == 1
        cs = report.cases[0]
        assert cs.status == "error"
        assert cs.exact_match is False
        assert cs.cer == pytest.approx(1.0)

    def test_orphan_result_included(self):
        """Result with no matching case keeps status metrics."""
        results = [
            BenchmarkResult(case_id="extra", status="success", elapsed_s=0.5),
        ]
        report = score([], results)
        assert report.total_cases == 1
        assert report.n_success == 1
        cs = report.cases[0]
        assert cs.exact_match is None  # no case → no expected PT

    def test_empty_inputs(self):
        report = score([], [])
        assert report.total_cases == 0
        assert report.pass_rate_top1 == 0.0
        assert report.avg_time == 0.0

    def test_match_via_runner_match_rank(self):
        """Top-5 detection falls back to runner's match_rank when the
        expected PT is beyond the stored top-K candidates."""
        cases = [
            BenchmarkCase(
                case_id="deep", ciphertext="A", script="s.py",
                expected_plaintext="TARGET",
            ),
        ]
        results = [
            BenchmarkResult(
                case_id="deep",
                status="success",
                elapsed_s=0.1,
                # top_candidates does NOT contain "TARGET"
                top_candidates=[
                    CandidateResult(score=5.0, plaintext="WRONG", method="m"),
                ],
                predicted_plaintext="WRONG",
                # But match_rank says it was found at position 4
                match_rank=4,
            ),
        ]
        report = score(cases, results)
        cs = report.cases[0]
        assert cs.top1_match is False
        assert cs.top5_match is True  # rank 4 ≤ 5
        assert cs.match_rank == 4
