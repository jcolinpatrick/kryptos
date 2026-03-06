"""Tests for the bench subsystem: schema, JSONL I/O, normalization."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Ensure project root is importable
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from bench.schema import (
    BenchmarkCase,
    BenchmarkResult,
    CandidateResult,
    normalize_text,
)
from bench.io import read_suite, write_results, read_results


# ── Normalization ────────────────────────────────────────────────────────────


class TestNormalization:
    def test_uppercase(self):
        assert normalize_text("hello") == "HELLO"

    def test_strip_spaces_default(self):
        assert normalize_text("HELLO WORLD") == "HELLOWORLD"

    def test_keep_only_az(self):
        assert normalize_text("H3LLO W0RLD!") == "HLLOWRLD"

    def test_empty_string(self):
        assert normalize_text("") == ""

    def test_mixed_case_with_numbers(self):
        assert normalize_text("Attack at Dawn 123") == "ATTACKATDAWN"

    def test_strip_spaces_false_still_removes_non_alpha(self):
        # strip_spaces=False skips the whitespace collapse step,
        # but the [^A-Z] filter still removes non-letters
        assert normalize_text("AB CD", strip_spaces=False) == "ABCD"

    def test_tabs_and_newlines(self):
        assert normalize_text("A\tB\nC") == "ABC"


# ── BenchmarkCase ────────────────────────────────────────────────────────────


class TestBenchmarkCase:
    def test_round_trip(self):
        case = BenchmarkCase(
            case_id="test1",
            ciphertext="URYYBJBEYQ",
            script="scripts/examples/e_caesar_standard.py",
            expected_plaintext="HELLOWORLD",
            expected_family="substitution",
            label="ROT-13 test",
        )
        d = case.to_dict()
        restored = BenchmarkCase.from_dict(d)
        assert restored.case_id == case.case_id
        assert restored.ciphertext == case.ciphertext
        assert restored.expected_plaintext == case.expected_plaintext
        assert restored.script == case.script

    def test_normalization_on_init(self):
        case = BenchmarkCase(
            case_id="test",
            ciphertext="hello world",
            script="test.py",
            expected_plaintext="foo bar",
        )
        assert case.ciphertext == "HELLOWORLD"
        assert case.expected_plaintext == "FOOBAR"

    def test_minimal_fields_omit_empty(self):
        case = BenchmarkCase(case_id="min", ciphertext="ABC", script="t.py")
        d = case.to_dict()
        assert "expected_plaintext" not in d
        assert "expected_key" not in d
        assert "params" not in d

    def test_from_dict_missing_optional_fields(self):
        data = {"case_id": "x", "ciphertext": "ABC", "script": "s.py"}
        case = BenchmarkCase.from_dict(data)
        assert case.expected_plaintext == ""
        assert case.params == {}

    def test_params_round_trip(self):
        case = BenchmarkCase(
            case_id="p",
            ciphertext="ABC",
            script="s.py",
            params={"shift": 3},
        )
        d = case.to_dict()
        assert d["params"] == {"shift": 3}
        restored = BenchmarkCase.from_dict(d)
        assert restored.params == {"shift": 3}


# ── BenchmarkResult ──────────────────────────────────────────────────────────


class TestBenchmarkResult:
    def test_round_trip(self):
        result = BenchmarkResult(
            case_id="test1",
            status="success",
            elapsed_s=1.234,
            n_candidates=25,
            top_candidates=[
                CandidateResult(score=3.0, plaintext="HELLO", method="ROT-13"),
            ],
            predicted_plaintext="HELLO",
            match_plaintext=True,
            match_rank=1,
        )
        d = result.to_dict()
        restored = BenchmarkResult.from_dict(d)
        assert restored.case_id == "test1"
        assert restored.status == "success"
        assert len(restored.top_candidates) == 1
        assert restored.top_candidates[0].plaintext == "HELLO"
        assert restored.match_plaintext is True
        assert restored.match_rank == 1

    def test_error_result(self):
        result = BenchmarkResult(
            case_id="err",
            status="error",
            error="ImportError: no module",
        )
        d = result.to_dict()
        assert d["status"] == "error"
        assert "ImportError" in d["error"]

    def test_elapsed_rounded(self):
        result = BenchmarkResult(
            case_id="t", status="success", elapsed_s=1.23456789
        )
        d = result.to_dict()
        assert d["elapsed_s"] == 1.2346


# ── JSONL I/O ────────────────────────────────────────────────────────────────


class TestJSONLIO:
    def test_read_suite_basic(self, tmp_path):
        suite = tmp_path / "suite.jsonl"
        lines = [
            {"case_id": "c1", "ciphertext": "ABC", "script": "s1.py"},
            {"case_id": "c2", "ciphertext": "DEF", "script": "s2.py",
             "expected_plaintext": "ABC"},
        ]
        suite.write_text("\n".join(json.dumps(l) for l in lines) + "\n")

        loaded = read_suite(suite)
        assert len(loaded) == 2
        assert loaded[0].case_id == "c1"
        assert loaded[1].expected_plaintext == "ABC"

    def test_skip_blank_lines(self, tmp_path):
        suite = tmp_path / "suite.jsonl"
        suite.write_text(
            '{"case_id":"c1","ciphertext":"A","script":"s.py"}\n'
            "\n"
            '{"case_id":"c2","ciphertext":"B","script":"s.py"}\n'
        )
        assert len(read_suite(suite)) == 2

    def test_skip_comment_lines(self, tmp_path):
        suite = tmp_path / "suite.jsonl"
        suite.write_text(
            "// comment\n"
            '{"case_id":"c1","ciphertext":"A","script":"s.py"}\n'
        )
        assert len(read_suite(suite)) == 1

    def test_invalid_json_raises(self, tmp_path):
        suite = tmp_path / "suite.jsonl"
        suite.write_text("not json\n")
        with pytest.raises(ValueError, match="invalid case"):
            read_suite(suite)

    def test_missing_required_field_raises(self, tmp_path):
        suite = tmp_path / "suite.jsonl"
        suite.write_text('{"case_id": "c1"}\n')  # missing ciphertext + script
        with pytest.raises(ValueError, match="invalid case"):
            read_suite(suite)

    def test_write_read_results_round_trip(self, tmp_path):
        results = [
            BenchmarkResult(case_id="c1", status="success", elapsed_s=1.0),
            BenchmarkResult(case_id="c2", status="error", error="boom"),
        ]
        out = tmp_path / "results.jsonl"
        write_results(results, out)

        loaded = read_results(out)
        assert len(loaded) == 2
        assert loaded[0].case_id == "c1"
        assert loaded[0].status == "success"
        assert loaded[1].error == "boom"

    def test_write_creates_parent_dirs(self, tmp_path):
        deep = tmp_path / "a" / "b" / "results.jsonl"
        write_results(
            [BenchmarkResult(case_id="x", status="success")], deep
        )
        assert deep.exists()
        assert len(read_results(deep)) == 1

    def test_smoke_suite_loads(self):
        """Verify the checked-in tier0_smoke.jsonl parses without error."""
        suite_path = _ROOT / "bench" / "suites" / "tier0_smoke.jsonl"
        cases = read_suite(suite_path)
        assert len(cases) == 10
        ids = {c.case_id for c in cases}
        assert "rot13_hello" in ids
        assert "k4_smoke" in ids
