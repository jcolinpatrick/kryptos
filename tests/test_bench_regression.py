"""Tests for regression check infrastructure.

Verifies that:
- Eval suites load correctly and contain expected cases
- The benchmark Caesar script achieves 100% top-1 on tier0_eval
- The benchmark Caesar script achieves >= 90% top-5 on tier1_eval
- The regression script is executable and well-formed
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from bench.io import read_suite


# ── Suite file integrity ─────────────────────────────────────────────────


class TestEvalSuites:
    def test_tier0_eval_loads(self):
        cases = read_suite("bench/suites/tier0_eval.jsonl")
        assert len(cases) == 15

    def test_tier0_eval_all_have_expected_pt(self):
        cases = read_suite("bench/suites/tier0_eval.jsonl")
        for c in cases:
            assert c.expected_plaintext, f"{c.case_id} missing expected_plaintext"

    def test_tier0_eval_all_have_family(self):
        cases = read_suite("bench/suites/tier0_eval.jsonl")
        for c in cases:
            assert c.expected_family == "substitution"

    def test_tier0_eval_uses_benchmark_script(self):
        cases = read_suite("bench/suites/tier0_eval.jsonl")
        for c in cases:
            assert c.script == "scripts/examples/e_caesar_benchmark.py"

    def test_tier0_eval_case_ids_unique(self):
        cases = read_suite("bench/suites/tier0_eval.jsonl")
        ids = [c.case_id for c in cases]
        assert len(ids) == len(set(ids))

    def test_tier1_eval_loads(self):
        cases = read_suite("bench/suites/tier1_eval.jsonl")
        assert len(cases) == 10

    def test_tier1_eval_all_have_expected_pt(self):
        cases = read_suite("bench/suites/tier1_eval.jsonl")
        for c in cases:
            assert c.expected_plaintext, f"{c.case_id} missing expected_plaintext"

    def test_tier1_eval_uses_benchmark_script(self):
        cases = read_suite("bench/suites/tier1_eval.jsonl")
        for c in cases:
            assert c.script == "scripts/examples/e_caesar_benchmark.py"


# ── Benchmark pass-rate assertions ───────────────────────────────────────


class TestTier0PassRate:
    """Tier 0 must achieve 100% top-1 pass rate."""

    @pytest.fixture(scope="class")
    def tier0_report(self):
        from bench.runner import run_suite
        from bench.scorer import score

        cases = read_suite("bench/suites/tier0_eval.jsonl")
        results = run_suite(cases, top_k=5)
        return score(cases, results)

    def test_pass_rate_top1_is_100(self, tier0_report):
        assert tier0_report.pass_rate_top1 == 1.0

    def test_pass_rate_top5_is_100(self, tier0_report):
        assert tier0_report.pass_rate_top5 == 1.0

    def test_exact_match_rate_is_100(self, tier0_report):
        assert tier0_report.exact_match_rate == 1.0

    def test_no_errors(self, tier0_report):
        assert tier0_report.n_error == 0

    def test_no_no_results(self, tier0_report):
        assert tier0_report.n_no_results == 0

    def test_all_cases_rank_1(self, tier0_report):
        for cs in tier0_report.cases:
            assert cs.match_rank == 1, f"{cs.case_id} has rank {cs.match_rank}"


class TestTier1PassRate:
    """Tier 1 must achieve >= 90% top-5 pass rate."""

    @pytest.fixture(scope="class")
    def tier1_report(self):
        from bench.runner import run_suite
        from bench.scorer import score

        cases = read_suite("bench/suites/tier1_eval.jsonl")
        results = run_suite(cases, top_k=5)
        return score(cases, results)

    def test_pass_rate_top5_at_least_90(self, tier1_report):
        assert tier1_report.pass_rate_top5 >= 0.9

    def test_no_errors(self, tier1_report):
        assert tier1_report.n_error == 0


# ── Regression script integrity ──────────────────────────────────────────


class TestRegressionScript:
    def test_script_exists(self):
        assert Path("scripts/regression_check.sh").exists()

    def test_script_is_executable(self):
        p = Path("scripts/regression_check.sh")
        mode = p.stat().st_mode
        assert mode & stat.S_IXUSR, "Script is not executable"

    def test_script_has_shebang(self):
        p = Path("scripts/regression_check.sh")
        first_line = p.read_text().split("\n")[0]
        assert first_line.startswith("#!/"), "Missing shebang line"

    def test_script_references_eval_suites(self):
        content = Path("scripts/regression_check.sh").read_text()
        assert "tier0_eval.jsonl" in content
        assert "tier1_eval.jsonl" in content

    def test_script_checks_pass_rate(self):
        content = Path("scripts/regression_check.sh").read_text()
        assert "pass_rate_top1" in content
        assert "pass_rate_top5" in content


# ── Benchmark Caesar script ──────────────────────────────────────────────


class TestBenchmarkCaesarScript:
    def test_script_exists(self):
        assert Path("scripts/examples/e_caesar_benchmark.py").exists()

    def test_has_attack_function(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "bench_caesar",
            "scripts/examples/e_caesar_benchmark.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert hasattr(module, "attack")
        assert callable(module.attack)

    def test_returns_correct_format(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "bench_caesar_fmt",
            "scripts/examples/e_caesar_benchmark.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        results = module.attack("URYYBJBEYQ")
        assert isinstance(results, list)
        assert len(results) == 26  # all 26 shifts
        score, pt, method = results[0]
        assert isinstance(score, float)
        assert isinstance(pt, str)
        assert isinstance(method, str)

    def test_top1_is_correct_for_rot13(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "bench_caesar_rot13",
            "scripts/examples/e_caesar_benchmark.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        results = module.attack("URYYBJBEYQ")
        assert results[0][1] == "HELLOWORLD"
