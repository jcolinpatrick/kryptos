"""Benchmark scorer — per-case and aggregate metrics from suite + results.

Loads a suite (expected values) and results (predictions), joins by
``case_id``, and computes:

Per-case:
  - exact_match (normalized plaintext comparison)
  - CER (character error rate via Levenshtein distance)
  - top-1 / top-5 success (expected PT found within top-K candidates)
  - family accuracy (predicted vs expected cipher family)

Aggregate:
  - pass_rate_top1, pass_rate_top5 (overall and by family)
  - average / p50 / p90 timing
  - failure breakdown (errors, timeouts, empty outputs)

WER is intentionally omitted: ``normalize_text()`` strips all non-A-Z
characters (including spaces), making word boundaries unrecoverable.
If a future normalization mode preserves spaces, WER can be added here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from bench.schema import BenchmarkCase, BenchmarkResult, normalize_text


# ── Edit distance ────────────────────────────────────────────────────────────


def _levenshtein(a: str, b: str) -> int:
    """Minimum edit distance (insert / delete / substitute)."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for ca in a:
        curr = [prev[0] + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr.append(min(
                curr[j] + 1,        # insert
                prev[j + 1] + 1,    # delete
                prev[j] + cost,     # substitute
            ))
        prev = curr
    return prev[-1]


def character_error_rate(predicted: str, expected: str) -> float:
    """CER = levenshtein(predicted, expected) / len(expected).

    Both strings should already be normalized.
    Returns 0.0 when both are empty, 1.0 when expected is empty but
    predicted is not.
    """
    if not expected:
        return 0.0 if not predicted else 1.0
    return _levenshtein(predicted, expected) / len(expected)


# ── Percentile helper ────────────────────────────────────────────────────────


def _percentile(sorted_vals: List[float], p: float) -> float:
    """*p*-th percentile (0–100) via linear interpolation."""
    if not sorted_vals:
        return 0.0
    n = len(sorted_vals)
    k = (p / 100.0) * (n - 1)
    lo = int(k)
    hi = min(lo + 1, n - 1)
    frac = k - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac


# ── Per-case scoring ─────────────────────────────────────────────────────────


@dataclass
class CaseScore:
    """Metrics for a single benchmark case."""

    case_id: str
    status: str
    elapsed_s: float
    error: str = ""

    # Plaintext matching (None when suite has no expected_plaintext)
    exact_match: Optional[bool] = None
    cer: Optional[float] = None
    top1_match: Optional[bool] = None
    top5_match: Optional[bool] = None
    match_rank: int = -1  # 1-indexed, -1 when N/A or not found

    # Family matching (None when suite has no expected_family)
    family_match: Optional[bool] = None
    expected_family: str = ""
    predicted_family: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "case_id": self.case_id,
            "status": self.status,
            "elapsed_s": round(self.elapsed_s, 4),
        }
        if self.error:
            d["error"] = self.error
        if self.exact_match is not None:
            d["exact_match"] = self.exact_match
        if self.cer is not None:
            d["cer"] = round(self.cer, 4)
        if self.top1_match is not None:
            d["top1_match"] = self.top1_match
        if self.top5_match is not None:
            d["top5_match"] = self.top5_match
        if self.match_rank >= 0:
            d["match_rank"] = self.match_rank
        if self.family_match is not None:
            d["family_match"] = self.family_match
        if self.expected_family:
            d["expected_family"] = self.expected_family
        if self.predicted_family:
            d["predicted_family"] = self.predicted_family
        return d


# ── Family-level aggregation ─────────────────────────────────────────────────


@dataclass
class FamilyStats:
    """Aggregate stats for one cipher family."""

    family: str
    n_cases: int = 0
    n_with_expected_pt: int = 0
    n_top1: int = 0
    n_top5: int = 0
    n_exact: int = 0
    total_cer: float = 0.0

    @property
    def pass_rate_top1(self) -> float:
        return self.n_top1 / self.n_with_expected_pt if self.n_with_expected_pt else 0.0

    @property
    def pass_rate_top5(self) -> float:
        return self.n_top5 / self.n_with_expected_pt if self.n_with_expected_pt else 0.0

    @property
    def avg_cer(self) -> float:
        return self.total_cer / self.n_with_expected_pt if self.n_with_expected_pt else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "family": self.family,
            "n_cases": self.n_cases,
            "n_with_expected_pt": self.n_with_expected_pt,
            "pass_rate_top1": round(self.pass_rate_top1, 4),
            "pass_rate_top5": round(self.pass_rate_top5, 4),
            "avg_cer": round(self.avg_cer, 4),
        }


# ── Full report ──────────────────────────────────────────────────────────────


@dataclass
class ScoringReport:
    """Complete benchmark scoring report."""

    # Counts
    total_cases: int = 0
    cases_with_expected_pt: int = 0
    cases_with_expected_family: int = 0

    # Rates (over evaluable cases)
    pass_rate_top1: float = 0.0
    pass_rate_top5: float = 0.0
    exact_match_rate: float = 0.0
    avg_cer: float = 0.0
    family_accuracy: float = 0.0

    # Timing
    avg_time: float = 0.0
    p50_time: float = 0.0
    p90_time: float = 0.0

    # Failure breakdown
    n_success: int = 0
    n_error: int = 0
    n_no_results: int = 0
    n_timeout: int = 0  # subset of n_error where message contains "timeout"

    # Groupings
    by_family: Dict[str, FamilyStats] = field(default_factory=dict)

    # Per-case detail
    cases: List[CaseScore] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_cases": self.total_cases,
            "cases_with_expected_pt": self.cases_with_expected_pt,
            "cases_with_expected_family": self.cases_with_expected_family,
            "pass_rate_top1": round(self.pass_rate_top1, 4),
            "pass_rate_top5": round(self.pass_rate_top5, 4),
            "exact_match_rate": round(self.exact_match_rate, 4),
            "avg_cer": round(self.avg_cer, 4),
            "family_accuracy": round(self.family_accuracy, 4),
            "avg_time": round(self.avg_time, 4),
            "p50_time": round(self.p50_time, 4),
            "p90_time": round(self.p90_time, 4),
            "n_success": self.n_success,
            "n_error": self.n_error,
            "n_no_results": self.n_no_results,
            "n_timeout": self.n_timeout,
            "by_family": {k: v.to_dict() for k, v in sorted(self.by_family.items())},
            "cases": [c.to_dict() for c in self.cases],
        }

    def to_markdown(self) -> str:
        lines = [
            "# Benchmark Scoring Report",
            "",
            "## Summary",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| Total cases | {self.total_cases} |",
            f"| Cases with expected PT | {self.cases_with_expected_pt} |",
            f"| Cases with expected family | {self.cases_with_expected_family} |",
            f"| Pass rate (top-1) | {self.pass_rate_top1:.1%} |",
            f"| Pass rate (top-5) | {self.pass_rate_top5:.1%} |",
            f"| Exact match rate | {self.exact_match_rate:.1%} |",
            f"| Average CER | {self.avg_cer:.4f} |",
            f"| Family accuracy | {self.family_accuracy:.1%} |",
            "",
            "## Timing",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| Average | {self.avg_time:.4f}s |",
            f"| P50 | {self.p50_time:.4f}s |",
            f"| P90 | {self.p90_time:.4f}s |",
            "",
            "## Failure Breakdown",
            "",
            "| Status | Count |",
            "|---|---|",
            f"| Success | {self.n_success} |",
            f"| Error | {self.n_error} |",
            f"| No results | {self.n_no_results} |",
            f"| Timeout | {self.n_timeout} |",
        ]

        if self.by_family:
            lines.extend([
                "",
                "## By Family",
                "",
                "| Family | Cases | Top-1 | Top-5 | Avg CER |",
                "|---|---|---|---|---|",
            ])
            for fam in sorted(self.by_family):
                s = self.by_family[fam]
                lines.append(
                    f"| {s.family} | {s.n_cases} "
                    f"| {s.pass_rate_top1:.1%} "
                    f"| {s.pass_rate_top5:.1%} "
                    f"| {s.avg_cer:.4f} |"
                )

        lines.extend([
            "",
            "## Per-case Results",
            "",
            "| Case | Status | Exact | CER | Top-1 | Top-5 | Time |",
            "|---|---|---|---|---|---|---|",
        ])
        _yn = {True: "Yes", False: "No", None: "-"}
        for cs in self.cases:
            cer_s = f"{cs.cer:.4f}" if cs.cer is not None else "-"
            lines.append(
                f"| {cs.case_id} | {cs.status} "
                f"| {_yn[cs.exact_match]} | {cer_s} "
                f"| {_yn[cs.top1_match]} | {_yn[cs.top5_match]} "
                f"| {cs.elapsed_s:.4f}s |"
            )

        lines.append("")
        return "\n".join(lines)


# ── Main scoring function ───────────────────────────────────────────────────


def score(
    cases: List[BenchmarkCase],
    results: List[BenchmarkResult],
) -> ScoringReport:
    """Score benchmark results against expected values from the suite.

    Joins *cases* and *results* by ``case_id``.  Cases without a
    matching result are recorded as errors.  Results without a matching
    case are included (status metrics only, no accuracy).
    """
    result_map: Dict[str, BenchmarkResult] = {r.case_id: r for r in results}
    case_map: Dict[str, BenchmarkCase] = {c.case_id: c for c in cases}

    # Stable ordering: suite cases first, then orphan results
    ordered_ids: List[str] = [c.case_id for c in cases]
    for r in results:
        if r.case_id not in case_map:
            ordered_ids.append(r.case_id)

    report = ScoringReport(total_cases=len(ordered_ids))

    all_times: List[float] = []
    n_top1 = n_top5 = n_exact = n_family_correct = 0
    total_cer = 0.0
    n_cer = 0

    for cid in ordered_ids:
        case = case_map.get(cid)
        result = result_map.get(cid)

        # ── Missing result → synthetic error ─────────────────────────
        if result is None:
            cs = CaseScore(case_id=cid, status="error", elapsed_s=0.0,
                           error="No result found for this case")
            if case and case.expected_plaintext:
                cs.exact_match = False
                cs.cer = 1.0
                cs.top1_match = False
                cs.top5_match = False
                report.cases_with_expected_pt += 1
                total_cer += 1.0
                n_cer += 1
            if case and case.expected_family:
                cs.expected_family = case.expected_family
                cs.family_match = False
                report.cases_with_expected_family += 1
            report.n_error += 1
            report.cases.append(cs)
            continue

        # ── We have a result ─────────────────────────────────────────
        cs = CaseScore(
            case_id=cid,
            status=result.status,
            elapsed_s=result.elapsed_s,
            error=result.error,
            predicted_family=result.predicted_family,
        )
        all_times.append(result.elapsed_s)

        # Status counters
        if result.status == "success":
            report.n_success += 1
        elif result.status == "error":
            report.n_error += 1
            if "timeout" in result.error.lower():
                report.n_timeout += 1
        elif result.status == "no_results":
            report.n_no_results += 1

        # ── Plaintext accuracy ───────────────────────────────────────
        expected_pt = case.expected_plaintext if case else ""
        if expected_pt:
            report.cases_with_expected_pt += 1
            norm_expected = normalize_text(expected_pt)
            norm_predicted = normalize_text(result.predicted_plaintext)

            # Exact match (top-1 prediction vs ground truth)
            cs.exact_match = norm_predicted == norm_expected
            if cs.exact_match:
                n_exact += 1

            # CER
            cs.cer = character_error_rate(norm_predicted, norm_expected)
            total_cer += cs.cer
            n_cer += 1

            # Top-K: scan stored candidates for the expected text
            rank = -1
            if result.top_candidates:
                for i, cand in enumerate(result.top_candidates):
                    if normalize_text(cand.plaintext) == norm_expected:
                        rank = i + 1
                        break

            # Fall back to runner's match_rank (covers ranks beyond
            # stored top-K)
            if rank < 0 and result.match_rank >= 1:
                rank = result.match_rank

            cs.top1_match = rank == 1
            cs.top5_match = 1 <= rank <= 5
            cs.match_rank = rank
            if cs.top1_match:
                n_top1 += 1
            if cs.top5_match:
                n_top5 += 1

        # ── Family accuracy ──────────────────────────────────────────
        expected_fam = case.expected_family if case else ""
        if expected_fam:
            report.cases_with_expected_family += 1
            cs.expected_family = expected_fam
            cs.family_match = (
                result.predicted_family != ""
                and result.predicted_family.strip().lower()
                    == expected_fam.strip().lower()
            )
            if cs.family_match:
                n_family_correct += 1

        # ── By-family grouping ───────────────────────────────────────
        fam_key = expected_fam or result.predicted_family or "(unknown)"
        if fam_key not in report.by_family:
            report.by_family[fam_key] = FamilyStats(family=fam_key)
        fs = report.by_family[fam_key]
        fs.n_cases += 1
        if expected_pt:
            fs.n_with_expected_pt += 1
            if cs.top1_match:
                fs.n_top1 += 1
            if cs.top5_match:
                fs.n_top5 += 1
            if cs.exact_match:
                fs.n_exact += 1
            if cs.cer is not None:
                fs.total_cer += cs.cer

        report.cases.append(cs)

    # ── Aggregate rates ──────────────────────────────────────────────────
    n_pt = report.cases_with_expected_pt
    if n_pt:
        report.pass_rate_top1 = n_top1 / n_pt
        report.pass_rate_top5 = n_top5 / n_pt
        report.exact_match_rate = n_exact / n_pt
    if n_cer:
        report.avg_cer = total_cer / n_cer
    if report.cases_with_expected_family:
        report.family_accuracy = n_family_correct / report.cases_with_expected_family

    # ── Timing ───────────────────────────────────────────────────────────
    if all_times:
        report.avg_time = sum(all_times) / len(all_times)
        st = sorted(all_times)
        report.p50_time = _percentile(st, 50)
        report.p90_time = _percentile(st, 90)

    return report
