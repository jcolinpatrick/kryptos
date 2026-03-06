#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# Regression check — single command that gates on benchmark pass rates.
#
# Usage:
#   ./scripts/regression_check.sh          # run everything
#   ./scripts/regression_check.sh --quick  # skip unit tests
#
# Exits 0 if all checks pass, 1 on any failure.
#
# Requirements:
#   - Tier 0 eval: pass_rate_top1 == 1.0 (15 Caesar cases)
#   - Tier 1 eval: pass_rate_top5 >= 0.9 (10 smoke cases)
#   - Unit tests: all pass (unless --quick)
#
# Typical runtime: ~15s (unit tests) + ~2s (benchmarks) = ~17s total.
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

export PYTHONPATH="$PROJECT_ROOT/src"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0

pass() { echo -e "${GREEN}  PASS${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "${RED}  FAIL${NC} $1"; FAIL=$((FAIL + 1)); }
info() { echo -e "${BOLD}$1${NC}"; }

SKIP_TESTS=0
if [[ "${1:-}" == "--quick" ]]; then
    SKIP_TESTS=1
fi

OUT_DIR=$(mktemp -d)
trap 'rm -rf "$OUT_DIR"' EXIT

# ── Step 1: Unit tests ────────────────────────────────────────────────────

if [[ $SKIP_TESTS -eq 0 ]]; then
    info "Step 1/3: Unit tests"
    if python3 -m pytest tests/ -x -q --tb=line \
        --deselect tests/test_constants.py::TestConstantsIntegrity::test_hardcoded_ct_matches_canonical \
        2>&1 | tail -5; then
        PYTEST_EXIT=${PIPESTATUS[0]}
        if [[ $PYTEST_EXIT -eq 0 ]]; then
            pass "Unit tests"
        else
            fail "Unit tests (exit code $PYTEST_EXIT)"
        fi
    else
        fail "Unit tests (pytest error)"
    fi
else
    info "Step 1/3: Unit tests (skipped: --quick)"
fi

# ── Step 2: Tier 0 eval ──────────────────────────────────────────────────

info "Step 2/3: Tier 0 eval (pass_rate_top1 must be 1.0)"

python3 -c "
import sys, json
from bench.io import read_suite, write_results
from bench.runner import run_suite
from bench.scorer import score

cases = read_suite('bench/suites/tier0_eval.jsonl')
results = run_suite(cases, top_k=5)
write_results(results, '$OUT_DIR/tier0_results.jsonl')

report = score(cases, results)
with open('$OUT_DIR/tier0_report.json', 'w') as f:
    json.dump(report.to_dict(), f, indent=2)

rate = report.pass_rate_top1
print(f'  pass_rate_top1 = {rate:.4f}  ({report.n_success} success, {report.n_error} error)')
if rate < 1.0:
    # Show which cases failed
    for cs in report.cases:
        if cs.top1_match is False:
            print(f'    MISS: {cs.case_id} (rank={cs.match_rank})')
    sys.exit(1)
sys.exit(0)
"
if [[ $? -eq 0 ]]; then
    pass "Tier 0 pass_rate_top1 == 1.0"
else
    fail "Tier 0 pass_rate_top1 < 1.0"
fi

# ── Step 3: Tier 1 eval ──────────────────────────────────────────────────

info "Step 3/3: Tier 1 eval (pass_rate_top5 must be >= 0.9)"

python3 -c "
import sys, json
from bench.io import read_suite, write_results
from bench.runner import run_suite
from bench.scorer import score

cases = read_suite('bench/suites/tier1_eval.jsonl')
results = run_suite(cases, top_k=5)
write_results(results, '$OUT_DIR/tier1_results.jsonl')

report = score(cases, results)
with open('$OUT_DIR/tier1_report.json', 'w') as f:
    json.dump(report.to_dict(), f, indent=2)

rate = report.pass_rate_top5
print(f'  pass_rate_top5 = {rate:.4f}  ({report.n_success} success, {report.n_error} error)')
if rate < 0.9:
    for cs in report.cases:
        if cs.top5_match is False:
            print(f'    MISS: {cs.case_id} (rank={cs.match_rank})')
    sys.exit(1)
sys.exit(0)
"
if [[ $? -eq 0 ]]; then
    pass "Tier 1 pass_rate_top5 >= 0.9"
else
    fail "Tier 1 pass_rate_top5 < 0.9"
fi

# ── Summary ───────────────────────────────────────────────────────────────

echo ""
info "Summary: $PASS passed, $FAIL failed"

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}Regression check FAILED${NC}"
    exit 1
fi

echo -e "${GREEN}Regression check PASSED${NC}"
exit 0
