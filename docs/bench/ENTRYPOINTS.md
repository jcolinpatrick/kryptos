# Execution Entrypoints Reference

How ciphertext analysis runs end-to-end: entrypoints, parameter passing, scoring, and output.

---

## Entrypoint 1: CLI (`python -m kryptos`)

**Files:** `src/kryptos/__main__.py` (L1-5) → `src/kryptos/cli/main.py` (L177-238)

| Subcommand | What it does |
|---|---|
| `doctor` | Environment health check |
| `sweep <config.toml> [--workers N]` | Load sweep config — **stub only** (L31-33: prints message, never runs SweepRunner) |
| `reproduce <manifest.json>` | Reproduce a prior run from manifest |
| `novelty generate` | Generate hypotheses → `db/novelty_ledger.sqlite` |
| `novelty triage [--limit N]` | Triage pending hypotheses |
| `novelty status` | Show hypothesis counts and RQ coverage |
| `report <db.sqlite> top [--limit N] [--min-score N]` | Show top results from a sweep DB |

```bash
PYTHONPATH=src python -m kryptos doctor
PYTHONPATH=src python -m kryptos novelty status
PYTHONPATH=src python -m kryptos report db/sweep.sqlite top --limit 20
```

**Gap:** No "run one ciphertext" command. Ciphertext is always `CT` from `constants.py`.

---

## Entrypoint 2: Script Dispatcher (`run_attack.py`)

**File:** `run_attack.py` (L1-362, project root)

Discovers scripts under `scripts/`, filters by family/status, and runs them. Scripts with a standard `attack()` function are called directly; legacy scripts without `attack()` are invoked as subprocesses.

| Mode | What it does |
|---|---|
| `--list [--verbose] [--family F] [--status S]` | List scripts with metadata |
| `--run --family F --status S [--min-score N]` | Run matching scripts |
| `--run --id e_script_name` | Run a single script by ID |
| `--manifest [-o file.json]` | Generate manifest JSON |
| `--reconcile` | Check header vs exhaustion log mismatches |
| `--exhaustion-summary` | Summarize exhaustion log |

```bash
PYTHONPATH=src python run_attack.py --list --verbose
PYTHONPATH=src python run_attack.py --run --family grille --status active
PYTHONPATH=src python run_attack.py --run --id e_caesar_standard --verbose
```

**How it invokes scripts** (L90-113):
1. `load_attack_module()` dynamically imports the script via `importlib`
2. Calls `module.attack(CT, **params)` if `attack` attribute exists
3. Falls back to `run_legacy_subprocess()` (L116-137) for scripts without `attack()`

**Output:** Prints results to stdout. Updates `exhaustion_log.json` via `record_run()`.

**Gap:** Ciphertext is always `CT` from `constants.py` (L157, L202). No way to pass arbitrary ciphertext.

---

## Entrypoint 3: Agent Campaigns (`kryptosbot/solve.py`)

**File:** `kryptosbot/solve.py`

Multi-agent campaign runner using Claude Agent SDK. Requires `claude-agent-sdk` and API tokens.

| Mode | What it does |
|---|---|
| default (no args) | Blitz: 6 parallel agents |
| `compute` | Free local CPU compute strategies |
| `run <strategy>` | Run a single named strategy |
| `list` | Show all available strategies |
| `report` | Show campaign results |

Not suitable for benchmarking (requires API tokens, non-deterministic).

---

## Entrypoint 4: Direct Python API (Integration Point)

This is the real integration point for benchmarking and programmatic use.

### Attack Contract

Every standard attack script exports:

```python
def attack(ciphertext: str, **params) -> list[tuple[float, str, str]]:
    """Returns [(score, plaintext, method_description), ...] sorted by score desc."""
```

**Reference implementation:** `scripts/examples/e_caesar_standard.py` (L39-55)

### Scoring Functions

**Anchored scoring** — cribs at fixed positions 21-33, 63-73:

```python
# src/kryptos/kernel/scoring/aggregate.py L87-139
from kryptos.kernel.scoring.aggregate import score_candidate, ScoreBreakdown

sb: ScoreBreakdown = score_candidate(plaintext)
# sb.crib_score       — 0-24 (primary signal)
# sb.ene_score        — 0-13 (EASTNORTHEAST match)
# sb.bc_score         — 0-11 (BERLINCLOCK match)
# sb.ic_value         — Index of coincidence
# sb.bean_passed      — Bean constraint check (requires bean_result arg)
# sb.crib_classification — "noise"|"interesting"|"signal"|"breakthrough"
# sb.summary          — Human-readable one-liner
```

**Free scoring** — cribs searched at any position (for scrambled-CT work):

```python
# src/kryptos/kernel/scoring/aggregate.py L212-275
from kryptos.kernel.scoring.aggregate import score_candidate_free, FreeScoreBreakdown

fsb: FreeScoreBreakdown = score_candidate_free(plaintext)
# fsb.ene_found, fsb.bc_found, fsb.both_found
# fsb.canonical_positions — True if found at standard positions
```

**Full evaluation pipeline** (adds keystream + Bean checking):

```python
# src/kryptos/pipeline/evaluation.py L44-77
from kryptos.pipeline.evaluation import evaluate_candidate, EvaluationResult

result: EvaluationResult = evaluate_candidate(
    plaintext,
    keystream=None,        # optional List[int]
    bean_result=None,      # optional BeanResult
    ngram_scorer=None,     # optional NgramScorer
    metadata=None,         # optional dict
)
# result.score         — ScoreBreakdown
# result.is_breakthrough
# result.summary
```

### N-gram Scorer

```python
# src/kryptos/kernel/scoring/ngram.py L63-85
from kryptos.kernel.scoring.ngram import NgramScorer, get_default_scorer

scorer = get_default_scorer()           # loads data/english_quadgrams.json
scorer = NgramScorer.from_file("data/english_quadgrams.json")

total = scorer.score("THEQUICKBROWNFOX")       # total log-prob
per_char = scorer.score_per_char("THEQUICKBROWNFOX")  # avg per char
# Scores above -4.5/char → strong English; below -6.0 → likely wrong
```

### Constants

```python
# src/kryptos/kernel/constants.py
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, N_CRIBS
# CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
# CT_LEN = 97
# CRIB_DICT = {21: "E", 22: "A", ..., 33: "T", 63: "B", ..., 73: "K"}
# N_CRIBS = 24
```

---

## Scoring Pipeline Chain

```
attack(ciphertext) → [(score, plaintext, method), ...]
                          ↓
                    score_candidate(plaintext)          # aggregate.py L87
                          ↓
              ┌───────────┼───────────┐
              ↓           ↓           ↓
    score_cribs_detailed  ic()    NgramScorer.score()   # crib_score.py, ic.py, ngram.py
              ↓           ↓           ↓
              └───────────┼───────────┘
                          ↓
                    ScoreBreakdown                      # dataclass with .summary, .to_dict()
```

For the full pipeline path (with Bean constraints and keystream):

```
evaluate_candidate(plaintext, keystream, bean_result)   # evaluation.py L44
    ↓
    verify_bean(keystream)                               # bean.py
    ↓
    score_candidate(plaintext, bean_result, ngram_scorer) # aggregate.py L87
    ↓
    EvaluationResult(plaintext, score, ...)
```

---

## Output Locations

| Entrypoint | Output |
|---|---|
| CLI (`-m kryptos`) | stdout, `db/` SQLite |
| `run_attack.py` | stdout, `exhaustion_log.json` |
| `kryptosbot/solve.py` | `results/campaigns/`, `results/compute/` |
| Direct API | Return values (in-process) |
| Individual scripts | `results/<experiment_id>.json` or `results/<experiment_id>/` |
| `bench/cli.py run` | `results/bench/results.jsonl` (JSONL) |

---

## Benchmark Wrapper

For a single-command "run one ciphertext" interface, use `bench/run_single.py`:

```bash
# Run an attack script against default K4 ciphertext
PYTHONPATH=src python bench/run_single.py --script scripts/examples/e_caesar_standard.py

# Run against custom ciphertext
PYTHONPATH=src python bench/run_single.py --script scripts/examples/e_caesar_standard.py --ct ZICVTWQNGRZGVTWAVZHCQYGLMGJ

# Score a known plaintext (eval-only mode)
PYTHONPATH=src python bench/run_single.py --eval-only --pt WEAREDISCOVEREDSAVEYOURSELF
```

Output is JSON to stdout, machine-readable.

---

## Benchmark Suite Runner

Run a full suite of test cases against attack scripts, collect top-K candidates and metadata, and write structured results.

### Suite format (JSONL)

Each line in a suite file is a JSON object:

```json
{"case_id": "rot13_hello", "ciphertext": "URYYBJBEYQ", "script": "scripts/examples/e_caesar_standard.py", "expected_plaintext": "HELLOWORLD", "expected_family": "substitution", "label": "ROT-13 test"}
```

Required fields: `case_id`, `ciphertext`, `script`. Optional: `expected_plaintext`, `expected_key`, `expected_family`, `label`, `params`.

Blank lines and `//` comment lines are skipped.

### Running suites

```bash
# Run the smoke suite (sequential)
PYTHONPATH=src python bench/cli.py run --suite bench/suites/tier0_smoke.jsonl

# Run with 4 parallel workers
PYTHONPATH=src python bench/cli.py run --suite bench/suites/tier0_smoke.jsonl --parallel 4

# Custom output directory and top-K
PYTHONPATH=src python bench/cli.py run --suite bench/suites/tier0_smoke.jsonl --top-k 10 --out results/bench/

# Via the kryptos CLI
PYTHONPATH=src python -m kryptos bench run --suite bench/suites/tier0_smoke.jsonl --parallel 4
```

### Output format (JSONL)

Results are written to `<out>/results.jsonl`, one JSON object per line:

```json
{
  "case_id": "rot13_hello",
  "status": "success",
  "elapsed_s": 0.001,
  "n_candidates": 25,
  "top_candidates": [{"score": 3.0, "plaintext": "...", "method": "Caesar ROT-2", "canonical_score": {...}}],
  "predicted_plaintext": "...",
  "predicted_family": "substitution",
  "match_plaintext": true,
  "match_rank": 13,
  "error": "",
  "script": "scripts/examples/e_caesar_standard.py",
  "ciphertext": "URYYBJBEYQ"
}
```

Status values: `"success"`, `"error"`, `"no_results"`. Errors are captured as structured results (never silently dropped).

### Regression Checks

A single command gates on benchmark pass rates:

```bash
# Full check: unit tests + Tier 0 + Tier 1 (~50s)
./scripts/regression_check.sh

# Quick check: benchmarks only, skip unit tests (~2s)
./scripts/regression_check.sh --quick
```

**Pass criteria:**
- Unit tests: all pass (1 known-failing test deselected)
- Tier 0: `pass_rate_top1 == 1.0` (15 Caesar eval cases)
- Tier 1: `pass_rate_top5 >= 0.9` (10 smoke cases)

The eval suites use `scripts/examples/e_caesar_benchmark.py`, which scores candidates by quadgram fitness (English-likeness) rather than K4-specific crib matching, ensuring the correct plaintext reliably ranks #1.

### Architecture

```
bench/
├── __init__.py
├── schema.py       — BenchmarkCase, BenchmarkResult, CandidateResult, normalize_text()
├── io.py           — read_suite(), write_results(), read_results()
├── runner.py       — run_suite() with multiprocessing.Pool
├── scorer.py       — Per-case and aggregate metrics, ScoringReport
├── validator.py    — Post-selection plausibility validation
├── segmenter.py    — Sliding-window IOC analysis, mixed-input detection
├── generate.py     — Deterministic suite generator (Tiers 0–3)
├── cli.py          — CLI entry point (run, score, generate)
├── run_single.py   — Single-script / eval-only wrapper
├── samples/
│   └── mixed_vig_qwerty.json  — Sample mixed-input output
└── suites/
    ├── tier0_smoke.jsonl       — 10-case smoke suite (K4-scored Caesar)
    ├── tier0_eval.jsonl        — 15-case eval suite (quadgram-scored Caesar)
    ├── tier1_eval.jsonl        — 10-case eval suite (quadgram-scored Caesar)
    ├── tier0_generated.jsonl   — Generated Tier 0 (via bench generate)
    ├── tier1_generated.jsonl   — Generated Tier 1
    ├── tier2_generated.jsonl   — Generated Tier 2
    └── tier3_generated.jsonl   — Generated Tier 3
```
