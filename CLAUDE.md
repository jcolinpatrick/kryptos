# STOP. DO NOT SKIP THIS SECTION.

You MUST complete ALL of these steps before executing any task:

1. Read this entire CLAUDE.md
2. Read MEMORY.md — the decision-support index (paradigm, constants, what's open).
   MEMORY.md is loaded automatically; individual topic files in `memory/` are on-demand — read only when relevant to the current task.
3. Read `memory/elimination_ledger.md` — the complete elimination record by attack family
4. If the user's request matches ANYTHING already disproved or tested,
   TELL THE USER and do NOT run it again
5. Search scripts/ for existing tools — do NOT write new code if a script exists
   `run_attack.py --list --verbose | grep KEYWORD`
6. Check results/ for prior output matching the planned parameters
   `ls results/ | grep KEYWORD` or search `exhaustion_log.json`

If you skip these steps and re-test an eliminated hypothesis, you are 
wasting 28 CPU cores and burning API tokens for zero value.

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

This repo has one purpose: determine the **true plaintext** and the **full encryption method** of **Kryptos K4**.

**Contents:** [K4 Quick Reference](#the-k4-problem--quick-reference) · [Dev Setup & Commands](#development-setup--commands) · [Architecture](#architecture) · [Scores](#interpreting-scores) · [Gotchas](#key-gotchas) · [Truth Taxonomy](#truth-taxonomy-mandatory) · [Reference Docs](#reference-documents) · [Multi-Agent](#multi-agent-mode--solve-k4)

---

## The K4 Problem — Quick Reference

**Kryptos** is a sculpture at CIA headquarters containing four encrypted messages (K1–K4). K1–K3 were solved in 1999. **K4 (97 characters) has been unsolved since 1990.**

**Carved text (SCRAMBLED — NOT the real ciphertext):** `OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR`

**Known plaintext (0-indexed positions in carved text):**
- Positions 21–33: `EASTNORTHEAST`
- Positions 63–73: `BERLINCLOCK`

**Two systems CONFIRMED** [PRIMARY SOURCE]: Sanborn dedication speech + Scheidt (Wired). No single-layer classical cipher works on the carved text (exhaustively tested). 880+ experiments, 669B+ configs, ZERO breakthroughs.

**→ Volatile research state lives in MEMORY.md** (read at session start per step 2 above): current paradigm, full elimination list (22 categories), confirmed findings, open attack surface, key constants, and user policies. CLAUDE.md has the durable technical setup; MEMORY.md has the evolving cryptanalytic state. See [`reports/final_synthesis.md`](reports/final_synthesis.md) for the elimination landscape.

---

## Development Setup & Commands

**Python 3.11+** required (uses `tomllib` from stdlib; dev environment runs 3.12.3). **No external runtime dependencies** — stdlib only. `pytest` is the only dev dependency. No `pyproject.toml` or `setup.py` — `pip install -e .` will not work. All commands require `PYTHONPATH=src`. **Repo:** `github.com/jcolinpatrick/kryptos`.

**Common imports** (all require `PYTHONPATH=src`):
```python
from kryptos.kernel.constants import CT, CRIB_POSITIONS, BEAN_EQ, BEAN_INEQ
from kryptos.kernel.alphabet import AZ, KA, keyword_mixed_alphabet
from kryptos.kernel.text import sanitize, text_to_nums, nums_to_text
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free
from kryptos.kernel.transforms.vigenere import decrypt_vigenere, decrypt_beaufort
```

A `venv/` exists (gitignored) for non-core work. Activate with `source venv/bin/activate`. Packages: `numpy`, `pymupdf` (PDF), `jinja2` (site builder), `fastapi`, `uvicorn`, `python-dotenv`, `anthropic` (API server), `agent-sdk` (KryptosBot SDK). Core code uses stdlib only.

**Code style:** No linter or formatter configured. No enforced style conventions beyond stdlib-only for core code.

**Git workflow:** Development happens directly on `main`. No branch naming conventions or PR process — this is a solo research project with computational partners.

```bash
# Run all tests
PYTHONPATH=src pytest tests/

# Run a single test file or test
PYTHONPATH=src pytest tests/test_transforms.py
PYTHONPATH=src pytest tests/test_transforms.py::TestVigenereFamily::test_text_roundtrip_vig -v

# Run an experiment script (always use -u for unbuffered output)
PYTHONPATH=src python3 -u scripts/_uncategorized/e_nsa_01_interval7.py

# Dispatch runner: list, run by family/status, reconcile
PYTHONPATH=src python3 run_attack.py --list --verbose
PYTHONPATH=src python3 run_attack.py --run --family grille --status active
PYTHONPATH=src python3 run_attack.py --reconcile

# Benchmark framework
PYTHONPATH=src python3 bench/cli.py run --suite bench/suites/tier0_smoke.jsonl
PYTHONPATH=src python3 bench/cli.py score --suite bench/suites/tier0_smoke.jsonl --results results/bench/results.jsonl
PYTHONPATH=src python3 bench/cli.py generate --tiers 0,1,2,3 --n 25 --seed 42 --out bench/suites/

# Environment health check
PYTHONPATH=src python3 -m kryptos doctor

# CLI: sweep, reproduce, novelty, report
PYTHONPATH=src python3 -m kryptos sweep <config.toml> --workers 8
PYTHONPATH=src python3 -m kryptos reproduce <manifest.json>
PYTHONPATH=src python3 -m kryptos novelty generate
PYTHONPATH=src python3 -m kryptos novelty triage --limit 50
PYTHONPATH=src python3 -m kryptos novelty status
PYTHONPATH=src python3 -m kryptos report <db.sqlite> top --limit 20 --min-score 10

# Site builder (requires venv)
source venv/bin/activate && python3 site_builder/build.py
cd site && python3 -m http.server 8000

# API server (requires venv)
source venv/bin/activate && python3 site_builder/serve.py
```

---

## Architecture

Four layers with strict dependency direction: **kernel → pipeline → novelty → cli**

### Source layout (`src/kryptos/`)

- **kernel/** — Pure computation, zero external dependencies, **all positions 0-indexed**.
  - `constants.py` — **SINGLE source of truth**: CT, cribs, Bean constraints, keystream values, scoring thresholds. Runs `_verify()` at import time. **Never define CT or cribs elsewhere.**
  - `alphabet.py` — `AZ`/`KA` singletons, `keyword_mixed_alphabet()`. See "Key Gotchas" for KA ordering.
  - `transforms/` — Cipher implementations + composable pipeline builder (`compose.py`: `TransformConfig` → `PipelineConfig` → `build_pipeline()`)
  - `scoring/` — Under `kernel/`, NOT a top-level module. Two canonical paths in `aggregate.py`: `score_candidate()` (anchored cribs at fixed positions) and `score_candidate_free()` (cribs searched anywhere — critical for scrambled-CT paradigm). Thresholds: NOISE=6, STORE=10, SIGNAL=18, BREAKTHROUGH=24.
  - `constraints/` — Bean equality/inequality (`bean.py`), crib scoring, self-encrypting position checks
  - `persistence/` — WAL-mode SQLite + JSONL artifacts
- **pipeline/** — `evaluate_candidate()` is the primary entry point. `SweepRunner` handles parallel execution with checkpointing and resume.
- **novelty/** — Hypothesis-driven search: `Hypothesis` dataclass → `triage_batch()` → `NoveltyLedger` (SQLite). Wired to 13 research questions (RQ-1..RQ-13). See `src/kryptos/novelty/generators.py` for adding new hypotheses.
- **corpus/** — Egyptological corpus pipeline for running-key testing: `schema.py` (dataclasses), `normalize.py` (transliteration rules), `variants.py` (controlled variant expansion), `ingest.py` (local + Gutenberg ingestion).
- **cli/** — Thin wrappers for `doctor`, `sweep`, `reproduce`, `novelty`, `report`.

### Data flow

```
Hypothesis generators → triage → NoveltyLedger (db/novelty_ledger.sqlite)
    ↓ (promoted)
SweepRunner → worker functions (parallel)
    ↓
kernel/transforms/compose.py (pipeline execution)
    ↓
kernel/constraints/ (crib + Bean filtering)
    ↓
pipeline/evaluation.py → scoring/aggregate.py (ScoreBreakdown)
    ↓
kernel/persistence/sqlite.py (results DB) + JsonlWriter (logs)
```

### Experiment scripts (`scripts/`)

Hundreds of attack scripts organized into 31 family subdirectories. Each script has a parseable metadata header and is tracked in `exhaustion_log.json`. Use `run_attack.py --list` to discover scripts or `run_attack.py --run --family <name>` to dispatch by family.

**All family directories:** `_infra` (infrastructure/utilities, not attacks), `_uncategorized`, `analysis`, `antipodes`, `blitz`, `campaigns`, `cfm`, `crib_analysis`, `encoding`, `examples`, `exploration`, `fractionation`, `geodetic`, `geometry`, `grille`, `k2_coords`, `k3_continuity`, `mirror_ka`, `multi_layer`, `overlay`, `polyalphabetic`, `running_key`, `statistical`, `substitution`, `tableau`, `team`, `thematic`, `transposition`, `two_system`, `yar`.

**Exhaustion log locations:** Root `exhaustion_log.json` (authoritative, 2878 lines) and `scripts/EXHAUSTION.json` (legacy copy). Use the root file.

**Script infrastructure (`scripts/lib/`):**
- `header.py` — Parse/validate metadata headers (Cipher, Family, Status, Keyspace, Last run, Best score)
- `exhaustion.py` — CRUD for root `exhaustion_log.json` (authoritative source of truth for status)
- `discover.py` — Recursive script discovery and manifest generation
- `migrate.py` — Batch migration CLI for adding headers

**Standard `attack()` contract** (26 scripts migrated, remainder use legacy subprocess mode):
```python
def attack(ciphertext: str, **params) -> list[tuple[float, str, str]]:
    """Returns [(score, plaintext, method_description), ...] sorted by score desc."""
```

**Script naming:** `e_` = experiment (standard metadata header required), `f_` = formal campaign (longer-running, may use custom header format). Both live in family subdirectories.

**Writing a new experiment script:**
1. Place it in the appropriate family subdirectory: `scripts/<family>/e_<topic>_<nn>_<short_name>.py`
2. Add a standard metadata header (see `scripts/examples/e_caesar_standard.py`)
3. Import constants from `kryptos.kernel.constants` (never hardcode CT/cribs)
4. Implement `attack(ciphertext, **params)` returning `list[tuple[float, str, str]]`
5. Write results to `results/<experiment_id>.json` or `results/<experiment_id>/`
6. Register in `exhaustion_log.json` via `scripts/lib/exhaustion.update()`
7. Use `python3 -u` for unbuffered output when running in background

**Standalone script bootstrap** (for scripts run directly, not via `run_attack.py`):
```python
import sys, os
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))
```
**Note:** This assumes the script is exactly 2 directories deep (e.g. `scripts/grille/e_foo.py`). For deeper nesting (e.g. `scripts/transposition/other/`), add another `os.path.dirname()` wrapper per extra level.

### Benchmark framework (`bench/`)

Cipher-solving benchmark suite for regression testing and scoring validation. CLI: `PYTHONPATH=src python bench/cli.py run --suite bench/suites/tier0_smoke.jsonl`. Modules: `runner.py` (execute suites), `scorer.py` (score results), `segmenter.py` (segment ciphertexts), `validator.py` (validate solutions), `generate.py` (generate new suites), `io.py` (JSONL I/O). Suites in `bench/suites/` (tier0–tier3). Test coverage in `tests/test_bench*.py`.

### Tests

Three test categories: **Unit tests** (`test_transforms.py`, `test_constraints.py`, `test_scoring.py`, `test_pipeline.py`, `test_novelty.py`, `test_alphabet.py`, `test_constants.py`, `test_free_crib.py`, `test_corpus.py`, `test_attack_lib.py`) cover each layer. **QA verification tests** (`test_qa_structural_claims.py`, `test_qa_kernel_verify.py`, `test_qa_frac_cross_verify.py`, `test_qa_pipeline_novelty.py`, `test_audit_regression.py`) are higher-level cross-checks that validate structural claims, FRAC results, audit assumptions, and pipeline-novelty integration. **Benchmark tests** (`test_bench.py`, `test_bench_generate.py`, `test_bench_regression.py`, `test_bench_scorer.py`, `test_bench_segmenter.py`, `test_bench_validator.py`) cover the `bench/` framework.

### Key data files

- `data/ct.txt` — K4 ciphertext (97 chars)
- `data/english_quadgrams.json` — Quadgram log-probabilities (2 MB, top-level dict: `{"THAN": -3.776, ...}`)
- `db/` — SQLite databases (sweep results, novelty ledger) — **gitignored**
- `wordlists/english.txt` — 1M+ words (merged Kaikki/Wiktextract + original); `wordlists/thematic_keywords.txt` — thematic keywords for key-phrase testing
- `reference/` — Carter book PDF + text extracts, Sanborn correspondence, NSA docs, Ed Scheidt dossier, video transcripts, KryptosFan findings, Cardan grille image
- `reports/` — Human-readable analysis reports (tracked)
- `anomaly_registry.md` — Physical anomalies in the Kryptos sculpture
- `external/` — Third-party reference projects (patrickkellogg-Kryptos, enigmator cipher tools)
- `docs/crypto_field_manual/` — Durable cryptographic knowledge base (cipher catalog, people/orgs timeline, K4 mapping matrix)

### Site builder (`site_builder/`)

Builds the `internal.com` static site. Output goes to `site/` (gitignored). Key modules: `data_loader.py` (loads experiment data from DBs/artifacts), `categorizer.py` (classifies experiments by method), `search_index.py` (generates client-side search index), `overrides.toml` (per-experiment display overrides). Commands in the "Development Setup" section above.

### API backend (`api/`)

FastAPI backend for internal.com. Theory classifier endpoint (Claude-powered), submission queue (SQLite), CORS, rate limiting. Mounts `site/` as static files. Commands in the "Development Setup" section above.

### KryptosBot SDK (`<internal>/`)

Agent SDK research campaign runner. Separate from the core `src/kryptos/` package. Two-level namespace: `<internal>/<internal>/` is the Python package (imports as `internal.internal.*`). Entry points: `python3 <internal>/solve.py` (campaigns), `python3 <internal>/monitor.py` (live dashboard). Key modules: `strategies.py` (23 strategies in 4 modes: UNSCRAMBLE/REASONING/COMPUTE/LEGACY), `agent_runner.py` (session loop + token tracking), `compute.py` (local multiprocessing). Requires venv. Results go to `results/` (gitignored).

### Other directories

- **`bin/`** — Standalone engine scripts for Antipodes and cylinder rotation analysis (`antipodes_device_engine.py`, `antipodes_key_engine.py`, `cylinder_rotation_engine.py`).
- **`jobs/`** — Job queue with `pending/`, `running/`, `done/`, `failed/` subdirectories for experiment management.
- **`deploy/`** — Production deployment configs: systemd service (`internal-api.service`), nginx config, cron updater, setup script.
- **`tools/`** — Utility scripts (e.g. `generate_quadgrams.py` for rebuilding quadgram data).

**Top-level scripts:** `run_attack.py` (dispatch runner), `run_lean.py` (lightweight runner), `worker.py` (job worker), `k4_job_runner.sh` (shell job harness).

### Gitignored directories

`db/`, `results/` (unified KryptosBot output: `campaigns/`, `compute/`), `artifacts/`, `agent_logs/`, `work/`, `tmp/`, `venv/`, `site/`, `checkpoints/`, `blitz_results/`, `kbot_results/`, `split_results/`, `forensic_output/` — per-run data, must not be committed.

---

## Interpreting Scores

Two scoring paths in `kernel/scoring/aggregate.py`: `score_candidate()` (anchored cribs at fixed positions) and `score_candidate_free()` (cribs searched anywhere — for scrambled-CT work). Both return a breakdown with `crib_score` (0–24), `bean_passed`, `ic_value`, `ngram_score`, and `crib_classification`.

| Score | Classification | Stored? | Meaning |
|-------|---------------|---------|---------|
| 0–9   | noise         | No (≤9) | Expected random performance |
| 10–17 | interesting   | Yes     | Worth logging, likely noise |
| 18–23 | signal        | Yes     | Statistically significant, investigate |
| 24    | breakthrough  | Yes     | All cribs match — potential solution (requires Bean PASS) |

**False positive warning**: `period_consistency()` is underdetermined when `period >= (num_crib_positions / constraints_per_residue)`. At period 24, random configs score ~19.2/24; at period 17, ~17.3/24. Only period ≤7 gives meaningful discrimination (~8.2/24 expected). **All high scores at large periods are false positives.** With the full 242 Bean inequality set, ALL periods 1–26 are eliminated for periodic substitution on the raw 97-char carved text.

---

## Key Gotchas

These are non-obvious pitfalls discovered through prior sessions. Check these first when debugging unexpected results.

- **0-indexed positions everywhere**: Cribs are at 21–33 and 63–73 (0-indexed). Legacy code and some public sources use 1-indexed (22–34, 64–74). Mixing conventions is the #1 source of bugs.
- **KA alphabet has non-standard ordering**: `KRYPTOSABCDEFGHIJLMNQUVWXZ` — all 26 letters present but reordered (keyword "KRYPTOS" first). The `KA` singleton uses this ordering; standard `AZ` uses alphabetical. Both contain all 26 letters. (The "KA has no J" claim in prior versions was **wrong**.)
- **Vigenère vs Beaufort sign conventions**: `K = (CT - PT) mod 26` for Vigenère, `K = (CT + PT) mod 26` for Beaufort, `K = (PT - CT) mod 26` for Variant Beaufort. Mixing these silently produces wrong keystream.
- **Bean constraint is variant-independent**: CT[27]=CT[65]=P and PT[27]=PT[65]=R, so the equality k[27]=k[65] holds regardless of cipher variant. The 242 inequalities are also variant-independent (derived from all C(24,2)=276 crib pairs; 242 have distinct key values under all 3 variants).
- **Transposition permutation convention**: `output[i] = input[perm[i]]` — this is the "gather" convention. `invert_perm()` gives the "scatter" direction.
- **IC below random**: K4's IC ≈ 0.0361 is below the random expectation of 0.0385. [INTERNAL RESULT] FRAC agent (E-FRAC-04) showed this deviation is NOT statistically significant for a 97-char text. Do not use IC alone as a discriminator.
- **constants.py self-verifies at import**: If you modify CT, cribs, or Bean values incorrectly, the import itself will raise an assertion error.
- **Unbuffered output for background tasks**: Always use `python3 -u` when running scripts in background. Without `-u`, Python buffers stdout and you see no output until the process ends.
- **Bifid 5×5 impossible for K4**: All 26 letters appear in K4 CT; any cipher requiring a 25-letter alphabet (I/J merged) is eliminated.
- **15/24 is a FALSE SIGNAL, not a near-miss**: Both DEFECTOR:AZ_beau+col7 and PALIMPSEST:AZ_beau+col7 reach 15/24 — but autokey is **structurally impossible** (mathematical proof via crib-to-crib feedback contradictions: 7/8 connections are contradictions at offset=8, ALL offsets fail). The 15/24 comes from non-crib degrees of freedom, not from real signal. PALIMPSEST reaches 15/24 at 78% frequency (39/50 restarts) vs DEFECTOR at 6% — both are artifacts. Do NOT chase higher scores on any keyword+col7+autokey model.
- **Autokey is provably impossible on K4**: PT-autokey and CT-autokey both fail structurally because crib positions feed back into each other at offsets ≤44. This is not a search failure — it's a mathematical impossibility. See `memory/keystream_forensics_v2.md`.
- **K2 numbers are NOT direct cipher keys**: Despite encoding 73/24/13/11, K2's "38 degrees 57 minutes 6.5 seconds" as raw numbers produce only noise (6/24 max) when used as Vigenère keys, transposition keys, or autokey primers. The encoding is confirmed real but the operational mechanism is unknown.
- **Beaufort A=0 is the confirmed default**: Use A=0 indexing for all Beaufort operations unless explicitly testing A=1. Both conventions must be tested in positional experiments.
- **Standalone script `_ROOT` depth**: The bootstrap snippet (`_ROOT = os.path.dirname(os.path.dirname(...))`) assumes the script is exactly 2 directories deep (e.g. `scripts/grille/e_foo.py`). Scripts at 3+ levels need additional `os.path.dirname()` wrappers or they'll get `ModuleNotFoundError`.

---

## Truth Taxonomy (MANDATORY)

Every nontrivial statement must be classified as one of:

- **[PUBLIC FACT]** Verified by reputable public reporting or primary-source statements.
- **[DERIVED FACT]** Deterministic consequence of PUBLIC FACTS, reproducible by a provided command/script.
- **[INTERNAL RESULT]** Empirical result produced by this repo; must include **artifact pointers** and a **repro command**.
- **[HYPOTHESIS]** Plausible claim not yet proven; must include a test plan.
- **[POLICY]** Operating rule for how we work (not a claim about Kryptos reality).

**Hard rule:** Nothing may appear as "ground truth" unless it is **[PUBLIC FACT]** or **[DERIVED FACT]** with a reproducible check.

### Code skepticism

[POLICY] Never assume existing code is correct. When results look "impossible" or "breakthrough", suspect: indexing (0 vs 1), permutation direction, alphabet ordering/merges, Beaufort/Vigenère sign conventions, boundary inclusivity, unintended mutation/caching.

### Validation gates

Results are not trusted until they pass:
1. Unit tests pass
2. Minimal reference implementation reproduces outcome
3. Invariant checks (bijection, reversibility, crib alignment)
4. Reproduce from a clean process (fresh interpreter)

---

## Reference Documents

Domain knowledge, public facts, and detailed operating policies live in separate files:

- **`docs/kryptos_ground_truth.md`** — Public facts (CT, cribs, 2025 disclosures), internal results policy, hypothesis classes, creativity doctrine
- **`docs/invariants.md`** — Verified computational invariants (keystream, Bean constraints, alphabets, eliminated hypotheses)
- **`docs/elimination_tiers.md`** — Elimination confidence tiers (Tier 1–4) with full tables of what has/hasn't been tested. Tier 1 = mathematically proven eliminated; Tier 2 = exhaustively searched (single-layer only — **OPEN as one layer of multi-layer**); Tier 4 = untested bespoke methods. **Critical framing:** All Tier 2 eliminations assume direct positional correspondence (CT[i] → PT[i]).
- **`docs/research_questions.md`** — Prioritized unknowns (RQ-1 through RQ-13) with current state and next steps
- **`docs/two_ground_truths.md`** — Physical sculpture vs Sanborn's intent: two distinct ground truths for K4 analysis
- **`anomaly_registry.md`** — Physical anomalies in the Kryptos sculpture (misspellings, alignments, narrative anomaly allocation)

---

## Multi-Agent Mode — Solve K4

**ALL agents are focused on ONE goal: derive the full encryption method and solve K4.**

**Key constraints for teammates:**
- Import constants from `kryptos.kernel.constants` — never hardcode CT/cribs
- DO NOT re-run ANY hypothesis listed in MEMORY.md's "PROVEN IMPOSSIBLE" or "DO NOT TEST" sections
- Current hypotheses: see Quick Reference above + Claude Code auto-memory (`cardan_grille.md`, `73_char_hypothesis.md`)
- **→ Full elimination list, current leads, and open attack surface: see MEMORY.md**

**KryptosBot agent runner:** `python3 <internal>/solve.py` launches the unified campaign runner. See `<internal>` for full usage. Key commands: `solve.py` (6 parallel agents), `solve.py compute` (free local CPU), `solve.py run <name>` (single strategy), `solve.py list` (show all strategies).

**Historical reference:** Previous custom 6-agent harness (170+ experiments) archived in `archive/legacy_harness/` and `archive/session_reports/`. Comprehensive synthesis: [`reports/final_synthesis.md`](reports/final_synthesis.md).

---

*Last updated: 2026-03-19 — Mission: derive K4 method & solve. Volatile research state (best leads, eliminations, open hypotheses) maintained in MEMORY.md.*
*Primary author: Colin Patrick (human lead) + Claude (computational partner)*
