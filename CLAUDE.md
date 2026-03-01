# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

This repo has one purpose: determine the **true plaintext** and the **full encryption method** of **Kryptos K4**.

---

## The K4 Problem — Quick Reference

**Kryptos** is a sculpture at CIA headquarters containing four encrypted messages (K1–K4). K1–K3 were solved in 1999. **K4 (97 characters) has been unsolved since 1990.**

**Ciphertext:** `OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR`

**Known plaintext (0-indexed):**
- Positions 21–33: `EASTNORTHEAST`
- Positions 63–73: `BERLINCLOCK`

**What we know:** [DERIVED FACT] No single-layer classical cipher works (exhaustively tested, 375+ experiments, 669B+ configurations). [HYPOTHESIS] K4 is likely multi-layered (substitution + transposition), based on Sanborn's "two separate systems" statement and elimination of all single-layer methods. [HYPOTHESIS] The method is likely executable by hand (Scheidt's background, 1989 technology), but this is unproven. [HYPOTHESIS] K4 had a **mask applied before encryption** — Scheidt (WIRED 2005): "I masked the English language... solve the technique first then the puzzle." If true, English IC/frequency analysis is mute and cannot discriminate K4 candidates. See [`reports/final_synthesis.md`](reports/final_synthesis.md) for the full elimination landscape.

**What we don't know:** The specific transposition method, the specific substitution method, the full plaintext (only 24/97 characters known).

---

## Development Setup & Commands

**Python 3.11+** required (uses `tomllib` from stdlib). **No external runtime dependencies** — stdlib only. `pytest` is the only dev dependency. No `pyproject.toml` or `setup.py` — `pip install -e .` will not work. All commands require `PYTHONPATH=src`.

A `venv/` exists with numpy, pymupdf, and jinja2 but is gitignored. Activate with `source venv/bin/activate` if needed for PDF/matrix work or the site builder, but core code uses stdlib only.

```bash
# Run all tests
PYTHONPATH=src pytest tests/

# Run a single test file or test
PYTHONPATH=src pytest tests/test_transforms.py
PYTHONPATH=src pytest tests/test_transforms.py::TestVigenereFamily::test_text_roundtrip_vig -v

# Run an experiment script (always use -u for unbuffered output)
PYTHONPATH=src python3 -u scripts/e_nsa_01_interval7.py

# Environment health check
PYTHONPATH=src python3 -m kryptos doctor

# CLI: sweep, reproduce, novelty, report
PYTHONPATH=src python3 -m kryptos sweep <config.toml> --workers 8
PYTHONPATH=src python3 -m kryptos reproduce <manifest.json>
PYTHONPATH=src python3 -m kryptos novelty generate
PYTHONPATH=src python3 -m kryptos novelty triage --limit 50
PYTHONPATH=src python3 -m kryptos novelty status
PYTHONPATH=src python3 -m kryptos report <db.sqlite> top --limit 20 --min-score 10
```

---

## Architecture

Four layers with strict dependency direction: **kernel → pipeline → novelty → cli**

### Source layout (`src/kryptos/`)

- **kernel/** — Pure computation, zero external dependencies, **all positions 0-indexed**.
  - `constants.py` — **SINGLE source of truth**: CT, cribs, Bean constraints, keystream values, scoring thresholds. Runs `_verify()` at import time. **Never define CT or cribs elsewhere.**
  - `transforms/` — Cipher implementations (Vigenère/Beaufort, transpositions, Polybius) + composable pipeline builder (`compose.py`: `TransformConfig` → `PipelineConfig` → `build_pipeline()`)
  - `constraints/` — Crib scoring (`crib.py`), Bean equality/inequality (`bean.py`), consistency checks (`consistency.py` — self-encrypting positions, monoalphabetic consistency)
  - `scoring/aggregate.py` — `score_candidate()` is **THE canonical scoring path**. Thresholds: NOISE=6, STORE=10, SIGNAL=18, BREAKTHROUGH=24.
  - `persistence/` — WAL-mode SQLite (runs/results/eliminations/checkpoints) + JSONL artifacts
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

Standalone experiment scripts, each runnable with `PYTHONPATH=src python3 -u scripts/<name>.py`. Prefixed by agent/topic (e.g. `e_frac_*`, `e_chart_*`, `e_explorer_*`, `k4_*`). ~350 scripts exist including ~150 legacy `e_s_*.py` from earlier sessions.

**Writing a new experiment script:**
1. Name it `scripts/e_<topic>_<nn>_<short_name>.py` (topic prefix groups related work, e.g. `e_chart_*`, `e_antipodes_*`, `e_bespoke_*`)
2. Import constants from `kryptos.kernel.constants` (never hardcode CT/cribs)
3. Write results to `results/<experiment_id>.json` or `results/<experiment_id>/`
4. Print a final summary with best score, config, and artifact path
5. Use `python3 -u` for unbuffered output when running in background

### Tests

Two test categories: **Unit tests** (`test_transforms.py`, `test_constraints.py`, `test_scoring.py`, `test_pipeline.py`, `test_novelty.py`, `test_alphabet.py`, `test_constants.py`, `test_free_crib.py`, `test_corpus.py`) cover each layer. **QA verification tests** (`test_qa_structural_claims.py`, `test_qa_kernel_verify.py`, `test_qa_frac_cross_verify.py`, `test_qa_pipeline_novelty.py`, `test_audit_regression.py`) are higher-level cross-checks that validate structural claims, FRAC results, audit assumptions, and pipeline-novelty integration.

### Key data files

- `data/ct.txt` — K4 ciphertext (97 chars)
- `data/english_quadgrams.json` — Quadgram log-probabilities (2 MB, top-level dict: `{"THAN": -3.776, ...}`)
- `db/` — SQLite databases (sweep results, novelty ledger) — **gitignored**
- `wordlists/english.txt` — 370K words
- `reference/` — Carter book PDF + text extracts, Sanborn correspondence, NSA docs
- `reports/` — Human-readable analysis reports (tracked)
- `anomaly_registry.md` — Physical anomalies in the Kryptos sculpture
- `external/` — Third-party reference project (patrickkellogg-Kryptos)

### Site builder (`site_builder/`)

Builds the `kryptosbot.com` static site. Requires jinja2 (in venv). Build with `python3 site_builder/build.py`, preview with `cd site && python3 -m http.server 8000`. Output goes to `site/` (gitignored). Key modules: `data_loader.py` (loads experiment data from DBs/artifacts), `categorizer.py` (classifies experiments by method), `search_index.py` (generates client-side search index), `overrides.toml` (per-experiment display overrides).

### KryptosBot SDK (`kryptosbot/`)

Claude Agent SDK multi-agent campaign runner. Separate from the core `src/kryptos/` package. Key modules: `orchestrator.py` (campaign coordination), `worker.py` (parallel execution), `framework_strategies.py` (strategy definitions), `compute.py` (kernel integration), `database.py` (results DB). Run campaigns with `python3 kryptosbot/run_kryptosbot.py`. Requires `python-dotenv` and `anthropic` SDK (in venv). Results go to `kryptosbot/kryptosbot_results.db`.

### Gitignored directories

`db/`, `results/`, `artifacts/`, `agent_logs/`, `work/`, `tmp/`, `venv/`, `site/` — per-run data, must not be committed.

---

## Interpreting Scores

`score_candidate()` returns a `ScoreBreakdown` with these key fields:
- **crib_matches** (0–24): Number of crib positions where derived key is consistent. Primary signal.
- **bean_passed** (bool): Whether Bean equality (k[27]=k[65]) and all 21 inequalities hold.
- **ic**: Index of coincidence of the candidate plaintext.

| Score | Classification | Stored? | Meaning |
|-------|---------------|---------|---------|
| 0–9   | noise         | No (≤9) | Expected random performance |
| 10–17 | interesting   | Yes     | Worth logging, likely noise |
| 18–23 | signal        | Yes     | Statistically significant, investigate |
| 24    | breakthrough  | Yes     | All cribs match — potential solution (requires Bean PASS) |

Note: `is_above_noise()` triggers at score > 6, but `is_storable()` and DB persistence trigger at score ≥ 10 (`STORE_THRESHOLD`). Scores 7–9 are above noise floor but not persisted.

**False positive warning**: At periods ≥17, random configs score 17+/24 due to underdetermination. Only scores at period ≤7 are meaningful discriminators. **Note:** FRAC agent (E-FRAC-07) proved periods 2–7 are Bean-impossible for transposition + periodic substitution; only periods {8, 13, 16, 19, 20, 23, 24, 26} are Bean-compatible. This narrows the viable search space but does not change the scoring rule.

---

## Key Gotchas

These are non-obvious pitfalls discovered through prior sessions. Check these first when debugging unexpected results.

- **0-indexed positions everywhere**: Cribs are at 21–33 and 63–73 (0-indexed). Legacy code and some public sources use 1-indexed (22–34, 64–74). Mixing conventions is the #1 source of bugs.
- **KA alphabet has non-standard ordering**: `KRYPTOSABCDEFGHIJLMNQUVWXZ` — all 26 letters present but reordered (keyword "KRYPTOS" first). The `KA` singleton uses this ordering; standard `AZ` uses alphabetical. Both contain all 26 letters. (The "KA has no J" claim in prior versions was **wrong**.)
- **Vigenère vs Beaufort sign conventions**: `K = (CT - PT) mod 26` for Vigenère, `K = (CT + PT) mod 26` for Beaufort, `K = (PT - CT) mod 26` for Variant Beaufort. Mixing these silently produces wrong keystream.
- **Bean constraint is variant-independent**: CT[27]=CT[65]=P and PT[27]=PT[65]=R, so the equality k[27]=k[65] holds regardless of cipher variant. The 21 inequalities are also variant-independent.
- **Transposition permutation convention**: `output[i] = input[perm[i]]` — this is the "gather" convention. `invert_perm()` gives the "scatter" direction.
- **IC below random**: K4's IC ≈ 0.0361 is below the random expectation of 0.0385. [INTERNAL RESULT] FRAC agent (E-FRAC-04) showed this deviation is NOT statistically significant for a 97-char text. Do not use IC alone as a discriminator.
- **constants.py self-verifies at import**: If you modify CT, cribs, or Bean values incorrectly, the import itself will raise an assertion error.
- **Unbuffered output for background tasks**: Always use `python3 -u` when running scripts in background. Without `-u`, Python buffers stdout and you see no output until the process ends.
- **Scoring underdetermination at high periods**: `period_consistency()` is underdetermined when `period >= (num_crib_positions / constraints_per_residue)`. At period 24, random configs score ~19.2/24; at period 17, ~17.3/24. Only period ≤7 gives meaningful discrimination (~8.2/24 expected random). **All high scores at large periods are false positives.**
- **Bifid 5×5 impossible for K4**: All 26 letters appear in K4 CT; any cipher requiring a 25-letter alphabet (I/J merged) is eliminated.

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
- **`anomaly_registry.md`** — Physical anomalies in the Kryptos sculpture (misspellings, alignments, narrative anomaly allocation)

---

## Multi-Agent Mode

This project uses **official Claude Code agent teams** (enabled in `.claude/settings.local.json`). Three agents: **Lead** (interactive, manages tasks), **Explorer** (creative/physical hypotheses, plan approval required), **Validator** (reproduces signals, multi-objective scoring).

**Key constraints for teammates:**
- Import constants from `kryptos.kernel.constants` — never hardcode CT/cribs
- Use `score_candidate()` from `kryptos.kernel.scoring.aggregate` — never hand-roll scoring
- Only scores at period <= 7 are meaningful (see Key Gotchas)
- Multi-objective thresholds: crib=24/24 + Bean PASS + quadgram > -4.84/char + IC > 0.055 + non-crib words >= 7 chars >= 3

**Compute separation:** `k4_job_runner.sh` handles CPU-heavy sweeps independently. Write sweep scripts to `jobs/pending/`.

**Historical reference:** Previous custom 6-agent harness (170+ experiments) archived in `archive/legacy_harness/` and `archive/session_reports/`. Comprehensive synthesis: [`reports/final_synthesis.md`](reports/final_synthesis.md).

---

*Last updated: 2026-03-01 — 375+ experiments complete (669B+ configs), computational work paused pending Antipodes inspection*
*Primary author: Colin Patrick (human lead) + Claude (computational partner)*
