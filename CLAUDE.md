# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

This repo has one purpose: determine the **true plaintext** and the **full encryption method** of **Kryptos K4**.

This repo supports **parallel multi-agent operation**. If the environment variable `$K4_AGENT_ID` is set, you are one agent in a team. Read [`AGENT_PROMPT.md`](AGENT_PROMPT.md) before doing anything else.

---

## Development Setup

**Python 3.12+** required (uses `tomllib` from stdlib). **No external runtime dependencies** — stdlib only. `pytest` is the only dev dependency.

**Primary development path** (no `pyproject.toml` or `setup.py` — `pip install -e .` will not work):
```bash
PYTHONPATH=src python3 -u scripts/<name>.py   # run scripts (-u for unbuffered output)
PYTHONPATH=src pytest tests/                   # run tests (install pytest: pip install --user pytest)
```

---

## Common Commands

```bash
# Run all tests
PYTHONPATH=src pytest tests/

# Run a single test file or test
PYTHONPATH=src pytest tests/test_transforms.py
PYTHONPATH=src pytest tests/test_transforms.py::test_vigenere_roundtrip -v

# Run an experiment script (always use -u for unbuffered output)
PYTHONPATH=src python3 -u scripts/e_nsa_01_interval7.py

# Environment health check
PYTHONPATH=src python3 -m kryptos doctor

# CLI commands
PYTHONPATH=src python3 -m kryptos sweep <config.toml>             # run a sweep campaign
PYTHONPATH=src python3 -m kryptos sweep <config.toml> --workers 8  # with parallelism
PYTHONPATH=src python3 -m kryptos reproduce <manifest.json>        # reproduce a prior run
PYTHONPATH=src python3 -m kryptos novelty generate                 # generate hypotheses
PYTHONPATH=src python3 -m kryptos novelty triage --limit 50        # triage pending hypotheses
PYTHONPATH=src python3 -m kryptos novelty status                   # show hypothesis counts + RQ coverage
PYTHONPATH=src python3 -m kryptos report <db.sqlite> top --limit 20 --min-score 10  # top results
```

---

## Architecture

Four layers with strict dependency direction: **kernel → pipeline → novelty → cli**

### Source layout (`src/kryptos/`)

- **kernel/** — Pure computation, zero external dependencies, **all positions 0-indexed**.
  - `constants.py` — **SINGLE source of truth**: CT, cribs, Bean constraints, keystream values, scoring thresholds. Runs `_verify()` at import time. **Never define CT or cribs elsewhere.**
  - `transforms/` — Cipher implementations (Vigenère/Beaufort, transpositions, Polybius) + composable pipeline builder (`compose.py`: `TransformConfig` → `PipelineConfig` → `build_pipeline()`)
  - `constraints/` — Crib scoring, Bean equality/inequality, self-encrypting checks
  - `scoring/aggregate.py` — `score_candidate()` is **THE canonical scoring path**. Thresholds: NOISE=6, STORE=10, SIGNAL=18, BREAKTHROUGH=24.
  - `persistence/` — WAL-mode SQLite (runs/results/eliminations/checkpoints) + JSONL artifacts
- **pipeline/** — `evaluate_candidate()` is the primary entry point. `SweepRunner` handles parallel execution with checkpointing and resume.
- **novelty/** — Hypothesis-driven search: `Hypothesis` dataclass → `triage_batch()` → `NoveltyLedger` (SQLite). Wired to 13 research questions (RQ-1..RQ-13).
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

Standalone experiment scripts, each runnable with `PYTHONPATH=src python3 -u scripts/<name>.py`.

**Naming conventions:**
- `k4_*.py` — Core attack vectors (algebraic, SA, running key, two-layer, reading orders)
- `e01_*` through `e06_*` — Numbered elimination experiments
- `e_nsa_*.py` — NSA document-inspired experiments
- `e_desp_*.py` / `e_s_*.py` — Structural experiments
- `e_frac_*.py` — FRAC agent experiments (statistical analysis, width hypotheses, key distribution)
- `e_tableau_*.py` — Tableau agent experiments (K3-method variants, keyword tableaux)

**Writing a new experiment script:**
1. Name it `scripts/e_<id>_<short_name>.py` (next available number)
2. Import constants from `kryptos.kernel.constants` (never hardcode CT/cribs)
3. Write results to `results/<experiment_id>.json` or `results/<experiment_id>/`
4. Print a final summary with best score, config, and artifact path
5. Use `python3 -u` for unbuffered output when running in background

### Key data files

- `data/ct.txt` — K4 ciphertext (97 chars)
- `data/english_quadgrams.json` — Quadgram log-probabilities (2 MB, top-level dict: `{"THAN": -3.776, ...}`)
- `db/` — SQLite databases (sweep results, novelty ledger) — **gitignored**
- `wordlists/english.txt` — 370K words
- `reference/` — Carter book PDF + text extracts, Sanborn correspondence, NSA docs
- `obsolete/` — 65 quarantined legacy files with index — nothing deleted, kept for reference

### Other directories

- `external/` — Third-party reference project (patrickkellogg-Kryptos)
- `results/`, `artifacts/` — Experiment outputs — **gitignored**
- `reports/` — Human-readable analysis reports
- `anomaly_registry.md` — Physical anomalies in the Kryptos sculpture

### Gitignored directories

`.gitignore` excludes `db/`, `results/`, `artifacts/`, `agent_logs/`, `work/`, `tmp/`, `venv/`. These contain per-run data and must not be committed. The `jobs/` and `reports/` directories are tracked.

---

## Interpreting Scores

`score_candidate()` returns a `ScoreBreakdown` with these key fields:
- **crib_matches** (0–24): Number of crib positions where derived key is consistent. Primary signal.
- **bean_passed** (bool): Whether Bean equality (k[27]=k[65]) and all 21 inequalities hold.
- **ic**: Index of coincidence of the candidate plaintext.

| Score | Classification | Meaning |
|-------|---------------|---------|
| ≤6    | NOISE         | Expected random performance |
| 7–17  | STORE         | Worth logging, likely noise |
| 18–23 | SIGNAL        | Statistically significant, investigate |
| 24    | BREAKTHROUGH  | All cribs match — potential solution |

**False positive warning**: At periods ≥17, random configs score 17+/24 due to underdetermination. Only scores at period ≤7 are meaningful discriminators. **Note:** FRAC agent (E-FRAC-07) proved periods 2–7 are Bean-impossible for transposition + periodic substitution; only periods {8, 13, 16, 19, 20, 23, 24, 26} are Bean-compatible. This narrows the viable search space but does not change the scoring rule.

### Sweep config format (TOML)

```toml
[campaign]
name = "example"
transposition_family = "identity"
cipher_variants = ["vigenere", "beaufort"]
periods = [4, 5, 6, 7]
db_path = "db/sweep.sqlite"
workers = 8
```

### Adding a hypothesis to the novelty engine

1. Add a generator function in `src/kryptos/novelty/generators.py` that yields `Hypothesis` objects
2. Each hypothesis needs: `description`, `transform_stack`, `research_questions` (list of `ResearchQuestion` enums, RQ1–RQ13), `triage_tests`, and `expected_signatures`
3. Register the generator in the `ALL_GENERATORS` list at the bottom of `generators.py`
4. Run `PYTHONPATH=src python3 -m kryptos novelty generate` to populate the ledger
5. Run `PYTHONPATH=src python3 -m kryptos novelty triage --limit N` to test cheaply before expensive sweeps

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
- **`docs/elimination_tiers.md`** — Elimination confidence tiers (Tier 1–4) with full tables of what has/hasn't been tested
- **`docs/research_questions.md`** — Prioritized unknowns (RQ-1 through RQ-13) with current state and next steps
- **`docs/ARCHITECTURE_PLAN.md`** — Original architecture plan for the refactored codebase
- **`anomaly_registry.md`** — Physical anomalies in the Kryptos sculpture (misspellings, alignments)

---

## Multi-Agent Mode

This project uses **official Claude Code agent teams** (experimental feature, enabled in `.claude/settings.local.json`). The previous custom harness system (6 agents, git worktrees, lockfiles) completed 170+ experiments and is now archived.

**Current team structure (3 agents):**
- **Lead**: Interactive session. Manages task list, synthesizes findings, decides what to test next.
- **Explorer**: Tests creative/physical/non-standard cipher hypotheses. Low compute, high analysis. Should require plan approval.
- **Validator**: Reproduces claimed signals, runs multi-objective scoring (crib + quadgram + word count + Bean), stress-tests candidates. Can use Sonnet for cost efficiency.

**Key constraints for teammates:**
- Import constants from `kryptos.kernel.constants` — never hardcode CT/cribs
- Use `score_candidate()` from `kryptos.kernel.scoring.aggregate` — never hand-roll scoring
- Only scores at period <= 7 are meaningful (see Key Gotchas)
- Multi-objective thresholds: crib=24/24 + Bean PASS + quadgram > -4.84/char + IC > 0.055 + non-crib words >= 7 chars >= 3

**Historical reference:** The previous custom harness (`AGENT_PROMPT.md`, `k4_agent_harness.sh`, `k4_setup_agents.sh`, `k4_launch_all.sh`) and its full experiment log (`reports/progress_archive.md`) are preserved for reference. The comprehensive synthesis is at [`reports/final_synthesis.md`](reports/final_synthesis.md).

**Compute separation:** `k4_job_runner.sh` remains available for CPU-heavy sweeps independent of the agent team. Write sweep scripts to `jobs/pending/`, the runner handles execution.

---

## Elimination Confidence Tiers

Detailed elimination status for all tested cipher families is maintained in [`docs/elimination_tiers.md`](docs/elimination_tiers.md). Summary:

- **Tier 1 (mathematical proofs, ~99.9%):** Pure transposition, periodic polyalphabetic (direct correspondence), Hill 2×2/3×3 — permanently eliminated.
- **Tier 2 (exhaustive search, direct correspondence only, ~95%):** Vigenère, Beaufort, Bifid, Playfair, Nihilist, etc. — eliminated as single-layer but **OPEN** as substitution layer after transposition.
- **Tier 3 (now eliminated):** ADFGVX/ADFGX (structurally impossible — 6-letter output vs 26-letter CT), turning grille 10×10 (structurally impossible — E-S-104), straddling checkerboard (digit output). All former Tier 3 ciphers are now Tier 1 or Tier 2.
- **Tier 4 (never tested, 0%):** Bespoke physical methods, position-dependent alphabets, non-standard structures not yet conceived.

**Critical framing:** All Tier 2 eliminations assume direct positional correspondence (CT[i] maps to PT[i]). They do NOT eliminate these ciphers as one layer of a multi-layer system.

---

## The K4 Problem — Quick Reference

**Kryptos** is a sculpture at CIA headquarters containing four encrypted messages (K1–K4). K1–K3 were solved in 1999. **K4 (97 characters) has been unsolved since 1990.**

**Ciphertext:** `OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR`

**Known plaintext (0-indexed):**
- Positions 21–33: `EASTNORTHEAST`
- Positions 63–73: `BERLINCLOCK`

**What we know:** [DERIVED FACT] No single-layer classical cipher works (exhaustively tested, 200+ experiments, 65M+ configurations). [HYPOTHESIS] K4 is likely multi-layered (substitution + transposition), based on Sanborn's "two separate systems" statement and elimination of all single-layer methods. [HYPOTHESIS] The method is likely executable by hand (Scheidt's background, 1989 technology), but this is unproven. See [`reports/final_synthesis.md`](reports/final_synthesis.md) for the full elimination landscape.

**What we don't know:** The specific transposition method, the specific substitution method, the full plaintext (only 24/97 characters known).

---

*Last updated: 2026-02-20 — Migrated to official agent teams, archived custom harness (170+ experiments complete)*
*Primary author: Colin Patrick (human lead) + Claude (computational partner)*
