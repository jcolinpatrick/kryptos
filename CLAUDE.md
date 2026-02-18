# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

This repo has one purpose: determine the **true plaintext** and the **full encryption method** of **Kryptos K4**.

**Roles**
- Claude = **reasoning agent** (cryptographer, experiment designer, scientific analyst, creative investigator).
- This machine + repo = **computational workhorse** (long, resumable runs are acceptable).

---

## Development Setup

**Python**: 3.12+ required (uses `tomllib` from stdlib). No external runtime dependencies — stdlib only.

**Primary development path** (venv exists at `./venv` but may lack all packages):
```bash
PYTHONPATH=src python3 -u scripts/<name>.py   # run scripts (-u for unbuffered output)
PYTHONPATH=src pytest tests/                   # run tests (install pytest: pip install --user pytest)
```

**Alternative (full install)**: `pyproject.toml` is missing from the working tree — package metadata survives in `src/kryptos.egg-info/`. Recreate pyproject.toml from egg-info if needed, then `pip install -e ".[dev]"`. The package uses `src/` layout (`src/kryptos/`).

**No external runtime dependencies** — the entire codebase uses only Python stdlib. `pytest` is the only dev dependency.

## Common Commands

```bash
# Run all tests
PYTHONPATH=src pytest tests/

# Run a single test file or test
PYTHONPATH=src pytest tests/test_transforms.py
PYTHONPATH=src pytest tests/test_transforms.py::test_vigenere_roundtrip -v

# Run an experiment script (always use -u for unbuffered output)
PYTHONPATH=src python3 -u scripts/e_nsa_01_interval7.py

# Environment health check (18 checks)
PYTHONPATH=src python3 -m kryptos doctor

# CLI commands (use PYTHONPATH=src prefix since venv is absent)
PYTHONPATH=src python3 -m kryptos sweep <config.toml>             # run a sweep campaign
PYTHONPATH=src python3 -m kryptos sweep <config.toml> --workers 8  # with parallelism
PYTHONPATH=src python3 -m kryptos reproduce <manifest.json>        # reproduce a prior run
PYTHONPATH=src python3 -m kryptos novelty generate                 # generate hypotheses
PYTHONPATH=src python3 -m kryptos novelty triage --limit 50        # triage pending hypotheses
PYTHONPATH=src python3 -m kryptos novelty status                   # show hypothesis counts + RQ coverage
PYTHONPATH=src python3 -m kryptos report <db.sqlite> top --limit 20 --min-score 10  # top results
```

## Architecture

### Source layout (`src/kryptos/`)

Four layers, each with a clear dependency direction: **kernel → pipeline → novelty → cli**

- **kernel/** — Pure computation, zero external dependencies, **all positions 0-indexed**.
  - `constants.py` — **SINGLE source of truth**: CT, cribs, Bean constraints, keystream values, scoring thresholds. Runs `_verify()` at import time. **Never define CT or cribs elsewhere.**
  - `transforms/` — Cipher implementations (Vigenère/Beaufort, transpositions, Polybius) + composable pipeline builder (`compose.py`: `TransformConfig` → `PipelineConfig` → `build_pipeline()`)
  - `constraints/` — Crib scoring, Bean equality/inequality, self-encrypting checks
  - `scoring/aggregate.py` — `score_candidate()` is **THE canonical scoring path**. Thresholds: NOISE=6, STORE=10, SIGNAL=18, BREAKTHROUGH=24.
  - `persistence/` — WAL-mode SQLite (runs/results/eliminations/checkpoints) + JSONL artifacts
- **pipeline/** — `evaluate_candidate()` is the primary entry point. `SweepRunner` handles parallel execution with checkpointing and resume.
- **novelty/** — Hypothesis-driven search: `Hypothesis` dataclass → `triage_batch()` → `NoveltyLedger` (SQLite). Wired to 13 research questions (RQ-1..RQ-13).
- **cli/** — Thin wrappers for `doctor`, `sweep`, `reproduce`, `novelty`, `report`.

### Test suite (`tests/`)

7 test files, pytest class-based. Run with `PYTHONPATH=src pytest tests/`.

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

25 standalone experiment scripts. Each is self-contained and runnable with `PYTHONPATH=src python3 -u scripts/<name>.py`.

**Naming conventions:**
- `k4_*.py` — Core attack vectors (algebraic, SA, running key, two-layer, reading orders, etc.)
- `e01_*` through `e06_*` — Numbered elimination experiments
- `e_nsa_*.py` — NSA document-inspired experiments
- `e_desp_*.py` / `e_s_*.py` — Desperation/structural experiments

**Writing a new experiment script:**
1. Name it `scripts/e_<id>_<short_name>.py` (next available number)
2. Import constants from `kryptos.kernel.constants` (never hardcode CT/cribs)
3. Write results to `results/<experiment_id>.json` or `results/<experiment_id>/`
4. Print a final summary with best score, config, and artifact path
5. Use `python3 -u` for unbuffered output when running in background

### Key data files

- `data/ct.txt` — K4 ciphertext (97 chars)
- `db/` — SQLite databases (sweep results, novelty ledger)
- `wordlists/english.txt` — 370K words
- `reference/` — Carter book PDF + text extracts, Sanborn correspondence, archival references
- `docs/research_questions.md` — Prioritized unknowns (RQ-1 through RQ-13)

**Note**: `tools/validate_public_invariants.py` does not yet exist (create if needed per Appendix A). `tools/generate_quadgrams.py` is the only tool in `tools/`.

### Other directories

- `external/` — Third-party reference project (patrickkellogg-Kryptos).
- `anomaly_registry.md` — Catalog of physical anomalies in the Kryptos sculpture (misspellings, alignments).
- `docs/` — `research_questions.md` (RQ-1 through RQ-13), `invariants.md`, `ARCHITECTURE_PLAN.md`.

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

### Interpreting scores

`score_candidate()` returns a `ScoreBreakdown` with these key fields:
- **crib_matches** (0–24): Number of crib positions where derived key is consistent. This is the primary signal.
- **bean_pass** (bool): Whether Bean equality (k[27]=k[65]) and all 21 inequalities hold.
- **ic**: Index of coincidence of the candidate plaintext.

**Thresholds** (from `constants.py`):
| Score | Classification | Meaning |
|-------|---------------|---------|
| ≤6    | NOISE         | Expected random performance |
| 7–17  | STORE         | Worth logging, likely noise |
| 18–23 | SIGNAL        | Statistically significant, investigate |
| 24    | BREAKTHROUGH  | All cribs match — potential solution |

**False positive warning**: At periods ≥17, random configs score 17+/24 due to underdetermination. Only scores at period ≤7 are meaningful discriminators.

### Adding a hypothesis to the novelty engine

1. Add a generator function in `src/kryptos/novelty/generators.py` that yields `Hypothesis` objects
2. Each hypothesis needs: `name`, `description`, `research_question` (RQ-1 through RQ-13), `test_plan`, and `parameters` dict
3. Register the generator in the `ALL_GENERATORS` list at the bottom of `generators.py`
4. Run `PYTHONPATH=src python3 -m kryptos novelty generate` to populate the ledger
5. Run `PYTHONPATH=src python3 -m kryptos novelty triage --limit N` to test cheaply before expensive sweeps

---

## Key Gotchas

These are non-obvious pitfalls discovered through prior sessions. Check these first when debugging unexpected results.

- **0-indexed positions everywhere**: Cribs are at 21–33 and 63–73 (0-indexed). Legacy code and some public sources use 1-indexed (22–34, 64–74). Mixing conventions is the #1 source of bugs.
- **KA alphabet has no J**: `KRYPTOSABCDEFGHIJLMNQUVWXZ` — the `KA` singleton merges I/J. Standard `AZ` does not.
- **Vigenère vs Beaufort sign conventions**: `K = (CT - PT) mod 26` for Vigenère, `K = (CT + PT) mod 26` for Beaufort, `K = (PT - CT) mod 26` for Variant Beaufort. Mixing these silently produces wrong keystream.
- **Bean constraint is variant-independent**: CT[27]=CT[65]=P and PT[27]=PT[65]=R, so the equality k[27]=k[65] holds regardless of cipher variant. The 21 inequalities are also variant-independent.
- **Transposition permutation convention**: `output[i] = input[perm[i]]` — this is the "gather" convention. `invert_perm()` gives the "scatter" direction.
- **Quadgram file location**: `data/english_quadgrams.json` (2 MB, nested `{"logp": {...}}`).
- **IC below random**: K4's IC ≈ 0.0361 is *below* the random expectation of 0.0385, which is unusual and constraining.
- **pyproject.toml missing**: Package metadata survives in `src/kryptos.egg-info/`. Recreate pyproject.toml from egg-info if needed for fresh install.
- **constants.py self-verifies at import**: If you modify CT, cribs, or Bean values incorrectly, the import itself will raise an assertion error.
- **Unbuffered output for background tasks**: Always use `python3 -u` when running scripts in background. Without `-u`, Python buffers stdout and you see no output until the process ends.
- **Scoring underdetermination at high periods**: `period_consistency()` is underdetermined when `period >= (num_crib_positions / constraints_per_residue)`. At period 24, random configs score ~19.2/24; at period 17, ~17.3/24. Only period ≤7 gives meaningful discrimination (~8.2/24 expected random). **All high scores at large periods are false positives.**

---

## Truth Taxonomy (MANDATORY)

Every nontrivial statement must be explicitly classified as one of:

- **[PUBLIC FACT]** Verified by reputable public reporting or primary-source statements.
- **[DERIVED FACT]** Deterministic consequence of PUBLIC FACTS (e.g., computed from ciphertext + public cribs), reproducible by a provided command/script.
- **[INTERNAL RESULT]** Empirical result produced by this repo; must include **artifact pointers** and a **repro command**.
- **[HYPOTHESIS]** Plausible claim not yet proven; must include a test plan.
- **[POLICY]** Operating rule for how we work (not a claim about Kryptos reality).

**Hard rule:** Nothing may appear as “ground truth” unless it is **[PUBLIC FACT]** or **[DERIVED FACT]** with a reproducible check.

---

## Primary Objective

[POLICY] Determine the exact encryption process and plaintext of Kryptos K4 through:
- evidence-driven reasoning
- computationally verifiable experiments
- reproducible results
- systematic elimination of impossibilities

[POLICY] A “solution” is valid only if it satisfies **all constraints** simultaneously and deterministically, and can be reproduced from a clean run.

---

# (A) Proven / Public Facts and Derived Facts

## A1) Kryptos K4 ciphertext (canonical)

[PUBLIC FACT] K4 ciphertext:
OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR

[DERIVED FACT] Length = 97  
[DERIVED FACT] Starts with `O`, ends with `R`

[DERIVED FACT] Index of Coincidence (IC) on full ciphertext:
- IC(K4) ≈ 0.036082… (recompute via `tools/validate_public_invariants.py` or the snippet in Appendix)

[DERIVED FACT] Uniform-random IC expectation for 26 letters is 1/26 ≈ 0.0384615…

---

## A2) Public cribs (0-indexed positions)

[PUBLIC FACT] Publicly released clues imply these plaintext placements (0-indexed, inclusive):
- Positions **21–33**: `EASTNORTHEAST`
- Positions **63–73**: `BERLINCLOCK`

[DERIVED FACT] The same in 1-indexed human counting:
- 22–34 = EASTNORTHEAST
- 64–74 = BERLINCLOCK

---

## A3) Deterministic consequences of ciphertext + cribs

### A3.1 Self-equality and non-equality examples

[DERIVED FACT] At position 32: CT[32] = `S` and PT[32] = `S`  
[DERIVED FACT] At position 73: CT[73] = `K` and PT[73] = `K`

[DERIVED FACT] Not self-equal examples:
- CT[27] = `P` while PT[27] = `R`
- CT[28] = `R` while PT[28] = `T`

### A3.2 Implied keystream fragments under AZ Vigenère convention

Definition used here:
- Alphabet: A=0, …, Z=25
- “Implied keystream” at position i is **K[i] = (CT[i] − PT[i]) mod 26**

[DERIVED FACT] For PT `EASTNORTHEAST` at positions 21–33:
- K[21..33] = `BLZCDCYYGCKAZ`
- Numeric = (1,11,25,2,3,2,24,24,6,2,10,0,25)

[DERIVED FACT] For PT `BERLINCLOCK` at positions 63–73:
- K[63..73] = `MUYKLGKORNA`
- Numeric = (12,20,24,10,11,6,10,14,17,13,0)

[DERIVED FACT] Equality implied by the above:
- K[27] = `Y` (24)
- K[65] = `Y` (24)
- Therefore K[27] = K[65] = 24

---

## A4) 2025 public disclosures about K4 and K5 (facts only)

[PUBLIC FACT] K4 plaintext was reportedly found in Smithsonian archival materials and is not publicly released; access is sealed until 2075 (per 2025 reporting).  
[PUBLIC FACT] Sanborn-related “coding charts / original coding system” materials were auctioned, and public reporting cites a sale price of $962,500 (per 2025 reporting).  
[PUBLIC FACT] Additional 2025 reporting attributes to Sanborn that:
- K4’s solution relates to **two historical events** (reported as 1986 Egypt-related and 1989 Berlin Wall-related).
- The theme involves “delivering a message” (phrasing varies by report).
- K5 exists, is **97 characters**, and will share **some coded words at the same positions** as K4.
- K5 is connected conceptually to K2 (“it’s buried out there somewhere” phrasing appears in reporting).

**Important:** These are public-report facts about **claims and disclosures**, not proof of any specific cipher mechanism.

---

# (B) Internal Reproducible Results (MUST have artifact pointers)

## B0) Rule: internal results are not “truth” without artifacts

[POLICY] Any repo-generated claim belongs here as **[INTERNAL RESULT]**, and MUST include:
1) **Repro command** (copy/paste runnable)
2) **Artifact pointers**
   - code path(s)
   - run manifest (JSON/YAML/TOML) including parameters
   - output logs
   - DB file + query (if persisted)
   - git commit hash (or equivalent version stamp)
3) **Acceptance criteria** and whether it was met

If any item is missing, it is **not a result**—it is a hypothesis.

---

## B1) Internal Results Registry (fill with real entries)

Create/maintain a file (recommended): `docs/internal_results_registry.md` with entries like:

- **IR-0001**
  - Claim: …
  - Repro: `…`
  - Artifacts:
    - Code: `…`
    - Manifest: `…`
    - Logs: `…`
    - DB: `…` (plus query)
    - Commit: `…`
  - Status: reproduced Y/N, by whom, on what date

[POLICY] Claude must update the registry whenever a result is referenced in analysis or used to eliminate search space.

---

## B2) Repo “constants” are policies until proven

Examples of things that must NOT be asserted as “constants” unless validated locally:
- exact file paths (e.g., where Bean constraints live)
- counts (number of scripts/tests/DB size)
- “canonical package” claims
- “doctor checks” counts

[POLICY] If we want these to be treated as stable, we must add validation commands in Appendix D and keep them current.

---

# (C) Hypotheses and Operating Policies

## C1) Two-lane operating model

[POLICY] Lane A — Verification (hard science)
- strict reproducibility
- explicit search spaces
- precise acceptance criteria
- no narrative leaps
- code output is not “truth” without validation gates (below)

[POLICY] Lane B — Exploration (creative but disciplined)
- speculation is allowed ONLY when labeled **[HYPOTHESIS]**
- every hypothesis must end with a test plan
- prefer hypotheses that reduce entropy if true (high leverage)

---

## C2) Code skepticism doctrine

[POLICY] Never assume existing code is correct.

[POLICY] When results look “impossible” or “breakthrough”:
- suspect indexing (0 vs 1)
- permutation direction conventions
- alphabet ordering / merges (IJ, etc.)
- Beaufort/Vigenère sign conventions
- boundary inclusivity of cribs
- unintended mutation/caching/globals
- mismatched normalization rules

[POLICY] Prefer differential validation:
- write a minimal reference implementation for critical primitives
- compare against main implementation on randomized micro-tests (fixed seed)

---

## C3) Validation gates (must pass before trusting conclusions)

[POLICY] Gate 1: unit tests pass (fast)  
[POLICY] Gate 2: minimal reference implementation reproduces outcome  
[POLICY] Gate 3: invariant checks (bijection, reversibility, crib alignment)  
[POLICY] Gate 4: reproduce from a clean process (fresh interpreter); if persisted, validate DB deterministically

---

## C4) Creativity doctrine (structured)

[POLICY] Creativity is required, but must remain testable and reproducible.

**Public sentiment (accurate framing):**
- [PUBLIC FACT] Public reporting attributes to Sanborn: “Who says it is even a math solution?” (wording varies by report).
- [PUBLIC FACT] Public reporting attributes to Scheidt: K4 involves multiple stages / masking (details disputed; treat as clue/constraint, not proof).

[POLICY] Acceptable hypothesis classes:
- manual/procedural ciphers (paper rules, clocks, grids)
- orthographic manipulation (misspellings, omissions, punctuation as control)
- language-base changes (alphabet ordering, digraph rules)
- artifact-driven parameters (clock/quartz/lodestone/coordinates mapping to route/offset/primer)
- geometry/layout (reading order, projections, serpentine traversals)
- layering with a human-in-the-loop branching step

[POLICY] Every hypothesis must produce:
1) one-paragraph falsifiable statement
2) mapping to parameters
3) minimal fast test
4) expanded sweep definition + pruning
5) expected outcomes (what increases belief vs kills it)

---

## C5) K5 relationship to K4 (strictly hypothesis)

[HYPOTHESIS] K5 sharing coded words at the same positions as K4 may constrain how Sanborn reused structure across messages.  
**Not allowed as fact:** “therefore K4 is position-dependent” or eliminating stateful ciphers.  
**Test plan:** Use only claims supported by public reporting + any internal artifacts you possess; if attempting eliminations, demonstrate them with explicit assumptions and proofs.

---

# Appendix A — Public invariants validator (REQUIRED)

[POLICY] Maintain a runnable validator script that recomputes all **[DERIVED FACTS]** from **[PUBLIC FACTS]**.

Recommended location: `tools/validate_public_invariants.py`

Minimum checks:
- ciphertext length, first/last char
- crib alignment at 21..33 and 63..73
- implied keystream fragments (AZ subtraction)
- IC(full) and IC(0..20) (report both)
- print a one-line “PASS/FAIL” summary

If the repo does not yet have this, create it immediately.

