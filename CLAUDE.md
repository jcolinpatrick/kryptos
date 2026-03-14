# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

This repo has one purpose: determine the **true plaintext** and the **full encryption method** of **Kryptos K4**.

---

## The K4 Problem — Quick Reference

**Kryptos** is a sculpture at CIA headquarters containing four encrypted messages (K1–K4). K1–K3 were solved in 1999. **K4 (97 characters) has been unsolved since 1990.**

**Carved text (SCRAMBLED — NOT the real ciphertext):** `OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR`

**Known plaintext (0-indexed positions in carved text):**
- Positions 21–33: `EASTNORTHEAST`
- Positions 63–73: `BERLINCLOCK`

**CRITICAL PARADIGM (2026-03-08):** [USER GROUND TRUTH] The 97 carved characters involve **TWO SYSTEMS** of encipherment (confirmed via Sanborn dedication speech). The current leading model:
```
73-char PT → System 1 (substitution?) → 73-char CT → System 2 (insert 24 nulls + scramble) → 97 carved chars
```
Every prior experiment (600+, 669B+ configs) assumed positional correspondence on 97 chars and FAILED. The **singular mission** is to derive the full encryption method and solve K4.

**73-character hypothesis:** Sanborn's yellow legal pad (auction lot) has boxed numbers: "14 Lines" "342" "8 lines" "73". K4 = 8 lines, but carved K4 = 97 chars → **24 chars are nulls/filler**. **TRIPLE-24 COINCIDENCE**: (1) 97-73=24, (2) EASTNORTHEAST(13)+BERLINCLOCK(11)=24 crib chars, (3) Weltzeituhr=24 facets. BERLINCLOCK literally references a 24-faceted clock.

**Cardan grille (reframed as selection mask):** The grille may SELECTS 73 real chars from 97 (original Cardan function — read through holes, ignore blocked positions), rather than reordering all 97. Extract (100 chars, from 28×31 grid): `HJLVKDJQZKIVPCMWSAFOPCKBDLHIFXRYVFIJMXEIOMQFJNXZKILKRDIYSCLMQVZACEIMVSEFHLQKRGILVHNQXWTCDKIKJUFQRXCD`. See Claude Code auto-memory `cardan_grille.md` and `73_char_hypothesis.md`.

**W-as-delimiter:** 5 W's at positions [20, 36, 48, 58, 74] bracket the cribs — W at 20 immediately before EASTNORTHEAST (21), W at 74 immediately after BERLINCLOCK (73). May act as telegram-style word separators. Sanborn's clue "(CLUE) what's the point?" may reference W as period/full stop.

**What we know:** [DERIVED FACT] No single-layer classical cipher works on the carved text (exhaustively tested). [DERIVED FACT] Null mask + periodic Vig/Beau/VBeau (periods 1-23) is IMPOSSIBLE for ANY choice of 24 null positions (proven 2026-03-11 via exhaustive (n1,n2,n3) enumeration). [DERIVED FACT] MITM sub (mono, periodic, autokey) × structured transposition (14 families, ~1.2B configs) = ZERO hits (proven 2026-03-12/13). [DERIVED FACT] Four-Square, Playfair, Two-Square, VIC cipher, 2-round Feistel, Gronsfeld, Porta, Trithemius — ALL eliminated as single layer (2026-03-13). [PUBLIC FACT, PRIMARY SOURCE] Sanborn: "There are TWO SYSTEMS of enciphering the bottom text... designed to UNVEIL ITSELF... pull up one layer, come to the next." [HYPOTHESIS] The Cardan grille selects 73 of 97 positions (null mask). See [`reports/final_synthesis.md`](reports/final_synthesis.md) for the elimination landscape.

**Current best lead (2026-03-14):** [INTERNAL RESULT] DEFECTOR:AZ_beau + col7 transposition + null mask scores **15/24** (ene=7/13, bcl=8/11). This is a **confirmed hard 3-swap local maximum** (223.7M evals, zero improvement). Achieves 3.3% of SA restarts (5/150). 17/24 null positions are identical across all 6 distinct 15/24 masks. 4/5 W-positions are consensus nulls, supporting the W-delimiter hypothesis. DEFECTOR:AZ_beau:col7 is **uniquely** at 15/24 — all 18 other keyword/variant/alphabet combinations tested max at 14/24. Model ceiling at 15/24 suggests it may be incomplete or the correct model with wrong parameters.

**K2 coordinates encode K4 structure:** [DERIVED FACT] K2's "38 degrees" → 3²+8²=**73**, 3×8=**24**, 3+8=**11**. "6.5" → ×2=**13**, 6+5=**11**. UNIQUE two-digit number with all three properties. Monte Carlo: ~1 in 180M by chance. Operational mechanism unknown.

**What we don't know:** Which 24 of 97 positions are nulls, whether cribs apply to carved or real CT positions, the structural rule governing null placement, and whether the correct cipher model is a variant of the DEFECTOR:AZ_beau+col7 model or something entirely different. Running key, monoalphabetic, and autokey are all eliminated WITH standard transposition — the surviving cipher space requires either non-standard transposition, a bespoke combination, or a model we haven't conceived.

---

## Development Setup & Commands

**Python 3.11+** required (uses `tomllib` from stdlib). **No external runtime dependencies** — stdlib only. `pytest` is the only dev dependency. No `pyproject.toml` or `setup.py` — `pip install -e .` will not work. All commands require `PYTHONPATH=src`.

A `venv/` exists with numpy, pymupdf, and jinja2 but is gitignored. Activate with `source venv/bin/activate` if needed for PDF/matrix work or the site builder, but core code uses stdlib only.

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
```

---

## Architecture

Four layers with strict dependency direction: **kernel → pipeline → novelty → cli**

### Source layout (`src/kryptos/`)

- **kernel/** — Pure computation, zero external dependencies, **all positions 0-indexed**.
  - `constants.py` — **SINGLE source of truth**: CT, cribs, Bean constraints, keystream values, scoring thresholds. Runs `_verify()` at import time. **Never define CT or cribs elsewhere.**
  - `alphabet.py` — `Alphabet` class, `AZ`/`KA` singletons, `keyword_mixed_alphabet()`, `THEMATIC_KEYWORDS`
  - `text.py` — Text normalization: `sanitize()`, `text_to_nums()`, `nums_to_text()`, `char_to_num()`, `num_to_char()`
  - `transforms/` — Cipher implementations (Vigenère/Beaufort, transpositions, Polybius) + composable pipeline builder (`compose.py`: `TransformConfig` → `PipelineConfig` → `build_pipeline()`)
  - `constraints/` — Crib scoring (`crib.py`), Bean equality/inequality (`bean.py`), consistency checks (`consistency.py` — self-encrypting positions, monoalphabetic consistency)
  - `scoring/aggregate.py` — Two canonical scoring paths: `score_candidate()` (anchored cribs at fixed positions) and `score_candidate_free()` (cribs searched anywhere — critical for scrambled-CT paradigm). Thresholds: NOISE=6, STORE=10, SIGNAL=18, BREAKTHROUGH=24. Individual scorers: `crib_score.py`, `free_crib.py`, `ic.py`, `ngram.py`.
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

607+ standardized attack scripts organized into ~28 family subdirectories (e.g. `scripts/grille/`, `scripts/transposition/`, `scripts/blitz/`, `scripts/tableau/`, `scripts/team/`, `scripts/yar/`, `scripts/campaigns/`). Each script has a parseable metadata header and is tracked in `exhaustion_log.json` (574 entries; newer scripts may not yet be registered). Use `run_attack.py --list` to discover scripts or `run_attack.py --run --family <name>` to dispatch by family.

**Script infrastructure (`scripts/lib/`):**
- `header.py` — Parse/validate metadata headers (Cipher, Family, Status, Keyspace, Last run, Best score)
- `exhaustion.py` — CRUD for `exhaustion_log.json` (authoritative source of truth for status)
- `discover.py` — Recursive script discovery and manifest generation
- `migrate.py` — Batch migration CLI for adding headers

**Standard `attack()` contract** (15 scripts migrated, remainder use legacy subprocess mode):
```python
def attack(ciphertext: str, **params) -> list[tuple[float, str, str]]:
    """Returns [(score, plaintext, method_description), ...] sorted by score desc."""
```

**Writing a new experiment script:**
1. Place it in the appropriate family subdirectory: `scripts/<family>/e_<topic>_<nn>_<short_name>.py`
2. Add a standard metadata header (see `scripts/examples/e_caesar_standard.py`)
3. Import constants from `kryptos.kernel.constants` (never hardcode CT/cribs)
4. Implement `attack(ciphertext, **params)` returning `list[tuple[float, str, str]]`
5. Write results to `results/<experiment_id>.json` or `results/<experiment_id>/`
6. Register in `exhaustion_log.json` via `scripts/lib/exhaustion.update()`
7. Use `python3 -u` for unbuffered output when running in background

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

Builds the `kryptosbot.com` static site. Requires jinja2 (in venv). Build with `python3 site_builder/build.py`, preview with `cd site && python3 -m http.server 8000`. Output goes to `site/` (gitignored). Key modules: `data_loader.py` (loads experiment data from DBs/artifacts), `categorizer.py` (classifies experiments by method), `search_index.py` (generates client-side search index), `overrides.toml` (per-experiment display overrides).

### API backend (`api/`)

FastAPI backend for kryptosbot.com. Theory classifier endpoint (Claude-powered), submission queue (SQLite), CORS, rate limiting. Run with `python3 site_builder/serve.py` (requires venv: fastapi, uvicorn, python-dotenv, anthropic). Mounts `site/` as static files.

### KryptosBot SDK (`kryptosbot/`)

Claude Agent SDK multi-agent campaign runner. Separate from the core `src/kryptos/` package. Two-level namespace: `kryptosbot/kryptosbot/` is the Python package (imports as `kryptosbot.kryptosbot.*`). Entry points: `python3 kryptosbot/solve.py` (campaigns), `python3 kryptosbot/monitor.py` (live dashboard). Key modules in `kryptosbot/kryptosbot/`: `strategies.py` (23 strategies in 4 modes: UNSCRAMBLE/REASONING/COMPUTE/LEGACY), `agent_runner.py` (session loop + token tracking), `sdk_wrapper.py` (SDK safety wrapper), `compute.py` (local multiprocessing), `database.py` (SQLite). Requires `claude-agent-sdk` and `python-dotenv` (in venv). Results go to `results/` (gitignored).

### Other directories

- **`bench/`** — Benchmark framework (see above).
- **`bin/`** — Standalone engine scripts for Antipodes and cylinder rotation analysis (`antipodes_device_engine.py`, `antipodes_key_engine.py`, `cylinder_rotation_engine.py`).
- **`jobs/`** — Job queue with `pending/`, `running/`, `done/`, `failed/` subdirectories for experiment management.
- **`deploy/`** — Production deployment configs: systemd service (`kryptosbot-api.service`), nginx config, cron updater, setup script.
- **`tools/`** — Utility scripts (e.g. `generate_quadgrams.py` for rebuilding quadgram data).

**Top-level scripts:** `run_attack.py` (dispatch runner), `run_lean.py` (lightweight runner), `worker.py` (job worker), `k4_job_runner.sh` (shell job harness).

### Gitignored directories

`db/`, `results/` (unified KryptosBot output: `campaigns/`, `compute/`), `artifacts/`, `agent_logs/`, `work/`, `tmp/`, `venv/`, `site/`, `checkpoints/`, `blitz_results/`, `kbot_results/`, `split_results/` — per-run data, must not be committed.

---

## Interpreting Scores

`score_candidate()` returns a `ScoreBreakdown` with these key fields:
- **crib_score** (0–24): Number of crib positions where derived key is consistent. Primary signal. (Split into `ene_score` 0–13 and `bc_score` 0–11.)
- **bean_passed** (bool): Whether Bean equality (k[27]=k[65]) and all 242 variant-independent inequalities hold.
- **ic_value**: Index of coincidence of the candidate plaintext.
- **ngram_score** / **ngram_per_char**: Optional n-gram quality metrics.
- **crib_classification**: One of "noise", "interesting", "signal", "breakthrough".

`score_candidate_free()` returns a `FreeScoreBreakdown` with the same interface but searches for cribs at any position (for scrambled-CT work).

| Score | Classification | Stored? | Meaning |
|-------|---------------|---------|---------|
| 0–9   | noise         | No (≤9) | Expected random performance |
| 10–17 | interesting   | Yes     | Worth logging, likely noise |
| 18–23 | signal        | Yes     | Statistically significant, investigate |
| 24    | breakthrough  | Yes     | All cribs match — potential solution (requires Bean PASS) |

Note: `is_above_noise()` triggers at score > 6, but `is_storable()` and DB persistence trigger at score ≥ 10 (`STORE_THRESHOLD`). Scores 7–9 are above noise floor but not persisted.

**False positive warning**: At periods ≥17, random configs score 17+/24 due to underdetermination. Only scores at period ≤7 are meaningful discriminators. **Note:** With the full 242 variant-independent Bean inequality set, ALL periods 1–26 are eliminated for periodic substitution on the raw 97-char carved text. The previous result (only periods 2–7 eliminated) used an incomplete 21-pair subset.

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
- **Scoring underdetermination at high periods**: `period_consistency()` is underdetermined when `period >= (num_crib_positions / constraints_per_residue)`. At period 24, random configs score ~19.2/24; at period 17, ~17.3/24. Only period ≤7 gives meaningful discrimination (~8.2/24 expected random). **All high scores at large periods are false positives.**
- **Bifid 5×5 impossible for K4**: All 26 letters appear in K4 CT; any cipher requiring a 25-letter alphabet (I/J merged) is eliminated.
- **15/24 is a hard local maximum**: SA and hill-climbing on the DEFECTOR:AZ_beau+col7+null-mask model get stuck at 15/24. Exhaustive 2-swap (1.95M evals) and 3-swap (223.7M evals) find ZERO improvements. Do not waste time running more SA restarts or small-neighborhood searches on this model — explore different models or larger structural changes instead.
- **K2 numbers are NOT direct cipher keys**: Despite encoding 73/24/13/11, K2's "38 degrees 57 minutes 6.5 seconds" as raw numbers produce only noise (6/24 max) when used as Vigenère keys, transposition keys, or autokey primers. The encoding is confirmed real but the operational mechanism is unknown.

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
- Grille details and current hypotheses: see Quick Reference above + Claude Code auto-memory (`cardan_grille.md`, `73_char_hypothesis.md`)
- DO NOT re-run old direct-decryption attacks on 97 chars — they assumed wrong positional correspondence
- DO NOT re-run MITM sub×transposition — mono/periodic/autokey sub × 14 standard transposition families exhaustively eliminated (~1.2B configs, ZERO hits, 2026-03-12/13)
- DO NOT run more SA/hill-climbing on DEFECTOR:AZ_beau+col7 — 15/24 is a confirmed hard 3-swap local max (223.7M evals)
- **Current best lead:** DEFECTOR:AZ_beau + col7 transposition + null mask = 15/24. Uniquely highest among 19 keyword/variant combinations tested. See "Current best lead" in Quick Reference above.
- Top keyword candidates (by pigeonhole letter-supply): KRYPTOS, KOMPASS, DEFECTOR, COLOPHON, ABSCISSA — note: ALL fail full Bean check on raw 97-char text (consistent with two-system model)
- **HOROLOGE and ENIGMA are ELIMINATED** (pigeonhole analysis)
- **Also eliminated:** Four-Square, Playfair, Two-Square, VIC, Feistel, Gronsfeld, Porta, Trithemius, all periodic sub on raw 97 AND any null-extracted 73

**KryptosBot agent runner:** `python3 kryptosbot/solve.py` launches the unified campaign runner. See `kryptosbot/RUNBOOK.md` for full usage. Key commands: `solve.py` (6 parallel agents), `solve.py compute` (free local CPU), `solve.py run <name>` (single strategy), `solve.py list` (show all strategies).

**Historical reference:** Previous custom 6-agent harness (170+ experiments) archived in `archive/legacy_harness/` and `archive/session_reports/`. Comprehensive synthesis: [`reports/final_synthesis.md`](reports/final_synthesis.md).

---

*Last updated: 2026-03-14 — Mission: derive K4 method & solve. Best lead: DEFECTOR:AZ_beau+col7+null-mask=15/24 (hard 3-swap local max). Standard sub×trans exhaustively eliminated (~1.2B configs). Four-Square/VIC/Feistel/digraphic all eliminated. Surviving space: non-standard transposition, bespoke combinations, or unconceived models. K2 coords confirmed to encode 73/24/13/11 (mechanism unknown). Top keywords: DEFECTOR (uniquely 15/24 with col7), KRYPTOS, KOMPASS, COLOPHON, ABSCISSA*
*Primary author: Colin Patrick (human lead) + Claude (computational partner)*
