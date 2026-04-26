# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

This repo has one purpose: determine the **true plaintext** and the **full encryption method** of **Kryptos K4**.

**Contents:** [Pre-flight](#pre-flight-every-task--do-not-skip) · [K4 Problem](#the-k4-problem--quick-reference) · [Dev Setup](#development-setup--commands) · [Architecture](#architecture) · [Gotchas](#key-gotchas) · [Scores](#interpreting-scores) · [Compute](#compute-environment--high-power-vm) · [Truth Taxonomy](#truth-taxonomy-mandatory) · [Reference Docs](#reference-documents) · [Memory](#persistent-memory-claude-and-memory) · [Multi-Agent](#multi-agent-mode--solve-k4)

---

## Pre-flight (EVERY task — do NOT skip)

1. Read this entire CLAUDE.md (operational doctrine only — not research state).
2. **Run the session briefing** — authoritative derived state:
   ```bash
   PYTHONPATH=src python3 scripts/_infra/session_briefing.py
   ```
   Reads `exhaustion_log.json`, `results/*.json`, and `docs/elimination_tiers.md` to produce a current elimination landscape, anomalies, open attack surface, and DO NOT TEST list. **It replaces all hand-maintained elimination ledgers.** If the briefing errors or is unusably slow, fall back to reading `MEMORY.md` §1–5 and `docs/elimination_tiers.md` directly, and tell the user the briefing failed so the failure doesn't go silent.
3. Read **`MEMORY.md`** (auto-loaded) — live control document: current state, hard blockers, active bins, open audits, do-not-revive list. Short by design.
4. Read **`docs/README_current_state.md`** — canonical entry index for the live path (claim registry, methodological audits, historical/retired quarantines).
5. Check **`docs/methodological_audits.md`** for any open audit that touches your task. Disputed claims block new compute until their audit closes.
6. If the task matches anything in the briefing's TIER 1 / DO NOT TEST sections or the `MEMORY.md` do-not-revive list → **STOP, tell the user, do NOT re-run**.
7. `run_attack.py --list --verbose | grep KEYWORD` — search before writing new code.
8. **If the task involves CPU-bound work**: `bash scripts/vm_capability_report.sh` — establish runtime capabilities (see [Compute Environment](#compute-environment--high-power-vm)).
9. **If the task involves the internalloop**: read `<internal>` (~5 min) — one-page operator onboarding for the research runner. Covers the three commands, where truth lives, and 5 common failure modes.
10. **If the task modifies the kernel's scoring or transforms**: run `PYTHONPATH=src python3 <internal> --panel all --mode dry-run` — falsification test that K1/K2 are still rediscoverable. Takes ~1 second. Added in framework internal phase 7 (2026-04-21) as the project's standing fitness check.

Skipping these steps and re-testing an eliminated hypothesis wastes 28 CPU cores and burns API tokens for zero value.

---

## The K4 Problem — Quick Reference

**Kryptos** is a sculpture at CIA headquarters containing four encrypted messages (K1–K4). K1–K3 were solved in 1998–1999. **K4 (97 characters) has been unsolved since 1990.** Two encryption systems are reported by the creator; treat such statements as Tier-3 community hearsay unless independently corroborated (see `feedback_sanborn_epistemic_weight.md`).

CLAUDE.md is **operational doctrine only**: how to work, where truth lives, how to classify claims, how to avoid re-testing dead hypotheses. It does **not** describe the current favorite theory, what the project is "close" to, or any leading hypothesis framing. For that see:

- **`MEMORY.md`** — live control document (current state, bins, audits, do-not-revive).
- **`docs/README_current_state.md`** — canonical entry index.
- **`docs/claims_registry.json`** — structured seed registry of live / disputed / retired / historical-snapshot claims.
- **`docs/methodological_audits.md`** — open epistemic audits.

Historical strategy snapshots live in `docs/history/` and `reports/final_synthesis.md` (both banner-labelled HISTORICAL SNAPSHOT). Retired research notes live in `memory/retired/`. Do not cite either as current doctrine.

---

## Development Setup & Commands

**Python 3.11+** required (uses `tomllib` from stdlib; dev environment runs 3.12.3). **No external runtime dependencies** — stdlib only. `pytest` is the only dev dependency. No `pyproject.toml` or `setup.py` for the core project — `pip install -e .` will not work. All commands require `PYTHONPATH=src`. (`<internal>/` has its own `pyproject.toml` for the Agent SDK dependency — that's separate.) **Repo:** `github.com/jcolinpatrick/kryptos`.

Common kernel symbols (`CT`, `CRIB_POSITIONS`, `BEAN_EQ`/`BEAN_INEQ`, `KA`, `score_candidate`, `decrypt_vigenere`/`decrypt_beaufort`) live under `kryptos.kernel.{constants,alphabet,scoring.aggregate,transforms.vigenere}`. Grep there before assuming a name.

A `venv/` exists (gitignored) for non-core work pinned in root `requirements.txt` (numpy, scipy, z3-solver, ortools, statsmodels, simanneal, rich, anthropic, agent-sdk, fastapi, uvicorn, jinja2, pymupdf). None of this is imported by core `kryptos` code. No linter or formatter configured. Development happens directly on `main`.

```bash
# Run all tests (~2 minutes, 1500+ tests, no expected failures).
# Exact count drifts; authoritative: `PYTHONPATH=src pytest tests/ --collect-only -q | tail -1`
PYTHONPATH=src pytest tests/

# Run a single test file or test
PYTHONPATH=src pytest tests/test_transforms.py
PYTHONPATH=src pytest tests/test_transforms.py::TestVigenereFamily::test_text_roundtrip_vig -v

# Run an experiment script (always use -u for unbuffered output)
PYTHONPATH=src python3 -u scripts/_uncategorized/e_nsa_01_interval7.py

# Environment health check
PYTHONPATH=src python3 -m kryptos doctor

# CLI: sweep, reproduce, novelty, report
PYTHONPATH=src python3 -m kryptos sweep <config.toml> --workers 8
PYTHONPATH=src python3 -m kryptos reproduce <manifest.json>
PYTHONPATH=src python3 -m kryptos novelty generate
PYTHONPATH=src python3 -m kryptos novelty triage --limit 50
PYTHONPATH=src python3 -m kryptos report <db.sqlite> top --limit 20 --min-score 10

# Verify a hypothesis hasn't already been tested (check BEFORE running anything new)
PYTHONPATH=src python3 run_attack.py --exhaustion-summary | grep -i FAMILY
PYTHONPATH=src python3 run_attack.py --list --verbose | grep -i KEYWORD

# Benchmark: PYTHONPATH=src python3 bench/cli.py run --suite bench/suites/tier0_smoke.jsonl

# K4Bench (synthetic calibration; redirects ledger to db/k4bench/, never touches real-K4 state)
PYTHONPATH=src python3 -u <internal> --bench-challenge bench/k4bench/challenges/K4B-001.json [--bench-attempts-out <out.json>]
```

For site builder, API server, and deployment commands, see [`docs/operations.md`](docs/operations.md).

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
- **campaigns/** — Campaign runners for structured multi-layer searches. `two_layer/` handles substitution+transposition sweeps with checkpoint/resume (`checkpoint.py`), coverage tracking (`coverage.py`), parallel dispatch (`parallel.py`), and evaluation (`evaluation.py`). `w_delimiter/` is a second campaign family. `manifest.py` and `historical_eliminations.py` track what's been tested.
- **admissibility/** — Pre-flight feasibility gates: `periodic_admissibility.py` (period-based filtering), `procedure_policy.py` (procedural constraint enforcement), `corpus_policy.py` (running-key source validation), `certificate.py` (admissibility certificates for audit trails).
- **composition/** — Orchestrator for multi-step cipher compositions: `orchestrator.py` drives multi-layer pipelines, `scoring_bridge.py` adapts kernel scoring for composed candidates, `constraints.py` enforces cross-layer constraints, `registry.py`/`ledger.py` track composition families and results.
- **detectors/** — Joint two-sided detector for the E-FRAC-54 family. Scores PT and implied running-key tape simultaneously (`T = L_PT + L_K - Penalty`) to prevent mono DOF from absorbing the quadgram budget on 97 chars.
- **language/** — Soft grammar prior for K4 candidate phrases. Models telegraphic/directive registers, verb/noun phrase templates, and anchor-context plausibility around the two known cribs. This is a **soft prior only** -- it never promotes candidates to signal status; use it for ranking short fill candidates.
- **cipher_discovery/** — DB-backed pipeline for identifying hand-executable cipher variants relevant to K4: seed expansion, knowledge-base construction, classification, and deduplication. Separate from the attack scripts.
- **cli/** — Thin wrappers for `doctor`, `sweep`, `reproduce`, `novelty`, `report`.

**`<internal>/` (separate subproject, NOT under `src/kryptos/`)** — Research runner built on the Agent SDK. Has its own `pyproject.toml`, its own `.env` (see `<internal>`), its own runbook (`<internal>`), and depends on `agent-sdk`. **Do not confuse with the core `kryptos` package** — they have independent dependency trees and different API key env vars. Core kryptos must stay stdlib-only; internalmay use anything in its own venv.

**K4Bench mode (`bench/k4bench/` + `<internal>` + `bench_records.py`)** — Synthetic calibration suite of 25 K4-shaped challenges. Activate with `--bench-challenge <path>` on `run_controller.py`; this installs kernel overrides **before** any `kryptos.kernel` import, swaps the ledger to `db/k4bench/`, suppresses real-K4 prompt surfaces, and emits an attempt artifact in `k4bench.attempts.v1` schema. `bench_load` rejects any file containing answer-like keys; sealed answers must never reach controller paths or prompt-visible code. See MEMORY.md `project_k4bench_mode_pipeline_gates_landed_2026_04_26.md`.

**`external/` (repo root, NOT under `src/`)** — Third-party reference material checked into the tree:
- `external/bean_k4testing/` — Bean's reference C / SageMath implementation of the K4 constraints (`k4-bean3.c`, `k4-perm-test.c`, `kryptos-k4-sage.txt`, `k4testing.py`). This is the **authoritative cross-check** for `kernel/constants.py` Bean equality/inequality values. When debugging constraint semantics or verifying a new Bean-derived claim, diff against this reference, do not re-derive from the paper.
- `external/claude-plugins-official/` — Unpinned plugin source, reference only.

**`copy/` (repo root)** — Curated software-review snapshot of internal(114 files, flat layout, original paths encoded in filenames). Regenerated for third-party software review. **Do not edit directly** — changes belong in `<internal>/`. Exclude from grep when working on the live controller.

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

Several hundred attack scripts across ~40 subdirectories in `scripts/` (run `ls scripts/` for the current list). For current counts and exhaustion state, run `PYTHONPATH=src python3 run_attack.py --exhaustion-summary` — **do not cite hardcoded numbers**, they drift. Each script has a metadata header; tracked in root `exhaustion_log.json` (authoritative — ignore `scripts/EXHAUSTION.json`). Some scripts live at the `scripts/` root level (e.g. `blitz_*.py`, `geometric_null_mask_*.py`) rather than in subdirectories.

**Subdirectories:** Run `ls scripts/` for the full list. Key families: `substitution/`, `transposition/`, `fractionation/`, `grille/`, `polyalphabetic/`, `running_key/`, `encoding/`, `multi_layer/`, `novel/`, `blitz/` (fast hypothesis sweeps), `analysis/` (non-attack analytical scripts), `_infra/` (utilities), `hypothesis_tests/` (harness scripts — h_* prefix), `stego_mechanism/`, `tableau/`, `statistical/`, `cfm/` (crypto field manual hypotheses), `two_system/`, `yar/`, `team/`. Additional research threads: `antipodes/`, `archive_evidence/`, `crib_analysis/`, `exploration/`, `geodetic/`, `geometry/`, `k2_coords/`, `k3_continuity/`, `mirror_ka/`, `overlay/`, `thematic/` (subdirs: `berlin_clock/`, `sculpture_physical/`).

**`scripts/lib/`** — Shared infrastructure for experiment scripts: `header.py` (metadata header parsing), `exhaustion.py` (exhaustion log CRUD), `discover.py` (script discovery). Used by `run_attack.py`.

**Discovery & dispatch** via `run_attack.py` (5 modes):
```bash
PYTHONPATH=src python3 run_attack.py --list --verbose              # List all scripts with metadata
PYTHONPATH=src python3 run_attack.py --run --family grille          # Run scripts by family
PYTHONPATH=src python3 run_attack.py --run --id e_caesar_01         # Run a single script by ID
PYTHONPATH=src python3 run_attack.py --manifest -o manifest.json    # Generate manifest JSON
PYTHONPATH=src python3 run_attack.py --reconcile                    # Check header vs log mismatches
PYTHONPATH=src python3 run_attack.py --exhaustion-summary           # Summarize exhaustion log
# Filters: --family, --status (exhausted|active|promising), --min-score, --attack-only, --header-only, --timeout, --top-n
```

**Naming:** `e_` = experiment, `f_` = formal campaign, `h_` = harness (structured multi-config evaluator, lives in `scripts/hypothesis_tests/`), `blitz_` = fast hypothesis sweep (some live at `scripts/` root level). Subdirectory scripts live in `scripts/<family>/`. `_infra/` = utilities, not attacks.

**Second runner — `run_lean.py`** (root, separate from `run_attack.py`): two-phase runner — Phase A does local multiprocessing compute with zero tokens (statistical profiling, simple-cipher disproof, keyword sweeps, columnar brute-force), then Phase B spends tokens on an Agent SDK synthesis pass over Phase A outputs. Use `run_lean.py` for token-efficient hypothesis sweeps where the LLM only adds value at the synthesis step; use `run_attack.py` for script-family dispatch against the ~45 `scripts/*/` subdirectories. Do not confuse the two — they have overlapping names but distinct purposes.

**Standard contract** (see `scripts/examples/e_caesar_standard.py` for full template):
```python
def attack(ciphertext: str, **params) -> list[tuple[float, str, str]]:
    """Returns [(score, plaintext, method_description), ...] sorted by score desc."""
```

**Standalone bootstrap** (scripts 2 dirs deep; add `os.path.dirname()` per extra level):
```python
import sys, os
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))
```

**Adding a new script:** (1) Name it `e_<family>_<nn>_<description>.py` in the appropriate `scripts/<family>/` subdirectory. (2) Include a metadata header (see `scripts/examples/e_caesar_standard.py`). (3) Register it in root `exhaustion_log.json` (NOT `scripts/EXHAUSTION.json`). (4) Use the standalone bootstrap above (adjust `os.path.dirname()` depth if deeper than 2 levels — see "Key Gotchas"), import constants from `kryptos.kernel.constants` (never hardcode), and implement the `attack()` contract.

### Tests

Three categories: **Unit** (`test_transforms.py`, `test_scoring.py`, etc.), **QA verification** (`test_qa_*.py`, `test_audit_*.py` — structural claims and audit assumptions), **Benchmark** (`test_bench*.py`).

**Adding tests:** Place in `tests/test_<module>.py` matching the source module. QA tests go in `test_qa_*.py`. No test framework beyond `pytest` — use plain `assert`. Run single: `PYTHONPATH=src pytest tests/test_transforms.py::TestClass::test_name -v`.

### Key data files

- `data/english_quadgrams.json` — Quadgram log-probabilities (2 MB, `{"THAN": -3.776, ...}`)
- `wordlists/english.txt` — 1M+ words; `wordlists/thematic_keywords.txt` — thematic keywords
- `reference/` — Primary sources (Carter book, Sanborn correspondence, NSA docs, Ed Scheidt dossier, video transcripts, PDFs)
- `docs/crypto_field_manual/` — Durable cryptographic knowledge base
- `memory/` (repo root) — Checked-in live research notes (keystream forensics, width analysis, TICOM). **Retired notes live under `memory/retired/`** — do not cite them as evidence. See `memory/retired/README.md`.

### Data persistence & symlinks

Data directories are **symlinked** to a separate data partition:
- `db/` → `/data/db` — SQLite databases (novelty ledger, results)
- `artifacts/` → `/data/artifacts` — Result artifacts (JSONL logs)
- `checkpoints/` — Campaign checkpointing for resumable runs
- `exhaustion_log.json` — **Authoritative** experiment log (root level — ignore `scripts/EXHAUSTION.json`)

### Supporting systems & operations

Supporting systems (site builder, API, campaign runner, benchmarks, deployment) are documented in [`docs/operations.md`](docs/operations.md).

---

## Key Gotchas

These are non-obvious pitfalls discovered through prior sessions. Check these first when debugging unexpected results.

- **Every command needs `PYTHONPATH=src`**: There is no `setup.py` or `pyproject.toml`. Forgetting `PYTHONPATH=src` is the most common `ModuleNotFoundError`.
- **`scoring/` is at `kernel/scoring/`**: NOT a top-level package. Import from `kryptos.kernel.scoring.aggregate`.
- **0-indexed positions everywhere**: Cribs are at 21–33 and 63–73 (0-indexed). Legacy code and some public sources use 1-indexed (22–34, 64–74). Mixing conventions is the #1 source of bugs.
- **KA alphabet has non-standard ordering**: `KRYPTOSABCDEFGHIJLMNQUVWXZ` — all 26 letters present but reordered (keyword "KRYPTOS" first). The `KA` singleton uses this ordering; standard `AZ` uses alphabetical. Both contain all 26 letters. (The "KA has no J" claim in prior versions was **wrong**.)
- **Vigenère vs Beaufort sign conventions**: `K = (CT - PT) mod 26` for Vigenère, `K = (CT + PT) mod 26` for Beaufort, `K = (PT - CT) mod 26` for Variant Beaufort. Mixing these silently produces wrong keystream.
- **Bean constraint is variant-independent**: CT[27]=CT[65]=P and PT[27]=PT[65]=R, so the equality k[27]=k[65] holds regardless of cipher variant. The 242 inequalities are also variant-independent (derived from all C(24,2)=276 crib pairs; 242 have distinct key values under all 3 variants). The 101 linear constraints (`BEAN_LINEAR`) are likewise variant-independent. All three constraint types are checked by `verify_bean()` and `verify_bean_simple()`. Combined, they admit exactly **624 valid keystreams** at the 24 crib positions.
- **Transposition permutation convention**: `output[i] = input[perm[i]]` — this is the "gather" convention. `invert_perm()` gives the "scatter" direction.
- **IC below random**: K4's IC ≈ 0.0361 is below the random expectation of 0.0385. [INTERNAL RESULT] FRAC agent (E-FRAC-04) showed this deviation is NOT statistically significant for a 97-char text. Do not use IC alone as a discriminator.
- **constants.py self-verifies at import**: If you modify CT, cribs, or Bean values incorrectly, the import itself will raise an assertion error.
- **Unbuffered output for background tasks**: Always use `python3 -u` when running scripts in background. Without `-u`, Python buffers stdout and you see no output until the process ends.
- **Bifid 5×5 impossible for K4**: All 26 letters appear in K4 CT; any cipher requiring a 25-letter alphabet (I/J merged) is eliminated.
- **High scores are almost always false signals**: See `MEMORY.md` §5 "Do-Not-Revive List" and the `BREAKTHROUGH` label caveat in `docs/README_current_state.md` §4. The `BREAKTHROUGH` label (`crib_score == 24 && bean_passed`) is an **input to validation**, not an output of it — historical emission has been dominated by post-hoc overfits. Treat it as a candidate for investigation, not a solution. See `docs/methodological_audits.md` AUDIT-3.
- **Beaufort A=0 is the confirmed default**: Use A=0 indexing for all Beaufort operations unless explicitly testing A=1. Both conventions must be tested in positional experiments.
- **Standalone script `_ROOT` depth**: The bootstrap snippet (`_ROOT = os.path.dirname(os.path.dirname(...))`) assumes the script is exactly 2 directories deep (e.g. `scripts/grille/e_foo.py`). Scripts at 3+ levels need additional `os.path.dirname()` wrappers or they'll get `ModuleNotFoundError`. Robust alternative: `_ROOT = os.path.dirname(os.path.abspath(__file__))` then `while not os.path.exists(os.path.join(_ROOT, 'src')): _ROOT = os.path.dirname(_ROOT)`.
- **Always import constants, never hardcode**: For CT/cribs/Bean values, import from `kryptos.kernel.constants`. A prior session generated a script with fabricated null positions that shared only 3/17 values with the consensus — the results were silently invalid. **Caveat on `CONSENSUS_NULL_POSITIONS`**: the 17-position null mask in `kernel/constants.py` is pending retraction — it was derived from the retired palette hypothesis and has no independent verification. Do not cite it as established fact in new theories. See `memory/project_consensus_nulls_epistemic_status_2026_04_14.md`.
- **`doctor` `bean_count` always FAILs — not a real problem**: `cli/doctor.py:35` checks `len(BEAN_INEQ) == 21` but the constant has held 242 inequalities since the Bean Linear constraints expansion. This is a stale threshold, not an environment error. All other `doctor` checks are authoritative; ignore `bean_count` until the check is updated.
- **Exhaustion log — one authoritative source**: Root `exhaustion_log.json` is the single source of truth. The former second log at `scripts/EXHAUSTION.json` was retired and renamed to `scripts/EXHAUSTION.json.RETIRED` (see `scripts/EXHAUSTION.json.RETIRED.README` for the retirement note). If any script or doc still references `scripts/EXHAUSTION.json`, that's a stale pointer — fix it to read the root log.
- **Two `.env` files — don't mix them up**: `.env` (root) = `ANTHROPIC_API_KEY` + `KBOT_CLASSIFY_API_KEY` + `NTFY_TOPIC`. `<internal>` = Agent SDK API key (see `<internal>`). Loading the wrong one gives silent auth failures.
- **K4Bench sealed answers must not enter prompt context**: any `bench/k4bench/answers/*` (when present) and any answer-keyed JSON are off-limits to controller paths. `bench_load.load_k4bench_challenge()` rejects answer-like keys at load time — that's the boundary. Don't add helpers that bypass it; sealed answer leakage invalidates the calibration run.
- **Quagmire III requires explicit convention args**: `quagmire_encrypt` / `quagmire_decrypt` in `src/kryptos/kernel/transforms/quagmire.py` only reproduce the Kryptos K1/K2 convention when called with `pt_alphabet_keyword=..., ct_alphabet_keyword='KRYPTOS', indicator='K'`. Calling with the wrong shape does NOT raise — it silently produces output that fails K1/K2 ground-truth regression. `scripts/campaigns/f_w10_quagmire_iii_v1.py` was historically misconfigured this way; K1/K2 regression tests landed 2026-04-21 as the standing guard. Before trusting any new Quagmire result, verify the regression tests pass.
- **Never `git push origin main` directly — use the publish script**: `<internal>/` and `<internal>` are private and intentionally excluded from the public GitHub mirror. A pre-push hook at `.githooks/pre-push` blocks any push containing those paths (DELETIONS of forbidden paths are allowed in case of past leakage; ADDITIONS are blocked). To publish to the public mirror, run `ops/publish/publish_to_github.sh` — it uses an isolated git worktree to filter the private paths and falls back to `git apply --3way` then cherry-pick on conflicts. The privacy boundary is a deliberate protection policy, not an oversight; never propose un-ignoring `<internal>/` or removing the hook. See `feedback_publish_workflow.md` and `feedback_internal_gitignored_by_design.md`.

---

## Interpreting Scores

Two scoring paths in `kernel/scoring/aggregate.py`: `score_candidate()` (anchored cribs at fixed positions) and `score_candidate_free()` (cribs searched anywhere — for scrambled-CT work). Both return a breakdown with `crib_score` (0–24), `bean_passed`, `ic_value`, `ngram_score`, and `crib_classification`.

| Score | Classification | Stored? | Meaning |
|-------|---------------|---------|---------|
| 0–9   | noise         | No (≤9) | Expected random performance |
| 10–17 | interesting   | Yes     | Worth logging, likely noise |
| 18–23 | signal        | Yes     | Statistically significant, investigate |
| 24    | breakthrough  | Yes     | All cribs match — potential solution (requires Bean PASS AND ngram floor AND p-value gate) |

**Phase 6 p-value gate (2026-04-21):** Alerts now gate on `p_value_vs_null <= 1e-6` in addition to crib_score. Under the random_text null, crib_score >= 18 gives `p ≈ 3.7e-21` (exact Binomial tail) — 15 orders of magnitude below the gate, so the gate is effectively a no-op on real signal but suppresses false SIGNAL alerts at lower crib scores under tighter nulls (shuffled_ct, matched_variant_family). When the null cache is missing, the gate fails open to legacy crib-only gating with a WARNING — the framework never goes silent on a high score. To rebuild the cache: `PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines.py` (~18 seconds).

**False positive warning**: `period_consistency()` is underdetermined when `period >= (num_crib_positions / constraints_per_residue)`. At period 24, random configs score ~19.2/24; at period 17, ~17.3/24. Only period ≤7 gives meaningful discrimination (~8.2/24 expected). **All high scores at large periods are false positives.** With the full 242 Bean inequality set, ALL periods 1–26 are eliminated for periodic substitution on the raw 97-char carved text.

---

## Short Layered Ciphertext Search Policy

On short (<=120 char), masked, or multi-layer ciphertexts: surface statistics (IC, Kasiski, autocorrelation) are **advisory only** — they may be artifacts of an unseen layer. Never hard-prune branches based on weak/absent statistical signals. Test both peel orders for two-layer hypotheses. Separate structural search from keyword search.

**Full policy:** [`docs/search_policy.md`](docs/search_policy.md)

---

## Compute Environment — High-Power VM

This project runs on a **dedicated high-capability VM**. All computational work must be planned accordingly. Do NOT write single-threaded scripts for parallelizable workloads.

### Default runtime assumptions

| Resource | Value |
|----------|-------|
| vCPUs | ~28 |
| RAM | ~12 GB |
| Swap | ~8 GB |
| Disk | Fast local (check `df -h`) |
| Python venv | `/home/cpatrick/kryptos/venv/` |
| Capability report | `bash scripts/vm_capability_report.sh` |

Treat this as the default runtime context. Do not behave as if this is a constrained laptop or sandbox unless a fresh capability check proves otherwise.

### Session-start capability check

At the beginning of each session involving CPU-bound work (brute force, Monte Carlo, SA, parameter sweeps, corpus processing, scoring, batch analysis), run:

```bash
bash scripts/vm_capability_report.sh       # writes results/vm_capability.txt
bash scripts/vm_capability_report.sh --json # also writes results/vm_capability.json
```

The report output is **authoritative session runtime state**, not informational text. It writes to `results/vm_capability.txt` (human-readable sections: OS / CPU / MEMORY / DISK / PYTHON / GPU) and optionally `results/vm_capability.json`. Parse `vCPUs:` from the CPU section for worker pool sizing, `Avail:` from MEMORY for per-worker footprint budgeting, and the DISK section for checkpoint / SQLite space planning. Prefer the `--json` variant when scripting downstream sizing logic.

### Multi-core execution policy

**[POLICY] For CPU-bound, safely parallelizable workloads, aggressive multi-core execution is the DEFAULT, not an optional enhancement.**

- Use `multiprocessing.Pool` (or equivalent) for independent SA restarts, parameter sweeps, candidate evaluations, Monte Carlo trials, and corpus scans.
- Worker count: `max(1, cpu_count() - 2)` is the standard default. Deviate only for documented reasons (memory pressure, I/O contention, algorithmic dependencies).
- **Single-threaded execution of parallelizable work requires explicit justification.** "I forgot" or "it's simpler" are not justifications.

### Compute planning (before writing heavy scripts)

Before implementing any CPU-bound or batch script, produce an execution plan covering:

1. **Workload type**: CPU-bound, I/O-bound, or mixed
2. **Parallelization**: Is `multiprocessing` appropriate? If not, why?
3. **Worker count**: Default and rationale for deviation
4. **Batching**: How work is chunked for progress reporting
5. **Checkpointing**: Can interrupted runs resume? (Required for jobs >10 min)
6. **Memory**: Estimated per-worker footprint × worker count vs. available RAM
7. **Storage**: Output format, estimated size, WAL mode for SQLite if applicable

**Caveats:** the policy doesn't mean "always 28 workers" (memory, I/O, and algorithmic structure can justify fewer), doesn't apply to <30-second smoke tests, and never overrides correctness — a buggy parallel impl is worse than a correct serial one.

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

### Canonical live path (read these for current state)

- **`docs/README_current_state.md`** — canonical entry index; read after CLAUDE.md + session briefing + MEMORY.md
- **`docs/claims_registry.json`** — structured registry of major live / disputed / retired / historical claims
- **`docs/methodological_audits.md`** — open epistemic audits; disputed claims block new compute until their audit closes

### Durable domain & invariant docs

- **`docs/kryptos_ground_truth.md`** — Public facts (CT, cribs, 2025 disclosures), internal results policy, hypothesis classes
- **`docs/invariants.md`** — Verified computational invariants (keystream, Bean constraints, alphabets, eliminated hypotheses)
- **`docs/elimination_tiers.md`** — Elimination confidence tiers. Tier 1 = proven under stated assumptions; Tier 2 = exhaustively searched (single-layer only — **OPEN as one layer of multi-layer**); Tier 4 = untested bespoke methods. **Critical framing:** All Tier 1/2 eliminations assume direct positional correspondence `CT[i] → PT[i]`. The "SOURCE-INDEPENDENT" wording on Tier 1 columnar rows is currently **disputed** — see `docs/methodological_audits.md` AUDIT-1 before citing.
- **`docs/research_questions.md`** — Prioritized unknowns (RQ-1 through RQ-13)
- **`docs/two_ground_truths.md`** — Physical sculpture vs creator intent
- **`docs/anomaly_registry.md`** — Physical anomalies in the sculpture
- **`docs/operations.md`** — Supporting systems, deployment, service management
- **`<internal>`** — One-page operator onboarding for the research runner. Start here for any task that touches the internalloop. Authored in framework internal phase 9 (2026-04-21).
- **`<internal>`** — Full architecture: controller cycle, DSL + dispatcher, null baselines, alert path. Updated 2026-04-21 for Phases 4-6.
- **`<internal>`** — Phases 1-9 handoff summary. Every phase, every artifact, every test delta, every behavior change.
- **`<internal>/K4_SYNTHETIC_T1_POSTMORTEM_CHECKLIST.md`** — Working example of a preregistered postmortem with binding pass/fail criteria; canonical reference for how synthetic-calibration runs are reviewed without post-hoc relaxation.

### Historical / retired (not authoritative — do not cite as current)

- **`docs/history/`** — Historical strategy snapshots, demoted status reports (each banner-labelled)
- **`reports/final_synthesis.md`** — 2026-02-20 synthesis, kept at original path for link stability, in-file HISTORICAL SNAPSHOT banner
- **`memory/retired/`** — Retired research notes (palette/null-mask family, retired 2026-04-01)
- **`docs/retired_claims/`** — Landing page for retired claims
- **`<historical-planning>/`** — Historical March 2026 research planning (specs/plans). Demoted 2026-04-09; many stego plans rest on the retired palette construct. **Not current doctrine** — see the directory's own `README.md` banner before citing anything under it.

### External primary references

- [Bean 2021](https://ecp.ep.liu.se/index.php/histocrypt/article/view/153) — "Cryptodiagnosis of Kryptos K4," HistoCrypt 2021 (source of Bean equality/inequality constraints)
- [Elonka Dunin's Kryptos page](https://elonka.com/kryptos/) — Community hub, authoritative CT transcription
- [`reference/ed_scheidt_dossier.md`](reference/ed_scheidt_dossier.md) — What the co-creator has revealed publicly
- [`reference/sanborn_open_letter_aug2025.md`](reference/sanborn_open_letter_aug2025.md) — AI verification, K5 confirmed
- [`reference/cia_1996_memo.md`](reference/cia_1996_memo.md) — **Tier-3 hearsay**, mirrored from the Oranchak repo 2026-04-21. Three of its four cipher diagnoses are known-wrong; its "K4 = OTP" claim carries no evidentiary weight. Cite with the Tier-3 banner and never as support for an OTP hypothesis. Related mirrored assets: `data/k4_candidate_fills_oranchak.csv`, `wordlists/quagmire[34]_keywords_oranchak.txt`.

### Operations quick-reference

The live site (`internal.com`) runs on this machine. Full details in [`docs/operations.md`](docs/operations.md).

```bash
sudo systemctl status|restart internal-api.service   # API on 127.0.0.1:8321
journalctl -u internal-api -f                         # API logs
source venv/bin/activate && python3 ops/site_builder/build.py  # Rebuild site
python3 ops/api/admin.py list|test|publish|reject <id>         # Theory admin
ops/deploy/cron_update.sh --force                              # Force deploy
```

---

## Persistent Memory (`.claude/` and `memory/`)

Two `memory/` directories exist — don't confuse them:

- **`.claude/projects/.../memory/`** — Claude Code's session-persistent memory. Read via Claude Code's memory system (not filesystem paths).
- **`memory/`** (repo root) — Checked-in research notes. Live notes at `memory/*.md`. **Retired notes quarantined under `memory/retired/`** — do not cite as evidence; each file carries a RETIRED banner and the old path carries a stub pointer. See `memory/retired/README.md`.

**`MEMORY.md`** (auto-loaded) is the **live control document**: current state, hard blockers, active bins, open audits, do-not-revive list. Short by design. CLAUDE.md holds durable operational doctrine; MEMORY.md holds volatile live state. Structured claims live in `docs/claims_registry.json`; open audits in `docs/methodological_audits.md`; historical snapshots in `docs/history/`.

---

## Multi-Agent Mode — Solve K4

- **KryptosBot controller (live entry point):** `PYTHONPATH=src python3 -u <internal>`. See `<internal>` (one-page operator guide) and `<internal>` (full architecture). The legacy `<internal>/solve.py` and `<internal>/campaign_v2.py` entry points were quarantined in framework internal phase 1; `campaign_v2.py` survives only as an `ImportError` stub at `<internal>`. `<internal>` is now a redirect stub pointing at `ORIENT.md`.
- **Post-R3 control flow (2026-04-21):** Controller worker path now dispatches through `dispatcher.execute()`; Category-A workers no longer call Claude directly, and the kernel overrule is preserved across the DSL handoff. R3-0.5 extended the DSL to 9 kinds (added procedural / grille / polybius translators). **`<internal>/K4_RUN_PROTOCOL_R3.md` supersedes `round2/K4_RUN_PROTOCOL.md`** for any post-R3 run; do not follow the R2 protocol.
- **internal review system (current research system):** candidate generators + adversarial review + statistical-review gate + lead evaluator. Live state and day-by-day build notes in `MEMORY.md` under "Project (current state)" — read those, not this section, for what's actually running. Two cycle loops exist (`controller.run` and `run_controller.do_run`); any phase addition must patch **both**.
- **AGENTS.md** — operating instructions (`AGENTS.md` at repo root). Codex performs debugging, troubleshooting, and hardening passes as an independent auditor. Defines hard constraints (free text never drives control flow, worker scores never trusted, timeout means inconclusive), autonomous fix scope (off-by-one, resume bugs, weak tests, misleading docs), and areas requiring extra caution (kernel constants, Bean logic, elimination semantics). Codex treats prior Claude Code conclusions as hypotheses to verify, not facts.
- **Historical reference:** `archive/legacy_harness/`, `archive/session_reports/`, `docs/history/`, [`reports/final_synthesis.md`](reports/final_synthesis.md) (banner-labelled HISTORICAL SNAPSHOT).

---

## Kryptos project context
- Primary objective: detect recurring, evidence-backed visual anomalies or
  structural clues in Kryptos-related image corpora without overcalling
  artifacts.
- Maintain repo-relative paths in prompts, scripts, and reports.
- Treat chart images as registered document comparisons when possible.
- Treat physical surface imagery separately from document scans.
- Project artifacts should be written under `analysis_runs/` unless a task says
  otherwise.
- Stable confirmed findings belong in project records, not only in agent memory.

---

*Last updated: 2026-04-26. CLAUDE.md is **operational doctrine only**. Live research state lives in MEMORY.md, structured claims in `docs/claims_registry.json`, open audits in `docs/methodological_audits.md`, canonical entry index in `docs/README_current_state.md`. For prior-revision history, see `git log CLAUDE.md`.*

*Primary author: Colin Patrick (human lead) + Claude (computational partner).*

*Conflict-resolution rule: verify freshness with `git log -1 --format=%cd CLAUDE.md MEMORY.md`. If CLAUDE.md is older than MEMORY.md and the two disagree on research state (not operational doctrine), trust MEMORY.md and flag the drift. Operational doctrine in CLAUDE.md is always authoritative regardless of date.*
