# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

This repo has one purpose: determine the **true plaintext** and the **full encryption method** of **Kryptos K4**.

CLAUDE.md is **operational doctrine only** — how to work, where truth lives, how to classify claims, how to avoid re-testing dead hypotheses. It does not describe the current favorite theory or what the project is "close" to. For research state see `MEMORY.md` (auto-loaded), `docs/README_current_state.md` (entry index), `docs/claims_registry.json` (live/disputed/retired claims), `docs/methodological_audits.md` (open audits). Historical snapshots: `docs/history/`, `reports/final_synthesis.md` (banner-labelled). Retired notes: `memory/retired/`. Do not cite either as current doctrine.

**Posture as of 2026-05-01:** Real-K4 attack work is **active**. Per Colin's directive, pursue any path with non-zero chance of solve, including infinitesimally-small-probability swings. Evidence-gap closure (`docs/REAL_K4_EVIDENCE_GAP_REGISTER.md`) and synthetic K4Bench calibration are parallel, not gates.

---

## Pre-flight (EVERY task — do NOT skip)

**Always:**

1. Read this entire CLAUDE.md (operational doctrine only).
2. **Run the session briefing** — authoritative derived state:
   ```bash
   PYTHONPATH=src python3 scripts/_infra/session_briefing.py
   ```
   Reads `exhaustion_log.json`, `results/*.json`, and `docs/elimination_tiers.md` to produce a current elimination landscape, anomalies, open attack surface, and DO NOT TEST list. Replaces all hand-maintained elimination ledgers. If it errors or is unusably slow, fall back to `MEMORY.md` §1–5 + `docs/elimination_tiers.md` and tell the user the briefing failed.
3. Read **`MEMORY.md`** (auto-loaded) — live control document: current state, hard blockers, active bins, open audits, do-not-revive list. Short by design.
4. Read **`docs/README_current_state.md`** — canonical entry index for the live path (claim registry, methodological audits, historical/retired quarantines).
5. Check **`docs/methodological_audits.md`** for any open audit that touches your task. Disputed claims block new compute until their audit closes.
6. If the task matches anything in the briefing's TIER 1 / DO NOT TEST sections or the `MEMORY.md` do-not-revive list → **STOP, tell the user, do NOT re-run**.
7. `run_attack.py --list --verbose | grep KEYWORD` — search before writing new code.

**Conditional (only if the task involves the named area):**

8. **CPU-bound work**: `bash scripts/vm_capability_report.sh` — establish runtime capabilities (see [Compute Environment](#compute-environment--high-power-vm)).
9. **kryptosbot loop**: read `kryptosbot/ORIENT.md` (~5 min) — one-page operator onboarding.
10. **Modifying kernel scoring or transforms**: `PYTHONPATH=src python3 kryptosbot/self_test.py --panel all --mode dry-run` — ~1s falsification test that K1/K2 are still rediscoverable. Project's standing fitness check.

Skipping these and re-testing an eliminated hypothesis wastes 28 CPU cores and burns API tokens for zero value.

---

## The K4 Problem

**Kryptos** is a sculpture at CIA headquarters with four encrypted messages. K1–K3 solved 1998–1999. **K4 (97 characters) has been unsolved since 1990.** Two encryption systems are reported by the creator; treat such statements as Tier-3 community hearsay unless independently corroborated (see `feedback_sanborn_epistemic_weight.md`).

---

## Development Setup & Commands

**Python 3.11+** required (uses stdlib `tomllib`; dev runs 3.12.3). **No external runtime dependencies** — stdlib only. `pytest` is the only dev dep. No `pyproject.toml` or `setup.py` for the core project — `pip install -e .` will not work. **All commands require `PYTHONPATH=src`.** (`kryptosbot/` has its own `pyproject.toml` for the Agent SDK — separate.) Repo: `github.com/jcolinpatrick/kryptos`. A gitignored `venv/` exists for non-core work pinned in root `requirements.txt`. No linter or formatter configured. Development happens directly on `main`.

Common kernel symbols (`CT`, `CRIB_POSITIONS`, `BEAN_EQ`/`BEAN_INEQ`, `KA`, `score_candidate`, `decrypt_vigenere`/`decrypt_beaufort`) live under `kryptos.kernel.{constants,alphabet,scoring.aggregate,transforms.vigenere}`. Grep there before assuming a name.

```bash
# Run all tests (~2 minutes, 3900+ tests, no expected failures).
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

# K4Bench (synthetic calibration mode — see Architecture § K4Bench for what it overrides)
PYTHONPATH=src python3 -u kryptosbot/run_controller.py --bench-challenge bench/k4bench/challenges/K4B-001.json [--bench-attempts-out <out.json>]
```

For site builder, API server, and deployment commands, see [`docs/operations.md`](docs/operations.md).

---

## Architecture

Four layers with strict dependency direction: **kernel → pipeline → novelty → cli**

### Source layout (`src/kryptos/`)

- **kernel/** — Pure computation, zero external dependencies, **all positions 0-indexed**.
  - `constants.py` — **SINGLE source of truth**: CT, cribs, Bean constraints, keystream values, scoring thresholds. Runs `_verify()` at import time. **Never define CT or cribs elsewhere.**
  - `alphabet.py` — `AZ`/`KA` singletons, `keyword_mixed_alphabet()`. See "Key Gotchas" for KA ordering.
  - `transforms/` — Cipher implementations + composable pipeline builder (`compose.py`: `TransformConfig` → `PipelineConfig` → `build_pipeline()`).
  - `scoring/` — Under `kernel/`, NOT a top-level module. Two canonical paths in `aggregate.py`: `score_candidate()` (anchored cribs at fixed positions) and `score_candidate_free()` (cribs searched anywhere — for scrambled-CT). Thresholds: NOISE=6, STORE=10, SIGNAL=18, BREAKTHROUGH=24.
  - `constraints/` — Bean equality/inequality (`bean.py`), crib scoring, self-encrypting position checks.
  - `persistence/` — WAL-mode SQLite + JSONL artifacts.
- **pipeline/** — `evaluate_candidate()` is the primary entry point; `SweepRunner` handles parallel execution with checkpointing/resume. Data flow: hypothesis → triage → NoveltyLedger → SweepRunner → kernel transforms+constraints → `pipeline/evaluation.py` → kernel/persistence.
- **novelty/** — Hypothesis-driven search wired to RQ-1..RQ-13. Add hypotheses in `generators.py`.
- **campaigns/** — Multi-layer campaign runners (`two_layer/`, `w_delimiter/`). `manifest.py` + `historical_eliminations.py` track what's been tested.
- **admissibility/, composition/, detectors/, language/, cipher_discovery/, corpus/, cli/** — Specialized subsystems; one-line summaries are misleading — read the directory.

**`kryptosbot/` (separate subproject, NOT under `src/kryptos/`)** — Multi-agent runner on Claude Agent SDK. Own `pyproject.toml`, `.env` (see `kryptosbot/.env.template`), depends on `claude-agent-sdk`. **Don't confuse with core `kryptos`** — independent deps, different API key env vars. Core kryptos stays stdlib-only; kryptosbot may use anything in its own venv.

**CT-perturbation harness (`kryptosbot/ct_perturbation.py`; Stage A 2026-05-01, Stage B preregistered 2026-05-02)** — Hamming-1 (Stage A) + Hamming-2 archive-anchored (Stage B) CT-perturbation campaigns. **Design contract:** every CT-dependent computation accepts CT as an explicit argument; Bean equality / inequality / linear sets are **re-derived** from perturbed CT against the canonical crib dictionary, never read from frozen `kernel.constants`. No global mutation, no `KRYPTOS_CT_OVERRIDE` for real-K4 paths (override is K4Bench-only — see Gotchas). Pre-reg, coverage audit, triage reports under `docs/campaigns/ct_perturbation_stage_{a,b}_*.md`. Runner: `scripts/campaigns/ct_perturbation_stage_a.py`. When extending, follow the same explicit-CT contract.

**K4Bench mode (`bench/k4bench/` + `kryptosbot/bench_loader.py` + `bench_attempts.py`)** — Synthetic calibration suite of 25 K4-shaped challenges. `--bench-challenge <path>` on `run_controller.py` installs kernel overrides **before** any `kryptos.kernel` import, swaps ledger to `db/k4bench/`, suppresses real-K4 prompt surfaces, emits attempts in `k4bench.attempts.v1` schema. `bench_loader` rejects answer-like keys at load; sealed answers must never reach controller paths.

**`external/` (repo root)** — Third-party reference material:
- `external/bean_k4testing/` — Bean's C/SageMath reference (`k4-bean3.c`, `k4-perm-test.c`, `kryptos-k4-sage.txt`, `k4testing.py`). **Authoritative cross-check** for `kernel/constants.py` Bean values; diff against this when verifying Bean-derived claims.
- `external/claude-plugins-official/` — Reference only.

**`copy/` (repo root)** — Curated software-review snapshot of kryptosbot. **Don't edit directly** — changes belong in `kryptosbot/`. Exclude from grep.

### Experiment scripts (`scripts/`)

Several hundred attack scripts across ~40 subdirectories — run `ls scripts/` for the current list. For counts and exhaustion state, run `PYTHONPATH=src python3 run_attack.py --exhaustion-summary` — **do not cite hardcoded numbers**, they drift. Each script has a metadata header; tracked in root `exhaustion_log.json` (authoritative — ignore `scripts/EXHAUSTION.json`). Some scripts (e.g. `blitz_*.py`) live at `scripts/` root rather than in subdirectories.

`scripts/lib/` — Shared infrastructure (`header.py`, `exhaustion.py`, `discover.py`) used by `run_attack.py`.

**Discovery & dispatch** via `run_attack.py`:
```bash
PYTHONPATH=src python3 run_attack.py --list --verbose              # List all scripts with metadata
PYTHONPATH=src python3 run_attack.py --run --family grille          # Run scripts by family
PYTHONPATH=src python3 run_attack.py --run --id e_caesar_01         # Run a single script by ID
PYTHONPATH=src python3 run_attack.py --manifest -o manifest.json    # Generate manifest JSON
PYTHONPATH=src python3 run_attack.py --reconcile                    # Check header vs log mismatches
PYTHONPATH=src python3 run_attack.py --exhaustion-summary           # Summarize exhaustion log
# Filters: --family, --status (exhausted|active|promising), --min-score, --attack-only, --header-only, --timeout, --top-n
```

**Naming:** `e_` = experiment, `f_` = formal campaign, `h_` = harness (in `scripts/hypothesis_tests/`), `blitz_` = fast hypothesis sweep. `_infra/` = utilities, not attacks.

**Second runner — `run_lean.py`** (root, separate from `run_attack.py`): two-phase — Phase A is local multiprocessing with zero tokens (statistical profiling, simple-cipher disproof, keyword sweeps, columnar brute-force); Phase B spends tokens on an Agent SDK synthesis pass over Phase A outputs. Use `run_lean.py` for token-efficient sweeps where the LLM only adds value at synthesis; use `run_attack.py` for script-family dispatch. Don't confuse them.

**Standard contract** (template: `scripts/examples/e_caesar_standard.py`):
```python
def attack(ciphertext: str, **params) -> list[tuple[float, str, str]]:
    """Returns [(score, plaintext, method_description), ...] sorted by score desc."""
```

**Adding a new script:** Use the template. Place under `scripts/<family>/`, name `e_<family>_<nn>_<description>.py`, register in root `exhaustion_log.json`, import constants from `kryptos.kernel.constants` (never hardcode). Bootstrap: `_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))` for 2-deep scripts (see Gotchas for 3+ levels).

### Tests

Three categories: **Unit** (`test_transforms.py`, `test_scoring.py`, etc.), **QA verification** (`test_qa_*.py`, `test_audit_*.py`), **Benchmark** (`test_bench*.py`). No framework beyond `pytest` — plain `assert`. Place in `tests/test_<module>.py` matching the source module.

### Key data files

- `data/english_quadgrams.json` — Quadgram log-probabilities (2 MB)
- `wordlists/english.txt` (1M+ words); `wordlists/thematic_keywords.txt`
- `reference/` — Primary sources (Carter book, Sanborn correspondence, NSA docs, Scheidt dossier, transcripts, PDFs)
- `docs/crypto_field_manual/` — Durable cryptographic knowledge base
- `memory/` (repo root) — Checked-in research notes. **Retired notes live under `memory/retired/`** — do not cite as evidence.

### Data persistence & symlinks

- `db/` → `/data/db` — SQLite (novelty ledger, results)
- `artifacts/` → `/data/artifacts` — JSONL logs
- `checkpoints/` — Resumable campaign state
- `exhaustion_log.json` — **Authoritative** experiment log (root level — ignore `scripts/EXHAUSTION.json`)

Supporting systems (site builder, API, campaigns, deployment) live in [`docs/operations.md`](docs/operations.md).

---

## Key Gotchas

These are non-obvious pitfalls discovered through prior sessions. Check these first when debugging unexpected results.

- **Every command needs `PYTHONPATH=src`**: There is no `setup.py` or `pyproject.toml`. Forgetting `PYTHONPATH=src` is the most common `ModuleNotFoundError`.
- **`scoring/` is at `kernel/scoring/`**: NOT a top-level package. Import from `kryptos.kernel.scoring.aggregate`.
- **0-indexed positions everywhere**: Cribs are at 21–33 and 63–73 (0-indexed). Legacy code and some public sources use 1-indexed (22–34, 64–74). Mixing conventions is the #1 source of bugs.
- **KA alphabet has non-standard ordering**: `KRYPTOSABCDEFGHIJLMNQUVWXZ` — all 26 letters present but reordered (keyword "KRYPTOS" first). The `KA` singleton uses this ordering; standard `AZ` uses alphabetical. Both contain all 26 letters. (The "KA has no J" claim in prior versions was **wrong**.)
- **Vigenère vs Beaufort sign conventions**: `K = (CT - PT) mod 26` for Vigenère, `K = (CT + PT) mod 26` for Beaufort, `K = (PT - CT) mod 26` for Variant Beaufort. Mixing these silently produces wrong keystream.
- **Bean constraint is variant-independent**: CT[27]=CT[65]=P, PT[27]=PT[65]=R, so k[27]=k[65] holds regardless of variant. 242 inequalities (from C(24,2)=276 crib pairs, 242 distinct under all 3 variants) and 101 linear constraints (`BEAN_LINEAR`) are likewise variant-independent. All checked by `verify_bean()` / `verify_bean_simple()`. Admit exactly **624 valid keystreams** at the 24 crib positions.
- **Transposition permutation convention**: `output[i] = input[perm[i]]` — this is the "gather" convention. `invert_perm()` gives the "scatter" direction.
- **IC below random**: K4's IC ≈ 0.0361 is below the random expectation of 0.0385. [INTERNAL RESULT] FRAC agent (E-FRAC-04) showed this deviation is NOT statistically significant for a 97-char text. Do not use IC alone as a discriminator.
- **constants.py self-verifies at import**: If you modify CT, cribs, or Bean values incorrectly, the import itself will raise an assertion error.
- **Unbuffered output for background tasks**: Always use `python3 -u` when running scripts in background. Without `-u`, Python buffers stdout and you see no output until the process ends.
- **Bifid 5×5 impossible for K4**: All 26 letters appear in K4 CT; any cipher requiring a 25-letter alphabet (I/J merged) is eliminated.
- **High scores are almost always false signals**: See `MEMORY.md` §5 "Do-Not-Revive List" and `docs/README_current_state.md` §4. `BREAKTHROUGH` (`crib_score == 24 && bean_passed`) is an **input to validation, not an output** — historically dominated by post-hoc overfits. Treat as a candidate for investigation, not a solution. See `docs/methodological_audits.md` AUDIT-3.
- **Beaufort A=0 is the confirmed default**: Use A=0 indexing for all Beaufort operations unless explicitly testing A=1. Both conventions must be tested in positional experiments.
- **Standalone script `_ROOT` depth**: The bootstrap snippet (`_ROOT = os.path.dirname(os.path.dirname(...))`) assumes the script is exactly 2 directories deep (e.g. `scripts/grille/e_foo.py`). Scripts at 3+ levels need additional `os.path.dirname()` wrappers or they'll get `ModuleNotFoundError`. Robust alternative: `_ROOT = os.path.dirname(os.path.abspath(__file__))` then `while not os.path.exists(os.path.join(_ROOT, 'src')): _ROOT = os.path.dirname(_ROOT)`.
- **Always import constants, never hardcode**: For CT/cribs/Bean values, import from `kryptos.kernel.constants`. A prior session fabricated null positions sharing only 3/17 values with consensus — silently invalid. **Caveat on `CONSENSUS_NULL_POSITIONS`**: the 17-position null mask is pending retraction (derived from retired palette hypothesis, no independent verification). Don't cite as established fact. See `memory/project_consensus_nulls_epistemic_status_2026_04_14.md`.
- **`doctor` Bean checks are authoritative**: `python3 -m kryptos doctor` now verifies the current Bean constants (`bean_eq_count == 1`, `bean_ineq_count == 242`, `bean_linear_count == 101`). Any Bean-related `doctor` failure is a real pre-flight failure to diagnose before trusting downstream scoring.
- **Exhaustion log — one authoritative source**: Root `exhaustion_log.json` is the single source of truth. The former second log at `scripts/EXHAUSTION.json` was retired and renamed to `scripts/EXHAUSTION.json.RETIRED` (see `scripts/EXHAUSTION.json.RETIRED.README` for the retirement note). If any script or doc still references `scripts/EXHAUSTION.json`, that's a stale pointer — fix it to read the root log.
- **Two `.env` files — don't mix them up**: `.env` (root) = `ANTHROPIC_API_KEY` + `KBOT_CLASSIFY_API_KEY` + `NTFY_TOPIC`. `kryptosbot/.env` = Agent SDK API key (see `kryptosbot/.env.template`). Loading the wrong one gives silent auth failures.
- **K4Bench sealed answers must not enter prompt context**: any `bench/k4bench/answers/*` (when present) and any answer-keyed JSON are off-limits to controller paths. `bench_loader.load_k4bench_challenge()` rejects answer-like keys at load time — that's the boundary. Don't add helpers that bypass it; sealed answer leakage invalidates the calibration run.
- **`KRYPTOS_CRIB_DICT_OVERRIDE` is K4Bench-only**: env var that swaps the crib dictionary for synthetic challenges. Must be installed *before* `kryptos.kernel.constants` imports (handled by `bench_loader`). Setting it manually for real-K4 work is a correctness violation — real cribs come from disclosure, not env. The K4Bench loader is the only legitimate caller.
- **Quagmire III requires explicit convention args**: `quagmire_encrypt`/`quagmire_decrypt` in `transforms/quagmire.py` only reproduce K1/K2 convention with `pt_alphabet_keyword=..., ct_alphabet_keyword='KRYPTOS', indicator='K'`. Wrong shape does NOT raise — silently fails K1/K2 regression. `scripts/campaigns/f_w10_quagmire_iii_v1.py` was historically misconfigured; K1/K2 regression tests (landed 2026-04-21) are the standing guard. Verify regression passes before trusting new Quagmire results.
- **Never `git push origin main` directly — use the publish script**: `kryptosbot/` and `docs/maturation/` are private, excluded from the public mirror. Pre-push hook `.githooks/pre-push` blocks any push containing those paths (deletions allowed; additions blocked). To publish, run `ops/publish/publish_to_github.sh` — isolated worktree filters private paths, falls back to `git apply --3way` then cherry-pick on conflicts. Privacy boundary is deliberate; never propose un-ignoring or removing the hook. See `feedback_publish_workflow.md`, `feedback_kryptosbot_gitignored_by_design.md`.
- **Image-analysis output goes under `analysis_runs/`**: chart-scan comparisons are registered-document workflows; physical-surface (sculpture) imagery is a separate workflow — don't conflate them. Use repo-relative paths in prompts, scripts, and reports. Stable confirmed findings belong in project records (claims registry / docs), not only in agent memory.

---

## Interpreting Scores

Two scoring paths in `kernel/scoring/aggregate.py`: `score_candidate()` (anchored cribs at fixed positions) and `score_candidate_free()` (cribs searched anywhere — for scrambled-CT work). Both return a breakdown with `crib_score` (0–24), `bean_passed`, `ic_value`, `ngram_score`, and `crib_classification`.

| Score | Classification | Stored? | Meaning |
|-------|---------------|---------|---------|
| 0–9   | noise         | No (≤9) | Expected random performance |
| 10–17 | interesting   | Yes     | Worth logging, likely noise |
| 18–23 | signal        | Yes     | Statistically significant, investigate |
| 24    | breakthrough  | Yes     | All cribs match — potential solution (requires Bean PASS AND ngram floor AND p-value gate) |

**Phase 6 p-value gate (2026-04-21):** Alerts gate on `p_value_vs_null <= 1e-6` in addition to crib_score. Under the random_text null, crib_score >= 18 gives `p ≈ 3.7e-21` — 15 orders of magnitude below the gate, so the gate is effectively a no-op on real signal but suppresses false SIGNAL alerts at lower crib scores under tighter nulls (shuffled_ct, matched_variant_family). When the null cache is missing, the gate fails open to legacy crib-only gating with a WARNING — the framework never goes silent on a high score. Rebuild cache: `PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines.py` (~18 seconds).

**False positive warning**: `period_consistency()` is underdetermined when `period >= (num_crib_positions / constraints_per_residue)`. At period 24, random configs score ~19.2/24; at period 17, ~17.3/24. Only period ≤7 gives meaningful discrimination (~8.2/24 expected). **All high scores at large periods are false positives.** With the full 242 Bean inequality set, ALL periods 1–26 are eliminated for periodic substitution on the raw 97-char carved text.

---

## Short Layered Ciphertext Search Policy

On short (<=120 char), masked, or multi-layer ciphertexts: surface statistics (IC, Kasiski, autocorrelation) are **advisory only** — they may be artifacts of an unseen layer. Never hard-prune branches based on weak/absent statistical signals. Test both peel orders for two-layer hypotheses. Separate structural search from keyword search.

**Full policy:** [`docs/search_policy.md`](docs/search_policy.md)

---

## Compute Environment — High-Power VM

This project runs on a **dedicated high-capability VM**. Plan computational work accordingly. Do NOT write single-threaded scripts for parallelizable workloads.

| Resource | Value |
|----------|-------|
| vCPUs | ~28 |
| RAM | ~12 GB |
| Swap | ~8 GB |
| Disk | Fast local (`df -h`) |
| Python venv | `/home/cpatrick/kryptos/venv/` |
| Capability report | `bash scripts/vm_capability_report.sh` |

**Session-start capability check** (CPU-bound work): `bash scripts/vm_capability_report.sh [--json]` writes `results/vm_capability.txt` and (with `--json`) `results/vm_capability.json`. Authoritative session runtime state. Parse `vCPUs:` for worker pool sizing, `Avail:` from MEMORY for per-worker footprint budgeting, DISK section for checkpoint/SQLite space. Prefer `--json` when scripting downstream sizing logic.

### Multi-core execution policy

**[POLICY] For CPU-bound, safely parallelizable workloads, aggressive multi-core execution is the DEFAULT, not an optional enhancement.**

- Use `multiprocessing.Pool` (or equivalent) for independent SA restarts, parameter sweeps, candidate evaluations, Monte Carlo trials, corpus scans.
- Worker count: `max(1, cpu_count() - 2)` is the standard default. Deviate only for documented reasons (memory pressure, I/O contention, algorithmic dependencies).
- **Single-threaded execution of parallelizable work requires explicit justification.** "I forgot" or "it's simpler" are not justifications.

### Compute planning (before heavy scripts)

Document: workload type (CPU/IO/mixed); parallelization plan + worker count + rationale for deviation; checkpointing (required for jobs >10 min); per-worker memory × worker count vs. available RAM; output format and SQLite WAL mode if applicable.

**Caveats:** the policy doesn't mean "always 28 workers" (memory, I/O, and algorithmic structure can justify fewer); doesn't apply to <30s smoke tests; never overrides correctness — a buggy parallel impl is worse than a correct serial one.

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

Results are not trusted until they pass: (1) unit tests pass; (2) minimal reference implementation reproduces outcome; (3) invariant checks (bijection, reversibility, crib alignment); (4) reproduce from a clean process (fresh interpreter).

---

## Reference Documents

**Live state (cite these, not the long catalogue):** `MEMORY.md` (auto-loaded), `docs/README_current_state.md` (canonical entry index), `docs/claims_registry.json` (live/disputed/retired claims), `docs/methodological_audits.md` (open audits). All other doc paths flow from these.

**Operational doctrine pointers:**
- `docs/elimination_tiers.md` — Tier 1/2/4 framework. **All Tier 1/2 eliminations assume direct positional CT[i]→PT[i].** Tier 1 "SOURCE-INDEPENDENT" wording on columnar is **disputed** — see `docs/methodological_audits.md` AUDIT-1 before citing.
- `docs/REAL_K4_CURRENT_POSITION.md` — Authoritative real-K4 status; non-claim statement. Read before any progress claim.
- `docs/REAL_K4_EVIDENCE_GAP_REGISTER.md` + `docs/REAL_K4_EVIDENCE_ACQUISITION_PLAN.md` — Ten gaps + priority order.
- `docs/REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md` — Eleven-rule admission gate (incl. Sanborn public-comment doctrine, rule 11).
- `docs/audits/` — Audit dossiers paired with runners under `scripts/audit/`.
- `docs/campaigns/` — Per-campaign pre-registration, coverage audit, triage.
- `docs/kryptos_ground_truth.md`, `docs/invariants.md`, `docs/research_questions.md` — Public facts, computational invariants, RQ-1..RQ-13.
- `docs/two_ground_truths.md`, `docs/anomaly_registry.md` — Physical sculpture vs creator intent; anomalies.
- `kryptosbot/ORIENT.md` + `kryptosbot/ARCHITECTURE.md` — Multi-agent runner.
- `docs/maturation/round3/K4_RUN_PROTOCOL_R3.md` — supersedes R2; do not follow R2.
- `docs/maturation/SUMMARY.md`, `docs/maturation/round3/K4_SYNTHETIC_T1_POSTMORTEM_CHECKLIST.md` — Phases 1–9 handoff; preregistered postmortem template.

**External primary references:**
- [Bean 2021](https://ecp.ep.liu.se/index.php/histocrypt/article/view/153) — Source of Bean equality/inequality constraints.
- [Elonka Dunin's Kryptos page](https://elonka.com/kryptos/) — Authoritative CT transcription.
- [`reference/cia_1996_memo.md`](reference/cia_1996_memo.md) — **Tier-3 hearsay**; three of four cipher diagnoses known-wrong; "K4 = OTP" claim carries no evidentiary weight. Cite with Tier-3 banner.
- [`reference/ed_scheidt_dossier.md`](reference/ed_scheidt_dossier.md), [`reference/sanborn_open_letter_aug2025.md`](reference/sanborn_open_letter_aug2025.md).

**Historical / retired (do NOT cite as current):** `docs/history/`, `reports/final_synthesis.md`, `memory/retired/`, `docs/retired_claims/`, `docs/superpowers/` (all carry banners).

**Operations quick-reference** (full details in [`docs/operations.md`](docs/operations.md)):
```bash
sudo systemctl status|restart kryptosbot-api.service     # API on 127.0.0.1:8321
journalctl -u kryptosbot-api -f                          # API logs
source venv/bin/activate && python3 ops/site_builder/build.py
python3 ops/api/admin.py list|test|publish|reject <id>
ops/deploy/cron_update.sh --force
python3 k4_monitor.py [--log results/long_run_*.log] [--once|--demo]
```

---

## Persistent Memory

Two `memory/` directories — don't confuse them:
- **`.claude/projects/.../memory/`** — Claude Code's session-persistent memory (read via Claude Code's memory system, not filesystem paths).
- **`memory/`** (repo root) — Checked-in research notes. Live at `memory/*.md`; **retired under `memory/retired/`** (each banner-labelled). See `memory/retired/README.md`.

`MEMORY.md` is the live control document; CLAUDE.md is durable doctrine. If they disagree on research state, trust MEMORY.md.

---

## Multi-Agent Mode — Solve K4

- **Live entry point:** `PYTHONPATH=src python3 -u kryptosbot/run_controller.py`. See `kryptosbot/ORIENT.md` (one-page) + `kryptosbot/ARCHITECTURE.md` (full). Legacy `solve.py`/`campaign_v2.py` quarantined; `kryptosbot/RUNBOOK.md` redirects to `ORIENT.md`.
- **Post-R3 control flow (2026-04-21):** Worker path dispatches through `job_dispatcher.execute()`; Category-A workers no longer call Claude directly; kernel overrule preserved across DSL handoff. R3-0.5 extended DSL to 9 kinds. **`docs/maturation/round3/K4_RUN_PROTOCOL_R3.md` supersedes R2** — don't follow R2.
- **Pantheon:** persona-routed theorists + sibling red-team-disprover + statistical-audit gate + lead-pursuit evaluator. Live state in `MEMORY.md`. **Two cycle loops exist** (`controller.run` and `run_controller.do_run`); any phase addition must patch BOTH.
- **`AGENTS.md` (repo root)** — Codex operating instructions. Codex audits independently. Hard constraints: free text never drives control flow, worker scores never trusted, timeout = inconclusive. Treats prior Claude conclusions as hypotheses, not facts.

---

*Last updated: 2026-05-02. CLAUDE.md = **operational doctrine only**; live research state in MEMORY.md, structured claims in `docs/claims_registry.json`, audits in `docs/methodological_audits.md`, entry index in `docs/README_current_state.md`. Conflict rule: verify freshness via `git log -1 --format=%cd CLAUDE.md MEMORY.md`; if they disagree on research state, trust MEMORY.md. Operational doctrine in CLAUDE.md is always authoritative regardless of date.*
