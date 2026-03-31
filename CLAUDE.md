# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

This repo has one purpose: determine the **true plaintext** and the **full encryption method** of **Kryptos K4**.

**Contents:** [Pre-flight](#pre-flight-every-task--do-not-skip) · [K4 Problem](#the-k4-problem--quick-reference) · [Dev Setup](#development-setup--commands) · [Architecture](#architecture) · [Gotchas](#key-gotchas) · [Scores](#interpreting-scores) · [Compute](#compute-environment--high-power-vm) · [Truth Taxonomy](#truth-taxonomy-mandatory) · [Reference Docs](#reference-documents) · [Memory](#persistent-memory-claude-and-memory) · [Multi-Agent](#multi-agent-mode--solve-k4)

---

## Pre-flight (EVERY task — do NOT skip)

1. Read this entire CLAUDE.md
2. **Run the session briefing** — the single most important step:
   ```bash
   PYTHONPATH=src python3 scripts/_infra/session_briefing.py
   ```
   This reads `exhaustion_log.json` (939 entries), `results/*.json` (309 files), and `docs/elimination_tiers.md` to produce a current elimination landscape, confirmed anomalies, open attack surface, and DO NOT TEST list. **It replaces all hand-maintained elimination ledgers** — the data is always fresh.
3. Read MEMORY.md (auto-loaded) — volatile strategic state, hard blockers, next actions
4. If the task matches anything in the briefing's TIER 1 or DO NOT TEST sections → **STOP, tell the user, do NOT re-run**
5. `run_attack.py --list --verbose | grep KEYWORD` — search before writing new code
6. **If the task involves CPU-bound work**: `bash scripts/vm_capability_report.sh` — establish runtime capabilities (see [Compute Environment](#compute-environment--high-power-vm))

Skipping these steps and re-testing an eliminated hypothesis wastes 28 CPU cores and burns API tokens for zero value.

---

## The K4 Problem — Quick Reference

**Kryptos** is a sculpture at CIA headquarters containing four encrypted messages (K1–K4). K1–K3 were solved in 1999. **K4 (97 characters) has been unsolved since 1990.** Two encryption systems confirmed [PRIMARY SOURCE]. No single-layer classical cipher works (exhaustively tested).

**→ CT, cribs, constants, eliminations, confirmed findings, open attack surface, and current leading hypotheses are in MEMORY.md** (auto-loaded). CLAUDE.md has durable technical setup; MEMORY.md has volatile research state. See [`reports/final_synthesis.md`](reports/final_synthesis.md) for the elimination landscape.

---

## Development Setup & Commands

**Python 3.11+** required (uses `tomllib` from stdlib; dev environment runs 3.12.3). **No external runtime dependencies** — stdlib only. `pytest` is the only dev dependency. No `pyproject.toml` or `setup.py` for the core project — `pip install -e .` will not work. All commands require `PYTHONPATH=src`. (`kryptosbot/` has its own `pyproject.toml` for the Agent SDK dependency — that's separate.) **Repo:** `github.com/jcolinpatrick/kryptos`.

**Common imports** (all require `PYTHONPATH=src`):
```python
from kryptos.kernel.constants import CT, CRIB_POSITIONS, BEAN_EQ, BEAN_INEQ, CONSENSUS_NULL_POSITIONS
from kryptos.kernel.alphabet import AZ, KA, keyword_mixed_alphabet
from kryptos.kernel.text import sanitize, text_to_nums, nums_to_text
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free
from kryptos.kernel.transforms.vigenere import decrypt_vigenere, decrypt_beaufort
```

A `venv/` exists (gitignored) for non-core work. Activate with `source venv/bin/activate`. Packages: `numpy`, `pymupdf` (PDF), `jinja2` (site builder), `fastapi`, `uvicorn`, `python-dotenv`, `anthropic` (API server), `claude-agent-sdk` (KryptosBot SDK). Core code uses stdlib only.

**Code style:** No linter or formatter configured. No enforced style conventions beyond stdlib-only for core code.

**Git workflow:** Development happens directly on `main`. No branch naming conventions or PR process — this is a solo research project with computational partners.

```bash
# Run all tests (969 tests, ~80s, no expected failures)
PYTHONPATH=src pytest tests/

# Run a single test file or test
PYTHONPATH=src pytest tests/test_transforms.py
PYTHONPATH=src pytest tests/test_transforms.py::TestVigenereFamily::test_text_roundtrip_vig -v

# Run an experiment script (always use -u for unbuffered output)
PYTHONPATH=src python3 -u scripts/_uncategorized/e_nsa_01_interval7.py

# Dispatch runner — full documentation in "Experiment scripts" section below
PYTHONPATH=src python3 run_attack.py --list --verbose | grep KEYWORD

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

~1,000 attack scripts across ~50 entries in `scripts/` (939 tracked in exhaustion log including deleted/renamed). Each has a metadata header; tracked in root `exhaustion_log.json` (authoritative — ignore `scripts/EXHAUSTION.json`). Some scripts live at the `scripts/` root level (e.g. `blitz_*.py`, `geometric_null_mask_*.py`) rather than in subdirectories.

**Subdirectories:** Run `ls scripts/` for the full list. Key families: `substitution/`, `transposition/`, `fractionation/`, `grille/`, `polyalphabetic/`, `running_key/`, `encoding/`, `multi_layer/`, `novel/`, `blitz/` (fast hypothesis sweeps), `analysis/` (non-attack analytical scripts), `_infra/` (utilities). Additional research threads: `antipodes/`, `archive_evidence/`, `crib_analysis/`, `exploration/`, `geodetic/`, `geometry/`, `k2_coords/`, `k3_continuity/`, `mirror_ka/`, `overlay/`.

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

**Naming:** `e_` = experiment, `f_` = formal campaign, `blitz_` = fast hypothesis sweep (some live at `scripts/` root level). Subdirectory scripts live in `scripts/<family>/`. `_infra/` = utilities, not attacks.

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
- `reference/` — Primary sources (525 files: Carter book, Sanborn correspondence, NSA docs, Ed Scheidt dossier, video transcripts, PDFs)
- `docs/crypto_field_manual/` — Durable cryptographic knowledge base
- `memory/` (repo root) — Checked-in research notes: keystream forensics, palette investigations, width analysis

### Data persistence & symlinks

Data directories are **symlinked** to a separate data partition:
- `db/` → `/data/db` — SQLite databases (novelty ledger, results)
- `artifacts/` → `/data/artifacts` — Result artifacts (JSONL logs)
- `kryptosbot_results.db` — Main results database (project root, ~1.8 GB)
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
- **Bean constraint is variant-independent**: CT[27]=CT[65]=P and PT[27]=PT[65]=R, so the equality k[27]=k[65] holds regardless of cipher variant. The 242 inequalities are also variant-independent (derived from all C(24,2)=276 crib pairs; 242 have distinct key values under all 3 variants).
- **Transposition permutation convention**: `output[i] = input[perm[i]]` — this is the "gather" convention. `invert_perm()` gives the "scatter" direction.
- **IC below random**: K4's IC ≈ 0.0361 is below the random expectation of 0.0385. [INTERNAL RESULT] FRAC agent (E-FRAC-04) showed this deviation is NOT statistically significant for a 97-char text. Do not use IC alone as a discriminator.
- **constants.py self-verifies at import**: If you modify CT, cribs, or Bean values incorrectly, the import itself will raise an assertion error.
- **Unbuffered output for background tasks**: Always use `python3 -u` when running scripts in background. Without `-u`, Python buffers stdout and you see no output until the process ends.
- **Bifid 5×5 impossible for K4**: All 26 letters appear in K4 CT; any cipher requiring a 25-letter alphabet (I/J merged) is eliminated.
- **High scores are almost always false signals**: See MEMORY.md "DO NOT TEST" section for proven-impossible hypotheses (autokey, DEFECTOR/PALIMPSEST 15/24, K2 numbers as keys, etc.). These are research eliminations, not dev bugs — consult MEMORY.md before investigating any "promising" score.
- **Beaufort A=0 is the confirmed default**: Use A=0 indexing for all Beaufort operations unless explicitly testing A=1. Both conventions must be tested in positional experiments.
- **Standalone script `_ROOT` depth**: The bootstrap snippet (`_ROOT = os.path.dirname(os.path.dirname(...))`) assumes the script is exactly 2 directories deep (e.g. `scripts/grille/e_foo.py`). Scripts at 3+ levels need additional `os.path.dirname()` wrappers or they'll get `ModuleNotFoundError`. Robust alternative: `_ROOT = os.path.dirname(os.path.abspath(__file__))` then `while not os.path.exists(os.path.join(_ROOT, 'src')): _ROOT = os.path.dirname(_ROOT)`.
- **Always import constants, never hardcode**: This includes `CONSENSUS_NULL_POSITIONS`, not just CT/cribs. A prior session generated a script with fabricated null positions that shared only 3/17 values with the consensus — the results were silently invalid. Import from `kryptos.kernel.constants`.
- **Two exhaustion logs — only one is authoritative**: Root `exhaustion_log.json` is the single source of truth. `scripts/EXHAUSTION.json` is stale — never read from or write to it.
- **Two `.env` files — don't mix them up**: `.env` (root) = `ANTHROPIC_API_KEY` + `KBOT_CLASSIFY_API_KEY` + `NTFY_TOPIC`. `kryptosbot/.env` = Agent SDK API key (see `kryptosbot/.env.template`). Loading the wrong one gives silent auth failures.

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
bash scripts/vm_capability_report.sh
```

The report output is **authoritative session runtime state**, not informational text. Use the reported vCPU count, available RAM, and disk space to size worker pools, batch sizes, and checkpoint intervals.

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

### What this policy does NOT mean

- It does NOT mean "always use 28 workers." Overhead, memory, I/O bottlenecks, and algorithmic structure can justify fewer.
- It does NOT apply to quick one-off tests, smoke tests, or scripts that complete in <30 seconds.
- It does NOT override correctness. A parallel implementation that's buggy is worse than a correct serial one.

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
- **`docs/anomaly_registry.md`** — Physical anomalies in the Kryptos sculpture (misspellings, alignments, narrative anomaly allocation)
- **`docs/operations.md`** — Supporting systems, deployment, service management, environment files

### External primary references

- [Bean 2021](https://eprint.iacr.org/2021/1549) — Constraint analysis of K4 keystream (source of Bean equality/inequality constraints)
- [Elonka Dunin's Kryptos page](https://elonka.com/kryptos/) — Community hub, authoritative CT transcription
- [`reference/ed_scheidt_dossier.md`](reference/ed_scheidt_dossier.md) — What the co-creator has revealed publicly
- [`reference/sanborn_open_letter_aug2025.md`](reference/sanborn_open_letter_aug2025.md) — AI verification, K5 confirmed

### Operations quick-reference

The live site (`kryptosbot.com`) runs on this machine. Full details in [`docs/operations.md`](docs/operations.md).

```bash
sudo systemctl status|restart kryptosbot-api.service   # API on 127.0.0.1:8321
journalctl -u kryptosbot-api -f                         # API logs
source venv/bin/activate && python3 ops/site_builder/build.py  # Rebuild site
python3 ops/api/admin.py list|test|publish|reject <id>         # Theory admin
ops/deploy/cron_update.sh --force                              # Force deploy
```

---

## Persistent Memory (`.claude/` and `memory/`)

Two `memory/` directories exist — don't confuse them:

- **`.claude/projects/.../memory/`** — Claude Code's session-persistent memory (120+ topic files). This is where `elimination_ledger.md`, `confirmed_findings.md`, etc. live. Referenced from MEMORY.md's topic index. Read via Claude Code's memory system (not filesystem paths).
- **`memory/`** (repo root) — Checked-in research notes (11 files). Supplementary analysis documents (palette investigations, keystream forensics, etc.). These are regular repo files, not session memory.

**MEMORY.md** (auto-loaded) is the decision-support index — paradigm, eliminations, confirmed findings, open attack surface. CLAUDE.md has durable technical setup; MEMORY.md has volatile research state.

---

## Multi-Agent Mode — Solve K4

- **KryptosBot runner:** `python3 kryptosbot/solve.py`. See `kryptosbot/RUNBOOK.md`.
- **Campaign runner:** `PYTHONPATH=src python3 -u kryptosbot/campaign_v2.py` (supports `--local-only`, `--dry-run`).
- **Historical reference:** `archive/legacy_harness/`, `archive/session_reports/`, [`reports/final_synthesis.md`](reports/final_synthesis.md).

---

*Last updated: 2026-03-31 — Mission: derive K4 method & solve. Volatile research state (best leads, eliminations, open hypotheses) maintained in MEMORY.md.*
*Primary author: Colin Patrick (human lead) + Claude (computational partner)*
