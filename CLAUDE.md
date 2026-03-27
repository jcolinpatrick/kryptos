# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## STOP. DO NOT SKIP THIS SECTION.

You MUST complete ALL of these steps before executing any task:

1. Read this entire CLAUDE.md
2. Read `elimination_ledger.md` from Claude Code session memory (`.claude/projects/…/memory/`) — the complete elimination record by attack family.
   **Do NOT use a filesystem path** — access it via the memory system. This is session memory, not the repo `memory/` directory.
   **This is the most-skipped step and the #1 cause of wasted computation.**
3. Read MEMORY.md — the decision-support index (paradigm, constants, what's open).
   MEMORY.md is loaded automatically; individual topic files in `memory/` are on-demand — read only when relevant to the current task.
4. If the user's request matches ANYTHING already disproved or tested,
   TELL THE USER and do NOT run it again
5. Search scripts/ for existing tools — do NOT write new code if a script exists
   `run_attack.py --list --verbose | grep KEYWORD`
   Also check `results/` and `exhaustion_log.json` for prior output matching your planned parameters.

If you skip these steps and re-test an eliminated hypothesis, you are
wasting 28 CPU cores and burning API tokens for zero value.

This repo has one purpose: determine the **true plaintext** and the **full encryption method** of **Kryptos K4**.

**Contents:** [K4 Quick Reference](#the-k4-problem--quick-reference) · [Dev Setup & Commands](#development-setup--commands) · [Architecture](#architecture) · [Operations](#operations--deployment) · [Scores](#interpreting-scores) · [Gotchas](#key-gotchas) · [Truth Taxonomy](#truth-taxonomy-mandatory) · [Reference Docs](#reference-documents) · [Multi-Agent](#multi-agent-mode--solve-k4)

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
# Run all tests
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

# Benchmark: PYTHONPATH=src python3 bench/cli.py run --suite bench/suites/tier0_smoke.jsonl
# Site builder: source venv/bin/activate && python3 ops/site_builder/build.py
# API server: source venv/bin/activate && python3 ops/site_builder/serve.py
# Theory admin: python3 ops/api/admin.py list|test|publish|reject <id>
# Service: sudo systemctl status|restart kryptosbot-api.service
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

~950 attack scripts in ~35 subdirectories (928+ tracked in exhaustion log including deleted/renamed). Each has a metadata header; tracked in root `exhaustion_log.json` (authoritative — ignore `scripts/EXHAUSTION.json`). Infrastructure in `scripts/lib/` (header parsing, exhaustion log CRUD, discovery).

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

**Naming:** `e_` = experiment, `f_` = formal campaign. Both live in `scripts/<family>/` subdirectories. `_infra/` = utilities, not attacks.

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

### Key data files

- `data/english_quadgrams.json` — Quadgram log-probabilities (2 MB, `{"THAN": -3.776, ...}`)
- `wordlists/english.txt` — 1M+ words; `wordlists/thematic_keywords.txt` — thematic keywords
- `reference/` — Primary sources (525 files: Carter book, Sanborn correspondence, NSA docs, Ed Scheidt dossier, video transcripts, PDFs)
- `docs/crypto_field_manual/` — Durable cryptographic knowledge base
- `memory/` (repo root) — Checked-in research notes: keystream forensics, palette investigations, width analysis

### Supporting systems

- **`ops/site_builder/`** — Builds `kryptosbot.com` → `site/` (gitignored). Config: `overrides.toml`.
- **`ops/api/`** — FastAPI backend: theory classifier (`classifier.py`), submission queue (`queue.py`), admin CLI (`admin.py`). Mounts `site/` as static. Requires `venv/`.
- **`kryptosbot/`** — Claude Agent SDK multi-agent runner. Ops guide: `RUNBOOK.md` (root). Has its own `pyproject.toml` with `claude-agent-sdk` dependency.
  - `solve.py` — Original entry point (single-agent).
  - `campaign_v2.py` — **Active campaign runner**: Phases 1–5 (free compute: row key forensics, fractionation, state machines), Phase 6+ (Opus-guided, API budget). Entry: `PYTHONPATH=src python3 -u kryptosbot/campaign_v2.py`. Supports `--local-only`, `--dry-run`.
  - `monitor.py` — Live campaign dashboard: `python3 kryptosbot/monitor.py [--interval 1]`. Scans `results/campaigns/` for active sessions.
  - `polybius_scorer.py` — Polybius coordinate extraction and crib scoring.
- **`bench/`** — Benchmark suite (tier0–tier3). CLI: `bench/cli.py run|score|generate`. Tests: `tests/test_bench*.py`.
- **`reports/`** — 45+ synthesis files from experiment campaigns. Summary JSONs (`*.summary.json`), audit matrices, synthesis markdown. Key file: [`reports/final_synthesis.md`](reports/final_synthesis.md).
- **`archive/`** — `legacy_harness/` (old agent code), `session_reports/` (historical outputs).
- **`ops/deploy/`** — Production deployment: systemd unit, nginx config, setup script, 30-min cron CI/CD loop.
- **`ops/scheduled/`** — Non-interactive Claude Code prompts (nightly review) + shell health check via `health-check.sh`.
- **`ops/tools/`** — Ops utilities: `analyze_traffic.sh` (nginx log analysis, bot detection), `generate_quadgrams.py`.
- **`bin/`** — Specialized cipher engines (antipodes, cylinder rotation) — historical hypothesis testing.
- **`external/`** — Imported external research (enigmator, patrickkellogg-Kryptos) — not maintained.

### Data persistence & symlinks

Data directories are **symlinked** to a separate data partition:
- `db/` → `/data/db` — SQLite databases (novelty ledger, results)
- `artifacts/` → `/data/artifacts` — Result artifacts (JSONL logs)
- `kryptosbot_results.db` — Main results database (project root, ~1.8 GB)
- `checkpoints/` — Campaign checkpointing for resumable runs
- `exhaustion_log.json` — **Authoritative** experiment log (root level — ignore `scripts/EXHAUSTION.json`)

### Operations & deployment

The live site (`kryptosbot.com`) runs on this same machine:

```bash
# Service management
sudo systemctl status|restart kryptosbot-api.service   # API on 127.0.0.1:8321
journalctl -u kryptosbot-api -f                         # API logs (live tail)

# Nginx (reverse proxy, SSL via Let's Encrypt, rate limiting: 10 req/s per IP)
sudo nginx -t && sudo systemctl reload nginx

# 30-min CI/CD cron (flock prevents overlap, checksum-based rebuild)
# Crontab: */30 * * * * flock -n /tmp/kryptosbot-cron.lock ops/deploy/cron_update.sh
ops/deploy/cron_update.sh --force    # Force rebuild
ops/deploy/cron_update.sh --dry-run  # Skip git commit

# Scheduled prompts and health checks
ops/scheduled/run-prompt.sh ops/scheduled/nightly-review.txt
ops/scheduled/health-check.sh     # Zero-cost morning health check (replaces Claude briefing)

# Traffic analysis
ops/tools/analyze_traffic.sh      # Bot vs human breakdown from nginx logs
```

**Log locations:**
- API: `journalctl -u kryptosbot-api`
- Cron: `logs/cron_update.log`
- Scheduled prompts: `logs/scheduler.log`, `logs/scheduled_output_*.log`

**Environment files** (TWO `.env` files — don't confuse them):
- `.env` (root) — `ANTHROPIC_API_KEY`, `KBOT_CLASSIFY_API_KEY`, `NTFY_TOPIC` (push notifications for theory submissions)
- `kryptosbot/.env` — API key for Agent SDK campaigns (see `kryptosbot/.env.template`)

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

Applies whenever the target ciphertext is short (roughly <= 120 chars), partially masked, or plausibly multi-layer.

### Core rule

For short layered ciphertexts, early statistics are **advisory only**.
IC peaks, Kasiski repeats, autocorrelation peaks, DFT peaks, hill-climber optima, and n-gram improvements may be artifacts of:
- an outer transposition layer
- padding geometry
- null insertion/removal assumptions
- wrong layer order
- wrong alphabet convention
- short-text variance

Do **not** treat these signals as structural proof.

### Mandatory search behavior

- Never hard-prune a branch solely because final-ciphertext IC, period detection, or repeated-fragment evidence is weak, absent, or points elsewhere.
- Always consider heterogeneous layering, including:
  - transposition + periodic substitution
  - transposition + digraphic substitution
  - Polybius-derived layer + substitution/transposition
  - mixed alphabets / keyed tableaux
- For any two-layer hypothesis, test **both peel orders**:
  1. undo transposition first, then test substitution/polyalphabetic families
  2. undo substitution/polyalphabetic first, then test transposition families
- Do not assume final-ciphertext period evidence reflects the real key period if transposition may still be present.
- Do not assume absence of obvious digraphic signal rules out Playfair / Two-Square / Four-Square.
- Preserve multiple structurally distinct branches in parallel.

### Beam preservation policy

Retain a diverse beam across:
- layer order
- cipher family
- transposition width / rectangle shape
- key length
- alphabet convention
- padding / null assumptions

Do not let one statistic dominate the beam prematurely.

### Structural-first policy

Separate **structural search** from **keyword search**.

1. First search for plausible decompositions:
   - number of layers
   - family combinations
   - peel order
   - transposition geometry
   - masking / padding assumptions

2. Only then spend major compute on keyword dictionaries inside the strongest structural branches.

Do not burn compute on large keyword sweeps inside branches whose structure is still weakly supported.

### Scoring policy

Score candidates at three levels:
- **family-likeness** — does the intermediate resemble the expected residue of a cipher family?
- **plaintext-likeness** — does it resemble normalized English?
- **context coherence** — does it fit public Kryptos/Sanborn constraints without overclaiming?

A branch may remain alive if family-likeness improves sharply even when plaintext-likeness is still poor.

### Failure-report policy

When no solution is found, report:
- which structural branches were tested
- which were pruned and why
- which signals may have been deceptive
- which family/order combinations remain underexplored
- what concrete next campaigns should run

Do not give shallow “no signal” conclusions for short layered texts.
On short ciphertexts, signal suppression is expected and is not evidence against a hand-executable multi-layer design.


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

*Last updated: 2026-03-26 — Mission: derive K4 method & solve. Volatile research state (best leads, eliminations, open hypotheses) maintained in MEMORY.md.*
*Primary author: Colin Patrick (human lead) + Claude (computational partner)*
