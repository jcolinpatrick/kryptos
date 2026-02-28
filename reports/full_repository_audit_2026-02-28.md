# Full Repository Audit — 2026-02-28

**Auditor:** KryptosBot (Claude Opus 4.6)
**Scope:** Entire `/home/cpatrick/kryptos/` repository
**Method:** Automated deep inspection of all source code, scripts, data, databases, logs, documentation, and memory files. All 513 tests confirmed passing. All 351 scripts confirmed syntactically valid.

---

## 1. Repository Map

### Core Source Code (`src/kryptos/`, 2,709 LOC, 688K)

| Layer | Path | Purpose | Status |
|-------|------|---------|--------|
| kernel/constants | `constants.py` | Single source of truth: CT, cribs, Bean, thresholds | ACTIVE, self-verifying |
| kernel/alphabet | `alphabet.py` | Alphabet models (AZ, KA, keyword-mixed) | ACTIVE |
| kernel/text | `text.py` | Text normalization (sanitize, encode/decode) | ACTIVE |
| kernel/config | `config.py` | Frozen config dataclasses with SHA256 hashing | ACTIVE |
| kernel/constraints | `crib.py`, `bean.py`, `consistency.py` | Crib scoring, Bean EQ/INEQ, self-encryption checks | ACTIVE |
| kernel/scoring | `aggregate.py`, `crib_score.py`, `ic.py`, `ngram.py`, `free_crib.py` | Canonical scoring path + IC + quadgrams + position-free variant | ACTIVE |
| kernel/transforms | `vigenere.py`, `transposition.py`, `polybius.py`, `compose.py` | Cipher implementations + composable pipeline builder | ACTIVE |
| kernel/persistence | `sqlite.py`, `artifacts.py` | WAL-mode SQLite + JSONL logging | ACTIVE |
| pipeline | `evaluation.py`, `runners.py`, `experiments.py` | Evaluation entry points, parallel SweepRunner, worker templates | ACTIVE |
| novelty | `hypothesis.py`, `generators.py`, `triage.py`, `ledger.py` | Hypothesis lifecycle: generate → triage → track → prevent repeats | ACTIVE |
| cli | `main.py`, `doctor.py`, `reproduce.py` | CLI commands: doctor, sweep, reproduce, novelty, report | ACTIVE |

**Verdict: KEEP ALL.** Zero dead code found. All modules confirmed active via `__pycache__` evidence and import analysis. Code quality is production-grade.

### Experiment Scripts (`scripts/`, 351 files, 175K LOC, 14 MB)

| Prefix | Count | Era | Description |
|--------|-------|-----|-------------|
| `e_s_*` | 153 | Feb 18-19, 27 | Legacy session scripts — the experimental backbone |
| `e_frac_*` | 55 | Feb 20, 27 | FRAC agent: analytical/structural proofs |
| `e_team_*` | 21 | Feb 27 | Operation Final Vector team experiments |
| `e_bespoke_*` | 12 | Feb 27 | Bespoke cipher methods |
| `e_chart_*` | 12 | Feb 27 | Chart/coding-chart hypotheses |
| `e_audit_*` | 11 | Feb 27 | Audit/verification experiments |
| `e_cfm_*` | 10 | Feb 27 | Crypto Field Manual-derived |
| `e_antipodes_*` | 10 | Feb 27 | Antipodes sculpture analysis |
| `e_roman_*` | 7 | Feb 27 | Roman numeral/coordinate hypotheses |
| `e_explorer_*` | 7 | Feb 27 | Explorer agent experiments |
| `e_novel_*` | 6 | Feb 27 | Novel attack methods |
| `k4_*` | 13 | Feb 18, 27 | Early K4-focused scripts |
| `e0[1-6]_*` | 6 | Feb 18 | Earliest experiments |
| Other | 28 | Various | Misc standalone (opgold, rerun, webster, nsa, marathon, dragnet) |

### Infrastructure

| Component | Path | Size | Status |
|-----------|------|------|--------|
| API server | `api/` | 60K | RUNNING (systemd, FastAPI + Haiku classifier for kryptosbot.com) |
| Compute engines | `bin/` | 204K | READY (4 Antipodes engines, pending jobs exist) |
| Deployment | `deploy/` | 28K | RUNNING (cron every 30 min, nginx, systemd) |
| Site builder | `site_builder/` | 276K | RUNNING (Jinja2, auto-rebuilds to `site/`) |
| Job queue | `jobs/` | 296K | 8 pending, 1 done, orchestrated by `k4_job_runner.sh` |
| Tests | `tests/` | 1.1 MB | 513 tests, ALL PASSING |

### Data

| Component | Path | Size | Status |
|-----------|------|------|--------|
| Ciphertext | `data/ct.txt` | 98B | Core dependency |
| Quadgrams | `data/english_quadgrams.json` | 2.0 MB | Core dependency |
| Wordlists | `wordlists/` | 4.1 MB | Core dependency |
| Reference materials | `reference/` | 48 MB | Primary sources (PDFs, texts, 90 images) |
| External project | `external/` | 4.6 MB | Third-party reference |
| Databases | `db/` | 340K | 3 active SQLite DBs |
| Results | `results/` | 372K | 54 experiment outputs, feeds website |
| Reports | `reports/` | 416K | 14 analysis reports |
| Docs | `docs/` | 192K | 9 reference documents |
| Archive | `archive/` | 856K | Legacy harness + session reports + dragnet |

### Transient / Working

| Component | Path | Size | Status |
|-----------|------|------|--------|
| Gutenberg caches | `tmp/` | **125 MB** | Downloaded corpora, experiments complete |
| Working files | `work/` | 256K | Audit outputs from Feb 27 |
| Agent logs | `agent_logs/` | 276K | 2 log files from Feb 26 |
| Artifacts | `artifacts/` | 312K | Earlier session outputs |
| Checkpoints | `checkpoints/` | 44K | Antipodes engine resume data |
| Logs | `logs/` | 248K | Cron build logs (active) |
| Manifests | `manifests/` | 0 | Empty directory |

---

## 2. Execution Status Matrix

### Core Infrastructure

| Component | Purpose | Status | Evidence |
|-----------|---------|--------|----------|
| `src/kryptos/` | Kernel + pipeline + novelty + CLI | **ACTIVE** | All `__pycache__/` populated, 513 tests pass, constants self-verify |
| `api/` | Theory classifier for kryptosbot.com | **ACTIVE** | systemd service running, 43 MB RAM, port 8321 |
| `deploy/cron_update.sh` | Auto-rebuild site every 30 min | **ACTIVE** | Crontab confirmed, last run 2026-02-28 08:00:45 |
| `site_builder/` | Static site generator | **ACTIVE** | 134 pages, 117 eliminations, auto-deployed |
| `k4_job_runner.sh` | Job orchestrator | **DORMANT** | Script exists, 8 pending jobs, not currently running |

### Experiment Scripts (351 total)

| Category | Historically Run | Result Artifacts | Current Relevance |
|----------|-----------------|-----------------|-------------------|
| `e_s_*` (153) | YES — bulk of 669B+ configs | 9/153 have `results/` JSON | **ARCHIVAL** — all served as elimination evidence, none produced signals |
| `e_frac_*` (55) | YES — analytical proofs | 0 in `results/` (stdout capture) | **ARCHIVAL** — foundational proofs (Bean impossibility, underdetermination) |
| `e_team_*` (21) | YES — Final Vector campaign | 17/21 have `results/` JSON | **ARCHIVAL** — comprehensive multi-agent sweep, ALL NOISE |
| `e_cfm_*` (10) | YES — all executed Feb 27 | 10/10 have `results/` JSON | **ARCHIVAL** — systematic gap-filling, all eliminated or underdetermined |
| `e_antipodes_*` (10) | PARTIALLY — 04 and 08 just run | 2/10 have `results/` JSON | **ACTIVE** — Antipodes remains an open research direction |
| `e_chart_*` (12) | YES — Feb 27 | 3/12 have `results/` JSON | **ARCHIVAL** — chart hypothesis eliminated |
| `e_bespoke_*` (12) | YES — Feb 27 | 2/12 have `results/` JSON | **ARCHIVAL** — bespoke methods tested, all noise |
| `e_audit_*` (11) | YES — Feb 27 | varies | **ARCHIVAL** — verification complete |
| `k4_*` (13) | HISTORICALLY — Feb 18 | 0 in `results/` | **ARCHIVAL** — earliest scripts, superseded by kernel |
| `e_explorer_*` (7) | YES — Feb 27 | varies | **ARCHIVAL** — exploratory, all noise |
| `e_novel_*` (6) | YES — Feb 27 | varies | **ARCHIVAL** — novel methods tested |
| Other (28) | VARIES | varies | Mixed — some active (marathon, dragnet), some archival |

### Pending / Never Run

| Item | Status | Evidence |
|------|--------|----------|
| `jobs/pending/` (8 items) | **NEVER RUN** | No `done/` counterparts, no result artifacts |
| `bin/antipodes_device_engine.py` | **READY, NOT RUN** | Checkpoint files at initial state |
| 5 `ad-h*` JSON manifests | **NEVER RUN** | Reference `bin/antipodes_device_engine.py` |

---

## 3. Legacy Contamination Findings

### 3.1 Stale Documentation References

| File | Issue | Severity |
|------|-------|----------|
| `docs/invariants.md` lines 11, 70-71, 108-111 | References `k4lab.py`, `domain.py`, `k4suite/k4suite/core/cribs.py` — a superseded codebase that does not exist in this repo | **MODERATE** — misleads anyone reading the doc |
| `docs/invariants.md` section 8 | States K5 position-dependence eliminates Chaocipher/Enigma as **fact**; `kryptos_ground_truth.md` correctly labels this as **HYPOTHESIS** | **MODERATE** — violates the project's own truth taxonomy |
| `docs/research_questions.md` line 74 | References "k4suite" | **LOW** — easy to misread as current |
| `docs/kryptos_ground_truth.md` | References `tools/validate_public_invariants.py` — never created | **LOW** — aspirational, not harmful |
| `docs/crypto_field_manual/30_k4_mapping_matrix.md` | References `e_cfm_05_sculpture_geometry.py` but actual script is `e_cfm_05_nomenclator_model.py` | **LOW** — wrong filename |
| `anomaly_registry.md` line ~302 | Claims "KRYPTOS alphabet has 24 unique letters (J is absent)" — **WRONG**, KA has all 26 letters. Contains an inline "wait, let me check this" that was never resolved | **MODERATE** — factual error in a tracked file |

### 3.2 Hardcoded Constants (57 scripts)

Scripts `e_s_65` through `e_s_105` (41 files) and `k4_*` (12 files) hardcode CT, cribs, and Bean constraints inline instead of importing from `kernel.constants`. The values are correct, but these scripts:
- Cannot benefit from future corrections if cribs or CT were revised
- Duplicate 61 Vigenère implementations, 105 columnar transposition implementations, and 48 scoring implementations

**Risk:** Low (K4 CT is ground-truth-agnostic and identical on both sculptures). But these scripts cannot participate in automated validation if constants.py assertions change.

### 3.3 Outdated Experiment Count

MEMORY.md header says "295+ experiments" while CLAUDE.md says "320+". The E-CFM and Final Vector sections within MEMORY.md itself document 25+ additional experiments beyond the 295 count. The header is stale.

### 3.4 Missing Eliminations in docs/elimination_tiers.md

Last updated 2026-02-21. Missing all E-CFM experiments (00-09) and Operation Final Vector results (Feb 27). These are documented in MEMORY.md but not in the elimination tiers doc that is supposed to be the authoritative elimination reference.

---

## 4. Redundancy and Dead-Weight Findings

### 4.1 Dead Weight (safe to delete)

| Item | Size | Reason |
|------|------|--------|
| `tmp/gutenberg_cache/` | 91 MB | Downloaded Gutenberg texts for E-CFM-09 — experiment complete (ALL NOISE), re-downloadable |
| `tmp/gutenberg_french/` | 14 MB | French corpus for Final Vector — experiment complete, re-downloadable |
| `tmp/gutenberg_german/` | 5.5 MB | German corpus for Final Vector — experiment complete, re-downloadable |
| `tmp/gutenberg_it_es/` | 16 MB | Italian/Spanish corpus for Final Vector — experiment complete, re-downloadable |
| `tmp/verify_k1.py` | 4K | One-off verification script, orphaned |
| `manifests/` | 0 | Empty directory, zero references in codebase |
| `reference/Pictures/*- Copy.jpg` (7 files) | 56K | Byte-identical duplicates of existing images, tracked in git |
| `reference/MEMORY_backup_2026-02-27.md` | 16K | Manual backup of MEMORY.md, superseded by current version |
| `jobs/pending/__pycache__/` | 126K | Compiled bytecode in a data directory |

**Total recoverable: ~127 MB** (dominated by Gutenberg caches)

### 4.2 Low-Value Retained Items

| Item | Size | Reason to Consider Removing |
|------|------|----------------------------|
| `agent_logs/` (2 files) | 276K | Historical logs from Feb 26, results already in `results/` JSON |
| `work/` (13 files) | 256K | Transient audit outputs from Feb 27, findings captured in `reports/` and `memory/` |
| `.pytest_cache/` | 72K | Standard pytest artifact, regenerated automatically |

### 4.3 Script Redundancy

| Issue | Count | Details |
|-------|-------|---------|
| "b" variant scripts | 11 | e.g., `e_s_33b` supersedes parts of `e_s_33`. Original + revision both retained |
| Naming collision | 4 scripts | `e_audit_05` has 4 different scripts sharing the same sequence number |
| Superseded version | 1 | `e_team_narrative_pt.py` (has character-count bugs) superseded by `e_team_narrative_pt_v2.py` |
| Missing sequence numbers | 7 | e_s_111, 113-116, 118, 126 — gaps in numbering (deleted or never created) |
| Eliminated hypothesis scripts | ~11 | Scripts that test provably eliminated hypotheses (Bifid, AMSCO, Myszkowski, etc.) — but these ARE the elimination evidence |

### 4.4 Git Health

- Git object store: 383 MB of **loose objects with zero packs**. `git gc` would significantly reduce `.git` size.
- 90 tracked images in `reference/Pictures/` (~42 MB), including 30 video stills (~26 MB). Not using Git LFS.
- Prior cleanup already removed ~1.16 GB of sweep databases (documented in `db/DELETED_DATABASES.md`).

---

## 5. Risk Assessment

### 5.1 Misleading Artifacts

| Risk | Severity | Details |
|------|----------|---------|
| `anomaly_registry.md` "24 unique letters" error | **HIGH** | A tracked file with a factual error about the KA alphabet. Any agent reading this file could conclude J is missing from the Kryptos alphabet, leading to wrong analysis. The inline "wait, let me check this" makes this especially dangerous — it looks like an acknowledged uncertainty rather than a confirmed error. |
| `docs/invariants.md` k4suite references | **MODERATE** | A reader could waste time looking for `k4suite/k4suite/core/cribs.py` or `k4lab.py`. These don't exist. The current equivalents are in `src/kryptos/kernel/`. |
| `docs/invariants.md` K5 fact-vs-hypothesis | **MODERATE** | States as fact what `kryptos_ground_truth.md` correctly labels as hypothesis. Could cause a future agent to incorrectly eliminate state-dependent ciphers from consideration. |
| `docs/elimination_tiers.md` missing latest eliminations | **MODERATE** | The "authoritative" elimination reference is missing a full week of experiments (E-CFM-00 through 09, Final Vector). An agent consulting this doc would not know about the homophonic, nomenclator, K3-rotational, or Gutenberg running key eliminations. |
| Hardcoded constants in 57 scripts | **LOW** | Values are currently correct. Risk materializes only if CT/cribs were ever revised (unlikely given K4 CT is sculpture-agnostic). |
| `e_team_narrative_pt.py` (v1 with bugs) | **LOW** | Superseded by v2, but both exist. An agent might accidentally run v1. |

### 5.2 Structural Risks

| Risk | Severity | Details |
|------|----------|---------|
| Scoring underdetermination at high periods | **NOTED** (not a bug) | Well-documented in CLAUDE.md and MEMORY.md. Any score at period > 7 is statistically meaningless. This is a fundamental mathematical property, not a code defect. |
| Fixed crib position assumption | **NOTED** (not a bug) | All scoring assumes cribs at positions 21-33, 63-73. The `free_crib.py` scorer exists to test this assumption. If cribs are wrong, the entire scoring apparatus is blind. |
| No conflicting scoring implementations | **CLEAN** | All code funnels through `score_candidate()`. No alternative scoring paths found. |
| No stale filters or pruning rules | **CLEAN** | Bean constraints are mathematically sound and variant-independent. No outdated heuristics found in kernel code. |

---

## 6. Recommended Action Plan

### KEEP (no changes needed)

| Item | Reason |
|------|--------|
| `src/kryptos/` (entire kernel, pipeline, novelty, cli) | Production-quality, zero dead code, all tests pass |
| `data/ct.txt`, `data/english_quadgrams.json` | Core data dependencies |
| `wordlists/` | Core data dependency |
| `db/` (3 SQLite databases) | Active: novelty ledger, results, theory queue |
| `results/` (54 experiment outputs) | Feeds the live website |
| `api/` | Running production service |
| `deploy/` | Running production infrastructure |
| `site_builder/` | Running production site generator |
| `logs/cron_update.log` | Active operational logging |
| `k4_job_runner.sh` | Job orchestration (dormant but functional) |
| `bin/` (4 Antipodes engines) | Ready for pending jobs |
| `jobs/pending/` (8 jobs, minus `__pycache__/`) | Planned work |
| `checkpoints/` | Resume data for Antipodes runs (tiny, 44K) |
| `tests/` | 513 passing tests |
| `.claude/settings.local.json` | Agent team configuration |
| `.gitignore`, `.env` | Standard config (env correctly gitignored) |

### REFACTOR (update content, keep file)

| Item | Action | Priority |
|------|--------|----------|
| `anomaly_registry.md` line ~302 | Fix "24 unique letters" error → "all 26 letters, non-standard ordering". Remove the "wait, let me check this" | **HIGH** |
| `docs/invariants.md` | Replace all `k4suite`/`k4lab` references with `kryptos.kernel.*`. Add `[HYPOTHESIS]` label to K5 section 8 | **HIGH** |
| `docs/elimination_tiers.md` | Append E-CFM-00 through 09 and Operation Final Vector eliminations | **MODERATE** |
| `docs/research_questions.md` line 74 | Replace "k4suite" with "kryptos.kernel" | **LOW** |
| `docs/crypto_field_manual/30_k4_mapping_matrix.md` | Fix script reference: `e_cfm_05_sculpture_geometry.py` → `e_cfm_05_nomenclator_model.py` | **LOW** |
| `MEMORY.md` header | Update "295+" → "320+" experiments | **LOW** |

### ARCHIVE (move to `archive/`, keep for historical reference)

| Item | Current Location | Reason |
|------|-----------------|--------|
| (nothing new to archive) | — | The prior archival pass (session reports, legacy harness, dragnet) was well-executed. No additional archival needed. |

### DELETE (safe to remove)

| Item | Size | Reason |
|------|------|--------|
| `tmp/gutenberg_cache/` | 91 MB | Experiment complete, re-downloadable |
| `tmp/gutenberg_french/` | 14 MB | Experiment complete, re-downloadable |
| `tmp/gutenberg_german/` | 5.5 MB | Experiment complete, re-downloadable |
| `tmp/gutenberg_it_es/` | 16 MB | Experiment complete, re-downloadable |
| `tmp/verify_k1.py` | 4K | Orphaned one-off script |
| `manifests/` | 0 | Empty, unreferenced |
| `reference/Pictures/*- Copy.jpg` (7 files) | 56K | Byte-identical duplicates |
| `reference/MEMORY_backup_2026-02-27.md` | 16K | Superseded backup |
| `jobs/pending/__pycache__/` | 126K | Bytecode in data dir |

**Total deletable: ~127 MB**

### QUARANTINE (review before deciding)

| Item | Size | Concern |
|------|------|---------|
| `work/` (13 files) | 256K | Audit reports and verification scripts from Feb 27. Findings are captured in `reports/` and `memory/`, so these may be redundant. But some verification scripts (`verify_bean_pairs.py`, `verify_eliminations.py`) could be promoted to `scripts/` or `tests/` if valuable |
| `agent_logs/` (2 files) | 276K | Historical logs. Results already in `results/`. Delete unless you want raw execution traces |
| `artifacts/` (26 items) | 312K | Earlier session outputs (Feb 13-20). Partially redundant with `results/`. Only `run_manifest.json` has a code reference. Could be pruned or kept as-is (312K is negligible) |
| `e_team_narrative_pt.py` | 20K | Has character-count bugs, superseded by v2. Delete or rename to `_SUPERSEDED` |

---

## 7. Cleanup Strategy

### Immediate Actions (< 5 minutes, 127 MB recovered)

```bash
# 1. Delete Gutenberg caches (125 MB)
rm -rf tmp/gutenberg_cache tmp/gutenberg_french tmp/gutenberg_german tmp/gutenberg_it_es
rm -f tmp/verify_k1.py

# 2. Delete empty directory
rmdir manifests/

# 3. Delete duplicate images from git
git rm "reference/Pictures/centeredtableau - Copy.jpg"
git rm "reference/Pictures/cipherback - Copy.jpg"
git rm "reference/Pictures/cipherlowerleft - Copy.jpg"
git rm "reference/Pictures/cipherlowermiddle - Copy.jpg"
git rm "reference/Pictures/cipherlowerright - Copy.jpg"
git rm "reference/Pictures/ciphermidleft - Copy.jpg"
git rm "reference/Pictures/ciphermidmiddle - Copy.jpg"

# 4. Delete stale backup
rm -f reference/MEMORY_backup_2026-02-27.md

# 5. Delete pycache from jobs
rm -rf jobs/pending/__pycache__/

# 6. Pack git objects
git gc
```

### Documentation Fixes (< 30 minutes)

1. Fix `anomaly_registry.md` alphabet error
2. Update `docs/invariants.md` path references and K5 truth label
3. Append latest eliminations to `docs/elimination_tiers.md`
4. Fix minor references in `research_questions.md` and crypto field manual

### What the Trusted Active Core Should Be After Cleanup

```
kryptos/
├── src/kryptos/           # Computational kernel (UNTOUCHED — grade A)
├── tests/                 # 513 tests (ALL PASSING)
├── scripts/               # 351 experiment scripts (historical record + active research)
├── bin/                   # Antipodes compute engines
├── api/                   # Live theory classifier
├── site_builder/          # Live site generator
├── deploy/                # Production infrastructure
├── data/                  # CT + quadgrams
├── wordlists/             # English dictionary
├── db/                    # Active databases
├── results/               # Experiment outputs (feeds website)
├── reports/               # Analysis reports
├── docs/                  # Reference documentation (after fixes)
├── reference/             # Primary source materials (after dedup)
├── archive/               # Historical record
├── external/              # Third-party reference
├── jobs/                  # Job queue
├── checkpoints/           # Antipodes resume data
├── logs/                  # Operational logs
├── CLAUDE.md              # Project instructions
├── anomaly_registry.md    # Physical anomalies (after fix)
├── k4_job_runner.sh       # Job orchestrator
└── .gitignore, .env       # Config
```

**What gets removed:** `tmp/` contents (125 MB caches), `manifests/` (empty), 7 duplicate images, 1 stale backup, 1 stray `__pycache__/`.

**What gets fixed:** 6 documentation issues (1 factual error, 3 stale references, 1 missing week of eliminations, 1 experiment count).

**What stays unchanged:** The entire `src/kryptos/` kernel, all 351 scripts, all tests, all infrastructure, all databases, all reports. The codebase is fundamentally sound.

---

## 8. Executive Summary

**This repository is in excellent shape.** The core source code (`src/kryptos/`) scored grade A — zero dead code, zero stale logic, zero conflicting implementations. All 513 tests pass. The four-layer architecture (kernel → pipeline → novelty → CLI) is clean and well-maintained. The canonical scoring path (`score_candidate()`) is properly enforced. Bean constraints are mathematically sound.

**The 351 experiment scripts are a legitimate historical record**, not clutter. They collectively represent 320+ experiments testing 669B+ configurations across every major classical cipher family. Each script that tests an eliminated hypothesis IS the elimination evidence. Deleting them would destroy provenance.

**The cleanup opportunity is modest:** 127 MB of downloadable caches, 7 duplicate images, an empty directory, and a stale backup. The documentation has 6 issues ranging from a factual error in the anomaly registry to stale path references in the invariants doc. All are straightforward fixes.

**The only real risk is the anomaly_registry.md alphabet error** — a tracked file claiming the KA alphabet has 24 letters when it has 26. This should be fixed immediately as it could mislead future analysis.

**Bottom line:** Clean the caches, fix the docs, pack the git objects, and this repo is a well-organized cryptanalytic workspace ready for the next phase of research.
