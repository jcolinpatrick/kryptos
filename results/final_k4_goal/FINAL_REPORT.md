# K4 Autonomous Solve-or-Prove-Open — FINAL REPORT

**Run date:** 2026-06-06
**Repo HEAD:** `a3b264cce265856a972c3756cbfb576286a0c79c` (branch `main`)
**Operator:** autonomous `/goal` session (Claude Code)
**Status:** COMPLETE — all directed experiments finished (procedural sweep + primary 50-cycle controller + 2 counterfactuals); all verification done.

---

## 0. VERDICT

**`EXHAUSTED_CURRENT_REPO`** (final).

No 97-character plaintext (nor any documented second-level extraction) in this
repository simultaneously satisfies the canonical validation gate
(`crib_score==24` AND `bean_passed` AND an English body) under kernel scoring.
Across **13,302 distinct candidate plaintexts** ever produced by this repo,
re-scored from scratch by the canonical kernel, **zero** are kernel-validated
solves. Every high-crib candidate is a Bean-failing forced-crib overfit. The
bounded direct-mapping classical-cipher space and the bounded public-source ×
non-direct-alignment frontier are exhausted (corroborated by prior closures in
`MEMORY.md`). The remaining open space is **engineering / acquisition, not
compute** (see §6, §8).

This is **not** a claim that K4 is unsolvable — it is a scoped, reproducible
statement that the current repository's bounded, dispatchable search surface
contains no solution and that the live frontier requires materially new inputs.

---

## 1. PREFLIGHT (all gates GREEN)

| Gate | Command | Result |
|------|---------|--------|
| Kernel/Bean sanity | `python3 -m kryptos doctor` | **PASS** (all 21 checks; Bean 1 eq / 242 ineq / 101 linear) |
| Derived state | `scripts/_infra/session_briefing.py` | OK (1036 scripts tracked, 302 exhausted) |
| Readiness gate | `kryptosbot/self_test.py --panel all --mode dry-run --cycles 20000` | **3/3** (K1/K2/K3 rediscovered, 0.92s) |
| Full suite | `pytest kryptosbot/tests/ -q` | initial: 2617 passed, **11 failed** (stale null) → after fix: **2628 passed, 1 skipped** (re-run `-n 8`, 2:14) — see §1.1 |
| Open audits | `docs/methodological_audits.md` | AUDIT-1..4 all CLOSED — no compute blockers |

### 1.1 Null-cache staleness (diagnosed and fixed)

The 11 initial failures were all in `test_r3_synthetic_alert_path.py`
(matched-family null consulted at signal). Root cause: the null-baseline cache
is keyed to git HEAD; it was built at the prior commit `dbd6005` and HEAD was
`a3b264c`. **Two scripts are required to fully rebuild it:**

- `scripts/_infra/calibrate_null_baselines.py` (~25s) → generic + random/shuffled baselines.
- `scripts/_infra/calibrate_null_baselines_r2_4.py` (~20s) → the 10 **per-family** matched baselines (beaufort, variant_beaufort, columnar_single/double, rail_fence, myszkowski, route, vigenere).

After running both, `test_r3_synthetic_alert_path.py` → **29/29 pass**.
The running controller re-reads the cache per alert-check, so the rebuild
re-calibrated it live; meanwhile its p-gate fails OPEN (never silent on a high
score), so no signal was at risk of being missed.

---

## 2. PROCEDURAL SWEEP (directed experiment #1) — CLEAN NULL

```
PYTHONPATH=src python3 -m kryptosbot.procedural_enumerator --sweep \
  --max-cost-minutes 240 --report-path results/final_k4_goal/procedural_sweep.json
```

12 of 17 procedural recipes executed (5 admissibility-rejected). **Best crib
score 4/24**, below the NOISE floor (6) and below the random null max (7-8/24
over 100K samples). Zero Bean passes. Artifact:
`results/final_k4_goal/procedural_sweep.json`.

| recipe | tested | best | bean |
|--------|-------:|-----:|------|
| P-KRYPTOS-KW | 10 | 3.0 | False |
| P-A5-4b | 5 | 3.0 | False |
| P-BC-KW | 5 | 2.0 | False |
| P-F1-1 | 5 | 4.0 | False |
| P-SANBORN-VOCAB | 8 | 1.0 | False |
| (others) | ≤5 | ≤2.0 | False |

---

## 3. CANONICAL CANDIDATE HARVEST — 0 SOLVES IN 13,302 PLAINTEXTS

Reproducible: `results/final_k4_goal/harvest_top_candidates.py [--deep]`.
Scans result JSONs for any 97-char A-Z plaintext, re-scores each with the
**full kernel scorer** (crib + Bean + quadgram ngram + dictionary words).

- Top-level scan: 436 files, 1,742 unique PTs.
- Deep scan: **21,619 files, 13,302 unique PTs.**
- **Kernel-validated solves (crib==24 & bean & words≥8): 0.**

Top candidates (all forced-crib overfits — note `bean=False`, `is_bt=False` throughout):

| # | crib | bean | ngram_pc | words | is_bt | source |
|---|-----:|------|---------:|------:|-------|--------|
| 1 | 24 | False | -6.067 | 23 | False | results/e_autokey_k4.json |
| 2 | 24 | False | -3.750 | 22 | False | results/e_polybius_coord_exploit.json |
| 3 | 24 | False | -6.162 | 22 | False | results/breakthroughs/alert_20260413T223205_…breakthrough.json |
| 4 | 24 | False | -3.667 | 21 | False | results/e_model_b_running_key_sa.json |
| 5-20 | 24 | False | -3.6…-4.6 | 20-21 | False | f_ap_constrained_sa_v1 / e_polybius_coord_exploit / … |

**Interpretation:** simulated-annealing searches trivially produce text that is
both English-looking (≈22 dictionary words, ngram_pc ≈ -3.7) AND crib-perfect
(24/24) — because they optimize for exactly those objectives. The **Bean
constraints** (k[27]=k[65], 242 inequalities, 101 linear relations) are
structural consequences of a real additive/periodic keystream at the crib
positions; a free-text optimizer that pastes cribs cannot satisfy them. `bean`
is the discriminator that separates "looks like a solution" from "is one." All
13,302 fail it. Artifacts: `top_candidates.json`, `verified_candidates.json`.

### 3.1 The p-value gate is necessary but NOT sufficient

The single-candidate full-gate verifier `verify_breakthrough.py` (self-tested,
`--selftest` PASS) was run on the top forced-crib overfit. Its **matched-family
null p-value is 1.1e-34** — astronomically "significant," because crib_score=24
is so improbable under random text that *any* crib paste yields a vanishing p.
The verifier nonetheless returns **REJECT** because `bean_passed=False`,
`is_breakthrough=False`, and the body is non-English (forced-crib). Lesson: a
tiny p-value on `crib_score` is an artifact of forcing the cribs; the real
discriminators are **Bean** + **English body** + the **forced-crib check**.
This is why the project gates on Bean ∧ ngram-floor ∧ p-value, never p alone.
`verify_breakthrough.py` is the canonical tool to run against any future
candidate at crib_score≥18.

---

## 4. HISTORICAL ALERT AUDIT — 0 REAL-K4 SOLVES

Reproducible: `results/final_k4_goal/audit_alerts.py` → `alert_audit.json`.
All 17 files under `results/breakthroughs/` re-verified:

- **2 real-K4 alerts** (`20260413T195351`, `20260413T223205`): both **FORCED-CRIB**
  — cribs in place, gibberish body (vowel ratio 0.0 / 0.196 vs English ~0.38;
  ngram_pc -6.16 / -5.84). The `20260413T195351` file self-reports
  `crib_score=24, bean_passed=True` but is an **80-char non-direct candidate**
  (cribs at pos 13/51) with a gibberish body and controller composite `score=0.0`.
  Kernel `is_breakthrough=False` for both.
- **15 K4Bench alerts** (`hcc-k4b-*`): synthetic-calibration artifacts; they
  solved *different* synthetic CTs and score 0-4 against the *real* K4 cribs —
  exactly as expected. Not real-K4 claims.

This is the AUDIT-3 pattern made concrete: `crib_classification: breakthrough`
is the raw crib-only *input* label; `is_breakthrough` is the validated *output*
gate, and it rejects every one.

---

## 5. CONTROLLER PRIMARY RUN (directed experiment #2)

```
PYTHONPATH=src python3 kryptosbot/run_controller.py --verify-transport \
  --cycles 50 --theories 8 --workers 4 --timeout 60 \
  --alert-on signal --db db/final_k4_goal.sqlite
```

- **Transport verification: PROCEED** (direct-api OK 5.3s; subscription-sdk OK 6.0s).
- 16 pantheon agents loaded; ledger pinned `synthetic_mode=real`.

**RUN COMPLETE — 50/50 cycles:**

| metric | value |
|--------|------:|
| Cycles completed | 50 |
| Theories proposed | 399 |
| Kernel-tested (dispatched) | 61 |
| Eliminated | 38 |
| **Promising** | **0** |
| Max kernel-verified crib_score | **7/24** (= random null ceiling) |
| SIGNAL/BREAKTHROUGH alerts | **0** |
| Bean passes | **0** |

Kernel crib_score histogram across 64 scored experiments:
`{0:33, 2:10, 3:1, 4:6, 5:6, 6:3, 7:5}` — **everything at or below the random
null max (7-8/24).** Families most explored (the genuinely open frontier):
key_tape (121 theories), multi_layer (105), crib_analysis (56), geometry (35),
mirror_ka (28), k3_continuity (27), k2_coords (20).

**8 candidates reached the crib≥6 storage floor** (3×crib6, 5×crib7) — all
persisted with full provenance in `candidates_persisted.json`. Every one:
`bean=False`, `is_breakthrough=False`, `ngram_per_char ≈ -6.3…-6.4` (the random
floor → gibberish body). The crib=7 candidates show matched-family p ≈ 2e-5,
but this is a **look-elsewhere artifact** (max-of-64 at the matched-null tail),
not signal — the alert gate is crib≥18 precisely to suppress it.

One recoverable SDK session crash occurred (`Fatal error in message reader`,
GOTCHA2-class; the controller continued — 3 theories ended in `error` status,
yielding 0 candidates each, no halt). The thinking-gate (`opus-4-8` →
`{"type":"disabled"}`) kept the crash rate to a single event over 50 cycles.

**Disprover behavior confirmed:** the LLM theorist generated finite, on-frontier
hypotheses; the critic + red-team gates rejected the majority (335 criticized,
38 eliminated) — correctly invoking Bean-elimination knowledge (e.g. rejecting
Quagmire IV / periodic substitution because the 242-inequality set eliminates
it); the 61 dispatched all kernel-scored at noise. **No solution; no signal.**

---

## 6. NEWLY ELIMINATED / RE-CONFIRMED ASSUMPTION BUNDLES

This run did not eliminate a new cipher *family*, but it **re-confirmed at
canonical scale** that:

1. No accumulated candidate (13,302 PTs) is a solve under the full gate.
2. Every "breakthrough"/"success"-labelled artifact is a Bean-failing forced
   crib — the label semantics warning in AUDIT-3 holds empirically.
3. The procedural-recipe corpus (the project's distilled "most-promising
   hand-procedures") produces only sub-noise scores.

Permanent closures (from the briefing, unchanged) remain the binding facts:
direct CT[i]→PT[i] classical space is exhausted (pure transposition impossible;
all periodic polyalphabetic Bean-eliminated; all autokey×transposition capped;
Hill/fractionation impossible; columnar/double-columnar/Myszkowski = noise).

### 6.1 Still-open families (by alignment model)

The closure certificate is **scoped to alignment model**. Closed under the
direct model; the broader models remain outside the certificate but are NOT
cleanly compute-attackable with the current toolchain:

| Model | Status | Why not just sweep it |
|-------|--------|-----------------------|
| `direct_ct_pt` | **EXHAUSTED** (this run + briefing) | classical hand-cipher space closed |
| `ct73_null_extracted` | open in principle | depends on the retired null-palette mask; no live mask hypothesis |
| `arbitrary_null_mask` | open in principle | unbounded (mask positions unknown); no defined statistic since the palette was retired |
| `non_direct_alignment` | **bounded public cells closed** (Carter tape, named reorderings — `MEMORY.md` 2026-06-05) | `crib_alignment='free'/'post_transposition'` is **not honored by the real-K4 scorer** (toolchain trap, confirmed 2026-05-28) → Category-B manual only |
| `joint_mask_mechanism` | open in principle | mask + cipher must be solved together; no bounded enumeration without a declared mask model |

The most-explored live families this run (`key_tape`, `multi_layer`,
`k3_continuity`, `geometry`) are all dispatchable and were swept to noise. The
genuinely-untested cells are blocked on either a **toolchain gap** (free
alignment scoring is unwired) or **missing external inputs** (a declared
mask/corpus/chart), not on compute budget.

---

## 7. COUNTERFACTUAL SENSITIVITY (directed experiment #3)

Both counterfactuals suppress a community-derived prior to test whether the
primary all-noise result is an artifact of how the theorist is seeded. Each ran
12 cycles (sensitivity check, not a solve attempt) on its own ledger.

| run | flag suppressed | cycles | proposed | tested | promising | signals | max crib | crib≥6 |
|-----|-----------------|-------:|---------:|-------:|----------:|--------:|---------:|-------:|
| primary | (none) | 50 | 399 | 61 | **0** | 0 | 7/24 | 8 |
| CF1 `noor` | Oranchak community corpora | 12 | 96 | 20 | **0** | 0 | **4/24** | **0** |
| CF2 `noserp` | AAA serpentine-Vigenère anchor | 12 | 96 | 10 | **0** | 0 | **3/24** | **0** |

**Result: the negative is robust.** With the community Oranchak corpora
suppressed, and (separately) with the AAA serpentine anchor suppressed, the
controller still generates the same on-frontier families — `key_tape` (43/38
theories) and `multi_layer` (36/40) dominate both, as in the primary — and
still reaches **0 promising, 0 signals**. The counterfactual ledgers are in
fact *cleaner* than the primary (max crib 3-4/24, zero candidates at the crib≥6
storage floor). The primary's all-noise conclusion is **not** an artifact of
community-theory seeding; removing those priors does not surface anything.

Ledgers: `db/final_k4_goal_noor.sqlite`, `db/final_k4_goal_noserp.sqlite`.
Logs: `controller_noor.log`, `controller_noserp.log`.

---

## 8. SINGLE NEXT BEST FINITE EXPERIMENT

Per the briefing's open frontier and the prior-session conclusion (D1
Mono+Trans+Running-key is mathematically underdetermined; bounded public ×
non-direct cells closed), **no remaining pure-compute sweep has positive
expected value.** The single highest-value *finite* move is **acquisition-gated**:

> **Operationalize a declared, licensed running-key corpus under a
> non-direct (post-transposition) alignment** — i.e. pre-register ONE specific
> public text + transposition route + additive variant as a bounded
> `HypothesisSpec`, with a matched-family null and a hard kill criterion. This
> is the only cell that is both untested and dispatchable, and it is bounded
> only once a corpus + route is *declared* (otherwise it is unbounded keyword
> fishing, which the policy forbids).

All other genuine moves require **new external evidence** (a square-on photo for
GAP-04/NDYAHR; a public chart/procedure license for the bespoke-cipher bin) —
not more search.

---

## 9. ARTIFACT INDEX (all reproducible)

| Artifact | What |
|----------|------|
| `procedural_sweep.json` / `.log` | directed procedural sweep |
| `verify_candidates.py` / `verified_candidates.json` | flagged-OPEN re-verification |
| `harvest_top_candidates.py` / `top_candidates.json` / `harvest_deep.log` | full-repo top-20 verified |
| `audit_alerts.py` / `alert_audit.json` | all 17 breakthrough alerts re-verified |
| `verify_breakthrough.py` | single-candidate full validation gate (crib+Bean+ngram+words+matched-null p + controls + forced-crib); `--selftest` PASS |
| `controller_primary.log` / `controller_noor.log` / `controller_noserp.log` | the 3 controller runs |
| `candidates_persisted.json` | all 8 crib≥6 candidates (provenance + canonical verification) |
| `calibrate_r2_4.log` | per-family null rebuild |
| `db/final_k4_goal{,_noor,_noserp}.sqlite` | controller ledgers (primary + 2 counterfactuals) |

_Run `PYTHONPATH=src python3 results/final_k4_goal/<script>.py` to reproduce any table._

---

## 10. COMMANDS / EXIT LEDGER

| # | command | exit | result |
|---|---------|-----:|--------|
| 1 | `python3 -m kryptos doctor` | 0 | 21/21 PASS |
| 2 | `scripts/_infra/session_briefing.py` | 0 | landscape OK (1036 scripts, 302 exhausted) |
| 3 | `kryptosbot/self_test.py --panel all --mode dry-run --cycles 20000` | 0 | **3/3** K1/K2/K3 |
| 4 | `pytest kryptosbot/tests/ -q` (1st) | 1 | 2617 pass, **11 fail** (stale null) |
| 5 | `calibrate_null_baselines.py` | 0 | generic baselines → HEAD |
| 6 | `calibrate_null_baselines_r2_4.py` | 0 | 10 per-family baselines → HEAD |
| 7 | `pytest kryptosbot/tests/test_r3_synthetic_alert_path.py` | 0 | **29/29 pass** (fixed) |
| 8 | `pytest kryptosbot/tests/ -q -n 8` (2nd) | 0 | **2628 pass, 1 skip** |
| 9 | `procedural_enumerator --sweep --max-cost-minutes 240` | 0 | clean null (best 4/24) |
| 10 | `harvest_top_candidates.py --deep` | 0 | 13,302 PTs, **0 solves** |
| 11 | `audit_alerts.py` | 0 | 17 alerts, **0 real solves** |
| 12 | `verify_breakthrough.py --selftest` | 0 | rejects top overfit (PASS) |
| 13 | `run_controller.py --verify-transport --cycles 50 …` | 0 | 50 cycles, **0 promising** |
| 14 | `run_controller.py --no-oranchak-corpora --cycles 12 …` | 0 | 12 cycles, **0 promising** |
| 15 | `run_controller.py --no-serpentine-anchor --cycles 12 …` | 0 | 12 cycles, **0 promising** |

**Deliverables intentionally NOT written** (no solve): `BREAKTHROUGH.md`,
`results/real_ct.json`. A solve would have required `verify_breakthrough.py` to
return `SOLVE_CANDIDATE`; it did not for any candidate.
