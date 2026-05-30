# Controller-Closure Integrity Audit

**Date:** 2026-05-30 · **Ledger HEAD:** `9a19210` · **Scope:** every closure in the real-K4
theory ledger (`db/theory_ledger.sqlite`, 2751 theories, 2731 closed). Bench closures
(`db/k4bench/`) are out of scope. **Read-only.** No code or ledger was modified.

**Trigger:** the dispatcher candidate scorer (`kryptosbot/job_dispatcher.py:1807`)
unconditionally calls anchored `score_candidate`; `score_candidate_free` is never reached
from the dispatch path. A real-K4 `HypothesisSpec` may declare `crib_alignment` of `free` or
`post_transposition` (both accepted DSL values, propagated at `job_dispatcher.py:507`), but
the resulting `crib_score` is computed at the fixed as-carved crib positions (21-33, 63-73).

---

## 0. CORRECTION (2026-05-30, post-publication) — the "phantom" finding was overstated

The original §1-§3 below claimed **234 mislabeled phantom closures**. **That central
finding is RETRACTED.** A decisive round-trip test (added after publication) shows the
dispatcher only ever builds *decryption* pipelines that **undo** every transform
(`columnar` is translated with `direction:"undo"`, `job_dispatcher.py:741`), so the output
is natural-order candidate plaintext with cribs back at the canonical 21-33 / 63-73.
Therefore **anchored `score_candidate` is the CORRECT test** for every pipeline the
dispatcher can build. [DERIVED FACT — repro below]

- Full-inversion two-layer transposition+substitution → anchored recovers **24/24**.
- Transposition-only (`columnar`) decrypt → anchored recovers **24/24**.

Structural breakdown of the 234 (artifact §6): 208 multilayer (trans+sub) + 12 sub-only +
21 transposition-only. **All are valid disproofs.** The `post_transposition` / `free` labels
are **redundant metadata injected by the controller's own theorist prompt** ("Example B" at
`controller.py:3943` teaches `post_transposition` for two-layer ciphers; the correct label
for a full-decryption pipeline is `direct_positional`). The label being ignored does **not**
invalidate the disproof, because the disproof tests the direct-alignment reading, which is
what those specs actually are.

Precise residual truth:
- The dispatcher correctly tests the **direct-alignment reading** of any spec. It does **not**
  test a **free / search-anywhere** reading (`score_candidate_free` is genuinely unwired).
  A spec labeled `free` had its narrower direct-alignment hypothesis validly disproved; its
  broader "cribs anywhere" reading was never tested — but that reading is **not dispatchable**
  and belongs to the standalone harnesses, which §C found CLEAN.
- So the honest count of *mis-scored* dispatcher closures is **~0**, not 234. The honest
  defect is a **labeling/UX problem** (misleading tags + a prompt that teaches them), plus a
  **latent capability gap** (no free-search in the dispatcher).

**Reproduction of the correction:**
```bash
PYTHONPATH=src python3 - <<'PY'
from kryptos.kernel.constants import CT, CRIB_DICT
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.transforms.compose import PipelineConfig, TransformConfig, TransformType, build_pipeline
from kryptos.kernel.transforms.transposition import columnar_perm
pt=['X']*len(CT)
for p,c in CRIB_DICT.items(): pt[p]=c
PT=''.join(pt); perm=columnar_perm(7,[3,1,4,0,6,2,5],len(CT))
CTx=build_pipeline(PipelineConfig("e",steps=(TransformConfig(TransformType.TRANSPOSITION_FULL,{"perm":perm,"direction":"apply"}),),direction="encrypt"))(PT)
rec=build_pipeline(PipelineConfig("d",steps=(TransformConfig(TransformType.TRANSPOSITION_FULL,{"perm":perm,"direction":"undo"}),),direction="decrypt"))(CTx)
print("trans-only recovered crib_score:", score_candidate(rec).crib_score)  # 24
PY
```

**Status of the two recommended actions (originally §5.1, §5.2):**
- **Relabel the 234 → REVOKED.** They are valid disproofs; relabeling would erase real
  eliminations.
- **Dispatcher reject of non-direct alignment → REVOKED** (would block legitimate two-layer /
  transposition cipher search that the dispatcher tests correctly). The reject was prototyped,
  found to be a regression by this round-trip, and reverted before commit.

**What still stands unchanged:** §4 (the `eliminated`-status over-claim: 383 red-team batch,
41 orphaned-on-restart, 36 empty silent closures), §C (canonical memory/docs records CLEAN),
and the ERROR_AS_DISPROOF / SCORED_OTHER findings. Those are independent of the alignment
question. The lesson: Stream D validated the classifier was *faithfully implemented* but
inherited the framing that "non-direct label = phantom"; it did not empirically test scorer
correctness. The round-trip is what the audit should have done first.

Read §1-§3 below as the (now-corrected) original text, retained for the record.

---

## 1. Bottom line  *(SUPERSEDED in part by §0 — phantom bullets retracted)*

- **The defect is real and the harm is mislabeling, not wrongful elimination.** Across the
  whole ledger, the maximum anchored `crib_score` among confirmed-phantom closures is **5/24**
  (SIGNAL gate = 18, STORE = 10). No candidate was suppressed; the damage is that a set of
  closures recorded as *disproved* actually mean *the declared non-direct frontier was never
  tested.* [INTERNAL RESULT — artifact §6]
- **No canonical project record is contaminated.** Every non-direct-alignment closure claim in
  the five memory notes and the `docs/campaigns/` prereg files rests on a **standalone
  harness** that runs outside the dispatcher and scores correctly for its declared alignment.
  None of those scripts appear in the ledger experiments table. The dispatcher-phantom records
  are a **disjoint population**; no memory/doc closure claim is built on them. [INTERNAL RESULT
  — Stream C, §3]
- **234 ledger closures are confirmed mislabeled** (187 dispatcher + 47 agent-SDK scratch),
  plus 1 indeterminate, on the non-direct-alignment frontier. They should read *inconclusive /
  frontier untested*, not *disproved/eliminated*. [INTERNAL RESULT — Streams A/B/D]
- **A separate, larger labeling issue:** 383 closures were batch-relabeled to `eliminated`
  from red-team rejection without ever being dispatched; 41 were force-`completed` on a
  controller restart without a test; 36 carry no recorded reason. The *reasons* are mostly
  sound, but `eliminated` over-claims empirical disproof for argued-dead theories. [INTERNAL
  RESULT — Stream E, §4]

---

## 2. Closure classification (2731 closed theories)

Produced deterministically by `scripts/audit/audit_controller_closures.py` and independently
re-derived byte-for-byte by an adversarial validator (Stream D).

| Class | Count | Integrity |
|---|---:|---|
| PRE_DISPATCH_REJECT (critic / red-team, never ran) | 794 | **sound** — gate working |
| ARGUMENT_ELIMINATION (no experiment) | 762 | **mixed** — see §4 |
| REAL_DISPROOF (direct-positional; anchored = correct test) | 486 | **sound** |
| ADMISSIBILITY_DEDUP (exhaustion/overlap duplicate) | 360 | **sound** — dedup working |
| **PHANTOM_DISPATCHER** (non-direct, dispatcher anchored-scored) | **187** | **mislabeled** |
| PHANTOM_UNVERIFIED (non-direct, agent-SDK scratch) | 54 | resolved → 47 phantom / 6 sound / 1 indet (§3) |
| ERROR_AS_DISPROOF | 48 | **sound** (44 `error`; 4 re-dispatch hygiene) |
| SCORED_OTHER | 40 | **sound** (inconclusive/timeout; 2 forced artifacts) |

Sound by construction: PRE_DISPATCH_REJECT + REAL_DISPROOF + ADMISSIBILITY_DEDUP = **1640**.

---

## 3. The phantom population (confirmed defect)

**PHANTOM_DISPATCHER = 187.** Adversarially re-verified, zero misclassifications: every one
declares `crib_alignment ∈ {free, post_transposition}` in its `dsl_spec`, has a
`dsl_dispatcher` `disproved` experiment, and was scored anchored. Anchored crib distribution
`{0:11, 1:34, 2:48, 3:43, 4:47, 5:4}` — max **5/24**. Family spread: encoding 150,
k3_continuity 26, transposition 17. [INTERNAL RESULT — Stream D]

**PHANTOM_UNVERIFIED = 54** (agent-SDK scratch path, `agent_sdk_non_dsl_category`), resolved
per-experiment (Stream B):
- **47 CONFIRMED_PHANTOM** — the scratch script scored cribs anchored at the as-carved
  positions despite a `free`/`post_transposition` declaration. Decisive tell: many report a
  `bean_passed` kill criterion, and Bean is mathematically undefined under free alignment
  (`score_candidate_free` does not compute it). Reporting a Bean result *proves* anchored
  scoring. Strongest instance: `2a2331df14b5` declares `crib_alignment=free` yet reports
  "No Bean PASS for any tested configuration."
- **6 SOUND** — the worker explicitly used `score_candidate_free` / an anywhere-search as the
  operative kill criterion (e.g. `9dc17cac494a`: "scored with kernel score_candidate_free
  (cribs searched anywhere)", max 0 across 1.64M configs). These eliminations are method-valid
  *within their bounded universes only*; none is a global non-direct closure.
- **1 INDETERMINATE** — `355bc41a29bf` (single-letter-removal) scored "adjusted for position
  shift," neither clearly anchored nor clearly free.

**Total confirmed mislabeled: 187 + 47 = 234** (+1 indeterminate).

**Operator-facing surface (Stream A):** all 34 phantoms appearing in the four scanned terminal
logs are narrated as `disproved score=X in Ns`, with **zero** alignment caveat, and folded
into the per-cycle `N disproved` and run-header `eliminated` tallies. In one case the log
prints `post-transposition crib alignment` in red-team prose and then reports the sibling spec
"disproved ... no evidence gain" — the transposition-first alignment was never tested, so "no
evidence gain" is itself wrong. Log/ledger identity reconciliation is exact (0 log-only, 0
ledger-only closures); the discrepancy is purely *verb vs reality*. **153 of the 187
dispatcher phantoms were dispatched in run logs not among the four scanned** and their
narration is unaudited (assumed identical). [INTERNAL RESULT — Stream A, open question]

### Why the canonical records are clean (Stream C)

The recorded non-direct-alignment closures use harnesses that bypass the dispatcher entirely:

| Canonical claim | Basis | Verdict |
|---|---|---|
| 2026-05-28 cribforce periodic-inner | `f_non_direct_alignment_cribforce_2026_05_28.py` → `solve_periodic` re-derives Bean from the **permuted** CT (`solve.py:247`) and scores the reordered text (`solve.py:299`) | CLEAN |
| 2026-05-29 non-periodic public-tape inner | `f_non_direct_alignment_tape_inner_2026_05_29.py` — physically permutes CT first, then anchored `score_candidate` (the *correct* realization of post_transposition, per prereg) | CLEAN |
| 2026-05-29 C7 segmented public tape | `f_c7_segmented_public_tape_2026_05_29.py` — direct-positional, anchored score is the honest discriminator by construction | CLEAN |
| 2026-05-25 frontier closures (probe + masked tape ×2 + masked Quagmire III) | standalone probes; Bean re-derived from reordered CT; K1/K2 regression PASS | CLEAN |
| 2026-05-28 order-stat-trap; 2026-05-29 matched-null harness (`route_null.py`) | analytic/methodological, kernel-pure stdlib | CLEAN (not a closure) |

SQL confirms **0** experiments for each of these script names in the ledger; their only
non-null `script_id`s are 6 local `rerun:*` entries. The defect cannot have touched them.

---

## 4. Secondary finding: `eliminated` over-claim (Stream E)

The 762 ARGUMENT_ELIMINATION closures have **zero experiments** — the anchored defect never
bit them (never scored) — but the `eliminated` status (enum: "conclusively disproved")
over-claims for theories closed by argument:

- **383 RED-TEAM** — a 2026-05-15 batch relabel of red-team-rejected (conf ≥ 0.8) theories,
  never dispatched. Reasons largely sound (179 cite a prior empirical/Bean/E-FRAC kill, 123 a
  structural contradiction from public-fact cribs, 80 other), but the correct status is
  `withdrawn` / argued-dead, not `eliminated`. **Inflates the eliminated count.**
- **41 ORPHANED ("found in running")** — `reconcile_orphaned_running` transitions RUNNING →
  `completed` on restart with **no result**. Administratively closed, **untested**.
- **36 EMPTY** — blank `failure_reason`, no experiment, 34/36 zero score and empty outcome.
  **Unexplained silent closures.**
- **77 KILL_CRITERION + 26 KC1 + 4 KC2 + 13 EXHAUSTION + 37 NOISE** — sound: bounded universes
  with numeric kill criteria, classified here only because written to the theory row rather
  than the experiments table (so no kernel-verification provenance link).
- **123-126 of the 762** declare non-direct alignment but were closed by argument (never
  scored) — correctly *not* phantom, but non-direct frontiers closed without empirical test.

**ERROR_AS_DISPROOF nuance (cleared):** 44/48 are `status=error` (correctly inconclusive). The
4 `eliminated` ones (`c0a882118502`, `c32914a07aae`, `5a0b5bc6e49e`, `b3702015777c`) have an
errored linked experiment but are backed by a documented `[POST-FIX RE-DISPATCH 2026-05-15]`
NOISE result in `outcome_summary` (matching MEMORY.md's key_tape 8-ERROR note). The re-dispatch
was written to the theory row but never logged as a new experiment, so the deterministic
classifier only sees the stale error. **Not a leak — a ledger-hygiene gap.**

---

## 5. Recommendations (no action taken; read-only audit)

Priority order, smallest-blast-radius first:

1. **Relabel the 234 confirmed phantom closures** from `disproved`/`eliminated` to
   `inconclusive` / `frontier_untested`. The non-direct-alignment frontier they claim to cover
   is **open**, not closed. (IDs enumerated in the artifact, §6.)
2. **Land the scoped dispatcher reject** (the originally-requested fix): reject any **real-K4**
   spec with `crib_alignment != direct_positional` at admissibility, *scoped to non-bench*
   (bench legitimately uses `post_transposition` via the challenge crib dict and
   `_score_known_cribs` at `job_dispatcher.py:1798`; `controller.py:3943`, `bench_fallback.py`,
   `hand_cipher_core.py`, and ~6 capability tests depend on it). This prevents new phantoms
   without breaking the HCC suite. Alternative: implement the `score_candidate_free` branch in
   `_evaluate_single_config`.
3. **Relabel the 383 red-team batch eliminations** to `withdrawn`; **set orphaned-on-restart
   to a non-`completed` status**; **trace or annotate the 36 empty closures.**
4. **Ledger hygiene:** have the re-dispatch path link a fresh experiment row (closes the
   ERROR_AS_DISPROOF=4 artifact for future audits).
5. **Audit the remaining 153 dispatcher phantoms' narration** by sweeping the full
   `results/*.log` corpus (the 4 scanned logs covered only 34).

---

## 6. Reproduction & artifacts

```bash
# Deterministic backbone (read-only on the ledger):
PYTHONPATH=src python3 scripts/audit/audit_controller_closures.py
#   -> audits/controller_closure_audit_2026_05_30/closure_classification.json
#      (klass_counts, phantom_summary, full records[] with per-theory class + ids)
```

- **Classifier + artifact:** `scripts/audit/audit_controller_closures.py`,
  `audits/controller_closure_audit_2026_05_30/closure_classification.json`
- **Defect site:** `kryptosbot/job_dispatcher.py:1807` (anchored scorer), `:507` (alignment
  propagated but unused), `:1798` (bench-only `_score_known_cribs`).
- **Contract reference:** `dispatcher-dsl-contract` skill, "Known Dispatcher Limitations";
  prior note `scripts/audit/audit_dsl_dispatcher_semantics.py`.
- **Confirmed-phantom agent-SDK ids (47), sound (6), indeterminate (1):** Stream B
  reconciliation block in the workflow transcript.

## 7b. Actions applied (2026-05-30)

After the §0 correction (which revoked the relabel-234 and dispatcher-reject actions as
unfounded), the user authorized the two follow-ups that survive the correction. Both applied:

1. **`eliminated` over-claim cleanup (DB).** Backup
   `db/theory_ledger.sqlite.bak.20260530T123513Z.preclosureaudit` taken first; single
   transaction; each row annotated in `notes` with prior status + reason (reversible).
   - **393** red-team batch closures (`status=eliminated`, no experiment, failure_reason
     "red-team rejected"): `eliminated → withdrawn` (argued-dead, never dispatched).
   - **41** orphaned-on-restart closures (no experiment, "Orphaned: found in RUNNING"):
     `completed/eliminated → error` (not a real test; re-testable). The 7 orphaned rows that
     carry a real recorded experiment (incl. `726978e4`, 5472 configs tested) were left intact.
   - Net: eliminated 1403→1010, withdrawn 279→672, completed 482→441, error 52→93. Ledger
     re-load via `TheoryLedger` verified (both new statuses are valid `TheoryStatus` enum
     values; `count_by_status` and `recent_outcomes` load clean).
2. **Example B prompt fix (`controller.py`).** Two-layer columnar+Vigenère example changed
   `post_transposition → direct_positional` (it is a full-decryption pipeline, so cribs return
   to canonical), plus a note on the `crib_alignment` enum line stating only
   `direct_positional` is dispatcher-scored and genuine off-canonical hypotheses must be
   `dsl_spec: null` (Category-B). 536 prompt/dsl/contract/admissibility/prompt-layer tests pass.

NOT applied (revoked by §0): the dispatcher `crib_alignment` reject and the relabel of the
"234 phantom" closures.

## 7c. Git/log trace of the 35 "empty" silent closures (2026-05-30)

Traced. **They are transport / SDK failures, not real eliminations.** Signature (all 35,
current DB): `status` completed (34) + error (1), `best_score=0.0`, critic `decision=approve`
(conf 0.95), **no** experiment row, **blank** failure_reason and outcome. `created != updated`
with a created→updated gap of 130s-11494s (median ~13 min), so each entered a cycle and was
closed minutes later. Updated-at clusters (5 @ 2026-04-13T15:33, 5 @ 2026-04-30T20:20, plus
2+2+2) are per-cycle batch writes; the set spans 2026-04-11 .. 2026-05-06.

8 of the 35 still appear in retained terminal logs, and **every one shows a transport-layer
failure**, not a kernel result:
- API rate limit: `6b29c398`, `d37cbe33` → "You've hit your limit · resets 5pm".
- Red-team pre-check SDK crash: `9532ad32`, `8683fa97`, `502c2228` → "redteam pre-check SDK
  error ... Command failed with exit code 1" (and `status=error` for these).

The other 27 are not in retained logs (their cycles weren't captured) but share the identical
signature. The **absence of a failure_reason is itself the tell**: a real scored disproof
writes `failure_reason="NOISE: best crib_score 0/24"`; a blank reason means the
result-recording path never ran because the worker/red-team SDK call threw first. Commit
`5872302` (2026-04-17, "Harden controller outcome and ledger audit paths") tightened this, but
the 2026-04-30 cluster postdates it, so the hardening did not fully close the silent-failure
path.

**Conclusion:** these 35 are the same class as the orphaned set — "not a real test" mislabeled
as `completed`. Per `TheoryStatus.ERROR` ("worker errored / transport failed; not a real
test"), the honest status is `error`.

**APPLIED 2026-05-30:** the 34 `completed → error` relabel was applied (backup
`db/theory_ledger.sqlite.bak.20260530T125714Z.preEmptyRelabel`; single transaction;
notes-annotated/reversible; the 1 row already `error` left as-is). Net: completed 441→407,
error 93→127. Ledger re-load via `TheoryLedger` verified. Cumulative status counts after all
three relabels (red-team, orphaned, empty): approved 20, completed 407, criticized 515,
eliminated 1010, error 127, withdrawn 672.

## 7. Truth-taxonomy register

- [DERIVED FACT] `score_candidate_free` is absent from the dispatch call graph; real-K4 specs
  are scored anchored regardless of `crib_alignment`. *Repro:* `grep -n score_candidate
  kryptosbot/job_dispatcher.py` (only `:1807`).
- [INTERNAL RESULT] 234 confirmed mislabeled non-direct closures; max anchored crib 5/24; no
  wrongful kill. *Artifact:* §6 JSON + Streams A/B/D.
- [INTERNAL RESULT] Zero canonical memory/doc closure claims contaminated; all use standalone
  harnesses absent from the ledger. *Artifact:* Stream C (8 script-name LIKE queries → 0
  experiments each).
- [INTERNAL RESULT] 383 red-team `eliminated` are argued-dead batch relabels; 41 orphaned
  untested; 36 unexplained. *Artifact:* Stream E.
- [POLICY] `eliminated` should mean empirically disproved; argued-dead belongs in `withdrawn`.
  K4 remains **unsolved**; this audit changes no solve status.
