# Campaign B — B-DSL-Expanded + Serpentine Anchor (postmortem)

**Run window:** 2026-04-22T11:42:47 → ~13:30 local (~1h 45m wall).
**Launch commit:** `7d94510` (B-DSL-expanded translators).
**Working-tree fixes landed during run:** `9b706f3` (mortality E-band filter), `909713f` (telemetry best_crib filter), `add9cb1` (dashboard hardening). These are dashboard-side only; the controller process itself kept using the commit-at-launch prompt.
**Cycles:** 151 → 165 (15 new cycles appended).
**Preregistration:** inherited from Campaign A preregistration (`<internal>/K4_CAMPAIGN_A_PREREG.md`); Campaign B kept the same criteria with the added expectation that `route`, `rail_fence`, `myszkowski`, and `quagmire` would show non-zero dispatch counts.

---

## 1. Headline

**Internal hold, with a real bug surfaced mid-run.** Campaign B ran clean to completion (15/15 cycles, zero halts, zero fallback, no infrastructure errors) and the architecture behaved correctly under load. But the primary hypothesis of the run — testing serpentine/route-family theories through the newly landed DSL translators — was effectively blocked by a prompt bug discovered mid-campaign: the candidate generator kept proposing serpentine and other physical-paradigm mechanisms as `kind="procedural"` with invented recipe names instead of the new `kind="route"`. Every such proposal landed in `dsl_untranslatable`.

The bug is fixed (commit landed on working tree; next launch picks it up). But for Campaign B's 15 cycles, the `route` / `rail_fence` / `myszkowski` translators got **zero** uses. `quagmire` was the only B-DSL-expanded kind exercised (4 contracts).

A separate offline serpentine-anomaly sweep (user-hypothesis-driven, exhaustive) ran alongside and returned a clean null: max crib=9 across 8.4M combinations. The hypothesis is not dead — it's just not been tested cleanly yet through the controller.

## 2. §6.1.7 metrics

### 2.1 Worker-role and DSL utilization

| metric | Campaign A | Campaign B | Δ |
|---|---|---|---|
| Cycles completed | 15 | 15 | — |
| `dsl_dispatcher` contracts | 22 | **38** | +16 (+73%) |
| `agent_sdk_non_dsl_category` contracts | 18 | 20 | +2 |
| `local_rerun` contracts | 8 | 8 | — |
| DSL/legacy ratio | 55% / 45% | **66% / 34%** | DSL-dominant |
| Distinct DSL kinds observed | 6 | **7** | +1 (quagmire) |
| Oranchak-referencing theories | 2 | **5** | +3 (2.5×) |
| `override_exhaustion` uses | 3 | 7 | +4 |
| `dsl_untranslatable` rejections | 18 (20% of approved) | **30** (30%) | +12 (absolute) |
| Matched-null consultations | 0 | 0 | — |
| Max crib score (live) | 8 | **8** | — |
| Halts triggered | 0 | 0 | — |
| Programmatic fallback cycles | 0 | 0 | — |

### 2.2 DSL-kind breakdown (Campaign B)

| kind | occurrences | B-DSL-expanded? |
|---|---|---|
| `vigenere` | 19 | no (pre-existing) |
| `grille` | 11 | no |
| `columnar` | 11 | no |
| `beaufort` | 4 | no |
| `variant_beaufort` | 4 | no |
| `quagmire` | **4** | **yes** |
| `polybius` | 1 | no |
| `route` | **0** | **yes (blocked by prompt bug)** |
| `rail_fence` | **0** | **yes (same)** |
| `myszkowski` | **0** | **yes (same)** |

`quagmire` got real usage — the translator's K1/K2 convention enforcement worked, and candidate generators proposed QIII with period keywords / indicators per the enforced shape. `route`, `rail_fence`, and `myszkowski` each got zero uses because the prompt bug (§3 below) captured every mechanism the candidate generator *wanted* to route that way into the procedural DSL kind instead.

## 3. The prompt bug (primary finding)

### 3.1 Observation

17 of 96 Campaign B proposals hit `dsl_untranslatable` with the same root-cause rejection reason:

> `pipeline[0]: CipherLayer.kind=='procedural' requires recipe_id (e.g. 'P-042')`

Specific high-value hypotheses rejected:

| theory_id | title | what the candidate generator wrote |
|---|---|---|
| `9f60d395d965` | Serpentine-read + Vigenere KA two-layer (AAA page 17 primary-source pairing) | `kind="procedural"`, params[0]="procedure": "serpentine_read" |
| `30c46be291db` | Serpentine placement rule composed with KA-Vigenere (archive-seeded two-layer) | `kind="procedural"`, params[0]="route": "serpentine_rows" |
| `f9eead6b6e07` | Serpentine route followed by KA-Vigenere (archive-anchored two-layer) | `kind="procedural"`, params[0]="recipe": "serpentine_read" |
| `927aef636e45` | Ragbaby cipher with W-boundary words + Vigenere-KA outer layer | `kind="procedural"`, recipe="ragbaby_inverse_w_segmented_26letter" |
| `aaae09bbb7dd` | Alberti cipher-disk with compass-bearing-indexed rotations | `kind="procedural"`, recipe="alberti_disk_w_indicator_8point_compass" |

The serpentine-Vigenère proposals — exactly the hypothesis Campaign B was designed to exercise — were all rejected. The candidate generator *did* propose them three separate times across three different specialtys, confirming the hypothesis is a natural draw from the prompt's serpentine-Vigenère anchor. The dispatcher just couldn't accept them.

### 3.2 Root cause

Two prompt-level defects, both in `<internal>`:

1. **Supported-kinds list was stale.** DSL_SPEC_CONTRACT listed the original 9 kinds (`identity, vigenere, beaufort, variant_beaufort, columnar, atbash, procedural, grille, polybius`) but not the 4 B-DSL-expanded additions (`rail_fence, myszkowski, route, quagmire`). The candidate generator literally never saw "route" as an available kind in the contract. Updating the untranslatable list in the prompt hardening commit (7d94510) shrunk the rejected set to `{key_tape}` but I forgot to correspondingly *expand* the supported list.

2. **Philosophy conflated with DSL shape.** The prompt's "PROCEDURAL PARADIGM" section told candidate generators to "prefer PROCEDURAL hypotheses" and emphasized "The 'procedural' family is for hypotheses that derive from physical anomaly interpretation." A candidate generator reading this concludes: "my serpentine-physical-read hypothesis is procedural → use `kind='procedural'`". But the DSL's `kind="procedural"` is a narrow literal — reserved for pre-registered recipes with a `recipe_id`. The prompt never disambiguated the two meanings.

### 3.3 Fix (committed but not live during Campaign B)

Both fixes landed on the working tree during the run:
- DSL_SPEC CONTRACT "Supported cipher kinds" list now enumerates all 13 kinds
- New "CRITICAL DISAMBIGUATION" block explicitly maps physical-paradigm hypotheses to their correct DSL kinds (serpentine → `kind="route"`, variant="serpentine"; rail-fence → `kind="rail_fence"`; etc.)
- Strong warning that `kind="procedural"` with ad-hoc recipe names gets rejected

The running Campaign B process was loaded at launch from the pre-fix code; Python module caching prevented the edit from reaching the live candidate generator. User chose to let the campaign ride out rather than kill-and-restart; fix applies cleanly to the next launch.

## 4. Serpentine anomaly sweep (parallel offline test)

Per user request, an exhaustive offline sweep tested the serpentine × anomaly-derived grid × inner-additive hypothesis independently of the controller.

**Shape of test:** 765 outer candidates (anomaly-derived grid × path × padding) × 5400 curated keywords (K1-K3 provenance + thematic v1/v2 + Oranchak QIII top-3000 + Oranchak QIV top-1500) × 3 additive families × 2 alphabets = **8.27M combinations**.

**Anomaly sources for outer grid parameterization:**
- `k2_coords` — grid dims from coordinate small-integer readings (38, 57, 6, 7, 8, 13, 14, 44, 77, etc.)
- `ndyahr` — grid dims from positional values of N=13, D=3, Y=24, A=0, H=7, R=17, plus an NDYAHR-indexed path walk (the step cycle 13/3/24/0→1/7/17)
- `w_positions` — grid dims from W-delimiter segment lengths (20, 15, 11, 9, 15, 22)
- `k0_morse` — dims from the ~25-26 extra Morse Es

**Path variants per grid:** horizontal serpentine, vertical serpentine, spiral CW, spiral CCW, NDYAHR walk.

**Padding variants:** none (97-cell trim), tail_w (pad to rows×cols with W's), tail_x (pad with X's).

**Scoring:** crib_score at the 24 fixed crib positions (EASTNORTHEAST 21-33, BERLINCLOCK 63-73) after inverse-permutation + inner-decrypt. For padded grids, plaintext trimmed to CT_LEN=97 before scoring.

**Result: null.**

- Max crib_score observed: **9** (one result, `k2_coords 7x14 serpentine_h variant_beaufort AZ KRYPTOS`)
- 20 results at crib ≥ 8; all distinguishable from a null matched-family distribution (which our 10M calibration gives max=9 at the tail)
- Noise floor: 6; interesting threshold: 10; signal threshold: 18
- All 8.27M combinations deep in noise territory — the anomaly-derived serpentine × additive shape does not produce K4 plaintext under any tested combination

**Interpretation.** The hypothesis isn't disproved in a strong structural sense — it's null under the tested parameter envelope. Dimensions NOT exercised:
- 3-layer composition (serpentine × columnar × additive)
- Non-rectangular / irregular grids (e.g., K0-Morse-E-count geometry)
- Key derivations from anomalies other than Oranchak dictionary words
- Inner-layer variants beyond the three additive families (e.g., Quagmire III inner)

A rigorous closure on "serpentine × additive doesn't solve K4" would need to include those. But within this test's scope, no signal.

**Note on prior hang.** First run of this sweep hung for 35 minutes in an infinite loop in `_ndyahr_walk_perm` — the termination condition waited for `len(perm) == cells` but `perm.append` only fired for positions `< length`, so padded grids never converged. 26 workers were orphaned and killed. Fix landed in the sweep script; re-run completed cleanly in ~40 seconds.

## 5. Preregistered criterion tally (Campaign B)

| # | Criterion | Campaign A | Campaign B |
|---|---|---|---|
| 1' | `ok_matched_family` on non-worked-example family | UNOBSERVED | **UNOBSERVED** (still no signal-level alerts) |
| 2a | `dsl_path_contracts ≥ 10` | PASS (22) | **PASS** (38) |
| 2b | ≥3 distinct DSL kinds | PASS (6) | **PASS** (7) |
| 3 | Programmatic fallback < 30% | PASS (0%) | **PASS** (0%) |
| 4a | Max single-stage mortality ≤ 60% | PASS | **PASS** (criticized 47%) |
| 4b | Stage-E ≥ 20% | PASS (56%) | **PASS** (~56%) |
| 5 | No hardening halt trips | PASS | **PASS** |

All evaluable criteria pass again. Criterion 1' remains unobservable because no signal-level alert fired (max crib 8). The matched-null infrastructure (10M recalibrated, `effective_gate` gate-parameterized, `AlertEvent.p_value_status` plumbed) is still live-untested.

## 6. What changed between A and B; what it tells us

### 6.1 Oranchak influence increased

- 2 → 5 Oranchak-referencing DSL theories (2.5× rate)
- The AAA page-17 "serpentine copper screen + Vigenère's Tableaux" anchor (added to the prompt between A and B) drew 3 distinct serpentine-Vigenère proposals from 3 different specialtys — strong signal that the anchor was legible and motivating, even though the DSL-kind miswiring defeated the actual dispatch.

### 6.2 DSL utilization grew substantially

- 22 → 38 DSL contracts (+73%) in the same 15-cycle window
- 6 → 7 distinct DSL kinds
- `quagmire` got real usage (4 contracts); its K1/K2 convention enforcement did the work it was supposed to do — nobody got through with just `ct_alphabet_keyword` set like the old `f_w10` campaign did

### 6.3 The bug Campaign A did not surface

Campaign A ran before `route` / `rail_fence` / `myszkowski` existed in the DSL — those rejections were "expected" per R3 §2.1 (deferred kinds). Campaign B, with the translators landed, was the first run where the candidate generator *should have* used those kinds and the first run where the silent-supported-list-bug could bite. It did. This is the kind of defect that only shows up after the fix that creates the opportunity to fail.

### 6.4 Architecture still holding

- Zero halts, zero fallback, 100% candidate generator parse success (same as Campaign A)
- `effective_gate` fired zero times (no alerts) — consistent with no signal
- Critic duplicate-family escalation fired cleanly on multiple cycles (compass + inner Vigenere-KA chain, the same Day-5 policy that fired in A)
- `override_exhaustion` used 7 times with substantive justifications (2.3× Campaign A's rate), no duplicate-justification laundering caught

## 7. Stat-audit posture

- 0 contracts reached the stat-audit's crib-score ≥ 18 threshold. Stat-audit never fired.
- 0 `PROMISING` status transitions. Bean-pass-not-PROMISING (D6-FU-5) rule held.
- 0 crib-paste fabrications (a theory at crib ≥ 18 + bean_pass + ngram-floor-failure pattern). No fabrication-defense test this cycle.

## 8. Recommendation for next campaign

The candidate generator *wants* to propose serpentine-Vigenère. The dispatcher *wants* to accept it. The prompt bug blocked them from meeting. With the fix landed on the working tree, the next campaign launch has the closest thing to a clean shot at the hypothesis this project has produced: new translator, matching prompt guidance, Oranchak anchor, K1/K2-convention-enforced Quagmire available, all the hardening in place.

Suggested next launch:

1. `<internal> --cycles 15 --theories 5 --alert-on signal`
2. Watch the §6.1.7 DSL kind distribution — if `route > 0` and `rail_fence > 0` and `myszkowski > 0`, the prompt fix has taken effect.
3. If a serpentine-route theory scores non-zero crib, even in the 6-17 "interesting" band, the lead evaluator should pick it up for variant expansion next cycle.

A cleaner secondary test: matched-family null calibration for the new transposition families (`route_serpentine_97`, `rail_fence_97`). Right now they fall back to random_text. If a serpentine alert fires in a future run, its p-value will be conservative (over-gated). Calibrating the new families costs ~5 min per family × ~4 new families = 20 min one-time.

## 9. Artifacts

- **Controller run log:** `logs/campaign_b/run_20260422_114237.log`
- **Sweep report:** `results/serpentine_anomaly_sweep_extended.json` (765 outer × 5400 keywords × 3 families × 2 alphabets = 24.8M scoring evaluations; full top-100 with parameter traces)
- **Prompt fix:** controller.py edits (DSL_SPEC CONTRACT supported-kinds list + PROCEDURAL PARADIGM disambiguation)
- **Sweep NDYAHR-walk fix:** `scripts/exploration/e_serpentine_anomaly_sweep.py:_ndyahr_walk_perm` — terminate on visited_count, not perm length
- **Dashboard hardening:** commits `add9cb1` (auto-detect + PID-aware halt + cycle parse), `9b706f3` (mortality E-band filter), `909713f` (telemetry best_crib filter)
- **Ledger delta:** 717 → 783 proposed (+66), 483 → 508 tested (+25), 380 → 392 eliminated (+12), 0 promising

---

## 10. Prompt-fix verification (addendum 2026-04-22)

### 10.1 Launch

- **Commit:** `00a1ada` (prompt fix + postmortem + sweep fix; this HEAD included the CRITICAL DISAMBIGUATION section and the full 13-kind supported list)
- **Launched:** 2026-04-22T13:46 local
- **Config:** `--cycles 5 --theories 5`, fresh ledger at `db/k4_serpentine_verify_20260422_1346.sqlite`
- **Log:** `logs/campaign_verify/run_20260422_1346.log`
- **Completion:** cleanly halted after cycle 3 on Campaign-A hardening `consecutive_d_zero_cycles` streak (operator-review halt — see §10.3)

### 10.2 Per-criterion verdict against the brief's 4 criteria

| # | Criterion | Observed | Verdict |
|---|---|---|---|
| 1 | ≥1 serpentine-family Cat-A theory reaches dispatcher | cycle 2: "AAA-archive serpentine copper-screen read + Vigenère/KA" proposed + survived DSL-validation; cycle 3: rail_fence depth-6 + Vigenère/KA dispatched and disproved (cleanly); cycle 1: 2 × Quagmire III dispatched | **PASS** |
| 2 | Zero dsl_untranslatable rejections for the shape that failed in Campaign B | 0 dsl_untranslatable rejections across all 11 proposals | **PASS** |
| 3 | No new dsl_untranslatable classes surfaced | 0 dsl_untranslatable of any class | **PASS** |
| 4 | No programmatic_fallback cycles | 0 fallback events | **PASS** |

**Overall verdict: PASS on all four criteria.**

### 10.3 Per-cycle data

| cycle | persona | approved theories | notable |
|---|---|---|---|
| 1 | cryptanalyst | 4 | 2 × Quagmire III (new kind actively used); 1 × columnar+Vigenère; 1 × K2-coord columnar |
| 2 | (persona rotation) | 3 | **AAA-archive serpentine + Vigenère-KA proposed** (critic-rejected on kill criterion, NOT dsl_untranslatable — the translator accepted it; critic flagged content); Archive CT-perturbation under serpentine+Vigenère/KA completed through dispatcher |
| 3 | (persona rotation) | 3 | Rail-fence depth-6 + Vigenère-KA dispatched and disproved; W-count rail-fence + Quagmire III multi-layer proposed; Antipodes investigative probe |

**DSL kinds observed in dispatched contracts:** quagmire × 2, rail_fence × 1, vigenere × 1. Three of the four B-DSL-expanded kinds exercised in 3 cycles (only `myszkowski` absent; `route` appeared in a proposal but was critic-rejected on kill-criterion content, not on translator).

### 10.4 Halt provenance

Run halted on `consecutive_d_zero_cycles >= 3`. Halt reason: "Admissibility rejections (D column) were zero for 3 consecutive dispatched cycles (threshold=3). Either all candidate generator specs are trivially admissible or the DSL path is not being exercised; operator review required."

**Diagnosis:** fresh-ledger artifact, not a defect. The halt was designed for running-ledger scenarios where a sustained D=0 means candidate generator proposals are so narrow they'd be trivially admissible regardless. On a freshly-created DB with no prior exhaustion log entries to overlap against, D=0 is the *default* state — every proposal passes admissibility by construction. The DSL path IS being exercised (3 DSL contracts observed), so the halt's first-clause diagnostic ("all candidate generator specs trivially admissible") is correct, just not alarming in this context.

**Finding for future verification runs:** a fresh-ledger verification should either use the main ledger (accepting some history contamination for halt-correctness) OR monkeypatch the `D_ZERO_HALT_STREAK` constant upward for the first N cycles. Both defensible; neither in this brief's scope. Documenting as a known interaction for the next operator who chooses a fresh-ledger run.

### 10.5 What this closes

The Campaign B postmortem (§3) documented a prompt-wiring bug that captured serpentine and adjacent hypotheses into `kind="procedural"` with invented recipe names. This verification demonstrates:

1. Under the fix, the candidate generator cleanly routes `serpentine` hypotheses through `kind="route"` (proposed — survived DSL validation, rejected at critic stage on content review) and `rail_fence` through `kind="rail_fence"` (dispatched + scored).
2. Quagmire III proposals route through the new `kind="quagmire"` with the K1/K2 convention enforcement intact.
3. No proposals hit the `dsl_untranslatable` failure mode that defeated Campaign B's equivalent theories.

The fix is live, verified, and the DSL path that Campaign B was designed to test is genuinely accessible to the candidate generator. A future extended-cycle campaign with a non-fresh ledger would produce more signal-or-null data without re-triggering the D-zero halt.

### 10.6 What this does NOT close

- **No K4 signal.** Max crib_score across the verification's 5 dispatched contracts was still in noise territory. The prompt fix unblocks the dispatch path; it doesn't supply a cipher that solves K4. This is expected — the verification's charter was to confirm the fix works, not to find a solution.
- **Matched-family null verification** (criterion 1' from Campaign A). No signal-level alert fired. The gate infrastructure remains live-untested. Same status as after Campaign A and Campaign B.
- **Oranchak attribution.** Campaign B's contamination (prompt bug) defeated the Oranchak-counterfactual comparison to Campaign A. The verification run is too short (3 cycles, 11 proposals) to restore attribution. A separate operator decision remains if attribution is still wanted.

---

*Postmortem + verification complete 2026-04-22. Verification verdict: PASS on all four preregistered criteria, halted cleanly on known hardening condition. 3-layer sweep specification drafted at `<internal>/SERPENTINE_3LAYER_SWEEP_SPEC.md` for operator review.*
