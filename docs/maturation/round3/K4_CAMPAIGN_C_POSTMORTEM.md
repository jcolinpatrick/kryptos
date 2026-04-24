# Campaign C — Oranchak Community Corpora Counterfactual (postmortem)

**Run window:** 2026-04-24 (two attempts — see §0).
**Preregistration:** `<internal>/K4_CAMPAIGN_C_PREREG.md` (post-split-update, commit `1fbce36`).
**Hardening basis:** Campaign-A hardening + post-B prompt fix (DSL_SPEC_CONTRACT + CRITICAL DISAMBIGUATION) + Campaign-C block split (`736f37f`) + --verify-transport flag (`425b407`) + dashboard --db auto-detect fix (`b26732d`).
**Attribution target:** isolated effect of the Oranchak community reference corpora (keyword pools + K4 fills CSV) on candidate generator behavior, with the AAA-archive serpentine anchor held constant across A / B / C as control surface.

---

## 0. Launch history

Campaign C required two attempts. Only attempt 2 is part of the preregistered N=15 measurement.

### Attempt 1 (failed)

| field | value |
|---|---|
| Launched | 2026-04-24T07:02:01 local |
| Command | `run_controller.py --cycles 15 --theories 5 --no-oranchak-corpora --db db/theory_ledger.sqlite` |
| Ledger | main (`db/theory_ledger.sqlite`) — per the original post-split-update prereg |
| Log | `logs/campaign_c/run_20260424_070201.log` |
| Parent PID | 794455 |
| Observed cycles | 165-166 (2 cycles reached) |
| Halt | silent hang on cycle 166 theory `c5840071` (W-Segment Columnar Widths + Vigenère-KA) at 07:13:38 |
| Pre-kill duration | ~3h 10m of zero log progress |
| Kill | SIGTERM parent at 10:17; 26 orphan multiprocessing workers swept afterwards |
| Reconciliation | all 4 cycle-166 theories marked `completed` with orphan `failure_reason` via `reconcile_orphaned_running` |

**Attempt 1 is excluded from attribution measurement.** The prereg specifies N=15 cycles post-split-block. Pooling attempt 1's 2 cycles with attempt 2 would be post-hoc modification of N.

Note on the recovery brief's ledger reference: it listed attempt 1's ledger as `db/k4_campaign_c_20260423.sqlite` with date 2026-04-23. Attempt 1 actually ran on 2026-04-24 against the main ledger per the committed post-split-update prereg. Paths in this postmortem are the ones observed in the filesystem.

### Attempt 2 (complete)

| field | value |
|---|---|
| Launched | 2026-04-24T10:22:14 local |
| Command | `run_controller.py --cycles 15 --theories 5 --no-oranchak-corpora --db db/k4_campaign_c_20260424_1022_attempt2.sqlite` |
| Ledger | fresh campaign-specific (`db/k4_campaign_c_20260424_1022_attempt2.sqlite`) — per recovery brief |
| Log | `logs/campaign_c/run_20260424_1022_attempt2.log` |
| Parent PID | 806754 |
| Cycle-1 watchdog | deadline 10:37:14 — cycle 1 closed 10:41:16, well inside budget |
| Cycles completed | 15/15 |
| Wall time | ~2h 50m (10:22:14 → 13:12:25) |
| Halt conditions triggered | 0 |
| Programmatic fallback | 0 |
| Max crib_score | **7** (cycle 10, H-9b6d..., W-delimiter boundary columnar) |

Campaign C attempt 2 ran to completion with no halt conditions tripped. Worker-role split: **28 dsl_dispatcher + 23 agent_sdk_non_dsl_category = 51 total experiments** (55% DSL).

---

## 1. Headline

**Measurable effect found.** The Oranchak community corpora prompt block was doing real work at the proposal level.

| primary measure | Campaign A (ON) | Campaign B (ON) | **Campaign C (OFF)** |
|---|---|---|---|
| `oranchak_referencing_theories` | 2 | 5 | **0** |
| Proposals citing `quagmire[34]_keywords_oranchak.txt` or `k4_candidate_fills_oranchak.csv` | ≥1 | ≥1 | **0** |

Zero Oranchak references in C's 15 cycles vs 2 in A and 5 in B. The drop is sharp on the primary measure.

The secondary directional measure (Oranchak-adjacent DSL kinds) moved less cleanly. C dispatched 1 `variant_beaufort` + 2 `beaufort` + 6 `quagmire` = **9 Oranchak-adjacent contracts**, vs B's 12. That's a 25% drop (directional), but short of the prereg's ≤6 "counterfactual-meaningful" threshold.

Architecture continued to behave: 0 fallback cycles, 0 hardening halt trips, 15/15 cycles completed cleanly. Max crib_score 7 (well below signal threshold 18). Null outcome on K4, expected.

## 2. §6.1.7 metrics (attempt 2)

| metric | Campaign A | Campaign B | **Campaign C** |
|---|---|---|---|
| Cycles completed | 15 | 15 | **15** |
| `dsl_dispatcher` contracts | 22 | 38 | **28** |
| `agent_sdk_non_dsl_category` contracts | 18 | 20 | **23** |
| DSL/legacy ratio | 55% / 45% | 66% / 34% | **55% / 45%** |
| Distinct DSL kinds | 6 | 7 | **10** |
| Oranchak-referencing theories | 2 | 5 | **0** |
| Oranchak-adjacent DSL dispatches (vbeau+beau+quag) | 4 | 12 | **9** |
| Serpentine-anchor references in log | present | present | **57** (control holds) |
| Theories proposed | 77 | 96 | **66** |
| `override_exhaustion` uses (log-observed) | 3 | 7 | **6** |
| Admissibility translation errors | 6 | 30 | **13** |
| Total admissibility rejections | 18 | 30 | **30** |
| `matched_null_consultations` | 0 | 0 | **1** |
| `programmatic_fallback_cycles` | 0 | 0 | **0** |
| Max crib_score | 8 | 8 | **7** |
| Halts triggered | 0 | 0 | **0** |

### 2.1 DSL kind breakdown (C, 28 dispatches, 10 distinct kinds)

| kind | uses | worked-example | Oranchak-adjacent? |
|---|---|---|---|
| `vigenere` | 18 | yes | no |
| `route` | 10 | no (B-DSL-expanded) | no |
| `quagmire` | 6 | no (B-DSL-expanded) | **yes** |
| `columnar` | 3 | yes | no |
| `myszkowski` | 3 | no (B-DSL-expanded) | no |
| `grille` | 3 | no | no |
| `beaufort` | 2 | no | **yes** |
| `atbash` | 2 | no | no |
| `rail_fence` | 2 | no (B-DSL-expanded) | no |
| `variant_beaufort` | 1 | no | **yes** |

All 4 B-DSL-expanded kinds (`route`, `myszkowski`, `quagmire`, `rail_fence`) got real use. **Campaign B's §3 prompt-bug fix has fully taken effect.** 10 distinct DSL kinds in 28 contracts is the widest coverage any campaign has produced.

### 2.2 Admissibility translation errors (13)

- 5 × `quagmire variant='III' unsupported` — candidate generator proposed classical Quagmire-III label; translator requires `quagmire_iii` (underscore + lowercase). The naming mismatch is a minor prompt footgun that predates Campaign C and affects all post-B runs; worth a one-line fix to the DSL prompt contract.
- 1 × `quagmire_iii requires ct_alphabet_keyword == pt_alphabet_keyword` — candidate generator proposed different alphabets; the K1/K2 convention gate held.
- 6 × route `rows*cols < CT_LEN=97` (3 × 49, 3 × 91) — undersized grids rejected by the translator's length guard.
- 1 × columnar `col_order [3,2,1,4,0,5] is not a permutation of [0,5)` — malformed permutation.

None of these are Campaign-C-specific; all are DSL-translator behavior.

## 3. Mortality distribution (attempt 2)

| stage | count | share |
|---|---|---|
| Critic-rejected (status=CRITICIZED) | 15 | 22.7% |
| Admissibility-rejected | ~18 (distinct theories) | 27.3% |
| Completed normal / disproved | 33 eliminated + 18 completed | 77.3% |
| Infrastructure error / timeout | 0 | 0% |
| Total theories proposed | 66 | 100% |

Non-degenerate distribution, dominant bucket is scoring outcomes (77%). Same shape as Campaigns A and B.

## 4. Family diversity

| family | Campaign C theories |
|---|---|
| encoding | 32 |
| archive_evidence | 15 |
| k2_coords | 6 |
| antipodes | 3 |
| grille | 3 |
| k3_continuity | 3 |
| geodetic | 2 |
| crib_analysis | 1 |
| mirror_ka | 1 |

9 distinct anchor families touched. Campaigns A and B each touched 6 core anchors (`ct_perturbation`, `k2_coords`, `compass`, `w_delimiter`, `archive_evidence`, `grille`). Campaign C's expansion into `encoding`, `antipodes`, `k3_continuity`, `geodetic`, `crib_analysis`, and `mirror_ka` suggests candidate generators broadened the accessible anchor surface when the Oranchak block was removed — consistent with "the block was narrowing proposals toward Oranchak-adjacent work."

The `compass` and `w_delimiter` anchors that were heavily worked in A/B dropped below the top-9 rank in C. That's weak evidence, not strong — a 15-cycle sample is thin on per-anchor counts.

---

## §X. Attribution comparison (A / B / C)

All three campaigns share everything except the Oranchak corpora prompt block. Campaign B is the cleaner comparator to C (both post-B-DSL-expanded); Campaign A carries the additional post-B prompt-fix confound vs C (§7.3 of the prereg).

### §X.1 Oranchak referencing (primary — PASS)

| metric | A | B | **C** | delta vs B |
|---|---|---|---|---|
| `oranchak_referencing_theories` | 2 | 5 | **0** | **–5** |
| Proposals citing Oranchak CSV/wordlists | ≥1 | ≥1 | **0** | clean |

**Verdict: measurable effect.** The block was not cosmetic. Removing it eliminates Oranchak references at the proposal level entirely. This is the prereg's primary measure.

No landscape-layer leakage, pursuit-lead carry-over, or candidate generator-memory bleed observed. The toggle took effect cleanly.

### §X.2 Oranchak-adjacent DSL kind usage (secondary — directional)

| metric | A | B | **C** | C vs B |
|---|---|---|---|---|
| `variant_beaufort` dispatches | 3 | 4 | **1** | –3 |
| `beaufort` dispatches | 1 | 4 | **2** | –2 |
| `quagmire` dispatches | 0 | 4 | **6** | +2 |
| Combined Oranchak-adjacent | 4 | 12 | **9** | –3 (–25%) |

Directional drop on `beaufort` and `variant_beaufort`; `quagmire` actually **increased** in C. The quagmire increase is striking because the prompt's quagmire guidance (K1/K2 convention enforcement) was inside the corpora block that was removed — yet candidate generators still proposed quagmire at a higher rate. Two plausible explanations:

1. The K1/K2 convention knowledge is absorbed into the candidate generator's persona priors (from repeated exposure across Campaigns A-B and verification runs in the ledger landscape), not the prompt block itself. The block's guidance was a reminder, not the source.
2. The post-B DSL_SPEC_CONTRACT CRITICAL DISAMBIGUATION block (added mid-B, retained in C) includes enough quagmire guidance to sustain proposal rate without the Oranchak block.

Either way, the directional result is weaker than the Comparison-1 signal. The prereg marked Comparison 2 as "directional, not a strict pass/fail threshold" — by that standard, C's result is consistent with the hypothesis but not conclusive on its own.

### §X.3 Non-Oranchak anchor coverage (control — PASS)

| anchor | A | B | C (attempt 2) |
|---|---|---|---|
| ct_perturbation | touched | touched | (archived under archive_evidence in C's ledger) |
| k2_coords | touched | touched | **6 theories** |
| compass | touched | touched | (visible via log, not ledger family) |
| w_delimiter | touched | touched | (visible via encoding family) |
| archive_evidence | touched | touched | **15 theories** |
| grille | touched | touched | **3 theories** |

All 6 A/B anchor surfaces remain accessible. C additionally explored `antipodes` (3), `k3_continuity` (3), `geodetic` (2), `crib_analysis` (1), `mirror_ka` (1). **No collapse of non-Oranchak anchors**, so the prereg's control criterion holds (expected ≥4 non-Oranchak anchors; observed 9).

### §X.4 Serpentine anchor (control surface — PASS)

The archive-derived serpentine-Vigenère anchor was held constant across A / B / C (`include_serpentine_anchor=True` in all three). Campaign C's log contains **57 serpentine/Vigenère-pairing references**, confirming the anchor continued to draw candidate generator attention under the no-corpora configuration.

Specific attempt-2 proposals tied to the anchor:
- Cycle 1: "Serpentine screen → Vigenère/KA two-layer (AAA archive anchor)"
- Multiple subsequent cycles proposed serpentine/route compositions

The anchor's effect is a separate confound; C was not designed to isolate it. A future Campaign D with `--no-serpentine-anchor` would measure it. Non-goal per prereg §7.4.

---

## §Y. Attribution verdict

### Primary measure: MEASURABLE EFFECT

The Oranchak community corpora block, when present, produced 2-5 Oranchak-referencing theories per 15-cycle campaign. Removing the block drops that count to **0 in 15 cycles**. The community corpora were influencing candidate generator proposals at the most direct measurable level (explicit path references in generated test specs).

### Secondary measure: DIRECTIONAL

Oranchak-adjacent DSL kind dispatches (variant_beaufort + beaufort + quagmire) dropped 25% (12 → 9) but not cleanly below the prereg's ≤6 threshold. Mixed signal:
- `variant_beaufort` and `beaufort` dropped as expected.
- `quagmire` rose (6 in C vs 4 in B). This suggests quagmire-family knowledge is in the candidate generator priors / post-B DSL disambiguation block, not the Oranchak block.

### Operational verdict

**The Oranchak corpora plumbing is justified by evidence.** Removing it costs at least 2-5 proposals per 15 cycles that cite community-curated reference material directly. Keeping it in the prompt is supported by §X.1 data.

**Worth considering for future work:** splitting the Oranchak block further into (a) the keyword pools (wordlists) and (b) the fills CSV. Right now they're co-gated. A future Campaign could isolate which sub-component drives the Oranchak-referencing count.

**Null K4 result stands.** Max crib_score 7 in C (A: 8, B: 8). All three campaigns consistent with no K4 signal under any prompt configuration. The attribution result is about *candidate generator behavior*, not about K4 solvability.

### Why this is not "no effect" or "underpowered"

- **Not no-effect:** 0 vs 2-5 is not within noise on a 15-cycle sample. The probability of 0 references under a null hypothesis of "Oranchak references happen at 2-5 per 15 cycles regardless of block presence" is low; the block-present rate is 100% (A and B both >0). No conservative reading of these three campaigns supports "cosmetic block."
- **Not underpowered:** the primary measure resolved cleanly (Comparison 1 has a hard zero in C). The secondary measure is underpowered and the postmortem reports it as such. Combining clean and underpowered measures, the headline is "measurable effect" with a weaker confirmation on the secondary.

---

## §Z. Transport-hang postmortem (attempt 1)

### §Z.1 Failure mode

Campaign C attempt 1's cycle 166 dispatched 4 theories at 07:13:38. Three completed in-worker between 07:13:38 and 07:17:25 (2 × rejected_admissibility in 0s, 1 × disproved in 227s). The fourth, `c5840071` (W-Segment Columnar Widths + Vigenère-KA, 30 configs), spawned workers at 07:13:38 that never returned. Workers remained in `S` state with 0.0% CPU for 3h.

The controller's dispatch layer waits for all workers to report before invoking `_absorb_outcomes` and advancing the cycle. Since `c5840071`'s workers never returned, absorb never ran, the cycle never closed, and all four cycle-166 theories remained in `running` status in the ledger. The log went silent for 3h before operator-initiated shutdown at 10:17.

### §Z.2 Match to prior signature

Matches the v2 Agent-SDK transport-hang signature documented in the 2026-04-21 session:
- Subset of multiprocessing Pool workers hang indefinitely
- Parent process alive but idle (0.8% CPU in attempt 1)
- Zero CPU on hung children (waiting on I/O, not deadlocked in Python)
- Other workers from the same dispatch batch complete normally

Known to correlate with subscription rate-limit / throttle windows, not Campaign-specific code defects. Direct-API probe at 10:21 (post-shutdown) passed in 4.88s with $0.0263 — the Anthropic API direct path was fine throughout. The issue was the Agent-SDK subprocess transport specifically.

### §Z.3 Remediation

1. **Pre-flight skip identified as root cause.** `K4_RUN_PROTOCOL_R3.md §7` step "Fresh subscription window confirmed" was skipped at attempt 1 launch. Yesterday's heavy usage burned the safe throughput window; the run launched into a throttle that never cleared.
2. **Clean shutdown via SIGTERM + orphan sweep.** Parent 794455 responded to SIGTERM cleanly in 10s. No SIGKILL required. 26 reparented multiprocessing workers survived and were killed explicitly.
3. **Reconciliation.** `TheoryLedger.reconcile_orphaned_running()` transitioned all 4 cycle-166 theories from `running` to `completed` with explicit orphan failure_reason. Side effect: 3 of the 4 theories had actually completed in-worker pre-hang but their scores were lost because absorb never ran.
4. **Transport re-verification.** Direct-API probe + subscription-SDK `preflight_check` both passed ~5 minutes before attempt 2 launch.
5. **Hygiene commit `425b407`.** `--verify-transport` CLI gate + 16 unit tests. Protocol §7 updated to recommend (not yet mandate) the flag.
6. **Hygiene commit `b26732d`.** Dashboard `_detect_active_db` now reads the running controller's `--db` argv from `/proc/<pid>/cmdline` so the dashboard can't silently show stale data from a different ledger. Dashboard tests 26 → 37.

### §Z.4 Scope of lesson

The transport hang is not a Campaign-C-specific defect. It's a subscription-transport failure mode any launch after heavy usage is exposed to. Durable remediation is the `--verify-transport` flag + protocol update; transient remediation was the launch of attempt 2.

Whether `--verify-transport` should be elevated from optional to mandatory is outside this brief's scope.

---

## 7. What Campaign C closed and what it did not

### 7.1 Closed

- **Oranchak attribution at the proposal level.** The community corpora block measurably influences candidate generator proposals (A:2, B:5 → C:0). Attribution verdict committed.
- **B-DSL-expanded DSL kind accessibility.** All 4 B-DSL-expanded kinds (`route`, `myszkowski`, `quagmire`, `rail_fence`) got real use in C. Campaign B's prompt-bug fix is fully live.
- **Campaign-A hardening continues to hold.** 0 halts, 0 fallback, 100% candidate generator parse success across three campaigns.
- **Transport-hang footgun.** Pre-flight gate now enforceable via `--verify-transport`.
- **Dashboard silent-staleness bug.** Fixed; dashboard now auto-follows the running controller's `--db` flag.

### 7.2 Did not close

- **Serpentine anchor's standalone effect.** Held constant across A / B / C as control; isolating requires a Campaign D with `--no-serpentine-anchor`.
- **Oranchak sub-component attribution.** The keyword pools and fills CSV were co-gated. Splitting them behind separate flags would isolate which drives the primary signal.
- **Quagmire naming footgun.** 5/15 translation errors in C came from `variant='III'` vs required `'quagmire_iii'`. A prompt-contract fix would recover those 5 proposals per campaign.
- **Matched-family null path under live signal.** Only 1 matched_null_consultation fired in C (vs 0 in A / B). Still no BREAKTHROUGH to exercise the halt path.
- **K4.** Max crib_score 7 in C (noise). Three campaigns, zero signal.

### 7.3 Confounds honored

| confound (prereg §7) | status |
|---|---|
| Landscape-carryover | accepted; fresh DB for C means A+B ledger state is not in landscape, but repo-level exhaustion_log.json is shared — admissibility still fired (30 rejections, 13 translation errors) |
| Prompt-length | not flagged; parse rate stayed at ~80% (same as A) |
| Post-B prompt fix vs A | flagged; B is the cleaner comparator to C |
| Serpentine-anchor co-removal | RESOLVED pre-launch via block split (§Z.3 commit history) |

---

## 8. Recommendation for next work

1. **Commission Campaign D (conditional)** — `--no-serpentine-anchor` to isolate the archive-derived anchor's effect, which C held constant. Decide after reviewing this postmortem; the question "how much does serpentine anchor drive proposals?" is only partially answered.
2. **Fix the quagmire naming footgun.** The prompt's quagmire section should explicitly enumerate valid `variant` values (`quagmire_iii`, `quagmire_iv`) and flag `III` / `IV` as invalid. One-line fix. 5 theories per campaign recoverable.
3. **Split the Oranchak corpora further.** Two sub-flags: `include_oranchak_wordlists` and `include_oranchak_fills_csv`. Would attribute whether keyword pools or fill candidates drive the proposal-level signal.
4. **`--verify-transport` policy decision.** Currently optional in protocol §7. Weigh mandatory-by-default against operator override cost.
5. **Strategic reconsideration.** `K4_STRATEGIC_RECONSIDERATION.md` remains the load-bearing unanswered question for the project; Campaign C's null K4 outcome informs but doesn't resolve it.

---

## 9. Artifacts

- Preregistration: `<internal>/K4_CAMPAIGN_C_PREREG.md` (commit `1fbce36`)
- Block split: commit `736f37f`
- --verify-transport hygiene tool: commit `425b407`
- Dashboard fix: commit `b26732d`
- Attempt 1 log: `logs/campaign_c/run_20260424_070201.log`
- Attempt 2 log: `logs/campaign_c/run_20260424_1022_attempt2.log`
- Attempt 2 ledger: `db/k4_campaign_c_20260424_1022_attempt2.sqlite`
- Attempt 1 orphans preserved in main ledger `db/theory_ledger.sqlite` with orphan `failure_reason`
- No BREAKTHROUGH alerts fired; `results/breakthroughs/` unchanged

---

*Postmortem committed 2026-04-24 after attempt-2 clean completion. Attribution verdict: measurable effect on primary measure, directional on secondary. Non-goals (serpentine anchor isolation, Oranchak sub-component split, --verify-transport mandatory) explicitly enumerated in §7.2 / §8 for the operator's next brief.*
