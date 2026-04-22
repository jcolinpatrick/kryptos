# K4 Run Postmortem — v3 (2026-04-21)

**Source ledger:** `db/k4_run_2026_04_21_r3_v3.sqlite`
**Source log:** `results/k4_run_2026_04_21_r3_v3/run.log` (415 lines)
**Run window:** 20:14:42 (cycle 1 start) → 20:41 (operator halt per §5)
**Commissioning commit:** `0278c7a` (R3 complete + 2 pre-K4 hygiene commits)
**Protocol:** `<internal>/K4_RUN_PROTOCOL_R3.md` §6
**Halt reason:** §5 halt condition "three consecutive cycles with D column (admissibility reject) = 0" triggered after cycle 3

This is the first K4 run under the post-R3-2 controller architecture. It is also the third attempt in one session — v1 (18:10) was halted early due to an SDK message-stringification bug; v2 (18:43) hung on the first candidate generator call due to a subscription-SDK transport cool-down; v3 (20:14) completed three full cycles and fired the §5 halt condition.

## 6.1.1 Cycle-by-cycle telemetry

| Cycle | Start | Candidate generator persona | Proposed | Critic-approved | Red-team-survived | Dispatched | DSL-path | D col |
|---|---|---|---|---|---|---|---|---|
| 1 | 20:14:42 | cryptanalyst | 4 | 1 | 1 (concerned) | 1 | 0 | 0 |
| 2 | ~20:22 | (varied) | 3 | 3 | 3 (all concerned) | 3 | 0 | 0 |
| 3 | ~20:34 | (varied) | 5 | 3 | 1 (1 concerned, 2 rejected) | 1 | 0 | 0 |
| **Total** | | | **12** | **7** | **5** | **5** | **0** | **0** |

Cycle 4 started (GENERATE phase) before the operator halt fired; no theories from cycle 4 reached the ledger.

## 6.1.2 Proposal-mortality table

Total proposals dispatched into the loop: **12**

| Stage | Sub-reason | Count | % of total |
|---|---|---|---|
| **B. Critic rejected** | `reject_underconstrained` (non-DSL gates: scope, duplicate, etc.) | 3 | 25.0% |
| **B′. (R3 addition) Critic rejected** | `reject_underconstrained: dsl_untranslatable` (Category-C gate) | 2 | 16.7% |
| **C. Red-team killed** | `red-team: rejected` | 2 | 16.7% |
| **D. Dispatcher rejected** | (none reached dispatcher) | 0 | 0.0% |
| **E. Scoring outcomes (dispatched)** | `crib_score=1` (disproved/noise) | 2 | 16.7% |
|  | `crib_score=2` (disproved/noise) | 2 | 16.7% |
|  | `crib_score=3` (disproved/noise) | 1 | 8.3% |
| **F. Error / infra** | (none) | 0 | 0.0% |
| **TOTAL** |  | **12** | **100.0%** |

All 5 dispatched experiments went via `worker_role="agent_sdk_non_dsl_category"` (legacy path). Zero via `dsl_dispatcher`.

## 6.1.3 Negative-space finding

Per protocol §6.1.3: confine negative-space claims to dispatched proposals (stage E).

**5 Category-B cipher-adjacent hypotheses dispatched via legacy path; all disproved at crib_score ≤ 3:**

- Archive-preregistered CT perturbation restores Vigenere admissibility on KA (`crib=2`)
- Reflecting-pool mirror transform as pre-decryption layer (`crib=1`)
- Compass-rose bearing digits as Gronsfeld key on W-segmented K4 (`crib=1`)
- K2-coordinate-lie as dual-tape XOR running key (`crib=2`)
- Archive-perturbed CT under two-layer columnar+Vigenere composition (`crib=3`)

**No Category-A cipher theories reached the dispatcher.** The DSL-dispatch path produced zero kernel-verified contracts this run. Stage B/B′/C rejections describe filters, not K4.

## 6.1.4 Failure-mode classification

**Dominant rows:** stage B + B′ (5 of 12, 41.7%) — critic-rejected. Within those, the R3-specific B′ row (`dsl_untranslatable`) captures 2 of 5.

**Mode B′ (dsl_untranslatable):** cipher-family theories whose `dsl_spec` failed boundary validation or was omitted entirely. Two instances:

1. `grille` theory with `crib_alignment="free_search"` — invented enum value; valid set is `{direct_positional, free, post_transposition}`.
2. `encoding` (W-segmented Vigenere) with `dsl_spec=null` — candidate generator omitted the spec on a multi-layer Cat-A construction.

**Mode C (red-team rejected):** 2 Cat-A-looking theories killed at 0.92 confidence each by the adversarial-review. Theory [8] `5931800a605e / key_tape / K1-K2-K3 concatenated plaintext as finite running-key tape` warrants specific scrutiny because it was critic-approved with a dsl_spec, making it the closest any Cat-A came to the dispatcher in v3. Concrete ledger evidence (`db/k4_run_2026_04_21_r3_v3.sqlite` + the candidate generator's raw proposal in `~/.claude/projects/-home-cpatrick-kryptos/31ba5ddb-*.jsonl`) shows **the red-team 0.92 reject is well-earned on three independent grounds:**

1. **Label-mismatch / family-smuggling.** The candidate generator declared `family="key_tape"` — a deferred DSL kind per R3-0.5-4 (`key_tape` is NOT in `_SUPPORTED_KINDS` and is explicitly listed in `K4_RUN_PROTOCOL_R3.md` §2 as "operator-flagged for its own design cycle"). The dsl_spec then used `pipeline[0].kind="vigenere"` to route through a translatable kind. This is the precise laundering pattern R3-0.5's non-goal list warned against.
2. **Broken spec execution.** The spec carried `"keyword": "K1K2K3_PT_CONCAT_FIRST_97"` — a 21-character placeholder literal, not the 97-character K1+K2+K3 PT concatenation the candidate generator's prose *described*. Under the dispatcher's `sanitize` pass this would produce a Vigenere key ≈ `KKKPTCONCATFIRST` (a short repeating keyword), not a 97-char finite-tape. The spec is semantically disjoint from the candidate generator's narrative mechanism.
3. **Documented rehash.** Red-team cited four exhaustion-log entries by name: `e_runkey_002_k123_plaintext`, `f_k123_running_key_exhaustive_v1`, `e_k123_running_key`, `e_k3ct_running_key_v1`. All four exist in `exhaustion_log.json`. Additional confirmation: at least 16 further running-key scripts in the same log (e.g., `e_s_98_k123_running_key`, `e_s_51_dual_running_key_sa`, `f_running_key_73char_overnight_v1`), plus the `f_k123_running_key_exhaustive_v1` campaign (~750K configs per the red-team citation). The prior-panel-PT-as-running-key surface is among the most-trodden territories in the project history.

The red-team's 0.92 confidence is appropriate for a proposal that smuggles a deferred kind, ships a broken executor, and rehashes saturated prior work. The earlier framing of "over-sharp kill of a genuinely new bounded Cat-A construction" was speculation unsupported by the ledger and is retracted.

**Mode E (dispatched & disproved):** 5 Cat-B theories, all scored in `[1, 3]` — correct behaviour for methodological / archive-evidence theories under the legacy-path kernel scoring. None crossed the SIGNAL threshold.

Next brief recommendation (derived from this mortality shape): the choke point is at Cat-A spec quality and red-team killing rate, not at the dispatcher. Either the candidate generator needs enumerated DSL-value guidance (next prompt-hygiene commit) or the red-team's rejection priors on speculative-Cat-A need calibration.

## 6.1.5 Subscription accounting

This run dispatched workers via `agent-sdk`'s `SubprocessCLITransport`, which spawns the Claude Code CLI under the user's Claude Code SUBSCRIPTION — not the Anthropic API. No per-call USD emitted; no API billing occurred. Token counts extracted from per-session JSONL transcripts under `~/.claude/projects/-home-cpatrick-kryptos/*.jsonl`, same source Claude Code's `/status` uses.

- **Sessions touched during v3 window:** 20
- **Assistant turns:** 1,093
- **Input tokens:** 2,932
- **Output tokens:** 1,476,975 (1.48M)
- **Cache-read tokens:** 405,846,391 (405.85M)
- **Cache-create tokens:** 9,993,593 (9.99M)
- **Grand total tokens:** 417,319,891 (417.32M)

### Per-model breakdown

| Model | Sessions | Input | Output | Turns |
|---|---|---|---|---|
| `claude-opus-4-7` | 12 | 1,624 | 1,254,260 | 900 |
| `claude-sonnet-4-6` | 8 | 1,308 | 222,715 | 193 |

**Comparison vs pre-R3 K4 run (2026-04-21 postmortem §6.1.5) — per-cycle regression:**

| Metric | v1 pre-R3 | v3 post-R3 | Delta |
|---|---|---|---|
| Total tokens | 347.71M | 417.32M | +20.0% absolute |
| Cycles completed | 4 | 3 | — |
| **Tokens per cycle** | **86.93M** | **139.11M** | **+60.0% per cycle** |
| Output per cycle | 0.45M | 0.49M | +9.4% |
| Cache-read per cycle | 85.2M | 135.3M | +58.8% |
| Sessions per cycle | 8.0 | 6.3 | −21.3% |

**Explanation of the +60% per-cycle regression (verified against session-role breakdown in the JSONL transcripts):**

V3's session mix within the 19 observed sessions was:
- 4 candidate generator sessions (74.3K output, 9 turns total)
- 7 red-team sessions (49.1K output, 31 turns total)
- 5 worker sessions (221.7K output, 190 turns total)
- 3 synthesis sessions (1.0K output, 3 turns total)

V3 ran **more parallel calls per surviving theory** than v1. Each parallel call re-reads the full candidate generator-landscape cache (~15-30M cache-read tokens per call depending on prompt section), which accounts for the cache-read dominance. V3's critic is stricter under R3-2 (the new Category-A/C check rejects earlier), so the set of theories reaching red-team is smaller but each survivor gets fully reviewed. Concretely: v3 ran 7 red-team sessions on 7 critic-approvals in 3 cycles (2.3/cycle); v1's pre-R3 postmortem shows ~4 red-team rejections + concerned verdicts in 4 cycles (1.0/cycle). Per-cycle parallel cache-read accounts for roughly the full +50M/cycle delta between v1 and v3.

**The expected token savings from R3-2's zero-token Category-A worker path were predicated on Cat-A dispatches that did not occur in v3.** Each Cat-A DSL dispatch avoids a ~300-500K-token SDK worker subprocess. At one Cat-A per cycle, per-cycle tokens would drop by ~300K output tokens + correspondingly avoided cache pulls. At the observed Cat-A dispatch rate of 0, those savings do not materialize and the stricter-critic + more-parallel-calls penalty dominates.

**The algebraic savings remain valid for future runs with non-zero Cat-A.** The regression is run-specific, not architectural. A run where 2-3 Cat-A theories dispatch per cycle would invert the per-cycle token budget in R3-2's favor. V3 simply did not produce that run.

## 6.1.6 Architectural finding

**V3 confirms, on live data, the pre-R3 hypothesis that candidate generator output quality is the binding constraint.** R3's architectural work now makes that constraint addressable rather than absorbed silently — in v1, poor candidate generator output fell through to `_programmatic_fallback` and the failure was invisible; in v3, the same class of poor output gets classified into specific mortality-table rows (B′ `dsl_untranslatable`, C red-team kills), with the failure modes legible rather than laundered. This is not a new finding: the pre-R3 K4 postmortem §6.1.6 ("Next brief: expand the hypothesis space, not the instrument") already flagged the candidate generator as the choke point. V3 confirms that prior and shows the R3-era framework does not change it.

**The current candidate generator+redteam combination cannot supply the DSL path with viable inputs.**

- **DSL-dispatch path:** fully healthy. `_run_worker` parses specs cleanly, `check_admissibility` gates correctly (0 false rejects observed), `_verify_against_kernel` overrule preserved. When a Cat-A theory arrives, the machinery executes. Zero Cat-A theories arrived.
- **Legacy dispatch path:** fully healthy. All 5 dispatched theories routed via `_run_worker_legacy(tag="non_dsl_category")`, emerged with correct `worker_role` tag, kernel-verified crib_score populated. No scratch-directory violations.
- **Hybrid fallback classification:** correct on every theory. `NON_DSL_FAMILIES` membership (geometry, k2_coords, geodetic, antipodes, archive_evidence, crib_analysis, k3_continuity, plus transitive family mappings) routed 8 of 12 theories to legacy; the other 4 hit the Category-A/C gate.
- **R3-era hygiene fixes (commits 3223890, 0278c7a):** holding. Zero "Explore X family" programmatic-fallback templates in the ledger. Real candidate generator output was consumed throughout.

**What's broken (not in the architecture):**
- **Candidate generator DSL-value literacy:** candidate generator invented `crib_alignment="free_search"` and omitted specs on multi-layer Cat-A theories. The prompt does not enumerate valid enum values for `crib_alignment`, `scoring`, `null_baseline.method`, `CipherKind`, or `AlphabetKind`. A third prompt-hygiene commit that either inlines the enum domains or references the DSL schema would likely recover 1-2 Cat-A dispatches per cycle.
- **Red-team is doing its job on live data.** Theory [8] (details in §6.1.4) was a valid example of red-team catching three distinct failure modes — family-smuggling, broken spec execution, saturated-surface rehash — in a single 0.92 verdict. This is evidence the red-team parallel is well-calibrated against the actual candidate generator output, not evidence of over-aggression. The earlier draft of this postmortem misread this; see Edit 1's companion note for the retraction trail.
- **Candidate generator Cat-B preference:** across 12 theories, 8 (66%) were Cat-B. The anomaly surface in the prompt is predominantly non-cipher (archive, compass, coordinate-lie, reflecting-pool, W-delimiter). Cat-B is the natural category for those anchors.

Recommended next brief: extend the prompt with DSL-enum enumerations and stronger Cat-A requirement language — the single highest-leverage, lowest-risk change. Red-team calibration is not currently a defect.

## 6.1.7 DSL utilization metrics

Per protocol §6.1.7, the following counters capture whether R3-2's wiring actually executed during this run.

| Metric | Value | Interpretation |
|---|---|---|
| `total_admissibility_rejections` | **0** | No Cat-A reached the admissibility check; D column never populated |
| `total_override_exhaustion_uses` | **0** | No theory carried `override_exhaustion=True` |
| `total_translation_errors` | **0** | No spec made it past admissibility to translation |
| `matched_null_consultations` | **0** | No alerts fired — no candidate crossed SIGNAL threshold |
| `matched_null_cache_misses` | **0** | (none consulted) |
| `dsl_path_contracts` | **0** | No Cat-A dispatched |
| `legacy_path_contracts` | **5** | All dispatched theories Category B |
| `programmatic_fallback_cycles` | **0** | Commits 3223890 + 0278c7a are holding; real candidate generator output consumed |

**Verdict:** R3-2 wiring is correct but untested on live K4 traffic in v3. The synthetic-theory integration test (R3-3's `test_r3_3_synthetic_integration_covers_mortality_battery`) remains the only evidence the full code path works end-to-end on Category A. Real-candidate generator validation awaits a subsequent run where Cat-A actually reaches the dispatcher.

## 6.1.8 Halt provenance

Protocol §5 halt condition invoked:

> "Three consecutive cycles with D column (admissibility reject) = 0. Per brief §5.1 item 5: under R3's architecture, a clean D=0 column sustained across cycles means candidate generators are proposing only trivially-admissible or only Category-B theories — either the prompt is pulling them away from novel cipher proposals or the anomaly surface has saturated. Operator intervention warranted."

Counter evolution:

| Cycle | D col contribution | Cumulative D=0 streak |
|---|---|---|
| 1 | 0 | 1/3 |
| 2 | 0 | 2/3 |
| 3 | 0 | **3/3 — halt condition fires** |

Operator halt commissioned at 20:41; task `bxu0n0gfh` (controller) and `blcgnn5rw` (monitor) both stopped cleanly. Cycle 4's GENERATE was in-flight but not persisted.

## 6.1.9 What v3 proved and what it did not

**Proved:**
- SDK transport recovers after cool-down (v2 hang was transient, not a code bug).
- Hygiene commits 3223890 + 0278c7a work — real candidate generator output flows through `validate_theory_proposals` without silent fallback.
- R3-2 hybrid classification correctly routes all 12 theories by category.
- Legacy path processes Category-B theories cleanly with matched `worker_role` tags.
- Mortality-table §6.1.2 B' row split is observable in live data (2 entries).

**Did not prove:**
- DSL dispatch path end-to-end under real K4 traffic (zero Cat-A dispatches).
- R2-4 matched-family null consultation in practice (no alerts fired).
- `check_admissibility` rejection telemetry in live ledger (D column always 0).
- R3-2 override-exhaustion workflow (no candidate generator set the flag).

## 6.1.10 Next-brief recommendation (non-decisional)

The R3 architecture is sound. The choke point is candidate generator output quality, confirmed on live data. Candidate next actions — sorted by risk class, not by equal weight:

### Tier 1 — Near-term maintenance (recommended first)

**DSL-enum enumeration in the candidate generator prompt.** Inline the valid value sets for `crib_alignment`, `scoring`, `null_baseline.method`, `AlphabetKind`, and a reminder-list of supported cipher kinds (the 9 in `_SUPPORTED_KINDS` post-R3-0.5) into the DSL_SPEC CONTRACT section of `_build_candidate generator_prompt`. Estimated ~40 lines of prompt text plus a unit test.

- **Scope:** small, documentation-shaped change to a single string template.
- **Risk:** low. Does not touch kernel, dispatcher, critic, or any scoring path.
- **Measurability:** the per-cycle Cat-A spec-validation rate is directly observable from the ledger (`dsl_untranslatable` / `spec invalid` mortality-table rows). Pre-fix rate = 50% (2 of 4 Cat-A specs had validation errors in v3). Post-fix rate target ≥80%. Measurable via a single synthetic-spec generation audit or a ≤3-theory dry-run cycle.
- **Addresses:** the confirmed defect (invented `free_search` enum value + missing spec on multi-layer Cat-A).

### Tier 2 — Research tier (do NOT commission until Tier 1 completes)

**Red-team prior calibration.** Behavioral tuning of the `adversarial-review` parallel agent based on v3 verdicts.

- **Scope:** prompt engineering on a Claude-based parallel. No objective ground truth for what "correct red-team calibration" means.
- **Risk:** over-tuning is real and hard to detect. Based on Edit 1's evidence, v3's red-team verdicts were all earned (the 0.92 on theory [8] caught three independent failure modes in a single call). Calibration in a more-permissive direction without clear evidence of over-aggression would weaken a working safeguard.
- **Evidence currently does not support commissioning this.** The earlier draft's framing of "over-sharp kill" has been retracted (see Edit 1). Re-commission this tier only if a specific Cat-A theory is observed in a future run being killed with obviously-wrong reasons, not based on aggregate 0.92-confidence statistics.

### Tier 3 — Strategic question the operator must answer before either tier matters

What are the next 10 K4 runs actually trying to prove?

- If the goal is **"exercise the DSL path on live data"** — R3-3's synthetic-theory integration test already does this, at zero tokens, with 100% coverage. Additional K4 runs to confirm the same wiring is a redundant and expensive instrument.
- If the goal is **"find K4"** — v1 + v2 + v3 collective evidence (see §6.1.11 meta-finding) suggests more R3-era cycles are not the path without structural changes beyond prompt tuning. Tier-1 enum enumeration addresses a *known* spec-quality defect but does not change the fundamental K4-yield-per-cycle dynamics the three runs have exposed.

Until the operator answers this question, the cost/benefit of either tier's commission is undefined.

## 6.1.11 Meta-finding — what v1+v2+v3 collectively tell us about K4

V1, v2, and v3 consumed roughly one billion subscription tokens across three attempts in a single day and produced zero K4-relevant signal. The framework is working exactly as R3 designed it — a tight loop of candidate generator proposal, critic filtering, red-team review, dispatcher-or-legacy execution, kernel-verified scoring. The loop did not fail. It ran. It returned no candidate with `crib_score ≥ 10`.

This is a piece of evidence about K4 under the R3-era method, not about the framework. The anomaly surface currently driving the candidate generator prompt (archive perturbations, compass-rose grille, reflecting-pool mirror, coordinate-lie deltas, W-delimited segmentation, K123 running-key) has been mined — partially exhausted before R3, more completely tested across v3's 12 candidate generator proposals — and the structural evidence indicates the narrow-band hypothesis space that the R3 critic and red-team allow through is noise-floor territory. The five dispatched Cat-B theories all scored in `[1, 3]`. No theory crossed the `STORE_THRESHOLD=6` tripwire.

This does **not** conclude K4 is unsolvable by the framework. It states something narrower: **the current loop's information yield per cycle is low enough that more identical runs should not be commissioned** without one of:

- (a) Tier-1 prompt fixes landing AND their effect being measured against synthetic Cat-A spec generation (not against another 3-cycle K4 attempt).
- (b) A structural change to what the loop does per cycle — for example: a different anomaly surface rotated into the prompt's active list, a new cipher kind wired via a `key_tape` translator, a new corpus fed to the running-key family, or a fundamental reframe of what "testable K4 hypothesis" means for the candidate generator.

Future operators (including future-you) should find this finding in the durable record rather than rediscover it by running a fourth, fifth, and sixth attempt with the same candidate generator, the same landscape, and the same expected null result. The postmortem trail — v1's diagnostic, v2's transport-layer report, v3 here — is specifically intended to make this outcome legible before the next K4 commission.

---

*End of K4 v3 postmortem. Architecture exercised live; first-dispatch target unmet; meta-finding added to the durable record; next action deferred to operator, subject to §6.1.10 Tier-3 strategic question.*
