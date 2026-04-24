# Campaign C — Oranchak Counterfactual (preregistration)

**Commissioned:** 2026-04-24
**Reference campaigns:**
  - Campaign A (2026-04-22 AM, `<internal>`) — ran *with* Oranchak block, first observed 2 Oranchak-referencing theories.
  - Campaign B (2026-04-22 PM, `<internal>/K4_CAMPAIGN_B_POSTMORTEM.md`) — also ran *with* Oranchak block (plus serpentine anchor addition); observed 5 Oranchak-referencing theories. B-DSL-expanded landed mid-run; a prompt-wiring bug defeated the serpentine/route/rail_fence/myszkowski translators. Postmortem §10.6 explicitly names "Oranchak attribution" as still-open because Campaign B's contamination defeated a clean A/B.
  - Verification run (2026-04-22 PM, Campaign B postmortem §10) — 3-cycle smoke test of the prompt fix; too short for Oranchak attribution.

**Working-tree basis:** post-Campaign-B prompt fix (DSL_SPEC_CONTRACT supported-kinds enumerated, CRITICAL DISAMBIGUATION block, serpentine/rail_fence/route/quagmire dispatchable) + Campaign-A hardening + new `include_oranchak_corpora` toggle (2026-04-24).
**Status:** PREREGISTERED — do not edit success criteria after launch.

---

## 1. Research question

Did the `_render_oranchak_corpora_for_prompt` block, introduced in the Campaign-A hardening and retained through Campaign B, **actually influence candidate generator behavior**, or was the observed Oranchak-referencing theory rate (2 in A, 5 in B) driven by something else (e.g., landscape state, persona rotation, Campaign-B's additional serpentine anchor)?

Campaign A §7.2 flagged this as an un-evaluated axis. Campaign B postmortem §10.6 flagged the same axis as **still open** after Campaign B's prompt-wiring bug contaminated a clean A/B comparison. Campaign C runs on the **fixed post-B prompt** with the Oranchak block **off** and treats both A and B as baselines.

This is an **A/B/C prompt-content evaluation**, not a K4 solve attempt. All three runs are allowed to produce zero signal; the evaluation is over observable behavioral differences.

## 2. Launch configuration

```bash
PYTHONPATH=src python3 -u <internal> \
    --cycles 15 --theories 5 \
    --no-oranchak-corpora \
    --db db/theory_ledger.sqlite
```

**Flag rationale (updated post-split).** The initial Campaign C draft used `--no-oranchak` (shorthand that suppresses both sub-blocks). The pre-launch diagnostic in §10 surfaced that `--no-oranchak` strips the AAA-archive serpentine-Vigenère anchor along with the community corpora — so C as originally scoped would measure the aggregate effect of two distinct provenance categories, not the keyword-pool effect alone. The block was split by provenance (commit: post-hoc r3 hygiene commit) and Campaign C's launch flag was updated to `--no-oranchak-corpora`, which suppresses *only* the community corpora and leaves the archive anchor as a held-constant control surface across A, B, and C.

Matched against the Campaign-A and Campaign-B launches on every axis except:

- **`include_oranchak_corpora=False`, `include_serpentine_anchor=True`** (Campaign C only) — the sole *intended* prompt delta vs. B.
- **Post-B prompt fix is live** (Campaign C and any future A/B baseline run) — differs from Campaign A by the DSL_SPEC_CONTRACT expansion and CRITICAL DISAMBIGUATION block. This is a real confound against A (§7.3); B is the cleaner comparator.
- Same main ledger (`db/theory_ledger.sqlite`) — so C's landscape input reflects A + B + verification outcomes.
- Same R2-4 matched-null cache.
- Same R3-0.5 DSL kind coverage (13 kinds post-B-DSL-expanded).
- Same Campaign-A hardening halt conditions.
- No code changes to either renderer. Both gates live in `_build_candidate generator_prompt`.

## 3. Preregistered comparisons (primary — must all hold for "counterfactual-meaningful")

The comparison baselines are Campaigns A and B. Campaign B is the stronger baseline because it shares the post-R3-0.5 DSL coverage with C; Campaign A is a secondary comparator across the post-B prompt-fix confound.

### Comparison 1 — Oranchak referencing drops to ~0

| Metric | A (observed) | B (observed) | C (expected if block was real) |
|---|---|---|---|
| `oranchak_referencing_theories` | 2 | 5 | **0** |
| DSL specs with `__ORANCHAK_*__` pattern in keyword sweep | ≥1 | ≥1 | **0** |
| Proposals citing `quagmire3_keywords_oranchak.txt` / `quagmire4_keywords_oranchak.txt` / `k4_candidate_fills_oranchak.csv` | ≥1 | ≥1 | **0** |

**Kill rule for the block's significance:** If C still shows Oranchak-named paths in candidate generator proposals despite the block being absent, either (a) candidate generator memory from prior Campaign A/B/verification is bleeding in via the ledger landscape, (b) pursuit-leads are carrying Oranchak content forward, or (c) the toggle silently failed. The postmortem must distinguish these three.

### Comparison 2 — Quagmire-family and Oranchak-adjacent DSL kind usage drops materially

Campaign A dispatched 3 `variant_beaufort` + 1 `beaufort` + 0 `quagmire` DSL contracts (pre-quagmire). Campaign B dispatched 4 `variant_beaufort` + 4 `beaufort` + 4 `quagmire` = 12 Oranchak-adjacent contracts. Both runs had the block on.

**Expected in C:** The combined (`variant_beaufort` + `beaufort` + `quagmire`) dispatch count should drop vs. Campaign B. A "counterfactual-meaningful" result is a combined count **≤ 6** (half of Campaign B's 12). DSL kind mix should shift back toward `vigenere` + `columnar` + `grille` dominance.

This is **directional**, not a strict pass/fail threshold. N=15 cycles is too small for significance testing on mix fractions. Treat a visible shift as consistent with the hypothesis; treat no shift as evidence the block was cosmetic.

### Comparison 3 — Non-Oranchak anchors remain accessible

Campaign A touched 6 anchor surfaces (`ct_perturbation`, `k2_coords`, `compass`, `w_delimiter`, `archive_evidence`, `grille`); Campaign B added serpentine/physical-paradigm surfaces.

**Expected in C:** ≥4 non-Oranchak anchors touched (control surface should not collapse when only the Oranchak block is removed). A collapse to ≤2 anchors would suggest the prompt block was widening generic exploration, not just Oranchak-specific exploration — an alternative interpretation worth surfacing in the postmortem.

## 4. Preregistered comparisons (secondary — informational only)

These observations are *recorded* but do **not** gate the conclusion:

- **Max single-cycle crib_score.** A = 8, B = 8. C > 8 is noteworthy but statistically unsurprising at N=15.
- **Total theories proposed.** A = 77, B = 96. C within ±20% of B is consistent with "prompt-content change only"; sharper swings suggest prompt-length effects on candidate generator economics.
- **`programmatic_fallback_cycles`.** A = 0, B = 0. C > 0 would be interesting.
- **`total_override_exhaustion_uses`.** A = 3, B = 7. C distribution informs whether Oranchak was encouraging override-exhaustion flags.
- **Serpentine-route-family usage.** Campaign B's serpentine anchor was part of the Oranchak prompt block. C will strip that anchor along with the keyword pools. Expect `route` / `rail_fence` / `myszkowski` dispatch counts to drop. The verification run showed these dispatch cleanly when proposed; C tests whether the candidate generator still proposes them without the serpentine-Vigenère prompt pairing.

## 5. What this campaign does NOT test

- **K4 solvability.** Expected null, same as A and B.
- **Oranchak content *quality*.** Even if Comparisons 1-3 show the block was doing real work, that work could be noise. Isolating quality requires a separate harness with a synthetic K4-like target.
- **The post-B prompt fix against Campaign A.** A ran pre-fix; C runs post-fix. Any A-vs-C behavioral delta is confounded by the prompt fix. B-vs-C is the cleaner comparison.
- **Prompt-length effects.** The Oranchak block is ~1.2KB (post-B-DSL-expanded expansion). C's candidate generator runs against a prompt shorter by ~1.2KB. If C's candidate generator parse rate or tool-use distribution shifts materially, the shift could be attributable to prompt length rather than Oranchak content specifically. This is a known confound; document but don't re-derive conclusions under it.

## 6. Halt conditions (auto-enforced by the hardening)

Same as A and B:

1. Fallback streak ≥3 consecutive cycles.
2. D-zero streak ≥3 consecutive dispatched cycles.
3. BREAKTHROUGH alert with `p_value_status ∈ {matched_null_miss, cache_miss}`.
4. Panic from `_verify_against_kernel`.

Note: Campaign B's verification addendum (§10.4) documented that fresh-ledger runs trip D-zero almost by default. C uses the main ledger, so D-zero is not expected to fire prematurely.

## 7. Confounding accounting

### 7.1 Landscape-carryover confound (accepted, larger than for Campaign B)

Campaign C runs on the same ledger as A and B, so C's landscape input includes **A's 77 + B's ~96 + verification's ~11 ≈ 184 prior proposals**. The landscape's anomaly-exploration counts, pursuit leads, and recent-outcomes window are all meaningfully different from A-launch or B-launch state. The postmortem must report the landscape delta explicitly (snapshot landscape at B-launch vs. C-launch) so the "same starting state" assumption of the A/B/C comparison is not silently violated.

### 7.2 Prompt-length confound (accepted, mitigation conditional)

Removing ~1.2KB of content from the candidate generator prompt *may* affect parsing rates or tool-use economics. If Campaign C shows a material drop in `candidate generator_parse_successes` (say, below A's 80% / B's ~equivalent) or a jump in tool-use counts, the postmortem must flag this and optionally motivate a Campaign D with a same-length-non-Oranchak filler block.

### 7.3 Post-B prompt fix confound (accepted)

The DSL_SPEC_CONTRACT supported-kinds list and CRITICAL DISAMBIGUATION block that landed between B and C are a real prompt delta. This blocks a clean A-vs-C comparison; only B-vs-C is clean on this axis. The postmortem should report A-vs-C deltas separately and caveat them.

### 7.4 Serpentine-anchor co-removal (RESOLVED pre-launch via block split)

**Original concern.** The serpentine-Vigenère anchor (AAA archive page 17) was embedded *inside* the Oranchak prompt block. The initial Campaign C plan using `--no-oranchak` would have removed the anchor along with the keyword pools, bundling two distinct provenance categories (community-derived + archive-derived) behind a single flag.

**Resolution.** Pre-launch, the Oranchak prompt block was split by provenance into two independently-gated sub-blocks (community corpora; archive anchor). Campaign C now uses `--no-oranchak-corpora`, which suppresses *only* the community corpora and preserves the archive anchor as a control surface across all three campaigns.

**Why this matters for attribution.** With the anchor held constant in A, B, and C, any serpentine-family / route-family proposals observed in C can be attributed to the anchor (or to landscape / pursuit-lead carry-over) rather than to the removed content. The anchor's own effect is NOT measured by Campaign C — that's an explicit non-goal. A future Campaign D with `--no-serpentine-anchor` would isolate it if operator commissions that.

## 8. Mandatory postmortem (R3 §6.1.7 + Campaign-A additions + Campaign-C additions)

All fields from Campaign A's §6.1.7 postmortem checklist plus:

- **Campaign-C addition:** `oranchak_block_present_in_prompt` — boolean, sampled from the first `_build_candidate generator_prompt` invocation, confirms the toggle took effect.
- **Campaign-C addition:** Side-by-side A/B/C comparison table for Comparisons 1-3.
- **Campaign-C addition:** Landscape snapshot delta (C-launch vs. B-launch) — new pursuit leads, new exhaustion counts, anomaly-exploration delta.
- **Campaign-C addition:** Named confound status from §7 — which fired, how handled.
- **Campaign-C addition:** If Comparison 1 kill rule triggers (Oranchak-referencing > 0 in C), the breakdown of root cause (ledger carry-over, pursuit lead, toggle failure).

## 9. Operator sign-off

Before launch:

- [x] Campaign-A + Campaign-B hardening in working tree (no regressions)
- [x] Post-B prompt fix in working tree (DSL supported-kinds + CRITICAL DISAMBIGUATION block)
- [x] Block-split surgery: Oranchak corpora + serpentine anchor gated independently (2026-04-24)
- [x] `include_oranchak_corpora` + `include_serpentine_anchor` toggles on `ControllerConfig`, both default True
- [x] `--no-oranchak-corpora` + `--no-serpentine-anchor` + `--no-oranchak` (shorthand for both) wired through `run_controller.py`
- [x] 4-combination unit tests pin prompt content for each (corpora, anchor) flag state
- [x] CLI-level tests verify `--no-oranchak` shorthand maps to both sub-flags and preserves pre-split single-flag reproducibility
- [x] All 859 internaltests + 1557 core tests pass
- [x] Self-test unchanged: K1/15, K2/17, K3/9345
- [x] This preregistration document committed with the updated launch command before the launch runs
- [ ] Launch command recorded in run log with timestamp
- [ ] Postmortem mandatory §6.1.7 + Campaign-A additions + Campaign-C additions committed after run

## 10. Pre-launch diagnostic and block-split rationale (2026-04-24)

The first version of this prereg specified `--no-oranchak` as the launch flag. A pre-launch review surfaced that the Oranchak prompt block aggregated three distinct content sections under one flag:

1. Community keyword corpora + usage guidance + epistemic caveat (sections 1, 2, 4) — Oranchak-Reddit-derived.
2. Archive-derived AAA-page-17 serpentine-Vigenère anchor (section 3) — Sanborn archive primary source.

Two provenance categories, conflated. Running C as originally scoped would have measured their aggregate effect against no-block, which is *not* what the research question asks. The preregistration committed to isolating the keyword-pool effect.

**Resolution landed pre-launch:**
- `_render_oranchak_corpora_for_prompt` keeps sections 1/2/4 (community-only).
- New `_render_serpentine_anchor_for_prompt` owns section 3 (archive-only).
- `_build_candidate generator_prompt` gates each independently via `include_oranchak_corpora` and `include_serpentine_anchor`.
- `--no-oranchak` remains as a shorthand that sets both False (Campaign-A launch-command reproducibility).
- `--no-oranchak-corpora` and `--no-serpentine-anchor` added for targeted isolation.
- 4-combination unit tests pin the prompt content at each flag state.

**What this means for Campaign C.** The research question ("do the Oranchak keyword pools change candidate generator behavior?") is measured cleanly with the anchor held constant across A, B, and C. Serpentine-family proposals in C are interpretable against the control (anchor-present) rather than confounded by anchor absence.

**What this does NOT measure.** The anchor's effect on proposals is NOT isolated by Campaign C. A future operator-commissioned Campaign D with `--no-serpentine-anchor` (anchor off, corpora on) could isolate it against C and B. Outside Campaign C's scope.

---

*This preregistration locks the three primary comparisons. Any post-hoc weakening of comparison thresholds invalidates the counterfactual reading.*
