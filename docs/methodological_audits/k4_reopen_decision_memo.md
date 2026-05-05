# K4 Reopen Decision Memo

**Date:** 2026-05-04
**Author:** Claude Opus 4.7 acting as principal research engineer / epistemic auditor
**Git commit:** `eac95e70cd90716f0295412b13b62709b28e0571` (post-Phase 5/6 audits)
**Phase coverage:** Phases 0–6 of the K4 Evidence Calibration and Reopening Plan complete; Phase 2.1 (methodological-family conditional null) deferred.

---

## Executive Decision

**Continue no-new-search moratorium**, with one concrete authorized item: complete Phase 2.1 (methodological-family conditional null) before any new K4 search is reopened.

This is a tighter posture than "reopen narrow campaign" because the central methodological gap — the conditional null for the high-mean ledger families (k3_continuity, k2_coords, archive_evidence, key_tape, geometry, antipodes, geodetic) — is not yet calibrated. Without that calibration, family-level score elevations cannot be interpreted, and any new search would inherit the same unresolved confound that motivated this entire calibration phase.

---

## Evidence Basis

### Conditional admitted-theory null result

**Phase 2 status:** design contract committed; DSL-cipher subset implemented and quick-mode validated.

Phase 2 calibration (DSL-cipher families: vigenere, beaufort, var_beaufort × AZ/KA, 200 samples per stratum):

| Stratum | Mean | Stdev | Max |
|---|---:|---:|---:|
| vigenere AZ | 0.895 | 0.916 | 4 |
| vigenere KA | 1.250 | 1.111 | 4 |
| beaufort AZ | 0.765 | 0.913 | 4 |
| beaufort KA | 0.930 | 0.877 | 4 |
| var_beaufort AZ | 0.725 | 0.907 | 4 |
| var_beaufort KA | 1.075 | 0.987 | 5 |

**Headline answer (from `results/null_baselines/admitted_theory/ledger_comparison.json`):**

> "inconclusive due to insufficient sampling — Phase 2 DSL-cipher null does not reach the methodological families (k3_continuity, k2_coords, archive_evidence, key_tape, geometry, encoding) showing the highest ledger means; Phase 2.1 methodological null required."

The DSL-cipher null's mean across strata is ~0.94, very close to the random_text null mean of 0.92. **The DSL-cipher subset of admitted-theory space is statistically indistinguishable from random under crib-score**. This is itself an informative finding: the curated thematic keyword pool does not encode K4 cribs in any systematic way that elevates scores above random.

The per-family elevations in the ledger (geodetic +1.54, k3_continuity +1.21, etc.) come from methodological-family theories whose null is not in this Phase 2 calibration. **Cannot answer the family-level signal question without Phase 2.1.**

Note: KA-family means run ~0.3 score points above AZ-family means consistently. This is a real KA-vs-AZ effect of the curated keyword pool but is small (within 1 stdev) and not by itself evidence of cryptographic content.

### Period-stratified score-17 result

**Phase 3 status:** complete. Original elimination preserved.

Theory `3041e54d` (W-as-Scheidt-rest-marker, score 17/24) is eliminated by **three independent kill conditions**:

1. **KC1**: `crib_score >= 20` threshold not crossed (max 17).
2. **KC2**: 6 Bean inequality violations at periods {19, 38}; 7 violations at {23, 46}; 117 at p=2. Any periodic key at these periods is mathematically impossible.
3. **Core mechanism**: ENE and BCL crib regions share key indices for all p ≤ 73, requiring contradictory keystream values.

The score-17 case is structurally eliminated, not statistically eliminated. The period-aware-null question is moot because Bean structural impossibility binds first. **No reopening warranted.**

### Lead-band audit result

**Phase 4 status:** complete. No reopening.

All 36 ledger entries with `best_score BETWEEN 6 AND 9` classified:

- 13 mechanical eliminations (Bean violations, primality, parity, geometric incompatibility)
- 18 bounded-exhaustive-zero eliminations
- 4 statistical-noise-under-matched-null eliminations
- 1 kernel-verified degeneracy (worker self-reported 13/24, kernel verifier confirmed 6/24)
- 1 prose-only judgment (AAA page-17 serpentine interpretation), but bounded-exhaustive results hold under either interpretation
- **0 heuristic budget cuts** | **0 requires-rerun**

**Recommended reopened leads: 0.** The lead-pursuit gate's track record across this audit window (36 entries → 0 promoted) is consistent with both "no genuine signal in this score range" and "promotion threshold correctly calibrated." Discriminating these requires Phase 2.1.

### DSL coverage result

**Phase 5 status:** complete.

| Metric | Value |
|---|---:|
| DSL-valid kinds (`_VALID_CIPHER_KINDS`) | 19 |
| Dispatcher-supported kinds (`_SUPPORTED_KINDS`) | 19 |
| Valid without translation | 0 |
| Supported but not DSL-valid | 0 |

Every DSL-valid kind has a kernel transform and at least 3 test files. Unsupported-kind rejection demonstrated working in cycle 201 (real `dsl_untranslatable` rejection of "Compass-Rose Per-Position Variant Tape" — a kind not in the valid set). Kernel-overrule contract verified (lifetime kernel-overrule count = 6, all caught at the dispatcher → kernel boundary).

**No DSL-side blockers.**

### Known-answer self-test result

**Phase 6 status:** complete (dry-run; no real-API spend).

```
PYTHONPATH=src python3 kryptosbot/self_test.py --panel all --mode dry-run
=== Summary ===
  solved: 2/3  total_wall=0.05s
```

K1 and K2 rediscover cleanly. K3 not solved in 500-cycle dry-run budget — this is the documented expected behavior, not a regression. Per CLAUDE.md, K1/K2 rediscovery is the standing fitness check; K3 requires longer cycles + Pollux preprocessing.

**Real-API K1 self-test NOT run** (would require explicit operator authorization for paid spend; not authorized this session).

---

## What Is Still Not Known

### Remaining uncalibrated nulls

1. **Methodological-family conditional null** (Phase 2.1) — the biggest gap. Highest-priority follow-up. Required to interpret the per-family score elevations (geodetic +1.54, k3_continuity +1.21, k2_coords +1.11, archive_evidence +0.90).
2. **CT-perturbation conditional null.** Theories that perturb the canonical CT before scoring need their own conditional null. Stage A's clean-negative result does not generalize to Stage B and beyond without re-calibration per perturbation depth.
3. **Multi-layer composition conditional null.** Tier-1/Tier-2 eliminations are single-layer; multi-layer remains an open scope.
4. **Period-stratified random-keystream null.** CLAUDE.md cites doctrine ("at period 24, random configs score ~19.2/24") but no formally calibrated period-stratified null is filed. The score-17 case did not need it (binding mathematical elimination), but future cases at borderline scores in the underdetermined regime would.

### Remaining unsupported cipher kinds

**None within DSL.** Every DSL-valid kind is supported. Any *additional* cipher families (Hill, Playfair, Chaocipher, fractionated Morse, etc.) would need to be added to both `_VALID_CIPHER_KINDS` and `_SUPPORTED_KINDS` with new kernel transforms and tests. No such expansion is currently scoped.

### Remaining human-authored failure reasons

1 case in Phase 4 audit (`bbc2df53` — AAA page-17 serpentine interpretation). Bounded-exhaustive results hold under either interpretation, so the elimination is sound. But the prose judgment is human, not algebraic.

### Remaining claims with weak provenance

Per the project's claim taxonomy in `docs/claims_registry.json`:
- 1 `bean_reported_not_rerun` claim (Stehle Δ5 / KRYPTOS-letter proximity; per MEMORY.md, was promoted to `project_reverified_statistical_anomaly` 2026-05-02, but the original `bean_reported_not_rerun` archival entry remains).
- 7 `interpretive_physical_observation` claims (sculpture geometry / physical interpretive material).

Neither class is in scope for hard elimination basis. The `claim_policy.py` gates prevent their use as binding constraints.

---

## Authorized Search Space

Per the directive's gate ("Only after Phase 1–6 audits pass, recommend narrowly bounded new search"), and given Phase 2.1 is incomplete:

**No new K4 search authorized at this time.**

The single authorized work item is **complete Phase 2.1 — methodological-family conditional null calibration**. The scope:

- **family**: methodological-family null sampler covering at minimum {k3_continuity, k2_coords, archive_evidence, antipodes, geodetic, geometry}
- **mechanism**: synthetic worker-script invocation with random parameter sampling that mirrors the parameter distributions personas use, but does not condition on K4 cribs
- **dsl_spec shape**: not applicable (methodological families set `dsl_spec: null`)
- **compute budget**: 10K samples per family, ~few hours on the 28-vCPU VM (rough estimate, refine after design)
- **null baseline**: this calibration IS the null baseline; output integrates into `null_baselines/admitted_theory_manifest.json`
- **kill criteria**: per-family ledger mean exceeds null mean by less than 2 sigma after Bonferroni correction → "no signal in family"; exceeds by more than 2 sigma → "warrants bounded retest of that family"
- **success criteria**: a calibrated conditional null distribution per family sufficient to discriminate signal from admissibility-gating bias
- **artifacts to write**: per-family JSONL distributions under `results/null_baselines/admitted_theory/`, manifest entries
- **multiplicity correction**: Bonferroni across all calibrated families (currently 6+, expansion-friendly)
- **halt condition**: synthetic null sampler produces samples that themselves enter the SIGNAL range (>=18) on K4 — would indicate the sampler is accidentally crib-optimizing and require rework

---

## Claims That Must Not Be Made

The following claims are **not supported** by the current evidence and **must not** be written into project doctrine:

- ❌ "K4 has no cryptographic signal."
- ❌ "All high scores are artifacts."
- ❌ "Family X is globally eliminated."
- ❌ "Search has been exhausted."
- ❌ "Admissibility-gating bias has been ruled out as the source of family elevations."
- ❌ "Physical anomaly Y is cryptographically binding."
- ❌ "The retired palette / null mask family was correct after all."
- ❌ "K3 not solving in 500-cycle dry-run is a framework regression."
- ❌ "The score-17 case is statistically extreme under any null."

The supported claims (with reproducibility):

- ✅ "After 879 tested theories, no entry is currently in the SIGNAL (score ≥ 18) range."
- ✅ "Every entry at score ≥ 16 has a documented elimination reason."
- ✅ "The DSL/dispatcher coverage is at 100% with no avoidable gaps."
- ✅ "K1 and K2 are rediscoverable in the framework's dry-run path."
- ✅ "Per-family score elevations are real and statistically detectable, but cannot be interpreted as cryptographic content until the admitted-theory conditional null is calibrated for the methodological-family path."
- ✅ "The framework's safety gates (critic, red-team, admissibility, kernel-overrule, lead-pursuit) have been working correctly across the audited campaign window — no false promotion of a noisy result has occurred in the audit-visible record."

---

## Next-Action Recommendation

1. **Approve the moratorium continuation** — no new K4 search until Phase 2.1 lands.
2. **Authorize the Phase 2.1 build** — methodological-family null sampler. This is its own brainstorm/plan/build cycle (similar in scope to the key_tape DSL build). Estimated 2–4 days.
3. **Defer real-API K1 self-test** — only worth running if there's a specific reason to test the LLM-side spec generation; not blocking right now.
4. **Defer Stage B v1 runner** — the Phase 5 stub provides clean failure for personas, no urgent need to build the full runner without an operator-supplied A.

The substantive next step is Phase 2.1. Everything else is downstream of that calibration.

---

## Reproducibility checklist

- [x] `python3 -m kryptos doctor` returns all-PASS.
- [x] `null_baselines/manifest.json` `kernel_commit` matches current kernel (`7105ac297264`).
- [x] Phase 1 SQL queries reproducible from `current_signal_inventory.md`.
- [x] Phase 2 calibration script committed (`scripts/_infra/calibrate_admitted_theory_null.py`).
- [x] Phase 2 quick-mode output: `null_baselines/admitted_theory_manifest.json`.
- [x] Phase 2 ledger comparison: `results/null_baselines/admitted_theory/ledger_comparison.json`.
- [x] Phase 3 audit grounded in ledger record `3041e54d` `failure_reason` field (kernel-verified, not prose-only).
- [x] Phase 4 audit grounded in ledger records for all 36 6–9-band entries.
- [x] Phase 5 dossier matches live `_VALID_CIPHER_KINDS` and `_SUPPORTED_KINDS`.
- [x] Phase 6 dry-run K1/K2 self-test rerun and documented.
- [x] All audit memos under `docs/methodological_audits/` reference exact reproductions.

---

*Authored 2026-05-04 by Claude Opus 4.7 acting as principal research engineer / epistemic auditor. The decision is to **continue the no-new-search moratorium** and **authorize Phase 2.1 only**. This is the most productive next direction per the project's discipline: do not search wider until the project can distinguish signal from admitted-theory overfit.*

---

## Update — 2026-05-04 (Tier 1 `.claude` hardening pass)

**This update does not rewrite the original memo. The decision context
above remains historically accurate. The status below reflects what
happened after Phase 2.1 was authorized.**

### Phase 2.1 attempted and completed; result inconclusive

Phase 2.1 (methodological-family conditional null calibration) was
implemented and run. Outputs:

- `scripts/_infra/calibrate_methodological_null.py` (v1.0)
- `null_baselines/methodological_null_manifest.json`
- `results/null_baselines/methodological_null/<family>__v1.jsonl`
- `results/null_baselines/methodological_null/ledger_comparison.json`
- `docs/methodological_audits/methodological_null_decision_memo.md`
  (the calibration's own decision memo)

**Headline answer per the original directive's allowed answers:**
`inconclusive due to insufficient sampling or invalid synthetic model`.
Specifically: invalid synthetic model for **4 of 6 families**.

| Family | Max ratio (synth / ledger) | Faithful regime? |
|---|---:|---|
| k2_coords | 1.00 | yes |
| encoding | 0.86 | yes |
| geometry | 0.38 | no |
| k3_continuity | 0.25 | no |
| key_tape | 0.25 | no |
| archive_evidence | 0.21 | no |

For the two faithful families (`k2_coords`, `encoding`) the mean
elevation is small (+1.04, +0.20) and within ~1σ of the synthetic null
— consistent with admissibility-bias rather than cryptographic content.
This generalizes only to those two families.

For the four non-faithful families the synthetic null does NOT reach
the ledger BREAKTHROUGH regime because uniform parameter sampling does
not construct the algebraic-degeneracy / structural-overfit patterns
that drove the score-24 ledger artifacts. The ledger's high means in
those families are pulled up by documented overfits (Bean-invariance
under non-crib edits, period-impossibility-with-prime-grid, bounded
keyword exhaustion, primer search saturation). Phase 2.1's uniform
sampler is structurally too weak to fairly bound these regimes.

**The honest verdict is therefore: the Phase 2.1 result does NOT
discharge the no-new-search moratorium.** The original framing of the
memo (no broad reopening until Phase 2.1 lands) is unchanged in
spirit; what changed is that Phase 2.1 landing produced an
inconclusive result, not a closure.

### What this means for the verdict in the body of this memo

The body says the no-new-search moratorium continues with one
authorized item: complete Phase 2.1. That item is now done in the
sense that the calibrator exists, has been run, and the comparison has
been produced. **The next authorized item is Phase 2.2**:
mechanism-aware family-specific synthetic generators that do construct
the algebraic-degeneracy regimes ledger theorists explored.

Phase 2.2 design is committed at
`docs/methodological_audits/methodological_null_phase2_2_design.md`.
Implementation has not been authorized in this Tier 1 pass; that is its
own scope decision.

### What this means alongside Tier 1 `.claude` hardening (2026-05-04)

In parallel with the Phase 2.1 outcome, the Claude prompt-layer audit
(`docs/methodological_audits/claude_agents_skills_adversarial_audit.md`)
produced a PARTIAL verdict on the `.claude` layer. Tier 1 hardening was
implemented on 2026-05-04 and adds:

- four critical skills: `known-answer-validation`,
  `dispatcher-dsl-contract`, `conditional-null-methodology`,
  `prompt-contract-lint`;
- repaired stale skills: `project-onboarding`, `results-protocol`,
  `disproof-protocol`, `k4-stego-cracker`,
  `otp-null-keystream-forensics`;
- repaired stale agents: `stego-analyst`, `forensic-photo-analyst`,
  `kryptos-corpus-forensics`, `script-auditor`,
  `escape-room-cryptanalyst`, `cipher-discovery-builder`,
  `research-chancellor` — manual-only markers and controller-context
  blocks added;
- `.claude/settings.local.json` retired-constant import allow-rule
  removed;
- a deterministic `.claude` linter test suite at
  `kryptosbot/tests/test_claude_prompt_layer.py`;
- a single readiness gate at
  `docs/methodological_audits/k4_campaign_readiness_gate.md`.

### Combined posture as of 2026-05-04

1. **No-new-search moratorium continues.** Original gate held.
2. **Phase 2.1 was attempted and is inconclusive for 4 of 6 families.**
   Original "complete Phase 2.1" item is closed; result does not
   reopen search.
3. **Phase 2.2 mechanism-aware methodological null is now the
   authorized next constructive step.** Design committed; implementation
   pending.
4. **Tier 1 `.claude` hardening landed.** The prompt layer is no longer
   the documented primary blocker. The new linter test must run green
   on every change; the readiness gate is the single decision surface.
5. **Even with both Phase 2.2 and Tier 1 green, K4 search reopening
   requires a positive decision through the readiness gate**, not just
   a green check elsewhere.

The original "claims that must not be made" list at the bottom of this
memo's body is unchanged and remains binding. Specifically: no
"K4 has no signal" claim, no "framework can solve K4" claim, no
rehabilitation of retired claims through Tier 1 cleanup.

*Update authored 2026-05-04 as part of the Tier 1 `.claude` hardening
pass. The original 2026-05-04 memo above is preserved verbatim as
historical record.*
