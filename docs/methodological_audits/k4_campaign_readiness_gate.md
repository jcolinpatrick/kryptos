# K4 Campaign Readiness Gate

**Status as of 2026-05-04:** This is the single doc that decides whether
a K4 campaign may run. It supersedes any informal "ready / not ready"
language elsewhere in the project. CLAUDE.md is operational doctrine;
MEMORY.md indexes live state; this gate decides whether new K4 search
is permitted.

---

## Current Decision

**BLOCKED.**

Tier 1 `.claude` hardening landed 2026-05-04 and is described below;
methodological-family conditional null Phase 2.1 remains inconclusive
for four families pending Phase 2.2 mechanism-aware-generator
implementation. Until Phase 2.2 produces faithful synthetic generators
for `k3_continuity`, `archive_evidence`, `key_tape`, and `geometry`,
broad K4 search is not gate-cleared. Narrow retests authorized below.

The default expected verdict on this gate is BLOCKED. Promotion to
`READY_FOR_NARROW_RETESTS_ONLY` or `READY_FOR_BROAD_CAMPAIGN` requires
ALL required green checks below to pass with reproducible artifacts
and an explicit decision memo.

## Required Green Checks

| Check | Status | Evidence | Owner |
|---|---|---|---|
| Pre-flight `kryptos doctor` | GREEN | All checks pass; see `kryptos.cli.doctor` output 2026-05-04. | repo-wide |
| Known-answer validation | GREEN | Re-verified 2026-05-27: `self_test.py --panel all --mode dry-run --cycles 20000` solved 3/3 in 0.86s wall, exit 0 (k1 via quagmire_iii cyc 15 peak 20/20; k2 via quagmire_iii cyc 17 peak 20/20; k3 via columnar_double cyc 9345 peak 20/20). Doctor pre-flight all PASS same date. Prior: 3/3 in 0.89s on 2026-05-04. The real-K4 masking-solver entry point `kryptos.admissibility.mask_campaign_gate.run_guarded_mask_search` now consumes this gate's outcome as a `ReadinessFact` and refuses to launch on RED / doctor-fail. See `known-answer-validation` skill. | known-answer-validation skill |
| .claude linter tests | PENDING | `kryptosbot/tests/test_claude_prompt_layer.py` landed 2026-05-04. Must pass on every change. | prompt-contract-lint skill |
| DSL/dispatcher contract teaching | GREEN | `dispatcher-dsl-contract` skill landed 2026-05-04; `kryptosbot/tests/test_dispatcher_doc_parity.py` and `test_job_dispatcher.py` baseline passing. | dispatcher-dsl-contract skill |
| Null-baseline freshness | GREEN (post-rebuild 2026-05-06) | Stale cache was observed at runtime during the 2026-05-06 controller diagnostic run (cycle 245, cache_commit=`4694094…` vs current_commit=`dd5d30c…`); the controller correctly fail-opened to legacy crib-only gating per CLAUDE.md doctrine. Rebuilt 2026-05-06 against current HEAD: `scripts/_infra/calibrate_null_baselines.py` (now 7 jobs, 25.1s including newly-added KA entries), `calibrate_null_baselines_r2_4.py` (7 matched-variant-family baselines, 15.9s), `calibrate_methodological_null.py` (Phase 2.1, 5.0s), `calibrate_methodological_null_phase2_2.py` (Phase 2.2 v3, 11.1s). **All 14/14 manifest entries now match HEAD** — the prior 2-entry KA-alphabet caveat is closed. The KA caches were not vestigial; `dsl_tools.get_cached(..., alphabet="KA")` consumes them when KA-alphabet null distributions are requested, but they were lazy-built and not in the standard calibrator's eager-rebuild matrix. Two new jobs added to `_STANDARD_JOBS`: `crib_score × random_text × KA × n=97` and `ngram_score × random_text × KA × n=97`. The shuffled_ct × KA cell was deliberately omitted (shuffled_ct is alphabet-invariant). **Operational rule:** after any commit that changes scoring paths, rerun all calibrators before launching cycles. | conditional-null-methodology skill |
| Methodological-null Phase 2.1 status | RED | Phase 2.1 inconclusive: synthetic-null max-ratio < 0.40 for k3_continuity, archive_evidence, key_tape, geometry (see `docs/methodological_audits/methodological_null_decision_memo.md`). Phase 2.2 design landed; implementation pending. | conditional-null-methodology skill |
| Retired-claim scan | GREEN | `CONSENSUS_NULL_POSITIONS` retired to `kryptos.kernel.retired`; settings.local.json stale import removed 2026-05-04; remaining mentions in agents/skills are policy-gated. | prompt-contract-lint skill |
| Prompt-contract scan | GREEN | `prompt-contract-lint` skill landed 2026-05-04; controller-routed agents updated with controller-context blocks; `escape-room-cryptanalyst`, `cipher-discovery-builder`, `research-chancellor` carry explicit Task/Agent-blocked language. | prompt-contract-lint skill |
| Stale-path scan | GREEN | `memory/elimination_ledger.md` and `memory/confirmed_findings.md` references in stego skill, otp-null skill, and stego-analyst agent removed 2026-05-04. Lint test enforces. | prompt-contract-lint skill |
| Manual-only agent scan | GREEN | `forensic-photo-analyst`, `kryptos-corpus-forensics`, `script-auditor` carry explicit "Manual-only agent. Not routed by the controller." markers in body. | known-answer-validation + prompt-contract-lint skills |

A check is **GREEN** only when its evidence is reproducible from this
repo at the cited commit and the matching skill / test enforces it.

## Verdict Mapping

| Verdict | When to use |
|---|---|
| `BLOCKED` | Any check is RED, or any required skill/test is missing. |
| `READY_FOR_NARROW_RETESTS_ONLY` | All checks GREEN except one of: (a) Phase 2.1 methodological null still inconclusive but the proposed retest is in a family where the synthetic null IS faithful (`k2_coords` or `encoding`) AND has a kernel-verified, dispatcher-compatible `HypothesisSpec`. |
| `READY_FOR_BROAD_CAMPAIGN` | All checks GREEN, including Phase 2.2 mechanism-aware-generator implementation produces synthetic null max-ratio ≥ 0.80 for every target family. |

## Commands

Run from repo root, in this order. Do not skip.

### 1. Pre-flight

```bash
PYTHONPATH=src python3 -m kryptos doctor
PYTHONPATH=src python3 scripts/_infra/session_briefing.py
PYTHONPATH=src python3 kryptosbot/run_controller.py --summary
PYTHONPATH=src python3 kryptosbot/run_controller.py --inventory
```

### 2. Known-answer gate

```bash
PYTHONPATH=src python3 kryptosbot/self_test.py --panel all --mode dry-run --cycles 20000
```

Required summary: `solved: 3/3`. K3 must complete at or before the
documented cap. Default 500-cycle runs are NOT the gate (K3 fails at
500 by design).

### 3. .claude linter

```bash
PYTHONPATH=.:src python3 -m pytest kryptosbot/tests/test_claude_prompt_layer.py -q
```

### 4. DSL / dispatcher regression

```bash
PYTHONPATH=.:src python3 -m pytest kryptosbot/tests/test_routing.py kryptosbot/tests/test_job_dispatcher.py kryptosbot/tests/test_r2_1_columnar_double.py kryptosbot/tests/test_dispatcher_doc_parity.py kryptosbot/tests/test_hypothesis_dsl.py -q
```

### 5. Null-baseline calibration freshness

The controller's alert p-value gate compares each cache entry's
`kernel_commit_at_write` against the current HEAD and **refuses to
consume stale calibration**, fail-opening to legacy crib-only gating
with a WARNING (per CLAUDE.md). To restore strict gating, rebuild every
cache against the current commit BEFORE launching cycles:

```bash
# Base distributions: random_text AZ/KA, shuffled_ct AZ, matched_variant_family AZ, ngram variants. ~18s.
PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines.py

# R2-4 per-variant matched-family distributions (vigenere/beaufort/var_beaufort/columnar_single/columnar_double). ~15s.
PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines_r2_4.py

# Methodological-family null + ledger comparison. ~5s.
PYTHONPATH=src python3 -u scripts/_infra/calibrate_methodological_null.py --ledger-comparison
```

Verify freshness against HEAD:

```bash
python3 -c "
import json, subprocess
head = subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode().strip()
m = json.load(open('null_baselines/manifest.json'))
for k, v in sorted(m.get('distributions', {}).items()):
    kc = v.get('kernel_commit') or v.get('kernel_commit_at_write') or ''
    flag = '✓' if kc == head else 'STALE'
    print(f'{flag:>5} {k}  {kc[:16]}')
"
```

Inspect `null_baselines/manifest.json`,
`null_baselines/methodological_null_manifest.json`, and
`results/null_baselines/methodological_null/ledger_comparison.json`.

**Operational rule:** the rebuild commands are cheap (combined < 1
minute). Run them after any commit that changes scoring, transforms,
or admissibility paths. Stale caches do not silently degrade the
framework — fail-open is loud — but they downgrade alert precision and
are a fixable readiness blocker, not a tolerable steady state.

### 6. Retired-claim and stale-path scan

```bash
grep -rn -E "CONSENSUS_NULL_POSITIONS|null[_ -]palette|\\{B,G,I,K,O,W,Z\\}" .claude/ docs/methodological_audits/
grep -rn -E "memory/elimination_ledger\\.md|memory/confirmed_findings\\.md" .claude/
```

Each match must be explicitly retired/policy-gated or removed.

### 7. Prompt-contract scan

```bash
grep -rn -E "Agent tool|launch (sub)?agent|Task tool|use the Agent|commission (the )?agent" .claude/agents/
```

Controller-routed agents must NOT instruct Claude to use Task / Agent /
subagent delegation (they may quote it as illustrative commentary
inside an explicit "Controller Context" block that says it does not
apply at runtime).

## Blockers (current)

1. **Methodological-null Phase 2.2 not implemented.** Synthetic
   generators for `k3_continuity`, `archive_evidence`, `key_tape`, and
   `geometry` do not yet construct the algebraic-degeneracy regimes
   that produced score-24 ledger BREAKTHROUGHs. Until Phase 2.2 lands,
   family elevations cannot be interpreted as signal vs admissibility-
   bias for these four families. See
   `docs/methodological_audits/methodological_null_phase2_2_design.md`.
2. **`.claude` linter test must run green on every change.** Drift in
   the prompt layer is the documented primary failure mode of this
   project. The linter is the durable defence; if it fails, the gate
   fails.

## What This Gate Does Not Prove

This gate proves the harness can rediscover three already-solved panels
under a documented cycle cap, that the prompt layer is currently free of
known stale references and retired-claim revival, and that the DSL /
dispatcher / kernel verification path is regression-stable. **It does
NOT prove the framework can solve K4.** A green gate is necessary, not
sufficient.

## Claims That Must Not Be Made

The following claims are **not supported** by passing this gate. Do not
write them into project doctrine, public documentation, or community
posts:

- "K4 has no signal."
- "The framework can solve K4 because K1/K2/K3 pass."
- "Physical evidence is cryptographic constraint."
- "Score elevation is signal without matched conditional null."
- "All family elevations are admissibility-bias artifacts."
- "The methodological null is closed."
- "Retired claims (null palette / consensus null positions) are
  rehabilitated."
- "Tier 1 / Tier 2 elimination wording on columnar is undisputed."

## Operator Procedure

To request a verdict change:

1. Run all commands above. Capture exit codes and key outputs.
2. Write the per-check evidence into the table above (with date and
   commit).
3. If any check is RED, the verdict stays `BLOCKED`. Document the
   blocker.
4. If all checks are GREEN AND Phase 2.2 is implemented, propose
   `READY_FOR_BROAD_CAMPAIGN` with a dated decision memo.
5. If Phase 2.2 is unfinished but a narrow retest is justified inside
   a faithful-null family, propose `READY_FOR_NARROW_RETESTS_ONLY`
   with the family, the bounded `HypothesisSpec`, and the matched null.

A verdict change is recorded by editing this file with a dated entry,
and by updating the relevant claim in `docs/claims_registry.json`. The
historical decision memo (`k4_reopen_decision_memo.md`) is appended,
not rewritten.

---

*Last updated 2026-05-04 by Tier 1 .claude hardening. Initial verdict
remains `BLOCKED` pending Phase 2.2 mechanism-aware-generator
implementation.*
