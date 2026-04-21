# Phase R3-1 — Audit + Cutover Contract

**Date:** 2026-04-21
**Phase:** R3-1 (audit, no code changes)
**Status:** Deliverables complete. **Stop condition triggered (see §3) — escalation to operator required before R3-2.**

---

## 1. Deliverables produced

Two design documents, written without any code changes:

1. **`docs/maturation/round3/CURRENT_WORKER_PATH.md`** — map of the pre-R3 worker path. Every function, every file, every line number. Covers: (a) the full call chain from `ResearchController.run()` through `_run_worker`, (b) what the worker receives today (prompt shape, tools, scratch convention), (c) what it returns (`WorkerContract` schema, parse flow, kernel overrule), (d) where each of R2-1 through R2-5 connects into the new path with explicit file + line references, (e) orphan helpers in `kryptosbot/job_dispatcher.py` and `kryptosbot/hypothesis_dsl.py` that R3-2 will wire, (f) Phase-3/R2 invariants the cutover must preserve.

2. **`docs/maturation/round3/DSL_CUTOVER_CONTRACT.md`** — implementation target for R3-2. Covers: (a) theorist output contract with three worked examples (Vigenère-on-KA single-layer, two-layer columnar-then-Vigenère, explicitly-untranslatable hypothesis with `dsl_spec=null`), (b) fallback policy decision (**FB-1 chosen** — critic rejects untranslatable proposals), (c) full pseudo-code for the new `_run_worker`, (d) the new `WorkerStatus.REJECTED_ADMISSIBILITY` enum value with semantics and downstream consumer updates, (e) `TheoryRecord.dsl_spec` field + ledger schema change, (f) backward-compat plan for `_run_worker_legacy`, (g) alert-path integration for matched-family nulls (R2-4 wiring).

Both documents are self-sufficient. R3-2 needs no further design decisions to start implementation; R3-3 has a specific test matrix to aim at. Brief §2.3 acceptance criteria satisfied except for the §3 escalation below.

---

## 2. Acceptance criteria (brief §2.3)

| Criterion | Status |
|---|---|
| Both documents written and reviewable | ✓ |
| Every R2 component's integration point named with file + line number | ✓ (CURRENT_WORKER_PATH.md §4) |
| Fallback policy chosen with rationale | ✓ FB-1, per DSL_CUTOVER_CONTRACT.md §2 |
| Pseudo-code for new `_run_worker` complete | ✓ DSL_CUTOVER_CONTRACT.md §3 |
| Postmortem §6.1.6 cross-referenced | ✓ CURRENT_WORKER_PATH.md §2 |
| No code changes in R3-1 | ✓ (design phase only) |

---

## 3. ESCALATION — Stop condition triggered

### 3.1 What the brief said to watch for

Brief §2.3 stop condition (verbatim):

> "if R3-1 surfaces that the DSL cannot express a cipher family that's currently a live research priority, halt and escalate. The brief assumes the DSL's coverage is sufficient for R3's scope; if that assumption is wrong, R3 becomes a larger effort and needs rescoping."

### 3.2 What R3-1 surfaced

**The DSL covers only a thin slice of what theorists propose.** `_SUPPORTED_KINDS` in `kryptosbot/job_dispatcher.py:247` is:

```
{identity, vigenere, beaufort, variant_beaufort, columnar, atbash}
```

The existing `theory_ledger.sqlite` records 637+ theories with this family distribution (top 15):

| Family | Count | DSL-expressible? |
|---|---|---|
| `key_tape` | 121 | **no** — OTP-like / procedural |
| `geometry` | 109 | **no** — spatial / procedural |
| `grille` | 92 | **no** — Cardano grille / procedural |
| `encoding` | 65 | partial (some encodings map to vigenere; most don't) |
| `k2_coords` | 64 | **no** — geodetic / procedural |
| `archive_evidence` | 50 | **no** — investigative / non-cipher |
| `crib_analysis` | 50 | **no** — methodological / non-cipher |
| `k3_continuity` | 24 | **no** — methodological |
| `geodetic` | 14 | **no** — coordinate-based |
| `procedural` | 9 | **no** — explicit procedural |
| `antipodes` | 8 | **no** — installation-based |
| `novel` | 7 | variable — catch-all |
| `fractionation` | 6 | **no** — polybius-class (polybius kind not translated) |
| `double_columnar` | 3 | **yes** — two-layer columnar |
| `mirror_ka` | 3 | **yes** — vigenere/beaufort on KA alphabet |

The theorist prompt actively steers toward procedural output. `kryptosbot/controller.py:1474–1491`:

> **IMPORTANT — THE PROCEDURAL PARADIGM:** Sanborn is a sculptor, not a cryptographer. [...] Prefer PROCEDURAL hypotheses — concrete step-by-step physical operations a sculptor could execute by hand — over algebraic ones. [...] The "procedural" family is for hypotheses that derive from physical anomaly interpretation rather than cipher taxonomy. **Use it.**

This is itself a durable project memory (`procedural_paradigm_shift.md` in `MEMORY.md §Project`) dating from the shift away from algebraic saturation. The procedural paradigm is a **live research priority**, not a legacy framing.

### 3.3 Why this triggers the stop condition

Under FB-1 (the recommended fallback), any theory whose `dsl_spec` has an untranslatable layer kind gets rejected at the critic stage. Applying FB-1 to historical theorist output would reject an estimated **95%+ of proposals** (only `double_columnar` + `mirror_ka` + occasional single-layer-vigenere/beaufort survive).

R3-3 §4.4 sets an 80% spec-production floor; the brief's stop condition fires at 50%. Real-theorist behaviour today is far below that. Projecting forward:

- **R3-3's readiness test would fail** immediately. R3 cannot reach its own exit criterion.
- **Live K4 cycles after R3 would have near-zero throughput.** Theorists would propose, critic would reject, cycle would end. No compute spent. No hypotheses tested. The framework technically runs, but produces no research.
- **FB-1's "force theorists to propose what the framework can actually test" becomes "force theorists to stop using the paradigm the project has spent the last six weeks validating."** That is the failure mode flagged in `feedback_accept_specific_disproofs.md` ("when a hypothesis is shown to have a specific mechanical error, fix or abandon the broken step. NEVER pivot to a different claim that preserves emotional commitment while avoiding the error"). Pivoting the theorist off procedural theories to satisfy a DSL gap is the correct analogue: fix the gap, don't launder around it.

### 3.4 Options

Four routes forward, in increasing order of scope expansion:

**Option α — Proceed to R3-2 as written, accept low throughput.**
Minimal effort. R3-2 implements the cutover, R3-3's test uses only DSL-expressible synthetic theories to pass, real-theorist test is documented as "reachable only after DSL growth." R3-4 protocol carries a prominent caveat. This is the most brief-faithful option but effectively stalls K4 research on the controller until a later brief grows the DSL.

**Option β — Use FB-2 for untranslatable theories.**
Rewrite §2 of DSL_CUTOVER_CONTRACT to choose FB-2 instead of FB-1: untranslatable theories route through `_run_worker_legacy` (SDK subprocess), with explicit ledger tagging. Preserves theorist paradigm. Downside: the postmortem §6.1.6 gap persists for those theories — they still write freeform Python in `worker_scratch/`, R2 components still don't fire for them, Row D still reads zero for that subset. Partially defeats R3's purpose.

**Option γ — Rescope R3 to include targeted DSL growth.**
Add two or three phases before R3-2: extend `_SUPPORTED_KINDS` to cover `procedural` (via recipe-ID dispatch to `procedural_anomaly_recipes.md`), `polybius`, and at least skeletal `grille`. Likely 2-3 week addition. Still "wire what exists" in spirit — the listings are in `_VALID_CIPHER_KINDS` already; just the translators are missing. The brief's own §6.1 says "Do not expand the DSL" but explicitly defers that to "a later brief, not absorbed here" — Option γ formalizes a pre-R3-2 brief rather than informally absorbing.

**Option δ — Parallel tracks.**
Controller runs R3-routed DSL-dispatch for the narrow set of DSL-expressible theories (double_columnar, mirror_ka, some encoding, some novel) and `_run_worker_legacy` runs for everything else, with a ledger tag distinguishing the two. Each theory advertises which track it targets. Similar to Option β but explicit and auditable. Downside: sustains two dispatch paths indefinitely, which the brief explicitly wanted to close in R4.

### 3.5 Recommended option

**Option γ** — rescope to include DSL growth.

Rationale:

1. **Brief's own §2.3 stop condition frames this as the right response:** "R3 becomes a larger effort and needs rescoping." The stop condition is designed for this exact surprise.
2. **The durable project memory `procedural_paradigm_shift.md` + `procedural_anomaly_recipes.md` treat procedural as the live path.** Cutting theorists off from it to satisfy R3's scope pick would be the pivot-to-avoid-specific-error anti-pattern.
3. **`_VALID_CIPHER_KINDS` already lists procedural/polybius/grille/etc.** — the schema acknowledges them; only the dispatcher translators are missing. This is DSL **completion**, not DSL **growth**.
4. **The postmortem's gap-close goal is preserved.** Option γ still wires every theory through the dispatcher.
5. **FB-1 regains its epistemic value** once the DSL actually expresses what theorists want to propose.

Option β is a close second — it preserves theorist throughput with minimal new work, at the cost of keeping a sizable fraction of dispatches on the legacy path. Option α is the most faithful to the brief's letter and the weakest outcome in practice. Option δ buys nothing over Option β that's worth the added complexity.

### 3.6 Non-decisions R3-1 can record

Regardless of which option the operator chooses, three R3-1 findings stand:

1. **The pseudo-code for the new `_run_worker` is correct and reusable.** Options α/β/γ/δ all use it for their DSL-path dispatches. DSL_CUTOVER_CONTRACT.md §3 is not affected by the escalation.
2. **`WorkerStatus.REJECTED_ADMISSIBILITY` is a valid new enum value** regardless of how broadly the DSL covers theorist output.
3. **`TheoryRecord.dsl_spec` schema addition is the right shape** regardless of translator coverage — theories carry their spec, whatever the spec covers.

R3-2 can implement these three pieces independently of the coverage decision. Only the fallback policy and theorist prompt change depend on the operator's answer.

---

## 4. No code changes this phase

Per brief §2.3, R3-1 is design-only. Verified:

```
git status --short
?? docs/maturation/round2/K4_RUN_POSTMORTEM.md
?? docs/maturation/round3/          # R3-00 preflight + R3-1 docs only
?? f0aac050-0944-40df-a3bb-16628000f6d6.png
?? scripts/_infra/k4_run_postmortem.py
?? tests/test_k4_run_dashboard.py
```

Only additions under `docs/maturation/round3/` (and `null_baselines/manifest.json` unmodified since R3-00 noted it).

---

## 5. Commit plan

R3-1 lands as a single commit containing:

- `docs/maturation/round3/phase_R3_00_preflight.md`
- `docs/maturation/round3/CURRENT_WORKER_PATH.md`
- `docs/maturation/round3/DSL_CUTOVER_CONTRACT.md`
- `docs/maturation/round3/phase_R3_01_report.md` (this file)
- `results/self_test/r3_baseline_dryrun.json`
- `results/self_test/r3_entry_cycles20000.json`

Proposed commit message: `maturation round 3 phase R3-1: worker-path audit + cutover contract (escalation required)`.

---

## 6. Next action

**This phase does not auto-advance to R3-2.** Per brief §2.3's stop condition, the operator's decision on §3.5 is required before implementation begins. The docs are committed; operator is asked to choose between α/β/γ/δ (or a variant) before R3-2 starts.

If the operator chooses Option α (proceed as-written), R3-2 can start immediately with the DSL_CUTOVER_CONTRACT as-is.

If Option β, DSL_CUTOVER_CONTRACT §2 is revised to choose FB-2, R3-3's real-theorist test is rescoped to measure fraction-of-theories-on-DSL-path rather than raw spec-production rate, and R3-2 picks up.

If Option γ, a new pre-R3-2 brief is authored that extends `_SUPPORTED_KINDS` coverage. R3-2 and R3-3 wait.

If Option δ, DSL_CUTOVER_CONTRACT §2 is revised to describe the dual-track model and §7 (alert integration) is extended to cover both tracks' contracts. R3-2 picks up.

---

*End of phase_R3_01_report.md. The R3-1 work is complete to the extent the brief allows; the stop condition blocks further autonomous progress.*
