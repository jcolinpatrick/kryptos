# Controller Maturity Audit — 2026-05-16

**Auditor:** Claude (autonomous, full-autonomy session)
**Question:** Is `kryptosbot/run_controller.py` mature enough to find cryptographic signal in K4 and exploit it?
**Verdict:** **NO — mature enough to RUN safely without producing signal, but NOT mature enough to FIND a solution.**

---

## Executive summary

The controller is a well-instrumented, defensively-coded research loop with sound
kernel verification, proper halt conditions, and effective elimination
bookkeeping. It does not crash, does not silently accept false-positive
plaintexts, and does not silently lose state.

It also does not find anything. Across **528 controller cycles and 2007 proposed
theories** persisted in the live ledger (`/data/db/theory_ledger.sqlite`, last
touched 2026-05-08), the recorded `theories_promising` count is **zero**. The
distribution of best-scores is fully explained by random-noise generation plus
crib-paste artifacts caught by downstream filters. No persisted experiment has
ever reached the moderate-signal band (crib_score 10–17) under a non-paste
plaintext. The known-answer gate confirms the kernel is sound (K1, K2, K3 all
discoverable by the in-process strategies) but the LLM-driven theorist that
actually drives the cycle cannot reach those families through its current
prompt + DSL surface.

The most likely category of failure is **hypothesis-generation immaturity**,
not kernel or dispatcher immaturity. Concrete defects below identify what can
be fixed before the next live run.

---

## Evidence

### 1. Kernel is sound

`PYTHONPATH=src python3 kryptosbot/self_test.py --panel all --mode dry-run`
with sufficient `--cycles`:

| Panel | Discovered | Cycles to discovery | Peak |
| --- | --- | --- | --- |
| K1 | yes  | 15    | 20/20 |
| K2 | yes  | 17    | 20/20 |
| K3 | yes  | **9 345** | 20/20 (at `--cycles 20000`) |

The CLAUDE.md pre-flight invocation does not specify `--cycles`, which defaults
to `--cycles 10` in some call sites and produces a misleading "K3 not solved"
banner. With `--cycles 1000` K3 sits at peak 5/20 — easily misread as "kernel
broken when it is "default budget too small". **Recommendation: change the
documented self-test invocation to `--cycles 20000` for the K3 panel, or raise
the K3 panel's default budget.**

### 2. Verifier (`contracts._verify_against_kernel`) is sound — one minor bug

Of 1 168 persisted experiments, 38 had `fields_overwritten=True` and 25 of
those involved a worker attempting to claim a non-zero score that the kernel
disagreed with. None of the false claims were promoted to `promising` status.

**Bug — LANDED 2026-05-16.** Plaintexts of length 97 that contain non-A-Z
characters (in practice, `?` placeholders) bypass the length check, then crash
`verify_bean_simple` inside the kernel call because `text_to_nums` silently
drops the `?` chars. The exception is caught and the score is zeroed, but the
`verification_error` field leaks the kernel's complaint as if the verifier
itself were broken.

Fix: explicit alphabet guard in `contracts.py:_verify_against_kernel` between
the length check and the kernel call. New regression test
`TestCategory6_UnicodeSmuggling::test_question_mark_placeholder_rejected_cleanly`
locked in. Two existing tests (`test_accented_char_triggers_exception_branch`,
`test_cyrillic_homoglyph_triggers_exception_branch`) renamed and updated to
assert the new clean error message; behavior is unchanged (zero score fields,
fields_overwritten=True) — only the message text is now diagnostic.

Repro:

```python
from kryptosbot.contracts import _verify_against_kernel, WorkerContract
pt = "?NTM??X?LJ?VDH?D?APVUUCYFNFWFDSAXQ?WUKNVHQZO?BABV?AMTR?C??D?ERFAEZBDRJLZLMERPBQXVYDT?SK?W????EI?A"
c = WorkerContract(hypothesis_id="x", best_plaintext=pt)
_verify_against_kernel(c)
# verification_error: "Kernel verification raised: verify_bean_simple requires a length-97 keystream, got 76. ..."
```

**Fix direction.** Reject any plaintext containing non-A-Z chars at the top
of `_verify_against_kernel`, before the length check, with a clear
`verification_error`. The score outcome is already correct; only the message is
wrong. ~5 LOC change, see `kryptosbot/contracts.py:99`.

### 3. Theory ledger shows zero progress toward signal

Live ledger snapshot:

| Field | Value |
| --- | --- |
| cycle_number | 528 |
| theories_proposed | 2 007 |
| theories_tested | 1 200 |
| theories_eliminated | 819 |
| theories_promising | **0** |
| status `eliminated` | 1 277 |
| status `withdrawn` | 279 |
| status `criticized` | 47 |
| status `approved` | 14 |

Score distribution across all 2 007 persisted theories:

| best_score band | count | % |
| --- | --- | --- |
| `[0, 1)` | 1 526 | 76.0 |
| `[1, 4)` | 300 | 14.9 |
| `[4, 7)` | 155 | 7.7 |
| `[7, 10)` | 16 | 0.8 |
| `[10, 14)` | 0 | 0.0 |
| `[14, 16)` | 0 | 0.0 |
| `[16, 18)` | 2 | 0.1 |
| `[18, 24)` | 0 | 0.0 |
| `[24, 25)` | 8 | 0.4 |

The bimodal pattern — almost everything at noise floor (≤7) plus a thin tail at
24 — is the signature of a controller that is either (a) producing only
already-eliminated families or (b) producing crib-paste artifacts. Both are true
here:

* All 8 (+1 in experiments table) crib_score=24 events have plaintexts of the
  form `<random A-Z>EASTNORTHEAST<random A-Z>BERLINCLOCK<random A-Z>`. They
  are not solutions; they are workers constructing PTs that literally contain
  the cribs at the canonical positions. The Bean check passes because 624
  Bean-valid keystreams exist and a worker can pick a PT that lands on any
  of them. Downstream ngram-floor and stat-audit gates correctly identified
  every one as noise.

* Only 2 theories reached the band [16, 18). Both were correctly disproved.
  Nothing in the band [10, 16) has ever been observed across 528 cycles.

### 4. Admissibility rejects: 23% overall, **49.5% on the DSL-dispatcher path**

Of 1 168 persisted experiments:

| Worker outcome | Count | % |
| --- | --- | --- |
| disproved | 842 | 72.1 |
| rejected_admissibility | **273** | **23.4** |
| inconclusive | 29 | 2.5 |
| error | 16 | 1.4 |
| timeout | 6 | 0.5 |
| success | 2 | 0.2 |

But the 23% overall figure understates the problem when split by worker role:

| worker_role | total | disproved | rej_admissibility | inconclusive | error | timeout | success |
| --- | --- | --- | --- | --- | --- | --- | --- |
| dsl_dispatcher | 551 | 262 | **273 (49.5%)** | 6 | 10 | 0 | 0 |
| agent_sdk | 396 | 372 | 0 | 16 | 6 | 0 | 2 |
| agent_sdk_non_dsl_category | 213 | 200 | 0 | 7 | 0 | 6 | 0 |
| local_rerun | 8 | 8 | 0 | 0 | 0 | 0 | 0 |

`dsl_dispatcher` is the kernel-direct path that R3 (2026-04-21) introduced
specifically to remove worker-side LLM calls — and **half of its dispatches
never run a single kernel cycle** because the LLM-produced DSL fails
admissibility. The R3 efficiency win on the worker side is being eaten by
upstream specification waste.

The admissibility rejects split roughly half-and-half between two distinct
failure modes:

| Reject reason class | Count | Diagnosis |
| --- | --- | --- |
| `translation error: <param>` | ≈ 134 | LLM theorist produced DSL that fails validation |
| `exhaustion overlap: <N> prior entries` | ≈ 140 | dispatcher's substring heuristic, often false-positive |

Examples from the live data (verbatim, top frequencies):

* 32 × `quagmire_iii requires ct_alphabet_keyword == p…`
* 26 × `route layer rows*cols=49 must be >= CT_LEN=97 …`
* 25 × `quagmire_iv requires distinct ct/pt alphabet k…`
* 23 × `route layer requires variant in {'serpentine',…}`
* 48 × `exhaustion overlap: 10 prior entries already cover this spec's as…`
* 40 × `exhaustion overlap: 17 prior entries already cover this spec's as…`

The theorist is paying full tokens (theorist + critic + red-team) for ~23% of
all dispatches that never reach a worker. Half of that is a model-side problem
(theorist DSL fluency), half is a dispatcher-side problem (over-aggressive
exhaustion-overlap heuristic — already documented in
`kryptosbot/ORIENT.md §5.3` as a known false-positive surface).

### 5. Theorist is stuck on noise-floor families

Per-family score distribution across all 2 007 theories:

| family | n | mean | max |
| --- | --- | --- | --- |
| encoding | 826 | 0.78 | 7.0 |
| key_tape | 207 | 0.75 | 24.0 |
| archive_evidence | 196 | 1.30 | 24.0 |
| k2_coords | 177 | 0.61 | 6.0 |
| grille | 162 | 0.64 | 24.0 |
| geometry | 128 | 0.97 | 16.0 |
| crib_analysis | 98 | 0.94 | 24.0 |
| k3_continuity | 93 | 1.37 | 24.0 |
| antipodes | 45 | 0.98 | 6.0 |
| geodetic | 26 | 1.42 | 8.0 |
| procedural | 10 | 0.52 | 5.0 |
| novel | 7 | 0.00 | 0.0 |
| fractionation | 6 | 0.01 | 0.0 |

Four families (`encoding`, `key_tape`, `archive_evidence`, `k2_coords`)
account for **1 406 / 2 007 = 70 %** of all theories. All four have mean
best_score < 1.5 — i.e. the controller is spending 70% of its hypothesis budget
on families that empirically never escape the noise floor. The critic is
rejecting only ~2.3 % of encoding-family theories despite 826 trials of
empirical evidence that the family produces no signal. The critic does not
re-weight against empirical family yield; it gates only on the static
TIER_1/TIER_2 elimination registries.

### 6. The last run halted on a hardening counter

Final controller state from `controller_state.state` JSON:

```
halt_reason_hardening: "Admissibility rejections (D column) were zero for 3
consecutive dispatched cycles (threshold=3). Either all theorist specs are
trivially admissible or the DSL path is not being exercised; operator review
required."
consecutive_d_zero_cycles: 3
```

This is the system working as designed — it stopped itself when the diagnostic
"D-column" (admissibility rejections per cycle) collapsed to zero, which is
treated as suspicious because in nominal operation a 23%-reject rate is
expected. But it is also a symptom: the controller does not have an automatic
"resume with reset" path. It halted and waited for an operator.

### 7. The kernel-overrule mechanism is the only thing keeping false signal from leaking

Of the 9 crib_score=24 events, **5 were not overruled by the verifier** — i.e.
the kernel agreed with the worker that the math is correct (crib_score=24,
bean_passed=True). The ngram floor (per-char ≤ -5.5 downgrades BREAKTHROUGH →
SIGNAL) and the stat-audit step catch them downstream. There is no upstream
gate that prevents a worker from constructing a PT that is a literal crib paste
plus a Bean-valid keystream — that is mathematically allowed by the cipher
algebra, and the kernel is right to accept it.

A simple, cheap defense is missing: a per-experiment **crib-paste detector**.
Definition: if the plaintext at non-crib positions has a quadgram per-char
score below, say, -6.2 AND the crib positions exactly match the canonical
plaintext, the worker is constructing a crib paste and the result should be
classified as `disproved_crib_paste` with no further compute. This catches 9
events directly and saves the elimination round-trip on similar future
attempts.

---

## What is wasted compute and what isn't

| Category | Wasted? | Estimated share |
| --- | --- | --- |
| 273 admissibility rejects (paid theorist + critic + red-team tokens; no worker run) | yes | ~23 % of cycle cost |
| 9 crib-paste 24/24 events (full elimination round-trip) | partly — they did produce real elimination evidence, but at a cost vastly higher than a 1-line paste detector | small absolute, large per-event |
| 826 `encoding`-family theories | partly — most are confirming a known-noisy family, but the controller has no mechanism to back off once it's clear the family is empirically dead | ~40 % of all theories |
| 1 526 score-0 theories (76 %) | not strictly wasted — many are valid disproofs of mathematically-impossible hypotheses, which IS the project's elimination work | the "expected" floor |
| Local reruns (8) | no | tiny |

The headline number is that ~63 % of the controller's budget is going into work
that, with the current generator + critic, is statistically guaranteed to
produce no signal. The remaining ~37 % is doing genuine elimination work, which
is the project's actual current product.

---

## Concrete recommendations, ordered by ROI

### Tier A — small fixes, high payoff

1. **Crib-paste detector at worker-result intake.** ~30 LOC in
   `kryptosbot/contracts.py` after `_verify_against_kernel`. Reject any
   contract where (a) crib_score == 24 AND (b) non-crib ngram per-char ≤ -6.2.
   Reclassify status as `disproved_crib_paste`; do not run the full
   elimination pipeline on it. Saves 9 events of compute already and an
   unbounded number going forward.

2. **Fix the `?`-plaintext leak in `_verify_against_kernel`.** ~5 LOC. Reject
   non-A-Z chars BEFORE the kernel call. Already does the right thing
   silently; this only fixes the misleading error string and adds a clean
   `verification_error` for an audit category that doesn't have one today.

3. **Update CLAUDE.md / ORIENT.md self-test invocation.** Change documented
   pre-flight to use `--cycles 20000` (or raise the K3 panel's internal
   default). At the documented `--cycles 1000` the K3 panel falsely appears
   broken at peak=5/20. Real budget needed is ~9 345 candidates.

### Tier B — medium effort, medium payoff

4. **Empirical-yield re-weighting in the critic.** Track per-family
   `mean_best_score` and `count_promoted_to_signal_or_above` in the ledger.
   When `n >= 50` AND `count_promoted_to_signal_or_above == 0`, downgrade the
   family's critic priority. The current critic only honours static
   TIER_1/TIER_2 lists; it has no view of "we tried this 800 times and got
   nothing." 70% of the theorist budget is currently going into four such
   families.

**Update 2026-05-16:** Tier A recommendation #4 (empirical-yield re-weighting in the critic) LANDED as Phase 1 of the yield-feedback feedback loop. See `docs/specs/2026-05-16-yield-feedback-design.md` for design and `docs/plans/2026-05-16-yield-feedback-implementation.md` for the implementation plan. Phase 2 (Tier A #1: crib-paste detector + cipher-discovery KB injection) and Phase 3 (Tier C: few-shot library) designed for, not built. Smoke-tested 2026-05-16 against live ledger: encoding (n=826) and k2_coords (n=177) classified empirically_dead; key_tape and archive_evidence remain low_yield because crib-paste artifacts at best=24 protect them under the current policy (closes under Phase 2's crib-paste detector).

5. **Tighten the exhaustion-overlap heuristic** (`kryptosbot/job_dispatcher.py
   ::_exhaustion_overlap`). The current substring match against
   `exhaustion_log.json` family fields produces ~140 false positives (50 % of
   all admissibility rejects). Either (a) require exact spec-hash match before
   rejecting, or (b) demote overlap from rejection to a `caveat` field that
   the worker can still run with. Already flagged as a known-issue in
   ORIENT.md §5.3.

6. **DSL fluency training data for the theorist.** ~134 admissibility rejects
   are translation errors (quagmire_iii / quagmire_iv keyword shape mismatch,
   route rows*cols < 97, etc.). Either constrain the theorist prompt with
   strict DSL examples for these families, or run a DSL-lint step BEFORE the
   critic / red-team so token cost is paid only for syntactically valid
   specs.

### Tier C — larger restructuring, foundational

7. **Reframe the cycle around UNTESTED surface, not LLM imagination.** The
   theorist currently re-derives hypothesis ideas from the prompt anomaly /
   landscape surface, with no direct view of "what cipher families /
   parameter regions actually have ZERO coverage". The session_briefing
   already computes most of this. A "next-bin" generator that enumerates
   ground-truth-uncovered cells of the (family × parameter × layer-order)
   space and asks the theorist to commit to a specific bin would replace a
   large fraction of the noise-floor families with theory work that is
   actually new.

8. **Per-cycle synthesis must influence next-cycle theory generation.** The
   `CycleSynthesis` field is built end-of-cycle and consumed by the next
   cycle's landscape (`controller.py` ~ line 1634). But it is presented as
   narrative text in the theorist prompt; there is no machine-checked
   constraint that the theorist NOT re-propose what last cycle eliminated.
   The current evidence (826 encoding-family theories, 91% eliminated) is
   that the soft signal is being ignored.

---

## What I would NOT do

* Add more LLM-driven phases. The current loop already has critic →
  red-team → worker → stat-audit → lead-pursuit → synthesis. Adding a
  seventh LLM phase paid in tokens without changing the upstream generator
  will not change the score distribution.

* Add a "K4Bench is broken" verdict to MEMORY.md. K4Bench (synthetic
  challenges) is a calibration mode, not the live workload. It is doing what
  it was built to do.

* Tighten the BREAKTHROUGH alert. The 9 crib-paste events were correctly
  identified and classified as artifacts within the existing alert pipeline.
  The alert system is mature.

---

## Bottom line

The controller is fit for **elimination work**, which is what it is
empirically doing (1 277 eliminations across 528 cycles is real coverage).

The controller is **not** fit for **solution work** as currently configured.
The proximate cause is that the hypothesis generator pays full price to
re-propose families that have proven empirically dead. The kernel, verifier,
dispatcher, alert pipeline, and halt conditions are not the bottleneck.

If the question is "can this controller, AS IS, find K4 in another N
cycles?" — extrapolating from 528 cycles of zero promising outcomes, the
answer is "extremely unlikely without the Tier A/B fixes above."

If the question is "is the controller broken?" — no. It is mature, it does
not lie about what it found, and it does not consume tokens silently. It is
just looking in the wrong region of hypothesis-space, and lacks the feedback
mechanism to redirect itself.
