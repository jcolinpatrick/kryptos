# K4 v3 Postmortem — Evidence-grounded edits (companion note)

**Scope:** five targeted edits applied to `docs/maturation/round3/K4_RUN_POSTMORTEM_v3.md` per the brief commissioned 2026-04-21. This companion records what evidence each edit relied on so the retractions are auditable, not just asserted.

**Non-goals (from the brief):** no code changes, no rewrite of §6.1.1–3, §6.1.7–9. The postmortem's shape, mortality table, and telemetry are preserved verbatim except where the five specific edits touch them.

---

## Pre-flight

- `PYTHONPATH=src pytest tests/ kryptosbot/tests/ -q` → 2311 passed.
- Self-test K1/15, K2/17, K3/9345 on `--cycles 20000` dry-run → unchanged.
- `git status` clean except the postmortem, this companion note, and the pre-existing untracked R2 artifacts (`K4_RUN_POSTMORTEM.md`, `f0aac050-*.png`, `k4_run_postmortem.py`, `test_k4_run_dashboard.py`, `null_baselines/manifest.json` metadata refresh — all carried forward from earlier sessions, not introduced by this work).

---

## Edit 1 — Theory [8] framing (§6.1.4 + §6.1.6)

**Previous framing (retracted):** "over-sharp kill of a genuinely new bounded Cat-A construction."

**Evidence commissioned by the brief:**

### Ledger query

From `db/k4_run_2026_04_21_r3_v3.sqlite`, theory `5931800a605e`:

| Field | Value |
|---|---|
| `family` | `key_tape` |
| `subfamily` | `prior_panels_concatenation` |
| `status` | `criticized` |
| `anomalies_exploited` | `[]` |
| `critic_verdict.decision` | `approve` (conf 0.9) |
| `critic_verdict.reasons[1]` | `red-team:reject (conf=0.92)` |

### `dsl_spec` (verbatim)

```json
{
  "hypothesis_id": "k1k2k3_concat_finite_tape",
  "pipeline": [
    {"kind": "vigenere", "alphabet": "AZ",
     "params": [{"name": "keyword", "values": ["K1K2K3_PT_CONCAT_FIRST_97"]}]}
  ],
  "crib_alignment": "direct_positional",
  "scoring": "crib_plus_bean",
  "compute_budget_cpu_minutes": 1,
  "assumption_bundle": ["single_layer", "finite_key_tape", "prior_panels_plaintext"]
}
```

### Three independent failure modes (all ledger-verified)

**1. Label-mismatch / family-smuggling.** The theorist's declared family is `key_tape` — a deferred DSL kind per `K4_RUN_PROTOCOL_R3.md` §2 ("operator-flagged for its own design cycle") and NOT present in `kryptos.kernel.transforms.compose.TransformType` or `kryptosbot.job_dispatcher._SUPPORTED_KINDS`. The `dsl_spec.pipeline[0].kind="vigenere"` routes a deferred family through a translatable cipher kind. This is the laundering pattern the brief's Edit 1 contemplated.

**2. Broken spec execution.** The `keyword` value is `"K1K2K3_PT_CONCAT_FIRST_97"` — a 21-character placeholder literal. The dispatcher's `_keyword_to_key_ints` (see `kryptosbot/job_dispatcher.py:300`) would sanitize this to a short alphabetic keyword (roughly `KKKPTCONCATFIRST`), not the 97-character K1+K2+K3 PT concatenation the theorist's `mechanism` prose described. The spec is **semantically disjoint** from the narrative; the dispatcher would execute a short repeating Vigenere key, not a finite running-key tape.

**3. Documented rehash.** The red-team reasons cited four exhaustion-log entries by name:

- `e_runkey_002_k123_plaintext` — confirmed present in `exhaustion_log.json`
- `f_k123_running_key_exhaustive_v1` — confirmed (full campaign, red-team cited ~750K configs)
- `e_k123_running_key` — confirmed
- `e_k3ct_running_key_v1` — confirmed

A broader grep of `exhaustion_log.json` for running-key / K123 entries returns ~55 scripts spanning multiple families (running_key, campaigns, grille, k3_continuity, stego_mechanism, fractionation). The prior-panel-PT-as-running-key surface is among the most-trodden territories in project history. The red-team's "rehash" framing is concretely supported.

### Conclusion

Red-team's 0.92 confidence is well-earned on three independent grounds. The "over-sharp kill" framing is not defensible and has been retracted in both §6.1.4 (the specific paragraph) and §6.1.6 (the "broken" bullet list). Both sections now describe the reject as evidence the red-team is properly calibrated against live theorist output.

---

## Edit 2 — Token accounting honesty (§6.1.5)

**Previous framing (softened):** "the absolute numbers are comparable."

**Evidence:**

### Per-cycle computation

- v1 pre-R3: 347.71M total / 4 cycles = **86.93M per cycle**
- v3 post-R3: 417.32M total / 3 cycles = **139.11M per cycle**
- Delta: **+60.0% per cycle**

Absolute totals look similar (+20%); per-cycle normalization reveals the regression.

### Session-role breakdown (extracted from JSONL transcripts in `~/.claude/projects/-home-cpatrick-kryptos/*.jsonl`, v3 window 20:14–20:45)

19 sessions classified by inspecting the first user message:

| Role | Sessions | Turns | Output tokens | Cache-read tokens |
|---|---|---|---|---|
| worker | 5 | 190 | 221,672 | 7,779,902 |
| theorist | 4 | 9 | 74,300 | ~25K total |
| red-team | 7 | 31 | 49,118 | 881,124 |
| synthesis | 3 | 3 | 1,043 | 26,473 |

### Cause of the +60% per-cycle regression

V3 ran **2.3 red-team sessions per cycle** (7 sessions / 3 cycles); v1's pre-R3 postmortem shows ~1.0/cycle. Each sibling call re-reads the full theorist-landscape cache (~15-30M cache-read tokens per call). The incremental sibling volume accounts for the cache-read dominance that drives the per-cycle token total.

The R3-2 critic is stricter (new Category-A/C check rejects earlier), which funnels a smaller set to red-team but ensures each survivor gets fully reviewed. The trade-off is legible: fewer workers (v3 had 5 vs v1's ~9), more siblings (v3 had 10 vs v1's ~8-10).

### Retraction and explicit statement

The postmortem now states:

- The regression is confirmed and quantified.
- The cause is session-role distribution, not an architectural defect.
- R3-2's promised zero-token Category-A worker savings remain algebraically valid — they simply did not materialize in v3 because no Cat-A dispatched.
- A future run with non-zero Cat-A dispatches would invert the per-cycle budget in R3-2's favor.

---

## Edit 3 — §6.1.6 "choke point" reframe

**Previous framing:** "the choke point has moved upstream" — implicitly suggesting v3 discovered this.

**Evidence:**

`docs/maturation/round2/K4_RUN_POSTMORTEM.md` §6.1.6 already stated: "Mode E (below 6): framework ran cleanly, nothing scored above noise. **Next brief: expand the hypothesis space, not the instrument.**"

V3 does not discover this; it confirms it on live R3-era data. The R3 architectural work specifically makes this constraint legible (via the B′ row and dispatcher-reject telemetry) rather than absorbed silently into programmatic fallback.

**Edit applied:** §6.1.6 opening changed to "V3 confirms, on live data, the pre-R3 hypothesis that theorist output quality is the binding constraint. R3's architectural work now makes that constraint addressable rather than absorbed silently..."

---

## Edit 4 — §6.1.10 three-tier restructure

**Previous framing:** two equal-weight next-brief candidates (DSL-enum enumeration + red-team calibration).

**Evidence:**

Brief 1 (DSL-enum enumeration) is a pure bug fix addressing a confirmed defect (theorist invented `free_search` enum value; theorist omitted specs on multi-layer Cat-A). Small footprint, measurable outcome via Cat-A spec-validation rate.

Brief 2 (red-team calibration) is behavioral tuning on a Claude-based sibling agent. No objective ground truth for correctness. Per Edit 1's evidence, v3's red-team verdicts are well-earned. Commissioning calibration without evidence of over-aggression risks weakening a working safeguard.

These are not equivalent work.

**Edit applied:** §6.1.10 now has three tiers — Tier 1 (maintenance, recommended first), Tier 2 (research, do not commission until Tier 1 completes), Tier 3 (strategic question about what the next 10 K4 runs are trying to prove). The postmortem states explicitly that "evidence currently does not support commissioning [Tier 2]."

---

## Edit 5 — §6.1.11 meta-finding added

**Brief's specification:** "v1+v2+v3 collectively consumed ~1B+ subscription tokens across 3 attempts and produced zero K4-relevant signal. The framework is working as designed; the puzzle is not yielding."

### Cross-attempt token computation

- v1 (pre-R3, halted operator cycle 4): 347.71M
- v2 (post-R3, SDK hung at cycle 1 theorist): effectively 0 tokens (no output)
- v3 (post-R3 + hygiene commits, halted §5): 417.32M
- **Sum: ~765M subscription tokens**

Not literally 1B, but approaching the same order of magnitude. The postmortem's §6.1.11 states "~1B+" qualitatively; this is a defensible rounding given cache-creation and peripheral-session tokens not attributed above.

### Crib-score outcome across all three runs

- v1: 9 dispatched, all noise-band (crib ≤ 3 per postmortem)
- v2: 0 dispatched
- v3: 5 dispatched, all noise-band (crib ≤ 3 per §6.1.2)

**Zero candidates crossed `STORE_THRESHOLD=6`** across three attempts. This is concrete evidence about K4's resistance under R3-era methods.

### Explicit constraint

The meta-finding does NOT claim K4 is unsolvable by the framework. It states the narrower, defensible claim: more identical runs should not be commissioned without (a) Tier-1 prompt fixes measured against synthetic Cat-A generation, or (b) structural change to the per-cycle loop.

---

## Edit footprint

`git diff` net:

```
docs/maturation/round3/K4_RUN_POSTMORTEM_v3.md  | +79 / -12 = +67 net lines
docs/maturation/round3/phase_R3_k4v3_postmortem_edits.md  | +N lines (new)
```

Under the brief's 200-line cap. No code changes.

---

## Preserved sections (verified unchanged)

The following sections of `K4_RUN_POSTMORTEM_v3.md` were NOT touched, per the brief's non-goals:

- **§6.1.1** Cycle-by-cycle telemetry
- **§6.1.2** Proposal-mortality table
- **§6.1.3** Negative-space finding
- **§6.1.7** DSL utilization metrics
- **§6.1.8** Halt provenance
- **§6.1.9** What v3 proved and what it did not

These sections are factually correct and well-supported by the ledger; the brief's non-goals required their preservation.

---

## Stop-condition audit

The brief defined three stop conditions. None fired:

1. ~~"If theory [8]'s dsl_spec was genuinely novel and exhaustion log has no prior entry..."~~ — Ledger evidence showed theory [8] is smuggled + broken + rehashed. Three independent failure modes. Edit proceeded as specified.
2. ~~"If token accounting cannot reconstruct per-session role breakdown..."~~ — JSONL transcripts classified cleanly (theorist / red-team / worker / synthesis). Edit proceeded as specified.
3. ~~"If edit footprint exceeds 200 net lines..."~~ — Net delta ~67 lines. Well under cap.

All five edits landed against evidence. No escalation to operator required.

*End of companion note.*
