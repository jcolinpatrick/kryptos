# T1 (SERPENTINE) postmortem — handoff checklist

**Status when this checklist was written:** T1 launched 2026-04-25T20:08:03Z and was running. This file is a self-contained handoff so any future Claude Code session can pick up the postmortem without context from the launch session.

**To use this checklist:** read the whole file, then execute the steps in order. Do not skip the binding-criteria section — the postmortem is preregistered and post-hoc relaxation is not allowed.

---

## 0. Operational state at launch (point-in-time facts)

These paths and facts were true at launch. The DB and log are the live artifacts; verify each path exists before relying on it.

| Item | Value |
|---|---|
| Launch time (UTC) | 2026-04-25T20:08:03Z |
| Test id | `t1_serpentine` |
| Mechanism | Quagmire III on KRYPTOS-mixed alphabet, indicator='K' |
| Keyword | `SERPENTINE` |
| Synthetic CT | `DZFTVZIVQQQVYCFTAQQIFVBCIFCJWZLMAAIAIBJVXVBCSQIRXFPMYGWQCAWZLFFEVQUTFQWJDPHXNBWLDJXDFPVDZVRPAMITD` |
| Synthetic PT | `THERESEARCHERSREPORTSEASTNORTHEASTTHENWEMEASUREFORWARDFROMTHEREBERLINCLOCKPOINTSTOWARDMUSEUMSITES` |
| Run DB | `db/synth_t1_serpentine_20260425_200803.sqlite` |
| Sentinel JSON | `db/synth_t1_serpentine_20260425_200803.synthetic_mode.json` |
| Stdout/err log | `logs/synth_signal/t1_serpentine_20260425_200803.log` |
| Bundle manifest | `synth_signal/t1_serpentine/manifest.json` |
| Cycles requested | 30 (extension to 60 allowed once if cycle 30 shows non-trivial progress) |
| Theories per cycle | 5 |
| `--alert-on` | `signal` |

The PID at launch was 924474; by the time you read this, that PID is likely either gone (run completed) or different (if anything was restarted). Don't trust the PID number — check by name.

---

## 1. Required reading (do not skip)

Read these in order before doing anything operational:

1. **`docs/maturation/round3/SYNTHETIC_SIGNAL_CALIBRATION_SPEC.md`** — binding preregistration. Pay attention to:
   - §1.1 — T1 PASS/FAIL criteria (locked)
   - §3.3 — postmortem template (the structure your output must follow)
   - §4 — decision matrix (binding interpretation table; do not relax)
   - §5 — sign-off checklist (already checked off pre-launch)

2. **`memory/` (auto-memory):** the project memo `project_synthetic_signal_calibration_launched.md` should be loaded automatically via MEMORY.md. If it's not in your context, read it manually from the auto-memory store. It carries the project state at launch.

3. **`feedback_accept_specific_disproofs.md`** (auto-memory): the postmortem must be honest. If T1 fails, name the specific failure mode; do not pivot to a different claim that preserves the calibration's emotional value.

---

## 2. Step 1 — Is T1 still running?

Check process state:

```bash
ps -ef | grep -E "run_controller.py.*synth_t1_serpentine_20260425_200803" | grep -v grep
```

**If a process is found:** T1 is still running. **Do NOT write the postmortem yet.** Skip ahead to §6 (Still-running protocol) and stop.

**If no process is found:** T1 has exited. Continue to §3.

Also confirm the run was not killed prematurely. A clean exit means the controller wrote a final summary; a kill leaves the log truncated mid-cycle. Look at the tail of the log:

```bash
tail -50 logs/synth_signal/t1_serpentine_20260425_200803.log
```

A clean run will end with a `RUN COMPLETE` panel. A kill will end mid-cycle. A crash will end with a Python traceback.

---

## 3. Step 2 — Read the log for headline facts

These are the values you need for the postmortem template:

```bash
LOG=logs/synth_signal/t1_serpentine_20260425_200803.log

# Cycles completed
grep -c "CYCLE [0-9]*/30" "$LOG"
# or look at the highest cycle number that fired:
grep -oE "CYCLE [0-9]+/30" "$LOG" | sort -t' ' -k2 -n | tail -1

# Highest crib score reached at any point
grep -oE "crib[ _]?score[ =:]*[0-9]+" "$LOG" | grep -oE "[0-9]+" | sort -n | tail -5

# Any SIGNAL alerts fired
grep -i "SIGNAL\|BREAKTHROUGH\|alert" "$LOG" | head -20

# Any halt / fallback / infrastructure issues
grep -iE "halt|fallback|fatal|error|traceback" "$LOG" | head -10

# Any mention of SERPENTINE-as-keyword being attempted
grep -i "serpentine" "$LOG" | head -20

# Quagmire dispatches
grep -i "quagmire" "$LOG" | head -20
```

Record the answers; you'll need them for §3.3 of the spec.

---

## 4. Step 3 — Query the ledger

The DB is SQLite. Read-only queries are safe even if anything's still touching it (WAL mode).

```bash
DB=db/synth_t1_serpentine_20260425_200803.sqlite

# Schema
sqlite3 "$DB" ".tables"
sqlite3 "$DB" ".schema theories"

# Theory totals
sqlite3 "$DB" "SELECT COUNT(*) AS total FROM theories;"
sqlite3 "$DB" "SELECT status, COUNT(*) FROM theories GROUP BY status;"

# Highest crib score from experiments / scoring
sqlite3 "$DB" "SELECT MAX(crib_score) FROM experiments;" 2>/dev/null || true
sqlite3 "$DB" "SELECT * FROM experiments ORDER BY crib_score DESC LIMIT 5;" 2>/dev/null || true

# Alert events (the gate-bearing field)
sqlite3 "$DB" ".schema alert_events" 2>/dev/null || true
sqlite3 "$DB" "SELECT * FROM alert_events;" 2>/dev/null || true

# Whether SERPENTINE was ever a keyword in any DSL spec
sqlite3 "$DB" "SELECT title, summary FROM theories WHERE summary LIKE '%SERPENTINE%' OR title LIKE '%SERPENTINE%';"
```

Schema names may have shifted; if a query errors, run `.tables` and `.schema <table>` to find the equivalent. The kryptosbot DB is documented in `kryptosbot/database.py`.

---

## 5. Step 4 — Apply binding criteria from spec §1.1

These are locked; do not relax.

**T1 PASS** = at least one alert in the run with ALL of:
- `crib_score >= 18`
- `bean_passed = True`
- `ngram_per_char >= -4.0`
- `p_value_vs_null <= 1e-6`

**T1 FAIL** = no SIGNAL by cycle 60 (extension to 60 was preregistered; second extension forbidden).

**T1 INCONCLUSIVE** = infrastructure failure before cycle 30 (process killed for non-research reason, fatal kernel error, DB corruption). Re-run after fix; do NOT pool with new attempt.

**Caveat on the p-value gate:** the matched-family null cache is computed against real K4. Under synthetic CT it is *approximately* correct (length 97, same alphabet structure) — the spec §1.3 explicitly accepts this approximation. If SIGNAL fires with crib≥18 + bean + ngram but the architecture's p-value lookup misses or warns, treat the alert as a PASS provided the warning is the documented "fail-open" behavior, not a real null mismatch.

---

## 6. Step 5 — Write the postmortem

**Path:** `docs/maturation/round3/K4_SYNTHETIC_T1_POSTMORTEM.md`

**Template:** spec §3.3. Required fields:

- Outcome: PASS / FAIL / INCONCLUSIVE per §1.1 criteria
- `cycles_to_signal` (if PASS) or `cycles_at_halt` (if FAIL)
- DSL kind distribution across the run; compare to Campaign A (vigenere 12, columnar 8, grille 5, variant_beaufort 3, beaufort 1, polybius 1) and Campaign B (which added quagmire 4)
- Whether quagmire was dispatched at all, and how many times
- Whether the keyword `SERPENTINE` was attempted (verifiable in the theory ledger via the §4 grep)
- Theorist parse success rate, fallback rate, halt counters
- Any prompt-bug or DSL-coverage anomalies surfaced
- One-paragraph interpretation against `K4_STRATEGIC_RECONSIDERATION.md` §2 (Purpose A vs B) and §3 (stop conditions). Do this honestly per `feedback_accept_specific_disproofs.md`.

**Cross-reference the binding decision matrix in spec §4.** Map (T1 result, T2 not-yet-run) to the operative interpretation. Do NOT make up new cells.

If T1 PASSed: prepare the T2 launch command but do **NOT** launch it. Leave that for Colin.

```bash
# T2 launch command (PREPARE ONLY; do NOT execute without Colin's go-ahead)
PYTHONPATH=src python3 -u scripts/_infra/synth_signal/launch.py \
  --test-id t2_defector --cycles 100 --theories 5
```

T2 has three meaningful outcomes per spec §1.2:
1. PASS (architecture finds DEFECTOR on synthetic) — elimination scoping works correctly
2. FAIL via cycle exhaustion — standard miss, compare cycles to T1
3. FAIL via early rejection — architectural bug; the controller refuses to try DEFECTOR because of real-K4 elimination history. Detected by grepping red-team-disprover verdicts and CRITICIZED-stage theory-ledger entries for "DEFECTOR" + elimination tokens ("AUDIT", "do not", "eliminated", "exhaustively confirmed"). This outcome is high-value even though T2 "fails."

If T1 FAILed: do not prepare T2; the FAIL row of the decision matrix says T2 is moot.

---

## 7. Step 6 — Update memory

Update the project memo at `project_synthetic_signal_calibration_launched.md` (in the auto-memory store) to reflect outcome:

- If PASS: rename description from "LAUNCHED" to "T1 PASS — calibration data captured (cycles_to_signal=N)"
- If FAIL: rename to "T1 FAIL — no signal by cycle 60; scale-axis hypothesis weakened"
- If INCONCLUSIVE: rename to "T1 INCONCLUSIVE — re-run after fix, do not pool"

Also update the MEMORY.md index line for this entry. Do not delete the entry; just update the description.

---

## 8. Step 7 — Commit (no push)

The postmortem and memory updates can be committed locally. Commit message style matches recent project commits — use `synthetic signal:` as the scope prefix. Per `feedback_no_github_push.md`: do NOT push. Local commit only.

```bash
git add docs/maturation/round3/K4_SYNTHETIC_T1_POSTMORTEM.md
# (Memory updates are auto-tracked elsewhere; do not stage them here.)
git commit -m "synthetic signal: T1 (SERPENTINE) postmortem — <PASS|FAIL|INCONCLUSIVE>"
```

---

## §6 protocol — T1 still running at handoff time

If §2 found the controller still alive:

1. **Do NOT write the postmortem.** It would either be wrong (premature) or contaminate the binding outcome.
2. Read enough of the log to understand current state — cycles completed, max crib score, any halt/fallback signals.
3. Write a one-paragraph status note at `docs/maturation/round3/K4_SYNTHETIC_T1_STATUS_<TIMESTAMP>.md` with:
   - Cycle reached
   - Wall time elapsed since launch
   - Highest crib score so far
   - Any infrastructure anomalies
4. Tell Colin the run is still live; recommend coming back in ~4 hours OR when the dashboard / log shows the run wrapping up.
5. Do NOT abort, kill, or restart the run. The spec's INCONCLUSIVE outcome (re-run after fix; do NOT pool) means an interrupted run can't be cleanly resumed.

---

## Notes on the architecture this checklist assumes

- The DB and log are local-only artifacts on Colin's machine. If you're a remote agent (cloud-sandboxed), you cannot do this work. Decline and route back to a local Claude Code session.
- The kryptosbot/ package is gitignored by design (`feedback_kryptosbot_gitignored_by_design.md`); a remote checkout will not contain it. This checklist works only against the live local repo.
- The synthetic CT is bit-identical across runs (deterministic function of mechanism + keyword + canonical PT), so the manifest and synthetic_ct.txt should match the values in §0 of this checklist; if they don't, something rebuilt the bundle and the run is suspect.

---

*Checklist authored 2026-04-25 to bridge the launch session with whatever future session writes the postmortem. Self-contained by construction.*
