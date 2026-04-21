# ORIENT.md — how to operate kryptosbot

**Last updated:** 2026-04-21 (framework maturation Phase 9)
**Target audience:** anyone (including future-you) who just walked into this repo

---

## 1. One sentence

`kryptosbot/` is a multi-agent research loop that enumerates bounded
cryptanalytic hypotheses against Kryptos K4 and runs them through the
kernel at `src/kryptos/`.

---

## 2. Three commands to know

```bash
# 1. PRE-FLIGHT — do this every session BEFORE anything else
PYTHONPATH=src python3 -m kryptos doctor
PYTHONPATH=src python3 scripts/_infra/session_briefing.py
PYTHONPATH=src pytest kryptosbot/tests/ -q

# 2. RUN the controller (real API — costs money)
PYTHONPATH=src python3 kryptosbot/run_controller.py

# 3. STATUS — what's the research landscape?
PYTHONPATH=src python3 scripts/_infra/session_briefing.py
```

There are more commands — `procedural_enumerator`, `self_test`,
`calibrate_null_baselines` — but the three above are what you reach
for first. See §6 for the wider catalogue.

---

## 3. Where truth lives

| Doc | Purpose |
|---|---|
| `CLAUDE.md` at repo root | Operational doctrine for any Claude session. Pre-flight, code standards, truth taxonomy, compute policy. Stable; rarely edited. |
| `MEMORY.md` at repo root | Live control document. Current state, hard blockers, active bins, open audits, do-not-revive list. **Always loaded** into Claude sessions. Short by design. |
| `kryptosbot/ARCHITECTURE.md` | Architecture of the kryptosbot research loop: controller cycle, DSL + dispatcher, null baselines, alert path. Updated 2026-04-21 for Phases 4-6. |
| `kryptosbot/ORIENT.md` | This file. One-page operator onboarding. |
| `docs/README_current_state.md` | Canonical entry index for live research state. |
| `docs/claims_registry.json` | Structured live / disputed / retired / historical claims. |
| `docs/methodological_audits.md` | Open epistemic audits. A disputed claim blocks new compute until its audit closes. |
| `docs/elimination_tiers.md` | Elimination confidence tiers. **Tier-1 / Tier-2** are single-layer-only — they do NOT kill multi-layer hypotheses. |
| `docs/procedural_recipes.json` | Structured recipe source (~17 entries); the procedural enumerator's input. |
| `docs/maturation/` | Phases 1-9 reports. `SUMMARY.md` is the handoff document. |

**Key rule:** research truth lives in `MEMORY.md` + `docs/`. Operational
doctrine lives in `CLAUDE.md`. `kryptosbot/` is an execution layer; it
describes how research *runs*, not what research has *found*.

---

## 4. What breaks if you skip pre-flight

Skipping pre-flight is the #1 way to re-test an eliminated hypothesis
and burn compute or API tokens for zero value.

- `kryptos doctor`: if the bean_count check fails, the kernel constants
  have drifted and every downstream scoring call is suspect.
- `session_briefing.py`: surfaces the live DO-NOT-TEST list + open
  anomalies. Without it you don't know what's in-scope.
- `pytest kryptosbot/tests/`: surfaces any regression in the verifier,
  dispatcher, or alert gate. If this is red, you CANNOT trust alert
  output from the controller.

Pre-flight takes ~2 minutes total. Saving 2 minutes here has cost
this project multi-day re-test cycles in the past.

---

## 5. Common failure modes & diagnostics

### 5.1 Controller reports a BREAKTHROUGH in the first cycle

Almost certainly a false positive. Check in order:

1. `contract.fields_overwritten` — if True, the kernel verifier already
   overruled a worker self-report. The alert should not have fired.
2. `contract.worker_self_report` — shows what the worker claimed.
   Usually `crib_score=24, bean_passed=True` despite a PT that scores 0.
3. `null_baselines/manifest.json` — confirm the p-value gate is
   calibrated on this kernel commit. If it shows a different commit,
   run `scripts/_infra/calibrate_null_baselines.py`.
4. Per-scorer p-value — for a real signal, crib_score=24 under
   random_text gives p ≈ 10⁻³⁴. If the logged p-value is larger, the
   calibration is misaligned (but the result still shouldn't pass the
   ngram-floor check).

### 5.2 "Alert is UNCALIBRATED" WARNING in the log

The null baseline cache is missing. This is not a bug — it's the
designed fail-open: the alert degrades to pre-Phase-6 crib-score-only
gating so no high score goes silent. To re-enable p-value gating:

```bash
PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines.py
```

Full run is ~18 seconds. Commits the manifest; the full cache lands
gitignored under `results/null_baselines/`.

### 5.3 Dispatcher rejects a spec with "exhaustion overlap"

The dispatcher's `_exhaustion_overlap` heuristic substring-matches the
spec's cipher kinds against `exhaustion_log.json` family fields.
Frequent false positives for common families (vigenere, beaufort,
columnar all overlap something). Workarounds:

- In a test, pass `exhaustion_log={}` to `execute(spec, exhaustion_log={})`.
- In production, the admissibility-reject reason is logged verbatim so
  an operator can override by confirming the prior entry doesn't
  actually cover the current spec and re-running with `exhaustion_log={}`.
- See `kryptosbot/job_dispatcher.py::_exhaustion_overlap` for the
  heuristic's exact logic.

### 5.4 Worker crashes with "alphabet 'KA' not supported in Phase 4 dispatcher"

The Phase 4 DSL dispatcher only handles AZ alphabet for Vigenère-family
layers. Theorist proposed a KA / Quagmire III hypothesis; dispatcher
rejects at admissibility time with a clear pointer. Fix: either the
theorist routes through a different cipher family, or the operator
extends `_translate_layer` with a Quagmire III case. The Phase-7
self-test notes this as a known gap (report §6.1).

### 5.5 Procedural sweep returns `tested=0` on several recipes

Admissibility rejection due to the same exhaustion-overlap heuristic as
§5.3. The dispatcher writes a JSON artifact even when admissibility
rejects, so the rejection reason is auditable. To force-run an
admissibility-rejected recipe, run it directly:

```python
from kryptosbot.job_dispatcher import execute
from kryptosbot.procedural_enumerator import load_recipes, recipe_to_spec
spec = recipe_to_spec(next(r for r in load_recipes() if r.recipe_id == "P-E0e-1a"))
result = execute(spec, exhaustion_log={})   # skip the overlap check
print(result.to_dict())
```

---

## 6. Command catalogue

| Command | What it does |
|---|---|
| `kryptos doctor` | Environment sanity — constants, alphabets, Bean counts, kernel imports |
| `scripts/_infra/session_briefing.py` | Live research state summary |
| `kryptosbot/run_controller.py` | Main research loop (real API) |
| `kryptosbot/self_test.py --panel all --mode dry-run` | K1/K2/K3 rediscovery benchmark (no API) |
| `kryptosbot/procedural_enumerator.py --dry-run` | List admissible procedural recipes |
| `kryptosbot/procedural_enumerator.py --sweep` | Dispatch all admissible procedural recipes |
| `scripts/_infra/calibrate_null_baselines.py` | Build the null-baseline cache |
| `run_attack.py --exhaustion-summary` | Summarise the experiment-script exhaustion log |

All commands take `PYTHONPATH=src`. Scripts that write to `results/`
are safe to run repeatedly — the results directory is gitignored.

---

## 7. What to read next

- If you're fixing a bug in the kernel: start with `CLAUDE.md` §Architecture.
- If you're adding a new cipher family: `kryptosbot/ARCHITECTURE.md`
  §DSL + dispatcher.
- If you're doing cryptanalytic research: `MEMORY.md` first, then
  `docs/methodological_audits.md` for open audits.
- If you're reviewing what changed in the past quarter's maturation:
  `docs/maturation/SUMMARY.md`.
