# Phase 1 — Legacy-surface quarantine — Report

**Date:** 2026-04-20
**Entry baseline:** `5ad398d wip: pre-maturation baseline ...`
**Goal:** stop the framework from tripping new contributors (and future-you) on dead code
paths. No behaviour change for the live controller.

---

## 1. Dead-import confirmation (brief §3.1)

All five modules probed in the brief raise `ModuleNotFoundError`:

| Module | Status | Notes |
|---|---|---|
| `kryptosbot.analyst_prompts` | **MISSING** | Imported by `kryptosbot/campaign_v2.py:38`; confirmed broken. |
| `kryptosbot.framework_strategies` | **MISSING** | Imported by `kryptosbot/worker.py:23`; confirmed broken. |
| `kryptosbot.strategies` | **MISSING** | No live importer found. |
| `kryptosbot.solve` | **MISSING** | Referenced only by CLAUDE.md §Multi-Agent Mode (L401) and `docs/operations.md:10`. |
| `kryptosbot.monitor` | **MISSING** | No live importer found. |

Files physically present but importing broken dependencies:

- `kryptosbot/campaign_v2.py` — imports `kryptosbot.analyst_prompts`. **QUARANTINED.**
- `kryptosbot/worker.py` — imports `kryptosbot.framework_strategies` (relative). **QUARANTINED.**

Files referenced in stale doctrine but already absent from the tree (pre-existing gap):
- `kryptosbot/solve.py`, `kryptosbot/monitor.py`, `kryptosbot/strategies.py`,
  `kryptosbot/framework_strategies.py`, `kryptosbot/analyst_prompts.py`.

---

## 2. Quarantine moves (brief §3.2)

New directory `kryptosbot/_archive/` created with an explanatory `__init__.py`.

| From | To | Mechanism |
|---|---|---|
| `kryptosbot/campaign_v2.py` | `kryptosbot/_archive/campaign_v2.py` | `git mv` (preserves history) |
| `kryptosbot/worker.py` | `kryptosbot/_archive/worker.py` | `git mv` (preserves history) |

Each original path now holds a 16-line stub that raises `ImportError` with a pointer to
`run_controller` / `agent_runner` and a pointer to the archived source. Verified:

```bash
$ python3 -c "import kryptosbot.campaign_v2"
ImportError: kryptosbot.campaign_v2 is deprecated ...
$ python3 -c "import kryptosbot.worker"
ImportError: kryptosbot.worker is deprecated ...
$ python3 -c "import kryptosbot._archive"
(silent — package import only; individual modules under _archive not imported)
```

`kryptosbot/_archive/__init__.py` documents the directory as "do not import."

---

## 3. Stale exhaustion log retired (brief §3.3)

| Action | Path |
|---|---|
| Renamed | `scripts/EXHAUSTION.json` → `scripts/EXHAUSTION.json.RETIRED` |
| New file | `scripts/EXHAUSTION.json.RETIRED.README` (one-paragraph pointer) |

Authoritative log remains `exhaustion_log.json` at repo root (unchanged). Three live
references to the old path were surveyed:

| Location | Nature | Action |
|---|---|---|
| `scripts/_infra/session_briefing.py:576` | Pitfall warning string (`"NOT scripts/EXHAUSTION.json"`) | Left unchanged — the warning is correct. |
| `docs/maturation/phase_00_briefing.txt:221` | Same string, captured artifact | N/A — artifact, not code. |
| `CLAUDE.md:181` | Doctrine sentence mentioning the old path | **Defer to Phase 9 surgical doctrine updates.** |

No code path reads the retired file.

---

## 4. Doctor `bean_count` check fixed (brief §3.4)

`src/kryptos/cli/doctor.py` line ~35 previously asserted
`len(BEAN_EQ) == 1 and len(BEAN_INEQ) == 21`. The `21` was the pre-2025 inequality count;
the canonical count became 242 when the 101 Bean linear constraints were added. The check
has silently failed for months (CLAUDE.md §Key Gotchas documents this as a known bug).

**Fix:** split into three explicit checks pinned to the canonical values from
`kernel/constants.py`, with an inline comment explaining the expansion protocol:

```python
checks.append(("bean_eq_count",     len(BEAN_EQ)     == 1,   f"n={len(BEAN_EQ)}"))
checks.append(("bean_ineq_count",   len(BEAN_INEQ)   == 242, f"n={len(BEAN_INEQ)}"))
checks.append(("bean_linear_count", len(BEAN_LINEAR) == 101, f"n={len(BEAN_LINEAR)}"))
```

Canonical values confirmed at import: `len(BEAN_EQ)=1`, `len(BEAN_INEQ)=242`,
`len(BEAN_LINEAR)=101`. [DERIVED FACT]

**Post-fix `doctor` output:** 20 PASS, 0 FAIL, exit 0.

**New test:** `tests/test_doctor.py` calls `run_doctor(verbose=False)` and asserts it
returns True. Guards against regressions.

---

## 5. `kryptosbot/RUNBOOK.md` replaced with stub (brief §3.5)

**Unexpected finding:** the original 280-line `kryptosbot/RUNBOOK.md` was gitignored
(`.gitignore:84`) and never tracked. Existing in-repo links
(e.g. `CLAUDE.md:401 "See kryptosbot/RUNBOOK.md"`) therefore 404'd on any fresh clone.

**Action:** removed `kryptosbot/RUNBOOK.md` from `.gitignore`, replaced the local 280-line
file with the brief's 5-line stub pointing to `ORIENT.md` (to be written in Phase 9),
`ARCHITECTURE.md`, and `MEMORY.md`. Stub will land in the repo with the Phase 1 commit.

Note: the separate `ops/RUNBOOK.md` (gitignored at `.gitignore:61`) is untouched — it is
out of the brief's scope (operations, not kryptosbot runtime). Left for future hygiene.

---

## 6. Acceptance criteria (brief §3.6)

| Criterion | Status |
|---|---|
| `python3 -c "import kryptosbot.campaign_v2"` raises `ImportError` with our message | ✅ |
| `PYTHONPATH=src python3 -m kryptos doctor` exits 0 with zero failures | ✅ (20 PASS) |
| `PYTHONPATH=src pytest tests/ -q` green | ✅ (**1522 passed**, +1 from baseline) |
| `PYTHONPATH=src pytest kryptosbot/tests/ -q` green | ✅ (364 passed) |
| `docs/maturation/phase_01_report.md` exists | ✅ (this file) |
| Single clean phase commit | (forthcoming) |

---

## 7. Deferred items (not Phase 1 scope)

Tracked for later-phase work:

### Phase 9 (doctrine surgical updates)

1. **`CLAUDE.md:401`** — "KryptosBot runner: `python3 kryptosbot/solve.py`. See
   `kryptosbot/RUNBOOK.md`." Both references are now broken: `solve.py` has never existed
   in the current tree, and RUNBOOK.md is now a stub pointing to ORIENT.md.
2. **`CLAUDE.md:402`** — "Campaign runner: `PYTHONPATH=src python3 -u
   kryptosbot/campaign_v2.py`." Stub at that path now raises `ImportError`.
3. **`CLAUDE.md:181`** — sentence mentioning the stale `scripts/EXHAUSTION.json` as
   authoritative-relative-to-this.
4. **`docs/operations.md:9-11`** — three lines describing `campaign_v2.py` as an
   "Active campaign runner" and listing `solve.py`, `monitor.py`, `strategies.py` as
   "preserved components."

### Future hygiene (unscheduled)

5. `scripts/vm_capability_report.sh:198` — `VCPUS: unbound variable` bug; `--json` mode
   fails. Unrelated to this brief.
6. `ops/RUNBOOK.md` — gitignored separate file, 404s on fresh clone. Separate scope.

---

## 8. Changed files summary

```
A  docs/maturation/phase_00_briefing.txt       (Phase 0 artifact)
A  docs/maturation/phase_00_inventory.txt      (Phase 0 artifact)
A  docs/maturation/phase_00_preflight.md       (Phase 0 report)
A  docs/maturation/phase_01_report.md          (this file)
M  .gitignore                                  (unignore kryptosbot/RUNBOOK.md)
M  src/kryptos/cli/doctor.py                   (bean_count → bean_eq/ineq/linear pins)
A  tests/test_doctor.py                        (regression guard)
R  kryptosbot/campaign_v2.py → kryptosbot/_archive/campaign_v2.py
A  kryptosbot/campaign_v2.py                   (16-line ImportError stub)
R  kryptosbot/worker.py      → kryptosbot/_archive/worker.py
A  kryptosbot/worker.py                        (16-line ImportError stub)
A  kryptosbot/_archive/__init__.py             (package doc)
A  kryptosbot/RUNBOOK.md                       (5-line stub pointing to ORIENT.md)
R  scripts/EXHAUSTION.json → scripts/EXHAUSTION.json.RETIRED
A  scripts/EXHAUSTION.json.RETIRED.README      (one-paragraph pointer)
```

Net line delta: +~180 lines of stubs/docs, −576 lines (the archived modules shift paths so
don't count as deletions, but the 280-line RUNBOOK replacement does).

No behaviour change to the controller, kernel, or any production path. All test suites green.
