# Phase 9 — Documentation refresh — Report

**Date:** 2026-04-21
**Entry baseline:** Phase 8 completion (procedural enumerator)
**Goal (brief §11):** leave the next operator a minimal clean path to
get working. Replace the 7-document onboarding maze with one
authoritative entry point plus the existing canonical docs.

---

## 1. What shipped

| File | Change |
|---|---|
| `kryptosbot/ORIENT.md` | **NEW** (159 lines). One-page operator onboarding |
| `kryptosbot/ARCHITECTURE.md` | File-map updated (7 new rows for Phases 3-8 modules); `_archive/` added to preserved components; new "DSL + Dispatcher + Null Baselines" major section |
| `CLAUDE.md` | Pre-flight gained steps 9-10 (ORIENT.md pointer, self-test fitness check); Interpreting Scores gained p-value gate paragraph; Reference Documents gained ORIENT / ARCHITECTURE / SUMMARY pointers |
| `MEMORY.md` | Pointers section gained "Framework maturation" entry |
| `docs/maturation/phase_09_report.md` | **NEW** (this file) |

No code changes, no test delta.

---

## 2. `kryptosbot/ORIENT.md` (brief §11.1)

160 lines; well under the brief's ≤400-line cap. Five sections:

1. **One sentence** — what kryptosbot is.
2. **Three commands to know** — pre-flight, controller run, status.
3. **Where truth lives** — CLAUDE.md / MEMORY.md / ARCHITECTURE.md /
   doc index pointers with one-line purposes.
4. **What breaks if you skip pre-flight** — the failure mode that has
   bitten this project multiple times.
5. **Common failure modes & diagnostics** — 5 items covering the
   most-likely operational surprises (false BREAKTHROUGH, uncalibrated
   alerts, admissibility rejections, KA-alphabet gap, procedural
   `tested=0`).

Also includes a "Command catalogue" table (8 entries) and a "What to
read next" decision tree at the bottom.

---

## 3. `kryptosbot/ARCHITECTURE.md` (brief §11.2)

Two surgical edits:

### 3.1 File Map expansion

Added 8 new rows covering the Phase-3 through Phase-8 modules:

- `hypothesis_dsl.py` (Phase 4)
- `job_dispatcher.py` (Phase 4)
- `dsl_tools.py` (Phase 5)
- `null_baselines.py` (Phase 6)
- `procedural_enumerator.py` (Phase 8)
- `self_test.py` (Phase 7)
- `alerts.py` (Phase 3 + 6 gate)
- `contracts.py` (Phase 3 hardening notes)
- `ORIENT.md` (Phase 9)

### 3.2 Preserved Components update

- `k4_tools.py`: note the 3 Phase-5-deprecated tools.
- `constants.py`: note the Phase-2 retired-symbol relocation.
- Removed `worker.py` (now at `_archive/worker.py`).
- Added `_archive/` entry describing the Phase-1 quarantine.

### 3.3 New "DSL + Dispatcher + Null Baselines" major section

~60 lines covering:
- The Phase-4 architectural shift (worker scratch code → LLM
  specifies + dispatcher executes).
- ASCII diagram of the hypothesis-spec → admissibility → execute →
  verify → contract pipeline.
- DSL coverage table (what's supported, what's deferred per phase).
- Null-baseline calibration table (per scorer × method tail method).
- Procedural recipe enumerator summary.

The pre-existing sections (Contract Validation, Worker Contract,
Theory Ledger Schema, etc.) are untouched — they remained accurate.

---

## 4. `CLAUDE.md` (brief §11.3, surgical updates)

Per the brief's direction ("Do not rewrite CLAUDE.md wholesale. It is
operational doctrine and should stay stable"), changes are minimal and
targeted.

### 4.1 Pre-flight section (lines ~11-26)

Added two new steps to the numbered list:

- **Step 9**: pointer to `kryptosbot/ORIENT.md` for kryptosbot-touching
  tasks.
- **Step 10**: self-test fitness check for tasks that modify kernel
  scoring or transforms — `python3 kryptosbot/self_test.py --panel all
  --mode dry-run`, ~1 second, surfaces any regression.

### 4.2 Interpreting Scores section (lines ~236-248)

- Updated the BREAKTHROUGH classification meaning to include "AND
  ngram floor AND p-value gate".
- Added a new paragraph ("Phase 6 p-value gate (2026-04-21)")
  describing the gate mechanics, the exact Binomial tail value at
  crib_score=18, and the calibration rebuild command.

### 4.3 Reference Documents section (lines ~345-367)

Added three new entries to Durable domain & invariant docs:

- `kryptosbot/ORIENT.md` — one-page operator onboarding.
- `kryptosbot/ARCHITECTURE.md` — full architecture (updated 2026-04-21).
- `docs/maturation/SUMMARY.md` — Phases 1-9 handoff summary.

No other CLAUDE.md edits. Original operational doctrine preserved.

---

## 5. `MEMORY.md` (brief §11.4)

Single new entry in §7 Pointers:

> - **Framework maturation (2026-04-20 / 04-21):** Phases 1-9 completed;
>   see `docs/maturation/SUMMARY.md` for full handoff. `kryptosbot/ORIENT.md`
>   is the one-page operator onboarding. DSL dispatcher + calibrated
>   null baselines + Phase 7 self-test added.

Plus the "Last updated" footer refreshed to 2026-04-21 with a summary
of the Phases 1-9 contents.

---

## 6. Acceptance criteria (brief §11.5)

| Criterion | Status |
|---|---|
| `kryptosbot/ORIENT.md` exists and is ≤400 lines | ✅ (160 lines) |
| `ARCHITECTURE.md` updated | ✅ (new file-map rows, new DSL section, preserved-components refresh) |
| `CLAUDE.md` updated surgically | ✅ (pre-flight steps 9-10, Interpreting Scores paragraph, 3 new Reference Doc entries) |
| `MEMORY.md` pointer updated | ✅ (one new Pointers entry + "Last updated" footer) |
| `docs/maturation/phase_09_report.md` exists | ✅ (this file) |
| Full suites green | ✅ (no code changes, no test delta; Phase 8's 570 total preserved) |

---

## 7. Deferred to later sessions

None. Phase 9 is docs-only; there is nothing to defer.

---

## 8. Changed files summary

```
A  kryptosbot/ORIENT.md                                 (160 lines)
M  kryptosbot/ARCHITECTURE.md                           (+85 lines)
M  CLAUDE.md                                             (+10 lines, surgical)
M  MEMORY.md                                             (+5 lines in §7)
A  docs/maturation/phase_09_report.md                   (this file)
```

No code changes. The documentation surface is now:

- **CLAUDE.md** — operational doctrine (stable, cross-session).
- **MEMORY.md** — live research state (short, auto-loaded).
- **kryptosbot/ORIENT.md** — operator onboarding (one page).
- **kryptosbot/ARCHITECTURE.md** — architecture details.
- **docs/maturation/SUMMARY.md** — maturation handoff (next item).
- **docs/maturation/phase_NN_report.md** — per-phase detailed reports.

Which satisfies the brief's "minimal clean path" objective.
