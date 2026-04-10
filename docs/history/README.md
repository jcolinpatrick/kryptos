---
status: historical_snapshots_index
type: pointer
---

# `docs/history/` — Historical Strategy Snapshots

This directory holds **historical snapshots** of project strategy, status
reports, and research posture. Files here were authoritative at the time they
were written but have since been **superseded**.

**They are not current doctrine.** Do not use them to drive new work.

## Where current doctrine lives

If you want the current state of the project, go here instead:

1. **Run the session briefing** (authoritative derived state):
   ```bash
   PYTHONPATH=src python3 scripts/_infra/session_briefing.py
   ```
2. **`MEMORY.md`** (live control document, repo root).
3. **`docs/README_current_state.md`** (canonical index of live docs).
4. **`docs/claims_registry.json`** (structured live/retired/disputed claims).
5. **`docs/methodological_audits.md`** (open audits).

## Contents

| File | Snapshot date | Superseded by | Notes |
|------|---------------|---------------|-------|
| `status_report_2026_03_22.md` | 2026-03-22 | MEMORY.md + `docs/exhaustion_audit_2026_04_08.md` + `docs/exhaustion_certificate_2026_04_08.md` | Describes a pre-composition-campaign posture; predates the v1+v2+v3 composition results, the score-conditioned null retirement of the palette family, and the Team of Rivals exhaustion audit. Some quantitative claims (script counts, config counts, "strongest anomaly" language) are now stale or retired. |

## Sibling historical references (kept in place for link stability)

Some historical documents are **not** moved here because they are referenced
from many live docs (e.g. `reports/final_synthesis.md`, dated 2026-02-20).
Those files carry an in-place HISTORICAL SNAPSHOT banner at the top. Treat
them the same way: traceability only, not live doctrine.

## Rules

- Do not cite a file in `docs/history/` as current evidence.
- Do not revive a strategy framing from a historical snapshot without first
  checking whether it has been explicitly superseded in MEMORY or
  `docs/methodological_audits.md`.
- If you find a direct contradiction between a historical snapshot and
  current live doctrine, **current live doctrine wins** and the
  contradiction should be logged as an audit item.
