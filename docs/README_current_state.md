---
status: live
type: canonical_entry_index
last_updated: 2026-06-11
---

# Current State — Canonical Entry Index

> **Public readers:** the one-document status read is
> [`docs/REAL_K4_CURRENT_POSITION.md`](REAL_K4_CURRENT_POSITION.md)
> (updated 2026-06-11: May–June empirical record, gap-register status,
> live leads). The plain-language version is on
> [kryptosbot.com/findings](https://kryptosbot.com/findings/). Items
> below that reference `MEMORY.md` or the session briefing refer to
> agent-session state that exists on the research machine, not in this
> repository.

**If you are a fresh agent landing in this repo, this is the file to start with
after `CLAUDE.md`.** It tells you where *live* state lives and how to
distinguish it from historical or retired material.

---

## 1. The live path (read in this order)

1. **`CLAUDE.md`** — operational doctrine only (pre-flight, architecture,
   commands, invariants, truth taxonomy, compute policy). Does not describe
   what we currently believe about K4.
2. **Session briefing** — authoritative derived state, always fresh:
   ```bash
   PYTHONPATH=src python3 scripts/_infra/session_briefing.py
   ```
3. **`MEMORY.md`** — live control document: current project state, hard
   blockers, active bins, stop conditions, open audits, do-not-revive list.
   Short by design.
4. **`docs/claims_registry.json`** — structured seed registry of major
   live, disputed, retired, and historical-snapshot claims.
5. **`docs/methodological_audits.md`** — open epistemic audits. These take
   precedence over new compute.
6. **`docs/elimination_tiers.md`** — elimination landscape. Tier 1
   assumptions now explicitly include "direct positional crib mapping"
   and the "source-independent" wording is scope-corrected (AUDIT-1
   closed 2026-04-09). Every Bean-based Tier 1 row is read as
   *"within the analyzed cipher class, under the stated assumptions"*
   — not as a universal impossibility claim.
7. **`docs/exhaustion_certificate_2026_04_08.md`** — latest exhaustion
   certificate.
8. **`docs/preregistered_thresholds_2026_04_08.md`** — thresholds for the
   final honest search window.
9. **`docs/exhaustion_audit_2026_04_08.md`** — Team of Rivals audit board.

---

## 2. Historical / retired material (do not mistake for live)

| Path | What it holds | How to read it |
|------|---------------|----------------|
| `docs/history/` | Historical strategy snapshots, status reports | Traceability only. Each file carries a HISTORICAL SNAPSHOT banner. |
| `reports/final_synthesis.md` | 2026-02-20 multi-agent campaign synthesis | Kept at original path for link stability; carries in-file HISTORICAL SNAPSHOT banner. |
| `memory/retired/` | Retired research notes (palette/null-mask family) | Quarantined. See `memory/retired/README.md`. Do not cite as evidence. |
| `docs/retired_claims/` | Landing page for retired claims | Pointer into `memory/retired/`. |

**Rule:** nothing in these paths should be promoted back into the live path
without an explicit rehabilitation entry in `docs/claims_registry.json`
and an audit close in `docs/methodological_audits.md`.

---

## 3. Live vs disputed vs retired — quick classifier

| If the claim... | ...treat it as |
|-----------------|----------------|
| Appears in the session briefing output | Live derived state |
| Appears in `MEMORY.md` current-state section | Live volatile state |
| Appears in `docs/claims_registry.json` with `status: live` | Live structured claim |
| Appears in `docs/claims_registry.json` with `status: disputed` | **Stop; read the matching audit item in `docs/methodological_audits.md`** |
| Appears in a file under `memory/retired/` or `docs/history/` | Historical/retired — do not cite |
| Uses language like "breakthrough", "strongest evidence", or "proven impossible" without a matching registry entry | **Treat as suspect** and check the registry + audits before acting |
| Uses "source-independent" without an explicit cipher-class scope | **Treat as suspect**: the only justified usage is *"running-key-source-independent within the analyzed cipher class"* — see `C-BEAN-01` and AUDIT-1 (closed) |

---

## 4. The "BREAKTHROUGH" label is not what it sounds like

The scoring pipeline emits the label `BREAKTHROUGH` when `crib_score == 24`
and `bean_passed`. On this codebase that label has historically been emitted
by post-hoc overfits at least as often as by real candidates.

**`BREAKTHROUGH` is an input to the validation gates in `CLAUDE.md`
§"Validation gates", not an output of them.** A `BREAKTHROUGH`-labelled
result that has not passed unit tests + reference-implementation reproduction
+ invariant checks + clean-interpreter reproduction is a **candidate for
investigation**, not a solution. See `docs/methodological_audits.md` AUDIT-3.

---

## 5. When live state and memory disagree

Live state wins. In order:

1. Session briefing output (derived from current data)
2. `MEMORY.md` current-state section
3. `docs/claims_registry.json`
4. `docs/methodological_audits.md`
5. Everything else

If you encounter an apparent contradiction you cannot resolve, add it as a
new audit item in `docs/methodological_audits.md` and mark the affected
claim `disputed` in the registry.
