---
status: live
type: open_audits
owner_doc: MEMORY.md
---

# Methodological Audits — Open

This document surfaces **unresolved methodological disputes** that could
silently invalidate claims made elsewhere in the repo. Each audit item is a
claim, a concrete worry, and the condition that would close the audit.

Audits here are **not** research hypotheses. They are epistemic integrity
issues. They take precedence over new compute.

If you are about to act on a claim that appears in this file, **read the
relevant audit item first** and treat the claim as `disputed` until the audit
is closed.

---

## AUDIT-1 — "Source-independent Tier 1" wording for Bean-based column eliminations

**Status:** CLOSED 2026-04-09 (wording scope-corrected; see Closed section below)
**Raised:** 2026-04-09 (epistemic control-plane refactor)
**Affected claims:**

- `docs/elimination_tiers.md` Tier 1, rows for columnar w4 and w6/8/9
  ("Columnar (wN) + ANY additive key — SOURCE-INDEPENDENT")
- `docs/exhaustion_certificate_2026_04_08.md` §4–5
- `MEMORY.md` last-updated footer ("strengthened to source-independent Tier 1")
- Any downstream citation of "no source text of any length can produce a
  solution at widths {4,6,8,9}"

**The worry (in plain terms):**

The Tier 1 elimination says: under the full 242-inequality Bean constraint,
zero of the enumerated (column-ordering × {Vig,Beau,VarBeau}) pairs admit a
Bean-consistent keystream at widths 4, 6, 8, and 9. That is a correct
arithmetic statement about the 97-character carved ciphertext under the
direct-positional crib mapping.

The word **"SOURCE-INDEPENDENT"** is being used to mean *"no running-key
source text matters."* That is true within the tested cipher shape. It is
**not** a proof that no composed cipher of shape
`outer_transposition ∘ columnar ∘ additive` can solve K4, because:

1. The 242 Bean inequalities are derived from the 24 crib pairs under the
   assumption that `CT[i]` corresponds directly to the plaintext letter at
   crib position `i`. Any outer operation that rearranges the visible CT
   before the columnar step breaks that direct correspondence and the Bean
   inequalities no longer apply as derived.
2. "Columnar + any additive key" is a two-layer cipher. The Tier 1 claim
   eliminates that two-layer family under the carved-CT direct-positional
   mapping. It does **not** eliminate the three-layer family
   `outer ∘ columnar ∘ additive` under a non-direct mapping, even though
   the columnar + additive substructure is identical.
3. The word "source-independent" in current docs blurs (1) "independent of
   the choice of running-key source text" with (2) "independent of any
   assumption about how the crib positions map into the cipher." Only (1)
   is proven. (2) is not.

**Concrete risk:**

A fresh agent reading `elimination_tiers.md` may conclude that the entire
`columnar + additive` pattern is dead at widths {4,6,8,9} and skip composed
hypotheses that still nominally contain a columnar + additive substructure.
That is the exact kind of silent over-elimination this audit is meant to
prevent.

**What would close this audit:**

- Rewrite the relevant Tier 1 rows to state the assumption explicitly:
  *"under the direct-positional crib mapping `CT[i] → PT[i]`, no additive
  running key at widths {4,6,8,9} × columnar can produce a Bean-consistent
  keystream on the carved CT."*
- Replace "SOURCE-INDEPENDENT" with "running-key-source-independent
  (under direct-positional crib mapping)" or similar precise language.
- Add an explicit carve-out noting that the elimination does not cover
  composed ciphers where an outer layer precedes columnar on the CT.
- Update the claim registry entry `C-BEAN-01` below to `status: live` once
  the rewrite lands.

**Pointer into the claim registry:** `C-BEAN-01` (see
`docs/claims_registry.json`).

---

## AUDIT-2 — Retired palette material still cited by live artifacts

**Status:** CLOSED 2026-04-09 (downstream artifacts banner-demoted or tagged retired; see Closed section)
**Raised:** 2026-04-09 (epistemic control-plane refactor)

**The worry:**

The palette family was retired 2026-04-01 via the score-conditioned null
test (`docs/a1_score_conditioned_null_report.md`). However, several live
artifacts still reference it as if it were evidence:

- `docs/superpowers/specs/2026-03-23-stego-backward-propagation-design.md`
- `docs/superpowers/specs/2026-03-23-stego-layer-research-plan.md`
- `docs/superpowers/plans/2026-03-23-stego-backward-propagation.md`
- `docs/public_surface_map.md` rows for the palette docs
- `reports/audit_remediation_2026_04_01.md` (this one is correct — it
  *documents* the remediation — but downstream readers may misread it)
- `scripts/_infra/session_briefing.py` (search for `bcl_palette_keystream`)

**What would close this audit:**

- Each downstream file should either (a) drop the palette citation, (b) add
  an inline `[RETIRED 2026-04-01]` tag, or (c) link into `memory/retired/`
  with explicit retired framing.
- The session briefing script should either stop surfacing palette claims
  or mark them retired in its output.

---

## AUDIT-3 — `BREAKTHROUGH` / `bean_ok` label semantics

**Status:** OPEN — `documentation only`
**Raised:** 2026-04-09 (this refactor)

The scoring pipeline classifies `crib_score == 24 && bean_passed` as
`BREAKTHROUGH`. That label reads like *"potential solution."* In practice, on
this codebase, it has meant post-hoc overfit artifacts as often as genuine
candidates (see `MEMORY.md` DO NOT TEST list and `docs/claim_inventory.md`).

**What would close this audit:**

- Add a short note in `docs/invariants.md` and in
  `docs/README_current_state.md` explaining that the `BREAKTHROUGH` label is
  an *input to validation*, not an output of validation; it triggers the
  validation gates in CLAUDE.md §"Validation gates", it does not satisfy
  them.
- Optionally rename the label in `kernel/scoring/aggregate.py` to
  `ALL_CRIBS_MATCH` and keep `BREAKTHROUGH` as an alias.

The renaming is optional; the documentation note is mandatory for this
audit to close.

---

## Rules for this file

- An audit closes only when **every affected claim** listed under it has
  been explicitly rewritten, retired, or promoted.
- Closed audits move to an `## Closed` section at the bottom with a date
  and the commits that closed them, so the history is auditable.
- New audits must specify: raised-date, affected claims, concrete worry,
  and close condition. No vague audits.

---

## Closed

### AUDIT-1 — CLOSED 2026-04-09

**Resolution:** scope-corrected the "SOURCE-INDEPENDENT" wording in every load-bearing doc that carried it. The claim is preserved in its exact justified form ("running-key-source-independent within the analyzed cipher class: columnar w∈{4,6,8,9} × Vig/Beau/VarBeau on the carved CT under direct positional crib mapping") and rejected in its overclaimed form ("universal impossibility across all composed ciphers").

**Edits that closed the audit:**

- `docs/elimination_tiers.md` — Tier 1 assumptions section gained a new assumption 3 ("direct positional crib mapping") and a dedicated "Scope of 'source-independent' wording" paragraph. The three affected rows (w6/8/9 Bean, w4 Bean, Tier 2 running-key row) were rewritten to use "running-key-source-independent within the analyzed class" and to list what is **not** eliminated (composed ciphers with outer layers preceding columnar, non-additive keystreams, cipher classes that break direct positional crib mapping).
- `docs/exhaustion_certificate_2026_04_08.md` — §4 block quote, §9.1, and §11 bullet 1 all rewritten with the narrower scope.
- `docs/admissibility_architecture.md` — "Empirical status at revocation" block rewritten.
- `docs/c1_downgrade_basis_note_2026_04_08.md` — three passages rewritten.
- `docs/claims_registry.json` — `C-BEAN-01` flipped from `disputed` to `live` with narrower `scope` and corrected `statement`.
- `MEMORY.md` — "Hard Blocker 3" language adjusted.
- `docs/README_current_state.md` — removed the "currently being audited" stub reference.

**Residue:** None in the load-bearing docs. If a future reader finds any remaining instance of unscoped "SOURCE-INDEPENDENT" in a live doc under `docs/` or `MEMORY.md`, treat it as a bug and open a new audit item.

### AUDIT-2 — CLOSED 2026-04-09

**Resolution:** the downstream live artifacts that still referenced retired palette material have been either (a) banner-demoted as pre-retirement historical research plans, or (b) explicitly tagged "retired" in-place where the citation was in an audit-tracking table.

**Edits that closed the audit:**

- `docs/superpowers/README.md` — new README marking the entire directory as historical research planning material authored in March 2026, before the 2026-04-01 palette retirement. Any palette-dependent stego plan in the directory is historical-only.
- `docs/superpowers/specs/2026-03-23-stego-backward-propagation-design.md` — HISTORICAL/PALETTE-DEPENDENT banner prepended.
- `docs/superpowers/specs/2026-03-23-stego-layer-research-plan.md` — same.
- `docs/superpowers/plans/2026-03-23-stego-backward-propagation.md` — same.
- `docs/public_surface_map.md` — Tier 4 rows updated to point at the retired paths under `memory/retired/` and labelled retired.
- `scripts/_infra/session_briefing.py` — NULL_PALETTE line in §"CRITICAL CONSTANTS" tagged retired; new §"DISPUTED & RETIRED CLAIMS" pulled from `docs/claims_registry.json`; existing "RETIRED ANOMALIES" section left in place (it was already correctly bucketed).

**Residue:** several other March-2026 palette-dependent files under `docs/superpowers/` are covered by the directory README but do not carry per-file banners. This is intentional — the directory README is sufficient for the remaining files because none of them are cited from current live docs as evidence. If any of them is later promoted back toward live status, it needs its own banner or rewrite first.
