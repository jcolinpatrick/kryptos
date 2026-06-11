---
status: quarantine index
type: retired_claims_index
---

# `memory/retired/` — Quarantine for Retired Research Notes

This directory holds research notes whose core construct has been **retired**.
Documents here are kept for traceability only. They are **not** live doctrine,
**not** authoritative, and **not** valid inputs to new hypotheses or compute.

If you are a fresh agent and you landed in a file under this directory, **stop
and read this index first** before citing anything from the file itself.

## Epistemic rules for this directory

- Nothing under `memory/retired/` may be used to justify a new compute swing.
- Nothing under `memory/retired/` may be cited as current evidence in reports,
  public copy, or the claim registry except with an explicit `status: retired`.
- Any file in this directory must carry a top-of-file RETIRED banner plus
  YAML frontmatter naming the superseding document.
- If you find live content that still implicitly depends on a retired construct,
  treat that as a **contradiction to resolve** and surface it in
  `docs/methodological_audits.md`.

## Current contents (palette / null-mask family, retired 2026-04-01)

| File | Retired reason | Superseded by |
|------|----------------|---------------|
| `palette_deep_investigation.md` | Core palette {B,G,I,K,O,W,Z} identified by SA optimization on the data it was then tested against — post-hoc selection. | `docs/a1_score_conditioned_null_report.md` |
| `bcl_palette_keystream.md` | "Model-independent" framing was Beaufort-A=0 specific; enrichment dissolves under score-conditioned null. | `docs/a1_score_conditioned_null_report.md`, `docs/claim_inventory.md` row 1 |
| `palette_mod35_rule.md` | "35/35 PERFECT" was in-sample post-hoc fit; LOO-CV ≈ 47%. | `docs/claim_inventory.md` row 4, `docs/audit_remediation_2026_04_01.md` |
| `palette_null_separator.md` | Separator statistic inherits the retired palette definition. | `docs/a1_score_conditioned_null_report.md` |
| `polybius_row_selection.md` | KRYPTOS×SEVEN row-selection model is built on top of the retired 7-letter palette. | `docs/a1_score_conditioned_null_report.md` |

## Why not delete them?

Because retired findings are useful negative evidence: future agents need to be
able to reconstruct *why* these constructs were believed and *how* they failed.
Deleting them would let the same post-hoc pattern re-enter through a fresh
rediscovery. A retired file with a banner is harder to accidentally promote
than a missing file whose lessons are forgotten.

## Stub pointers

Each retired file also has a one-page stub at its old `memory/<name>.md`
location pointing here. Both the stub and the full document carry the retired
banner.
