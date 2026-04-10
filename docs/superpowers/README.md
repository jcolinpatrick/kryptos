---
status: HISTORICAL research planning — not authoritative
namespace_demoted_on: 2026-04-09
reason: Directory contains research proposals, specs, and plans authored March 17–23, 2026. Several of the stego-layer plans (all `2026-03-23-stego-*` files, plus some `2026-03-19-*` and `2026-03-20-*` specs) are built on top of the palette {B,G,I,K,O,W,Z} construct, which was retired 2026-04-01 as a post-hoc selection artifact.
superseded_by: docs/a1_score_conditioned_null_report.md (score-conditioned null), memory/retired/README.md (palette quarantine), MEMORY.md (live research state)
---

# `docs/superpowers/` — Historical Research Planning

This directory holds **research proposals, design specs, and implementation
plans** authored as part of the superpowers / spec-driven planning track in
March 2026. It is **not** current doctrine.

Everything in this directory is a **historical research plan** for work that
either:

- was executed and produced null results (in which case the authoritative
  record is in `reports/`, `results/`, `exhaustion_log.json`, or
  `MEMORY.md`), or
- was never executed and is now superseded by the April 2026 audits and
  retirements, or
- is built on top of the **retired** palette `{B,G,I,K,O,W,Z}` construct
  and its derived null-mask rules.

## What this means for a fresh agent

**Do not treat any file under `docs/superpowers/` as live doctrine.** If you
find an interesting idea here:

1. Check whether it was executed — look at `reports/`, `results/`, and
   `exhaustion_log.json`.
2. Check whether its premises are still valid — in particular, any plan
   that starts from the palette, mod-35 rule, BCL enrichment, Polybius
   row-selection, or the 7-distinct-letter claim is built on a
   **retired** premise. See `memory/retired/README.md` and
   `docs/a1_score_conditioned_null_report.md`.
3. Check whether the current `MEMORY.md` active bins already cover the
   idea in an updated form.

## Palette-dependent files in this directory

The following files materially depend on the retired palette construct or
its derived rules and must be read as historical only:

- `plans/2026-03-23-stego-backward-propagation.md`
- `plans/2026-03-23-stego-layer-solve.md`
- `plans/2026-03-23-stego-mechanism-formalization.md`
- `specs/2026-03-23-stego-backward-propagation-design.md`
- `specs/2026-03-23-stego-layer-research-plan.md`
- `specs/2026-03-23-stego-mechanism-formalization-design.md`
- `specs/2026-03-20-stego-keyword-progressive-design.md`
- `specs/2026-03-19-isbn-hunt-design.md` (palette references)
- `specs/2026-03-19-k4-wheel-grid-analysis-design.md` (palette references)
- `specs/2026-03-19-polybius-coordinate-exploit-design.md` (palette references)
- `specs/2026-03-23-visual-cryptography-hypothesis.md` (palette references)
- `plans/2026-03-19-isbn-hunt.md` (palette references)
- `plans/2026-03-19-k4-wheel-grid-analysis.md` (palette references)

The three files explicitly named in AUDIT-2 (two stego-backward-propagation
files plus the stego layer research plan) also carry per-file HISTORICAL /
PALETTE-DEPENDENT banners for redundancy. The rest are covered by this
README only.

## Rules

- Do not cite any file under `docs/superpowers/` as evidence in
  `MEMORY.md`, `docs/claims_registry.json`, `docs/elimination_tiers.md`,
  or any report that informs current research direction.
- Do not promote a palette-dependent plan back into an active bin without
  first producing new non-palette evidence and logging a claim-registry
  rehabilitation entry.
- Do not build new live specs under `docs/superpowers/` — if you are
  planning new work, use `drafts/`, a live `docs/` file, or a new
  claim-registry entry.
