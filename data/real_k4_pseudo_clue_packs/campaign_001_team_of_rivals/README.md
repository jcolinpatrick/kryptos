# Real-K4 Bridge Campaign 001 — Team-of-Rivals

> **STATUS: CLOSED (null result, 2026-04-30).** See `CLOSURE.md` in this
> directory for the full closure note. The pipeline is validated; the
> tested pseudo-clue families produced no real-K4 signal at this search
> breadth and **must not be expanded blindly**. See
> `docs/REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md` for the stricter standard
> any future pack must meet.

Generated 2026-04-30 by curated authoring (`human_curator`, run id `campaign-001-tor-f*`).

## What this is

The first curated Team-of-Rivals campaign for the real-K4 LLM↔HCC bridge. Builds on
the bootstrap fixture packs at `data/real_k4_pseudo_clue_packs/0?_*.json`. Where the
bootstrap fixtures were narrowly-scoped pipeline tests, this campaign organizes 31
pseudo-clue packs around 7 rival hypothesis families. Each family includes at least
one proponent pack, one skeptic-minimal pack, and at least one alternative-mechanism
pack so a reviewer can attribute any signal to a specific structural commitment
rather than to an unconstrained search.

## Family inventory

| Code | Family | Packs |
|------|--------|-------|
| F1   | Public crib geometry (BERLIN/CLOCK, EAST/NORTHEAST as keys) | 5 |
| F2   | Sanborn/Scheidt two-systems / masked-English (Tier-3 hearsay) | 5 |
| F3   | Stehle anomaly (+5 / spacing-4) | 4 |
| F4   | BCL Beaufort enrichment (post-retired-palette policy) | 4 |
| F5   | Width-21 vertical bigrams (and post-null widths 10, 17) | 5 |
| F6   | NDYAHR / YAR shifted-letter anomaly | 4 |
| F7   | K2/K3 provenance analogy (PALIMPSEST / ABSCISSA / KRYPTOS / K3 widths) | 4 |
| **Total** | | **31** |

## Hard rules honored by every pack

- No K4Bench data, no sealed-answer text.
- Every keyword, numeric role, operation hint, and composition template cites at
  least one provenance item declared in the same pack.
- `allow_project_safe_defaults=false` and `allow_default_widths=false` everywhere
  unless explicitly justified in caveats.
- Allowed keyword pools are derived from EVIDENCE, not from the generic Tier-2
  legacy keyword pool — packs in F1/F2/F5/F6 explicitly enumerate `allowed_keywords`.
- Every pack carries a `generation_run_id` of `campaign-001-tor-f<N>` so the audit
  artifact can be filtered by family.

## Caveat hierarchy (project policy)

- Sanborn / Scheidt public statements: **Tier-3 hearsay** per
  `feedback_sanborn_epistemic_weight`. Proponent packs in F2 explicitly tag
  `tier_3_creator_statement` and call out the Tier-3 status in `caveats`.
- Retired claims (BCL palette `{B,G,I,K,O,W,Z}`): **Tier-5 placeholder only**.
  Pack 44 exists ONLY to keep the retired claim VISIBLE in the audit, not to
  build new compute on top of it.
- Speculative position-anchor / numerology readings (F1-14, F6-63, F6-64):
  Tier-5 self-flagged.

## Within-family rivals

Each family is structured as a falsification panel. The skeptic-minimal pack
defines the per-family floor; the proponent pack defines the per-family ceiling
under the proponent's structural commitment. Alternative-mechanism packs swap
ONE structural commitment at a time (role-swap, layer-swap, parameter-swap)
so any net signal can be attributed to the swapped axis.

## Non-claim banner (echoed from `real_k4_bridge_audit`)

This campaign is an **interpretive pipeline test**. NO real-K4 progress is
claimed. Promotion to candidate-pending requires the null baseline gate
(p ≤ 0.001 against the analytical Binomial null over the number of candidates
dispatched). Sealed K4Bench answers are not accessed and cannot influence the
artifact.
