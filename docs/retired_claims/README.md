---
status: retired_claims_index
type: pointer
---

# Retired Claims — Index

This is the **canonical landing page** for retired research claims.

Most retired material currently lives in `memory/retired/` (the palette / null-mask
family retired 2026-04-01). This file exists so that an agent searching under
`docs/` still finds the quarantine.

## Where retired material lives

- **`memory/retired/`** — Retired research notes (full documents, with banners).
  See `memory/retired/README.md` for the quarantine index.
- **`docs/history/`** — Historical strategy snapshots and status reports that
  are no longer authoritative. See `docs/history/README.md`.

## Current retired families

| Family | Retired | Reason | Index |
|--------|---------|--------|-------|
| Palette {B,G,I,K,O,W,Z} + all derived null-mask constructs | 2026-04-01 | Post-hoc selection artifact — fails score-conditioned null | `memory/retired/README.md` |

## Rules

- Do not promote anything from a retired path into the live claim registry
  (`docs/claims_registry.json`) without an explicit rehabilitation entry that
  names new evidence.
- Do not link to retired files from `MEMORY.md` as if they were live.
- If a live document still materially depends on retired content, that is a
  **methodological audit item** — log it in `docs/methodological_audits.md`.
