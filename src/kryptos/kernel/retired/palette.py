"""Retired null-palette constants (moved from kryptos.kernel.constants).

RETIRED 2026-04-14 (claim_id: null_palette_retired; see
`docs/claims_registry.json` entry `C-PALETTE-01`).

The 7-letter palette and the 17-position consensus null mask were
retired after matched controls (April 2026) disproved the palette's
specificity:
- Among 100 random 7-letter palettes, `BGIKOWZ` ranked in the 1st
  percentile for cross-model mask agreement.
- 76 of 133 single-letter-swap neighbours outperformed it.

The symbols remain importable here for historical reproducibility only.
Their OUTPUT is NOT live evidence (see `kryptos.kernel.constraints.stego`,
which returns `status="retired"` on every StegoProperty).

DO NOT IMPORT FROM LIVE CODE PATHS.

Allow-list for legitimate historical-reproducibility importers lives in
`tests/test_retired_usage.py`.

See also:
- `memory/project_consensus_nulls_epistemic_status_2026_04_14.md`
- `docs/a1_score_conditioned_null_report.md`
- `<internal>` — candidate generator-output-level revival guard.
"""
from __future__ import annotations

from typing import FrozenSet

from kryptos.kernel.constants import ALPH, CRIB_POSITIONS, CT_LEN, N_CRIBS

NULL_PALETTE: FrozenSet[str] = frozenset("BGIKOWZ")

CONSENSUS_NULL_POSITIONS: FrozenSet[int] = frozenset(
    {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}
)

BEAUFORT_KEYSTREAM_AT_CRIBS: str = "JLJODEGKUKKKLOCGGBGOKTRU"


def _verify() -> None:
    """Verify retired constants at import time (relaxed post-retirement).

    Lengths are relaxed to accept 0 (future physical removal) OR the
    historical lengths (7 / 17 / 24), so a future physical removal can
    land without crashing every import. Physical removal is NOT in
    scope for the 2026-04-14 quarantine per Colin's constraint.
    """
    assert len(NULL_PALETTE) in (0, 7), (
        f"NULL_PALETTE should have 0 (retired, physically removed) or 7 "
        f"(retired, historical length); got {len(NULL_PALETTE)}"
    )
    assert all(c in ALPH for c in NULL_PALETTE), "NULL_PALETTE must be uppercase A-Z"

    assert len(CONSENSUS_NULL_POSITIONS) in (0, 17), (
        f"CONSENSUS_NULL_POSITIONS should have 0 (retired, physically "
        f"removed) or 17 (retired, historical length); got "
        f"{len(CONSENSUS_NULL_POSITIONS)}"
    )
    assert all(0 <= p < CT_LEN for p in CONSENSUS_NULL_POSITIONS), (
        "Null positions must be in [0, CT_LEN)"
    )
    assert not CONSENSUS_NULL_POSITIONS & CRIB_POSITIONS, (
        "Null positions must not overlap crib positions"
    )

    assert len(BEAUFORT_KEYSTREAM_AT_CRIBS) == N_CRIBS, (
        f"Keystream string must have {N_CRIBS} chars; "
        f"got {len(BEAUFORT_KEYSTREAM_AT_CRIBS)}"
    )
    # Numeric cross-check against BEAUFORT_KEY_ENE/BC is intentionally
    # omitted here (lives in the live constants module) — this module
    # does not want to create a circular import or a live dependency on
    # the numeric Beaufort keys, which remain unretired.


_verify()
