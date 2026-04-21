"""Retired kernel constants — imported only for historical reproducibility.

Nothing exported from this package may appear in a live code path. The
provenance layer marks every member as RETIRED_CLAIM (see
`docs/claims_registry.json` entry `C-PALETTE-01`, retired 2026-04-14).

If a new caller imports from here, the CI check in
`tests/test_retired_usage.py` will fail. The allow-list in that test
enumerates every file that is permitted to depend on these retired
constants for historical-reproducibility purposes only.

Structure:
- `palette.py` — NULL_PALETTE, CONSENSUS_NULL_POSITIONS,
  BEAUFORT_KEYSTREAM_AT_CRIBS (retired 2026-04-14).

See also:
- `memory/project_consensus_nulls_epistemic_status_2026_04_14.md`
- `docs/a1_score_conditioned_null_report.md`
- `kryptosbot/critic.py` — theorist-output-level revival guard (regex).
- `tests/test_retired_usage.py` — import-level revival guard (AST).
"""

from .palette import (
    BEAUFORT_KEYSTREAM_AT_CRIBS,
    CONSENSUS_NULL_POSITIONS,
    NULL_PALETTE,
)

__all__ = [
    "BEAUFORT_KEYSTREAM_AT_CRIBS",
    "CONSENSUS_NULL_POSITIONS",
    "NULL_PALETTE",
]
