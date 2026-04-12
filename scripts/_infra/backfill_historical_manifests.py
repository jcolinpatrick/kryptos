#!/usr/bin/env python3
"""
Cipher: n/a (infrastructure)
Family: _infra
Status: active
Keyspace: ~28 historical eliminations
Last run:
Best score:

Generate JSON campaign manifests from the HISTORICAL_ELIMINATIONS source
of truth. Output: results/campaign_manifests/historical/<canonical_id>.json

Run:
    PYTHONPATH=src python3 scripts/_infra/backfill_historical_manifests.py

Idempotent: re-running produces the same set of files with the same content.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "src"))

from kryptos.campaigns.historical_eliminations import (
    HISTORICAL_ELIMINATIONS,
    H1_CAVEAT,
    HistoricalElimination,
)
from kryptos.campaigns.manifest import CampaignManifest, CampaignVerdict


# Fixed backfill timestamp — kept stable so re-runs are byte-identical.
BACKFILL_TIMESTAMP = "2026-04-11T00:00:00+00:00"


def historical_to_manifest(entry: HistoricalElimination) -> CampaignManifest:
    """Convert a HistoricalElimination to a CampaignManifest."""
    return CampaignManifest(
        campaign_id=entry.canonical_id,
        campaign_name=entry.name,
        completed_at=BACKFILL_TIMESTAMP,
        verdict=entry.verdict.value,
        verdict_summary=entry.verdict_summary,
        evidence_pointer=entry.source_doc_pointer,
        family_updates=entry.family_updates,
        scope_caveats=list(entry.scope_caveats),
        scope_does_not_cover=list(entry.scope_does_not_cover),
        notes=entry.notes or (
            f"Historical backfill from {entry.source_row_id}. "
            f"{entry.quantitative_summary}"
        ).strip(),
    )


def main() -> int:
    historical_dir = _ROOT / "results" / "campaign_manifests" / "historical"
    historical_dir.mkdir(parents=True, exist_ok=True)

    written = 0
    skipped = 0
    family_ids_touched: set[str] = set()

    for entry in HISTORICAL_ELIMINATIONS:
        manifest = historical_to_manifest(entry)
        errors = manifest.validate()
        if errors:
            print(
                f"SKIP {entry.canonical_id}: {errors}",
                file=sys.stderr,
            )
            skipped += 1
            continue

        target = historical_dir / f"{entry.canonical_id}.json"
        target.write_text(json.dumps(manifest.to_dict(), indent=2) + "\n")
        written += 1
        family_ids_touched.update(entry.family_updates.keys())

    print(f"Wrote {written} historical manifests to {historical_dir}")
    if skipped:
        print(f"Skipped {skipped} entries (validation errors)")
    print(f"Unique family_ids touched: {len(family_ids_touched)}")
    print(f"Family IDs: {sorted(family_ids_touched)}")
    return 0 if skipped == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
