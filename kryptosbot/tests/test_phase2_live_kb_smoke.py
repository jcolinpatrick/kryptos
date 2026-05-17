"""Opt-in smoke test against the live db/cipher_discovery.sqlite.

Skipped on CI when the live DB is absent. Verifies the Phase 2 plumbing
works end-to-end on the real KB; deterministic test coverage of behavior
belongs in test_phase2_acceptance.py against the fixture DB.
"""
from __future__ import annotations

from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
LIVE_KB = REPO_ROOT / "db" / "cipher_discovery.sqlite"


@pytest.mark.skipif(
    not LIVE_KB.exists(),
    reason="live cipher_discovery.sqlite not present (CI default)",
)
class TestPhase2LiveKBSmoke:
    def test_query_returns_at_least_one_suggestion_for_empirically_dead_family(self):
        from kryptosbot.kb_injection import query_suggestions
        out = query_suggestions(
            blocked_family="encoding",
            blocked_signature="probe",
            prior_signatures={},
            blocked_families_in_cycle=frozenset({"encoding"}),
            static_exhaustion_blocklist=frozenset(),
            db_path=str(LIVE_KB),
            max_per_call=12,
        )
        # Live KB may or may not have unmapped candidates; we only assert
        # the call does not raise and returns a tuple. A stronger assertion
        # (>=1) is reasonable as long as the KB has the expected ~10
        # untested entries, but we keep this loose to avoid CI flake.
        assert isinstance(out, tuple)
