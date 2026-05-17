"""Shared pytest fixtures for kryptosbot tests.

Promoted from ``test_critic_empirical_death.py`` so the Phase 2
acceptance suite (``test_phase2_acceptance.py``) can reuse the same
fixture shapes without duplicating setup. The fixtures intentionally
describe the same hypothesis surface used by the Task-15 KB-injection
tests: an ``encoding`` family that is ``empirically_dead`` in the
yield index, and a theory whose subfamily / signature would normally
trigger the bypass IF priors are absent.
"""
from __future__ import annotations

import pytest

from kryptosbot.family_yield import FamilyYieldStats, FamilyYieldVerdict
from kryptosbot.models import TheoryRecord, TheoryStatus


@pytest.fixture
def dead_encoding_yield() -> FamilyYieldVerdict:
    """An ``encoding`` family verdict in ``empirically_dead`` status."""
    stats = FamilyYieldStats("encoding", 826, 0.78, 7.0, 0, 825)
    return FamilyYieldVerdict("encoding", "empirically_dead", ("r",), stats)


@pytest.fixture
def encoding_theory() -> TheoryRecord:
    """A bypass-INELIGIBLE encoding theory (subfamily / sig already seen).

    Tests that consume this fixture also seed ``prior_subfamilies`` and
    ``prior_signatures`` so the bypass cannot fire and the empirical-death
    gate triggers the KB query.
    """
    return TheoryRecord(
        hypothesis_id="hid_kb_test",
        title="t", core_claim="c", mechanism="m",
        family="encoding", subfamily="vigenere",
        status=TheoryStatus.PROPOSED,
    )


@pytest.fixture
def encoding_theory_with_novel_subfamily_and_signature() -> TheoryRecord:
    """A bypass-ELIGIBLE encoding theory.

    Both subfamily (``brand_new_subfamily``) and the computed mechanism
    signature are absent from the priors that the consuming test installs.
    """
    return TheoryRecord(
        hypothesis_id="hid_kb_test_bypass",
        title="t", core_claim="c", mechanism="m",
        family="encoding", subfamily="brand_new_subfamily",
        status=TheoryStatus.PROPOSED,
    )
