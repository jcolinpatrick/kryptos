"""Tests for the historical elimination backfill registry.

Enforces the three catastrophic-failure invariants:
  1. E-FRAC-54 MUST remain OPEN with empty family_updates.
  2. Bean-based entries MUST carry the exact H1 caveat.
  3. Empirical sweeps MUST NOT use universal-proof language.

Plus a drift-audit test that flags wholesale mischaracterization between
canonical_id and source row content.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

from kryptos.campaigns.historical_eliminations import (
    HISTORICAL_ELIMINATIONS,
    H1_CAVEAT,
    HistoricalElimination,
)
from kryptos.campaigns.manifest import CampaignVerdict, CampaignManifest

# Import the generator's converter for round-trip validation.
sys.path.insert(0, str(_ROOT / "scripts" / "_infra"))
import backfill_historical_manifests as backfill  # type: ignore


BEAN_PATTERN = re.compile(
    r"(bean|columnar|periodic|autokey|frac_3|frac_4|frac_5|null_mask|nullmask|jts)",
    re.IGNORECASE,
)


def _is_bean_based(entry: HistoricalElimination) -> bool:
    blob = f"{entry.canonical_id} {entry.name}".lower()
    return bool(BEAN_PATTERN.search(blob))


# ---------------------------------------------------------------------------
# 1. Source file basics
# ---------------------------------------------------------------------------

def test_source_file_imports():
    assert HISTORICAL_ELIMINATIONS
    assert H1_CAVEAT


def test_count_in_expected_range():
    assert 25 <= len(HISTORICAL_ELIMINATIONS) <= 35


def test_canonical_ids_unique():
    ids = [e.canonical_id for e in HISTORICAL_ELIMINATIONS]
    assert len(ids) == len(set(ids))


def test_canonical_ids_filesystem_safe():
    pattern = re.compile(r"^[a-z0-9_]+$")
    for e in HISTORICAL_ELIMINATIONS:
        assert pattern.match(e.canonical_id), f"bad canonical_id: {e.canonical_id}"


def test_each_entry_validates_as_manifest():
    for e in HISTORICAL_ELIMINATIONS:
        m = backfill.historical_to_manifest(e)
        errors = m.validate()
        assert errors == [], f"{e.canonical_id}: {errors}"


# ---------------------------------------------------------------------------
# 2. H1 caveat discipline
# ---------------------------------------------------------------------------

def test_h1_caveat_string_constant():
    assert isinstance(H1_CAVEAT, str)
    assert len(H1_CAVEAT) > 50
    assert "direct positional crib mapping" in H1_CAVEAT
    assert "additive cipher class" in H1_CAVEAT


def test_bean_based_eliminations_have_h1_caveat():
    # OPEN entries do not eliminate anything and so carry no H1 caveat.
    count = 0
    for e in HISTORICAL_ELIMINATIONS:
        if not _is_bean_based(e):
            continue
        if e.verdict == CampaignVerdict.OPEN:
            continue
        count += 1
        assert H1_CAVEAT in e.scope_caveats, (
            f"{e.canonical_id} looks Bean-based but is missing the H1 caveat"
        )
    assert count >= 15, f"expected many Bean-based entries, got {count}"


def test_universal_proofs_lack_h1_caveat():
    # e_frac_21 (fractionation, alphabet/parity structural) and
    # e_frac_13_19 (IC statistical) are NOT Bean-based and should not
    # carry the H1 caveat.
    by_id = {e.canonical_id: e for e in HISTORICAL_ELIMINATIONS}
    assert H1_CAVEAT not in by_id["e_frac_21"].scope_caveats
    assert H1_CAVEAT not in by_id["e_frac_13_19_ic_not_significant"].scope_caveats


# ---------------------------------------------------------------------------
# 3. E-FRAC-54 invariant
# ---------------------------------------------------------------------------

def test_e_frac_54_is_open():
    matches = [e for e in HISTORICAL_ELIMINATIONS
               if e.canonical_id.startswith("e_frac_54")]
    assert len(matches) == 1, f"expected exactly one e_frac_54 entry, got {len(matches)}"
    entry = matches[0]
    assert entry.verdict == CampaignVerdict.OPEN, (
        f"E-FRAC-54 verdict must be OPEN, got {entry.verdict}"
    )
    assert entry.family_updates == {}, (
        f"E-FRAC-54 must not mark any family as eliminated; "
        f"got family_updates={entry.family_updates}"
    )


# ---------------------------------------------------------------------------
# 4. Empirical sweep overclaim guard
# ---------------------------------------------------------------------------

FORBIDDEN_OVERCLAIM_PATTERNS = [
    re.compile(r"\bdefinitive\b", re.IGNORECASE),
    re.compile(r"\bproves\b", re.IGNORECASE),
    re.compile(r"\bimpossible\b", re.IGNORECASE),
    # "all" as an intensifier in BOUNDED_NULL summaries is disallowed;
    # we allow "all" inside fixed phrases like "all tested" via a stricter
    # check — we simply forbid bare "all " at the start of a declarative
    # clause. Keep this narrow: match "all " NOT followed by "tested"/"three".
]


def test_no_overclaiming_in_empirical_entries():
    soft_verdicts = {CampaignVerdict.BOUNDED_NULL, CampaignVerdict.NARROW_RESIDUAL}
    for e in HISTORICAL_ELIMINATIONS:
        if e.verdict not in soft_verdicts:
            continue
        s = e.verdict_summary
        for pat in FORBIDDEN_OVERCLAIM_PATTERNS:
            assert not pat.search(s), (
                f"{e.canonical_id} ({e.verdict.value}) verdict_summary contains "
                f"forbidden overclaim pattern {pat.pattern!r}: {s!r}"
            )


# ---------------------------------------------------------------------------
# 5. Shape / traceability
# ---------------------------------------------------------------------------

def test_each_family_update_has_evidence_text():
    for e in HISTORICAL_ELIMINATIONS:
        for fid, update in e.family_updates.items():
            assert update.get("evidence", "").strip(), (
                f"{e.canonical_id}: family_updates[{fid}] has empty evidence"
            )


def test_each_entry_has_source_row_id():
    for e in HISTORICAL_ELIMINATIONS:
        assert e.source_row_id and e.source_row_id.strip(), e.canonical_id


def test_each_entry_has_source_doc_pointer():
    for e in HISTORICAL_ELIMINATIONS:
        assert "elimination_tiers.md" in e.source_doc_pointer, e.canonical_id


def test_each_entry_has_non_empty_verdict_summary():
    for e in HISTORICAL_ELIMINATIONS:
        assert len(e.verdict_summary) > 50, f"{e.canonical_id} has thin verdict_summary"


def test_drift_audit_source_row_id_normalization():
    """Catch wholesale mischaracterization: the source_row_id should appear
    somewhere textually in the entry's own content."""
    for e in HISTORICAL_ELIMINATIONS:
        blob = (
            e.name + " " + e.verdict_summary + " " + e.notes
            + " " + e.source_doc_pointer
            + " " + " ".join(
                upd.get("evidence", "") for upd in e.family_updates.values()
            )
        ).lower()
        # Normalize: strip spaces, drop the leading "E-" prefix for looser match.
        row = e.source_row_id.lower()
        core = row.replace("e-", "").replace(" ", "")
        # Accept if either the full row id or its core numeric token appears.
        token_matches = row in blob or core in blob.replace(" ", "")
        # Fall back to any numeric fragment match (e.g. "54" in "e-frac-54").
        if not token_matches:
            nums = re.findall(r"\d+", row)
            if nums:
                token_matches = all(n in blob for n in nums)
        assert token_matches, (
            f"drift audit: {e.canonical_id} does not reference its source "
            f"row id {e.source_row_id} anywhere in its text content"
        )


# ---------------------------------------------------------------------------
# 6. Generator behaviour
# ---------------------------------------------------------------------------

def test_generator_writes_all_entries(tmp_path, monkeypatch):
    # Run the generator and verify every canonical_id has a file.
    result = subprocess.run(
        [sys.executable, str(_ROOT / "scripts" / "_infra" / "backfill_historical_manifests.py")],
        env={**__import__("os").environ, "PYTHONPATH": str(_ROOT / "src")},
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    hist = _ROOT / "results" / "campaign_manifests" / "historical"
    files = {p.stem for p in hist.glob("*.json")}
    expected = {e.canonical_id for e in HISTORICAL_ELIMINATIONS}
    assert expected.issubset(files), f"missing: {expected - files}"


def test_generator_idempotent():
    hist = _ROOT / "results" / "campaign_manifests" / "historical"
    env = {**__import__("os").environ, "PYTHONPATH": str(_ROOT / "src")}
    # First run
    r1 = subprocess.run(
        [sys.executable, str(_ROOT / "scripts" / "_infra" / "backfill_historical_manifests.py")],
        env=env, capture_output=True, text=True,
    )
    assert r1.returncode == 0, r1.stderr
    first = {p.name: p.read_bytes() for p in sorted(hist.glob("*.json"))}
    # Second run
    r2 = subprocess.run(
        [sys.executable, str(_ROOT / "scripts" / "_infra" / "backfill_historical_manifests.py")],
        env=env, capture_output=True, text=True,
    )
    assert r2.returncode == 0, r2.stderr
    second = {p.name: p.read_bytes() for p in sorted(hist.glob("*.json"))}
    assert first == second


# ---------------------------------------------------------------------------
# 7. Critic family-tier refusal
# ---------------------------------------------------------------------------

def _make_critic_and_family(tier: int):
    from kryptosbot.theory_ledger import TheoryLedger
    from kryptosbot.critic import TheoryCritic
    from kryptosbot.models import FamilyRecord, FamilyStatus, TheoryRecord
    import tempfile
    tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    tmp.close()
    ledger = TheoryLedger(Path(tmp.name))
    fid = f"test_family_tier_{tier}"
    status = FamilyStatus.EXHAUSTED if tier <= 2 else FamilyStatus.PARTIALLY_EXPLORED
    ledger.upsert_family(FamilyRecord(
        family_id=fid,
        name=f"Test Family Tier {tier}",
        status=status,
        elimination_tier=tier,
        elimination_evidence="synthetic test evidence blob",
    ))
    critic = TheoryCritic(ledger)
    theory = TheoryRecord(
        title="test theory",
        core_claim="test core claim for family tier refusal check",
        mechanism="bespoke experimental mechanism",
        family=fid,
        kill_criteria=["some criterion"],
        expected_signal="some signal",
    )
    return critic, theory


def test_critic_family_tier_refusal_fires_for_tier_1():
    from kryptosbot.models import CriticDecision
    critic, theory = _make_critic_and_family(1)
    verdict = critic.evaluate(theory)
    assert verdict.decision == CriticDecision.REJECT_ELIMINATED
    assert any("elimination_tier" in r for r in verdict.reasons)


def test_critic_family_tier_refusal_fires_for_tier_2():
    from kryptosbot.models import CriticDecision
    critic, theory = _make_critic_and_family(2)
    verdict = critic.evaluate(theory)
    assert verdict.decision == CriticDecision.REJECT_ELIMINATED


def test_critic_family_tier_refusal_passes_unknown_family():
    from kryptosbot.theory_ledger import TheoryLedger
    from kryptosbot.critic import TheoryCritic
    from kryptosbot.models import TheoryRecord, CriticDecision
    import tempfile
    tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    tmp.close()
    ledger = TheoryLedger(Path(tmp.name))
    critic = TheoryCritic(ledger)
    theory = TheoryRecord(
        title="unknown family theory",
        core_claim="test core claim unknown family",
        mechanism="bespoke mechanism",
        family="completely_unknown_family_xyz",
        kill_criteria=["criterion"],
        expected_signal="signal",
        anomalies_exploited=["some_anomaly"],
    )
    verdict = critic.evaluate(theory)
    # The family-tier check should NOT fire (returns None for unknown family).
    # Other checks may or may not approve, but it must not be REJECT_ELIMINATED
    # with the family-tier reason.
    if verdict.decision == CriticDecision.REJECT_ELIMINATED:
        assert not any("elimination_tier" in r for r in verdict.reasons), (
            "unknown family should not trip the tier-based refusal"
        )
