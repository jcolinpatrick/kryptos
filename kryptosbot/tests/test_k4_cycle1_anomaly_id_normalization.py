"""K4 cycle-1 hygiene: anomaly-id normalization (commit 2).

Regression tests for the secondary cycle-1 bug: the theorist wrote
anomaly references as "<canonical_id> <free-form commentary>" but the
validator did exact-match on the entire string, rejecting 4 of 5
theories for cosmetic reasons. The fix (``_normalize_anomaly_id``)
takes the first whitespace/paren-split token and lets the downstream
exact-match handle the canonicality check unchanged.

See docs/maturation/round3/K4_RUN_CYCLE1_DIAGNOSTIC.md for the
production trace.
"""
from __future__ import annotations

import json

import pytest

from kryptosbot.contracts import (
    _normalize_anomaly_id,
    validate_theory_proposals,
)


# ─── _normalize_anomaly_id: direct unit tests ────────────────────────────────


def test_normalize_bare_canonical_id_passthrough():
    """A bare canonical id is returned unchanged."""
    assert _normalize_anomaly_id("ct_perturbation") == "ct_perturbation"
    assert _normalize_anomaly_id("aaa_compass_cipher") == "aaa_compass_cipher"


def test_normalize_strips_trailing_parenthetical():
    """'aaa_compass_cipher (tie to ...)' → 'aaa_compass_cipher'."""
    value = "aaa_compass_cipher (tie to physical sculpture geometry specifically)"
    assert _normalize_anomaly_id(value) == "aaa_compass_cipher"


def test_normalize_strips_trailing_prose():
    """'k3_continuity as under-explored source material' → 'k3_continuity'."""
    value = "k3_continuity as under-explored source material"
    assert _normalize_anomaly_id(value) == "k3_continuity"


def test_normalize_strips_prose_before_parenthetical():
    """'mirror_ka is listed as underexplored (0 tested)' → 'mirror_ka'."""
    value = "mirror_ka is listed as underexplored (0 tested)"
    assert _normalize_anomaly_id(value) == "mirror_ka"


def test_normalize_takes_first_token_not_prefix_match():
    """Operator spec: exact-match on first token, NO prefix matching.
    If the theorist writes 'archive-attested K3 misspellings', the
    normalizer returns 'archive-attested' — the downstream exact-match
    against canonical anomaly_ids will then reject it (which is the
    right outcome, since 'archive-attested' is not a canonical id)."""
    value = "archive-attested K3 misspellings as intentional key spelling"
    assert _normalize_anomaly_id(value) == "archive-attested"


def test_normalize_empty_and_whitespace_only_inputs():
    assert _normalize_anomaly_id("") == ""
    assert _normalize_anomaly_id("   ") == ""
    assert _normalize_anomaly_id("\t\n") == ""


def test_normalize_leading_whitespace_is_stripped():
    assert _normalize_anomaly_id("  ct_perturbation  ") == "ct_perturbation"


def test_normalize_trailing_punctuation_is_stripped():
    """Trailing , . ; : are dropped, but hyphens / underscores WITHIN
    the id stay because they're valid id chars."""
    assert _normalize_anomaly_id("ct_perturbation,") == "ct_perturbation"
    assert _normalize_anomaly_id("ct_perturbation.") == "ct_perturbation"
    # But id-internal chars are preserved.
    assert _normalize_anomaly_id("archive-attested") == "archive-attested"
    assert _normalize_anomaly_id("aaa_compass_cipher") == "aaa_compass_cipher"


def test_normalize_paren_takes_priority_over_whitespace():
    """If the first delimiter is '(' with no preceding space, we still
    cut at '(' — no whitespace needed. The id is e.g.
    'canonical_id(inline_paren)'."""
    # (Unusual shape but we handle it defensively.)
    assert _normalize_anomaly_id("canonical_id(paren)") == "canonical_id"


def test_normalize_does_not_prefix_match_against_canonical_set():
    """Spec: 'no prefix matching'. If the theorist writes
    'ct_perturbation_alt', the normalizer returns the whole string (no
    whitespace or paren to split on). Downstream exact-match rejects
    it, which is correct — 'ct_perturbation_alt' is not the canonical
    'ct_perturbation'."""
    value = "ct_perturbation_alt"  # hypothetical non-canonical variant
    assert _normalize_anomaly_id(value) == "ct_perturbation_alt"
    # The validator's canonical check downstream rejects this.


# ─── End-to-end: validate_theory_proposals with normalized ids ──────────────


def test_validate_theory_proposals_accepts_parenthetical_anomaly_ref():
    """Before commit 2: rejected because exact-match failed. After:
    normalized to the bare id, which exact-matches canonical set."""
    raw = json.dumps([{
        "title": "T",
        "core_claim": "c",
        "mechanism": "m",
        "family": "grille",
        "anomalies_exploited": [
            "aaa_compass_cipher (tie to physical sculpture geometry)"
        ],
    }])
    report = validate_theory_proposals(raw)
    assert len(report.valid) == 1, (
        f"parenthetical annotation should normalize away; got "
        f"invalid={report.invalid}, errors={report.errors}"
    )


def test_validate_theory_proposals_accepts_prose_trail_canonical_anomaly():
    """Normalizer strips prose, downstream exact-match accepts the
    canonical bare id. Use `width21_vertical_bigrams` (a canonical
    anomaly per registries.KNOWN_ANOMALIES) rather than `k3_continuity`
    (which is a FAMILY, not an anomaly)."""
    raw = json.dumps([{
        "title": "T",
        "core_claim": "c",
        "mechanism": "m",
        "family": "novel",
        "anomalies_exploited": [
            "width21_vertical_bigrams as the primary structural signal"
        ],
    }])
    report = validate_theory_proposals(raw)
    assert len(report.valid) == 1, (
        f"prose trail on canonical anomaly_id should normalize and pass; "
        f"got invalid={report.invalid}"
    )


def test_validate_theory_proposals_still_rejects_non_canonical_first_token():
    """If the first token is not canonical, the theory is still
    rejected — the normalizer doesn't invent canonicality."""
    raw = json.dumps([{
        "title": "T",
        "core_claim": "c",
        "mechanism": "m",
        "family": "novel",
        "anomalies_exploited": ["archive-attested K3 misspellings"],  # not canonical
    }])
    report = validate_theory_proposals(raw)
    assert not report.valid, (
        "non-canonical first tokens must still fail exact-match; "
        "the normalizer strips commentary, not canonicality"
    )
    assert report.invalid
    # The error message should reference 'archive-attested' as the
    # normalized-but-still-invalid id.
    err = report.invalid[0].get("error", "")
    assert "archive-attested" in err or "anomalies_exploited" in err


def test_validate_theory_proposals_rejects_empty_anomaly_entry():
    """Empty-string or whitespace-only entries still fail."""
    raw = json.dumps([{
        "title": "T",
        "core_claim": "c",
        "mechanism": "m",
        "family": "novel",
        "anomalies_exploited": ["   "],
    }])
    report = validate_theory_proposals(raw)
    assert not report.valid


# ─── Replay test: cycle-1 with BOTH fixes applied ────────────────────────────


def test_replay_cycle1_post_both_fixes_yields_two_valid():
    """End-to-end payoff of commits 1 + 2 against the frozen cycle-1
    fixture. Load the 2026-04-21 cycle-1 theorist response, run it
    through _extract_message_text then validate_theory_proposals.

    Observed yield: 2 valid theories.
    - #0 archive_evidence / Cat-B: anomalies_exploited=['ct_perturbation']
      (canonical anomaly_id, passes directly)
    - #3 grille / Cat-A: anomalies_exploited=['aaa_compass_cipher (tie...)']
      (normalizer strips parenthetical → 'aaa_compass_cipher' is canonical)

    The other 3 theorist theories fail because the theorist confused
    the `anomalies_exploited` field semantics — it should reference
    canonical anomaly_ids from registries.KNOWN_ANOMALIES (17 entries
    like ct_perturbation, aaa_compass_cipher, width21_vertical_bigrams,
    etc.) but the theorist wrote FAMILY names (k3_continuity, k2_coords,
    mirror_ka) which are not canonical anomalies even after
    normalization. That's a theorist-prompt clarity issue for a later
    hygiene pass; commit 2's normalizer correctly handles the
    parenthetical-prose-trail shape and is not at fault for the
    anomaly-vs-family confusion.

    If this assertion rises above 2, either the canonical anomaly set
    has grown (check KNOWN_ANOMALIES registry) or the theorist prompt
    clarification landed and updated the fixture. Investigate the
    increase rather than silently accepting.
    """
    from pathlib import Path
    from kryptosbot.controller import _extract_message_text

    raw_path = (
        Path(__file__).resolve().parent / "fixtures" / "theorist_cycle1_raw.txt"
    )
    raw_text = raw_path.read_text()

    from dataclasses import dataclass

    @dataclass
    class FakeTextBlock:
        text: str
        type: str = "text"

    extracted = _extract_message_text([FakeTextBlock(text=raw_text)])
    report = validate_theory_proposals(extracted)

    assert len(report.valid) == 2, (
        f"expected 2 valid theorist-proposed theories post-fixes; got "
        f"valid={len(report.valid)}, invalid={len(report.invalid)}. "
        f"The other 3 fail because the theorist wrote family names "
        f"(k3_continuity, k2_coords, mirror_ka) in anomalies_exploited "
        f"where canonical anomaly_ids are required. See test docstring."
    )
    titles = {t.title[:40] for t in report.valid}
    assert any("CT perturbation" in t for t in titles), (
        "ct_perturbation theory (Cat-B) should parse"
    )
    assert any("Compass-rose" in t for t in titles), (
        "Cardan grille theory (Cat-A, aaa_compass_cipher anomaly) "
        "should parse after normalizer strips the parenthetical"
    )


def test_replay_cycle1_cat_a_theory_carries_grille_dsl_spec():
    """The single Cat-A theory that survives the fixture replay (the
    Cardan grille) must arrive at the critic with a well-formed grille
    dsl_spec. This is the R3-2 downstream checkpoint for this replay.
    """
    from pathlib import Path
    from kryptosbot.controller import _extract_message_text
    from kryptosbot.critic import NON_DSL_FAMILIES

    raw_path = (
        Path(__file__).resolve().parent / "fixtures" / "theorist_cycle1_raw.txt"
    )
    raw_text = raw_path.read_text()

    from dataclasses import dataclass

    @dataclass
    class FakeTextBlock:
        text: str
        type: str = "text"

    extracted = _extract_message_text([FakeTextBlock(text=raw_text)])
    report = validate_theory_proposals(extracted)

    cat_a = [t for t in report.valid
             if (t.family or "").lower() not in NON_DSL_FAMILIES]
    assert len(cat_a) == 1, (
        f"one Cat-A theory expected in the replay yield; got {len(cat_a)}"
    )
    grille_theory = cat_a[0]
    assert grille_theory.dsl_spec, (
        "Cat-A theory should carry a dsl_spec; the theorist's raw "
        "response included one per the cycle-1 diagnostic"
    )
    pipeline = grille_theory.dsl_spec.get("pipeline", [])
    assert pipeline and pipeline[0].get("kind") == "grille", (
        f"Cat-A theory's pipeline should start with a grille kind; "
        f"got {[l.get('kind') for l in pipeline]}"
    )
