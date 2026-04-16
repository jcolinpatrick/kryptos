"""KryptosBot oracle hardening regressions."""

from __future__ import annotations

from kryptosbot.oracle import (
    format_results_for_feedback,
    test_stego_placement_rule as oracle_test_stego_placement_rule,
)


def test_stego_placement_rule_does_not_score_against_retired_consensus_mask():
    result = oracle_test_stego_placement_rule(
        {"name": "synthetic", "predicted_positions": [0, 1, 2, 3]}
    )
    assert result["verdict"] == "RETIRED_UNTESTABLE"
    assert result["retired_claim_id"] == "null_palette_retired"
    assert "f1_score" not in result
    assert "precision" not in result
    assert "consensus_count" not in result


def test_stego_placement_feedback_reports_retirement_not_f1():
    result = oracle_test_stego_placement_rule(
        {"name": "synthetic", "predicted_positions": [0, 1, 2, 3]}
    )
    text = format_results_for_feedback([result])
    assert "RETIRED_UNTESTABLE" in text
    assert "Null placement rules are no longer scored" in text
    assert "F1:" not in text
