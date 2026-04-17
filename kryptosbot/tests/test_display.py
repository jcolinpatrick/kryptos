from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from kryptosbot.display import _resolve_anomaly_display_text


def test_resolve_anomaly_display_text_adds_provenance_badges():
    assert _resolve_anomaly_display_text({
        "title": "Minor crib diffs",
        "claim_id": "bean_minor_diffs",
    }).endswith("[Bean-reported, not project-rerun]")

    assert _resolve_anomaly_display_text({
        "title": "Width-21 bigrams",
        "claim_id": "width21_bigrams",
    }).endswith("[project-verified anomaly, ranking feature]")

    assert _resolve_anomaly_display_text({
        "title": "Raised YAR",
        "claim_id": "yar_physical_existence",
    }).endswith("[physical existence verified]")

    assert _resolve_anomaly_display_text({
        "title": "YAR means something",
        "claim_id": "yar_cryptographic_interpretation",
    }).endswith("[physical fact, crypto role unproven]")

    assert _resolve_anomaly_display_text({
        "title": "Bean equality",
        "claim_id": "bean_equality",
    }).endswith("[H1-conditional]")

    assert _resolve_anomaly_display_text({
        "title": "Retired palette",
        "claim_id": "null_palette_retired",
    }).endswith("[RETIRED]")


def test_resolve_anomaly_display_text_falls_back_to_title_for_unknown_claims():
    assert _resolve_anomaly_display_text({"title": "Unknown anomaly"}) == "Unknown anomaly"
    assert _resolve_anomaly_display_text({
        "title": "Unknown claim",
        "claim_id": "not_a_real_claim",
    }) == "Unknown claim"


def test_print_landscape_shows_counts_and_badged_anomalies(capsys):
    from kryptosbot import display

    display.print_landscape({
        "cycle_delta": {"new_tested": 2, "new_eliminated": 1},
        "standing_constraints": ["bean_equality"],
        "active_families": [],
        "underexplored_families": [],
        "open_anomalies": [
            {
                "id": "bean_minor_diffs",
                "title": "Minor crib diffs",
                "claim_id": "bean_minor_diffs",
                "explored_by": 0,
            },
            {
                "id": "width21_vertical_bigrams",
                "title": "Width-21 bigrams",
                "claim_id": "width21_bigrams",
                "explored_by": 3,
            },
        ],
        "prompt_anomaly_count": 2,
        "registry_open_anomaly_count": 3,
        "unaddressed_anomalies": [
            {
                "id": "bean_minor_diffs",
                "title": "Minor crib diffs",
                "claim_id": "bean_minor_diffs",
            },
        ],
        "recent_outcomes": [],
    })

    out = capsys.readouterr().out
    assert "Prompt anomalies (2 active / 3 registry-open)" in out
    assert "Minor crib diffs [Bean-reported, not project-rerun]" in out
    assert "Width-21 bigrams [project-verified anomaly, ranking feature]" in out
    assert "unaddressed" in out


def test_print_landscape_shows_no_prompt_anomalies_banner_when_empty(capsys):
    from kryptosbot import display

    display.print_landscape({
        "cycle_delta": {},
        "standing_constraints": [],
        "active_families": [],
        "underexplored_families": [],
        "open_anomalies": [],
        "prompt_anomaly_count": 0,
        "registry_open_anomaly_count": 4,
        "unaddressed_anomalies": [],
        "recent_outcomes": [],
    })

    out = capsys.readouterr().out
    assert "No prompt anomalies active (4 registry-open)" in out
