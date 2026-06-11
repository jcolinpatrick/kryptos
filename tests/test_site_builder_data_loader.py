from __future__ import annotations

import json

from ops.site_builder.data_loader import build_eliminations_from_results, load_results_json


def test_load_results_json_flattens_top_level_list_payloads(tmp_path):
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    payload = [
        {"hypothesis_id": "H1", "composite_score": 1.23},
        {"hypothesis_id": "H2", "composite_score": 4.56},
    ]
    (results_dir / "source_text_hypothesis_scores.json").write_text(json.dumps(payload))

    loaded = load_results_json(str(results_dir))

    assert len(loaded) == 2
    assert loaded[0]["hypothesis_id"] == "H1"
    assert loaded[0]["_source_file"] == "source_text_hypothesis_scores.json#0"
    assert loaded[1]["hypothesis_id"] == "H2"
    assert loaded[1]["_source_file"] == "source_text_hypothesis_scores.json#1"


def test_ancillary_list_payloads_do_not_become_eliminations(tmp_path):
    results_dir = tmp_path / "results"
    scripts_dir = tmp_path / "scripts"
    results_dir.mkdir()
    scripts_dir.mkdir()
    payload = [{"hypothesis_id": "H1", "composite_score": 1.23}]
    (results_dir / "source_text_hypothesis_scores.json").write_text(json.dumps(payload))

    loaded = load_results_json(str(results_dir))
    eliminations = build_eliminations_from_results(
        loaded, existing_ids=set(), overrides={}, scripts_dir=str(scripts_dir)
    )

    assert eliminations == []


# ---------------------------------------------------------------------------
# _humanize_title degenerate-fallback guard
# ---------------------------------------------------------------------------

from ops.site_builder.data_loader import SiteElimination, _humanize_title


def test_humanize_title_degenerate_id_derives_from_script_filename():
    # E-S-46 used to collapse to the single letter "S" (prefix + version
    # suffix stripping). The script filename carries the real meaning.
    elim = SiteElimination(
        id="E-S-46",
        title="E-S-46",
        description="",
        experiment_script="scripts/substitution/e_s_46_position_alphabets.py",
    )
    title = _humanize_title(elim)
    assert title != "S"
    assert "position alphabets" in title.lower()
    assert "E-S-46" in title


def test_humanize_title_degenerate_id_derives_from_key_finding():
    elim = SiteElimination(
        id="E-POLY-01",
        title="E-POLY-01",
        description="",
        extra={"key_finding": "ALL_NOISE — polyalphabetic formally eliminated at all periods"},
    )
    title = _humanize_title(elim)
    assert title.lower() != "poly"
    assert "polyalphabetic" in title.lower()


def test_humanize_title_degenerate_id_last_resort_keeps_unique_id():
    elim = SiteElimination(id="E-COMPOSE-02", title="E-COMPOSE-02", description="")
    title = _humanize_title(elim)
    assert title != "Compose"
    assert "E-COMPOSE-02" in title


def test_humanize_title_good_titles_untouched():
    good = "Hill cipher with YAR-derived matrix parameters (width 9)"
    elim = SiteElimination(id="E-S-151", title=good)
    assert _humanize_title(elim) == good


def test_humanize_title_blitz_stub_treated_as_degenerate():
    elim = SiteElimination(
        id="BLITZ-V7",
        title="BLITZ-V7/RESULTS",
        description="",
        extra={"key_finding": "Fourteen lead families swept in one pass, all noise"},
    )
    title = _humanize_title(elim)
    assert title != "Blitz V7"
    assert len(title) > 10


def test_humanize_title_truncates_paragraph_titles():
    long_title = (
        "this corrects the earlier sweep and supersedes the previous run, "
        "covering additional widths and both alphabets across every period "
        "with the revised scoring path and the corrected crib positions too"
    )
    elim = SiteElimination(id="E-X-01", title=long_title)
    out = _humanize_title(elim)
    assert len(out) <= 110


# ---------------------------------------------------------------------------
# Timestamp normalization (run-id style -> ISO)
# ---------------------------------------------------------------------------

from ops.site_builder.data_loader import _normalize_timestamp


def test_normalize_timestamp_runid_with_time():
    assert _normalize_timestamp("20260404_090825") == "2026-04-04"


def test_normalize_timestamp_runid_with_short_suffix():
    assert _normalize_timestamp("20260403_2") == "2026-04-03"


def test_normalize_timestamp_bare_compact_date():
    assert _normalize_timestamp("20260525") == "2026-05-25"


def test_normalize_timestamp_iso_passthrough():
    assert _normalize_timestamp("2026-05-25T15:04:35.123") == "2026-05-25T15:04:35.123"
    assert _normalize_timestamp("2026-05-25") == "2026-05-25"


def test_normalize_timestamp_empty_and_junk_passthrough():
    assert _normalize_timestamp("") == ""
    assert _normalize_timestamp("unknown") == "unknown"


def test_results_elimination_gets_normalized_date(tmp_path):
    results_dir = tmp_path / "results"
    scripts_dir = tmp_path / "scripts"
    results_dir.mkdir()
    scripts_dir.mkdir()
    payload = {
        "experiment": "E-TEST-99",
        "description": "A test elimination record",
        "verdict": "NOISE",
        "timestamp": "20260404_090825",
    }
    (results_dir / "e_test_99.json").write_text(json.dumps(payload))

    loaded = load_results_json(str(results_dir))
    elims = build_eliminations_from_results(
        loaded, existing_ids=set(), overrides={}, scripts_dir=str(scripts_dir)
    )
    assert len(elims) == 1
    assert elims[0].date_tested == "2026-04-04"


def test_sanitize_rq_text_strips_internal_notation():
    from ops.site_builder.data_loader import _sanitize_rq_text
    raw = ("[HYPOTHESIS] It may be position-dependent based on the K5 inference "
           "(see `docs/kryptos_ground_truth.md` C5), but this is unproven within "
           "the repo's direct-positional correspondence model.")
    out = _sanitize_rq_text(raw)
    assert "[HYPOTHESIS]" not in out
    assert "`" not in out
    assert "docs/kryptos_ground_truth" not in out
    assert "standard letter-for-letter reading" in out


def test_humanize_title_truncates_long_colon_suffix():
    long_human = (
        "autokey chain propagation from crib bootstrap. Phase 4 scores 24/24 "
        "circularly because cribs are used to derive the key and then scored "
        "against themselves, which inflates the apparent match rate badly"
    )
    elim = SiteElimination(id="E-AK-09", title=f"E-AK-09: {long_human}")
    out = _humanize_title(elim)
    assert len(out) <= 110
