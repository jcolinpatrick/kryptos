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
