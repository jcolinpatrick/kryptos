"""Tests for swing_k1_artifacts."""
import json
from pathlib import Path

import pytest


def test_manifest_round_trip(tmp_path):
    from kryptosbot.swing_k1_artifacts import write_manifest, read_manifest
    out = tmp_path / "manifest.json"
    write_manifest(
        out_path=out,
        universe_hash="a" * 64,
        kernel_commit="b" * 40,
        prereg_thresholds={"promotion_p_max": 1e-6, "s2_min_match_len": 8, "s3_min_strength": 0.95},
        mask_catalog_path="data/swing_k1/mask_catalog_2026_05_11.json",
        corpus_manifest_path="data/swing_k1/tier_a_manifest.json",
        total_config_count=20256,
    )
    m = read_manifest(out)
    assert m["universe_hash"] == "a" * 64
    assert m["kernel_commit"] == "b" * 40
    assert m["total_config_count"] == 20256


def test_configs_jsonl_appends(tmp_path):
    from kryptosbot.swing_k1_artifacts import append_config_row
    out = tmp_path / "configs.jsonl"
    append_config_row(out, {"spec_hash": "x", "bean_passed": False})
    append_config_row(out, {"spec_hash": "y", "bean_passed": True})
    lines = out.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2
    assert json.loads(lines[0])["spec_hash"] == "x"
    assert json.loads(lines[1])["bean_passed"] is True


def test_verdict_md_includes_required_sections(tmp_path):
    from kryptosbot.swing_k1_artifacts import write_verdict_md
    out = tmp_path / "verdict.md"
    write_verdict_md(
        out_path=out,
        classification="NULL_LEVEL",
        universe_hash="z" * 64,
        total_configs=20256,
        admitted_count=0,
        promotions_count=0,
        tier_b_hits_count=0,
    )
    text = out.read_text(encoding="utf-8")
    assert "Universe hash" in text
    assert "Classification" in text
    assert "NULL_LEVEL" in text
    assert "Non-claim banner" in text


def test_split_artifacts_writes_filtered_views(tmp_path):
    """split_artifacts reads configs.jsonl and emits admitted/promotions/tier_b views."""
    from kryptosbot.swing_k1_artifacts import append_config_row, split_artifacts
    cfg = tmp_path / "configs.jsonl"
    append_config_row(cfg, {"spec_hash": "a", "bean_passed": False, "promote_eligible": False})
    append_config_row(cfg, {"spec_hash": "b", "bean_passed": True, "promote_eligible": False})
    append_config_row(cfg, {"spec_hash": "c", "bean_passed": True, "promote_eligible": True,
                            "s1_tier_b_match": None})
    append_config_row(cfg, {"spec_hash": "d", "bean_passed": True, "promote_eligible": False,
                            "s1_tier_b_match": {"source": "fake", "offset": 0, "len": 24}})
    counts = split_artifacts(tmp_path)
    assert counts["admitted"] == 3
    assert counts["promotions"] == 1
    assert counts["tier_b_hits"] == 1
    # File contents are filtered views.
    import json
    admitted = [json.loads(l) for l in (tmp_path / "admitted_keystreams.jsonl").read_text().splitlines()]
    assert {r["spec_hash"] for r in admitted} == {"b", "c", "d"}
    promotions = [json.loads(l) for l in (tmp_path / "promotions.jsonl").read_text().splitlines()]
    assert {r["spec_hash"] for r in promotions} == {"c"}


def test_null_calibration_emitter_round_trip(tmp_path):
    from kryptosbot.swing_k1_artifacts import write_null_calibration
    out = tmp_path / "null_calibration.json"
    write_null_calibration(
        out_path=out,
        method="empirical_shuffled_ct",
        n_trials=10_000,
        sampled_config_count=100,
        baseline_max_joint_event_count=0,
        candidate_p_values={},  # empty when no promotion-eligible candidates
    )
    import json
    d = json.loads(out.read_text())
    assert d["method"] == "empirical_shuffled_ct"
    assert d["n_trials"] == 10_000
    assert d["baseline_max_joint_event_count"] == 0
