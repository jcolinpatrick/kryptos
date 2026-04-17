from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "campaigns"))

import e_marathon_01_final_assault as marathon  # noqa: E402


def test_marathon_checkpoint_load_rejects_duplicate_phases(tmp_path, monkeypatch):
    ckpt = tmp_path / "checkpoint.json"
    monkeypatch.setattr(marathon, "CHECKPOINT_PATH", ckpt)
    ckpt.write_text(json.dumps({
        "phases_done": [0, 1, 1],
        "sa_seeds_done": 0,
        "phase1_done": False,
        "top_candidates": [],
        "total_configs": 0,
        "start_time": 1.0,
    }))
    with pytest.raises(ValueError, match="unique"):
        marathon.Checkpoint.load()


def test_marathon_checkpoint_load_rejects_unknown_phase(tmp_path, monkeypatch):
    ckpt = tmp_path / "checkpoint.json"
    monkeypatch.setattr(marathon, "CHECKPOINT_PATH", ckpt)
    ckpt.write_text(json.dumps({
        "phases_done": [0, 4],
        "sa_seeds_done": 0,
        "phase1_done": False,
        "top_candidates": [],
        "total_configs": 0,
        "start_time": 1.0,
    }))
    with pytest.raises(ValueError, match="0..3"):
        marathon.Checkpoint.load()


def test_marathon_checkpoint_load_rejects_nondict_top_candidates(tmp_path, monkeypatch):
    ckpt = tmp_path / "checkpoint.json"
    monkeypatch.setattr(marathon, "CHECKPOINT_PATH", ckpt)
    ckpt.write_text(json.dumps({
        "phases_done": [0, 1],
        "sa_seeds_done": 10,
        "phase1_done": True,
        "top_candidates": ["bad-row"],
        "total_configs": 123,
        "start_time": 1.0,
    }))
    with pytest.raises(ValueError, match="dict rows"):
        marathon.Checkpoint.load()
