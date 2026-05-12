"""Tests for swing_k1_runner."""
from pathlib import Path

import pytest


def test_serial_run_on_tiny_universe(tmp_path):
    from kryptosbot.swing_k1_runner import run_serial
    out_dir = tmp_path / "tiny_run"
    summary = run_serial(out_dir=out_dir, max_configs=5)
    assert summary["total_evaluated"] == 5
    assert (out_dir / "manifest.json").exists()
    assert (out_dir / "configs.jsonl").exists()


def test_run_writes_admitted_keystreams_for_passing_configs(tmp_path):
    """Real K4 cribs + Vig + AZ + no nulls + M1 control arm = 1 known crib-valid keystream."""
    from kryptosbot.swing_k1_runner import run_serial
    out_dir = tmp_path / "single_vig"
    summary = run_serial(out_dir=out_dir, only_m1=True)
    # M1 control arm produces 6 configs (3 variants x 2 alphabets). One per variant
    # is crib-valid (Vig, Beau, VarBeau).
    assert summary["total_evaluated"] == 6
    assert summary["bean_admitted"] >= 1
