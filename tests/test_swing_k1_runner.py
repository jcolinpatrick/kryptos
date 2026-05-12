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


def test_parallel_run_matches_serial_on_tiny_universe(tmp_path):
    from kryptosbot.swing_k1_runner import run_parallel, run_serial
    out_serial = tmp_path / "serial"
    out_parallel = tmp_path / "parallel"
    s = run_serial(out_dir=out_serial, max_configs=20)
    p = run_parallel(out_dir=out_parallel, max_configs=20, n_workers=2, per_task_timeout_sec=30)
    assert s["total_evaluated"] == p["total_evaluated"]
    assert s["bean_admitted"] == p["bean_admitted"]


def test_parallel_records_timeout_synthetic_result(tmp_path, monkeypatch):
    """Per feedback_pool_worker_no_per_task_timeout.md, hung workers must not block the pool."""
    # Trigger a synthetic 0.01s timeout on every task. Expect timeout rows in configs.jsonl.
    from kryptosbot.swing_k1_runner import run_parallel
    out_dir = tmp_path / "timeouts"
    summary = run_parallel(out_dir=out_dir, max_configs=5, n_workers=2, per_task_timeout_sec=0.01)
    # All 5 should be timed out and recorded as such.
    import json
    rows = [json.loads(l) for l in (out_dir / "configs.jsonl").read_text(encoding="utf-8").splitlines()]
    assert all("per_task_timeout" in r.get("error", "") for r in rows)
