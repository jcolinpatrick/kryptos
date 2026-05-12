"""Tests for the swing_k1 CLI."""
import subprocess
import sys
from pathlib import Path


def test_cli_help_runs():
    r = subprocess.run(
        [sys.executable, "scripts/campaigns/swing_k1_key_tape.py", "--help"],
        capture_output=True, text=True, env={"PYTHONPATH": "src"},
    )
    assert r.returncode == 0
    assert "swing_k1" in r.stdout.lower() or "swing-k1" in r.stdout.lower()


def test_cli_dry_run_writes_manifest(tmp_path):
    out_dir = tmp_path / "dry"
    r = subprocess.run(
        [sys.executable, "scripts/campaigns/swing_k1_key_tape.py",
         "--dry-run", "--max-configs", "10", "--out-dir", str(out_dir)],
        capture_output=True, text=True, env={"PYTHONPATH": "src"},
    )
    assert r.returncode == 0, f"stderr: {r.stderr}"
    assert (out_dir / "manifest.json").exists()
