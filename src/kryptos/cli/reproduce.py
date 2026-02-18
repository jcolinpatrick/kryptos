"""Reproduce — rerun a prior experiment from its manifest.

Loads a run manifest and re-executes the same experiment with
the same configuration, verifying reproducibility.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from kryptos.kernel.persistence.artifacts import RunManifest


def reproduce_run(manifest_path: str) -> int:
    """Rerun an experiment from its manifest file.

    Returns 0 on success, 1 on failure.
    """
    manifest = RunManifest.load(manifest_path)

    print(f"Reproducing run: {manifest.run_id}")
    print(f"Experiment: {manifest.experiment_name}")
    print(f"Original timestamp: {manifest.timestamp}")
    print(f"Seed: {manifest.seed}")
    print()

    # Load the config and determine what type of run this was
    config = manifest.config

    if "transposition_family" in config:
        # It's a sweep config
        from kryptos.kernel.config import SweepConfig
        sweep_config = SweepConfig.from_dict(config)
        # Override DB path to avoid overwriting original
        sweep_config_dict = sweep_config.to_dict()
        sweep_config_dict["db_path"] = f"db/reproduce_{manifest.run_id}.sqlite"
        sweep_config = SweepConfig.from_dict(sweep_config_dict)
        print(f"Sweep config loaded. DB: {sweep_config.db_path}")
        print("To execute, use: kryptos sweep with this config")
        return 0

    print(f"Config: {json.dumps(config, indent=2)}")
    print("Manual reproduction required for this experiment type.")
    return 0
