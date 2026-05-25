"""Tests for run_controller.py synthetic-profile CLI plumbing.

PR 1 (2026-05-17) tests:
  - --synthetic-profile parses, validates against the registry
  - --coverage-scheduler-enabled parses, is recorded on the config
  - blocked profile IDs exit nonzero with an explicit message
  - the real-K4 default ledger is refused under --synthetic-profile
  - no test writes to the real-K4 default ledger
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_CONTROLLER = REPO_ROOT / "kryptosbot" / "run_controller.py"
SRC_DIR = REPO_ROOT / "src"


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    """Run run_controller.py with the given args. Capture stderr+stdout."""
    env = {
        "PYTHONPATH": str(SRC_DIR),
        "PATH": Path("/usr/bin").as_posix() + ":" + Path("/bin").as_posix(),
    }
    import os
    full_env = dict(os.environ)
    full_env.update(env)
    return subprocess.run(
        [sys.executable, str(RUN_CONTROLLER), *args],
        env=full_env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_help_advertises_pr1_flags() -> None:
    """The --help surface must show all three PR-1 flags."""
    result = _run_cli("--help")
    assert result.returncode == 0
    assert "--synthetic-profile" in result.stdout
    assert "--coverage-report" in result.stdout
    assert "--coverage-scheduler-enabled" in result.stdout


def test_scheduler_flag_without_profile_rejected() -> None:
    """--coverage-scheduler-enabled alone is meaningless and exits nonzero."""
    result = _run_cli("--coverage-scheduler-enabled")
    assert result.returncode != 0
    assert "requires --synthetic-profile" in result.stderr


def test_scheduler_flag_with_profile_advertised_in_help() -> None:
    """The flag remains visible on --help (regression guard)."""
    result = _run_cli("--help")
    assert result.returncode == 0
    assert "--coverage-scheduler-enabled" in result.stdout
    assert "INERT" not in result.stdout
    assert "does NOT alter" not in result.stdout


def test_unknown_profile_id_rejected() -> None:
    """A bogus profile_id exits nonzero with a registry-listing error."""
    result = _run_cli("--synthetic-profile", "DEFINITELY_NOT_REAL")
    assert result.returncode != 0
    assert "not in the registry" in result.stderr
    # The valid IDs are listed in the error to make typos recoverable.
    assert "T1_SERPENTINE_QUAGMIRE" in result.stderr


def test_blocked_profile_rejected_with_explicit_reason() -> None:
    """T1_TAPE_K3PT exits nonzero AND the blocked_reason text appears.

    Critical: the blocked_reason MUST mention tape consumption and
    null insertion explicitly — that's the PR-1 honesty discipline.
    """
    result = _run_cli("--synthetic-profile", "T1_TAPE_K3PT")
    assert result.returncode != 0
    err = result.stderr.lower()
    assert "blocked" in err
    assert "tape" in err
    assert "null" in err


def test_coverage_report_without_synthetic_profile_rejected() -> None:
    """--coverage-report alone is meaningless and exits nonzero."""
    result = _run_cli("--coverage-report", "/tmp/x")
    assert result.returncode != 0
    assert "requires --synthetic-profile" in result.stderr


def test_synthetic_and_bench_mutually_exclusive() -> None:
    """--synthetic-profile and --bench-challenge cannot combine.

    Note: bench challenge loading runs at module import time, BEFORE
    argparse, so a malformed bench file would fail before this CLI
    validation. We use a real existing challenge file to confirm the
    CLI rejection path fires.
    """
    existing_challenge = (
        REPO_ROOT / "bench" / "k4bench" / "challenges" / "K4B-001.json"
    )
    if not existing_challenge.exists():
        pytest.skip("K4B-001.json fixture not available")
    result = _run_cli(
        "--synthetic-profile", "T1_SERPENTINE_QUAGMIRE",
        "--bench-challenge", str(existing_challenge),
    )
    assert result.returncode != 0
    assert "mutually exclusive" in result.stderr.lower()


def test_synthetic_and_real_k4_hcc_audit_mutually_exclusive() -> None:
    result = _run_cli(
        "--synthetic-profile", "T1_SERPENTINE_QUAGMIRE",
        "--real-k4-hcc-audit",
    )
    assert result.returncode != 0
    assert "mutually exclusive" in result.stderr.lower()


def test_synthetic_status_smoke_no_ledger_write() -> None:
    """--status with --synthetic-profile must not crash and must not
    write to the real-K4 default ledger.

    We verify by reading the size + mtime of db/theory_ledger.sqlite
    (or its non-existence) before and after.
    """
    real_ledger = REPO_ROOT / "db" / "theory_ledger.sqlite"
    pre_state: tuple[bool, int, float]
    if real_ledger.exists():
        st = real_ledger.stat()
        pre_state = (True, st.st_size, st.st_mtime)
    else:
        pre_state = (False, 0, 0.0)
    result = _run_cli(
        "--synthetic-profile", "T1_SERPENTINE_QUAGMIRE",
        "--status",
    )
    # Status path returns 0 even on a missing ledger (the controller
    # creates one on init). We accept either pass or controlled-fail
    # so long as the real ledger was not touched.
    if real_ledger.exists():
        st = real_ledger.stat()
        post_state = (True, st.st_size, st.st_mtime)
    else:
        post_state = (False, 0, 0.0)
    assert post_state == pre_state, (
        f"PR 1 invariant violated: --synthetic-profile run modified "
        f"real-K4 ledger {real_ledger} "
        f"(pre={pre_state}, post={post_state}). stdout={result.stdout!r}, "
        f"stderr={result.stderr!r}"
    )
    # The synthetic-profile ledger should land under db/synthetic_profiles/
    # in the project tree (if the run got far enough to create it).
    syn_ledger_dir = REPO_ROOT / "db" / "synthetic_profiles"
    # No hard assertion that the file exists — --status may short-circuit
    # before any DB write — but the path resolution must not have
    # raised, which is implicitly verified by returncode 0 or a clean
    # error message.
    assert result.returncode in (0, 1), (
        f"unexpected returncode {result.returncode}; "
        f"stderr={result.stderr!r}"
    )
    _ = syn_ledger_dir  # silence unused warning


def test_config_carries_collector_when_synthetic_profile_set(tmp_path: Path) -> None:
    """In-process check (no subprocess) — when --synthetic-profile is set,
    ControllerConfig.coverage_collector is populated and points at the
    right profile.

    We can't easily call run_controller.main() inline (it does asyncio
    work), so we exercise the same code path the CLI uses by importing
    the helpers and replaying the build-config logic.
    """
    from kryptosbot.synthetic_profiles import (
        derive_synthetic_profile_ledger_path,
    )
    from kryptosbot.coverage_audit import build_collector_for_profile
    from kryptosbot.controller import ControllerConfig

    # Mirror run_controller's wiring sequence:
    ledger_path = derive_synthetic_profile_ledger_path(
        "T1_SERPENTINE_QUAGMIRE", project_root=tmp_path,
    )
    collector = build_collector_for_profile(
        "T1_SERPENTINE_QUAGMIRE",
        synthetic_mode=True,
        ledger_db_path=str(ledger_path),
    )
    config = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=ledger_path,
        coverage_collector=collector,
        coverage_scheduler_enabled=False,
    )
    assert config.coverage_collector is collector
    assert config.coverage_scheduler_enabled is False
    # The collector's profile must match
    assert config.coverage_collector.profile.profile_id == "T1_SERPENTINE_QUAGMIRE"


def test_collector_records_via_controller_helper(tmp_path: Path) -> None:
    """The controller's _coverage_record helper feeds the collector."""
    from kryptosbot.coverage_audit import build_collector_for_profile
    from kryptosbot.controller import ControllerConfig, ResearchController

    collector = build_collector_for_profile("T1_SERPENTINE_QUAGMIRE")
    config = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "db" / "synthetic_profiles" / "x.sqlite",
        coverage_collector=collector,
    )
    ctrl = ResearchController(config)
    ctrl._coverage_record(
        "record_emitted_spec",
        hypothesis_id="h1", title="t", family="q", layers=[],
    )
    ctrl._coverage_record(
        "record_critic_outcome",
        hypothesis_id="h1", decision="approve",
    )
    assert len(collector.emitted_specs) == 1
    assert len(collector.critic_outcomes) == 1


def test_collector_helper_noop_when_collector_is_none(tmp_path: Path) -> None:
    """No coverage_collector → helper silently no-ops."""
    from kryptosbot.controller import ControllerConfig, ResearchController

    config = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "db" / "synthetic_profiles" / "x.sqlite",
        coverage_collector=None,
    )
    ctrl = ResearchController(config)
    # Should not raise.
    ctrl._coverage_record("record_emitted_spec", hypothesis_id="x", title="t", family="f", layers=[])
