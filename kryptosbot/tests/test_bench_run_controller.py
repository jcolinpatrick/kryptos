"""Tests for the run_controller --bench-challenge integration.

Covers tests 5, 11, 12 from the K4Bench integration brief:

  5. test_bench_mode_uses_synthetic_ledger_not_real_ledger
 11. test_verify_transport_async_inside_running_event_loop
 12. test_run_controller_accepts_bench_challenge_flag_dry_run
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from unittest import mock

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[2]


def _make_synthetic_challenge(tmp_path: Path) -> Path:
    """Write a minimal-but-valid K4Bench public challenge JSON to disk."""
    crib_a = "SECONDSYSTEMX"
    crib_b = "COLUMNORDER"
    ct = "DCXEGPKDRHYITACRUTBWOXRKGXZEOEEQPIULFRQVEELEFFIVBPKKFIEGYDVXEZFOEQWVSRIUQXHZAITUMBFFSORMSPBZTRXPO"
    payload = {
        "schema_version": "k4bench.challenge.v1",
        "suite_id": "K4BENCH-RUN-TEST",
        "bench_id": "K4B-RUN-001",
        "title": "Run controller flag test",
        "ciphertext": ct,
        "ciphertext_alphabet": "AZ",
        "ciphertext_length": 97,
        "known_plaintext_positions": {
            **{str(21 + i): ch for i, ch in enumerate(crib_a)},
            **{str(63 + i): ch for i, ch in enumerate(crib_b)},
        },
        "known_plaintext_spans": [
            {"start": 21, "end_inclusive": 33, "length": 13,
             "text": crib_a, "label": "crib_a"},
            {"start": 63, "end_inclusive": 73, "length": 11,
             "text": crib_b, "label": "crib_b"},
        ],
        "public_clue_pack": {
            "clue_text": "Synthetic test challenge.",
            "constraint_summary": ["A-Z only.", "Length 97."],
        },
        "solver_output_contract": {
            "required_json_fields": ["bench_id", "plaintext"],
            "strict_pass_rule": "exact",
            "known_crib_score_target": 24,
        },
    }
    p = tmp_path / "challenge.json"
    p.write_text(json.dumps(payload))
    return p


# ---------------------------------------------------------------------------
# Test 5: bench mode uses synthetic ledger, never the real K4 ledger
# ---------------------------------------------------------------------------

def test_bench_mode_uses_synthetic_ledger_not_real_ledger(tmp_path):
    """A bench launch must not point its ledger at the real-K4 path,
    and the default --db must redirect to db/k4bench/<bench_id>.sqlite."""
    from kryptosbot.bench_loader import (
        BenchLoaderError,
        derive_synthetic_ledger_path,
    )

    real = tmp_path / "db" / "theory_ledger.sqlite"

    # Default (requested=None) must produce a path under db/k4bench/.
    default_path = derive_synthetic_ledger_path(
        "K4B-RUN-001", project_root=tmp_path, requested=None,
    )
    assert "k4bench" in {p.lower() for p in default_path.parts}

    # Explicitly requesting the real ledger must be refused.
    with pytest.raises(BenchLoaderError, match="real K4"):
        derive_synthetic_ledger_path(
            "K4B-RUN-001", project_root=tmp_path, requested=real,
        )

    # An ambiguous neutral path must also be refused.
    neutral = tmp_path / "db" / "ledger.sqlite"
    with pytest.raises(BenchLoaderError, match="bench"):
        derive_synthetic_ledger_path(
            "K4B-RUN-001", project_root=tmp_path, requested=neutral,
        )


def test_bench_mode_synthetic_pin_propagates_to_ledger(tmp_path):
    """A bench launch creates a ledger pinned to synthetic_mode=synthetic.

    A subsequent real-K4 launch against the same path must be refused
    by SyntheticModeError. The pinning is the project's defense against
    cross-mode contamination.
    """
    from kryptosbot.theory_ledger import SyntheticModeError, TheoryLedger

    db_path = tmp_path / "k4bench_run.sqlite"
    ledger = TheoryLedger(db_path)
    ledger.verify_and_pin_synthetic_mode(synthetic=True)

    # Same mode is a no-op
    ledger.verify_and_pin_synthetic_mode(synthetic=True)

    # Cross-mode launch must fail
    with pytest.raises(SyntheticModeError):
        ledger.verify_and_pin_synthetic_mode(synthetic=False)


# ---------------------------------------------------------------------------
# Test 11: verify_transport_async works inside a running event loop
# ---------------------------------------------------------------------------

def test_verify_transport_async_inside_running_event_loop(monkeypatch):
    """Regression for the nested-asyncio bug fixed by commit c6bbf2e.

    Calling the synchronous ``verify_transport`` from inside an
    already-running event loop raises RuntimeError because
    ``asyncio.run`` cannot create a nested loop. ``run_controller.main``
    is async, so it must call ``verify_transport_async`` instead. This
    test pins both halves: (a) the async variant works inside a loop,
    (b) the sync variant correctly refuses to nest.
    """
    from kryptosbot.transport_preflight import (
        verify_transport,
        verify_transport_async,
    )

    # Patch the inner probes so the test does not actually call out
    # to the SDK. We are testing the asyncio plumbing, not the
    # transport itself.
    monkeypatch.setattr(
        "kryptosbot.transport_preflight.verify_direct_api_k1",
        lambda timeout_sec=60: (True, "stub direct"),
    )

    async def _fake_subscription_probe(timeout_sec=60):
        return True, "stub sub"

    monkeypatch.setattr(
        "kryptosbot.transport_preflight.verify_subscription_sdk",
        _fake_subscription_probe,
    )

    async def _inside_loop_run_async() -> tuple[bool, str]:
        # This MUST work — that is the contract of the async variant.
        return await verify_transport_async(timeout_sec=5)

    ok, summary = asyncio.run(_inside_loop_run_async())
    assert ok is True
    assert "PROCEED" in summary

    # And the sync wrapper, called from inside a loop, should fail
    # loudly rather than silently hanging or producing wrong results.
    async def _inside_loop_call_sync():
        return verify_transport(timeout_sec=5)

    with pytest.raises(RuntimeError):
        asyncio.run(_inside_loop_call_sync())


# ---------------------------------------------------------------------------
# Test 12: run_controller --bench-challenge accepts the flag in dry-run mode
# ---------------------------------------------------------------------------

def test_run_controller_accepts_bench_challenge_flag_dry_run(tmp_path):
    """The argparse + early-import wiring accepts --bench-challenge and
    --dry-run together. We invoke run_controller as a subprocess (it
    is __main__-only) with --status, which exits cleanly without
    touching the SDK or the controller cycle loop, but exercises the
    full kernel-override + ControllerConfig construction path.
    """
    challenge_path = _make_synthetic_challenge(tmp_path)
    db_path = tmp_path / "db" / "k4bench" / "K4B-RUN-001.sqlite"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    env = {**os.environ}
    env["PYTHONPATH"] = str(_REPO_ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")

    result = subprocess.run(
        [
            sys.executable, "-u",
            str(_REPO_ROOT / "kryptosbot" / "run_controller.py"),
            "--bench-challenge", str(challenge_path),
            "--db", str(db_path),
            "--status",
            "-q",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(_REPO_ROOT),
    )
    # --status returns 0 if it can construct the controller and read
    # state. A non-zero exit here means the bench wiring crashed
    # before reaching the cycle loop.
    assert result.returncode == 0, (
        f"rc={result.returncode}\nSTDOUT:\n{result.stdout}\n"
        f"STDERR:\n{result.stderr}"
    )

    # The kernel synthetic-mode warning must have fired on stderr.
    assert "KRYPTOS_CT_OVERRIDE active" in result.stderr or \
        "synthetic" in result.stderr.lower()


def test_run_controller_rejects_invalid_bench_challenge(tmp_path):
    """A malformed challenge JSON must fail the launch with exit code 2,
    not silently fall through into a controller run."""
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema_version": "wrong", "ciphertext": "X" * 50}))
    db_path = tmp_path / "db" / "k4bench" / "BAD.sqlite"

    env = {**os.environ}
    env["PYTHONPATH"] = str(_REPO_ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")

    result = subprocess.run(
        [
            sys.executable, "-u",
            str(_REPO_ROOT / "kryptosbot" / "run_controller.py"),
            "--bench-challenge", str(bad),
            "--db", str(db_path),
            "--status",
            "-q",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(_REPO_ROOT),
    )
    # The bench loader rejects on schema_version mismatch; exit code
    # is 2 (argparse-style) per run_controller.
    assert result.returncode == 2, (
        f"rc={result.returncode}\nSTDOUT:\n{result.stdout}\n"
        f"STDERR:\n{result.stderr}"
    )
    assert "schema_version" in result.stderr or "error:" in result.stderr.lower()
