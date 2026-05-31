"""Lever A: trust the sweep tool's KERNEL-VERIFIED result, not the LLM's prose.

A live run showed the theorist label a hand-authored, keyword-swapped single
config "confirmed solve" — and the controller dispatched that (1/24). The fix:
``sweep_clue_bounded`` runs kernel-verified searches (execute()), records each
finding to a registry, and the controller surfaces the best VERIFIED finding
itself, so an LLM hallucination can never masquerade as a solve.
"""

import asyncio
import pathlib

from kryptosbot import dsl_tools
from kryptosbot.solver import best_verified_finding

_ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_sweep_tool_records_kernel_verified_finding():
    dsl_tools.reset_sweep_findings()
    # Runs against the real-K4 kernel CT (no bench override here); it won't
    # solve, but it must RECORD a kernel-verified finding with the right shape.
    asyncio.run(dsl_tools.sweep_clue_bounded_tool.handler(
        {"families": ["columnar", "vigenere"], "keywords": ["KRYPTOS", "BERLIN"]}
    ))
    findings = dsl_tools.get_sweep_findings()
    assert len(findings) == 1
    f = findings[0]
    for key in ("solved", "best_score", "n_cribs", "plaintext", "config_id", "families", "keywords"):
        assert key in f, (key, f)
    assert isinstance(f["solved"], bool)
    assert isinstance(f["best_score"], int)


def test_reset_clears_findings():
    dsl_tools.reset_sweep_findings()
    assert dsl_tools.get_sweep_findings() == []


def test_best_verified_finding_prefers_solve_then_score():
    findings = [
        {"solved": False, "best_score": 7, "plaintext": "a"},
        {"solved": True, "best_score": 24, "plaintext": "WIN"},
        {"solved": False, "best_score": 16, "plaintext": "b"},
    ]
    best = best_verified_finding(findings)
    assert best["plaintext"] == "WIN" and best["solved"] is True
    # No solve -> highest score wins.
    best2 = best_verified_finding([{"solved": False, "best_score": 7}, {"solved": False, "best_score": 16}])
    assert best2["best_score"] == 16
    assert best_verified_finding([]) is None


def test_controller_surfaces_verified_sweep_finding():
    src = (_ROOT / "controller.py").read_text()
    # Controller must read the registry and reset it per cycle, and trust the
    # verified finding rather than the theorist's prose.
    assert "get_sweep_findings" in src
    assert "reset_sweep_findings" in src
    assert "best_verified_finding" in src
    # A kernel-verified solve is the authoritative outcome: the run halts on it.
    assert "_last_verified_sweep_finding" in src
    assert "RUN HALTED" in src
