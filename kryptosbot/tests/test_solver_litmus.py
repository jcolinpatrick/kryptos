"""Repeatable litmus gate for the autonomous solver.

Locks the capability across all three difficulty bands using only round-0
(two-layer) sweeps, which are fast (~4s each). These public-CT challenges must
stay solvable; a regression in solver.py, the keyword-columnar DSL feature, or
the dispatcher turns this red. Uses public ciphertext + public cribs only and
never hardcodes a plaintext — each is discovered by the bounded sweep.

The deeper 3-layer challenges are exercised by the full litmus script (not the
unit suite) to keep this gate fast.
"""

import json
import pathlib

import pytest

from kryptosbot.solver import solve

_CHDIR = pathlib.Path(__file__).resolve().parents[2] / "bench/k4bench/challenges"

# Challenges the solver cracks with round-0 (two-layer) sweeps, one per family
# shape, spanning bronze / silver / gold.
_ROUND0_SOLVES = [
    "K4B-001",  # bronze: columnar + vigenere
    "K4B-002",  # bronze: rail-fence + mirror(atbash)
    "K4B-004",  # bronze: columnar/rail + variant_beaufort
    "K4B-005",  # bronze: columnar + KRYPTOS-alphabet substitution
    "K4B-010",  # silver: reverse_blocks + variant_beaufort + KA
    "K4B-014",  # silver: columnar + variant_beaufort
    "K4B-016",  # gold:   reverse_blocks + vigenere + KA
]


@pytest.mark.parametrize("bench_id", _ROUND0_SOLVES)
def test_round0_litmus_solves(bench_id):
    p = json.loads((_CHDIR / f"{bench_id}.json").read_text())
    result = solve(
        ciphertext=p["ciphertext"],
        crib_dict={int(k): v for k, v in p["known_plaintext_positions"].items()},
        clue_text=p["public_clue_pack"]["clue_text"],
        title=p["title"],
        constraint_summary=tuple(p["public_clue_pack"]["constraint_summary"]),
        max_rounds=1,
    )
    assert result.solved, f"{bench_id}: best {result.best_score}/{result.n_cribs}"
