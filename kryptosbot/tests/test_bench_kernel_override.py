"""Tests for K4Bench kernel CT/crib override propagation.

Covers tests 6-9 from the K4Bench integration brief:

  6. test_bench_mode_score_candidate_uses_challenge_cribs
  7. test_bench_mode_worker_contract_verification_uses_challenge_cribs
  8. test_bench_mode_job_dispatcher_workers_use_challenge_ct
  9. test_bench_prompt_contains_challenge_ct_not_real_k4_ct
 10. test_bench_prompt_does_not_contain_plaintext_or_answer_layers

The kernel reads ``KRYPTOS_CT_OVERRIDE`` and ``KRYPTOS_CRIB_DICT_OVERRIDE``
once at import time. To test the override path without polluting the
test process kernel state, we run each scenario in an isolated
subprocess that imports ``kryptos.kernel.constants`` fresh.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Synthetic challenge fixture (constructed inline so the test file does not
# depend on bench/k4bench/challenges/*.json existing at test time)
# ---------------------------------------------------------------------------

# A K4-shaped 97-char CT with cribs at 21-33 and 63-73.
def _build_synthetic_ct(crib_at_21: str, crib_at_63: str) -> str:
    """Build a 97-char A-Z string whose declared crib positions match.

    The non-crib positions are deterministically filled with "X" so the
    string is reproducible across test runs. The cribs are NOT decryptable
    — these tests validate that the kernel propagates the override, not
    that any cipher actually works.
    """
    out = list("X" * 97)
    for i, ch in enumerate(crib_at_21):
        out[21 + i] = ch
    for i, ch in enumerate(crib_at_63):
        out[63 + i] = ch
    return "".join(out)


_SYN_CT = "DCXEGPKDRHYITACRUTBWOXRKGXZEOEEQPIULFRQVEELEFFIVBPKKFIEGYDVXEZFOEQWVSRIUQXHZAITUMBFFSORMSPBZTRXPO"
_SYN_CRIB_A = "SECONDSYSTEMX"   # positions 21-33
_SYN_CRIB_B = "COLUMNORDER"     # positions 63-73
_SYN_CRIB_DICT = {
    **{str(21 + i): ch for i, ch in enumerate(_SYN_CRIB_A)},
    **{str(63 + i): ch for i, ch in enumerate(_SYN_CRIB_B)},
}


def _run_subprocess(env_extra: dict[str, str], code: str) -> str:
    """Run a fresh Python subprocess with the given environment.

    The kernel constants module reads env vars at first import. To test
    the override path we need a clean process every time.
    """
    env = {**os.environ, **env_extra}
    env["PYTHONPATH"] = str(_REPO_ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        env=env,
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
        timeout=60,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"Subprocess failed (rc={result.returncode}):\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    return result.stdout


def _bench_env() -> dict[str, str]:
    return {
        "KRYPTOS_CT_OVERRIDE": _SYN_CT,
        "KRYPTOS_CRIB_DICT_OVERRIDE": json.dumps(_SYN_CRIB_DICT),
    }


# ---------------------------------------------------------------------------
# Test 6: score_candidate uses challenge cribs
# ---------------------------------------------------------------------------

def test_bench_mode_score_candidate_uses_challenge_cribs():
    """Under bench overrides, score_candidate scores against the
    challenge cribs (SECONDSYSTEMX / COLUMNORDER), not the K4 cribs
    (EASTNORTHEAST / BERLINCLOCK).

    A 97-char plaintext that is the literal concatenation of the
    challenge cribs at the right positions must score 24/24.
    """
    pt = _build_synthetic_ct(_SYN_CRIB_A, _SYN_CRIB_B)
    code = f"""
import json
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.constants import CRIB_DICT
score = score_cribs({pt!r})
print(json.dumps({{'score': score, 'crib21': CRIB_DICT[21], 'crib63': CRIB_DICT[63]}}))
"""
    out = _run_subprocess(_bench_env(), code)
    payload = json.loads(out.strip().splitlines()[-1])
    assert payload["score"] == 24
    assert payload["crib21"] == "S"  # not "E" (real K4)
    assert payload["crib63"] == "C"  # not "B" (real K4)


def test_bench_mode_score_candidate_rejects_real_k4_plaintext():
    """A plaintext that has the real K4 cribs (EASTNORTHEAST + BERLINCLOCK)
    at the right positions should NOT score 24 under bench mode — the
    challenge cribs are different content."""
    real_k4_pt = _build_synthetic_ct("EASTNORTHEAST", "BERLINCLOCK")
    code = f"""
from kryptos.kernel.scoring.crib_score import score_cribs
print(score_cribs({real_k4_pt!r}))
"""
    out = _run_subprocess(_bench_env(), code)
    score = int(out.strip().splitlines()[-1])
    # The real K4 crib content has near-zero overlap with the
    # synthetic crib content at these positions; whatever shared
    # letters happen to fall at the same offsets are coincidental
    # collisions (e.g. N at position 25 and 68). Score must be far
    # below the 24/24 you would get from the synthetic cribs.
    assert score < 5, (
        f"Score {score} is too high — bench cribs may not be in effect"
    )


# ---------------------------------------------------------------------------
# Test 7: worker contract verification uses challenge cribs
# ---------------------------------------------------------------------------

def test_bench_mode_worker_contract_verification_uses_challenge_cribs():
    """contracts._verify_against_kernel must score worker plaintexts
    against the bench challenge cribs, not real K4 cribs.

    Phase 2 note: the verifier's crib-paste artifact detector masks the
    *real* K4 crib slices (21-33 and 63-73) when computing the non-crib
    ngram score — those slices are also where the bench cribs live, so
    masking applies identically. We use plausible English filler at the
    non-crib positions to keep the ngram score above the -6.2 paste floor;
    X-filler would cause the verifier to reject the result as a crib_paste
    artifact and zero crib_score, masking the bench-override propagation
    we're actually testing.
    """
    # Build a 97-char PT with bench cribs at canonical positions and
    # English filler elsewhere — same shape as _build_synthetic_ct but
    # with a paste-safe filler.
    english_src = ("THEQUICKBROWNFOXJUMPSOVERLAZYDOG" * 4)[:97]
    pt_chars = list(english_src)
    for i, ch in enumerate(_SYN_CRIB_A):
        pt_chars[21 + i] = ch
    for i, ch in enumerate(_SYN_CRIB_B):
        pt_chars[63 + i] = ch
    pt = "".join(pt_chars)
    code = f"""
import json
from kryptosbot.models import WorkerContract, WorkerStatus
from kryptosbot.contracts import _verify_against_kernel
contract = WorkerContract(
    hypothesis_id='HID-TEST',
    status=WorkerStatus.SUCCESS,
    score=20.0,
    crib_score=20,
    bean_passed=True,
    best_plaintext={pt!r},
)
_verify_against_kernel(contract)
print(json.dumps({{'crib_score': contract.crib_score, 'bean_passed': contract.bean_passed}}))
"""
    out = _run_subprocess(_bench_env(), code)
    payload = json.loads(out.strip().splitlines()[-1])
    # The challenge cribs all match the plaintext we built, so the
    # kernel-recomputed crib_score must be 24 (overruling the 20 the
    # worker self-reported).
    assert payload["crib_score"] == 24


# ---------------------------------------------------------------------------
# Test 8: job_dispatcher multiprocessing workers use challenge CT
# ---------------------------------------------------------------------------

def test_bench_mode_job_dispatcher_workers_use_challenge_ct():
    """Forked multiprocessing workers must inherit the override.

    On Linux fork is the default Pool start method; both os.environ
    and the parent's already-imported kernel module memory are
    inherited. We exercise both paths by importing in the worker.
    """
    code = """
import json
from multiprocessing import Pool

def worker(_x):
    from kryptos.kernel.constants import CT, CRIB_DICT
    return {'ct_head': CT[:8], 'crib21': CRIB_DICT[21], 'crib63': CRIB_DICT[63]}

# Pre-import in parent so the override is visible via fork-COW.
from kryptos.kernel.constants import CT  # noqa
with Pool(2) as p:
    results = p.map(worker, [1, 2])
print(json.dumps(results[-1]))
"""
    out = _run_subprocess(_bench_env(), code)
    # The last JSON line is the printed result. Stderr warnings are
    # fine; we only need stdout.
    payload = json.loads(out.strip().splitlines()[-1])
    assert payload["ct_head"] == _SYN_CT[:8]
    assert payload["crib21"] == "S"
    assert payload["crib63"] == "C"


# ---------------------------------------------------------------------------
# Test 9 + 10: prompt redaction
# ---------------------------------------------------------------------------

def test_bench_prompt_contains_challenge_ct_not_real_k4_ct(tmp_path):
    """The K4Bench prompt block contains the challenge CT and cribs,
    not the real K4 CT or cribs."""
    from kryptosbot.bench_loader import K4BenchChallenge

    challenge = K4BenchChallenge(
        bench_id="K4B-PROMPT-T1",
        suite_id="K4BENCH-TEST",
        title="Prompt redaction test",
        ciphertext=_SYN_CT,
        ciphertext_alphabet="AZ",
        crib_dict={int(k): v for k, v in _SYN_CRIB_DICT.items()},
        crib_spans=(
            (21, 33, _SYN_CRIB_A, "crib_a"),
            (63, 73, _SYN_CRIB_B, "crib_b"),
        ),
        clue_text="Some clue.",
        constraint_summary=("A-Z only.",),
        solver_required_fields=("bench_id", "plaintext"),
        strict_pass_rule="exact",
        known_crib_score_target=24,
        challenge_path=tmp_path / "fake.json",
    )

    block = challenge.prompt_block()

    # Must contain the synthetic CT and crib content
    assert _SYN_CT in block
    assert _SYN_CRIB_A in block
    assert _SYN_CRIB_B in block

    # Must NOT contain the real K4 CT (full string)
    real_k4_ct = (
        "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWAT"
        "JKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
    )
    assert real_k4_ct not in block

    # Must NOT contain the real K4 crib content
    assert "EASTNORTHEAST" not in block
    assert "BERLINCLOCK" not in block

    # And must explicitly tell the model this is not real K4
    assert "NOT REAL K4" in block.upper() or "synthetic" in block.lower()


def test_bench_prompt_does_not_contain_plaintext_or_answer_layers(tmp_path):
    """The prompt block exposed to theorists/workers must not contain
    sealed-answer fields. The challenge JSON cannot carry them (the
    loader refuses such files), but we also pin the prompt-block
    output here as a defense in depth."""
    from kryptosbot.bench_loader import K4BenchChallenge

    challenge = K4BenchChallenge(
        bench_id="K4B-PROMPT-T2",
        suite_id="K4BENCH-TEST",
        title="No-answer test",
        ciphertext=_SYN_CT,
        ciphertext_alphabet="AZ",
        crib_dict={int(k): v for k, v in _SYN_CRIB_DICT.items()},
        crib_spans=(
            (21, 33, _SYN_CRIB_A, "crib_a"),
            (63, 73, _SYN_CRIB_B, "crib_b"),
        ),
        clue_text="Some clue.",
        constraint_summary=("A-Z only.",),
        solver_required_fields=("bench_id", "plaintext"),
        strict_pass_rule="exact",
        known_crib_score_target=24,
        challenge_path=tmp_path / "fake.json",
    )

    block = challenge.prompt_block().lower()

    forbidden_substrings = [
        "encryption_layers_in_order",
        "decryption_layers_in_order",
        "sealed",
        "answer_count",
        "decryption_key",
        "encryption_key",
        "solution_layers",
    ]
    for needle in forbidden_substrings:
        assert needle not in block, (
            f"Prompt block must not contain forbidden field {needle!r}"
        )
