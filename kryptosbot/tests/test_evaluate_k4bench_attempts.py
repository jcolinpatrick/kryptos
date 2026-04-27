"""Tests for tools/evaluate_k4bench_attempts.py.

Covers the user-mandated cases from the K4Bench evaluator spec:

  1. Four attempts under one bench_id where best crib_score is NOT the
     last entry — the evaluator must pick the highest score, not the
     last position.
  2. Empty layers yields method_functional=None.
  3. Replay attempted but produces wrong plaintext yields
     method_functional=False.
  4. Replay produces the submitted plaintext yields
     method_functional=True.
  5. strict_pass is True only when plaintext_exact AND
     method_functional == True; method_functional == None never
     satisfies strict_pass even when plaintext_exact is True.

The evaluator lives outside the kryptosbot package, so we add the
repo root to sys.path before importing it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools import evaluate_k4bench_attempts as ev  # noqa: E402


# --- Helpers -----------------------------------------------------------------


# A K4-shaped synthetic challenge: identity ciphertext == plaintext, both
# 97 chars, alphabetic. Using identity layers means replay produces
# exactly the input ciphertext, which is also the answer plaintext when
# we want method_functional=True. For mismatches we just substitute a
# different submitted_plaintext.
_IDENTITY_PT = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRS"
assert len(_IDENTITY_PT) == 97 and _IDENTITY_PT.isalpha() and _IDENTITY_PT.isupper()
_IDENTITY_CT = _IDENTITY_PT  # identity layer ⇒ CT == PT


def _attempt(
    *,
    bench_id: str = "K4B-T01",
    plaintext: str = _IDENTITY_PT,
    crib_score: int = 0,
    confidence: float = 0.0,
    layers: list[dict] | None = None,
    bindings: list[list] | None = None,
    method_summary: str = "",
) -> dict:
    """Build one attempt-shaped dict for the artifact."""
    return {
        "bench_id": bench_id,
        "plaintext": plaintext,
        "confidence": confidence,
        "method_summary": method_summary,
        "layers": layers if layers is not None else [],
        "crib_score": crib_score,
        "evidence": {},
        "reproducibility_notes": "",
        "best_config_bindings": bindings or [],
    }


def _artifact(attempts: list[dict]) -> dict:
    """Wrap an attempts list in the k4bench.attempts.v1 envelope."""
    return {
        "schema_version": "k4bench.attempts.v1",
        "generated_at": "2026-04-27T00:00:00+00:00",
        "challenge": {"bench_id": "K4B-T01"},
        "ledger_summary": {},
        "attempts": attempts,
        "notes": "",
    }


def _answers(*, plaintext: str = _IDENTITY_PT, ciphertext: str = _IDENTITY_CT) -> dict:
    """Build the by-bench-id answer map for one challenge."""
    return {
        "K4B-T01": {
            "bench_id": "K4B-T01",
            "ciphertext": ciphertext,
            "plaintext": plaintext,
        },
    }


def _identity_layers() -> list[dict]:
    """One identity layer — replays to identity (PT == CT)."""
    return [{"kind": "identity", "alphabet": "AZ", "params": [], "recipe_id": None}]


def _vigenere_layers(keyword: str = "CEDAR") -> list[dict]:
    """One Vigenere layer with a fixed keyword."""
    return [{
        "kind": "vigenere",
        "alphabet": "AZ",
        "params": [{
            "name": "keyword",
            "values": [keyword],
            "start": None,
            "stop": None,
            "source_corpus": None,
            "cardinality_cap": 10000,
        }],
        "recipe_id": None,
    }]


# --- Test 1: best is not last ------------------------------------------------


def test_evaluator_picks_best_crib_score_not_last_attempt():
    """User-mandated: four attempts under one bench_id where best
    crib_score is NOT the last entry. Mirrors the real K4B-001
    artifact (crib_scores 4, 2, 2, 1, ordered first-to-last).
    """
    attempts = [
        _attempt(crib_score=4, confidence=0.16, plaintext="A" * 97),
        _attempt(crib_score=2, confidence=0.08, plaintext="B" * 97),
        _attempt(crib_score=2, confidence=0.08, plaintext="C" * 97),
        _attempt(crib_score=1, confidence=0.04, plaintext="D" * 97),
    ]
    answers = _answers(plaintext="Z" * 97, ciphertext=_IDENTITY_CT)
    report = ev.evaluate(answers, _artifact(attempts))
    assert len(report["per_bench"]) == 1
    bench = report["per_bench"][0]
    assert bench["bench_id"] == "K4B-T01"
    assert bench["n_attempts_seen"] == 4
    assert bench["chosen_attempt_index"] == 0  # first attempt has crib_score=4
    assert bench["claimed_crib_score"] == 4
    assert bench["claimed_plaintext_preview"].startswith("AAA")


def test_evaluator_picks_best_when_best_is_truly_last():
    """Sanity: when the best DOES land last, the evaluator still picks
    it. Guards against the inverse foot-gun (always picking index 0).
    """
    attempts = [
        _attempt(crib_score=1, plaintext="A" * 97),
        _attempt(crib_score=2, plaintext="B" * 97),
        _attempt(crib_score=2, plaintext="C" * 97),
        _attempt(crib_score=4, plaintext="Z" * 97),  # best, last
    ]
    answers = _answers(plaintext="Z" * 97, ciphertext=_IDENTITY_CT)
    report = ev.evaluate(answers, _artifact(attempts))
    bench = report["per_bench"][0]
    assert bench["chosen_attempt_index"] == 3
    assert bench["claimed_crib_score"] == 4


def test_evaluator_breaks_ties_by_confidence():
    """Tie on crib_score → higher confidence wins."""
    attempts = [
        _attempt(crib_score=2, confidence=0.10, plaintext="A" * 97),
        _attempt(crib_score=2, confidence=0.30, plaintext="B" * 97),  # best
        _attempt(crib_score=2, confidence=0.20, plaintext="C" * 97),
    ]
    answers = _answers(plaintext="Z" * 97, ciphertext=_IDENTITY_CT)
    report = ev.evaluate(answers, _artifact(attempts))
    bench = report["per_bench"][0]
    assert bench["chosen_attempt_index"] == 1
    assert bench["claimed_confidence"] == 0.30


# --- Test 2: empty layers → method_functional=None ---------------------------


def test_empty_layers_yields_method_functional_null():
    """User-mandated: empty layers yields method_functional=None.
    Empty layers should NOT be conflated with replay failure.
    """
    attempts = [_attempt(crib_score=4, plaintext=_IDENTITY_PT, layers=[])]
    answers = _answers()
    report = ev.evaluate(answers, _artifact(attempts))
    bench = report["per_bench"][0]
    assert bench["method_functional"] is None
    # plaintext_exact is True (the submitted PT == answer PT) but
    # strict_pass must still be False because method_functional is None.
    assert bench["plaintext_exact"] is True
    assert bench["strict_pass"] is False


def test_unsupported_layer_kind_yields_method_functional_null():
    """A layer kind outside the dispatcher's supported set is treated
    as 'cannot fairly judge', not as failure. method_functional=None.
    """
    bogus_layers = [{
        "kind": "telepathy",
        "alphabet": "AZ",
        "params": [],
        "recipe_id": None,
    }]
    attempts = [_attempt(plaintext=_IDENTITY_PT, layers=bogus_layers)]
    answers = _answers()
    report = ev.evaluate(answers, _artifact(attempts))
    bench = report["per_bench"][0]
    assert bench["method_functional"] is None
    assert bench["replay_error"] is not None
    assert "unsupported" in bench["replay_error"]
    assert bench["strict_pass"] is False


# --- Test 3: replay mismatch → method_functional=False -----------------------


def test_replay_mismatch_yields_method_functional_false():
    """Replay attempted, layers run, but the resulting plaintext does
    not match the submitted plaintext → method_functional=False.

    Identity layer applied to _IDENTITY_CT produces _IDENTITY_PT. We
    submit a DIFFERENT plaintext, so the mismatch surfaces as False.
    """
    attempts = [_attempt(
        plaintext="Z" * 97,        # claimed PT
        layers=_identity_layers(),  # would actually decrypt to _IDENTITY_PT
    )]
    answers = _answers(plaintext="Z" * 97, ciphertext=_IDENTITY_CT)
    report = ev.evaluate(answers, _artifact(attempts))
    bench = report["per_bench"][0]
    assert bench["method_functional"] is False
    # plaintext_exact is True (submitted ZZZ == answer ZZZ), but
    # method_functional False blocks strict_pass.
    assert bench["plaintext_exact"] is True
    assert bench["strict_pass"] is False


# --- Test 4: replay success → method_functional=True -------------------------


def test_replay_success_yields_method_functional_true():
    """Identity layer on identity CT produces the submitted PT."""
    attempts = [_attempt(
        plaintext=_IDENTITY_PT,
        layers=_identity_layers(),
    )]
    answers = _answers()
    report = ev.evaluate(answers, _artifact(attempts))
    bench = report["per_bench"][0]
    assert bench["method_functional"] is True
    assert bench["plaintext_exact"] is True
    assert bench["strict_pass"] is True


def test_vigenere_replay_success():
    """Vigenere(CEDAR) decrypt on Vigenere(CEDAR)-encrypted CT yields
    the original PT. Confirms a real cipher kind round-trips through
    the evaluator's replay.
    """
    keyword = "CEDAR"
    # Build CT by encrypting _IDENTITY_PT with Vigenere CEDAR
    key_ints = [ord(c) - 65 for c in keyword]
    ct_chars = []
    for i, ch in enumerate(_IDENTITY_PT):
        shift = key_ints[i % len(key_ints)]
        ct_chars.append(chr((ord(ch) - 65 + shift) % 26 + 65))
    ct = "".join(ct_chars)
    attempts = [_attempt(
        plaintext=_IDENTITY_PT,
        layers=_vigenere_layers(keyword),
    )]
    answers = _answers(plaintext=_IDENTITY_PT, ciphertext=ct)
    report = ev.evaluate(answers, _artifact(attempts))
    bench = report["per_bench"][0]
    assert bench["method_functional"] is True
    assert bench["plaintext_exact"] is True
    assert bench["strict_pass"] is True


# --- Test 5: strict_pass truth table -----------------------------------------


@pytest.mark.parametrize(
    "plaintext_match, method_func_state, expected_strict_pass",
    [
        # Both pass dimensions True → strict_pass True
        (True, "true", True),
        # Either one False → strict_pass False
        (False, "true", False),
        (True, "false", False),
        (False, "false", False),
        # method_functional == None never satisfies strict_pass,
        # even when plaintext_exact is True
        (True, "null", False),
        (False, "null", False),
    ],
)
def test_strict_pass_truth_table(plaintext_match, method_func_state, expected_strict_pass):
    """Verify the binding rule: strict_pass = plaintext_exact AND
    (method_functional is True). None never passes.
    """
    if method_func_state == "true":
        layers = _identity_layers()         # replay returns _IDENTITY_PT
        submitted_pt = _IDENTITY_PT
    elif method_func_state == "false":
        layers = _identity_layers()         # replay returns _IDENTITY_PT
        submitted_pt = "Z" * 97             # mismatch ⇒ method False
    else:  # null
        layers = []                         # no layers ⇒ method None
        submitted_pt = _IDENTITY_PT

    if plaintext_match:
        answer_pt = submitted_pt
    else:
        answer_pt = "X" * 97

    attempts = [_attempt(plaintext=submitted_pt, layers=layers)]
    answers = _answers(plaintext=answer_pt, ciphertext=_IDENTITY_CT)
    report = ev.evaluate(answers, _artifact(attempts))
    bench = report["per_bench"][0]
    assert bench["strict_pass"] is expected_strict_pass


# --- Existing-artifact regression --------------------------------------------


def test_existing_k4b001_artifact_picks_score_4_not_score_1(tmp_path: Path):
    """User-mandated regression: the existing K4B-001 attempt artifact
    (results/k4bench_attempts/K4B-001_fallback_attempt.json) has four
    attempts with crib_scores 4, 2, 2, 1. The evaluator must report
    claimed_crib_score=4, NOT claimed_crib_score=1.

    This test loads the actual artifact from disk; it pins the bug
    the user observed (an older evaluator picked the LAST attempt).
    """
    artifact_path = (
        _REPO_ROOT / "results" / "k4bench_attempts" /
        "K4B-001_fallback_attempt.json"
    )
    if not artifact_path.exists():
        pytest.skip(f"existing K4B-001 artifact not on disk at {artifact_path}")

    # Build a minimal answers fixture for K4B-001. We do not have the
    # sealed answer, so use the artifact's own claimed plaintext; that
    # forces plaintext_exact=True so we can isolate the ranking check.
    with artifact_path.open() as f:
        artifact = json.load(f)
    bench_id = artifact["attempts"][0]["bench_id"]
    # Best (highest crib_score) attempt's plaintext, not first-or-last
    best_pt = max(
        artifact["attempts"],
        key=lambda a: (a.get("crib_score", 0), a.get("confidence", 0.0)),
    )["plaintext"]

    challenge_path = _REPO_ROOT / "bench" / "k4bench" / "challenges" / f"{bench_id}.json"
    with challenge_path.open() as f:
        challenge = json.load(f)
    answers = {
        bench_id: {
            "bench_id": bench_id,
            "ciphertext": challenge["ciphertext"],
            "plaintext": best_pt,
        },
    }

    report = ev.evaluate(answers, artifact)
    assert len(report["per_bench"]) == 1
    bench = report["per_bench"][0]
    # The bug-fix point: claimed_crib_score must be 4, not 1.
    assert bench["claimed_crib_score"] == 4, (
        f"Expected best attempt (crib_score=4) to be picked; "
        f"got {bench['claimed_crib_score']} — evaluator regressed to "
        f"last-attempt selection."
    )


# --- Answers loader behaviour ------------------------------------------------


def test_answers_loader_accepts_list_shape(tmp_path: Path):
    answers_file = tmp_path / "answers.json"
    answers_file.write_text(json.dumps([
        {"bench_id": "K4B-T01", "ciphertext": _IDENTITY_CT, "plaintext": _IDENTITY_PT},
    ]))
    loaded = ev._load_answers(answers_file)
    assert "K4B-T01" in loaded


def test_answers_loader_accepts_dict_shape(tmp_path: Path):
    answers_file = tmp_path / "answers.json"
    answers_file.write_text(json.dumps({
        "K4B-T01": {"ciphertext": _IDENTITY_CT, "plaintext": _IDENTITY_PT},
    }))
    loaded = ev._load_answers(answers_file)
    assert "K4B-T01" in loaded


def test_answers_loader_accepts_envelope_shape(tmp_path: Path):
    answers_file = tmp_path / "answers.json"
    answers_file.write_text(json.dumps({
        "answers": [
            {"bench_id": "K4B-T01", "ciphertext": _IDENTITY_CT, "plaintext": _IDENTITY_PT},
        ],
    }))
    loaded = ev._load_answers(answers_file)
    assert "K4B-T01" in loaded


def test_answers_loader_rejects_bad_plaintext_length(tmp_path: Path):
    answers_file = tmp_path / "answers.json"
    answers_file.write_text(json.dumps([
        {"bench_id": "K4B-T01", "ciphertext": _IDENTITY_CT, "plaintext": "TOOSHORT"},
    ]))
    with pytest.raises(ev.EvaluatorError):
        ev._load_answers(answers_file)


# --- CLI smoke ---------------------------------------------------------------


def test_cli_writes_to_out_path(tmp_path: Path):
    """End-to-end: --attempts and --answers in, --out file populated."""
    attempts_file = tmp_path / "attempts.json"
    answers_file = tmp_path / "answers.json"
    out_file = tmp_path / "report.json"

    attempts_file.write_text(json.dumps(_artifact([
        _attempt(plaintext=_IDENTITY_PT, layers=_identity_layers(), crib_score=24),
    ])))
    answers_file.write_text(json.dumps([
        {"bench_id": "K4B-T01", "ciphertext": _IDENTITY_CT, "plaintext": _IDENTITY_PT},
    ]))

    rc = ev.main([
        "--attempts", str(attempts_file),
        "--answers", str(answers_file),
        "--out", str(out_file),
    ])
    assert rc == 0  # PASS
    report = json.loads(out_file.read_text())
    assert report["summary"]["verdict"] == "PASS"
    assert report["per_bench"][0]["strict_pass"] is True


def test_cli_returns_nonzero_on_failure(tmp_path: Path):
    """Mismatched plaintext → strict_pass False → exit code 1."""
    attempts_file = tmp_path / "attempts.json"
    answers_file = tmp_path / "answers.json"
    out_file = tmp_path / "report.json"

    attempts_file.write_text(json.dumps(_artifact([
        _attempt(plaintext="Z" * 97, layers=_identity_layers()),
    ])))
    answers_file.write_text(json.dumps([
        {"bench_id": "K4B-T01", "ciphertext": _IDENTITY_CT, "plaintext": _IDENTITY_PT},
    ]))

    rc = ev.main([
        "--attempts", str(attempts_file),
        "--answers", str(answers_file),
        "--out", str(out_file),
    ])
    assert rc == 1  # FAIL
    report = json.loads(out_file.read_text())
    assert report["summary"]["verdict"] == "FAIL"
