"""Tests for the K4Bench public-challenge loader.

Covers tests 1-4 from the K4Bench integration brief:

  1. test_bench_loader_accepts_public_challenge
  2. test_bench_loader_rejects_answer_like_file
  3. test_bench_loader_requires_97_char_ct
  4. test_bench_loader_requires_24_crib_positions
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kryptosbot.bench_loader import (
    BenchLoaderError,
    K4BenchChallenge,
    derive_synthetic_ledger_path,
    load_k4bench_challenge,
)


# A minimal-but-valid synthetic challenge fixture. All 24 K4-shape
# positions are present (21-33 inclusive, 63-73 inclusive). The CT is
# random A-Z noise of length 97 — the loader does not care that this
# is unsolvable, only that the structure is correct.
_FIXTURE_CT = (
    "ABCDEFGHIJKLMNOPQRSTU"
    "SECONDSYSTEMX"             # positions 21-33 (13 chars)
    "VWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"  # positions 34-63... wait
)
# Build the CT directly so positions 21-33 = "SECONDSYSTEMX",
# 63-73 = "COLUMNORDER" by construction.
_BUILDER = list("X" * 97)
for i, ch in enumerate("SECONDSYSTEMX"):
    _BUILDER[21 + i] = ch
for i, ch in enumerate("COLUMNORDER"):
    _BUILDER[63 + i] = ch
# Distinct CT (no relation to the cribs since this is a loader test).
_FIXTURE_CT = (
    "DCXEGPKDRHYITACRUTBWO"
    "XRKGXZEOEEQPI"
    "ULFRQVEELEFFIVBPKKFIEGYDVXEZFOEQ"
    "WVSRIUQXHZA"
    "ITUMBFFSORMSPBZTRXPO"
)
assert len(_FIXTURE_CT) == 97


def _public_payload() -> dict:
    """Return a minimal-but-valid K4Bench public challenge dict."""
    return {
        "schema_version": "k4bench.challenge.v1",
        "suite_id": "K4BENCH-TEST",
        "bench_id": "K4B-TEST-001",
        "title": "Test fixture",
        "ciphertext": _FIXTURE_CT,
        "ciphertext_alphabet": "AZ",
        "ciphertext_length": 97,
        "known_plaintext_positions": {
            **{str(21 + i): ch for i, ch in enumerate("SECONDSYSTEMX")},
            **{str(63 + i): ch for i, ch in enumerate("COLUMNORDER")},
        },
        "known_plaintext_spans": [
            {"start": 21, "end_inclusive": 33, "length": 13,
             "text": "SECONDSYSTEMX", "label": "crib_a"},
            {"start": 63, "end_inclusive": 73, "length": 11,
             "text": "COLUMNORDER", "label": "crib_b"},
        ],
        "public_clue_pack": {
            "clue_text": "Test clue text.",
            "constraint_summary": ["A-Z only.", "Length is 97."],
        },
        "solver_output_contract": {
            "required_json_fields": ["bench_id", "plaintext"],
            "strict_pass_rule": "exact plaintext + method",
            "known_crib_score_target": 24,
        },
    }


def _write(tmp_path: Path, payload: dict) -> Path:
    p = tmp_path / "challenge.json"
    p.write_text(json.dumps(payload))
    return p


# ---------------------------------------------------------------------------
# Test 1: accepts a public challenge
# ---------------------------------------------------------------------------

def test_bench_loader_accepts_public_challenge(tmp_path):
    """A valid K4Bench public challenge JSON loads cleanly."""
    path = _write(tmp_path, _public_payload())
    challenge = load_k4bench_challenge(path)

    assert isinstance(challenge, K4BenchChallenge)
    assert challenge.bench_id == "K4B-TEST-001"
    assert challenge.suite_id == "K4BENCH-TEST"
    assert challenge.ciphertext == _FIXTURE_CT
    assert challenge.ciphertext_length == 97
    assert challenge.n_cribs == 24
    assert challenge.crib_dict[21] == "S"
    assert challenge.crib_dict[33] == "X"
    assert challenge.crib_dict[63] == "C"
    assert challenge.crib_dict[73] == "R"
    assert len(challenge.crib_spans) == 2
    assert challenge.clue_text == "Test clue text."
    assert "bench_id" in challenge.solver_required_fields


def test_bench_loader_accepts_real_K4B_001():
    """The shipped K4B-001 challenge JSON loads cleanly.

    Regression: any change to the loader or the shipped challenge JSON
    that breaks this test breaks every controller bench run.
    """
    repo_root = Path(__file__).resolve().parents[2]
    challenge_path = repo_root / "bench" / "k4bench" / "challenges" / "K4B-001.json"
    if not challenge_path.exists():
        pytest.skip(f"K4B-001 fixture missing at {challenge_path}")
    challenge = load_k4bench_challenge(challenge_path)
    assert challenge.bench_id == "K4B-001"
    assert challenge.ciphertext_length == 97
    assert challenge.n_cribs == 24


# ---------------------------------------------------------------------------
# Test 2: rejects answer-like files
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("forbidden_field,forbidden_value", [
    ("plaintext", "X" * 97),
    ("answer", {"plaintext": "X" * 97}),
    ("encryption_layers_in_order", [{"kind": "vigenere"}]),
    ("decryption_layers_in_order", [{"kind": "vigenere"}]),
    ("sealed", True),
    ("answer_count", 1),
    ("solution", "secret"),
    ("decryption_key", "KEY"),
])
def test_bench_loader_rejects_answer_like_file(
    tmp_path, forbidden_field, forbidden_value,
):
    """Any answer-like field at any nesting level must trigger refusal."""
    payload = _public_payload()
    payload[forbidden_field] = forbidden_value
    path = _write(tmp_path, payload)

    with pytest.raises(BenchLoaderError, match="forbidden"):
        load_k4bench_challenge(path)


def test_bench_loader_rejects_nested_answer_field(tmp_path):
    """Nested answer-like fields must also be refused.

    The walker descends into dicts and lists so a sealed answer
    dropped under public_clue_pack.answer is caught.
    """
    payload = _public_payload()
    payload["public_clue_pack"]["plaintext"] = "X" * 97
    path = _write(tmp_path, payload)

    with pytest.raises(BenchLoaderError, match="forbidden"):
        load_k4bench_challenge(path)


# ---------------------------------------------------------------------------
# Test 3: requires 97-char CT
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_ct", [
    "A" * 96,         # too short
    "A" * 98,         # too long
    "A" * 50,         # half-length
    "",               # empty
])
def test_bench_loader_requires_97_char_ct(tmp_path, bad_ct):
    payload = _public_payload()
    payload["ciphertext"] = bad_ct
    payload["ciphertext_length"] = len(bad_ct)
    path = _write(tmp_path, payload)

    with pytest.raises(BenchLoaderError, match="length|ciphertext"):
        load_k4bench_challenge(path)


def test_bench_loader_requires_uppercase_az(tmp_path):
    payload = _public_payload()
    payload["ciphertext"] = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrs"
    path = _write(tmp_path, payload)
    with pytest.raises(BenchLoaderError, match="uppercase A-Z"):
        load_k4bench_challenge(path)


# ---------------------------------------------------------------------------
# Test 4: requires the 24 K4-shape crib positions
# ---------------------------------------------------------------------------

def test_bench_loader_requires_24_crib_positions(tmp_path):
    """Missing one position out of the 24 must trip validation."""
    payload = _public_payload()
    # Drop position 33 ("X")
    del payload["known_plaintext_positions"]["33"]
    # Adjust the corresponding span to keep length consistent — but we
    # still expect failure because the position set is wrong.
    payload["known_plaintext_spans"][0]["text"] = "SECONDSYSTEM"
    payload["known_plaintext_spans"][0]["length"] = 12
    payload["known_plaintext_spans"][0]["end_inclusive"] = 32
    path = _write(tmp_path, payload)

    with pytest.raises(BenchLoaderError, match="24 positions"):
        load_k4bench_challenge(path)


def test_bench_loader_rejects_extra_crib_position(tmp_path):
    """Adding a 25th position must trip validation too."""
    payload = _public_payload()
    payload["known_plaintext_positions"]["44"] = "Z"
    path = _write(tmp_path, payload)

    with pytest.raises(BenchLoaderError, match="Extra"):
        load_k4bench_challenge(path)


def test_bench_loader_rejects_span_text_position_mismatch(tmp_path):
    """If a span declares text that disagrees with positions, refuse."""
    payload = _public_payload()
    # Tamper: set span text to letters that don't match positions
    payload["known_plaintext_spans"][0]["text"] = "QUACKQUACKQUACK"[:13]
    path = _write(tmp_path, payload)
    with pytest.raises(BenchLoaderError, match="disagrees"):
        load_k4bench_challenge(path)


# ---------------------------------------------------------------------------
# Synthetic-ledger path resolver
# ---------------------------------------------------------------------------

def test_derive_synthetic_ledger_path_default(tmp_path):
    out = derive_synthetic_ledger_path(
        "K4B-TEST-001", project_root=tmp_path, requested=None,
    )
    assert "k4bench" in {p.lower() for p in out.parts}
    assert out.name == "K4B-TEST-001.sqlite"


def test_derive_synthetic_ledger_path_refuses_real(tmp_path):
    real = tmp_path / "db" / "theory_ledger.sqlite"
    with pytest.raises(BenchLoaderError, match="real K4 ledger"):
        derive_synthetic_ledger_path(
            "K4B-TEST-001", project_root=tmp_path, requested=real,
        )


def test_derive_synthetic_ledger_path_refuses_neutral_path(tmp_path):
    """A path that has no bench/synthetic segment is refused."""
    neutral = tmp_path / "db" / "ledger.sqlite"
    with pytest.raises(BenchLoaderError, match="bench"):
        derive_synthetic_ledger_path(
            "K4B-TEST-001", project_root=tmp_path, requested=neutral,
        )


def test_derive_synthetic_ledger_path_accepts_explicit_bench_dir(tmp_path):
    requested = tmp_path / "db" / "k4bench" / "custom.sqlite"
    out = derive_synthetic_ledger_path(
        "K4B-TEST-001", project_root=tmp_path, requested=requested,
    )
    assert out == requested.resolve()
