from kryptosbot.coverage_synthetic import (
    CANONICAL_PLAINTEXT,
    generate_synthetic_challenge,
)
from kryptosbot.synthetic_profiles import all_profiles, get_profile


def test_canonical_plaintext_is_97_upper_alpha() -> None:
    assert len(CANONICAL_PLAINTEXT) == 97
    assert CANONICAL_PLAINTEXT.isalpha()
    assert CANONICAL_PLAINTEXT.isupper()


def test_generated_ct_is_97_chars_and_differs_from_pt() -> None:
    for pid in ("T1_SERPENTINE_QUAGMIRE", "T1_BERLINCLOCK_COLUMNAR"):
        spec = get_profile(pid).closing_spec
        ct, cribs = generate_synthetic_challenge(spec)
        assert len(ct) == 97
        assert ct != CANONICAL_PLAINTEXT  # mechanism actually transformed it
        assert len(cribs) == 24


def test_cribs_are_canonical_pt_at_standard_positions() -> None:
    from kryptos.kernel.constants import CRIB_POSITIONS
    spec = get_profile("T1_SERPENTINE_QUAGMIRE").closing_spec
    _, cribs = generate_synthetic_challenge(spec)
    assert set(cribs.keys()) == set(CRIB_POSITIONS)
    for pos in CRIB_POSITIONS:
        assert cribs[pos] == CANONICAL_PLAINTEXT[pos]


def test_round_trip_recovers_plaintext_via_dispatch() -> None:
    # The generated CT, dispatched through the closing_spec (decrypt
    # direction), must recover CANONICAL_PLAINTEXT exactly -> crib_score 24.
    from kryptosbot import job_dispatcher
    for pid in ("T1_SERPENTINE_QUAGMIRE", "T1_BERLINCLOCK_COLUMNAR"):
        spec = get_profile(pid).closing_spec
        ct, cribs = generate_synthetic_challenge(spec)
        result = job_dispatcher.execute_from_json(
            spec, challenge_ciphertext=ct, challenge_crib_dict=cribs,
            bench_mode=True, parallel=False,
        )
        assert result.best_score == 24, (pid, result.best_score)


def test_multi_layer_spec_rejected() -> None:
    import pytest
    two_layer = {
        "hypothesis_id": "two",
        "pipeline": [
            {"kind": "atbash", "alphabet": "AZ", "params": []},
            {"kind": "atbash", "alphabet": "AZ", "params": []},
        ],
        "compute_budget_cpu_minutes": 30,
    }
    with pytest.raises(ValueError):
        generate_synthetic_challenge(two_layer)
