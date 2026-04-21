"""R3-0.5-2 tests: grille translator.

Covers the Cardano-grille gather path under the permutation-only
interpretation. The grille layer dispatches through
``TransformType.GRILLE`` which delegates to
``kryptos.kernel.transforms.grille.apply_grille_permutation``.

Adversarial coverage required by the brief: every error mode in
``validate_grille_mask`` is exercised; translator error messages
mention the specific validation failure; the defensive guard against
accidental kernel bypass is exercised.
"""
from __future__ import annotations

import random

import pytest

from kryptos.kernel.constants import CT, CT_LEN
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.transforms.compose import TransformType
from kryptos.kernel.transforms.grille import (
    apply_grille_permutation,
    validate_grille_mask,
)
from kryptos.kernel.transforms.transposition import apply_perm, invert_perm
from kryptosbot.hypothesis_dsl import (
    CipherLayer,
    HypothesisSpec,
    ParamRange,
    _VALID_CIPHER_KINDS,
)
from kryptosbot.job_dispatcher import (
    DispatcherError,
    _SUPPORTED_KINDS,
    _translate_layer,
    execute,
)


# ─── Kind registration ───────────────────────────────────────────────────────


def test_grille_in_dispatcher_supported_kinds():
    assert "grille" in _SUPPORTED_KINDS


def test_grille_in_dsl_valid_cipher_kinds():
    """R3-0.5-2 added grille to the DSL literal so HypothesisSpec
    validation accepts it. Regression guard against removal."""
    assert "grille" in _VALID_CIPHER_KINDS


def test_grille_in_transform_type_enum():
    """compose.py registration must be present for dispatch."""
    assert TransformType.GRILLE.value == "grille"


# ─── validate_grille_mask ────────────────────────────────────────────────────


def test_validate_mask_identity_ok():
    errors = validate_grille_mask(list(range(97)), CT_LEN)
    assert errors == []


def test_validate_mask_reverse_ok():
    errors = validate_grille_mask(list(range(96, -1, -1)), CT_LEN)
    assert errors == []


def test_validate_mask_wrong_length():
    errors = validate_grille_mask([0, 1, 2], CT_LEN)
    assert any("length 3" in e for e in errors)


def test_validate_mask_duplicates():
    mask = list(range(97))
    mask[10] = mask[20]  # duplicate
    errors = validate_grille_mask(mask, CT_LEN)
    assert any("duplicate" in e for e in errors)


def test_validate_mask_out_of_range_high():
    mask = list(range(97))
    mask[0] = 999
    errors = validate_grille_mask(mask, CT_LEN)
    assert any("out-of-range" in e for e in errors)


def test_validate_mask_negative_position():
    mask = list(range(97))
    mask[0] = -1
    errors = validate_grille_mask(mask, CT_LEN)
    assert any("negative" in e for e in errors)


def test_validate_mask_non_int_entries():
    mask = list(range(97))
    mask[0] = "zero"
    errors = validate_grille_mask(mask, CT_LEN)
    assert any("non-bool ints" in e for e in errors)


def test_validate_mask_rejects_bool_entries():
    """Python's True/False are ints. The validator must reject them
    specifically; otherwise a mask [False, True, 2, 3, ...] would
    parse as [0, 1, 2, 3, ...] and silently succeed."""
    mask = [False, True] + list(range(2, 97))
    errors = validate_grille_mask(mask, CT_LEN)
    assert any("non-bool ints" in e for e in errors)


# ─── apply_grille_permutation ────────────────────────────────────────────────


def test_apply_grille_identity_returns_input_unchanged():
    mask = list(range(97))
    out = apply_grille_permutation(CT, mask)
    assert out == CT


def test_apply_grille_reverse():
    mask = list(range(96, -1, -1))
    out = apply_grille_permutation(CT, mask)
    assert out == CT[::-1]


def test_apply_grille_matches_apply_perm():
    """apply_grille_permutation is semantically identical to
    apply_perm for the permutation-only interpretation. Regression
    guard against divergence if either implementation is refactored."""
    random.seed(42)
    mask = list(range(97))
    random.shuffle(mask)
    assert apply_grille_permutation(CT, mask) == apply_perm(CT, mask)


def test_apply_grille_bijection_property_random_masks():
    """Gather is bijective: applying the inverse mask reconstructs
    the original text. Property test over 50 random permutations
    to catch any bit-rot in the invert_perm / apply_perm chain."""
    rng = random.Random(12345)
    for _ in range(50):
        mask = list(range(97))
        rng.shuffle(mask)
        permuted = apply_grille_permutation(CT, mask)
        inverse = invert_perm(mask)
        recovered = apply_grille_permutation(permuted, inverse)
        assert recovered == CT


# ─── _translate_layer case ───────────────────────────────────────────────────


def test_translate_grille_missing_hole_mask_raises():
    layer = CipherLayer(kind="grille", alphabet="AZ")
    with pytest.raises(DispatcherError, match="requires 'hole_mask'"):
        _translate_layer(layer, binding={})


def test_translate_grille_non_list_hole_mask_raises():
    layer = CipherLayer(kind="grille", alphabet="AZ")
    with pytest.raises(DispatcherError, match="must be list/tuple"):
        _translate_layer(layer, binding={"hole_mask": "not a list"})


def test_translate_grille_invalid_mask_raises_with_specific_error():
    layer = CipherLayer(kind="grille", alphabet="AZ")
    # Mask is only 10 positions (wrong length).
    with pytest.raises(DispatcherError, match="invalid:.*length"):
        _translate_layer(layer, binding={"hole_mask": list(range(10))})


def test_translate_grille_valid_mask_produces_correct_step_dict():
    layer = CipherLayer(kind="grille", alphabet="AZ")
    mask = list(range(97))
    step = _translate_layer(layer, binding={"hole_mask": mask})
    assert step["type"] == "grille"
    assert step["params"]["mask_order"] == mask
    # Step dict must be JSON-serializable (multiprocessing picklability).
    import json
    json.dumps(step)


def test_translate_grille_tuple_mask_accepted():
    """Masks passed as tuples must work the same as lists — they're
    immutable but semantically identical."""
    layer = CipherLayer(kind="grille", alphabet="AZ")
    mask = tuple(range(97))
    step = _translate_layer(layer, binding={"hole_mask": mask})
    assert step["type"] == "grille"
    # Translator normalizes to list for JSON serialization.
    assert step["params"]["mask_order"] == list(mask)


# ─── End-to-end dispatch ─────────────────────────────────────────────────────


def test_execute_grille_identity_dispatches_and_kernel_scores():
    """Identity mask yields CT unchanged; kernel scores the raw CT."""
    spec = HypothesisSpec(
        hypothesis_id="e2e-grille-identity",
        pipeline=[CipherLayer(
            kind="grille",
            params=[ParamRange(name="hole_mask",
                               values=[list(range(97))])],
        )],
    )
    # Pass empty exhaustion_log — the grille family is exhausted in the
    # live log, but this test targets dispatch semantics, not admissibility
    # policy. The R2-3 override mechanism is tested separately.
    result = execute(spec, parallel=False, exhaustion_log={})
    assert result.admissibility_verdict == "ok"
    assert result.total_tested == 1
    kernel_breakdown = score_candidate(CT)
    assert result.best_candidate is not None
    assert result.best_candidate["crib_score"] == int(
        kernel_breakdown.crib_score
    )
    assert result.best_candidate["bean_passed"] == bool(
        kernel_breakdown.bean_passed
    )


def test_execute_grille_sweeps_multiple_masks():
    """ParamRange with multiple mask values enumerates them all."""
    masks = [
        list(range(97)),
        list(range(96, -1, -1)),
        list(range(0, 97, 2)) + list(range(1, 97, 2)),
    ]
    spec = HypothesisSpec(
        hypothesis_id="e2e-grille-sweep",
        pipeline=[CipherLayer(
            kind="grille",
            params=[ParamRange(name="hole_mask", values=masks)],
        )],
    )
    result = execute(spec, parallel=False, exhaustion_log={})
    assert result.admissibility_verdict == "ok"
    assert result.total_tested == 3


def test_execute_grille_kernel_overrule_preserved():
    """The identity mask dispatches to CT — the kernel score on that
    output must equal the kernel score on raw CT (no shim can silently
    shift it)."""
    spec = HypothesisSpec(
        hypothesis_id="e2e-grille-overrule",
        pipeline=[CipherLayer(
            kind="grille",
            params=[ParamRange(name="hole_mask",
                               values=[list(range(97))])],
        )],
    )
    result = execute(spec, parallel=False, exhaustion_log={})
    assert result.best_candidate is not None
    # Candidate plaintext IS CT for identity mask.
    assert result.best_candidate["candidate_pt"] == CT
    # Kernel-verified fields match the kernel's direct computation.
    kernel_breakdown = score_candidate(CT)
    assert result.best_candidate["crib_score"] == int(
        kernel_breakdown.crib_score
    )
    assert result.best_candidate["bean_passed"] == bool(
        kernel_breakdown.bean_passed
    )


def test_execute_grille_reversed_mask_produces_noise():
    """Reversed CT should score sub-noise (it's not the real plaintext).
    This is a sanity check that reversing actually happens — not a
    correctness claim about K4."""
    spec = HypothesisSpec(
        hypothesis_id="e2e-grille-reverse",
        pipeline=[CipherLayer(
            kind="grille",
            params=[ParamRange(name="hole_mask",
                               values=[list(range(96, -1, -1))])],
        )],
    )
    result = execute(spec, parallel=False, exhaustion_log={})
    assert result.admissibility_verdict == "ok"
    assert result.best_candidate is not None
    # Verify: candidate_pt is CT reversed.
    assert result.best_candidate["candidate_pt"] == CT[::-1]
    # Kernel score matches direct computation on reversed CT.
    assert result.best_candidate["crib_score"] == int(
        score_candidate(CT[::-1]).crib_score
    )
