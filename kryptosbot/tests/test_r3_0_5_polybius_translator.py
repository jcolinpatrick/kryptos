"""R3-0.5-3 tests: polybius translator.

Covers the polybius-family layer translation via
``TransformType.BIFID`` dispatch. Straight polybius (length-doubling)
is deferred; R3-0.5-3 supports ``variant='bifid'`` only.

Per CLAUDE.md §Gotchas: Bifid 5x5 single-layer is impossible for K4
because all 26 letters appear in the CT and the 5x5 grid forces a
25-letter alphabet. These tests exercise dispatch and kernel
overrule correctness; they do NOT claim K4 signal.
"""
from __future__ import annotations

import pytest

from kryptos.kernel.constants import CT
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.transforms.compose import TransformType
from kryptos.kernel.transforms.polybius import (
    bifid_decrypt,
    bifid_encrypt,
    make_polybius_5x5,
)
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


def test_polybius_in_dispatcher_supported_kinds():
    assert "polybius" in _SUPPORTED_KINDS


def test_polybius_in_dsl_valid_cipher_kinds():
    """polybius was already in _VALID_CIPHER_KINDS before R3-0.5-3;
    this test is a regression guard."""
    assert "polybius" in _VALID_CIPHER_KINDS


def test_bifid_transformtype_already_registered():
    """R3-0.5-3 wires the translator over existing BIFID dispatch.
    If TransformType.BIFID is ever renamed or removed, this test
    catches the break before runtime."""
    assert TransformType.BIFID.value == "bifid"


# ─── Kernel roundtrip sanity ─────────────────────────────────────────────────


def test_bifid_kernel_roundtrip_identity():
    """Sanity check the underlying kernel primitives. Bifid roundtrip
    on a 25-letter-alphabet plaintext must recover the original."""
    grid = make_polybius_5x5("KRYPTOS", "IJ")
    pt = "HELLOWORLD"
    ct_ = bifid_encrypt(pt, grid, 5)
    rt = bifid_decrypt(ct_, grid, 5)
    assert rt == pt


def test_make_polybius_5x5_empty_keyword_is_canonical_alphabet():
    """Empty keyword produces A-Z order (with I/J merged to drop J)."""
    grid = make_polybius_5x5("", "IJ")
    assert len(grid) == 25
    # Should start with ABCDEFGHI (J merged) K...
    assert grid[:9] == list("ABCDEFGHI")
    assert "J" not in grid


def test_make_polybius_5x5_keyword_prefixes_alphabet():
    """Keyword 'KRYPTOS' prefixes the grid with those letters in order."""
    grid = make_polybius_5x5("KRYPTOS", "IJ")
    assert "".join(grid[:7]) == "KRYPTOS"


# ─── Translator: adversarial paths ───────────────────────────────────────────


def test_translate_polybius_missing_square_keyword_raises():
    layer = CipherLayer(kind="polybius", alphabet="AZ")
    with pytest.raises(DispatcherError, match="requires 'square_keyword'"):
        _translate_layer(layer, binding={})


def test_translate_polybius_non_string_keyword_raises():
    layer = CipherLayer(kind="polybius", alphabet="AZ")
    with pytest.raises(DispatcherError, match="must be str"):
        _translate_layer(layer, binding={"square_keyword": 12345})


def test_translate_polybius_straight_variant_raises_with_deferral_note():
    """variant='polybius' (straight, length-doubling) is explicitly
    deferred. Error message must say so."""
    layer = CipherLayer(kind="polybius", alphabet="AZ")
    with pytest.raises(DispatcherError, match="deferred"):
        _translate_layer(layer, binding={
            "square_keyword": "KRYPTOS",
            "variant": "polybius",
        })


def test_translate_polybius_unknown_variant_raises():
    layer = CipherLayer(kind="polybius", alphabet="AZ")
    with pytest.raises(DispatcherError, match="unsupported"):
        _translate_layer(layer, binding={
            "square_keyword": "KRYPTOS",
            "variant": "nonsense",
        })


def test_translate_polybius_bad_merge_length_raises():
    layer = CipherLayer(kind="polybius", alphabet="AZ")
    with pytest.raises(DispatcherError, match="2-char string"):
        _translate_layer(layer, binding={
            "square_keyword": "KRYPTOS",
            "merge": "IJK",
        })


def test_translate_polybius_bad_direction_raises():
    layer = CipherLayer(kind="polybius", alphabet="AZ")
    with pytest.raises(DispatcherError, match="encrypt|decrypt"):
        _translate_layer(layer, binding={
            "square_keyword": "KRYPTOS",
            "direction": "sideways",
        })


def test_translate_polybius_negative_period_raises():
    layer = CipherLayer(kind="polybius", alphabet="AZ")
    with pytest.raises(DispatcherError, match="non-negative"):
        _translate_layer(layer, binding={
            "square_keyword": "KRYPTOS",
            "period": -5,
        })


def test_translate_polybius_non_int_period_raises():
    layer = CipherLayer(kind="polybius", alphabet="AZ")
    with pytest.raises(DispatcherError, match="non-negative int"):
        _translate_layer(layer, binding={
            "square_keyword": "KRYPTOS",
            "period": 3.14,
        })


def test_translate_polybius_bool_period_rejected():
    """Python's True is an int (== 1); the translator must reject
    bool explicitly to avoid silent success on True/False periods."""
    layer = CipherLayer(kind="polybius", alphabet="AZ")
    with pytest.raises(DispatcherError, match="non-negative int"):
        _translate_layer(layer, binding={
            "square_keyword": "KRYPTOS",
            "period": True,
        })


# ─── Translator: happy path ──────────────────────────────────────────────────


def test_translate_polybius_minimal_binding_produces_bifid_step():
    layer = CipherLayer(kind="polybius", alphabet="AZ")
    step = _translate_layer(layer, binding={"square_keyword": "KRYPTOS"})
    assert step["type"] == "bifid"
    assert step["params"]["keyword"] == "KRYPTOS"
    assert step["params"]["merge"] == "IJ"  # default
    assert step["params"]["period"] == 0    # default (full-length)
    assert step["params"]["direction"] == "decrypt"  # default


def test_translate_polybius_empty_keyword_accepted():
    """Empty string is a valid keyword (canonical A-Z order)."""
    layer = CipherLayer(kind="polybius", alphabet="AZ")
    step = _translate_layer(layer, binding={"square_keyword": ""})
    assert step["type"] == "bifid"
    assert step["params"]["keyword"] == ""


def test_translate_polybius_all_params_plumbed_through():
    layer = CipherLayer(kind="polybius", alphabet="AZ")
    step = _translate_layer(layer, binding={
        "square_keyword": "PALIMPSEST",
        "merge": "CK",
        "period": 7,
        "direction": "encrypt",
        "variant": "bifid",
    })
    assert step["type"] == "bifid"
    assert step["params"]["keyword"] == "PALIMPSEST"
    assert step["params"]["merge"] == "CK"
    assert step["params"]["period"] == 7
    assert step["params"]["direction"] == "encrypt"


# ─── End-to-end dispatch ─────────────────────────────────────────────────────


def test_execute_polybius_dispatches_on_k4_ct():
    """Dispatching polybius on raw K4 CT must run without error.
    The score will be noise-level (the 26-letter gotcha), but
    admissibility and kernel scoring must complete cleanly."""
    spec = HypothesisSpec(
        hypothesis_id="e2e-poly",
        pipeline=[CipherLayer(
            kind="polybius",
            params=[ParamRange(name="square_keyword",
                               values=["KRYPTOS"])],
        )],
    )
    result = execute(spec, parallel=False, exhaustion_log={})
    assert result.admissibility_verdict == "ok"
    assert result.total_tested == 1
    assert result.best_candidate is not None
    # candidate_pt is whatever bifid_decrypt produces on raw CT with
    # a KRYPTOS grid — well-defined; the key invariant is that it's
    # a 97-char string.
    assert len(result.best_candidate["candidate_pt"]) == 97


def test_execute_polybius_sweeps_multiple_keywords():
    spec = HypothesisSpec(
        hypothesis_id="e2e-poly-sweep",
        pipeline=[CipherLayer(
            kind="polybius",
            params=[ParamRange(name="square_keyword",
                               values=["KRYPTOS", "PALIMPSEST", "ABSCISSA"])],
        )],
    )
    result = execute(spec, parallel=False, exhaustion_log={})
    assert result.admissibility_verdict == "ok"
    assert result.total_tested == 3


def test_execute_polybius_kernel_overrule_preserved():
    """Kernel overrule on the polybius path: crib_score and
    bean_passed are the kernel's values on the decrypted output,
    not any worker-reported values."""
    spec = HypothesisSpec(
        hypothesis_id="e2e-poly-overrule",
        pipeline=[CipherLayer(
            kind="polybius",
            params=[ParamRange(name="square_keyword",
                               values=["KRYPTOS"])],
        )],
    )
    result = execute(spec, parallel=False, exhaustion_log={})
    assert result.best_candidate is not None
    candidate_pt = result.best_candidate["candidate_pt"]
    kernel_breakdown = score_candidate(candidate_pt)
    assert result.best_candidate["crib_score"] == int(
        kernel_breakdown.crib_score
    )
    assert result.best_candidate["bean_passed"] == bool(
        kernel_breakdown.bean_passed
    )
