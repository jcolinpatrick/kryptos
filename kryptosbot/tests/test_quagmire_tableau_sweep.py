"""Quagmire III tableau-keyword sweep (DSL diagonal-constraint fix).

THE GAP THIS CLOSES (k4_dynamic_solve 2026-05-28, final_report.md:120/151):
ParamRange axes are independent Cartesian. A Quagmire III tableau sweep
needs the DIAGONAL of the (ct_alphabet_keyword x pt_alphabet_keyword)
square — only ct_kw == pt_kw pairs are valid Q-III tableaus — but listing
N values on both keyword axes enumerates N^2-N off-diagonal bindings, the
translator (correctly) raises on the first one, and execute() rejects the
ENTIRE spec. Net effect: one tableau per spec; the 5 non-KRYPTOS tableaus
in the C1/C5 clusters were left "NOT a tested negative".

THE FIX: a single `tableau_keyword` param on the quagmire layer that the
translator expands to the identical ct==pt pair. One independent axis →
axis_product == total_tested stays exact (no binding skipping; the
off-diagonal abort semantics for explicit ct/pt lists are intentionally
UNCHANGED — see the regression test at the bottom).

The headline test proves the payoff end-to-end: a 12-config tableau sweep
through the real execute() path recovers a planted Quagmire III config at
crib 24/24 without hand-pinning the tableau.
"""

import pytest

from kryptos.kernel.transforms.quagmire import quagmire_encrypt, quagmire_decrypt

from kryptosbot.hypothesis_dsl import (
    HypothesisSpec, CipherLayer, ParamRange, NullBaselineSpec,
)
from kryptosbot.job_dispatcher import DispatcherError, _translate_layer, execute


_LAYER = CipherLayer(kind="quagmire", alphabet="AZ", params=[])

# Synthetic known-answer fixture: a 97-char PT carrying the canonical crib
# strings at the canonical 0-indexed positions (21-33 EASTNORTHEAST,
# 63-73 BERLINCLOCK), encrypted with one tableau drawn from the sweep set.
_PT = (
    "THESECRETMESSAGEBEGIN"          # 0-20   (21 chars)
    "EASTNORTHEAST"                   # 21-33  (13 chars)
    "WHILETHECOLDWINDSWEEPSOVERTHE"   # 34-62  (29 chars)
    "BERLINCLOCK"                     # 63-73  (11 chars)
    "TOWERATMIDNIGHTSHARPLYX"         # 74-96  (23 chars)
)
_TRUE_TABLEAU = "LATITUDE"
_TRUE_PERIOD_KW = "AZIMUTH"
_TRUE_INDICATOR = "K"
_TABLEAU_SWEEP = ["KRYPTOS", "PALIMPSEST", "ABSCISSA",
                  "LATITUDE", "MAGNETIC", "COMPASS"]


def _synthetic_challenge() -> tuple[str, dict[int, str]]:
    assert len(_PT) == 97
    ct = quagmire_encrypt(
        _PT,
        period_keyword=_TRUE_PERIOD_KW,
        indicator=_TRUE_INDICATOR,
        ct_alphabet_keyword=_TRUE_TABLEAU,
        pt_alphabet_keyword=_TRUE_TABLEAU,
    )
    assert len(ct) == 97
    # Sanity: the kernel round-trips, so the planted config is recoverable.
    assert quagmire_decrypt(
        ct,
        period_keyword=_TRUE_PERIOD_KW,
        indicator=_TRUE_INDICATOR,
        ct_alphabet_keyword=_TRUE_TABLEAU,
        pt_alphabet_keyword=_TRUE_TABLEAU,
    ) == _PT
    cribs = {i: _PT[i] for i in range(21, 34)}
    cribs.update({i: _PT[i] for i in range(63, 74)})
    assert len(cribs) == 24
    return ct, cribs


# ─── Translator-level behavior ───────────────────────────────────────────────

def test_tableau_keyword_translates_same_as_explicit_pin():
    via_tableau = _translate_layer(_LAYER, {
        "tableau_keyword": "ABSCISSA",
        "period_keyword": "AZIMUTH",
        "indicator": "K",
    }, text_length=97)
    via_explicit = _translate_layer(_LAYER, {
        "ct_alphabet_keyword": "ABSCISSA",
        "pt_alphabet_keyword": "ABSCISSA",
        "period_keyword": "AZIMUTH",
        "indicator": "K",
    }, text_length=97)
    assert via_tableau == via_explicit
    assert via_tableau["type"] == "quagmire"
    assert via_tableau["params"]["ct_alphabet_keyword"] == "ABSCISSA"
    assert via_tableau["params"]["pt_alphabet_keyword"] == "ABSCISSA"


def test_tableau_keyword_rejected_for_quagmire_iv():
    with pytest.raises(DispatcherError, match="quagmire_iii"):
        _translate_layer(_LAYER, {
            "tableau_keyword": "ABSCISSA",
            "variant": "quagmire_iv",
            "period_keyword": "AZIMUTH",
            "indicator": "K",
        }, text_length=97)


def test_tableau_keyword_conflicts_with_explicit_ct_keyword():
    with pytest.raises(DispatcherError, match="mutually exclusive"):
        _translate_layer(_LAYER, {
            "tableau_keyword": "ABSCISSA",
            "ct_alphabet_keyword": "KRYPTOS",
            "period_keyword": "AZIMUTH",
            "indicator": "K",
        }, text_length=97)


def test_tableau_keyword_conflicts_with_explicit_pt_keyword():
    with pytest.raises(DispatcherError, match="mutually exclusive"):
        _translate_layer(_LAYER, {
            "tableau_keyword": "ABSCISSA",
            "pt_alphabet_keyword": "KRYPTOS",
            "period_keyword": "AZIMUTH",
            "indicator": "K",
        }, text_length=97)


def test_tableau_keyword_must_be_nonempty_string():
    for bad in ("", 7, None):
        binding = {
            "tableau_keyword": bad,
            "period_keyword": "AZIMUTH",
            "indicator": "K",
        }
        if bad is None:
            # None means "param absent" — falls through to the existing
            # ct/pt requirement, which must still reject the binding.
            with pytest.raises(DispatcherError, match="ct_alphabet_keyword"):
                _translate_layer(_LAYER, binding, text_length=97)
        else:
            with pytest.raises(DispatcherError, match="tableau_keyword"):
                _translate_layer(_LAYER, binding, text_length=97)


# ─── DSL-level structural validation ─────────────────────────────────────────

def test_layer_validate_rejects_tableau_plus_explicit_keyword_params():
    layer = CipherLayer(kind="quagmire", alphabet="AZ", params=[
        ParamRange(name="tableau_keyword", values=["KRYPTOS", "ABSCISSA"]),
        ParamRange(name="ct_alphabet_keyword", values=["KRYPTOS"]),
        ParamRange(name="period_keyword", values=["AZIMUTH"]),
        ParamRange(name="indicator", values=["K"]),
    ])
    errors = layer.validate()
    assert any("tableau_keyword" in e for e in errors), errors


def test_layer_validate_accepts_pure_tableau_sweep():
    layer = CipherLayer(kind="quagmire", alphabet="AZ", params=[
        ParamRange(name="tableau_keyword", values=_TABLEAU_SWEEP),
        ParamRange(name="period_keyword", values=["AZIMUTH"]),
        ParamRange(name="indicator", values=["K"]),
    ])
    assert layer.validate() == []


# ─── Headline: end-to-end diagonal sweep through the real dispatcher ─────────

def test_diagonal_tableau_sweep_recovers_planted_quagmire_iii():
    ct, cribs = _synthetic_challenge()
    spec = HypothesisSpec(
        hypothesis_id="qiii-tableau-sweep",
        pipeline=[
            CipherLayer(kind="quagmire", alphabet="AZ", params=[
                ParamRange(name="tableau_keyword", values=_TABLEAU_SWEEP),
                ParamRange(name="period_keyword",
                           values=[_TRUE_PERIOD_KW, "BEARING"]),
                ParamRange(name="indicator", values=[_TRUE_INDICATOR]),
            ]),
        ],
        null_baseline=NullBaselineSpec(method="shuffled_ct", n_samples=200),
        compute_budget_cpu_minutes=5,
        assumption_bundle=["ct97_direct_positional", "az_a0", "no_null_mask"],
    )
    assert spec.validate() == []
    assert spec.expected_cardinality() == 12  # 6 tableaus x 2 period kws x 1

    # bench_mode=True: independent known-answer challenge; the real-K4
    # exhaustion log does not apply (same pattern as test_keyword_columnar).
    result = execute(
        spec, bench_mode=True, challenge_ciphertext=ct, challenge_crib_dict=cribs,
    )
    assert result.admissibility_verdict != "rejected", result.admissibility_reasons
    assert result.total_tested == 12          # axis_product == total_tested, exact
    assert result.best_candidate is not None
    assert int(result.best_candidate["crib_score"]) == 24, result.best_candidate
    assert result.best_candidate["candidate_pt"] == _PT


# ─── Regression guard: explicit off-diagonal semantics UNCHANGED ─────────────

def test_independent_ct_pt_lists_still_reject_whole_spec():
    """The old (broken) encoding must keep failing loudly, not silently
    shrink the universe: skipping off-diagonal bindings would break the
    axis_product == total_tested cardinality accounting."""
    ct, cribs = _synthetic_challenge()
    spec = HypothesisSpec(
        hypothesis_id="qiii-offdiagonal-regression",
        pipeline=[
            CipherLayer(kind="quagmire", alphabet="AZ", params=[
                ParamRange(name="ct_alphabet_keyword", values=["KRYPTOS", "ABSCISSA"]),
                ParamRange(name="pt_alphabet_keyword", values=["KRYPTOS", "ABSCISSA"]),
                ParamRange(name="period_keyword", values=["AZIMUTH"]),
                ParamRange(name="indicator", values=["K"]),
            ]),
        ],
        null_baseline=NullBaselineSpec(method="shuffled_ct", n_samples=200),
        compute_budget_cpu_minutes=5,
        assumption_bundle=["ct97_direct_positional", "az_a0", "no_null_mask"],
    )
    result = execute(
        spec, bench_mode=True, challenge_ciphertext=ct, challenge_crib_dict=cribs,
    )
    assert result.admissibility_verdict == "rejected"


# ─── post_transposition coverage: route outer × tableau sweep ────────────────
# Coverage-gap fill (2026-06-10 patch-safety audit): the campaign shape
# "route outer × Quagmire III tableau_keyword inner under post_transposition"
# previously had NO unit coverage — only the 2026-06-09 campaign artifacts
# (qtab arm B1) exercised it. These two tests pin (a) planted-config recovery
# through the real execute() path under post_transposition, and (b) the
# byte-identity of an explicit-permutation grille encoding with the named
# route_boustrophedon encoding — the convention the route-outer ×
# Quagmire-III-inner campaign relies on when sweeping explicit route perms
# as a grille hole_mask axis.

from kryptos.kernel.transforms.transposition import invert_perm, serpentine_perm

_ROUTE_WIDTH = 7
_ROUTE_VERTICAL = False


def _route_planted_challenge() -> tuple[str, dict[int, str], list[int]]:
    inner_ct, cribs = _synthetic_challenge()
    rows = (97 + _ROUTE_WIDTH - 1) // _ROUTE_WIDTH
    perm = serpentine_perm(rows, _ROUTE_WIDTH, 97, vertical=_ROUTE_VERTICAL)
    # Encrypt-direction route: CT[i] = X[perm[i]] ("do" gather); the
    # dispatcher's decrypt pipeline applies direction="undo" and recovers X.
    ct = "".join(inner_ct[perm[i]] for i in range(97))
    return ct, cribs, list(perm)


def _qiii_sweep_layer() -> CipherLayer:
    return CipherLayer(kind="quagmire", alphabet="AZ", params=[
        ParamRange(name="tableau_keyword", values=_TABLEAU_SWEEP),
        ParamRange(name="period_keyword", values=[_TRUE_PERIOD_KW, "BEARING"]),
        ParamRange(name="indicator", values=[_TRUE_INDICATOR]),
    ])


def test_route_outer_tableau_sweep_post_transposition_recovers_planted():
    ct, cribs, _ = _route_planted_challenge()
    spec = HypothesisSpec(
        hypothesis_id="qiii-route-outer-posttrans",
        pipeline=[
            CipherLayer(kind="route_boustrophedon", alphabet="AZ", params=[
                ParamRange(name="width", values=[_ROUTE_WIDTH]),
                ParamRange(name="vertical", values=[_ROUTE_VERTICAL]),
            ]),
            _qiii_sweep_layer(),
        ],
        crib_alignment="post_transposition",
        null_baseline=NullBaselineSpec(method="shuffled_ct", n_samples=200),
        compute_budget_cpu_minutes=5,
        assumption_bundle=["transposed", "az_a0", "no_null_mask",
                           "non_direct_alignment"],
    )
    assert spec.validate() == []
    assert spec.expected_cardinality() == 12
    result = execute(
        spec, bench_mode=True, challenge_ciphertext=ct, challenge_crib_dict=cribs,
    )
    assert result.admissibility_verdict != "rejected", result.admissibility_reasons
    assert result.total_tested == 12
    best = result.best_candidate
    assert best is not None
    assert int(best["crib_score"]) == 24, best
    assert best["candidate_pt"] == _PT
    assert str(best.get("scoring_mode", "")).startswith("post_transposition")


def test_grille_perm_encoding_byte_identical_to_route_boustrophedon():
    """undo(perm) == gather(invert(perm)): a grille layer carrying the
    inverse serpentine perm as hole_mask must reproduce the named
    route_boustrophedon layer exactly (same recovered PT, same crib score,
    same cardinality accounting)."""
    ct, cribs, perm = _route_planted_challenge()
    spec = HypothesisSpec(
        hypothesis_id="qiii-grille-perm-posttrans",
        pipeline=[
            CipherLayer(kind="grille", alphabet="AZ", params=[
                ParamRange(name="hole_mask", values=[invert_perm(perm)]),
            ]),
            _qiii_sweep_layer(),
        ],
        crib_alignment="post_transposition",
        null_baseline=NullBaselineSpec(method="shuffled_ct", n_samples=200),
        compute_budget_cpu_minutes=5,
        assumption_bundle=["transposed", "az_a0", "no_null_mask",
                           "non_direct_alignment"],
    )
    assert spec.validate() == []
    assert spec.expected_cardinality() == 12
    result = execute(
        spec, bench_mode=True, challenge_ciphertext=ct, challenge_crib_dict=cribs,
    )
    assert result.admissibility_verdict != "rejected", result.admissibility_reasons
    assert result.total_tested == 12
    best = result.best_candidate
    assert best is not None
    assert int(best["crib_score"]) == 24, best
    assert best["candidate_pt"] == _PT
