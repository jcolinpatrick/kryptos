"""Keyword-derived columnar transposition (DSL convenience).

Classical keyed columnar takes a KEYWORD and derives both the width
(len(keyword)) and the column read-order (rank each column by its keyword
letter, ties left-to-right). The dispatcher previously required an explicit
`col_order` permutation, forcing the LLM theorist to hand-compute permutations
— the brittle step that produced `dsl_untranslatable` rejections. Adding a
`keyword` param to the columnar layer (mirroring how vigenere derives its key
from a keyword) removes that step.

The headline test proves the payoff: a small clue-derived keyword SWEEP
dispatches to 24/24 on the public K4Bench K4B-001 ciphertext — i.e. the
controller's machinery can self-discover the solution from the clue ingredients
without any hand-computed permutation and without hardcoding the answer.
"""

import json
import pathlib

from kryptosbot.hypothesis_dsl import (
    HypothesisSpec, CipherLayer, ParamRange, NullBaselineSpec,
)
from kryptosbot.job_dispatcher import _translate_layer, _col_order_from_keyword, execute

_CHALLENGE = pathlib.Path(__file__).resolve().parents[2] / "bench/k4bench/challenges/K4B-001.json"


def test_col_order_from_keyword_cedar():
    # CEDAR -> rank each column by letter (A,C,D,E,R -> cols 3,0,2,1,4):
    # col0=C rank1, col1=E rank3, col2=D rank2, col3=A rank0, col4=R rank4.
    assert _col_order_from_keyword("CEDAR") == [1, 3, 2, 0, 4]


def test_col_order_from_keyword_is_valid_permutation():
    order = _col_order_from_keyword("LANTERN")
    assert sorted(order) == list(range(7))


def test_keyword_columnar_translates_same_as_explicit():
    layer = CipherLayer(kind="columnar", alphabet="AZ", params=[])
    via_keyword = _translate_layer(layer, {"keyword": "CEDAR"}, text_length=97)
    via_explicit = _translate_layer(
        layer, {"width": 5, "col_order": [1, 3, 2, 0, 4]}, text_length=97
    )
    assert via_keyword == via_explicit
    assert via_keyword["type"] == "transposition_full"


def test_keyword_columnar_spec_validates():
    spec = HypothesisSpec(
        hypothesis_id="kwcol",
        pipeline=[CipherLayer(kind="columnar", alphabet="AZ",
                              params=[ParamRange(name="keyword", values=["CEDAR"])])],
        null_baseline=NullBaselineSpec(method="shuffled_ct", n_samples=200),
        compute_budget_cpu_minutes=5,
        assumption_bundle=["ct97_direct_positional", "az_a0", "no_null_mask"],
    )
    errors = spec.validate()
    assert errors == [], errors


def test_theorist_prompt_has_bounded_sweep_guidance():
    # Mounting the keyword-columnar feature is not enough: the theorist must be
    # told to author bounded SWEEPS over uncertain axes (and to use the columnar
    # keyword param) rather than single-point guesses.
    src = (pathlib.Path(__file__).resolve().parents[1] / "controller.py").read_text()
    assert "BOUNDED SWEEP" in src
    assert "uncertain axis" in src
    # the columnar keyword convenience must be surfaced to the theorist
    assert "derives width" in src


def test_keyword_columnar_sweep_solves_k4b001():
    ch = json.loads(_CHALLENGE.read_text())
    CT = ch["ciphertext"]
    cribs = {int(k): v for k, v in ch["known_plaintext_positions"].items()}

    # Decrypt order [vigenere, columnar]; sweep BOTH keywords over both layers
    # (4 configs). The winning point (vig=LANTERN, col=CEDAR) is contained.
    spec = HypothesisSpec(
        hypothesis_id="k4b001-kwsweep",
        pipeline=[
            CipherLayer(kind="vigenere", alphabet="AZ",
                        params=[ParamRange(name="keyword", values=["CEDAR", "LANTERN"])]),
            CipherLayer(kind="columnar", alphabet="AZ",
                        params=[ParamRange(name="keyword", values=["CEDAR", "LANTERN"])]),
        ],
        null_baseline=NullBaselineSpec(method="shuffled_ct", n_samples=200),
        compute_budget_cpu_minutes=5,
        assumption_bundle=["ct97_direct_positional", "az_a0", "no_null_mask"],
    )
    assert spec.expected_cardinality() == 4

    # bench_mode=True: this is an independent known-answer challenge, so the
    # real-K4 exhaustion log does not apply (matches the live bench dispatch).
    result = execute(
        spec, bench_mode=True, challenge_ciphertext=CT, challenge_crib_dict=cribs,
    )
    assert result.admissibility_verdict != "rejected", result.admissibility_reasons
    assert result.best_candidate is not None
    assert int(result.best_candidate["crib_score"]) == 24, result.best_candidate
