"""Suite-assurance Task C — synthetic known-answer benchmark zoo.

Eight K4-shaped known-answer fixtures spanning the alignment/cipher
classes the goal requires (direct additive periodic + non-periodic,
route+additive, columnar+quagmire, grille+additive, non-Bean
non-additive, second-level extraction, free alignment), each dispatched
through the REAL ``execute()`` path + contract boundary in a subprocess
with kernel env overrides, plus the null-mask+additive class exercised
through the kernel masking verifier in-process.

PASS criterion per fixture: the suite either SOLVES it (planted PT
recovered, winning binding identified, frame labels and Bean status
exactly as expected) or CORRECTLY CLASSIFIES it (second-level extraction
is a declared toolchain gap, not a silent miss).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from kryptosbot.tests.zoo_fixtures import (
    ALL_SUBPROCESS_FIXTURES,
    CANONICAL_CRIBS,
    ZooFixture,
    english_pt,
    fixture_payload,
)

_REPO = Path(__file__).resolve().parents[2]
_RUNNER = Path(__file__).resolve().parent / "zoo_runner.py"


def run_fixture(fx: ZooFixture) -> dict:
    payload_path = Path(
        os.environ.get("TMPDIR", "/tmp")
    ) / f"zoo_{fx.fixture_id}_{os.getpid()}.json"
    payload_path.write_text(json.dumps(fixture_payload(fx)))
    env = dict(os.environ)
    env["KRYPTOS_CT_OVERRIDE"] = fx.carved_ct
    env["KRYPTOS_CRIB_DICT_OVERRIDE"] = json.dumps(
        {str(k): v for k, v in fx.crib_dict.items()}
    )
    env["PYTHONPATH"] = f"{_REPO / 'src'}:{_REPO}"
    proc = subprocess.run(
        [sys.executable, str(_RUNNER), str(payload_path)],
        capture_output=True, text=True, timeout=300, env=env, cwd=str(_REPO),
    )
    payload_path.unlink(missing_ok=True)
    assert proc.returncode == 0, (
        f"runner failed for {fx.fixture_id}: "
        f"stdout={proc.stdout[-2000:]} stderr={proc.stderr[-2000:]}"
    )
    line = next(
        (l for l in proc.stdout.splitlines() if l.startswith("ZOO_RESULT:")),
        None,
    )
    assert line, f"no ZOO_RESULT line: {proc.stdout[-2000:]}"
    return json.loads(line[len("ZOO_RESULT:"):])


def _assert_solved(fx: ZooFixture, obs: dict) -> None:
    exp = fx.expected
    best = obs["best"]
    assert obs["admissibility_verdict"] == "ok", obs
    assert best["pt_matches_planted"] is True, (
        f"{fx.fixture_id}: planted PT not recovered: {obs}"
    )
    assert best["crib_score"] == exp["crib_score"], obs
    assert best["scoring_mode"] == exp["scoring_mode"], obs
    assert best["bean_passed"] == exp["bean_passed"], (
        f"{fx.fixture_id}: bean frame expectation violated: {obs} "
        f"(expected {exp['bean_passed']}; {fx.notes})"
    )
    if "canonical_positions" in exp:
        assert best["canonical_positions"] == exp["canonical_positions"], obs
    if "winning_binding" in exp:
        flat = {k: v for k, v in obs["best_config_bindings"]}
        key, val = exp["winning_binding"]
        assert flat.get(key) == val, (
            f"{fx.fixture_id}: winning binding {key}={flat.get(key)!r}, "
            f"expected {val!r}"
        )
    # Contract boundary must carry the kernel-verified values through
    # (B-1/B-2 fix): crib preserved in the declared frame; Bean follows
    # the frame expectation.
    assert obs["contract"]["crib_score"] == exp["crib_score"], (
        f"{fx.fixture_id}: contract boundary altered crib_score: {obs}"
    )
    assert obs["contract"]["bean_passed"] == exp["bean_passed"], obs


@pytest.mark.parametrize(
    "builder", ALL_SUBPROCESS_FIXTURES, ids=lambda b: b.__name__,
)
def test_zoo_fixture_solves_or_classifies(builder):
    fx = builder()
    obs = run_fixture(fx)
    _assert_solved(fx, obs)
    if fx.fixture_id == "F8":
        # Second-level extraction: declared toolchain gap. The hidden
        # message must NOT be claimed anywhere in the structured output
        # (no extractor exists — silence here is the CORRECT behavior,
        # and the gap is recorded in the coverage matrix).
        hidden = fx.extra["hidden_message"]
        assert hidden not in json.dumps(obs), (
            "a second-level extraction surfaced without any extractor — "
            "investigate where it came from"
        )


def test_zoo_f6_null_mask_additive_in_process():
    """Null-mask + additive through the kernel masking verifier:
    cribs remapped into extracted coordinates, Bean re-derived per mask.
    True mask + true key verify; wrong mask fails cribs."""
    from kryptos.kernel.masking.verify import verify_masked_candidate
    from kryptos.kernel.masking.solve import CipherVariant

    pt97 = english_pt()
    null_positions = (0, 5, 11, 40, 55, 90)  # none on crib positions
    keep = [i for i in range(97) if i not in null_positions]
    pt_payload = "".join(pt97[i] for i in keep)  # 91-char true PT

    key = [3, 17, 9, 21, 5]  # period-5 additive key on the payload
    ct_payload = "".join(
        chr(65 + ((ord(c) - 65) + key[i % 5]) % 26)
        for i, c in enumerate(pt_payload)
    )
    # Re-insert nulls (letter 'Q') at the null positions to build CT97.
    ct_chars: list[str] = []
    it = iter(ct_payload)
    for i in range(97):
        ct_chars.append("Q" if i in null_positions else next(it))
    ct97 = "".join(ct_chars)

    # Crib dict in CT97 coordinates (cribs untouched by the mask).
    crib97 = dict(CANONICAL_CRIBS)

    mask = frozenset(null_positions)  # NullMask is a FrozenSet[int] alias
    full_key = [key[i % 5] for i in range(len(ct_payload))]
    res = verify_masked_candidate(
        ct97, mask, CipherVariant.VIGENERE, full_key, crib_dict=crib97,
    )
    assert res.crib_score == 24, res
    assert res.bean_passed is True, (
        f"per-mask re-derived Bean should PASS for the planted key: {res}"
    )

    # NOTE (zoo observation): a wrong mask that PRESERVES the null count
    # before each crib block (e.g. shifting every null by +1) produces an
    # identical crib-region decrypt — crib score alone cannot distinguish
    # count-preserving mask shifts. That equivalence class is why
    # unconstrained mask search is gated on more than crib score
    # (calibrated ngram floor / pre-registered statistic). The negative
    # control below CHANGES the count before the ENE block (4 nulls
    # instead of 3), which misaligns the remapped cribs.
    wrong = frozenset((0, 5, 11, 15, 55, 90))
    res_wrong = verify_masked_candidate(
        ct97, wrong, CipherVariant.VIGENERE, full_key, crib_dict=crib97,
    )
    assert res_wrong.crib_score < 24, (
        "count-changing wrong mask must not verify as a solve"
    )
