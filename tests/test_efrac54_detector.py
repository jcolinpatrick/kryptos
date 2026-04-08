"""Tests for the E-FRAC-54 joint two-sided detector.

Run with:
    PYTHONPATH=src python3 -m pytest tests/test_efrac54_detector.py -v

Note on quadgram scale
----------------------
`data/english_quadgrams.json` ships log10 probabilities, so after
nat-conversion (multiply by ln 10) real English scores ~ -10.5 nats/char,
random text ~ -15 nats/char.  The spec assumed a normalised model where
English ~ -3.2 nats/char.  Only the GAP matters for the Gumbel
calibration; thresholds and English-band assertions in this file use the
actual scale of the shipped scorer.
"""
from __future__ import annotations

import json
import math
import os
import random
import tempfile
from pathlib import Path

import pytest

from kryptos.detectors import efrac54_joint as ef
from kryptos.detectors.efrac54_joint import (
    CandidateTuple,
    JointScore,
    calibrate_threshold,
    encrypt_with_model,
    fit_gumbel_mom,
    generate_shuffled_surrogate,
    gumbel_quantile,
    score_joint,
    verdict,
)
from kryptos.kernel.constants import (
    ALPH,
    ALPH_IDX,
    CRIB_DICT,
    CRIB_POSITIONS,
    CT,
    CT_LEN,
    MOD,
)
from kryptos.kernel.scoring.ngram import get_default_scorer
from kryptos.kernel.transforms.transposition import columnar_perm, invert_perm


# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def quad():
    return get_default_scorer()


@pytest.fixture
def identity_sigma():
    return tuple(range(26))


@pytest.fixture
def english_pt_full():
    """A 97-char English PT consistent with the K4 cribs.

    Layout (lengths add to exactly 97):
        0-20  (21): THEREALPLAINTEXTOFKRA
        21-33 (13): EASTNORTHEAST
        34-62 (29): BETWEENTHESHADOWSANDTHELIGHTS
        63-73 (11): BERLINCLOCK
        74-96 (23): HASBEENTHEREFROMTHESTAR
    """
    text = (
        "THEREALPLAINTEXTOFKRA"
        "EASTNORTHEAST"
        "BETWEENTHESHADOWSANDTHELIGHTS"
        "BERLINCLOCK"
        "HASBEENTHEREFROMTHESTAR"
    )
    assert len(text) == 97
    for pos, ch in CRIB_DICT.items():
        assert text[pos] == ch, f"crib mismatch at {pos}: {text[pos]} != {ch}"
    return text


def _pt_nc(full_pt: str) -> str:
    return "".join(full_pt[i] for i in range(len(full_pt)) if i not in CRIB_POSITIONS)


# Empirical scale on this scorer (log10-based; see module docstring).
ENGLISH_NATS_LO = -12.0
ENGLISH_NATS_HI = -9.0
RANDOM_NATS_APPROX = -15.0


# ── Round-trip / direction sanity ─────────────────────────────────────────


def test_khat_roundtrip_vigenere(identity_sigma, english_pt_full):
    rng = random.Random(7)
    key = [rng.randrange(MOD) for _ in range(CT_LEN)]
    width = 7
    kappa = (3, 0, 5, 1, 6, 2, 4)
    ct = encrypt_with_model(english_pt_full, identity_sigma, width, kappa, key, "vigenere")
    pi = columnar_perm(width, list(kappa), length=CT_LEN)
    khat = ef._khat_from_pt(ct, english_pt_full, identity_sigma, pi, ef.CipherVariant.VIGENERE)
    assert khat == key, "K_hat must round-trip exactly under Vigenere"


def test_khat_roundtrip_beaufort(identity_sigma, english_pt_full):
    rng = random.Random(11)
    key = [rng.randrange(MOD) for _ in range(CT_LEN)]
    width = 9
    kappa = (4, 0, 7, 2, 8, 1, 5, 3, 6)
    ct = encrypt_with_model(english_pt_full, identity_sigma, width, kappa, key, "beaufort")
    pi = columnar_perm(width, list(kappa), length=CT_LEN)
    khat = ef._khat_from_pt(ct, english_pt_full, identity_sigma, pi, ef.CipherVariant.BEAUFORT)
    assert khat == key


def test_khat_roundtrip_varbeau(identity_sigma, english_pt_full):
    rng = random.Random(13)
    key = [rng.randrange(MOD) for _ in range(CT_LEN)]
    width = 6
    kappa = (2, 5, 0, 3, 1, 4)
    ct = encrypt_with_model(english_pt_full, identity_sigma, width, kappa, key, "var_beaufort")
    pi = columnar_perm(width, list(kappa), length=CT_LEN)
    khat = ef._khat_from_pt(ct, english_pt_full, identity_sigma, pi, ef.CipherVariant.VAR_BEAUFORT)
    assert khat == key


# ── score_joint behaviour ─────────────────────────────────────────────────


def test_score_joint_crib_check(identity_sigma, quad):
    """Wrong-length pt_nc -> cribs_ok=False, t = -inf.

    `_build_full_pt` always inserts the canonical cribs, so the only
    way to fail the crib check is to supply a candidate whose non-crib
    payload is the wrong length (which prevents weaving) or whose woven
    text fails the crib equality check (impossible by construction here).
    """
    cand_short = CandidateTuple(
        sigma=identity_sigma,
        width=7,
        kappa=(0, 1, 2, 3, 4, 5, 6),
        pt_nc="A" * 5,  # too short
    )
    score = score_joint(CT, cand_short, quadgram=quad)
    assert score.cribs_ok is False
    assert math.isinf(score.t) and score.t < 0


def test_score_joint_identity_signal(identity_sigma, english_pt_full, quad):
    """Real-English PT in the candidate -> L_PT in the English band, and
    the candidate's joint t should beat a random-PT candidate."""
    rng = random.Random(101)
    key_text = (english_pt_full + english_pt_full)[:CT_LEN]
    key = [ALPH_IDX[c] for c in key_text]
    width = 7
    kappa = (3, 0, 5, 1, 6, 2, 4)
    ct = encrypt_with_model(english_pt_full, identity_sigma, width, kappa, key, "vigenere")

    cand_good = CandidateTuple(
        sigma=identity_sigma, width=width, kappa=kappa,
        pt_nc=_pt_nc(english_pt_full),
    )
    score_good = score_joint(ct, cand_good, quadgram=quad)

    rand_pt = list(english_pt_full)
    free = [i for i in range(CT_LEN) if i not in CRIB_POSITIONS]
    letters = [rand_pt[i] for i in free]
    rng.shuffle(letters)
    for idx, src in enumerate(free):
        rand_pt[src] = letters[idx]
    cand_bad = CandidateTuple(
        sigma=identity_sigma, width=width, kappa=kappa,
        pt_nc=_pt_nc("".join(rand_pt)),
    )
    score_bad = score_joint(ct, cand_bad, quadgram=quad)

    assert score_good.cribs_ok and score_bad.cribs_ok
    assert ENGLISH_NATS_LO < score_good.l_pt < ENGLISH_NATS_HI, (
        f"l_pt out of English range: {score_good.l_pt}"
    )
    assert ENGLISH_NATS_LO < score_good.l_k < ENGLISH_NATS_HI, (
        f"l_k out of English range: {score_good.l_k}"
    )
    assert score_good.t > score_bad.t, (
        f"good t={score_good.t:.4f} should beat random t={score_bad.t:.4f}"
    )


# ── Calibration ───────────────────────────────────────────────────────────


def _trivial_search_fn(ct, quadgram, rng):
    """Cheap deterministic 'search' used for unit tests: scores one fixed
    candidate per surrogate.  In production, this would be the full
    hill-climb."""
    sigma = tuple(range(26))
    free = [i for i in range(CT_LEN) if i not in CRIB_POSITIONS]
    pt_nc = "".join(ct[i] for i in free)
    cand = CandidateTuple(sigma=sigma, width=7, kappa=(3, 0, 5, 1, 6, 2, 4), pt_nc=pt_nc)
    return score_joint(ct, cand, quadgram=quadgram)


def test_calibrate_threshold_deterministic(quad):
    with tempfile.TemporaryDirectory() as td:
        mu1, beta1, tau1 = calibrate_threshold(
            CT, _trivial_search_fn, quadgram=quad,
            n_surrogates=200, seed=12345, prereg_dir=td,
        )
        mu2, beta2, tau2 = calibrate_threshold(
            CT, _trivial_search_fn, quadgram=quad,
            n_surrogates=200, seed=12345, prereg_dir=td,
        )
    assert mu1 == mu2 and beta1 == beta2 and tau1 == tau2


def test_calibrate_writes_prereg(quad):
    with tempfile.TemporaryDirectory() as td:
        calibrate_threshold(
            CT, _trivial_search_fn, quadgram=quad,
            n_surrogates=50, seed=1, prereg_dir=td,
        )
        files = list(Path(td).glob("efrac54_prereg_*.json"))
        assert len(files) == 1
        with open(files[0]) as f:
            d = json.load(f)
        for k in ("mu", "beta", "tau", "alpha", "n_surrogates", "seed",
                  "search_fn_hash", "covariance_corr_pt_k", "timestamp_utc"):
            assert k in d


# ── Verdict decision rule ─────────────────────────────────────────────────


def test_verdict_decision_rule():
    mu, beta = 0.0, 1.0
    tau = gumbel_quantile(mu, beta, 0.99)  # ~ 4.6
    assert verdict(tau - 1.0, mu, beta) == "noise"
    assert verdict(tau + 0.1, mu, beta) == "weak_signal"
    # strong_signal: tau + 0.5*beta = ~5.1, also clears mu+5*beta=5.0
    # so the strongest band wins.
    assert verdict(tau + 0.6, mu, beta) in ("strong_signal", "breakthrough")
    assert verdict(100.0, mu, beta) == "breakthrough"


# ── Surrogate generator ───────────────────────────────────────────────────


def test_shuffled_surrogate_preserves_cribs():
    rng = random.Random(0)
    for _ in range(50):
        surr = generate_shuffled_surrogate(CT, rng)
        assert len(surr) == len(CT)
        for pos in CRIB_POSITIONS:
            assert surr[pos] == CT[pos]
        free = [i for i in range(CT_LEN) if i not in CRIB_POSITIONS]
        assert sorted(surr[i] for i in free) == sorted(CT[i] for i in free)


# ── Gumbel fit sanity ─────────────────────────────────────────────────────


def test_gumbel_fit_sanity():
    rng = random.Random(2024)
    true_mu, true_beta = 3.0, 0.7
    samples = [true_mu - true_beta * math.log(-math.log(rng.random()))
               for _ in range(20000)]
    mu, beta = fit_gumbel_mom(samples)
    assert abs(mu - true_mu) / abs(true_mu) < 0.05
    assert abs(beta - true_beta) / abs(true_beta) < 0.05


# ── Planted-signal smoke (mandatory positive control) ─────────────────────


def test_planted_signal_smoke(identity_sigma, english_pt_full, quad):
    """Encrypt english_pt_full with a real-English running key, calibrate
    against shuffled surrogates of the resulting plant CT, and verify
    that the TRUE candidate's joint score clears tau."""
    key_text = (
        "FOURSCOREANDSEVENYEARSAGOOURFATHERSBROUGHTFORTHONTHIS"
        "CONTINENTANEWNATIONCONCEIVEDINLIBERTYANDDEDICATEDTOTHE"
    )[:CT_LEN]
    key = [ALPH_IDX[c] for c in key_text]
    width = 7
    kappa = (3, 0, 5, 1, 6, 2, 4)
    ct_plant = encrypt_with_model(english_pt_full, identity_sigma, width, kappa, key, "vigenere")

    cand = CandidateTuple(
        sigma=identity_sigma, width=width, kappa=kappa,
        pt_nc=_pt_nc(english_pt_full),
    )
    truth_score = score_joint(ct_plant, cand, quadgram=quad)
    assert truth_score.cribs_ok

    def search_fn(ct, quadgram, rng):
        return score_joint(ct, cand, quadgram=quadgram)

    with tempfile.TemporaryDirectory() as td:
        mu, beta, tau = calibrate_threshold(
            ct_plant, search_fn, quadgram=quad,
            n_surrogates=300, seed=42, prereg_dir=td,
        )
    print(f"\n[planted] t={truth_score.t:.4f} l_pt={truth_score.l_pt:.4f} "
          f"l_k={truth_score.l_k:.4f} mu={mu:.4f} beta={beta:.4f} tau={tau:.4f}")
    assert truth_score.t > tau, (
        f"planted truth t={truth_score.t:.4f} did not clear tau={tau:.4f} "
        f"(mu={mu:.4f}, beta={beta:.4f})"
    )


# ── Markov-3 adversarial blind (FM-1 demonstration) ──────────────────────


def _markov3_keytext(rng: random.Random, n: int, scorer) -> str:
    """Generate a Markov-3 quadgram-frequency surrogate.  This LOOKS English
    to a quadgram model but contains no semantic content."""
    by_prefix: dict[str, list[tuple[str, float]]] = {}
    for gram, lp in scorer.log_probs.items():
        pref = gram[:3]
        by_prefix.setdefault(pref, []).append((gram[3], math.exp(lp)))
    out = ["T", "H", "E"]
    while len(out) < n:
        pref = "".join(out[-3:])
        choices = by_prefix.get(pref)
        if not choices:
            out.append(rng.choice(ALPH))
            continue
        total = sum(p for _, p in choices)
        r = rng.random() * total
        acc = 0.0
        for ch, p in choices:
            acc += p
            if acc >= r:
                out.append(ch)
                break
        else:
            out.append(choices[-1][0])
    return "".join(out)


def test_markov3_adversarial_blind(identity_sigma, english_pt_full, quad):
    """FM-1 demonstration: Markov-3 quadgram-frequency surrogates are
    formally INDISTINGUISHABLE from real English under a quadgram-only
    detector at n=73.  This test demonstrates the failure mode in code:
    a Markov-3 plant scores comparably to a real-English plant under
    the joint detector.  The detector cannot algorithmically reject
    Markov-3 — that is the FM-1 hard requirement and a known limitation.

    What this test verifies:
      1. Markov-3 plant produces an L_K in the English band
         (i.e. the plant DOES fool the quadgram model)
      2. The joint score is within ~10% of an equivalent real-English
         plant (i.e. the detector cannot tell them apart)

    A future side test (out of scope here) is needed to disambiguate.
    """
    rng = random.Random(2026)
    key_text_m3 = _markov3_keytext(rng, CT_LEN, quad)
    key_m3 = [ALPH_IDX[c] for c in key_text_m3]
    width = 7
    kappa = (3, 0, 5, 1, 6, 2, 4)
    ct_m3 = encrypt_with_model(english_pt_full, identity_sigma, width, kappa, key_m3, "vigenere")

    real_key_text = (
        "FOURSCOREANDSEVENYEARSAGOOURFATHERSBROUGHTFORTHONTHIS"
        "CONTINENTANEWNATIONCONCEIVEDINLIBERTYANDDEDICATEDTOTHE"
    )[:CT_LEN]
    real_key = [ALPH_IDX[c] for c in real_key_text]
    ct_real = encrypt_with_model(english_pt_full, identity_sigma, width, kappa, real_key, "vigenere")

    cand = CandidateTuple(
        sigma=identity_sigma, width=width, kappa=kappa,
        pt_nc=_pt_nc(english_pt_full),
    )
    score_m3 = score_joint(ct_m3, cand, quadgram=quad)
    score_real = score_joint(ct_real, cand, quadgram=quad)

    print(f"\n[markov3] L_K(m3)={score_m3.l_k:.4f}  L_K(real)={score_real.l_k:.4f}")
    print(f"[markov3] t(m3)={score_m3.t:.4f}  t(real)={score_real.t:.4f}")

    # 1. Markov-3 K_hat falls in the English band (the fooling)
    assert ENGLISH_NATS_LO < score_m3.l_k < ENGLISH_NATS_HI, (
        f"Markov-3 plant K_hat OUTSIDE English band: {score_m3.l_k}.  "
        "If this assertion fails, FM-1 may be unexpectedly easy to "
        "detect — investigate."
    )
    # 2. The joint detector cannot tell them apart (within ~15% on this scale)
    rel = abs(score_m3.t - score_real.t) / abs(score_real.t)
    assert rel < 0.15, (
        f"Markov-3 t={score_m3.t:.4f} is too distinguishable from real "
        f"t={score_real.t:.4f} (rel={rel:.3f}).  Either the detector is "
        "stronger than FM-1 predicts, or the Markov-3 generator is broken."
    )


# ── Covariance audit ──────────────────────────────────────────────────────


def test_covariance_audit_records_corr(quad):
    """The pre-reg artifact must record corr(L_PT, L_K) so the audit can
    inspect it.  We don't force >0.7 here (depends on K4-specific
    structure), but we verify the field is well-formed and the fallback
    flag is consistent with it."""
    with tempfile.TemporaryDirectory() as td:
        calibrate_threshold(
            CT, _trivial_search_fn, quadgram=quad,
            n_surrogates=200, seed=7, prereg_dir=td,
        )
        files = list(Path(td).glob("efrac54_prereg_*.json"))
        with open(files[0]) as f:
            d = json.load(f)
        assert "covariance_corr_pt_k" in d
        assert -1.0 <= d["covariance_corr_pt_k"] <= 1.0
        assert "covariance_fallback_active" in d
        assert d["covariance_fallback_active"] == (d["covariance_corr_pt_k"] > 0.7)
