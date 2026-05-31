"""Lever B2 safe scaffolding: null-mask model + null-aware scoring + matched null.

Non-destructive: no kernel.constants mutation, no Bean rewrite. A NullMask marks
which of the 97 positions are nulls (filler); the "real message" is the rest.
``score_under_null_mask`` re-derives the crib score from each candidate+mask via
the kernel's free scorer (real-K4 cribs). ``matched_null_pvalue`` is the
REQUIRED gate: a high crib_score under a mask is only meaningful if that mask
beats random masks of the same size — otherwise the free parameters fit noise.
"""

from kryptosbot.null_mask import (
    NullMask, apply_null_mask, score_under_null_mask, matched_null_pvalue,
)

_ENE = "EASTNORTHEAST"   # 13
_BC = "BERLINCLOCK"      # 11


def test_nullmask_validation():
    assert NullMask(frozenset({1, 2, 3})).validate() == []
    assert NullMask(frozenset({200})).validate()          # out of range
    assert NullMask(frozenset(range(97))).validate()      # all-null (no real message)
    assert NullMask(frozenset()).n_nulls == 0


def test_apply_null_mask_removes_positions():
    assert apply_null_mask("ABCDE", NullMask(frozenset({1, 3}), length=5)) == "ACE"


# Candidate where ENE is broken by ONE null at index 12; removing it reveals
# EASTNORTHEAST. BC is already contiguous. So mask={12} is the SPECIAL mask.
_SPECIAL_PT = "EASTNORTHEAS" + "Q" + "T" + "X" * 36 + _BC + "X" * 36
# Candidate where both cribs are already contiguous; no null is needed, so a
# mask is NOT special (the cribs survive almost any same-size mask).
_NOTSPECIAL_PT = _ENE + "X" * 37 + _BC + "X" * 36


def test_score_under_null_mask_reveals_cribs():
    assert len(_SPECIAL_PT) == 97
    # Without removing the Q, ENE is broken -> only BC found (11).
    assert score_under_null_mask(_SPECIAL_PT, NullMask(frozenset()))["crib_score"] == 11
    # Removing the Q at index 12 reveals EASTNORTHEAST -> both cribs (24).
    assert score_under_null_mask(_SPECIAL_PT, NullMask(frozenset({12})))["crib_score"] == 24


def test_matched_null_placement_pvalue_round_trip():
    # Build a plaintext with cribs at canonical positions + a known null
    # placement, ENCRYPT it with a finite key tape, then the gate must find
    # that the true placement decrypts the cribs (low p) while random same-size
    # placements shift the tape alignment and don't (it's special).
    from kryptos.kernel.transforms.key_tape import apply_key_tape
    from kryptos.kernel.transforms.vigenere import CipherVariant
    from kryptosbot.null_mask import matched_null_placement_pvalue

    pt = list("X" * 97)
    pt[21:34] = list(_ENE)
    pt[63:74] = list(_BC)
    pt = "".join(pt)
    crib_dict = {21 + i: _ENE[i] for i in range(13)}
    crib_dict.update({63 + i: _BC[i] for i in range(11)})
    tape = tuple((i * 7 + 3) % 26 for i in range(97))  # covers all non-null positions
    nulls = frozenset({5, 50, 90})         # the true null placement
    ct = apply_key_tape(
        pt, tape, variant=CipherVariant.BEAUFORT, direction="encrypt",
        null_positions=nulls, null_rule="skip",
    )

    res = matched_null_placement_pvalue(
        ct, tape=tape, variant="beaufort", null_rule="skip",
        observed_null_positions=nulls, crib_dict=crib_dict,
        n_trials=300, seed=0,
    )
    assert res["observed_crib_score"] == 24, res     # true placement recovers all cribs
    # The true placement lands in the rarer tail vs random same-size placements.
    # (p is only mildly low here BECAUSE 3 nulls carry little constraint — an
    # honest property: few-null hypotheses are weakly distinguishable, which is
    # precisely why this gate is required. More nulls => lower p.)
    assert res["p_value"] < 0.20, res
    assert res["matched_null"] == "random_null_placement"


def test_matched_null_placement_pvalue_bean_prune_is_conditional_null():
    # bean_prune computes the matched null over Bean-ADMISSIBLE placements only
    # — the correct denominator IF Bean is used as a cheap prefilter before
    # scoring. STRUCTURAL FACT (not an accident of this fixture): a placement
    # that scores 24/24 is ALWAYS Bean-admissible, because a perfect crib match
    # makes the implied keystream crib-consistent and Bean is derived from those
    # same (ct, crib) pairs. So {score 24} ⊆ {Bean-admissible}: conditioning on
    # Bean cannot REMOVE a 24-scorer and therefore CANNOT sharpen the raw
    # crib-score placement gate (it can only raise p by dropping low scorers
    # from the denominator). Per-mask Bean's real leverage is tape-space
    # pruning, not placement-gate sharpening.
    from kryptos.kernel.transforms.key_tape import apply_key_tape
    from kryptos.kernel.transforms.vigenere import CipherVariant
    from kryptosbot.null_mask import matched_null_placement_pvalue

    pt = list("X" * 97)
    pt[21:34] = list(_ENE)
    pt[63:74] = list(_BC)
    pt = "".join(pt)
    crib_dict = {21 + i: _ENE[i] for i in range(13)}
    crib_dict.update({63 + i: _BC[i] for i in range(11)})
    tape = tuple((i * 7 + 3) % 26 for i in range(97))
    nulls = frozenset({5, 50, 90})
    ct = apply_key_tape(
        pt, tape, variant=CipherVariant.BEAUFORT, direction="encrypt",
        null_positions=nulls, null_rule="skip",
    )

    base = matched_null_placement_pvalue(
        ct, tape=tape, variant="beaufort", null_rule="skip",
        observed_null_positions=nulls, crib_dict=crib_dict, n_trials=400, seed=0,
    )
    pruned = matched_null_placement_pvalue(
        ct, tape=tape, variant="beaufort", null_rule="skip",
        observed_null_positions=nulls, crib_dict=crib_dict, n_trials=400, seed=0,
        bean_prune=True,
    )
    assert pruned["observed_crib_score"] == 24, pruned
    assert pruned["observed_bean_admissible"] is True, pruned
    assert pruned["matched_null"] == "random_null_placement_bean_pruned"
    # Bean prunes some placements (denominator below the trial count)...
    assert pruned["n_bean_admissible"] < pruned["n_trials"], pruned
    # ...but every 24-scorer survives Bean, so the conditional p is NOT smaller
    # than the raw p — Bean does not sharpen the placement gate.
    assert pruned["p_value"] >= base["p_value"] - 1e-9, (pruned, base)


def test_matched_null_placement_pvalue_gibberish_is_not_special():
    from kryptosbot.null_mask import matched_null_placement_pvalue
    crib_dict = {21 + i: _ENE[i] for i in range(13)}
    crib_dict.update({63 + i: _BC[i] for i in range(11)})
    res = matched_null_placement_pvalue(
        "Q" * 97, tape=tuple((i * 5 + 1) % 26 for i in range(97)), variant="vigenere", null_rule="skip",
        observed_null_positions=frozenset({10, 40, 80}), crib_dict=crib_dict,
        n_trials=200, seed=1,
    )
    assert res["observed_crib_score"] < 18          # gibberish: no real cribs
    assert res["p_value"] > 0.5, res                # placement explains nothing


def _real_k4_crib_keystream_array():
    """Build a length-97 keystream whose 24 crib positions hold the real-K4
    Beaufort-implied key (k=(c+p)%26). This array satisfies canonical Bean by
    definition — non-crib positions are irrelevant (no constraint references
    them)."""
    from kryptos.kernel.constants import CT, CRIB_DICT
    ks = [0] * 97
    for pos, ch in CRIB_DICT.items():
        ks[pos] = (ord(CT[pos]) - 65 + ord(ch) - 65) % 26
    return ks


def test_rederive_bean_under_null_no_null_reproduces_canonical():
    # REGRESSION ANCHOR: with no nulls (identity tape-index map), the re-derived
    # Bean must reproduce the kernel's canonical constants exactly. Proven on
    # known ground BEFORE trusting the re-derivation on null cases.
    from kryptos.kernel.constants import CT, CRIB_DICT, BEAN_EQ, BEAN_INEQ, BEAN_LINEAR
    from kryptosbot.null_mask import rederive_bean_under_null

    eq, ineq, linear = rederive_bean_under_null(
        CT, null_positions=frozenset(), null_rule="skip", crib_dict=dict(CRIB_DICT),
    )
    assert eq == ((27, 65),), eq
    assert len(eq) == len(BEAN_EQ) == 1
    assert len(ineq) == len(BEAN_INEQ) == 242
    assert len(linear) == len(BEAN_LINEAR) == 101
    # CONSUME with no nulls is also identity.
    eq2, ineq2, lin2 = rederive_bean_under_null(
        CT, null_positions=frozenset(), null_rule="consume", crib_dict=dict(CRIB_DICT),
    )
    assert (eq2, len(ineq2), len(lin2)) == (((27, 65),), 242, 101)


def test_rederive_bean_under_null_skip_shifts_indices():
    # Under SKIP, a null before a crib position decrements that position's tape
    # index by the count of nulls before it. eq (27,65) with nulls {5,50}:
    #   tape_idx(27) = 27 - |{5}|      = 26
    #   tape_idx(65) = 65 - |{5,50}|   = 63
    from kryptos.kernel.constants import CT, CRIB_DICT
    from kryptosbot.null_mask import rederive_bean_under_null

    eq, ineq, linear = rederive_bean_under_null(
        CT, null_positions=frozenset({5, 50}), null_rule="skip", crib_dict=dict(CRIB_DICT),
    )
    assert eq == ((26, 63),), eq          # shifted, not (27,65)
    assert len(ineq) == 242               # count preserved (injective shift)
    assert len(linear) == 101
    # CONSUME does NOT shift (key advances at nulls too -> identity index map).
    eqc, _, _ = rederive_bean_under_null(
        CT, null_positions=frozenset({5, 50}), null_rule="consume", crib_dict=dict(CRIB_DICT),
    )
    assert eqc == ((27, 65),), eqc


def test_rederive_bean_under_null_crib_on_null_rejected():
    # A null cannot sit on a known crib position (it would erase a known letter).
    import pytest
    from kryptos.kernel.constants import CT, CRIB_DICT
    from kryptosbot.null_mask import rederive_bean_under_null
    with pytest.raises(ValueError):
        rederive_bean_under_null(
            CT, null_positions=frozenset({27}), null_rule="skip", crib_dict=dict(CRIB_DICT),
        )


def test_bean_admissible_under_null_accepts_real_keystream_rejects_corruption():
    # The real-K4 crib keystream satisfies canonical Bean -> admissible (no null).
    from kryptos.kernel.constants import CT, CRIB_DICT
    from kryptosbot.null_mask import bean_admissible_under_null

    ks = _real_k4_crib_keystream_array()
    assert bean_admissible_under_null(
        CT, tuple(ks), null_positions=frozenset(), null_rule="skip",
        crib_dict=dict(CRIB_DICT),
    ) is True
    # Break the one equality k[27]==k[65] -> Bean-inadmissible.
    bad = list(ks)
    bad[65] = (bad[27] + 1) % 26
    assert bean_admissible_under_null(
        CT, tuple(bad), null_positions=frozenset(), null_rule="skip",
        crib_dict=dict(CRIB_DICT),
    ) is False


def test_bean_admissible_under_null_short_tape_inadmissible():
    # A finite tape too short to reach a referenced tape index is inadmissible
    # (exhausted), not an exception.
    from kryptos.kernel.constants import CT, CRIB_DICT
    from kryptosbot.null_mask import bean_admissible_under_null
    assert bean_admissible_under_null(
        CT, (1, 2, 3), null_positions=frozenset(), null_rule="skip",
        crib_dict=dict(CRIB_DICT),
    ) is False


def _roundtrip_ct_true_tape():
    """A synthetic CT whose true (tape, nulls, beaufort) decrypts the cribs at
    canonical positions. Returns (ct, true_tape, nulls, crib_dict)."""
    from kryptos.kernel.transforms.key_tape import apply_key_tape
    from kryptos.kernel.transforms.vigenere import CipherVariant
    pt = list("X" * 97)
    pt[21:34] = list(_ENE)
    pt[63:74] = list(_BC)
    pt = "".join(pt)
    crib_dict = {21 + i: _ENE[i] for i in range(13)}
    crib_dict.update({63 + i: _BC[i] for i in range(11)})
    tape = tuple((i * 7 + 3) % 26 for i in range(97))
    nulls = frozenset({5, 50, 90})
    ct = apply_key_tape(
        pt, tape, variant=CipherVariant.BEAUFORT, direction="encrypt",
        null_positions=nulls, null_rule="skip",
    )
    return ct, tape, nulls, crib_dict


def test_tape_search_prunes_bean_inadmissible_before_scoring():
    from kryptosbot.null_mask import tape_search
    ct, true_tape, nulls, crib_dict = _roundtrip_ct_true_tape()

    # decoy1: all-zeros tape violates the 242 inequalities -> Bean-inadmissible.
    decoy_zeros = (tuple([0] * 97), frozenset(), "beaufort")
    # decoy2: a different per-position tape + nulls + wrong variant.
    decoy_other = (tuple((i * 3 + 1) % 26 for i in range(97)), frozenset({1, 2, 3}), "vigenere")
    true_cand = (true_tape, nulls, "beaufort")

    res = tape_search(
        ct, [decoy_zeros, true_cand, decoy_other],
        crib_dict=crib_dict, null_rule="skip",
    )
    assert res["n_candidates"] == 3
    # The all-zeros decoy is Bean-inadmissible -> pruned -> never scored.
    assert res["n_bean_admissible"] < res["n_candidates"], res
    scored_tapes = [s["tape"] for s in res["survivors"]]
    assert tuple([0] * 97) not in scored_tapes
    # The true candidate survives the prefilter and scores 24/24.
    assert res["best"] is not None
    assert res["best"]["crib_score"] == 24, res["best"]
    assert res["best"]["tape"] == true_tape
    # Only Bean-survivors are scored.
    assert res["n_scored"] == len(res["survivors"]) <= res["n_bean_admissible"]


def test_tape_search_prunes_short_exhausted_tape():
    from kryptosbot.null_mask import tape_search
    ct, _true_tape, _nulls, crib_dict = _roundtrip_ct_true_tape()
    res = tape_search(
        ct, [((1, 2, 3), frozenset(), "beaufort")],
        crib_dict=crib_dict, null_rule="skip",
    )
    assert res["n_candidates"] == 1
    assert res["n_bean_admissible"] == 0      # exhausted tape pruned by prefilter
    assert res["best"] is None


def test_matched_null_pvalue_flags_special_vs_noise():
    # The special mask beats random same-size masks -> low p.
    special = matched_null_pvalue(_SPECIAL_PT, NullMask(frozenset({12})), n_trials=200, seed=0)
    assert 0.0 <= special["p_value"] <= 1.0
    assert special["p_value"] < 0.10, special

    # A mask over an already-solved candidate is NOT special: the cribs survive
    # almost any same-size mask -> high p (the mask explains nothing).
    notspecial = matched_null_pvalue(_NOTSPECIAL_PT, NullMask(frozenset({70})), n_trials=200, seed=0)
    assert notspecial["p_value"] > 0.5, notspecial
