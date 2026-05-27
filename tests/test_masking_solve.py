"""Joint mask x mechanism solver: synthetic recovery tests.

These tests plant a fully-known masked challenge (known plaintext, known null
mask, known periodic key/variant), then require the solver to RECOVER the mask
and mechanism from the carved ciphertext plus a bounded mask universe -- not
merely verify a supplied answer.  This is the central fitness gate from
docs/specs/2026-05-27-joint-mask-mechanism-solver-implementation-brief.md.
"""
from __future__ import annotations

from kryptos.kernel.masking.mask import NullMask
from kryptos.kernel.masking.solve import (
    MaskedCandidate, calibrated_ngram_floor, select_solves, solve_periodic,
)
from kryptos.kernel.scoring.ngram import get_default_scorer
from kryptos.kernel.transforms.vigenere import CipherVariant, encrypt_text


def _build_masked_challenge(
    pt_prime: str,
    key: list[int],
    variant: CipherVariant,
    mask_positions: set[int],
    crib_pt_indices: list[int],
):
    """Construct a synthetic masked challenge from known components.

    Returns (carved_ct, mask, crib_dict_carved, ct_prime).

    The carved ciphertext is CT' (= encrypt(pt_prime)) with null filler
    characters spliced in at ``mask_positions`` (carved coordinates).  Cribs
    are emitted in CARVED coordinates so the solver must remap them itself.
    """
    ct_prime = encrypt_text(pt_prime, key, variant)
    mask: NullMask = frozenset(mask_positions)
    carved_len = len(ct_prime) + len(mask)

    carved_chars: list[str] = []
    src = iter(ct_prime)
    for pos in range(carved_len):
        carved_chars.append("Q" if pos in mask else next(src))
    carved = "".join(carved_chars)

    # CT' index j lives at the j-th non-mask carved position.
    nonmask = [p for p in range(carved_len) if p not in mask]
    crib_dict = {nonmask[j]: pt_prime[j] for j in crib_pt_indices}
    return carved, mask, crib_dict, ct_prime


def test_solver_recovers_planted_mask_and_periodic_key():
    pt_prime = "ATTACKATDAWNXKRYPTOSCLOCK"  # 25 chars, arbitrary known PT
    true_key = [3, 17, 8, 22]              # period 4
    true_variant = CipherVariant.VIGENERE
    true_mask_positions = {5, 11, 19}      # nulls, disjoint from real cribs
    # crib PT indices 0..7 cover all four residue classes mod 4 (twice each),
    # so the key is fully FORCED with zero free residues.
    crib_pt_indices = [0, 1, 2, 3, 4, 5, 6, 7]

    carved, true_mask, crib_dict, ct_prime = _build_masked_challenge(
        pt_prime, true_key, true_variant, true_mask_positions, crib_pt_indices
    )

    # Bounded mask universe: the true mask plus decoys.  Decoys are
    # crib-disjoint (cribs are never nulls), as a valid universe requires.
    universe = [
        true_mask,
        frozenset({9, 10, 13}),
        frozenset({14, 16, 23}),
        frozenset({17, 24, 25}),
    ]

    candidates = solve_periodic(
        carved,
        universe,
        periods=range(3, 8),
        crib_dict=crib_dict,
    )

    assert isinstance(candidates, list)
    assert all(isinstance(c, MaskedCandidate) for c in candidates)

    hit = [
        c
        for c in candidates
        if c.mask == true_mask
        and c.variant == true_variant
        and c.period == len(true_key)
        and tuple(c.key) == tuple(true_key)
    ]
    assert len(hit) >= 1, "solver did not recover the planted (mask, variant, key)"

    recovered = hit[0]
    assert recovered.plaintext == ct_prime_decrypts_to(pt_prime)
    assert recovered.bean_passed is True


def ct_prime_decrypts_to(pt_prime: str) -> str:
    # The recovered plaintext must equal the planted plaintext exactly.
    return pt_prime


def test_negative_control_no_false_solve_when_true_mask_excluded():
    """With the true mask absent, no candidate clears a language gate that the
    true plaintext clears.  Bean is auto-satisfied for crib-forced keys, so the
    only real discriminator is n-gram quality on the non-crib positions."""
    pt_prime = "THEQUICKBROWNFOXJUMPSOVER"  # 25 chars, strongly English
    true_key = [3, 17, 8, 22]
    true_variant = CipherVariant.VIGENERE
    true_mask_positions = {5, 11, 19}
    crib_pt_indices = [0, 1, 2, 3, 4, 5, 6, 7]

    carved, true_mask, crib_dict, _ = _build_masked_challenge(
        pt_prime, true_key, true_variant, true_mask_positions, crib_pt_indices
    )
    scorer = get_default_scorer()
    decoys = [
        frozenset({9, 10, 13}),
        frozenset({14, 16, 23}),
        frozenset({17, 24, 25}),
    ]

    cand_with = solve_periodic(
        carved, [true_mask, *decoys], periods=range(3, 9),
        crib_dict=crib_dict, ngram_scorer=scorer,
    )
    cand_without = solve_periodic(
        carved, decoys, periods=range(3, 9),
        crib_dict=crib_dict, ngram_scorer=scorer,
    )

    # The truth is the unique argmax by language quality when present.
    truth = max(cand_with, key=lambda c: c.ngram_score)
    assert truth.mask == true_mask
    assert truth.variant == true_variant
    assert truth.plaintext == pt_prime

    # No DECOY-mask candidate reaches the true mask's language quality.  (The
    # true mask may recover the true plaintext at several redundant periods,
    # e.g. p=4 and p=8; those are the same correct answer, not false solves.)
    decoy_cands = [c for c in cand_with if c.mask != true_mask]
    decoy_max = max((c.ngram_score for c in decoy_cands), default=float("-inf"))
    assert decoy_max < truth.ngram_score

    # A gate placed between the populations admits the truth and ONLY the truth
    # when present, and admits NOTHING when the true mask is excluded.
    floor = (
        (decoy_max + truth.ngram_score) / 2
        if decoy_cands
        else truth.ngram_score - 1.0
    )
    solves_with = select_solves(cand_with, ngram_floor=floor)
    solves_without = select_solves(cand_without, ngram_floor=floor)

    assert solves_with, "gate rejected the true solve"
    assert all(c.mask == true_mask for c in solves_with)
    assert solves_without == []


def test_calibrated_floor_is_monotone_in_universe_size():
    """A mask-universe-aware floor must rise as the universe grows: more masks
    mean more chances for a coincidental high score, so the bar goes up."""
    sizes = [1, 5, 25, 100, 1000, 10000]
    floors = [
        calibrated_ngram_floor(n, null_mean=-150.0, null_std=2.0, alpha=0.01)
        for n in sizes
    ]
    assert all(b >= a for a, b in zip(floors, floors[1:])), "floor decreased"
    assert all(b > a for a, b in zip(floors, floors[1:])), "floor not strict"
    # A single-candidate universe still sits above the null mean (one-sided gate).
    assert floors[0] > -150.0


def test_multiplicity_penalty_demotes_a_fixed_solve_in_a_large_universe():
    """The same planted solve clears the gate in a bounded universe but not in
    an astronomically large one: bounding the universe is what makes a mask
    solve promotable."""
    pt_prime = "THEQUICKBROWNFOXJUMPSOVER"
    true_key = [3, 17, 8, 22]
    true_variant = CipherVariant.VIGENERE
    true_mask_positions = {5, 11, 19}
    crib_pt_indices = [0, 1, 2, 3, 4, 5, 6, 7]

    carved, true_mask, crib_dict, _ = _build_masked_challenge(
        pt_prime, true_key, true_variant, true_mask_positions, crib_pt_indices
    )
    scorer = get_default_scorer()
    candidates = solve_periodic(
        carved, [true_mask], periods=range(3, 9),
        crib_dict=crib_dict, ngram_scorer=scorer,
    )
    truth_ngram = max(c.ngram_score for c in candidates)

    # Illustrative null: the true solve sits 5 sigma above coincidental noise.
    null_mean = truth_ngram - 5.0
    null_std = 1.0
    floor_small = calibrated_ngram_floor(1, null_mean=null_mean, null_std=null_std)
    floor_large = calibrated_ngram_floor(10**6, null_mean=null_mean, null_std=null_std)

    assert floor_small < truth_ngram   # bounded universe admits the solve
    assert floor_large > truth_ngram   # astronomically large universe does not

    assert select_solves(candidates, ngram_floor=floor_small)
    assert select_solves(candidates, ngram_floor=floor_large) == []


def test_solver_recovers_free_residues_via_ngram_search():
    """When cribs cover only some residue classes, the solver must SEARCH the
    free residues (n-gram-guided), not just force the covered ones."""
    pt_prime = "DEFENDTHEEASTWALLOFTHECASTLE"  # 28 chars, clean English
    true_key = [3, 17, 8, 22, 5, 11]            # period 6
    true_variant = CipherVariant.VIGENERE
    true_mask_positions = {7, 16, 25}
    # Cribs land only on residues {0,1,2} mod 6 -> residues {3,4,5} are FREE.
    crib_pt_indices = [0, 1, 2, 6, 7, 8, 12, 13, 14]

    carved, true_mask, crib_dict, _ = _build_masked_challenge(
        pt_prime, true_key, true_variant, true_mask_positions, crib_pt_indices
    )
    scorer = get_default_scorer()

    candidates = solve_periodic(
        carved,
        [true_mask],
        periods=[6],
        crib_dict=crib_dict,
        variants=[CipherVariant.VIGENERE],
        ngram_scorer=scorer,
    )

    hit = [
        c
        for c in candidates
        if c.mask == true_mask and c.period == 6 and c.plaintext == pt_prime
    ]
    assert len(hit) == 1, "free-residue search did not recover the true plaintext"
    assert tuple(hit[0].key) == tuple(true_key)


def test_empirical_null_places_true_solve_as_outlier():
    """The empirically estimated null (random free-residue fills under fixed
    forced residues) must place the true English solve far in its right tail."""
    import statistics
    from kryptos.kernel.masking.mask import extract_ct, remap_crib_dict
    from kryptos.kernel.masking.solve import estimate_ngram_null

    pt_prime = "DEFENDTHEEASTWALLOFTHECASTLE"
    true_key = [3, 17, 8, 22, 5, 11]
    true_variant = CipherVariant.VIGENERE
    true_mask_positions = {7, 16, 25}
    crib_pt_indices = [0, 1, 2, 6, 7, 8, 12, 13, 14]  # residues {0,1,2} mod 6 -> {3,4,5} free
    carved, true_mask, crib_dict, _ = _build_masked_challenge(
        pt_prime, true_key, true_variant, true_mask_positions, crib_pt_indices
    )
    scorer = get_default_scorer()
    ct_prime = extract_ct(carved, true_mask)
    cribs = remap_crib_dict(crib_dict, true_mask)

    null = estimate_ngram_null(
        ct_prime, cribs, true_variant, 6, scorer, n_samples=5000, seed=1,
    )
    assert len(null) == 5000
    mean = statistics.fmean(null)
    sd = statistics.pstdev(null)
    assert sd > 0
    assert scorer.score(pt_prime) > mean + 5 * sd


def test_empirical_floor_monotone_and_bounded():
    """The non-parametric order-statistic floor rises with universe size and
    never exceeds the observed null maximum (honest empirical tail)."""
    from kryptos.kernel.masking.solve import calibrated_ngram_floor_empirical

    null = [float(x) for x in range(1000)]
    sizes = [1, 5, 25, 100, 1000, 10000]
    floors = [calibrated_ngram_floor_empirical(null, n, alpha=0.01) for n in sizes]
    assert all(b >= a for a, b in zip(floors, floors[1:])), "floor decreased"
    assert floors[-1] > floors[0], "floor did not rise with universe size"
    assert all(f <= max(null) for f in floors), "floor exceeded observed null max"


def test_select_solves_e0b_gate_filters_by_kset_distance():
    """The optional E0b gate excludes candidates whose K-set distance exceeds
    the calibrated threshold; None (no K-set positions) never clears it."""
    from kryptos.kernel.masking.solve import select_solves as _ss

    def mk(e0b):
        return MaskedCandidate(
            mask=frozenset(), variant=CipherVariant.VIGENERE, period=4,
            key=(0,), plaintext="X", crib_score=24, bean_passed=True,
            ngram_score=0.0, e0b_mean_distance=e0b, e0b_count=(0 if e0b is None else 10),
        )

    cands = [mk(2.0), mk(3.0), mk(None)]
    # E0b gate off (default): bean + ngram floor only -> all three pass.
    assert len(_ss(cands, ngram_floor=-1.0)) == 3
    # E0b gate on at 2.5: only the 2.0 candidate clears; 3.0 and None excluded.
    out = _ss(cands, ngram_floor=-1.0, e0b_max=2.5)
    assert [c.e0b_mean_distance for c in out] == [2.0]


def test_solve_periodic_populates_e0b_fields():
    pt_prime = "DEFENDTHEEASTWALLOFTHECASTLE"
    true_key = [3, 17, 8, 22, 5, 11]
    true_variant = CipherVariant.VIGENERE
    true_mask_positions = {7, 16, 25}
    crib_pt_indices = [0, 1, 2, 6, 7, 8, 12, 13, 14]
    carved, true_mask, crib_dict, _ = _build_masked_challenge(
        pt_prime, true_key, true_variant, true_mask_positions, crib_pt_indices
    )
    scorer = get_default_scorer()
    candidates = solve_periodic(
        carved, [true_mask], periods=[6], crib_dict=crib_dict,
        variants=[CipherVariant.VIGENERE], ngram_scorer=scorer,
    )
    assert candidates
    for c in candidates:
        assert c.e0b_mean_distance is not None
        assert c.e0b_count >= 0
