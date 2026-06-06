"""Tests for the mono-invariant running-key detector (E-FRAC-54 / BIN-D D1)."""
import math
import os
import random
from itertools import combinations

from kryptos.detectors.mono_invariant_runkey import english_lag_stats as els
from kryptos.detectors.mono_invariant_runkey import forced_differences as fd
from kryptos.detectors.mono_invariant_runkey import transposition_universe as tu
from kryptos.detectors.mono_invariant_runkey import llr_detector as ld
from kryptos.detectors.mono_invariant_runkey import synthesize as syn
from kryptos.detectors.mono_invariant_runkey import null_calibration as nc

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_KAHN = os.path.join(_ROOT, "reference", "running_key_texts", "kahn_codebreakers_1967.txt")


# ── Task 1: english lag stats ────────────────────────────────────────────────
def test_lag_stats_sum_to_one_and_lag1_nonuniform():
    text = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 200
    stats = els.build_lag_stats(text, l_max=12)
    assert set(stats) == set(range(1, 13))
    for lag, probs in stats.items():
        assert len(probs) == 26
        assert abs(sum(probs) - 1.0) < 1e-9

    def entropy(p):
        return -sum(x * math.log2(x) for x in p if x > 0)

    assert entropy(stats[1]) < math.log2(26) - 0.05


# ── Task 2: forced differences ───────────────────────────────────────────────
def test_model1_forced_diff_handcomputed_and_mono_invariant():
    crib = [(0, 0), (1, 0), (2, 1)]
    ct = [3, 7, 10, 0, 0]
    perm = [0, 1, 2, 3, 4]
    diffs = fd.forced_diffs_model1(ct, crib, perm, variant="vigenere")
    assert diffs == [(22, 1)]  # CT[0]-CT[1] = 3-7 = -4 = 22 ; lag 1
    diffs_vb = fd.forced_diffs_model1(ct, crib, perm, variant="var_beaufort")
    assert diffs_vb == [(4, 1)]


def test_model2_forced_diff_collision_gated():
    crib = [(0, 4), (1, 19)]
    ct = [9, 9, 0]
    perm = [0, 1, 2]
    diffs = fd.forced_diffs_model2(ct, crib, perm, variant="vigenere")
    assert diffs == [(15, 1)]  # PT[1]-PT[0] = 19-4 = 15
    ct2 = [9, 10, 0]
    assert fd.forced_diffs_model2(ct2, crib, perm, variant="vigenere") == []


# ── Task 3: transposition universe ───────────────────────────────────────────
def test_universe_counts_and_valid_perms():
    names_perms = list(tu.iter_universe(n=97))
    # columnar 6!+8!+9! = 403920 plus grid routes (<=52, duplicates collapse possible)
    n_grid = len(names_perms) - 403920
    assert 403920 + 40 <= len(names_perms) <= 403920 + 52, len(names_perms)
    assert n_grid >= 40
    for name, perm in names_perms[:200] + names_perms[-60:]:
        assert sorted(perm) == list(range(97))
    h1 = tu.universe_hash(n=97)
    h2 = tu.universe_hash(n=97)
    assert h1 == h2 and len(h1) == 64


# ── Task 4: LLR ──────────────────────────────────────────────────────────────
def test_llr_zero_on_uniform_positive_on_english_consistent():
    uniform = {lag: [1 / 26] * 26 for lag in range(1, 13)}
    assert abs(ld.llr([(5, 1), (9, 2)], uniform, l_max=12)) < 1e-9
    peaked = {lag: [1 / 26] * 26 for lag in range(1, 13)}
    peaked[1] = [0.0] * 26
    peaked[1][5] = 1.0
    assert ld.llr([(5, 1)], peaked, l_max=12) > 0


# ── Task 5: synthesize round-trip (correctness guard) ────────────────────────
def test_synth_model1_forced_diffs_match_planted_runkey():
    rng = random.Random(1)
    n = 97
    pt = [rng.randrange(26) for _ in range(n)]
    crib = [(p, pt[p]) for p in list(range(21, 34)) + list(range(63, 74))]
    runkey = [rng.randrange(26) for _ in range(n)]
    sigma = list(range(26))
    rng.shuffle(sigma)
    perm = list(range(n))
    rng.shuffle(perm)
    ct = syn.synthesize_model1(pt, runkey, sigma, perm, variant="vigenere")
    diffs = fd.forced_diffs_model1(ct, crib, perm, variant="vigenere")
    by_letter = {}
    for p, v in crib:
        by_letter.setdefault(v, []).append(p)
    expected = []
    for ps in by_letter.values():
        for a, b in combinations(sorted(ps), 2):
            expected.append(((runkey[perm[a]] - runkey[perm[b]]) % 26, abs(perm[a] - perm[b])))
    assert sorted(diffs) == sorted(expected)


def test_synth_model2_forced_diffs_match_planted_runkey():
    rng = random.Random(3)
    n = 97
    pt = [rng.randrange(26) for _ in range(n)]
    crib = [(p, pt[p]) for p in list(range(21, 34)) + list(range(63, 74))]
    runkey = [rng.randrange(26) for _ in range(n)]
    sigma = list(range(26))
    rng.shuffle(sigma)
    perm = list(range(n))
    rng.shuffle(perm)
    ct = syn.synthesize_model2(pt, runkey, sigma, perm, variant="vigenere")
    diffs = fd.forced_diffs_model2(ct, crib, perm, variant="vigenere")
    # every emitted constraint must equal the true planted runkey difference K[p1]-K[p2]
    cribd = dict(crib)
    # reconstruct via colliding crib image pairs
    expected = []
    for (p1, _), (p2, _) in combinations(crib, 2):
        if ct[perm[p1]] == ct[perm[p2]]:
            expected.append(((runkey[p1] - runkey[p2]) % 26, abs(p1 - p2)))
    assert sorted(diffs) == sorted(expected)
    assert len(diffs) >= 1  # random collisions should yield at least one constraint


# ── Task 6: null calibration ─────────────────────────────────────────────────
def test_shuffle_preserves_letter_multiset():
    rng = random.Random(0)
    ct = [rng.randrange(26) for _ in range(97)]
    sh = nc.shuffle_ct(ct, rng)
    assert sorted(sh) == sorted(ct)


def test_max_llr_runs_small_universe():
    rng = random.Random(2)
    ct = [rng.randrange(26) for _ in range(97)]
    crib = [(p, rng.randrange(26)) for p in list(range(21, 34)) + list(range(63, 74))]
    uni = [("identity", list(range(97))), ("reverse", list(range(96, -1, -1)))]
    stats = {lag: [1 / 26] * 26 for lag in range(1, 13)}
    best, mx = nc.max_llr_over_universe(ct, crib, uni, ("vigenere",), ("model1",), stats, l_max=12)
    assert isinstance(mx, float) and best["name"] in {"identity", "reverse"}


# ── Task 7: synthetic recovery go/no-go — FINDING: detector is underpowered ──
# The machinery is correct (round-trip tests above prove forced_differences inverts
# synthesize). This test ENCODES THE MEASURED FINDING: across planted Mono+Trans+
# Running-key solutions, the true transposition's LLR does NOT rise above a full-
# universe-max shuffle null — recovery rate is ~0 (Model 1) because the ~11 forced
# differences land at large, uniform-regime lags and are drowned by the 404K-perm
# look-elsewhere burden. This is the sharpened, quantified DETECTOR_UNDERPOWERED
# result (cf. E-FRAC-54). If a future change makes the detector powerful, this guard
# flips and must be revisited.
def _detection_rate(model, variant, n_trials, stats, eng_idx, uni_factory):
    from kryptos.kernel.transforms.transposition import columnar_perm
    rng = random.Random(100)
    crib_pos = list(range(21, 34)) + list(range(63, 74))
    rec = 0
    synth = syn.synthesize_model1 if model == "model1" else syn.synthesize_model2
    for t in range(n_trials):
        off = rng.randrange(len(eng_idx) - 200)
        runkey = eng_idx[off:off + 97]
        pt = [rng.randrange(26) for _ in range(97)]
        crib = [(p, pt[p]) for p in crib_pos]
        sigma = list(range(26))
        rng.shuffle(sigma)
        perm = list(columnar_perm(8, tuple(random.Random(t).sample(range(8), 8)), 97))
        ct = synth(pt, runkey, sigma, perm, variant)
        _, real_max = nc.max_llr_over_universe(ct, crib, uni_factory(), (variant,), (model,), stats)
        nullmax = []
        r2 = random.Random(7 + t)
        for _ in range(30):
            sh = nc.shuffle_ct(ct, r2)
            nullmax.append(nc.max_llr_over_universe(sh, crib, uni_factory(), (variant,), (model,), stats)[1])
        nullmax.sort()
        if real_max > nullmax[int(0.95 * len(nullmax))]:
            rec += 1
    return rec / n_trials


def test_synthetic_recovery_is_underpowered():
    import itertools
    from kryptos.kernel.transforms.transposition import columnar_perm
    eng = open(_KAHN, encoding="utf-8", errors="ignore").read()
    stats = els.build_lag_stats(eng, l_max=12)
    eng_idx = [ord(c) - 65 for c in eng.upper() if "A" <= c.upper() <= "Z"]

    def small_uni():
        yield ("identity", list(range(97)))
        yield ("reverse", list(range(96, -1, -1)))
        for w in (6, 8, 9):
            for order in itertools.islice(itertools.permutations(range(w)), 0, 4000, 11):
                yield (f"col{w}", list(columnar_perm(w, order, 97)))

    rate = _detection_rate("model1", "vigenere", 8, stats, eng_idx, small_uni)
    # Documented finding: Model-1 recovery is far below any useful floor (measured ~0.0).
    assert rate < 0.5, f"detector unexpectedly powerful (rate={rate}); revisit the finding"
