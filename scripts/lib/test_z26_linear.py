"""Unit tests for z26_linear -- the exact Z_26 foundation for the Quagmire III/IV sweeps.

Every case here has an answer known by construction or by published ground truth
(K1 / K2).  The module's value is the True/False/None contract of
`injective_point_exists`, so these tests hunt OVER-elimination (a False where the
truth is True) at least as hard as under-elimination.
"""
from __future__ import annotations

import itertools
import math
import os
import random
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))
sys.path.insert(0, os.path.join(_ROOT, "kryptosbot"))

from z26_linear import (  # noqa: E402
    Z26Space, crt, free_columns, gauss_mod_p, injective_point_exists,
    injective_point_report, solve_z26,
)

KRY = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNGEUNA"
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRRYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVH"
    "DWKBFUFPWNTDFIYCUQZEREEVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ"
    "FKZBSFDQVGOGIPUFXHHDRKFFHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBD"
    "MVPNFQXEZLGREDNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)


def _matvec(rows, x, p):
    return [sum(a * b for a, b in zip(r, x)) % p for r in rows]


# ------------------------------------------------------------- 1. gauss_mod_p

def test_gauss_random_consistent_systems_recovered():
    rng = random.Random(11)
    for p in (2, 13):
        for _ in range(200):
            n, m = rng.randrange(1, 8), rng.randrange(1, 10)
            rows = [[rng.randrange(p) for _ in range(n)] for _ in range(m)]
            x = [rng.randrange(p) for _ in range(n)]
            rhs = _matvec(rows, x, p)
            out = gauss_mod_p(rows, rhs, n, p)
            assert out is not None, "consistent system reported inconsistent"
            part, null = out
            assert _matvec(rows, part, p) == rhs
            for v in null:
                assert _matvec(rows, v, p) == [0] * m
            assert len({tuple(v) for v in null}) == len(null)
            if p ** n <= 4096:
                brute = {tuple(y) for y in itertools.product(range(p), repeat=n)
                         if _matvec(rows, y, p) == rhs}
                got = set()
                for coef in itertools.product(range(p), repeat=len(null)):
                    y = list(part)
                    for c, v in zip(coef, null):
                        y = [(a + c * b) % p for a, b in zip(y, v)]
                    got.add(tuple(y))
                assert got == brute, "affine parametrisation is not the solution set"


def test_gauss_rejects_inconsistent_systems():
    assert gauss_mod_p([[1, 0], [1, 0]], [0, 1], 2, 2) is None
    assert gauss_mod_p([[1, 1], [1, 1]], [3, 5], 2, 13) is None
    assert gauss_mod_p([[0, 0]], [1], 2, 13) is None
    assert gauss_mod_p([[1, 1], [2, 2]], [3, 6], 2, 13) is not None   # rank deficient, consistent
    assert gauss_mod_p([[0, 0]], [0], 2, 13) is not None


def test_gauss_empty_system_is_whole_space():
    part, null = gauss_mod_p([], [], 3, 13)
    assert part == [0, 0, 0] and len(null) == 3


def test_gauss_rank_deficiency_dimension():
    # three copies of one equation in four unknowns -> rank 1, nullity 3
    rows = [[1, 2, 3, 4], [2, 4, 6, 8], [3, 6, 9, 12]]
    part, null = gauss_mod_p(rows, [1, 2, 3], 4, 13)
    assert len(null) == 3
    assert _matvec(rows, part, 13) == [1, 2, 3]


# ---------------------------------------------------------------- 2. solve_z26

def test_solve_z26_random_consistent_systems():
    rng = random.Random(23)
    for _ in range(150):
        n, m = rng.randrange(1, 6), rng.randrange(1, 8)
        rows = [[rng.randrange(26) for _ in range(n)] for _ in range(m)]
        x = [rng.randrange(26) for _ in range(n)]
        rhs = _matvec(rows, x, 26)
        sp = solve_z26(rows, rhs, n)
        assert sp is not None
        assert sp.contains(x), "the planted solution is not in the reported space"
        assert _matvec(rows, sp.particular, 26) == rhs
        for g in sp.generators:
            assert _matvec(rows, g, 26) == [0] * m
        if n <= 3:
            brute = {tuple(y) for y in itertools.product(range(26), repeat=n)
                     if _matvec(rows, y, 26) == rhs}
            got = {sp.point(c2, c13)
                   for c2 in itertools.product(range(2), repeat=sp.dim2)
                   for c13 in itertools.product(range(13), repeat=sp.dim13)}
            assert got == brute, "parametrisation does not cover the solution set exactly"
            assert sp.size == len(brute), "reported cardinality is wrong"


def test_solve_z26_detects_non_field_inconsistency():
    """Z_26 is not a field.  13x = 1 is consistent mod 2 and inconsistent mod 13;
    a solver that worked over one modulus, or that inverted naively, would miss it."""
    assert solve_z26([[13]], [1], 1) is None
    assert solve_z26([[2]], [1], 1) is None
    sp = solve_z26([[2]], [4], 1)                    # zero divisors -> two solutions
    assert sp is not None and sp.size == 2
    assert {sp.point(c2, c13) for c2 in itertools.product(range(2), repeat=sp.dim2)
            for c13 in itertools.product(range(13), repeat=sp.dim13)} == {(2,), (15,)}


def test_crt_and_whole_space():
    for a in range(2):
        for b in range(13):
            x = crt(a, b)
            assert x % 2 == a and x % 13 == b
    sp = solve_z26([], [], 2)
    assert sp.size == 26 ** 2 and sp.dim2 == 2 and sp.dim13 == 2


def test_free_columns():
    assert free_columns([[1, 0, 0], [0, 0, 0]], 3) == [1, 2]
    assert free_columns([[26, 0]], 2) == [0, 1]


# ------------------------------------------------- Quagmire systems (builders)

def _q3_system(ct, pt, period, variant="vig"):
    """One mixed alphabet.  vig: pi(c) - pi(p) - k = 0;  beau: pi(c) + pi(p) - k = 0;
    vbeau: -pi(c) + pi(p) - k = 0.  Unknowns 0..25 = pi, 26.. = k."""
    n = 26 + period
    cc, cp = {"vig": (1, -1), "beau": (1, 1), "vbeau": (-1, 1)}[variant]
    rows, rhs = [], []
    for i, (c, p) in enumerate(zip(ct, pt)):
        row = [0] * n
        row[ord(c) - 65] = (row[ord(c) - 65] + cc) % 26
        row[ord(p) - 65] = (row[ord(p) - 65] + cp) % 26
        row[26 + i % period] = 25
        rows.append(row)
        rhs.append(0)
    return rows, rhs, n


def _q3_gauge(truth, t, period, variant):
    """Adding t to every pi value is a symmetry only if the key absorbs it:
    vig/vbeau leave k alone, beau needs k + 2t."""
    dk = 2 * t if variant == "beau" else 0
    return ([(v + t) % 26 for v in truth[:26]]
            + [(v + dk) % 26 for v in truth[26:]])


def _q4_system(ct, pt, period, variant="vig"):
    """Unknowns 0..25 = pi_p, 26..51 = pi_c, 52.. = k."""
    n = 52 + period
    rows, rhs = [], []
    for i, (c, p) in enumerate(zip(ct, pt)):
        row = [0] * n
        ci, pi_ = 26 + ord(c) - 65, ord(p) - 65
        if variant == "vig":                # pi_c(c) - pi_p(p) - k = 0
            row[ci], row[pi_] = 1, 25
        elif variant == "beau":             # pi_c(c) + pi_p(p) - k = 0
            row[ci], row[pi_] = 1, 1
        else:                               # vbeau: -pi_c(c) + pi_p(p) - k = 0
            row[ci], row[pi_] = 25, 1
        row[52 + i % period] = 25
        rows.append(row)
        rhs.append(0)
    return rows, rhs, n


def _encrypt(pt, alpha_p, alpha_c, key, variant):
    ip = {ch: i for i, ch in enumerate(alpha_p)}
    period = len(key)
    out = []
    for i, p in enumerate(pt):
        k = key[i % period]
        if variant == "vig":
            v = (ip[p] + k) % 26
        elif variant == "beau":
            v = (k - ip[p]) % 26
        else:
            v = (ip[p] - k) % 26
        out.append(alpha_c[v])
    return "".join(out)


# ------------------------------------------- 3. known permutation recovered

def test_q3_system_is_homogeneous_so_consistency_is_vacuous():
    """STRUCTURAL FACT the sweeps must not misreport: the Quagmire crib system is
    HOMOGENEOUS (pi=const, k=0 always solves it), so `solve_z26` can never return
    None for Q3/Q4 and 'consistent' carries exactly zero information.  All power
    is in injectivity."""
    import compute as C
    for period in range(1, 15):
        rows, rhs, n = _q3_system(C.K1_CT, C.K1_PT, period)
        assert all(v == 0 for v in rhs)
        assert solve_z26(rows, rhs, n) is not None
        assert solve_z26(rows, rhs, n).contains([0] * n)


def test_known_permutation_recovered_up_to_gauge_and_scalar():
    """POSITIVE CONTROL.  Synthesise from a KNOWN random mixed alphabet, key and
    period; the true point must lie in the recovered space, the space must be
    exactly the trivial orbit (gauge shift x global scalar), and injectivity must
    be reported True."""
    rng = random.Random(5)
    passed = 0
    trials = 0
    for _ in range(15):
        for variant in ("vig", "beau", "vbeau"):
            trials += 1
            alpha = "".join(rng.sample(STD, 26))
            period = rng.randrange(3, 8)
            key = [rng.randrange(26) for _ in range(period)]
            while math.gcd(26, *key) != 1:          # see test_even_key_inflates_the_trivial_orbit
                key = [rng.randrange(26) for _ in range(period)]
            pt = "".join(rng.choice(STD) for _ in range(400))
            ct = _encrypt(pt, alpha, alpha, key, variant)
            rows, rhs, n = _q3_system(ct, pt, period, variant)
            sp = solve_z26(rows, rhs, n)
            assert sp is not None
            idx = {ch: i for i, ch in enumerate(alpha)}
            truth = [idx[STD[i]] for i in range(26)] + list(key)
            assert sp.contains(truth), f"{variant}: planted alphabet+key not in the space"
            assert sp.contains(_q3_gauge(truth, 7, period, variant)), "gauge missing"
            # The trivial orbit is gauge x scalar = 26^2 = 676, sometimes inflated
            # by one extra factor of 13 (see test_even_key_inflates_the_trivial_orbit
            # and the Beaufort parity analogue).  It must never be smaller than the
            # trivial orbit, and must stay small enough for the test to have power.
            assert 676 <= sp.size <= 26 ** 3, f"{variant}: got {sp.describe()}"
            assert sp.contains([(3 * v) % 26 for v in truth]), "scalar multiple missing"
            assert injective_point_exists(sp, list(range(26))) is True
            passed += 1
    assert passed == trials, f"positive control {passed}/{trials}"


def test_even_key_inflates_the_trivial_orbit():
    """CAVEAT the sweeps must carry: the "no information" solution-space size is
    NOT always 26^2.  pi(c)-pi(p)=k[r] only pins pi up to functions that are
    affine on each coset of <k>, so when every key shift is even (gcd(26,k)=2)
    the trivial orbit is 13x larger.  Dimension above 2 is therefore not
    evidence by itself."""
    rng = random.Random(31)
    alpha = "".join(rng.sample(STD, 26))
    period = 5
    pt = "".join(rng.choice(STD) for _ in range(800))
    sizes = {}
    for key in ([1, 4, 7, 12, 19], [2, 4, 8, 12, 18]):
        ct = _encrypt(pt, alpha, alpha, key, "vig")
        rows, rhs, n = _q3_system(ct, pt, period, "vig")
        sizes[math.gcd(26, *key)] = solve_z26(rows, rhs, n).size
    assert sizes[1] == 676
    assert sizes[2] == 676 * 13, sizes


def test_q4_positive_control_all_variants():
    """Q4: two independent mixed alphabets.  The truth must survive, both
    alphabets must be reported injectable."""
    rng = random.Random(9)
    passed = trials = 0
    for _ in range(9):
        for variant in ("vig", "beau", "vbeau"):
            trials += 1
            ap = "".join(rng.sample(STD, 26))
            ac = "".join(rng.sample(STD, 26))
            period = rng.randrange(3, 8)
            key = [rng.randrange(26) for _ in range(period)]
            pt = "".join(rng.choice(STD) for _ in range(400))
            ct = _encrypt(pt, ap, ac, key, variant)
            rows, rhs, n = _q4_system(ct, pt, period, variant)
            sp = solve_z26(rows, rhs, n)
            assert sp is not None
            ipp = {ch: i for i, ch in enumerate(ap)}
            ipc = {ch: i for i, ch in enumerate(ac)}
            truth = ([ipp[STD[i]] for i in range(26)] + [ipc[STD[i]] for i in range(26)]
                     + list(key))
            assert sp.contains(truth), f"Q4 {variant}: planted solution not in the space"
            got = injective_point_exists(sp, [list(range(26)), list(range(26, 52))])
            assert got is True, f"Q4 {variant}: OVER-ELIMINATION, got {got}"
            passed += 1
    assert passed == trials, f"Q4 positive control {passed}/{trials}"


# ------------------------------------------------------------- 4. injectivity

def _pointspace(values):
    return Z26Space(n=len(values), part2=tuple(v % 2 for v in values), basis2=(),
                    part13=tuple(v % 13 for v in values), basis13=())


def test_injectivity_single_point_cases():
    assert injective_point_exists(_pointspace([0, 1, 2]), [0, 1, 2]) is True
    rep = injective_point_report(_pointspace([0, 1, 0]), [0, 1, 2])
    assert rep.decision is False and rep.exhaustive
    assert "equal at every point" in rep.reason


def test_injectivity_pigeonhole_and_full_freedom():
    sp = solve_z26([], [], 30)
    rep = injective_point_report(sp, list(range(27)))
    assert rep.decision is False and "pigeonhole" in rep.reason
    assert injective_point_exists(sp, list(range(26))) is True   # 26 free slots: easy


def test_injectivity_two_free_letters():
    sp = Z26Space(n=2, part2=(0, 0), basis2=((0, 1),), part13=(0, 0), basis13=((0, 1),))
    rep = injective_point_report(sp, [0, 1])
    assert rep.decision is True and rep.witness[0] != rep.witness[1]


def test_injectivity_false_with_nontrivial_space_mod2():
    """Slot values (0, 13c, 13+13c), c in Z_2.  No pair is identically equal, but
    both points collide somewhere -> a sound False that needs the full search."""
    sp = Z26Space(n=3, part2=(0, 0, 1), basis2=((0, 1, 1),), part13=(0, 0, 0), basis13=())
    assert {sp.point([c]) for c in (0, 1)} == {(0, 0, 13), (0, 13, 0)}
    rep = injective_point_report(sp, [0, 1, 2])
    assert rep.decision is False and rep.exhaustive
    assert "complete search" in rep.reason


def test_injectivity_true_mod13_only():
    """Slot values (0, 2c, 4c), c in Z_13: c=1 gives (0,2,4)."""
    sp = Z26Space(n=3, part2=(0, 0, 0), basis2=(), part13=(0, 0, 0), basis13=((0, 1, 2),))
    rep = injective_point_report(sp, [0, 1, 2])
    assert rep.decision is True and len(set(rep.witness)) == 3


def test_gauge_direction_does_not_inflate_reported_rank():
    """A direction that shifts every slot equally must vanish from the difference
    dimensions, or the sweeps will misreport how much freedom is left."""
    sp = Z26Space(n=3, part2=(0, 1, 0), basis2=((1, 1, 1),), part13=(0, 5, 9),
                  basis13=((1, 1, 1),))
    rep = injective_point_report(sp, [0, 1, 2])
    assert rep.diff_rank2 == 0 and rep.diff_rank13 == 0
    assert rep.decision is True


def test_injectivity_matches_brute_force_on_random_small_spaces():
    """ANTI-OVER-ELIMINATION CONTROL: agree with exhaustive enumeration on every
    small space, in both directions."""
    rng = random.Random(77)
    ntrue = nfalse = 0
    for _ in range(500):
        n = rng.randrange(2, 5)
        d2, d13 = rng.randrange(0, 3), rng.randrange(0, 2)
        sp = Z26Space(
            n=n,
            part2=tuple(rng.randrange(2) for _ in range(n)),
            basis2=tuple(tuple(rng.randrange(2) for _ in range(n)) for _ in range(d2)),
            part13=tuple(rng.randrange(13) for _ in range(n)),
            basis13=tuple(tuple(rng.randrange(13) for _ in range(n)) for _ in range(d13)),
        )
        brute = any(len(set(sp.point(c2, c13))) == n
                    for c2 in itertools.product(range(2), repeat=d2)
                    for c13 in itertools.product(range(13), repeat=d13))
        got = injective_point_exists(sp, list(range(n)))
        assert got is brute, f"decider {got} vs brute force {brute}"
        ntrue += brute
        nfalse += not brute
    assert ntrue > 50 and nfalse > 10, f"degenerate test mix: {ntrue} True / {nfalse} False"


def test_injectivity_two_groups_quagmire_iv_shape():
    """Q4 needs pi_p and pi_c injective SEPARATELY; collisions across the two
    groups are legal."""
    sp = _pointspace([0, 1, 0, 1])
    assert injective_point_exists(sp, [[0, 1], [2, 3]]) is True
    assert injective_point_exists(sp, [[0, 2], [1, 3]]) is False


def test_inconclusive_is_reported_not_guessed():
    """A budget-out must surface as None.  It must never masquerade as False."""
    rng = random.Random(3)
    n = 24
    sp = Z26Space(
        n=n,
        part2=tuple(rng.randrange(2) for _ in range(n)),
        basis2=tuple(tuple(rng.randrange(2) for _ in range(n)) for _ in range(14)),
        part13=tuple(rng.randrange(13) for _ in range(n)),
        basis13=tuple(tuple(rng.randrange(13) for _ in range(n)) for _ in range(14)),
    )
    rep = injective_point_report(sp, list(range(n)), node_budget=1, restarts=2)
    assert rep.decision is not False, "budget exhaustion must never become an elimination"
    if rep.decision is None:
        assert "INCONCLUSIVE" in " ".join(rep.notes)


# ----------------------------------------------------------- 5. real-data control

def _panels():
    import compute as C
    return [("K1", C.K1_CT, C.K1_PT, "PALIMPSEST", 10),
            ("K2", K2_CT, C.K2_PT, "ABSCISSA", 8)]


def test_real_k1_k2_quagmire_iii_recovered():
    """REAL-DATA CONTROL.  K1 and K2 are published Quagmire III panels.  At their
    true period the KRYPTOS alphabet with the true keyword must be in the space,
    the gauge shift must be in the space, and injectivity must be True."""
    idx = {ch: i for i, ch in enumerate(KRY)}
    for name, ct, pt, kw, period in _panels():
        m = min(len(ct), len(pt))
        rows, rhs, n = _q3_system(ct[:m], pt[:m], period)
        sp = solve_z26(rows, rhs, n)
        assert sp is not None, f"{name}: true panel CONTRADICTED -- unsound"
        truth = [idx[STD[i]] for i in range(26)] + [idx[kw[r]] for r in range(period)]
        assert sp.contains(truth), f"{name}: KRYPTOS alphabet + {kw} not in the space"
        assert sp.contains(_q3_gauge(truth, 7, period, "vig")), \
            f"{name}: gauge direction missing"
        rep = injective_point_report(sp, list(range(26)))
        assert rep.decision is True, f"{name}: declared non-injective -- OVER-ELIMINATION"
        assert len(set(rep.witness[:26])) == 26


def test_real_k1_k2_wrong_periods_are_eliminated():
    """POWER.  The same decider must eliminate every period that is not a
    multiple of the true one -- for ALL 26! alphabets at once."""
    for name, ct, pt, kw, period in _panels():
        m = min(len(ct), len(pt))
        surviving = []
        for p in range(1, 21):
            rows, rhs, n = _q3_system(ct[:m], pt[:m], p)
            sp = solve_z26(rows, rhs, n)
            assert sp is not None, "homogeneous system cannot be inconsistent"
            if injective_point_exists(sp, list(range(26))) is not False:
                surviving.append(p)
        assert surviving == [p for p in range(1, 21) if p % period == 0], \
            f"{name}: surviving periods {surviving}, expected multiples of {period}"


def test_real_k1_single_letter_corruption_is_caught():
    """POWER.  One wrong ciphertext letter must break injectivity at the true
    period; if it never did, the filter would have no discriminating power."""
    import compute as C
    caught = 0
    for ch in STD:
        if ch == C.K1_CT[5]:
            continue
        ct = C.K1_CT[:5] + ch + C.K1_CT[6:]
        rows, rhs, n = _q3_system(ct, C.K1_PT, 10)
        if injective_point_exists(solve_z26(rows, rhs, n), list(range(26))) is False:
            caught += 1
    assert caught >= 24, f"only {caught}/25 corruptions caught"


def test_real_k1_shuffled_ct_matched_null():
    """MATCHED NULL for the real-data control: a shuffled K1 ciphertext must not
    survive the same procedure at the true period."""
    import compute as C
    rng = random.Random(0)
    survived = 0
    trials = 60
    for _ in range(trials):
        ct = list(C.K1_CT)
        rng.shuffle(ct)
        rows, rhs, n = _q3_system("".join(ct), C.K1_PT, 10)
        if injective_point_exists(solve_z26(rows, rhs, n), list(range(26))) is True:
            survived += 1
    assert survived <= 1, f"shuffled-CT survival {survived}/{trials} -- filter has no power"
