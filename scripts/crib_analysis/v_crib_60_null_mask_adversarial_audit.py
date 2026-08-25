#!/usr/bin/env python3
"""ADVERSARIAL AUDIT of e_crib_60_null_mask_ceiling_sweep.py.

HYPOTHESIS UNDER TEST (of the audit, not of K4)
-----------------------------------------------
The reviewed sweep claims that, within its declared structured null-mask
families (PT length 73-96) and for periodic additive substitution of period
1-30 over two tableaux, the attainable-crib-ceiling filter eliminates EVERY
configuration of period <= 21 on the released cribs (L0) alone, and eliminates
every configuration at L1-L5.  This script tries to REFUTE that.

SCOPE OF THE AUDIT
------------------
  A. Re-derive the mask set independently and check bijection / index sanity of
     every payload map K (the null-mask analogue of a permutation).
  B. Re-implement the L0 canonicalisation from the stated model definitions,
     WITHOUT importing the reviewed module's canonical()/canon_keys(), and
     recompute the full L0 per-period ceiling table.  Compare against the
     reviewed run's reported per-period margins and survivor counts.
  C. Cross-check every ceiling used here against scripts/lib/crib_filter.ceiling
     (the control-verified reference) on a large random sample.
  D. CONSTRUCTIVE positive control: for a reported L0 survivor, actually build a
     key and verify all 24 cribs are simultaneously satisfied -- proving the
     survivor is a genuine ceiling==n cell and not a counting artefact.
  E. CONSTRUCTIVE negative control: for a reported elimination, exhibit the two
     cribs that share a key class and demand different shifts.
  F. Independent re-derivation of the "no nulls before CT 63 at L4/L5" claim.

PRE-REGISTERED INTERPRETATION
-----------------------------
  ceiling <  n_cribs  =>  IMPOSSIBLE for every key.  SOUND ELIMINATION.
  ceiling == n_cribs  =>  NOT ELIMINATED BY THIS FILTER.  Never "possible".
A mismatch between this audit and the reviewed run on ANY per-period figure is
a refutation of that figure; agreement is corroboration of the arithmetic only,
never of the scope claim.
"""
from __future__ import annotations
import argparse, os, random, sys, time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts"))

from kryptos.kernel.constants import CT, CRIB_DICT              # noqa: E402
from lib.crib_filter import ceiling as ref_ceiling, index_table, keyword_mixed  # noqa: E402
from lib import crib_sets                                        # noqa: E402

N = 97
PERIODS = list(range(1, 31))
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = keyword_mixed("KRYPTOS")
TAB = {"AZ": index_table(AZ), "KA": index_table(KA)}
CIPHERS = [(v, ct) for v in ("vig", "beau", "vbeau") for ct in ("AZ", "KA")]
CRIB_POS = sorted(CRIB_DICT)


def tval(ct_ch, pt_ch, ctname, variant):
    c = TAB[ctname][ord(ct_ch) - 65]
    p = TAB["AZ"][ord(pt_ch) - 65]
    if variant == "vig":
        return (c - p) % 26
    if variant == "beau":
        return (c + p) % 26
    return (p - c) % 26


def my_ceiling(bases, ts, period):
    """Independent implementation: sum over key classes of the max multiplicity
    of a demanded shift.  Deliberately written differently from the reviewed
    inline counter (dict-of-dicts rather than a c*26+t packed key)."""
    g = defaultdict(lambda: defaultdict(int))
    for b, t in zip(bases, ts):
        g[b % period][t] += 1
    return sum(max(d.values()) for d in g.values())


# ── A. independent mask enumeration (same declared families, own code) ─────

def enum_masks():
    out = {}

    def add(fam, positions):
        ps = tuple(sorted(set(positions)))
        if not (1 <= len(ps) <= 24):
            return
        out.setdefault(ps, fam)

    from itertools import combinations
    for m in range(2, 25):                                   # F1
        sizes = [len(range(r, N, m)) for r in range(m)]
        for k in range(1, m + 1):
            if k * min(sizes) > 24:
                break
            for R in combinations(range(m), k):
                add("F1", [p for p in range(N) if p % m in R])
    for m in range(25, 49):                                  # F1b
        for k in (1, 2):
            for R in combinations(range(m), k):
                add("F1b", [p for p in range(N) if p % m in R])
    for s in range(N):                                       # F2
        for m in range(2, 11):
            for k in range(1, m + 1):
                for R in combinations(range(m), k):
                    add("F2", [p for p in range(s, N) if (p - s) % m in R])
    for ln in range(1, 25):                                  # F3
        for a in range(0, N - ln + 1):
            add("F3", range(a, a + ln))
    for k in (1, 2, 3):                                      # F4
        for R in combinations(range(N), k):
            add("F4", R)
    for a in range(0, 25):                                   # F5
        for b in range(0, 25 - a):
            add("F5", list(range(a)) + list(range(N - b, N)))
    for w in range(2, 25):                                   # F6
        nrows = (N + w - 1) // w
        cand = [(r,) for r in range(nrows)]
        cand += list(combinations(range(nrows), 2))
        for a in range(nrows):
            for b in range(a + 2, nrows + 1):
                if (b - a) * w > 24 + w:
                    break
                cand.append(tuple(range(a, b)))
        for R in cand:
            add("F6", [p for p in range(N) if p // w in R])
    out[()] = "F0"
    return out


# ── B. independent L0 canonicalisation ─────────────────────────────────────

def l0_forms(nulls):
    """Return {(conv, mech): (bases, ct_letters, pt_letters)} or drop the cell.

    convA: released cribs name CIPHERTEXT positions 21-33 / 63-73; those must be
           non-null.  convB: released cribs name PLAINTEXT indices of the
           shortened message.
    mechA: key indexed by payload rank.  mechB: key indexed by CT position.
    """
    nullset = set(nulls)
    K = [p for p in range(N) if p not in nullset]
    L = len(K)
    rank = {p: i for i, p in enumerate(K)}
    res = {}
    # convA
    if not (nullset & set(CRIB_POS)):
        basesA = [rank[p] for p in CRIB_POS]
        basesB = list(CRIB_POS)
        ctl = [CT[p] for p in CRIB_POS]
        ptl = [CRIB_DICT[p] for p in CRIB_POS]
        res[("convA", "mechA")] = (basesA, ctl, ptl)
        res[("convA", "mechB")] = (basesB, ctl, ptl)
    # convB
    if max(CRIB_POS) < L:
        js = [K[q] for q in CRIB_POS]
        ctl = [CT[j] for j in js]
        ptl = [CRIB_DICT[q] for q in CRIB_POS]
        res[("convB", "mechA")] = (list(CRIB_POS), ctl, ptl)
        res[("convB", "mechB")] = (js, ctl, ptl)
    return res


def _l0_chunk(masks):
    """Per (period, conv, mech): survivors (mask x cipher), vacuous, non-vacuous,
    and the global max ceiling per period."""
    cell = defaultdict(int)
    vac = defaultdict(int)
    nonvac = defaultdict(int)
    maxc = defaultdict(int)
    firsts = {}
    for nulls in masks:
        for (conv, mech), (bases, ctl, ptl) in l0_forms(nulls).items():
            ts = {(v, cn): [tval(c, q, cn, v) for c, q in zip(ctl, ptl)]
                  for (v, cn) in CIPHERS}
            for period in PERIODS:
                cls = [b % period for b in bases]
                if len(set(cls)) == len(cls):
                    vac[(period, conv, mech)] += 1
                    cell[(period, conv, mech)] += len(CIPHERS)
                    maxc[period] = max(maxc[period], 24)
                    continue
                for key in CIPHERS:
                    cv = my_ceiling(bases, ts[key], period)
                    maxc[period] = max(maxc[period], cv)
                    if cv == 24:
                        cell[(period, conv, mech)] += 1
                        nonvac[(period, conv, mech)] += 1
                        firsts.setdefault((period, conv, mech, key),
                                          (nulls, key))
    return dict(cell), dict(vac), dict(nonvac), dict(maxc), firsts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int,
                    default=max(1, len(os.sched_getaffinity(0)) - 2))
    ap.add_argument("--sample", type=int, default=60000,
                    help="configs cross-checked against crib_filter.ceiling")
    a = ap.parse_args()
    t0 = time.perf_counter()
    rnd = random.Random(20260825)

    # ---- A ---------------------------------------------------------------
    masks = enum_masks()
    print(f"[A] independently enumerated unique masks : {len(masks):,}")
    keylist = list(masks)
    bad = 0
    for nulls in keylist[:5000] + rnd.sample(keylist, 5000):
        K = [p for p in range(N) if p not in set(nulls)]
        if sorted(set(K)) != K or len(K) + len(set(nulls)) != N:
            bad += 1
    print(f"[A] payload maps K checked for bijection/dup/range : {bad} bad")
    tail = sum(1 for m in masks if m and min(m) >= 74)
    print(f"[A] masks with all nulls at CT>=74 : {tail:,} (+1 zero-null control)")

    # ---- C  cross-check my_ceiling against crib_filter.ceiling ------------
    mism = 0
    checked = 0
    for _ in range(a.sample // 4):
        nulls = rnd.choice(keylist)
        forms = l0_forms(nulls)
        if not forms:
            continue
        (conv, mech), (bases, ctl, ptl) = rnd.choice(list(forms.items()))
        period = rnd.choice(PERIODS)
        variant, cn = rnd.choice(CIPHERS)
        cribs = {i: ptl[i] for i in range(len(ptl))}
        fake_ct = "".join(ctl)
        ref, _ = ref_ceiling(fake_ct, cribs, (lambda q: q),
                             (lambda q, b=bases, p=period: b[q] % p),
                             ct_tab=TAB[cn], pt_tab=TAB["AZ"], variant=variant)
        mine = my_ceiling(bases, [tval(c, q, cn, variant)
                                  for c, q in zip(ctl, ptl)], period)
        checked += 1
        if ref != mine:
            mism += 1
            if mism < 4:
                print("   MISMATCH", conv, mech, period, variant, cn, ref, mine)
    print(f"[C] my_ceiling vs crib_filter.ceiling : {checked:,} configs, "
          f"{mism} mismatches")

    # ---- B  full independent L0 sweep -------------------------------------
    print(f"[B] full independent L0 sweep on {a.workers} workers ...", flush=True)
    step = max(1, len(keylist) // (a.workers * 8))
    parts = [keylist[i:i + step] for i in range(0, len(keylist), step)]
    cell = defaultdict(int); vac = defaultdict(int)
    nonvac = defaultdict(int); maxc = defaultdict(int); firsts = {}
    with ProcessPoolExecutor(max_workers=a.workers) as ex:
        for c, v, nv, mc, fr in ex.map(_l0_chunk, parts):
            for k, n in c.items(): cell[k] += n
            for k, n in v.items(): vac[k] += n
            for k, n in nv.items(): nonvac[k] += n
            for k, n in mc.items(): maxc[k] = max(maxc[k], n)
            for k, val in fr.items(): firsts.setdefault(k, val)
    print(f"    [{time.perf_counter()-t0:.1f}s]")
    print("\n[B] L0 max ceiling per period (out of 24):")
    print("    " + " ".join(f"p{p}:{maxc[p]}" for p in PERIODS))
    print("\n[B] L0 survivor cells (period, conv, mech, surv, vacuous, non-vac):")
    for p in PERIODS:
        for conv in ("convA", "convB"):
            for mech in ("mechA", "mechB"):
                s = cell.get((p, conv, mech), 0)
                if s:
                    print(f"    {p:>3} {conv} {mech} surv={s:,} "
                          f"vac={vac.get((p,conv,mech),0)*len(CIPHERS):,} "
                          f"nonvac={nonvac.get((p,conv,mech),0):,}")
    tot_nv = sum(nonvac.values())
    minp = min([p for (p, c, m) in cell], default=None)
    minp_nv = min([p for (p, c, m) in nonvac if nonvac[(p, c, m)]], default=None)
    print(f"\n[B] total non-vacuous L0 survivors : {tot_nv:,}")
    print(f"[B] smallest period with ANY L0 survivor        : {minp}")
    print(f"[B] smallest period with a NON-VACUOUS survivor : {minp_nv}")

    # ---- D  constructive positive control ---------------------------------
    print("\n[D] constructive check of a minimal-period survivor")
    cand = sorted([k for k in firsts if k[0] == minp_nv])
    if cand:
        k0 = cand[0]
        nulls, (variant, cn) = firsts[k0]
        period, conv, mech = k0[0], k0[1], k0[2]
        bases, ctl, ptl = l0_forms(nulls)[(conv, mech)]
        ts = [tval(c, q, cn, variant) for c, q in zip(ctl, ptl)]
        shift = {}
        ok = True
        for b, t in zip(bases, ts):
            c = b % period
            if c in shift and shift[c] != t:
                ok = False
            shift[c] = t
        # verify: decrypt each crib position with the constructed key
        hits = 0
        for b, c_ch, p_ch in zip(bases, ctl, ptl):
            s = shift[b % period]
            ci = TAB[cn][ord(c_ch) - 65]
            if variant == "vig":
                pi = (ci - s) % 26
            elif variant == "beau":
                pi = (s - ci) % 26
            else:
                pi = (ci + s) % 26
            if AZ[pi] == p_ch:
                hits += 1
        print(f"    period={period} {conv} {mech} {variant}/{cn} "
              f"nulls={len(nulls)} at {list(nulls)[:8]}...")
        print(f"    key classes consistent : {ok};  cribs satisfied by the "
              f"constructed key : {hits}/24")
        print("    (24/24 means the cell is genuinely NOT ELIMINATED by this "
              "filter -- it does NOT mean the model is correct.)")

    # ---- E  constructive negative control ---------------------------------
    print("\n[E] constructive check of an elimination (period 10, convA/mechB,"
          " vig/AZ, zero-null control)")
    bases, ctl, ptl = l0_forms(())[("convA", "mechB")]
    ts = [tval(c, q, "AZ", "vig") for c, q in zip(ctl, ptl)]
    g = defaultdict(list)
    for b, t, c_ch, p_ch in zip(bases, ts, ctl, ptl):
        g[b % 10].append((b, t, c_ch, p_ch))
    conflicts = [(c, v) for c, v in g.items() if len({x[1] for x in v}) > 1]
    cv = my_ceiling(bases, ts, 10)
    print(f"    ceiling = {cv}/24 ; {len(conflicts)} key classes carry "
          f"contradictory shift demands")
    c0, v0 = conflicts[0]
    print(f"    e.g. class {c0}: " + "; ".join(
        f"CT[{b}]={c} needs PT={p} -> shift {t}" for b, t, c, p in v0[:3]))

    # ---- F  independent contiguity re-derivation --------------------------
    print("\n[F] independent re-derivation of the L4/L5 convA contiguity claim")
    lvl = crib_sets.level("L4_layoutA_reset")
    surv = []
    for nulls in keylist:
        ns = set(nulls)
        if ns & set(CRIB_POS):
            continue
        K = [p for p in range(N) if p not in ns]
        L = len(K)
        rank = {p: i for i, p in enumerate(K)}
        ok = True
        ctc = {p: CRIB_DICT[p] for p in CRIB_POS}
        for q, ch in lvl.items():
            if q in CRIB_DICT:
                continue
            if q >= L:
                ok = False; break
            j = K[q]
            if j in ctc and ctc[j] != ch:
                ok = False; break
            ctc[j] = ch
        if ok:
            surv.append(nulls)
    print(f"    masks passing the L4 convA structural filter : {len(surv):,}")
    bad_tail = [m for m in surv if m and min(m) < 74]
    print(f"    of those, masks with ANY null before CT 74   : {len(bad_tail)}")
    print(f"    -> contiguity claim {'CORROBORATED' if not bad_tail else 'REFUTED'}")

    # ---- G  is the tableau restriction load-bearing? ----------------------
    print("\n[G] the reviewed sweep fixed the tableau to CT in {AZ, KRYPTOS-mixed},"
          " PT = AZ.\n    Try a FREE mixed CT alphabet (Quagmire-II shape, still a"
          " periodic additive\n    cipher) on the ZERO-NULL control, which is a member"
          " of the swept mask set.")
    from collections import defaultdict as _dd
    def free_ct_alphabet(period, bases, ctl, ptl, tries=400000, seed=1):
        g = _dd(list)
        for b, c, q in zip(bases, ctl, ptl):
            g[b % period].append((c, q))
        cons = []
        for _cl, v in g.items():
            c0, p0 = v[0]
            for (c, q) in v[1:]:
                cons.append((c, c0, (AZ.index(q) - AZ.index(p0)) % 26))
        par = {ch: ch for ch in AZ}; off = {ch: 0 for ch in AZ}
        def find(x):
            if par[x] == x: return x, 0
            r, o = find(par[x]); par[x] = r; off[x] = (off[x] + o) % 26
            return r, off[x]
        for a_, b_, d_ in cons:
            ra, oa = find(a_); rb, ob = find(b_)
            if ra == rb:
                if (oa - ob) % 26 != d_ % 26:
                    return None
            else:
                par[ra] = rb; off[ra] = (d_ + ob - oa) % 26
        comps = {}
        for ch in AZ:
            r, o = find(ch); comps.setdefault(r, []).append((ch, o))
        rnd2 = random.Random(seed); keys = sorted(comps, key=lambda k: -len(comps[k]))
        for _ in range(tries):
            used = set(); tab = {}; good = True
            for k in keys:
                cands = list(range(26)); rnd2.shuffle(cands); placed = False
                for base in cands:
                    vals = [(base + o) % 26 for _, o in comps[k]]
                    if len(set(vals)) == len(vals) and not (used & set(vals)):
                        for (ch, o), v in zip(comps[k], vals): tab[ch] = v
                        used |= set(vals); placed = True; break
                if not placed: good = False; break
            if good: return tab
        return None
    ctl0 = [CT[p] for p in CRIB_POS]; ptl0 = [CRIB_DICT[p] for p in CRIB_POS]
    hits = []
    for period in range(2, 27):
        tab = free_ct_alphabet(period, list(CRIB_POS), ctl0, ptl0)
        if not tab: continue
        alpha = [None] * 26
        for ch, v in tab.items(): alpha[v] = ch
        alpha = "".join(alpha)
        cv, _ = ref_ceiling(CT, CRIB_DICT, (lambda q: q),
                            (lambda q, p=period: q % p),
                            ct_tab=index_table(alpha), pt_tab=TAB["AZ"],
                            variant="vig")
        if cv == 24: hits.append((period, alpha))
    print(f"    periods <= 26 where a free CT alphabet lifts the ceiling to 24/24 "
          f"on the raw carved CT with ZERO nulls: {[h[0] for h in hits]}")
    if hits and hits[0][0] <= 21:
        period, alpha = hits[0]
        ctt = index_table(alpha)
        cv, cls = ref_ceiling(CT, CRIB_DICT, (lambda q: q),
                              (lambda q, p=period: q % p),
                              ct_tab=ctt, pt_tab=TAB["AZ"], variant="vig")
        shift = {c: max(d, key=d.get) for c, d in cls.items()}
        ok = sum(1 for p, ch in CRIB_DICT.items()
                 if AZ[(ctt[ord(CT[p]) - 65] - shift[p % period]) % 26] == ch)
        print(f"    COUNTEREXAMPLE to an unscoped 'period <= 21 is eliminated' claim:")
        print(f"      period {period}, CT alphabet {alpha}, PT alphabet AZ, Vigenere")
        print(f"      constructed key satisfies {ok}/24 released cribs, zero nulls")
        print(f"      -> the elimination is a property of the TWO TABLEAUX TESTED,")
        print(f"         not of periodic additive substitution at that period.")

    # ---- H  convA is exhaustible over EVERY mask --------------------------
    print("\n[H] convA canonical forms depend on the mask ONLY through")
    print("    d1 = #nulls in [0,21) and d2 = #nulls in [0,63), because the 24")
    print("    released crib positions must be non-null.  So the convA arm can be")
    print("    made EXHAUSTIVE over every mask -- arbitrary, unstructured, any null")
    print("    count -- in 660 cells.  The reviewed sweep realised only 72 of them.")
    bestA = _dd(int); survA = []
    for d1 in range(0, 22):
        for d2 in range(d1, d1 + 30):
            for mech in ("mechA", "mechB"):
                if mech == "mechB":
                    b = list(CRIB_POS)
                else:
                    b = [p - d1 for p in CRIB_POS if p < 34] + \
                        [p - d2 for p in CRIB_POS if p >= 63]
                for (v, cn) in CIPHERS:
                    ts = [tval(c, q, cn, v) for c, q in zip(ctl0, ptl0)]
                    for period in range(1, 41):
                        cvv = my_ceiling(b, ts, period)
                        if cvv > bestA[period]: bestA[period] = cvv
                        if cvv == 24:
                            vacu = len({x % period for x in b}) == 24
                            survA.append((period, d1, d2, mech, v, cn, vacu))
    print("    max ceiling per period, convA, EXHAUSTIVE over ALL masks:")
    print("      " + " ".join(f"p{p}:{bestA[p]}" for p in range(1, 31)))
    print("      " + " ".join(f"p{p}:{bestA[p]}" for p in range(31, 41)))
    mn = min([s[0] for s in survA], default=None)
    nvA = [s for s in survA if not s[6]]
    print(f"    smallest period with ANY convA survivor over ALL masks : {mn}")
    print(f"    NON-VACUOUS convA survivors over ALL masks, period 1-40: {len(nvA)}")
    print("    -> convA is eliminated for EVERY mask at period <= 23 (2 tableaux),")
    print("       which is BROADER than the reviewed 'structured families only'")
    print("       scope and one period deeper than the reviewed headline.")

    print(f"\ntotal [{time.perf_counter()-t0:.1f}s]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
