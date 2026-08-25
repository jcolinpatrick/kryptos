#!/usr/bin/env python3
"""NULL-MASK / SHORT-PLAINTEXT models under the attainable-crib-ceiling filter.

HYPOTHESIS UNDER TEST
---------------------
K4's plaintext is SHORTER than 97 characters. Some ciphertext positions are
nulls (filler). The message is carried by the non-null CT positions, in order.
The cipher acting on the payload is a periodic polyalphabetic substitution
(Vigenere / Beaufort / variant Beaufort, standard or KRYPTOS-mixed tableau)
with period 1-30.

Because the plaintext is short, a crib's CT-frame position is NOT its PT-frame
position. That is the whole point of this family, and it is what makes the
extended crib levels unusually powerful: PT[0:18] (L1), PT[0:21] (L2+) and
PT[34:63] (L4/L5) are CONTIGUOUS runs, so under a null mask they must land on
the first k non-null CT positions IN ORDER. That is a hard combinatorial
constraint on the mask before any key is considered.

TWO MECHANISMS (the "peel orders" for this family)
--------------------------------------------------
  mechA  "interrupted keystream" -- PT is enciphered with the periodic key
         indexed by PAYLOAD position, then nulls are INSERTED into the
         ciphertext. Key class of CT position j is rank(j) mod period, where
         rank(j) = number of non-null positions before j.
  mechB  "padded plaintext"      -- nulls are inserted into the PLAINTEXT
         first, then the whole 97-char string is enciphered positionally.
         Key class of CT position j is j mod period.

TWO CRIB-ANCHORING CONVENTIONS (a genuine ambiguity, both reported)
-------------------------------------------------------------------
  convA  CT-anchored released cribs. Sanborn named CIPHERTEXT character
         positions, so CT[21:34]->EASTNORTHEAST and CT[63:74]->BERLINCLOCK,
         which additionally REQUIRES those 24 CT positions to be non-null.
         Extended (L1-L5) cribs stay PT-anchored: PT index q sits at CT K[q].
  convB  PT-anchored released cribs. The released text sits at PT indices
         21-33 / 63-73 of the shortened message. All cribs then live in one
         frame and no position is forced non-null.

SCOPE -- STRUCTURED MASK FAMILIES ONLY
--------------------------------------
The space of arbitrary masks is astronomical: with 24 nulls chosen freely from
97 positions it is C(97,24) ~ 1.3e22. NOTHING here covers that. This sweep is
exhaustive only within the declared, structured families below (plus all
arbitrary masks of <=3 nulls), for PT lengths 73-96 (1-24 nulls), plus the
0-null control:
  F1_residue        p mod m in R, m 2..24, every R with null count 1..24
  F1b_residue_wide  p mod m in R, m 25..48, |R| <= 2
  F2_tail_residue   p >= s and (p-s) mod m in R, s 0..96, m 2..10, every R
  F3_block          one contiguous run of nulls, length 1..24
  F4_arbitrary_le3  EVERY mask with 1, 2 or 3 nulls anywhere (unstructured)
  F5_head_tail      a-char prefix + b-char suffix, 1 <= a+b <= 24
  F6_rows           whole grid rows null: (p // w) in R, w 2..24, with R
                    either <=2 arbitrary rows or one contiguous run of rows

The retired 7-letter palette and the retired 17-position CONSENSUS_NULL_POSITIONS
mask are NOT revived as evidence. Residue rules are tested on their own terms.

PRE-REGISTERED INTERPRETATION -- fixed before the run
-----------------------------------------------------
ceiling is an UPPER BOUND over ALL keys, so the implication is one way:
    ceiling <  n_cribs  =>  IMPOSSIBLE for every key.   SOUND ELIMINATION.
    ceiling == n_cribs  =>  NOT ELIMINATED BY THIS FILTER.
"ceiling == n" NEVER means a solution exists. A survivor survived a filter.
A structural failure (crib position is null / plaintext too short / two cribs
demand different letters at one CT position) is likewise a SOUND ELIMINATION
of that configuration, and is counted as eliminated.

L0_released is the only EVIDENCE level; its results are unconditional within
the declared mask scope. Every elimination at L1-L5 is CONDITIONAL on an
unproven plaintext hypothesis and must be reported as such.

USAGE
    PYTHONPATH=src python3 -u scripts/crib_analysis/e_crib_60_null_mask_ceiling_sweep.py \
        [--workers N] [--out results/null_mask_ceiling.json] [--quick]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from itertools import combinations

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts"))

from kryptos.kernel.constants import CT, CRIB_DICT          # noqa: E402
from lib.crib_filter import (ceiling, index_table,          # noqa: E402
                             keyword_mixed)
from lib import crib_sets                                   # noqa: E402

N = 97
MIN_NULLS, MAX_NULLS = 0, 24          # PT length 97 down to 73
PERIODS = list(range(1, 31))
MECHS = ("mechA_interrupted", "mechB_padded")
CONVS = ("convA_ct_anchored", "convB_pt_anchored")

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = keyword_mixed("KRYPTOS")
_TAB = {"AZ": index_table(AZ), "KA": index_table(KA)}
# (variant, ct alphabet, pt alphabet)
CIPHERS = [(v, ct, "AZ") for v in ("vig", "beau", "vbeau") for ct in ("AZ", "KA")]


# ─────────────────────────── mask families ────────────────────────────────

def _bm(positions) -> int:
    """Pack a set of null positions into a 97-bit integer."""
    v = 0
    for p in positions:
        v |= 1 << p
    return v


def _popcount(v: int) -> int:
    return bin(v).count("1")


def _mask_families():
    """Yield (family, label, null_positions_as_97bit_int). Duplicates OK."""
    # F1 / F1b -- residue classes
    for m in range(2, 25):
        sizes = [len(range(r, N, m)) for r in range(m)]
        for k in range(1, m + 1):
            if k * min(sizes) > MAX_NULLS:
                break
            for R in combinations(range(m), k):
                c = sum(sizes[r] for r in R)
                if 1 <= c <= MAX_NULLS:
                    yield ("F1_residue", f"m={m},R={list(R)}",
                           _bm(p for p in range(N) if p % m in R))
    for m in range(25, 49):
        sizes = [len(range(r, N, m)) for r in range(m)]
        for k in (1, 2):
            for R in combinations(range(m), k):
                c = sum(sizes[r] for r in R)
                if 1 <= c <= MAX_NULLS:
                    yield ("F1b_residue_wide", f"m={m},R={list(R)}",
                           _bm(p for p in range(N) if p % m in R))
    # F2 -- tail-restricted residue (nulls only from offset s onward)
    for s in range(N):
        for m in range(2, 11):
            for k in range(1, m + 1):
                for R in combinations(range(m), k):
                    ps = [p for p in range(s, N) if (p - s) % m in R]
                    if 1 <= len(ps) <= MAX_NULLS:
                        yield ("F2_tail_residue", f"s={s},m={m},R={list(R)}",
                               _bm(ps))
    # F3 -- one contiguous block
    for ln in range(1, MAX_NULLS + 1):
        for a in range(0, N - ln + 1):
            yield ("F3_block", f"[{a},{a+ln})", _bm(range(a, a + ln)))
    # F4 -- every arbitrary mask with <=3 nulls
    for k in (1, 2, 3):
        for R in combinations(range(N), k):
            yield ("F4_arbitrary_le3", f"{list(R)}", _bm(R))
    # F5 -- prefix + suffix
    for a in range(0, MAX_NULLS + 1):
        for b in range(0, MAX_NULLS + 1 - a):
            if 1 <= a + b <= MAX_NULLS:
                yield ("F5_head_tail", f"head={a},tail={b}",
                       _bm(list(range(a)) + list(range(N - b, N))))
    # F6 -- whole grid rows are null.  BOUNDED: at most two arbitrary rows,
    # or one contiguous run of rows.  (All k-subsets of rows is combinatorially
    # explosive -- C(49,12) at w=2 -- and is NOT covered.)
    for w in range(2, 25):
        nrows = (N + w - 1) // w
        cand = []
        for r in range(nrows):
            cand.append((r,))
        for R in combinations(range(nrows), 2):
            cand.append(R)
        for a in range(nrows):
            for b in range(a + 2, nrows + 1):
                if (b - a) * w > MAX_NULLS + w:
                    break
                cand.append(tuple(range(a, b)))
        for R in cand:
            ps = [p for p in range(N) if p // w in R]
            if 1 <= len(ps) <= MAX_NULLS:
                yield ("F6_rows", f"w={w},rows={list(R)}", _bm(ps))
    # control -- no nulls at all (the direct 97-char model)
    yield ("F0_control_no_nulls", "none", 0)


def build_masks():
    seen: dict[int, tuple[str, str]] = {}
    fam_raw: dict[str, int] = defaultdict(int)
    for fam, label, ns in _mask_families():
        fam_raw[fam] += 1
        if ns not in seen:
            seen[ns] = (fam, label)
    return seen, dict(fam_raw)


# ───────────────────── canonicalisation (stage 1) ─────────────────────────

LEVEL_DICTS = {lv: crib_sets.level(lv) for lv in crib_sets.LEVELS}
RELEASED = set(CRIB_DICT)


def canonical(K, L, rank, nullbits: int, level: str, conv: str):
    """Reduce (mask, level, convention) to the crib constraints in the CT frame.

    Returns (ctc, ptidx) or (None, reason) if the configuration is structurally
    impossible -- a SOUND elimination requiring no key search:
      * a released crib sits on a null position (convA), or
      * the plaintext is too short to contain a crib index, or
      * two cribs demand different plaintext letters at one CT position.
    """
    lvl = LEVEL_DICTS[level]
    ctc: dict[int, str] = {}
    ptidx: dict[int, int] = {}

    if conv == "convA_ct_anchored":
        for p, ch in CRIB_DICT.items():
            if (nullbits >> p) & 1:
                return None, "released_crib_position_is_null"
            ctc[p] = ch
            ptidx[p] = rank[p]
        for q, ch in lvl.items():
            if q in RELEASED:
                continue
            if q >= L:
                return None, "plaintext_too_short_for_extended_crib"
            j = K[q]
            if j in ctc and ctc[j] != ch:
                return None, "crib_letter_contradiction"
            ctc[j] = ch
            ptidx[j] = q
    else:                                   # convB -- everything PT-anchored
        for q, ch in lvl.items():
            if q >= L:
                return None, "plaintext_too_short_for_crib"
            j = K[q]
            ctc[j] = ch
            ptidx[j] = q
    return ctc, ptidx


def canon_keys(ctc, ptidx):
    """The ONLY thing the ceiling depends on: the multiset of
    (key-class-base, CT letter, PT letter).  Two configurations with the same
    canonical form have the same ceiling at every period and every cipher, so
    deduplicating on it is EXACT, not a sample."""
    kA = tuple(sorted((ptidx[j], CT[j], ctc[j]) for j in ctc))   # mechA
    kB = tuple(sorted((j, CT[j], ctc[j]) for j in ctc))          # mechB
    return kA, kB


def _canon_chunk(args):
    lo, hi, masks = args
    out = defaultdict(int)                  # (level,conv,mech,key,n_eff) -> weight
    ex: dict = {}                           # same key -> one representative mask
    dead = defaultdict(int)                 # (level,conv,mech,reason)    -> weight
    mA, mB = MECHS
    for ns in masks:
        K = [p for p in range(N) if not (ns >> p) & 1]
        L = len(K)
        rank = {p: i for i, p in enumerate(K)}
        for level in crib_sets.LEVELS:
            for conv in CONVS:
                ctc, info = canonical(K, L, rank, ns, level, conv)
                if ctc is None:
                    dead[(level, conv, mA, info)] += 1
                    dead[(level, conv, mB, info)] += 1
                    continue
                kA, kB = canon_keys(ctc, info)
                n_eff = len(ctc)
                for mech, key in ((mA, kA), (mB, kB)):
                    t = (level, conv, mech, key, n_eff)
                    out[t] += 1
                    if t not in ex:
                        ex[t] = ns
    return dict(out), dict(ex), dict(dead)


# ───────────────────────── ceiling sweep (stage 2) ────────────────────────

def _ceiling_from(cls, ts):
    """sum over key classes of the max multiplicity of a demanded shift."""
    cnt: dict = {}
    for c, t in zip(cls, ts):
        k = c * 26 + t
        cnt[k] = cnt.get(k, 0) + 1
    best: dict = {}
    for k, v in cnt.items():
        c = k // 26
        if v > best.get(c, 0):
            best[c] = v
    return sum(best.values())


def _sweep_chunk(items):
    """items: (level,conv,mech,key,n_eff,weight,mask). Returns per-level
    aggregates plus survivor descriptors."""
    agg = defaultdict(lambda: {"tested": 0, "surv": 0, "maxc": -1})
    surv = defaultdict(list)
    ncip = len(CIPHERS)
    for (level, conv, mech, key, n_eff, weight, mask) in items:
        bases = [b for b, _, _ in key]
        tsl = []
        for (variant, ctname, ptname) in CIPHERS:
            ctt, ptt = _TAB[ctname], _TAB[ptname]
            if variant == "vig":
                tsl.append([(ctt[ord(c) - 65] - ptt[ord(q) - 65]) % 26
                            for _, c, q in key])
            elif variant == "beau":
                tsl.append([(ctt[ord(c) - 65] + ptt[ord(q) - 65]) % 26
                            for _, c, q in key])
            else:
                tsl.append([(ptt[ord(q) - 65] - ctt[ord(c) - 65]) % 26
                            for _, c, q in key])
        a = agg[level]
        for period in PERIODS:
            cls = [b % period for b in bases]
            a["tested"] += weight * ncip
            if len(set(cls)) == len(cls):
                # every crib in its own key class -> ceiling == n_eff for EVERY
                # cipher.  The filter is vacuous here; nothing is eliminated.
                a["surv"] += weight * ncip
                if n_eff > a["maxc"]:
                    a["maxc"] = n_eff
                if len(surv[level]) < 3000:
                    surv[level].append((conv, mech, "ALL", "ALL", period,
                                        n_eff, n_eff, weight, mask))
                continue
            for ci, (variant, ctname, ptname) in enumerate(CIPHERS):
                cv = _ceiling_from(cls, tsl[ci])
                if cv > a["maxc"]:
                    a["maxc"] = cv
                if cv == n_eff:
                    a["surv"] += weight
                    if len(surv[level]) < 3000:
                        surv[level].append((conv, mech, variant, ctname,
                                            period, cv, n_eff, weight, mask))
    return ({k: dict(v) for k, v in agg.items()},
            {k: v for k, v in surv.items()})


# ─────────────────────────────── driver ───────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int,
                    default=max(1, len(os.sched_getaffinity(0)) - 2))
    ap.add_argument("--out", default=os.path.join(_ROOT, "results",
                                                  "null_mask_ceiling_sweep.json"))
    ap.add_argument("--quick", action="store_true",
                    help="skip F2 (largest family) for a fast smoke run")
    args = ap.parse_args()

    t0 = time.perf_counter()
    print(f"[{time.strftime('%H:%M:%S')}] enumerating structured mask families ...",
          flush=True)
    seen, fam_raw = build_masks()
    if args.quick:
        seen = {k: v for k, v in seen.items() if v[0] != "F2_tail_residue"}
    masks = list(seen)
    fam_uniq = defaultdict(int)
    for ns in masks:
        fam_uniq[seen[ns][0]] += 1
    print(f"  raw generated : {sum(fam_raw.values()):,}")
    print(f"  unique masks  : {len(masks):,}")
    for f in sorted(fam_uniq):
        print(f"    {f:<20} unique {fam_uniq[f]:>9,}  (raw {fam_raw.get(f,0):>9,})")
    print(f"  [{time.perf_counter()-t0:.1f}s]", flush=True)

    # ---- stage 1: structural filter + canonicalisation --------------------
    print(f"[{time.strftime('%H:%M:%S')}] stage 1: structural filter / "
          f"canonicalisation on {args.workers} workers ...", flush=True)
    chunks = []
    step = max(1, len(masks) // (args.workers * 8))
    for i in range(0, len(masks), step):
        chunks.append((i, i + step, masks[i:i + step]))
    canon: dict = defaultdict(int)
    canon_ex: dict = {}
    dead: dict = defaultdict(int)
    done = 0
    with ProcessPoolExecutor(max_workers=args.workers) as ex:
        for out, exm, dd in ex.map(_canon_chunk, chunks):
            for k, v in out.items():
                canon[k] += v
            for k, v in exm.items():
                canon_ex.setdefault(k, v)
            for k, v in dd.items():
                dead[k] += v
            done += 1
            if done % 20 == 0:
                print(f"    {done}/{len(chunks)} chunks "
                      f"[{time.perf_counter()-t0:.0f}s]", flush=True)
    n_struct_dead = sum(dead.values())
    n_alive = sum(canon.values())
    print(f"  mask x level x conv x mech tuples : {n_struct_dead + n_alive:,}")
    print(f"    structurally ELIMINATED         : {n_struct_dead:,}")
    print(f"    surviving to ceiling stage      : {n_alive:,}")
    print(f"    distinct canonical forms        : {len(canon):,}")
    print(f"  [{time.perf_counter()-t0:.1f}s]", flush=True)

    # ---- stage 2: ceiling sweep over periods x ciphers --------------------
    print(f"[{time.strftime('%H:%M:%S')}] stage 2: ceiling sweep "
          f"({len(PERIODS)} periods x {len(CIPHERS)} cipher configs) ...",
          flush=True)
    items = [(lv, cv, mc, key, n_eff, w, canon_ex[(lv, cv, mc, key, n_eff)])
             for (lv, cv, mc, key, n_eff), w in canon.items()]
    step2 = max(1, len(items) // (args.workers * 8))
    parts = [items[i:i + step2] for i in range(0, len(items), step2)]
    agg = defaultdict(lambda: {"tested": 0, "surv": 0, "maxc": -1})
    examples = defaultdict(list)
    done = 0
    with ProcessPoolExecutor(max_workers=args.workers) as ex:
        for a, ee in ex.map(_sweep_chunk, parts):
            for lv, d in a.items():
                t = agg[lv]
                t["tested"] += d["tested"]
                t["surv"] += d["surv"]
                t["maxc"] = max(t["maxc"], d["maxc"])
            for lv, lst in ee.items():
                if len(examples[lv]) < 3000:
                    examples[lv].extend(lst[:3000 - len(examples[lv])])
            done += 1
            if done % 20 == 0:
                print(f"    {done}/{len(parts)} chunks "
                      f"[{time.perf_counter()-t0:.0f}s]", flush=True)
    print(f"  [{time.perf_counter()-t0:.1f}s]", flush=True)

    # ---- fold structural eliminations into the per-level totals -----------
    ncfg = len(PERIODS) * len(CIPHERS)
    struct_by_level = defaultdict(int)
    for (lv, cv, mc, reason), w in dead.items():
        struct_by_level[lv] += w * ncfg
    reasons = defaultdict(int)
    for (lv, cv, mc, reason), w in dead.items():
        reasons[(lv, reason)] += w * ncfg

    print("\n" + "=" * 78)
    print("RESULT -- ceiling == n_cribs means NOT ELIMINATED, never 'solvable'")
    print("=" * 78)
    report = {}
    for lv in crib_sets.LEVELS:
        a = agg.get(lv, {"tested": 0, "surv": 0, "maxc": -1})
        tot = a["tested"] + struct_by_level[lv]
        n_lvl = len(LEVEL_DICTS[lv])
        report[lv] = {
            "n_cribs_level": n_lvl,
            "configs_tested": tot,
            "structurally_eliminated": struct_by_level[lv],
            "ceiling_stage_configs": a["tested"],
            "survivors": a["surv"],
            "max_ceiling": a["maxc"],
            "eliminated": tot - a["surv"],
            "survivor_examples": [
                {"convention": e[0], "mechanism": e[1], "variant": e[2],
                 "ct_alphabet": e[3], "period": e[4], "ceiling": e[5],
                 "n_eff": e[6], "masks_in_class": e[7],
                 "mask_family": seen[e[8]][0], "mask": seen[e[8]][1],
                 "n_nulls": bin(e[8]).count("1")}
                for e in examples.get(lv, [])[:40]],
        }
        print(f"\n{lv}  (n_cribs={n_lvl})")
        print(f"  configs tested          : {tot:,}")
        print(f"    structurally killed   : {struct_by_level[lv]:,}")
        print(f"    reached ceiling stage : {a['tested']:,}")
        print(f"  max ceiling attained    : {a['maxc']}")
        print(f"  NOT eliminated          : {a['surv']:,}")
        for (l2, r), w in sorted(reasons.items()):
            if l2 == lv:
                print(f"    structural reason: {r:<42} {w:,}")
        for e in examples.get(lv, [])[:8]:
            fam, lab = seen[e[8]]
            print(f"    survivor: conv={e[0]} mech={e[1]} var={e[2]} "
                  f"ct={e[3]} p={e[4]} ceil={e[5]}/{e[6]} "
                  f"nulls={bin(e[8]).count('1')} {fam}:{lab}")

    payload = {
        "script": os.path.abspath(__file__),
        "family": "null_mask_short_plaintext",
        "unique_masks": len(masks),
        "mask_families_unique": dict(fam_uniq),
        "periods": [PERIODS[0], PERIODS[-1]],
        "ciphers": [list(c) for c in CIPHERS],
        "mechanisms": list(MECHS),
        "conventions": list(CONVS),
        "by_level": report,
        "elapsed_s": time.perf_counter() - t0,
    }
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(payload, fh, indent=2, default=str)
    print(f"\nwrote {args.out}   [{time.perf_counter()-t0:.1f}s total]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
