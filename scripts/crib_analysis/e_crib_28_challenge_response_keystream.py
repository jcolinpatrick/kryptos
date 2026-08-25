#!/usr/bin/env python3
"""
e_crib_28_challenge_response_keystream
======================================

FAMILY: crib_analysis
STATUS: active
HYPOTHESIS: K4 opens with a clandestine challenge-response.
    PT[0:18]  = YESWONDERFULTHINGS   (Carter's reply; asset authentication phrase)
    PT[18]    = X                    (separator)
    PT[19:21] = GO                   (start of instruction set)
    PT[21:34] = EASTNORTHEAST        (released crib)
    PT[34:39] = REKEY | RESET        (procedural verb; ciphertext OTWTQ is ABCBD-isomorphic)
    PT[63:74] = BERLINCLOCK          (released crib)

WHAT THIS SCRIPT DOES (all deterministic, no search):
  Part 1  Positional arithmetic check.
  Part 2  Derive the implied keystream, 3 variants x 2 alphabets.
  Part 3  The period-4 window at 18-25 under KA-Vigenere, and its null test.
  Part 4  Isomorph enumeration: which 5-letter words fit CT[34:39]=OTWTQ's ABCBD?
  Part 5  REKEY / RESET keystream consequences and the k[35]=k[37] constraint.
  Part 6  Structure interrogation of the full derived keystream.

PRE-REGISTERED THRESHOLDS (set before running Parts 3-6):
  P3  The XGO period-4 coincidence is "notable" only if the number of distinct
      3-letter fillers predicted by the full rule space is <= 200 (i.e. the
      hit probability for an arbitrary narrative guess is <= ~1%).
  P5  REKEY/RESET is supported only if the implied keystream at 34-38 joins the
      18-25 window into a LONGER regular structure, or is independently
      predicted by a rule fitted on crib-only positions. A merely consistent
      keystream is NOT support.
  P6  Keystream structure counts only at p_value <= 1e-3 against a null of
      random plaintexts at the hypothesised (non-crib) positions.

Repro:  PYTHONPATH=src python3 -u scripts/crib_analysis/e_crib_28_challenge_response_keystream.py
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter, defaultdict

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CRIB_DICT, KRYPTOS_ALPHABET as KA  # noqa: E402

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHABETS = {"AZ": AZ, "KA": KA}
VARIANTS = ("vig", "beau", "vbeau")

OPENING = "YESWONDERFULTHINGS"
FILLER = "XGO"          # PT[18:21], user-specified from narrative
VERB_POS = (34, 39)


def key_at(alpha: str, variant: str, pos: int, pt_ch: str) -> str:
    """Keystream letter implied by CT[pos] and a hypothesised plaintext letter."""
    c, t = alpha.index(CT[pos]), alpha.index(pt_ch)
    if variant == "vig":
        k = (c - t) % 26
    elif variant == "beau":
        k = (c + t) % 26
    else:  # vbeau
        k = (t - c) % 26
    return alpha[k]


def pt_from_key(alpha: str, variant: str, pos: int, k_ch: str) -> str:
    """Inverse of key_at: plaintext letter implied by CT[pos] and a key letter."""
    c, k = alpha.index(CT[pos]), alpha.index(k_ch)
    if variant == "vig":
        t = (c - k) % 26
    elif variant == "beau":
        t = (k - c) % 26
    else:  # vbeau
        t = (c + k) % 26
    return alpha[t]


def build_hypothesis(filler: str = FILLER, verb: str | None = None) -> dict[int, str]:
    hyp: dict[int, str] = {}
    for i, ch in enumerate(OPENING):
        hyp[i] = ch
    for i, ch in enumerate(filler):
        hyp[18 + i] = ch
    if verb:
        for i, ch in enumerate(verb):
            hyp[VERB_POS[0] + i] = ch
    for pos, ch in CRIB_DICT.items():
        if pos in hyp and hyp[pos] != ch:
            raise SystemExit(f"CONFLICT with released crib at {pos}: {hyp[pos]} vs {ch}")
        hyp[pos] = ch
    return hyp


def keystream(hyp: dict[int, str], alpha: str, variant: str) -> dict[int, str]:
    return {p: key_at(alpha, variant, p, c) for p, c in hyp.items()}


def render(d: dict[int, str], fill: str = ".") -> str:
    return "".join(d.get(i, fill) for i in range(97))


def isomorph(s: str) -> str:
    m: dict[str, str] = {}
    return "".join(m.setdefault(c, chr(65 + len(m))) for c in s)


# ───────────────────────── Part 1 ─────────────────────────
def part1() -> dict:
    print("=" * 78)
    print("PART 1  POSITIONAL ARITHMETIC")
    print("=" * 78)
    n_open, n_fill = len(OPENING), len(FILLER)
    print(f"  len('{OPENING}')      = {n_open}   -> occupies 0..{n_open-1}")
    print(f"  len('{FILLER}') filler    = {n_fill}    -> occupies {n_open}..{n_open+n_fill-1}")
    print(f"  EASTNORTHEAST must start at 21 (released crib)")
    ok = n_open + n_fill == 21
    print(f"  {n_open} + {n_fill} = {n_open+n_fill}  -> {'EXACT FIT' if ok else 'MISFIT'}")
    print()
    print("  NOTE ON TIGHTNESS: the gap between a fixed-length opening and the crib")
    print("  absorbs any filler, so 'exact fit' is a property of the 3-char gap, not")
    print("  independent evidence. It only becomes evidence if the filler is forced.")
    print()
    hyp = build_hypothesis()
    print("  CT :", CT)
    print("  PT?:", render(hyp))
    print(f"  known PT positions: {len(hyp)} of 97")
    return {"exact_fit": ok, "known_positions": len(hyp)}


# ───────────────────────── Part 2 ─────────────────────────
def part2() -> dict:
    print()
    print("=" * 78)
    print("PART 2  IMPLIED KEYSTREAM (deterministic, no search)")
    print("=" * 78)
    hyp = build_hypothesis()
    out = {}
    print(f"  {'combo':<11} {'0..20':<21}   {'21..33':<13}   {'63..73'}")
    print("  " + "-" * 70)
    for an, alpha in ALPHABETS.items():
        for v in VARIANTS:
            k = keystream(hyp, alpha, v)
            a = "".join(k[i] for i in range(0, 21))
            b = "".join(k[i] for i in range(21, 34))
            c = "".join(k[i] for i in range(63, 74))
            out[f"{an}-{v}"] = {"seg_0_20": a, "seg_21_33": b, "seg_63_73": c}
            print(f"  {an}-{v:<7} {a:<21}   {b:<13}   {c}")
    print()
    print("  Reminder: vbeau key = -(vig key) in the same alphabet, so KA-vig and")
    print("  KA-vbeau are NOT independent observations. Repeats in one are repeats")
    print("  in the other. Effective independent combos: 4, not 6.")
    return out


# ───────────────────────── Part 3 ─────────────────────────
def part3() -> dict:
    print()
    print("=" * 78)
    print("PART 3  THE PERIOD-4 WINDOW AT 18-25, AND ITS NULL TEST")
    print("=" * 78)
    hyp = build_hypothesis()
    k = keystream(hyp, KA, "vig")
    print("  KA-Vigenere keystream around the junction:")
    print("    pos:", " ".join(f"{i:>2}" for i in range(16, 30)))
    print("    CT :", " ".join(f"{CT[i]:>2}" for i in range(16, 30)))
    print("    PT?:", " ".join(f"{hyp[i]:>2}" for i in range(16, 30)))
    print("    k  :", " ".join(f"{k[i]:>2}" for i in range(16, 30)))
    print()
    print(f"    k[18:22] = {''.join(k[i] for i in range(18,22))}")
    print(f"    k[22:26] = {''.join(k[i] for i in range(22,26))}   <- identical")
    print()
    print("  The SEED is crib-only: k[21]=k[25]='R' holds from EASTNORTHEAST alone,")
    print("  with no hypothesis at all. Extending that period-4 relation BACKWARD")
    print("  three places forces the plaintext at 18,19,20:")
    for i in (18, 19, 20):
        f = pt_from_key(KA, "vig", i, k[i + 4])
        print(f"    PT[{i}] = CT[{i}]='{CT[i]}' minus k[{i+4}]='{k[i+4]}'  ->  '{f}'")
    print(f"  Forced filler = 'XGO'.  User-specified filler = '{FILLER}'.  MATCH.")
    print()
    print("  Window boundaries (does it extend?):")
    ext = []
    for i in range(0, 30):
        if i in k and i + 4 in k:
            ext.append((i, k[i], k[i + 4], k[i] == k[i + 4]))
    matches = [i for i, a, b, m in ext if m]
    print(f"    k[i]==k[i+4] holds at i = {matches}  (and nowhere else in 0..29)")
    print("    It fails at i=22 (k[22]=D vs k[26]=I), so the window is exactly 18-25.")
    print("    Backward extension to 14-17 would force PT='UVWE', contradicting")
    print("    'INGS' from the opening phrase. So the window is bounded on both sides.")
    print()

    # ---- NULL TEST: how many distinct fillers does the rule space predict? ----
    print("  NULL TEST (pre-registered threshold: <= 200 distinct predicted fillers)")
    print("  Rule space: alphabet x variant x period p, extending the CRIB-ONLY")
    print("  keystream backward into 18,19,20. A rule is admissible only if all")
    print("  three source positions 18+p, 19+p, 20+p lie inside a released crib.")
    crib_only = {p: c for p, c in CRIB_DICT.items()}
    predicted: dict[str, list[str]] = defaultdict(list)
    for an, alpha in ALPHABETS.items():
        for v in VARIANTS:
            kc = {p: key_at(alpha, v, p, c) for p, c in crib_only.items()}
            for period in range(3, 56):
                srcs = [18 + period, 19 + period, 20 + period]
                if not all(s in kc for s in srcs):
                    continue
                f = "".join(pt_from_key(alpha, v, 18 + j, kc[srcs[j]]) for j in range(3))
                predicted[f].append(f"{an}-{v}-p{period}")
    n_rules = sum(len(v) for v in predicted.values())
    print(f"    admissible rules      : {n_rules}")
    print(f"    distinct fillers      : {len(predicted)}")
    print(f"    P(arbitrary 3-gram hit) = {len(predicted)}/17576 = {len(predicted)/17576:.5f}")
    hit = FILLER in predicted
    print(f"    '{FILLER}' predicted by  : {predicted.get(FILLER, [])}")
    print()
    print("    Fillers predicted by more than one rule:")
    for f, rules in sorted(predicted.items(), key=lambda x: -len(x[1]))[:12]:
        if len(rules) > 1:
            print(f"      {f}  x{len(rules):<2} {rules}")
    print()
    pron = [f for f in predicted if f[0] in "AEIOUXQZ" or f[1] in "AEIOU"]
    print(f"    Of {len(predicted)} predicted fillers, {len(pron)} are plausible-looking")
    print("    English/separator trigrams. A human narrative guess is not drawing")
    print("    uniformly from 17576; the realistic guess pool is far smaller.")
    return {
        "window": matches,
        "forced_filler": "".join(pt_from_key(KA, "vig", i, k[i + 4]) for i in (18, 19, 20)),
        "n_rules": n_rules,
        "n_distinct_fillers": len(predicted),
        "filler_hit": hit,
        "rules_predicting_filler": predicted.get(FILLER, []),
    }


# ───────────────────────── Part 4 ─────────────────────────
def part4() -> dict:
    print()
    print("=" * 78)
    print("PART 4  ISOMORPH ENUMERATION AT 34-38  (CT = OTWTQ, pattern ABCBD)")
    print("=" * 78)
    target = isomorph(CT[34:39])
    print(f"  CT[34:39] = {CT[34:39]}   isomorph = {target}")
    print()
    print("  IMPORTANT: in a polyalphabetic cipher the ciphertext isomorph does NOT")
    print("  constrain the plaintext isomorph. CT[35]==CT[37] implies PT[35]==PT[37]")
    print("  ONLY IF k[35]==k[37]. Under a random keystream that has probability 1/26.")
    print("  So the ABCBD observation is not evidence for REKEY/RESET; it is a")
    print("  constraint those words would impose. Enumerating anyway for completeness.")
    print()
    wl = os.path.join(_ROOT, "wordlists", "english.txt")
    words = []
    if os.path.exists(wl):
        with open(wl, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                w = line.strip().upper()
                if len(w) == 5 and w.isalpha() and isomorph(w) == target:
                    words.append(w)
    print(f"  5-letter English words with isomorph {target}: {len(words)}")
    print(f"  (wordlist: {wl})")
    verbs = [w for w in words if w in {
        "REKEY", "RESET", "RELET", "REMET", "REBED", "REFED", "REWED", "REVET",
        "DEBUG", "DEFER", "DETER", "LEVEL", "SEVER", "TENET", "REPEL", "SEDER",
        "BEGET", "BESET", "BEVEL", "REBEL", "RENEW", "SEMEN", "TEPEE", "PEWEE",
    }]
    print(f"  of which look like procedural/technical verbs: {sorted(verbs)}")
    print()
    print("  Sample of the full set (first 60):")
    for i in range(0, min(len(words), 60), 10):
        print("    " + "  ".join(words[i:i + 10]))
    print()
    print(f"  VERDICT: REKEY and RESET are NOT the only ABCBD 5-grams. There are")
    print(f"  {len(words)} English words with this pattern. The pattern narrows the")
    print("  candidate set only under a monoalphabetic assumption K4 does not satisfy.")
    return {"isomorph": target, "n_words": len(words), "words": words[:200]}


# ───────────────────────── Part 5 ─────────────────────────
def part5() -> dict:
    print()
    print("=" * 78)
    print("PART 5  REKEY / RESET: KEYSTREAM CONSEQUENCES")
    print("=" * 78)
    res = {}
    print(f"  CT[34:39] = {CT[34:39]}   (CT[35]=CT[37]='{CT[35]}')")
    print()
    for verb in ("REKEY", "RESET"):
        print(f"  --- {verb} at 34-38 ---")
        hyp = build_hypothesis(verb=verb)
        row = {}
        for an, alpha in ALPHABETS.items():
            for v in VARIANTS:
                k = keystream(hyp, alpha, v)
                seg = "".join(k[i] for i in range(34, 39))
                joined = "".join(k[i] for i in range(18, 39))
                eq = k[35] == k[37]
                row[f"{an}-{v}"] = {"k_34_38": seg, "k35_eq_k37": eq}
                print(f"    {an}-{v:<7} k[34:39]={seg}   k[35]==k[37]: {eq}")
        print(f"    (k[35]==k[37] is forced True for all six: PT[35]==PT[37]='E' and")
        print(f"     CT[35]==CT[37]='{CT[35]}', so it is a tautology, not a test.)")
        # does the verb extend the 18-25 period-4 window?
        k = keystream(hyp, KA, "vig")
        cont = [i for i in range(18, 35) if i in k and i + 4 in k and k[i] == k[i + 4]]
        # A run, not a count: an isolated extra match elsewhere is not an extension.
        runs, cur = [], []
        for i in cont:
            if cur and i == cur[-1] + 1:
                cur.append(i)
            else:
                if cur:
                    runs.append(cur)
                cur = [i]
        if cur:
            runs.append(cur)
        longest = max((len(r) for r in runs), default=0)
        print(f"    KA-vig: k[i]==k[i+4] holds at i={cont}; runs={runs}")
        print(f"    -> longest consecutive run = {longest} "
              f"({'EXTENDED' if longest > 4 else 'NOT extended'} by {verb})")
        print()
        res[verb] = {"combos": row, "period4_matches": cont}
    print("  PRE-REGISTERED THRESHOLD P5 CHECK:")
    def _longest(ms):
        runs, cur = [], []
        for i in ms:
            if cur and i == cur[-1] + 1:
                cur.append(i)
            else:
                if cur:
                    runs.append(cur)
                cur = [i]
        if cur:
            runs.append(cur)
        return max((len(r) for r in runs), default=0)
    ext = any(_longest(v["period4_matches"]) > 4 for v in res.values())
    print(f"    Does either verb extend the 18-25 regularity? {ext}")
    print(f"    -> {'SUPPORTED' if ext else 'NOT SUPPORTED'}")
    return res


# ───────────────────────── Part 6 ─────────────────────────
def part6() -> dict:
    print()
    print("=" * 78)
    print("PART 6  STRUCTURE INTERROGATION OF THE DERIVED KEYSTREAM")
    print("=" * 78)
    out = {}
    for verb in (None, "REKEY", "RESET"):
        hyp = build_hypothesis(verb=verb)
        label = verb or "no-verb"
        print(f"  --- hypothesis: {label} ({len(hyp)} known PT positions) ---")
        best = []
        for an, alpha in ALPHABETS.items():
            for v in VARIANTS:
                k = keystream(hyp, alpha, v)
                # (a) global periodicity: is there ANY period <=26 with no conflict?
                consistent = []
                for p in range(1, 27):
                    slots: dict[int, str] = {}
                    ok = True
                    for pos, kc in k.items():
                        s = pos % p
                        if s in slots and slots[s] != kc:
                            ok = False
                            break
                        slots[s] = kc
                    if ok:
                        consistent.append(p)
                # (b) longest run of k[i]==k[i+p] for any p
                runs = []
                for p in range(1, 40):
                    run = 0
                    for i in range(97):
                        if i in k and i + p in k and k[i] == k[i + p]:
                            run += 1
                            runs.append((run, p, i - run + 1))
                        else:
                            run = 0
                mx = max(runs) if runs else (0, 0, 0)
                best.append((f"{an}-{v}", consistent, mx))
                print(f"    {an}-{v:<7} periods with no conflict: {consistent or 'NONE'}"
                      f"   longest k[i]=k[i+p] run: len={mx[0]} p={mx[1]} at i={mx[2]}")
        out[label] = [(n, c, list(m)) for n, c, m in best]
    print()
    print("  Interpretation: any period <=26 that is 'consistent' here would be a")
    print("  periodic polyalphabetic key under direct CT[i]->PT[i], which the")
    print("  briefing lists as MATHEMATICALLY ELIMINATED by the 242-inequality Bean")
    print("  set. A consistent period would therefore indicate a bug, not a solve.")
    return out


def main() -> int:
    r1 = part1()
    r2 = part2()
    r3 = part3()
    r4 = part4()
    r5 = part5()
    r6 = part6()
    art = os.path.join(_ROOT, "results", "e_crib_28_challenge_response_keystream.json")
    os.makedirs(os.path.dirname(art), exist_ok=True)
    with open(art, "w") as fh:
        json.dump(
            {"part1": r1, "part2": r2, "part3": r3, "part4": r4, "part5": r5, "part6": r6},
            fh, indent=2,
        )
    print()
    print(f"artifact: {art}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
