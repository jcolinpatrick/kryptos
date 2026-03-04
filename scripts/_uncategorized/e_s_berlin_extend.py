#!/usr/bin/env python3 -u
"""
Cipher: uncategorized
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
e_s_berlin_extend.py — Bidirectional crib extension from BERLINCLOCK (pos 63-73).

STRATEGY
--------
For each cipher variant (Vigenère, Beaufort, Variant Beaufort):

  1. Display the exact 24-position keystream derived from both cribs.
  2. Verify Bean EQ/INEQ against the known keystream.
  3. Check which periods 1-26 are consistent with the 24 known key values.
  4. BEAM SEARCH (key-quality) — positions 74-96:
       At each position, try all 26 PT letters.  Compute implied key value.
       Score the running key text accumulated so far (treating the keystream as
       a running-key source document).  Keep top-B beams.
  5. BEAM SEARCH (pt-quality) — positions 74-96:
       Same, but score the PT fragment (not the key).
  6. BEAM SEARCH backward — positions 0-20.
  7. BEAM SEARCH between cribs — positions 34-62.
  8. CANDIDATE PHRASE TEST — try likely words/phrases immediately after BC
       and immediately before ENE.  Report implied key and its readability.
  9. Gronsfeld and Porta keystream analysis (structural variants).
 10. XOR analysis (treat CT as bytes mod 26, same arithmetic but labelled).

KEY QUESTION: Does the 23-position extension to the right (74-96) produce any
              PT fragment that scores above noise AND whose implied key looks
              like coherent text?

Output: results/e_s_berlin_extend.json  +  console report.
"""

import sys
import json
import math
import heapq
from pathlib import Path

sys.path.insert(0, 'src')

from kryptos.kernel.constants import (
    CT, CT_LEN, MOD, ALPH, ALPH_IDX,
    CRIB_DICT, CRIB_POSITIONS,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.constraints.bean import verify_bean
from kryptos.kernel.scoring.ngram import get_default_scorer

# ── Constants ──────────────────────────────────────────────────────────────

CT_VALS = [ALPH_IDX[c] for c in CT]

# ENE occupies positions 21-33; BC occupies 63-73.
ENE_START, ENE_WORD = 21, "EASTNORTHEAST"
BC_START,  BC_WORD  = 63, "BERLINCLOCK"

# Three regions we extend into
AFTER_BC   = list(range(74, 97))      # 23 positions
BEFORE_ENE = list(range(0, 21))       # 21 positions
BETWEEN    = list(range(34, 63))      # 29 positions

BEAM_WIDTH  = 100   # keep top-100 beams at each step
REPORT_TOP  =   5   # show top-5 in console


# ── Cipher variant definitions ─────────────────────────────────────────────

VARIANTS = {
    "Vigenere":    dict(
        key_fn  = lambda c, p: (c - p) % MOD,   # K = C - P
        pt_fn   = lambda c, k: (c - k) % MOD,   # P = C - K
        ks_ene  = VIGENERE_KEY_ENE,
        ks_bc   = VIGENERE_KEY_BC,
    ),
    "Beaufort":    dict(
        key_fn  = lambda c, p: (c + p) % MOD,   # K = C + P
        pt_fn   = lambda c, k: (k - c) % MOD,   # P = K - C
        ks_ene  = BEAUFORT_KEY_ENE,
        ks_bc   = BEAUFORT_KEY_BC,
    ),
    "VarBeaufort": dict(
        key_fn  = lambda c, p: (p - c) % MOD,   # K = P - C
        pt_fn   = lambda c, k: (c + k) % MOD,   # P = C + K
        # var-beaufort: key = P - C.  Negate Vigenere key.
        ks_ene  = tuple((-v) % MOD for v in VIGENERE_KEY_ENE),
        ks_bc   = tuple((-v) % MOD for v in VIGENERE_KEY_BC),
    ),
}


# ── Utility ────────────────────────────────────────────────────────────────

def ks_to_str(vals):
    return "".join(ALPH[v] for v in vals)

def int_to_letter(v):
    return ALPH[v % MOD]

def check_periods(ks_dict):
    """Return list of periods 1-26 that are consistent with the sparse keystream."""
    consistent = []
    for period in range(1, 27):
        residue = {}
        ok = True
        for pos, kv in ks_dict.items():
            r = pos % period
            if r in residue:
                if residue[r] != kv:
                    ok = False
                    break
            else:
                residue[r] = kv
        if ok:
            consistent.append(period)
    return consistent


def check_bean(ks_dict):
    """Check Bean EQ and INEQ against a sparse keystream dict."""
    eq_pass, eq_fail = [], []
    for i, j in BEAN_EQ:
        if i in ks_dict and j in ks_dict:
            if ks_dict[i] == ks_dict[j]:
                eq_pass.append((i, j))
            else:
                eq_fail.append((i, j, ks_dict[i], ks_dict[j]))

    ineq_pass, ineq_fail = [], []
    for i, j in BEAN_INEQ:
        if i in ks_dict and j in ks_dict:
            if ks_dict[i] != ks_dict[j]:
                ineq_pass.append((i, j))
            else:
                ineq_fail.append((i, j, ks_dict[i]))

    return dict(
        eq_pass=eq_pass, eq_fail=eq_fail,
        ineq_pass=ineq_pass, ineq_fail=ineq_fail,
        verdict="PASS" if not eq_fail and not ineq_fail else "FAIL",
    )


# ── Beam search ────────────────────────────────────────────────────────────

def beam_search(
    positions,          # list of CT positions to decode
    key_fn,             # (ct_val, pt_val) -> key_val
    pt_fn,              # (ct_val, key_val) -> pt_val  [unused here but kept]
    context_key_vals,   # list of int: known keystream leading into `positions`
    scorer,             # NgramScorer
    score_mode="key",   # "key" (score running-key text) or "pt" (score plaintext)
    beam_width=BEAM_WIDTH,
):
    """Beam-search best PT/key at given positions.

    Each beam state: (cumulative_score, pt_vals, key_vals)
    cumulative_score = ngram score of the last ≤20 chars of the scored sequence.
    """
    beam = [(0.0, [], [])]   # (score, pt_vals, key_vals)

    for pos in positions:
        cv = CT_VALS[pos]
        next_beam = []

        for (_, pt_vals, key_vals) in beam:
            for pt_idx in range(MOD):
                kv = key_fn(cv, pt_idx)
                new_pt  = pt_vals  + [pt_idx]
                new_key = key_vals + [kv]

                # Score: use last 20 chars of the relevant sequence
                if score_mode == "key":
                    seq = context_key_vals + new_key
                    window = seq[-20:]
                    text = ks_to_str(window)
                else:
                    seq = new_pt
                    window = seq[-20:]
                    text = ks_to_str(window)

                if len(text) >= 4:
                    sc = scorer.score_per_char(text)
                else:
                    sc = scorer._floor

                next_beam.append((sc, new_pt, new_key))

        # Keep top beam_width
        next_beam.sort(key=lambda x: x[0], reverse=True)
        beam = next_beam[:beam_width]

    return beam


# ── Candidate phrase test ───────────────────────────────────────────────────

# Thematically likely words/phrases immediately AFTER BERLINCLOCK (pos 74)
AFTER_BC_PHRASES = [
    # Clock-related
    "ISATFOUR",   "ATFOUR",  "ATFIVE",     "ATNOON",
    "MIDNIGHT",   "NOON",    "SHOWS",       "READS",
    "REMINDER",   "REMINDS",
    # Berlin Wall
    "THEWALL",    "FELL",    "FREEDOM",     "CHECKPOINT",
    "ISDOWN",     "WALL",    "BERLIN",
    # Narrative
    "BETWEEN",    "ALMOST",  "NORTHEAST",   "SHADOW",
    "LAYERS",     "BURIED",  "DISCOVERED",  "MESSAGE",
    "NINETYSEVEN",
    # Short fillers
    "IS", "AT", "OF", "THE", "AND", "IN", "IT",
]

# Thematically likely words/phrases immediately BEFORE EASTNORTHEAST (pos 0-20)
BEFORE_ENE_PHRASES = [
    "SLOWLY", "DESPARATLY", "DESPERATELY", "UNDERGROUND",
    "BETWEEN", "SHADOW", "THEREWAS", "VIRTUAL", "LAYERS",
    "INVISIBLY", "UNSEEN", "BENEATH", "ABSCISSA",
    "ITWAS",  "THISIS", "WITHIN",
]

def test_phrase_at_pos(phrase, start_pos, key_fn, scorer):
    """Place `phrase` at `start_pos` in CT; compute implied key; score it."""
    if start_pos + len(phrase) > CT_LEN:
        return None
    # Check no overlap with crib positions
    phrase_positions = set(range(start_pos, start_pos + len(phrase)))
    if phrase_positions & CRIB_POSITIONS:
        return None

    key_vals = []
    for i, ch in enumerate(phrase):
        pos = start_pos + i
        cv  = CT_VALS[pos]
        pv  = ALPH_IDX[ch]
        key_vals.append(key_fn(cv, pv))

    key_str = ks_to_str(key_vals)
    if len(key_str) >= 4:
        key_score = scorer.score_per_char(key_str)
    else:
        key_score = scorer._floor

    return dict(
        phrase=phrase,
        start=start_pos,
        key_fragment=key_str,
        key_score=round(key_score, 4),
    )


def test_all_positions(phrase, key_fn, scorer):
    """Try phrase at every valid non-crib position."""
    results = []
    for start_pos in range(CT_LEN - len(phrase) + 1):
        r = test_phrase_at_pos(phrase, start_pos, key_fn, scorer)
        if r is not None:
            results.append(r)
    if results:
        results.sort(key=lambda x: x["key_score"], reverse=True)
    return results


# ── Main analysis ──────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("e_s_berlin_extend.py — Bidirectional crib extension from BERLINCLOCK")
    print("=" * 70)

    scorer = get_default_scorer()
    print(f"[OK] NgramScorer loaded (floor={scorer._floor:.2f})")

    all_results = {}

    for vname, vdict in VARIANTS.items():
        key_fn = vdict["key_fn"]
        pt_fn  = vdict["pt_fn"]

        # ── 1. Known keystream ─────────────────────────────────────────────
        ks_ene_list = list(vdict["ks_ene"])
        ks_bc_list  = list(vdict["ks_bc"])
        ks_ene_str  = ks_to_str(ks_ene_list)
        ks_bc_str   = ks_to_str(ks_bc_list)

        # Build sparse dict indexed by CT position
        ks_dict = {}
        for i, kv in enumerate(ks_ene_list):
            ks_dict[ENE_START + i] = kv
        for i, kv in enumerate(ks_bc_list):
            ks_dict[BC_START + i] = kv

        print(f"\n{'='*60}")
        print(f"  Variant: {vname}")
        print(f"{'='*60}")
        print(f"  ENE keystream (pos 21-33): {ks_ene_str}")
        print(f"  BC  keystream (pos 63-73): {ks_bc_str}")
        print(f"  Combined 24-pos key (numeric): {list(ks_dict[p] for p in sorted(ks_dict))}")

        # ── 2. Bean check ──────────────────────────────────────────────────
        bean = check_bean(ks_dict)
        print(f"\n  Bean EQ  pass={len(bean['eq_pass'])}  fail={len(bean['eq_fail'])}")
        if bean["eq_fail"]:
            for i, j, ki, kj in bean["eq_fail"]:
                print(f"    EQ FAIL: k[{i}]={ALPH[ki]}({ki}) != k[{j}]={ALPH[kj]}({kj})")
        print(f"  Bean INEQ pass={len(bean['ineq_pass'])}  fail={len(bean['ineq_fail'])}")
        if bean["ineq_fail"]:
            for i, j, kv in bean["ineq_fail"]:
                print(f"    INEQ FAIL: k[{i}]=k[{j}]={ALPH[kv]}({kv})")
        print(f"  Bean verdict: {bean['verdict']}")

        # ── 3. Period consistency ──────────────────────────────────────────
        consistent_periods = check_periods(ks_dict)
        print(f"\n  Periods consistent with 24 keystream values: {consistent_periods}")

        # ── 4. First-difference analysis of BC keystream ──────────────────
        diffs_bc  = [(ks_bc_list[i+1] - ks_bc_list[i]) % MOD for i in range(len(ks_bc_list)-1)]
        diffs_ene = [(ks_ene_list[i+1] - ks_ene_list[i]) % MOD for i in range(len(ks_ene_list)-1)]
        print(f"\n  ENE first-diffs (mod 26): {diffs_ene}")
        print(f"  BC  first-diffs (mod 26): {diffs_bc}")

        # ── 5. Beam search AFTER BC (74-96, 23 positions) ─────────────────
        # Score mode: "key" — we want the keystream to look like natural text
        context_bc = ks_bc_list  # last 11 known key values before pos 74
        beam_after_key = beam_search(
            AFTER_BC, key_fn, pt_fn, context_bc, scorer,
            score_mode="key", beam_width=BEAM_WIDTH,
        )
        # Score mode: "pt" — we want the plaintext to look like English
        beam_after_pt = beam_search(
            AFTER_BC, key_fn, pt_fn, [], scorer,
            score_mode="pt", beam_width=BEAM_WIDTH,
        )

        print(f"\n  --- Beam search AFTER BERLINCLOCK (pos 74-96) ---")
        print(f"  [key-quality scoring] Top {REPORT_TOP} PT fragments:")
        for rank, (sc, pt_vals, key_vals) in enumerate(beam_after_key[:REPORT_TOP], 1):
            pt_str  = ks_to_str(pt_vals)
            key_str = ks_to_str(key_vals)
            print(f"    #{rank}: PT={pt_str}  KEY_TAIL={key_str}  score={sc:.4f}")

        print(f"\n  [pt-quality scoring] Top {REPORT_TOP} PT fragments:")
        for rank, (sc, pt_vals, key_vals) in enumerate(beam_after_pt[:REPORT_TOP], 1):
            pt_str  = ks_to_str(pt_vals)
            key_str = ks_to_str(key_vals)
            print(f"    #{rank}: PT={pt_str}  KEY={key_str}  score={sc:.4f}")

        # ── 6. Beam search BEFORE ENE (0-20, 21 positions) ────────────────
        # Context: approach ENE from the left
        # We work left-to-right but the beam "earns" score as we approach ENE
        context_ene = ks_ene_list  # use ENE keystream as right-context
        beam_before_pt = beam_search(
            BEFORE_ENE, key_fn, pt_fn, [], scorer,
            score_mode="pt", beam_width=BEAM_WIDTH,
        )
        print(f"\n  --- Beam search BEFORE EASTNORTHEAST (pos 0-20) ---")
        print(f"  [pt-quality] Top {REPORT_TOP}:")
        for rank, (sc, pt_vals, key_vals) in enumerate(beam_before_pt[:REPORT_TOP], 1):
            pt_str  = ks_to_str(pt_vals)
            key_str = ks_to_str(key_vals)
            print(f"    #{rank}: PT={pt_str}  KEY={key_str}  score={sc:.4f}")

        # ── 7. Beam search BETWEEN cribs (34-62, 29 positions) ────────────
        beam_between_pt = beam_search(
            BETWEEN, key_fn, pt_fn, [], scorer,
            score_mode="pt", beam_width=BEAM_WIDTH,
        )
        print(f"\n  --- Beam search BETWEEN cribs (pos 34-62) ---")
        print(f"  [pt-quality] Top {REPORT_TOP}:")
        for rank, (sc, pt_vals, key_vals) in enumerate(beam_between_pt[:REPORT_TOP], 1):
            pt_str  = ks_to_str(pt_vals)
            key_str = ks_to_str(key_vals)
            print(f"    #{rank}: PT={pt_str}  KEY={key_str}  score={sc:.4f}")

        # ── 8. Candidate phrase test ───────────────────────────────────────
        print(f"\n  --- Candidate phrase tests (best placement for each phrase) ---")
        phrase_results = {}
        for phrase in AFTER_BC_PHRASES + BEFORE_ENE_PHRASES:
            best = test_phrase_at_pos(phrase, 74, key_fn, scorer)  # start after BC
            if best is None:
                best = test_phrase_at_pos(phrase, 0, key_fn, scorer)  # fallback
            phrase_results[phrase] = best

        # Sort by key score
        ranked = sorted(
            [(p, r) for p, r in phrase_results.items() if r is not None],
            key=lambda x: x[1]["key_score"], reverse=True
        )
        print(f"  Top 10 candidate phrases by key readability at suggested position:")
        for phrase, r in ranked[:10]:
            print(f"    phrase={phrase:<20} pos={r['start']:2d}  key={r['key_fragment']}  "
                  f"key_score={r['key_score']:.4f}")

        # ── 8b. Sweep phrase at ALL non-crib positions ─────────────────────
        # For the top-5 after-BC phrases, find the global best placement
        print(f"\n  --- Top AFTER-BC phrases — global best placement sweep ---")
        after_bc_sweep = []
        for phrase in AFTER_BC_PHRASES:
            best_results = test_all_positions(phrase, key_fn, scorer)
            if best_results:
                after_bc_sweep.append((phrase, best_results[0]))

        after_bc_sweep.sort(key=lambda x: x[1]["key_score"], reverse=True)
        for phrase, r in after_bc_sweep[:10]:
            print(f"    phrase={phrase:<20} best_pos={r['start']:2d}  "
                  f"key={r['key_fragment']}  key_score={r['key_score']:.4f}")

        # ── 9. Keystream correlation between ENE and BC ────────────────────
        print(f"\n  --- Keystream correlation ENE vs BC ---")
        # Do the two 11-char overlap substrings have similar distributions?
        ene_set = set(ks_ene_list)
        bc_set  = set(ks_bc_list)
        shared  = ene_set & bc_set
        print(f"  ENE unique key values: {sorted(ene_set)}")
        print(f"  BC  unique key values: {sorted(bc_set)}")
        print(f"  Shared values: {sorted(shared)}")
        # If the key is periodic with period p, many values should be shared
        print(f"  Jaccard similarity: {len(shared) / len(ene_set | bc_set):.3f}")

        # ── 10. Gronsfeld keystream check ──────────────────────────────────
        # Gronsfeld uses digits 0-9 as key. Under Vigenère variant,
        # K values can only be in {0..9}. Check if our known keystream fits.
        gronsfeld_compat = all(v < 10 for v in ks_dict.values())
        print(f"\n  Gronsfeld compatibility (key ∈ {{0-9}}): {gronsfeld_compat}")
        if not gronsfeld_compat:
            oob = [(pos, v) for pos, v in ks_dict.items() if v >= 10]
            print(f"  Out-of-range: {oob[:5]}{'...' if len(oob)>5 else ''}")

        # ── Store results ──────────────────────────────────────────────────
        all_results[vname] = dict(
            ks_ene=ks_ene_str,
            ks_bc=ks_bc_str,
            bean=bean,
            consistent_periods=consistent_periods,
            diffs_ene=diffs_ene,
            diffs_bc=diffs_bc,
            gronsfeld_compat=gronsfeld_compat,
            beam_after_key_top5=[
                dict(score=round(sc, 4),
                     pt=ks_to_str(pv),
                     key=ks_to_str(kv))
                for sc, pv, kv in beam_after_key[:5]
            ],
            beam_after_pt_top5=[
                dict(score=round(sc, 4),
                     pt=ks_to_str(pv),
                     key=ks_to_str(kv))
                for sc, pv, kv in beam_after_pt[:5]
            ],
            beam_before_pt_top5=[
                dict(score=round(sc, 4),
                     pt=ks_to_str(pv),
                     key=ks_to_str(kv))
                for sc, pv, kv in beam_before_pt[:5]
            ],
            beam_between_pt_top5=[
                dict(score=round(sc, 4),
                     pt=ks_to_str(pv),
                     key=ks_to_str(kv))
                for sc, pv, kv in beam_between_pt[:5]
            ],
            phrase_top10=[
                dict(placement_pos=r["start"], phrase=p,
                     key_fragment=r["key_fragment"], key_score=r["key_score"])
                for p, r in ranked[:10]
            ],
            after_bc_sweep_top10=[
                dict(placement_pos=r["start"], phrase=p,
                     key_fragment=r["key_fragment"], key_score=r["key_score"])
                for p, r in after_bc_sweep[:10]
            ],
        )

    # ── Summary: compare best beam scores across variants ─────────────────
    print("\n" + "=" * 70)
    print("SUMMARY — Best beam scores across variants and regions")
    print("=" * 70)

    ENGLISH_FLOOR_PER_CHAR = -4.84   # Breakthrough threshold from CLAUDE.md
    RANDOM_FLOOR_PER_CHAR  = -5.8    # Approximate noise floor for quadgrams

    headers = ("Variant", "Region", "Mode", "Best score/char", "Best PT fragment")
    print(f"  {'Variant':<14} {'Region':<12} {'Mode':<8} {'Best/char':>10}  PT fragment")
    print(f"  {'-'*14} {'-'*12} {'-'*8} {'-'*10}  {'-'*25}")

    for vname, vres in all_results.items():
        rows = [
            (vname, "after_BC",  "key", vres["beam_after_key_top5"]),
            (vname, "after_BC",  "pt",  vres["beam_after_pt_top5"]),
            (vname, "before_ENE","pt",  vres["beam_before_pt_top5"]),
            (vname, "between",   "pt",  vres["beam_between_pt_top5"]),
        ]
        for vn, region, mode, beams in rows:
            if beams:
                best_sc = beams[0]["score"]
                best_pt = beams[0]["pt"]
                flag = " <<< SIGNAL" if best_sc > ENGLISH_FLOOR_PER_CHAR else ""
                print(f"  {vn:<14} {region:<12} {mode:<8} {best_sc:>10.4f}  {best_pt}{flag}")

    # ── Save JSON ──────────────────────────────────────────────────────────
    out_path = Path("results/e_s_berlin_extend.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n[SAVED] {out_path}")

    # ── Critical assessment ───────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("CRITICAL ASSESSMENT")
    print("=" * 70)
    print("""
INTERPRETATION GUIDE
--------------------
The beam search finds the BEST-CASE PT/key fragments assuming a running-key
additive cipher with NO transposition.

* If beam scores consistently hover near RANDOM_FLOOR_PER_CHAR (≈ -5.8):
  → The positions after/before/between cribs carry NO usable signal under
    the identity-transposition running-key model.
  → This is consistent with prior evidence: all 130M+ corpus chars fail.

* If beam scores exceed ENGLISH_FLOOR_PER_CHAR (> -4.84):
  → This is a candidate for further investigation, BUT note that a 23-char
    greedy beam starting from a free all-26 search WILL find something
    that looks like English by chance.  The key additional check is:
    does the 23-char extension ALSO satisfy Bean constraints when combined
    with the 24 known key positions?

* Gronsfeld compatibility: if the key values are all in {0..9}, the cipher
  could use a decimal digit key (Gronsfeld).  If not, Gronsfeld is eliminated.

* Porta: Porta produces symmetric pairs; we would need PT+K < 26 always.
  Check: max(K_val + PT_val) for known positions.

All three variants are algebraically equivalent for known-plaintext key
recovery; only the EXTENSION differs because it depends on the assumed
direction of the cipher operation.
""")


if __name__ == "__main__":
    main()
