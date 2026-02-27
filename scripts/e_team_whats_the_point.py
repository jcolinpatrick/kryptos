#!/usr/bin/env python3
"""E-TEAM-WHATS-THE-POINT: Test Sanborn's 2025 clue phrases as key material.

Sanborn's August 2025 open letter clue: "(CLUE) what's the point?
Power resides with a secret, not without it."

Also: "codes are about delivering a message"

Tests these phrases as:
1. Periodic Vigenere/Beaufort/VarBeau keys
2. Running keys (all 3 variants, identity transposition)
3. Columnar transposition keywords
4. Combined: columnar trans + periodic/running substitution
5. EAST constraint filter check

Special note: "WHATSTHEPOINT" = 13 chars = same as EASTNORTHEAST.
"""
import sys
import os
import json
import time
from itertools import permutations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, N_CRIBS,
    CRIB_DICT, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
)
from kryptos.kernel.transforms.transposition import (
    apply_perm, invert_perm, columnar_perm, keyword_to_order,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constraints.bean import verify_bean

# ── Configuration ──────────────────────────────────────────────────────

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
RESULTS_PATH = os.path.join(BASE_DIR, "results", "e_team_whats_the_point.json")

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

# EAST gap-9 diffs
EAST_DIFFS_VIG = [1, 25, 1, 23]
EAST_DIFFS_VARBEAU = [25, 1, 25, 3]

# ── Key phrases to test ───────────────────────────────────────────────

KEY_PHRASES = {
    # Primary clue phrases (Aug 2025)
    "WHATSTHEPOINT": "Sanborn clue phrase (13 chars = ENE length)",
    "POWERRESIDESWITHASECREETNOTWITHOUTIT": "Full clue phrase",
    "POWERRESIDESWITHASECREET": "Truncated clue",
    "POWERRESIDESWITHASECRETNOT": "Clue with NOT",
    "POWERRESIDESWITHA": "Clue fragment (17 chars)",
    "WHATSTHEPOINTPOWERRESIDESWITHASECREETNOTWITHOUTIT": "Full sentence combined",
    "WHATISTHEPOINT": "Alternate phrasing",
    "THEPOINTISTHEPOINT": "Variant",

    # Secondary phrases
    "CODESAREABOUTDELIVERINGAMESSAGE": "Sanborn 2025 clue #2",
    "DELIVERINGAMESSAGE": "Keyword from clue #2 (18 chars)",
    "SECRETPOWER": "Reversed concept",
    "POWERRESIDES": "Fragment",
    "POINTOFSECRET": "Derived phrase",
    "THESECRET": "Core concept",
    "NOTWITHOURIT": "Fragment",

    # K2 connection
    "ITSBURIEDOUTTHERESOMEWHERE": "K2/K5 connection",
    "BURIEDOUTTHERESOMEWHERE": "K2 variant",
    "WHOKNOWSTHEEXACTLOCATION": "K2 phrase",
    "ONLYWW": "K2 enigmatic ending",

    # Weltzeituhr (2025 revelation: BERLINCLOCK = Weltzeituhr)
    "WELTZEITUHR": "Berlin Clock in German (11 chars = BC length!)",
    "WORLDTIMECLOCK": "Weltzeituhr in English",
    "ALEXANDERPLATZ": "Weltzeituhr location (14 chars)",
    "BERLINALEXANDERPLATZ": "Full location",

    # "Who says it is even a math solution?" (Nov 2025)
    "WHOSAYSITISEVENAMATH": "Spy Museum quote fragment",
    "WHOSAYSITISEVENAMATHSOLUTION": "Full Spy Museum quote",
    "CREATIVITY": "Sanborn's counsel",
    "NOTAMATH": "Concept",
    "NOTAMATHSOLUTION": "Full concept",

    # Egypt trip 1986
    "EGYPT": "1986 Egypt trip",
    "PHARAOH": "Egyptian connection",
    "TUTANKHAMUN": "K3 connection (Tut's tomb)",
    "HOWARDCARTER": "K3 discoverer",
    "THEVALLEYOFTHEKINGS": "K3 location",
    "WONDERFULTHINGS": "Carter's famous reply (15 chars)",
    "CANYOUSEEANYTHINGQ": "K3 ending (18 chars)",

    # Meta / self-referential
    "KRYPTOS": "Sculpture name (7 chars)",
    "KRYPTOSABCDEFGHIJLMNQUVWXZ": "Full KA alphabet",
    "JIMSANBORN": "Artist name",
    "EDSHEIDT": "Cryptographer (alternate spelling)",
    "EDSCHEIDT": "Cryptographer",
    "WILLIAMWEBSTER": "CIA DCI during installation",
    "WEBSTER": "DCI surname",
    "NINTYSEVENDAYS": "Webster served 4 years + 97 days",
    "NINETYSEVEN": "K4 length as text",

    # Combinatorial: Weltzeituhr + Whatsthepoint
    "WHATSTHEPOINTWELTZEITUHR": "Combined clues",
    "WELTZEITUHRWHATSTHEPOINT": "Combined reversed",
    "POINTWELTZEITUHR": "Combined short",

    # Phrases with corrected spelling
    "POWERRESIDESWITHA SECRETNOTWITHOUTIT": "With space replaced",
}

# Clean: strip non-alpha
def clean(s):
    return "".join(c for c in s.upper() if c in ALPH)

KEY_PHRASES_CLEAN = {clean(k): v for k, v in KEY_PHRASES.items() if len(clean(k)) >= 3}


# ── Helper functions ───────────────────────────────────────────────────

def check_east_constraint(key_list):
    """Check EAST gap-9 diffs on the key."""
    if len(key_list) < 34:
        return False, False
    diffs = [(key_list[30+i] - key_list[21+i]) % MOD for i in range(4)]
    return (diffs == EAST_DIFFS_VIG), (diffs == EAST_DIFFS_VARBEAU)


def test_periodic_key(phrase, desc):
    """Test phrase as periodic Vigenere/Beaufort/VarBeau key."""
    results = []
    key_num = [ALPH_IDX[c] for c in phrase]
    period = len(phrase)

    # Extend key to CT_LEN for Bean check
    full_key = [key_num[i % period] for i in range(CT_LEN)]
    bean_result = verify_bean(full_key)
    east_vig, east_varbeau = check_east_constraint(full_key)

    for variant in VARIANTS:
        pt = decrypt_text(CT, key_num, variant)
        sc = score_candidate(pt, bean_result)

        results.append({
            "phrase": phrase,
            "desc": desc,
            "mode": "periodic",
            "period": period,
            "variant": variant.value,
            "crib_score": sc.crib_score,
            "bean_passed": sc.bean_passed,
            "ic": sc.ic_value,
            "classification": sc.crib_classification,
            "east_vig": east_vig,
            "east_varbeau": east_varbeau,
            "pt_snippet": pt[:50],
            "summary": sc.summary,
        })

    return results


def test_running_key(phrase, desc):
    """Test phrase as running key (must be >= 97 chars)."""
    if len(phrase) < CT_LEN:
        return []

    results = []
    key_str = phrase[:CT_LEN]
    key_num = [ALPH_IDX[c] for c in key_str]

    bean_result = verify_bean(key_num)
    east_vig, east_varbeau = check_east_constraint(key_num)

    for variant in VARIANTS:
        pt = decrypt_text(CT, key_num, variant)
        sc = score_candidate(pt, bean_result)

        results.append({
            "phrase": phrase[:30] + ("..." if len(phrase) > 30 else ""),
            "desc": desc,
            "mode": "running_key",
            "variant": variant.value,
            "crib_score": sc.crib_score,
            "bean_passed": sc.bean_passed,
            "ic": sc.ic_value,
            "classification": sc.crib_classification,
            "east_vig": east_vig,
            "east_varbeau": east_varbeau,
            "pt_snippet": pt[:50],
            "summary": sc.summary,
        })

    return results


def test_columnar_trans(phrase, desc, widths=range(5, 16)):
    """Test phrase as columnar transposition keyword, then Vig/Beau/VarBeau."""
    results = []

    for width in widths:
        if len(phrase) < width:
            continue

        col_order = keyword_to_order(phrase, width)
        if col_order is None:
            continue

        # Forward transposition
        perm = columnar_perm(width, col_order, CT_LEN)
        ct_trans = apply_perm(CT, perm)

        # Inverse transposition
        inv_perm = invert_perm(perm)
        ct_inv = apply_perm(CT, inv_perm)

        for ct_variant, trans_dir in [(ct_trans, "fwd"), (ct_inv, "inv")]:
            # Test the transposed CT directly as plaintext
            sc_direct = score_candidate(ct_variant)
            results.append({
                "phrase": phrase[:20],
                "desc": desc,
                "mode": f"columnar_trans_{trans_dir}",
                "width": width,
                "variant": "none",
                "crib_score": sc_direct.crib_score,
                "bean_passed": sc_direct.bean_passed,
                "ic": sc_direct.ic_value,
                "classification": sc_direct.crib_classification,
                "pt_snippet": ct_variant[:50],
                "summary": sc_direct.summary,
            })

            # Then also try each periodic key on the transposed CT
            for variant in VARIANTS:
                key_num = [ALPH_IDX[c] for c in phrase]
                pt = decrypt_text(ct_variant, key_num, variant)
                full_key = [key_num[i % len(key_num)] for i in range(CT_LEN)]
                bean_result = verify_bean(full_key)
                sc = score_candidate(pt, bean_result)

                if sc.crib_score >= 3:  # Only record interesting results
                    results.append({
                        "phrase": phrase[:20],
                        "desc": desc,
                        "mode": f"columnar_{trans_dir}+periodic",
                        "width": width,
                        "variant": variant.value,
                        "crib_score": sc.crib_score,
                        "bean_passed": sc.bean_passed,
                        "ic": sc.ic_value,
                        "classification": sc.crib_classification,
                        "pt_snippet": pt[:50],
                        "summary": sc.summary,
                    })

    return results


def test_combined_trans_running(phrase, running_phrase, desc, widths=range(7, 14)):
    """Columnar transposition (by phrase keyword) then running key decryption."""
    results = []
    if len(running_phrase) < CT_LEN:
        return results

    key_str = running_phrase[:CT_LEN]
    key_num = [ALPH_IDX[c] for c in key_str]

    for width in widths:
        if len(phrase) < width:
            continue

        col_order = keyword_to_order(phrase, width)
        if col_order is None:
            continue

        perm = columnar_perm(width, col_order, CT_LEN)
        inv_perm = invert_perm(perm)

        for perm_used, trans_dir in [(perm, "fwd"), (inv_perm, "inv")]:
            ct_trans = apply_perm(CT, perm_used)

            for variant in VARIANTS:
                pt = decrypt_text(ct_trans, key_num, variant)
                bean_result = verify_bean(key_num)
                sc = score_candidate(pt, bean_result)

                if sc.crib_score >= 3:
                    results.append({
                        "phrase": phrase[:20],
                        "running": running_phrase[:20] + "...",
                        "desc": desc,
                        "mode": f"columnar_{trans_dir}+running",
                        "width": width,
                        "variant": variant.value,
                        "crib_score": sc.crib_score,
                        "bean_passed": sc.bean_passed,
                        "ic": sc.ic_value,
                        "pt_snippet": pt[:50],
                        "summary": sc.summary,
                    })

    return results


def test_repeated_to_97(phrase, desc):
    """For short phrases, repeat to fill 97 chars and test as running key."""
    if len(phrase) >= CT_LEN:
        return test_running_key(phrase, desc)

    # Repeat phrase to >= 97 chars
    repeats = (CT_LEN // len(phrase)) + 1
    extended = (phrase * repeats)[:CT_LEN]
    return test_running_key(extended, f"{desc} (repeated to 97)")


# ── Main ───────────────────────────────────────────────────────────────

def main():
    t0 = time.time()

    print("=" * 70)
    print("E-TEAM-WHATS-THE-POINT: Sanborn 2025 Clue Phrases as Key Material")
    print("=" * 70)

    all_results = []
    total_tested = 0
    best_overall = {"crib_score": -1}
    east_matches = []

    def track(results):
        nonlocal total_tested, best_overall
        for r in results:
            total_tested += 1
            all_results.append(r)
            if r["crib_score"] > best_overall.get("crib_score", -1):
                best_overall = r
            if r.get("east_vig") or r.get("east_varbeau"):
                east_matches.append(r)

    # ── Phase 1: Periodic keys ─────────────────────────────────────────
    print(f"\n[Phase 1] Periodic keys ({len(KEY_PHRASES_CLEAN)} phrases)")
    for phrase, desc in sorted(KEY_PHRASES_CLEAN.items()):
        results = test_periodic_key(phrase, desc)
        track(results)
        best = max(results, key=lambda x: x["crib_score"])
        if best["crib_score"] >= 4 or best["bean_passed"]:
            print(f"  {phrase[:30]:30s} period={len(phrase):2d} "
                  f"best={best['crib_score']}/{N_CRIBS} "
                  f"bean={best['bean_passed']} "
                  f"variant={best['variant']}")

    # Special attention: WHATSTHEPOINT at period 13
    wtp = "WHATSTHEPOINT"
    print(f"\n  *** WHATSTHEPOINT (period 13 = ENE crib length) ***")
    wtp_results = [r for r in all_results if r.get("phrase") == wtp and r.get("mode") == "periodic"]
    for r in wtp_results:
        print(f"    {r['variant']:14s} score={r['crib_score']}/{N_CRIBS} "
              f"bean={r['bean_passed']} PT={r['pt_snippet'][:40]}")

    # WELTZEITUHR at period 11 = BC crib length
    wz = "WELTZEITUHR"
    print(f"\n  *** WELTZEITUHR (period 11 = BC crib length) ***")
    wz_results = [r for r in all_results if r.get("phrase") == wz and r.get("mode") == "periodic"]
    for r in wz_results:
        print(f"    {r['variant']:14s} score={r['crib_score']}/{N_CRIBS} "
              f"bean={r['bean_passed']} PT={r['pt_snippet'][:40]}")

    print(f"\n  Phase 1 total: {total_tested} configs tested")

    # ── Phase 2: Running keys (phrases >= 97 chars, or repeated) ───────
    print(f"\n[Phase 2] Running keys + repeated phrases")
    count_before = total_tested
    for phrase, desc in sorted(KEY_PHRASES_CLEAN.items()):
        if len(phrase) >= CT_LEN:
            results = test_running_key(phrase, desc)
        else:
            results = test_repeated_to_97(phrase, desc)
        track(results)
        best = max(results, key=lambda x: x["crib_score"]) if results else None
        if best and (best["crib_score"] >= 4 or best.get("bean_passed")):
            print(f"  {phrase[:30]:30s} len={len(phrase):2d} "
                  f"best={best['crib_score']}/{N_CRIBS} "
                  f"bean={best.get('bean_passed')}")
    print(f"  Phase 2: {total_tested - count_before} configs")

    # ── Phase 3: Columnar transposition ────────────────────────────────
    print(f"\n[Phase 3] Columnar transposition (widths 5-15)")
    count_before = total_tested
    for phrase, desc in sorted(KEY_PHRASES_CLEAN.items()):
        if len(phrase) < 5:
            continue
        results = test_columnar_trans(phrase, desc)
        track(results)
        if results:
            best = max(results, key=lambda x: x["crib_score"])
            if best["crib_score"] >= 4:
                print(f"  {phrase[:25]:25s} w={best.get('width','')} "
                      f"score={best['crib_score']}/{N_CRIBS} "
                      f"mode={best['mode']}")
    print(f"  Phase 3: {total_tested - count_before} configs")

    # ── Phase 4: Combined — columnar trans + running key ───────────────
    print(f"\n[Phase 4] Columnar trans + running key combos")
    count_before = total_tested

    # Try key combos: use one phrase for transposition, another for running key
    long_phrases = {k: v for k, v in KEY_PHRASES_CLEAN.items() if len(k) >= CT_LEN}
    trans_phrases = {k: v for k, v in KEY_PHRASES_CLEAN.items() if 7 <= len(k) <= 15}

    for t_phrase, t_desc in sorted(trans_phrases.items()):
        for r_phrase, r_desc in sorted(long_phrases.items()):
            results = test_combined_trans_running(
                t_phrase, r_phrase,
                f"trans={t_desc}, run={r_desc}",
            )
            track(results)
            if results:
                best = max(results, key=lambda x: x["crib_score"])
                if best["crib_score"] >= 5:
                    print(f"  trans={t_phrase[:15]} + run={r_phrase[:15]}... "
                          f"score={best['crib_score']}/{N_CRIBS}")

    # Also: use one phrase for BOTH trans keyword and periodic key
    for phrase, desc in sorted(KEY_PHRASES_CLEAN.items()):
        if len(phrase) < 7:
            continue
        # Phrase as trans keyword, same phrase repeated as running key
        extended = (phrase * ((CT_LEN // len(phrase)) + 1))[:CT_LEN]
        results = test_combined_trans_running(
            phrase, extended,
            f"self-keyed trans+run: {desc}",
            widths=range(7, min(len(phrase) + 1, 16)),
        )
        track(results)

    print(f"  Phase 4: {total_tested - count_before} configs")

    # ── Phase 5: Concatenation combos ──────────────────────────────────
    print(f"\n[Phase 5] Concatenated phrase combinations as running key")
    count_before = total_tested

    # Try pairs of short phrases concatenated
    important_phrases = [
        "WHATSTHEPOINT",
        "WELTZEITUHR",
        "KRYPTOS",
        "EASTNORTHEAST",
        "BERLINCLOCK",
        "WONDERFULTHINGS",
        "CREATIVITY",
        "EGYPT",
        "HOWARDCARTER",
        "SECRETPOWER",
        "DELIVERINGAMESSAGE",
        "CANYOUSEEANYTHINGQ",
        "WILLIAMWEBSTER",
        "JIMSANBORN",
        "EDSCHEIDT",
        "NINETYSEVEN",
    ]

    for i, p1 in enumerate(important_phrases):
        for p2 in important_phrases[i:]:
            for order in [(p1, p2), (p2, p1)]:
                combined = order[0] + order[1]
                if len(combined) < CT_LEN:
                    # Pad with repeat
                    combined = (combined * ((CT_LEN // len(combined)) + 1))[:CT_LEN]

                key_num = [ALPH_IDX[c] for c in combined[:CT_LEN]]
                bean_result = verify_bean(key_num)

                for variant in VARIANTS:
                    pt = decrypt_text(CT, key_num, variant)
                    sc = score_candidate(pt, bean_result)
                    total_tested += 1

                    if sc.crib_score >= 4 or sc.bean_passed:
                        r = {
                            "phrase": f"{order[0]}+{order[1]}",
                            "desc": "concatenated pair",
                            "mode": "concat_running",
                            "variant": variant.value,
                            "crib_score": sc.crib_score,
                            "bean_passed": sc.bean_passed,
                            "ic": sc.ic_value,
                            "pt_snippet": pt[:50],
                            "summary": sc.summary,
                        }
                        all_results.append(r)
                        if sc.crib_score > best_overall.get("crib_score", -1):
                            best_overall = r
                        print(f"  {order[0][:12]}+{order[1][:12]} "
                              f"score={sc.crib_score}/{N_CRIBS} "
                              f"bean={sc.bean_passed} {variant.value}")

    print(f"  Phase 5: {total_tested - count_before} configs")

    # ── Summary ────────────────────────────────────────────────────────
    elapsed = time.time() - t0

    print("\n" + "=" * 70)
    print("FINAL SUMMARY — E-TEAM-WHATS-THE-POINT")
    print("=" * 70)
    print(f"Total configurations tested: {total_tested}")
    print(f"Total results recorded:      {len(all_results)}")
    print(f"EAST constraint matches:     {len(east_matches)}")
    print(f"Elapsed:                     {elapsed:.1f}s")

    if best_overall.get("crib_score", -1) >= 0:
        print(f"\nBest score: {best_overall['crib_score']}/{N_CRIBS}")
        print(f"  Phrase:   {best_overall.get('phrase', '?')}")
        print(f"  Desc:     {best_overall.get('desc', '?')}")
        print(f"  Mode:     {best_overall.get('mode', '?')}")
        print(f"  Variant:  {best_overall.get('variant', '?')}")
        print(f"  Bean:     {best_overall.get('bean_passed', '?')}")
        print(f"  PT:       {best_overall.get('pt_snippet', '?')}")

    if east_matches:
        print(f"\nEAST constraint matches ({len(east_matches)}):")
        for em in east_matches[:10]:
            print(f"  {em.get('phrase','')[:25]} mode={em.get('mode','')} "
                  f"score={em['crib_score']} bean={em.get('bean_passed','')} "
                  f"vig={em.get('east_vig','')} varbeau={em.get('east_varbeau','')}")

    # Score distribution
    score_dist = {}
    for r in all_results:
        s = r["crib_score"]
        score_dist[s] = score_dist.get(s, 0) + 1
    if score_dist:
        print(f"\nScore distribution: {dict(sorted(score_dist.items()))}")

    # Verdict
    max_score = best_overall.get("crib_score", 0)
    if max_score >= 18:
        verdict = "SIGNAL"
    elif max_score >= 10:
        verdict = "INTERESTING"
    else:
        verdict = "NOISE"

    print(f"\nVERDICT: {verdict}")

    # ── Write results ──────────────────────────────────────────────────
    output = {
        "experiment": "E-TEAM-WHATS-THE-POINT",
        "description": "Sanborn 2025 clue phrases as key material (periodic, running, columnar, combined)",
        "total_tested": total_tested,
        "total_recorded": len(all_results),
        "east_matches_count": len(east_matches),
        "elapsed_seconds": round(elapsed, 1),
        "verdict": verdict,
        "best_result": best_overall if best_overall.get("crib_score", -1) >= 0 else None,
        "east_matches": east_matches[:20],
        "score_distribution": dict(sorted(score_dist.items())) if score_dist else {},
        "top_results": sorted(all_results, key=lambda x: x["crib_score"], reverse=True)[:50],
        "phrases_tested": list(KEY_PHRASES_CLEAN.keys()),
        "phases": [
            "periodic (all phrases × 3 variants)",
            "running_key (extended/repeated × 3 variants)",
            "columnar_trans (widths 5-15 × fwd/inv × direct + periodic)",
            "columnar_trans + running_key combos",
            "concatenated phrase pairs",
        ],
    }

    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults written to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
