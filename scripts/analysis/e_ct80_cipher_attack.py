#!/usr/bin/env python3
"""
E-CT80-CIPHER-ATTACK: Cipher attacks on CT80 (97 chars minus 17 consensus nulls)

Hypothesis: K4 has exactly 17 nulls (not 24), giving an 80-character ciphertext.
After null removal, crib positions shift, so we use score_candidate_free
(free-position crib search).

Tests:
  1. Periodic Beaufort/Vigenere/VarBeau with 22 thematic keywords
  2. All 26 single-letter keys x 3 variants
  3. Col7 untranspose on CT80 then periodic keywords
  4. Running key from K1/K2/K3 plaintext
  5. Scoring with score_candidate_free (threshold >= 6)

Family: analysis
Status: active
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

import sys
import os
import json
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD, CONSENSUS_NULL_POSITIONS, KRYPTOS_ALPHABET,
)
from kryptos.kernel.scoring.aggregate import score_candidate_free

# ---------------------------------------------------------------------------
# Build CT80
# ---------------------------------------------------------------------------
NULL_POS = sorted(CONSENSUS_NULL_POSITIONS)
CT80 = "".join(CT[i] for i in range(CT_LEN) if i not in CONSENSUS_NULL_POSITIONS)
assert len(CT80) == 80, f"Expected 80, got {len(CT80)}"

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = KRYPTOS_ALPHABET

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "SHADOW", "BERLIN",
    "SCHEIDT", "SANBORN", "SEVEN", "CLOCK", "EAST", "NORTH", "LAYER",
    "CHART", "TOWER", "MORSE", "CIPHER", "SECRET", "HIDDEN", "ANTIPODES",
    "LUCID", "MATRIX",
]

# K1/K2/K3 approximate plaintexts (well-known public solutions)
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHETHENOUANCEOFIQLLUSION"
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUABORTTOTHESIGNALSWEREDEPENDENTONADEQUATELYMODULATINGTHEFREQUENCYOFRADIATIONXTHEFORECASTCAMEINTHECLEARANDOFFEREDNOCOVERINDICATIVEOFTHETRANSMITTERSORADDRESSEEXTHECONTROLWASSOMEWHATSTRAINED"
K3_PT = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBABORISTHATHEHADPREVIOUSLYONLYHADAGLIMPSEOFCOULDNOWBESEENINITSENTIRETYITWASANECTASYOFWONDERFULSOMETHINGHEHADNEVERSEENBEFOREITWASWONDERFULSOMETHINGHEHADNEVERSEENBEFOREALLOFSUDDENWHATAPPEAREDTOBEEMPTYSPACEMAYBETHATWASAMISTAKEXITWASNOTTHATHEWASUNPREPAREDTOTAKETHEEXPECTEDVIEWITWASQUITEREMARKABLETHATHIS"

RUNNING_KEYS = {
    "K1_PT": K1_PT,
    "K2_PT": K2_PT,
    "K3_PT": K3_PT,
    "K1K2K3": K1_PT + K2_PT + K3_PT,
}

SCORE_THRESHOLD = 6

# ---------------------------------------------------------------------------
# Decryption helpers (standard A=0 mod 26)
# ---------------------------------------------------------------------------

def char_to_num(c, alpha=AZ):
    return alpha.index(c)


def num_to_char(n, alpha=AZ):
    return alpha[n % 26]


def decrypt_periodic(ct, key, variant, alpha=AZ):
    """Decrypt ct with periodic key under variant (vig/beau/varbeau), using alpha."""
    klen = len(key)
    key_nums = [char_to_num(k, alpha) for k in key]
    out = []
    for i, c in enumerate(ct):
        ci = char_to_num(c, alpha)
        ki = key_nums[i % klen]
        if variant == "vig":
            pi = (ci - ki) % MOD
        elif variant == "beau":
            pi = (ki - ci) % MOD
        elif variant == "varbeau":
            pi = (ci + ki) % MOD
        else:
            raise ValueError(variant)
        out.append(num_to_char(pi, alpha))
    return "".join(out)


def decrypt_running_key(ct, running_key, variant, alpha=AZ):
    """Decrypt ct with a running key (same length or longer)."""
    out = []
    for i, c in enumerate(ct):
        if i >= len(running_key):
            break
        ci = char_to_num(c, alpha)
        ki = char_to_num(running_key[i], alpha)
        if variant == "vig":
            pi = (ci - ki) % MOD
        elif variant == "beau":
            pi = (ki - ci) % MOD
        elif variant == "varbeau":
            pi = (ci + ki) % MOD
        else:
            raise ValueError(variant)
        out.append(num_to_char(pi, alpha))
    return "".join(out)


def columnar_untranspose(ct, ncols):
    """Undo columnar transposition with ncols columns (read by columns, write by rows)."""
    nrows = len(ct) // ncols
    remainder = len(ct) % ncols
    # Build column lengths
    col_lens = []
    for c in range(ncols):
        col_lens.append(nrows + (1 if c < remainder else 0))
    # Split ct into columns
    cols = []
    idx = 0
    for clen in col_lens:
        cols.append(ct[idx:idx + clen])
        idx += clen
    # Read row by row
    out = []
    for r in range(nrows + (1 if remainder > 0 else 0)):
        for c in range(ncols):
            if r < len(cols[c]):
                out.append(cols[c][r])
    return "".join(out)


# ---------------------------------------------------------------------------
# Main attack
# ---------------------------------------------------------------------------

def main():
    start_time = time.time()
    hits = []
    configs_tested = 0

    def check(pt, method):
        nonlocal configs_tested
        configs_tested += 1
        result = score_candidate_free(pt)
        score = result.crib_score
        if score >= SCORE_THRESHOLD:
            hit = {
                "method": method,
                "score": score,
                "ene_found": result.ene_found,
                "bc_found": result.bc_found,
                "ic": round(result.ic_value, 4),
                "plaintext": pt,
                "classification": result.crib_classification,
            }
            hits.append(hit)
            print(f"  HIT [{score}/24] {method} -> {pt[:40]}...")
        return score

    print(f"CT80: {CT80}")
    print(f"CT80 length: {len(CT80)}")
    print(f"Null positions removed: {NULL_POS}")
    print()

    # -----------------------------------------------------------------------
    # 1. Periodic keywords x 3 variants x 2 alphabets
    # -----------------------------------------------------------------------
    print("=== Phase 1: Periodic keyword decryption ===")
    for kw in KEYWORDS:
        for variant in ("vig", "beau", "varbeau"):
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                method = f"periodic|{variant}|{alpha_name}|key={kw}"
                pt = decrypt_periodic(CT80, kw, variant, alpha)
                check(pt, method)
    print(f"  Phase 1 done: {configs_tested} configs")

    # -----------------------------------------------------------------------
    # 2. Single-letter keys x 3 variants x 2 alphabets
    # -----------------------------------------------------------------------
    print("=== Phase 2: Single-letter keys (Caesar shifts) ===")
    for letter in AZ:
        for variant in ("vig", "beau", "varbeau"):
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                method = f"single_key|{variant}|{alpha_name}|key={letter}"
                pt = decrypt_periodic(CT80, letter, variant, alpha)
                check(pt, method)
    print(f"  Phase 2 done: {configs_tested} configs")

    # -----------------------------------------------------------------------
    # 3. Col7 untranspose on CT80, then periodic keywords
    # -----------------------------------------------------------------------
    print("=== Phase 3: Col7 untranspose + periodic keywords ===")
    ct80_untrans = columnar_untranspose(CT80, 7)
    print(f"  CT80 after col7 untranspose: {ct80_untrans}")
    for kw in KEYWORDS:
        for variant in ("vig", "beau", "varbeau"):
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                method = f"col7_untrans|{variant}|{alpha_name}|key={kw}"
                pt = decrypt_periodic(ct80_untrans, kw, variant, alpha)
                check(pt, method)
    # Also try other widths: 5, 8, 10, 16, 20
    for width in (5, 8, 10, 16, 20):
        ct80_w = columnar_untranspose(CT80, width)
        for kw in KEYWORDS:
            for variant in ("vig", "beau", "varbeau"):
                for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                    method = f"col{width}_untrans|{variant}|{alpha_name}|key={kw}"
                    pt = decrypt_periodic(ct80_w, kw, variant, alpha)
                    check(pt, method)
    print(f"  Phase 3 done: {configs_tested} configs")

    # -----------------------------------------------------------------------
    # 4. Running key from K1/K2/K3 plaintext
    # -----------------------------------------------------------------------
    print("=== Phase 4: Running key from K1/K2/K3 ===")
    for rk_name, rk_text in RUNNING_KEYS.items():
        # Sanitize running key
        rk_clean = "".join(c for c in rk_text.upper() if c in AZ)
        if len(rk_clean) < len(CT80):
            print(f"  Warning: {rk_name} ({len(rk_clean)} chars) shorter than CT80 ({len(CT80)}), skipping partial")
            # Still try with what we have
        for variant in ("vig", "beau", "varbeau"):
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                method = f"running_key|{variant}|{alpha_name}|source={rk_name}"
                pt = decrypt_running_key(CT80, rk_clean, variant, alpha)
                check(pt, method)
                # Also try with offsets into longer keys
                if len(rk_clean) > len(CT80):
                    for offset in range(1, min(len(rk_clean) - len(CT80) + 1, 50)):
                        method_off = f"running_key|{variant}|{alpha_name}|source={rk_name}|off={offset}"
                        pt = decrypt_running_key(CT80, rk_clean[offset:], variant, alpha)
                        check(pt, method_off)
    # Also try col7 untranspose + running key
    for rk_name, rk_text in RUNNING_KEYS.items():
        rk_clean = "".join(c for c in rk_text.upper() if c in AZ)
        for variant in ("vig", "beau", "varbeau"):
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                method = f"col7_untrans_running_key|{variant}|{alpha_name}|source={rk_name}"
                pt = decrypt_running_key(ct80_untrans, rk_clean, variant, alpha)
                check(pt, method)
    print(f"  Phase 4 done: {configs_tested} configs")

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    elapsed = time.time() - start_time
    print()
    print(f"=== SUMMARY ===")
    print(f"Configs tested: {configs_tested}")
    print(f"Hits (score >= {SCORE_THRESHOLD}): {len(hits)}")
    print(f"Elapsed: {elapsed:.1f}s")

    if hits:
        hits.sort(key=lambda h: h["score"], reverse=True)
        print(f"\nTop hits:")
        for h in hits[:20]:
            print(f"  [{h['score']}/24] {h['method']}")
            print(f"    PT: {h['plaintext'][:60]}...")
            print(f"    ENE={h['ene_found']} BC={h['bc_found']} IC={h['ic']}")
    else:
        print("\nNo hits above threshold.")

    # -----------------------------------------------------------------------
    # Save artifact
    # -----------------------------------------------------------------------
    artifact = {
        "experiment": "E-CT80-CIPHER-ATTACK",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "ct80": CT80,
        "ct80_length": len(CT80),
        "null_positions_removed": NULL_POS,
        "configs_tested": configs_tested,
        "threshold": SCORE_THRESHOLD,
        "hits": hits,
        "keywords_tested": KEYWORDS,
        "variants_tested": ["vig", "beau", "varbeau"],
        "alphabets_tested": ["AZ", "KA"],
        "phases": [
            "periodic_keywords",
            "single_letter_keys",
            "columnar_untranspose_keywords",
            "running_key_k1k2k3",
        ],
        "elapsed_seconds": round(elapsed, 1),
        "verdict": "NOISE" if not hits else (
            "SIGNAL" if any(h["score"] >= 18 for h in hits)
            else "INTERESTING" if any(h["score"] >= 10 for h in hits)
            else "WEAK"
        ),
    }

    out_path = os.path.join(_ROOT, "results", "ct80_cipher_attack.json")
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\nArtifact saved: {out_path}")


if __name__ == "__main__":
    main()
