#!/usr/bin/env python3
"""
Cipher: running key
Family: running_key
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-ANTIPODES-04: Running Key from Sculpture Text

HYPOTHESIS: The running key for K4 comes from text physically visible on the
Kryptos/Antipodes sculptures. Sanborn says "kryptos is available to all" — the
key is literally carved in copper.

WHY ANTIPODES: The Antipodes text sequence (K3→K4→K1→K2) provides a specific
ordering. Running key from known texts was tested (E-FRAC-49/50), but NOT with:
(a) Antipodes-specific ordering, (b) K3 PLAINTEXT as key, (c) the TABLEAU
itself read row-by-row as key source.

METHOD:
1. Sculpture ciphertext as key (Antipodes ordering: K3+K4+K1K2 = 865 chars)
2. K3 plaintext (Carter text) as key
3. K1+K2 plaintexts as key
4. Tableau read row-by-row as key
5. K3 PT tail + autokey into K4

COST: ~2500 offsets × 3 variants × 5 sources ≈ 37K. Under 10 sec.
"""

import json
import os
import sys
import time
from typing import List, Dict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, N_CRIBS,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
    vig_decrypt, beau_decrypt, varbeau_decrypt,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.constraints.bean import verify_bean_simple
from kryptos.kernel.transforms.vigenere import recover_key_at_positions

# ── Sculpture texts ──────────────────────────────────────────────────────

# K1 ciphertext (63 chars, public fact)
K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"

# K2 ciphertext (369 chars, public fact)
K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)

# K3 ciphertext (336 chars, public fact)
K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)

# K4 ciphertext = CT (imported from constants)

# K1 plaintext (public fact)
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUABOROFDARKNESS"  # not exact

# K2 plaintext (public fact, approximate)
K2_PT = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELD"
    "XTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATION"
    "XDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWS"
    "THEEXACTLOCATIONONLYWWTHISISHISTLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTY"
    "SEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTES"
    "FORTYFOURSECONDSWESTXLAYERTWO"
)

# K3 plaintext (public fact)
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFJPASSAGEDEBABORETURNST"
    "OTHEEARLIESTTASKWASENTALANTSANDHOWTESIDWALLSITTWASFORCED"
    "HEWALLSLOWLYWERECAVINGINTHEYWEREONLYABLETONOTREADITVERYC"
    "LEARLYWASTHEREACHAROOMBEYONDTHECHAMBERQCANYOUSEEANYTHINGQ"
)

# Antipodes sequence: K3+K4+K1K2+K3+K4+K1K2 (truncated)
ANTIPODES_CT = K3_CT + CT + K1_CT + K2_CT

# Full Kryptos ciphertext (K1+K2+K3+K4)
KRYPTOS_CT = K1_CT + K2_CT + K3_CT + CT

# Known plaintexts concatenated
ALL_KNOWN_PT = K1_PT + K2_PT + K3_PT

# ── Tableau as running key ───────────────────────────────────────────────

def build_tableau_key() -> str:
    """Read KA tableau row-by-row as a running key source."""
    # KA tableau: row r has alphabet shifted by r positions
    rows = []
    for r in range(26):
        row = "".join(KRYPTOS_ALPHABET[(r + c) % 26] for c in range(26))
        rows.append(row)
    return "".join(rows)  # 676 chars


DECRYPT_FNS = {
    CipherVariant.VIGENERE: vig_decrypt,
    CipherVariant.BEAUFORT: beau_decrypt,
    CipherVariant.VAR_BEAUFORT: varbeau_decrypt,
}

def text_to_key(text: str) -> List[int]:
    """Convert text to numeric key (A=0)."""
    return [ord(c) - 65 for c in text.upper() if c.isalpha()]


def try_running_key(
    source_name: str, source_text: str,
    variant: CipherVariant, offset: int,
) -> Dict:
    """Try a running key at given offset, return result dict."""
    key_text = source_text[offset:]
    if len(key_text) < CT_LEN:
        return {"crib_score": 0}
    key = text_to_key(key_text[:CT_LEN])
    if len(key) < CT_LEN:
        return {"crib_score": 0}
    pt = decrypt_text(CT, key, variant)
    sc = score_cribs(pt)

    result = {
        "source": source_name,
        "variant": variant.value,
        "offset": offset,
        "crib_score": sc,
        "plaintext": pt,
        "key_fragment": key_text[:20],
    }

    if sc >= 24:
        # Check Bean
        key_full = [0] * CT_LEN
        for i in range(CT_LEN):
            key_full[i] = key[i]
        bean = verify_bean_simple(key_full)
        result["bean_pass"] = bean

    return result


def try_autokey(
    seed: List[int], variant: CipherVariant, mode: str = "pt",
) -> Dict:
    """Try autokey cipher with given seed."""
    decrypt_fn = DECRYPT_FNS[variant]
    key = list(seed)
    pt_nums = []

    for i in range(CT_LEN):
        c = ord(CT[i]) - 65
        if i < len(key):
            k = key[i]
        else:
            if mode == "pt":
                k = pt_nums[-1]  # PT-autokey
            else:
                k = ord(CT[i - len(seed)]) - 65  # CT-autokey
        p = decrypt_fn(c, k)
        pt_nums.append(p)

    pt = "".join(chr(p + 65) for p in pt_nums)
    sc = score_cribs(pt)

    return {
        "source": f"autokey_{mode}",
        "variant": variant.value,
        "seed_len": len(seed),
        "crib_score": sc,
        "plaintext": pt,
    }


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-ANTIPODES-04: Running Key from Sculpture Text")
    print("=" * 70)

    best_score = 0
    best_result = None
    total_configs = 0
    above_noise = []

    variants = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

    # Build all key sources
    tableau_key = build_tableau_key()

    sources = [
        ("Antipodes_CT", ANTIPODES_CT),
        ("Kryptos_CT", KRYPTOS_CT),
        ("K3_CT", K3_CT),
        ("K1_CT", K1_CT),
        ("K2_CT", K2_CT),
        ("K3_PT", K3_PT),
        ("K1_PT", K1_PT),
        ("K2_PT", K2_PT),
        ("All_known_PT", ALL_KNOWN_PT),
        ("Tableau_rows", tableau_key),
    ]

    for source_name, source_text in sources:
        # Clean to alpha only
        clean = "".join(c for c in source_text.upper() if c.isalpha())
        max_offset = max(0, len(clean) - CT_LEN)

        print(f"\n--- Source: {source_name} ({len(clean)} chars, {max_offset+1} offsets) ---")
        src_best = 0

        for offset in range(max_offset + 1):
            for variant in variants:
                total_configs += 1
                result = try_running_key(source_name, clean, variant, offset)
                sc = result["crib_score"]

                if sc > best_score:
                    best_score = sc
                    best_result = result
                    if sc > NOISE_FLOOR:
                        print(f"  NEW BEST: {sc}/24, {source_name} offset={offset}, "
                              f"{variant.value}")
                        if sc >= STORE_THRESHOLD:
                            print(f"  PT: {result['plaintext']}")

                if sc > src_best:
                    src_best = sc

                if sc > NOISE_FLOOR:
                    above_noise.append({
                        "source": source_name,
                        "variant": variant.value,
                        "offset": offset,
                        "crib_score": sc,
                    })

        print(f"  Best for {source_name}: {src_best}/24")

    # ── Autokey tests ────────────────────────────────────────────────────
    print("\n--- Autokey tests (K3 PT tail as seed) ---")
    k3_clean = "".join(c for c in K3_PT.upper() if c.isalpha())

    for seed_len in [1, 3, 5, 7, 10, 13, 18, 26]:
        for seed_start in range(max(0, len(k3_clean) - seed_len - 5),
                                 len(k3_clean) - seed_len + 1):
            seed = [ord(c) - 65 for c in k3_clean[seed_start:seed_start+seed_len]]

            for variant in variants:
                for mode in ["pt", "ct"]:
                    total_configs += 1
                    result = try_autokey(seed, variant, mode)
                    sc = result["crib_score"]

                    if sc > best_score:
                        best_score = sc
                        best_result = result
                        best_result["seed_start"] = seed_start
                        if sc > NOISE_FLOOR:
                            print(f"  NEW BEST autokey: {sc}/24, mode={mode}, "
                                  f"seed_start={seed_start}, seed_len={seed_len}, "
                                  f"{variant.value}")

                    if sc > NOISE_FLOOR:
                        above_noise.append({
                            "source": f"autokey_{mode}",
                            "variant": variant.value,
                            "seed_start": seed_start,
                            "seed_len": seed_len,
                            "crib_score": sc,
                        })

    # ── Reversed sources ─────────────────────────────────────────────────
    print("\n--- Reversed text sources ---")
    for source_name, source_text in sources[:5]:
        clean = "".join(c for c in source_text.upper() if c.isalpha())[::-1]
        max_offset = max(0, len(clean) - CT_LEN)

        for offset in range(max_offset + 1):
            for variant in variants:
                total_configs += 1
                result = try_running_key(f"{source_name}_rev", clean, variant, offset)
                sc = result["crib_score"]
                if sc > best_score:
                    best_score = sc
                    best_result = result
                    if sc > NOISE_FLOOR:
                        print(f"  NEW BEST reversed: {sc}/24, {source_name}_rev "
                              f"offset={offset}, {variant.value}")
                if sc > NOISE_FLOOR:
                    above_noise.append({
                        "source": f"{source_name}_rev",
                        "variant": variant.value,
                        "offset": offset,
                        "crib_score": sc,
                    })

    elapsed = time.time() - t0

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total configs tested: {total_configs:,}")
    print(f"Best crib score: {best_score}/24")
    if best_result:
        for k, v in best_result.items():
            if k != "plaintext":
                print(f"  {k}: {v}")
        if best_score >= STORE_THRESHOLD:
            print(f"Best plaintext: {best_result.get('plaintext')}")
    print(f"Above-noise results: {len(above_noise)}")
    print(f"Elapsed: {elapsed:.1f}s")

    # ── Write results ─────────────────────────────────────────────────────
    outdir = os.path.join(os.path.dirname(__file__), '..', 'results', 'e_antipodes_04')
    os.makedirs(outdir, exist_ok=True)
    summary = {
        "experiment": "E-ANTIPODES-04",
        "hypothesis": "Running key from sculpture text (Antipodes ordering, K3 PT, tableau)",
        "total_configs": total_configs,
        "best_score": best_score,
        "best_result": {k: v for k, v in best_result.items() if k != "plaintext"} if best_result else None,
        "above_noise_count": len(above_noise),
        "sources_tested": [s[0] for s in sources] + [f"{s[0]}_rev" for s in sources[:5]],
        "elapsed_seconds": elapsed,
    }
    with open(os.path.join(outdir, 'summary.json'), 'w') as f:
        json.dump(summary, f, indent=2)
    if above_noise:
        above_noise.sort(key=lambda x: x["crib_score"], reverse=True)
        with open(os.path.join(outdir, 'above_noise.json'), 'w') as f:
            json.dump(above_noise[:100], f, indent=2)

    print(f"\nResults written to {outdir}/")
    if best_score <= NOISE_FLOOR:
        print("\nCONCLUSION: NOISE — Sculpture running key hypothesis not supported.")
    else:
        print(f"\nCONCLUSION: Score {best_score}/24 detected — "
              f"{'investigate!' if best_score >= STORE_THRESHOLD else 'likely noise.'}")


if __name__ == "__main__":
    main()
