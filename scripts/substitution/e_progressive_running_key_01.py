#!/usr/bin/env python3
"""
Cipher:     Progressive running key (Beaufort/Vigenere/VarBeau)
Family:     substitution
Status:     active
Keyspace:   ~133K configs (CT97) + ~133K (CT73) = ~266K total
Last run:   2026-03-22
Best score: TBD

Progressive running key: key[i] = (source[(i+offset) % L] + a*i) % 26
where source is a K-section CT/keyword, offset is circular, a is slope 0-25.

This is DIFFERENT from:
  - "keyword x progressive functions" (PROVEN #15): tested individual keywords
    NOT running keys from K-section texts
  - "K3 CT as running key" (PROVEN #27): only slope a=0 (plain running key)
  - "Running key from Gutenberg" (PROVEN #29): no progressive slope applied

Motivation: Sanborn's "slightly different tableau" could mean each successive
column of the Vigenere tableau is shifted by a constant increment, producing
key[i] = source[i+offset] + a*i mod 26.
"""

import sys, os, json, time
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH, ALPH_IDX, MOD
)

# ── Source texts ────────────────────────────────────────────────────────

K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA"
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNET"
    "PRNGATIHNRARPESLNNELEBLPIIACAEWMTW"
    "NDITEENRAHCTENEUDRETNHAEOETFOL"
    "SEDTIWENHAEIOYTEYQHEENCTAYCREIFTBR"
    "SPAMHHEWENATAMATEGYEERLBTEEFO"
    "ASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIA"
    "AHTTMSTEWPIEROAGRIEWFEBAECTDD"
    "HILCEIHSITEGOEAOSDDRYDLORITRKLMLEHA"
    "GTDHARDPNEOHMGFMFEUHEECDMRIP"
    "FEIMEHNLSSTTRTVDOHW"
)

K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE"
    "GGWHKKDQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA"
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI"
    "HHDDDUVHDWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX"
    "FLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ"
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP"
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)

K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"

# K0 Morse plaintext (letters only, no E markers)
K0_PT = "VIRTUALLYINVISIBLEDIGETALINTERPRETATIUMEMORYFORCESSHADOWLUCIDTISYOURPOSITIONSOSRQ"

# Build CT73 from Model B (remove 17 consensus nulls)
CONSENSUS_NULLS = frozenset({0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85})

# ── Crib setup ──────────────────────────────────────────────────────────

# CT97 cribs: positions in the 97-char carved text
CRIB_POS_97 = sorted(CRIB_DICT.keys())  # 24 positions
CRIB_VALS_97 = {pos: ALPH_IDX[CRIB_DICT[pos]] for pos in CRIB_POS_97}
CT_VALS = [ALPH_IDX[c] for c in CT]

# Required keystream values at crib positions for each variant
# Beaufort:  C = (K - P) mod 26  =>  K = (C + P) mod 26
# Vigenere:  C = (P + K) mod 26  =>  K = (C - P) mod 26
# VarBeau:   C = (P - K) mod 26  =>  K = (P - C) mod 26
REQ_KEY_97 = {}
for variant in ("beau", "vig", "vbeau"):
    REQ_KEY_97[variant] = {}
    for pos in CRIB_POS_97:
        c = CT_VALS[pos]
        p = CRIB_VALS_97[pos]
        if variant == "beau":
            REQ_KEY_97[variant][pos] = (c + p) % 26
        elif variant == "vig":
            REQ_KEY_97[variant][pos] = (c - p) % 26
        else:  # vbeau
            REQ_KEY_97[variant][pos] = (p - c) % 26

# CT73 setup: remove consensus nulls, remap crib positions
ct73_chars = []
pos97_to_pos73 = {}
idx73 = 0
for i in range(CT_LEN):
    if i not in CONSENSUS_NULLS:
        ct73_chars.append(CT[i])
        pos97_to_pos73[i] = idx73
        idx73 += 1
CT73 = "".join(ct73_chars)
CT73_LEN = len(CT73)
CT73_VALS = [ALPH_IDX[c] for c in CT73]

# Remap cribs to CT73 positions
CRIB_POS_73 = {}
for pos in CRIB_POS_97:
    if pos in pos97_to_pos73:
        CRIB_POS_73[pos97_to_pos73[pos]] = CRIB_VALS_97[pos]

CRIB_POS_73_LIST = sorted(CRIB_POS_73.keys())

REQ_KEY_73 = {}
for variant in ("beau", "vig", "vbeau"):
    REQ_KEY_73[variant] = {}
    for pos73, pt_val in CRIB_POS_73.items():
        c = CT73_VALS[pos73]
        p = pt_val
        if variant == "beau":
            REQ_KEY_73[variant][pos73] = (c + p) % 26
        elif variant == "vig":
            REQ_KEY_73[variant][pos73] = (c - p) % 26
        else:
            REQ_KEY_73[variant][pos73] = (p - c) % 26

# ── Source text definitions ─────────────────────────────────────────────

def sanitize(text):
    """Extract only uppercase A-Z characters."""
    return "".join(c for c in text.upper() if c in ALPH)

K3K4_CT = K3_CT + "Q" + CT  # ? delimiter + K4 = 434 chars
K1K2_CT = K1_CT + K2_CT     # 63 + 372 = 435 chars

SOURCES = {
    "K3_CT":         sanitize(K3_CT),
    "K2_CT":         sanitize(K2_CT),
    "K1_CT":         sanitize(K1_CT),
    "K3QK4_CT":      sanitize(K3K4_CT),
    "K1K2_CT":       sanitize(K1K2_CT),
    "KRYPTOS_rep":   ("KRYPTOS" * 14)[:97],
    "PALIMPSEST_rep": ("PALIMPSEST" * 10)[:97],
    "ABSCISSA_rep":  ("ABSCISSA" * 13)[:97],
    "K0_PT":         sanitize(K0_PT),
    # Also test reversed forms
    "K3_CT_rev":     sanitize(K3_CT)[::-1],
    "K2_CT_rev":     sanitize(K2_CT)[::-1],
    "K1_CT_rev":     sanitize(K1_CT)[::-1],
    # Combined plaintexts
    "K1K2K3_CT":     sanitize(K1_CT + K2_CT + K3_CT),
}

VARIANTS = ("beau", "vig", "vbeau")

# ── Scoring function ────────────────────────────────────────────────────

def score_progressive(source_vals, src_len, offset, slope, req_key, crib_positions, ct_len):
    """Score a progressive running key config by counting crib matches.

    key[i] = (source_vals[(i + offset) % src_len] + slope * i) % 26
    """
    matches = 0
    for pos in crib_positions:
        src_idx = (pos + offset) % src_len
        key_val = (source_vals[src_idx] + slope * pos) % 26
        if key_val == req_key[pos]:
            matches += 1
    return matches

# ── Main sweep ──────────────────────────────────────────────────────────

def main():
    t0 = time.time()

    print("=" * 72)
    print("K4 Progressive Running Key Test")
    print("=" * 72)
    print(f"CT97: {CT} ({CT_LEN} chars)")
    print(f"CT73: {CT73} ({CT73_LEN} chars)")
    print(f"Crib positions (CT97): {CRIB_POS_97}")
    print(f"Crib positions (CT73): {CRIB_POS_73_LIST}")
    print(f"Sources: {list(SOURCES.keys())}")
    print(f"Variants: {VARIANTS}")
    print(f"Slopes: 0-25")
    print()

    # Verify a=0 should match known results (K3 CT running key best=5/24)
    print("Sanity check: K3_CT slope=0 Beaufort should match prior result (best~5/24)")

    all_hits = []  # (score, source_name, variant, offset, slope, model)
    total_configs = 0
    best_overall = 0

    # ── CT97 sweep ──────────────────────────────────────────────────────
    print("\n--- MODEL A: CT97 (97 chars, cribs at original positions) ---\n")

    for src_name, src_text in SOURCES.items():
        src_vals = [ALPH_IDX[c] for c in src_text]
        src_len = len(src_text)

        best_for_src = 0
        best_detail = None
        src_configs = 0

        for variant in VARIANTS:
            req = REQ_KEY_97[variant]

            # For short repeated keywords, only need offsets 0 to keyword_len-1
            if src_name.endswith("_rep") and src_len <= 20:
                # Find base keyword length
                base_len = len(src_name.split("_")[0])
                offsets = range(base_len)
            else:
                offsets = range(src_len)

            for offset in offsets:
                for slope in range(26):
                    src_configs += 1
                    total_configs += 1

                    score = score_progressive(
                        src_vals, src_len, offset, slope,
                        req, CRIB_POS_97, CT_LEN
                    )

                    if score > best_for_src:
                        best_for_src = score
                        best_detail = (variant, offset, slope)

                    if score > best_overall:
                        best_overall = score

                    if score >= 8:
                        all_hits.append((score, src_name, variant, offset, slope, "CT97"))

        v, o, s = best_detail if best_detail else ("?", 0, 0)
        status = "***" if best_for_src >= 8 else ""
        print(f"  {src_name:20s}: best={best_for_src:2d}/24  ({v}, offset={o}, slope={s})  [{src_configs:,d} configs] {status}")

    # ── CT73 sweep ──────────────────────────────────────────────────────
    print("\n--- MODEL B: CT73 (73 chars, consensus nulls removed) ---\n")

    for src_name, src_text in SOURCES.items():
        src_vals = [ALPH_IDX[c] for c in src_text]
        src_len = len(src_text)

        best_for_src = 0
        best_detail = None
        src_configs = 0

        for variant in VARIANTS:
            req = REQ_KEY_73[variant]

            if src_name.endswith("_rep") and src_len <= 20:
                base_len = len(src_name.split("_")[0])
                offsets = range(base_len)
            else:
                offsets = range(src_len)

            for offset in offsets:
                for slope in range(26):
                    src_configs += 1
                    total_configs += 1

                    score = score_progressive(
                        src_vals, src_len, offset, slope,
                        req, CRIB_POS_73_LIST, CT73_LEN
                    )

                    if score > best_for_src:
                        best_for_src = score
                        best_detail = (variant, offset, slope)

                    if score > best_overall:
                        best_overall = score

                    if score >= 8:
                        all_hits.append((score, src_name, variant, offset, slope, "CT73"))

        v, o, s = best_detail if best_detail else ("?", 0, 0)
        status = "***" if best_for_src >= 8 else ""
        print(f"  {src_name:20s}: best={best_for_src:2d}/24  ({v}, offset={o}, slope={s})  [{src_configs:,d} configs] {status}")

    # ── Also test KA alphabet (Kryptos-keyed) ──────────────────────────
    # Despite the task spec saying AZ only, testing KA is cheap and important
    # because the encoding chart uses KA
    KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
    KA_IDX = {c: i for i, c in enumerate(KA)}

    print("\n--- MODEL A: CT97 with KA alphabet ---\n")

    # Recompute required keystream under KA
    CT_VALS_KA = [KA_IDX[c] for c in CT]
    REQ_KEY_97_KA = {}
    for variant in VARIANTS:
        REQ_KEY_97_KA[variant] = {}
        for pos in CRIB_POS_97:
            c = CT_VALS_KA[pos]
            p = KA_IDX[CRIB_DICT[pos]]
            if variant == "beau":
                REQ_KEY_97_KA[variant][pos] = (c + p) % 26
            elif variant == "vig":
                REQ_KEY_97_KA[variant][pos] = (c - p) % 26
            else:
                REQ_KEY_97_KA[variant][pos] = (p - c) % 26

    # Only test long sources under KA (not keywords which were already tested)
    KA_SOURCES = {k: v for k, v in SOURCES.items() if not k.endswith("_rep")}

    for src_name, src_text in KA_SOURCES.items():
        src_vals = [KA_IDX[c] for c in src_text]
        src_len = len(src_text)

        best_for_src = 0
        best_detail = None
        src_configs = 0

        for variant in VARIANTS:
            req = REQ_KEY_97_KA[variant]

            for offset in range(src_len):
                for slope in range(26):
                    src_configs += 1
                    total_configs += 1

                    score = score_progressive(
                        src_vals, src_len, offset, slope,
                        req, CRIB_POS_97, CT_LEN
                    )

                    if score > best_for_src:
                        best_for_src = score
                        best_detail = (variant, offset, slope)

                    if score > best_overall:
                        best_overall = score

                    if score >= 8:
                        all_hits.append((score, src_name + "_KA", variant, offset, slope, "CT97_KA"))

        v, o, s = best_detail if best_detail else ("?", 0, 0)
        status = "***" if best_for_src >= 8 else ""
        print(f"  {src_name:20s}: best={best_for_src:2d}/24  ({v}, offset={o}, slope={s})  [{src_configs:,d} configs] {status}")

    # CT73 with KA
    print("\n--- MODEL B: CT73 with KA alphabet ---\n")

    CT73_VALS_KA = [KA_IDX[c] for c in CT73]
    REQ_KEY_73_KA = {}
    for variant in VARIANTS:
        REQ_KEY_73_KA[variant] = {}
        for pos73, pt_val_az in CRIB_POS_73.items():
            c = CT73_VALS_KA[pos73]
            # pt_val_az is in AZ indexing, need KA indexing
            pt_letter = ALPH[pt_val_az]
            p = KA_IDX[pt_letter]
            if variant == "beau":
                REQ_KEY_73_KA[variant][pos73] = (c + p) % 26
            elif variant == "vig":
                REQ_KEY_73_KA[variant][pos73] = (c - p) % 26
            else:
                REQ_KEY_73_KA[variant][pos73] = (p - c) % 26

    for src_name, src_text in KA_SOURCES.items():
        src_vals = [KA_IDX[c] for c in src_text]
        src_len = len(src_text)

        best_for_src = 0
        best_detail = None
        src_configs = 0

        for variant in VARIANTS:
            req = REQ_KEY_73_KA[variant]

            for offset in range(src_len):
                for slope in range(26):
                    src_configs += 1
                    total_configs += 1

                    score = score_progressive(
                        src_vals, src_len, offset, slope,
                        req, CRIB_POS_73_LIST, CT73_LEN
                    )

                    if score > best_for_src:
                        best_for_src = score
                        best_detail = (variant, offset, slope)

                    if score > best_overall:
                        best_overall = score

                    if score >= 8:
                        all_hits.append((score, src_name + "_KA", variant, offset, slope, "CT73_KA"))

        v, o, s = best_detail if best_detail else ("?", 0, 0)
        status = "***" if best_for_src >= 8 else ""
        print(f"  {src_name:20s}: best={best_for_src:2d}/24  ({v}, offset={o}, slope={s})  [{src_configs:,d} configs] {status}")

    # ── Summary ─────────────────────────────────────────────────────────
    elapsed = time.time() - t0

    print("\n" + "=" * 72)
    print(f"TOTAL: {total_configs:,d} configs in {elapsed:.1f}s")
    print(f"BEST OVERALL: {best_overall}/24")
    print()

    if all_hits:
        all_hits.sort(key=lambda x: -x[0])
        print(f"HITS >= 8/24: {len(all_hits)}")
        for score, src, var, off, sl, model in all_hits[:20]:
            print(f"  {score}/24  {src:20s}  {var:6s}  offset={off:4d}  slope={sl:2d}  [{model}]")
    else:
        print("HITS >= 8/24: NONE")

    # Verdict
    if best_overall >= 18:
        verdict = "SIGNAL"
    elif best_overall >= 12:
        verdict = "interesting"
    elif best_overall >= 8:
        verdict = "elevated_noise"
    else:
        verdict = "noise"

    print(f"\nVERDICT: {verdict}")

    # ── Write results ───────────────────────────────────────────────────
    results = {
        "experiment": "e_progressive_running_key_01",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "description": "Progressive running key: key[i] = (source[(i+offset)%L] + a*i) % 26",
        "hypothesis": "Sanborn's 'slightly different tableau' = linear slope added to running key",
        "sources_tested": list(SOURCES.keys()),
        "alphabets": ["AZ", "KA"],
        "models": ["CT97", "CT73"],
        "variants": list(VARIANTS),
        "slopes": "0-25",
        "total_configs": total_configs,
        "elapsed_s": round(elapsed, 1),
        "best_overall": best_overall,
        "hits_8plus": [
            {
                "score": h[0],
                "source": h[1],
                "variant": h[2],
                "offset": h[3],
                "slope": h[4],
                "model": h[5],
            }
            for h in all_hits
        ],
        "verdict": verdict,
        "conclusion": (
            f"Progressive running key with {len(SOURCES)} source texts, "
            f"26 slopes, 3 cipher variants, 2 alphabets (AZ/KA), "
            f"2 models (CT97/CT73). Best={best_overall}/24. "
            f"{'NOISE — progressive slope does NOT improve running key results.' if best_overall < 8 else ''}"
            f"{'Elevated but likely noise.' if 8 <= best_overall < 12 else ''}"
            f"{'INTERESTING — requires investigation.' if best_overall >= 12 else ''}"
        ),
        "eliminates": (
            "Progressive running key where source is K-section CT/PT/keyword "
            "and slope a=0..25, for both CT97 and CT73 with consensus null mask."
        ) if best_overall < 12 else "nothing yet",
    }

    out_path = os.path.join(_ROOT, "results", "e_progressive_running_key_01.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults written to: {out_path}")

if __name__ == "__main__":
    main()
