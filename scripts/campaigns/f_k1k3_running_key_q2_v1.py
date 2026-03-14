#!/usr/bin/env python3
"""K1-K3 plaintext as running key for K4 via Quagmire II and related tableaux.

Cipher:    Running key (Q2 / Beaufort-Q2 / standard Vigenere)
Family:    campaigns
Status:    active
Keyspace:  ~770 offsets x 7 key sources x 3 variants x 2 alphabets = ~32K direct
           + null-mask SA: 7 sources x 3 variants x 2 alphabets x 20 restarts x 4000 steps
Best score: TBD
Last run:  2026-03-14

Sanborn: "I have left instructions in the earlier text that refer to later text."
K1-K3 plaintext is the most obvious candidate for a running key on K4.

Models tested:
  1. Q2 running key:  PT = KA[(KA.index(CT) - AZ.index(key)) % 26]
  2. Q2 Beaufort:     PT = KA[(AZ.index(key) - KA.index(CT)) % 26]
  3. Standard AZ Vig: PT = AZ[(AZ.index(CT) - AZ.index(key)) % 26]
  4. Standard AZ Beau: PT = AZ[(AZ.index(key) - AZ.index(CT)) % 26]
  5. Var Beaufort AZ:  PT = AZ[(AZ.index(key) + AZ.index(CT)) % 26]  (equiv to Beau encrypt)

Key sources: K1 alone, K2 alone, K3 alone, K1+K2+K3, K3+K2+K1 (reversed), K2+K3, K1+K2.

For null-mask versions: SA optimizes which 24 of 97 positions are nulls.
After removing nulls, 73-char CT is decrypted at each tested offset.
"""

import sys
import time
import random
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, CRIB_POSITIONS, ALPH, MOD

# ── Constants ────────────────────────────────────────────────────────────
CT97 = CT
N = 97
N_NULLS = 24
N_PT = 73
AZ = ALPH
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

AZ_IDX = {c: i for i, c in enumerate(AZ)}
KA_IDX = {c: i for i, c in enumerate(KA)}

ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_START = 21
BCL_START = 63

# ── K1-K3 Plaintexts ────────────────────────────────────────────────────

K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUA" \
        "NCEOFIQLUSION"  # 63 chars

K2_PT = ("ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHS"
         "MAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTED"
         "UNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANABORANDLANGLEY"
         "KNOWABOUTTHISTHEYSHOULDITSBURABORIEDSOMEWHEREXWHOKNOWS"
         "THEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHT"
         "DEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTY"
         "SEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWEST")  # ~369 chars

K3_PT = ("SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHAT"
         "ENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLI"
         "NGHANDSIMADEATINYBREACHOINTHEUPPERLEFTHANDCORNERANDTHEN"
         "WIDEONINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDPEABOREDIN"
         "THEDARKHOTAIRESCHAPINGFROMTHECHAMBOERCAUSEDTHEFLAMETOFL"
         "ICKERBUTPRESENTLYDETAILSOFTHEROOMWITHINEMERGEDFROMTHEMI"
         "STXCANYOUSEEANYTHINGQ")  # ~337 chars

# Sanitize
def sanitize(s):
    return ''.join(c for c in s.upper() if c.isalpha())

K1 = sanitize(K1_PT)
K2 = sanitize(K2_PT)
K3 = sanitize(K3_PT)
K123 = K1 + K2 + K3
K321 = K3 + K2 + K1
K23  = K2 + K3
K12  = K1 + K2

KEY_SOURCES = {
    "K1":       K1,
    "K2":       K2,
    "K3":       K3,
    "K1+K2+K3": K123,
    "K3+K2+K1": K321,
    "K2+K3":    K23,
    "K1+K2":    K12,
}

# ── Decrypt Functions ────────────────────────────────────────────────────

def q2_decrypt(ct_str, key_str):
    """Quagmire II: PT[i] = KA[ (KA_IDX[CT[i]] - AZ_IDX[key[i]]) % 26 ]"""
    pt = []
    for i in range(len(ct_str)):
        ci = KA_IDX[ct_str[i]]
        ki = AZ_IDX[key_str[i]]
        pt.append(KA[(ci - ki) % 26])
    return ''.join(pt)


def q2_beau_decrypt(ct_str, key_str):
    """Q2 Beaufort: PT[i] = KA[ (AZ_IDX[key[i]] - KA_IDX[CT[i]]) % 26 ]"""
    pt = []
    for i in range(len(ct_str)):
        ci = KA_IDX[ct_str[i]]
        ki = AZ_IDX[key_str[i]]
        pt.append(KA[(ki - ci) % 26])
    return ''.join(pt)


def az_vig_decrypt(ct_str, key_str):
    """Standard AZ Vigenere: PT[i] = AZ[ (AZ_IDX[CT[i]] - AZ_IDX[key[i]]) % 26 ]"""
    pt = []
    for i in range(len(ct_str)):
        ci = AZ_IDX[ct_str[i]]
        ki = AZ_IDX[key_str[i]]
        pt.append(AZ[(ci - ki) % 26])
    return ''.join(pt)


def az_beau_decrypt(ct_str, key_str):
    """Standard AZ Beaufort: PT[i] = AZ[ (AZ_IDX[key[i]] - AZ_IDX[CT[i]]) % 26 ]"""
    pt = []
    for i in range(len(ct_str)):
        ci = AZ_IDX[ct_str[i]]
        ki = AZ_IDX[key_str[i]]
        pt.append(AZ[(ki - ci) % 26])
    return ''.join(pt)


def az_vbeau_decrypt(ct_str, key_str):
    """AZ Variant Beaufort: PT[i] = AZ[ (AZ_IDX[key[i]] + AZ_IDX[CT[i]]) % 26 ]
    (This is Beaufort encryption applied as decryption)"""
    pt = []
    for i in range(len(ct_str)):
        ci = AZ_IDX[ct_str[i]]
        ki = AZ_IDX[key_str[i]]
        pt.append(AZ[(ki + ci) % 26])
    return ''.join(pt)


DECRYPT_FUNCS = {
    "Q2_vig":     q2_decrypt,
    "Q2_beau":    q2_beau_decrypt,
    "AZ_vig":     az_vig_decrypt,
    "AZ_beau":    az_beau_decrypt,
    "AZ_vbeau":   az_vbeau_decrypt,
}

# ── Scoring ──────────────────────────────────────────────────────────────

def count_crib_hits_97(pt97):
    """Count crib matches for a 97-char plaintext (direct, no null mask)."""
    total = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt97) and pt97[pos] == ch:
            total += 1
    return total


def count_crib_hits_73(pt73, n1, n2):
    """Count crib matches for a 73-char plaintext with null-adjusted positions.
    n1 = nulls before ENE_START, n2 = nulls before BCL_START."""
    ene_s = ENE_START - n1
    bcl_s = BCL_START - n2
    e = sum(1 for j, c in enumerate(ENE_WORD) if ene_s + j < len(pt73) and pt73[ene_s + j] == c)
    b = sum(1 for j, c in enumerate(BCL_WORD) if bcl_s + j < len(pt73) and pt73[bcl_s + j] == c)
    return e + b, e, b


# ══════════════════════════════════════════════════════════════════════════
# PHASE 1: Direct running key on 97 chars (no null mask)
# ══════════════════════════════════════════════════════════════════════════

def phase1():
    print("=" * 70)
    print("PHASE 1: Direct running key on 97 chars (all offsets)")
    print("=" * 70)
    print()

    best_global = 0
    best_info = ""

    for src_name, key_text in KEY_SOURCES.items():
        n_offsets = len(key_text) - N + 1
        if n_offsets < 1:
            print(f"  {src_name}: too short ({len(key_text)} chars), skipping")
            continue

        for var_name, decrypt_fn in DECRYPT_FUNCS.items():
            best_score = 0
            best_offset = -1
            best_pt = ""

            for offset in range(n_offsets):
                key_window = key_text[offset:offset + N]
                pt = decrypt_fn(CT97, key_window)
                sc = count_crib_hits_97(pt)

                if sc > best_score:
                    best_score = sc
                    best_offset = offset
                    best_pt = pt

            flag = " ***" if best_score >= 10 else ""
            print(f"  {src_name:12s} {var_name:10s}  offsets=0..{n_offsets-1:4d}  "
                  f"best={best_score:2d}/24 at offset={best_offset}{flag}")

            if best_score >= 8:
                print(f"    PT = {best_pt}")
                key_used = key_text[best_offset:best_offset + N]
                print(f"    Key= {key_used[:60]}...")

            if best_score > best_global:
                best_global = best_score
                best_info = f"{src_name}/{var_name} offset={best_offset} score={best_score}/24"

    print(f"\n  PHASE 1 BEST: {best_info} (global={best_global}/24)")
    return best_global


# ══════════════════════════════════════════════════════════════════════════
# PHASE 2: Cyclic/wrapping key (key repeats if shorter than CT)
# ══════════════════════════════════════════════════════════════════════════

def phase2():
    print()
    print("=" * 70)
    print("PHASE 2: Cyclic key (key wraps around)")
    print("=" * 70)
    print()

    best_global = 0
    best_info = ""

    for src_name, key_text in KEY_SOURCES.items():
        for var_name, decrypt_fn in DECRYPT_FUNCS.items():
            klen = len(key_text)
            best_score = 0
            best_offset = -1
            best_pt = ""

            for offset in range(klen):
                key_window = ''.join(key_text[(offset + i) % klen] for i in range(N))
                pt = decrypt_fn(CT97, key_window)
                sc = count_crib_hits_97(pt)

                if sc > best_score:
                    best_score = sc
                    best_offset = offset
                    best_pt = pt

            flag = " ***" if best_score >= 10 else ""
            print(f"  {src_name:12s} {var_name:10s}  cyclic offsets=0..{klen-1:4d}  "
                  f"best={best_score:2d}/24 at offset={best_offset}{flag}")

            if best_score >= 8:
                print(f"    PT = {best_pt}")

            if best_score > best_global:
                best_global = best_score
                best_info = f"{src_name}/{var_name} cyclic offset={best_offset} score={best_score}/24"

    print(f"\n  PHASE 2 BEST: {best_info} (global={best_global}/24)")
    return best_global


# ══════════════════════════════════════════════════════════════════════════
# PHASE 3: Null-mask SA with running key on 73 chars
# ══════════════════════════════════════════════════════════════════════════

def sa_null_mask_running_key(key73, decrypt_fn, n_restarts=20, n_steps=4000, seed=42):
    """SA to optimize 24-null mask, decrypting remaining 73 chars with given key.

    Returns (best_score, best_ene, best_bcl, best_mask, best_pt).
    """
    rng = random.Random(seed)
    crib_pos_set = frozenset(CRIB_POSITIONS)

    best_global_sc = 0
    best_global_mask = None
    best_global_pt = ""
    best_global_e = 0
    best_global_b = 0

    for restart in range(n_restarts):
        # Random initial mask
        positions = list(range(N))
        rng.shuffle(positions)
        null_set = set(positions[:N_NULLS])

        def evaluate(ns):
            ns_frozen = frozenset(ns)
            ct73 = ''.join(CT97[i] for i in range(N) if i not in ns_frozen)
            if len(ct73) != N_PT:
                return 0, 0, 0, ""

            # Decrypt 73-char CT with the given key
            pt73 = decrypt_fn(ct73, key73)

            n1 = sum(1 for p in ns_frozen if p < ENE_START)
            n2 = sum(1 for p in ns_frozen if p < BCL_START)
            total, e, b = count_crib_hits_73(pt73, n1, n2)
            return total, e, b, pt73

        sc, e, b, pt = evaluate(null_set)
        best_sc = sc
        best_mask = set(null_set)
        best_pt = pt
        best_e = e
        best_b = b

        non_null = [i for i in range(N) if i not in null_set]

        for step in range(n_steps):
            T = max(0.01, 1.0 * (1.0 - step / n_steps))

            # Swap: move one position from null to non-null and vice versa
            out_idx = rng.randrange(N_NULLS)
            null_list = sorted(null_set)
            out_pos = null_list[out_idx]

            non_null_list = sorted(set(range(N)) - null_set)
            in_idx = rng.randrange(len(non_null_list))
            in_pos = non_null_list[in_idx]

            null_set.discard(out_pos)
            null_set.add(in_pos)

            new_sc, new_e, new_b, new_pt = evaluate(null_set)
            delta = new_sc - sc

            if delta > 0 or rng.random() < (2.718281828 ** (delta / T) if T > 0 else 0):
                sc = new_sc
                if sc > best_sc:
                    best_sc = sc
                    best_mask = set(null_set)
                    best_pt = new_pt
                    best_e = new_e
                    best_b = new_b
            else:
                null_set.discard(in_pos)
                null_set.add(out_pos)

        if best_sc > best_global_sc:
            best_global_sc = best_sc
            best_global_mask = sorted(best_mask)
            best_global_pt = best_pt
            best_global_e = best_e
            best_global_b = best_b

    return best_global_sc, best_global_e, best_global_b, best_global_mask, best_global_pt


def phase3():
    print()
    print("=" * 70)
    print("PHASE 3: Null-mask SA + running key on 73 chars")
    print("         (20 restarts, 4000 steps each)")
    print("=" * 70)
    print()

    best_global = 0
    best_info = ""
    results = []

    # For each key source, test several starting offsets within the key
    # We need exactly 73 chars of key
    test_configs = []

    for src_name, key_text in KEY_SOURCES.items():
        klen = len(key_text)
        if klen < N_PT:
            # Cyclic wrap
            offsets_to_test = list(range(0, klen, max(1, klen // 10)))
        else:
            # Sample offsets
            n_offsets = klen - N_PT + 1
            if n_offsets <= 20:
                offsets_to_test = list(range(n_offsets))
            else:
                offsets_to_test = list(range(0, n_offsets, max(1, n_offsets // 10)))
            # Always include 0
            if 0 not in offsets_to_test:
                offsets_to_test.insert(0, 0)

        for offset in offsets_to_test:
            if klen >= N_PT:
                key73 = key_text[offset:offset + N_PT]
            else:
                key73 = ''.join(key_text[(offset + i) % klen] for i in range(N_PT))
            test_configs.append((src_name, offset, key73))

    total_configs = len(test_configs) * len(DECRYPT_FUNCS)
    print(f"  Total configs: {total_configs} (key_offsets={len(test_configs)} x variants={len(DECRYPT_FUNCS)})")
    print()

    t0 = time.time()
    done = 0

    for src_name, offset, key73 in test_configs:
        for var_name, decrypt_fn in DECRYPT_FUNCS.items():
            sc, e, b, mask, pt = sa_null_mask_running_key(
                key73, decrypt_fn, n_restarts=20, n_steps=4000, seed=42
            )
            done += 1

            flag = ""
            if sc >= 10:
                flag = " *** SIGNAL ***"
            elif sc >= 8:
                flag = " *"

            if sc >= 7 or done % 50 == 0:
                elapsed = time.time() - t0
                print(f"  [{done}/{total_configs} {elapsed:.0f}s] {src_name:12s} off={offset:4d} "
                      f"{var_name:10s} → {sc:2d}/24 (ene={e}/13 bcl={b}/11){flag}")

            if sc >= 10:
                print(f"    PT  = {pt}")
                print(f"    mask= {mask}")

            if sc > best_global:
                best_global = sc
                best_info = (f"{src_name}/{var_name} offset={offset} "
                             f"score={sc}/24 ene={e}/13 bcl={b}/11")
                results.append({
                    "source": src_name, "variant": var_name, "offset": offset,
                    "score": sc, "ene": e, "bcl": b, "mask": mask, "pt": pt
                })

    elapsed = time.time() - t0
    print(f"\n  PHASE 3 BEST: {best_info} (global={best_global}/24) [{elapsed:.0f}s]")
    return best_global, results


# ══════════════════════════════════════════════════════════════════════════
# PHASE 4: Required key character analysis
# ══════════════════════════════════════════════════════════════════════════

def phase4():
    """For each variant, derive what running key characters are REQUIRED at
    crib positions. Then check if K1/K2/K3 contain those exact characters
    at any alignment."""
    print()
    print("=" * 70)
    print("PHASE 4: Required key analysis (what key chars are needed?)")
    print("=" * 70)
    print()

    variants_for_analysis = {
        "Q2_vig":   lambda ci, pi: (KA_IDX[CT97[ci]] - AZ_IDX[CRIB_DICT[ci]]) % 26,
        "Q2_beau":  lambda ci, pi: (KA_IDX[CT97[ci]] + AZ_IDX[CRIB_DICT[ci]]) % 26,
        # For Q2_beau decrypt: PT = KA[(AZ_IDX[key] - KA_IDX[CT]) % 26]
        # So: AZ_IDX[key] = (KA_IDX[PT] + KA_IDX[CT]) % 26 -- NO
        # Let's derive properly:
        # PT = KA[(AZ_IDX[key] - KA_IDX[CT]) % 26]
        # KA_IDX[PT] = (AZ_IDX[key] - KA_IDX[CT]) % 26
        # AZ_IDX[key] = (KA_IDX[PT] + KA_IDX[CT]) % 26
        "AZ_vig":   lambda ci, pi: (AZ_IDX[CT97[ci]] - AZ_IDX[CRIB_DICT[ci]]) % 26,
        "AZ_beau":  lambda ci, pi: (AZ_IDX[CT97[ci]] + AZ_IDX[CRIB_DICT[ci]]) % 26,
    }

    crib_positions = sorted(CRIB_DICT.keys())

    # Properly derive required key for each variant
    print("  Required key characters at crib positions:")
    print()

    for var_name in ["Q2_vig", "Q2_beau", "AZ_vig", "AZ_beau", "AZ_vbeau"]:
        required_keys = {}
        for pos in crib_positions:
            ct_ch = CT97[pos]
            pt_ch = CRIB_DICT[pos]

            if var_name == "Q2_vig":
                # PT = KA[(KA_IDX[CT] - AZ_IDX[key]) % 26]
                # KA_IDX[PT] = (KA_IDX[CT] - AZ_IDX[key]) % 26
                # AZ_IDX[key] = (KA_IDX[CT] - KA_IDX[PT]) % 26
                k_val = (KA_IDX[ct_ch] - KA_IDX[pt_ch]) % 26
                k_ch = AZ[k_val]  # key is read via AZ
            elif var_name == "Q2_beau":
                # PT = KA[(AZ_IDX[key] - KA_IDX[CT]) % 26]
                # KA_IDX[PT] = (AZ_IDX[key] - KA_IDX[CT]) % 26
                # AZ_IDX[key] = (KA_IDX[PT] + KA_IDX[CT]) % 26
                k_val = (KA_IDX[pt_ch] + KA_IDX[ct_ch]) % 26
                k_ch = AZ[k_val]
            elif var_name == "AZ_vig":
                # PT = AZ[(AZ_IDX[CT] - AZ_IDX[key]) % 26]
                # AZ_IDX[key] = (AZ_IDX[CT] - AZ_IDX[PT]) % 26
                k_val = (AZ_IDX[ct_ch] - AZ_IDX[pt_ch]) % 26
                k_ch = AZ[k_val]
            elif var_name == "AZ_beau":
                # PT = AZ[(AZ_IDX[key] - AZ_IDX[CT]) % 26]
                # AZ_IDX[key] = (AZ_IDX[PT] + AZ_IDX[CT]) % 26
                k_val = (AZ_IDX[pt_ch] + AZ_IDX[ct_ch]) % 26
                k_ch = AZ[k_val]
            elif var_name == "AZ_vbeau":
                # PT = AZ[(AZ_IDX[key] + AZ_IDX[CT]) % 26]
                # AZ_IDX[key] = (AZ_IDX[PT] - AZ_IDX[CT]) % 26
                k_val = (AZ_IDX[pt_ch] - AZ_IDX[ct_ch]) % 26
                k_ch = AZ[k_val]

            required_keys[pos] = k_ch

        key_str = ''.join(required_keys[p] for p in crib_positions)
        print(f"  {var_name:10s}: required key @ cribs = {key_str}")

        # Now check: does any 97-char window of K1+K2+K3 have these chars at positions?
        best_match = 0
        best_off = -1
        for src_name, key_text in KEY_SOURCES.items():
            n_offsets = len(key_text) - N + 1
            if n_offsets < 1:
                continue
            for off in range(n_offsets):
                matches = 0
                for pos in crib_positions:
                    if key_text[off + pos] == required_keys[pos]:
                        matches += 1
                if matches > best_match:
                    best_match = matches
                    best_off = off
                    best_src = src_name

        if best_match >= 4:
            print(f"    Best key alignment: {best_match}/24 matches at {best_src} offset={best_off}")
        else:
            print(f"    Best key alignment: {best_match}/24 (noise)")

    print()
    return


# ══════════════════════════════════════════════════════════════════════════
# PHASE 5: Quagmire II with keyword-mixed CT alphabet
# ══════════════════════════════════════════════════════════════════════════

def phase5():
    """Test Q2 with keyword-mixed alphabets on CT side too.

    Q2 standard: CT alphabet = keyword-mixed (KA), PT alphabet = AZ.
    But what if BOTH alphabets are mixed? Or if the key is read via KA?
    """
    print()
    print("=" * 70)
    print("PHASE 5: Extended Q2 with various alphabet combinations")
    print("=" * 70)
    print()

    # Additional alphabets to try as the CT and key alphabets
    alphs = {
        "AZ": AZ,
        "KA": KA,
    }

    best_global = 0
    best_info = ""

    for ct_alph_name, ct_alph in alphs.items():
        ct_idx = {c: i for i, c in enumerate(ct_alph)}
        for key_alph_name, key_alph in alphs.items():
            key_idx = {c: i for i, c in enumerate(key_alph)}
            for pt_alph_name, pt_alph in alphs.items():
                # Vig-like: PT = pt_alph[(ct_idx[CT] - key_idx[key]) % 26]
                # Beau-like: PT = pt_alph[(key_idx[key] - ct_idx[CT]) % 26]
                for mode in ["vig", "beau"]:
                    label = f"CT={ct_alph_name} Key={key_alph_name} PT={pt_alph_name} {mode}"

                    # Skip pure AZ_vig / AZ_beau (already in phase 1)
                    # and KA/AZ/KA vig (standard Q2, already tested)
                    # Actually let's test all to be thorough

                    for src_name, key_text in KEY_SOURCES.items():
                        n_offsets = len(key_text) - N + 1
                        if n_offsets < 1:
                            continue

                        best_sc = 0
                        best_off = -1

                        for offset in range(n_offsets):
                            key_window = key_text[offset:offset + N]
                            pt_chars = []
                            for i in range(N):
                                ci = ct_idx[CT97[i]]
                                ki = key_idx[key_window[i]]
                                if mode == "vig":
                                    pi = (ci - ki) % 26
                                else:
                                    pi = (ki - ci) % 26
                                pt_chars.append(pt_alph[pi])
                            pt = ''.join(pt_chars)
                            sc = count_crib_hits_97(pt)
                            if sc > best_sc:
                                best_sc = sc
                                best_off = offset
                                best_pt = pt

                        if best_sc > best_global:
                            best_global = best_sc
                            best_info = f"{label} {src_name} offset={best_off} score={best_sc}/24"

                        if best_sc >= 8:
                            print(f"  {label:45s} {src_name:12s} → {best_sc:2d}/24 off={best_off}")

    if best_global >= 7:
        print(f"\n  PHASE 5 BEST: {best_info} (global={best_global}/24)")
    else:
        print(f"\n  PHASE 5: All scores <= {best_global}/24 (noise floor)")

    return best_global


# ══════════════════════════════════════════════════════════════════════════
# PHASE 6: Quagmire III/IV variants with running key
# ══════════════════════════════════════════════════════════════════════════

def phase6():
    """Test Quagmire III (keyword-mixed PT and CT alphabets) and
    Quagmire IV (keyword-mixed PT, CT, and key alphabets).

    Q3: Both alphabets are keyword-mixed; the key letter determines shift.
    Q4: Like Q3 but key is also read through a mixed alphabet.
    """
    print()
    print("=" * 70)
    print("PHASE 6: Quagmire III/IV with K1-K3 running key")
    print("=" * 70)
    print()

    # In Q3, the tableau has mixed alphabet rows, each shifted by the key letter.
    # Encrypt: For key letter K, find K in the base alphabet. Shift the mixed
    #          alphabet by that amount. Read CT from the shifted row at PT position.
    # Decrypt: Reverse the process.

    # Q3 decrypt (both PT and CT alphabet = KA):
    # The indicator row is AZ. For key char k:
    #   shift = AZ.index(k)
    #   shifted_KA[j] = KA[(j + shift) % 26]
    #   CT_char is in shifted_KA at some position j
    #   PT = KA[j]  (since both alphabets are KA)
    # Actually in Q3: PT alph = CT alph = mixed. Key determines row.
    #   j = shifted_KA.index(CT_char) = index in shifted KA
    #   But shifted_KA[j] = KA[(j + shift) % 26] = CT
    #   So KA_IDX[CT] = (j + shift) % 26
    #   j = (KA_IDX[CT] - shift) % 26
    #   PT = KA[j] = KA[(KA_IDX[CT] - AZ_IDX[key]) % 26]

    # Wait -- that's the same as Q2. Q3 is different because the INDICATOR alphabet
    # is also mixed. Let me re-derive:
    #
    # Q2: PT alph = AZ, CT alph = KA, indicator = AZ
    #   Find key in indicator (AZ). Shift CT alphabet (KA).
    #   CT = shifted_KA[AZ_IDX[PT]] where shifted_KA[j] = KA[(j + AZ_IDX[key]) % 26]
    #   So CT = KA[(AZ_IDX[PT] + AZ_IDX[key]) % 26]
    #   Decrypt: AZ_IDX[PT] = (KA_IDX[CT] - AZ_IDX[key]) % 26
    #   PT = AZ[(KA_IDX[CT] - AZ_IDX[key]) % 26]
    #
    # Q3: PT alph = KA, CT alph = KA, indicator = KA
    #   Find key in indicator (KA). Shift CT alphabet (KA).
    #   CT = KA[(KA_IDX[PT] + KA_IDX[key]) % 26]
    #   Decrypt: KA_IDX[PT] = (KA_IDX[CT] - KA_IDX[key]) % 26
    #   PT = KA[(KA_IDX[CT] - KA_IDX[key]) % 26]
    #
    # Q4: like Q3 but key alphabet is different from PT/CT alphabet
    #   Find key in key_alphabet. Use that index as shift.
    #   CT = KA[(KA_IDX[PT] + KEY_IDX[key]) % 26]
    #   Decrypt: PT = KA[(KA_IDX[CT] - KEY_IDX[key]) % 26]

    # So Q3 with KA is: PT = KA[(KA_IDX[CT] - KA_IDX[key]) % 26]
    # This is DIFFERENT from Q2 because key is indexed via KA not AZ.

    best_global = 0
    best_info = ""

    # Test Q3-KA: key indexed via KA
    for mode_name, sign in [("Q3_KA_vig", -1), ("Q3_KA_beau", 1)]:
        for src_name, key_text in KEY_SOURCES.items():
            n_offsets = len(key_text) - N + 1
            if n_offsets < 1:
                continue

            best_sc = 0
            best_off = -1
            best_pt = ""

            for offset in range(n_offsets):
                key_window = key_text[offset:offset + N]
                pt_chars = []
                for i in range(N):
                    ci = KA_IDX[CT97[i]]
                    ki = KA_IDX[key_window[i]]  # Key indexed via KA!
                    if sign == -1:
                        pi = (ci - ki) % 26
                    else:
                        pi = (ki - ci) % 26
                    pt_chars.append(KA[pi])
                pt = ''.join(pt_chars)
                sc = count_crib_hits_97(pt)
                if sc > best_sc:
                    best_sc = sc
                    best_off = offset
                    best_pt = pt

            if best_sc >= 7:
                print(f"  {mode_name:15s} {src_name:12s} → {best_sc:2d}/24 off={best_off}")
            if best_sc > best_global:
                best_global = best_sc
                best_info = f"{mode_name} {src_name} offset={best_off} score={best_sc}/24"

    # Test Q4-like: key indexed via AZ, PT/CT via KA (already done as Q2, skip)
    # Test: key indexed via KA, PT via AZ, CT via KA
    for mode_name, sign in [("Q4_KA_key_AZ_pt_vig", -1), ("Q4_KA_key_AZ_pt_beau", 1)]:
        for src_name, key_text in KEY_SOURCES.items():
            n_offsets = len(key_text) - N + 1
            if n_offsets < 1:
                continue

            best_sc = 0
            best_off = -1

            for offset in range(n_offsets):
                key_window = key_text[offset:offset + N]
                pt_chars = []
                for i in range(N):
                    ci = KA_IDX[CT97[i]]
                    ki = KA_IDX[key_window[i]]
                    if sign == -1:
                        pi = (ci - ki) % 26
                    else:
                        pi = (ki - ci) % 26
                    pt_chars.append(AZ[pi])  # PT via AZ
                pt = ''.join(pt_chars)
                sc = count_crib_hits_97(pt)
                if sc > best_sc:
                    best_sc = sc
                    best_off = offset

            if best_sc >= 7:
                print(f"  {mode_name:30s} {src_name:12s} → {best_sc:2d}/24 off={best_off}")
            if best_sc > best_global:
                best_global = best_sc
                best_info = f"{mode_name} {src_name} offset={best_off} score={best_sc}/24"

    if best_global >= 7:
        print(f"\n  PHASE 6 BEST: {best_info} (global={best_global}/24)")
    else:
        print(f"\n  PHASE 6: All scores <= {best_global}/24 (noise floor)")

    return best_global


# ══════════════════════════════════════════════════════════════════════════
# PHASE 7: Statistics and verification
# ══════════════════════════════════════════════════════════════════════════

def phase7():
    """Print summary statistics and verify key source lengths."""
    print()
    print("=" * 70)
    print("PHASE 7: Key source statistics and expected baseline")
    print("=" * 70)
    print()

    for name, text in KEY_SOURCES.items():
        print(f"  {name:12s}: {len(text):4d} chars, offsets for 97-char: "
              f"{max(0, len(text) - N + 1):4d}, for 73-char: {max(0, len(text) - N_PT + 1):4d}")

    # Expected random score
    print()
    print(f"  Expected random crib matches per trial: {24.0/26:.2f} (24 positions x 1/26 each)")
    print(f"  Noise floor: ~6-7/24 (SA can push random coincidences to ~7)")
    print(f"  Meaningful signal threshold: >=10/24")
    print(f"  Breakthrough: 24/24")

    # Verify K1/K2/K3 text content
    print()
    print(f"  K1 starts: {K1[:30]}...")
    print(f"  K2 starts: {K2[:30]}...")
    print(f"  K3 starts: {K3[:30]}...")
    print(f"  K1+K2+K3:  {len(K123)} chars total")
    print()
    return


# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 70)
    print("  K1-K3 RUNNING KEY ON K4 VIA QUAGMIRE II + VARIANTS")
    print("  Sanborn: 'instructions in the earlier text refer to later text'")
    print("=" * 70)
    print(f"  CT97 = {CT97}")
    print(f"  KA   = {KA}")
    print(f"  AZ   = {AZ}")
    print()

    t_start = time.time()

    phase7()       # Statistics first
    p1 = phase1()  # Direct running key on 97
    p2 = phase2()  # Cyclic key
    p5 = phase5()  # Extended Q2 with all alphabet combos
    p6 = phase6()  # Quagmire III/IV
    p4 = phase4()  # Required key analysis
    p3_score, p3_results = phase3()  # Null-mask SA (slowest)

    elapsed = time.time() - t_start

    print()
    print("=" * 70)
    print("  FINAL SUMMARY")
    print("=" * 70)
    print(f"  Phase 1 (direct 97-char):     best {p1}/24")
    print(f"  Phase 2 (cyclic key):         best {p2}/24")
    print(f"  Phase 5 (extended Q2 combos): best {p5}/24")
    print(f"  Phase 6 (Q3/Q4 variants):     best {p6}/24")
    print(f"  Phase 3 (null-mask SA):        best {p3_score}/24")
    print(f"  Total elapsed: {elapsed:.1f}s")
    print()

    overall_best = max(p1, p2, p3_score, p5, p6)

    verdict = {
        "experiment": "f_k1k3_running_key_q2_v1",
        "overall_best": overall_best,
        "phase1_direct": p1,
        "phase2_cyclic": p2,
        "phase5_extended_q2": p5,
        "phase6_q3q4": p6,
        "phase3_null_mask_sa": p3_score,
        "status": "signal" if overall_best >= 10 else "noise",
        "conclusion": (
            f"K1-K3 running key through Q2/Beau/Vig/Q3/Q4 tableaux: "
            f"best {overall_best}/24. "
            + ("BELOW noise threshold. K1-K3 plaintext is NOT the running key under tested models."
               if overall_best < 10 else
               "ABOVE noise - investigate further!")
        ),
    }

    print("verdict:", json.dumps(verdict, indent=2))
    return overall_best


if __name__ == "__main__":
    main()
