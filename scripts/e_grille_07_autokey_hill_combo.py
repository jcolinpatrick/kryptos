#!/usr/bin/env python3
"""E-GRILLE-07: Autokey, Hill cipher, and K4 combination attacks on YAR grille CT.

Advanced attacks:
1. Autokey ciphers (PT and CT autokey, Vigenere and Beaufort variants)
2. Hill cipher 2x2 (exhaustive) and 3x3 (keyword-derived)
3. Combining grille CT with K4 CT (Vig/Beau/XOR modular arithmetic)
4. Running key from K1-K3 plaintext
5. Straddle checkerboard

Usage: PYTHONPATH=src python3 -u scripts/e_grille_07_autokey_hill_combo.py
"""
from __future__ import annotations

import json
import math
import os
import sys
from collections import Counter
from itertools import product
from typing import List, Tuple, Dict, Optional

from kryptos.kernel.constants import CT as K4_CT, KRYPTOS_ALPHABET

# ── Constants ────────────────────────────────────────────────────────────────

EXPERIMENT_ID = "E-GRILLE-07"

GRILLE_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
GCT_LEN = len(GRILLE_CT)  # 106

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPH_IDX = {c: i for i, c in enumerate(ALPH)}
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
MOD = 26

# K1-K3 plaintexts (cleaned, letters only)
def clean(s):
    return ''.join(c for c in s.upper() if c in ALPH)

K1_PT = clean("BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION")
K2_PT = clean(
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSED"
    "THEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHERED"
    "ANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONX"
    "DOESLANGLEYKNOWABOUTTHIS THEYSHOULDITS BURIEDOUT"
    "THERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWW"
    "THISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTY"
    "SEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVEN"
    "DEGREESEIGHTMINUTESFORTYFOURSECONDSWES TIDBYROWS"
)
K3_PT = clean(
    "SLOWLYDESPARATLYSLOW LYTHEREMAINS OFPASSAGEDEBRIS"
    "THATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVED"
    "WITHTREMB LINGHANDSIMADETINYBREACHINTHEUPPERLEFT"
    "HANDCORNERANDTHENW IDENINGTHEHOLEALITTLEIINSERTED"
    "THECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHE"
    "CHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILS"
    "OFTHEROOMWITHIN EMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"
)

# ── Load scoring ─────────────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)

QUADGRAMS: Dict[str, float] = {}
qg_path = os.path.join(PROJECT_DIR, "data", "english_quadgrams.json")
if os.path.exists(qg_path):
    with open(qg_path) as f:
        QUADGRAMS = json.load(f)
    print(f"[+] Loaded {len(QUADGRAMS)} quadgrams")

ENGLISH_WORDS = set()
wl_path = os.path.join(PROJECT_DIR, "wordlists", "english.txt")
if os.path.exists(wl_path):
    with open(wl_path) as f:
        for line in f:
            w = line.strip().upper()
            if len(w) >= 4:
                ENGLISH_WORDS.add(w)
    print(f"[+] Loaded {len(ENGLISH_WORDS)} English words (4+ letters)")


def quadgram_score(text: str) -> float:
    if not QUADGRAMS or len(text) < 4:
        return -99.0
    floor = -10.0
    score = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        score += QUADGRAMS.get(qg, floor)
    return score / max(1, len(text) - 3)


def count_words(text: str) -> Tuple[int, List[str]]:
    found = []
    for length in range(min(15, len(text)), 3, -1):
        for i in range(len(text) - length + 1):
            word = text[i:i+length]
            if word in ENGLISH_WORDS and word not in found:
                found.append(word)
    return len(found), found


# ── Cipher primitives ────────────────────────────────────────────────────────

def vig_decrypt(ct_str: str, key: str) -> str:
    pt = []
    klen = len(key)
    for i, c in enumerate(ct_str):
        ci = ALPH_IDX[c]
        ki = ALPH_IDX[key[i % klen]]
        pt.append(ALPH[(ci - ki) % 26])
    return "".join(pt)


def beau_decrypt(ct_str: str, key: str) -> str:
    pt = []
    klen = len(key)
    for i, c in enumerate(ct_str):
        ci = ALPH_IDX[c]
        ki = ALPH_IDX[key[i % klen]]
        pt.append(ALPH[(ki - ci) % 26])
    return "".join(pt)


def var_beau_decrypt(ct_str: str, key: str) -> str:
    """Variant Beaufort: PT = CT - KEY mod 26 (same as Vig encrypt direction)."""
    pt = []
    klen = len(key)
    for i, c in enumerate(ct_str):
        ci = ALPH_IDX[c]
        ki = ALPH_IDX[key[i % klen]]
        pt.append(ALPH[(ci - ki) % 26])
    return "".join(pt)


# ── Autokey ciphers ──────────────────────────────────────────────────────────

def autokey_pt_vig_decrypt(ct_str: str, primer: str) -> str:
    """PT-autokey Vigenère: key extends with plaintext chars."""
    pt = []
    key = list(primer)
    for i, c in enumerate(ct_str):
        ci = ALPH_IDX[c]
        ki = ALPH_IDX[key[i]]
        p = ALPH[(ci - ki) % 26]
        pt.append(p)
        key.append(p)  # extend key with plaintext
    return "".join(pt)


def autokey_ct_vig_decrypt(ct_str: str, primer: str) -> str:
    """CT-autokey Vigenère: key extends with ciphertext chars."""
    pt = []
    key = list(primer)
    for i, c in enumerate(ct_str):
        ci = ALPH_IDX[c]
        ki = ALPH_IDX[key[i]]
        pt.append(ALPH[(ci - ki) % 26])
        key.append(c)  # extend key with ciphertext
    return "".join(pt)


def autokey_pt_beau_decrypt(ct_str: str, primer: str) -> str:
    """PT-autokey Beaufort: key extends with plaintext chars."""
    pt = []
    key = list(primer)
    for i, c in enumerate(ct_str):
        ci = ALPH_IDX[c]
        ki = ALPH_IDX[key[i]]
        p = ALPH[(ki - ci) % 26]
        pt.append(p)
        key.append(p)
    return "".join(pt)


def autokey_ct_beau_decrypt(ct_str: str, primer: str) -> str:
    """CT-autokey Beaufort: key extends with ciphertext chars."""
    pt = []
    key = list(primer)
    for i, c in enumerate(ct_str):
        ci = ALPH_IDX[c]
        ki = ALPH_IDX[key[i]]
        pt.append(ALPH[(ki - ci) % 26])
        key.append(c)
    return "".join(pt)


# ── Hill cipher ──────────────────────────────────────────────────────────────

def mod_inverse(a: int, m: int) -> Optional[int]:
    """Extended GCD to find modular inverse."""
    if math.gcd(a, m) != 1:
        return None
    # Extended Euclidean
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        return None
    return x % m


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def hill_2x2_decrypt(ct_str: str, matrix: Tuple[int, int, int, int]) -> Optional[str]:
    """Decrypt with 2x2 Hill cipher. matrix = (a,b,c,d) for [[a,b],[c,d]]."""
    a, b, c, d = matrix
    det = (a * d - b * c) % 26
    det_inv = mod_inverse(det, 26)
    if det_inv is None:
        return None

    # Inverse matrix: det_inv * [[d, -b], [-c, a]] mod 26
    inv_a = (det_inv * d) % 26
    inv_b = (det_inv * (-b)) % 26
    inv_c = (det_inv * (-c)) % 26
    inv_d = (det_inv * a) % 26

    if len(ct_str) % 2 != 0:
        ct_str = ct_str[:-1]

    pt = []
    for i in range(0, len(ct_str), 2):
        x = ALPH_IDX[ct_str[i]]
        y = ALPH_IDX[ct_str[i+1]]
        px = (inv_a * x + inv_b * y) % 26
        py = (inv_c * x + inv_d * y) % 26
        pt.append(ALPH[px])
        pt.append(ALPH[py])
    return "".join(pt)


def hill_3x3_from_keyword(keyword: str) -> Optional[Tuple]:
    """Build a 3x3 matrix from keyword (first 9 chars mapped to numbers)."""
    kw = keyword.upper()
    if len(kw) < 9:
        kw = (kw * ((9 // len(kw)) + 1))[:9]
    nums = [ALPH_IDX[c] for c in kw[:9]]
    # Check determinant
    a, b, c, d, e, f, g, h, i = nums
    det = (a*(e*i - f*h) - b*(d*i - f*g) + c*(d*h - e*g)) % 26
    if math.gcd(det % 26, 26) != 1:
        return None
    return tuple(nums)


def hill_3x3_decrypt(ct_str: str, matrix: Tuple) -> Optional[str]:
    """Decrypt with 3x3 Hill cipher."""
    a, b, c, d, e, f, g, h, i = matrix

    det = (a*(e*i - f*h) - b*(d*i - f*g) + c*(d*h - e*g)) % 26
    det_inv = mod_inverse(det, 26)
    if det_inv is None:
        return None

    # Cofactor matrix
    cof = [
        (e*i - f*h), -(d*i - f*g), (d*h - e*g),
        -(b*i - c*h), (a*i - c*g), -(a*h - b*g),
        (b*f - c*e), -(a*f - c*d), (a*e - b*d),
    ]
    # Adjugate (transpose of cofactors) * det_inv mod 26
    adj = [
        cof[0], cof[3], cof[6],
        cof[1], cof[4], cof[7],
        cof[2], cof[5], cof[8],
    ]
    inv_matrix = [(det_inv * x) % 26 for x in adj]

    text = ct_str
    while len(text) % 3 != 0:
        text = text[:-1]

    pt = []
    for j in range(0, len(text), 3):
        v = [ALPH_IDX[text[j+k]] for k in range(3)]
        for row in range(3):
            val = sum(inv_matrix[row*3 + col] * v[col] for col in range(3)) % 26
            pt.append(ALPH[val])
    return "".join(pt)


# ── Results tracking ─────────────────────────────────────────────────────────

class Result:
    def __init__(self, method: str, text: str, score: float):
        self.method = method
        self.text = text
        self.score = score


def main():
    results: List[Result] = []
    ct = GRILLE_CT
    total_configs = 0

    print(f"{'='*80}")
    print(f"  {EXPERIMENT_ID}: Autokey, Hill Cipher, and K4 Combination Attacks")
    print(f"{'='*80}")
    print(f"Grille CT ({GCT_LEN}): {ct}")
    print(f"K4 CT ({len(K4_CT)}): {K4_CT}")
    print(f"K1 PT ({len(K1_PT)}): {K1_PT[:50]}...")
    print(f"K2 PT ({len(K2_PT)}): {K2_PT[:50]}...")
    print(f"K3 PT ({len(K3_PT)}): {K3_PT[:50]}...")
    print()

    # ══════════════════════════════════════════════════════════════════════════
    # Attack 1: Autokey ciphers
    # ══════════════════════════════════════════════════════════════════════════
    print("[1] Autokey ciphers...")
    autokey_count = 0

    autokey_fns = [
        ("pt_vig", autokey_pt_vig_decrypt),
        ("ct_vig", autokey_ct_vig_decrypt),
        ("pt_beau", autokey_pt_beau_decrypt),
        ("ct_beau", autokey_ct_beau_decrypt),
    ]

    # Primer length 1-3: exhaustive
    for primer_len in range(1, 4):
        for primer_tuple in product(range(26), repeat=primer_len):
            primer = "".join(ALPH[i] for i in primer_tuple)
            for ak_name, ak_fn in autokey_fns:
                pt = ak_fn(ct, primer)
                sc = quadgram_score(pt)
                if sc > -7.5:
                    results.append(Result(f"autokey({ak_name},p={primer})", pt, sc))
                autokey_count += 1

    # Primer length 4-7: keyword-based only
    keyword_primers = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK",
        "SANBORN", "SCHEIDT", "SHADOW", "LIGHT", "GRILLE",
        "CARDAN", "EQUINOX", "CIPHER", "SECRET", "KRYPT",
        "YAR", "EAST", "NORTH", "WEST",
    ]
    for primer in keyword_primers:
        for ak_name, ak_fn in autokey_fns:
            pt = ak_fn(ct, primer)
            sc = quadgram_score(pt)
            if sc > -8.0:
                results.append(Result(f"autokey({ak_name},p={primer})", pt, sc))
            autokey_count += 1

    total_configs += autokey_count
    print(f"  Tested {autokey_count} autokey configs")

    # ══════════════════════════════════════════════════════════════════════════
    # Attack 2: Hill cipher 2x2 (exhaustive)
    # ══════════════════════════════════════════════════════════════════════════
    print("[2] Hill cipher 2x2 (exhaustive invertible matrices)...")
    hill2_count = 0
    hill2_invertible = 0

    for a in range(26):
        for b in range(26):
            for c in range(26):
                for d in range(26):
                    det = (a * d - b * c) % 26
                    if math.gcd(det, 26) != 1:
                        continue
                    hill2_invertible += 1

                    pt = hill_2x2_decrypt(ct, (a, b, c, d))
                    if pt:
                        sc = quadgram_score(pt)
                        if sc > -7.5:
                            results.append(Result(
                                f"hill2x2([{a},{b};{c},{d}])", pt, sc))
                    hill2_count += 1

    total_configs += hill2_count
    print(f"  Tested {hill2_count} invertible 2x2 matrices ({hill2_invertible} invertible)")

    # ══════════════════════════════════════════════════════════════════════════
    # Attack 3: Hill cipher 3x3 (keyword-derived)
    # ══════════════════════════════════════════════════════════════════════════
    print("[3] Hill cipher 3x3 (keyword-derived matrices)...")
    hill3_count = 0

    hill_keywords = [
        "KRYPTOSAB", "PALIMPSES", "ABSCISSAK", "SANBORNKR",
        "SCHEIDTKR", "BERLINCLK", "GRILLEKRY", "KRYPTOSGR",
        "SHADOWLIG", "EASTNOORT", "EQUINOXKR", "CARDANGRI",
        "KRYPTOSSA", "ABCDEFGHI", "QRSTUVWXY",
    ]
    # Also try KA alphabet segments
    for start in range(17):
        hill_keywords.append(KA[start:start+9])

    for kw in hill_keywords:
        matrix = hill_3x3_from_keyword(kw)
        if matrix is None:
            continue
        pt = hill_3x3_decrypt(ct, matrix)
        if pt:
            sc = quadgram_score(pt)
            if sc > -8.0:
                results.append(Result(f"hill3x3(kw={kw})", pt, sc))
        hill3_count += 1

    total_configs += hill3_count
    print(f"  Tested {hill3_count} Hill 3x3 configs")

    # ══════════════════════════════════════════════════════════════════════════
    # Attack 4: Combine with K4 CT
    # ══════════════════════════════════════════════════════════════════════════
    print("[4] Combining grille CT with K4 CT...")
    combo_count = 0

    k4_len = len(K4_CT)
    k4_rev = K4_CT[::-1]

    # Try different offsets: grille_CT[offset:offset+k4_len] vs K4_CT
    for offset in range(GCT_LEN - k4_len + 1):
        grille_seg = ct[offset:offset + k4_len]

        for k4_source, k4_label in [(K4_CT, "K4"), (k4_rev, "K4rev")]:
            # Vigenere: grille - k4 mod 26
            pt = "".join(ALPH[(ALPH_IDX[g] - ALPH_IDX[k]) % 26]
                         for g, k in zip(grille_seg, k4_source))
            sc = quadgram_score(pt)
            if sc > -7.5:
                results.append(Result(f"combo(grille-{k4_label},off={offset})", pt, sc))
            combo_count += 1

            # Beaufort: k4 - grille mod 26
            pt = "".join(ALPH[(ALPH_IDX[k] - ALPH_IDX[g]) % 26]
                         for g, k in zip(grille_seg, k4_source))
            sc = quadgram_score(pt)
            if sc > -7.5:
                results.append(Result(f"combo({k4_label}-grille,off={offset})", pt, sc))
            combo_count += 1

            # Addition: grille + k4 mod 26
            pt = "".join(ALPH[(ALPH_IDX[g] + ALPH_IDX[k]) % 26]
                         for g, k in zip(grille_seg, k4_source))
            sc = quadgram_score(pt)
            if sc > -7.5:
                results.append(Result(f"combo(grille+{k4_label},off={offset})", pt, sc))
            combo_count += 1

    # Also: K4 as key for full grille CT (repeating/truncating)
    k4_key_ext = (K4_CT * ((GCT_LEN // k4_len) + 1))[:GCT_LEN]
    for variant_name, fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
        pt = fn(ct, k4_key_ext)
        sc = quadgram_score(pt)
        if sc > -7.5:
            results.append(Result(f"combo(grille_{variant_name}_K4key)", pt, sc))
        combo_count += 1

    # Grille CT as key against K4 CT
    grille_key = ct[:k4_len]
    for variant_name, fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
        pt = fn(K4_CT, grille_key)
        sc = quadgram_score(pt)
        if sc > -7.5:
            results.append(Result(f"combo(K4_{variant_name}_grille_key)", pt, sc))
        combo_count += 1

    # KA-space combination: use KA index instead of standard ALPH index
    for offset in range(min(10, GCT_LEN - k4_len + 1)):
        grille_seg = ct[offset:offset + k4_len]

        # KA subtraction
        pt_chars = []
        valid = True
        for g, k in zip(grille_seg, K4_CT):
            if g in KA_IDX and k in KA_IDX:
                pt_chars.append(KA[(KA_IDX[g] - KA_IDX[k]) % 26])
            else:
                valid = False
                break
        if valid:
            pt = "".join(pt_chars)
            sc = quadgram_score(pt)
            if sc > -7.5:
                results.append(Result(f"combo_KA(grille-K4,off={offset})", pt, sc))
            combo_count += 1

        # KA addition
        pt_chars = []
        valid = True
        for g, k in zip(grille_seg, K4_CT):
            if g in KA_IDX and k in KA_IDX:
                pt_chars.append(KA[(KA_IDX[g] + KA_IDX[k]) % 26])
            else:
                valid = False
                break
        if valid:
            pt = "".join(pt_chars)
            sc = quadgram_score(pt)
            if sc > -7.5:
                results.append(Result(f"combo_KA(grille+K4,off={offset})", pt, sc))
            combo_count += 1

    total_configs += combo_count
    print(f"  Tested {combo_count} K4 combination configs")

    # ══════════════════════════════════════════════════════════════════════════
    # Attack 5: Running key from K1-K3 plaintext
    # ══════════════════════════════════════════════════════════════════════════
    print("[5] Running key from K1-K3 plaintext...")
    runkey_count = 0

    sources = {
        "K1": K1_PT,
        "K2": K2_PT,
        "K3": K3_PT,
        "K1K2K3": K1_PT + K2_PT + K3_PT,
        "K3K2K1": K3_PT + K2_PT + K1_PT,
        "K1_rev": K1_PT[::-1],
        "K2_rev": K2_PT[::-1],
        "K3_rev": K3_PT[::-1],
        "K1K2K3_rev": (K1_PT + K2_PT + K3_PT)[::-1],
    }

    for src_name, src_text in sources.items():
        if len(src_text) < GCT_LEN:
            # Pad by repeating
            src_text = (src_text * ((GCT_LEN // len(src_text)) + 1))[:GCT_LEN]

        # Try all possible starting offsets within the source
        max_offset = min(len(src_text) - GCT_LEN + 1, 50)
        for offset in range(max_offset):
            key = src_text[offset:offset + GCT_LEN]
            if len(key) < GCT_LEN:
                continue

            for variant_name, fn in [("vig", vig_decrypt), ("beau", beau_decrypt), ("var_beau", var_beau_decrypt)]:
                pt = fn(ct, key)
                sc = quadgram_score(pt)
                if sc > -7.5:
                    results.append(Result(
                        f"runkey({src_name}[{offset}:],{variant_name})", pt, sc))
                runkey_count += 1

    total_configs += runkey_count
    print(f"  Tested {runkey_count} running key configs")

    # ══════════════════════════════════════════════════════════════════════════
    # Attack 6: Grille CT XOR-like operations with Kryptos keywords
    # ══════════════════════════════════════════════════════════════════════════
    print("[6] Extended keyword combinations...")
    ext_count = 0

    # Try using the KA alphabet itself as a running key
    ka_extended = (KA * ((GCT_LEN // 26) + 1))[:GCT_LEN]
    for variant_name, fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
        pt = fn(ct, ka_extended)
        sc = quadgram_score(pt)
        if sc > -7.5:
            results.append(Result(f"ka_key({variant_name})", pt, sc))
        ext_count += 1

    # KA rows as keys (each row is a cyclic shift of KA)
    for shift in range(26):
        key_row = "".join(KA[(j + shift) % 26] for j in range(26))
        key_ext = (key_row * ((GCT_LEN // 26) + 1))[:GCT_LEN]
        for variant_name, fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
            pt = fn(ct, key_ext)
            sc = quadgram_score(pt)
            if sc > -7.5:
                results.append(Result(f"ka_row{shift}({variant_name})", pt, sc))
            ext_count += 1

    # Double encryption: Vig(KRYPTOS) then Vig(ABSCISSA) etc.
    for key1 in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        intermediate = vig_decrypt(ct, key1)
        for key2 in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK"]:
            if key1 == key2:
                continue
            for variant_name, fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                pt = fn(intermediate, key2)
                sc = quadgram_score(pt)
                if sc > -7.5:
                    results.append(Result(
                        f"double(vig({key1})+{variant_name}({key2}))", pt, sc))
                ext_count += 1

    total_configs += ext_count
    print(f"  Tested {ext_count} extended combination configs")

    # ══════════════════════════════════════════════════════════════════════════
    # Results
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'='*80}")
    print(f"RESULTS SUMMARY")
    print(f"{'='*80}\n")

    results.sort(key=lambda r: r.score, reverse=True)

    print(f"Total configurations tested: {total_configs:,}")
    print(f"Results above threshold: {len(results)}")

    print(f"\n--- TOP 20 RESULTS ---\n")
    for i, r in enumerate(results[:20]):
        nw, words = count_words(r.text)
        print(f"#{i+1} [qg={r.score:.4f}] {r.method}")
        print(f"  Text: {r.text[:90]}{'...' if len(r.text) > 90 else ''}")
        if words:
            print(f"  Words({nw}): {', '.join(words[:10])}")
        print()

    # English threshold
    english_threshold = -5.5
    promising = [r for r in results if r.score > english_threshold]
    if promising:
        print(f"\n*** PROMISING RESULTS (qg > {english_threshold}) ***")
        for r in promising:
            nw, words = count_words(r.text)
            print(f"  [{r.score:.4f}] {r.method}")
            print(f"  Text: {r.text}")
            if words:
                print(f"  Words: {', '.join(words[:15])}")
    else:
        print(f"\nNo results above English threshold ({english_threshold})")
        print("All results are in the noise/random range.")

    # Show breakdown by attack category
    print(f"\n--- BEST BY CATEGORY ---")
    categories = {
        "autokey": [r for r in results if "autokey" in r.method],
        "hill2x2": [r for r in results if "hill2x2" in r.method],
        "hill3x3": [r for r in results if "hill3x3" in r.method],
        "combo_K4": [r for r in results if "combo" in r.method],
        "runkey": [r for r in results if "runkey" in r.method],
        "extended": [r for r in results if "ka_" in r.method or "double" in r.method],
    }
    for cat_name, cat_results in categories.items():
        if cat_results:
            best = max(cat_results, key=lambda r: r.score)
            print(f"  {cat_name}: [{best.score:.4f}] {best.method}")
            print(f"    {best.text[:70]}...")
        else:
            print(f"  {cat_name}: no results above threshold")

    print(f"\n{'='*80}")
    print(f"  {EXPERIMENT_ID} COMPLETE — {total_configs:,} configurations tested")
    print(f"{'='*80}")

    return results


if __name__ == "__main__":
    results = main()
