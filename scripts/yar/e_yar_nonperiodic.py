#!/usr/bin/env python3
"""
Cipher: YAR grille
Family: yar
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-YAR-NONPERIODIC: Non-periodic substitution methods on YAR-modified K4 CT.

The YAR hypothesis: at 9 positions where Y, A, or R appear in K4, the carved
character is replaced by the tableau character visible through a grille hole.
This produces a modified CT with an IC spike at period 7 (0.0547 vs 0.0419).

Standard periodic Vigenere/Beaufort did NOT produce consistent keys.  This
script tests non-periodic and variant substitution models.

Approaches tested:
  1. Autokey Vigenere/Beaufort (PT-autokey and CT-autokey)
  2. Progressive key (key shifts +N each cycle)
  3. Running key from sculpture text (K1/K2/K3 PT, tableau rows, Morse)
  4. Interrupted key (skip/reset at YAR positions)
  5. Mixed cipher type (Beaufort at YAR, Vigenere elsewhere, and vice versa)
  6. Grid-position key (row,col in 28x31 grid)
  7. Quagmire variants (I/II/III/IV)
  8. Hill climbing on non-YAR positions with cribs pinned

Run: PYTHONPATH=src python3 -u scripts/e_yar_nonperiodic.py
"""

from __future__ import annotations

import sys
import json
import math
import random
import time
import itertools
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, "src")
from kryptos.kernel.constants import CT as ORIGINAL_CT, CRIB_DICT, KRYPTOS_ALPHABET

# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = KRYPTOS_ALPHABET  # "KRYPTOSABCDEFGHIJLMNQUVWXZ"
N = 97

# YAR-modified CT
MODIFIED_CT = (
    "OBKKUOXOGHULBSOLIFBBWFLJVQQPUNGKSSOTWTQSJQSSEKZZWFTJKLUDIQWINFBNRPVTTMZFPKWGDKZXTJCDIGKUHUXUEKCCD"
)
assert len(MODIFIED_CT) == N

# The 9 YAR modification positions (0-indexed)
YAR_POSITIONS = frozenset([3, 23, 28, 49, 57, 64, 90, 95, 96])

# Cribs (0-indexed): 21-33=EASTNORTHEAST, 63-73=BERLINCLOCK
CRIB_MAP = dict(CRIB_DICT)  # {pos: plaintext_char}
CRIB_ENE = "EASTNORTHEAST"  # positions 21-33
CRIB_BC = "BERLINCLOCK"      # positions 63-73

# K1-K3 plaintexts (for running key)
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELD"
    "XTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATION"
    "XDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWS"
    "THEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTY"
    "SEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTES"
    "FORTYFOURSECONDSWESTXLAYERTWO"
)
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFJPASSAGEDEBABORETURNST"
    "OTHEEARLIESTTASKWASENTALANTSANDHOWTESIDWALLSITTWASFORCED"
    "HEWALLSLOWLYWERECAVINGINTHEYWEREONLYABLETONOTREADITVERYC"
    "LEARLYWASTHEREACHAROOMBEYONDTHECHAMBERQCANYOUSEEANYTHINGQ"
)
MORSE_TEXT = "VIRTUALLYINVISIBLEDIGETALINTERPRETATITSOS"

# KA Vigenere tableau rows (key letter -> shifted KA row)
TABLEAU_ROWS_TEXT = [
    "KRYPTOSABCDEFGHIJLMNQUVWXZ",   # Row A
    "RYPTOSABCDEFGHIJLMNQUVWXZK",   # Row B
    "YPTOSABCDEFGHIJLMNQUVWXZKR",   # Row C
    "PTOSABCDEFGHIJLMNQUVWXZKRY",   # Row D
    "TOSABCDEFGHIJLMNQUVWXZKRYP",   # Row E
    "OSABCDEFGHIJLMNQUVWXZKRYPT",   # Row F
    "SABCDEFGHIJLMNQUVWXZKRYPTO",   # Row G
    "ABCDEFGHIJLMNQUVWXZKRYPTOS",   # Row H
    "BCDEFGHIJLMNQUVWXZKRYPTOSA",   # Row I
    "CDEFGHIJLMNQUVWXZKRYPTOSAB",   # Row J
    "DEFGHIJLMNQUVWXZKRYPTOSABC",   # Row K
    "EFGHIJLMNQUVWXZKRYPTOSABCD",   # Row L
    "FGHIJLMNQUVWXZKRYPTOSABCDE",   # Row M
    "GHIJLMNQUVWXZKRYPTOSABCDEF",   # Row N
    "HIJLMNQUVWXZKRYPTOSABCDEFG",   # Row O
    "IJLMNQUVWXZKRYPTOSABCDEFGH",   # Row P
    "JLMNQUVWXZKRYPTOSABCDEFGHI",   # Row Q
    "LMNQUVWXZKRYPTOSABCDEFGHIJ",   # Row R
    "MNQUVWXZKRYPTOSABCDEFGHIJL",   # Row S
    "NQUVWXZKRYPTOSABCDEFGHIJLM",   # Row T
    "QUVWXZKRYPTOSABCDEFGHIJLMN",   # Row U
    "UVWXZKRYPTOSABCDEFGHIJLMNQ",   # Row V
    "VWXZKRYPTOSABCDEFGHIJLMNQU",   # Row W
    "WXZKRYPTOSABCDEFGHIJLMNQUV",   # Row X
    "XZKRYPTOSABCDEFGHIJLMNQUVW",   # Row Y
    "ZKRYPTOSABCDEFGHIJLMNQUVWX",   # Row Z
]
TABLEAU_FLAT = "".join(TABLEAU_ROWS_TEXT)  # 676 chars for running key

# Keywords to test
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN",
    "SCHEIDT", "BERLIN", "CLOCK", "EAST", "NORTH",
    "LIGHT", "ANTIPODES", "MEDUSA", "ENIGMA", "EQUINOX",
    "IQLUSION", "ILLUSION", "KRYPTOSABCDEFGHIJLMNQUVWXZ",
]

# Grid layout: K4 starts at row 24, col 27 in 28x31 grid
K4_GRID_START_ROW = 24
K4_GRID_START_COL = 27
GRID_WIDTH = 31
GRID_HEIGHT = 28

# ──────────────────────────────────────────────────────────────────────────────
# QUADGRAM SCORER
# ──────────────────────────────────────────────────────────────────────────────

print("Loading quadgrams...", flush=True)
_QUAD = json.loads(Path("data/english_quadgrams.json").read_text())
_FLOOR = min(_QUAD.values()) - 1.0
print(f"  Loaded {len(_QUAD)} quadgrams, floor={_FLOOR:.3f}", flush=True)


def quad_score(text: str) -> float:
    """Total quadgram log-probability."""
    s = text.upper()
    if len(s) < 4:
        return _FLOOR
    return sum(_QUAD.get(s[i : i + 4], _FLOOR) for i in range(len(s) - 3))


def quad_per_char(text: str) -> float:
    """Quadgram score per quadgram position."""
    n = len(text)
    if n < 4:
        return -10.0
    return quad_score(text) / (n - 3)


def ic(text: str) -> float:
    """Index of coincidence."""
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text.upper())
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


# ──────────────────────────────────────────────────────────────────────────────
# CIPHER PRIMITIVES
# ──────────────────────────────────────────────────────────────────────────────


def _idx(alpha: str):
    """Build char->index lookup for an alphabet."""
    return {c: i for i, c in enumerate(alpha)}


AZ_IDX = _idx(AZ)
KA_IDX = _idx(KA)


def vig_enc_char(pt_char: str, key_char: str, alpha: str, aidx: dict) -> str:
    """Encrypt one character with Vigenere."""
    n = len(alpha)
    return alpha[(aidx[pt_char] + aidx[key_char]) % n]


def vig_dec_char(ct_char: str, key_char: str, alpha: str, aidx: dict) -> str:
    """Decrypt one character with Vigenere."""
    n = len(alpha)
    return alpha[(aidx[ct_char] - aidx[key_char]) % n]


def beau_dec_char(ct_char: str, key_char: str, alpha: str, aidx: dict) -> str:
    """Decrypt one character with Beaufort."""
    n = len(alpha)
    return alpha[(aidx[key_char] - aidx[ct_char]) % n]


def varbeau_dec_char(ct_char: str, key_char: str, alpha: str, aidx: dict) -> str:
    """Decrypt one character with Variant Beaufort."""
    n = len(alpha)
    return alpha[(aidx[ct_char] - aidx[key_char]) % n]  # same as vig_dec


def vig_dec(ct: str, key: str, alpha: str = AZ) -> str:
    aidx = _idx(alpha)
    n = len(alpha)
    klen = len(key)
    kv = [aidx[k] for k in key]
    return "".join(alpha[(aidx[c] - kv[i % klen]) % n] for i, c in enumerate(ct))


def beau_dec(ct: str, key: str, alpha: str = AZ) -> str:
    aidx = _idx(alpha)
    n = len(alpha)
    klen = len(key)
    kv = [aidx[k] for k in key]
    return "".join(alpha[(kv[i % klen] - aidx[c]) % n] for i, c in enumerate(ct))


def vig_key_from_ct_pt(ct_char: str, pt_char: str, alpha: str, aidx: dict) -> int:
    """Recover Vigenere key index: k = (CT - PT) mod n."""
    n = len(alpha)
    return (aidx[ct_char] - aidx[pt_char]) % n


def beau_key_from_ct_pt(ct_char: str, pt_char: str, alpha: str, aidx: dict) -> int:
    """Recover Beaufort key index: k = (CT + PT) mod n."""
    n = len(alpha)
    return (aidx[ct_char] + aidx[pt_char]) % n


def varbeau_key_from_ct_pt(ct_char: str, pt_char: str, alpha: str, aidx: dict) -> int:
    """Recover Variant Beaufort key index: k = (PT - CT) mod n."""
    n = len(alpha)
    return (aidx[pt_char] - aidx[ct_char]) % n


# ──────────────────────────────────────────────────────────────────────────────
# HELPER: Derive key at crib positions, check consistency
# ──────────────────────────────────────────────────────────────────────────────


def derive_crib_keys(ct: str, cipher_type: str, alpha: str) -> dict:
    """Derive key values at each crib position. Returns {pos: key_index}."""
    aidx = _idx(alpha)
    result = {}
    for pos, pt_char in CRIB_MAP.items():
        ct_char = ct[pos]
        if cipher_type == "vig":
            result[pos] = vig_key_from_ct_pt(ct_char, pt_char, alpha, aidx)
        elif cipher_type == "beau":
            result[pos] = beau_key_from_ct_pt(ct_char, pt_char, alpha, aidx)
        elif cipher_type == "varbeau":
            result[pos] = varbeau_key_from_ct_pt(ct_char, pt_char, alpha, aidx)
    return result


def check_period_consistency(key_map: dict, period: int) -> tuple:
    """Check if key values are consistent with a given period.
    Returns (n_consistent, n_total, residue_conflicts)."""
    residues = defaultdict(set)
    for pos, kval in key_map.items():
        residues[pos % period].add(kval)
    consistent = sum(1 for s in residues.values() if len(s) == 1)
    conflicts = {r: s for r, s in residues.items() if len(s) > 1}
    total = len(residues)
    return consistent, total, conflicts


# ──────────────────────────────────────────────────────────────────────────────
# GLOBAL RESULTS TRACKING
# ──────────────────────────────────────────────────────────────────────────────

ALL_RESULTS = []


def record_result(approach: str, desc: str, pt: str, qg_score: float, details: str = ""):
    ALL_RESULTS.append({
        "approach": approach,
        "desc": desc,
        "plaintext": pt,
        "qg_per_char": qg_score,
        "details": details,
    })


# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 0: Baseline — periodic Vig/Beaufort on modified CT (for comparison)
# ══════════════════════════════════════════════════════════════════════════════


def test_baseline():
    print("\n" + "=" * 78)
    print("APPROACH 0: BASELINE — Periodic Vig/Beaufort on YAR-modified CT")
    print("=" * 78, flush=True)

    ct = MODIFIED_CT
    best = (-999, "", "", "")

    for cipher_type in ["vig", "beau", "varbeau"]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            key_map = derive_crib_keys(ct, cipher_type, alpha)

            for period in range(1, 27):
                cons, tot, conflicts = check_period_consistency(key_map, period)
                if cons == tot and tot > 0:
                    # Fully consistent — build key and decrypt
                    residues = {}
                    for pos, kval in key_map.items():
                        residues[pos % period] = kval

                    # Check if all residues covered
                    if len(residues) < period:
                        # Try all combos for uncovered residues — too many, skip
                        continue

                    key = "".join(alpha[residues[r]] for r in range(period))
                    if cipher_type == "vig":
                        pt = vig_dec(ct, key, alpha)
                    elif cipher_type == "beau":
                        pt = beau_dec(ct, key, alpha)
                    else:
                        pt = vig_dec(ct, key, alpha)  # varbeau dec = vig dec

                    qg = quad_per_char(pt)
                    if qg > best[0]:
                        best = (qg, pt, f"{cipher_type}/{alpha_name}/p{period}/key={key}", key)

                    if qg > -7.0:
                        print(f"  {cipher_type}/{alpha_name} period {period}: key={key}, qg={qg:.3f}")
                        print(f"    PT: {pt[:60]}...")

    qg, pt, desc, key = best
    print(f"\n  BEST BASELINE: {desc}")
    print(f"    qg/char = {qg:.4f}")
    print(f"    PT: {pt}", flush=True)
    record_result("baseline", desc, pt, qg)


# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 1: Autokey Vigenere/Beaufort
# ══════════════════════════════════════════════════════════════════════════════


def autokey_vig_dec_pt(ct: str, seed: str, alpha: str = AZ) -> str:
    """Autokey Vigenere decryption using plaintext extension.
    Key = seed || PT[0] || PT[1] || ...
    CT[i] = (PT[i] + K[i]) mod 26, so PT[i] = (CT[i] - K[i]) mod 26.
    K[i] = seed[i] for i < len(seed), else PT[i - len(seed)]."""
    aidx = _idx(alpha)
    n = len(alpha)
    slen = len(seed)
    seed_vals = [aidx[c] for c in seed]
    pt = []
    for i, c in enumerate(ct):
        if i < slen:
            k = seed_vals[i]
        else:
            k = aidx[pt[i - slen]]
        pt.append(alpha[(aidx[c] - k) % n])
    return "".join(pt)


def autokey_vig_dec_ct(ct: str, seed: str, alpha: str = AZ) -> str:
    """Autokey Vigenere decryption using ciphertext extension.
    K[i] = seed[i] for i < len(seed), else CT[i - len(seed)]."""
    aidx = _idx(alpha)
    n = len(alpha)
    slen = len(seed)
    seed_vals = [aidx[c] for c in seed]
    pt = []
    for i, c in enumerate(ct):
        if i < slen:
            k = seed_vals[i]
        else:
            k = aidx[ct[i - slen]]
        pt.append(alpha[(aidx[c] - k) % n])
    return "".join(pt)


def autokey_beau_dec_pt(ct: str, seed: str, alpha: str = AZ) -> str:
    """Autokey Beaufort decryption using plaintext extension.
    CT[i] = (K[i] - PT[i]) mod 26, so PT[i] = (K[i] - CT[i]) mod 26."""
    aidx = _idx(alpha)
    n = len(alpha)
    slen = len(seed)
    seed_vals = [aidx[c] for c in seed]
    pt = []
    for i, c in enumerate(ct):
        if i < slen:
            k = seed_vals[i]
        else:
            k = aidx[pt[i - slen]]
        pt.append(alpha[(k - aidx[c]) % n])
    return "".join(pt)


def autokey_beau_dec_ct(ct: str, seed: str, alpha: str = AZ) -> str:
    """Autokey Beaufort decryption using ciphertext extension."""
    aidx = _idx(alpha)
    n = len(alpha)
    slen = len(seed)
    seed_vals = [aidx[c] for c in seed]
    pt = []
    for i, c in enumerate(ct):
        if i < slen:
            k = seed_vals[i]
        else:
            k = aidx[ct[i - slen]]
        pt.append(alpha[(k - aidx[c]) % n])
    return "".join(pt)


def test_autokey():
    print("\n" + "=" * 78)
    print("APPROACH 1: AUTOKEY Vigenere/Beaufort (PT-autokey and CT-autokey)")
    print("=" * 78, flush=True)

    ct = MODIFIED_CT
    best = (-999, "", "", "")

    # Derive seed keys from crib positions for period 7
    # At crib positions, extract what the key WOULD be
    # Then use consecutive crib positions to form 7-letter seeds
    seed_keywords = list(KEYWORDS)

    # Also derive seeds from crib-position key values
    for cipher_type in ["vig", "beau"]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            key_map = derive_crib_keys(ct, cipher_type, alpha)
            # Extract a seed from the first 7 crib positions
            crib_pos_sorted = sorted(key_map.keys())
            if len(crib_pos_sorted) >= 7:
                seed = "".join(alpha[key_map[p]] for p in crib_pos_sorted[:7])
                if seed not in seed_keywords:
                    seed_keywords.append(seed)

    # All autokey variants x all seeds x both alphabets
    autokey_fns = [
        ("autokey_vig_pt", autokey_vig_dec_pt),
        ("autokey_vig_ct", autokey_vig_dec_ct),
        ("autokey_beau_pt", autokey_beau_dec_pt),
        ("autokey_beau_ct", autokey_beau_dec_ct),
    ]

    tested = 0
    for fn_name, fn in autokey_fns:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for seed in seed_keywords:
                # Ensure seed uses only characters in alpha
                if not all(c in alpha for c in seed):
                    continue
                pt = fn(ct, seed, alpha)
                qg = quad_per_char(pt)
                tested += 1

                if qg > best[0]:
                    best = (qg, pt, f"{fn_name}/{alpha_name}/seed={seed}", seed)

                if qg > -6.5:
                    print(f"  {fn_name}/{alpha_name} seed={seed}: qg={qg:.3f}")
                    print(f"    PT: {pt[:60]}...", flush=True)

    # Also try ALL single-letter seeds (length 1)
    for fn_name, fn in autokey_fns:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for seed_char in alpha:
                pt = fn(ct, seed_char, alpha)
                qg = quad_per_char(pt)
                tested += 1
                if qg > best[0]:
                    best = (qg, pt, f"{fn_name}/{alpha_name}/seed={seed_char}", seed_char)

    qg, pt, desc, seed = best
    print(f"\n  BEST AUTOKEY ({tested} tested): {desc}")
    print(f"    qg/char = {qg:.4f}")
    print(f"    PT: {pt}", flush=True)
    record_result("autokey", desc, pt, qg)


# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 2: Progressive key (key shifts each cycle)
# ══════════════════════════════════════════════════════════════════════════════


def progressive_vig_dec(ct: str, key: str, shift: int, alpha: str = AZ) -> str:
    """Vigenere with key that shifts by `shift` positions each full cycle.
    Cycle 0: key as-is. Cycle 1: each key char += shift. Etc."""
    aidx = _idx(alpha)
    n = len(alpha)
    klen = len(key)
    kv = [aidx[c] for c in key]
    pt = []
    for i, c in enumerate(ct):
        cycle = i // klen
        k = (kv[i % klen] + cycle * shift) % n
        pt.append(alpha[(aidx[c] - k) % n])
    return "".join(pt)


def progressive_beau_dec(ct: str, key: str, shift: int, alpha: str = AZ) -> str:
    aidx = _idx(alpha)
    n = len(alpha)
    klen = len(key)
    kv = [aidx[c] for c in key]
    pt = []
    for i, c in enumerate(ct):
        cycle = i // klen
        k = (kv[i % klen] + cycle * shift) % n
        pt.append(alpha[(k - aidx[c]) % n])
    return "".join(pt)


def progressive_vig_dec_perchar(ct: str, key: str, shift: int, alpha: str = AZ) -> str:
    """Progressive key that shifts per character position, not per cycle.
    K[i] = key[i % klen] + (i * shift) mod 26."""
    aidx = _idx(alpha)
    n = len(alpha)
    klen = len(key)
    kv = [aidx[c] for c in key]
    pt = []
    for i, c in enumerate(ct):
        k = (kv[i % klen] + i * shift) % n
        pt.append(alpha[(aidx[c] - k) % n])
    return "".join(pt)


def test_progressive():
    print("\n" + "=" * 78)
    print("APPROACH 2: PROGRESSIVE KEY (key shifts +N each cycle or per-char)")
    print("=" * 78, flush=True)

    ct = MODIFIED_CT
    best = (-999, "", "", "")
    tested = 0

    for cipher_type, fn in [("vig", progressive_vig_dec), ("beau", progressive_beau_dec)]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for kw in KEYWORDS:
                if not all(c in alpha for c in kw):
                    continue
                for shift in range(1, 26):
                    pt = fn(ct, kw, shift, alpha)
                    qg = quad_per_char(pt)
                    tested += 1
                    if qg > best[0]:
                        best = (qg, pt, f"prog_{cipher_type}_cycle/{alpha_name}/key={kw}/shift={shift}", kw)
                    if qg > -6.5:
                        print(f"  prog_{cipher_type}_cycle/{alpha_name} key={kw} shift={shift}: qg={qg:.3f}")
                        print(f"    PT: {pt[:60]}...", flush=True)

    # Per-character progressive
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for kw in KEYWORDS:
            if not all(c in alpha for c in kw):
                continue
            for shift in range(1, 26):
                pt = progressive_vig_dec_perchar(ct, kw, shift, alpha)
                qg = quad_per_char(pt)
                tested += 1
                if qg > best[0]:
                    best = (qg, pt, f"prog_vig_perchar/{alpha_name}/key={kw}/shift={shift}", kw)

    qg, pt, desc, kw = best
    print(f"\n  BEST PROGRESSIVE ({tested} tested): {desc}")
    print(f"    qg/char = {qg:.4f}")
    print(f"    PT: {pt}", flush=True)
    record_result("progressive", desc, pt, qg)


# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 3: Running key from sculpture text
# ══════════════════════════════════════════════════════════════════════════════


def test_running_key():
    print("\n" + "=" * 78)
    print("APPROACH 3: RUNNING KEY from sculpture text")
    print("=" * 78, flush=True)

    ct = MODIFIED_CT
    best = (-999, "", "", "")
    tested = 0

    # Build running key sources
    running_keys = {
        "K1_PT": K1_PT,
        "K2_PT": K2_PT,
        "K3_PT": K3_PT,
        "K1K2K3_PT": K1_PT + K2_PT + K3_PT,
        "K3K2K1_PT": K3_PT + K2_PT + K1_PT,
        "MORSE": MORSE_TEXT,
        "TABLEAU_FLAT": TABLEAU_FLAT,
        "KA_repeated": KA * 4,  # 104 chars
        "K2_PT_rev": K2_PT[::-1],
        "K3_PT_rev": K3_PT[::-1],
        # Tableau row-by-row concatenated (column-reading of tableau)
        "TABLEAU_COLS": "".join(TABLEAU_ROWS_TEXT[r][c] for c in range(26) for r in range(26)),
    }

    # Also add K1/K2/K3 CT
    K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
    K2_CT = (
        "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKK"
        "DQMCPFQZDQMMIAGPFXHQRLGTIMVMZJANQLVKQE"
        "DARVFYQEKJFKLMYZHDVFXUQGKMPFWGHCQDEXT"
        "WRHJIYPVQICYGALFDXTFHKAIIILAEJVABWQSV"
        "DQZVBIRGIMEJFGRMUYNLKFGVHSVCRYPTOIVFE"
        "JVIKQTHVHELKFEIIIGMMPAHSMEKMQEDSQJBGD"
        "NZNQMVSIJZGEHMIZTSFKIYJHIURHPFJIEQEVHEK"
        "UHRFCVWDIIRGXSMJUGCYBWBFCBQRZNCYBGMN"
        "GBHLJM"
    )
    K3_CT = (
        "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA"
        "CHTNREYULDSLLSLLNOHSNOSMRWXMNETP"
        "RNGATIHNRARPESLNNELEBLPIIACAEWMTW"
        "NDITEENRAHCTENEUDRETNHAEOETFOLSED"
        "TIWENHAEIOYTEYQHEENCTAYCREIFTSPAR"
        "DNTHENIGHSKNDFCMRFTNLIRGHFDHRRTS"
        "ETMHSTCSDNLKATEEEMUHNACGCYYINVME"
        "DFXEGAHTDIDNNEXJLSAYQEQTIISLMDQE"
        "FEPHYLKSDQTCNFADPBKFPIMFATLKRYMA"
        "GGEETTCGAIHDDQPFNEHFLIPNAPLPPIGF"
        "VFDEWTSNTASKLNESSHQLMHRDIFRE"
    )
    running_keys["K1_CT"] = K1_CT
    running_keys["K2_CT"] = K2_CT
    running_keys["K3_CT"] = K3_CT
    running_keys["K1K2K3_CT"] = K1_CT + K2_CT + K3_CT

    # Full ciphertext as carved on sculpture
    FULL_CT = K1_CT + K2_CT + K3_CT + ORIGINAL_CT
    running_keys["FULL_CT"] = FULL_CT
    running_keys["FULL_CT_from_K4_start"] = FULL_CT[768:]  # K4 starts at position 768

    for rk_name, rk_text in running_keys.items():
        if len(rk_text) < N:
            # Pad by repeating
            rk_text = (rk_text * ((N // len(rk_text)) + 2))[:N]

        # Try multiple offsets into the running key
        max_offset = min(len(rk_text) - N, 200)
        if max_offset < 0:
            max_offset = 0

        for offset in range(0, max_offset + 1):
            rk_slice = rk_text[offset : offset + N]
            if len(rk_slice) < N:
                continue

            for cipher_type in ["vig", "beau"]:
                for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                    aidx = _idx(alpha)
                    n_alpha = len(alpha)

                    pt_chars = []
                    for i in range(N):
                        ct_c = ct[i]
                        k_c = rk_slice[i]
                        if ct_c not in aidx or k_c not in aidx:
                            pt_chars.append("X")
                            continue
                        if cipher_type == "vig":
                            pt_chars.append(alpha[(aidx[ct_c] - aidx[k_c]) % n_alpha])
                        else:
                            pt_chars.append(alpha[(aidx[k_c] - aidx[ct_c]) % n_alpha])
                    pt = "".join(pt_chars)
                    qg = quad_per_char(pt)
                    tested += 1

                    if qg > best[0]:
                        best = (qg, pt, f"running_{cipher_type}/{alpha_name}/src={rk_name}/off={offset}", rk_name)

                    if qg > -6.5:
                        print(f"  running_{cipher_type}/{alpha_name} src={rk_name} off={offset}: qg={qg:.3f}")
                        print(f"    PT: {pt[:60]}...", flush=True)

    qg, pt, desc, src = best
    print(f"\n  BEST RUNNING KEY ({tested} tested): {desc}")
    print(f"    qg/char = {qg:.4f}")
    print(f"    PT: {pt}", flush=True)
    record_result("running_key", desc, pt, qg)


# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 4: Interrupted key (period-7 key, skip/reset at YAR positions)
# ══════════════════════════════════════════════════════════════════════════════


def test_interrupted_key():
    print("\n" + "=" * 78)
    print("APPROACH 4: INTERRUPTED KEY (period-7 key, skip/reset at YAR positions)")
    print("=" * 78, flush=True)

    ct = MODIFIED_CT
    best = (-999, "", "", "")
    tested = 0

    for cipher_type in ["vig", "beau"]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            aidx = _idx(alpha)
            n_alpha = len(alpha)

            for kw in KEYWORDS:
                if not all(c in alpha for c in kw):
                    continue
                klen = len(kw)
                kv = [aidx[c] for c in kw]

                # Mode 1: Skip YAR positions in key counter
                # (key advances only at non-YAR positions, YAR positions use fixed key=0)
                pt1 = []
                ki = 0
                for i in range(N):
                    if i in YAR_POSITIONS:
                        # YAR position: try key=0 (identity, since grille handles these)
                        k = 0
                    else:
                        k = kv[ki % klen]
                        ki += 1
                    if cipher_type == "vig":
                        pt1.append(alpha[(aidx[ct[i]] - k) % n_alpha])
                    else:
                        pt1.append(alpha[(k - aidx[ct[i]]) % n_alpha])
                pt1 = "".join(pt1)
                qg1 = quad_per_char(pt1)
                tested += 1
                if qg1 > best[0]:
                    best = (qg1, pt1, f"interrupted_skip/{cipher_type}/{alpha_name}/key={kw}", kw)

                # Mode 2: Skip YAR positions in key counter, AND at YAR positions
                # try all 26 possible key values (brute force small)
                # Too expensive for all, just try key = each key letter
                for yar_key_idx in range(26):
                    pt2 = []
                    ki = 0
                    for i in range(N):
                        if i in YAR_POSITIONS:
                            k = yar_key_idx
                        else:
                            k = kv[ki % klen]
                            ki += 1
                        if cipher_type == "vig":
                            pt2.append(alpha[(aidx[ct[i]] - k) % n_alpha])
                        else:
                            pt2.append(alpha[(k - aidx[ct[i]]) % n_alpha])
                    pt2 = "".join(pt2)
                    qg2 = quad_per_char(pt2)
                    tested += 1
                    if qg2 > best[0]:
                        best = (qg2, pt2, f"interrupted_yarkey/{cipher_type}/{alpha_name}/key={kw}/yark={alpha[yar_key_idx]}", kw)

                # Mode 3: Reset key index to 0 at each YAR position
                pt3 = []
                ki = 0
                for i in range(N):
                    if i in YAR_POSITIONS:
                        ki = 0  # reset
                    k = kv[ki % klen]
                    ki += 1
                    if cipher_type == "vig":
                        pt3.append(alpha[(aidx[ct[i]] - k) % n_alpha])
                    else:
                        pt3.append(alpha[(k - aidx[ct[i]]) % n_alpha])
                pt3 = "".join(pt3)
                qg3 = quad_per_char(pt3)
                tested += 1
                if qg3 > best[0]:
                    best = (qg3, pt3, f"interrupted_reset/{cipher_type}/{alpha_name}/key={kw}", kw)

                # Mode 4: Key counter counts ALL positions, but YAR positions
                # get their key from a DIFFERENT keyword
                for kw2 in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                    if not all(c in alpha for c in kw2):
                        continue
                    kv2 = [aidx[c] for c in kw2]
                    klen2 = len(kw2)
                    pt4 = []
                    yi = 0
                    for i in range(N):
                        if i in YAR_POSITIONS:
                            k = kv2[yi % klen2]
                            yi += 1
                        else:
                            k = kv[i % klen]
                        if cipher_type == "vig":
                            pt4.append(alpha[(aidx[ct[i]] - k) % n_alpha])
                        else:
                            pt4.append(alpha[(k - aidx[ct[i]]) % n_alpha])
                    pt4 = "".join(pt4)
                    qg4 = quad_per_char(pt4)
                    tested += 1
                    if qg4 > best[0]:
                        best = (qg4, pt4, f"interrupted_dual/{cipher_type}/{alpha_name}/key1={kw}/key2={kw2}", kw)

                if qg1 > -6.5 or qg3 > -6.5:
                    print(f"  {cipher_type}/{alpha_name} key={kw}: skip={qg1:.3f} reset={qg3:.3f}", flush=True)

    qg, pt, desc, kw = best
    print(f"\n  BEST INTERRUPTED ({tested} tested): {desc}")
    print(f"    qg/char = {qg:.4f}")
    print(f"    PT: {pt}", flush=True)
    record_result("interrupted", desc, pt, qg)


# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 5: Mixed cipher type (Beaufort at YAR positions, Vigenere elsewhere)
# ══════════════════════════════════════════════════════════════════════════════


def test_mixed_cipher():
    print("\n" + "=" * 78)
    print("APPROACH 5: MIXED CIPHER (Beaufort at YAR, Vigenere elsewhere & vice versa)")
    print("=" * 78, flush=True)

    ct = MODIFIED_CT
    best = (-999, "", "", "")
    tested = 0

    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        aidx = _idx(alpha)
        n_alpha = len(alpha)

        for kw in KEYWORDS:
            if not all(c in alpha for c in kw):
                continue
            klen = len(kw)
            kv = [aidx[c] for c in kw]

            # Mode A: Vig everywhere, Beau at YAR
            pt_a = []
            for i in range(N):
                k = kv[i % klen]
                if i in YAR_POSITIONS:
                    pt_a.append(alpha[(k - aidx[ct[i]]) % n_alpha])  # Beaufort
                else:
                    pt_a.append(alpha[(aidx[ct[i]] - k) % n_alpha])  # Vigenere
            pt_a = "".join(pt_a)
            qg_a = quad_per_char(pt_a)
            tested += 1
            if qg_a > best[0]:
                best = (qg_a, pt_a, f"mixed_vig_beau_yar/{alpha_name}/key={kw}", kw)

            # Mode B: Beau everywhere, Vig at YAR
            pt_b = []
            for i in range(N):
                k = kv[i % klen]
                if i in YAR_POSITIONS:
                    pt_b.append(alpha[(aidx[ct[i]] - k) % n_alpha])  # Vigenere
                else:
                    pt_b.append(alpha[(k - aidx[ct[i]]) % n_alpha])  # Beaufort
            pt_b = "".join(pt_b)
            qg_b = quad_per_char(pt_b)
            tested += 1
            if qg_b > best[0]:
                best = (qg_b, pt_b, f"mixed_beau_vig_yar/{alpha_name}/key={kw}", kw)

            # Mode C: Vig at non-YAR with key counter skipping YAR, Beau at YAR with separate counter
            pt_c = []
            ki_main = 0
            ki_yar = 0
            for i in range(N):
                if i in YAR_POSITIONS:
                    k = kv[ki_yar % klen]
                    ki_yar += 1
                    pt_c.append(alpha[(k - aidx[ct[i]]) % n_alpha])  # Beaufort
                else:
                    k = kv[ki_main % klen]
                    ki_main += 1
                    pt_c.append(alpha[(aidx[ct[i]] - k) % n_alpha])  # Vigenere
            pt_c = "".join(pt_c)
            qg_c = quad_per_char(pt_c)
            tested += 1
            if qg_c > best[0]:
                best = (qg_c, pt_c, f"mixed_split_counters/{alpha_name}/key={kw}", kw)

            # Mode D: VarBeau at YAR, Vig elsewhere
            pt_d = []
            for i in range(N):
                k = kv[i % klen]
                if i in YAR_POSITIONS:
                    # Variant Beaufort: PT = CT - K (same as Vig decrypt)
                    pt_d.append(alpha[(aidx[ct[i]] - k) % n_alpha])
                else:
                    pt_d.append(alpha[(aidx[ct[i]] - k) % n_alpha])
            pt_d = "".join(pt_d)
            # This is just regular Vig — skip

    qg, pt, desc, kw = best
    print(f"\n  BEST MIXED ({tested} tested): {desc}")
    print(f"    qg/char = {qg:.4f}")
    print(f"    PT: {pt}", flush=True)
    record_result("mixed_cipher", desc, pt, qg)


# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 6: Grid-position key
# ══════════════════════════════════════════════════════════════════════════════


def test_grid_key():
    print("\n" + "=" * 78)
    print("APPROACH 6: GRID-POSITION KEY (row, col in 28x31 grid)")
    print("=" * 78, flush=True)

    ct = MODIFIED_CT
    best = (-999, "", "", "")
    tested = 0

    # K4 positions in 28x31 grid (K4 starts at row 24, col 27)
    k4_grid_positions = []
    pos = K4_GRID_START_ROW * GRID_WIDTH + K4_GRID_START_COL
    for i in range(N):
        r = pos // GRID_WIDTH
        c = pos % GRID_WIDTH
        k4_grid_positions.append((r, c))
        pos += 1

    # Method A: key = row value
    # Method B: key = col value
    # Method C: key = (row + col) mod 26
    # Method D: key = (row * col) mod 26
    # Method E: key = row value using a keyword-mapped alphabet for row
    # Method F: key = col mod period of keyword

    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        aidx = _idx(alpha)
        n_alpha = len(alpha)

        for method_name, key_fn in [
            ("row", lambda r, c: r % n_alpha),
            ("col", lambda r, c: c % n_alpha),
            ("row+col", lambda r, c: (r + c) % n_alpha),
            ("row*col", lambda r, c: (r * c) % n_alpha),
            ("row-col", lambda r, c: (r - c) % n_alpha),
            ("row_xor_col", lambda r, c: (r ^ c) % n_alpha),
            ("row*31+col", lambda r, c: (r * 31 + c) % n_alpha),
        ]:
            for cipher_type in ["vig", "beau"]:
                pt_chars = []
                for i in range(N):
                    r, c = k4_grid_positions[i]
                    k = key_fn(r, c)
                    if cipher_type == "vig":
                        pt_chars.append(alpha[(aidx[ct[i]] - k) % n_alpha])
                    else:
                        pt_chars.append(alpha[(k - aidx[ct[i]]) % n_alpha])
                pt = "".join(pt_chars)
                qg = quad_per_char(pt)
                tested += 1
                if qg > best[0]:
                    best = (qg, pt, f"grid_{method_name}/{cipher_type}/{alpha_name}", method_name)

        # Method G: Key from KA tableau at grid position
        # The Kryptos tableau row keys run A-Z; column headers run
        # KRYPTOS... At position (r,c), the tableau character is
        # KA_shifted_by_row[col].
        # Specifically: tableau[key_letter][col] = KA[(KA.index(key_letter) + col) % 26]
        # If row index maps to a key letter (rows 1-26 of physical tableau = A-Z)

        # Physical tableau: rows 1-26 map to key letters A-Z, columns 0-25 map to KA positions
        # For K4 grid positions (rows 24-27), map row to key letter
        for cipher_type in ["vig", "beau"]:
            pt_chars = []
            for i in range(N):
                r, c = k4_grid_positions[i]
                # Tableau row key: rows 1-26 => A-Z, row 0 and 27 are headers
                # K4 spans rows 24-27
                if 1 <= r <= 26:
                    key_letter_idx = r - 1  # 0-indexed A=0
                    # Column in tableau: physical columns 1-30 (first col is key letter)
                    # The cipher text column is c+1 in physical, mapping to KA position c
                    tab_col = c  # 0-indexed column of cipher grid
                    # Key value from KA shift: KA[(key_letter_idx + tab_col) % 26]
                    k = (key_letter_idx + tab_col) % n_alpha
                else:
                    k = 0  # header rows, fallback
                if cipher_type == "vig":
                    pt_chars.append(alpha[(aidx[ct[i]] - k) % n_alpha])
                else:
                    pt_chars.append(alpha[(k - aidx[ct[i]]) % n_alpha])
            pt = "".join(pt_chars)
            qg = quad_per_char(pt)
            tested += 1
            if qg > best[0]:
                best = (qg, pt, f"grid_tableau/{cipher_type}/{alpha_name}", "tableau_row_col")

    # Method H: Key from keyword applied to columns
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        aidx = _idx(alpha)
        n_alpha = len(alpha)
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            if not all(c in alpha for c in kw):
                continue
            klen = len(kw)
            kv = [aidx[c] for c in kw]
            for cipher_type in ["vig", "beau"]:
                pt_chars = []
                for i in range(N):
                    r, c = k4_grid_positions[i]
                    k = (kv[c % klen] + r) % n_alpha
                    if cipher_type == "vig":
                        pt_chars.append(alpha[(aidx[ct[i]] - k) % n_alpha])
                    else:
                        pt_chars.append(alpha[(k - aidx[ct[i]]) % n_alpha])
                pt = "".join(pt_chars)
                qg = quad_per_char(pt)
                tested += 1
                if qg > best[0]:
                    best = (qg, pt, f"grid_kw_col/{cipher_type}/{alpha_name}/kw={kw}", kw)

    qg, pt, desc, method = best
    print(f"\n  BEST GRID KEY ({tested} tested): {desc}")
    print(f"    qg/char = {qg:.4f}")
    print(f"    PT: {pt}", flush=True)
    record_result("grid_key", desc, pt, qg)


# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 7: Quagmire variants (I/II/III/IV)
# ══════════════════════════════════════════════════════════════════════════════


def quagmire_I_dec(ct: str, key: str, pt_alpha: str, ct_alpha: str = AZ) -> str:
    """Quagmire I: PT uses keyed alphabet, CT uses standard alphabet.
    Encryption: find PT char in pt_alpha, get its index, shift by key, index into ct_alpha.
    Decryption: reverse."""
    ct_idx = _idx(ct_alpha)
    pt_idx = _idx(pt_alpha)
    n = len(ct_alpha)
    klen = len(key)
    kv = [ct_idx[c] for c in key]
    pt = []
    for i, c in enumerate(ct):
        k = kv[i % klen]
        # CT[i] = ct_alpha[(pt_idx[PT[i]] + k) % n]
        # pt_idx[PT[i]] = (ct_idx[CT[i]] - k) % n
        pos_in_pt_alpha = (ct_idx[c] - k) % n
        pt.append(pt_alpha[pos_in_pt_alpha])
    return "".join(pt)


def quagmire_II_dec(ct: str, key: str, ct_alpha_keyed: str, pt_alpha: str = AZ) -> str:
    """Quagmire II: CT uses keyed alphabet, PT uses standard alphabet.
    The keyed alphabet is shifted by key letter each position."""
    pt_idx = _idx(pt_alpha)
    ct_k_idx = _idx(ct_alpha_keyed)
    n = len(pt_alpha)
    klen = len(key)
    kv = [ct_k_idx[c] for c in key]
    pt = []
    for i, c in enumerate(ct):
        k = kv[i % klen]
        # CT[i] at position ct_k_idx[CT[i]], shifted by key position in keyed alpha
        pos = (ct_k_idx[c] - k) % n
        pt.append(pt_alpha[pos])
    return "".join(pt)


def quagmire_III_dec(ct: str, key: str, keyed_alpha: str) -> str:
    """Quagmire III: Both PT and CT use same keyed alphabet.
    Same as standard Vig but in keyed alphabet space."""
    ka_idx = _idx(keyed_alpha)
    n = len(keyed_alpha)
    klen = len(key)
    kv = [ka_idx[c] for c in key]
    pt = []
    for i, c in enumerate(ct):
        k = kv[i % klen]
        pt.append(keyed_alpha[(ka_idx[c] - k) % n])
    return "".join(pt)


def quagmire_IV_dec(ct: str, key: str, pt_alpha: str, ct_alpha: str) -> str:
    """Quagmire IV: PT and CT use different keyed alphabets."""
    pt_idx_map = _idx(pt_alpha)
    ct_idx_map = _idx(ct_alpha)
    n = len(pt_alpha)
    klen = len(key)
    # Key is indexed in CT alphabet
    kv = [ct_idx_map[c] for c in key]
    pt = []
    for i, c in enumerate(ct):
        k = kv[i % klen]
        pos = (ct_idx_map[c] - k) % n
        pt.append(pt_alpha[pos])
    return "".join(pt)


def test_quagmire():
    print("\n" + "=" * 78)
    print("APPROACH 7: QUAGMIRE VARIANTS (I/II/III/IV)")
    print("=" * 78, flush=True)

    ct = MODIFIED_CT
    best = (-999, "", "", "")
    tested = 0

    # Build some keyed alphabets
    def make_keyed_alpha(keyword: str, base: str = AZ) -> str:
        seen = set()
        result = []
        for c in keyword + base:
            if c not in seen:
                result.append(c)
                seen.add(c)
        return "".join(result)

    keyed_alphas = {
        "KA": KA,
        "KRYPTOS_keyed": make_keyed_alpha("KRYPTOS"),
        "PALIMPSEST_keyed": make_keyed_alpha("PALIMPSEST"),
        "ABSCISSA_keyed": make_keyed_alpha("ABSCISSA"),
        "BERLIN_keyed": make_keyed_alpha("BERLIN"),
        "SHADOW_keyed": make_keyed_alpha("SHADOW"),
    }

    for kw in KEYWORDS:
        if len(kw) > 26:
            continue
        for ka_name, ka in keyed_alphas.items():
            if not all(c in ka for c in kw):
                continue

            # Quagmire I: PT=keyed, CT=AZ
            pt = quagmire_I_dec(ct, kw, ka, AZ)
            qg = quad_per_char(pt)
            tested += 1
            if qg > best[0]:
                best = (qg, pt, f"quagI/pt={ka_name}/ct=AZ/key={kw}", kw)

            # Quagmire II: PT=AZ, CT=keyed
            pt = quagmire_II_dec(ct, kw, ka, AZ)
            qg = quad_per_char(pt)
            tested += 1
            if qg > best[0]:
                best = (qg, pt, f"quagII/pt=AZ/ct={ka_name}/key={kw}", kw)

            # Quagmire III: both keyed
            pt = quagmire_III_dec(ct, kw, ka)
            qg = quad_per_char(pt)
            tested += 1
            if qg > best[0]:
                best = (qg, pt, f"quagIII/alpha={ka_name}/key={kw}", kw)

            # Quagmire IV: PT=AZ, CT=keyed (or PT=keyed, CT=AZ)
            pt = quagmire_IV_dec(ct, kw, AZ, ka)
            qg = quad_per_char(pt)
            tested += 1
            if qg > best[0]:
                best = (qg, pt, f"quagIV/pt=AZ/ct={ka_name}/key={kw}", kw)

            pt = quagmire_IV_dec(ct, kw, ka, AZ)
            qg = quad_per_char(pt)
            tested += 1
            if qg > best[0]:
                best = (qg, pt, f"quagIV/pt={ka_name}/ct=AZ/key={kw}", kw)

        # Also try Quagmire with different keyed alpha for PT vs CT
        for ka_name2, ka2 in keyed_alphas.items():
            if ka_name2 == ka_name:
                continue
            if not all(c in ka for c in kw):
                continue
            pt = quagmire_IV_dec(ct, kw, ka, ka2)
            qg = quad_per_char(pt)
            tested += 1
            if qg > best[0]:
                best = (qg, pt, f"quagIV/pt={ka_name}/ct={ka_name2}/key={kw}", kw)

    qg, pt, desc, kw = best
    print(f"\n  BEST QUAGMIRE ({tested} tested): {desc}")
    print(f"    qg/char = {qg:.4f}")
    print(f"    PT: {pt}", flush=True)
    record_result("quagmire", desc, pt, qg)


# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 8: Hill climbing on non-YAR positions with cribs pinned
# ══════════════════════════════════════════════════════════════════════════════


def test_hillclimb():
    print("\n" + "=" * 78)
    print("APPROACH 8: HILL CLIMBING (optimize full key with cribs pinned)")
    print("=" * 78, flush=True)

    ct = MODIFIED_CT
    best_overall = (-999, "", "", "")

    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for cipher_type in ["vig", "beau"]:
            aidx = _idx(alpha)
            n_alpha = len(alpha)

            # Derive the key value at each crib position
            crib_key = {}
            for pos, pt_char in CRIB_MAP.items():
                ct_char = ct[pos]
                if cipher_type == "vig":
                    crib_key[pos] = vig_key_from_ct_pt(ct_char, pt_char, alpha, aidx)
                else:
                    crib_key[pos] = beau_key_from_ct_pt(ct_char, pt_char, alpha, aidx)

            # Initialize full 97-key array
            key = [0] * N
            for pos, kval in crib_key.items():
                key[pos] = kval

            # Non-crib, non-YAR positions to optimize
            free_positions = [i for i in range(N) if i not in CRIB_MAP]

            # Initialize free positions randomly
            random.seed(42)
            for p in free_positions:
                key[p] = random.randint(0, n_alpha - 1)

            def decrypt_with_key(k):
                pt = []
                for i in range(N):
                    if cipher_type == "vig":
                        pt.append(alpha[(aidx[ct[i]] - k[i]) % n_alpha])
                    else:
                        pt.append(alpha[(k[i] - aidx[ct[i]]) % n_alpha])
                return "".join(pt)

            # Hill climb: randomly change one free position's key, keep if better
            current_key = key[:]
            current_pt = decrypt_with_key(current_key)
            current_score = quad_score(current_pt)
            best_score = current_score
            best_pt = current_pt
            best_key = current_key[:]

            n_iters = 200000
            n_improve = 0
            t0 = time.time()

            for iteration in range(n_iters):
                # Pick a random free position
                pos = random.choice(free_positions)
                old_val = current_key[pos]

                # Try a random new value
                new_val = random.randint(0, n_alpha - 1)
                if new_val == old_val:
                    continue

                current_key[pos] = new_val
                new_pt = decrypt_with_key(current_key)
                new_score = quad_score(new_pt)

                if new_score > current_score:
                    current_score = new_score
                    current_pt = new_pt
                    n_improve += 1
                    if new_score > best_score:
                        best_score = new_score
                        best_pt = new_pt
                        best_key = current_key[:]
                else:
                    # Revert
                    current_key[pos] = old_val

            elapsed = time.time() - t0
            qg = quad_per_char(best_pt)

            desc = f"hillclimb/{cipher_type}/{alpha_name}"
            print(f"  {desc}: {n_iters} iters ({elapsed:.1f}s), {n_improve} improvements")
            print(f"    qg/char = {qg:.4f}, IC = {ic(best_pt):.4f}")
            print(f"    PT: {best_pt}", flush=True)

            # Verify cribs are correct
            crib_ok = all(best_pt[p] == c for p, c in CRIB_MAP.items())
            print(f"    Cribs preserved: {crib_ok}")

            if qg > best_overall[0]:
                best_overall = (qg, best_pt, desc, "")

            # Also do SA (simulated annealing) for deeper exploration
            print(f"  Running SA for {cipher_type}/{alpha_name}...", flush=True)
            sa_key = best_key[:]
            sa_pt = decrypt_with_key(sa_key)
            sa_score = quad_score(sa_pt)
            sa_best_score = sa_score
            sa_best_pt = sa_pt

            temp = 2.0
            cooling = 0.99995
            sa_iters = 300000

            for iteration in range(sa_iters):
                pos = random.choice(free_positions)
                old_val = sa_key[pos]
                new_val = random.randint(0, n_alpha - 1)
                if new_val == old_val:
                    continue

                sa_key[pos] = new_val
                new_pt = decrypt_with_key(sa_key)
                new_score = quad_score(new_pt)

                delta = new_score - sa_score
                if delta > 0 or random.random() < math.exp(delta / max(temp, 0.001)):
                    sa_score = new_score
                    sa_pt = new_pt
                    if new_score > sa_best_score:
                        sa_best_score = new_score
                        sa_best_pt = new_pt
                else:
                    sa_key[pos] = old_val

                temp *= cooling

            qg_sa = quad_per_char(sa_best_pt)
            print(f"  SA {cipher_type}/{alpha_name}: qg/char = {qg_sa:.4f}, IC = {ic(sa_best_pt):.4f}")
            print(f"    PT: {sa_best_pt}", flush=True)
            crib_ok = all(sa_best_pt[p] == c for p, c in CRIB_MAP.items())
            print(f"    Cribs preserved: {crib_ok}")

            if qg_sa > best_overall[0]:
                best_overall = (qg_sa, sa_best_pt, f"SA/{cipher_type}/{alpha_name}", "")

    qg, pt, desc, _ = best_overall
    record_result("hillclimb", desc, pt, qg)


# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 8b: Period-7 key with crib-derived values + brute-force free residues
# ══════════════════════════════════════════════════════════════════════════════


def test_crib_derived_periodic():
    """For each cipher/alpha combo, derive key at crib positions and check
    which periods have consistent key values.  For consistent periods,
    brute-force the remaining residue classes."""
    print("\n" + "=" * 78)
    print("APPROACH 8b: CRIB-DERIVED PERIODIC KEY (brute-force free residues)")
    print("=" * 78, flush=True)

    ct = MODIFIED_CT
    best = (-999, "", "", "")
    tested = 0

    for cipher_type in ["vig", "beau", "varbeau"]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            aidx = _idx(alpha)
            n_alpha = len(alpha)
            key_map = derive_crib_keys(ct, cipher_type, alpha)

            for period in range(2, 20):
                cons, tot, conflicts = check_period_consistency(key_map, period)
                if conflicts:
                    continue  # Not consistent at this period

                # Build the key for covered residues
                residues = {}
                for pos, kval in key_map.items():
                    residues[pos % period] = kval

                # Find uncovered residues
                uncovered = [r for r in range(period) if r not in residues]

                if len(uncovered) > 3:
                    continue  # Too many to brute-force (26^4 = 450K+)

                # Brute-force uncovered residues
                if len(uncovered) == 0:
                    combos = [()]
                else:
                    combos = itertools.product(range(n_alpha), repeat=len(uncovered))

                for combo in combos:
                    full_key = dict(residues)
                    for r, v in zip(uncovered, combo):
                        full_key[r] = v

                    # Decrypt
                    pt_chars = []
                    for i in range(N):
                        k = full_key[i % period]
                        if cipher_type == "vig" or cipher_type == "varbeau":
                            pt_chars.append(alpha[(aidx[ct[i]] - k) % n_alpha])
                        else:
                            pt_chars.append(alpha[(k - aidx[ct[i]]) % n_alpha])
                    pt = "".join(pt_chars)
                    qg = quad_per_char(pt)
                    tested += 1

                    if qg > best[0]:
                        best = (qg, pt, f"periodic_{cipher_type}/{alpha_name}/p={period}", "")
                        key_str = "".join(alpha[full_key[r]] for r in range(period))
                        best = (qg, pt, f"periodic_{cipher_type}/{alpha_name}/p={period}/key={key_str}", key_str)

                    if qg > -6.0:
                        key_str = "".join(alpha[full_key[r]] for r in range(period))
                        print(f"  {cipher_type}/{alpha_name} p={period} key={key_str}: qg={qg:.3f}")
                        print(f"    PT: {pt[:60]}...", flush=True)

    qg, pt, desc, key_str = best
    print(f"\n  BEST CRIB-DERIVED PERIODIC ({tested} tested): {desc}")
    print(f"    qg/char = {qg:.4f}")
    print(f"    PT: {pt}", flush=True)
    record_result("crib_periodic", desc, pt, qg)


# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 9: Key analysis — show key values at all crib positions
# ══════════════════════════════════════════════════════════════════════════════


def analyze_key_structure():
    """Print key values at all crib positions for the modified CT to help
    identify non-periodic structure."""
    print("\n" + "=" * 78)
    print("KEY STRUCTURE ANALYSIS — modified CT crib-derived keys")
    print("=" * 78, flush=True)

    ct = MODIFIED_CT

    for cipher_type in ["vig", "beau"]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            aidx = _idx(alpha)
            key_map = derive_crib_keys(ct, cipher_type, alpha)

            print(f"\n  {cipher_type}/{alpha_name}:")
            print(f"  {'Pos':>4} {'CT':>3} {'PT':>3} {'Key#':>5} {'KeyCh':>6} {'pos%7':>5} {'pos%8':>5} {'pos%10':>6}")
            print(f"  {'----':>4} {'---':>3} {'---':>3} {'-----':>5} {'------':>6} {'-----':>5} {'-----':>5} {'------':>6}")

            for pos in sorted(key_map.keys()):
                kval = key_map[pos]
                print(f"  {pos:4d} {ct[pos]:>3} {CRIB_MAP[pos]:>3} {kval:5d} {alpha[kval]:>6} {pos%7:5d} {pos%8:5d} {pos%10:6d}")

            # Check all periods 1-26
            print(f"\n  Period consistency for {cipher_type}/{alpha_name}:")
            for p in range(1, 27):
                cons, tot, conflicts = check_period_consistency(key_map, p)
                status = "CONSISTENT" if not conflicts else f"{cons}/{tot} ({len(conflicts)} conflicts)"
                if not conflicts:
                    # Show the key
                    residues = {}
                    for pos, kval in key_map.items():
                        residues[pos % p] = kval
                    key_str = "".join(alpha[residues.get(r, 0)] for r in range(p))
                    print(f"    period {p:2d}: {status} key={key_str}")
                elif cons >= tot - 2:
                    print(f"    period {p:2d}: {status}")

            # Check for arithmetic progressions in key values
            sorted_keys = [(pos, key_map[pos]) for pos in sorted(key_map.keys())]
            diffs = [(sorted_keys[i+1][1] - sorted_keys[i][1]) % 26
                     for i in range(len(sorted_keys) - 1)]
            print(f"\n  Key value diffs (consecutive crib positions): {diffs}")

    print(flush=True)


# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 10: Comprehensive autokey with ALL seed lengths 1-13
# ══════════════════════════════════════════════════════════════════════════════


def test_autokey_exhaustive():
    """Try autokey with seeds derived from crib-position key values at all
    possible starting positions."""
    print("\n" + "=" * 78)
    print("APPROACH 10: EXHAUSTIVE AUTOKEY (seeds from crib key values)")
    print("=" * 78, flush=True)

    ct = MODIFIED_CT
    best = (-999, "", "", "")
    tested = 0

    for cipher_type in ["vig", "beau"]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            aidx = _idx(alpha)
            key_map = derive_crib_keys(ct, cipher_type, alpha)

            # Get ordered key values
            ordered = [key_map[p] for p in sorted(key_map.keys())]

            # Try seeds of length 1-13 from consecutive crib key values
            for seed_start in range(24):
                for seed_len in range(1, min(14, 25 - seed_start)):
                    seed = "".join(alpha[ordered[seed_start + j]] for j in range(seed_len))

                    for ak_type, ak_fn in [
                        ("akv_pt", autokey_vig_dec_pt),
                        ("akv_ct", autokey_vig_dec_ct),
                        ("akb_pt", autokey_beau_dec_pt),
                        ("akb_ct", autokey_beau_dec_ct),
                    ]:
                        pt = ak_fn(ct, seed, alpha)
                        qg = quad_per_char(pt)
                        tested += 1
                        if qg > best[0]:
                            best = (qg, pt, f"{ak_type}/{cipher_type}/{alpha_name}/seed={seed}(from_crib@{seed_start})", seed)

    qg, pt, desc, seed = best
    print(f"\n  BEST EXHAUSTIVE AUTOKEY ({tested} tested): {desc}")
    print(f"    qg/char = {qg:.4f}")
    print(f"    PT: {pt}", flush=True)
    record_result("autokey_exhaust", desc, pt, qg)


# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 11: Also test on ORIGINAL (un-modified) CT for comparison
# ══════════════════════════════════════════════════════════════════════════════


def test_original_autokey():
    """Run autokey on the ORIGINAL CT for baseline comparison."""
    print("\n" + "=" * 78)
    print("APPROACH 11: AUTOKEY on ORIGINAL CT (comparison baseline)")
    print("=" * 78, flush=True)

    ct = ORIGINAL_CT
    best = (-999, "", "", "")
    tested = 0

    all_seeds = list(KEYWORDS)
    # Add single letters
    all_seeds += list(AZ)

    for fn_name, fn in [
        ("akv_pt", autokey_vig_dec_pt),
        ("akv_ct", autokey_vig_dec_ct),
        ("akb_pt", autokey_beau_dec_pt),
        ("akb_ct", autokey_beau_dec_ct),
    ]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for seed in all_seeds:
                if not all(c in alpha for c in seed):
                    continue
                pt = fn(ct, seed, alpha)
                qg = quad_per_char(pt)
                tested += 1
                if qg > best[0]:
                    best = (qg, pt, f"ORIG_{fn_name}/{alpha_name}/seed={seed}", seed)

    qg, pt, desc, seed = best
    print(f"\n  BEST ORIGINAL CT AUTOKEY ({tested} tested): {desc}")
    print(f"    qg/char = {qg:.4f}")
    print(f"    PT: {pt}", flush=True)
    record_result("orig_autokey", desc, pt, qg)


# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 12: Gromark / running key with numerical offset
# ══════════════════════════════════════════════════════════════════════════════


def test_gromark():
    """Gromark cipher: key is a running sum (Fibonacci-like) sequence.
    Key[0..n-1] = seed, Key[i] = (Key[i-n] + Key[i-n+1]) mod 10 or mod 26."""
    print("\n" + "=" * 78)
    print("APPROACH 12: GROMARK / FIBONACCI KEY")
    print("=" * 78, flush=True)

    ct = MODIFIED_CT
    best = (-999, "", "", "")
    tested = 0

    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        aidx = _idx(alpha)
        n_alpha = len(alpha)

        # Gromark with seed derived from keyword
        for kw in KEYWORDS:
            if not all(c in alpha for c in kw):
                continue
            seed_vals = [aidx[c] for c in kw]
            klen = len(seed_vals)

            # Extend key using Fibonacci-like recurrence mod 26
            full_key = list(seed_vals)
            while len(full_key) < N:
                next_val = (full_key[-klen] + full_key[-klen + 1]) % n_alpha
                full_key.append(next_val)

            for cipher_type in ["vig", "beau"]:
                pt_chars = []
                for i in range(N):
                    k = full_key[i]
                    if cipher_type == "vig":
                        pt_chars.append(alpha[(aidx[ct[i]] - k) % n_alpha])
                    else:
                        pt_chars.append(alpha[(k - aidx[ct[i]]) % n_alpha])
                pt = "".join(pt_chars)
                qg = quad_per_char(pt)
                tested += 1
                if qg > best[0]:
                    best = (qg, pt, f"gromark_{cipher_type}/{alpha_name}/seed={kw}", kw)

            # Also try additive (all seed chars) recurrence
            full_key2 = list(seed_vals)
            while len(full_key2) < N:
                next_val = sum(full_key2[-klen:]) % n_alpha
                full_key2.append(next_val)

            for cipher_type in ["vig", "beau"]:
                pt_chars = []
                for i in range(N):
                    k = full_key2[i]
                    if cipher_type == "vig":
                        pt_chars.append(alpha[(aidx[ct[i]] - k) % n_alpha])
                    else:
                        pt_chars.append(alpha[(k - aidx[ct[i]]) % n_alpha])
                pt = "".join(pt_chars)
                qg = quad_per_char(pt)
                tested += 1
                if qg > best[0]:
                    best = (qg, pt, f"gromark_additive_{cipher_type}/{alpha_name}/seed={kw}", kw)

    qg, pt, desc, kw = best
    print(f"\n  BEST GROMARK ({tested} tested): {desc}")
    print(f"    qg/char = {qg:.4f}")
    print(f"    PT: {pt}", flush=True)
    record_result("gromark", desc, pt, qg)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════


def main():
    t_start = time.time()

    print("=" * 78)
    print("E-YAR-NONPERIODIC: Non-periodic substitution on YAR-modified K4 CT")
    print("=" * 78)
    print(f"Original CT: {ORIGINAL_CT}")
    print(f"Modified CT: {MODIFIED_CT}")
    print(f"YAR positions: {sorted(YAR_POSITIONS)}")
    print(f"IC original: {ic(ORIGINAL_CT):.4f}")
    print(f"IC modified: {ic(MODIFIED_CT):.4f}")

    # Show the 9 changes
    print("\nYAR changes:")
    for i in sorted(YAR_POSITIONS):
        print(f"  pos {i:2d}: {ORIGINAL_CT[i]} -> {MODIFIED_CT[i]}")
    print(flush=True)

    # Run key structure analysis first
    analyze_key_structure()

    # Run all approaches
    test_baseline()
    test_autokey()
    test_progressive()
    test_running_key()
    test_interrupted_key()
    test_mixed_cipher()
    test_grid_key()
    test_quagmire()
    test_crib_derived_periodic()
    test_autokey_exhaustive()
    test_original_autokey()
    test_gromark()
    test_hillclimb()

    # ── Final Summary ──
    elapsed = time.time() - t_start
    print("\n" + "=" * 78)
    print("FINAL SUMMARY — All approaches ranked by quadgram score")
    print("=" * 78)
    print(f"Total elapsed: {elapsed:.1f}s\n")

    ALL_RESULTS.sort(key=lambda r: r["qg_per_char"], reverse=True)

    print(f"{'Rank':>4} {'qg/char':>8} {'Approach':<20} {'Description'}")
    print(f"{'----':>4} {'-------':>8} {'--------':<20} {'-----------'}")

    for i, r in enumerate(ALL_RESULTS):
        print(f"{i+1:4d} {r['qg_per_char']:8.4f} {r['approach']:<20} {r['desc'][:80]}")

    # Show top 5 plaintexts
    print("\n" + "-" * 78)
    print("TOP 5 PLAINTEXTS:")
    print("-" * 78)
    for i, r in enumerate(ALL_RESULTS[:5]):
        print(f"\n  #{i+1} [{r['approach']}] qg/char={r['qg_per_char']:.4f}")
        print(f"  {r['desc']}")
        print(f"  PT: {r['plaintext']}")
        pt = r["plaintext"]
        print(f"  IC: {ic(pt):.4f}")
        # Check if cribs appear
        for crib_start, crib_text in [(21, CRIB_ENE), (63, CRIB_BC)]:
            actual = pt[crib_start : crib_start + len(crib_text)]
            match = sum(1 for a, b in zip(actual, crib_text) if a == b)
            print(f"  Crib {crib_text}: {match}/{len(crib_text)} at pos {crib_start} (got: {actual})")

    print("\n" + "=" * 78)
    print("ENGLISH REFERENCE: qg/char ~ -4.2, IC ~ 0.067")
    print("RANDOM REFERENCE:  qg/char ~ -10.0, IC ~ 0.038")
    print("=" * 78, flush=True)


if __name__ == "__main__":
    main()
