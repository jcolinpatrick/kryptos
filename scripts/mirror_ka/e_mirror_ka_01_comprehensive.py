#!/usr/bin/env python3
"""Mirror-KA Comprehensive Test

Cipher: Mirror-KA (reversed Kryptos Alphabet)
Family: mirror_ka
Status: active
Keyspace: ~500K+ configs across 6 test categories
Last run: never
Best score: n/a

Tests the reversed KA alphabet as a cipher device:
- The Kryptos tableau is "intentionally flipped" (CIA page)
- Reading from the front reverses every row
- Reversed KA = ZXWVUQNMLJIHGFEDCBASOTYPRK

Test categories:
1. Mirror-KA Vig/Beau/VarBeau with thematic keywords
2. Mirror-KA single-letter keys (period 1)
3. Mirror-KA autokey (PT and CT feedback)
4. Mirror-KA running key from K1/K2/K3 plaintext
5. Cross-alphabet (standard KA + reversed KA)
6. Mirror-KA periodic (periods 2-13) with keywords
7. Bean reversed-KA mod-5 constraint analysis
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, CRIB_WORDS, MOD, ALPH, ALPH_IDX

# ── Alphabets ────────────────────────────────────────────────────────────────

KA_SEQ = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
MIRROR_KA_SEQ = KA_SEQ[::-1]  # ZXWVUQNMLJIHGFEDCBASOTYPRK

assert len(KA_SEQ) == 26 and len(set(KA_SEQ)) == 26
assert len(MIRROR_KA_SEQ) == 26 and len(set(MIRROR_KA_SEQ)) == 26

# Build index tables
KA_IDX = {c: i for i, c in enumerate(KA_SEQ)}
MKA_IDX = {c: i for i, c in enumerate(MIRROR_KA_SEQ)}

print(f"Standard KA:  {KA_SEQ}")
print(f"Reversed KA:  {MIRROR_KA_SEQ}")
print()

# Verify user-provided mappings
print("Reversed KA mapping:")
# Actual reversal of KRYPTOSABCDEFGHIJLMNQUVWXZ = ZXWVUQNMLJIHGFEDCBASOTPYRK
# Note: user provided Y=22,P=23 but actual reversal has P=22,Y=23
# KA ends ...UVWXZ, so reversed starts ZXW... and ends ...OTPYRK
for i, c in enumerate(MIRROR_KA_SEQ):
    print(f"  {c}={i}", end="")
    if (i + 1) % 10 == 0:
        print()
print()
assert MIRROR_KA_SEQ == "ZXWVUQNMLJIHGFEDCBASOTPYRK", f"Unexpected reversal: {MIRROR_KA_SEQ}"
print("  Reversed KA verified: ZXWVUQNMLJIHGFEDCBASOTPYRK")
print()

# ── Crib scoring ─────────────────────────────────────────────────────────────

def crib_score(candidate):
    """Score candidate plaintext against known cribs. Returns (total, ene, bc)."""
    ene = 0
    bc = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(candidate) and candidate[pos] == ch:
            if pos <= 33:
                ene += 1
            else:
                bc += 1
    return ene + bc, ene, bc


def free_crib_score(candidate):
    """Search for cribs at ANY position in candidate. Returns best total."""
    best = 0
    for start, word in CRIB_WORDS:
        for offset in range(len(candidate) - len(word) + 1):
            matches = sum(1 for i, ch in enumerate(word) if candidate[offset + i] == ch)
            best = max(best, matches)
    # Also check substring containment
    for _, word in CRIB_WORDS:
        if word in candidate:
            best = max(best, len(word))
    return best


# ── Cipher functions using arbitrary alphabet indexing ────────────────────────

def decrypt_vig(ct, key, ct_idx, key_idx, alph_seq):
    """Vigenère decrypt: PT_val = (CT_val - KEY_val) mod 26, using given alphabet."""
    result = []
    klen = len(key)
    for i, c in enumerate(ct):
        cv = ct_idx[c]
        kv = key_idx[key[i % klen]]
        pv = (cv - kv) % 26
        result.append(alph_seq[pv])
    return ''.join(result)


def decrypt_beau(ct, key, ct_idx, key_idx, alph_seq):
    """Beaufort decrypt: PT_val = (KEY_val - CT_val) mod 26, using given alphabet."""
    result = []
    klen = len(key)
    for i, c in enumerate(ct):
        cv = ct_idx[c]
        kv = key_idx[key[i % klen]]
        pv = (kv - cv) % 26
        result.append(alph_seq[pv])
    return ''.join(result)


def decrypt_varbeau(ct, key, ct_idx, key_idx, alph_seq):
    """Variant Beaufort decrypt: PT_val = (CT_val + KEY_val) mod 26, using given alphabet."""
    result = []
    klen = len(key)
    for i, c in enumerate(ct):
        cv = ct_idx[c]
        kv = key_idx[key[i % klen]]
        pv = (cv + kv) % 26
        result.append(alph_seq[pv])
    return ''.join(result)


# ── Autokey functions ────────────────────────────────────────────────────────

def decrypt_autokey_pt(ct, seed, ct_idx, key_idx, alph_seq, variant='vig'):
    """Autokey with plaintext feedback."""
    result = []
    key_val = key_idx[seed]
    for i, c in enumerate(ct):
        cv = ct_idx[c]
        if variant == 'vig':
            pv = (cv - key_val) % 26
        elif variant == 'beau':
            pv = (key_val - cv) % 26
        else:  # varbeau
            pv = (cv + key_val) % 26
        pt_char = alph_seq[pv]
        result.append(pt_char)
        key_val = ct_idx[pt_char]  # PT feedback uses same alphabet indexing
    return ''.join(result)


def decrypt_autokey_ct(ct, seed, ct_idx, key_idx, alph_seq, variant='vig'):
    """Autokey with ciphertext feedback."""
    result = []
    key_val = key_idx[seed]
    for i, c in enumerate(ct):
        cv = ct_idx[c]
        if variant == 'vig':
            pv = (cv - key_val) % 26
        elif variant == 'beau':
            pv = (key_val - cv) % 26
        else:  # varbeau
            pv = (cv + key_val) % 26
        result.append(alph_seq[pv])
        key_val = cv  # CT feedback
    return ''.join(result)


# ── K1/K2/K3 Plaintexts ─────────────────────────────────────────────────────

K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUABORDSTHISYOUCANSEEYESCANTLEFTERSEECARTEREXPEDITIONNINETEENTWENTYTWO"
# Remove non-alpha
K1_PT = ''.join(c for c in K1_PT.upper() if c.isalpha())

K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGABORDSKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERE XWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEITGHTMINUTESFORTYFOURSECONDSWEST"
K2_PT = ''.join(c for c in K2_PT.upper() if c.isalpha())

K3_PT = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDABORSWEREBROUGHTTOLIGHTWITHTREMBLITNGHANDSIMADEATINYBREACHINTHECORNERWITHFLAMINGCANDLEIWASPRISENTKNOWKNOWINGANYTHINGMAKECLARYPERHANDSTHEDARKNESSOFMANYCENTURIES"
K3_PT = ''.join(c for c in K3_PT.upper() if c.isalpha())

K123_PT = K1_PT + K2_PT + K3_PT

# ── Keywords to test ─────────────────────────────────────────────────────────

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "KOMPASS", "DEFECTOR", "COLOPHON",
    "BERLIN", "CLOCK", "BERLINCLOCK", "SANBORN", "SCHEIDT", "SHADOW",
    "COMPASS", "GRILLE", "ENIGMA", "SECRET", "HIDDEN", "MASK", "FIVE",
    "NORTH", "EAST", "POINT", "CIPHER", "PUZZLE", "SPHINX", "EGYPT",
    "CARTER", "URANIA", "LODESTONE", "QUARTZ", "HOROLOGE",
    "WELTZEITUHR", "MENGENLEHREUHR", "ALEXANDERPLATZ",
]

VARIANTS = {
    'vig': decrypt_vig,
    'beau': decrypt_beau,
    'varbeau': decrypt_varbeau,
}

# ── Collect results ──────────────────────────────────────────────────────────

all_results = []  # (score, ene, bc, variant, method, key, snippet)
REPORT_THRESHOLD = 6  # Report anything interesting

def record(score, ene, bc, variant, method, key, pt):
    snippet = pt[:40] + "..." if len(pt) > 40 else pt
    all_results.append((score, ene, bc, variant, method, key, snippet, pt))
    if score >= REPORT_THRESHOLD:
        print(f"  ** SCORE {score} (ENE={ene}, BC={bc}) [{variant}] key={key} method={method}")
        print(f"     PT: {pt}")


# ══════════════════════════════════════════════════════════════════════════════
# TEST 1: Mirror-KA Vig/Beau/VarBeau with thematic keywords
# ══════════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("TEST 1: Mirror-KA with thematic keywords")
print("=" * 80)

configs_1 = 0
for kw in KEYWORDS:
    for vname, vfunc in VARIANTS.items():
        pt = vfunc(CT, kw, MKA_IDX, MKA_IDX, MIRROR_KA_SEQ)
        score, ene, bc = crib_score(pt)
        configs_1 += 1
        record(score, ene, bc, vname, "mirror_ka_keyword", kw, pt)

        # Also: key indexed in standard KA, CT indexed in mirror KA
        pt2 = vfunc(CT, kw, MKA_IDX, KA_IDX, MIRROR_KA_SEQ)
        score2, ene2, bc2 = crib_score(pt2)
        configs_1 += 1
        record(score2, ene2, bc2, vname, "mirror_ka_ct+ka_key", kw, pt2)

        # Also: CT indexed in KA, key indexed in mirror KA
        pt3 = vfunc(CT, kw, KA_IDX, MKA_IDX, MIRROR_KA_SEQ)
        score3, ene3, bc3 = crib_score(pt3)
        configs_1 += 1
        record(score3, ene3, bc3, vname, "ka_ct+mirror_ka_key", kw, pt3)

        # Standard AZ indexing but output to mirror KA
        pt4 = vfunc(CT, kw, ALPH_IDX, ALPH_IDX, MIRROR_KA_SEQ)
        score4, ene4, bc4 = crib_score(pt4)
        configs_1 += 1
        record(score4, ene4, bc4, vname, "az_idx_mirror_out", kw, pt4)

        # Mirror KA indexing, AZ output
        pt5 = vfunc(CT, kw, MKA_IDX, MKA_IDX, ALPH)
        score5, ene5, bc5 = crib_score(pt5)
        configs_1 += 1
        record(score5, ene5, bc5, vname, "mirror_idx_az_out", kw, pt5)

print(f"  Tested {configs_1} keyword configs")
print()

# ══════════════════════════════════════════════════════════════════════════════
# TEST 2: Mirror-KA single-letter keys (period 1)
# ══════════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("TEST 2: Mirror-KA single-letter keys (Caesar-like)")
print("=" * 80)

configs_2 = 0
for ch in ALPH:
    for vname, vfunc in VARIANTS.items():
        # All mirror KA
        pt = vfunc(CT, ch, MKA_IDX, MKA_IDX, MIRROR_KA_SEQ)
        score, ene, bc = crib_score(pt)
        configs_2 += 1
        record(score, ene, bc, vname, "mirror_ka_caesar", ch, pt)

        # Mirror KA index, standard AZ output
        pt2 = vfunc(CT, ch, MKA_IDX, MKA_IDX, ALPH)
        score2, ene2, bc2 = crib_score(pt2)
        configs_2 += 1
        record(score2, ene2, bc2, vname, "mirror_idx_az_out_caesar", ch, pt2)

        # AZ index, mirror KA output
        pt3 = vfunc(CT, ch, ALPH_IDX, ALPH_IDX, MIRROR_KA_SEQ)
        score3, ene3, bc3 = crib_score(pt3)
        configs_2 += 1
        record(score3, ene3, bc3, vname, "az_idx_mirror_out_caesar", ch, pt3)

print(f"  Tested {configs_2} single-letter configs")
print()

# ══════════════════════════════════════════════════════════════════════════════
# TEST 3: Mirror-KA autokey
# ══════════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("TEST 3: Mirror-KA autokey (PT and CT feedback)")
print("=" * 80)

configs_3 = 0
for seed in ALPH:
    for variant in ['vig', 'beau', 'varbeau']:
        # PT feedback, all mirror KA
        pt = decrypt_autokey_pt(CT, seed, MKA_IDX, MKA_IDX, MIRROR_KA_SEQ, variant)
        score, ene, bc = crib_score(pt)
        configs_3 += 1
        record(score, ene, bc, variant, "mirror_ka_autokey_pt", seed, pt)

        # CT feedback, all mirror KA
        pt2 = decrypt_autokey_ct(CT, seed, MKA_IDX, MKA_IDX, MIRROR_KA_SEQ, variant)
        score2, ene2, bc2 = crib_score(pt2)
        configs_3 += 1
        record(score2, ene2, bc2, variant, "mirror_ka_autokey_ct", seed, pt2)

        # PT feedback, mirror idx, AZ output
        pt3 = decrypt_autokey_pt(CT, seed, MKA_IDX, MKA_IDX, ALPH, variant)
        score3, ene3, bc3 = crib_score(pt3)
        configs_3 += 1
        record(score3, ene3, bc3, variant, "mirror_autokey_pt_az_out", seed, pt3)

        # CT feedback, mirror idx, AZ output
        pt4 = decrypt_autokey_ct(CT, seed, MKA_IDX, MKA_IDX, ALPH, variant)
        score4, ene4, bc4 = crib_score(pt4)
        configs_3 += 1
        record(score4, ene4, bc4, variant, "mirror_autokey_ct_az_out", seed, pt4)

# Also test autokey with multi-char seeds from keywords
for kw in KEYWORDS[:10]:  # top 10 keywords
    for variant in ['vig', 'beau', 'varbeau']:
        # Extend autokey: use keyword as primer, then PT/CT feedback
        # PT feedback
        pt_chars = []
        key_vals = [MKA_IDX[c] for c in kw]
        for i, c in enumerate(CT):
            cv = MKA_IDX[c]
            if i < len(kw):
                kv = key_vals[i]
            else:
                kv = MKA_IDX[pt_chars[i - len(kw)]]  # PT feedback after primer
            if variant == 'vig':
                pv = (cv - kv) % 26
            elif variant == 'beau':
                pv = (kv - cv) % 26
            else:
                pv = (cv + kv) % 26
            pt_chars.append(MIRROR_KA_SEQ[pv])
        pt = ''.join(pt_chars)
        score, ene, bc = crib_score(pt)
        configs_3 += 1
        record(score, ene, bc, variant, f"mirror_ka_autokey_pt_primer", kw, pt)

        # CT feedback
        pt_chars = []
        for i, c in enumerate(CT):
            cv = MKA_IDX[c]
            if i < len(kw):
                kv = key_vals[i]
            else:
                kv = MKA_IDX[CT[i - len(kw)]]  # CT feedback after primer
            if variant == 'vig':
                pv = (cv - kv) % 26
            elif variant == 'beau':
                pv = (kv - cv) % 26
            else:
                pv = (cv + kv) % 26
            pt_chars.append(MIRROR_KA_SEQ[pv])
        pt = ''.join(pt_chars)
        score, ene, bc = crib_score(pt)
        configs_3 += 1
        record(score, ene, bc, variant, f"mirror_ka_autokey_ct_primer", kw, pt)

print(f"  Tested {configs_3} autokey configs")
print()

# ══════════════════════════════════════════════════════════════════════════════
# TEST 4: Mirror-KA running key from K1/K2/K3 plaintext
# ══════════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("TEST 4: Mirror-KA running key from K1/K2/K3 plaintext")
print("=" * 80)

configs_4 = 0
running_keys = {
    "K1": K1_PT,
    "K2": K2_PT,
    "K3": K3_PT,
    "K123": K123_PT,
    "K1_rev": K1_PT[::-1],
    "K2_rev": K2_PT[::-1],
    "K3_rev": K3_PT[::-1],
    "K123_rev": K123_PT[::-1],
}

for rk_name, rk_text in running_keys.items():
    if len(rk_text) < CT_LEN:
        continue
    # Try all possible offsets into the running key
    max_offset = len(rk_text) - CT_LEN
    for offset in range(max_offset + 1):
        key_seg = rk_text[offset:offset + CT_LEN]
        for vname, vfunc in VARIANTS.items():
            # Mirror KA indexing
            pt = vfunc(CT, key_seg, MKA_IDX, MKA_IDX, MIRROR_KA_SEQ)
            score, ene, bc = crib_score(pt)
            configs_4 += 1
            record(score, ene, bc, vname, f"mirror_ka_running_{rk_name}", f"offset={offset}", pt)

            # Also AZ indexing with mirror output
            pt2 = vfunc(CT, key_seg, ALPH_IDX, ALPH_IDX, MIRROR_KA_SEQ)
            score2, ene2, bc2 = crib_score(pt2)
            configs_4 += 1
            record(score2, ene2, bc2, vname, f"az_running_mirror_out_{rk_name}", f"offset={offset}", pt2)

            # Free crib search too
            fscore = free_crib_score(pt)
            if fscore >= 5:
                print(f"  FREE CRIB {fscore}: [{vname}] {rk_name} offset={offset}: {pt[:60]}...")

            if configs_4 % 10000 == 0:
                print(f"  ... {configs_4} running-key configs tested", flush=True)

print(f"  Tested {configs_4} running-key configs")
print()

# ══════════════════════════════════════════════════════════════════════════════
# TEST 5: Cross-alphabet (standard KA + reversed KA)
# ══════════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("TEST 5: Cross-alphabet (KA × MirrorKA)")
print("=" * 80)

configs_5 = 0
# Quagmire-style: one alphabet for PT axis, different for CT axis
# 4 combinations: (KA,MKA), (MKA,KA), (AZ,MKA), (MKA,AZ)
cross_configs = [
    ("KA_ct,MKA_key", KA_IDX, MKA_IDX, KA_SEQ),
    ("MKA_ct,KA_key", MKA_IDX, KA_IDX, KA_SEQ),
    ("KA_ct,MKA_key,MKA_out", KA_IDX, MKA_IDX, MIRROR_KA_SEQ),
    ("MKA_ct,KA_key,MKA_out", MKA_IDX, KA_IDX, MIRROR_KA_SEQ),
    ("AZ_ct,MKA_key,AZ_out", ALPH_IDX, MKA_IDX, ALPH),
    ("MKA_ct,AZ_key,AZ_out", MKA_IDX, ALPH_IDX, ALPH),
    ("AZ_ct,MKA_key,MKA_out", ALPH_IDX, MKA_IDX, MIRROR_KA_SEQ),
    ("MKA_ct,AZ_key,MKA_out", MKA_IDX, ALPH_IDX, MIRROR_KA_SEQ),
]

for cross_name, ct_idx, key_idx, out_seq in cross_configs:
    for kw in KEYWORDS:
        for vname, vfunc in VARIANTS.items():
            pt = vfunc(CT, kw, ct_idx, key_idx, out_seq)
            score, ene, bc = crib_score(pt)
            configs_5 += 1
            record(score, ene, bc, vname, f"cross_{cross_name}", kw, pt)

    # Also single-letter keys
    for ch in ALPH:
        for vname, vfunc in VARIANTS.items():
            pt = vfunc(CT, ch, ct_idx, key_idx, out_seq)
            score, ene, bc = crib_score(pt)
            configs_5 += 1
            record(score, ene, bc, vname, f"cross_{cross_name}_caesar", ch, pt)

print(f"  Tested {configs_5} cross-alphabet configs")
print()

# ══════════════════════════════════════════════════════════════════════════════
# TEST 6: Mirror-KA periodic (periods 2-13)
# ══════════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("TEST 6: Mirror-KA periodic, periods 2-13")
print("=" * 80)

configs_6 = 0
period_keywords = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "KOMPASS", "DEFECTOR",
    "COLOPHON", "BERLIN", "CLOCK", "BERLINCLOCK", "SANBORN",
    "SCHEIDT", "SHADOW", "COMPASS", "GRILLE", "ENIGMA",
    "SECRET", "HIDDEN", "MASK", "FIVE", "NORTH", "EAST", "POINT",
]

for kw in period_keywords:
    kw_len = len(kw)
    if kw_len < 2 or kw_len > 13:
        continue
    for vname, vfunc in VARIANTS.items():
        # Pure mirror KA
        pt = vfunc(CT, kw, MKA_IDX, MKA_IDX, MIRROR_KA_SEQ)
        score, ene, bc = crib_score(pt)
        configs_6 += 1
        record(score, ene, bc, vname, f"mirror_ka_p{kw_len}", kw, pt)

        # Mirror KA with AZ output
        pt2 = vfunc(CT, kw, MKA_IDX, MKA_IDX, ALPH)
        score2, ene2, bc2 = crib_score(pt2)
        configs_6 += 1
        record(score2, ene2, bc2, vname, f"mirror_ka_p{kw_len}_az_out", kw, pt2)

# Also: systematic period sweep with ALL possible 2-letter keys
for p in range(2, 8):
    print(f"  Period {p}: testing all {26**p} keys...", flush=True)
    if 26**p > 500000:
        print(f"    Skipping (too large: {26**p})")
        continue
    for key_num in range(26**p):
        key = ''
        n = key_num
        for _ in range(p):
            key = MIRROR_KA_SEQ[n % 26] + key
            n //= 26
        for vname, vfunc in VARIANTS.items():
            pt = vfunc(CT, key, MKA_IDX, MKA_IDX, MIRROR_KA_SEQ)
            score, ene, bc = crib_score(pt)
            configs_6 += 1
            if score >= REPORT_THRESHOLD:
                record(score, ene, bc, vname, f"mirror_ka_p{p}_exhaust", key, pt)

print(f"  Tested {configs_6} periodic configs")
print()

# ══════════════════════════════════════════════════════════════════════════════
# TEST 7: Bean reversed-KA mod-5 constraint analysis
# ══════════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("TEST 7: Bean reversed-KA mod-5 analysis")
print("=" * 80)

# First, compute the key values at crib positions under all three variants
# using reversed-KA indexing
print("\nKey values at crib positions (reversed KA indexing):")
print(f"{'Pos':>3} {'CT':>3} {'PT':>3} {'CT_mka':>7} {'PT_mka':>7} {'k_vig':>6} {'k_beau':>7} {'k_vbeau':>8} {'vig%5':>5} {'beau%5':>6} {'vbeau%5':>7}")
print("-" * 90)

vig_keys = {}
beau_keys = {}
vbeau_keys = {}
vig_mod5_count = 0
beau_mod5_count = 0
vbeau_mod5_count = 0

for pos in sorted(CRIB_DICT.keys()):
    ct_ch = CT[pos]
    pt_ch = CRIB_DICT[pos]
    ct_v = MKA_IDX[ct_ch]
    pt_v = MKA_IDX[pt_ch]
    kv = (ct_v - pt_v) % 26
    kb = (ct_v + pt_v) % 26
    kvb = (pt_v - ct_v) % 26
    vig_keys[pos] = kv
    beau_keys[pos] = kb
    vbeau_keys[pos] = kvb
    if kv % 5 == 0:
        vig_mod5_count += 1
    if kb % 5 == 0:
        beau_mod5_count += 1
    if kvb % 5 == 0:
        vbeau_mod5_count += 1
    print(f"{pos:3d} {ct_ch:>3} {pt_ch:>3} {ct_v:7d} {pt_v:7d} {kv:6d} {kb:7d} {kvb:8d} {'*' if kv%5==0 else '':>5} {'*' if kb%5==0 else '':>6} {'*' if kvb%5==0 else '':>7}")

print()
print(f"Vig mod-5 count:    {vig_mod5_count}/24 (expected ~4.8 by chance)")
print(f"Beau mod-5 count:   {beau_mod5_count}/24 (expected ~4.8 by chance)")
print(f"VarBeau mod-5 count:{vbeau_mod5_count}/24 (expected ~4.8 by chance)")

# Also with standard KA indexing
print("\nKey values at crib positions (standard KA indexing):")
ka_vig_mod5 = 0
ka_beau_mod5 = 0
for pos in sorted(CRIB_DICT.keys()):
    ct_ch = CT[pos]
    pt_ch = CRIB_DICT[pos]
    ct_v = KA_IDX[ct_ch]
    pt_v = KA_IDX[pt_ch]
    kv = (ct_v - pt_v) % 26
    kb = (ct_v + pt_v) % 26
    if kv % 5 == 0:
        ka_vig_mod5 += 1
    if kb % 5 == 0:
        ka_beau_mod5 += 1
print(f"Standard KA Vig mod-5:  {ka_vig_mod5}/24")
print(f"Standard KA Beau mod-5: {ka_beau_mod5}/24")

# Also with standard AZ indexing
print("\nKey values at crib positions (standard AZ indexing):")
az_vig_mod5 = 0
az_beau_mod5 = 0
for pos in sorted(CRIB_DICT.keys()):
    ct_ch = CT[pos]
    pt_ch = CRIB_DICT[pos]
    ct_v = ALPH_IDX[ct_ch]
    pt_v = ALPH_IDX[pt_ch]
    kv = (ct_v - pt_v) % 26
    kb = (ct_v + pt_v) % 26
    if kv % 5 == 0:
        az_vig_mod5 += 1
    if kb % 5 == 0:
        az_beau_mod5 += 1
print(f"Standard AZ Vig mod-5:  {az_vig_mod5}/24")
print(f"Standard AZ Beau mod-5: {az_beau_mod5}/24")

# Search for keywords where key values at crib positions are multiples of 5
print("\n\nSearching for keywords with high mod-5 alignment (reversed KA)...")

# Build a broader keyword list
import itertools
broad_keywords = list(KEYWORDS)
# Add 3-7 letter combos from letters that map to multiples of 5 in reversed KA
mod5_chars = [MIRROR_KA_SEQ[i] for i in range(26) if i % 5 == 0]
print(f"Characters with MKA index divisible by 5: {mod5_chars}")
# That's Z(0), Q(5), I(10), D(15), O(20), K(25) → also 0 mod 5

# For each keyword, check how many crib-position key values are mod-5
print("\nKeyword mod-5 alignment scores (reversed KA, Vig):")
mod5_results = []
for kw in KEYWORDS:
    kw_len = len(kw)
    count = 0
    for pos in sorted(CRIB_DICT.keys()):
        kv = MKA_IDX[kw[pos % kw_len]]
        if kv % 5 == 0:
            count += 1
    mod5_results.append((count, kw))
mod5_results.sort(reverse=True)
for count, kw in mod5_results[:15]:
    print(f"  {kw:20s}: {count}/24 key positions are mod-5 (kw_len={len(kw)})")

# Now: if the cipher is Vig with reversed KA, and key values at crib positions
# should produce the right keystream values, what key characters are needed?
print("\n\nRequired key characters at crib positions (Vig, reversed KA):")
print("  If periodic key of period P, then key[pos % P] must equal:")
for pos in sorted(CRIB_DICT.keys()):
    kv = vig_keys[pos]
    key_char = MIRROR_KA_SEQ[kv]
    print(f"  pos {pos:2d} (pos%7={pos%7}): key_val={kv:2d} → key_char={key_char} (mod5={'YES' if kv%5==0 else 'no'})")

# Check: for period 7 (KRYPTOS length), do key[pos%7] values agree?
print("\nConsistency check for period 7 (Vig, reversed KA):")
for r in range(7):
    positions_in_residue = [p for p in sorted(CRIB_DICT.keys()) if p % 7 == r]
    if positions_in_residue:
        vals = [vig_keys[p] for p in positions_in_residue]
        chars = [MIRROR_KA_SEQ[v] for v in vals]
        consistent = len(set(vals)) == 1
        print(f"  residue {r}: positions {positions_in_residue} → key_vals {vals} → chars {chars} → {'CONSISTENT' if consistent else 'CONFLICT'}")

print("\nConsistency check for period 7 (Beau, reversed KA):")
for r in range(7):
    positions_in_residue = [p for p in sorted(CRIB_DICT.keys()) if p % 7 == r]
    if positions_in_residue:
        vals = [beau_keys[p] for p in positions_in_residue]
        chars = [MIRROR_KA_SEQ[v] for v in vals]
        consistent = len(set(vals)) == 1
        print(f"  residue {r}: positions {positions_in_residue} → key_vals {vals} → chars {chars} → {'CONSISTENT' if consistent else 'CONFLICT'}")

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("SUMMARY OF ALL RESULTS")
print("=" * 80)

total = len(all_results)
above_noise = [(s, e, b, v, m, k, sn, pt) for s, e, b, v, m, k, sn, pt in all_results if s >= 6]
above_store = [(s, e, b, v, m, k, sn, pt) for s, e, b, v, m, k, sn, pt in all_results if s >= 10]

print(f"\nTotal configurations tested: {configs_1 + configs_2 + configs_3 + configs_4 + configs_5 + configs_6}")
print(f"Results collected: {total}")
print(f"Score >= 6 (above noise): {len(above_noise)}")
print(f"Score >= 10 (storable): {len(above_store)}")

if above_noise:
    print("\nAll results with score >= 6:")
    above_noise.sort(key=lambda x: -x[0])
    for s, e, b, v, m, k, sn, pt in above_noise[:50]:
        print(f"  Score {s:2d} (ENE={e:2d}, BC={b:2d}) [{v:8s}] method={m:30s} key={k}")
        print(f"    PT: {pt}")

if above_store:
    print("\n*** SIGNIFICANT RESULTS (score >= 10) ***")
    above_store.sort(key=lambda x: -x[0])
    for s, e, b, v, m, k, sn, pt in above_store:
        print(f"  Score {s:2d} (ENE={e:2d}, BC={b:2d}) [{v:8s}] method={m} key={k}")
        print(f"    PT: {pt}")

# Score distribution
from collections import Counter
score_dist = Counter(s for s, _, _, _, _, _, _, _ in all_results)
print("\nScore distribution:")
for score in sorted(score_dist.keys()):
    count = score_dist[score]
    if count > 0:
        bar = '#' * min(count, 50)
        print(f"  {score:2d}: {count:6d} {bar}")

# Bean equality check on any score >= 6 results
if above_noise:
    print("\nBean equality check (k[27]==k[65]) on results with score >= 6:")
    for s, e, b, v, m, k_str, sn, pt in above_noise[:20]:
        # Recompute key values at 27 and 65
        k27_vig = (MKA_IDX[CT[27]] - MKA_IDX[pt[27]]) % 26
        k65_vig = (MKA_IDX[CT[65]] - MKA_IDX[pt[65]]) % 26
        k27_beau = (MKA_IDX[CT[27]] + MKA_IDX[pt[27]]) % 26
        k65_beau = (MKA_IDX[CT[65]] + MKA_IDX[pt[65]]) % 26
        bean_vig = "PASS" if k27_vig == k65_vig else "FAIL"
        bean_beau = "PASS" if k27_beau == k65_beau else "FAIL"
        print(f"  Score {s}: Bean(vig)={bean_vig} (k27={k27_vig},k65={k65_vig}) Bean(beau)={bean_beau} (k27={k27_beau},k65={k65_beau})")

print("\n\nDone.")
