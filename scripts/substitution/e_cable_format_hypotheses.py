#!/usr/bin/env python3
"""
E-CABLE-FORMAT: Test Cold War cable format hypotheses against K4.

Hypotheses:
  1. INDICATOR GROUP: First 5 chars (OBKRU) are a key indicator, not message.
     Real CT starts at position 5. Cribs shift by -5.
  2. X SEPARATORS: If plaintext contains X at separator positions (like K2),
     we can constrain the key at those positions. Test: W positions in CT
     decrypt to X in PT (telegram convention).
  3. DRYAD OFFSET: "T IS YOUR POSITION" = start reading at position T=19.
     Rotate CT by 19 before decryption.
  4. FIVE-LETTER GROUPS: CT was transmitted in groups of 5.
     Test columnar width 5, 10, 20 transpositions.
  5. INDICATOR + SKIP: First 5 are indicator, last 2 are padding (95 remains,
     or 73 message after removing 24 nulls from the 92 non-indicator chars).
  6. Q/X TERMINATORS: Last char of plaintext is Q (like K3) or X.
     If position 96→Q or 96→X, that constrains the key at position 96.
  7. COMBINED: null mask + indicator skip + cable-style transposition

Cipher: cable-format
Family: substitution
Status: active
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CRIB_DICT

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

DEFECTOR_NULLS = [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96]
W_POSITIONS = [20, 36, 48, 58, 74]

def vig(ct, key, a):
    return "".join(a[(a.index(c) - a.index(key[i%len(key)])) % 26] for i, c in enumerate(ct))
def beau(ct, key, a):
    return "".join(a[(a.index(key[i%len(key)]) - a.index(c)) % 26] for i, c in enumerate(ct))
def vbeau(ct, key, a):
    return "".join(a[(a.index(c) + a.index(key[i%len(key)])) % 26] for i, c in enumerate(ct))
def avig(ct, key, a):
    pt, fk = [], list(key)
    for i, c in enumerate(ct):
        p = (a.index(c) - a.index(fk[i])) % 26
        pt.append(a[p]); fk.append(a[p])
    return "".join(pt)
def abeau(ct, key, a):
    pt, fk = [], list(key)
    for i, c in enumerate(ct):
        p = (a.index(fk[i]) - a.index(c)) % 26
        pt.append(a[p]); fk.append(a[p])
    return "".join(pt)

def col_undo(ct, w):
    n = len(ct); rows = -(-n // w); rem = n % w
    r = [''] * n; pos = 0
    for c in range(w):
        cl = rows if (rem == 0 or c < rem) else rows - 1
        for row in range(cl):
            r[row * w + c] = ct[pos]; pos += 1
    return "".join(r)

def rotate(ct, offset):
    """Rotate CT by offset positions (circular shift)."""
    n = len(ct)
    offset = offset % n
    return ct[offset:] + ct[:offset]

def score(pt, cribs):
    s = sorted(cribs.keys())
    if len(s) < 2:
        return 0, 0, 0
    # Find split point between ENE and BC
    # ENE positions are the first contiguous block, BC the second
    ene_p = [p for p in s if p <= s[0] + 15][:13]
    bc_p = [p for p in s if p not in ene_p][:11]
    ene = sum(1 for p in ene_p if p < len(pt) and pt[p] == cribs[p])
    bc = sum(1 for p in bc_p if p < len(pt) and pt[p] == cribs[p])
    return ene + bc, ene, bc

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "KOMPASS",
            "COLOPHON", "SHADOW", "INVISIBLE", "NORTHWEST", "COPPER",
            "HIDDEN", "SECRET", "LANGLEY", "OLYMPUS", "HANDLER",
            "LAYERTWO", "BERLINCLOCK", "EASTNORTHEAST", "POSITION",
            "MERCURY", "PHOENIX", "CENTRAL", "AGENCY", "TELEGRAM",
            "CABLE", "OBKRU", "REPORT", "SIGNAL"]

CIPHERS = [
    ("vig_AZ", vig, AZ), ("beau_AZ", beau, AZ), ("vbeau_AZ", vbeau, AZ),
    ("vig_KA", vig, KA), ("beau_KA", beau, KA),
    ("avig_AZ", avig, AZ), ("abeau_AZ", abeau, AZ),
    ("avig_KA", avig, KA), ("abeau_KA", abeau, KA),
]

TRANS = [
    ("none", lambda ct: ct),
    ("col5", lambda ct: col_undo(ct, 5)),
    ("col7", lambda ct: col_undo(ct, 7)),
    ("col9", lambda ct: col_undo(ct, 9)),
    ("col10", lambda ct: col_undo(ct, 10)),
]

results = []
tested = 0


def test_config(ct_text, cribs, label, extra_trans=None):
    global tested
    for tn, tf in (extra_trans or TRANS):
        wct = tf(ct_text)
        for kw in KEYWORDS:
            for cn, cf, alpha in CIPHERS:
                try:
                    pt = cf(wct, kw, alpha)
                except:
                    continue
                tested += 1
                s, ene, bc = score(pt, cribs)
                if s >= 6:
                    results.append((s, ene, bc, f"{label}+{tn}+{kw}:{cn}", pt[:50]))


def test_batch(ct_text, cribs, label):
    """Test a CT/crib combo through all transpositions and ciphers."""
    for tn, tf in TRANS:
        wct = tf(ct_text)
        for kw in KEYWORDS:
            for cn, cf, alpha in CIPHERS:
                global tested
                try:
                    pt = cf(wct, kw, alpha)
                except:
                    continue
                tested += 1
                s, ene, bc = score(pt, cribs)
                if s >= 6:
                    results.append((s, ene, bc, f"{label}+{tn}+{kw}:{cn}", pt[:50]))


print("=" * 70)
print("COLD WAR CABLE FORMAT HYPOTHESES")
print("=" * 70)

# === HYPOTHESIS 1: Indicator group (skip first 5) ===
print("\n[1] INDICATOR GROUP: skip first 5 chars (OBKRU)...")
ct_skip5 = CT[5:]  # 92 chars
# Cribs shift: original pos 21 → new pos 16, etc.
cribs_skip5 = {k - 5: v for k, v in CRIB_DICT.items() if k >= 5}
test_batch(ct_skip5, cribs_skip5, "skip5")
print(f"  Tested: {tested}")

# === HYPOTHESIS 2: W positions decrypt to X (telegram separators) ===
print("\n[2] W→X CONSTRAINT: if W positions decrypt to X, derive key constraints...")
# For each cipher variant, what key letter at W positions produces X?
# Vig: X = CT - K → K = CT - X = W - X = 22 - 23 = -1 = 25 = Z
# Beau: X = K - CT → K = X + CT = 23 + 22 = 45 = 19 = T
# VBeau: X = CT + K → K = X - CT = 23 - 22 = 1 = B
print("  If W→X under Vigenere: key at W positions = Z")
print("  If W→X under Beaufort: key at W positions = T")
print("  If W→X under VarBeau:  key at W positions = B")
print("  Testing keywords containing these constraints...")

# Find keywords where the key letter at W positions matches
for kw in KEYWORDS:
    for variant, key_letter in [("vig", "Z"), ("beau", "T"), ("vbeau", "B")]:
        # Check if keyword puts key_letter at any W position
        matches = sum(1 for w in W_POSITIONS if kw[w % len(kw)] == key_letter)
        if matches >= 2:
            print(f"  {kw} ({variant}): {matches}/5 W-positions have key={key_letter}")

# Test all keywords but with W→X as bonus scoring
# Actually, just check if any decryption puts X at W positions
w_hits_best = 0
w_best_desc = ""
for kw in KEYWORDS:
    for cn, cf, alpha in CIPHERS:
        try:
            pt = cf(CT, kw, alpha)
        except:
            continue
        w_x_count = sum(1 for w in W_POSITIONS if w < len(pt) and pt[w] == "X")
        if w_x_count >= 3:
            print(f"  ** {w_x_count}/5 W→X: {kw}:{cn} → PT[W]={''.join(pt[w] for w in W_POSITIONS)}")
            if w_x_count > w_hits_best:
                w_hits_best = w_x_count
                w_best_desc = f"{kw}:{cn}"

# === HYPOTHESIS 3: DRYAD offset — rotate CT by T=19 ===
print(f"\n[3] DRYAD OFFSET: rotate CT by T=19 (and T=20, 0-indexed vs 1-indexed)...")
for offset in [19, 20, 5, 13, 24]:
    ct_rot = rotate(CT, offset)
    # Cribs also rotate
    cribs_rot = {(k - offset) % 97: v for k, v in CRIB_DICT.items()}
    test_batch(ct_rot, cribs_rot, f"rot{offset}")

prev = tested
print(f"  Tested: {tested - prev + tested} total")

# === HYPOTHESIS 4: Five-letter group transposition ===
print(f"\n[4] FIVE-LETTER GROUP transposition (width 5, 10, 19, 20)...")
for width in [5, 10, 19, 20]:
    ct_col = col_undo(CT, width)
    test_batch(ct_col, CRIB_DICT, f"fivegroup_w{width}")

# === HYPOTHESIS 5: Indicator skip + null mask ===
print(f"\n[5] INDICATOR SKIP + NULL MASK: skip 5 indicator chars, then apply null mask...")
# Remove first 5 (indicator), then remove nulls from remaining 92
# But DEFECTOR nulls are defined on the full 97 — need to adjust
# Nulls > 4 shift down by 5
adjusted_nulls = [n - 5 for n in DEFECTOR_NULLS if n >= 5]
ct_92 = CT[5:]
ns = set(adjusted_nulls)
ct_extracted = "".join(c for i, c in enumerate(ct_92) if i not in ns)
# Remap cribs
cribs_ind = {}
new_idx = 0
for i in range(len(ct_92)):
    if i not in ns:
        orig_pos = i + 5
        if orig_pos in CRIB_DICT:
            cribs_ind[new_idx] = CRIB_DICT[orig_pos]
        new_idx += 1

print(f"  After skip5 + null mask: {len(ct_extracted)} chars, {len(cribs_ind)} cribs")
if len(cribs_ind) > 0:
    test_batch(ct_extracted, cribs_ind, "skip5+nullmask")

# === HYPOTHESIS 6: Q/X terminator — last plaintext char is Q or X ===
print(f"\n[6] Q/X TERMINATOR: check if any config puts Q or X at last position...")
terminator_hits = []
for kw in KEYWORDS:
    for cn, cf, alpha in CIPHERS:
        try:
            pt = cf(CT, kw, alpha)
        except:
            continue
        last = pt[-1]
        if last in ("Q", "X"):
            s, ene, bc = score(pt, CRIB_DICT)
            if s >= 4:
                terminator_hits.append((s, ene, bc, f"term_{last}+{kw}:{cn}", pt[-10:]))

# Also test with col7
for kw in KEYWORDS:
    for cn, cf, alpha in CIPHERS:
        try:
            pt = cf(col_undo(CT, 7), kw, alpha)
        except:
            continue
        last = pt[-1]
        if last in ("Q", "X"):
            s, ene, bc = score(pt, CRIB_DICT)
            if s >= 4:
                terminator_hits.append((s, ene, bc, f"term_{last}+col7+{kw}:{cn}", pt[-10:]))

if terminator_hits:
    terminator_hits.sort(key=lambda x: -x[0])
    print(f"  Found {len(terminator_hits)} configs with Q/X terminator and score >= 4:")
    for s, ene, bc, desc, tail in terminator_hits[:10]:
        print(f"    {s}/24 (ene={ene} bc={bc}) {desc} ...{tail}")

# === HYPOTHESIS 7: OBKRU as keyword (first 5 chars = the key itself) ===
print(f"\n[7] OBKRU AS KEY: first 5 chars of CT used as the keyword...")
test_batch(CT, CRIB_DICT, "obkru_key")
# Already included OBKRU in KEYWORDS list above

# === HYPOTHESIS 8: Five-char indicator OBKRU selects starting position ===
print(f"\n[8] OBKRU AS INDICATOR: numeric value selects key offset...")
# O=14, B=1, K=10, R=17, U=20 → various combinations
for indicator_val in [14, 1, 10, 17, 20, 14+1, 10+17+20, (14*26+1), 14110+1720]:
    offset = indicator_val % 97
    ct_rot = rotate(CT, offset)
    cribs_rot = {(k - offset) % 97: v for k, v in CRIB_DICT.items()}
    for kw in KEYWORDS[:10]:  # subset for speed
        for cn, cf, alpha in [("abeau_AZ", abeau, AZ), ("avig_AZ", avig, AZ),
                               ("beau_AZ", beau, AZ), ("vig_AZ", vig, AZ)]:
            try:
                pt = cf(ct_rot, kw, alpha)
            except:
                continue
            tested += 1
            s, ene, bc = score(pt, cribs_rot)
            if s >= 6:
                results.append((s, ene, bc, f"obkru_ind({indicator_val}→rot{offset})+{kw}:{cn}", pt[:50]))

# === RESULTS ===
results.sort(key=lambda x: (-x[0], -x[1]))

print(f"\n{'='*70}")
print(f"TOTAL TESTED: {tested}")
print(f"SCORES >= 6: {len(results)}")
print(f"{'='*70}")

if results:
    print("\nTOP 20:")
    print("-" * 70)
    for s, ene, bc, desc, pt in results[:20]:
        print(f"  {s:2d}/24 (ene={ene:2d}/13 bc={bc:2d}/11) {desc}")
        print(f"      PT: {pt}...")
    print("-" * 70)
    best = results[0]
    if best[0] >= 10:
        print(f"\n*** ABOVE NOISE ({best[0]}/24) — INVESTIGATE ***")
    elif best[0] >= 7:
        print(f"\nBest: {best[0]}/24 — marginal.")
    else:
        print(f"\nBest: {best[0]}/24 — noise floor.")
else:
    print("\nAll noise.")
