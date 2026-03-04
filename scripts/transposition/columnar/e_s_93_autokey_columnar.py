#!/usr/bin/env python3
"""
Cipher: autokey
Family: transposition/columnar
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-93: Autokey Cipher Family + Width-7 Columnar

Tests autokey Vigenère/Beaufort (both plaintext-autokey and ciphertext-autokey)
combined with width-7 columnar transposition (Model B: trans→sub).

Rationale:
  - Autokey is the NATURAL evolution from K3's periodic Vigenère
  - Non-periodic key (matches our algebraic constraint)
  - Hand-executable with a standard tabula recta ("coding charts")
  - Ed Scheidt: "change in methodology from K3→K4"
  - K3 = width-8 columnar + period-8 Vig → K4 = width-7 columnar + autokey?

Autokey variants:
  1. PT-autokey Vigenère:  K[j] = primer[j] for j<p, K[j] = P[j-p] for j≥p
                           C[j] = (P[j] + K[j]) % 26
  2. CT-autokey Vigenère:  K[j] = primer[j] for j<p, K[j] = C[j-p] for j≥p
                           C[j] = (P[j] + K[j]) % 26
  3. PT-autokey Beaufort:  K[j] = P[j-p], C[j] = (K[j] - P[j]) % 26
  4. CT-autokey Beaufort:  K[j] = C[j-p], C[j] = (K[j] - P[j]) % 26

Model B: CT → columnar transposition → intermediate I → autokey decrypt → PT

For CT-autokey: K[j] depends on I[j-p] which is fully known → can check cribs directly
For PT-autokey: K[j] depends on P[j-p] → need sequential decryption

Search:
  Phase 1: CT-autokey, primer lengths 1-4, exhaustive (5040 × 26^p × 4 variants)
  Phase 2: PT-autokey, primer lengths 1-3, exhaustive with early termination
  Phase 3: Keyword primers (length 5-10) from dictionary, both CT and PT autokey
  Phase 4: Autokey WITHOUT transposition (pure autokey, all primers ≤7)
"""

import json, os, time
from itertools import permutations, product

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
I2N = {c: i for i, c in enumerate(AZ)}
CT_N = [I2N[c] for c in CT]

# 0-indexed cribs
CRIBS = {
    21:'E',22:'A',23:'S',24:'T',25:'N',26:'O',27:'R',28:'T',29:'H',30:'E',31:'A',32:'S',33:'T',
    63:'B',64:'E',65:'R',66:'L',67:'I',68:'N',69:'C',70:'L',71:'O',72:'C',73:'K'}
PT_FULL = {p: I2N[c] for p, c in CRIBS.items()}
CPOS = sorted(CRIBS.keys())

W = 7

def build_perm(order):
    nr = (N + W - 1) // W  # 14
    ns = nr * W - N  # 1
    p = []
    for k in range(W):
        c = order[k]
        sz = nr - 1 if c >= W - ns else nr
        for r in range(sz):
            p.append(r * W + c)
    return p

def inv_perm(perm):
    iv = [0] * N
    for i, p in enumerate(perm):
        iv[p] = i
    return iv

ORDERS = [list(o) for o in permutations(range(W))]
PERMS = [build_perm(o) for o in ORDERS]
INVS = [inv_perm(p) for p in PERMS]

# Precompute intermediates: I[j] = CT[perm[j]] for each ordering
# Model B: write CT in rows of 7, read columns in order → I
# Then decrypt I with autokey → PT
# I[j] = CT[perm[j]] where perm = columnar reading order
INTERMEDIATES = []
for oi in range(len(ORDERS)):
    intermed = [CT_N[PERMS[oi][j]] for j in range(N)]
    INTERMEDIATES.append(intermed)


def check_cribs(pt_array):
    """Count how many crib positions match."""
    score = 0
    for p in CPOS:
        if pt_array[p] == PT_FULL[p]:
            score += 1
    return score


def ct_autokey_decrypt(intermed, primer, variant):
    """Decrypt with CT-autokey (key from intermediate ciphertext).

    variant: 0=Vig, 1=Beau, 2=VBeau, 3=Beau-CT-autokey
    For Vig CT-autokey:  P[j] = (I[j] - K[j]) % 26, K[j<p]=primer, K[j≥p]=I[j-p]
    For Beau CT-autokey: P[j] = (K[j] - I[j]) % 26
    For VBeau CT-autokey: P[j] = (I[j] + K[j]) % 26 (variant Beaufort encryption is P = C - K)
    """
    p = len(primer)
    pt = [0] * N
    for j in range(N):
        k = primer[j] if j < p else intermed[j - p]
        if variant == 0:  # Vig: C = P + K → P = C - K
            pt[j] = (intermed[j] - k) % 26
        elif variant == 1:  # Beau: C = K - P → P = K - C
            pt[j] = (k - intermed[j]) % 26
        elif variant == 2:  # VBeau: C = P - K → P = C + K
            pt[j] = (intermed[j] + k) % 26
        else:  # Minuend: C = -(P + K) → not standard
            pt[j] = (26 - intermed[j] - k) % 26
    return pt


def pt_autokey_decrypt(intermed, primer, variant):
    """Decrypt with PT-autokey (key from plaintext). Sequential.

    For Vig PT-autokey:  C[j] = (P[j] + K[j]) % 26, K[j≥p] = P[j-p]
                         P[j] = (I[j] - K[j]) % 26
    For Beau PT-autokey: C[j] = (K[j] - P[j]) % 26
                         P[j] = (K[j] - I[j]) % 26
    """
    p = len(primer)
    pt = [0] * N
    for j in range(N):
        k = primer[j] if j < p else pt[j - p]
        if variant == 0:  # Vig
            pt[j] = (intermed[j] - k) % 26
        elif variant == 1:  # Beau
            pt[j] = (k - intermed[j]) % 26
        elif variant == 2:  # VBeau
            pt[j] = (intermed[j] + k) % 26
        else:
            pt[j] = (26 - intermed[j] - k) % 26
    return pt


print("=" * 70)
print("E-S-93: Autokey Cipher Family + Width-7 Columnar")
print(f"  N={N}, W={W}, orderings={len(ORDERS)}, cribs={len(CPOS)}")
print("=" * 70)

t0 = time.time()
VNAMES = ['Vig', 'Beau', 'VBeau', 'Minuend']
best_overall = 0
best_cfg = None
all_results = {}

# ── Phase 1: CT-autokey, primer lengths 1-4 ──────────────────────────
print("\n--- P1: CT-autokey + w7 columnar, primer 1-4 ---")

for plen in range(1, 5):
    best_p = 0
    best_p_cfg = None
    tested = 0

    for oi in range(len(ORDERS)):
        intermed = INTERMEDIATES[oi]

        for primer_tuple in product(range(26), repeat=plen):
            primer = list(primer_tuple)
            for vi in range(3):  # Vig, Beau, VBeau
                pt = ct_autokey_decrypt(intermed, primer, vi)
                score = check_cribs(pt)
                tested += 1

                if score > best_p:
                    best_p = score
                    primer_letters = ''.join(AZ[x] for x in primer)
                    best_p_cfg = (ORDERS[oi], VNAMES[vi], primer_letters)

                if score >= 20:
                    primer_letters = ''.join(AZ[x] for x in primer)
                    pt_text = ''.join(AZ[x] for x in pt)
                    print(f"  *** HIT: {score}/24 order={ORDERS[oi]} {VNAMES[vi]} "
                          f"primer='{primer_letters}'")
                    print(f"      PT: {pt_text}")

                if score >= 24:
                    print(f"\n  !!!!! BREAKTHROUGH: {score}/24 !!!!!")
                    print(f"  Order: {ORDERS[oi]}")
                    print(f"  Variant: {VNAMES[vi]}")
                    print(f"  Primer: {primer_letters}")
                    print(f"  PT: {pt_text}")

    elapsed = time.time() - t0
    print(f"  primer_len={plen}: best={best_p}/24 ({tested:,} tested, {elapsed:.0f}s) cfg={best_p_cfg}")

    if best_p > best_overall:
        best_overall = best_p
        best_cfg = ('P1_ct_autokey', plen, best_p_cfg)

all_results['P1_ct_autokey'] = {'best': best_overall, 'cfg': str(best_cfg)}
print(f"\n  P1 done: best={best_overall}/24, {time.time()-t0:.1f}s")


# ── Phase 2: PT-autokey, primer lengths 1-3 ──────────────────────────
print("\n--- P2: PT-autokey + w7 columnar, primer 1-3 ---")

p2_best = 0
p2_cfg = None

for plen in range(1, 4):
    best_p = 0
    tested = 0

    for oi in range(len(ORDERS)):
        intermed = INTERMEDIATES[oi]

        for primer_tuple in product(range(26), repeat=plen):
            primer = list(primer_tuple)
            for vi in range(3):
                pt = pt_autokey_decrypt(intermed, primer, vi)
                score = check_cribs(pt)
                tested += 1

                if score > best_p:
                    best_p = score
                    primer_letters = ''.join(AZ[x] for x in primer)
                    best_p_cfg = (ORDERS[oi], VNAMES[vi], primer_letters)

                if score >= 20:
                    primer_letters = ''.join(AZ[x] for x in primer)
                    pt_text = ''.join(AZ[x] for x in pt)
                    print(f"  *** HIT: {score}/24 order={ORDERS[oi]} {VNAMES[vi]} "
                          f"primer='{primer_letters}'")
                    print(f"      PT: {pt_text}")

                if score >= 24:
                    print(f"\n  !!!!! BREAKTHROUGH: {score}/24 !!!!!")

    elapsed = time.time() - t0
    print(f"  primer_len={plen}: best={best_p}/24 ({tested:,} tested, {elapsed:.0f}s)")

    if best_p > p2_best:
        p2_best = best_p
        p2_cfg = (plen, best_p_cfg)

all_results['P2_pt_autokey'] = {'best': p2_best, 'cfg': str(p2_cfg)}
if p2_best > best_overall:
    best_overall = p2_best
    best_cfg = ('P2_pt_autokey', p2_cfg)
print(f"\n  P2 done: best={p2_best}/24, {time.time()-t0:.1f}s")


# ── Phase 3: Keyword primers (length 5-10) ───────────────────────────
print("\n--- P3: Keyword primers + w7 columnar ---")

# Load primer candidates
PRIMER_WORDS = [
    # K1-K3 keywords and solutions
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "FORCES",
    # Sanborn clues
    "CLOCK", "BERLIN", "EGYPT", "POINT", "MESSAGE",
    "WHATSTHEPOINT", "DELIVERING",
    # People/places
    "SCHEIDT", "SANBORN", "WEBSTER", "LANGLEY",
    # CIA / Kryptos related
    "AGENCY", "CENTRAL", "INTELLIGENCE",
    # Compass/navigation
    "NORTH", "NORTHEAST", "NORTHWEST", "COMPASS", "BEARING",
    # K2 themes
    "BURIED", "UNDERGROUND", "HIDDEN", "SECRET",
    # Berlin Wall
    "FREEDOM", "CHECKPOINT", "CHARLIE",
    # Numbers as letters
    "SEVEN", "FORTY", "NINETY", "DEGREES",
]

# Also load from wordlist (5-10 letter words)
WORDLIST_PRIMERS = []
wl_path = "/home/cpatrick/kryptos/wordlists/english.txt"
if os.path.exists(wl_path):
    with open(wl_path) as f:
        for line in f:
            w = line.strip().upper()
            if 5 <= len(w) <= 10 and w.isalpha():
                WORDLIST_PRIMERS.append(w)

# Use the curated list + top 5000 most common words from wordlist
ALL_PRIMERS = list(set(PRIMER_WORDS + WORDLIST_PRIMERS[:5000]))
print(f"  Total primer candidates: {len(ALL_PRIMERS)}")

p3_best = 0
p3_cfg = None
tested = 0

for word in ALL_PRIMERS:
    primer = [I2N[c] for c in word]
    plen = len(primer)

    for oi in range(len(ORDERS)):
        intermed = INTERMEDIATES[oi]

        for vi in range(3):
            # CT-autokey
            pt = ct_autokey_decrypt(intermed, primer, vi)
            score = check_cribs(pt)
            tested += 1

            if score > p3_best:
                p3_best = score
                p3_cfg = ('CT', word, ORDERS[oi], VNAMES[vi])

            if score >= 20:
                pt_text = ''.join(AZ[x] for x in pt)
                print(f"  *** CT-AK HIT: {score}/24 '{word}' order={ORDERS[oi]} {VNAMES[vi]}")
                print(f"      PT: {pt_text}")

            # PT-autokey
            pt2 = pt_autokey_decrypt(intermed, primer, vi)
            score2 = check_cribs(pt2)
            tested += 1

            if score2 > p3_best:
                p3_best = score2
                p3_cfg = ('PT', word, ORDERS[oi], VNAMES[vi])

            if score2 >= 20:
                pt_text = ''.join(AZ[x] for x in pt2)
                print(f"  *** PT-AK HIT: {score2}/24 '{word}' order={ORDERS[oi]} {VNAMES[vi]}")
                print(f"      PT: {pt_text}")

    if tested % 1000000 == 0:
        print(f"    {tested:,} tested, best={p3_best}/24 ({time.time()-t0:.0f}s)")

elapsed = time.time() - t0
print(f"  P3: best={p3_best}/24, {tested:,} tested, {elapsed:.0f}s, cfg={p3_cfg}")

all_results['P3_keyword_primers'] = {'best': p3_best, 'cfg': str(p3_cfg)}
if p3_best > best_overall:
    best_overall = p3_best
    best_cfg = ('P3_keyword', p3_cfg)


# ── Phase 4: Pure autokey (NO transposition) ─────────────────────────
print("\n--- P4: Pure autokey (no transposition), primer 1-7 ---")

p4_best = 0
p4_cfg = None

for plen in range(1, 8):
    best_p = 0
    tested = 0

    for primer_tuple in product(range(26), repeat=plen):
        primer = list(primer_tuple)
        for vi in range(3):
            # CT-autokey (no transposition: intermediate = CT itself)
            pt = ct_autokey_decrypt(CT_N, primer, vi)
            score = check_cribs(pt)
            tested += 1

            if score > best_p:
                best_p = score
                primer_letters = ''.join(AZ[x] for x in primer)
                best_p_cfg = ('CT', VNAMES[vi], primer_letters)

            if score >= 18:
                primer_letters = ''.join(AZ[x] for x in primer)
                pt_text = ''.join(AZ[x] for x in pt)
                print(f"  HIT: {score}/24 CT-AK {VNAMES[vi]} primer='{primer_letters}' PT={pt_text[:40]}...")

            # PT-autokey
            pt2 = pt_autokey_decrypt(CT_N, primer, vi)
            score2 = check_cribs(pt2)
            tested += 1

            if score2 > best_p:
                best_p = score2
                primer_letters = ''.join(AZ[x] for x in primer)
                best_p_cfg = ('PT', VNAMES[vi], primer_letters)

            if score2 >= 18:
                primer_letters = ''.join(AZ[x] for x in primer)
                pt_text = ''.join(AZ[x] for x in pt2)
                print(f"  HIT: {score2}/24 PT-AK {VNAMES[vi]} primer='{primer_letters}' PT={pt_text[:40]}...")

    elapsed = time.time() - t0
    print(f"  primer_len={plen}: best={best_p}/24 ({tested:,} tested, {elapsed:.0f}s)")

    if best_p > p4_best:
        p4_best = best_p
        p4_cfg = (plen, best_p_cfg)

    # Stop if primer_len > 4 and no signal
    if plen >= 5 and best_p <= 4:
        print(f"  Stopping at plen={plen} (noise)")
        break

all_results['P4_pure_autokey'] = {'best': p4_best, 'cfg': str(p4_cfg)}
if p4_best > best_overall:
    best_overall = p4_best
    best_cfg = ('P4_pure_autokey', p4_cfg)


# ── Phase 5: Autokey with non-standard transpositions ─────────────────
print("\n--- P5: CT-autokey + non-columnar transpositions, primer 1-2 ---")

def rail_fence_perm(rails, n):
    """Rail fence cipher reading order."""
    rows = [[] for _ in range(rails)]
    direction = 1
    rail = 0
    for i in range(n):
        rows[rail].append(i)
        rail += direction
        if rail == rails:
            direction = -1
            rail = rails - 2
        elif rail < 0:
            direction = 1
            rail = 1
    perm = []
    for row in rows:
        perm.extend(row)
    return perm

p5_best = 0
p5_cfg = None
tested = 0

# Rail fence with various rail counts
for rails in range(3, 15):
    perm = rail_fence_perm(rails, N)
    intermed = [CT_N[perm[j]] for j in range(N)]

    for plen in range(1, 3):
        for primer_tuple in product(range(26), repeat=plen):
            primer = list(primer_tuple)
            for vi in range(3):
                pt = ct_autokey_decrypt(intermed, primer, vi)
                score = check_cribs(pt)
                tested += 1

                if score > p5_best:
                    p5_best = score
                    primer_letters = ''.join(AZ[x] for x in primer)
                    p5_cfg = (f'rail_{rails}', VNAMES[vi], primer_letters)

                pt2 = pt_autokey_decrypt(intermed, primer, vi)
                score2 = check_cribs(pt2)
                tested += 1

                if score2 > p5_best:
                    p5_best = score2
                    primer_letters = ''.join(AZ[x] for x in primer)
                    p5_cfg = (f'rail_{rails}_PT', VNAMES[vi], primer_letters)

                if max(score, score2) >= 18:
                    print(f"  HIT: {max(score,score2)}/24 rails={rails} primer={''.join(AZ[x] for x in primer)}")

# Diagonal route through 7×14 grid
for start_corner in range(4):  # TL, TR, BL, BR
    for direction in range(2):  # diagonal, anti-diagonal
        perm = []
        seen = set()
        rows, cols = 14, 7
        for d in range(rows + cols - 1):
            for r in range(rows):
                c = d - r if direction == 0 else r - (d - cols + 1)
                if direction == 1:
                    c = d - r
                if 0 <= c < cols and 0 <= r < rows:
                    idx = r * cols + c
                    if idx < N and idx not in seen:
                        perm.append(idx)
                        seen.add(idx)

        if len(perm) != N:
            continue

        intermed = [CT_N[perm[j]] for j in range(N)]
        for plen in range(1, 3):
            for primer_tuple in product(range(26), repeat=plen):
                primer = list(primer_tuple)
                for vi in range(3):
                    pt = ct_autokey_decrypt(intermed, primer, vi)
                    score = check_cribs(pt)
                    tested += 1
                    if score > p5_best:
                        p5_best = score
                        p5_cfg = (f'diag_{start_corner}_{direction}', VNAMES[vi],
                                  ''.join(AZ[x] for x in primer))

elapsed = time.time() - t0
print(f"  P5: best={p5_best}/24, {tested:,} tested, {elapsed:.0f}s, cfg={p5_cfg}")

all_results['P5_noncolumnar_autokey'] = {'best': p5_best, 'cfg': str(p5_cfg)}
if p5_best > best_overall:
    best_overall = p5_best
    best_cfg = ('P5_noncolumnar', p5_cfg)


# ── Summary ───────────────────────────────────────────────────────────
total_elapsed = time.time() - t0

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
for phase, data in sorted(all_results.items()):
    print(f"  {phase}: {data['best']}/24")
print(f"  Total: {total_elapsed:.1f}s")

if best_overall >= 18:
    print(f"\n  Verdict: SIGNAL — {best_overall}/24")
elif best_overall >= 10:
    print(f"\n  Verdict: INTERESTING — {best_overall}/24")
else:
    print(f"\n  Verdict: NOISE — {best_overall}/24")

os.makedirs("results", exist_ok=True)
out = {
    'experiment': 'E-S-93',
    'description': 'Autokey cipher family + width-7 columnar',
    'best_overall': best_overall,
    'best_cfg': str(best_cfg),
    'phases': all_results,
    'elapsed_seconds': total_elapsed,
}
with open("results/e_s_93_autokey_columnar.json", "w") as f:
    json.dump(out, f, indent=2)
print(f"\n  Artifact: results/e_s_93_autokey_columnar.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_93_autokey_columnar.py")
