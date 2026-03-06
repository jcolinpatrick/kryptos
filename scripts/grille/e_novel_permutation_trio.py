#!/usr/bin/env python3
"""
Three novel permutation experiments for K4 — all fast, all untested.

Experiment 1: Period-7 cycle permutations (K3's dominant step on K4's prime length)
Experiment 2: Crib position reversal (cribs in real CT, not carved text)
Experiment 3: Step-7/8 hybrid permutations (compound KRYPTOS+ABSCISSA stepping)

Cipher: Transposition + Vigenere/Beaufort
Family: grille
Status: active
Keyspace: ~10,000 total
Last run: never
Best score: n/a
"""
import sys, os, json, math
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)

# ── Quadgram scorer ──────────────────────────────────────────────────────────
QG_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json')
with open(QG_PATH) as f:
    QG = json.load(f)
QG_FLOOR = min(QG.values()) - 1.0

def qg_score(text):
    if len(text) < 4:
        return QG_FLOOR
    total = sum(QG.get(text[i:i+4], QG_FLOOR) for i in range(len(text) - 3))
    return total / (len(text) - 3)

# ── Cipher helpers ───────────────────────────────────────────────────────────
def vig_decrypt(ct, key):
    kl = len(key)
    return ''.join(ALPH[(ALPH_IDX[c] - ALPH_IDX[key[i % kl]]) % MOD] for i, c in enumerate(ct))

def beau_decrypt(ct, key):
    kl = len(key)
    return ''.join(ALPH[(ALPH_IDX[key[i % kl]] - ALPH_IDX[c]) % MOD] for i, c in enumerate(ct))

def varbeau_decrypt(ct, key):
    kl = len(key)
    return ''.join(ALPH[(ALPH_IDX[c] + ALPH_IDX[key[i % kl]]) % MOD] for i, c in enumerate(ct))

KEYWORDS = {
    'KRYPTOS': 'KRYPTOS',
    'PALIMPSEST': 'PALIMPSEST',
    'ABSCISSA': 'ABSCISSA',
    'SHADOW': 'SHADOW',
    'SANBORN': 'SANBORN',
    'VERDIGRIS': 'VERDIGRIS',
}

DECRYPTORS = {
    'Vig': vig_decrypt,
    'Beau': beau_decrypt,
    'VBeau': varbeau_decrypt,
}

def apply_perm(text, perm):
    """Apply permutation: output[i] = text[perm[i]] (gather convention)."""
    return ''.join(text[perm[i]] for i in range(len(perm)))

def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

def crib_score(pt):
    return sum(1 for pos, ch in CRIB_DICT.items() if pos < len(pt) and pt[pos] == ch)

def bean_check(keystream):
    """Check Bean constraints on a keystream (list of ints)."""
    for a, b in BEAN_EQ:
        if a < len(keystream) and b < len(keystream):
            if keystream[a] != keystream[b]:
                return False
    for a, b in BEAN_INEQ:
        if a < len(keystream) and b < len(keystream):
            if keystream[a] == keystream[b]:
                return False
    return True

def derive_keystream_vig(ct_text, pt_text):
    return [(ALPH_IDX[c] - ALPH_IDX[p]) % MOD for c, p in zip(ct_text, pt_text)]

def free_crib_search(pt, cribs=("EASTNORTHEAST", "BERLINCLOCK")):
    """Search for cribs anywhere in plaintext. Return (total_matched_chars, details)."""
    total = 0
    details = []
    for crib in cribs:
        idx = pt.find(crib)
        if idx >= 0:
            total += len(crib)
            details.append((crib, idx))
    return total, details

# ── Results tracking ─────────────────────────────────────────────────────────
results = []

def record(score, pt, method, perm=None, extra=None):
    entry = {'score': score, 'pt': pt[:70], 'method': method}
    if perm:
        entry['perm'] = perm[:20]
    if extra:
        entry['extra'] = extra
    results.append(entry)

def check_all_decryptions(unscrambled, method_prefix, perm=None):
    """Try all keyword × decryptor combos, record best results."""
    best_score = -999
    best_pt = ''
    best_method = ''
    for kname, key in KEYWORDS.items():
        for dname, decrypt in DECRYPTORS.items():
            pt = decrypt(unscrambled, key)
            cs = crib_score(pt)
            qs = qg_score(pt)
            method = f"{method_prefix} → {dname}/{kname}"

            # Check free cribs too
            fc, fc_details = free_crib_search(pt)

            if cs >= 3 or qs > -5.5 or fc > 0:
                ks = derive_keystream_vig(unscrambled, pt)
                bp = bean_check(ks)
                record(cs, pt, method, perm,
                       extra=f"qg={qs:.3f} bean={'PASS' if bp else 'fail'} free_cribs={fc_details}")

            if cs > best_score or (cs == best_score and qs > qg_score(best_pt)):
                best_score = cs
                best_pt = pt
                best_method = method

            if qs > best_score * 0.5 - 3:  # track by quadgram too
                if qs > -5.0:
                    record(cs, pt, method, perm, extra=f"qg={qs:.3f}")

    return best_score, best_pt, best_method


print("=" * 70)
print("NOVEL PERMUTATION TRIO — K4 EXPERIMENTS")
print("=" * 70)

# ══════════════════════════════════════════════════════════════════════════════
# EXPERIMENT 1: Period-7 Cycle Permutations
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("EXPERIMENT 1: Period-7 Cycle Permutations")
print("  Hypothesis: σ is a 97-cycle with period-7 step structure")
print("  σ(i) = (i + step * (i // period)) mod 97")
print("  Also: σ(i) = (i * multiplier + offset) mod 97 (affine)")
print("=" * 70)

exp1_best = (-999, '', '')
exp1_count = 0

# 1a: Multiplicative permutations mod 97 (96 choices × 97 offsets)
# σ(i) = (m*i + c) mod 97, m in 1..96 (all coprime to 97 since 97 is prime)
print("\n--- Phase 1a: Affine permutations mod 97 ---")
for m in range(1, 97):
    for c in range(97):
        perm = [(m * i + c) % 97 for i in range(97)]
        # Verify it's a valid permutation
        if len(set(perm)) != 97:
            continue
        unscrambled = apply_perm(CT, perm)
        exp1_count += 1

        for kname, key in KEYWORDS.items():
            for dname, decrypt in DECRYPTORS.items():
                pt = decrypt(unscrambled, key)
                cs = crib_score(pt)
                if cs > exp1_best[0]:
                    exp1_best = (cs, pt, f"Affine m={m},c={c} → {dname}/{kname}")
                if cs >= 4:
                    qs = qg_score(pt)
                    fc, fc_details = free_crib_search(pt)
                    record(cs, pt, f"Affine m={m},c={c} → {dname}/{kname}",
                           extra=f"qg={qs:.3f} free={fc_details}")

    if m % 20 == 0:
        print(f"  m={m}/96, {exp1_count:,} perms tested, best crib={exp1_best[0]}")

print(f"  Phase 1a complete: {exp1_count:,} affine perms, best crib={exp1_best[0]}")
if exp1_best[0] > 0:
    print(f"  Best: {exp1_best[2]}")
    print(f"  PT: {exp1_best[1][:70]}")

# 1b: Period-7 structured stepping
# σ(i) = (base_i + floor(i/7) * step_delta) mod 97
print("\n--- Phase 1b: Period-7 structured stepping ---")
exp1b_best = (-999, '', '')
exp1b_count = 0

for step in range(1, 97):
    for start in range(7):  # 7 starting offsets within the first period
        perm = []
        seen = set()
        valid = True
        for i in range(97):
            # Position = (start + (i % 7) * step + (i // 7) * 7) mod 97
            pos = (start + (i % 7) * step + (i // 7) * 7) % 97
            if pos in seen:
                valid = False
                break
            seen.add(pos)
            perm.append(pos)

        if not valid or len(perm) != 97:
            continue

        unscrambled = apply_perm(CT, perm)
        exp1b_count += 1

        for kname, key in KEYWORDS.items():
            for dname, decrypt in DECRYPTORS.items():
                pt = decrypt(unscrambled, key)
                cs = crib_score(pt)
                if cs > exp1b_best[0]:
                    exp1b_best = (cs, pt, f"Step7 step={step},start={start} → {dname}/{kname}")
                if cs >= 4:
                    qs = qg_score(pt)
                    record(cs, pt, f"Step7 step={step},start={start} → {dname}/{kname}",
                           extra=f"qg={qs:.3f}")

print(f"  Phase 1b complete: {exp1b_count:,} period-7 perms, best crib={exp1b_best[0]}")
if exp1b_best[0] > 0:
    print(f"  Best: {exp1b_best[2]}")

# 1c: Period-8 structured stepping (ABSCISSA)
print("\n--- Phase 1c: Period-8 structured stepping ---")
exp1c_best = (-999, '', '')
exp1c_count = 0

for step in range(1, 97):
    for start in range(8):
        perm = []
        seen = set()
        valid = True
        for i in range(97):
            pos = (start + (i % 8) * step + (i // 8) * 8) % 97
            if pos in seen:
                valid = False
                break
            seen.add(pos)
            perm.append(pos)

        if not valid or len(perm) != 97:
            continue

        unscrambled = apply_perm(CT, perm)
        exp1c_count += 1

        for kname, key in KEYWORDS.items():
            for dname, decrypt in DECRYPTORS.items():
                pt = decrypt(unscrambled, key)
                cs = crib_score(pt)
                if cs > exp1c_best[0]:
                    exp1c_best = (cs, pt, f"Step8 step={step},start={start} → {dname}/{kname}")
                if cs >= 4:
                    qs = qg_score(pt)
                    record(cs, pt, f"Step8 step={step},start={start} → {dname}/{kname}",
                           extra=f"qg={qs:.3f}")

print(f"  Phase 1c complete: {exp1c_count:,} period-8 perms, best crib={exp1c_best[0]}")
if exp1c_best[0] > 0:
    print(f"  Best: {exp1c_best[2]}")


# ══════════════════════════════════════════════════════════════════════════════
# EXPERIMENT 2: Crib Position Reversal
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("EXPERIMENT 2: Crib Position Reversal")
print("  Hypothesis: cribs are at fixed positions in REAL CT, not carved text")
print("  If real_CT[21:34] = Vig(EASTNORTHEAST, key), then we can derive")
print("  partial σ by finding where those CT letters appear in carved text")
print("=" * 70)

exp2_best = (-999, '', '')

# For each keyword and cipher variant, compute what the real CT would be
# at crib positions if the crib plaintext is correct
ENE = "EASTNORTHEAST"
BC = "BERLINCLOCK"

print("\n--- Phase 2a: Derive real CT at crib positions for each key ---")
for kname, key in KEYWORDS.items():
    kl = len(key)
    for dname in ['Vig', 'Beau', 'VBeau']:
        # Compute real_CT at ENE positions (21-33)
        real_ct_ene = []
        for i, ch in enumerate(ENE):
            pos = 21 + i
            k_ch = key[pos % kl]
            if dname == 'Vig':
                ct_ch = ALPH[(ALPH_IDX[ch] + ALPH_IDX[k_ch]) % MOD]
            elif dname == 'Beau':
                ct_ch = ALPH[(ALPH_IDX[k_ch] - ALPH_IDX[ch]) % MOD]
            else:  # VBeau
                ct_ch = ALPH[(ALPH_IDX[ch] - ALPH_IDX[k_ch]) % MOD]
            real_ct_ene.append(ct_ch)

        # Compute real_CT at BC positions (63-73)
        real_ct_bc = []
        for i, ch in enumerate(BC):
            pos = 63 + i
            k_ch = key[pos % kl]
            if dname == 'Vig':
                ct_ch = ALPH[(ALPH_IDX[ch] + ALPH_IDX[k_ch]) % MOD]
            elif dname == 'Beau':
                ct_ch = ALPH[(ALPH_IDX[k_ch] - ALPH_IDX[ch]) % MOD]
            else:
                ct_ch = ALPH[(ALPH_IDX[ch] - ALPH_IDX[k_ch]) % MOD]
            real_ct_bc.append(ct_ch)

        real_ct_ene_str = ''.join(real_ct_ene)
        real_ct_bc_str = ''.join(real_ct_bc)

        # Now: can we find these letters in the carved CT?
        # For each real_CT letter at position p, σ(p) is the carved position
        # So carved[σ(p)] = real_CT[p]
        # We need to find a valid assignment σ(21..33) → positions in CT
        # where CT[σ(21+i)] = real_ct_ene[i]

        # Build mapping: for each target letter, which carved positions have it?
        ct_positions = {}
        for i, ch in enumerate(CT):
            ct_positions.setdefault(ch, []).append(i)

        # Try to find a valid assignment for ENE crib
        # This is a constraint satisfaction problem
        # For each position in the crib, we need a carved position with the right letter
        # and all carved positions must be distinct

        ene_options = []
        for i, ch in enumerate(real_ct_ene):
            opts = ct_positions.get(ch, [])
            ene_options.append(opts)

        bc_options = []
        for i, ch in enumerate(real_ct_bc):
            opts = ct_positions.get(ch, [])
            bc_options.append(opts)

        # Count total assignments possible
        ene_total = 1
        for opts in ene_options:
            ene_total *= len(opts)

        bc_total = 1
        for opts in bc_options:
            bc_total *= len(opts)

        # If any position has 0 options, skip
        if any(len(o) == 0 for o in ene_options) or any(len(o) == 0 for o in bc_options):
            continue

        print(f"  {dname}/{kname}: real_CT(ENE)={real_ct_ene_str} "
              f"real_CT(BC)={real_ct_bc_str} "
              f"ENE assignments={ene_total:,} BC assignments={bc_total:,}")

        # For tractable cases, try all ENE assignments and score
        if ene_total <= 500_000:
            from itertools import product as iprod
            best_for_config = 0
            for assignment in iprod(*ene_options):
                if len(set(assignment)) != len(assignment):
                    continue  # must be distinct positions
                # This gives us σ(21)=assignment[0], σ(22)=assignment[1], ...
                # Build partial inverse: inv_σ[assignment[i]] = 21+i
                # Now try to decrypt the ENTIRE carved text as if it were the real CT
                # using this key, and check if the plaintext has cribs at positions 21-33
                # Actually — we need the FULL permutation. With only 13 positions known,
                # we can check: does the key derived from these 13 positions
                # show any pattern (e.g., periodic)?

                # Derive keystream at positions 21-33
                ks = []
                for idx, carved_pos in enumerate(assignment):
                    pt_ch = ENE[idx]
                    ct_ch = CT[carved_pos]
                    if dname == 'Vig':
                        k_val = (ALPH_IDX[ct_ch] - ALPH_IDX[pt_ch]) % MOD
                    elif dname == 'Beau':
                        k_val = (ALPH_IDX[ct_ch] + ALPH_IDX[pt_ch]) % MOD
                    else:
                        k_val = (ALPH_IDX[pt_ch] - ALPH_IDX[ct_ch]) % MOD
                    ks.append(k_val)

                # Check if keystream matches a periodic key
                for kw_name, kw in KEYWORDS.items():
                    kw_len = len(kw)
                    expected_ks = [ALPH_IDX[kw[(21 + j) % kw_len]] for j in range(13)]
                    if ks == expected_ks:
                        print(f"  *** KEY MATCH: {dname}/{kname} with σ mapping → "
                              f"keystream matches {kw_name}!")
                        print(f"      σ(21..33) = {list(assignment)}")
                        record(13, f"KEY_MATCH_ENE", f"CribRev {dname}/{kname}→{kw_name}",
                               extra=f"σ(21..33)={list(assignment)}")
                        best_for_config = 13

                    # Partial match
                    matches = sum(1 for a, b in zip(ks, expected_ks) if a == b)
                    if matches >= 8 and matches > best_for_config:
                        best_for_config = matches
                        if matches >= 10:
                            print(f"  ** Partial key match ({matches}/13): {dname}/{kname} "
                                  f"→ {kw_name}, σ(21..33)={list(assignment)}")

            if best_for_config >= 4:
                print(f"    Best ENE key match for {dname}/{kname}: {best_for_config}/13")

print(f"\n  Experiment 2 complete.")


# ══════════════════════════════════════════════════════════════════════════════
# EXPERIMENT 3: Step-7/8 Hybrid Permutations
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("EXPERIMENT 3: Step-7/8 Hybrid Permutations")
print("  Hypothesis: σ uses compound stepping with K3's factors")
print("  Alternating step-7 and step-8, or interleaved patterns")
print("=" * 70)

exp3_best = (-999, '', '')
exp3_count = 0

# 3a: Alternating step patterns
# Read position i uses step_a for even i, step_b for odd i
print("\n--- Phase 3a: Alternating dual-step ---")
for step_a in range(1, 50):  # first step
    for step_b in range(1, 50):  # second step
        if step_a == step_b:
            continue
        perm = [0] * 97
        pos = 0
        seen = set()
        valid = True
        for i in range(97):
            if pos in seen:
                valid = False
                break
            seen.add(pos)
            perm[i] = pos
            step = step_a if i % 2 == 0 else step_b
            pos = (pos + step) % 97
        if not valid or len(seen) != 97:
            continue

        unscrambled = apply_perm(CT, perm)
        exp3_count += 1

        for kname, key in KEYWORDS.items():
            for dname, decrypt in DECRYPTORS.items():
                pt = decrypt(unscrambled, key)
                cs = crib_score(pt)
                if cs > exp3_best[0]:
                    exp3_best = (cs, pt, f"Alt({step_a},{step_b}) → {dname}/{kname}")
                if cs >= 4:
                    qs = qg_score(pt)
                    record(cs, pt, f"Alt({step_a},{step_b}) → {dname}/{kname}",
                           extra=f"qg={qs:.3f}")

        # Also try inverse
        inv = invert_perm(perm)
        unscrambled_inv = apply_perm(CT, inv)
        for kname, key in KEYWORDS.items():
            for dname, decrypt in DECRYPTORS.items():
                pt = decrypt(unscrambled_inv, key)
                cs = crib_score(pt)
                if cs > exp3_best[0]:
                    exp3_best = (cs, pt, f"Alt({step_a},{step_b})^-1 → {dname}/{kname}")
                if cs >= 4:
                    qs = qg_score(pt)
                    record(cs, pt, f"Alt({step_a},{step_b})^-1 → {dname}/{kname}",
                           extra=f"qg={qs:.3f}")

    if step_a % 10 == 0:
        print(f"  step_a={step_a}/49, {exp3_count:,} hybrid perms, best crib={exp3_best[0]}")

print(f"  Phase 3a complete: {exp3_count:,} alternating perms, best crib={exp3_best[0]}")
if exp3_best[0] > 0:
    print(f"  Best: {exp3_best[2]}")

# 3b: K3-style double rotation scaled to K4
# K3: 24×14 → 8×42 (both = 336). K4 padded to 98 = 7×14 → 2×49
print("\n--- Phase 3b: K3-style double rotation (padded to 98=7×14) ---")
exp3b_best = (-999, '', '')
exp3b_count = 0

PAD_CHARS = ['X', 'Q', 'Z']  # try different padding characters
GRID_DIMS = [
    (7, 14),   # same col-dim as K3's first grid
    (14, 7),   # transposed
    (2, 49),   # second grid analog
    (49, 2),
]

for pad_ch in PAD_CHARS:
    for pad_pos in ['prefix', 'suffix']:
        padded = (pad_ch + CT) if pad_pos == 'prefix' else (CT + pad_ch)
        assert len(padded) == 98

        for rows1, cols1 in GRID_DIMS:
            if rows1 * cols1 != 98:
                continue
            for rows2, cols2 in GRID_DIMS:
                if rows2 * cols2 != 98:
                    continue
                if (rows1, cols1) == (rows2, cols2):
                    continue

                # K3 formula: write row-major into grid1, read col-major,
                # write row-major into grid2, read col-major
                # Grid 1: write row-major (rows1 × cols1), read col-major
                intermediate = ''
                for c in range(cols1):
                    for r in range(rows1):
                        intermediate += padded[r * cols1 + c]

                # Grid 2: write row-major (rows2 × cols2), read col-major
                output = ''
                for c in range(cols2):
                    for r in range(rows2):
                        output += intermediate[r * cols2 + c]

                # Extract the 97 non-pad chars
                if pad_pos == 'prefix':
                    # Find where the pad char ended up
                    unscrambled = output.replace(pad_ch, '', 1) if output.count(pad_ch) > CT.count(pad_ch) else output[:97]
                else:
                    unscrambled = output.replace(pad_ch, '', 1) if output.count(pad_ch) > CT.count(pad_ch) else output[:97]

                if len(unscrambled) != 97:
                    continue

                exp3b_count += 1

                for kname, key in KEYWORDS.items():
                    for dname, decrypt in DECRYPTORS.items():
                        pt = decrypt(unscrambled, key)
                        cs = crib_score(pt)
                        fc, fc_details = free_crib_search(pt)
                        if cs > exp3b_best[0]:
                            exp3b_best = (cs, pt,
                                f"DblRot pad={pad_ch}/{pad_pos} "
                                f"{rows1}×{cols1}→{rows2}×{cols2} → {dname}/{kname}")
                        if cs >= 3 or fc > 0:
                            qs = qg_score(pt)
                            record(cs, pt,
                                f"DblRot pad={pad_ch}/{pad_pos} "
                                f"{rows1}×{cols1}→{rows2}×{cols2} → {dname}/{kname}",
                                extra=f"qg={qs:.3f} free={fc_details}")

                # Also try: read row-major from each grid (reverse direction)
                intermediate2 = ''
                for r in range(rows1):
                    for c in range(cols1):
                        intermediate2 += padded[c * rows1 + r]  # col-major write, row-major read

                output2 = ''
                for r in range(rows2):
                    for c in range(cols2):
                        output2 += intermediate2[c * rows2 + r]

                if pad_pos == 'prefix':
                    unscrambled2 = output2.replace(pad_ch, '', 1) if output2.count(pad_ch) > CT.count(pad_ch) else output2[:97]
                else:
                    unscrambled2 = output2.replace(pad_ch, '', 1) if output2.count(pad_ch) > CT.count(pad_ch) else output2[:97]

                if len(unscrambled2) == 97:
                    exp3b_count += 1
                    for kname, key in KEYWORDS.items():
                        for dname, decrypt in DECRYPTORS.items():
                            pt = decrypt(unscrambled2, key)
                            cs = crib_score(pt)
                            fc, fc_details = free_crib_search(pt)
                            if cs > exp3b_best[0]:
                                exp3b_best = (cs, pt,
                                    f"DblRotRev pad={pad_ch}/{pad_pos} "
                                    f"{rows1}×{cols1}→{rows2}×{cols2} → {dname}/{kname}")
                            if cs >= 3 or fc > 0:
                                qs = qg_score(pt)
                                record(cs, pt,
                                    f"DblRotRev pad={pad_ch}/{pad_pos} "
                                    f"{rows1}×{cols1}→{rows2}×{cols2} → {dname}/{kname}",
                                    extra=f"qg={qs:.3f} free={fc_details}")

print(f"  Phase 3b complete: {exp3b_count:,} double rotations, best crib={exp3b_best[0]}")
if exp3b_best[0] > 0:
    print(f"  Best: {exp3b_best[2]}")

# 3c: Single-step cycles through all 96 coprime steps (extended)
print("\n--- Phase 3c: Single-step full 97-cycles ---")
exp3c_best = (-999, '', '')

for step in range(1, 97):
    perm = [(step * i) % 97 for i in range(97)]
    assert len(set(perm)) == 97  # always true for prime 97

    unscrambled = apply_perm(CT, perm)
    inv = invert_perm(perm)
    unscrambled_inv = apply_perm(CT, inv)

    for text, direction in [(unscrambled, 'fwd'), (unscrambled_inv, 'inv')]:
        for kname, key in KEYWORDS.items():
            for dname, decrypt in DECRYPTORS.items():
                pt = decrypt(text, key)
                cs = crib_score(pt)
                fc, _ = free_crib_search(pt)
                if cs > exp3c_best[0]:
                    exp3c_best = (cs, pt, f"Cycle97 step={step}/{direction} → {dname}/{kname}")
                if cs >= 4 or fc > 0:
                    qs = qg_score(pt)
                    record(cs, pt, f"Cycle97 step={step}/{direction} → {dname}/{kname}",
                           extra=f"qg={qs:.3f} fc={fc}")

print(f"  Phase 3c complete: 96 full cycles × 2 directions, best crib={exp3c_best[0]}")
if exp3c_best[0] > 0:
    print(f"  Best: {exp3c_best[2]}")


# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("SUMMARY — NOVEL PERMUTATION TRIO")
print("=" * 70)

# Collect all recorded results, dedupe, sort
if results:
    results.sort(key=lambda x: -x['score'])
    print(f"\nTotal recorded results (score >= 3 or notable): {len(results)}")
    print(f"\nTop 20:")
    for i, r in enumerate(results[:20]):
        print(f"  {i+1:2d}. [crib={r['score']:2d}] {r['method']}")
        print(f"      PT: {r['pt']}")
        if r.get('extra'):
            print(f"      {r['extra']}")
else:
    print("\nNo results above threshold.")

print(f"\nExperiment 1 (affine+period-7+period-8): best crib = {max(exp1_best[0], exp1b_best[0] if 'exp1b_best' in dir() else 0, exp1c_best[0] if 'exp1c_best' in dir() else 0)}")
print(f"Experiment 2 (crib reversal): see key match output above")
print(f"Experiment 3 (hybrid+double-rot+cycles): best crib = {max(exp3_best[0], exp3b_best[0], exp3c_best[0])}")

print("\n" + "=" * 70)
print("DONE")
print("=" * 70)
