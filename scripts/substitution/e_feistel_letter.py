#!/usr/bin/env python3
"""
DES-inspired letter-based Feistel / SPN cipher attack on K4.

Cipher:  Feistel network + SPN (letter-based DES analogue)
Family:  substitution
Status:  active
Keyspace: ~50K deterministic + SA refinement
Last run: never
Best score: N/A

Hypothesis: Scheidt designed a hand-executable Feistel/SPN using DES
architecture on letters. "Two systems" = S-box (sub) + P-box (trans).
Morse clue "DIGETAL INTERPRETATION" = digital cipher structure.
DES: 64-bit block - 8 parity = 56 effective. K4: 97 chars - 24 nulls = 73.
"""

import json, math, random, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, CRIB_DICT

QG_PATH = Path(__file__).resolve().parents[2] / "data" / "english_quadgrams.json"
with open(QG_PATH) as f:
    _qg = json.load(f)
QG_FLOOR = min(_qg.values()) - 1.0

def qg_score(text):
    return sum(_qg.get(text[i:i+4], QG_FLOOR) for i in range(len(text)-3))

def qg_per_char(text):
    n = len(text) - 3
    return qg_score(text) / n if n > 0 else QG_FLOOR

def crib_score(pt, crib_dict=CRIB_DICT):
    return sum(1 for pos, ch in crib_dict.items() if pos < len(pt) and pt[pos] == ch)

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def to_nums(text):
    return [ord(c) - ord('A') for c in text.upper()]

def to_text(nums):
    return ''.join(chr((n % 26) + ord('A')) for n in nums)

def keyword_alpha(kw):
    seen = set()
    result = []
    for ch in kw.upper():
        if ch.isalpha() and ch not in seen:
            result.append(ch)
            seen.add(ch)
    for ch in AZ:
        if ch not in seen:
            result.append(ch)
            seen.add(ch)
    return ''.join(result)

KEYWORDS = ["KRYPTOS", "KOMPASS", "DEFECTOR", "COLOPHON", "ABSCISSA",
            "PALIMPSEST", "BERLINCLOCK", "SHADOW", "LUCIFER", "SANBORN",
            "SCHEIDT", "CIPHER", "MATRIX", "DIGITAL"]

# ── Feistel round functions ─────────────────────────────────────────────────

def rf_vig(half, key):
    """Vigenere addition: half[i] + key[i%klen] mod 26"""
    kl = len(key)
    return [(half[i] + key[i % kl]) % 26 for i in range(len(half))]

def rf_beau(half, key):
    """Beaufort: key[i%klen] - half[i] mod 26"""
    kl = len(key)
    return [(key[i % kl] - half[i]) % 26 for i in range(len(half))]

def rf_sub(half, key):
    """Keyword substitution: use key to build alphabet, substitute"""
    alpha = keyword_alpha(to_text(key))
    table = {ord(AZ[i]) - ord('A'): ord(alpha[i]) - ord('A') for i in range(26)}
    return [table[h % 26] for h in half]

# ── P-box permutations ──────────────────────────────────────────────────────

def pb_identity(x): return list(x)
def pb_reverse(x): return list(reversed(x))
def pb_interleave(x):
    return [x[i] for i in range(0, len(x), 2)] + [x[i] for i in range(1, len(x), 2)]

# ── Feistel decrypt ─────────────────────────────────────────────────────────

def feistel_decrypt(ct_nums, key_nums, n_rounds, round_fn, pbox):
    """Decrypt using letter Feistel. Split at midpoint."""
    n = len(ct_nums)
    mid = n // 2
    L = list(ct_nums[:mid])
    R = list(ct_nums[mid:])

    for rnd in range(n_rounds, 0, -1):
        # Derive round subkey (rotate keyword by round number)
        rk = [(k + rnd * 3) % 26 for k in key_nums]

        # f(L, K_rnd) — L was R_{rnd-1} during encryption
        f_out = round_fn(L, rk)
        f_out = pbox(f_out)

        # Pad/truncate f_out to match R length
        if len(f_out) < len(R):
            f_out = f_out + f_out[:len(R) - len(f_out)]
        f_out = f_out[:len(R)]

        # Undo: new_L = R - f_out, new_R = L
        new_L = [(R[j] - f_out[j]) % 26 for j in range(len(R))]
        new_R = L[:]
        L, R = new_L, new_R

    return L + R

# ── SPN decrypt ──────────────────────────────────────────────────────────────

def make_stride_perm(n, stride):
    perm = []
    visited = set()
    pos = 0
    while len(perm) < n:
        while pos in visited:
            pos = (pos + 1) % n
        perm.append(pos)
        visited.add(pos)
        pos = (pos + stride) % n
    return perm

def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

def spn_decrypt(ct_nums, sub_inv, perm_inv, n_rounds):
    """SPN decrypt: n rounds of (inv_permute then inv_substitute)."""
    current = list(ct_nums)
    for _ in range(n_rounds):
        # Inverse permutation
        temp = [0] * len(current)
        for i in range(len(current)):
            temp[perm_inv[i]] = current[i]
        # Inverse substitution
        current = [sub_inv[c] for c in temp]
    return current

# ── Main ─────────────────────────────────────────────────────────────────────

def run():
    print("=" * 70)
    print("DES-INSPIRED LETTER FEISTEL / SPN ATTACK ON K4")
    print("=" * 70)
    print(f"CT ({len(CT)}): {CT}")
    print(f"Morse clue: 'DIGETAL INTERPRETATION' = digital cipher?")
    print(f"DES parallel: 64-8=56 effective bits. K4: 97-24=73 effective chars.")
    print()

    ct_nums = to_nums(CT)
    results = []
    best_crib = 0

    # ═══ PHASE 1: FEISTEL ON 97 CHARS ═══
    print(f"{'='*70}")
    print("PHASE 1: Letter Feistel on 97 chars")
    print("="*70)

    round_fns = [("vig", rf_vig), ("beau", rf_beau), ("sub", rf_sub)]
    pboxes = [("id", pb_identity), ("rev", pb_reverse), ("ilv", pb_interleave)]
    configs = 0

    for kw in KEYWORDS:
        key_nums = to_nums(kw)
        for n_rounds in range(1, 9):
            for fn_name, rfn in round_fns:
                for pb_name, pbox in pboxes:
                    pt_nums = feistel_decrypt(ct_nums, key_nums, n_rounds, rfn, pbox)
                    pt = to_text(pt_nums)
                    cs = crib_score(pt)
                    configs += 1
                    if cs > best_crib:
                        best_crib = cs
                    if cs >= 4:
                        qg = qg_per_char(pt)
                        desc = f"Feistel r={n_rounds} kw={kw} fn={fn_name} pb={pb_name}"
                        print(f"  crib={cs}/24 qg={qg:.3f} | {desc}")
                        results.append((cs, qg, desc, pt))

    print(f"  {configs} configs, best crib={best_crib}/24")

    # ═══ PHASE 2: SPN ON 97 CHARS ═══
    print(f"\n{'='*70}")
    print("PHASE 2: SPN (Sub-Perm Network) on 97 chars")
    print("="*70)

    # Build permutations of length 97
    perms = []
    for s in [2, 3, 5, 7, 11, 13, 17, 19, 23, 27, 29, 31, 37, 41, 43, 47]:
        perms.append((f"stride-{s}", make_stride_perm(97, s)))
    perms.append(("reverse", list(range(96, -1, -1))))
    perms.append(("affine-27-21", [(27*i + 21) % 97 for i in range(97)]))
    # K2-derived affines
    for a in [3, 5, 8, 11, 13, 24, 38, 44, 57]:
        for b in [0, 21, 63, 73]:
            if math.gcd(a, 97) == 1:
                perms.append((f"affine-{a}-{b}", [(a*i + b) % 97 for i in range(97)]))

    configs2 = 0
    best_crib2 = 0
    for kw in KEYWORDS:
        alpha = keyword_alpha(kw)
        sub_fwd = [ord(alpha[i]) - ord('A') for i in range(26)]
        sub_inv = [0] * 26
        for i in range(26):
            sub_inv[sub_fwd[i]] = i

        for perm_name, perm in perms:
            perm_inv = invert_perm(perm)
            for n_rounds in range(1, 7):
                pt_nums = spn_decrypt(ct_nums, sub_inv, perm_inv, n_rounds)
                pt = to_text(pt_nums)
                cs = crib_score(pt)
                configs2 += 1
                if cs > best_crib2:
                    best_crib2 = cs
                if cs >= 4:
                    qg = qg_per_char(pt)
                    desc = f"SPN r={n_rounds} kw={kw} p={perm_name}"
                    print(f"  crib={cs}/24 qg={qg:.3f} | {desc}")
                    results.append((cs, qg, desc, pt))

    print(f"  {configs2} configs, best crib={best_crib2}/24")

    # ═══ PHASE 3: SA OVER FEISTEL PARAMETERS ═══
    print(f"\n{'='*70}")
    print("PHASE 3: SA over Feistel + SPN (keyword alphabet + perm)")
    print("="*70)

    random.seed(42)
    best_sa = (-float('inf'), "", 0)

    for restart in range(50):
        # Random keyword alphabet
        alpha = list(AZ)
        random.shuffle(alpha)
        sub_fwd = [ord(alpha[i]) - ord('A') for i in range(26)]
        sub_inv = [0] * 26
        for i in range(26):
            sub_inv[sub_fwd[i]] = i

        # Random permutation of 97
        perm = list(range(97))
        random.shuffle(perm)
        perm_inv = invert_perm(perm)

        n_rounds = random.randint(1, 4)
        pt_nums = spn_decrypt(ct_nums, sub_inv, perm_inv, n_rounds)
        pt = to_text(pt_nums)
        cs = crib_score(pt)
        qg = qg_score(pt)
        score = qg + cs * 30.0

        for step in range(30000):
            t = 2.0 * (0.01 / 2.0) ** (step / 29999)

            # Mutate: swap two in alphabet OR swap two in permutation
            if random.random() < 0.5:
                new_alpha = list(alpha)
                i, j = random.sample(range(26), 2)
                new_alpha[i], new_alpha[j] = new_alpha[j], new_alpha[i]
                new_sub_fwd = [ord(new_alpha[k]) - ord('A') for k in range(26)]
                new_sub_inv = [0] * 26
                for k in range(26):
                    new_sub_inv[new_sub_fwd[k]] = k
                new_perm, new_perm_inv = perm, perm_inv
            else:
                new_alpha = alpha
                new_sub_inv = sub_inv
                new_perm = list(perm)
                i, j = random.sample(range(97), 2)
                new_perm[i], new_perm[j] = new_perm[j], new_perm[i]
                new_perm_inv = invert_perm(new_perm)
                new_sub_fwd = sub_fwd

            npt_nums = spn_decrypt(ct_nums, new_sub_inv, new_perm_inv, n_rounds)
            npt = to_text(npt_nums)
            ncs = crib_score(npt)
            nqg = qg_score(npt)
            new_score = nqg + ncs * 30.0

            if new_score > score or random.random() < math.exp((new_score - score) / t):
                alpha = new_alpha if isinstance(new_alpha, list) else list(new_alpha)
                sub_fwd = new_sub_fwd
                sub_inv = new_sub_inv
                perm = new_perm
                perm_inv = new_perm_inv
                score = new_score
                pt = npt
                cs = ncs

                if score > best_sa[0]:
                    best_sa = (score, npt, ncs)

        if restart % 10 == 0:
            print(f"  SA restart {restart}: best crib={best_sa[2]}/24 "
                  f"qg={qg_per_char(best_sa[1]):.3f} | {best_sa[1][:40]}...")

    print(f"  SA best: crib={best_sa[2]}/24 qg={qg_per_char(best_sa[1]):.3f}")
    if best_sa[2] >= 4:
        results.append((best_sa[2], qg_per_char(best_sa[1]), "SA-SPN", best_sa[1]))

    # ═══ SUMMARY ═══
    print(f"\n{'='*70}")
    print("SUMMARY")
    print("="*70)
    total = configs + configs2
    print(f"Deterministic: {total} configs")
    print(f"SA: 50 restarts × 30K steps")

    if results:
        results.sort(key=lambda x: (-x[0], -x[1]))
        for cs, qg, desc, pt in results[:10]:
            print(f"  crib={cs}/24 qg={qg:.3f} | {desc}")
    else:
        print("  No results above threshold (crib ≥ 4)")

if __name__ == "__main__":
    t0 = time.time()
    run()
    print(f"\nElapsed: {time.time()-t0:.1f}s")
