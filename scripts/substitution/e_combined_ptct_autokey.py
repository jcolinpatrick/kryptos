#!/usr/bin/env python3
"""
Combined PT+CT autokey cipher from Callimahos (Military Cryptanalytics Part III, NSA 1977).

Cipher:  combined PT+CT autokey (Callimahos Chapter XII)
Family:  substitution
Status:  exhausted
Keyspace: ~93K configs (exhaustive short primers + named keywords) x 2 models x 2 feedback x 2 cipher x 2 alpha
Last run: never
Best score: N/A

The key at each position is the mod-26 SUM of preceding plaintext AND ciphertext:
  - key[0..L-1] = primer (L letters)
  - For i >= L: key[i] = (PT[i-1] + CT_input[i-1]) mod 26   [immediate predecessor]
  - OR: key[i] = (PT[i-L] + CT_input[i-L]) mod 26            [offset-L predecessor]

Decryption:
  Beaufort: PT[i] = (key[i] - CT[i]) mod 26
  Vigenere: PT[i] = (CT[i] - key[i]) mod 26

This has NEVER been comprehensively tested on K4. Only ONE config was tested previously
(DEFECTOR:AZ_beau, L=8, offset-L, on consensus mask+col7). That scored within noise.

Tests:
  Phase 1: Exhaustive short primers (L=1,2,3) x 4 configs x 2 feedback x 2 models = ~148K
  Phase 2: Named keywords x 4 configs x 2 feedback x 2 models
  Phase 3: SA over null mask for best primers from Phases 1-2

Usage: PYTHONPATH=src python3 -u scripts/substitution/e_combined_ptct_autokey.py
"""

import sys, os, time, json, random, math
import multiprocessing as mp

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, CRIB_POSITIONS

# ── Constants ──────────────────────────────────────────────────────────────

CT97 = CT
N = 97
N_NULLS = 24
N_PT = 73
MOD = 26

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ_IDX = {c: i for i, c in enumerate(AZ)}
KA_IDX = {c: i for i, c in enumerate(KA)}
AZ_TO_KA = [KA_IDX[AZ[i]] for i in range(26)]
KA_TO_AZ = [AZ_IDX[KA[i]] for i in range(26)]

ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_START = 21
BCL_START = 63
ENE_NUMS_AZ = [AZ_IDX[c] for c in ENE_WORD]
BCL_NUMS_AZ = [AZ_IDX[c] for c in BCL_WORD]

CT_NUMS_AZ = [AZ_IDX[c] for c in CT97]
CT_NUMS_KA = [KA_IDX[c] for c in CT97]

# Known 15/24 null mask (consensus)
MASK_24 = frozenset([0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96])

# Load quadgrams
QG_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json')
with open(QG_PATH) as f:
    _qg = json.load(f)
QG_FLOOR = min(_qg.values()) - 1.0

def qg_per_char(text):
    if len(text) <= 3:
        return QG_FLOOR
    s = sum(_qg.get(text[i:i+4], QG_FLOOR) for i in range(len(text)-3))
    return s / (len(text) - 3)

# Named keywords to test
NAMED_KEYWORDS = [
    "DEFECTOR", "PALIMPSEST", "KRYPTOS", "SEVEN", "ABSCISSA",
    "KOMPASS", "DEFECTORPALIMPSEST", "PALIMPSESTDEFECTOR",
    "COLOPHON", "PARALLAX", "ENIGMA", "SHADOW", "MEDUSA",
    "BERLINCLOCK", "EASTNORTHEAST",
]

# ── Columnar transposition ─────────────────────────────────────────────────

def columnar_perm(n, width):
    n_rows = (n + width - 1) // width
    grid = []
    for row in range(n_rows):
        start = row * width
        grid.append(list(range(start, min(start+width, n))))
    perm = []
    for col in range(width):
        for row in range(n_rows):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm

def reverse_perm(perm):
    inv = [0]*len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

PERM_COL7_INV = reverse_perm(columnar_perm(N_PT, 7))

# ── Core decrypt: combined PT+CT autokey ───────────────────────────────────

def combined_autokey_decrypt(ct_nums, primer_nums, variant='beau', feedback='immediate'):
    """
    Decrypt using combined PT+CT autokey.

    variant: 'beau' = Beaufort (PT = K - CT), 'vig' = Vigenere (PT = CT - K), 'vbeau' = Var Beaufort (PT = CT + K)
    feedback: 'immediate' = key[i] = (PT[i-1] + CT[i-1]) % 26 for i >= L
              'offset'    = key[i] = (PT[i-L] + CT[i-L]) % 26 for i >= L
    """
    n = len(ct_nums)
    L = len(primer_nums)
    pt = [0] * n

    for i in range(n):
        if i < L:
            k = primer_nums[i]
        else:
            if feedback == 'immediate':
                fb_idx = i - 1
            else:  # offset
                fb_idx = i - L

            if fb_idx < 0:
                k = primer_nums[i % L]
            else:
                k = (pt[fb_idx] + ct_nums[fb_idx]) % 26

        if variant == 'beau':
            pt[i] = (k - ct_nums[i]) % 26
        elif variant == 'vig':
            pt[i] = (ct_nums[i] - k) % 26
        else:  # vbeau
            pt[i] = (ct_nums[i] + k) % 26

    return pt

# ── Scoring ──────────────────────────────────────────────────────────────

def score_at_positions(pt_nums, ene_s, bcl_s, ene_nums, bcl_nums):
    """Score PT against cribs at given shifted positions."""
    e = sum(1 for j in range(13) if ene_s+j < len(pt_nums) and pt_nums[ene_s+j] == ene_nums[j])
    b = sum(1 for j in range(11) if bcl_s+j < len(pt_nums) and pt_nums[bcl_s+j] == bcl_nums[j])
    return e + b, e, b

def score_model_a(pt_nums, null_mask, ene_nums, bcl_nums):
    """Model A: null mask + col7. Cribs shifted by null count before their positions."""
    n1 = sum(1 for p in null_mask if p < ENE_START)
    n2 = sum(1 for p in null_mask if p < BCL_START)
    ene_s = ENE_START - n1
    bcl_s = BCL_START - n2
    return score_at_positions(pt_nums, ene_s, bcl_s, ene_nums, bcl_nums)

def score_model_b(pt_nums, ene_nums, bcl_nums):
    """Model B: raw 97 chars, cribs at fixed positions 21-33 and 63-73."""
    return score_at_positions(pt_nums, ENE_START, BCL_START, ene_nums, bcl_nums)

def score_free(pt_str):
    """Check if cribs appear ANYWHERE in plaintext."""
    s = 0
    if ENE_WORD in pt_str:
        s += 13
    if BCL_WORD in pt_str:
        s += 11
    return s

# ── Convert between alphabets for scoring ──────────────────────────────────

def ka_nums_to_az_str(ka_nums):
    """Convert KA-indexed numbers to AZ string."""
    return ''.join(KA[n] for n in ka_nums)

def az_nums_to_str(az_nums):
    return ''.join(AZ[n] for n in az_nums)

# ── Worker function for parallel exhaustive search ─────────────────────────

def worker_exhaustive(args):
    """Process a batch of primers for one config."""
    primers_batch, alph_name, variant, feedback, model, ct_input, ene_nums, bcl_nums, null_mask = args

    results = []

    if alph_name == 'AZ':
        alph_idx = AZ_IDX
        to_str = az_nums_to_str
    else:
        alph_idx = KA_IDX
        to_str = ka_nums_to_az_str

    ct_nums = [alph_idx[c] for c in ct_input] if isinstance(ct_input[0], str) else ct_input

    for primer_str in primers_batch:
        try:
            primer_nums = [alph_idx[c] for c in primer_str]
        except KeyError:
            continue

        pt_nums = combined_autokey_decrypt(ct_nums, primer_nums, variant=variant, feedback=feedback)

        # Get string for crib matching
        if alph_name == 'KA':
            pt_str = ka_nums_to_az_str(pt_nums)
            pt_az_nums = [AZ_IDX[c] for c in pt_str]
        else:
            pt_str = az_nums_to_str(pt_nums)
            pt_az_nums = pt_nums

        # Score
        if model == 'A':
            sc, e, b = score_model_a(pt_az_nums, null_mask, ENE_NUMS_AZ, BCL_NUMS_AZ)
        else:
            sc, e, b = score_model_b(pt_az_nums, ENE_NUMS_AZ, BCL_NUMS_AZ)

        # Free crib check
        fscore = score_free(pt_str)

        if sc >= 7 or fscore >= 11:
            qg = qg_per_char(pt_str)
            results.append({
                'primer': primer_str,
                'alph': alph_name,
                'variant': variant,
                'feedback': feedback,
                'model': model,
                'score': sc,
                'ene': e,
                'bcl': b,
                'free_score': fscore,
                'qg': qg,
                'pt': pt_str[:80],
            })

    return results


# ── Phase 1: Exhaustive short primers ──────────────────────────────────────

def generate_primers(max_len):
    """Generate all primer strings of length 1..max_len."""
    primers = {1: [], 2: [], 3: []}
    for a in range(26):
        primers[1].append(AZ[a])
        for b in range(26):
            primers[2].append(AZ[a] + AZ[b])
            if max_len >= 3:
                for c in range(26):
                    primers[3].append(AZ[a] + AZ[b] + AZ[c])
    return primers


def run_phase1_model_b():
    """Phase 1: Exhaustive search on raw 97 chars (Model B)."""
    print("\n" + "="*78)
    print("PHASE 1: EXHAUSTIVE SHORT PRIMERS — MODEL B (Raw 97)")
    print("="*78)

    primers = generate_primers(3)
    configs = []

    # For Model B, cipher operates directly on raw CT97
    for variant in ['beau', 'vig', 'vbeau']:
        for feedback in ['immediate', 'offset']:
            for alph_name in ['AZ', 'KA']:
                ct_input = list(CT97)
                for L in [1, 2, 3]:
                    if feedback == 'offset' and L == 1:
                        continue  # offset-1 == immediate
                    batch_size = max(1, len(primers[L]) // 4)
                    batches = [primers[L][i:i+batch_size] for i in range(0, len(primers[L]), batch_size)]
                    for batch in batches:
                        configs.append((batch, alph_name, variant, feedback, 'B',
                                       ct_input, ENE_NUMS_AZ, BCL_NUMS_AZ, MASK_24))

    total_primers = sum(len(c[0]) for c in configs)
    print(f"  Total primer evaluations: {total_primers:,}")
    print(f"  Worker tasks: {len(configs)}")
    sys.stdout.flush()

    t0 = time.time()
    all_results = []

    n_workers = min(8, os.cpu_count() or 4)
    with mp.Pool(n_workers) as pool:
        for batch_results in pool.imap_unordered(worker_exhaustive, configs, chunksize=1):
            all_results.extend(batch_results)

    elapsed = time.time() - t0
    print(f"  Completed in {elapsed:.1f}s")
    print(f"  Results >= 7: {len(all_results)}")

    if all_results:
        all_results.sort(key=lambda r: -r['score'])
        print(f"\n  Top results (Model B):")
        for r in all_results[:20]:
            print(f"    {r['score']:2d}/24 (e={r['ene']}/13,b={r['bcl']}/11) "
                  f"{r['alph']}_{r['variant']}_{r['feedback']} L={len(r['primer'])} "
                  f"primer={r['primer']} qg={r['qg']:.3f} free={r['free_score']} "
                  f"| {r['pt'][:50]}")

    sys.stdout.flush()
    return all_results


def run_phase1_model_a():
    """Phase 1: Exhaustive search on Model A (null mask + col7)."""
    print("\n" + "="*78)
    print("PHASE 1: EXHAUSTIVE SHORT PRIMERS — MODEL A (Mask + Col7)")
    print("="*78)

    # Extract 73 chars and apply inverse col7
    ct73_raw = [CT97[i] for i in range(N) if i not in MASK_24]
    assert len(ct73_raw) == N_PT
    ct73_trans = [ct73_raw[PERM_COL7_INV[i]] for i in range(N_PT)]
    ct73_str = ''.join(ct73_trans)

    primers = generate_primers(3)
    configs = []

    for variant in ['beau', 'vig', 'vbeau']:
        for feedback in ['immediate', 'offset']:
            for alph_name in ['AZ', 'KA']:
                ct_input = list(ct73_str)
                for L in [1, 2, 3]:
                    if feedback == 'offset' and L == 1:
                        continue  # offset-1 == immediate
                    batch_size = max(1, len(primers[L]) // 4)
                    batches = [primers[L][i:i+batch_size] for i in range(0, len(primers[L]), batch_size)]
                    for batch in batches:
                        configs.append((batch, alph_name, variant, feedback, 'A',
                                       ct_input, ENE_NUMS_AZ, BCL_NUMS_AZ, MASK_24))

    total_primers = sum(len(c[0]) for c in configs)
    print(f"  Total primer evaluations: {total_primers:,}")
    sys.stdout.flush()

    t0 = time.time()
    all_results = []

    n_workers = min(8, os.cpu_count() or 4)
    with mp.Pool(n_workers) as pool:
        for batch_results in pool.imap_unordered(worker_exhaustive, configs, chunksize=1):
            all_results.extend(batch_results)

    elapsed = time.time() - t0
    print(f"  Completed in {elapsed:.1f}s")
    print(f"  Results >= 7: {len(all_results)}")

    if all_results:
        all_results.sort(key=lambda r: -r['score'])
        print(f"\n  Top results (Model A):")
        for r in all_results[:20]:
            print(f"    {r['score']:2d}/24 (e={r['ene']}/13,b={r['bcl']}/11) "
                  f"{r['alph']}_{r['variant']}_{r['feedback']} L={len(r['primer'])} "
                  f"primer={r['primer']} qg={r['qg']:.3f} free={r['free_score']} "
                  f"| {r['pt'][:50]}")

    sys.stdout.flush()
    return all_results


# ── Phase 2: Named keywords ───────────────────────────────────────────────

def run_phase2():
    """Phase 2: Test all named keywords on both models."""
    print("\n" + "="*78)
    print("PHASE 2: NAMED KEYWORDS — BOTH MODELS")
    print("="*78)

    # Extract 73 chars and apply inverse col7 for Model A
    ct73_raw = [CT97[i] for i in range(N) if i not in MASK_24]
    ct73_trans = [ct73_raw[PERM_COL7_INV[i]] for i in range(N_PT)]
    ct73_str = ''.join(ct73_trans)

    all_results = []
    configs_tested = 0

    for primer_str in NAMED_KEYWORDS:
        for variant in ['beau', 'vig', 'vbeau']:
            for feedback in ['immediate', 'offset']:
                for alph_name in ['AZ', 'KA']:
                    if alph_name == 'AZ':
                        alph_idx = AZ_IDX
                    else:
                        alph_idx = KA_IDX

                    try:
                        primer_nums = [alph_idx[c] for c in primer_str]
                    except KeyError:
                        continue

                    # Model B: raw 97
                    ct_nums_b = [alph_idx[c] for c in CT97]
                    pt_b = combined_autokey_decrypt(ct_nums_b, primer_nums, variant, feedback)
                    if alph_name == 'KA':
                        pt_str_b = ka_nums_to_az_str(pt_b)
                        pt_az_b = [AZ_IDX[c] for c in pt_str_b]
                    else:
                        pt_str_b = az_nums_to_str(pt_b)
                        pt_az_b = pt_b

                    sc_b, e_b, b_b = score_model_b(pt_az_b, ENE_NUMS_AZ, BCL_NUMS_AZ)
                    fscore_b = score_free(pt_str_b)
                    configs_tested += 1

                    if sc_b >= 6 or fscore_b >= 11:
                        qg = qg_per_char(pt_str_b)
                        all_results.append({
                            'primer': primer_str, 'alph': alph_name, 'variant': variant,
                            'feedback': feedback, 'model': 'B', 'score': sc_b,
                            'ene': e_b, 'bcl': b_b, 'free_score': fscore_b, 'qg': qg,
                            'pt': pt_str_b[:80],
                        })

                    # Model A: mask + col7
                    ct_nums_a = [alph_idx[c] for c in ct73_str]
                    pt_a = combined_autokey_decrypt(ct_nums_a, primer_nums, variant, feedback)
                    if alph_name == 'KA':
                        pt_str_a = ka_nums_to_az_str(pt_a)
                        pt_az_a = [AZ_IDX[c] for c in pt_str_a]
                    else:
                        pt_str_a = az_nums_to_str(pt_a)
                        pt_az_a = pt_a

                    sc_a, e_a, b_a = score_model_a(pt_az_a, MASK_24, ENE_NUMS_AZ, BCL_NUMS_AZ)
                    fscore_a = score_free(pt_str_a)
                    configs_tested += 1

                    if sc_a >= 6 or fscore_a >= 11:
                        qg = qg_per_char(pt_str_a)
                        all_results.append({
                            'primer': primer_str, 'alph': alph_name, 'variant': variant,
                            'feedback': feedback, 'model': 'A', 'score': sc_a,
                            'ene': e_a, 'bcl': b_a, 'free_score': fscore_a, 'qg': qg,
                            'pt': pt_str_a[:80],
                        })

    print(f"  Configs tested: {configs_tested:,}")
    print(f"  Results >= 6: {len(all_results)}")

    if all_results:
        all_results.sort(key=lambda r: -r['score'])
        print(f"\n  Top results (Named Keywords):")
        for r in all_results[:30]:
            print(f"    {r['score']:2d}/24 (e={r['ene']}/13,b={r['bcl']}/11) "
                  f"model={r['model']} {r['alph']}_{r['variant']}_{r['feedback']} "
                  f"primer={r['primer']} qg={r['qg']:.3f} free={r['free_score']} "
                  f"| {r['pt'][:50]}")

    sys.stdout.flush()
    return all_results


# ── Phase 3: SA over null mask for promising primers ────────────────────────

def sa_null_mask(ct97_str, primer_str, variant, feedback, alph_name,
                 n_restarts=20, n_steps=3000, seed=None):
    """Simulated annealing over null mask positions for combined autokey."""
    if alph_name == 'AZ':
        alph_idx = AZ_IDX
    else:
        alph_idx = KA_IDX

    try:
        primer_nums = [alph_idx[c] for c in primer_str]
    except KeyError:
        return 0, None, None

    non_crib = sorted([i for i in range(N) if i not in CRIB_POSITIONS])
    crib_list = sorted(CRIB_POSITIONS)

    rng = random.Random(seed or 42)
    best_global = 0
    best_mask_global = None
    best_pt_global = None

    for restart in range(n_restarts):
        # Random initial mask: choose 24 from non-crib positions
        mask = set(rng.sample(non_crib, N_NULLS))

        # Evaluate
        def evaluate(msk):
            msk_set = frozenset(msk)
            ct73 = [ct97_str[i] for i in range(N) if i not in msk_set]
            assert len(ct73) == N_PT, f"Expected {N_PT}, got {len(ct73)}"
            ct73_trans = [ct73[PERM_COL7_INV[i]] for i in range(N_PT)]
            ct_nums = [alph_idx[c] for c in ct73_trans]
            pt_nums = combined_autokey_decrypt(ct_nums, primer_nums, variant, feedback)

            if alph_name == 'KA':
                pt_str = ka_nums_to_az_str(pt_nums)
                pt_az = [AZ_IDX[c] for c in pt_str]
            else:
                pt_str = az_nums_to_str(pt_nums)
                pt_az = pt_nums

            sc, e, b = score_model_a(pt_az, msk_set, ENE_NUMS_AZ, BCL_NUMS_AZ)
            return sc, pt_str

        curr_score, curr_pt = evaluate(mask)
        best_score = curr_score
        best_mask = set(mask)
        best_pt = curr_pt

        T0 = 2.0
        for step in range(n_steps):
            T = T0 * (1.0 - step / n_steps)

            # Swap: move one position out of mask, one in
            remove = rng.choice(list(mask))
            candidates = [p for p in non_crib if p not in mask]
            if not candidates:
                continue
            add = rng.choice(candidates)

            mask.discard(remove)
            mask.add(add)

            new_score, new_pt = evaluate(mask)

            delta = new_score - curr_score
            if delta > 0 or (T > 0 and rng.random() < math.exp(delta / max(T, 1e-10))):
                curr_score = new_score
                curr_pt = new_pt
                if curr_score > best_score:
                    best_score = curr_score
                    best_mask = set(mask)
                    best_pt = curr_pt
            else:
                mask.discard(add)
                mask.add(remove)

        if best_score > best_global:
            best_global = best_score
            best_mask_global = best_mask
            best_pt_global = best_pt

    return best_global, best_mask_global, best_pt_global


def run_phase3(top_results):
    """Phase 3: SA over null mask for top-scoring primers."""
    print("\n" + "="*78)
    print("PHASE 3: SA OVER NULL MASK — TOP PRIMERS")
    print("="*78)

    # Collect unique (primer, variant, feedback, alph) configs from top results
    seen = set()
    candidates = []

    # Always include some named keywords regardless of Phase 1-2 results
    for kw in ['DEFECTOR', 'KRYPTOS', 'PALIMPSEST', 'SEVEN', 'KOMPASS', 'ABSCISSA']:
        for variant in ['beau', 'vig']:
            for feedback in ['immediate', 'offset']:
                for alph in ['AZ', 'KA']:
                    key = (kw, variant, feedback, alph)
                    if key not in seen:
                        seen.add(key)
                        candidates.append(key)

    # Add top results from earlier phases
    for r in top_results[:20]:
        key = (r['primer'], r['variant'], r['feedback'], r['alph'])
        if key not in seen:
            seen.add(key)
            candidates.append(key)

    print(f"  Candidates for SA: {len(candidates)}")
    sys.stdout.flush()

    all_results = []
    t0 = time.time()

    for i, (primer_str, variant, feedback, alph_name) in enumerate(candidates):
        sc, mask, pt = sa_null_mask(
            CT97, primer_str, variant, feedback, alph_name,
            n_restarts=20, n_steps=3000, seed=42
        )

        tag = f"{alph_name}_{variant}_{feedback}"
        print(f"  [{i+1}/{len(candidates)}] {primer_str}:{tag} -> {sc}/24", end="")

        if sc >= 10:
            print(f" *** SIGNAL *** pt={pt[:50]}")
        elif sc >= 7:
            print(f" (elevated)")
        else:
            print()

        all_results.append({
            'primer': primer_str, 'alph': alph_name, 'variant': variant,
            'feedback': feedback, 'model': 'A_SA', 'score': sc,
            'pt': pt[:80] if pt else '',
            'mask': sorted(mask) if mask else [],
        })

        sys.stdout.flush()

    elapsed = time.time() - t0
    print(f"\n  SA completed in {elapsed:.1f}s")

    all_results.sort(key=lambda r: -r['score'])
    print(f"\n  Top SA results:")
    for r in all_results[:20]:
        print(f"    {r['score']:2d}/24 {r['alph']}_{r['variant']}_{r['feedback']} "
              f"primer={r['primer']} | {r['pt'][:60]}")

    return all_results


# ── Analytical check: can combined autokey satisfy crib constraints? ────────

def analytical_check():
    """Quick analytical check: at crib positions, derive what key MUST be.
    For combined autokey, key depends on PT[i-1]+CT[i-1] which cascades.
    Unlike CT-autokey (fully determined) or PT-autokey (partially), combined
    autokey's key depends on BOTH outputs. Check consistency at adjacent crib pairs."""

    print("\n" + "="*78)
    print("ANALYTICAL CHECK: Combined Autokey Crib Consistency")
    print("="*78)

    crib_pos = sorted(CRIB_DICT.keys())

    # For immediate predecessor (offset=1), at crib position p:
    # key[p] = (PT[p-1] + CT[p-1]) mod 26
    # If p-1 is ALSO a crib position, both PT[p-1] and CT[p-1] are known
    # So key[p] is fully determined -> check if decrypt gives correct PT[p]

    print("\n  Immediate predecessor, adjacent crib pairs:")
    for variant_name, variant_tag in [('Beaufort', 'beau'), ('Vigenere', 'vig'), ('VarBeau', 'vbeau')]:
        for alph_name, alph, idx in [('AZ', AZ, AZ_IDX), ('KA', KA, KA_IDX)]:
            hits = 0
            misses = 0
            checks = 0
            for p in crib_pos:
                if p - 1 in CRIB_DICT:
                    # key[p] = (idx[PT[p-1]] + idx[CT[p-1]]) mod 26
                    pt_prev = idx[CRIB_DICT[p-1]]
                    ct_prev = idx[CT97[p-1]]
                    k = (pt_prev + ct_prev) % 26
                    ct_curr = idx[CT97[p]]

                    if variant_tag == 'beau':
                        pt_derived = (k - ct_curr) % 26
                    elif variant_tag == 'vig':
                        pt_derived = (ct_curr - k) % 26
                    else:
                        pt_derived = (ct_curr + k) % 26

                    expected = idx[CRIB_DICT[p]]
                    checks += 1
                    if pt_derived == expected:
                        hits += 1
                    else:
                        misses += 1

            status = "SURVIVES" if misses == 0 and checks > 0 else f"ELIMINATED ({misses} conflicts)"
            print(f"    {alph_name}_{variant_name}: {hits}/{checks} match, {misses} conflicts -> {status}")

    sys.stdout.flush()


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()
    print("=" * 78)
    print("COMBINED PT+CT AUTOKEY (Callimahos Military Cryptanalytics Part III)")
    print("=" * 78)
    print(f"CT ({N}): {CT97}")
    print(f"Cribs: ENE@21-33, BCL@63-73 (24 known positions)")
    print(f"Cipher: key[i] = (PT[i-d] + CT[i-d]) mod 26, d=1 or d=L")
    print(f"Variants: Beaufort (K-C), Vigenere (C-K), Var Beaufort (C+K)")
    print(f"Alphabets: AZ (standard), KA (KRYPTOS)")
    print()
    sys.stdout.flush()

    # Analytical check first
    analytical_check()

    # Phase 1: Exhaustive short primers on both models
    results_b = run_phase1_model_b()
    results_a = run_phase1_model_a()

    # Phase 2: Named keywords
    results_kw = run_phase2()

    # Phase 3: SA on null mask for top primers
    all_top = sorted(results_b + results_a + results_kw, key=lambda r: -r['score'])
    results_sa = run_phase3(all_top)

    total_time = time.time() - t0

    # Summary
    print("\n" + "=" * 78)
    print("FINAL SUMMARY")
    print("=" * 78)

    all_results = results_b + results_a + results_kw + results_sa
    best = max((r['score'] for r in all_results), default=0)

    print(f"  Total configs tested: ~{len(results_b)*3 + len(results_a)*3 + len(results_kw)*3:,}+ evaluations")
    print(f"  Best score: {best}/24")
    print(f"  Total time: {total_time:.1f}s")

    if best >= 10:
        print(f"\n  *** SIGNAL DETECTED — INVESTIGATE ***")
    else:
        print(f"\n  VERDICT: Combined PT+CT autokey = NOISE on K4")
        print(f"  Callimahos Chapter XII cipher ELIMINATED for K4")

    # Save results
    results_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results',
                                 'e_combined_ptct_autokey.json')
    output = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'cipher': 'combined_ptct_autokey_callimahos',
        'total_time_s': total_time,
        'best_score': best,
        'phase1_model_b_hits': len(results_b),
        'phase1_model_a_hits': len(results_a),
        'phase2_named_hits': len(results_kw),
        'phase3_sa_results': len(results_sa),
        'top_results': sorted(all_results, key=lambda r: -r['score'])[:50],
        'verdict': 'NOISE' if best < 10 else 'SIGNAL',
    }

    os.makedirs(os.path.dirname(results_path), exist_ok=True)
    with open(results_path, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\n  Results saved: {results_path}")
    sys.stdout.flush()


if __name__ == '__main__':
    main()
