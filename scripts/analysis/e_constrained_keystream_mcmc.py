#!/usr/bin/env python3
"""Constrained Keystream MCMC: fill unknown key positions using SA.

Cipher:     Beaufort A=0 (two-system model)
Family:     analysis
Status:     active
Keyspace:   MCMC exploration (12^49 theoretical, SA-guided)
Last run:   2026-03-21
Best score: TBD

Generates candidate 73-value keystreams satisfying all confirmed constraints:
- Restricted alphabet (12 values: B,C,D,E,G,J,K,L,O,R,T,U)
- Row clustering on KA Polybius grid
- AP enrichment (~50% from {G,K,O})
- Bean equality k[27]=k[65]
- 24 known values fixed at crib positions

Uses simulated annealing to maximize English quadgram score of
the resulting plaintext. Multiple restarts for robustness.
"""
import sys, os, json, random, math
from collections import Counter
from datetime import datetime
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, ALPH, ALPH_IDX, KRYPTOS_ALPHABET

KA = KRYPTOS_ALPHABET
KA_IDX = {ch: i for i, ch in enumerate(KA)}

def az(ch): return ALPH_IDX[ch]
def az_chr(v): return ALPH[v % 26]
def ka_row(ch): return KA_IDX[ch] // 5

def beaufort_key(ct_ch, pt_ch): return (az(ct_ch) + az(pt_ch)) % 26

# ── Known values ────────────────────────────────────────────────────────
ENE_KS = [beaufort_key(c, p) for c, p in zip(CT[21:34], "EASTNORTHEAST")]
BCL_KS = [beaufort_key(c, p) for c, p in zip(CT[63:74], "BERLINCLOCK")]

RESTRICTED = [1,2,3,4,6,9,10,11,14,17,19,20]  # AZ values
AP_AZ = {6, 10, 14}

# Load quadgrams
quadgram_file = os.path.join(_ROOT, "data", "english_quadgrams.json")
QUADGRAMS = {}
if os.path.exists(quadgram_file):
    with open(quadgram_file) as f:
        QUADGRAMS = json.load(f)

FLOOR = -10.0

# ── Null mask: use one specific 24-null configuration ───────────────────
# Consensus nulls (17): {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85}
# Varying (7): pick {38,44,55,87,93,94,95}
NULL_POSITIONS = frozenset({0,1,2,5,8,12,14,20,36,38,44,52,55,58,59,74,75,78,84,85,87,93,94,95})
assert len(NULL_POSITIONS) == 24

# Cipher positions: 97 - 24 = 73
CIPHER_POSITIONS = [p for p in range(97) if p not in NULL_POSITIONS]
assert len(CIPHER_POSITIONS) == 73

# Map cipher positions to indices in the 73-char keystream
POS_TO_IDX = {p: i for i, p in enumerate(CIPHER_POSITIONS)}

# Known keystream values at crib positions (within the 73-char space)
KNOWN = {}
for i, pos in enumerate(range(21, 34)):
    if pos in POS_TO_IDX:
        KNOWN[POS_TO_IDX[pos]] = ENE_KS[i]
for i, pos in enumerate(range(63, 74)):
    if pos in POS_TO_IDX:
        KNOWN[POS_TO_IDX[pos]] = BCL_KS[i]

# Bean equality: k[27] = k[65] in CT97 space
# Map to 73-char space
BEAN_EQ_IDX = None
if 27 in POS_TO_IDX and 65 in POS_TO_IDX:
    BEAN_EQ_IDX = (POS_TO_IDX[27], POS_TO_IDX[65])

# Unknown positions (to be filled by MCMC)
UNKNOWN_INDICES = [i for i in range(73) if i not in KNOWN]
N_UNKNOWN = len(UNKNOWN_INDICES)

print(f"Cipher positions: {len(CIPHER_POSITIONS)}")
print(f"Known keystream values: {len(KNOWN)}")
print(f"Unknown positions to fill: {N_UNKNOWN}")
print(f"Bean equality: indices {BEAN_EQ_IDX}")

# ── Scoring function ────────────────────────────────────────────────────

def score_keystream(ks73):
    """Score a 73-value keystream. Higher = better."""
    # 1. Decrypt to plaintext
    pt_chars = []
    for i, pos in enumerate(CIPHER_POSITIONS):
        pt_val = (ks73[i] - az(CT[pos])) % 26
        pt_chars.append(az_chr(pt_val))
    pt = ''.join(pt_chars)

    # 2. Quadgram score (primary objective)
    qg = 0.0
    n_qg = 0
    for i in range(len(pt) - 3):
        qg += QUADGRAMS.get(pt[i:i+4], FLOOR)
        n_qg += 1
    qg_per_char = qg / n_qg if n_qg > 0 else FLOOR

    # 3. Row clustering bonus
    letters = [az_chr(v) for v in ks73]
    rows = [ka_row(ch) for ch in letters]
    row_pairs = sum(1 for i in range(72) if rows[i] == rows[i+1])
    row_bonus = row_pairs * 0.1  # mild bonus

    # 4. AP bonus
    ap_count = sum(1 for v in ks73 if v in AP_AZ)
    ap_bonus = 0.0 if ap_count >= 30 else -0.5 * (30 - ap_count)  # penalize low AP

    return qg_per_char + row_bonus + ap_bonus, pt, qg_per_char

# ── SA worker ───────────────────────────────────────────────────────────

def sa_run(args):
    """One simulated annealing run."""
    run_id, n_steps, seed = args
    rng = random.Random(seed)

    # Initialize keystream
    ks = [0] * 73

    # Set known values
    for idx, val in KNOWN.items():
        ks[idx] = val

    # Initialize unknowns randomly from restricted set
    for idx in UNKNOWN_INDICES:
        ks[idx] = rng.choice(RESTRICTED)

    # Enforce Bean equality
    if BEAN_EQ_IDX:
        a, b = BEAN_EQ_IDX
        if a in UNKNOWN_INDICES or b in UNKNOWN_INDICES:
            # If one is known and the other unknown, set to match
            if a not in UNKNOWN_INDICES:
                ks[b] = ks[a]
            elif b not in UNKNOWN_INDICES:
                ks[a] = ks[b]
            else:
                # Both unknown: set both to same random value
                val = rng.choice(RESTRICTED)
                ks[a] = val
                ks[b] = val

    current_score, current_pt, current_qg = score_keystream(ks)
    best_score = current_score
    best_pt = current_pt
    best_qg = current_qg
    best_ks = ks[:]

    # Temperature schedule
    T_start = 2.0
    T_end = 0.01

    for step in range(n_steps):
        T = T_start * (T_end / T_start) ** (step / n_steps)

        # Pick random unknown position and propose new value
        idx = rng.choice(UNKNOWN_INDICES)
        old_val = ks[idx]
        new_val = rng.choice(RESTRICTED)
        while new_val == old_val and len(RESTRICTED) > 1:
            new_val = rng.choice(RESTRICTED)

        ks[idx] = new_val

        # Enforce Bean equality if this position is part of it
        old_partner = None
        if BEAN_EQ_IDX:
            a, b = BEAN_EQ_IDX
            if idx == a and b in UNKNOWN_INDICES:
                old_partner = (b, ks[b])
                ks[b] = new_val
            elif idx == b and a in UNKNOWN_INDICES:
                old_partner = (a, ks[a])
                ks[a] = new_val

        new_score, new_pt, new_qg = score_keystream(ks)
        delta = new_score - current_score

        if delta > 0 or rng.random() < math.exp(delta / T):
            current_score = new_score
            current_pt = new_pt
            current_qg = new_qg
            if new_score > best_score:
                best_score = new_score
                best_pt = new_pt
                best_qg = new_qg
                best_ks = ks[:]
        else:
            ks[idx] = old_val
            if old_partner:
                ks[old_partner[0]] = old_partner[1]

    # Final stats
    ap = sum(1 for v in best_ks if v in AP_AZ)
    distinct = len(set(best_ks))
    rows = [ka_row(az_chr(v)) for v in best_ks]
    row_pairs = sum(1 for i in range(72) if rows[i] == rows[i+1])

    return {
        'run_id': run_id,
        'best_score': best_score,
        'best_qg': best_qg,
        'best_pt': best_pt,
        'best_ks': ''.join(az_chr(v) for v in best_ks),
        'ap': ap,
        'distinct': distinct,
        'row_pairs': row_pairs,
    }

# ── Main ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    N_RESTARTS = 200
    N_STEPS = 500_000
    N_WORKERS = min(cpu_count(), 28)

    print("=" * 78)
    print("CONSTRAINED KEYSTREAM MCMC (SIMULATED ANNEALING)")
    print("=" * 78)
    print(f"\nRestarts: {N_RESTARTS}")
    print(f"Steps per restart: {N_STEPS:,}")
    print(f"Workers: {N_WORKERS}")
    print(f"Unknown positions: {N_UNKNOWN}")
    print(f"Restricted values: {[az_chr(v) for v in RESTRICTED]}")
    print(f"\nStarting...")

    start_time = datetime.now()

    work_items = [
        (i, N_STEPS, 20260321 * 1000 + i)
        for i in range(N_RESTARTS)
    ]

    all_results = []
    best_overall = None

    with Pool(N_WORKERS) as pool:
        for result in pool.imap_unordered(sa_run, work_items):
            all_results.append(result)
            if best_overall is None or result['best_score'] > best_overall['best_score']:
                best_overall = result

            if len(all_results) % 20 == 0:
                elapsed = (datetime.now() - start_time).total_seconds()
                print(f"  {len(all_results)}/{N_RESTARTS} done, "
                      f"best QG={best_overall['best_qg']:.3f}/char, "
                      f"{elapsed:.0f}s elapsed")

    elapsed = (datetime.now() - start_time).total_seconds()

    # Sort by score
    all_results.sort(key=lambda r: -r['best_score'])

    print(f"\n{'='*78}")
    print(f"RESULTS ({elapsed:.0f}s total)")
    print(f"{'='*78}")

    print(f"\nTOP 20 PLAINTEXT CANDIDATES:")
    for i, r in enumerate(all_results[:20]):
        print(f"\n  #{i+1} (run {r['run_id']}): QG={r['best_qg']:.3f}/char "
              f"AP={r['ap']}/73 RowP={r['row_pairs']} Dist={r['distinct']}")
        # Show plaintext with crib markers
        pt = r['best_pt']
        # Mark crib positions
        print(f"    PT: {pt[:21]}|{pt[21:34]}|{pt[34:63]}|{pt[63:74]}|{pt[74:]}")
        # Extract the inter-crib region (positions 34-62 in cipher space)
        inter_start = POS_TO_IDX.get(34, 0)
        inter_end = POS_TO_IDX.get(62, 0) + 1
        print(f"    Between cribs: {pt[inter_start:inter_end]}")

    # Score distribution
    scores = [r['best_qg'] for r in all_results]
    print(f"\n  Score distribution:")
    print(f"    Best:  {max(scores):.3f}/char")
    print(f"    Worst: {min(scores):.3f}/char")
    print(f"    Mean:  {sum(scores)/len(scores):.3f}/char")
    print(f"    English threshold: -4.0/char")
    print(f"    Random expected:   -7.0/char")

    # Check if any reach English threshold
    english_like = [r for r in all_results if r['best_qg'] >= -4.0]
    print(f"\n  Candidates reaching English threshold (≥-4.0): {len(english_like)}")

    # ── Save ────────────────────────────────────────────────────────────
    outfile = os.path.join(_ROOT, "results", "e_constrained_keystream_mcmc.json")
    os.makedirs(os.path.dirname(outfile), exist_ok=True)

    output = {
        "experiment": "e_constrained_keystream_mcmc",
        "timestamp": datetime.now().isoformat(),
        "description": "Constrained keystream MCMC with SA for 73-char Beaufort",
        "n_restarts": N_RESTARTS,
        "n_steps": N_STEPS,
        "n_workers": N_WORKERS,
        "elapsed_seconds": elapsed,
        "english_threshold_hits": len(english_like),
        "score_stats": {
            "best": max(scores), "worst": min(scores),
            "mean": sum(scores)/len(scores),
        },
        "top_10": [
            {
                "rank": i + 1,
                "run_id": r['run_id'],
                "qg_per_char": r['best_qg'],
                "plaintext": r['best_pt'],
                "keystream": r['best_ks'],
                "ap": r['ap'],
                "distinct": r['distinct'],
                "row_pairs": r['row_pairs'],
            }
            for i, r in enumerate(all_results[:10])
        ],
    }

    with open(outfile, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {outfile}")
