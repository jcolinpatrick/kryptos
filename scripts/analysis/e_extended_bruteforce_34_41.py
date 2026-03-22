#!/usr/bin/env python3
"""Extended brute-force positions 34-41 with AP and restricted alphabet filters.

Cipher:     Beaufort A=0 (two-system model)
Family:     analysis
Status:     active
Keyspace:   ~2.5M combinations (9 AP seeds × 12^5 restricted × 11 null configs)
Last run:   2026-03-21
Best score: TBD

Extends pos34_35 brute force to positions 37-41, using:
- 9 AP-constrained seed candidates for (34,35)
- 12-value restricted alphabet filter at each new position
- 11 null placement configurations for {38-41}
- Scoring: row clustering, AP enrichment, IC, quadgrams, Bean constraints
- Parallelized across available cores
"""
import sys, os, json, statistics
from collections import Counter
from datetime import datetime
from multiprocessing import Pool, cpu_count
from itertools import product

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, ALPH, ALPH_IDX, KRYPTOS_ALPHABET

KA = KRYPTOS_ALPHABET
KA_IDX = {ch: i for i, ch in enumerate(KA)}

def az(ch): return ALPH_IDX[ch]
def az_chr(v): return ALPH[v % 26]
def ka_row(ch): return KA_IDX[ch] // 5
def ka_col(ch): return KA_IDX[ch] % 5
def beaufort_key(ct_ch, pt_ch): return (az(ct_ch) + az(pt_ch)) % 26

def ic(values):
    n = len(values)
    if n < 2: return 0.0
    counts = Counter(values)
    return sum(f*(f-1) for f in counts.values()) / (n*(n-1))

# ── Known keystream ─────────────────────────────────────────────────────
ENE_KS = [beaufort_key(c, p) for c, p in zip(CT[21:34], "EASTNORTHEAST")]
BCL_KS = [beaufort_key(c, p) for c, p in zip(CT[63:74], "BERLINCLOCK")]
FULL_KS = ENE_KS + BCL_KS

# Restricted alphabet: 12 AZ values from known keystream
RESTRICTED = sorted(set(FULL_KS))  # [1,2,3,4,6,9,10,11,14,17,19,20]
AP_AZ = {6, 10, 14}
RESTRICTED_SET = set(RESTRICTED)

# Consensus null at 36 (skip always)
CONSENSUS_NULL_36 = True

# ── Load quadgrams ──────────────────────────────────────────────────────
quadgram_file = os.path.join(_ROOT, "data", "english_quadgrams.json")
QUADGRAMS = {}
if os.path.exists(quadgram_file):
    with open(quadgram_file) as f:
        QUADGRAMS = json.load(f)

FLOOR = -10.0

# ── AP-constrained seeds from pos34_35 ──────────────────────────────────
# These are the 9 (pt34, pt35) pairs with AP >= 8/15
def get_ap_seeds():
    seeds = []
    ct34 = az(CT[34])
    ct35 = az(CT[35])
    for pt34 in range(26):
        for pt35 in range(26):
            k34 = (ct34 + pt34) % 26
            k35 = (ct35 + pt35) % 26
            if k34 not in RESTRICTED_SET or k35 not in RESTRICTED_SET:
                continue
            ks15 = ENE_KS + [k34, k35]
            ap_count = sum(1 for v in ks15 if v in AP_AZ)
            if ap_count >= 8:
                seeds.append((k34, k35, pt34, pt35))
    return seeds

# ── Null configurations for positions 38-41 ─────────────────────────────
# Varying nulls: 2 of {38-45} are nulls. We test which of those might be in {38-41}.
# 0 nulls in {38-41}: positions 38,39,40,41 all cipher → 4 extra positions
# 1 null: C(4,1)=4 configs → 3 extra positions each
# 2 nulls: C(4,2)=6 configs → 2 extra positions each
def get_null_configs():
    """Return list of (config_name, cipher_positions) tuples.
    cipher_positions are the non-null positions in [37, 38, 39, 40, 41].
    Position 37 is always cipher (not in {38-45}).
    """
    configs = []
    base = [37]  # always cipher

    # 0 nulls in {38-41}
    configs.append(("0null_38_41", base + [38, 39, 40, 41]))

    # 1 null in {38-41}
    for null_pos in [38, 39, 40, 41]:
        remaining = [p for p in [38, 39, 40, 41] if p != null_pos]
        configs.append((f"null_{null_pos}", base + remaining))

    # 2 nulls in {38-41}
    for i in range(4):
        for j in range(i+1, 4):
            null_positions = [[38,39,40,41][i], [38,39,40,41][j]]
            remaining = [p for p in [38, 39, 40, 41] if p not in null_positions]
            configs.append((f"null_{null_positions[0]}_{null_positions[1]}", base + remaining))

    return configs

# ── Worker function ─────────────────────────────────────────────────────
def evaluate_config(args):
    """Evaluate one null configuration with all seed × extension combinations."""
    config_name, cipher_positions, seeds = args
    n_ext = len(cipher_positions)  # positions to fill (37 + subset of 38-41)
    ct_vals = [az(CT[p]) for p in cipher_positions]

    results = []

    for k34, k35, pt34, pt35 in seeds:
        # Base keystream: ENE(13) + k34 + k35 = 15 values
        base_ks = ENE_KS + [k34, k35]

        # Iterate restricted values for each cipher position
        for combo in product(RESTRICTED, repeat=n_ext):
            # Extended keystream
            ext_ks = list(base_ks) + list(combo)

            # Full keystream with BCL
            full_ks = ext_ks + BCL_KS
            n_full = len(full_ks)

            # ── Fast filters ──

            # 1. AP count in extended (should be ~50%)
            ap_count = sum(1 for v in ext_ks if v in AP_AZ)
            n_ext_ks = len(ext_ks)
            ap_rate = ap_count / n_ext_ks

            # Quick reject: AP too low
            if ap_rate < 0.35:
                continue

            # 2. Row clustering
            letters = [az_chr(v) for v in ext_ks]
            rows = [ka_row(ch) for ch in letters]
            row_pairs = sum(1 for i in range(n_ext_ks - 1) if rows[i] == rows[i+1])
            row_rate = row_pairs / (n_ext_ks - 1)

            # Quick reject: clustering too low
            if row_rate < 0.30:
                continue

            # 3. Column-0 count
            cols = [ka_col(ch) for ch in letters]
            col0 = sum(1 for c in cols if c == 0)

            # 4. IC of full keystream
            ic_full = ic(full_ks)

            # 5. Distinct values
            distinct = len(set(full_ks))

            # 6. Quadgram score for plaintext
            # Decrypt the cipher positions to get plaintext
            pt_chars = []
            pt_chars.append(az_chr(pt34))
            pt_chars.append(az_chr(pt35))
            # Position 36 = null (skip)
            for idx, pos in enumerate(cipher_positions):
                pt_val = (combo[idx] - az(CT[pos])) % 26
                pt_chars.append(az_chr(pt_val))

            pt_text = "EASTNORTHEAST" + ''.join(pt_chars)
            qg = 0.0
            if len(pt_text) >= 4:
                for i in range(len(pt_text) - 3):
                    qg += QUADGRAMS.get(pt_text[i:i+4], FLOOR)
                qg /= (len(pt_text) - 3)

            # ── Composite score ──
            composite = (
                row_pairs * 4.0 +
                ap_count * 2.5 +
                col0 * 2.0 +
                ic_full * 50.0 +
                (26 - distinct) * 1.0 +
                qg * -2.0  # More negative = worse → subtract
            )

            ks_str = ''.join(az_chr(v) for v in ext_ks)

            results.append({
                'config': config_name,
                'pt34': az_chr(pt34), 'pt35': az_chr(pt35),
                'k34': az_chr(k34), 'k35': az_chr(k35),
                'ext_keys': ''.join(az_chr(v) for v in combo),
                'cipher_pos': cipher_positions,
                'ks': ks_str,
                'pt': pt_text,
                'ap': ap_count, 'ap_rate': ap_rate,
                'row_pairs': row_pairs, 'row_rate': row_rate,
                'col0': col0, 'ic': ic_full, 'distinct': distinct,
                'qg': qg, 'composite': composite,
            })

    # Sort and keep top 100
    results.sort(key=lambda r: -r['composite'])
    return results[:100]

# ── Main ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 78)
    print("EXTENDED BRUTE FORCE: POSITIONS 34-41")
    print("=" * 78)

    seeds = get_ap_seeds()
    print(f"\nAP-constrained seeds (34,35): {len(seeds)}")
    for k34, k35, pt34, pt35 in seeds:
        print(f"  PT={az_chr(pt34)}{az_chr(pt35)} K={az_chr(k34)}{az_chr(k35)}")

    null_configs = get_null_configs()
    print(f"\nNull configurations: {len(null_configs)}")
    for name, positions in null_configs:
        print(f"  {name:20s}: cipher positions {positions}")

    # Prepare work items
    work_items = [
        (config_name, cipher_positions, seeds)
        for config_name, cipher_positions in null_configs
    ]

    # Compute total combinations
    total = sum(
        len(seeds) * len(RESTRICTED)**len(positions)
        for _, positions in null_configs
    )
    print(f"\nTotal combinations: {total:,}")

    n_workers = min(cpu_count(), 28)
    print(f"Workers: {n_workers}")
    print(f"\nStarting computation...")

    start_time = datetime.now()

    all_results = []
    with Pool(n_workers) as pool:
        for i, config_results in enumerate(pool.imap_unordered(evaluate_config, work_items)):
            elapsed = (datetime.now() - start_time).total_seconds()
            print(f"  Config {i+1}/{len(work_items)} done: "
                  f"{len(config_results)} candidates, {elapsed:.0f}s elapsed")
            all_results.extend(config_results)

    # Sort all results
    all_results.sort(key=lambda r: -r['composite'])

    elapsed = (datetime.now() - start_time).total_seconds()
    print(f"\nTotal time: {elapsed:.0f}s")
    print(f"Total candidates passing filters: {len(all_results)}")

    # ── Display results ─────────────────────────────────────────────────

    print(f"\n{'='*78}")
    print("TOP 50 CANDIDATES (ALL CONFIGS)")
    print("=" * 78)

    print(f"{'Rk':>3} {'Config':>20} {'PT34-5':>5} {'ExtKeys':>8} "
          f"{'AP':>3} {'RowP':>5} {'C0':>3} {'IC':>6} {'QG':>7} {'Score':>7}")
    print("-" * 85)

    for i, r in enumerate(all_results[:50]):
        print(f"{i+1:3d} {r['config']:>20} {r['pt34']}{r['pt35']:>3} "
              f"{r['ext_keys']:>8} "
              f"{r['ap']:3d} {r['row_pairs']:5d} {r['col0']:3d} "
              f"{r['ic']:6.4f} {r['qg']:7.3f} {r['composite']:7.1f}")

    # ── Deep analysis of top 10 ─────────────────────────────────────────

    print(f"\n{'='*78}")
    print("DEEP ANALYSIS — TOP 10")
    print("=" * 78)

    for i, r in enumerate(all_results[:10]):
        print(f"\n── #{i+1}: {r['config']} ──")
        print(f"  PT: {r['pt']}")
        print(f"  KS: {r['ks']}")
        print(f"  Cipher positions: {r['cipher_pos']}")
        print(f"  AP: {r['ap']}/{len(r['ks'])} ({r['ap_rate']:.0%})")
        print(f"  Row clustering: {r['row_pairs']} ({r['row_rate']:.0%})")
        print(f"  Col-0: {r['col0']}")
        print(f"  IC: {r['ic']:.4f}")
        print(f"  Distinct: {r['distinct']}")
        print(f"  Quadgram: {r['qg']:.3f}")
        print(f"  Composite: {r['composite']:.1f}")

    # ── Config comparison ───────────────────────────────────────────────

    print(f"\n{'='*78}")
    print("BEST SCORE BY NULL CONFIGURATION")
    print("=" * 78)

    config_bests = {}
    for r in all_results:
        cfg = r['config']
        if cfg not in config_bests or r['composite'] > config_bests[cfg]['composite']:
            config_bests[cfg] = r

    for cfg in sorted(config_bests.keys()):
        r = config_bests[cfg]
        print(f"  {cfg:20s}: {r['composite']:7.1f} — PT={r['pt'][13:]} KS={r['ks']}")

    # ── Save results ────────────────────────────────────────────────────
    outfile = os.path.join(_ROOT, "results", "e_extended_bruteforce_34_41.json")
    os.makedirs(os.path.dirname(outfile), exist_ok=True)

    output = {
        "experiment": "e_extended_bruteforce_34_41",
        "timestamp": datetime.now().isoformat(),
        "description": "Extended brute force pos 34-41 with AP + restricted alphabet filters",
        "total_combinations": total,
        "candidates_passing_filters": len(all_results),
        "elapsed_seconds": elapsed,
        "workers": n_workers,
        "top_20": [
            {
                "rank": i + 1,
                "config": r['config'],
                "pt": r['pt'],
                "ks": r['ks'],
                "ap": r['ap'], "row_pairs": r['row_pairs'],
                "ic": r['ic'], "qg": r['qg'],
                "composite": r['composite'],
            }
            for i, r in enumerate(all_results[:20])
        ],
    }

    with open(outfile, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {outfile}")
