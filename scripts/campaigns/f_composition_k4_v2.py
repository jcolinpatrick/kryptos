#!/usr/bin/env python3
"""
f_composition_k4_v2.py — Second production composition campaign against K4.

Extensions over v1:
  - Vigenere/Beaufort/VarBeaufort as inner cipher layers
  - 80-char null-extracted CT (cipher layer after stego removal)
  - Bean inequality pruning for single-layer periodic compositions
  - Transposition outer + cipher inner (the two-system hypothesis)
  - Additive outer + cipher inner (combined masking + cipher)

Campaign structure:
  D. Transposition outer × Vig/Beaufort inner (97-char)
  E. Transposition outer × Vig/Beaufort inner (80-char extracted)
  F. Additive outer × Vig/Beaufort inner (97-char, Bean-eq-passing only)
  G. Single-layer Vig/Beaufort on 80-char extracted text

Metadata:
  id: f_composition_k4_v2
  family: composition
  status: active
  attack_type: multi-layer composition search
  description: Two-system hypothesis testing with Vig/Beaufort inner layers
"""
import sys
import os
import json
import time

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, 'src'))

from kryptos.kernel.constants import CT, ALPH_IDX, CONSENSUS_NULL_POSITIONS
from kryptos.composition.orchestrator import CampaignPolicy, CompositionOrchestrator
from kryptos.composition.ledger import CompositionLedger


DB_PATH = os.path.join(_ROOT, 'db', 'composition_ledger.sqlite')
LOG_DIR = os.path.join(_ROOT, 'artifacts', 'composition')

# 80-char null-extracted ciphertext
CT_EXTRACTED = "".join(c for i, c in enumerate(CT) if i not in CONSENSUS_NULL_POSITIONS)

# Thematic keywords for cipher layers (not pre-filtered by Bean — pruning handles it)
CIPHER_KEYWORDS = [
    'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW',
    'BERLINCLOCK', 'EASTNORTHEAST', 'SANBORN', 'SCHEIDT',
    'KOMPASS', 'DEFECTOR', 'CLOCK', 'BERLIN',
    'WEBSTER', 'EQUINOX', 'VERDIGRIS', 'URANIA',
    'WORLDCLOCK', 'LANGLEY', 'CIA', 'NSA',
    'IQLUSION', 'DYAHR', 'VIRTUALLY', 'INVISIBLE',
    'DIGETAL', 'INTERPRETATU', 'LUCID', 'MEMORY',
]

# Transposition keywords
TRANS_KEYWORDS = [
    'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW',
    'BERLINCLOCK', 'SANBORN', 'SCHEIDT', 'CLOCK',
    'BERLIN', 'DEFECTOR', 'EQUINOX', 'VERDIGRIS',
]


def bean_equality_passes(keyword: str) -> bool:
    L = len(keyword)
    if L == 0:
        return False
    vals = [ALPH_IDX[c] for c in keyword.upper()]
    return vals[27 % L] == vals[65 % L]


def run_campaign_d(workers: int) -> dict:
    """Campaign D: Transposition outer × Vig/Beaufort inner (97-char CT)."""
    print(f"\n{'='*70}")
    print(f"CAMPAIGN D: Transposition outer x Vig/Beaufort inner (97-char)")
    print(f"{'='*70}")

    trans_families = ['transposition_columnar', 'transposition_rail_fence', 'block_transposition']
    cipher_families = ['vigenere', 'beaufort']

    results = {}
    for tf in trans_families:
        for cf in cipher_families:
            # Set up outer params based on transposition type
            if tf == 'transposition_rail_fence':
                outer_params = {'depths': list(range(2, 13))}
            elif tf == 'block_transposition':
                outer_params = {}  # uses default param gen
            else:
                outer_params = {'keywords': TRANS_KEYWORDS[:8]}  # limit for speed

            policy = CampaignPolicy(
                name=f'K4-v2-D-{tf[:6]}-{cf[:4]}',
                outer_families=[tf],
                inner_families=[cf],
                peel_orders=['outer_first', 'inner_first'],
                outer_params=outer_params,
                inner_params={'keywords': CIPHER_KEYWORDS},
                workers=workers,
                score_threshold=0,
                db_path=DB_PATH,
                log_dir=LOG_DIR,
            )

            orch = CompositionOrchestrator(policy)
            preview = orch.preview()
            print(f"\n  [{tf[:12]}/{cf[:4]}] stacks={preview['total_stacks']}, "
                  f"est_pruned={preview['estimated_pruned']}, "
                  f"est_to_test={preview['estimated_to_test']}")

            summary = orch.run()
            results[f'{tf}/{cf}'] = summary

    return results


def run_campaign_e(workers: int) -> dict:
    """Campaign E: Transposition outer × Vig/Beaufort inner (80-char extracted CT)."""
    print(f"\n{'='*70}")
    print(f"CAMPAIGN E: Transposition outer x Vig/Beaufort inner (80-char extracted)")
    print(f"  CT_EXTRACTED: {CT_EXTRACTED[:40]}... (len={len(CT_EXTRACTED)})")
    print(f"{'='*70}")

    trans_families = ['transposition_columnar', 'transposition_rail_fence']
    cipher_families = ['vigenere', 'beaufort']

    results = {}
    for tf in trans_families:
        for cf in cipher_families:
            if tf == 'transposition_rail_fence':
                outer_params = {'depths': list(range(2, 13))}
            else:
                outer_params = {'keywords': TRANS_KEYWORDS[:8]}

            policy = CampaignPolicy(
                name=f'K4-v2-E-{tf[:6]}-{cf[:4]}',
                outer_families=[tf],
                inner_families=[cf],
                peel_orders=['outer_first'],
                outer_params=outer_params,
                inner_params={'keywords': CIPHER_KEYWORDS},
                workers=workers,
                score_threshold=0,
                ciphertext=CT_EXTRACTED,
                db_path=DB_PATH,
                log_dir=LOG_DIR,
            )

            orch = CompositionOrchestrator(policy)
            preview = orch.preview()
            print(f"\n  [{tf[:12]}/{cf[:4]}/80c] stacks={preview['total_stacks']}, "
                  f"est_pruned={preview['estimated_pruned']}, "
                  f"est_to_test={preview['estimated_to_test']}")

            summary = orch.run()
            results[f'{tf}/{cf}/80c'] = summary

    return results


def run_campaign_f(workers: int) -> dict:
    """Campaign F: Additive outer × Vig/Beaufort inner (97-char, Bean-eq-passing masks)."""
    print(f"\n{'='*70}")
    print(f"CAMPAIGN F: Additive outer x Vig/Beaufort inner (97-char)")
    print(f"{'='*70}")

    # Only Bean-equality-passing additive masks (individual layer check skipped
    # because this is a multi-layer composition, but we pre-filter for efficiency)
    single_chars = [chr(c) for c in range(ord('A'), ord('Z') + 1)]
    mask_keywords = single_chars  # Single chars for outer additive mask

    cipher_families = ['vigenere', 'beaufort']

    results = {}
    for cf in cipher_families:
        policy = CampaignPolicy(
            name=f'K4-v2-F-add-{cf[:4]}',
            outer_families=['additive_mask'],
            inner_families=[cf],
            peel_orders=['outer_first'],
            outer_params={'keywords': mask_keywords},
            inner_params={'keywords': CIPHER_KEYWORDS},
            workers=workers,
            score_threshold=0,
            db_path=DB_PATH,
            log_dir=LOG_DIR,
        )

        orch = CompositionOrchestrator(policy)
        preview = orch.preview()
        print(f"\n  [add/{cf[:4]}] stacks={preview['total_stacks']}, "
              f"est_pruned={preview['estimated_pruned']}, "
              f"est_to_test={preview['estimated_to_test']}")

        summary = orch.run()
        results[f'add/{cf}'] = summary

    return results


def run_campaign_g(workers: int) -> dict:
    """Campaign G: Single-layer Vig/Beaufort on 80-char extracted text."""
    print(f"\n{'='*70}")
    print(f"CAMPAIGN G: Single Vig/Beaufort on 80-char extracted text")
    print(f"{'='*70}")

    cipher_families = ['vigenere', 'beaufort', 'var_beaufort']

    results = {}
    for cf in cipher_families:
        policy = CampaignPolicy(
            name=f'K4-v2-G-{cf[:4]}-80c',
            outer_families=[cf],
            inner_families=['identity'],
            peel_orders=['outer_first'],
            outer_params={'keywords': CIPHER_KEYWORDS},
            workers=workers,
            score_threshold=0,
            ciphertext=CT_EXTRACTED,
            db_path=DB_PATH,
            log_dir=LOG_DIR,
        )

        orch = CompositionOrchestrator(policy)
        preview = orch.preview()
        print(f"\n  [{cf[:4]}/80c] stacks={preview['total_stacks']}, "
              f"est_pruned={preview['estimated_pruned']}, "
              f"est_to_test={preview['estimated_to_test']}")

        summary = orch.run()
        results[f'{cf}/80c'] = summary

    return results


def main():
    import multiprocessing as mp
    workers = max(1, mp.cpu_count() - 2)
    print(f"Using {workers} workers on {mp.cpu_count()} CPUs")
    print(f"CT (97): {CT[:40]}...")
    print(f"CT extracted (80): {CT_EXTRACTED[:40]}...")

    all_results = {}
    t_total = time.time()

    # Campaign D: Trans × Cipher (97-char)
    t0 = time.time()
    results_d = run_campaign_d(workers)
    print(f"\nCampaign D completed in {time.time()-t0:.1f}s")
    for k, s in results_d.items():
        print(f"  {k}: tested={s['tested']}, pruned={s['pruned']}, best={s['best_score']}")
    all_results['D'] = results_d

    # Campaign E: Trans × Cipher (80-char extracted)
    t0 = time.time()
    results_e = run_campaign_e(workers)
    print(f"\nCampaign E completed in {time.time()-t0:.1f}s")
    for k, s in results_e.items():
        print(f"  {k}: tested={s['tested']}, pruned={s['pruned']}, best={s['best_score']}")
    all_results['E'] = results_e

    # Campaign F: Additive × Cipher (97-char)
    t0 = time.time()
    results_f = run_campaign_f(workers)
    print(f"\nCampaign F completed in {time.time()-t0:.1f}s")
    for k, s in results_f.items():
        print(f"  {k}: tested={s['tested']}, pruned={s['pruned']}, best={s['best_score']}")
    all_results['F'] = results_f

    # Campaign G: Single-layer cipher on extracted text
    t0 = time.time()
    results_g = run_campaign_g(workers)
    print(f"\nCampaign G completed in {time.time()-t0:.1f}s")
    for k, s in results_g.items():
        print(f"  {k}: tested={s['tested']}, pruned={s['pruned']}, best={s['best_score']}")
    all_results['G'] = results_g

    elapsed_total = time.time() - t_total
    print(f"\n{'='*70}")
    print(f"ALL v2 CAMPAIGNS COMPLETE in {elapsed_total:.1f}s")
    print(f"{'='*70}")

    # Final summary
    ledger = CompositionLedger(DB_PATH)
    campaigns = ledger.all_campaigns()
    v2_camps = [c for c in campaigns if c.get('name', '').startswith('K4-v2')]
    total_tested = sum(c.get('tested_branches', 0) for c in v2_camps)
    total_pruned = sum(c.get('pruned_branches', 0) for c in v2_camps)
    best_overall = max((c.get('best_score', 0) for c in v2_camps), default=0)

    print(f"\nv2 campaigns: {len(v2_camps)}")
    print(f"Total tested: {total_tested}")
    print(f"Total pruned: {total_pruned}")
    print(f"Best score: {best_overall}")

    # Score distribution for v2 only
    v2_ids = [c['campaign_id'] for c in v2_camps]
    placeholders = ','.join(['?' for _ in v2_ids])
    cursor = ledger.conn.execute(
        f"SELECT score, COUNT(*) FROM branches "
        f"WHERE campaign_id IN ({placeholders}) AND status = 'tested' "
        f"GROUP BY score ORDER BY score DESC",
        v2_ids,
    )
    print("\nScore distribution (v2 only):")
    for score, count in cursor.fetchall():
        bar = '#' * min(count, 60)
        print(f"  score={score:>3d}: {count:>6d} {bar}")

    # Top results
    print("\nTop results (v2, score >= 4):")
    cursor = ledger.conn.execute(
        f"SELECT b.score, b.ic_value, b.bean_pass, b.stack_json, b.plaintext, c.name "
        f"FROM branches b JOIN campaigns c ON b.campaign_id = c.campaign_id "
        f"WHERE b.campaign_id IN ({placeholders}) AND b.status = 'tested' AND b.score >= 4 "
        f"ORDER BY b.score DESC, b.ic_value LIMIT 30",
        v2_ids,
    )
    for row in cursor.fetchall():
        score, ic, bean, stack_json, pt, camp = row
        stack = json.loads(stack_json)
        layers_desc = " -> ".join(
            f"{l['family']}({l['params'].get('keyword', '')})"
            for l in stack.get('layers', [])
        )
        pt_preview = (pt or '')[:50]
        print(f"  score={score} ic={ic or 0:.4f} bean={'Y' if bean else 'N'} "
              f"camp={camp} layers={layers_desc}")
        if pt_preview:
            print(f"    PT: {pt_preview}")

    ledger.close()

    # Write results summary
    summary_path = os.path.join(_ROOT, 'reports', 'composition_v2_summary.json')
    os.makedirs(os.path.dirname(summary_path), exist_ok=True)
    with open(summary_path, 'w') as f:
        json.dump({
            'total_tested': total_tested,
            'total_pruned': total_pruned,
            'best_score': best_overall,
            'campaigns': {c['name']: {
                'tested': c.get('tested_branches', 0),
                'pruned': c.get('pruned_branches', 0),
                'best': c.get('best_score', 0),
            } for c in v2_camps},
            'all_results': {k: {sk: sv for sk, sv in v.items()} for k, v in all_results.items()},
        }, f, indent=2, default=str)
    print(f"\nSummary written to: {summary_path}")


if __name__ == '__main__':
    main()
