#!/usr/bin/env python3
"""
f_composition_k4_v3_stateful.py — Stateful/architecture-specific composition campaigns.

Tests the hypothesis that K4 uses a hand-executable, architecture-derived
masking system rather than standard periodic/transposition constructions.

Campaign structure:
  A. Progressive key (Fibonacci-like) as outer or inner layer
  B. Polarity switching schedules (Vig/Beau/VarBeau per position class)
  C. Band-scheduled polarity (Berlin clock bands select cipher variant)
  D. State-scheduled key modification
  E. Band-scheduled additive offsets (focused sweep)
  F. Compass-bearing offsets
  G. Best-of-breed: progressive + transposition combined

Metadata:
  id: f_composition_k4_v3_stateful
  family: composition
  status: active
  attack_type: stateful/architecture-specific composition search
  description: Nonstandard masking systems derived from sculpture architecture
"""
import sys
import os
import json
import time

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, 'src'))

from kryptos.kernel.constants import CT, ALPH_IDX
from kryptos.composition.orchestrator import CampaignPolicy, CompositionOrchestrator
from kryptos.composition.ledger import CompositionLedger


DB_PATH = os.path.join(_ROOT, 'db', 'composition_ledger.sqlite')
LOG_DIR = os.path.join(_ROOT, 'artifacts', 'composition')

THEMATIC_KW = [
    'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW',
    'BERLINCLOCK', 'EASTNORTHEAST', 'SANBORN', 'SCHEIDT',
    'KOMPASS', 'DEFECTOR', 'CLOCK', 'BERLIN',
    'WEBSTER', 'EQUINOX', 'VERDIGRIS',
]

FOCUSED_KW = [
    'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'BERLINCLOCK',
    'EASTNORTHEAST', 'SANBORN', 'SCHEIDT', 'DEFECTOR',
]


def run_campaign(name, outer, inner, peel_orders, outer_params=None,
                 inner_params=None, workers=26):
    """Run a single campaign and return summary."""
    policy = CampaignPolicy(
        name=name,
        outer_families=outer,
        inner_families=inner,
        peel_orders=peel_orders,
        outer_params=outer_params or {},
        inner_params=inner_params or {},
        workers=workers,
        score_threshold=0,
        db_path=DB_PATH,
        log_dir=LOG_DIR,
    )
    orch = CompositionOrchestrator(policy)
    preview = orch.preview()
    print(f"\n  [{name}] stacks={preview['total_stacks']}, "
          f"est_pruned={preview['estimated_pruned']}, "
          f"est_to_test={preview['estimated_to_test']}")
    return orch.run()


def main():
    import multiprocessing as mp
    workers = max(1, mp.cpu_count() - 2)
    print(f"Using {workers} workers on {mp.cpu_count()} CPUs")
    t_total = time.time()

    all_results = {}

    # ══════════════════════════════════════════════════════════════════
    # Campaign A: Progressive key (Fibonacci-like) × identity
    # ══════════════════════════════════════════════════════════════════
    print(f"\n{'='*70}")
    print("CAMPAIGN A: Progressive key (Fibonacci-like) × identity")
    print(f"{'='*70}")

    t0 = time.time()
    all_results['A_prog_identity'] = run_campaign(
        'K4-v3-A-prog-id',
        outer=['progressive_key'],
        inner=['identity'],
        peel_orders=['outer_first'],
        outer_params={'keywords': THEMATIC_KW},
        workers=workers,
    )
    print(f"  A completed in {time.time()-t0:.1f}s")

    # ══════════════════════════════════════════════════════════════════
    # Campaign B: Polarity switching × identity
    # ══════════════════════════════════════════════════════════════════
    print(f"\n{'='*70}")
    print("CAMPAIGN B: Polarity switching schedules × identity")
    print(f"{'='*70}")

    t0 = time.time()
    all_results['B_polarity_id'] = run_campaign(
        'K4-v3-B-polar-id',
        outer=['polarity_switch'],
        inner=['identity'],
        peel_orders=['outer_first'],
        outer_params={'keywords': FOCUSED_KW},
        workers=workers,
    )
    print(f"  B completed in {time.time()-t0:.1f}s")

    # ══════════════════════════════════════════════════════════════════
    # Campaign C: Band polarity (Berlin clock selects Vig/Beau/VarBeau)
    # ══════════════════════════════════════════════════════════════════
    print(f"\n{'='*70}")
    print("CAMPAIGN C: Band-polarity × identity")
    print(f"{'='*70}")

    t0 = time.time()
    # 240 band combos × 8 keywords = 1920
    all_results['C_bandpol_id'] = run_campaign(
        'K4-v3-C-bpol-id',
        outer=['band_polarity'],
        inner=['identity'],
        peel_orders=['outer_first'],
        outer_params={'keywords': FOCUSED_KW},
        workers=workers,
    )
    print(f"  C completed in {time.time()-t0:.1f}s")

    # ══════════════════════════════════════════════════════════════════
    # Campaign D: State-alphabet × identity
    # ══════════════════════════════════════════════════════════════════
    print(f"\n{'='*70}")
    print("CAMPAIGN D: State-scheduled key modification × identity")
    print(f"{'='*70}")

    t0 = time.time()
    all_results['D_state_id'] = run_campaign(
        'K4-v3-D-state-id',
        outer=['state_alphabet'],
        inner=['identity'],
        peel_orders=['outer_first'],
        outer_params={'keywords': FOCUSED_KW},
        workers=workers,
    )
    print(f"  D completed in {time.time()-t0:.1f}s")

    # ══════════════════════════════════════════════════════════════════
    # Campaign E: Band offsets (focused: prime offsets on bands B-E)
    # ══════════════════════════════════════════════════════════════════
    print(f"\n{'='*70}")
    print("CAMPAIGN E: Band-scheduled offsets × identity (focused)")
    print(f"{'='*70}")

    # Reduce parameter space: use fewer offset values
    focused_offsets = [0, 1, 3, 7, 13, 19, 25]
    t0 = time.time()
    all_results['E_bandoff_id'] = run_campaign(
        'K4-v3-E-boff-id',
        outer=['band_offset'],
        inner=['identity'],
        peel_orders=['outer_first'],
        outer_params={'offset_values': focused_offsets},
        workers=workers,
    )
    print(f"  E completed in {time.time()-t0:.1f}s")

    # ══════════════════════════════════════════════════════════════════
    # Campaign F: Compass offsets × identity
    # ══════════════════════════════════════════════════════════════════
    print(f"\n{'='*70}")
    print("CAMPAIGN F: Compass-bearing offsets × identity")
    print(f"{'='*70}")

    t0 = time.time()
    all_results['F_compass_id'] = run_campaign(
        'K4-v3-F-comp-id',
        outer=['compass_offset'],
        inner=['identity'],
        peel_orders=['outer_first'],
        workers=workers,
    )
    print(f"  F completed in {time.time()-t0:.1f}s")

    # ══════════════════════════════════════════════════════════════════
    # Campaign G: Progressive key + transposition (two-layer)
    # ══════════════════════════════════════════════════════════════════
    print(f"\n{'='*70}")
    print("CAMPAIGN G: Progressive key + transposition (two-layer)")
    print(f"{'='*70}")

    t0 = time.time()
    for tf in ['transposition_rail_fence', 'transposition_columnar']:
        if tf == 'transposition_rail_fence':
            ip = {'depths': list(range(2, 13))}
        else:
            ip = {'keywords': FOCUSED_KW[:6]}

        all_results[f'G_prog_{tf[:6]}'] = run_campaign(
            f'K4-v3-G-prog-{tf[:6]}',
            outer=['progressive_key'],
            inner=[tf],
            peel_orders=['outer_first', 'inner_first'],
            outer_params={'keywords': FOCUSED_KW},
            inner_params=ip,
            workers=workers,
        )
    print(f"  G completed in {time.time()-t0:.1f}s")

    # ══════════════════════════════════════════════════════════════════
    # Campaign H: Polarity switching + transposition (two-layer)
    # ══════════════════════════════════════════════════════════════════
    print(f"\n{'='*70}")
    print("CAMPAIGN H: Polarity switching + transposition (two-layer)")
    print(f"{'='*70}")

    t0 = time.time()
    all_results['H_polar_rail'] = run_campaign(
        'K4-v3-H-polar-rail',
        outer=['polarity_switch'],
        inner=['transposition_rail_fence'],
        peel_orders=['outer_first', 'inner_first'],
        outer_params={'keywords': FOCUSED_KW[:4],
                      'schedules': [[0, 1], [1, 0], [0, 1, 2], [0, 0, 1, 1]]},
        inner_params={'depths': list(range(2, 10))},
        workers=workers,
    )
    print(f"  H completed in {time.time()-t0:.1f}s")

    # ══════════════════════════════════════════════════════════════════
    # Summary
    # ══════════════════════════════════════════════════════════════════
    elapsed_total = time.time() - t_total
    print(f"\n{'='*70}")
    print(f"ALL v3 CAMPAIGNS COMPLETE in {elapsed_total:.1f}s")
    print(f"{'='*70}")

    ledger = CompositionLedger(DB_PATH)
    campaigns = ledger.all_campaigns()
    v3_camps = [c for c in campaigns if c.get('name', '').startswith('K4-v3')]
    total_tested = sum(c.get('tested_branches', 0) for c in v3_camps)
    total_pruned = sum(c.get('pruned_branches', 0) for c in v3_camps)
    best_overall = max((c.get('best_score', 0) for c in v3_camps), default=0)

    print(f"\nv3 stateful campaigns: {len(v3_camps)}")
    print(f"Total tested: {total_tested}")
    print(f"Total pruned: {total_pruned}")
    print(f"Best score: {best_overall}")

    # Per-campaign summary
    print("\nPer-campaign results:")
    for c in sorted(v3_camps, key=lambda x: x.get('best_score', 0), reverse=True):
        print(f"  {c['name']:<35s} tested={c.get('tested_branches', 0):>6d} "
              f"pruned={c.get('pruned_branches', 0):>6d} best={c.get('best_score', 0)}")

    # Score distribution
    v3_ids = [c['campaign_id'] for c in v3_camps]
    if v3_ids:
        placeholders = ','.join(['?' for _ in v3_ids])
        cursor = ledger.conn.execute(
            f"SELECT score, COUNT(*) FROM branches "
            f"WHERE campaign_id IN ({placeholders}) AND status = 'tested' "
            f"GROUP BY score ORDER BY score DESC",
            v3_ids,
        )
        print("\nScore distribution (v3 only):")
        for score, count in cursor.fetchall():
            bar = '#' * min(count, 60)
            print(f"  score={score:>3d}: {count:>6d} {bar}")

        # Top results
        print(f"\nTop results (v3, score >= 4):")
        cursor = ledger.conn.execute(
            f"SELECT b.score, b.ic_value, b.bean_pass, b.stack_json, b.plaintext, c.name "
            f"FROM branches b JOIN campaigns c ON b.campaign_id = c.campaign_id "
            f"WHERE b.campaign_id IN ({placeholders}) AND b.status = 'tested' AND b.score >= 4 "
            f"ORDER BY b.score DESC LIMIT 30",
            v3_ids,
        )
        for row in cursor.fetchall():
            score, ic, bean, stack_json, pt, camp = row
            stack = json.loads(stack_json)
            layers_desc = " -> ".join(
                f"{l['family']}({l['params'].get('keyword', '')[:12]})"
                for l in stack.get('layers', [])
            )
            print(f"  score={score} ic={ic or 0:.4f} bean={'Y' if bean else 'N'} "
                  f"camp={camp}")
            print(f"    layers={layers_desc}")

    ledger.close()

    # Write summary
    summary_path = os.path.join(_ROOT, 'reports', 'composition_v3_summary.json')
    os.makedirs(os.path.dirname(summary_path), exist_ok=True)
    with open(summary_path, 'w') as f:
        json.dump({
            'total_tested': total_tested,
            'total_pruned': total_pruned,
            'best_score': best_overall,
            'elapsed_seconds': elapsed_total,
            'all_results': all_results,
        }, f, indent=2, default=str)
    print(f"\nSummary: {summary_path}")


if __name__ == '__main__':
    main()
