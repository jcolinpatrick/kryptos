#!/usr/bin/env python3
"""
f_composition_k4_v1.py — First production composition campaign against K4.

Campaign structure:
  A. Additive mask outer × identity inner
     - All 26 single-char shifts (Caesar equivalent)
     - 17 length-2 thematic pairs
     - 24 multi-char thematic keywords that pass Bean equality
  B. Transposition outer × identity inner
     - Columnar, Myszkowski, rail fence, route, block transposition
  C. Additive + transposition two-layer compositions
     - Top masks from A × top transposition families from B

All campaigns use score_threshold=0 to preserve full distributions.

Metadata:
  id: f_composition_k4_v1
  family: composition
  status: active
  attack_type: multi-layer composition search
  description: First systematic two-layer composition campaign
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


# ── Keyword generation ────────────────────────────────────────────────

def bean_equality_passes(keyword: str) -> bool:
    """Check if a keyword passes Bean equality for additive masking."""
    L = len(keyword)
    if L == 0:
        return False
    vals = [ALPH_IDX[c] for c in keyword.upper()]
    return vals[27 % L] == vals[65 % L]


def build_additive_keywords() -> list:
    """Build the full set of Bean-equality-passing additive keywords."""
    # Single chars (Caesar shifts) — all pass
    single = [chr(c) for c in range(ord('A'), ord('Z') + 1)]

    # Length-2 thematic pairs — all pass since 27%2 == 65%2
    len2 = ['AB', 'KR', 'KY', 'PA', 'SA', 'BE', 'CL', 'UR', 'WO',
            'SC', 'DE', 'SH', 'EQ', 'VE', 'BL', 'NO', 'EA']

    # Multi-char from thematic wordlist + manual additions
    multi_candidates = [
        'SANBORN', 'DEFECTOR', 'SCHEIDT', 'PALIMPSEST', 'BERLINCLOCK',
        'KRYPTOS', 'ABSCISSA', 'WORLDCLOCK', 'ALEXANDERPLATZ', 'EASTNORTHEAST',
        'URANIA', 'SHADOW', 'BERLIN', 'CLOCK', 'KOMPASS', 'EQUINOX',
        'VERDIGRIS', 'WEBSTER', 'MASKING', 'LANGLEY', 'CIA', 'NSA',
        'IQLUSION', 'DYAHR', 'VIRTUALLY', 'INVISIBLE', 'DIGETAL',
        'INTERPRETATU', 'LUCID', 'MEMORY', 'NORTHWEST', 'NORTHEAST',
    ]

    # Load thematic keywords file
    kw_path = os.path.join(_ROOT, 'wordlists', 'thematic_keywords.txt')
    if os.path.exists(kw_path):
        with open(kw_path) as f:
            for line in f:
                w = line.strip().upper()
                if w and len(w) > 2 and all(c in ALPH_IDX for c in w):
                    if w not in multi_candidates:
                        multi_candidates.append(w)

    multi_passing = [kw for kw in multi_candidates if bean_equality_passes(kw)]

    all_kw = list(dict.fromkeys(single + len2 + multi_passing))  # dedup preserving order
    return all_kw


# ── Transposition keyword set ─────────────────────────────────────────

TRANSPOSITION_KEYWORDS = [
    'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'BERLINCLOCK',
    'SANBORN', 'SCHEIDT', 'CLOCK', 'BERLIN', 'KOMPASS',
    'DEFECTOR', 'EQUINOX', 'VERDIGRIS', 'WEBSTER',
]


# ── Campaign runner ───────────────────────────────────────────────────

DB_PATH = os.path.join(_ROOT, 'db', 'composition_ledger.sqlite')
LOG_DIR = os.path.join(_ROOT, 'artifacts', 'composition')


def run_campaign_a(workers: int) -> dict:
    """Campaign A: Additive mask outer × identity inner."""
    keywords = build_additive_keywords()
    print(f"\n{'='*70}")
    print(f"CAMPAIGN A: Additive mask outer × identity inner")
    print(f"  Keywords: {len(keywords)} total")
    print(f"  Workers: {workers}")
    print(f"{'='*70}")

    policy = CampaignPolicy(
        name='K4-comp-A-additive',
        outer_families=['additive_mask'],
        inner_families=['identity'],
        peel_orders=['outer_first'],
        outer_params={'keywords': keywords},
        workers=workers,
        score_threshold=0,
        db_path=DB_PATH,
        log_dir=LOG_DIR,
    )

    orch = CompositionOrchestrator(policy)
    preview = orch.preview()
    print(f"  Total stacks: {preview['total_stacks']}")
    print(f"  Est. pruned: {preview['estimated_pruned']}")
    print(f"  Est. to test: {preview['estimated_to_test']}")

    return orch.run()


def run_campaign_b(workers: int) -> dict:
    """Campaign B: Transposition outer × identity inner."""
    print(f"\n{'='*70}")
    print(f"CAMPAIGN B: Transposition outer × identity inner")
    print(f"  Workers: {workers}")
    print(f"{'='*70}")

    # Sub-campaigns for each transposition family
    families = [
        ('transposition_columnar', {'keywords': TRANSPOSITION_KEYWORDS}),
        ('transposition_myszkowski', {'keywords': TRANSPOSITION_KEYWORDS}),
        ('transposition_rail_fence', {'depths': list(range(2, 20))}),
        ('transposition_route', {}),  # uses defaults
        ('block_transposition', {}),  # uses defaults
    ]

    results = {}
    for fam, params in families:
        policy = CampaignPolicy(
            name=f'K4-comp-B-{fam}',
            outer_families=[fam],
            inner_families=['identity'],
            peel_orders=['outer_first', 'inner_first'],
            outer_params=params,
            workers=workers,
            score_threshold=0,
            db_path=DB_PATH,
            log_dir=LOG_DIR,
        )

        orch = CompositionOrchestrator(policy)
        preview = orch.preview()
        print(f"\n  [{fam}] stacks={preview['total_stacks']}, "
              f"est_pruned={preview['estimated_pruned']}, "
              f"est_to_test={preview['estimated_to_test']}")

        summary = orch.run()
        results[fam] = summary

    return results


def run_campaign_c(workers: int, top_masks: list, top_trans_families: list) -> dict:
    """Campaign C: Additive + transposition two-layer compositions."""
    print(f"\n{'='*70}")
    print(f"CAMPAIGN C: Additive + transposition two-layer")
    print(f"  Masks: {len(top_masks)}")
    print(f"  Trans families: {top_trans_families}")
    print(f"  Workers: {workers}")
    print(f"{'='*70}")

    results = {}
    for fam in top_trans_families:
        # Additive outer, transposition inner
        policy_ao = CampaignPolicy(
            name=f'K4-comp-C-add-outer-{fam}',
            outer_families=['additive_mask'],
            inner_families=[fam],
            peel_orders=['outer_first', 'inner_first'],
            outer_params={'keywords': top_masks},
            workers=workers,
            score_threshold=0,
            db_path=DB_PATH,
            log_dir=LOG_DIR,
        )

        orch = CompositionOrchestrator(policy_ao)
        preview = orch.preview()
        print(f"\n  [add_outer+{fam}] stacks={preview['total_stacks']}, "
              f"est_pruned={preview['estimated_pruned']}, "
              f"est_to_test={preview['estimated_to_test']}")

        summary = orch.run()
        results[f'add_outer+{fam}'] = summary

        # Transposition outer, additive inner
        policy_to = CampaignPolicy(
            name=f'K4-comp-C-{fam}-outer-add',
            outer_families=[fam],
            inner_families=['additive_mask'],
            peel_orders=['outer_first', 'inner_first'],
            inner_params={'keywords': top_masks},
            workers=workers,
            score_threshold=0,
            db_path=DB_PATH,
            log_dir=LOG_DIR,
        )

        orch = CompositionOrchestrator(policy_to)
        preview = orch.preview()
        print(f"\n  [{fam}_outer+add] stacks={preview['total_stacks']}, "
              f"est_pruned={preview['estimated_pruned']}, "
              f"est_to_test={preview['estimated_to_test']}")

        summary = orch.run()
        results[f'{fam}_outer+add'] = summary

    return results


def generate_report(db_path: str) -> str:
    """Generate a campaign report from the ledger."""
    ledger = CompositionLedger(db_path)
    lines = []
    lines.append("# K4 Composition Campaign Report — v1")
    lines.append(f"\nGenerated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    lines.append("")

    # Campaigns
    campaigns = ledger.all_campaigns()
    lines.append("## Campaigns\n")
    lines.append(f"| {'Name':<40s} | {'Status':<10s} | {'Total':>6s} | {'Tested':>6s} | {'Pruned':>6s} | {'Best':>5s} |")
    lines.append(f"|{'-'*42}|{'-'*12}|{'-'*8}|{'-'*8}|{'-'*8}|{'-'*7}|")
    for c in campaigns:
        lines.append(
            f"| {c.get('name','?'):<40s} | {c.get('status','?'):<10s} | "
            f"{c.get('total_branches',0):>6d} | {c.get('tested_branches',0):>6d} | "
            f"{c.get('pruned_branches',0):>6d} | {c.get('best_score',0):>5d} |"
        )

    # Coverage
    lines.append("\n## Coverage by Family\n")
    coverage = ledger.coverage_by_family()
    current_key = ""
    for row in coverage:
        key = row["campaign_key"]
        if key != current_key:
            current_key = key
            lines.append(f"\n**{key}**")
        lines.append(f"  - {row['status']}: {row['count']}")

    # Pruning
    lines.append("\n## Pruning Breakdown\n")
    pruning = ledger.pruning_summary()
    for ptype, count in sorted(pruning.items()):
        lines.append(f"- {ptype}: {count}")

    # Top results
    lines.append("\n## Top Results (all campaigns)\n")
    top = ledger.top_results(limit=30, min_score=0)
    if top:
        lines.append(f"| {'Score':>5s} | {'Bean':>4s} | {'IC':>6s} | Stack Hash | Plaintext (first 50) |")
        lines.append(f"|{'-'*7}|{'-'*6}|{'-'*8}|{'-'*12}|{'-'*52}|")
        for r in top:
            score = r.get('score', 0)
            bean = 'Y' if r.get('bean_pass') else 'N'
            ic_val = r.get('ic_value', 0.0) or 0.0
            sh = r.get('stack_hash', '')[:10]
            pt = r.get('plaintext', '')[:50]
            lines.append(f"| {score:>5d} | {bean:>4s} | {ic_val:>6.4f} | {sh:<10s} | {pt:<50s} |")
    else:
        lines.append("No results stored.")

    # Score distributions per campaign
    lines.append("\n## Score Distributions\n")
    for c in campaigns:
        cid = c.get('campaign_id')
        name = c.get('name', '?')
        cursor = ledger.conn.execute(
            "SELECT score, COUNT(*) FROM branches "
            "WHERE campaign_id = ? AND status = 'tested' "
            "GROUP BY score ORDER BY score DESC",
            (cid,)
        )
        dist = cursor.fetchall()
        if dist:
            lines.append(f"\n**{name}**")
            for score, count in dist:
                bar = '#' * min(count, 50)
                lines.append(f"  score={score:>3d}: {count:>5d} {bar}")

    ledger.close()
    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────────────

def main():
    import multiprocessing as mp
    workers = max(1, mp.cpu_count() - 2)
    print(f"Using {workers} workers on {mp.cpu_count()} CPUs")

    # Campaign A: Additive masks
    t0 = time.time()
    summary_a = run_campaign_a(workers)
    print(f"\nCampaign A completed in {time.time()-t0:.1f}s")
    print(json.dumps(summary_a, indent=2))

    # Campaign B: Transpositions
    t0 = time.time()
    summaries_b = run_campaign_b(workers)
    print(f"\nCampaign B completed in {time.time()-t0:.1f}s")
    for fam, s in summaries_b.items():
        print(f"  {fam}: tested={s['tested']}, pruned={s['pruned']}, best={s['best_score']}")

    # Determine top masks and transposition families for Campaign C
    ledger = CompositionLedger(DB_PATH)

    # Top additive masks by score
    cursor = ledger.conn.execute(
        "SELECT b.stack_json, b.score FROM branches b "
        "JOIN campaigns c ON b.campaign_id = c.campaign_id "
        "WHERE c.name = 'K4-comp-A-additive' AND b.status = 'tested' "
        "ORDER BY b.score DESC LIMIT 20"
    )
    top_mask_kws = set()
    for row in cursor.fetchall():
        try:
            stack = json.loads(row[0])
            kw = stack.get('layers', [{}])[0].get('params', {}).get('keyword', '')
            if kw:
                top_mask_kws.add(kw)
        except:
            pass

    # Also include all single-char and all multi-char that passed
    all_additive = build_additive_keywords()
    # For Campaign C, use a focused set: top scorers + all single-char
    top_masks = list(set(
        [chr(c) for c in range(ord('A'), ord('Z')+1)] +
        list(top_mask_kws)
    ))
    # Cap at 35 to keep combinatorics manageable
    top_masks = top_masks[:35]

    # Top transposition families
    top_trans = ['transposition_rail_fence', 'transposition_columnar', 'block_transposition']

    ledger.close()

    # Campaign C: Combined
    t0 = time.time()
    summaries_c = run_campaign_c(workers, top_masks, top_trans)
    print(f"\nCampaign C completed in {time.time()-t0:.1f}s")
    for key, s in summaries_c.items():
        print(f"  {key}: tested={s['tested']}, pruned={s['pruned']}, best={s['best_score']}")

    # Generate report
    report = generate_report(DB_PATH)
    report_path = os.path.join(_ROOT, 'reports', 'composition_campaign_v1.md')
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, 'w') as f:
        f.write(report)
    print(f"\nReport written to: {report_path}")

    # Also write machine-readable leaderboard
    ledger = CompositionLedger(DB_PATH)
    top_all = ledger.top_results(limit=50, min_score=0)
    leaderboard_path = os.path.join(_ROOT, 'reports', 'composition_leaderboard_v1.json')
    with open(leaderboard_path, 'w') as f:
        json.dump(top_all, f, indent=2, default=str)
    ledger.close()
    print(f"Leaderboard written to: {leaderboard_path}")


if __name__ == '__main__':
    main()
