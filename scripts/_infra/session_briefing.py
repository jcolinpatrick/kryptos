#!/usr/bin/env python3
"""Session briefing generator — produces a concise, current summary of the
K4 research state from authoritative data sources.

Run at the start of every Claude Code session:
    PYTHONPATH=src python3 scripts/_infra/session_briefing.py

Sources (in priority order):
  1. exhaustion_log.json     — 939 entries, family/status tracking
  2. results/*.json          — 309 result files, 156 with verdicts
  3. docs/elimination_tiers.md — Tier 1 mathematical proofs
  4. memory/*.md             — Checked-in research notes
  5. src/kryptos/kernel/constants.py — CT, cribs, null positions

Output: structured briefing to stdout (~120-150 lines).
"""

import sys
import os
import json
import glob
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, N_CRIBS, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    BEAN_EQ, BEAN_INEQ, CRIB_WORDS,
)

# ── Data loading ─────────────────────────────────────────────────────────────

def load_exhaustion_log():
    path = os.path.join(_ROOT, "exhaustion_log.json")
    with open(path) as f:
        return json.load(f)


def scan_results():
    """Scan results/*.json for verdicts, scores, timestamps."""
    entries = []
    for rf in sorted(glob.glob(os.path.join(_ROOT, "results", "*.json"))):
        try:
            with open(rf) as f:
                d = json.load(f)
            if not isinstance(d, dict):
                continue
            name = os.path.basename(rf).replace(".json", "")
            verdict = d.get("verdict") or d.get("verdict_status") or d.get("conclusion")
            if isinstance(verdict, dict):
                # Extract string summary from dict verdicts
                verdict = verdict.get("summary", str(verdict)[:60])
            best = d.get("best_score") or d.get("best_crib_score")
            ts = d.get("timestamp") or d.get("date")
            configs = d.get("total_configs") or d.get("configs_tested") or d.get("keyspace_tested")
            entries.append({
                "name": name,
                "verdict": str(verdict).upper()[:50] if verdict else None,
                "best_score": best,
                "timestamp": str(ts) if ts else None,
                "configs": configs,
            })
        except (json.JSONDecodeError, OSError):
            pass
    return entries


def scan_results_subdirs():
    """Scan results/*/summary.json for campaign-level verdicts."""
    entries = []
    for sd in sorted(glob.glob(os.path.join(_ROOT, "results", "*", "summary.json"))):
        try:
            with open(sd) as f:
                d = json.load(f)
            name = os.path.basename(os.path.dirname(sd))
            verdict = d.get("verdict") or d.get("status")
            best = d.get("best_score") or d.get("best_crib_score")
            configs = d.get("total_configs") or d.get("configs_tested")
            entries.append({
                "name": name,
                "verdict": str(verdict)[:50] if verdict else None,
                "best_score": best,
                "configs": configs,
            })
        except (json.JSONDecodeError, OSError):
            pass
    return entries


def count_results_files():
    """Count all results files including subdirectories."""
    json_files = glob.glob(os.path.join(_ROOT, "results", "*.json"))
    subdirs = glob.glob(os.path.join(_ROOT, "results", "*/"))
    return len(json_files), len(subdirs)


def count_scripts():
    """Count experiment scripts."""
    scripts = glob.glob(os.path.join(_ROOT, "scripts", "**", "e_*.py"), recursive=True)
    scripts += glob.glob(os.path.join(_ROOT, "scripts", "**", "f_*.py"), recursive=True)
    scripts += glob.glob(os.path.join(_ROOT, "scripts", "**", "blitz_*.py"), recursive=True)
    return len(scripts)


# ── Formatters ───────────────────────────────────────────────────────────────

def format_number(n):
    if n is None:
        return "?"
    if isinstance(n, str):
        return n
    if n >= 1e9:
        return f"{n/1e9:.1f}B"
    if n >= 1e6:
        return f"{n/1e6:.1f}M"
    if n >= 1e3:
        return f"{n/1e3:.1f}K"
    return str(n)


# ── Briefing sections ───────────────────────────────────────────────────────

def section_header():
    print("=" * 72)
    print("K4 SESSION BRIEFING")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}  |  "
          f"CT: {CT_LEN} chars  |  Cribs: {N_CRIBS} positions  |  "
          f"Bean: {len(BEAN_EQ)} eq + {len(BEAN_INEQ)} ineq")
    print("=" * 72)


def section_exhaustion_summary(elog):
    """Compact family-level elimination summary."""
    print()
    print("── ELIMINATION LANDSCAPE ──────────────────────────────────────────")
    print()

    # Group by family
    families = defaultdict(lambda: {"exhausted": 0, "active": 0, "total": 0})
    for k, v in elog.items():
        fam = v.get("family", "_unknown")
        status = v.get("status", "unknown")
        families[fam]["total"] += 1
        if status == "exhausted":
            families[fam]["exhausted"] += 1
        else:
            families[fam]["active"] += 1

    total = sum(f["total"] for f in families.values())
    total_exh = sum(f["exhausted"] for f in families.values())
    total_act = sum(f["active"] for f in families.values())

    print(f"  Scripts tracked: {total}  |  Exhausted: {total_exh}  |  Active: {total_act}")
    print()

    # Show families with most exhausted (the elimination evidence)
    print(f"  {'Family':<30s} {'Exh':>4s} {'Act':>4s} {'Tot':>4s}  Status")
    print(f"  {'-'*30} {'-'*4} {'-'*4} {'-'*4}  {'-'*20}")

    # Sort: fully exhausted families first, then by total descending
    sorted_fams = sorted(families.items(),
                         key=lambda x: (-x[1]["exhausted"], -x[1]["total"]))

    for fam, counts in sorted_fams:
        if counts["total"] < 2 and counts["exhausted"] == 0:
            continue  # Skip trivial active-only entries
        pct = counts["exhausted"] / counts["total"] * 100 if counts["total"] > 0 else 0
        if counts["exhausted"] == counts["total"]:
            status = "FULLY ELIMINATED"
        elif counts["exhausted"] > 0:
            status = f"{pct:.0f}% eliminated"
        else:
            status = "active"
        print(f"  {fam:<30s} {counts['exhausted']:>4d} {counts['active']:>4d} "
              f"{counts['total']:>4d}  {status}")

    print()


def section_tier1_proofs():
    """Permanent mathematical eliminations — the things that can NEVER work."""
    print("── TIER 1: MATHEMATICAL PROOFS (permanent, do NOT re-test) ────────")
    print()
    proofs = [
        "Pure transposition (CT has 2 E's, PT needs 3)",
        "ALL periodic polyalphabetic (periods 1-26, all variants, direct correspondence)",
        "ALL autokey variants + arbitrary transposition (structural: PT-max=16/24, CT-max=21/24)",
        "ALL fractionation families (bifid, trifid, ADFGVX, four-square — structural proofs)",
        "Hill 2x2/3x3 (algebraic impossibility)",
        "Gromark/Vimark (orders 1-8, 8.74B configs)",
        "Progressive key (Bean: delta in {0,13} only)",
        "Quadratic key (0/676 survive Bean)",
        "Fibonacci key (0/676 survive Bean)",
        "Columnar w5,w7: ZERO Bean passes across all orderings",
        "Columnar w6,w8,w9: exhaustive, max 13-14/24 = noise",
        "Columnar w10-15: sampled 100K each, all max 14/24 = noise",
        "ALL simple transposition families + periodic sub: max 13/24",
        "Double columnar (9 Bean-compatible width pairs): max 15/24 = random",
        "Myszkowski w5-13: max 15/24 = random",
        "AMSCO/Nihilist/Swapped w8-13: ZERO Bean passes",
        "ANY transposition + periodic key at 17 of 25 periods (Bean impossibility proof)",
        "Null mask (any 24 positions) + periodic sub p=1-23 (algebraic proof)",
        "Three-layer Sub+Trans+Sub at p1*p2<=50: ZERO candidates",
        "Mono+Trans+Periodic at periods 3-7: ZERO candidates (bipartite too stringent)",
    ]
    for p in proofs:
        print(f"  ✗ {p}")
    print()


def section_results_verdicts(results):
    """Key results with their verdicts."""
    print("── RECENT RESULTS WITH VERDICTS ───────────────────────────────────")
    print()

    # Categorize verdicts
    eliminated = []
    noise = []
    interesting = []
    other = []

    for r in results:
        v = r["verdict"]
        if v is None:
            continue
        if "ELIMINAT" in v or "DISPROVED" in v or "STRUCTURALLY" in v:
            eliminated.append(r)
        elif "NOISE" in v or "NOT SIGNIFICANT" in v:
            noise.append(r)
        elif "INTEREST" in v or "SIGNAL" in v or "PROMISING" in v or "ELEVATED" in v:
            interesting.append(r)
        else:
            other.append(r)

    print(f"  Eliminated: {len(eliminated)}  |  Noise: {len(noise)}  |  "
          f"Interesting: {len(interesting)}  |  Other: {len(other)}")
    print()

    # Show eliminated results (these are the important ones)
    if eliminated:
        print(f"  ELIMINATED ({len(eliminated)}):")
        for r in eliminated[:15]:
            score_str = f" best={r['best_score']}" if r["best_score"] is not None else ""
            print(f"    {r['name'][:45]:<45s} {r['verdict'][:25]}{score_str}")
        if len(eliminated) > 15:
            print(f"    ... and {len(eliminated)-15} more")
        print()

    # Show interesting (these need attention)
    if interesting:
        print(f"  INTERESTING/SIGNAL ({len(interesting)}):")
        for r in interesting:
            score_str = f" best={r['best_score']}" if r["best_score"] is not None else ""
            ts_str = f" ({r['timestamp'][:10]})" if r["timestamp"] else ""
            print(f"    {r['name'][:45]:<45s} {r['verdict'][:25]}{score_str}{ts_str}")
        print()


def section_confirmed_anomalies():
    """Anomalies that are real but unexploitable."""
    print("── CONFIRMED ANOMALIES (real but not yet exploitable) ─────────────")
    print()
    anomalies = [
        ("Null palette {B,G,I,K,O,W,Z}", "p~3e-5 nominal",
         "Model-conditional (positions shift w/ cipher model, Jaccard 0.161)"),
        ("SA does NOT create palette", "0/40K SA masks have ≤7 distinct",
         "Palette is K4-specific, not optimizer artifact"),
        ("KA mod-5 column structure", "p=0.0005",
         "All 7 palette letters in KA cols {0,3} of 5-wide grid"),
        ("BCL Beaufort keystream 7/8 palette", "p=0.0006",
         "Unique to Beaufort A=0; model-independent computation"),
        ("Beaufort keystream AP {G,K,O} 12/24", "p=3.9e-6",
         "Strongest single keystream signal; intrinsic to (CT,cribs) under Beaufort"),
        ("Width-21 bigram on CT97", "p=1.6e-4",
         "STEGO artifact — disappears after null extraction"),
        ("Width-10/17 bigrams on CT73", "p=6e-3/8e-3",
         "CIPHER layer — destroyed by col7 undo (col7 mathematical artifact)"),
        ("14-col grid asymmetry", "p~7e-5",
         "Filler density 55% left vs 17% right"),
    ]
    for name, pval, note in anomalies:
        print(f"  • {name} ({pval})")
        print(f"    {note}")
    print()


def section_do_not_test():
    """Hard stop list — things proven impossible or exhaustively tested."""
    print("── DO NOT TEST (without a materially new assumption) ──────────────")
    print()
    items = [
        "Any autokey variant (structural proof, all 4 variants × arbitrary transposition)",
        "DEFECTOR/PALIMPSEST as keywords (15/24 ceiling exhaustively confirmed)",
        "K2 numbers as keys (tested, noise)",
        "YES WONDERFUL THINGS as PT[0:18] (tested, noise)",
        "CIA cryptonym digraphs / Cold War keyword families (tested, noise)",
        "RS44 grid-mask (905.6M configs, noise)",
        "Full VIC pipeline (52M+ configs, noise)",
        "Wheatstone clock (327M configs, noise)",
        "ITA-2 XOR / Baudot mod-31 / Wilson prime mask / Sawtooth mask",
        "Interrupted-key Vigenere (14.7M configs)",
        "Ubchi null insertion / Soviet three-step / Sanborn matrix",
        "72+1 delimiter model",
        "NDYAHR (all 5 variants)",
        "K1-K3 PT as literal keys",
        "OBKOGBOWWKWIWGZIG as key material",
        "Periodic substitution on null-extracted CT73 at any period 1-23 (algebraic proof)",
    ]
    for item in items:
        print(f"  ✗ {item}")
    print()


def section_open_attack_surface():
    """What remains viable."""
    print("── OPEN ATTACK SURFACE ────────────────────────────────────────────")
    print()
    open_items = [
        ("Running key from UNTESTED source texts",
         "Model survives Bean. 13 mono DOF make detection hard. "
         "Priority: Kahn, Schliemann, pre-1990 Egyptological texts"),
        ("Bespoke chart-based system",
         "Archive shows 'Code Breaker' overlay, 'actual coding charts'. "
         "Non-standard mechanisms outside classical cipher families"),
        ("Multi-layer hand-executable systems",
         "Untested peel orders, non-obvious layer combinations. "
         "Mono+Trans+Running key is UNDERDETERMINED (E-FRAC-54)"),
        ("Model-free null mask search",
         "Palette confirmed not SA artifact (0/40K). "
         "Search for masks satisfying palette constraint scored by intermediate statistics"),
        ("External evidence",
         "K5 ciphertext, recovered coding charts, circled letters on IMG_1223-1235, "
         "Sanborn's coding system (in private hands)"),
        ("ABSCISSA as procedural/physical chart clue",
         "Not standard arithmetic (that's eliminated)"),
    ]
    for name, detail in open_items:
        print(f"  → {name}")
        print(f"    {detail}")
    print()


def section_critical_constants():
    """Key constants every session needs."""
    print("── CRITICAL CONSTANTS ─────────────────────────────────────────────")
    print()
    print(f"  CT: {CT}")
    for start, word in CRIB_WORDS:
        print(f"  Crib: positions {start}-{start+len(word)-1}: {word}")
    print(f"  Bean equality: k[{BEAN_EQ[0][0]}] = k[{BEAN_EQ[0][1]}]  "
          f"(242 variant-independent inequalities)")
    print(f"  Null palette: {sorted(NULL_PALETTE)}  "
          f"({len(CONSENSUS_NULL_POSITIONS)} consensus positions)")
    print(f"  Self-encrypting: CT[32]=PT[32]=S, CT[73]=PT[73]=K")
    print(f"  IC: 0.0361 (below random 0.0385, NOT significant for n=97)")
    print()


def section_pitfalls():
    """Non-obvious traps."""
    print("── PITFALLS ───────────────────────────────────────────────────────")
    print()
    pitfalls = [
        "ALL positions 0-indexed (cribs at 21-33, 63-73)",
        "Every command needs PYTHONPATH=src",
        "Import constants from kryptos.kernel.constants — NEVER hardcode",
        "Vigenere: K=(CT-PT)%26 | Beaufort: K=(CT+PT)%26 | VarBeau: K=(PT-CT)%26",
        "High scores at large periods are ALWAYS false positives (underdetermination)",
        "KA ordering: KRYPTOSABCDEFGHIJLMNQUVWXZ (non-standard, all 26 letters)",
        "Null positions are MODEL-DEPENDENT — state which model when reporting",
        "scoring/ is at kernel/scoring/, NOT a top-level module",
        "Root exhaustion_log.json is authoritative (NOT scripts/EXHAUSTION.json)",
    ]
    for p in pitfalls:
        print(f"  ⚠ {p}")
    print()


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    elog = load_exhaustion_log()
    results = scan_results()
    n_json, n_subdirs = count_results_files()
    n_scripts = count_scripts()

    section_header()
    section_critical_constants()
    section_exhaustion_summary(elog)
    section_tier1_proofs()
    section_do_not_test()
    section_confirmed_anomalies()
    section_results_verdicts(results)
    section_open_attack_surface()
    section_pitfalls()

    print("=" * 72)
    print(f"Data sources: exhaustion_log.json ({len(elog)} entries) | "
          f"results/ ({n_json} JSON + {n_subdirs} subdirs) | "
          f"{n_scripts} scripts")
    print(f"For detailed elimination proofs: docs/elimination_tiers.md")
    print(f"For experiment search: PYTHONPATH=src python3 run_attack.py --list --verbose | grep KEYWORD")
    print("=" * 72)


if __name__ == "__main__":
    main()
