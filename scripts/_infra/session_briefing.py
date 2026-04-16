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
    CT, CT_LEN, N_CRIBS,
    BEAN_EQ, BEAN_INEQ, BEAN_LINEAR, CRIB_WORDS,
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
          f"Bean: {len(BEAN_EQ)} eq + {len(BEAN_INEQ)} ineq + {len(BEAN_LINEAR)} linear")
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
    """Anomalies — separating surviving from retired."""
    print("── SURVIVING ANOMALIES (real but not yet exploitable) ───────────")
    print()
    surviving = [
        ("Width-21 bigram on CT97", "p=1.6e-4",
         "STEGO artifact — disappears after null extraction (documented, not actionable)"),
        ("Width-10/17 bigrams on CT73", "p=6e-3/8e-3",
         "CIPHER layer — destroyed by col7 undo (col7 mathematical artifact)"),
        ("Stehle constant-difference (pos 55-63)", "p~1/642 (corrected)",
         "Unique in K4; local coincidence, not a mechanism"),
    ]
    for name, pval, note in surviving:
        print(f"  • {name} ({pval})")
        print(f"    {note}")
    print()
    print("── RETIRED ANOMALIES (April 2026 audit) ────────────────────────")
    print()
    retired = [
        ("Null palette {B,G,I,K,O,W,Z}", "RETIRED",
         "Score-conditioned null: SA produces 11 distinct on K4 (p=0.30 vs shuffled)"),
        ("SA palette provenance (0/40K)", "RETIRED",
         "Moot — the palette claim itself is circular (post-hoc position selection)"),
        ("KA mod-5 column structure", "RETIRED",
         "Dependent on palette definition; fails all corrections"),
        ("BCL Beaufort keystream 7/8 palette", "RETIRED",
         "Dependent on palette; does not survive Bonferroni (corrected p=0.65)"),
        ("Beaufort keystream AP {G,K,O} 12/24", "RETIRED",
         "Look-elsewhere: 312 APs tested, corrected p=0.001 → Bonferroni dead"),
        ("14-col grid asymmetry", "RETIRED",
         "Dependent on palette positions; fails correction"),
        ("Mod-35 KRYPTOS×SEVEN table", "RETIRED",
         "LOO-CV accuracy 47% (below 49% baseline); zero predictive power"),
    ]
    for name, status, note in retired:
        print(f"  ✗ {name} — {status}")
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


def _bin_c_status(campaign_id):
    """Detect the actual closure state of a bin-C campaign.

    Returns (status, verdict, artifact_path) where status is one of
    {'CLOSED', 'TESTABLE', 'DEFERRED', 'UNKNOWN'}.  Reads result JSONs
    directly so the briefing never lies about already-closed work.

    Closure detection order (for each campaign):
      1. Campaign-specific result JSON with a `verdict` field
      2. Combined multi-campaign JSON where an entry's `campaign` == id
      3. Fall through to TESTABLE/DEFERRED per static hardcoded policy
    """
    # Map campaign id → list of (path, optional inner-campaign key)
    # relative to the repo root.  First match wins.
    artifact_map = {
        "C7": [
            # C7 closure comes from the admissibility sweep result.
            # Presence of this file with no UNCLEAR entries implies C7
            # work is done; for safety we also fall back to the
            # exhaustion certificate's existence.
            (os.path.join("results", "admissibility_elimination_v1",
                          "running_key_policy.json"), None),
            (os.path.join("docs", "exhaustion_certificate_2026_04_08.md"), None),
        ],
        "C1": [
            (os.path.join("results", "f_final_checklist_c1_c2.json"), "C1"),
            (os.path.join("results", "c1_carter_columnar_admissibility_v1",
                          "result.json"), None),
        ],
        "C2": [
            (os.path.join("results", "f_final_checklist_c1_c2.json"), "C2"),
            (os.path.join("results", "c2_kahn_columnar_admissibility_v1",
                          "result.json"), None),
        ],
        "C6": [
            (os.path.join("results", "f_final_checklist_c6.json"), None),
        ],
    }
    deferred = {"C3", "C4", "C5", "C8"}
    if campaign_id in deferred:
        return ("DEFERRED", None, None)

    for rel_path, inner_key in artifact_map.get(campaign_id, []):
        full_path = os.path.join(_ROOT, rel_path)
        if not os.path.exists(full_path):
            continue

        # Non-JSON fallback: existence of the exhaustion certificate
        # markdown is itself a closure signal for C7.
        if full_path.endswith(".md"):
            return ("CLOSED", "CERTIFIED", rel_path)

        try:
            with open(full_path) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue

        # Combined multi-campaign JSON: look for nested entry.
        if inner_key and isinstance(data, dict) and "campaigns" in data:
            for entry in data["campaigns"]:
                if isinstance(entry, dict) and entry.get("campaign") == inner_key:
                    return ("CLOSED", entry.get("verdict", "UNKNOWN"), rel_path)

        # Flat single-campaign JSON.
        verdict = data.get("verdict") if isinstance(data, dict) else None
        if verdict:
            return ("CLOSED", str(verdict).upper(), rel_path)

    return ("TESTABLE", None, None)


def section_open_attack_surface():
    """What remains viable. Bins from docs/exhaustion_audit_2026_04_08.md.

    Bin-C items are annotated with their actual closure state as detected
    from artifact files on disk (see `_bin_c_status`).  Closed items stay
    in the listing for audit continuity but are marked ✓ with their
    verdict and a pointer to the result JSON.
    """
    print("── FINAL CHECKLIST — BIN C (execution state) ──────────────────────")
    print()
    # (id, name, detail) — status is resolved at runtime
    bin_c = [
        ("C7", "Admissibility backlog",
         "Manual provenance review of ASSUMPTION_UNMET running-key scripts. "
         "Declare source, add license, or archive."),
        ("C1", "Carter Vol 1 + columnar w6/8/9 × 3 variants",
         "Admissibility-gated. Source: carter_tomb_vol1 (ARTIST_STATEMENT). "
         "Pre-registered thresholds: docs/preregistered_thresholds_2026_04_08.md"),
        ("C2", "Kahn Codebreakers + columnar w6/8/9 × 3 variants",
         "Admissibility-gated. Source: kahn_codebreakers (CREATOR_STATEMENT). "
         "Same thresholds."),
        ("C6", "Non-columnar 3-layer enumeration",
         "{additive,vig,beau} outer × {myszkowski,rail_fence,route,block} middle "
         "× {additive,vig,beau} inner."),
        ("C3", "Bifid as composition OUTER (DEFERRED)",
         "Only run if C1/C2/C6 escalates — priors too low otherwise."),
        ("C4", "Four-square as composition OUTER (DEFERRED)",
         "Only run if C1/C2/C6 escalates — priors too low otherwise."),
        ("C5", "Homophonic as composition OUTER (DEFERRED)",
         "Only run if earlier bin-C campaigns escalate."),
        ("C8", "Stateful seed-space expansion (DEFERRED)",
         "Only run if earlier bin-C campaigns escalate."),
    ]

    n_closed = 0
    n_testable = 0
    n_deferred = 0
    for cid, name, detail in bin_c:
        status, verdict, artifact = _bin_c_status(cid)
        if status == "CLOSED":
            n_closed += 1
            marker = "✓"
            tag = f"CLOSED ({verdict})" if verdict else "CLOSED"
        elif status == "DEFERRED":
            n_deferred += 1
            marker = "⊘"
            tag = "DEFERRED"
        else:
            n_testable += 1
            marker = "→"
            tag = "TESTABLE NOW"
        print(f"  {marker} {cid:<3s} {name} — {tag}")
        print(f"      {detail}")
        if artifact:
            print(f"      artifact: {artifact}")
    print()
    print(f"  Summary: {n_closed} closed, {n_testable} testable, "
          f"{n_deferred} deferred")
    if n_testable == 0 and n_closed > 0:
        print(f"  ⚠ All non-deferred bin-C campaigns are CLOSED. Running-key "
              f"and/or non-columnar 3-layer may already be downgraded — "
              f"consult docs/exhaustion_certificate_*.md before starting "
              f"new compute in these families.")
    print()
    print("── BIN D — weakly testable (engineering, not compute) ─────────────")
    print()
    bin_d = [
        ("Mono+Trans+Running-key",
         "E-FRAC-54: 13 mono DOF saturate detection. Needs new detector, not more sweeps."),
        ("Running-key from unknown NON-English text",
         "E-FRAC-51 bound is English-specific. Needs pre-declared language + CorpusLicense."),
        ("Archive-term operationalization (ABSCISSA, ATBASH, '4,8,10,26=Col')",
         "Needs parametric mapping from archive term to cipher family."),
        ("Pre-ENE (0-20) as separate sub-cipher",
         "E-FRAC-19: IC 'anomaly' Bonferroni p=1.0. No crib at 0-20."),
    ]
    for name, detail in bin_d:
        print(f"  → {name}")
        print(f"    {detail}")
    print()
    print("── BIN E — untestable under current clues (waiting list) ──────────")
    print()
    bin_e = [
        "Bespoke chart-based cipher — needs public chart OR CipherProcedureLicense schema",
        "Model-free null mask search — no defined statistic; palette retired April 2026",
        "K5 ciphertext cross-constraint — not published",
        "Circled letters IMG_1223-1235 — needs forensic archive extraction",
        "Photogrammetric sculpture data — needs primary-source field measurement",
        "Sanborn's private coding system — not public",
    ]
    for item in bin_e:
        print(f"  ⊘ {item}")
    print()
    print("  These are prerequisites for new testable hypotheses, not open families.")
    print()


def load_claims_registry():
    """Load docs/claims_registry.json, return [] on any error (briefing
    must not fail if the registry is absent or malformed)."""
    path = os.path.join(_ROOT, "docs", "claims_registry.json")
    try:
        with open(path) as f:
            data = json.load(f)
        return data.get("claims", [])
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []


def section_registry_flags():
    """Surface disputed and retired claim IDs from the canonical claims
    registry so that a session-start reader cannot silently inherit
    retired or disputed claims as live signal."""
    claims = load_claims_registry()
    if not claims:
        return
    disputed = [c for c in claims if c.get("status") == "disputed"]
    retired = [c for c in claims if c.get("status") == "retired"]
    superseded = [c for c in claims if c.get("status") == "superseded"]
    if not (disputed or retired or superseded):
        return
    print("── CLAIM REGISTRY — DISPUTED / RETIRED / SUPERSEDED ───────────────")
    print()
    print("  From docs/claims_registry.json. Do NOT cite these as live")
    print("  evidence without first checking docs/methodological_audits.md.")
    print()
    for bucket_name, bucket in (
        ("DISPUTED", disputed),
        ("RETIRED", retired),
        ("SUPERSEDED", superseded),
    ):
        if not bucket:
            continue
        print(f"  {bucket_name}:")
        for c in bucket:
            cid = c.get("claim_id", "?")
            stmt = c.get("statement", "")
            short = (stmt[:120] + "…") if len(stmt) > 120 else stmt
            print(f"    • {cid}: {short}")
        print()


def section_critical_constants():
    """Key constants every session needs."""
    print("── CRITICAL CONSTANTS ─────────────────────────────────────────────")
    print()
    print(f"  CT: {CT}")
    for start, word in CRIB_WORDS:
        print(f"  Crib: positions {start}-{start+len(word)-1}: {word}")
    print(f"  Bean equality: k[{BEAN_EQ[0][0]}] = k[{BEAN_EQ[0][1]}]  "
          f"({len(BEAN_INEQ)} inequalities + {len(BEAN_LINEAR)} linear constraints; "
          f"624 valid keystreams at crib positions)")
    # Null-palette / consensus-null-positions intentionally NOT printed.
    # That family is retired (claim_id: null_palette_retired,
    # memory/project_consensus_nulls_epistemic_status_2026_04_14.md).
    # Surfacing it on every session start was a prompt-embedded poison
    # per the 2026-04-14 audit. Do not re-add.
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
    section_registry_flags()
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
