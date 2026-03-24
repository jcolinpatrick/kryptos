#!/usr/bin/env python3
"""
KryptosBot Campaign V2 — Polybius Mechanism Search.

Replaces campaign.py's exhausted periodic-substitution paradigm with a
novel Polybius mechanism search powered by Claude Opus API credits.

Architecture:
    Phases 1-5:  Free computational phases (row key forensics, fractionation,
                 state machine walks, K1-K3 parallel, column coupling)
    Phase 6+:    Opus-guided exploration (API budget)
                 Opus reasons about the split-coordinate Polybius model,
                 proposes novel mechanisms, tests against the known row key.

Usage:
    PYTHONPATH=src python3 -u kryptosbot/campaign_v2.py
    PYTHONPATH=src python3 -u kryptosbot/campaign_v2.py --budget 250
    PYTHONPATH=src python3 -u kryptosbot/campaign_v2.py --local-only
    PYTHONPATH=src python3 -u kryptosbot/campaign_v2.py --dry-run
    PYTHONPATH=src python3 -u kryptosbot/campaign_v2.py --phase row_key
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import logging
import math
import multiprocessing as mp
import os
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure src/ and repo root are importable (no setup.py in this repo)
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, CRIB_POSITIONS, KRYPTOS_ALPHABET,
    NULL_PALETTE, CONSENSUS_NULL_POSITIONS, BEAUFORT_KEYSTREAM_AT_CRIBS,
    BEAN_EQ, BEAN_INEQ, N_CRIBS, ALPH, ALPH_IDX,
)
from kryptosbot.polybius_scorer import (
    ROW_KEY_AT_CRIBS, COL_KEY_AT_CRIBS, CRIB_POSITIONS_ORDERED,
    KA_WIDTH, KA_NROWS, KA_LETTER_TO_COORD, KA_COORD_TO_LETTER,
    PolybiusScore, check_row_key_consistency, row_key_from_plaintext,
    col_key_from_plaintext, count_crib_matches, score_polybius_candidate,
    check_bean_eq, check_bean_eq_row,
)

logger = logging.getLogger("kryptosbot.campaign_v2")

PROJECT_ROOT = _ROOT
CAMPAIGN_DIR = PROJECT_ROOT / "results" / "campaign_v2"
STATE_FILE = CAMPAIGN_DIR / "state.json"

KA = KRYPTOS_ALPHABET

# ---------------------------------------------------------------------------
# Campaign state
# ---------------------------------------------------------------------------

@dataclass
class CampaignV2State:
    """Persistent state for Polybius mechanism search campaign."""
    budget_total: float = 250.0
    budget_spent: float = 0.0
    model: str = "claude-opus-4-6"
    started_at: str = ""
    last_round_at: str = ""

    # Phase completion: "pending" | "done"
    phase_status: dict[str, str] = field(default_factory=dict)

    # Opus loop
    rounds_completed: int = 0
    total_hypotheses_tested: int = 0
    total_candidates_tested: int = 0
    conversation_history: list[dict] = field(default_factory=list)

    # Research journal (cumulative, never reset)
    journal_insights: list[str] = field(default_factory=list)
    journal_dead_ends: list[str] = field(default_factory=list)
    journal_mechanism_log: list[dict] = field(default_factory=list)
    journal_promising: list[dict] = field(default_factory=list)
    journal_current_thread: str = ""
    stagnation_counter: int = 0

    # Best results
    best_row_key_matches: int = 0
    best_crib_score: int = 0
    best_bean_passed: bool = False
    best_plaintext: str = ""
    best_method: str = ""

    # Phase result summaries
    phase_summaries: dict[str, str] = field(default_factory=dict)

    @property
    def budget_remaining(self) -> float:
        return max(0.0, self.budget_total - self.budget_spent)

    def is_phase_done(self, name: str) -> bool:
        return self.phase_status.get(name) == "done"

    def mark_phase_done(self, name: str, summary: str) -> None:
        self.phase_status[name] = "done"
        self.phase_summaries[name] = summary

    def update_best(self, score: PolybiusScore, plaintext: str, method: str) -> bool:
        improved = False
        if score.row_key_matches > self.best_row_key_matches:
            self.best_row_key_matches = score.row_key_matches
            improved = True
        if score.crib_score > self.best_crib_score:
            self.best_crib_score = score.crib_score
            improved = True
        if improved or (score.crib_score == self.best_crib_score and
                        score.row_key_matches >= self.best_row_key_matches):
            self.best_plaintext = plaintext[:200]
            self.best_method = method
            self.best_bean_passed = score.bean_eq_passed
        return improved


def load_state() -> CampaignV2State:
    if STATE_FILE.exists():
        try:
            data = json.loads(STATE_FILE.read_text())
            state = CampaignV2State(**{
                k: v for k, v in data.items()
                if k in CampaignV2State.__dataclass_fields__
            })
            logger.info("Loaded state: %d rounds, $%.2f spent",
                        state.rounds_completed, state.budget_spent)
            return state
        except Exception as e:
            logger.error("Failed to load state: %s (starting fresh)", e)
    return CampaignV2State(started_at=datetime.now(timezone.utc).isoformat())


def save_state(state: CampaignV2State) -> None:
    CAMPAIGN_DIR.mkdir(parents=True, exist_ok=True)
    state.last_round_at = datetime.now(timezone.utc).isoformat()
    data = asdict(state)
    # Trim large lists
    data["journal_mechanism_log"] = data["journal_mechanism_log"][-200:]
    data["journal_insights"] = data["journal_insights"][-100:]
    data["journal_dead_ends"] = data["journal_dead_ends"][-100:]
    data["conversation_history"] = data["conversation_history"][-8:]
    try:
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, default=str))
        tmp.rename(STATE_FILE)
    except Exception:
        STATE_FILE.write_text(json.dumps(data, indent=2, default=str))


# ---------------------------------------------------------------------------
# Phase 1: Row key forensics
# ---------------------------------------------------------------------------

def run_row_key_forensics(state: CampaignV2State, num_workers: int) -> None:
    """Exhaustively characterize the 24-value row key sequence."""
    if state.is_phase_done("row_key_forensics"):
        return

    print("\n" + "=" * 70)
    print("  PHASE 1: Row Key Forensics")
    print(f"  Target: {list(ROW_KEY_AT_CRIBS)}")
    print("=" * 70 + "\n")

    start = time.monotonic()
    results: dict[str, Any] = {"row_key": list(ROW_KEY_AT_CRIBS)}

    # 1. Value distribution
    from collections import Counter
    dist = Counter(ROW_KEY_AT_CRIBS)
    results["distribution"] = dict(dist)
    print(f"  Distribution: {dict(sorted(dist.items()))}")

    # 2. Runs test
    runs = 1
    for i in range(1, len(ROW_KEY_AT_CRIBS)):
        if ROW_KEY_AT_CRIBS[i] != ROW_KEY_AT_CRIBS[i - 1]:
            runs += 1
    results["runs"] = runs
    print(f"  Runs: {runs} (expected ~20.2 for random mod-6)")

    # 3. Autocorrelation at all lags
    n = len(ROW_KEY_AT_CRIBS)
    autocorr = {}
    for lag in range(1, n):
        matches = sum(1 for i in range(n - lag)
                      if ROW_KEY_AT_CRIBS[i] == ROW_KEY_AT_CRIBS[i + lag])
        autocorr[lag] = matches
    results["autocorrelation"] = autocorr
    best_lag = max(autocorr, key=autocorr.get)
    print(f"  Best autocorrelation: lag={best_lag}, matches={autocorr[best_lag]}/{n - best_lag}")

    # 4. Differencing (delta sequence)
    deltas = [(ROW_KEY_AT_CRIBS[i + 1] - ROW_KEY_AT_CRIBS[i]) % KA_NROWS
              for i in range(n - 1)]
    delta_dist = Counter(deltas)
    results["delta_sequence"] = deltas
    results["delta_distribution"] = dict(delta_dist)
    print(f"  Delta distribution: {dict(sorted(delta_dist.items()))}")

    # 5. All 720 permutations of {0..5} — does any transform produce a pattern?
    best_perm_autocorr = 0
    best_perm = None
    for perm in itertools.permutations(range(KA_NROWS)):
        transformed = [perm[v] for v in ROW_KEY_AT_CRIBS]
        # Check if transformed has better autocorrelation
        for lag in [1, 2, 3]:
            matches = sum(1 for i in range(n - lag)
                          if transformed[i] == transformed[i + lag])
            if matches > best_perm_autocorr:
                best_perm_autocorr = matches
                best_perm = (perm, lag, matches, transformed[:8])
    results["best_permutation_autocorr"] = {
        "perm": list(best_perm[0]) if best_perm else None,
        "lag": best_perm[1] if best_perm else None,
        "matches": best_perm_autocorr,
        "sample": best_perm[3] if best_perm else None,
    }
    print(f"  Best substitution permutation: {best_perm}")

    # 6. Test as LCG output: x[n+1] = (a*x[n] + b) mod 6
    best_lcg = {"matches": 0}
    for a in range(KA_NROWS):
        for b in range(KA_NROWS):
            for seed in range(KA_NROWS):
                seq = [seed]
                for _ in range(CT_LEN - 1):
                    seq.append((a * seq[-1] + b) % KA_NROWS)
                m, _ = check_row_key_consistency(seq)
                if m > best_lcg["matches"]:
                    best_lcg = {"a": a, "b": b, "seed": seed, "matches": m}
    results["best_lcg"] = best_lcg
    print(f"  Best LCG (a*x+b mod 6): {best_lcg}")

    # 7. Cross-reference with K1/K2/K3 PT row coordinates
    K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
    K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUABORTTHETRANSMISSIONTHEGOODSISVERYHIDDENXHOWDOESONEFIGURETHATOUT"
    # We don't actually know K4 PT, but K1/K2 PTs can be checked
    k1_rows = [KA_LETTER_TO_COORD[ch][0] if ch in KA_LETTER_TO_COORD else -1
               for ch in K1_PT.upper()]
    k2_rows = [KA_LETTER_TO_COORD[ch][0] if ch in KA_LETTER_TO_COORD else -1
               for ch in K2_PT.upper()]

    # Check if row key appears as substring
    rk_str = "".join(str(v) for v in ROW_KEY_AT_CRIBS)
    k1_str = "".join(str(v) for v in k1_rows if v >= 0)
    k2_str = "".join(str(v) for v in k2_rows if v >= 0)
    k1_match = rk_str in k1_str
    k2_match = rk_str in k2_str
    results["k1_substring_match"] = k1_match
    results["k2_substring_match"] = k2_match
    print(f"  Row key in K1 PT rows: {k1_match}")
    print(f"  Row key in K2 PT rows: {k2_match}")

    elapsed = time.monotonic() - start
    results["elapsed_seconds"] = elapsed
    print(f"\n  Phase 1 complete in {elapsed:.1f}s")

    # Save
    out_path = CAMPAIGN_DIR / "row_key_forensics.json"
    CAMPAIGN_DIR.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2))

    summary = (f"runs={runs}, best_lag={best_lag}({autocorr[best_lag]}), "
               f"best_lcg={best_lcg['matches']}/24")
    state.mark_phase_done("row_key_forensics", summary)
    save_state(state)


# ---------------------------------------------------------------------------
# Phase 2: Column coupling verification
# ---------------------------------------------------------------------------

def run_column_coupling_verify(state: CampaignV2State, num_workers: int) -> None:
    """Verify and extend the stego-cipher column coupling finding."""
    if state.is_phase_done("column_coupling"):
        return

    print("\n" + "=" * 70)
    print("  PHASE 2: Column Coupling Verification")
    print("=" * 70 + "\n")

    start = time.monotonic()
    results: dict[str, Any] = {}

    # Column keys at crib positions
    results["col_key_at_cribs"] = list(COL_KEY_AT_CRIBS)
    print(f"  Column key at cribs: {list(COL_KEY_AT_CRIBS)}")

    # Verify palette letters are in columns 0 and 3
    palette_cols = set()
    for ch in NULL_PALETTE:
        if ch in KA_LETTER_TO_COORD:
            palette_cols.add(KA_LETTER_TO_COORD[ch][1])
    results["palette_columns"] = sorted(palette_cols)
    print(f"  Palette {set(NULL_PALETTE)} occupies KA columns: {sorted(palette_cols)}")

    # Column key at consensus null positions
    null_col_keys = []
    for pos in sorted(CONSENSUS_NULL_POSITIONS):
        ct_ch = CT[pos]
        ct_c = KA_LETTER_TO_COORD[ct_ch][1]
        null_col_keys.append(ct_c)
    results["ct_col_at_consensus_nulls"] = null_col_keys
    from collections import Counter
    null_col_dist = Counter(null_col_keys)
    results["null_col_distribution"] = dict(null_col_dist)
    print(f"  CT column distribution at nulls: {dict(sorted(null_col_dist.items()))}")

    # Column key periodicity check
    col_autocorr = {}
    ck = list(COL_KEY_AT_CRIBS)
    for lag in range(1, len(ck)):
        matches = sum(1 for i in range(len(ck) - lag)
                      if ck[i] == ck[i + lag])
        col_autocorr[lag] = matches
    results["col_key_autocorrelation"] = col_autocorr
    if col_autocorr:
        best_lag = max(col_autocorr, key=col_autocorr.get)
        print(f"  Best col key autocorrelation: lag={best_lag}, matches={col_autocorr[best_lag]}")

    elapsed = time.monotonic() - start
    results["elapsed_seconds"] = elapsed
    print(f"\n  Phase 2 complete in {elapsed:.1f}s")

    out_path = CAMPAIGN_DIR / "column_coupling.json"
    CAMPAIGN_DIR.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2))

    summary = f"palette_cols={sorted(palette_cols)}, col_autocorr_best={col_autocorr.get(max(col_autocorr, key=col_autocorr.get), 0) if col_autocorr else 0}"
    state.mark_phase_done("column_coupling", summary)
    save_state(state)


# ---------------------------------------------------------------------------
# Phase 3: Non-standard fractionation sweep
# ---------------------------------------------------------------------------

def _fractionation_worker(args: tuple) -> dict:
    """Test a single fractionation variant. Runs in worker process."""
    import signal as _signal
    _signal.signal(_signal.SIGINT, _signal.SIG_IGN)

    variant, params = args
    _ROOT_W = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(_ROOT_W / "src"))

    from kryptos.kernel.constants import CT, KRYPTOS_ALPHABET, CRIB_DICT, ALPH
    from kryptosbot.polybius_scorer import (
        KA_LETTER_TO_COORD, KA_COORD_TO_LETTER, KA_NROWS, KA_WIDTH,
        check_row_key_consistency, count_crib_matches,
    )

    KA = KRYPTOS_ALPHABET
    best = {"variant": variant, "params": str(params), "rk_matches": 0, "crib_hits": 0}

    # Convert CT to coordinates
    ct_coords = []
    for ch in CT:
        if ch in KA_LETTER_TO_COORD:
            ct_coords.append(KA_LETTER_TO_COORD[ch])
        else:
            ct_coords.append((0, 0))

    ct_rows = [r for r, c in ct_coords]
    ct_cols = [c for r, c in ct_coords]

    if variant == "partial_frac_row_only":
        # Apply mod-6 shift only to rows, leave columns as-is
        shift = params["shift"]
        for keyword in params["keywords"]:
            kw_indices = [KA.index(ch) for ch in keyword]
            kw_len = len(kw_indices)
            pt_chars = []
            rk = []
            for i in range(len(CT)):
                ki = kw_indices[i % kw_len] // KA_WIDTH  # row of keyword char
                pt_r = (ct_rows[i] - ki + shift) % KA_NROWS
                pt_c = ct_cols[i]
                coord = (pt_r, pt_c)
                ch = KA_COORD_TO_LETTER.get(coord, 'A')
                pt_chars.append(ch)
                # Row key: Beaufort recovery
                rk.append((ct_rows[i] + (KA_LETTER_TO_COORD[ch][0] if ch in KA_LETTER_TO_COORD else 0)) % KA_NROWS)
            pt = "".join(pt_chars)
            m, _ = check_row_key_consistency(rk)
            c = count_crib_matches(pt)
            if m > best["rk_matches"] or (m == best["rk_matches"] and c > best["crib_hits"]):
                best.update({"rk_matches": m, "crib_hits": c,
                             "method": f"partial_row/{keyword}/shift{shift}"})

    elif variant == "delayed_bifid":
        # Pair position i with i+k instead of interleaving
        delay = params["delay"]
        period = params["period"]
        for keyword in params["keywords"]:
            kw_grid = {}
            kw_grid_inv = {}
            for idx, ch in enumerate(keyword + "".join(c for c in KA if c not in keyword)):
                r, c_ = idx // KA_WIDTH, idx % KA_WIDTH
                kw_grid[ch] = (r, c_)
                kw_grid_inv[(r, c_)] = ch

            # Standard bifid with delayed pairing
            n = len(CT)
            for p in range(max(2, period - 1), min(n, period + 2)):
                rows_flat = []
                cols_flat = []
                for start in range(0, n, p):
                    block = CT[start:start + p]
                    br = [kw_grid.get(ch, (0, 0))[0] for ch in block]
                    bc = [kw_grid.get(ch, (0, 0))[1] for ch in block]
                    # Delayed: shift cols by delay positions
                    shifted_cols = bc[delay:] + bc[:delay]
                    rows_flat.extend(br)
                    cols_flat.extend(shifted_cols)

                pt_chars = []
                for i in range(n):
                    coord = (rows_flat[i] % KA_NROWS, cols_flat[i] % KA_WIDTH)
                    pt_chars.append(kw_grid_inv.get(coord, 'A'))
                pt = "".join(pt_chars)
                c = count_crib_matches(pt)
                rk = []
                for i in range(n):
                    pt_r = kw_grid.get(pt_chars[i], (0, 0))[0]
                    ct_r = kw_grid.get(CT[i], (0, 0))[0]
                    rk.append((ct_r + pt_r) % KA_NROWS)
                m, _ = check_row_key_consistency(rk)
                if m > best["rk_matches"] or (m == best["rk_matches"] and c > best["crib_hits"]):
                    best.update({"rk_matches": m, "crib_hits": c,
                                 "method": f"delayed_bifid/{keyword}/d{delay}/p{p}"})

    elif variant == "separate_row_col_shift":
        # Shift rows and columns independently with different keys
        row_shift = params["row_shift"]
        col_shift = params["col_shift"]
        pt_chars = []
        for i in range(len(CT)):
            pt_r = (ct_rows[i] - row_shift[i % len(row_shift)]) % KA_NROWS
            pt_c = (ct_cols[i] - col_shift[i % len(col_shift)]) % KA_WIDTH
            coord = (pt_r, pt_c)
            pt_chars.append(KA_COORD_TO_LETTER.get(coord, 'A'))
        pt = "".join(pt_chars)
        rk = [(ct_rows[i] + KA_LETTER_TO_COORD.get(pt_chars[i], (0, 0))[0]) % KA_NROWS
              for i in range(len(CT))]
        m, _ = check_row_key_consistency(rk)
        c = count_crib_matches(pt)
        best.update({"rk_matches": m, "crib_hits": c,
                     "method": f"sep_shift/r{row_shift}/c{col_shift}"})

    return best


def run_fractionation_sweep(state: CampaignV2State, num_workers: int) -> None:
    """Sweep non-standard fractionation variants."""
    if state.is_phase_done("fractionation_sweep"):
        return

    print("\n" + "=" * 70)
    print("  PHASE 3: Non-Standard Fractionation Sweep")
    print("=" * 70 + "\n")

    start = time.monotonic()
    keywords = ["KRYPTOS", "ABSCISSA", "DEFECTOR", "KOMPASS", "SEVEN", "PALIMPSEST"]

    tasks = []
    # Partial fractionation: row-only shift
    for shift in range(KA_NROWS):
        tasks.append(("partial_frac_row_only", {"shift": shift, "keywords": keywords}))

    # Delayed bifid
    for delay in range(1, 6):
        for period in [5, 7, 8, 13, 14, 24, 97]:
            tasks.append(("delayed_bifid", {"delay": delay, "period": period, "keywords": keywords[:3]}))

    # Separate row/col shifts with small periodic keys
    for rp in range(1, 5):
        for cp in range(1, 4):
            for row_shift in itertools.product(range(KA_NROWS), repeat=rp):
                for col_shift in itertools.product(range(KA_WIDTH), repeat=cp):
                    tasks.append(("separate_row_col_shift",
                                  {"row_shift": list(row_shift), "col_shift": list(col_shift)}))
                    if len(tasks) > 100000:
                        break
                if len(tasks) > 100000:
                    break
            if len(tasks) > 100000:
                break
        if len(tasks) > 100000:
            break

    print(f"  Testing {len(tasks)} fractionation configs across {num_workers} workers...")

    best_overall = {"rk_matches": 0, "crib_hits": 0}
    notable = []

    with mp.Pool(num_workers) as pool:
        for i, result in enumerate(pool.imap_unordered(_fractionation_worker, tasks, chunksize=64)):
            if result["rk_matches"] > best_overall["rk_matches"]:
                best_overall = result
            if result["rk_matches"] >= 6:
                notable.append(result)
            if (i + 1) % 10000 == 0:
                print(f"    [{i + 1}/{len(tasks)}] best rk={best_overall['rk_matches']}/24 "
                      f"cribs={best_overall.get('crib_hits', 0)}")

    elapsed = time.monotonic() - start
    print(f"\n  Best: rk={best_overall['rk_matches']}/24, method={best_overall.get('method', '?')}")
    print(f"  Notable (≥6/24): {len(notable)}")
    print(f"  Phase 3 complete in {elapsed:.1f}s")

    out = {"best": best_overall, "notable": notable[:50], "total_configs": len(tasks),
           "elapsed_seconds": elapsed}
    out_path = CAMPAIGN_DIR / "fractionation_sweep.json"
    CAMPAIGN_DIR.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, default=str))

    summary = f"best_rk={best_overall['rk_matches']}/24, configs={len(tasks)}"
    state.mark_phase_done("fractionation_sweep", summary)
    save_state(state)


# ---------------------------------------------------------------------------
# Phase 4: Grid-mediated state machine walks
# ---------------------------------------------------------------------------

def _walk_worker(args: tuple) -> dict:
    """Test a batch of state machine walks. Runs in worker process."""
    import signal as _signal
    _signal.signal(_signal.SIGINT, _signal.SIG_IGN)

    batch = args  # list of (init_r, init_c, update_rule_id)
    _ROOT_W = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(_ROOT_W / "src"))

    from kryptos.kernel.constants import CT, KRYPTOS_ALPHABET
    from kryptosbot.polybius_scorer import (
        KA_LETTER_TO_COORD, KA_COORD_TO_LETTER, KA_NROWS, KA_WIDTH,
        check_row_key_consistency, count_crib_matches,
    )

    best = {"rk_matches": 0}

    for init_r, init_c, rule_id in batch:
        # Decode rule: (row_source, col_source, row_op, col_op)
        row_sources = ["ct_r", "ct_c", "pos_mod3", "pos_mod5", "prev_r"]
        col_sources = ["ct_c", "ct_r", "pos_mod3", "pos_mod5", "prev_c"]
        ops = ["add", "sub"]

        rs_idx = rule_id % len(row_sources)
        co_idx = (rule_id // len(row_sources)) % len(col_sources)
        ro_idx = (rule_id // (len(row_sources) * len(col_sources))) % len(ops)
        coo_idx = (rule_id // (len(row_sources) * len(col_sources) * len(ops))) % len(ops)

        state_r, state_c = init_r, init_c
        row_key = []
        pt_chars = []

        for i in range(len(CT)):
            ct_ch = CT[i]
            ct_r, ct_c = KA_LETTER_TO_COORD.get(ct_ch, (0, 0))

            # Row key = current state row
            row_key.append(state_r)

            # Decrypt: PT_r = (K_r - CT_r) % nrows for Beaufort
            pt_r = (state_r - ct_r) % KA_NROWS
            pt_c = (ct_c - state_c) % KA_WIDTH  # Vigenere column
            coord = (pt_r, pt_c)
            pt_ch = KA_COORD_TO_LETTER.get(coord, 'A')
            pt_chars.append(pt_ch)

            # Update state
            src_r_val = {"ct_r": ct_r, "ct_c": ct_c, "pos_mod3": i % 3,
                         "pos_mod5": i % 5, "prev_r": state_r}[row_sources[rs_idx]]
            src_c_val = {"ct_c": ct_c, "ct_r": ct_r, "pos_mod3": i % 3,
                         "pos_mod5": i % 5, "prev_c": state_c}[col_sources[co_idx]]

            if ops[ro_idx] == "add":
                state_r = (state_r + src_r_val) % KA_NROWS
            else:
                state_r = (state_r - src_r_val) % KA_NROWS

            if ops[coo_idx] == "add":
                state_c = (state_c + src_c_val) % KA_WIDTH
            else:
                state_c = (state_c - src_c_val) % KA_WIDTH

        m, _ = check_row_key_consistency(row_key)
        if m > best["rk_matches"]:
            c = count_crib_matches("".join(pt_chars))
            best = {"rk_matches": m, "crib_hits": c,
                    "init": (init_r, init_c), "rule_id": rule_id,
                    "method": f"walk/({init_r},{init_c})/rule{rule_id}"}

    return best


def run_state_machine_walks(state: CampaignV2State, num_workers: int) -> None:
    """Test grid-mediated state machine walks."""
    if state.is_phase_done("state_machine_walks"):
        return

    print("\n" + "=" * 70)
    print("  PHASE 4: Grid-Mediated State Machine Walks")
    print("=" * 70 + "\n")

    start = time.monotonic()

    # Generate all (init_r, init_c, rule_id) combinations
    n_rules = 5 * 5 * 2 * 2  # row_sources × col_sources × row_ops × col_ops = 100
    configs = []
    for r in range(KA_NROWS):
        for c in range(KA_WIDTH):
            for rule in range(n_rules):
                configs.append((r, c, rule))

    # Batch for workers
    batch_size = 50
    batches = [configs[i:i + batch_size] for i in range(0, len(configs), batch_size)]

    print(f"  Testing {len(configs)} walk configs in {len(batches)} batches...")

    best_overall = {"rk_matches": 0}
    notable = []

    with mp.Pool(num_workers) as pool:
        for i, result in enumerate(pool.imap_unordered(_walk_worker, batches, chunksize=4)):
            if result["rk_matches"] > best_overall["rk_matches"]:
                best_overall = result
            if result.get("rk_matches", 0) >= 6:
                notable.append(result)
            if (i + 1) % 100 == 0:
                print(f"    [{(i + 1) * batch_size}/{len(configs)}] best rk={best_overall['rk_matches']}/24")

    elapsed = time.monotonic() - start
    print(f"\n  Best: rk={best_overall['rk_matches']}/24, method={best_overall.get('method', '?')}")
    print(f"  Notable (≥6/24): {len(notable)}")
    print(f"  Phase 4 complete in {elapsed:.1f}s")

    out = {"best": best_overall, "notable": notable[:50], "total_configs": len(configs),
           "elapsed_seconds": elapsed}
    out_path = CAMPAIGN_DIR / "state_machine_walks.json"
    CAMPAIGN_DIR.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, default=str))

    summary = f"best_rk={best_overall['rk_matches']}/24, configs={len(configs)}"
    state.mark_phase_done("state_machine_walks", summary)
    save_state(state)


# ---------------------------------------------------------------------------
# Phase 5: K1-K3 parallel analysis
# ---------------------------------------------------------------------------

def run_k123_parallel(state: CampaignV2State, num_workers: int) -> None:
    """Analyze K1/K2/K3 Polybius coordinate patterns for K4 parallels."""
    if state.is_phase_done("k123_parallel"):
        return

    print("\n" + "=" * 70)
    print("  PHASE 5: K1-K3 Parallel Analysis")
    print("=" * 70 + "\n")

    start = time.monotonic()
    results: dict[str, Any] = {}

    # K1 and K2 known PT/CT/keywords
    K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
    K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
    K1_KEY = "PALIMPSEST"

    K2_CT = "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRRYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYCUQZEREEVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ"
    K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUABORTTHETRANSMISSIONTHEGOODSISVERYHIDDENXHOWDOESONEFIGURETHATOUT"
    # Note: K2 PT is shorter than CT due to 'X' insertions; we use what we have

    # Extract Polybius coordinates for K1
    k1_ct_rows = [KA_LETTER_TO_COORD.get(ch, (0, 0))[0] for ch in K1_CT]
    k1_pt_rows = [KA_LETTER_TO_COORD.get(ch, (0, 0))[0] for ch in K1_PT]
    k1_key_rows = [(k1_ct_rows[i] + k1_pt_rows[i]) % KA_NROWS
                   for i in range(min(len(K1_CT), len(K1_PT)))]

    results["k1_key_row_distribution"] = dict(
        __import__("collections").Counter(k1_key_rows))

    # Check K1 row key for same clustering pattern
    k1_runs = 1
    for i in range(1, len(k1_key_rows)):
        if k1_key_rows[i] != k1_key_rows[i - 1]:
            k1_runs += 1
    expected_runs_k1 = len(k1_key_rows) * (1 - 1 / KA_NROWS) + 1
    results["k1_runs"] = k1_runs
    results["k1_expected_runs"] = round(expected_runs_k1, 1)
    print(f"  K1 row key runs: {k1_runs} (expected {expected_runs_k1:.1f})")

    # Extract for K2
    k2_ct_rows = [KA_LETTER_TO_COORD.get(ch, (0, 0))[0] for ch in K2_CT]
    k2_pt_rows = [KA_LETTER_TO_COORD.get(ch, (0, 0))[0] for ch in K2_PT]
    k2_key_rows = [(k2_ct_rows[i] + k2_pt_rows[i]) % KA_NROWS
                   for i in range(min(len(K2_CT), len(K2_PT)))]

    results["k2_key_row_distribution"] = dict(
        __import__("collections").Counter(k2_key_rows))
    k2_runs = 1
    for i in range(1, len(k2_key_rows)):
        if k2_key_rows[i] != k2_key_rows[i - 1]:
            k2_runs += 1
    expected_runs_k2 = len(k2_key_rows) * (1 - 1 / KA_NROWS) + 1
    results["k2_runs"] = k2_runs
    results["k2_expected_runs"] = round(expected_runs_k2, 1)
    print(f"  K2 row key runs: {k2_runs} (expected {expected_runs_k2:.1f})")

    # Check if K1/K2 show palette enrichment in keystream
    k1_ks = []
    for i in range(min(len(K1_CT), len(K1_PT))):
        k = (ALPH_IDX.get(K1_CT[i], 0) + ALPH_IDX.get(K1_PT[i], 0)) % 26
        k1_ks.append(ALPH[k])
    k1_palette_count = sum(1 for ch in k1_ks if ch in NULL_PALETTE)
    results["k1_palette_enrichment"] = f"{k1_palette_count}/{len(k1_ks)}"
    print(f"  K1 keystream palette enrichment: {k1_palette_count}/{len(k1_ks)} "
          f"(expected {len(k1_ks) * 7 / 26:.1f})")

    elapsed = time.monotonic() - start
    results["elapsed_seconds"] = elapsed
    print(f"\n  Phase 5 complete in {elapsed:.1f}s")

    out_path = CAMPAIGN_DIR / "k123_parallel.json"
    CAMPAIGN_DIR.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2, default=str))

    summary = f"k1_runs={k1_runs}(exp {expected_runs_k1:.0f}), k2_runs={k2_runs}(exp {expected_runs_k2:.0f})"
    state.mark_phase_done("k123_parallel", summary)
    save_state(state)


# ---------------------------------------------------------------------------
# Opus system prompt and hypothesis format
# ---------------------------------------------------------------------------

POLYBIUS_SYSTEM_PROMPT = """You are an expert cryptanalyst solving Kryptos K4 — the last unsolved section of a CIA headquarters sculpture. Your specialty is discovering NOVEL Polybius-based mechanisms.

You are NOT searching for a known cipher. Every known cipher family has been tested and eliminated across 884 billion configurations. The mechanism you seek has "never appeared in cryptographic literature" but is hand-executable.

## THE POLYBIUS MODEL (joint p=1.4e-7)

KA Polybius grid (5 wide, 6 rows, alphabet: KRYPTOSABCDEFGHIJLMNQUVWXZ):
  Row 0: K R Y P T
  Row 1: O S A B C
  Row 2: D E F G H
  Row 3: I J L M N
  Row 4: Q U V W X
  Row 5: Z

TWO INDEPENDENT COORDINATE SYSTEMS on this grid:
- Columns (mod 5) = STEGO layer. Null palette {B,G,I,K,O,W,Z} in cols 0,3 only.
- Rows (mod 6) = CIPHER layer. Reduces encryption to a 6-value problem.

## THE ROW KEY — Your Primary Target

At 24 known crib positions, the Beaufort A=0 row key (K_r = (CT_r + PT_r) % 6):
  ENE (pos 21-33): [4, 4, 1, 4, 1, 5, 0, 0, 5, 4, 1, 2, 1]
  BC  (pos 63-73): [4, 2, 0, 1, 3, 3, 4, 2, 3, 1, 0]

Properties:
1. NOT periodic at any period (mathematical proof via 242 Bean inequalities)
2. Row clustering: 14 runs in 24 values vs 20.2 expected (p=0.0022)
3. 13/24 keystream values are palette letters {B,G,I,K,O,W,Z} (p=0.0043)
4. AP {G,K,O} at 12/24 positions (p=3.9e-6)
5. Bean equality: keystream at pos 27 = keystream at pos 65 (both = G)
6. Value 0 appears 5 times, value 1 appears 6 times, value 2 appears 4 times,
   value 3 appears 3 times, value 4 appears 5 times, value 5 appears 1 time

## HARD CONSTRAINTS (violations waste the round)

MATHEMATICAL PROOFS (no search can overcome):
- NO periodic substitution at ANY period on raw 97 chars
- NO autokey of any variant (crib-to-crib structural impossibility)

EXHAUSTIVE ELIMINATIONS (>1B configs each):
- Standard Bifid 5×6 (19K configs, noise), product cipher (1.2B MITM)
- VIC cipher (1.32B+), running key from 60K English texts (106B checks)
- Grid-position keying, palette as cipher key (80K+), modified grids (8K+)
- NDYAHR/K2 → row key derivation (all function types)

DISGUISED VERSIONS (these are the same as eliminated methods):
- "Modified Vigenere" = Vigenere (periodic). "Progressive key" = periodic/autokey.
- "Nihilist cipher" = periodic + constant. "Quagmire" = periodic with mixed alpha.

## WHAT TO PROPOSE

Novel mechanisms that:
1. Are non-standard but hand-executable (pencil + grid, 1990)
2. Are consistent with the row key fingerprint at 24 crib positions
3. Explain WHY the row key clusters (adjacent values persist)
4. Can be tested with <50K candidates per hypothesis
5. Are discoverable from public information (no chart dependency)"""


POLYBIUS_HYPOTHESIS_FORMAT = """
Return a JSON array of 2-5 hypotheses. Each must be genuinely NOVEL.

HYPOTHESIS TYPES:

1. "row_key_mechanism" — STRONGLY PREFERRED. Propose how the 97-position mod-6 row
   key is generated. Write: def compute_row_key(ct, ka, grid): return [list of 97 ints mod 6]
   Available in sandbox: K4 (ciphertext), KA, AZ, grid (PolybiusGrid with .letter_to_coord,
   .coord_to_letter, .nrows=6, .width=5), ROW_KEY_AT_CRIBS (target 24 values),
   CRIB_POSITIONS (list of 24 positions), NULL_PALETTE, CONSENSUS_NULLS.
   Framework checks your output against the known 24 values automatically.
   10-second timeout. Return a list of (key_sequence_97, label) tuples.

2. "coordinate_cipher" — Full decryption mechanism using the grid.
   Write: def mechanism(ct, grid): return [(plaintext, label), ...]
   Same sandbox environment. 60-second timeout, max 50K candidates.
   Score: crib matches + row key consistency + Bean check.

3. "structural_analysis" — Pure reasoning, no code.
   data: {"claim": "...", "evidence": "...", "verdict": "SUPPORTED|DISPROVED|INCONCLUSIVE",
          "insight": "what we learned"}

4. "verification_test" — Test a specific prediction from a prior round.
   data: {"python_code": "def verify(ct, grid): return {...}", "depends_on": "round_N_name"}

THE ROW KEY PUZZLE: What hand-executable process produces
[4,4,1,4,1,5,0,0,5,4,1,2,1, 4,2,0,1,3,3,4,2,3,1,0] at crib positions?

Return ONLY the JSON array, no other text."""


ELIMINATION_GUARD = """
ELIMINATION CHECK: Before proposing, verify your hypothesis is NOT:
- A periodic cipher in disguise (does the key repeat after P positions?)
- An autokey variant (does the key depend on previous PT/CT?)
- A standard cipher with a different name
- A mechanism that requires the non-public encoding chart

If you catch yourself about to propose any of these, STOP, explain why the
fingerprint data eliminates it, then propose something genuinely different."""


# ---------------------------------------------------------------------------
# Polybius sandbox wrapper
# ---------------------------------------------------------------------------

_POLYBIUS_SANDBOX_WRAPPER = '''
import json, sys, math, itertools, collections, string, re, random

K4 = "{k4}"
K4_LEN = {k4_len}
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
NULL_PALETTE = set("BGIKOWZ")
CONSENSUS_NULLS = {consensus_nulls}
ROW_KEY_AT_CRIBS = {row_key}
CRIB_POSITIONS = {crib_positions}

CRIBS = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]
CRIB_DICT = {{}}
for _pos, _text in CRIBS:
    for _j, _ch in enumerate(_text):
        CRIB_DICT[_pos + _j] = _ch

def crib_hits(pt):
    hits = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt) and pt[pos] == ch:
            hits += 1
    return hits

class PolybiusGrid:
    def __init__(self, alphabet, width=5):
        self.alphabet = alphabet
        self.width = width
        self.nrows = (len(alphabet) + width - 1) // width
        self.letter_to_coord = {{}}
        self.coord_to_letter = {{}}
        for i, ch in enumerate(alphabet):
            r, c = i // width, i % width
            self.letter_to_coord[ch] = (r, c)
            self.coord_to_letter[(r, c)] = ch

    def decrypt_beaufort(self, ct_ch, key_r, key_c):
        if ct_ch not in self.letter_to_coord: return ct_ch
        ct_r, ct_c = self.letter_to_coord[ct_ch]
        pt_r = (key_r - ct_r) % self.nrows
        pt_c = (ct_c - key_c) % self.width
        return self.coord_to_letter.get((pt_r, pt_c), 'A')

    def required_key(self, ct_ch, pt_ch):
        ct_r, ct_c = self.letter_to_coord[ct_ch]
        pt_r, pt_c = self.letter_to_coord[pt_ch]
        return ((ct_r + pt_r) % self.nrows, (ct_c - pt_c) % self.width)

grid = PolybiusGrid(KA, 5)

{user_code}

if __name__ == "__main__":
    try:
        if "compute_row_key" in dir():
            results = compute_row_key(K4, KA, grid)
            if isinstance(results, list) and results and isinstance(results[0], int):
                results = [(results, "single")]
            valid = []
            for item in results[:1000]:
                if isinstance(item, (list, tuple)) and len(item) >= 2:
                    seq = list(item[0]) if not isinstance(item[0], list) else item[0]
                    label = str(item[1])
                    if len(seq) >= 10:
                        valid.append([seq, label])
            json.dump(valid, sys.stdout)
        elif "mechanism" in dir():
            results = mechanism(K4, grid)
            valid = []
            for item in results[:50000]:
                if isinstance(item, (list, tuple)) and len(item) >= 2:
                    pt, label = str(item[0]), str(item[1])
                    if len(pt) >= 10 and pt.isalpha():
                        valid.append([pt, label])
            json.dump(valid, sys.stdout)
        elif "verify" in dir():
            result = verify(K4, grid)
            json.dump(result, sys.stdout)
        elif "generate" in dir():
            results = generate(K4)
            valid = []
            for item in results[:50000]:
                if isinstance(item, (list, tuple)) and len(item) >= 2:
                    pt, label = str(item[0]), str(item[1])
                    if len(pt) >= 10 and pt.isalpha():
                        valid.append([pt, label])
            json.dump(valid, sys.stdout)
        else:
            json.dump({{"error": "No compute_row_key, mechanism, verify, or generate function found"}}, sys.stdout)
    except Exception as e:
        json.dump({{"error": str(e)}}, sys.stdout)
'''


def _build_sandbox_code(user_code: str) -> str:
    """Build the full sandbox script from user code."""
    return _POLYBIUS_SANDBOX_WRAPPER.format(
        k4=CT,
        k4_len=CT_LEN,
        consensus_nulls=repr(sorted(CONSENSUS_NULL_POSITIONS)),
        row_key=repr(list(ROW_KEY_AT_CRIBS)),
        crib_positions=repr(list(CRIB_POSITIONS_ORDERED)),
        user_code=user_code,
    )


def _execute_sandboxed(code: str, timeout: int = 60) -> Any:
    """Execute code in a sandboxed subprocess, return parsed JSON output."""
    full_code = _build_sandbox_code(code)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(full_code)
        f.flush()
        tmp_path = f.name

    try:
        result = subprocess.run(
            [sys.executable, tmp_path],
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "PYTHONPATH": str(_ROOT / "src")},
        )
        if result.returncode != 0:
            stderr = result.stderr[:500] if result.stderr else "unknown error"
            return {"error": f"exit {result.returncode}: {stderr}"}
        if not result.stdout.strip():
            return {"error": "no output"}
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return {"error": f"timeout ({timeout}s)"}
    except json.JSONDecodeError as e:
        return {"error": f"JSON parse error: {e}"}
    except Exception as e:
        return {"error": str(e)}
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Hypothesis execution
# ---------------------------------------------------------------------------

def _test_row_key_mechanism(code: str, name: str) -> dict:
    """Execute a row_key_mechanism hypothesis and score against known row key."""
    raw = _execute_sandboxed(code, timeout=10)
    if isinstance(raw, dict) and "error" in raw:
        return {"name": name, "type": "row_key_mechanism", "error": raw["error"],
                "rk_matches": 0, "candidates": 0}

    if not isinstance(raw, list):
        return {"name": name, "type": "row_key_mechanism", "error": "not a list",
                "rk_matches": 0, "candidates": 0}

    best_matches = 0
    best_result = None

    for item in raw:
        if not isinstance(item, (list, tuple)) or len(item) < 2:
            continue
        seq, label = item[0], item[1]
        if not isinstance(seq, list) or len(seq) < CT_LEN:
            continue
        # Ensure mod 6
        seq = [int(v) % KA_NROWS for v in seq[:CT_LEN]]
        matches, mismatches = check_row_key_consistency(seq)
        bean_eq_row = check_bean_eq_row(seq)

        if matches > best_matches:
            best_matches = matches
            best_result = {
                "name": name, "type": "row_key_mechanism", "rk_matches": matches,
                "bean_eq_row": bean_eq_row, "label": str(label),
                "mismatches": [(p, pred, act) for p, pred, act in mismatches[:10]],
                "candidates": len(raw),
            }

    if best_result is None:
        return {"name": name, "type": "row_key_mechanism", "rk_matches": 0,
                "candidates": len(raw), "error": "no valid sequences"}
    return best_result


def _test_coordinate_cipher(code: str, name: str) -> dict:
    """Execute a coordinate_cipher hypothesis and score plaintext candidates."""
    raw = _execute_sandboxed(code, timeout=60)
    if isinstance(raw, dict) and "error" in raw:
        return {"name": name, "type": "coordinate_cipher", "error": raw["error"],
                "rk_matches": 0, "crib_hits": 0, "candidates": 0}

    if not isinstance(raw, list):
        return {"name": name, "type": "coordinate_cipher", "error": "not a list",
                "rk_matches": 0, "crib_hits": 0, "candidates": 0}

    best_score = None
    for item in raw:
        if not isinstance(item, (list, tuple)) or len(item) < 2:
            continue
        pt, label = str(item[0]).upper(), str(item[1])
        if len(pt) < 10 or not pt.isalpha():
            continue
        score = score_polybius_candidate(pt, mechanism_class=name)
        if best_score is None or score.row_key_matches > best_score.row_key_matches:
            best_score = score
            best_label = label
            best_pt = pt

    if best_score is None:
        return {"name": name, "type": "coordinate_cipher", "rk_matches": 0,
                "crib_hits": 0, "candidates": len(raw)}

    return {
        "name": name, "type": "coordinate_cipher",
        "rk_matches": best_score.row_key_matches,
        "crib_hits": best_score.crib_score,
        "bean_eq": best_score.bean_eq_passed,
        "label": best_label,
        "plaintext_preview": best_pt[:60],
        "candidates": len(raw),
        "is_signal": best_score.is_signal,
        "mismatches": [(p, pred, act) for p, pred, act in best_score.row_key_mismatches[:10]],
    }


def test_hypothesis(h: dict, name: str = "") -> dict:
    """Dispatch a hypothesis to the appropriate tester."""
    h_type = h.get("type", "")
    h_name = name or h.get("name", "unknown")
    data = h.get("data", {})
    code = data.get("python_code", "")

    if h_type == "row_key_mechanism":
        return _test_row_key_mechanism(code, h_name)
    elif h_type == "coordinate_cipher":
        return _test_coordinate_cipher(code, h_name)
    elif h_type == "structural_analysis":
        return {
            "name": h_name, "type": "structural_analysis",
            "claim": data.get("claim", ""),
            "insight": data.get("insight", ""),
            "verdict": data.get("verdict", "INCONCLUSIVE"),
        }
    elif h_type == "verification_test":
        raw = _execute_sandboxed(code, timeout=30)
        return {"name": h_name, "type": "verification_test", "result": raw}
    else:
        # Fallback: try as plaintext generator
        return _test_coordinate_cipher(code, h_name)


# ---------------------------------------------------------------------------
# Hypothesis filtering
# ---------------------------------------------------------------------------

ELIMINATED_PATTERNS = [
    "periodic", "vigenere", "beaufort period", "autokey", "nihilist",
    "quagmire", "porta", "gronsfeld", "affine", "caesar", "rot13",
    "standard bifid", "playfair", "four square", "two square",
    "running key from", "product cipher", "columnar trans",
]


def _filter_hypotheses(hypotheses: list[dict]) -> list[dict]:
    """Filter out hypotheses that are disguised eliminated approaches."""
    valid = []
    for h in hypotheses:
        desc = (h.get("description", "") + " " + h.get("name", "")).lower()
        skip = False
        for pattern in ELIMINATED_PATTERNS:
            if pattern in desc:
                code = h.get("data", {}).get("python_code", "").lower()
                # Allow if the code is testing something novel
                if "mod 6" in code or "nrows" in code or "coord" in code:
                    break  # Probably Polybius-aware, allow it
                print(f"    [FILTERED] {h.get('name', '?')}: matches '{pattern}'")
                skip = True
                break
        if not skip:
            valid.append(h)
    if len(valid) < len(hypotheses):
        print(f"    Filtered {len(hypotheses) - len(valid)} invalid hypotheses")
    return valid


# ---------------------------------------------------------------------------
# Opus context builder
# ---------------------------------------------------------------------------

def _build_v2_context(state: CampaignV2State, round_num: int) -> str:
    """Build per-round context for Opus."""
    # Phase summaries
    phase_lines = []
    for name, summary in state.phase_summaries.items():
        phase_lines.append(f"  - {name}: {summary}")
    phase_str = "\n".join(phase_lines) if phase_lines else "  (phases pending)"

    # Journal
    insights_str = "\n".join(f"  - {i}" for i in state.journal_insights[-10:]) or "  (none yet)"
    dead_ends_str = "\n".join(f"  - {d}" for d in state.journal_dead_ends[-15:]) or "  (none yet)"

    promising_str = ""
    if state.journal_promising:
        for p in state.journal_promising[-5:]:
            promising_str += f"  - {p.get('name', '?')}: rk={p.get('rk_matches', 0)}/24 — {p.get('method', '')}\n"
    else:
        promising_str = "  (none yet)\n"

    # Recent mechanism log
    recent_mechs = ""
    for m in state.journal_mechanism_log[-5:]:
        recent_mechs += f"  - {m.get('name', '?')}: rk={m.get('rk_matches', 0)}/24 [{m.get('verdict', '')}]\n"

    # Stagnation warning
    stagnation_warning = ""
    if state.stagnation_counter >= 3:
        stagnation_warning = """
REASONING RESET: Your last proposals scored below noise. Before proposing:
1. What ASSUMPTION were your recent proposals sharing?
2. What is the SIMPLEST mechanism you have NOT yet tried?
3. If you were Scheidt in 1989, what would you build with a Polybius grid
   and a pencil that a sculptor could execute?
"""

    # Elimination guard every 5 rounds
    guard = ""
    if round_num % 5 == 0:
        guard = "\n" + ELIMINATION_GUARD

    return f"""Round {round_num}. Budget: ${state.budget_spent:.2f}/${state.budget_total:.2f}.
Hypotheses tested: {state.total_hypotheses_tested}. Best row key: {state.best_row_key_matches}/24.

COMPUTATIONAL PHASE RESULTS:
{phase_str}

RESEARCH JOURNAL:
Key insights:
{insights_str}

Dead ends (do not revisit):
{dead_ends_str}

Promising partial matches:
{promising_str}
Recent mechanisms tested:
{recent_mechs}
Current thread: {state.journal_current_thread or '(open — propose a direction)'}
{stagnation_warning}{guard}
{POLYBIUS_HYPOTHESIS_FORMAT}"""


# ---------------------------------------------------------------------------
# Feedback formatter
# ---------------------------------------------------------------------------

def _format_feedback(round_results: list[dict]) -> str:
    """Format results for Opus feedback."""
    lines = ["## Round Results\n"]
    for r in round_results:
        if r.get("type") == "row_key_mechanism":
            lines.append(f"MECHANISM: {r['name']}")
            lines.append(f"  Row key matches: {r.get('rk_matches', 0)}/24")
            lines.append(f"  Bean EQ (row): {r.get('bean_eq_row', '?')}")
            if r.get("error"):
                lines.append(f"  ERROR: {r['error']}")
            elif r.get("rk_matches", 0) < 10:
                lines.append(f"  VERDICT: ELIMINATED (noise-level)")
            else:
                lines.append(f"  VERDICT: PARTIAL — investigate mismatch pattern")
                for pos, pred, actual in r.get("mismatches", [])[:5]:
                    lines.append(f"    pos {pos}: predicted row {pred}, actual row {actual}")

        elif r.get("type") == "coordinate_cipher":
            lines.append(f"CIPHER: {r['name']}")
            lines.append(f"  Row key: {r.get('rk_matches', 0)}/24, Cribs: {r.get('crib_hits', 0)}/24")
            if r.get("is_signal"):
                lines.append(f"  *** SIGNAL DETECTED ***")
            elif r.get("error"):
                lines.append(f"  ERROR: {r['error']}")

        elif r.get("type") == "structural_analysis":
            lines.append(f"ANALYSIS: {r['name']}")
            lines.append(f"  Insight: {r.get('insight', '?')}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main campaign loop
# ---------------------------------------------------------------------------

_shutdown_requested = False
_main_pid = None


def _signal_handler(signum, frame):
    global _shutdown_requested
    if os.getpid() != _main_pid:
        return
    if not _shutdown_requested:
        _shutdown_requested = True
        print("\n  Shutdown requested — finishing current round and saving state...")


def _load_api_key() -> str | None:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        return api_key
    env_file = Path(__file__).parent / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith("ANTHROPIC_API_KEY="):
                return line.split("=", 1)[1].strip()
    return None


def run_campaign_v2(
    *,
    budget: float = 250.0,
    model: str = "claude-opus-4-6",
    num_workers: int = 0,
    thinking_budget: int = 10000,
    local_only: bool = False,
    dry_run: bool = False,
    verbose: bool = False,
    phase: str = "",
) -> None:
    """Main campaign loop."""
    global _shutdown_requested, _main_pid

    if num_workers <= 0:
        num_workers = mp.cpu_count() or 4

    _main_pid = os.getpid()
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    state = load_state()
    state.budget_total = budget
    state.model = model

    if not state.started_at:
        state.started_at = datetime.now(timezone.utc).isoformat()

    print(f"\n{'=' * 70}")
    print(f"  KryptosBot Campaign V2 — Polybius Mechanism Search")
    print(f"{'=' * 70}")
    print(f"  Model:     {model}")
    print(f"  Budget:    ${state.budget_spent:.2f} / ${state.budget_total:.2f}")
    print(f"  Rounds:    {state.rounds_completed}")
    print(f"  Workers:   {num_workers}")
    print(f"  Best:      rk={state.best_row_key_matches}/24 cribs={state.best_crib_score}/24")
    phases_done = sum(1 for v in state.phase_status.values() if v == "done")
    print(f"  Phases:    {phases_done}/5 done")
    print(f"{'=' * 70}\n")

    if dry_run:
        _print_summary(state)
        return

    # --- Computational phases 1-5 ---
    phase_map = {
        "row_key": run_row_key_forensics,
        "coupling": run_column_coupling_verify,
        "fractionation": run_fractionation_sweep,
        "walks": run_state_machine_walks,
        "k123": run_k123_parallel,
    }

    if phase and phase in phase_map:
        phase_map[phase](state, num_workers)
        _print_summary(state)
        return

    # Run all pending phases
    for name, fn in phase_map.items():
        if _shutdown_requested:
            break
        fn(state, num_workers)

    if local_only or _shutdown_requested:
        _print_summary(state)
        return

    # --- Opus-guided phase ---
    api_key = _load_api_key()
    if not api_key:
        print("  No ANTHROPIC_API_KEY found.")
        print("  Set key in environment or kryptosbot/.env for Opus-guided search.")
        _print_summary(state)
        return

    from kryptosbot.api_client import KryptosAPIClient

    client = KryptosAPIClient(
        api_key=api_key,
        model=model,
        budget_usd=state.budget_remaining,
        conversation_mode=True,
    )
    # Override system prompt with Polybius-focused context
    client._system_blocks = [
        {
            "type": "text",
            "text": POLYBIUS_SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }
    ]
    client._conversation_history = list(state.conversation_history)

    print(f"\n  Entering Opus-guided exploration (budget: ${state.budget_remaining:.2f})")

    round_num = state.rounds_completed
    try:
        while not _shutdown_requested:
            round_num += 1

            remaining = state.budget_remaining - client.usage.cost_usd
            if remaining <= 0 or client.is_over_budget():
                print(f"\n  Budget exhausted (${state.budget_spent:.2f}/${state.budget_total:.2f})")
                break

            cost = state.budget_spent + client.usage.cost_usd
            print(f"\n{'=' * 70}")
            print(f"  Round {round_num} — ${cost:.2f}/${state.budget_total:.2f}")
            print(f"{'=' * 70}")

            # Build context
            context = _build_v2_context(state, round_num)

            # Generate hypotheses
            print(f"\n  [Opus] Generating hypotheses...")
            hypotheses = client.generate_hypotheses(context, thinking_budget=thinking_budget)

            if not hypotheses:
                print("    No hypotheses generated. Retrying in 10s...")
                state.rounds_completed = round_num
                save_state(state)
                time.sleep(10)
                continue

            hypotheses = _filter_hypotheses(hypotheses)

            print(f"  {len(hypotheses)} valid hypotheses:")
            for h in hypotheses:
                print(f"    - {h.get('name', '?')} [{h.get('type', '?')}]")

            # Test hypotheses
            round_results = []
            new_insights = False
            for h in hypotheses:
                if _shutdown_requested:
                    break
                h_name = h.get("name", "unknown")
                print(f"\n  [Test] {h_name}...")
                result = test_hypothesis(h, h_name)
                round_results.append(result)

                rk = result.get("rk_matches", 0)
                print(f"    rk={rk}/24", end="")
                if result.get("crib_hits"):
                    print(f" cribs={result['crib_hits']}/24", end="")
                if result.get("error"):
                    print(f" ERROR: {result['error'][:80]}", end="")
                print()

                # Update journal
                state.journal_mechanism_log.append({
                    "name": h_name, "round": round_num,
                    "rk_matches": rk,
                    "verdict": "SIGNAL" if result.get("is_signal") else
                               "PROMISING" if rk >= 10 else "NOISE",
                })

                if result.get("type") == "structural_analysis":
                    insight = result.get("insight", "")
                    if insight and insight not in state.journal_insights:
                        state.journal_insights.append(insight)
                        new_insights = True

                if rk >= 10:
                    state.journal_promising.append({
                        "name": h_name, "rk_matches": rk,
                        "method": result.get("label", result.get("method", "")),
                    })
                    new_insights = True

                if rk < 6 and result.get("type") != "structural_analysis":
                    desc = h.get("description", h_name)
                    if desc not in state.journal_dead_ends:
                        state.journal_dead_ends.append(desc)

                # Update best
                if rk > state.best_row_key_matches:
                    state.best_row_key_matches = rk
                    state.best_method = h_name

                # Signal check
                if result.get("is_signal"):
                    print(f"\n{'*' * 70}")
                    print(f"  *** SIGNAL: {h_name} — rk={rk}/24, cribs={result.get('crib_hits', 0)}/24 ***")
                    print(f"{'*' * 70}")

            # Stagnation detection
            if not new_insights and all(r.get("rk_matches", 0) < 10 for r in round_results):
                state.stagnation_counter += 1
            else:
                state.stagnation_counter = 0

            # Feed results back to Opus
            if round_results and not client.is_over_budget():
                feedback = _format_feedback(round_results)
                print(f"\n  [Opus] Analyzing results...")
                analysis = client.analyze_results(
                    [{"name": r["name"], "rk_matches": r.get("rk_matches", 0),
                      "type": r.get("type", ""), "error": r.get("error", "")}
                     for r in round_results],
                    context=feedback,
                )
                if analysis:
                    print(f"    {analysis[:200]}...")
                    # Extract thread direction from analysis
                    state.journal_current_thread = analysis[:200]

            # Update state
            state.budget_spent += client.usage.cost_usd
            client.usage = type(client.usage)(model=client.model)
            client.budget_usd = state.budget_remaining
            state.conversation_history = list(client._conversation_history[-8:])
            state.total_hypotheses_tested += len(round_results)
            state.rounds_completed = round_num
            save_state(state)

            print(f"\n  Round {round_num} complete: {len(round_results)} results, "
                  f"best_rk={state.best_row_key_matches}/24")

    except Exception as e:
        logger.error("Campaign error: %s", e, exc_info=True)
        print(f"\n  ERROR: {e}")
    finally:
        if client:
            state.budget_spent += client.usage.cost_usd
            state.conversation_history = list(client._conversation_history[-8:])
        state.rounds_completed = max(state.rounds_completed, round_num)
        save_state(state)
        _print_summary(state)


def _print_summary(state: CampaignV2State) -> None:
    print(f"\n{'=' * 70}")
    print(f"  CAMPAIGN V2 SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Rounds completed:    {state.rounds_completed}")
    print(f"  Budget spent:        ${state.budget_spent:.2f} / ${state.budget_total:.2f}")
    print(f"  Hypotheses tested:   {state.total_hypotheses_tested}")
    print(f"  Best row key:        {state.best_row_key_matches}/24")
    print(f"  Best crib score:     {state.best_crib_score}/24")
    print(f"  Best method:         {state.best_method}")
    print(f"\n  Phases:")
    for name in ["row_key_forensics", "column_coupling", "fractionation_sweep",
                 "state_machine_walks", "k123_parallel"]:
        status = state.phase_status.get(name, "pending")
        summary = state.phase_summaries.get(name, "")
        print(f"    {name}: {status}" + (f" — {summary}" if summary else ""))
    if state.journal_insights:
        print(f"\n  Key insights ({len(state.journal_insights)}):")
        for i in state.journal_insights[-5:]:
            print(f"    - {i[:100]}")
    if state.journal_promising:
        print(f"\n  Promising ({len(state.journal_promising)}):")
        for p in state.journal_promising[-5:]:
            print(f"    - {p.get('name', '?')}: rk={p.get('rk_matches', 0)}/24")
    print(f"\n  State saved: {STATE_FILE}")
    print(f"  Resume: PYTHONPATH=src python3 -u kryptosbot/campaign_v2.py")
    print(f"{'=' * 70}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="campaign_v2.py",
        description="KryptosBot Campaign V2 — Polybius Mechanism Search",
    )
    parser.add_argument("--budget", type=float, default=250.0,
                        help="Total API budget in USD (default: $250)")
    parser.add_argument("--model", type=str, default="claude-opus-4-6",
                        choices=["claude-sonnet-4-6", "claude-opus-4-6"],
                        help="Model for hypothesis generation")
    parser.add_argument("--workers", type=int, default=0,
                        help="CPU workers (default: all cores)")
    parser.add_argument("--thinking", type=int, default=10000,
                        help="Extended thinking budget in tokens")
    parser.add_argument("--local-only", action="store_true",
                        help="No API calls — computational phases only")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show campaign state without running")
    parser.add_argument("--verbose", action="store_true",
                        help="Debug logging")
    parser.add_argument("--reset", action="store_true",
                        help="Reset campaign state")
    parser.add_argument("--phase", type=str, default="",
                        choices=["", "row_key", "coupling", "fractionation", "walks", "k123"],
                        help="Run only a specific phase")

    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.reset:
        if STATE_FILE.exists():
            backup = STATE_FILE.with_suffix(f".backup_{int(time.time())}.json")
            STATE_FILE.rename(backup)
            print(f"  State backed up to {backup.name}")

    run_campaign_v2(
        budget=args.budget,
        model=args.model,
        num_workers=args.workers,
        thinking_budget=args.thinking,
        local_only=args.local_only,
        dry_run=args.dry_run,
        verbose=args.verbose,
        phase=args.phase,
    )


if __name__ == "__main__":
    main()
