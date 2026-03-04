#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-GRILLE-22: Model 2 Simulated Annealing Permutation Search

CONFIRMED MODEL (2026-03-03):
    PT → Cipher(key) → real_CT → Scramble(σ) → carved text

Strategy:
    For each (keyword, cipher, alphabet) assumption:
    1. Compute expected real_CT at 24 crib positions
    2. Check feasibility (required letters exist in carved text)
    3. Run SA on the full permutation space:
       - σ maps real_CT positions → carved positions: real_CT[j] = carved[σ(j)]
       - Swap σ(a) ↔ σ(b), score decrypt(unscramble(carved,σ), keyword)
       - Incremental quadgram scoring for O(1) per step
    4. Mix seeded starts (24 crib positions pre-satisfied) with random starts
    5. If cribs appear in decrypted text → SOLUTION

CRIB INTERPRETATION UNDER MODEL 2:
    Crib positions (21-33, 63-73) are PLAINTEXT positions, NOT carved text positions.
    PT[21..33] = EASTNORTHEAST, PT[63..73] = BERLINCLOCK.
    The cipher key at position j = keyword[j % period].
    So real_CT[j] = Encrypt(PT[j], key[j]) is known at 24 positions.
    The scramble maps real_CT → carved: carved[i] = real_CT[σ⁻¹(i)].
    Equivalently: real_CT[j] = carved[σ(j)].
    Constraint: carved[σ(j)] must equal expected_CT[j] at all 24 crib positions.

Usage:
    cd ~/kryptos
    PYTHONPATH=src python3 -u scripts/e_grille_22_model2_sa.py
    PYTHONPATH=src python3 -u scripts/e_grille_22_model2_sa.py --steps 2000000 --restarts 500
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import sys
import time
from collections import Counter
from multiprocessing import Pool, cpu_count
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────

K4_CARVED = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(K4_CARVED)  # 97

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# Crib positions in PLAINTEXT (= real_CT positions under Model 2)
CRIB1_POS, CRIB1_TEXT = 21, "EASTNORTHEAST"
CRIB2_POS, CRIB2_TEXT = 63, "BERLINCLOCK"

ALL_CRIBS = [(CRIB1_POS, CRIB1_TEXT), (CRIB2_POS, CRIB2_TEXT)]

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]

# ── Load quadgrams ──────────────────────────────────────────────────────────

_QG: dict[str, float] | None = None
_QG_FLOOR = -10.0


def _load_quadgrams() -> dict[str, float]:
    global _QG
    if _QG is not None:
        return _QG
    for p in [Path("data/english_quadgrams.json"),
              Path("../data/english_quadgrams.json"),
              Path(os.path.dirname(__file__)) / ".." / "data" / "english_quadgrams.json"]:
        if p.exists():
            _QG = json.loads(p.read_text())
            return _QG
    _QG = {}
    return _QG


# ── Precomputation ──────────────────────────────────────────────────────────

def build_letter_positions(text: str) -> dict[str, list[int]]:
    """Map each letter to its positions in the text."""
    lp: dict[str, list[int]] = {}
    for i, c in enumerate(text):
        lp.setdefault(c, []).append(i)
    return lp


K4_LETTER_POS = build_letter_positions(K4_CARVED)


def compute_expected_ct(keyword: str, cipher_type: str, alpha: str) -> dict[int, str]:
    """Compute expected real_CT character at each crib position.

    Under Vigenère encrypt: CT = (PT + KEY) mod 26
    Under Beaufort encrypt: CT = (KEY - PT) mod 26
    """
    n_alpha = len(alpha)
    expected: dict[int, str] = {}
    for crib_pos, crib_text in ALL_CRIBS:
        for j, pt_char in enumerate(crib_text):
            pos = crib_pos + j
            ki = alpha.index(keyword[pos % len(keyword)])
            pi = alpha.index(pt_char)
            if cipher_type == "vig":
                ct_idx = (pi + ki) % n_alpha
            else:  # beaufort
                ct_idx = (ki - pi) % n_alpha
            expected[pos] = alpha[ct_idx]
    return expected


def check_feasibility(expected_ct: dict[int, str]) -> tuple[bool, str]:
    """Check if required CT letters exist in carved text with sufficient count."""
    needed = Counter(expected_ct.values())
    for letter, count in needed.items():
        available = len(K4_LETTER_POS.get(letter, []))
        if available < count:
            return False, f"Need {count}×{letter}, only {available} available"
    return True, "OK"


# ── Permutation generation ──────────────────────────────────────────────────

def generate_seeded_perm(
    expected_ct: dict[int, str],
    rng: random.Random,
) -> list[int] | None:
    """Generate a permutation σ where σ(crib_pos) is valid for the constraint.

    σ(j) = carved position that should map to real_CT position j.
    Constraint: carved[σ(j)] = expected_ct[j] for all j in expected_ct.
    """
    used_carved: set[int] = set()
    sigma = list(range(N))  # will be overwritten

    # Assign crib positions first, in random order to get diverse starts
    crib_positions = list(expected_ct.keys())
    rng.shuffle(crib_positions)

    for pos in crib_positions:
        needed_letter = expected_ct[pos]
        candidates = [p for p in K4_LETTER_POS[needed_letter] if p not in used_carved]
        if not candidates:
            return None  # Conflict — try again
        sigma[pos] = rng.choice(candidates)
        used_carved.add(sigma[pos])

    # Fill remaining positions randomly
    remaining_real = [i for i in range(N) if i not in expected_ct]
    remaining_carved = [i for i in range(N) if i not in used_carved]
    rng.shuffle(remaining_carved)
    for real_pos, carved_pos in zip(remaining_real, remaining_carved):
        sigma[real_pos] = carved_pos

    return sigma


def generate_random_perm(rng: random.Random) -> list[int]:
    """Generate a completely random permutation."""
    sigma = list(range(N))
    rng.shuffle(sigma)
    return sigma


# ── SA Worker ───────────────────────────────────────────────────────────────

def sa_worker(args: tuple) -> dict:
    """Single SA restart. Returns best result found."""
    (config_name, keyword, cipher_type, alpha_name, alpha,
     n_steps, seed, use_seeded, expected_ct) = args

    rng = random.Random(seed)
    qg = _load_quadgrams()

    # Precompute character → alpha index lookup
    a2i = {c: i for i, c in enumerate(alpha)}
    n_alpha = len(alpha)

    # Precompute key indices for all 97 positions
    klen = len(keyword)
    key_idx = [a2i[keyword[j % klen]] for j in range(N)]

    # Precompute carved text as alpha indices
    carved_aidx = [a2i[c] for c in K4_CARVED]

    # Generate starting permutation
    sigma: list[int]
    if use_seeded and expected_ct:
        s = generate_seeded_perm(expected_ct, rng)
        if s is None:
            sigma = generate_random_perm(rng)
        else:
            sigma = s
    else:
        sigma = generate_random_perm(rng)

    # Compute initial PT (as list of chars) and score
    pt = [''] * N
    for j in range(N):
        ct_aidx = carved_aidx[sigma[j]]
        if cipher_type == "vig":
            pt_aidx = (ct_aidx - key_idx[j]) % n_alpha
        else:
            pt_aidx = (key_idx[j] - ct_aidx) % n_alpha
        pt[j] = alpha[pt_aidx]

    # Compute initial quadgram score
    current_score = 0.0
    for i in range(N - 3):
        qgram = pt[i] + pt[i+1] + pt[i+2] + pt[i+3]
        current_score += qg.get(qgram, _QG_FLOOR)

    best_score = current_score
    best_sigma = sigma[:]
    best_pt = ''.join(pt)

    # SA parameters
    T_init = 25.0
    T_min = 0.005
    cooling = math.exp(math.log(T_min / T_init) / max(n_steps, 1))
    T = T_init

    for step in range(n_steps):
        # Pick two random positions to swap in σ
        a = rng.randint(0, N - 1)
        b = rng.randint(0, N - 2)
        if b >= a:
            b += 1

        # Compute new PT chars at positions a and b after swap
        # After swap: σ(a) ← old σ(b), σ(b) ← old σ(a)
        new_ct_a_aidx = carved_aidx[sigma[b]]  # new CT at pos a
        new_ct_b_aidx = carved_aidx[sigma[a]]  # new CT at pos b

        if cipher_type == "vig":
            new_pt_a = alpha[(new_ct_a_aidx - key_idx[a]) % n_alpha]
            new_pt_b = alpha[(new_ct_b_aidx - key_idx[b]) % n_alpha]
        else:
            new_pt_a = alpha[(key_idx[a] - new_ct_a_aidx) % n_alpha]
            new_pt_b = alpha[(key_idx[b] - new_ct_b_aidx) % n_alpha]

        # Compute affected quadgram starts
        # Positions a and b changed → quadgrams starting at [a-3..a] and [b-3..b]
        affected = set()
        for p in (a, b):
            lo = max(0, p - 3)
            hi = min(N - 4, p)
            for s in range(lo, hi + 1):
                affected.add(s)

        # Compute old score contribution (before swap)
        old_contrib = 0.0
        for s in affected:
            qgram = pt[s] + pt[s+1] + pt[s+2] + pt[s+3]
            old_contrib += qg.get(qgram, _QG_FLOOR)

        # Temporarily apply swap
        old_pt_a, old_pt_b = pt[a], pt[b]
        pt[a], pt[b] = new_pt_a, new_pt_b

        # Compute new score contribution
        new_contrib = 0.0
        for s in affected:
            qgram = pt[s] + pt[s+1] + pt[s+2] + pt[s+3]
            new_contrib += qg.get(qgram, _QG_FLOOR)

        delta = new_contrib - old_contrib

        # SA acceptance
        if delta > 0 or rng.random() < math.exp(delta / T):
            # Accept: update sigma and score
            sigma[a], sigma[b] = sigma[b], sigma[a]
            current_score += delta
            if current_score > best_score:
                best_score = current_score
                best_sigma = sigma[:]
                best_pt = ''.join(pt)
        else:
            # Reject: restore PT
            pt[a], pt[b] = old_pt_a, old_pt_b

        T *= cooling

    # Final checks — only check the FINAL best_pt for cribs
    pt_str = best_pt
    ene_pos = pt_str.find("EASTNORTHEAST")
    bc_pos = pt_str.find("BERLINCLOCK")
    crib_found = (ene_pos >= 0 or bc_pos >= 0)

    # Also check shorter fragments
    fragments_found = []
    for frag in ["NORTHEAST", "EAST", "NORTH", "BERLIN", "CLOCK"]:
        if frag in pt_str:
            fragments_found.append(frag)

    return {
        "config": config_name,
        "keyword": keyword,
        "cipher": cipher_type,
        "alphabet": alpha_name,
        "seed": seed,
        "seeded": use_seeded,
        "best_score": round(best_score, 2),
        "best_score_per_char": round(best_score / (N - 3), 3),
        "best_pt": pt_str,
        "best_sigma": best_sigma,
        "crib_found": crib_found,
        "ene_pos": ene_pos,
        "bc_pos": bc_pos,
        "fragments": fragments_found,
    }


# ── Keystream periodicity detector ─────────────────────────────────────────

def keystream_check(sigma: list[int], max_period: int = 26) -> dict | None:
    """Given a permutation σ, derive keystream at 24 crib positions and
    check for periodicity. Model-free — doesn't assume any specific key.

    Under Vigenère: k[j] = (CT[j] - PT[j]) mod 26  (using AZ)
    Under Beaufort: k[j] = (CT[j] + PT[j]) mod 26  (using AZ)

    Here CT = real_CT[j] = carved[σ(j)].
    """
    # Derive keystream at crib positions for both Vig and Beau
    crib_positions = []
    for crib_pos, crib_text in ALL_CRIBS:
        for j, pt_char in enumerate(crib_text):
            pos = crib_pos + j
            ct_char = K4_CARVED[sigma[pos]]
            ct_idx = ord(ct_char) - ord('A')
            pt_idx = ord(pt_char) - ord('A')
            vig_k = (ct_idx - pt_idx) % 26
            beau_k = (ct_idx + pt_idx) % 26
            crib_positions.append((pos, vig_k, beau_k))

    # Check each period
    best_result = None
    for cipher_type, k_idx in [("vig", 1), ("beau", 2)]:
        for period in range(2, min(max_period + 1, 27)):
            # Group by residue class
            matches = 0
            total = 0
            residue_vals: dict[int, int | None] = {}
            ok = True
            for pos, vig_k, beau_k in crib_positions:
                k_val = vig_k if k_idx == 1 else beau_k
                r = pos % period
                if r in residue_vals:
                    total += 1
                    if residue_vals[r] == k_val:
                        matches += 1
                    else:
                        ok = False
                else:
                    residue_vals[r] = k_val

            if total > 0 and ok:
                # PERFECT periodicity — all residue classes agree
                return {
                    "cipher": cipher_type,
                    "period": period,
                    "matches": matches,
                    "total": total,
                    "residue_vals": {str(k): v for k, v in residue_vals.items()},
                }

            # Partial match — track best
            if total > 0 and matches > 0:
                score = matches / total
                if best_result is None or score > best_result.get("score", 0):
                    best_result = {
                        "cipher": cipher_type,
                        "period": period,
                        "matches": matches,
                        "total": total,
                        "score": score,
                    }

    return best_result


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Model 2 SA Permutation Search")
    parser.add_argument("--steps", type=int, default=1_000_000,
                        help="SA steps per restart (default: 1M)")
    parser.add_argument("--restarts", type=int, default=200,
                        help="SA restarts per config (default: 200)")
    parser.add_argument("--workers", type=int, default=min(cpu_count(), 28),
                        help="CPU workers (default: all cores)")
    parser.add_argument("--output", type=str, default="blitz_results/model2_sa",
                        help="Output directory")
    parser.add_argument("--config", type=str, default=None,
                        help="Run single config, e.g. 'KRYPTOS/vig/AZ'")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("  E-GRILLE-22: Model 2 SA Permutation Search")
    print("=" * 70)
    print(f"  CONFIRMED: PT → Cipher(key) → real_CT → Scramble(σ) → carved text")
    print(f"  Steps/restart: {args.steps:,}")
    print(f"  Restarts/config: {args.restarts}")
    print(f"  Workers: {args.workers}")
    print(f"  Output: {output_dir}")
    print()

    _load_quadgrams()

    # Build configurations
    configs = []
    for keyword in KEYWORDS:
        for cipher_type in ["vig", "beau"]:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                # Check all keyword chars are in alphabet
                if not all(c in alpha for c in keyword):
                    continue
                config_name = f"{keyword}/{cipher_type}/{alpha_name}"

                if args.config and args.config != config_name:
                    continue

                # Compute expected CT at crib positions
                expected_ct = compute_expected_ct(keyword, cipher_type, alpha)

                # Check feasibility
                feasible, msg = check_feasibility(expected_ct)
                if not feasible:
                    print(f"  SKIP {config_name}: {msg}")
                    continue

                # Count total constraint product for info
                needed_letters = Counter(expected_ct.values())
                domain_info = []
                for letter, count in sorted(needed_letters.items()):
                    avail = len(K4_LETTER_POS.get(letter, []))
                    domain_info.append(f"{letter}:{count}/{avail}")

                print(f"  CONFIG: {config_name} — FEASIBLE")
                print(f"    Expected CT at cribs: {''.join(expected_ct[k] for k in sorted(expected_ct.keys()))}")
                print(f"    Domains: {', '.join(domain_info)}")

                configs.append({
                    "name": config_name,
                    "keyword": keyword,
                    "cipher_type": cipher_type,
                    "alpha_name": alpha_name,
                    "alpha": alpha,
                    "expected_ct": expected_ct,
                })

    if not configs:
        print("\n  No feasible configurations found!")
        return

    print(f"\n  Total feasible configs: {len(configs)}")
    print(f"  Total SA runs: {len(configs) * args.restarts}")
    print()

    # Build SA tasks
    all_tasks = []
    for cfg in configs:
        for restart_idx in range(args.restarts):
            seed = hash((cfg["name"], restart_idx)) & 0xFFFFFFFF
            # Half seeded, half random
            use_seeded = (restart_idx % 2 == 0)
            all_tasks.append((
                cfg["name"], cfg["keyword"], cfg["cipher_type"],
                cfg["alpha_name"], cfg["alpha"],
                args.steps, seed, use_seeded, cfg["expected_ct"],
            ))

    print(f"  Launching {len(all_tasks)} SA instances across {args.workers} workers...")
    print("=" * 70)

    start_time = time.time()
    all_results: list[dict] = []
    crib_hits: list[dict] = []

    # Process in batches and report progress
    batch_size = args.workers * 2
    total_batches = (len(all_tasks) + batch_size - 1) // batch_size

    with Pool(args.workers) as pool:
        for batch_idx in range(0, len(all_tasks), batch_size):
            batch = all_tasks[batch_idx:batch_idx + batch_size]
            batch_num = batch_idx // batch_size + 1

            results = pool.map(sa_worker, batch)
            all_results.extend(results)

            # Check for crib hits
            for r in results:
                if r["crib_found"]:
                    crib_hits.append(r)
                    print(f"\n  *** CRIB HIT: {r['config']} seed={r['seed']} ***")
                    print(f"      PT: {r['best_pt']}")
                    print(f"      ENE@{r['ene_pos']} BC@{r['bc_pos']}")
                    print(f"      Score: {r['best_score']:.1f} ({r['best_score_per_char']:.3f}/char)")

            # Progress
            elapsed = time.time() - start_time
            best_so_far = max(all_results, key=lambda r: r["best_score"])
            completed = len(all_results)
            rate = completed / elapsed if elapsed > 0 else 0
            eta = (len(all_tasks) - completed) / rate if rate > 0 else 0

            print(f"  [{batch_num}/{total_batches}] "
                  f"{completed}/{len(all_tasks)} done | "
                  f"best={best_so_far['best_score']:.1f} ({best_so_far['config']}) | "
                  f"cribs={len(crib_hits)} | "
                  f"{elapsed:.0f}s elapsed, ~{eta:.0f}s remaining",
                  flush=True)

    total_elapsed = time.time() - start_time

    # ── Results summary ─────────────────────────────────────────────────
    print()
    print("=" * 70)
    print(f"  RESULTS — {total_elapsed:.0f}s total")
    print("=" * 70)

    # Sort by score
    all_results.sort(key=lambda r: -r["best_score"])

    # Per-config best scores
    config_bests: dict[str, dict] = {}
    for r in all_results:
        cfg = r["config"]
        if cfg not in config_bests or r["best_score"] > config_bests[cfg]["best_score"]:
            config_bests[cfg] = r

    print(f"\n  Per-config best scores:")
    print(f"  {'Config':<30s} {'Score':>8s} {'Per-char':>9s} {'Seeded':>7s} {'Fragments':>20s}")
    print(f"  {'-'*30} {'-'*8} {'-'*9} {'-'*7} {'-'*20}")
    for cfg_name in sorted(config_bests.keys()):
        r = config_bests[cfg_name]
        print(f"  {cfg_name:<30s} {r['best_score']:>8.1f} {r['best_score_per_char']:>9.3f} "
              f"{'Y' if r['seeded'] else 'N':>7s} {str(r['fragments']):>20s}")

    # Overall top 10
    print(f"\n  Top 10 overall:")
    for i, r in enumerate(all_results[:10]):
        print(f"  [{i+1:2d}] {r['config']:<25s} score={r['best_score']:>8.1f} "
              f"({r['best_score_per_char']:.3f}/char) seed={r['seed']}")
        print(f"       PT: {r['best_pt'][:60]}...")
        if r["fragments"]:
            print(f"       Fragments: {r['fragments']}")

    # Crib hits
    if crib_hits:
        print(f"\n  *** {len(crib_hits)} CRIB HITS ***")
        for r in crib_hits:
            print(f"\n  Config: {r['config']}")
            print(f"  PT: {r['best_pt']}")
            print(f"  Score: {r['best_score']:.1f} ({r['best_score_per_char']:.3f}/char)")
            print(f"  ENE@{r['ene_pos']} BC@{r['bc_pos']}")
            print(f"  Sigma: {r['best_sigma']}")
    else:
        print(f"\n  No full crib hits found.")

    # ── Keystream periodicity check on top results ──────────────────────
    print()
    print("=" * 70)
    print("  Keystream Periodicity Check (top 50 results)")
    print("=" * 70)

    period_hits = []
    for r in all_results[:50]:
        result = keystream_check(r["best_sigma"])
        if result and result.get("score", 0) >= 0.5:
            period_hits.append((r, result))
            print(f"  {r['config']} seed={r['seed']}: "
                  f"period={result.get('period','?')} "
                  f"cipher={result.get('cipher','?')} "
                  f"match={result.get('matches','?')}/{result.get('total','?')}")

    if not period_hits:
        print("  No significant periodicity found in keystream at crib positions.")

    # ── Save results ────────────────────────────────────────────────────
    save_data = {
        "experiment": "E-GRILLE-22",
        "model": "Model 2 (PT→Cipher→Scramble→carved)",
        "total_elapsed_seconds": round(total_elapsed, 1),
        "total_sa_runs": len(all_results),
        "steps_per_run": args.steps,
        "crib_hits": len(crib_hits),
        "config_bests": {k: {
            "config": v["config"], "score": v["best_score"],
            "score_per_char": v["best_score_per_char"],
            "pt_preview": v["best_pt"][:40],
            "fragments": v["fragments"],
        } for k, v in config_bests.items()},
        "top_10": [{
            "config": r["config"], "score": r["best_score"],
            "score_per_char": r["best_score_per_char"],
            "pt_preview": r["best_pt"][:60],
            "seed": r["seed"],
        } for r in all_results[:10]],
        "crib_hit_details": crib_hits if crib_hits else [],
    }

    out_path = output_dir / "e_grille_22_results.json"
    out_path.write_text(json.dumps(save_data, indent=2))
    print(f"\n  Results saved to {out_path}")

    # Save top result PT + sigma for further analysis
    if all_results:
        top = all_results[0]
        top_path = output_dir / "top_result.json"
        top_path.write_text(json.dumps({
            "config": top["config"],
            "score": top["best_score"],
            "plaintext": top["best_pt"],
            "sigma": top["best_sigma"],
            "crib_found": top["crib_found"],
        }, indent=2))

    print("=" * 70)
    print("  DONE")
    print("=" * 70)


if __name__ == "__main__":
    main()
