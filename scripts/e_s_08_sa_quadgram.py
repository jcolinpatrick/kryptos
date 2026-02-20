#!/usr/bin/env python3
"""E-S-08: SA over permutations with quadgram + crib fitness.

Searches for ANY transposition sigma such that:
  PT = vig_decrypt(sigma_inv(CT), periodic_key)
produces English text consistent with the 24 known crib positions.

Fitness = crib_match_bonus + quadgram_score_of_full_decryption.

For each candidate permutation sigma:
1. Derive key at 24 crib positions via key[p] = (CT[sigma_inv[p]] - PT[p]) mod 26
2. Use majority voting at each residue class to determine the period-q key
3. Decrypt all 97 positions with that key
4. Score: crib matches × 1000 + quadgram score

This avoids the underdetermination trap: even if cribs are satisfied, the
non-crib positions must also be English-like.

Tests periods 3, 4, 5, 6, 7 (the meaningful range).
"""

import json
import math
import os
import random
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_ENTRIES, CRIB_DICT, N_CRIBS, MOD, ALPH,
)

# ═══ Constants ═══════════════════════════════════════════════════════════

CT_INT = [ord(c) - 65 for c in CT]

_sorted = sorted(CRIB_ENTRIES, key=lambda x: x[0])
CRIB_POS = [p for p, _ in _sorted]
PT_CRIB_VAL = {p: ord(c) - 65 for p, c in _sorted}
CRIB_SET = set(CRIB_POS)

# ═══ Quadgram scorer ════════════════════════════════════════════════════

class QuadgramScorer:
    def __init__(self, path="data/english_quadgrams.json"):
        with open(path) as f:
            data = json.load(f)
        self.logp = data
        # Floor value for unseen quadgrams
        self.floor = min(data.values()) - 1.0

    def score(self, text):
        """Total log-probability of all quadgrams in text."""
        s = 0.0
        for i in range(len(text) - 3):
            q = text[i:i+4]
            s += self.logp.get(q, self.floor)
        return s

    def score_per_char(self, text):
        n = len(text) - 3
        return self.score(text) / n if n > 0 else self.floor


# ═══ Key derivation and decryption ══════════════════════════════════════

def derive_key_and_decrypt(sigma_inv, period, ct_int=CT_INT):
    """Derive periodic key from cribs, then decrypt all 97 chars.

    Returns (plaintext_str, crib_matches, key_tuple).
    """
    n = len(ct_int)

    # Derive key at crib positions
    key_at_crib = {}
    for p in CRIB_POS:
        key_at_crib[p] = (ct_int[sigma_inv[p]] - PT_CRIB_VAL[p]) % 26

    # Majority voting per residue class
    residue_vals = defaultdict(list)
    for p in CRIB_POS:
        residue_vals[p % period].append(key_at_crib[p])

    key = [0] * period
    for r in range(period):
        vals = residue_vals.get(r, [])
        if vals:
            key[r] = Counter(vals).most_common(1)[0][1]
        # else: key[r] stays 0

    # Decrypt
    pt = []
    for i in range(n):
        c = ct_int[sigma_inv[i]]
        k = key[i % period]
        pt.append((c - k) % 26)

    pt_str = ''.join(chr(v + 65) for v in pt)

    # Count crib matches
    matches = sum(1 for p, ch in CRIB_DICT.items()
                  if p < len(pt_str) and pt_str[p] == ch)

    return pt_str, matches, tuple(key)


# ═══ SA Engine ═══════════════════════════════════════════════════════════

def sa_search(
    scorer,
    period,
    n_restarts=100,
    steps_per_restart=200_000,
    t_start=2.0,
    t_end=0.001,
    seed=42,
):
    """SA over S_97 with quadgram + crib fitness."""

    rng = random.Random(seed)
    n = CT_LEN

    global_best = {
        "fitness": -1e9,
        "crib_matches": 0,
        "qscore": -1e9,
        "plaintext": "",
        "key": (),
        "sigma_inv": [],
    }
    restart_bests = []

    t0 = time.time()

    for restart in range(n_restarts):
        # Random permutation
        sigma = list(range(n))
        rng.shuffle(sigma)
        sigma_inv = [0] * n
        for i, s in enumerate(sigma):
            sigma_inv[s] = i

        # Initial fitness
        pt, matches, key = derive_key_and_decrypt(sigma_inv, period)
        qscore = scorer.score(pt)
        fitness = matches * 1000.0 + qscore

        best_fitness = fitness
        best_sigma_inv = list(sigma_inv)
        best_pt = pt
        best_matches = matches
        best_qscore = qscore
        best_key = key

        cooling = (t_end / t_start) ** (1.0 / steps_per_restart)
        temp = t_start

        accepted = 0

        for step in range(steps_per_restart):
            # Swap two positions in sigma
            i = rng.randrange(n)
            j = rng.randrange(n - 1)
            if j >= i:
                j += 1

            # Apply swap
            sigma[i], sigma[j] = sigma[j], sigma[i]
            a, b = sigma[i], sigma[j]  # new values at positions i, j
            # Update sigma_inv: sigma_inv[a] = i, sigma_inv[b] = j
            # (before swap: sigma_inv[a] = j, sigma_inv[b] = i)
            sigma_inv[a], sigma_inv[b] = i, j

            # Recompute fitness (full, not incremental — simpler, still fast enough)
            new_pt, new_matches, new_key = derive_key_and_decrypt(sigma_inv, period)
            new_qscore = scorer.score(new_pt)
            new_fitness = new_matches * 1000.0 + new_qscore

            delta = new_fitness - fitness
            if delta > 0 or (temp > 0 and rng.random() < math.exp(delta / temp)):
                # Accept
                fitness = new_fitness
                pt = new_pt
                matches = new_matches
                qscore = new_qscore
                key = new_key
                accepted += 1

                if fitness > best_fitness:
                    best_fitness = fitness
                    best_sigma_inv = list(sigma_inv)
                    best_pt = new_pt
                    best_matches = new_matches
                    best_qscore = new_qscore
                    best_key = new_key
            else:
                # Reject — undo swap
                sigma_inv[a], sigma_inv[b] = j, i
                sigma[i], sigma[j] = sigma[j], sigma[i]

            temp *= cooling

        restart_bests.append({
            "crib_matches": best_matches,
            "qscore": round(best_qscore, 2),
            "qscore_pc": round(best_qscore / max(1, CT_LEN - 3), 2),
            "fitness": round(best_fitness, 2),
            "key": list(best_key),
            "accept_rate": round(accepted / steps_per_restart, 3),
        })

        if best_fitness > global_best["fitness"]:
            global_best = {
                "fitness": round(best_fitness, 2),
                "crib_matches": best_matches,
                "qscore": round(best_qscore, 2),
                "qscore_pc": round(best_qscore / max(1, CT_LEN - 3), 2),
                "plaintext": best_pt,
                "key": list(best_key),
                "sigma_inv": best_sigma_inv,
            }

        if (restart + 1) % max(1, n_restarts // 10) == 0 or restart == 0:
            elapsed = time.time() - t0
            gb = global_best
            print(f"  [{restart+1:>4}/{n_restarts}] "
                  f"cribs={gb['crib_matches']}/24  "
                  f"qg/c={gb['qscore_pc']:.2f}  "
                  f"PT={gb['plaintext'][:30]}...  "
                  f"({elapsed:.0f}s)")
            sys.stdout.flush()

    elapsed = time.time() - t0
    return global_best, restart_bests, elapsed


def main():
    t_start = time.time()

    print("=" * 60)
    print("E-S-08: SA with Quadgram + Crib Fitness")
    print("=" * 60)
    print(f"Model: PT = vig_decrypt(sigma_inv(CT), periodic_key)")
    print(f"Fitness: crib_matches × 1000 + quadgram_score")
    print()

    scorer = QuadgramScorer()
    print(f"Quadgram scorer loaded: {len(scorer.logp):,} entries")
    print(f"  English reference: TION={scorer.logp.get('TION', 0):.3f}")
    print(f"  Floor: {scorer.floor:.3f}")

    # Test random plaintext score
    rng = random.Random(0)
    rand_text = ''.join(rng.choice(ALPH) for _ in range(97))
    rand_score = scorer.score_per_char(rand_text)
    print(f"  Random text score/char: {rand_score:.3f}")

    # Test English text score
    eng = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUA" \
          "NCESOFIQLUSIONITWASTOTALLYINVISIBLEHOWSTHATTOTAL"
    eng_score = scorer.score_per_char(eng[:97])
    print(f"  K1 plaintext score/char: {eng_score:.3f}")
    print()

    all_results = {}

    # Search at each meaningful period
    for period in [7, 5, 3, 6, 4]:
        print(f"\n{'=' * 60}")
        print(f"  Period {period} — 100 restarts × 200K steps")
        print(f"{'=' * 60}")
        sys.stdout.flush()

        best, bests, elapsed = sa_search(
            scorer, period,
            n_restarts=100,
            steps_per_restart=200_000,
            seed=42 + period,
        )

        print(f"\n  Best: cribs={best['crib_matches']}/24  "
              f"qg/c={best['qscore_pc']:.2f}  "
              f"key={best['key']}")
        print(f"  PT: {best['plaintext']}")

        # Score distribution
        qscores = [b["qscore_pc"] for b in bests]
        crib_scores = [b["crib_matches"] for b in bests]
        print(f"  Crib distribution: min={min(crib_scores)} "
              f"mean={sum(crib_scores)/len(crib_scores):.1f} "
              f"max={max(crib_scores)}")
        print(f"  Quadgram/char distribution: min={min(qscores):.2f} "
              f"mean={sum(qscores)/len(qscores):.2f} "
              f"max={max(qscores):.2f}")
        print(f"  Reference: English≈{eng_score:.2f}, Random≈{rand_score:.2f}")

        all_results[f"period_{period}"] = {
            "period": period,
            "best_crib_matches": best["crib_matches"],
            "best_qscore_pc": best["qscore_pc"],
            "best_plaintext": best["plaintext"],
            "best_key": best["key"],
            "elapsed_s": round(elapsed, 1),
            "n_restarts": 100,
            "steps_per_restart": 200_000,
            "crib_dist": {
                "min": min(crib_scores),
                "mean": round(sum(crib_scores) / len(crib_scores), 1),
                "max": max(crib_scores),
            },
            "qscore_dist": {
                "min": round(min(qscores), 3),
                "mean": round(sum(qscores) / len(qscores), 3),
                "max": round(max(qscores), 3),
            },
        }

    # ═══ Summary ═════════════════════════════════════════════════════════
    t_total = time.time() - t_start

    print(f"\n{'=' * 60}")
    print(f"  SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Total time: {t_total:.0f}s ({t_total/60:.1f} min)")
    print()

    for key, r in all_results.items():
        print(f"  {key}: cribs={r['best_crib_matches']}/24  "
              f"qg/c={r['best_qscore_pc']:.2f}  "
              f"key={r['best_key']}")
        print(f"    PT: {r['best_plaintext'][:60]}...")
    print()

    # Best overall
    best_entry = max(all_results.values(),
                     key=lambda x: x["best_crib_matches"] * 1000 + x["best_qscore_pc"])
    print(f"  Best overall: period={best_entry['period']}  "
          f"cribs={best_entry['best_crib_matches']}/24  "
          f"qg/c={best_entry['best_qscore_pc']:.2f}")
    print(f"  PT: {best_entry['best_plaintext']}")

    if best_entry["best_crib_matches"] >= 20 and best_entry["best_qscore_pc"] > -4.5:
        verdict = "INVESTIGATE"
    elif best_entry["best_crib_matches"] >= 24:
        verdict = "SIGNAL"
    else:
        verdict = "NOISE"

    print(f"  VERDICT: {verdict}")

    # Write results
    os.makedirs("results", exist_ok=True)
    outpath = "results/e_s_08_sa_quadgram.json"
    with open(outpath, "w") as f:
        json.dump({
            "experiment": "E-S-08",
            "hypothesis": "General transposition + periodic Vigenere (quadgram-guided SA)",
            "model": "PT = vig_decrypt(sigma_inv(CT), periodic_key)",
            "total_time_s": round(t_total, 1),
            "verdict": verdict,
            "results_by_period": all_results,
        }, f, indent=2, default=str)

    print(f"\n  Artifacts: {outpath}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_08_sa_quadgram.py")
    print(f"\nRESULT: cribs={best_entry['best_crib_matches']}/24 "
          f"qg/c={best_entry['best_qscore_pc']:.2f} verdict={verdict}")


if __name__ == "__main__":
    main()
