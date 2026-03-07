#!/usr/bin/env python3
"""
HOROLOGE Deep Investigation — Focused keyword evaluation campaign.

Tests HOROLOGE as:
  1. Vigenere/Beaufort keyword with simulated annealing (escapes hill-climbing optima)
  2. Gromark/Vimark primer in multiple bases and letter->number mappings
  3. Agent-guided investigation (SDK) feeding local compute results to Claude
  4. Genetic crossover of elite permutations from prior campaign

Architecture:
  Phase 1: Gromark primer sweep (local CPU, exhaustive, free)
  Phase 2: Simulated annealing permutation search (local CPU, free)
  Phase 3: Genetic crossover of top permutations (local CPU, free)
  Phase 4: Agent investigation with full context (SDK, costs tokens)

Usage:
    PYTHONPATH=src python3 -u kryptosbot/horologe_deep.py
    PYTHONPATH=src python3 -u kryptosbot/horologe_deep.py --local-only
    PYTHONPATH=src python3 -u kryptosbot/horologe_deep.py --phase gromark
    PYTHONPATH=src python3 -u kryptosbot/horologe_deep.py --phase sa
    PYTHONPATH=src python3 -u kryptosbot/horologe_deep.py --phase agent
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import math
import multiprocessing as mp
import os
import random
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("kryptosbot.horologe_deep")


# ---------------------------------------------------------------------------
# Constants (duplicated for worker isolation)
# ---------------------------------------------------------------------------

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
K4_LEN = 97
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
CRIBS = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]

HOROLOGE = "HOROLOGE"

# All crib positions sorted
_CRIB_ENTRIES = []
for _s, _t in CRIBS:
    for _j, _c in enumerate(_t):
        _CRIB_ENTRIES.append((_s + _j, _c, K4[_s + _j]))
_CRIB_ENTRIES.sort()
CRIB_POSITIONS = [e[0] for e in _CRIB_ENTRIES]
CRIB_PT = [e[1] for e in _CRIB_ENTRIES]
CRIB_CT = [e[2] for e in _CRIB_ENTRIES]
N_CRIBS = len(CRIB_POSITIONS)

# Bean constraints
BEAN_EQ = [(27, 65)]
BEAN_INEQ = [
    (24, 28), (28, 33), (24, 33), (21, 30), (21, 64), (30, 64),
    (68, 25), (22, 31), (66, 70), (26, 71), (69, 72), (23, 32),
    (71, 21), (25, 26), (24, 66), (31, 73), (29, 63), (32, 33),
    (67, 68), (27, 72), (23, 28),
]


# ---------------------------------------------------------------------------
# Quadgram scoring
# ---------------------------------------------------------------------------

_QUADGRAMS: dict[str, float] | None = None
_QG_FLOOR: float = -10.0


def _load_quadgrams() -> dict[str, float]:
    global _QUADGRAMS, _QG_FLOOR
    if _QUADGRAMS is not None:
        return _QUADGRAMS
    candidates = [
        Path(__file__).resolve().parent.parent / "data" / "english_quadgrams.json",
        Path("data/english_quadgrams.json"),
    ]
    for p in candidates:
        if p.exists():
            with open(p) as f:
                _QUADGRAMS = json.load(f)
            _QG_FLOOR = min(_QUADGRAMS.values()) - 1.0
            return _QUADGRAMS
    raise FileNotFoundError("Cannot find english_quadgrams.json")


def _score_text(text: str) -> float:
    qg = _load_quadgrams()
    if len(text) < 4:
        return -999.0
    return sum(qg.get(text[i:i + 4], _QG_FLOOR) for i in range(len(text) - 3))


def _score_per_char(text: str) -> float:
    n = len(text) - 3
    return _score_text(text) / max(1, n) if n > 0 else _QG_FLOOR


# ---------------------------------------------------------------------------
# Cipher functions
# ---------------------------------------------------------------------------

def _vig_decrypt(ct: str, key: str, alpha: str = AZ) -> str:
    result = []
    klen = len(key)
    for i, c in enumerate(ct):
        ci = alpha.index(c)
        ki = alpha.index(key[i % klen])
        pi = (ci - ki) % 26
        result.append(alpha[pi])
    return "".join(result)


def _beau_decrypt(ct: str, key: str, alpha: str = AZ) -> str:
    result = []
    klen = len(key)
    for i, c in enumerate(ct):
        ci = alpha.index(c)
        ki = alpha.index(key[i % klen])
        pi = (ki - ci) % 26
        result.append(alpha[pi])
    return "".join(result)


def _apply_perm(text: str, perm: list[int]) -> str:
    return "".join(text[p] for p in perm)


def _count_crib_hits(pt: str) -> int:
    hits = 0
    for pos, crib_text in CRIBS:
        end = pos + len(crib_text)
        if end <= len(pt):
            hits += sum(1 for j, c in enumerate(crib_text) if pt[pos + j] == c)
    return hits


def keyword_alphabet(kw: str) -> str:
    seen = set()
    alpha = []
    for ch in kw.upper():
        if ch.isalpha() and ch not in seen:
            seen.add(ch)
            alpha.append(ch)
    for ch in AZ:
        if ch not in seen:
            seen.add(ch)
            alpha.append(ch)
    return "".join(alpha)


# ---------------------------------------------------------------------------
# PHASE 1: Gromark Primer Sweep
# ---------------------------------------------------------------------------

# Multiple ways to convert HOROLOGE to numbers
HOROLOGE_MAPPINGS: dict[str, list[int]] = {
    "az_0": [AZ.index(c) for c in HOROLOGE],           # A=0: [7,14,17,14,11,14,6,4]
    "az_1": [(AZ.index(c) + 1) % 26 for c in HOROLOGE],  # A=1: [8,15,18,15,12,15,7,5]
    "ka_0": [KA.index(c) for c in HOROLOGE],            # KA ordering: different positions
    "mod10": [AZ.index(c) % 10 for c in HOROLOGE],      # mod 10: [7,4,7,4,1,4,6,4]
    "mod5": [AZ.index(c) % 5 for c in HOROLOGE],        # mod 5: [2,4,2,4,1,4,1,4]
}

# Also test truncations and rotations
for i in range(len(HOROLOGE)):
    rot = HOROLOGE[i:] + HOROLOGE[:i]
    if i > 0:
        HOROLOGE_MAPPINGS[f"rot{i}_az0"] = [AZ.index(c) for c in rot]


def _gromark_worker(args: tuple) -> dict:
    """Test one (mapping, base, variant, alphabet) Gromark combination."""
    mapping_name, primer, base, variant, alpha_label = args

    _load_quadgrams()

    alpha = KA if alpha_label == "KA" else (
        keyword_alphabet(HOROLOGE) if alpha_label == "HOROLOGE" else AZ
    )

    # Compute required keys at crib positions
    required = []
    for i in range(N_CRIBS):
        cn = alpha.index(CRIB_CT[i])
        pn = alpha.index(CRIB_PT[i])
        if variant == "vig":
            k = (cn - pn) % 26
        elif variant == "beau":
            k = (cn + pn) % 26
        else:  # varbeau
            k = (pn - cn) % 26
        required.append(k)

    # Reduce primer to base
    actual_primer = [d % base for d in primer]

    # Expand keystream with early crib termination
    ks = list(actual_primer)
    plen = len(actual_primer)
    crib_idx = 0
    failed = False

    # Check primer positions against cribs
    while crib_idx < N_CRIBS and CRIB_POSITIONS[crib_idx] < plen:
        if ks[CRIB_POSITIONS[crib_idx]] != required[crib_idx]:
            failed = True
            break
        crib_idx += 1

    if not failed:
        while len(ks) < K4_LEN:
            ks.append((ks[-plen] + ks[-(plen - 1)]) % base)
            pos = len(ks) - 1
            while crib_idx < N_CRIBS and CRIB_POSITIONS[crib_idx] == pos:
                if ks[pos] != required[crib_idx]:
                    failed = True
                    break
                crib_idx += 1
            if failed:
                break

    if failed or len(ks) < K4_LEN:
        return {
            "mapping": mapping_name, "base": base, "variant": variant,
            "alpha": alpha_label, "crib_pass": False, "score": -999.0,
        }

    # Decrypt
    ct_nums = [alpha.index(ch) for ch in K4]
    pt_chars = []
    for i in range(K4_LEN):
        if variant == "vig":
            p = (ct_nums[i] - ks[i]) % 26
        elif variant == "beau":
            p = (ks[i] - ct_nums[i]) % 26
        else:
            p = (ct_nums[i] + ks[i]) % 26
        pt_chars.append(alpha[p])
    pt = "".join(pt_chars)
    score = _score_per_char(pt)

    return {
        "mapping": mapping_name, "base": base, "variant": variant,
        "alpha": alpha_label, "crib_pass": True,
        "score": round(score, 3), "plaintext": pt,
        "primer": [d % base for d in primer],
        "method": f"gromark/{mapping_name}/b{base}/{variant}/{alpha_label}",
    }


def run_gromark_sweep(num_workers: int = 0) -> dict:
    """Exhaustive Gromark sweep with HOROLOGE-derived primers."""
    if num_workers <= 0:
        num_workers = mp.cpu_count() or 4

    print(f"\n{'=' * 70}")
    print(f"  PHASE 1: HOROLOGE Gromark Primer Sweep")
    print(f"  Mappings: {len(HOROLOGE_MAPPINGS)} (az_0, ka_0, mod10, rotations, ...)")
    print(f"  Bases: 2-26, Variants: vig/beau/varbeau")
    print(f"  Alphabets: AZ, KA, HOROLOGE-keyed")
    print(f"{'=' * 70}\n")

    work_items = []
    variants = ["vig", "beau", "varbeau"]
    alphabets = ["AZ", "KA", "HOROLOGE"]

    for mapping_name, primer in HOROLOGE_MAPPINGS.items():
        min_base = max(primer) + 1
        for base in range(max(2, min_base), 27):
            for variant in variants:
                for alpha_label in alphabets:
                    work_items.append((mapping_name, primer, base, variant, alpha_label))

    print(f"  Work items: {len(work_items)}")

    t0 = time.time()
    crib_pass = []
    total = 0

    with ProcessPoolExecutor(max_workers=num_workers) as pool:
        for result in pool.map(_gromark_worker, work_items, chunksize=50):
            total += 1
            if result["crib_pass"]:
                crib_pass.append(result)

    elapsed = time.time() - t0

    print(f"\n  Tested: {total} combinations in {elapsed:.1f}s")
    print(f"  Crib-pass: {len(crib_pass)}")

    if crib_pass:
        crib_pass.sort(key=lambda r: r["score"], reverse=True)
        print(f"\n  Top crib-passing results:")
        for r in crib_pass[:10]:
            print(f"    score={r['score']:+.3f} {r['method']}")
            print(f"      PT={r['plaintext'][:50]}...")
    else:
        print(f"  No Gromark primer derived from HOROLOGE matches all 24 crib positions.")

    return {
        "total_tested": total,
        "crib_pass": len(crib_pass),
        "elapsed": round(elapsed, 2),
        "top_results": crib_pass[:20],
    }


# ---------------------------------------------------------------------------
# PHASE 2: Simulated Annealing
# ---------------------------------------------------------------------------

def _sa_worker(args: tuple) -> dict:
    """Simulated annealing for one cipher/alphabet combo with HOROLOGE."""
    cipher, alphabet, iterations, initial_temp, cooling, restart_id = args

    alpha = KA if alphabet == "KA" else AZ
    decrypt_fn = _beau_decrypt if cipher == "beau" else _vig_decrypt

    # Start from identity with optional small perturbation
    perm = list(range(K4_LEN))
    if restart_id > 0:
        n_perturb = random.randint(2, min(10, restart_id + 2))
        for _ in range(n_perturb):
            a, b = random.sample(range(K4_LEN), 2)
            perm[a], perm[b] = perm[b], perm[a]

    ct = _apply_perm(K4, perm)
    pt = decrypt_fn(ct, HOROLOGE, alpha)
    current_score = _score_text(pt)
    best_score = current_score
    best_perm = list(perm)
    best_pt = pt

    temp = initial_temp
    accepted_worse = 0

    for it in range(iterations):
        # Adaptive temperature: geometric cooling
        temp = initial_temp * (cooling ** it)
        if temp < 0.01:
            temp = 0.01

        # Random swap
        i, j = random.sample(range(K4_LEN), 2)
        perm[i], perm[j] = perm[j], perm[i]

        ct = _apply_perm(K4, perm)
        pt = decrypt_fn(ct, HOROLOGE, alpha)
        score = _score_text(pt)

        delta = score - current_score

        # Accept better solutions always; accept worse with probability
        if delta > 0 or random.random() < math.exp(delta / temp):
            current_score = score
            if delta < 0:
                accepted_worse += 1
            if score > best_score:
                best_score = score
                best_perm = list(perm)
                best_pt = pt
        else:
            # Revert
            perm[i], perm[j] = perm[j], perm[i]

    displaced = sum(1 for i in range(K4_LEN) if best_perm[i] != i)
    crib_hits = _count_crib_hits(best_pt)

    return {
        "score": round(best_score, 2),
        "plaintext": best_pt,
        "perm": best_perm,
        "crib_hits": crib_hits,
        "method": f"sa/{cipher}/HOROLOGE/{alphabet}",
        "displaced": displaced,
        "accepted_worse": accepted_worse,
        "restart_id": restart_id,
    }


def run_simulated_annealing(
    *,
    iterations: int = 500_000,
    initial_temp: float = 50.0,
    cooling: float = 0.99999,
    restarts: int = 0,
    num_workers: int = 0,
) -> dict:
    """SA search over permutation space with HOROLOGE as keyword."""
    if num_workers <= 0:
        num_workers = mp.cpu_count() or 4
    if restarts <= 0:
        restarts = num_workers * 2

    print(f"\n{'=' * 70}")
    print(f"  PHASE 2: Simulated Annealing — HOROLOGE")
    print(f"  Iterations: {iterations:,} per restart")
    print(f"  Initial temp: {initial_temp}, Cooling: {cooling}")
    print(f"  Restarts: {restarts}, Workers: {num_workers}")
    print(f"{'=' * 70}\n")

    work_items = []
    for cipher in ("vig", "beau"):
        for alpha in ("AZ", "KA"):
            for rid in range(restarts):
                work_items.append((cipher, alpha, iterations, initial_temp, cooling, rid))

    t0 = time.time()
    all_results = []

    with ProcessPoolExecutor(max_workers=num_workers) as pool:
        futures = [pool.submit(_sa_worker, a) for a in work_items]
        for future in as_completed(futures):
            try:
                result = future.result()
                all_results.append(result)
            except Exception as e:
                logger.error("SA worker failed: %s", e)

    elapsed = time.time() - t0
    all_results.sort(key=lambda r: r["score"], reverse=True)

    print(f"\n  Completed {len(all_results)} SA runs in {elapsed:.1f}s")
    print(f"  Top 10 results:")
    for r in all_results[:10]:
        print(f"    score={r['score']:>8.1f}  cribs={r['crib_hits']}  "
              f"disp={r['displaced']:>3}  worse={r['accepted_worse']:>6}  {r['method']}")

    best = all_results[0] if all_results else None
    if best:
        print(f"\n  Best: score={best['score']:.1f} cribs={best['crib_hits']} {best['method']}")
        print(f"  PT: {best['plaintext'][:60]}...")

    return {
        "elapsed": round(elapsed, 2),
        "total_runs": len(all_results),
        "best": best,
        "top_results": all_results[:30],
    }


# ---------------------------------------------------------------------------
# PHASE 3: Genetic Crossover
# ---------------------------------------------------------------------------

def _crossover_perms(p1: list[int], p2: list[int]) -> list[int]:
    """Order crossover (OX) of two permutations."""
    n = len(p1)
    start, end = sorted(random.sample(range(n), 2))
    child = [-1] * n
    # Copy segment from p1
    child[start:end] = p1[start:end]
    # Fill rest from p2 in order
    p2_remaining = [x for x in p2 if x not in child[start:end]]
    idx = 0
    for i in range(n):
        if child[i] == -1:
            child[i] = p2_remaining[idx]
            idx += 1
    return child


def _genetic_worker(args: tuple) -> dict:
    """One generation of genetic crossover + hill-climbing."""
    parent1, parent2, cipher, alphabet, hc_iterations, gen_id = args

    alpha = KA if alphabet == "KA" else AZ
    decrypt_fn = _beau_decrypt if cipher == "beau" else _vig_decrypt

    # Create child via order crossover
    perm = _crossover_perms(parent1, parent2)

    # Hill-climb the child
    ct = _apply_perm(K4, perm)
    pt = decrypt_fn(ct, HOROLOGE, alpha)
    best_score = _score_text(pt)
    best_perm = list(perm)
    best_pt = pt

    for _ in range(hc_iterations):
        i, j = random.sample(range(K4_LEN), 2)
        perm[i], perm[j] = perm[j], perm[i]
        ct = _apply_perm(K4, perm)
        pt = decrypt_fn(ct, HOROLOGE, alpha)
        score = _score_text(pt)
        if score > best_score:
            best_score = score
            best_perm = list(perm)
            best_pt = pt
        else:
            perm[i], perm[j] = perm[j], perm[i]

    displaced = sum(1 for i in range(K4_LEN) if best_perm[i] != i)
    crib_hits = _count_crib_hits(best_pt)

    return {
        "score": round(best_score, 2),
        "plaintext": best_pt,
        "perm": best_perm,
        "crib_hits": crib_hits,
        "method": f"genetic/{cipher}/HOROLOGE/{alphabet}",
        "displaced": displaced,
        "gen_id": gen_id,
    }


def run_genetic_crossover(
    elite_perms: list[list[int]],
    *,
    generations: int = 5,
    offspring_per_gen: int = 0,
    hc_iterations: int = 100_000,
    num_workers: int = 0,
) -> dict:
    """Genetic crossover of elite permutations, each offspring hill-climbed."""
    if num_workers <= 0:
        num_workers = mp.cpu_count() or 4
    if offspring_per_gen <= 0:
        offspring_per_gen = num_workers * 2

    if len(elite_perms) < 2:
        print("  Need at least 2 elite permutations for crossover.")
        return {"error": "insufficient_elites"}

    print(f"\n{'=' * 70}")
    print(f"  PHASE 3: Genetic Crossover — HOROLOGE")
    print(f"  Elite pool: {len(elite_perms)} permutations")
    print(f"  Generations: {generations}, Offspring/gen: {offspring_per_gen}")
    print(f"  HC iterations per offspring: {hc_iterations:,}")
    print(f"{'=' * 70}\n")

    t0 = time.time()
    all_results = []
    population = list(elite_perms)

    for gen in range(generations):
        work_items = []
        for oid in range(offspring_per_gen):
            p1, p2 = random.sample(population, 2)
            cipher = random.choice(["vig", "beau"])
            alpha = random.choice(["AZ", "KA"])
            work_items.append((p1, p2, cipher, alpha, hc_iterations, oid))

        gen_results = []
        with ProcessPoolExecutor(max_workers=num_workers) as pool:
            futures = [pool.submit(_genetic_worker, a) for a in work_items]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    gen_results.append(result)
                    all_results.append(result)
                except Exception as e:
                    logger.error("Genetic worker failed: %s", e)

        # Add best offspring to population
        gen_results.sort(key=lambda r: r["score"], reverse=True)
        for r in gen_results[:5]:
            population.append(r["perm"])
        # Keep population bounded
        population = population[:50]

        best_gen = gen_results[0] if gen_results else None
        if best_gen:
            print(f"  Gen {gen + 1}: best={best_gen['score']:.1f} cribs={best_gen['crib_hits']} "
                  f"disp={best_gen['displaced']} {best_gen['method']}")

    elapsed = time.time() - t0
    all_results.sort(key=lambda r: r["score"], reverse=True)

    best = all_results[0] if all_results else None
    print(f"\n  Genetic crossover: {len(all_results)} offspring in {elapsed:.1f}s")
    if best:
        print(f"  Best: score={best['score']:.1f} cribs={best['crib_hits']} {best['method']}")
        print(f"  PT: {best['plaintext'][:60]}...")

    return {
        "elapsed": round(elapsed, 2),
        "total_offspring": len(all_results),
        "generations": generations,
        "best": best,
        "top_results": all_results[:30],
    }


# ---------------------------------------------------------------------------
# PHASE 4: Agent Investigation (SDK)
# ---------------------------------------------------------------------------

async def run_agent_investigation(
    gromark_results: dict,
    sa_results: dict,
    genetic_results: dict | None = None,
    *,
    max_turns: int = 15,
) -> dict:
    """Use Claude agent to reason about HOROLOGE findings and suggest next steps."""
    from kryptosbot.agent_runner import run_agent_session, AgentResult
    from kryptosbot.sdk_wrapper import preflight_check

    ok, msg = await preflight_check()
    if not ok:
        logger.error("SDK preflight failed: %s", msg)
        return {"error": msg}

    project_root = Path(__file__).resolve().parent.parent

    # Build rich context prompt
    gromark_summary = "NO crib-passing results" if gromark_results["crib_pass"] == 0 else (
        f"{gromark_results['crib_pass']} crib-passing results, best: "
        + json.dumps(gromark_results["top_results"][0], indent=2)
    )

    sa_best = sa_results.get("best")
    sa_summary = "No SA results" if not sa_best else (
        f"Best SA: score={sa_best['score']}, cribs={sa_best['crib_hits']}, "
        f"displaced={sa_best['displaced']}, method={sa_best['method']}\n"
        f"PT: {sa_best['plaintext'][:80]}"
    )

    genetic_summary = "Not run" if not genetic_results else (
        f"Best genetic: score={genetic_results['best']['score']}, "
        f"cribs={genetic_results['best']['crib_hits']}"
        if genetic_results.get("best") else "No results"
    )

    prompt = f"""\
## HOROLOGE Deep Investigation — Agent Phase

You are analyzing HOROLOGE as a potential keyword for the Kryptos K4 cipher.
Your job is to reason about the findings below and suggest NEW attack angles.

### Why HOROLOGE?
- HOROLOGE = "timepiece/clock" (Greek horologion) — direct semantic link to BERLINCLOCK crib
- Length 8, Bean-compatible: H-O-R-O-L-O-G-E has O at positions 1,3,5 (all odd)
- Bean equality satisfied: key[27%8]=key[65%8] → key[3]=key[1] → O=O
- Scored -345.0 with 4 crib hits in priority keyword sweep (best among 8 tested keywords)

### K4 Constants
CT: {K4}
Length: {K4_LEN}
Cribs: EASTNORTHEAST at 21-33, BERLINCLOCK at 63-73

### Phase 1: Gromark Primer Results
{gromark_summary}

**Prior exhaustive Gromark sweep (e_gromark_exhaustive.py):** 3,198,682,180 primers tested
across bases 2-26, primer lengths 2-6, AZ+KA alphabets, all 3 variants. ZERO crib-passes.
Gromark is functionally eliminated for short primers. HOROLOGE at plen=8 falls outside
that sweep (26^8 = 208B primers needed for exhaustive), but HOROLOGE-derived mappings
are tested in Phase 1 above.

### Phase 2: Simulated Annealing Results
{sa_summary}

### Phase 3: Genetic Crossover Results
{genetic_summary}

### Your Tasks
1. **Analyze the structural implications** of HOROLOGE having three O's at odd positions.
   What does this mean for the keystream? For the Vigenere tableau row selection?

2. **Consider HOROLOGE as a VARIANT key**: Could it be a Beaufort key? Variant Beaufort?
   Could it be applied to a non-standard alphabet (KRYPTOS-keyed)?

3. **Think about HOROLOGE + the Cardan grille**: If HOROLOGE is the substitution key,
   how might the grille reading order interact with it? Could the grille positions be
   derivable from HOROLOGE's letter values?

4. **Suggest 3-5 concrete, testable hypotheses** about how HOROLOGE might be used.
   Each should be specific enough to implement as a computation.

5. **If Gromark failed**: Explain why HOROLOGE as a Gromark primer doesn't work and
   what this tells us about the cipher structure.

### MANDATORY OUTPUT
At the END of your response, include:
```verdict
{{"verdict_status": "<promising|inconclusive|disproved>", "score": <number>,
 "summary": "<one-line>", "evidence": "<key evidence>",
 "hypotheses": ["<testable hypothesis 1>", "<hypothesis 2>", ...]}}
```
"""

    results_dir = project_root / "results" / "horologe_deep"
    results_dir.mkdir(parents=True, exist_ok=True)

    result = await run_agent_session(
        name="horologe_investigator",
        prompt=prompt,
        project_root=project_root,
        results_dir=results_dir,
        max_turns=max_turns,
        allowed_tools=["Read", "Bash", "Glob", "Grep"],
    )

    return {
        "crib_found": result.crib_found,
        "best_score": result.best_score,
        "verdict": result.verdict,
        "elapsed": result.elapsed_seconds,
        "raw_output_file": str(result.raw_output_file),
    }


# ---------------------------------------------------------------------------
# Campaign Orchestrator
# ---------------------------------------------------------------------------

def _load_elite_perms() -> list[list[int]]:
    """Load elite permutations from prior campaign state."""
    state_path = Path(__file__).resolve().parent.parent / "results" / "campaign" / "state.json"
    if not state_path.exists():
        return []
    try:
        with open(state_path) as f:
            state = json.load(f)
        elites = state.get("elite", [])
        perms = [e["perm"] for e in elites if "perm" in e]
        logger.info("Loaded %d elite permutations from campaign state", len(perms))
        return perms
    except Exception as e:
        logger.error("Failed to load elite perms: %s", e)
        return []


def run_all_local(num_workers: int = 0) -> dict:
    """Run all local (free) phases: Gromark + SA + Genetic."""
    results = {}

    # Phase 1: Gromark
    results["gromark"] = run_gromark_sweep(num_workers=num_workers)

    # Phase 2: Simulated Annealing
    results["sa"] = run_simulated_annealing(num_workers=num_workers)

    # Phase 3: Genetic Crossover (if elite perms available)
    elite_perms = _load_elite_perms()
    # Also add SA top perms
    if results["sa"].get("top_results"):
        for r in results["sa"]["top_results"][:10]:
            if "perm" in r:
                elite_perms.append(r["perm"])

    if len(elite_perms) >= 2:
        results["genetic"] = run_genetic_crossover(
            elite_perms, num_workers=num_workers,
        )
    else:
        print("\n  Skipping genetic crossover: need at least 2 elite permutations.")
        results["genetic"] = None

    return results


async def run_full_campaign(
    *,
    num_workers: int = 0,
    local_only: bool = False,
    max_turns: int = 15,
) -> dict:
    """Full HOROLOGE investigation: local phases + optional agent."""
    results = run_all_local(num_workers=num_workers)

    if not local_only:
        print(f"\n{'=' * 70}")
        print(f"  PHASE 4: Agent Investigation (SDK)")
        print(f"{'=' * 70}\n")
        results["agent"] = await run_agent_investigation(
            gromark_results=results["gromark"],
            sa_results=results["sa"],
            genetic_results=results.get("genetic"),
            max_turns=max_turns,
        )

    # Save results
    out_dir = Path(__file__).resolve().parent.parent / "results" / "horologe_deep"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Strip non-serializable data
    def _clean(obj):
        if isinstance(obj, dict):
            return {k: _clean(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_clean(v) for v in obj]
        if isinstance(obj, Path):
            return str(obj)
        return obj

    summary_path = out_dir / "summary.json"
    with open(summary_path, "w") as f:
        json.dump(_clean(results), f, indent=2, default=str)

    # Print final summary
    print(f"\n{'=' * 70}")
    print(f"  HOROLOGE DEEP INVESTIGATION — SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Gromark: {results['gromark']['crib_pass']} crib-pass / "
          f"{results['gromark']['total_tested']} tested ({results['gromark']['elapsed']}s)")

    sa_best = results["sa"].get("best")
    if sa_best:
        print(f"  SA best: score={sa_best['score']:.1f} cribs={sa_best['crib_hits']} "
              f"{sa_best['method']}")

    gen = results.get("genetic")
    if gen and gen.get("best"):
        print(f"  Genetic best: score={gen['best']['score']:.1f} cribs={gen['best']['crib_hits']} "
              f"{gen['best']['method']}")

    agent = results.get("agent")
    if agent and not agent.get("error"):
        print(f"  Agent: verdict={agent.get('verdict', {}).get('verdict_status', 'N/A')}")

    print(f"\n  Results: {summary_path}")
    print(f"{'=' * 70}\n")

    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="HOROLOGE Deep Investigation")
    parser.add_argument("--phase", choices=["gromark", "sa", "genetic", "agent", "all"],
                        default="all", help="Run specific phase (default: all)")
    parser.add_argument("--local-only", action="store_true",
                        help="Skip agent investigation (no API tokens)")
    parser.add_argument("--workers", type=int, default=0,
                        help="CPU workers (default: all cores)")
    parser.add_argument("--sa-iterations", type=int, default=500_000,
                        help="SA iterations per restart")
    parser.add_argument("--sa-restarts", type=int, default=0,
                        help="SA restarts (default: 2 × workers)")
    parser.add_argument("--sa-temp", type=float, default=50.0,
                        help="SA initial temperature")
    parser.add_argument("--genetic-gens", type=int, default=5,
                        help="Genetic crossover generations")
    parser.add_argument("--max-turns", type=int, default=15,
                        help="Max agent turns (SDK)")
    args = parser.parse_args()

    if args.phase == "gromark":
        run_gromark_sweep(num_workers=args.workers)
    elif args.phase == "sa":
        run_simulated_annealing(
            iterations=args.sa_iterations,
            initial_temp=args.sa_temp,
            restarts=args.sa_restarts,
            num_workers=args.workers,
        )
    elif args.phase == "genetic":
        elite_perms = _load_elite_perms()
        if len(elite_perms) >= 2:
            run_genetic_crossover(
                elite_perms,
                generations=args.genetic_gens,
                num_workers=args.workers,
            )
        else:
            print("Need at least 2 elite permutations. Run campaign.py first.")
    elif args.phase == "agent":
        # Need prior results
        out_dir = Path(__file__).resolve().parent.parent / "results" / "horologe_deep"
        summary_path = out_dir / "summary.json"
        if summary_path.exists():
            with open(summary_path) as f:
                prior = json.load(f)
            asyncio.run(run_agent_investigation(
                gromark_results=prior.get("gromark", {"crib_pass": 0, "top_results": []}),
                sa_results=prior.get("sa", {}),
                genetic_results=prior.get("genetic"),
                max_turns=args.max_turns,
            ))
        else:
            print("No prior results. Run local phases first.")
    else:
        asyncio.run(run_full_campaign(
            num_workers=args.workers,
            local_only=args.local_only,
            max_turns=args.max_turns,
        ))


if __name__ == "__main__":
    main()
