"""E04 H2 — Non-columnar × non-columnar composed Ts under TABP shape.

Pre-registered design: experiments/e04_h2_design.md.
Universe locked at run start; SHA-256 of normalized universe printed.

Encryption model (TABP shape):
  PT --[T_inner]--> x1 --[T_outer]--> x2 --[SUB]--> CT

Decryption (what we apply):
  CT --[SUB^-1]--> intermediate (length 97)
      --[T_outer^-1]--> stage
      --[T_inner^-1]--> PT

For efficiency: precompute 180 substitution intermediates once; for each
of 312 × 312 (T_inner, T_outer) pairs precompute the composed inverse
permutation **restricted to the 24 crib positions**; loop only counts
crib hits and only materialises full PT when a Tier 1+ candidate fires.
"""

import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.dirname(ROOT))

from independent_solve_2026_05_19.src.alphabets import AZ, KA
from independent_solve_2026_05_19.src.ciphers.vigenere import decrypt as vig_decrypt
from independent_solve_2026_05_19.src.ciphers.beaufort import (
    beaufort_decrypt, variant_beaufort_decrypt,
)
from independent_solve_2026_05_19.src.ciphers.transposition import (
    apply_perm, invert_perm,
    myszkowski_perm, rail_fence_perm,
    route_spiral_perm,
)


CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = 97
CT_BYTES = CT.encode('ascii')

KEYWORD_POOL_K4 = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA",
    "BERLIN", "CLOCK", "BERLINCLOCK",
    "EAST", "NORTHEAST", "EASTNORTHEAST",
    "WORLD", "WORLDCLOCK",
    "LANGLEY", "WEBSTER", "CARTER", "HOWARDCARTER", "TUTANKHAMUN",
    "LAYERTWO", "INVISIBLE", "IQLUSION", "SHADOW", "FORCES",
    "ATBASH", "ALEXANDERPLATZ",
    "SCHEIDT", "SANBORN",
    "MAGNETIC", "EARTHSMAGNETIC",
    "LUCIDMEMORY", "UNDERGRUUND", "DESPARATLY",
]
MYSZ_WIDTHS = list(range(5, 14))
RAIL_DEPTHS = list(range(2, 16))
SPIRAL_RECTS = [(7, 14), (8, 13), (9, 11), (10, 10), (11, 9), (13, 8), (14, 7)]
SPIRAL_DIRS = ["CW_from_NW", "CW_from_NE", "CCW_from_NW", "CCW_from_NE"]

SUB_VARIANTS = [
    ("vig",   vig_decrypt),
    ("beau",  beaufort_decrypt),
    ("vbeau", variant_beaufort_decrypt),
]
SUB_ALPHAS = [("AZ", AZ), ("KA", KA)]

CRIB_POS = list(range(21, 34)) + list(range(63, 74))  # 24 positions
EXPECTED_24 = b"EASTNORTHEAST" + b"BERLINCLOCK"        # 24 bytes
assert len(CRIB_POS) == 24 and len(EXPECTED_24) == 24


def expand_keyword(kw: str, w: int) -> str:
    if len(kw) >= w:
        return kw[:w]
    return (kw * (w // len(kw) + 1))[:w]


def build_perm_catalogue():
    """Return [(label, perm, perm_inv), ...] for all 312 non-columnar
    transpositions."""
    out = []
    for kw in KEYWORD_POOL_K4:
        for w in MYSZ_WIDTHS:
            k = expand_keyword(kw, w)
            p = myszkowski_perm(k, N)
            out.append((f"mysz|{kw}|w{w}", p, invert_perm(p)))
    for d in RAIL_DEPTHS:
        p = rail_fence_perm(d, N)
        out.append((f"rail|d{d}", p, invert_perm(p)))
    for (rows, cols) in SPIRAL_RECTS:
        for direction in SPIRAL_DIRS:
            p = route_spiral_perm(rows, cols, N, direction)
            out.append((f"spir|{rows}x{cols}|{direction}", p, invert_perm(p)))
    assert len(out) == 312, f"perm catalogue size {len(out)} != 312"
    return out


def precompute_sub_intermediates():
    """Return [(label_tuple, intermediate_bytes), ...] for 180 sub configs."""
    out = []
    for vname, fn in SUB_VARIANTS:
        for aname, alpha in SUB_ALPHAS:
            for kw in KEYWORD_POOL_K4:
                inter = fn(CT, kw, alpha).encode('ascii')
                out.append(((vname, aname, kw), inter))
    assert len(out) == 180
    return out


def compute_universe_hash(perm_catalogue):
    """SHA-256 of the locked universe descriptor."""
    perm_labels = sorted([lbl for (lbl, _, _) in perm_catalogue])
    descriptor = {
        "model": "TABP_PT_to_TI_to_TO_to_SUB_to_CT",
        "t_inner_catalogue": perm_labels,
        "t_outer_catalogue": perm_labels,
        "sub_variants": [v for v, _ in SUB_VARIANTS],
        "sub_alphabets": [a for a, _ in SUB_ALPHAS],
        "sub_keywords": sorted(KEYWORD_POOL_K4),
        "expected_total": 312 * 312 * 3 * 2 * 30,
    }
    data = json.dumps(descriptor, sort_keys=True).encode()
    return hashlib.sha256(data).hexdigest(), descriptor["expected_total"]


def main():
    print("E04 H2 sweep — non-columnar × non-columnar composed Ts under TABP")

    perm_catalogue = build_perm_catalogue()
    universe_hash, expected_total = compute_universe_hash(perm_catalogue)
    print(f"  universe SHA-256: {universe_hash}")
    print(f"  expected total configs: {expected_total}")

    sub_intermediates = precompute_sub_intermediates()
    print(f"  precomputed {len(sub_intermediates)} substitution intermediates")

    # Stream outputs
    candidates_path = os.path.join(ROOT, "results", "h2_candidates.jsonl")
    tier2_path = os.path.join(ROOT, "results", "e04_h2_tier2.jsonl")
    tier3_path = os.path.join(ROOT, "results", "e04_h2_tier3.jsonl")
    summary_path = os.path.join(ROOT, "results", "e04_h2_summary.json")
    open(candidates_path, "w").close()
    open(tier2_path, "w").close()
    open(tier3_path, "w").close()

    counters = {
        "evaluated": 0,
        "tier1_stored": 0,
        "tier2_logged": 0,
        "tier3_pre_kernel_pass": 0,
        "tier3_post_kernel_pass": 0,
    }
    bests = {
        "best_crib_score": (0, None),
        "best_combined_holdout": (0, None),
        "best_east_holdout": (0, None),
        "best_bcl_holdout":  (0, None),
    }

    n_perms = len(perm_catalogue)
    t0 = time.time()
    last_report = t0

    # Pre-extract inverse perms as tuples for fast indexing
    perm_invs = [inv for (_, _, inv) in perm_catalogue]
    perm_labels = [lbl for (lbl, _, _) in perm_catalogue]

    cf_outer = open(candidates_path, "a", buffering=1)
    cf_tier2 = open(tier2_path, "a", buffering=1)
    cf_tier3 = open(tier3_path, "a", buffering=1)
    try:
        for ti_idx in range(n_perms):
            ti_inv = perm_invs[ti_idx]
            for to_idx in range(n_perms):
                to_inv = perm_invs[to_idx]
                # composed_dec[i] = ti_inv[to_inv[i]]; we only need the 24 crib indices
                composed_24 = tuple(ti_inv[to_inv[p]] for p in CRIB_POS)

                for (vname, aname, kw), inter in sub_intermediates:
                    counters["evaluated"] += 1

                    # Count crib hits via 24-position lookup
                    east_hits = 0
                    for k in range(13):
                        if inter[composed_24[k]] == EXPECTED_24[k]:
                            east_hits += 1
                    bcl_hits = 0
                    for k in range(11):
                        if inter[composed_24[13 + k]] == EXPECTED_24[13 + k]:
                            bcl_hits += 1
                    total = east_hits + bcl_hits

                    if east_hits > bests["best_east_holdout"][0]:
                        bests["best_east_holdout"] = (east_hits, {
                            "ti": perm_labels[ti_idx], "to": perm_labels[to_idx],
                            "sub": f"{vname}/{aname}", "key": kw,
                        })
                    if bcl_hits > bests["best_bcl_holdout"][0]:
                        bests["best_bcl_holdout"] = (bcl_hits, {
                            "ti": perm_labels[ti_idx], "to": perm_labels[to_idx],
                            "sub": f"{vname}/{aname}", "key": kw,
                        })
                    if total > bests["best_crib_score"][0]:
                        bests["best_crib_score"] = (total, {
                            "ti": perm_labels[ti_idx], "to": perm_labels[to_idx],
                            "sub": f"{vname}/{aname}", "key": kw,
                            "east_hits": east_hits, "bcl_hits": bcl_hits,
                        })
                    if (east_hits + bcl_hits) > bests["best_combined_holdout"][0]:
                        bests["best_combined_holdout"] = (east_hits + bcl_hits, {
                            "ti": perm_labels[ti_idx], "to": perm_labels[to_idx],
                            "sub": f"{vname}/{aname}", "key": kw,
                            "east_hits": east_hits, "bcl_hits": bcl_hits,
                        })

                    if total < 10:
                        continue
                    # Tier 1+ candidate. Materialise full PT for logging.
                    # composed_dec full = [ti_inv[to_inv[i]] for i in range(N)]
                    composed_full = bytes(inter[ti_inv[to_inv[i]]] for i in range(N))
                    pt = composed_full.decode('ascii')
                    se_ok = (pt[32] == 'S') and (pt[73] == 'K')

                    rec = {
                        "ti": perm_labels[ti_idx], "to": perm_labels[to_idx],
                        "sub": f"{vname}/{aname}", "key": kw,
                        "crib_score": total,
                        "east_hits": east_hits, "bcl_hits": bcl_hits,
                        "self_encrypting_preserved": se_ok,
                    }
                    cf_outer.write(json.dumps(rec) + "\n")
                    counters["tier1_stored"] += 1

                    if east_hits >= 8 or bcl_hits >= 6:
                        cf_tier2.write(json.dumps(rec) + "\n")
                        counters["tier2_logged"] += 1
                        if total >= 18 and east_hits >= 9 and bcl_hits >= 7:
                            cf_tier3.write(json.dumps({**rec, "pt": pt}) + "\n")
                            counters["tier3_pre_kernel_pass"] += 1

            # Heartbeat
            now = time.time()
            if now - last_report >= 20.0:
                progress = (ti_idx + 1) * 180 * n_perms
                rate = progress / (now - t0)
                eta = (expected_total - progress) / max(rate, 1)
                print(f"  [{int(now-t0):>4}s] outer T_inner {ti_idx+1}/{n_perms} "
                      f"({progress:,} / {expected_total:,} configs, ~{rate/1000:.0f}K/s, "
                      f"ETA {int(eta)}s) "
                      f"tier1={counters['tier1_stored']} tier2={counters['tier2_logged']} "
                      f"tier3={counters['tier3_pre_kernel_pass']} "
                      f"best_score={bests['best_crib_score'][0]}")
                last_report = now
    finally:
        cf_outer.close()
        cf_tier2.close()
        cf_tier3.close()

    dt = time.time() - t0
    print(f"  elapsed: {dt:.2f}s ({counters['evaluated']:,} configs, "
          f"{counters['evaluated']/dt/1000:.1f}K/s)")

    # Kernel-side verification of Tier 3 candidates (if any)
    tier3_pass_after_kernel = []
    if counters["tier3_pre_kernel_pass"] > 0:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(ROOT)), "src"))
        try:
            from kryptos.kernel.scoring.aggregate import score_candidate
            with open(tier3_path) as f:
                for line in f:
                    rec = json.loads(line)
                    pt = rec["pt"]
                    s = score_candidate(pt)
                    bean_passed = bool(s.get("bean_passed"))
                    ngram_per_char = (s.get("ngram_score", 0.0) or 0.0) / max(1, len(pt))
                    if bean_passed and ngram_per_char >= -5.5:
                        tier3_pass_after_kernel.append({**rec, "kernel_score": s,
                                                        "ngram_per_char": ngram_per_char})
        except Exception as e:
            print(f"  WARNING: kernel verification step errored: {e}")
    counters["tier3_post_kernel_pass"] = len(tier3_pass_after_kernel)

    summary = {
        "experiment": "e04_h2",
        "universe_hash": universe_hash,
        "expected_total": expected_total,
        "elapsed_sec": round(dt, 3),
        "counters": counters,
        "bests": bests,
        "tier3_post_kernel_pass": tier3_pass_after_kernel,
    }
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2, default=str)

    print()
    print(f"  evaluated: {counters['evaluated']:,}")
    print(f"  tier1 stored (crib_score >= 10): {counters['tier1_stored']}")
    print(f"  tier2 logged: {counters['tier2_logged']}")
    print(f"  tier3 pre-kernel: {counters['tier3_pre_kernel_pass']}")
    print(f"  tier3 post-kernel verification: {counters['tier3_post_kernel_pass']}")
    print(f"  best crib_score: {bests['best_crib_score']}")
    print(f"  best EAST holdout: {bests['best_east_holdout']}")
    print(f"  best BCL holdout:  {bests['best_bcl_holdout']}")
    print(f"  best combined: {bests['best_combined_holdout']}")


if __name__ == "__main__":
    main()
