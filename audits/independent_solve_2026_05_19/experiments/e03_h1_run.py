"""E03 H1 — Non-columnar middle-layer 3-stack sweep.

Pre-registered design: experiments/e03_h1_design.md.
Universe locked at run start; SHA-256 of normalized universe printed.

Two encryption models:
  A: PT -> TRANS -> SUB -> CT   (decrypt: CT -> SUB^-1 -> TRANS^-1 -> PT)
  B: PT -> SUB   -> TRANS -> CT (decrypt: CT -> TRANS^-1 -> SUB^-1 -> PT)

Where TRANS in {Myszkowski(kw, w), Rail_Fence(d), Route_Spiral(r,c,dir)}
and SUB in {(Vig|Beau|VarBeau) over {AZ|KA} with one of 30 keywords}.
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
    route_spiral_perm, route_serpentine_perm,  # noqa: F401 (serpentine reserved for v2)
)
from independent_solve_2026_05_19.src.scoring import crib_score, holdout_predictions


CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = 97

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


def expand_keyword(kw: str, w: int) -> str:
    """Return a width-w keyword by truncation or cycling."""
    if len(kw) >= w:
        return kw[:w]
    return (kw * (w // len(kw) + 1))[:w]


def build_middle_perms():
    """Return [(label, perm), ...] for all 312 middle transpositions."""
    out = []
    # Myszkowski: 30 keywords × 9 widths = 270
    for kw in KEYWORD_POOL_K4:
        for w in MYSZ_WIDTHS:
            k = expand_keyword(kw, w)
            try:
                perm = myszkowski_perm(k, N)
            except Exception as e:
                raise RuntimeError(f"myszkowski {kw}@{w}: {e}")
            out.append((f"mysz|{kw}|w{w}", perm))
    # Rail-fence depth 2-15 = 14
    for d in RAIL_DEPTHS:
        out.append((f"rail|d{d}", rail_fence_perm(d, N)))
    # Route-spiral 7 rects × 4 dirs = 28
    for (rows, cols) in SPIRAL_RECTS:
        for d in SPIRAL_DIRS:
            out.append((f"spir|{rows}x{cols}|{d}", route_spiral_perm(rows, cols, N, d)))
    return out


def compute_universe_hash():
    """SHA-256 of the locked universe descriptor."""
    descriptor = {
        "models": ["A_TRANS_then_SUB", "B_SUB_then_TRANS"],
        "variants": [v for v, _ in SUB_VARIANTS],
        "alphabets": [a for a, _ in SUB_ALPHAS],
        "keyword_pool": sorted(KEYWORD_POOL_K4),
        "mysz_widths": sorted(MYSZ_WIDTHS),
        "rail_depths": sorted(RAIL_DEPTHS),
        "spiral_rects": sorted(SPIRAL_RECTS),
        "spiral_dirs": sorted(SPIRAL_DIRS),
    }
    data = json.dumps(descriptor, sort_keys=True).encode()
    return hashlib.sha256(data).hexdigest()


def evaluate_pt(pt: str) -> dict:
    """Score a decrypted plaintext against cribs and holdout structure."""
    hits_full, total_full, _ = crib_score(pt, withheld_crib_index=-1)
    holdout_east = holdout_predictions(pt, withheld_crib_index=0)
    holdout_bcl  = holdout_predictions(pt, withheld_crib_index=1)
    self_enc_ok = (pt[32].upper() == "S") and (pt[73].upper() == "K")
    return {
        "crib_score": hits_full,
        "holdout_east_hits": holdout_east["hits"],
        "holdout_east_predicted": holdout_east["predicted"],
        "holdout_bcl_hits": holdout_bcl["hits"],
        "holdout_bcl_predicted": holdout_bcl["predicted"],
        "self_encrypting_preserved": self_enc_ok,
    }


def main():
    universe_hash = compute_universe_hash()
    print(f"E03 H1 sweep")
    print(f"  universe SHA-256: {universe_hash}")
    middle_perms = build_middle_perms()
    n_middle = len(middle_perms)
    n_configs = 2 * 3 * 2 * len(KEYWORD_POOL_K4) * n_middle
    print(f"  middle transposition configs: {n_middle} ({270 + 14 + 28} expected)")
    print(f"  total configs (both models): {n_configs}")
    assert n_middle == 312, f"middle count {n_middle} != 312"
    assert n_configs == 112320, f"total {n_configs} != 112320"

    # Pre-compute inverse middle perms once
    middle_inv = [(lbl, perm, invert_perm(perm)) for (lbl, perm) in middle_perms]

    # Tiered output streams
    candidates_path = os.path.join(ROOT, "results", "candidates.jsonl")
    tier2_path = os.path.join(ROOT, "results", "e03_h1_tier2.jsonl")
    tier3_path = os.path.join(ROOT, "results", "e03_h1_tier3.jsonl")
    summary_path = os.path.join(ROOT, "results", "e03_h1_summary.json")
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

    t0 = time.time()

    for model in ("A", "B"):
        for vname, sub_dec in SUB_VARIANTS:
            for aname, alpha in SUB_ALPHAS:
                for kw in KEYWORD_POOL_K4:
                    if model == "A":
                        # CT -> SUB^-1 -> intermediate (length N) -> TRANS^-1 -> PT
                        intermediate = sub_dec(CT, kw, alpha)
                        for (tlbl, _, tinv) in middle_inv:
                            pt = apply_perm(intermediate, tinv)
                            ev = evaluate_pt(pt)
                            counters["evaluated"] += 1
                            update_bests(bests, ev, model, vname, aname, kw, tlbl)
                            process_tiers(ev, model, vname, aname, kw, tlbl, pt,
                                          counters, candidates_path, tier2_path, tier3_path)
                    else:  # model B
                        # CT -> TRANS^-1 -> intermediate -> SUB^-1 -> PT
                        for (tlbl, _, tinv) in middle_inv:
                            intermediate = apply_perm(CT, tinv)
                            pt = sub_dec(intermediate, kw, alpha)
                            ev = evaluate_pt(pt)
                            counters["evaluated"] += 1
                            update_bests(bests, ev, model, vname, aname, kw, tlbl)
                            process_tiers(ev, model, vname, aname, kw, tlbl, pt,
                                          counters, candidates_path, tier2_path, tier3_path)

    dt = time.time() - t0

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
        "universe_hash": universe_hash,
        "elapsed_sec": round(dt, 3),
        "counters": counters,
        "bests": bests,
        "tier3_post_kernel_pass": tier3_pass_after_kernel,
    }
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2, default=str)

    print(f"  elapsed: {dt:.2f}s")
    print(f"  evaluated: {counters['evaluated']}")
    print(f"  tier1 stored (crib_score >= 10): {counters['tier1_stored']}")
    print(f"  tier2 logged: {counters['tier2_logged']}")
    print(f"  tier3 pre-kernel: {counters['tier3_pre_kernel_pass']}")
    print(f"  tier3 post-kernel verification: {counters['tier3_post_kernel_pass']}")
    print(f"  best crib_score: {bests['best_crib_score']}")
    print(f"  best EAST holdout: {bests['best_east_holdout']}")
    print(f"  best BCL holdout:  {bests['best_bcl_holdout']}")
    print(f"  best combined holdout: {bests['best_combined_holdout']}")


def update_bests(bests, ev, model, vname, aname, kw, tlbl):
    record = {"model": model, "sub": f"{vname}/{aname}", "key": kw, "middle": tlbl, "ev": ev}
    if ev["crib_score"] > bests["best_crib_score"][0]:
        bests["best_crib_score"] = (ev["crib_score"], record)
    combined = ev["holdout_east_hits"] + ev["holdout_bcl_hits"]
    if combined > bests["best_combined_holdout"][0]:
        bests["best_combined_holdout"] = (combined, record)
    if ev["holdout_east_hits"] > bests["best_east_holdout"][0]:
        bests["best_east_holdout"] = (ev["holdout_east_hits"], record)
    if ev["holdout_bcl_hits"] > bests["best_bcl_holdout"][0]:
        bests["best_bcl_holdout"] = (ev["holdout_bcl_hits"], record)


def process_tiers(ev, model, vname, aname, kw, tlbl, pt, counters,
                  cand_path, t2_path, t3_path):
    rec_base = {
        "model": model, "sub": f"{vname}/{aname}", "key": kw, "middle": tlbl,
        "crib_score": ev["crib_score"],
        "holdout_east_hits": ev["holdout_east_hits"],
        "holdout_east_predicted": ev["holdout_east_predicted"],
        "holdout_bcl_hits": ev["holdout_bcl_hits"],
        "holdout_bcl_predicted": ev["holdout_bcl_predicted"],
        "self_encrypting_preserved": ev["self_encrypting_preserved"],
    }
    if ev["crib_score"] >= 10:
        with open(cand_path, "a") as f:
            f.write(json.dumps(rec_base) + "\n")
        counters["tier1_stored"] += 1
        if (ev["crib_score"] >= 10) and (
            ev["holdout_east_hits"] >= 8 or ev["holdout_bcl_hits"] >= 6
        ):
            with open(t2_path, "a") as f:
                f.write(json.dumps(rec_base) + "\n")
            counters["tier2_logged"] += 1
            if (ev["crib_score"] >= 18
                and ev["holdout_east_hits"] >= 9
                and ev["holdout_bcl_hits"] >= 7):
                with open(t3_path, "a") as f:
                    f.write(json.dumps({**rec_base, "pt": pt}) + "\n")
                counters["tier3_pre_kernel_pass"] += 1


if __name__ == "__main__":
    main()
