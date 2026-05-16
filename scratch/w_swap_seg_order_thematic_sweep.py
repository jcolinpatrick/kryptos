"""W-anchored swap + thematic keyword sweep against K4.

Variants tested:
  NONE                — baseline (no swap)
  SEG_ORDER_IMAGE     — W-as-separator content reversal (matches user's image SWAP 2)
                        Construction: segments = K4 split on W (W's removed),
                        reverse list, join with W. Central W stays at pos 48.
  SEG_ORDER_W_LED     — W-led segments reversed (alternative construction)
  FULL_REV            — full string reversal (= SWAP 1 in user's image)
  REFL_W58            — partial reflection around W at position 58 (had a
                        weak VARBEAU keyword-fragment hit at the spot-check)

For each variant, sweep:
  - 3 cipher variants (Vigenère, Beaufort, Variant Beaufort)
  - 2 alphabets (standard A-Z, KRYPTOS-mixed KA)
  - All keywords in wordlists/thematic_keywords_v2.txt (~881)

Total configurations: ~5 × 3 × 2 × 881 ≈ 26k. Runs in seconds on 28 cores.
"""

from __future__ import annotations
import sys
import os
import json
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT,
    STORE_THRESHOLD,
    SIGNAL_THRESHOLD,
    BREAKTHROUGH_THRESHOLD,
)
from kryptos.kernel.alphabet import AZ, KA
from kryptos.kernel.transforms.vigenere import decrypt_text, CipherVariant
from kryptos.kernel.scoring.aggregate import score_candidate

W_POSITIONS = [20, 36, 48, 58, 74]


def _split_w_led(ct: str) -> list[str]:
    """Each segment includes its leading W (except the first, which has none)."""
    segs = []
    last = 0
    for p in W_POSITIONS:
        segs.append(ct[last:p])
        last = p
    segs.append(ct[last:])
    return segs


def _split_w_free(ct: str) -> list[str]:
    """Segments are content between W's (W's excluded)."""
    contents = []
    last = 0
    for p in W_POSITIONS:
        contents.append(ct[last:p])
        last = p + 1
    contents.append(ct[last:])
    return contents


def swap_none(ct: str) -> str:
    return ct


def swap_full_reverse(ct: str) -> str:
    return ct[::-1]


def swap_seg_order_image(ct: str) -> str:
    """W-as-separator content reversal. Matches user's SWAP 2 image."""
    contents = _split_w_free(ct)
    return "W".join(reversed(contents))


def swap_seg_order_w_led(ct: str) -> str:
    """W-led segments reversed (alternate construction)."""
    segs = _split_w_led(ct)
    return "".join(reversed(segs))


def swap_refl_around(ct: str, pivot: int) -> str:
    n = len(ct)
    out = list(ct)
    for i in range(n):
        j = 2 * pivot - i
        if 0 <= j < n:
            out[i] = ct[j]
    return "".join(out)


VARIANTS_SWAP = [
    ("NONE",            swap_none(CT)),
    ("SEG_ORDER_IMAGE", swap_seg_order_image(CT)),
    ("SEG_ORDER_W_LED", swap_seg_order_w_led(CT)),
    ("FULL_REV",        swap_full_reverse(CT)),
    ("REFL_W58",        swap_refl_around(CT, 58)),
]

CIPHERS = [
    ("VIG",     CipherVariant.VIGENERE),
    ("BEAU",    CipherVariant.BEAUFORT),
    ("VARBEAU", CipherVariant.VAR_BEAUFORT),
]
ALPHABETS = [
    ("AZ", AZ),
    ("KA", KA),
]


def load_keywords(path: str) -> list[str]:
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            kw = "".join(c for c in line.upper() if c.isalpha())
            if 3 <= len(kw) <= 30:
                out.append(kw)
    seen = set()
    deduped = []
    for kw in out:
        if kw not in seen:
            seen.add(kw)
            deduped.append(kw)
    return deduped


def score_one(args):
    swap_name, ct_swapped, keyword, cipher_name, cipher_enum, alpha_name, alpha = args
    try:
        key_ints = [alpha.char_to_idx(c) for c in keyword]
    except (KeyError, ValueError):
        return None
    pt = decrypt_text(ct_swapped, key_ints, cipher_enum, alphabet=alpha)
    sc = score_candidate(pt)
    return (
        sc.crib_score,
        sc.crib_classification,
        swap_name,
        keyword,
        cipher_name,
        alpha_name,
        pt,
    )


def main():
    kws_path = os.path.join(_ROOT, "wordlists", "thematic_keywords_v2.txt")
    keywords = load_keywords(kws_path)

    print(f"Carved K4: {CT}")
    print(f"Keywords:  {len(keywords)} from {os.path.relpath(kws_path)}")
    print(f"Variants:  {[v[0] for v in VARIANTS_SWAP]}")
    print(f"Ciphers:   {[c[0] for c in CIPHERS]}")
    print(f"Alphabets: {[a[0] for a in ALPHABETS]}")
    total = len(VARIANTS_SWAP) * len(CIPHERS) * len(ALPHABETS) * len(keywords)
    print(f"Total configurations: {total}")
    print(f"Thresholds: STORE>={STORE_THRESHOLD}, SIGNAL>={SIGNAL_THRESHOLD}, BREAKTHROUGH>={BREAKTHROUGH_THRESHOLD}")
    print()

    work = []
    for swap_name, ct_swapped in VARIANTS_SWAP:
        for cname, cenum in CIPHERS:
            for aname, alpha in ALPHABETS:
                for kw in keywords:
                    work.append((swap_name, ct_swapped, kw, cname, cenum, aname, alpha))

    workers = max(1, cpu_count() - 2)
    print(f"Running on {workers} workers ...", flush=True)
    t0 = time.time()

    results = []
    completed = 0
    last_print = t0
    with ProcessPoolExecutor(max_workers=workers) as ex:
        for fut in as_completed(ex.submit(score_one, w) for w in work):
            r = fut.result()
            completed += 1
            if r is not None:
                results.append(r)
            now = time.time()
            if now - last_print > 5 or completed == total:
                rate = completed / (now - t0) if now > t0 else 0
                best_so_far = max((x[0] for x in results), default=0)
                print(f"  {completed:6d} / {total:6d}  ({rate:.0f}/s)  best_crib={best_so_far}", flush=True)
                last_print = now

    elapsed = time.time() - t0
    print(f"\nDone in {elapsed:.1f}s. Scored {len(results)} configurations.\n")

    results.sort(key=lambda x: (-x[0], -len(x[3])))

    # Top 30 overall
    print("=" * 110)
    print("TOP 30 BY CRIB SCORE")
    print("=" * 110)
    print(f"{'crib':>4} {'class':>14} {'swap':<18} {'keyword':<18} {'cipher':<8} {'alpha':<4} pt[:50]")
    print("-" * 110)
    for r in results[:30]:
        score, cls, swap_name, kw, cname, aname, pt = r
        print(f"{score:>4} {cls:>14} {swap_name:<18} {kw:<18} {cname:<8} {aname:<4} {pt[:50]}")

    # Per-variant best
    print(f"\n{'=' * 110}")
    print("BEST PER (swap × cipher × alphabet) CELL")
    print("=" * 110)
    cells = {}
    for r in results:
        score, cls, swap_name, kw, cname, aname, pt = r
        key = (swap_name, cname, aname)
        if key not in cells or cells[key][0] < score:
            cells[key] = r
    print(f"{'swap':<18} {'cipher':<8} {'alpha':<4} {'crib':>4} {'keyword':<18} pt[:50]")
    print("-" * 110)
    for (sname, cname, aname), r in sorted(cells.items()):
        score, cls, _, kw, _, _, pt = r
        print(f"{sname:<18} {cname:<8} {aname:<4} {score:>4} {kw:<18} {pt[:50]}")

    # STORE-or-better
    store_or_better = [r for r in results if r[0] >= STORE_THRESHOLD]
    print(f"\n{'=' * 110}")
    print(f"CONFIGURATIONS AT crib_score >= {STORE_THRESHOLD} ({len(store_or_better)} total)")
    print("=" * 110)
    for r in store_or_better:
        score, cls, swap_name, kw, cname, aname, pt = r
        print(f"  [{score:2d}/{cls}]  {swap_name} kw={kw} {cname}/{aname}")
        print(f"    PT: {pt}")

    # Persist artifact (deterministic reproduction)
    artifact_dir = os.path.join(_ROOT, "results", "w_anchor_reversal_v1")
    os.makedirs(artifact_dir, exist_ok=True)
    artifact_path = os.path.join(artifact_dir, "sweep_results.json")
    artifact = {
        "schema": "w_anchor_swap_thematic_sweep.v1",
        "run_date": time.strftime("%Y-%m-%d"),
        "ct_carved": CT,
        "swap_variants": [{"name": n, "swapped": s} for n, s in VARIANTS_SWAP],
        "ciphers": [c[0] for c in CIPHERS],
        "alphabets": [a[0] for a in ALPHABETS],
        "keyword_source": os.path.relpath(kws_path, _ROOT),
        "keyword_count": len(keywords),
        "configurations_total": total,
        "configurations_scored": len(results),
        "thresholds": {
            "STORE": STORE_THRESHOLD,
            "SIGNAL": SIGNAL_THRESHOLD,
            "BREAKTHROUGH": BREAKTHROUGH_THRESHOLD,
        },
        "elapsed_seconds": round(elapsed, 2),
        "best_per_cell": [
            {
                "swap": k[0], "cipher": k[1], "alphabet": k[2],
                "crib_score": v[0], "classification": v[1],
                "keyword": v[3], "plaintext": v[6],
            }
            for k, v in sorted(cells.items())
        ],
        "store_or_better": [
            {
                "crib_score": r[0], "classification": r[1],
                "swap": r[2], "keyword": r[3], "cipher": r[4],
                "alphabet": r[5], "plaintext": r[6],
            }
            for r in store_or_better
        ],
        "best_overall": (
            {
                "crib_score": results[0][0], "classification": results[0][1],
                "swap": results[0][2], "keyword": results[0][3],
                "cipher": results[0][4], "alphabet": results[0][5],
                "plaintext": results[0][6],
            }
            if results else None
        ),
    }
    with open(artifact_path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\nArtifact saved: {os.path.relpath(artifact_path, _ROOT)}")

    # Verdict
    signal_or_better = [r for r in results if r[0] >= SIGNAL_THRESHOLD]
    print(f"\n{'=' * 110}")
    if signal_or_better:
        print(f"!!! SIGNAL: {len(signal_or_better)} configuration(s) at crib_score >= {SIGNAL_THRESHOLD}")
        for r in signal_or_better[:10]:
            score, cls, swap_name, kw, cname, aname, pt = r
            print(f"  [{score:2d}]  {swap_name} kw={kw} {cname}/{aname}")
            print(f"      PT: {pt}")
    else:
        print(f"No configuration reached SIGNAL threshold ({SIGNAL_THRESHOLD}/24).")
        if results:
            best = results[0]
            print(f"Best overall: crib_score {best[0]}/24")
            print(f"  swap={best[2]} keyword={best[3]} cipher={best[4]} alphabet={best[5]}")
            print(f"  PT: {best[6]}")
    print("=" * 110)


if __name__ == "__main__":
    main()
