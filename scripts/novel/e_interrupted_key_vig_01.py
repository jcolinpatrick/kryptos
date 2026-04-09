"""
Cipher: Interrupted-key Vigenere
Family: novel
Status: exhausted
Keyspace: ~8 keywords x 5 models x variants = ~120+ configs per model
Last run:
Best score:
"""
import sys, os, json, time, itertools
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CRIB_DICT, ALPH, ALPH_IDX, MOD
from kryptos.kernel.scoring.aggregate import score_candidate

# ── Constants ────────────────────────────────────────────────────────────────

CT_NUMS = [ALPH_IDX[c] for c in CT]
CT_LEN = len(CT)

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "SHADOW", "BERLIN", "SCHEIDT", "SANBORN"]

# Common K4 letters for subset model
SUBSET_LETTERS = frozenset(ALPH_IDX[c] for c in "WZKB")

REPORT_THRESHOLD = 10
RESULTS = []

ALL_MODELS = [
    "skip_on_match",
    "skip_on_subset",
    "stall_on_match",
    "modular_skip_2",
    "modular_skip_3",
    "modular_skip_4",
    "modular_skip_5",
    "conditional_reverse",
]
ALL_VARIANTS = ["vigenere", "beaufort", "vbeau"]

# ── Interrupted-key decryption engine ────────────────────────────────────────

def decrypt_interrupted(ct_nums, key_nums, model, variant="vigenere"):
    """Decrypt with an interrupted-key Vigenere.

    The key pointer advances based on data-dependent rules.

    Models:
      skip_on_match:       key advances +2 when CT[i] == key_letter, else +1
      skip_on_subset:      key advances +2 when CT[i] in {W,Z,K,B}, else +1
      stall_on_match:      key does NOT advance when CT[i] == key_letter
      modular_skip_N:      key advances by (CT_val mod N + 1)
      conditional_reverse: key goes backward (-1) when CT value > 12, else +1
    """
    n = len(ct_nums)
    key_len = len(key_nums)
    if key_len == 0:
        return None

    pt_nums = [0] * n
    key_ptr = 0

    for i in range(n):
        k = key_nums[key_ptr % key_len]

        if variant == "vigenere":
            pt_nums[i] = (ct_nums[i] - k) % MOD
        elif variant == "beaufort":
            pt_nums[i] = (k - ct_nums[i]) % MOD
        elif variant == "vbeau":
            pt_nums[i] = (ct_nums[i] + k) % MOD

        if model == "skip_on_match":
            key_ptr += 2 if ct_nums[i] == k else 1
        elif model == "skip_on_subset":
            key_ptr += 2 if ct_nums[i] in SUBSET_LETTERS else 1
        elif model == "stall_on_match":
            if ct_nums[i] != k:
                key_ptr += 1
        elif model.startswith("modular_skip_"):
            step = int(model.split("_")[-1])
            key_ptr += (ct_nums[i] % step) + 1
        elif model == "conditional_reverse":
            if ct_nums[i] > 12:
                key_ptr -= 1
            else:
                key_ptr += 1
            if key_ptr < 0:
                key_ptr += key_len

    return pt_nums


def nums_to_text(nums):
    return "".join(ALPH[n % MOD] for n in nums)


def test_config(key_nums, key_label, model, variant):
    """Test a single config, return result dict if score >= threshold."""
    pt_nums = decrypt_interrupted(CT_NUMS, key_nums, model, variant)
    if pt_nums is None:
        return None

    pt_text = nums_to_text(pt_nums)
    result = score_candidate(pt_text)
    score = result.crib_score

    if score >= REPORT_THRESHOLD:
        return {
            "score": score,
            "plaintext": pt_text,
            "key": key_label,
            "model": model,
            "variant": variant,
            "bean_passed": result.bean_passed,
            "ic": result.ic_value,
            "classification": result.crib_classification,
        }
    return None


# ── Phase 1: Keyword sweep ──────────────────────────────────────────────────

def run_keyword_sweep():
    """Test all keyword + model + variant combinations."""
    tested = 0
    hits = 0
    total = len(KEYWORDS) * len(ALL_MODELS) * len(ALL_VARIANTS)
    print(f"\n=== Phase 1: Keyword sweep ({total} configs) ===")

    for keyword in KEYWORDS:
        key_nums = [ALPH_IDX[c] for c in keyword]
        for model in ALL_MODELS:
            for variant in ALL_VARIANTS:
                tested += 1
                r = test_config(key_nums, keyword, model, variant)
                if r is not None:
                    hits += 1
                    RESULTS.append(r)
                    print(f"  HIT: score={r['score']} model={model} var={variant} key={keyword} bean={r['bean_passed']}")

    print(f"Phase 1 done: {tested} tested, {hits} hits")
    return tested


# ── Phase 2: Exhaustive short keys (lengths 1-4) ────────────────────────────

def run_exhaustive_short_keys():
    """Exhaustive sweep of key lengths 1-4 (26^1 + 26^2 + 26^3 + 26^4 = 475,254 keys)."""
    tested = 0
    hits = 0

    for key_len in range(1, 5):
        space = 26 ** key_len
        configs = space * len(ALL_MODELS) * len(ALL_VARIANTS)
        print(f"\n=== Phase 2.{key_len}: Exhaustive len={key_len} ({space} keys, {configs} configs) ===")
        phase_tested = 0

        for key_tuple in itertools.product(range(26), repeat=key_len):
            key_nums = list(key_tuple)
            key_label = nums_to_text(key_nums)
            for model in ALL_MODELS:
                for variant in ALL_VARIANTS:
                    tested += 1
                    phase_tested += 1
                    r = test_config(key_nums, key_label, model, variant)
                    if r is not None:
                        hits += 1
                        RESULTS.append(r)
                        print(f"  HIT: score={r['score']} model={model} var={variant} key={key_label} bean={r['bean_passed']}")

            # Progress every 5000 keys
            if key_len >= 3 and phase_tested % (5000 * len(ALL_MODELS) * len(ALL_VARIANTS)) == 0:
                print(f"    ... {phase_tested // (len(ALL_MODELS) * len(ALL_VARIANTS))}/{space} keys done")

        print(f"  Len {key_len} done: {phase_tested} configs, {hits} total hits so far")

    print(f"Phase 2 done: {tested} tested, {hits} hits")
    return tested


# ── Phase 3: Reduced-alphabet keys (lengths 5-6) ────────────────────────────

def run_reduced_alphabet_keys():
    """Keys of length 5-6 drawn from KRYPTOS letters (7^5 + 7^6 = 134,456 keys)."""
    reduced = [ALPH_IDX[c] for c in "KRYPTOS"]  # 7 distinct values
    tested = 0
    hits = 0

    for key_len in range(5, 7):
        space = 7 ** key_len
        configs = space * len(ALL_MODELS) * len(ALL_VARIANTS)
        print(f"\n=== Phase 3.{key_len}: Reduced alphabet len={key_len} ({space} keys, {configs} configs) ===")
        phase_tested = 0

        for key_tuple in itertools.product(reduced, repeat=key_len):
            key_nums = list(key_tuple)
            key_label = nums_to_text(key_nums) + f"(r{key_len})"
            for model in ALL_MODELS:
                for variant in ALL_VARIANTS:
                    tested += 1
                    phase_tested += 1
                    r = test_config(key_nums, key_label, model, variant)
                    if r is not None:
                        hits += 1
                        RESULTS.append(r)
                        print(f"  HIT: score={r['score']} model={model} var={variant} key={key_label} bean={r['bean_passed']}")

            if phase_tested % (2000 * len(ALL_MODELS) * len(ALL_VARIANTS)) == 0:
                print(f"    ... {phase_tested // (len(ALL_MODELS) * len(ALL_VARIANTS))}/{space} keys done")

        print(f"  Len {key_len} done: {phase_tested} configs, {hits} total hits so far")

    print(f"Phase 3 done: {tested} tested, {hits} hits")
    return tested


# ── Phase 4: Arithmetic progression keys (lengths 5-8) ──────────────────────

def run_ap_keys():
    """Arithmetic progression keys: key[i] = (start + i*step) mod 26, lengths 5-8.
    26 starts * 25 steps * 4 lengths = 2600 keys."""
    tested = 0
    hits = 0
    total_keys = 26 * 25 * 4
    print(f"\n=== Phase 4: AP keys lengths 5-8 ({total_keys} keys) ===")

    for key_len in range(5, 9):
        for start in range(26):
            for step in range(1, 26):
                key_nums = [(start + i * step) % 26 for i in range(key_len)]
                key_label = nums_to_text(key_nums) + f"(AP s={start} d={step})"
                for model in ALL_MODELS:
                    for variant in ALL_VARIANTS:
                        tested += 1
                        r = test_config(key_nums, key_label, model, variant)
                        if r is not None:
                            hits += 1
                            RESULTS.append(r)
                            print(f"  HIT: score={r['score']} model={model} var={variant} key={key_label} bean={r['bean_passed']}")

    print(f"Phase 4 done: {tested} tested, {hits} hits")
    return tested


# ── Phase 5: Extended keywords with offsets ──────────────────────────────────

def run_keyword_offsets():
    """Test keywords with Caesar offsets (shift each letter by 0-25)."""
    tested = 0
    hits = 0
    total = len(KEYWORDS) * 26 * len(ALL_MODELS) * len(ALL_VARIANTS)
    print(f"\n=== Phase 5: Keywords + Caesar offsets ({total} configs) ===")

    for keyword in KEYWORDS:
        base_nums = [ALPH_IDX[c] for c in keyword]
        for offset in range(26):
            key_nums = [(v + offset) % 26 for v in base_nums]
            key_label = f"{keyword}+{offset}"
            for model in ALL_MODELS:
                for variant in ALL_VARIANTS:
                    tested += 1
                    r = test_config(key_nums, key_label, model, variant)
                    if r is not None:
                        hits += 1
                        RESULTS.append(r)
                        print(f"  HIT: score={r['score']} model={model} var={variant} key={key_label} bean={r['bean_passed']}")

    print(f"Phase 5 done: {tested} tested, {hits} hits")
    return tested


# ── Save results ─────────────────────────────────────────────────────────────

def save_results(total_tested, elapsed):
    output = {
        "attack": "interrupted_key_vigenere",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ciphertext": CT,
        "total_tested": total_tested,
        "elapsed_seconds": round(elapsed, 2),
        "threshold": REPORT_THRESHOLD,
        "models_tested": ALL_MODELS,
        "variants_tested": ALL_VARIANTS,
        "keywords_tested": KEYWORDS,
        "phases": [
            "keyword_sweep (8 keywords)",
            "exhaustive_short_keys (len 1-4, 475K keys)",
            "reduced_alphabet (len 5-6, KRYPTOS letters, 134K keys)",
            "arithmetic_progression (len 5-8, 2600 keys)",
            "keyword_offsets (8 keywords x 26 offsets)"
        ],
        "hits": sorted(RESULTS, key=lambda x: -x["score"]),
        "hit_count": len(RESULTS),
        "conclusion": "PROMISING" if any(r["score"] >= 18 for r in RESULTS)
                      else "INTERESTING" if RESULTS
                      else "NOISE"
    }

    out_path = os.path.join(_ROOT, "results", "interrupted_key_vig_20260324.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")
    return out_path


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 72)
    print("INTERRUPTED-KEY VIGENERE ATTACK")
    print(f"CT: {CT[:50]}... ({len(CT)} chars)")
    print(f"Cribs: pos 21-33 = EASTNORTHEAST, pos 63-73 = BERLINCLOCK")
    print(f"Score threshold: {REPORT_THRESHOLD}")
    print("=" * 72)

    t0 = time.time()
    total = 0
    total += run_keyword_sweep()
    total += run_exhaustive_short_keys()
    total += run_reduced_alphabet_keys()
    total += run_ap_keys()
    total += run_keyword_offsets()
    elapsed = time.time() - t0

    print("\n" + "=" * 72)
    print(f"FINAL SUMMARY: {total:,} configurations tested in {elapsed:.1f}s")
    print(f"Hits (score >= {REPORT_THRESHOLD}): {len(RESULTS)}")

    if RESULTS:
        print("\nTop results:")
        for r in sorted(RESULTS, key=lambda x: -x["score"])[:25]:
            print(f"  score={r['score']:2d} bean={str(r['bean_passed']):5s} model={r['model']:20s} var={r['variant']:8s} key={r['key']}")
            print(f"         PT: {r['plaintext'][:60]}")
    else:
        print("\nNo configurations scored >= 10. All models produce NOISE.")

    save_results(total, elapsed)
    print("=" * 72)


if __name__ == "__main__":
    main()
