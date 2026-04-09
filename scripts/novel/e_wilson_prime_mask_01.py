"""
Cipher: Wilson prime masking stream
Family: novel
Status: exhausted
Keyspace: 562 offsets x 3 variants x 6 models = ~10K configs
Last run:
Best score:
"""
import sys, os, json, time
from datetime import datetime, timezone
from decimal import Decimal, getcontext

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CRIB_DICT
from kryptos.kernel.scoring.aggregate import score_candidate

# ── Constants ────────────────────────────────────────────────────────────────

CT_NUMS = [ord(c) - ord('A') for c in CT]
CT_LEN = len(CT)

# Wilson primes: p where (p-1)! = -1 (mod p^2)
WILSON_PRIMES = [5, 13, 563]


# ── Decimal expansion via long division ──────────────────────────────────────

def repeating_decimal_digits(p, max_digits=2000):
    """Compute decimal digits of 1/p using long division.
    Returns the repeating block (list of ints 0-9)."""
    digits = []
    seen = {}
    remainder = 1
    # Skip the "0." part
    for i in range(max_digits):
        remainder *= 10
        digit = remainder // p
        remainder = remainder % p
        if remainder in seen:
            start = seen[remainder]
            return digits[start:]  # repeating block only
        seen[remainder] = i
        digits.append(digit)
        if remainder == 0:
            return digits  # terminates (e.g. 1/5)
    return digits  # fallback


def binary_expansion_bits(p, num_bits=2000):
    """Compute binary digits of 1/p using long division in base 2."""
    bits = []
    seen = {}
    remainder = 1
    for i in range(num_bits):
        remainder *= 2
        bit = remainder // p
        remainder = remainder % p
        if remainder in seen:
            start = seen[remainder]
            return bits[start:]
        seen[remainder] = i
        bits.append(bit)
        if remainder == 0:
            return bits
    return bits


# ── Keystream generation models ──────────────────────────────────────────────

def model_single_digits(digits, offset, length):
    """Model 1: single digits mod 26."""
    n = len(digits)
    return [digits[(offset + i) % n] % 26 for i in range(length)]


def model_digit_pairs(digits, offset, length):
    """Model 4: pairs of consecutive digits -> two-digit number mod 26."""
    n = len(digits)
    ks = []
    for i in range(length):
        idx = (offset + i * 2) % n
        idx2 = (offset + i * 2 + 1) % n
        val = digits[idx] * 10 + digits[idx2]
        ks.append(val % 26)
    return ks


def model_binary_groups(bits, offset, length):
    """Model 5: groups of 5 binary digits -> value mod 26."""
    n = len(bits)
    ks = []
    for i in range(length):
        val = 0
        for b in range(5):
            idx = (offset + i * 5 + b) % n
            val = val * 2 + bits[idx]
        ks.append(val % 26)
    return ks


# ── Decryption variants ─────────────────────────────────────────────────────

def decrypt_vigenere(ct_nums, key):
    return [(ct_nums[i] - key[i]) % 26 for i in range(len(ct_nums))]

def decrypt_beaufort(ct_nums, key):
    return [(key[i] - ct_nums[i]) % 26 for i in range(len(ct_nums))]

def decrypt_variant_beaufort(ct_nums, key):
    return [(ct_nums[i] + key[i]) % 26 for i in range(len(ct_nums))]


VARIANTS = [
    ("vigenere", decrypt_vigenere),
    ("beaufort", decrypt_beaufort),
    ("variant_beaufort", decrypt_variant_beaufort),
]


def nums_to_text(nums):
    return ''.join(chr(n + ord('A')) for n in nums)


# ── Scoring ──────────────────────────────────────────────────────────────────

def test_keystream(key, model_name, prime, offset, variant_name):
    """Test a keystream against all 3 cipher variants. Returns results with score >= 10."""
    results = []
    for vname, vfunc in VARIANTS:
        if variant_name and vname != variant_name:
            continue
        pt_nums = vfunc(CT_NUMS, key)
        pt = nums_to_text(pt_nums)
        breakdown = score_candidate(pt)
        score = breakdown.crib_score
        if score >= 10:
            results.append({
                "score": score,
                "plaintext": pt,
                "model": model_name,
                "prime": prime,
                "offset": offset,
                "variant": vname,
                "bean_passed": breakdown.bean_passed,
            })
    return results


# ── Main attack ──────────────────────────────────────────────────────────────

def run_attack():
    print("=" * 72)
    print("Wilson Prime 1/p Masking Stream Attack")
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Wilson primes: {WILSON_PRIMES}")
    print(f"Start: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 72)

    all_results = []
    total_configs = 0

    # Precompute decimal and binary expansions
    expansions = {}
    binary_expansions = {}
    for p in WILSON_PRIMES:
        digits = repeating_decimal_digits(p, max_digits=5000)
        expansions[p] = digits
        print(f"\n1/{p}: repeating block length = {len(digits)}, first 30 digits: {''.join(map(str, digits[:30]))}")

        bits = binary_expansion_bits(p, num_bits=5000)
        binary_expansions[p] = bits
        print(f"1/{p} binary: repeating block length = {len(bits)}, first 30 bits: {''.join(map(str, bits[:30]))}")

    # ── Model 1: Single digits mod 26 for each Wilson prime ──
    for p in WILSON_PRIMES:
        digits = expansions[p]
        period = len(digits)
        num_offsets = min(period, 1000)  # cap at 1000 for 1/5 which terminates
        print(f"\n--- Model 1: 1/{p} single digits mod 26, {num_offsets} offsets ---")
        for offset in range(num_offsets):
            key = model_single_digits(digits, offset, CT_LEN)
            for vname, vfunc in VARIANTS:
                total_configs += 1
                pt_nums = vfunc(CT_NUMS, key)
                pt = nums_to_text(pt_nums)
                breakdown = score_candidate(pt)
                if breakdown.crib_score >= 10:
                    r = {"score": breakdown.crib_score, "plaintext": pt,
                         "model": f"single_digits_1/{p}", "prime": p,
                         "offset": offset, "variant": vname,
                         "bean_passed": breakdown.bean_passed}
                    all_results.append(r)
                    print(f"  HIT: score={r['score']}, variant={vname}, offset={offset}, pt={pt[:40]}...")
        print(f"  Completed: {num_offsets * 3} configs")

    # ── Model 2: Digit pairs mod 26 ──
    for p in WILSON_PRIMES:
        digits = expansions[p]
        period = len(digits)
        num_offsets = min(period, 1000)
        print(f"\n--- Model 4: 1/{p} digit pairs mod 26, {num_offsets} offsets ---")
        for offset in range(num_offsets):
            key = model_digit_pairs(digits, offset, CT_LEN)
            for vname, vfunc in VARIANTS:
                total_configs += 1
                pt_nums = vfunc(CT_NUMS, key)
                pt = nums_to_text(pt_nums)
                breakdown = score_candidate(pt)
                if breakdown.crib_score >= 10:
                    r = {"score": breakdown.crib_score, "plaintext": pt,
                         "model": f"digit_pairs_1/{p}", "prime": p,
                         "offset": offset, "variant": vname,
                         "bean_passed": breakdown.bean_passed}
                    all_results.append(r)
                    print(f"  HIT: score={r['score']}, variant={vname}, offset={offset}, pt={pt[:40]}...")
        print(f"  Completed: {num_offsets * 3} configs")

    # ── Model 3: Binary groups of 5 bits mod 26 ──
    for p in WILSON_PRIMES:
        bits = binary_expansions[p]
        period = len(bits)
        num_offsets = min(period, 1000)
        print(f"\n--- Model 5: 1/{p} binary 5-bit groups mod 26, {num_offsets} offsets ---")
        for offset in range(num_offsets):
            key = model_binary_groups(bits, offset, CT_LEN)
            for vname, vfunc in VARIANTS:
                total_configs += 1
                pt_nums = vfunc(CT_NUMS, key)
                pt = nums_to_text(pt_nums)
                breakdown = score_candidate(pt)
                if breakdown.crib_score >= 10:
                    r = {"score": breakdown.crib_score, "plaintext": pt,
                         "model": f"binary_5bit_1/{p}", "prime": p,
                         "offset": offset, "variant": vname,
                         "bean_passed": breakdown.bean_passed}
                    all_results.append(r)
                    print(f"  HIT: score={r['score']}, variant={vname}, offset={offset}, pt={pt[:40]}...")
        print(f"  Completed: {num_offsets * 3} configs")

    # ── Model 6: Combined Wilson (interleave streams from 5, 13, 563) ──
    print(f"\n--- Model 6: Combined Wilson (interleave 1/5, 1/13, 1/563) ---")
    d5 = expansions[5]
    d13 = expansions[13]
    d563 = expansions[563]

    # 6a: Interleave: take digit from 5, then 13, then 563, cycling
    # 6b: Add digit streams mod 10 then mod 26
    # 6c: XOR-like: (d5 + d13 + d563) mod 26
    for offset in range(min(562, len(d563))):
        # 6a: Interleave
        key_interleave = []
        for i in range(CT_LEN):
            sources = [d5, d13, d563]
            src = sources[i % 3]
            key_interleave.append(src[(offset + i // 3) % len(src)] % 26)

        # 6b: Sum of streams mod 26
        key_sum = []
        for i in range(CT_LEN):
            v = (d5[(offset + i) % len(d5)] +
                 d13[(offset + i) % len(d13)] +
                 d563[(offset + i) % len(d563)]) % 26
            key_sum.append(v)

        for key, kname in [(key_interleave, "interleave"), (key_sum, "sum")]:
            for vname, vfunc in VARIANTS:
                total_configs += 1
                pt_nums = vfunc(CT_NUMS, key)
                pt = nums_to_text(pt_nums)
                breakdown = score_candidate(pt)
                if breakdown.crib_score >= 10:
                    r = {"score": breakdown.crib_score, "plaintext": pt,
                         "model": f"combined_{kname}", "prime": "5+13+563",
                         "offset": offset, "variant": vname,
                         "bean_passed": breakdown.bean_passed}
                    all_results.append(r)
                    print(f"  HIT: score={r['score']}, variant={vname}, model={kname}, offset={offset}, pt={pt[:40]}...")
    print(f"  Completed: {562 * 2 * 3} configs")

    # ── Summary ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print(f"TOTAL CONFIGS TESTED: {total_configs}")
    print(f"HITS (score >= 10): {len(all_results)}")
    if all_results:
        all_results.sort(key=lambda x: -x["score"])
        print("\nTop results:")
        for r in all_results[:20]:
            print(f"  score={r['score']:2d}  model={r['model']:30s}  variant={r['variant']:18s}  "
                  f"offset={r['offset']:4d}  bean={r['bean_passed']}  pt={r['plaintext'][:50]}...")
    else:
        print("No results scored >= 10. All configurations produce noise.")

    best_score = all_results[0]["score"] if all_results else 0
    print(f"\nBest score: {best_score}")
    print(f"End: {datetime.now(timezone.utc).isoformat()}")

    # ── Save results ─────────────────────────────────────────────────────────
    output = {
        "attack": "Wilson prime 1/p masking stream",
        "family": "novel",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ciphertext": CT,
        "models_tested": [
            "single_digits mod 26 (1/5, 1/13, 1/563)",
            "digit_pairs mod 26 (1/5, 1/13, 1/563)",
            "binary 5-bit groups mod 26 (1/5, 1/13, 1/563)",
            "combined interleave (5+13+563)",
            "combined sum (5+13+563)",
        ],
        "variants_tested": ["vigenere", "beaufort", "variant_beaufort"],
        "total_configs": total_configs,
        "hits_above_10": len(all_results),
        "best_score": best_score,
        "conclusion": "DISPROVED" if best_score < 10 else ("PROMISING" if best_score >= 18 else "INCONCLUSIVE"),
        "results": all_results[:50],
    }
    out_path = os.path.join(_ROOT, "results", f"wilson_prime_mask_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json")
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to: {out_path}")

    return output


if __name__ == "__main__":
    run_attack()
