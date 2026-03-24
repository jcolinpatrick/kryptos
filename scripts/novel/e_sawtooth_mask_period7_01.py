"""
Cipher: sawtooth mask + periodic polyalphabetic
Family: novel
Status: active
Keyspace: amplitudes 1-13 x phases 0-2A x periods 1-26 x 3 variants x 2 alphabets
Last run:
Best score:

Hypothesis (Rob Matson): Apply a triangular wave (sawtooth/zigzag) shift
to K4 ciphertext as a MASKING layer, then test the intermediate result
for periodic polyalphabetic substitution.

Matson found: amplitude 4, phase 0, descending first, produces IC of 6.83
at period 7 -- 3.65 sigma above mean.
"""

import sys, os, json, math
from datetime import datetime, timezone
from collections import defaultdict
from itertools import product

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
)
from kryptos.kernel.scoring.aggregate import score_candidate


# ---------------------------------------------------------------------------
# Sawtooth / triangular wave generation
# ---------------------------------------------------------------------------

def triangle_wave_shifts(length, amplitude, phase, descending_first=True):
    """Generate triangular wave shifts for each position.

    The wave oscillates between -amplitude and +amplitude with period 2*amplitude.

    For descending_first=True (Matson default):
        Starting from +amplitude, descend to -amplitude, then ascend back.
        shift[i] = amplitude - abs((i + phase) % (2*amplitude) - amplitude)
        ... but with sign: oscillates +A, +A-1, ..., 0, -1, ..., -A, -A+1, ..., 0, +1, ..., +A

    For ascending_first=False, we negate (or equivalently shift phase by amplitude).
    """
    if amplitude == 0:
        return [0] * length

    period = 2 * amplitude
    shifts = []
    for i in range(length):
        # Triangle wave: maps to 0..A..0..(-A)..0 over one full period of 2A
        # Position within period
        pos_in_period = (i + phase) % period
        # Unsigned triangle: 0 -> A -> 0
        unsigned = amplitude - abs(pos_in_period - amplitude)

        if descending_first:
            # Start at +A, descend to -A: shift = A - 2 * unsigned ... no.
            # Matson's version: descending first means we START at the peak (+A)
            # and go down. The standard triangle 0->A->0 starts at 0.
            # To start at A: shift phase so pos 0 maps to peak.
            # Actually let's use signed triangle directly:
            # signed_pos = (i + phase) % (2*period) mapped to [-A, +A]
            pass
        shifts.append(unsigned)

    # The above gives unsigned 0..A..0. For a SIGNED wave (-A to +A):
    # We need period = 4*A for a full signed cycle, OR we use 2*A for unsigned.
    # Matson's description: amplitude 4, the shift pattern bounces between +4 and -4.
    # Let's re-derive properly.
    return shifts


def signed_triangle_shifts(length, amplitude, phase, descending_first=True):
    """Signed triangular wave: oscillates between +amplitude and -amplitude.

    Full period = 4 * amplitude.

    descending_first=True: starts at +A, goes down to -A, back to +A.
    descending_first=False: starts at -A, goes up to +A, back to -A.
    """
    if amplitude == 0:
        return [0] * length

    full_period = 4 * amplitude
    shifts = []
    for i in range(length):
        p = (i + phase) % full_period
        # Map p to signed triangle:
        # p=0 -> +A, p=A -> 0, p=2A -> -A, p=3A -> 0, p=4A -> +A
        if p <= amplitude:
            val = amplitude - p
        elif p <= 3 * amplitude:
            val = p - 3 * amplitude
        else:
            val = p - 3 * amplitude
        # Simplify: standard approach
        # Actually let's use the clean formula
        pass

    # Clean implementation:
    shifts = []
    for i in range(length):
        p = (i + phase) % full_period
        # Unsigned triangle with period = full_period, range 0 to 2A
        half = 2 * amplitude
        unsigned = half - abs(p - half)  # 0 -> 2A -> 0 over full_period
        signed = unsigned - amplitude     # -A -> +A -> -A
        if not descending_first:
            signed = -signed
        shifts.append(signed)

    return shifts


def unsigned_triangle_shifts(length, amplitude, phase):
    """Unsigned triangular wave: oscillates between 0 and amplitude.

    Period = 2 * amplitude.
    """
    if amplitude == 0:
        return [0] * length

    period = 2 * amplitude
    shifts = []
    for i in range(length):
        p = (i + phase) % period
        val = amplitude - abs(p - amplitude)
        shifts.append(val)
    return shifts


# ---------------------------------------------------------------------------
# IC calculation
# ---------------------------------------------------------------------------

def compute_ic(text):
    """Index of Coincidence for a string of uppercase letters."""
    n = len(text)
    if n <= 1:
        return 0.0
    counts = [0] * 26
    for ch in text:
        counts[ALPH_IDX[ch]] += 1
    numerator = sum(c * (c - 1) for c in counts)
    return numerator / (n * (n - 1))


def compute_periodic_ic(text, period):
    """Mean IC across residue classes for a given period."""
    residues = [[] for _ in range(period)]
    for i, ch in enumerate(text):
        residues[i % period].append(ch)

    ic_values = []
    for r in residues:
        if len(r) > 1:
            ic_values.append(compute_ic("".join(r)))

    if not ic_values:
        return 0.0, []
    return sum(ic_values) / len(ic_values), ic_values


# ---------------------------------------------------------------------------
# Apply mask and decrypt
# ---------------------------------------------------------------------------

def apply_mask(ct_nums, shifts):
    """Apply sawtooth mask: intermediate[i] = (ct[i] - shift[i]) % 26"""
    return [(c - s) % MOD for c, s in zip(ct_nums, shifts)]


def nums_to_text(nums):
    return "".join(ALPH[n] for n in nums)


def text_to_nums(text):
    return [ALPH_IDX[c] for c in text]


def try_periodic_decrypt(intermediate_nums, period, variant="vigenere"):
    """Try all keys at a given period. Returns best (score, plaintext, key, method)."""
    best = (0, "", "", "")
    n = len(intermediate_nums)

    # For each residue class, determine the shift that maximizes crib matches
    # First, check crib-constrained approach
    key = [None] * period
    crib_constrained = 0

    for pos, pt_ch in CRIB_DICT.items():
        if pos >= n:
            continue
        r = pos % period
        ct_val = intermediate_nums[pos]
        pt_val = ALPH_IDX[pt_ch]

        if variant == "vigenere":
            k = (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            k = (ct_val + pt_val) % MOD
        elif variant == "varbeaufort":
            k = (pt_val - ct_val) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")

        if key[r] is None:
            key[r] = k
            crib_constrained += 1
        elif key[r] != k:
            # Conflict -- this period/variant is inconsistent with cribs
            return (0, "", "", f"{variant}/p{period}/CONFLICT")

    # Fill unconstrained residues by brute force (try all 26)
    free_residues = [r for r in range(period) if key[r] is None]

    if len(free_residues) > 6:
        # Too many free residues for brute force; use IC-based best guess
        for r in free_residues:
            # Pick shift that maximizes frequency correlation with English
            best_shift = 0
            best_corr = -1e9
            residue_chars = [intermediate_nums[i] for i in range(r, n, period)]
            # English letter frequencies (A=0 .. Z=25)
            eng_freq = [
                0.0817, 0.0149, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202,
                0.0609, 0.0697, 0.0015, 0.0077, 0.0403, 0.0241, 0.0675,
                0.0751, 0.0193, 0.0010, 0.0599, 0.0633, 0.0906, 0.0276,
                0.0098, 0.0236, 0.0015, 0.0197, 0.0007
            ]
            for s in range(MOD):
                if variant == "vigenere":
                    decrypted = [(c - s) % MOD for c in residue_chars]
                elif variant == "beaufort":
                    decrypted = [(s - c) % MOD for c in residue_chars]
                elif variant == "varbeaufort":
                    decrypted = [(c + s) % MOD for c in residue_chars]

                freq = [0.0] * 26
                for d in decrypted:
                    freq[d] += 1.0 / len(decrypted)
                corr = sum(freq[j] * eng_freq[j] for j in range(26))
                if corr > best_corr:
                    best_corr = corr
                    best_shift = s
            key[r] = best_shift
    else:
        # Brute-force free residues
        if not free_residues:
            # All constrained -- just decrypt
            pass
        else:
            best_result = _brute_force_free(intermediate_nums, period, variant,
                                            key, free_residues)
            return best_result

    # Decrypt with the determined key
    pt_nums = decrypt_with_key(intermediate_nums, key, period, variant)
    pt = nums_to_text(pt_nums)
    key_str = nums_to_text(key)
    result = score_candidate(pt)
    method = f"sawtooth+{variant}/p{period}/key={key_str}"
    return (result.crib_score, pt, key_str, method)


def decrypt_with_key(ct_nums, key, period, variant):
    """Decrypt intermediate nums with a periodic key."""
    pt = []
    for i, c in enumerate(ct_nums):
        k = key[i % period]
        if variant == "vigenere":
            pt.append((c - k) % MOD)
        elif variant == "beaufort":
            pt.append((k - c) % MOD)
        elif variant == "varbeaufort":
            pt.append((c + k) % MOD)
    return pt


def _brute_force_free(intermediate_nums, period, variant, key_template, free_residues):
    """Brute-force free residue classes (up to 6)."""
    best = (0, "", "", "")
    n = len(intermediate_nums)

    for combo in product(range(MOD), repeat=len(free_residues)):
        key = list(key_template)
        for r, s in zip(free_residues, combo):
            key[r] = s
        pt_nums = decrypt_with_key(intermediate_nums, key, period, variant)
        pt = nums_to_text(pt_nums)
        result = score_candidate(pt)
        if result.crib_score > best[0]:
            key_str = nums_to_text(key)
            method = f"sawtooth+{variant}/p{period}/key={key_str}"
            best = (result.crib_score, pt, key_str, method)
            if result.crib_score >= 18:
                print(f"  *** SIGNAL: {result.crib_score}/24 {method}")
                print(f"      PT: {pt}")
    return best


# ---------------------------------------------------------------------------
# Z-score computation
# ---------------------------------------------------------------------------

def ic_zscore(observed_ic, n_chars, period):
    """Z-score for mean periodic IC vs random expectation.

    Under random text, each residue class has IC ~ 1/26 = 0.03846.
    Variance of IC for a sample of size m: Var ~ 2/(m*(m-1)) * (1/26 - 1/26^2)
    ... simplified: sigma ~ sqrt(2 * p_random * (1 - p_random) / (m-1)) / sqrt(k)
    where k = number of residue classes, m = chars per class.
    """
    m = n_chars / period  # average chars per residue class
    if m <= 2:
        return 0.0
    random_ic = 1.0 / 26.0
    # Variance of IC for one class of size m (approximation)
    var_one = 2.0 * random_ic * (1.0 - random_ic) / (m * (m - 1))
    # Variance of mean over 'period' classes
    var_mean = var_one / period
    sigma = math.sqrt(var_mean) if var_mean > 0 else 1e-9
    return (observed_ic - random_ic) / sigma


# ---------------------------------------------------------------------------
# Main sweep
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("Sawtooth/Zigzag Mask + Periodic Polyalphabetic Attack on K4")
    print("=" * 70)
    print(f"CT ({CT_LEN} chars): {CT}")
    print(f"Cribs: {dict(sorted(CRIB_DICT.items()))}")
    print()

    ct_nums = text_to_nums(CT)

    # Phase 1: IC survey across all mask parameters
    print("PHASE 1: IC survey (amplitude x phase x direction x period)")
    print("-" * 70)

    ic_results = []
    random_ic = 1.0 / 26.0  # 0.03846

    for amplitude in range(1, 14):
        for descending_first in [True, False]:
            # For signed triangle: full period = 4*A, phases 0..4A-1
            # For unsigned triangle: period = 2*A, phases 0..2A-1
            # We test BOTH signed and unsigned interpretations
            for wave_type in ["signed", "unsigned"]:
                if wave_type == "signed":
                    phase_range = 4 * amplitude
                    shift_fn = lambda l, a, p, d=descending_first: signed_triangle_shifts(l, a, p, d)
                else:
                    phase_range = 2 * amplitude
                    shift_fn = lambda l, a, p: unsigned_triangle_shifts(l, a, p)

                for phase in range(phase_range):
                    if wave_type == "signed":
                        shifts = signed_triangle_shifts(CT_LEN, amplitude, phase, descending_first)
                    else:
                        shifts = unsigned_triangle_shifts(CT_LEN, amplitude, phase)

                    intermediate_nums = apply_mask(ct_nums, shifts)
                    intermediate_text = nums_to_text(intermediate_nums)

                    # Overall IC
                    overall_ic = compute_ic(intermediate_text)

                    # Periodic IC for periods 1-26
                    for period in range(1, 27):
                        mean_ic, per_class_ics = compute_periodic_ic(intermediate_text, period)
                        z = ic_zscore(mean_ic, CT_LEN, period)

                        dir_str = "desc" if descending_first else "asc"
                        if wave_type == "unsigned":
                            dir_str = "unsigned"

                        ic_results.append({
                            "amplitude": amplitude,
                            "phase": phase,
                            "direction": dir_str,
                            "wave_type": wave_type,
                            "period": period,
                            "mean_ic": mean_ic,
                            "overall_ic": overall_ic,
                            "z_score": z,
                            "max_class_ic": max(per_class_ics) if per_class_ics else 0,
                            "intermediate": intermediate_text,
                            "shifts_sample": shifts[:20],
                        })

    # Sort by z-score descending
    ic_results.sort(key=lambda x: x["z_score"], reverse=True)

    print(f"\nTotal configurations surveyed: {len(ic_results)}")
    print(f"\nTOP 30 by Z-score:")
    print(f"{'Amp':>3} {'Ph':>3} {'Dir':>9} {'Wave':>8} {'Per':>3} "
          f"{'MeanIC':>8} {'MaxIC':>8} {'Z':>8} {'OvrlIC':>8}")
    print("-" * 80)

    for r in ic_results[:30]:
        print(f"{r['amplitude']:3d} {r['phase']:3d} {r['direction']:>9} {r['wave_type']:>8} "
              f"{r['period']:3d} {r['mean_ic']:.5f} {r['max_class_ic']:.5f} "
              f"{r['z_score']:+8.3f} {r['overall_ic']:.5f}")

    # Phase 2: For top candidates with z > 2.0, try full decryption
    print("\n" + "=" * 70)
    print("PHASE 2: Decryption attack on promising IC candidates (z > 2.0)")
    print("=" * 70)

    # Deduplicate by intermediate text + period
    seen = set()
    candidates = []
    for r in ic_results:
        if r["z_score"] < 2.0:
            continue
        key = (r["intermediate"], r["period"])
        if key in seen:
            continue
        seen.add(key)
        candidates.append(r)

    print(f"\n{len(candidates)} candidate (intermediate, period) pairs with z > 2.0")

    decrypt_results = []
    for idx, cand in enumerate(candidates):
        intermediate_nums = text_to_nums(cand["intermediate"])
        period = cand["period"]

        for variant in ["vigenere", "beaufort", "varbeaufort"]:
            score, pt, key_str, method = try_periodic_decrypt(
                intermediate_nums, period, variant
            )
            if score > 0:
                full_method = (f"A={cand['amplitude']},ph={cand['phase']},"
                               f"{cand['direction']},{cand['wave_type']}/"
                               f"{method}")
                decrypt_results.append({
                    "crib_score": score,
                    "plaintext": pt,
                    "key": key_str,
                    "method": full_method,
                    "amplitude": cand["amplitude"],
                    "phase": cand["phase"],
                    "direction": cand["direction"],
                    "wave_type": cand["wave_type"],
                    "period": period,
                    "variant": variant,
                    "z_score": cand["z_score"],
                    "mean_ic": cand["mean_ic"],
                })

        if (idx + 1) % 50 == 0:
            print(f"  ... processed {idx+1}/{len(candidates)} candidates")

    decrypt_results.sort(key=lambda x: x["crib_score"], reverse=True)

    print(f"\nTOP 20 decryption results by crib score:")
    print(f"{'Score':>5} {'Amp':>3} {'Ph':>3} {'Dir':>5} {'Per':>3} {'Var':>10} "
          f"{'Z':>7} {'MeanIC':>7} {'Key':>10} PT")
    print("-" * 100)

    for r in decrypt_results[:20]:
        print(f"{r['crib_score']:5d} {r['amplitude']:3d} {r['phase']:3d} "
              f"{r['direction']:>5} {r['period']:3d} {r['variant']:>10} "
              f"{r['z_score']:+7.3f} {r['mean_ic']:.5f} {r['key']:>10} "
              f"{r['plaintext'][:50]}")

    # Phase 3: Specifically test Matson's parameters (A=4, phase=0, desc, period 7)
    print("\n" + "=" * 70)
    print("PHASE 3: Matson specific -- A=4, phase=0, descending, period 7")
    print("=" * 70)

    for wave_type in ["signed", "unsigned"]:
        for desc in [True, False]:
            if wave_type == "signed":
                shifts = signed_triangle_shifts(CT_LEN, 4, 0, desc)
            else:
                shifts = unsigned_triangle_shifts(CT_LEN, 4, 0)

            intermediate_nums = apply_mask(ct_nums, shifts)
            intermediate_text = nums_to_text(intermediate_nums)

            mean_ic, per_class = compute_periodic_ic(intermediate_text, 7)
            z = ic_zscore(mean_ic, CT_LEN, 7)

            dir_str = ("desc" if desc else "asc") if wave_type == "signed" else "unsigned"
            print(f"\n  Wave={wave_type}, dir={dir_str}")
            print(f"  Shifts[0:20]: {shifts[:20]}")
            print(f"  Intermediate: {intermediate_text}")
            print(f"  Overall IC: {compute_ic(intermediate_text):.5f}")
            print(f"  Period-7 mean IC: {mean_ic:.5f} (x1000 = {mean_ic*1000:.2f})")
            print(f"  Period-7 Z-score: {z:+.3f}")
            print(f"  Per-class ICs: {[f'{x:.4f}' for x in per_class]}")

            # Full decryption at period 7
            for variant in ["vigenere", "beaufort", "varbeaufort"]:
                score, pt, key_str, method = try_periodic_decrypt(
                    intermediate_nums, 7, variant
                )
                print(f"    {variant:12s}: score={score}/24, key={key_str}, "
                      f"PT={pt[:60]}")

    # Also try Matson's exact IC value of 6.83 (= 0.0683 * 100?)
    # Actually IC of 6.83 likely means 0.0683 (scaled by 100) or
    # the "kappa" value * 100. Let's find which params give IC near 0.0683.
    print("\n" + "=" * 70)
    print("PHASE 4: Searching for mean periodic IC near 0.0683 at period 7")
    print("=" * 70)

    near_matson = [r for r in ic_results
                   if r["period"] == 7 and abs(r["mean_ic"] * 100 - 6.83) < 0.5]
    near_matson.sort(key=lambda x: abs(x["mean_ic"] * 100 - 6.83))

    print(f"Found {len(near_matson)} configs with period-7 IC within 0.5 of 6.83 (x100):")
    for r in near_matson[:10]:
        print(f"  A={r['amplitude']}, ph={r['phase']}, dir={r['direction']}, "
              f"wave={r['wave_type']}, IC={r['mean_ic']*100:.2f}, z={r['z_score']:+.3f}")

    # Save results
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    outpath = os.path.join(_ROOT, "results", f"sawtooth_mask_{timestamp}.json")

    output = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attack": "sawtooth_mask + periodic_polyalphabetic",
        "ciphertext": CT,
        "parameters": {
            "amplitudes": "1-13",
            "phases": "0 to 4*A (signed) or 2*A (unsigned)",
            "directions": ["descending_first", "ascending_first", "unsigned"],
            "wave_types": ["signed", "unsigned"],
            "periods": "1-26",
            "variants": ["vigenere", "beaufort", "varbeaufort"],
        },
        "total_ic_configs": len(ic_results),
        "candidates_above_z2": len(candidates),
        "top_20_ic": [
            {k: v for k, v in r.items() if k != "intermediate"}
            for r in ic_results[:20]
        ],
        "top_20_decrypt": decrypt_results[:20],
        "matson_search": [
            {k: v for k, v in r.items() if k != "intermediate"}
            for r in near_matson[:10]
        ],
        "conclusion": "",  # filled below
    }

    # Determine conclusion
    max_crib = max((r["crib_score"] for r in decrypt_results), default=0)
    if max_crib >= 18:
        output["conclusion"] = f"PROMISING: max crib score {max_crib}/24"
    elif max_crib >= 10:
        output["conclusion"] = f"INTERESTING: max crib score {max_crib}/24, worth investigating"
    else:
        output["conclusion"] = f"NOISE: max crib score {max_crib}/24, no signal detected"

    with open(outpath, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n{'=' * 70}")
    print(f"Results saved to: {outpath}")
    print(f"Conclusion: {output['conclusion']}")
    print(f"Max crib score: {max_crib}/24")
    print(f"{'=' * 70}")

    return output


if __name__ == "__main__":
    main()
