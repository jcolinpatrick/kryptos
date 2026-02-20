#!/usr/bin/env python3
"""E-S-124: Palimpsest-as-method — K1-K3 texts as running key masks for K4.

A palimpsest is a document where earlier text shows through overwriting.
K1 keyword = PALIMPCEST. This may be a literal instruction.

Tests:
  (a) K3 PT read in 42×8 grid column order → running key for K4
  (b) K3 PT/CT linear as running key
  (c) K1 PT, K2 PT as running keys
  (d) K1/K2/K3 CT in various grid orders
  (e) Combined: K3 grid-order running key + width-7 columnar

Stage 4 of Progressive Solve Plan.
"""
import json
import os
import sys
import time
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, NOISE_FLOOR,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text, remove_additive_mask,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, apply_perm, invert_perm,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.scoring.ic import ic


# ── Known plaintexts and ciphertexts ────────────────────────────────────

K1_PT = (
    "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUA"
    "NCEOFIQLUSION"
)

K2_PT = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEE"
    "ARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRA"
    "NSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEY"
    "KNOWABOUTTHIS THEYSHOULDITSB URIEDOUTTHERESOMEWHER"
    "EXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESS"
    "AGEXTHIRTYEIGHTDEGREESF IFTYSEVENMINUTESSIXPOINTFI"
    "VESECONDSNORTHSEVENTYS EVENDEGREESE IGHTMINUTESFORT"
    "YFOURSECONDSWES TXLAYERTWO"
).replace(" ", "")

K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTH"
    "ATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITH"
    "TREMBLINGHANDSIMADEATINYBREACHINTHELEFTHANDCORNERA"
    "NDTHENWIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDP"
    "EEREDINTHEHOTAIRESCAPINGFROMTHECHAMBER CAUSEDTHEFLA"
    "METOF LICKERANDPRESENTLY DETAILSOFTHEROOMWITHINEMERGED"
    "FROMTHEMISTXCANYOUSEEANYTHINGQ"
).replace(" ", "")

K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"

K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLGTIMV"
    "MZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRRYIZET"
    "KZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYCUQZEREEVLDKFEZM"
    "OQQJLTTUGSYQPFEUNLAVIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKFFHQNTGPUAEC"
    "NUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGREDNQFMPNZGLFLPM"
    "RJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)

# K3 CT (336 chars — this is the text that appears on the sculpture for K3)
# Derived from the known plaintext + transposition method
K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOETFO"
    "LSEDTIWENHAEIOYTEYTECHEATOHTEMNRAAIOPTLNCLRFEWAARTKNELYPMTLHZTO"
    "NYTEALRMMSADEQMCSTEWPCXFLLEEMRDWFQSLLSQKEHSTFEPEXAOCRSTGQTAWAI"
    "SWCBEDRATNWPFLQLSTTOFAQNALCSWDTLQATDQALCLRTQWHTGPNYQFEASGMTZGE"
    "CZBDTQCTEQKYMWPTMGPBLIPPFPT"
)


def grid_column_read(text, rows, cols):
    """Read text written row-major into rows×cols grid, reading column-major."""
    grid_size = rows * cols
    padded = text[:grid_size] if len(text) >= grid_size else text + "A" * (grid_size - len(text))
    result = []
    for c in range(cols):
        for r in range(rows):
            idx = r * cols + c
            if idx < len(padded):
                result.append(padded[idx])
    return "".join(result)


def make_running_key(source_text, length):
    """Extend or truncate source text to desired length, cycling if needed."""
    if len(source_text) >= length:
        return source_text[:length]
    repeats = (length // len(source_text)) + 1
    return (source_text * repeats)[:length]


def test_running_key(ct, running_key_text, label, results_list):
    """Test a running key text against K4 CT. Returns best score."""
    rk = make_running_key(running_key_text, len(ct))
    rk_numeric = [ALPH_IDX.get(c, 0) for c in rk.upper() if c in ALPH_IDX]

    if len(rk_numeric) < len(ct):
        rk_numeric = rk_numeric + [0] * (len(ct) - len(rk_numeric))

    best = 0
    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
        pt = decrypt_text(ct, rk_numeric, variant)
        sc = score_cribs(pt)
        ic_val = ic(pt)
        if sc > best:
            best = sc
        if sc > NOISE_FLOOR:
            results_list.append({
                "label": label,
                "variant": variant.value,
                "score": sc,
                "ic": round(ic_val, 4),
                "pt_snippet": pt[:40],
            })
    return best


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-S-124: Palimpsest Method — K1-K3 as Running Key Masks")
    print("=" * 70)

    print(f"K1 PT length: {len(K1_PT)}")
    print(f"K2 PT length: {len(K2_PT)}")
    print(f"K3 PT length: {len(K3_PT)}")
    print(f"K1 CT length: {len(K1_CT)}")
    print(f"K2 CT length: {len(K2_CT)}")
    print(f"K3 CT length: {len(K3_CT)}")

    results = []
    best_overall = 0
    total_tested = 0

    # ── Phase 1: Linear running keys ─────────────────────────────────────
    print("\n--- Phase 1: Linear running keys (PT and CT from K1-K3) ---")

    linear_sources = {
        "K1_PT_linear": K1_PT,
        "K2_PT_linear": K2_PT,
        "K3_PT_linear": K3_PT,
        "K1_CT_linear": K1_CT,
        "K2_CT_linear": K2_CT,
        "K3_CT_linear": K3_CT,
        "K1K2K3_PT_concat": K1_PT + K2_PT + K3_PT,
        "K3K2K1_PT_concat": K3_PT + K2_PT + K1_PT,
        "K1K2K3_CT_concat": K1_CT + K2_CT + K3_CT,
    }

    for label, source in linear_sources.items():
        sc = test_running_key(CT, source, label, results)
        total_tested += 3
        if sc > best_overall:
            best_overall = sc
        print(f"  {label}: best={sc}/24")

    # ── Phase 2: K3 in grid-column order ─────────────────────────────────
    print("\n--- Phase 2: K3 PT/CT in grid column order ---")

    # K3 uses 42×8 grid → read column order gives different text
    grid_dims = [
        (42, 8),   # K3's known dimensions
        (8, 42),   # Transposed
        (14, 24),  # K3 intermediate
        (24, 14),  # K3 intermediate transposed
        (7, 48),   # Width-7 connection
        (48, 7),
    ]

    for source_name, source_text in [("K3_PT", K3_PT), ("K3_CT", K3_CT)]:
        for rows, cols in grid_dims:
            if rows * cols < len(source_text):
                # Truncate source to fit
                pass
            col_ordered = grid_column_read(source_text, rows, cols)
            label = f"{source_name}_grid_{rows}x{cols}_colread"
            sc = test_running_key(CT, col_ordered, label, results)
            total_tested += 3
            if sc > best_overall:
                best_overall = sc
            print(f"  {label}: best={sc}/24")

    # ── Phase 3: K1/K2 in grid-column order ──────────────────────────────
    print("\n--- Phase 3: K1/K2 PT in grid column order ---")
    for source_name, source_text in [("K1_PT", K1_PT), ("K2_PT", K2_PT)]:
        for rows, cols in [(7, 10), (10, 7), (8, 9), (9, 8), (13, 5), (5, 13)]:
            col_ordered = grid_column_read(source_text, rows, cols)
            label = f"{source_name}_grid_{rows}x{cols}_colread"
            sc = test_running_key(CT, col_ordered, label, results)
            total_tested += 3
            if sc > best_overall:
                best_overall = sc
            if sc > 3:
                print(f"  {label}: best={sc}/24")

    # ── Phase 4: Running key + width-7 columnar ─────────────────────────
    print("\n--- Phase 4: Best running keys + w7 columnar (sampled) ---")
    random.seed(124)
    w7_sample = [tuple(random.sample(range(7), 7)) for _ in range(500)]
    w7_sample.append(tuple(range(7)))
    w7_sample.append(tuple(range(6, -1, -1)))

    # Test top running key sources with w7 columnar
    top_sources = {
        "K3_PT_42x8_col": grid_column_read(K3_PT, 42, 8),
        "K3_PT_linear": K3_PT,
        "K3_CT_linear": K3_CT,
        "K2_PT_linear": K2_PT,
        "K1K2K3_PT": K1_PT + K2_PT + K3_PT,
    }

    phase4_best = 0
    for col_order in w7_sample:
        perm = columnar_perm(7, list(col_order), CT_LEN)
        inv = invert_perm(perm)
        ct_untrans = apply_perm(CT, inv)

        for src_name, src_text in top_sources.items():
            rk = make_running_key(src_text, CT_LEN)
            rk_numeric = [ALPH_IDX.get(c, 0) for c in rk.upper() if c in ALPH_IDX]
            if len(rk_numeric) < CT_LEN:
                rk_numeric += [0] * (CT_LEN - len(rk_numeric))

            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(ct_untrans, rk_numeric, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase4_best:
                    phase4_best = sc
                if sc > NOISE_FLOOR:
                    results.append({
                        "label": f"w7_{src_name}",
                        "col_order": list(col_order),
                        "variant": variant.value,
                        "score": sc,
                    })

    if phase4_best > best_overall:
        best_overall = phase4_best
    print(f"  w7 + running key best: {phase4_best}/24")

    # ── Phase 5: K3 "showing through" — XOR/subtract K3 from K4 ─────────
    print("\n--- Phase 5: K3 'showing through' K4 (positional overlap on sculpture) ---")
    # K3 and K4 are adjacent on the sculpture. K3 ends where K4 begins.
    # Test: what if K3 PT (in its original encrypted form) was used as a mask?

    # K3 CT is 336 chars. K4 starts after K3 on the sculpture.
    # The physical sculpture layout: K3 CT occupies rows 15-25
    # K4 CT occupies rows 25-30 (approx)
    # There might be physical overlap or continuation

    # Test: use the LAST 97 chars of K3 CT as running key for K4
    if len(K3_CT) >= CT_LEN:
        last_97_k3ct = K3_CT[-CT_LEN:]
        sc = test_running_key(CT, last_97_k3ct, "K3_CT_last97", results)
        total_tested += 3
        print(f"  K3 CT last 97 chars as RK: {sc}/24")
        if sc > best_overall:
            best_overall = sc

        # Also first 97
        first_97_k3ct = K3_CT[:CT_LEN]
        sc = test_running_key(CT, first_97_k3ct, "K3_CT_first97", results)
        total_tested += 3
        print(f"  K3 CT first 97 chars as RK: {sc}/24")
        if sc > best_overall:
            best_overall = sc

    # Test: K3 PT at specific offset ranges that physically overlap with K4
    # K3 is ~336 chars, K4 is 97 chars. If they overlap by N chars:
    for overlap in range(0, min(97, len(K3_PT)), 10):
        k3_segment = K3_PT[len(K3_PT) - overlap:] if overlap > 0 else ""
        k3_segment += K3_PT[:CT_LEN - len(k3_segment)]
        k3_segment = k3_segment[:CT_LEN]
        if len(k3_segment) == CT_LEN:
            sc = test_running_key(CT, k3_segment, f"K3_PT_overlap_{overlap}", results)
            total_tested += 3
            if sc > best_overall:
                best_overall = sc

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print(f"\n{'=' * 70}")
    print(f"SUMMARY (elapsed: {elapsed:.1f}s)")
    print(f"{'=' * 70}")
    print(f"Total configs tested: {total_tested}")
    print(f"Global best score: {best_overall}/24")
    print(f"Results above noise: {len(results)}")

    if results:
        print("\nTop results:")
        for r in sorted(results, key=lambda x: -x["score"])[:10]:
            print(f"  score={r['score']}/24 {r}")

    verdict = "SIGNAL" if best_overall >= 18 else ("STORE" if best_overall > NOISE_FLOOR else "NOISE")
    print(f"\nVERDICT: {verdict}")

    artifact = {
        "experiment_id": "e_s_124",
        "stage": 4,
        "hypothesis": "K1-K3 PT/CT in various reading orders serve as K4 running key (palimpsest)",
        "parameters_source": "K1-K3 PT/CT",
        "total_tested": total_tested,
        "best_score": best_overall,
        "above_noise": results[:50],
        "verdict": verdict,
        "runtime_seconds": elapsed,
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_s_124_palimpsest_method.py",
    }

    out_path = "artifacts/progressive_solve/stage4/palimpsest_method_results.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifacts written to {out_path}")


if __name__ == "__main__":
    main()
