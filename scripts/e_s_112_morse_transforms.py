#!/usr/bin/env python3
"""E-S-112: Morse code transforms and K0→K4 link tests.

Stage 0 of Progressive Solve Plan.

Parses the known Morse code transcription from K0, then tests:
  (a) K0 phrase fragments as Vigenère keys on K4
  (b) Crib-drag K0 fragments across K4 CT
  (c) E-position analysis (26 extra E's)
  (d) "T IS YOUR POSITION" → offset 19 rotation
  (e) XOR/Vigenère K0 fragments against K4
  (f) ALLY+ENVY verification for K0→K2 link
  (g) K0 reversed Morse interpretation
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, NOISE_FLOOR,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, apply_perm, invert_perm,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.scoring.ic import ic


# ── K0 Morse Code Content ───────────────────────────────────────────────
# Best transcription from Dunin + community consensus
# Phrases extracted from Morse code on the entrance slabs

K0_PHRASES = {
    "VIRTUALLY_INVISIBLE": "VIRTUALLYINVISIBLE",
    "DIGETAL_INTERPRETAT": "DIGETALINTERPRETAT",  # Truncated (ION missing)
    "T_IS_YOUR_POSITION": "TISYOURPOSITION",
    "SHADOW_FORCES": "SHADOWFORCES",
    "LUCID_MEMORY": "LUCIDMEMORY",
    "SOS": "SOS",
    "RQ": "RQ",
}

# ALLY+ENVY extraction: last 4 of VIRTUALLY + first 4 of INVISIBLE
ALLY_ENVY = "ALLYENVY"

# K2 CT (for ALLY+ENVY verification)
K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLGTIMV"
    "MZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRRYIZET"
    "KZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYCUQZEREEVLDKFEZM"
    "OQQJLTTUGSYQPFEUNLAVIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKFFHQNTGPUAEC"
    "NUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGREDNQFMPNZGLFLPM"
    "RJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)


def make_key(text):
    return [ALPH_IDX[c] for c in text.upper() if c in ALPH_IDX]


def crib_drag(ct, crib, variant=CipherVariant.VIGENERE):
    """Slide crib across CT, recovering key fragment at each position.
    Returns list of (position, recovered_key_fragment, key_as_text) tuples.
    """
    from kryptos.kernel.transforms.vigenere import KEY_RECOVERY
    fn = KEY_RECOVERY[variant]
    results = []
    crib_len = len(crib)

    for start in range(len(ct) - crib_len + 1):
        key_frag = []
        for i, p in enumerate(crib):
            c_idx = ALPH_IDX[ct[start + i]]
            p_idx = ALPH_IDX[p]
            k = fn(c_idx, p_idx)
            key_frag.append(k)
        key_text = "".join(ALPH[k] for k in key_frag)
        results.append((start, key_frag, key_text))

    return results


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-S-112: Morse Code Transforms & K0→K4 Tests")
    print("=" * 70)

    results = []
    best_overall = 0
    total_tested = 0

    # ── Phase 1: K0 phrases as Vigenère keys on K4 ──────────────────────
    print("\n--- Phase 1: K0 phrases as K4 Vigenère keys ---")
    for phrase_name, phrase in K0_PHRASES.items():
        key = make_key(phrase)
        best = 0
        best_var = ""
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
            pt = decrypt_text(CT, key, variant)
            sc = score_cribs(pt)
            total_tested += 1
            if sc > best:
                best = sc
                best_var = variant.value
            if sc > NOISE_FLOOR:
                results.append({
                    "phase": "phrase_as_key",
                    "phrase": phrase_name,
                    "variant": variant.value,
                    "score": sc,
                })
        if best > best_overall:
            best_overall = best
        print(f"  {phrase_name} (period {len(key)}): best={best}/24 ({best_var})")

    # Also test ALLY+ENVY as K4 key
    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
        pt = decrypt_text(CT, make_key(ALLY_ENVY), variant)
        sc = score_cribs(pt)
        total_tested += 1
        if sc > best_overall:
            best_overall = sc
        if sc > NOISE_FLOOR:
            results.append({"phase": "allyenvy_key", "variant": variant.value, "score": sc})
    print(f"  ALLYENVY: best={max(score_cribs(decrypt_text(CT, make_key(ALLY_ENVY), v)) for v in CipherVariant)}/24")

    # ── Phase 2: ALLY+ENVY → ABSCISSA verification (K0→K2 link) ─────────
    print("\n--- Phase 2: ALLY+ENVY crib drag on K2 CT ---")
    # Crib drag ABSCISSA across K2 CT using ALLY+ENVY as expected key
    ae_key = make_key(ALLY_ENVY)
    drag_results = crib_drag(K2_CT, "ABSCISSA", CipherVariant.VIGENERE)

    # Find where the recovered key matches ALLYENVY
    matches = []
    for pos, key_frag, key_text in drag_results:
        if key_text[:8] == ALLY_ENVY:
            matches.append(pos)
            print(f"  MATCH at K2 position {pos}: key={key_text}")

    # More broadly: find where key starts with ALLY
    for pos, key_frag, key_text in drag_results:
        if key_text[:4] == "ALLY":
            print(f"  Partial match (ALLY) at K2 position {pos}: key={key_text}")

    if not matches:
        print("  No exact ALLYENVY match found (expected — ALLYENVY→ABSCISSA uses Kryptos alphabet)")
        # Try with Kryptos alphabet
        print("  Trying with standard Vig crib drag of ALLYENVY against K2 CT...")
        # Decrypt K2 with ALLYENVY as key, look for ABSCISSA in plaintext
        for variant in CipherVariant:
            pt = decrypt_text(K2_CT, make_key(ALLY_ENVY), variant)
            if "ABSCISSA" in pt:
                print(f"  *** ABSCISSA found in K2 PT at position {pt.index('ABSCISSA')} using {variant.value}! ***")
            # Also check for partial
            for i in range(len(pt) - 3):
                if pt[i:i+4] == "ABSC":
                    print(f"  Partial ABSC at position {i} ({variant.value}): ...{pt[max(0,i-5):i+10]}...")

    # ── Phase 3: Crib drag K0 fragments across K4 ───────────────────────
    print("\n--- Phase 3: Crib drag K0 fragments across K4 CT ---")
    # For each K0 phrase, slide it across K4 CT, look at recovered keys
    # A meaningful result would be: key fragment is a recognizable word/pattern

    interesting_keys = []
    for phrase_name, phrase in K0_PHRASES.items():
        if len(phrase) < 4:
            continue
        drag_results = crib_drag(CT, phrase, CipherVariant.VIGENERE)
        for pos, key_frag, key_text in drag_results:
            # Check if key text contains common English patterns
            total_tested += 1
            # Simple heuristic: count common bigrams
            common_bigrams = {"TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT",
                            "EN", "ND", "TI", "ES", "OR", "TE", "OF", "ED",
                            "IS", "IT", "AL", "AR", "ST", "TO", "NT"}
            bigram_count = sum(1 for i in range(len(key_text)-1)
                              if key_text[i:i+2] in common_bigrams)
            if bigram_count >= 3:
                interesting_keys.append({
                    "phrase": phrase_name,
                    "ct_position": pos,
                    "key_text": key_text,
                    "bigram_count": bigram_count,
                })

    if interesting_keys:
        print(f"  Found {len(interesting_keys)} key fragments with ≥3 common bigrams:")
        for ik in sorted(interesting_keys, key=lambda x: -x["bigram_count"])[:10]:
            print(f"    {ik['phrase']} at pos {ik['ct_position']}: key={ik['key_text']} ({ik['bigram_count']} bigrams)")
    else:
        print("  No key fragments with ≥3 common bigrams found")

    # ── Phase 4: T=19 rotation + key tests ───────────────────────────────
    print("\n--- Phase 4: T=19 rotation of K4 CT ---")
    for offset in [19, 20]:
        ct_rotated = CT[offset:] + CT[:offset]
        # Test with all K0 phrases as keys
        for phrase_name, phrase in K0_PHRASES.items():
            key = make_key(phrase)
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(ct_rotated, key, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > best_overall:
                    best_overall = sc
                if sc > NOISE_FLOOR:
                    results.append({
                        "phase": "t_rotation",
                        "offset": offset,
                        "phrase": phrase_name,
                        "variant": variant.value,
                        "score": sc,
                    })

        # Also test rotated CT directly (maybe cribs are in different positions)
        sc_direct = score_cribs(ct_rotated)
        ic_rot = ic(ct_rotated)
        print(f"  Offset {offset}: direct cribs={sc_direct}/24, IC={ic_rot:.4f}")

    # ── Phase 5: E-marker analysis ───────────────────────────────────────
    print("\n--- Phase 5: E-position analysis ---")
    # The 26 extra E's in the Morse code. We don't have exact positions mapped
    # to K4, but we can test the concept: if positions 0-25 (or mod 26) are
    # marked, what does that mean?

    # Test: read K4 CT at every Nth position where N = letter ordinal
    for letter in "ETION":  # Common letters to test as position markers
        stride = ALPH_IDX[letter] + 1  # E→5, T→20, etc.
        if stride == 0:
            continue
        # Read every stride-th character
        selected = CT[::stride]
        sc = score_cribs(selected + "X" * (CT_LEN - len(selected)))
        total_tested += 1
        print(f"  Every {stride}th char ('{letter}'): {selected[:20]}... ({len(selected)} chars)")

    # Test: use positions 0,4,8,12,16,20,24 (every 4th = E positions in Morse dit pattern?)
    for stride in [4, 5, 7, 13, 26]:
        positions = list(range(0, CT_LEN, stride))
        selected = "".join(CT[p] for p in positions)
        print(f"  Stride {stride}: {selected[:20]}... ({len(selected)} chars)")

    # ── Phase 6: Subword extraction from K0 phrases ──────────────────────
    print("\n--- Phase 6: Subword extraction ---")
    # Extract all 4-8 letter substrings from K0 phrases, test as keys
    all_subwords = set()
    for phrase in K0_PHRASES.values():
        for length in range(4, min(9, len(phrase) + 1)):
            for start in range(len(phrase) - length + 1):
                all_subwords.add(phrase[start:start+length])

    phase6_best = 0
    for subword in all_subwords:
        key = make_key(subword)
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
            pt = decrypt_text(CT, key, variant)
            sc = score_cribs(pt)
            total_tested += 1
            if sc > phase6_best:
                phase6_best = sc
            if sc > NOISE_FLOOR:
                results.append({
                    "phase": "subword_key",
                    "subword": subword,
                    "variant": variant.value,
                    "score": sc,
                })

    if phase6_best > best_overall:
        best_overall = phase6_best
    print(f"  Tested {len(all_subwords)} subwords, best={phase6_best}/24")

    # ── Phase 7: K0 phrases + w7 columnar ────────────────────────────────
    print("\n--- Phase 7: K0 phrases + w7 columnar (sampled) ---")
    import random
    random.seed(112)
    w7_sample = [tuple(random.sample(range(7), 7)) for _ in range(300)]
    w7_sample.append(tuple(range(7)))

    phase7_best = 0
    for col_order in w7_sample:
        perm = columnar_perm(7, list(col_order), CT_LEN)
        inv = invert_perm(perm)
        ct_untrans = apply_perm(CT, inv)

        for phrase_name, phrase in K0_PHRASES.items():
            if len(phrase) < 4:
                continue
            key = make_key(phrase)
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(ct_untrans, key, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase7_best:
                    phase7_best = sc
                if sc > NOISE_FLOOR:
                    results.append({
                        "phase": "phrase_w7",
                        "phrase": phrase_name,
                        "col_order": list(col_order),
                        "variant": variant.value,
                        "score": sc,
                    })

    if phase7_best > best_overall:
        best_overall = phase7_best
    print(f"  w7 + K0 phrases best: {phase7_best}/24")

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
        "experiment_id": "e_s_112",
        "stage": 0,
        "hypothesis": "K0 Morse code fragments provide K4 key material or operational links",
        "parameters_source": "K0 Morse",
        "total_tested": total_tested,
        "best_score": best_overall,
        "above_noise": results[:50],
        "interesting_crib_drag_keys": interesting_keys[:20],
        "ally_envy_k2_matches": [],
        "verdict": verdict,
        "runtime_seconds": elapsed,
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_s_112_morse_transforms.py",
    }

    out_path = "artifacts/progressive_solve/stage0/k0_transforms_results.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifacts written to {out_path}")


if __name__ == "__main__":
    main()
