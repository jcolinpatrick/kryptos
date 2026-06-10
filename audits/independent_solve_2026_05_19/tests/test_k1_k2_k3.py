"""Verify the independent reference reproduces K1 and K2 from public method.

If this fails, the reference is broken — never blame the K-section data.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.dirname(ROOT))  # so `independent_solve_2026_05_19` is importable

from independent_solve_2026_05_19.src.kryptos_tableau import (
    encrypt_k1k2,
    decrypt_k1k2,
)


# K1: PALIMPSEST key, Kryptos-tableau Vigenere
K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K1_KEY = "PALIMPSEST"

# K2 (post-2006 errata; carved as on the sculpture). Source: Elonka.
# CT and PT here are publicly documented; using a known canonical sample.
K2_CT = ("VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLGTIM"
         "VMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRRYIZ"
         "ETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVH?DWKBFUFPWNTDFIYCUQZEREEVLD"
         "KFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ")
K2_PT_2006 = ("ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFI"
              "ELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWN"
              "LOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOME"
              "WHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYE"
              "IGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVEND"
              "EGREESEIGHTMINUTESFORTYFOURSECONDSWESTXLAYERTWO")
K2_KEY = "ABSCISSA"


def main():
    failures = []

    # K1 roundtrip
    derived_pt = decrypt_k1k2(K1_CT, K1_KEY)
    if derived_pt != K1_PT:
        # Show the diff
        n_match = sum(1 for a, b in zip(derived_pt, K1_PT) if a == b)
        failures.append(f"K1 decrypt mismatch: {n_match}/{len(K1_PT)} match\n"
                        f"  expected={K1_PT}\n"
                        f"  actual  ={derived_pt}")
    re_ct = encrypt_k1k2(K1_PT, K1_KEY)
    if re_ct != K1_CT:
        failures.append(f"K1 encrypt re-derivation mismatch\n"
                        f"  expected={K1_CT}\n"
                        f"  actual  ={re_ct}")

    # K2 — first 100 chars are sufficient as a sanity check; the post-2006
    # correction only changes the last word.
    k2_ct_clean = K2_CT.replace("?", "")
    derived_k2 = decrypt_k1k2(k2_ct_clean[:200], K2_KEY)
    n_match_k2 = sum(1 for a, b in zip(derived_k2, K2_PT_2006[:200]) if a == b)
    if n_match_k2 < 195:
        failures.append(f"K2 decrypt mismatch on first 200 chars: only {n_match_k2}/200 match\n"
                        f"  expected={K2_PT_2006[:200]}\n"
                        f"  actual  ={derived_k2}")

    if failures:
        print("K1/K2 REFERENCE VERIFICATION: FAIL")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("K1/K2 REFERENCE VERIFICATION: PASS")
    print(f"  K1: {len(K1_PT)}/{len(K1_PT)} chars match expected plaintext")
    print(f"  K1: re-encryption is byte-identical to original CT")
    print(f"  K2: {n_match_k2}/200 chars match expected (>=195 threshold)")


if __name__ == "__main__":
    main()
