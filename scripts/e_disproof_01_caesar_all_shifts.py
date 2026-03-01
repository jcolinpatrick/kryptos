"""E-DISPROOF-01: Caesar Cipher (ROT-1 through ROT-25) Disproof for K4.

Applies all 25 Caesar shifts to K4 and checks:
  (a) Does BERLINCLOCK appear at positions 63-73 (0-indexed)?
      [Note: 'positions 64-74' in 1-indexed == 63-73 in 0-indexed]
  (b) Does EASTNORTHEAST appear at positions 21-33 (0-indexed)?
  (c) Quadgram score (per-character) of the full 97-char output.
  (d) Index of Coincidence of the output.

Expected result: ALL 25 shifts are NOISE. This is a DISPROOF experiment.

Truth taxonomy:
  [DERIVED FACT] — deterministic from CT + Caesar formula.
  [PUBLIC FACT]  — BERLINCLOCK confirmed at pos 63-73 by Sanborn 2010.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is on path when run with PYTHONPATH=src
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_WORDS, CRIB_DICT, ALPH, MOD
from kryptos.kernel.scoring.ngram import get_default_scorer
from kryptos.kernel.scoring.ic import ic as compute_ic

# ── Caesar decryption ──────────────────────────────────────────────────────

def caesar_decrypt(ct: str, shift: int) -> str:
    """Decrypt Caesar cipher: PT[i] = (CT[i] - shift) mod 26."""
    return "".join(ALPH[(ALPH.index(c) - shift) % MOD] for c in ct)

# ── Crib check at fixed positions ─────────────────────────────────────────

def check_crib_at_position(pt: str, start: int, word: str) -> tuple[int, int]:
    """Return (matches, total) for word against pt at the given start position."""
    matches = sum(1 for i, ch in enumerate(word) if pt[start + i] == ch)
    return matches, len(word)

# ── Main analysis ─────────────────────────────────────────────────────────

def main() -> None:
    scorer = get_default_scorer()

    # English reference: score plaintext K3 as a sanity-check baseline
    K3_PT = "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNETPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOETFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLBTEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEBAECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDELPFOGLELRGXNLHCSNTZEXOVHYDAGDIHNTHUMestablilihooelet"
    k3_qg = scorer.score_per_char(K3_PT)

    print("=" * 76)
    print("E-DISPROOF-01: Caesar Cipher — All 25 Shifts Applied to K4")
    print("=" * 76)
    print(f"\nCiphertext  : {CT}")
    print(f"Length      : {CT_LEN} chars")
    print(f"Cribs (0-idx): ENE at 21-33, BERLINCLOCK at 63-73")
    print(f"\nK3 plaintext quadgram reference: {k3_qg:.4f}/char")
    print(f"Random text quadgram reference : ~-4.90/char (estimated)")
    print(f"English breakthrough threshold : > -4.84/char\n")

    # Header
    hdr = f"{'ROT':>4} | {'ENE':>5} | {'BC':>5} | {'Crib':>5} | {'QG/char':>8} | {'IC':>6} | {'BC_literal?':>12} | Decrypted[60:97]"
    print(hdr)
    print("-" * len(hdr))

    results = []
    for shift in range(1, 26):
        pt = caesar_decrypt(CT, shift)

        # Crib checks
        ene_m, ene_t = check_crib_at_position(pt, 21, "EASTNORTHEAST")
        bc_m, bc_t   = check_crib_at_position(pt, 63, "BERLINCLOCK")
        total_match  = ene_m + bc_m

        # Quadgram score
        qg = scorer.score_per_char(pt)

        # Index of coincidence
        ic_val = compute_ic(pt)

        # Literal substring check for BERLINCLOCK anywhere in pt
        bc_anywhere = "BERLINCLOCK" in pt

        results.append({
            "shift": shift,
            "pt": pt,
            "ene_m": ene_m, "ene_t": ene_t,
            "bc_m": bc_m, "bc_t": bc_t,
            "total": total_match,
            "qg": qg,
            "ic": ic_val,
            "bc_anywhere": bc_anywhere,
        })

        bc_flag = "YES ← CRIB HIT" if bc_anywhere else "no"
        print(
            f"ROT{shift:>2} | {ene_m:>3}/{ene_t} | {bc_m:>3}/{bc_t} | "
            f"{total_match:>3}/{ene_t+bc_t} | {qg:>8.4f} | {ic_val:>6.4f} | "
            f"{bc_flag:>12} | {pt[60:]}"
        )

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 76)
    print("SUMMARY")
    print("=" * 76)

    best = max(results, key=lambda r: r["total"])
    best_qg = max(results, key=lambda r: r["qg"])
    any_bc_hit = [r for r in results if r["bc_m"] == r["bc_t"]]
    any_ene_hit = [r for r in results if r["ene_m"] == r["ene_t"]]
    any_bc_anywhere = [r for r in results if r["bc_anywhere"]]

    print(f"\nBest crib score: ROT{best['shift']} → {best['total']}/{best['ene_t']+best['bc_t']} matches")
    print(f"Best quadgram  : ROT{best_qg['shift']} → {best_qg['qg']:.4f}/char (K3 ref: {k3_qg:.4f}/char)")

    if any_bc_hit:
        print(f"\n⚠  BERLINCLOCK exact at positions 63-73: {[r['shift'] for r in any_bc_hit]}")
    else:
        print("\n✓  BERLINCLOCK DOES NOT appear at positions 63-73 for ANY of 25 shifts.")

    if any_ene_hit:
        print(f"⚠  EASTNORTHEAST exact at positions 21-33: {[r['shift'] for r in any_ene_hit]}")
    else:
        print("✓  EASTNORTHEAST DOES NOT appear at positions 21-33 for ANY of 25 shifts.")

    if any_bc_anywhere:
        print(f"⚠  BERLINCLOCK appears ANYWHERE in PT: shifts {[r['shift'] for r in any_bc_anywhere]}")
    else:
        print("✓  BERLINCLOCK does not appear anywhere in any of 25 Caesar-shifted outputs.")

    print("\n── Self-encrypting position checks ──")
    for r in results:
        # CT[32]='S', CT[73]='K' — under Caesar ROT-n, PT[i] = (CT[i] - n) mod 26
        # For self-encrypting: PT[32] should equal CT[32]='S' if ROT-0 (trivial), else not
        pt32 = r["pt"][32]
        pt73 = r["pt"][73]
        if pt32 == "S" or pt73 == "K":
            print(f"  ROT{r['shift']:>2}: PT[32]={pt32} (CT[32]=S), PT[73]={pt73} (CT[73]=K)")

    print("\n── Verdict ──")
    max_crib = max(r["total"] for r in results)
    max_total = results[0]["ene_t"] + results[0]["bc_t"]
    print(f"Maximum crib matches across all 25 shifts: {max_crib}/{max_total}")
    print(f"Breakthrough threshold: {max_total}/{max_total}")
    if max_crib < max_total:
        print("\n[DERIVED FACT] Simple Caesar cipher (ROT-1 through ROT-25): ELIMINATED.")
        print("  Evidence: No shift produces both cribs correctly at their known positions.")
        print("  The crib positions are [PUBLIC FACT] — confirmed by Sanborn 2010/2025.")
        print("  This result is mathematically certain (exhaustive over 25 shifts).")
    else:
        print("\n⚠  UNEXPECTED: Some shift meets all cribs — requires investigation!")

    print()

if __name__ == "__main__":
    main()
