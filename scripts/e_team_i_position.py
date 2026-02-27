#!/usr/bin/env python3
"""
E-TEAM-I-POSITION: What does "I" at each unknown position tell us?

If K4 is a first-person response to K3's "Can you see anything?",
the standalone word "I" likely appears somewhere. For each possible
position, compute the implied key value under all three cipher
variants and check for matches against the 24 known key values.

A match implies a periodic relationship. Cross-reference with the
Bean-surviving periods {8, 13, 16, 19, 20, 23, 24, 26} to find
positions where "I" would be consistent with a viable period.

Usage: PYTHONPATH=src python3 -u scripts/e_team_i_position.py
"""

import sys, os
from math import gcd
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src'))
from kryptos.kernel.constants import (
    CT, VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)

CT_STR = CT
I_VAL = ord('I') - 65  # = 8

# Known key values at crib positions
# Vigenère: K = (CT - PT) mod 26
VIG_KEYS = {}
for offset, kval in enumerate(VIGENERE_KEY_ENE):
    VIG_KEYS[21 + offset] = kval
for offset, kval in enumerate(VIGENERE_KEY_BC):
    VIG_KEYS[63 + offset] = kval

# Beaufort: K = (CT + PT) mod 26
BEAU_KEYS = {}
for offset, kval in enumerate(BEAUFORT_KEY_ENE):
    BEAU_KEYS[21 + offset] = kval
for offset, kval in enumerate(BEAUFORT_KEY_BC):
    BEAU_KEYS[63 + offset] = kval

# Variant Beaufort: K = (PT - CT) mod 26
VARBEAU_KEYS = {}
for offset, kval in enumerate(VIGENERE_KEY_ENE):
    VARBEAU_KEYS[21 + offset] = (26 - kval) % 26  # negate Vig key
for offset, kval in enumerate(VIGENERE_KEY_BC):
    VARBEAU_KEYS[63 + offset] = (26 - kval) % 26

# Bean-surviving periods (from E-FRAC-35)
BEAN_PERIODS = {8, 13, 16, 19, 20, 23, 24, 26}

# All eliminated periods (E-FRAC-35 + E-AUDIT-01)
# Periods 2-7: Bean-impossible for periodic key
# Periods 8+: underdetermined but Bean-compatible
# ALL periods 2-26 eliminated by full pairwise constraints (E-AUDIT-01)
# But that assumes PERIODIC key — running key or procedural survives
PERIODIC_ELIMINATED = set(range(2, 27))

# Unknown position ranges
UNKNOWN_RANGES = list(range(0, 21)) + list(range(34, 63)) + list(range(74, 97))


def compute_key_at_pos(pos, pt_val, mode):
    """Compute key value at position given plaintext value."""
    ct_val = ord(CT_STR[pos]) - 65
    if mode == 'vig':
        return (ct_val - pt_val) % 26
    elif mode == 'beau':
        return (ct_val + pt_val) % 26
    elif mode == 'varbeau':
        return (pt_val - ct_val) % 26


def find_period_matches(pos, key_val, known_keys):
    """Find all known key positions with the same key value.
    Returns list of (matching_pos, implied_gcd_period)."""
    matches = []
    for kpos, kval in known_keys.items():
        if kval == key_val:
            diff = abs(pos - kpos)
            if diff > 0:
                matches.append((kpos, diff))
    return matches


def compute_consistent_periods(matches):
    """Given a list of (pos, diff) matches, find periods consistent with ALL."""
    if not matches:
        return set()
    diffs = [d for _, d in matches]
    g = diffs[0]
    for d in diffs[1:]:
        g = gcd(g, d)
    # All divisors of g that are >= 2
    periods = set()
    for p in range(2, g + 1):
        if g % p == 0:
            periods.add(p)
    return periods


def main():
    print("K4 'I' POSITION ANALYSIS")
    print("=" * 90)
    print(f"CT: {CT_STR}")
    print(f"\nAssumption: PT contains standalone word 'I' (PT[pos] = I = {I_VAL})")
    print(f"Known key values at 24 crib positions (21-33, 63-73)")
    print(f"Bean-surviving periods: {sorted(BEAN_PERIODS)}")
    print()

    # Show known key values for reference
    print("KNOWN KEY VALUES (Vigenère):")
    print("  Pos: ", end="")
    for p in sorted(VIG_KEYS):
        print(f"{p:3d}", end="")
    print()
    print("  Key: ", end="")
    for p in sorted(VIG_KEYS):
        print(f"  {chr(VIG_KEYS[p]+65)}", end="")
    print()
    print("  Val: ", end="")
    for p in sorted(VIG_KEYS):
        print(f"{VIG_KEYS[p]:3d}", end="")
    print("\n")

    # Reverse lookup: which key values appear, and at which positions
    val_to_pos_vig = defaultdict(list)
    for p, v in VIG_KEYS.items():
        val_to_pos_vig[v].append(p)

    print("KEY VALUE FREQUENCY (Vigenère):")
    for v in sorted(val_to_pos_vig.keys()):
        positions = val_to_pos_vig[v]
        print(f"  {chr(v+65)} ({v:2d}): appears at {positions} ({len(positions)}x)")
    print()

    # ── Main calculation ────────────────────────────────────────────
    for mode_name, mode_key, known_keys in [
        ("VIGENÈRE", "vig", VIG_KEYS),
        ("BEAUFORT", "beau", BEAU_KEYS),
        ("VAR.BEAUFORT", "varbeau", VARBEAU_KEYS),
    ]:
        print(f"\n{'='*90}")
        print(f"  [{mode_name}] — If PT[i] = 'I', what is K[i]?")
        print(f"{'='*90}")

        # Reverse lookup for this mode
        val_to_pos = defaultdict(list)
        for p, v in known_keys.items():
            val_to_pos[v].append(p)

        interesting = []

        for pos in UNKNOWN_RANGES:
            ct_char = CT_STR[pos]
            ct_val = ord(ct_char) - 65
            k_val = compute_key_at_pos(pos, I_VAL, mode_key)
            k_char = chr(k_val + 65)

            # Check matches
            matches = find_period_matches(pos, k_val, known_keys)
            consistent_periods = compute_consistent_periods(matches)
            bean_compatible = consistent_periods & BEAN_PERIODS

            # Self-encrypting?
            self_enc = (ct_val == I_VAL)  # CT[pos] == 'I' and PT[pos] == 'I'

            if matches:
                n_matches = len(matches)
                match_positions = [m[0] for m in matches]
                match_diffs = [m[1] for m in matches]

                tag = ""
                if self_enc:
                    tag = " *** SELF-ENCRYPTING (K=A) ***"
                elif bean_compatible:
                    tag = f" *** BEAN-COMPATIBLE PERIODS: {sorted(bean_compatible)} ***"
                elif n_matches >= 2:
                    tag = f" (multi-match, consistent p divides {gcd(*match_diffs) if len(match_diffs)>1 else match_diffs[0]})"

                interesting.append((pos, k_char, k_val, matches, consistent_periods,
                                   bean_compatible, self_enc, ct_char))

        # Print all unknown positions with their key values
        print(f"\n  {'Pos':>3s}  CT  K  {'KVal':>4s}  {'Matches with known keys':40s}  Notes")
        print(f"  {'—'*3}  ——  —  {'—'*4}  {'—'*40}  {'—'*30}")

        for pos in UNKNOWN_RANGES:
            ct_char = CT_STR[pos]
            ct_val = ord(ct_char) - 65
            k_val = compute_key_at_pos(pos, I_VAL, mode_key)
            k_char = chr(k_val + 65)

            matches = find_period_matches(pos, k_val, known_keys)
            self_enc = (ct_val == I_VAL)

            match_str = ""
            note = ""
            if self_enc:
                match_str = f"K=A (key=0)"
                note = "SELF-ENCRYPTING"
            elif matches:
                parts = []
                for mpos, mdiff in matches:
                    parts.append(f"K[{mpos}]={k_char}(Δ{mdiff})")
                match_str = ", ".join(parts)

                consistent_p = compute_consistent_periods(matches)
                bean_p = consistent_p & BEAN_PERIODS
                if bean_p:
                    note = f"Bean-OK periods: {sorted(bean_p)}"
                elif consistent_p:
                    note = f"periods: {sorted(consistent_p)}"

            # Mark likely positions for standalone "I"
            pos_marker = ""
            if pos in [0, 3, 4, 5, 6, 7, 8, 9]:
                pos_marker = "← early (likely I position)"

            print(f"  {pos:3d}  {ct_char}   {k_char}  {k_val:4d}  {match_str:40s}  {note}  {pos_marker}")

        # ── Highlight most interesting positions ────────────────────
        print(f"\n  MOST INTERESTING POSITIONS [{mode_name}]:")

        # Positions with Bean-compatible period matches
        bean_hits = [(p, k, kv, m, cp, bp, se, cc) for p, k, kv, m, cp, bp, se, cc
                     in interesting if bp and not se]
        if bean_hits:
            print(f"\n  Positions where I→key matches crib key at Bean-compatible period:")
            for pos, kc, kv, matches, cp, bp, se, cc in bean_hits:
                match_detail = ", ".join(f"K[{mp}]={kc} (Δ{md})" for mp, md in matches)
                print(f"    Pos {pos:2d}: CT={cc} → K={kc}({kv:2d})  {match_detail}")
                print(f"           Bean-compatible periods: {sorted(bp)}")
                # Check: what other crib positions share this residue class?
                for period in sorted(bp):
                    residue = pos % period
                    same_class = [p for p in known_keys if p % period == residue]
                    class_vals = [known_keys[p] for p in same_class]
                    all_match = all(v == kv for v in class_vals)
                    print(f"           Period {period}: residue {residue}, "
                          f"crib positions in class: {same_class}, "
                          f"their keys: {[chr(v+65) for v in class_vals]}, "
                          f"all={kc}? {'YES ✓' if all_match else 'NO ✗'}")

        # Positions with multiple matches (high constraint)
        multi = [(p, k, kv, m, cp, bp, se, cc) for p, k, kv, m, cp, bp, se, cc
                 in interesting if len(m) >= 2 and not se]
        if multi:
            print(f"\n  Positions where I→key matches MULTIPLE crib keys:")
            for pos, kc, kv, matches, cp, bp, se, cc in multi:
                match_detail = ", ".join(f"K[{mp}]={kc}(Δ{md})" for mp, md in matches)
                print(f"    Pos {pos:2d}: CT={cc} → K={kc}({kv:2d})  {match_detail}")

        # Self-encrypting positions
        se_hits = [(p, k, kv, m, cp, bp, se, cc) for p, k, kv, m, cp, bp, se, cc
                   in interesting if se]
        if se_hits:
            print(f"\n  Self-encrypting positions (CT=I=PT, key=A=0):")
            for pos, kc, kv, matches, cp, bp, se, cc in se_hits:
                print(f"    Pos {pos:2d}: CT=I, PT=I, K=A(0)")
                # Check relationship with other K=A positions
                other_a = [p for p, v in known_keys.items() if v == 0]
                if other_a:
                    diffs = [abs(pos - p) for p in other_a]
                    g = diffs[0]
                    for d in diffs[1:]:
                        g = gcd(g, d)
                    print(f"           Other K=A positions: {other_a}")
                    print(f"           Diffs: {diffs}, GCD={g}")
                    bp2 = {p for p in range(2, g+1) if g % p == 0} & BEAN_PERIODS
                    if bp2:
                        print(f"           Bean-compatible periods: {sorted(bp2)}")

    # ── Cross-variant synthesis ─────────────────────────────────────
    print(f"\n\n{'='*90}")
    print("CROSS-VARIANT SYNTHESIS: Best positions for standalone 'I'")
    print(f"{'='*90}")

    # For each position in 0-20 (most likely for a first-person opening),
    # show what ALL THREE variants say
    print(f"\n  Positions 0-20 (pre-ENE, first-person opening):")
    print(f"  {'Pos':>3s}  CT  {'Vig':>4s}  {'Beau':>4s}  {'VarB':>4s}  "
          f"{'Vig matches':>25s}  {'Beau matches':>25s}  {'VarB matches':>25s}")
    print(f"  {'—'*3}  ——  {'—'*4}  {'—'*4}  {'—'*4}  {'—'*25}  {'—'*25}  {'—'*25}")

    for pos in range(21):
        ct_char = CT_STR[pos]
        results = []
        for mode_key, known in [('vig', VIG_KEYS), ('beau', BEAU_KEYS), ('varbeau', VARBEAU_KEYS)]:
            kv = compute_key_at_pos(pos, I_VAL, mode_key)
            kc = chr(kv + 65)
            matches = find_period_matches(pos, kv, known)
            match_str = ",".join(f"{mp}" for mp, _ in matches) if matches else "-"
            results.append((kc, kv, match_str))

        print(f"  {pos:3d}  {ct_char}   {results[0][0]:>3s}  {results[1][0]:>3s}  {results[2][0]:>3s}  "
              f"{results[0][2]:>25s}  {results[1][2]:>25s}  {results[2][2]:>25s}")

    # ── Most likely "I" positions in first-person response ──────────
    print(f"\n\n{'='*90}")
    print("NARRATIVE-CONSTRAINED 'I' POSITIONS")
    print(f"{'='*90}")
    print("""
  If K4 begins with a first-person response to "Can you see anything?":

  Position 0: "I CAN SEE..." / "I COULD SEE..." / "I SAW..." / "I PEERED..."
  Position 3: "YES I CAN..." / "YES I SAW..."
  Position 4: "THEN I SAW..." / "WHAT I SAW..."
  Position 6: "SLOWLY I SAW..." / "BEYOND I SAW..."
  Position 7: "THROUGH I COULD..."

  The MOST LIKELY position is 0 (direct first-person answer).
  Second most likely: 3-4 (after "YES" or "WHAT/THEN").
""")

    # Deep analysis of position 0
    print("  DEEP ANALYSIS: PT[0] = 'I' (position 0)")
    print("  " + "—" * 60)
    for mode_name, mode_key, known_keys in [
        ("Vigenère", "vig", VIG_KEYS),
        ("Beaufort", "beau", BEAU_KEYS),
        ("Var.Beaufort", "varbeau", VARBEAU_KEYS),
    ]:
        kv = compute_key_at_pos(0, I_VAL, mode_key)
        kc = chr(kv + 65)
        matches = find_period_matches(0, kv, known_keys)

        print(f"\n  [{mode_name}] K[0] = {kc} ({kv})")
        if matches:
            for mpos, mdiff in matches:
                mk = chr(known_keys[mpos] + 65)
                print(f"    Matches K[{mpos}] = {mk} ({known_keys[mpos]}), Δ = {mdiff}")

                # What periods divide this diff?
                divs = [d for d in range(2, mdiff + 1) if mdiff % d == 0]
                bean_divs = [d for d in divs if d in BEAN_PERIODS]
                if bean_divs:
                    print(f"    → Bean-compatible periods that divide {mdiff}: {bean_divs}")
                else:
                    print(f"    → Divisors of {mdiff}: {divs[:10]}{'...' if len(divs)>10 else ''}")
                    print(f"    → None are Bean-compatible")
        else:
            print(f"    No matches with any known key value")
            print(f"    → K[0]={kc} is a NEW key value not seen at any crib position")
            print(f"    → Rules out all periods p where any crib pos ≡ 0 (mod p) has K≠{kc}")
            # Which periods does this eliminate?
            for period in sorted(BEAN_PERIODS):
                residue = 0 % period  # = 0
                same_class = [p for p in known_keys if p % period == 0]
                if same_class:
                    class_vals = set(known_keys[p] for p in same_class)
                    if kv not in class_vals:
                        print(f"       Period {period}: crib pos {same_class} have keys "
                              f"{[chr(v+65) for v in sorted(class_vals)]}, not {kc} → ELIMINATES p={period}")
                    else:
                        match_pos = [p for p in same_class if known_keys[p] == kv]
                        print(f"       Period {period}: matches K[{match_pos}]={kc} → COMPATIBLE with p={period}")

    # Also check position 16 (self-encrypting I)
    print(f"\n\n  SPECIAL CASE: PT[16] = 'I' (self-encrypting, CT[16] = I)")
    print("  " + "—" * 60)
    print(f"  CT[16] = I, so if PT[16] = I: K[16] = 0 = A")
    print(f"  Known K=A positions: 32 (S→S), 73 (K→K)")
    print(f"  Gaps: |16-32|=16, |16-73|=57, |32-73|=41")
    print(f"  GCD(16, 57, 41) = {gcd(gcd(16, 57), 41)}")
    g = gcd(gcd(16, 57), 41)
    bean_g = [p for p in range(2, g+1) if g % p == 0 and p in BEAN_PERIODS]
    print(f"  Bean-compatible divisors: {bean_g if bean_g else 'NONE'}")
    print(f"  → Three K=A positions at {16, 32, 73} have GCD=1")
    print(f"  → No periodic key can have K=A at all three positions")
    print(f"  → EITHER: (a) not all three are K=A (I is not at pos 16),")
    print(f"            (b) the key is non-periodic (running key, procedural),")
    print(f"            (c) there is a transposition layer")


if __name__ == '__main__':
    main()
