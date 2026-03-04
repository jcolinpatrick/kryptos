#!/usr/bin/env python3
"""
Cipher: YAR grille
Family: yar
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
Test YAR-modified CT as real ciphertext (NO scrambling).
Derive key at 24 crib positions, check periodic consistency.
"""

CT_MOD = "OBKKUOXOGHULBSOLIFBBWFLJVQQPUNGKSSOTWTQSJQSSEKZZWFTJKLUDIQWINFBNRPVTTMZFPKWGDKZXTJCDIGKUHUXUEKCCD"
CT_ORI = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# Cribs (0-indexed positions in K4)
CRIBS = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]

# Build crib position list
crib_positions = []
for start, word in CRIBS:
    for i, ch in enumerate(word):
        crib_positions.append((start + i, ch))

print("=" * 70)
print("CRIB-BASED KEY RECOVERY ON YAR-MODIFIED CT")
print("=" * 70)
print(f"\nModified CT: {CT_MOD}")
print(f"Length: {len(CT_MOD)}")
print(f"\nCrib positions ({len(crib_positions)} total):")
for pos, pt in crib_positions:
    print(f"  pos {pos:2d}: CT={CT_MOD[pos]}  PT={pt}  (mod7={pos%7})")

print("\n" + "=" * 70)
print("KEY DERIVATION AT CRIB POSITIONS")
print("=" * 70)

def derive_key_vig_az(ct_ch, pt_ch):
    """Vigenère AZ: k = (CT - PT) mod 26"""
    return (AZ.index(ct_ch) - AZ.index(pt_ch)) % 26

def derive_key_beau_az(ct_ch, pt_ch):
    """Beaufort AZ: k = (CT + PT) mod 26"""
    return (AZ.index(ct_ch) + AZ.index(pt_ch)) % 26

def derive_key_varbeau_az(ct_ch, pt_ch):
    """Variant Beaufort AZ: k = (PT - CT) mod 26"""
    return (AZ.index(pt_ch) - AZ.index(ct_ch)) % 26

def derive_key_vig_ka(ct_ch, pt_ch):
    """Vigenère KA: key_az_idx = (KA.index(CT) - AZ.index(PT)) mod 26"""
    return (KA.index(ct_ch) - AZ.index(pt_ch)) % 26

def derive_key_beau_ka(ct_ch, pt_ch):
    """Beaufort KA: key_az_idx = (KA.index(CT) + AZ.index(PT)) mod 26"""
    return (KA.index(ct_ch) + AZ.index(pt_ch)) % 26

def derive_key_varbeau_ka(ct_ch, pt_ch):
    """Variant Beaufort KA: key_az_idx = (AZ.index(PT) - KA.index(CT)) mod 26"""
    return (AZ.index(pt_ch) - KA.index(ct_ch)) % 26

variants = [
    ("VIG/AZ", derive_key_vig_az),
    ("BEAU/AZ", derive_key_beau_az),
    ("VARBEAU/AZ", derive_key_varbeau_az),
    ("VIG/KA", derive_key_vig_ka),
    ("BEAU/KA", derive_key_beau_ka),
    ("VARBEAU/KA", derive_key_varbeau_ka),
]

# For each variant, derive keys and check all periods
best_results = []

for ct_label, ct_source in [("MODIFIED", CT_MOD), ("ORIGINAL", CT_ORI)]:
    print(f"\n{'='*70}")
    print(f"  CT SOURCE: {ct_label}")
    print(f"{'='*70}")

    for name, derive_fn in variants:
        # Derive key values at crib positions
        keys = []
        for pos, pt in crib_positions:
            k = derive_fn(ct_source[pos], pt)
            keys.append((pos, k, AZ[k]))

        print(f"\n--- {name} on {ct_label} ---")
        print("  Pos  CT  PT  Key#  KeyLtr  mod7")
        for pos, k, kl in keys:
            pt = [p for p2, p in crib_positions if p2 == pos][0]
            print(f"  {pos:3d}   {ct_source[pos]}   {pt}    {k:2d}     {kl}      {pos%7}")

        # Check consistency at each period
        print(f"\n  Period consistency (how many crib pairs in same residue class agree):")
        best_period = 0
        best_score = -1

        for period in range(2, 27):
            # Group by residue
            residues = {}
            for pos, k, kl in keys:
                r = pos % period
                if r not in residues:
                    residues[r] = []
                residues[r].append((pos, k))

            # Count agreements: for each residue class with >1 entry,
            # find the most common key value and count matches
            total_constrained = 0
            total_agree = 0
            for r, entries in residues.items():
                if len(entries) > 1:
                    total_constrained += len(entries)
                    # Most common key in this residue
                    from collections import Counter
                    counts = Counter(k for _, k in entries)
                    best_k, best_count = counts.most_common(1)[0]
                    total_agree += best_count

            score = total_agree
            if score > best_score:
                best_score = score
                best_period = period

            if period <= 14 or score >= best_score:
                pct = (total_agree / total_constrained * 100) if total_constrained > 0 else 0
                flag = " <<<" if score == best_score and period == best_period else ""
                if period <= 14 or flag:
                    print(f"    p={period:2d}: {total_agree}/{total_constrained} agree ({pct:5.1f}%){flag}")

        # Show period 7 detail
        print(f"\n  === PERIOD 7 DETAIL ===")
        residues7 = {}
        for pos, k, kl in keys:
            r = pos % 7
            if r not in residues7:
                residues7[r] = []
            residues7[r].append((pos, k, kl))

        all_agree = True
        key7 = [None] * 7
        for r in sorted(residues7.keys()):
            entries = residues7[r]
            key_vals = set(k for _, k, _ in entries)
            agree = "AGREE" if len(key_vals) == 1 else "CONFLICT"
            if len(key_vals) > 1:
                all_agree = False
            detail = ", ".join(f"pos{p}={kl}({k})" for p, k, kl in entries)
            print(f"    col {r}: {agree:8s}  {detail}")
            if len(key_vals) == 1:
                key7[r] = entries[0][1]

        if all_agree:
            keyword = "".join(AZ[k] if k is not None else "?" for k in key7)
            print(f"\n  *** PERIOD 7 FULLY CONSISTENT! Key = {keyword} ***")

            # Decrypt full CT with this key
            if "KA" in name:
                if "VIG" in name and "VAR" not in name:
                    pt = ""
                    for i, c in enumerate(ct_source):
                        ki = key7[i % 7]
                        # CT = KA[(ki + AZ.index(PT)) % 26] → PT = AZ[(KA.index(CT) - ki) % 26]
                        pt += AZ[(KA.index(c) - ki) % 26]
                elif "BEAU" in name and "VAR" not in name:
                    pt = ""
                    for i, c in enumerate(ct_source):
                        ki = key7[i % 7]
                        pt += AZ[(ki - KA.index(c)) % 26]
                else:  # VARBEAU
                    pt = ""
                    for i, c in enumerate(ct_source):
                        ki = key7[i % 7]
                        pt += AZ[(KA.index(c) + ki) % 26]
            else:  # AZ
                if "VIG" in name and "VAR" not in name:
                    pt = ""
                    for i, c in enumerate(ct_source):
                        ki = key7[i % 7]
                        pt += AZ[(AZ.index(c) - ki) % 26]
                elif "BEAU" in name and "VAR" not in name:
                    pt = ""
                    for i, c in enumerate(ct_source):
                        ki = key7[i % 7]
                        pt += AZ[(ki - AZ.index(c)) % 26]
                else:  # VARBEAU
                    pt = ""
                    for i, c in enumerate(ct_source):
                        ki = key7[i % 7]
                        pt += AZ[(AZ.index(c) + ki) % 26]

            print(f"  Plaintext: {pt}")

            # Check for English words
            words_found = []
            for wlen in range(7, 3, -1):
                for start in range(len(pt) - wlen + 1):
                    chunk = pt[start:start+wlen].lower()
                    # Quick common word check
                    common = ["the", "and", "that", "with", "this", "from", "have", "they",
                              "been", "said", "each", "which", "their", "will", "other",
                              "about", "many", "then", "them", "would", "make", "like",
                              "just", "over", "such", "after", "year", "also", "back",
                              "could", "into", "only", "come", "made", "find", "here",
                              "thing", "give", "most", "east", "north", "west", "south",
                              "clock", "berlin", "under", "ground", "slowly", "light",
                              "between", "tunnel", "layer", "secret", "hidden", "ancient",
                              "wonderful", "things", "yes"]
                    if chunk in common:
                        words_found.append((start, chunk))
            if words_found:
                print(f"  Words found: {words_found}")

            best_results.append((name, ct_label, keyword, pt))

        # Also check period 8 (ABSCISSA length)
        print(f"\n  === PERIOD 8 DETAIL ===")
        residues8 = {}
        for pos, k, kl in keys:
            r = pos % 8
            if r not in residues8:
                residues8[r] = []
            residues8[r].append((pos, k, kl))

        all_agree8 = True
        for r in sorted(residues8.keys()):
            entries = residues8[r]
            key_vals = set(k for _, k, _ in entries)
            agree = "AGREE" if len(key_vals) == 1 else "CONFLICT"
            if len(key_vals) > 1:
                all_agree8 = False
            detail = ", ".join(f"pos{p}={kl}({k})" for p, k, kl in entries)
            print(f"    col {r}: {agree:8s}  {detail}")

# Bean constraint check
print("\n" + "=" * 70)
print("BEAN CONSTRAINT CHECK")
print("=" * 70)
print(f"\nBean EQ: CT[27]=CT[65] must hold (both should be same letter)")
print(f"  Original: CT[27]={CT_ORI[27]}, CT[65]={CT_ORI[65]}  {'PASS' if CT_ORI[27]==CT_ORI[65] else 'FAIL'}")
print(f"  Modified: CT[27]={CT_MOD[27]}, CT[65]={CT_MOD[65]}  {'PASS' if CT_MOD[27]==CT_MOD[65] else 'FAIL'}")

# Changes between original and modified
print("\n" + "=" * 70)
print("POSITION CHANGES (ORIGINAL → MODIFIED)")
print("=" * 70)
for i in range(97):
    if CT_ORI[i] != CT_MOD[i]:
        in_crib = any(start <= i <= start + len(word) - 1 for start, word in CRIBS)
        print(f"  pos {i:2d}: {CT_ORI[i]}→{CT_MOD[i]}  mod7={i%7}  {'IN CRIB' if in_crib else ''}")

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
if best_results:
    print("\nFULLY CONSISTENT PERIOD-7 RESULTS:")
    for name, ct_label, keyword, pt in best_results:
        print(f"\n  {name} on {ct_label}")
        print(f"  Key: {keyword}")
        print(f"  PT:  {pt}")
else:
    print("\nNo variant produced a fully consistent period-7 key.")
    print("Checking which variant comes closest...")

    # Find closest
    for ct_label, ct_source in [("MODIFIED", CT_MOD)]:
        for name, derive_fn in variants:
            keys = [(pos, derive_fn(ct_source[pos], pt)) for pos, pt in crib_positions]
            residues7 = {}
            for pos, k in keys:
                r = pos % 7
                if r not in residues7:
                    residues7[r] = []
                residues7[r].append(k)

            conflicts = 0
            total_entries = 0
            for r in range(7):
                if r in residues7 and len(residues7[r]) > 1:
                    vals = set(residues7[r])
                    if len(vals) > 1:
                        conflicts += len(residues7[r]) - max(Counter(residues7[r]).values())
                    total_entries += len(residues7[r])

            from collections import Counter
            print(f"  {name}: {conflicts} conflicts out of {total_entries} constrained positions")
