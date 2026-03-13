#!/usr/bin/env python3
"""
Autokey crib bridge analysis.

For Beaufort/Vig/VBeau PT autokey with primer length m:
- ENE crib at positions 21-33 forces specific PT values m positions earlier
- BERLINCLOCK crib at positions 63-73 forces specific PT values m positions earlier
- These two constraint sets must be CONSISTENT for the same key chain

Test: for each m from 1 to 96, propagate PT from both cribs and check consistency.
If m links the two constraint sets perfectly, we may have found the structure.

Also tests CT autokey and all alphabet/variant combos.
"""
import sys
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT as CT_STR, CRIB_DICT, KRYPTOS_ALPHABET as KA

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CT = [ord(c) - 65 for c in CT_STR]
N = len(CT)

ENE = "EASTNORTHEAST"
BLK = "BERLINCLOCK"
ENE_START, BLK_START = 21, 63

W_POSITIONS = [20, 36, 48, 58, 74]  # CT[i]=W at these positions

def aZ(a, s): return a.index(s)
def zA(a, i): return a[i % 26]

# ── Key stream from crib pair (CT[i], PT[i]) ────────────────────────────────
def ks_vig(alpha, ct_i, pt_i):
    """Vig: key = CT - PT"""
    return (aZ(alpha, ct_i) - aZ(alpha, pt_i)) % 26

def ks_beau(alpha, ct_i, pt_i):
    """Beaufort: key = CT + PT"""
    return (aZ(alpha, ct_i) + aZ(alpha, pt_i)) % 26

def ks_vbeau(alpha, ct_i, pt_i):
    """VBeau: key = PT - CT"""
    return (aZ(alpha, pt_i) - aZ(alpha, ct_i)) % 26

def pt_vig(alpha, key_i, ct_i):
    """Vig: PT = CT - key"""
    return zA(alpha, aZ(alpha, ct_i) - key_i)

def pt_beau(alpha, key_i, ct_i):
    """Beaufort: PT = key - CT"""
    return zA(alpha, key_i - aZ(alpha, ct_i))

def pt_vbeau(alpha, key_i, ct_i):
    """VBeau: PT = CT + key"""
    return zA(alpha, aZ(alpha, ct_i) + key_i)

VARIANTS = [
    ('AZ-Vig',   AZ, ks_vig,   pt_vig),
    ('AZ-Beau',  AZ, ks_beau,  pt_beau),
    ('AZ-VBeau', AZ, ks_vbeau, pt_vbeau),
    ('KA-Vig',   KA, ks_vig,   pt_vig),
    ('KA-Beau',  KA, ks_beau,  pt_beau),
    ('KA-VBeau', KA, ks_vbeau, pt_vbeau),
]

print("=" * 70)
print("PT AUTOKEY — ENE→BERLINCLOCK bridge analysis")
print("=" * 70)
print(f"CT: {CT_STR}")
print()

def test_pt_autokey_bridge(alpha, ks_fn, pt_fn, m):
    """
    For PT autokey with primer length m:
    - ENE at pos 21-33 forces PT[21-m : 34-m] (if all in valid range)
    - BLK at pos 63-73 forces PT[63-m : 74-m] (if all in valid range)
    Check if these two forced PT ranges are consistent (no conflicts).
    Also check W self-encrypting constraints.
    Returns (conflicts, forced_pt) where forced_pt is the partially determined PT.
    """
    forced_pt = {}  # position → letter

    # ENE constraint: PT[21+j] = ENE[j] → key[21+j] = PT[(21+j)-m] = PT[21+j-m]
    # PT[21+j-m] = ks_fn(CT_STR[21+j], ENE[j]) for each j
    for j, ene_ch in enumerate(ENE):
        pos = 21 + j  # crib position
        src_pos = pos - m  # PT position forced by autokey
        if 0 <= src_pos < N:
            key_val = ks_fn(alpha, CT_STR[pos], ene_ch)
            # key[pos] = PT[src_pos] → PT[src_pos] = key_val in index
            forced_letter = alpha[key_val]
            if src_pos in forced_pt and forced_pt[src_pos] != forced_letter:
                return None, None  # conflict from ENE alone
            forced_pt[src_pos] = forced_letter

    # BLK constraint: PT[63+j] = BLK[j] → key[63+j] = PT[63+j-m]
    for j, blk_ch in enumerate(BLK):
        pos = 63 + j
        src_pos = pos - m
        if 0 <= src_pos < N:
            key_val = ks_fn(alpha, CT_STR[pos], blk_ch)
            forced_letter = alpha[key_val]
            if src_pos in forced_pt and forced_pt[src_pos] != forced_letter:
                return None, None  # conflict between ENE and BLK
            forced_pt[src_pos] = forced_letter

    # W self-enc: for Beaufort: key[w_pos] = (W+W)%26 = 18 = S
    # key[w_pos] = PT[w_pos - m] → PT[w_pos - m] = S
    for w_pos in W_POSITIONS:
        # For Beaufort: key = CT + PT, so if CT[w_pos]=W, PT[w_pos]=W → key = W+W = 44%26 = 18 = S
        # But we need key[w_pos] = ks_fn(alpha, 'W', 'W')
        key_val = ks_fn(alpha, 'W', 'W')
        src_pos = w_pos - m
        if 0 <= src_pos < N:
            forced_letter = alpha[key_val]
            if src_pos in forced_pt and forced_pt[src_pos] != forced_letter:
                return None, None  # conflict with W constraint
            forced_pt[src_pos] = forced_letter

    return True, forced_pt

all_results = []

for vname, alpha, ks_fn, pt_fn in VARIANTS:
    for m in range(1, N):
        ok, forced = test_pt_autokey_bridge(alpha, ks_fn, pt_fn, m)
        if ok is None:
            continue

        # Count how many PT positions are forced
        n_forced = len(forced)

        # Now propagate the full PT using the forced values
        # Build the primer and propagate
        # primer[i] determines key[i] for i < m
        # For autokey: PT[i] = pt_fn(alpha, key[i], CT_STR[i])
        #   where key[i] = primer[i] (if i < m) or PT[i-m] (if i >= m)
        # But we don't have the primer; we have some PT positions fixed

        # Instead, check if the forced PT positions are self-consistent
        # when propagated through the autokey chain
        # Specifically: verify no forced position creates a conflict when
        # acting as a key m positions later

        extended_forced = dict(forced)
        converged = True
        for _ in range(3):  # propagate 3 times
            new_forced = dict(extended_forced)
            for src_pos, pt_ch in list(extended_forced.items()):
                target_pos = src_pos + m
                if target_pos < N:
                    # key[target_pos] = pt_ch → PT[target_pos] = pt_fn(alpha, key_val, CT_STR[target_pos])
                    key_val = alpha.index(pt_ch)
                    pt_val = pt_fn(alpha, key_val, CT_STR[target_pos])
                    if target_pos in new_forced and new_forced[target_pos] != pt_val:
                        converged = False
                        break
                    new_forced[target_pos] = pt_val
            if not converged:
                break
            extended_forced = new_forced

        if not converged:
            continue

        # Check cribs in extended_forced
        crib_hits = sum(1 for pos, ch in CRIB_DICT.items()
                        if pos in extended_forced and extended_forced[pos] == ch)
        w_hits = sum(1 for w_pos in W_POSITIONS
                     if w_pos in extended_forced and extended_forced[w_pos] == 'W')

        if crib_hits >= 20 or n_forced >= 20:
            all_results.append((crib_hits, w_hits, n_forced, vname, m, dict(extended_forced)))

all_results.sort(key=lambda x: (-x[0], -x[1], -x[2]))

print(f"{'Variant':<12} {'m':>3} {'Cribs':>6} {'W-hits':>7} {'Forced':>7}")
print("-" * 45)
for crib_hits, w_hits, n_forced, vname, m, ef in all_results[:30]:
    marker = " ★" if crib_hits == 24 else ""
    print(f"{vname:<12} {m:>3}  {crib_hits:>4}/24  {w_hits:>4}/5  {n_forced:>4}{marker}")

# ── Now test CT autokey ─────────────────────────────────────────────────────
print("\n\n" + "=" * 70)
print("CT AUTOKEY — bridge analysis")
print("=" * 70)

def test_ct_autokey_bridge(alpha, ks_fn, pt_fn, m):
    """For CT autokey: key[i] = primer[i] if i < m, else CT[i-m]."""
    forced_pt = {}

    # ENE: PT[21+j] = ENE[j] → (key[21+j] - CT[21+j]) = ... depends on variant
    # For Vig: PT[pos] = CT[pos] - key[pos]. With CT autokey: key[pos] = CT[pos-m].
    # So PT[pos] = CT[pos] - CT[pos-m] for pos >= m.
    # Check if this produces ENE and BLK.
    for j, ene_ch in enumerate(ENE):
        pos = 21 + j
        if pos < m:
            continue  # This position uses primer, which we don't fix
        ct_key = CT_STR[pos - m]  # key[pos] = CT[pos-m]
        key_val = alpha.index(ct_key)
        pt_val = pt_fn(alpha, key_val, CT_STR[pos])
        if pt_val != ene_ch:
            return None, None
        forced_pt[pos] = pt_val

    for j, blk_ch in enumerate(BLK):
        pos = 63 + j
        if pos < m:
            continue
        ct_key = CT_STR[pos - m]
        key_val = alpha.index(ct_key)
        pt_val = pt_fn(alpha, key_val, CT_STR[pos])
        if pt_val != blk_ch:
            return None, None
        forced_pt[pos] = pt_val

    return True, forced_pt

ct_results = []

for vname, alpha, ks_fn, pt_fn in VARIANTS:
    for m in range(1, N):
        ok, forced = test_ct_autokey_bridge(alpha, ks_fn, pt_fn, m)
        if ok is None:
            continue
        crib_hits = len(forced)
        if crib_hits >= 20:
            ct_results.append((crib_hits, vname, m, forced))

ct_results.sort(key=lambda x: -x[0])
print(f"\n{'Variant':<12} {'m':>3} {'Cribs':>6}  {'PT at known positions'}")
for crib_hits, vname, m, forced in ct_results[:20]:
    print(f"{vname:<12} {m:>3}  {crib_hits:>4}/24")
    # Reconstruct full PT for m
    _, alpha, ks_fn, pt_fn = [(n,a,ks,pt) for n,a,ks,pt in VARIANTS if n == vname][0]
    pt_out = []
    for i in range(N):
        if i < m:
            pt_out.append('?')
        else:
            ct_key = CT_STR[i - m]
            key_val = alpha.index(ct_key)
            pt_out.append(pt_fn(alpha, key_val, CT_STR[i]))
    pt_str = ''.join(pt_out)
    print(f"  PT: {pt_str[:40]}...")
    print(f"  ENE[21:34]: {pt_str[21:34]}")
    print(f"  BLK[63:74]: {pt_str[63:74]}")

print("\nDone.")
