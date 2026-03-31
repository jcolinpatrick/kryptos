#!/usr/bin/env python3
"""
E-K0-MASK-WRAP: Test null masks from K0 Morse with "wrapping underneath" variants.

Sanborn told Dunin the Morse code "continues under the rock." This means the
visible K0 text may be INCOMPLETE. Hidden characters change the E-group structure
and thus the run-length null mask.

Tests:
  1. Cyclic wrap: connect end→beginning (RQ→ee)
  2. Known missing: add "WHA" before "T IS YOUR POSITION" → "WHAT IS YOUR POSITION"
  3. Hidden E's: add 1-5 hidden E's at various positions (end, beginning, between panels)
  4. Hidden message chars: add 1-20 hidden non-E chars at various positions
  5. Brute-force: try all hidden suffixes of length 1-8 (E or non-E) appended
     to the visible text, and check which produce clean 24-null masks

For each variant, run the run-length mapping at all 97 offsets and check for
crib-clean masks. Score clean masks through the cipher pipeline.

Cipher: k0-mask-wrap
Family: grille
Status: active
Keyspace: ~500K variants
Last run: never
Best score: n/a
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys, os
from itertools import product
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CRIB_DICT

# --- K0 visible text ---
K0_VISIBLE = "eeVIRTUALLYeeeeeINVISIBLEeDIGETALeeeINTERPRETATIUeeSHADOWeeFORCESeeeee" \
             "LUCIDeeeMEMORYeTISYOURPOSITIONeSOS" \
             "RQ"

# Alternate with LUCID → fix
K0_VIS_ALT = K0_VISIBLE  # same for now

CRIB_SET = set(range(21, 34)) | set(range(63, 74))
assert len(CRIB_SET) == 24

# --- Helpers ---
def get_e_groups(text):
    groups = []
    i = 0
    while i < len(text):
        if text[i] == 'e':
            start = i
            while i < len(text) and text[i] == 'e':
                i += 1
            groups.append(i - start)
        else:
            i += 1
    return groups

def get_inter_group_msg(text):
    """Get message-letter counts between E-groups."""
    counts = []
    i = 0
    in_e = False
    msg_count = 0
    started = False
    while i < len(text):
        if text[i] == 'e':
            if not in_e and started:
                counts.append(msg_count)
                msg_count = 0
            in_e = True
            started = True
        else:
            in_e = False
            if started:
                msg_count += 1
        i += 1
    # Trailing message chars after last E-group
    if msg_count > 0:
        counts.append(msg_count)
    return counts

def runlength_mask(e_groups, inter_msg, start, n_ct=97):
    """Generate null positions from run-length pattern starting at offset."""
    nulls = []
    pos = start
    for gi in range(len(e_groups)):
        for _ in range(e_groups[gi]):
            nulls.append(pos % n_ct)
            pos += 1
        if gi < len(inter_msg):
            pos += inter_msg[gi]
    return nulls

def check_clean(nulls, need=24):
    """Check if first `need` unique null positions avoid all crib positions."""
    unique = list(dict.fromkeys(nulls))
    if len(unique) < need:
        return None
    mask = unique[:need]
    if set(mask) & CRIB_SET:
        return None
    return mask

def extract_ct(null_pos):
    ns = set(null_pos)
    return "".join(c for i, c in enumerate(CT) if i not in ns)

def remap_cribs(null_pos):
    ns = set(null_pos)
    cribs = {}
    new_idx = 0
    for i in range(len(CT)):
        if i not in ns:
            if i in CRIB_DICT:
                cribs[new_idx] = CRIB_DICT[i]
            new_idx += 1
    return cribs

# --- Cipher implementations (compact) ---
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

def vig(ct, key, a): return "".join(a[(a.index(c) - a.index(key[i%len(key)])) % 26] for i, c in enumerate(ct))
def beau(ct, key, a): return "".join(a[(a.index(key[i%len(key)]) - a.index(c)) % 26] for i, c in enumerate(ct))
def avig(ct, key, a):
    pt, fk = [], list(key)
    for i, c in enumerate(ct):
        p = (a.index(c) - a.index(fk[i])) % 26
        pt.append(a[p]); fk.append(a[p])
    return "".join(pt)
def abeau(ct, key, a):
    pt, fk = [], list(key)
    for i, c in enumerate(ct):
        p = (a.index(fk[i]) - a.index(c)) % 26
        pt.append(a[p]); fk.append(a[p])
    return "".join(pt)

def col_undo(ct, w):
    n = len(ct); rows = -(-n // w); rem = n % w
    r = [''] * n; pos = 0
    for c in range(w):
        cl = rows if (rem == 0 or c < rem) else rows - 1
        for row in range(cl):
            r[row * w + c] = ct[pos]; pos += 1
    return "".join(r)

def score(pt, cribs):
    s = sorted(cribs.keys())
    ene_p, bc_p = s[:13], s[13:]
    ene = sum(1 for p in ene_p if p < len(pt) and pt[p] == cribs[p])
    bc = sum(1 for p in bc_p if p < len(pt) and pt[p] == cribs[p])
    return ene + bc, ene, bc

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "KOMPASS",
            "COLOPHON", "SHADOW", "LUCID", "INVISIBLE", "POSITION",
            "DIGETAL", "BERLINCLOCK", "LAYERTWO", "NORTHEAST", "COMPASS"]

CIPHERS = [
    ("vig_AZ", vig, AZ), ("beau_AZ", beau, AZ),
    ("vig_KA", vig, KA), ("beau_KA", beau, KA),
    ("avig_AZ", avig, AZ), ("abeau_AZ", abeau, AZ),
    ("avig_KA", avig, KA), ("abeau_KA", abeau, KA),
]

TRANS = [
    ("none", lambda ct: ct),
    ("col7", lambda ct: col_undo(ct, 7)),
    ("col9", lambda ct: col_undo(ct, 9)),
    ("col10", lambda ct: col_undo(ct, 10)),
]

def score_mask(null_pos):
    """Score a mask through the full pipeline. Return best result."""
    ect = extract_ct(null_pos)
    cribs = remap_cribs(null_pos)
    if len(ect) != 73 or len(cribs) != 24:
        return 0, "", ""
    best = (0, "", "")
    for tn, tf in TRANS:
        wct = tf(ect)
        for kw in KEYWORDS:
            for cn, cf, alpha in CIPHERS:
                try:
                    pt = cf(wct, kw, alpha)
                except:
                    continue
                s, ene, bc = score(pt, cribs)
                if s > best[0]:
                    best = (s, f"{kw}:{cn}+{tn}", pt[:50])
    return best


def main():
    print("=" * 70)
    print("K0 MORSE NULL MASK — WRAP-AROUND SEARCH")
    print("=" * 70)

    visible_e = sum(1 for c in K0_VISIBLE if c == 'e')
    visible_msg = sum(1 for c in K0_VISIBLE if c != 'e')
    print(f"Visible K0: {len(K0_VISIBLE)} chars ({visible_e} E's, {visible_msg} message)")
    print(f"Visible E-groups: {get_e_groups(K0_VISIBLE)}")
    print()

    all_clean = []

    # === TEST 1: Cyclic wrap (treat as loop) ===
    print("[1] CYCLIC WRAP (connect RQ→ee at beginning)...")
    # Double the text and look for patterns
    cyclic = K0_VISIBLE + K0_VISIBLE
    e_groups = get_e_groups(K0_VISIBLE)
    inter_msg = get_inter_group_msg(K0_VISIBLE)
    # Add the wrap-around gap: from last E to first E through the seam
    # Last E is at some position, then SOSRQ (5 chars) before wrapping to ee
    print(f"  E-groups: {e_groups}")
    print(f"  Inter-group msg: {inter_msg}")
    clean = 0
    for start in range(97):
        nulls = runlength_mask(e_groups, inter_msg, start)
        mask = check_clean(nulls, 24)
        if mask:
            clean += 1
            all_clean.append(("cyclic", start, sorted(mask)))
    print(f"  Clean masks: {clean}/97")

    # === TEST 2: Add "WHA" prefix → "WHAT IS YOUR POSITION" ===
    print("\n[2] ADD 'WHA' PREFIX (hidden under rock)...")
    # Insert WHA before TISYOURPOSITION
    k0_wha = K0_VISIBLE.replace("TISYOURPOSITION", "WHATISYOURPOSITION")
    e_groups2 = get_e_groups(k0_wha)
    inter_msg2 = get_inter_group_msg(k0_wha)
    n_e2 = sum(1 for c in k0_wha if c == 'e')
    print(f"  Modified K0: {len(k0_wha)} chars, {n_e2} E's")
    print(f"  E-groups: {e_groups2}")
    print(f"  Inter-group msg: {inter_msg2}")
    clean = 0
    for start in range(97):
        nulls = runlength_mask(e_groups2, inter_msg2, start)
        mask = check_clean(nulls, 24)
        if mask:
            clean += 1
            all_clean.append(("wha_prefix", start, sorted(mask)))
    print(f"  Clean masks: {clean}/97")

    # === TEST 3: Hidden E's appended (1-5 extra E's at end) ===
    print("\n[3] HIDDEN E's APPENDED (1-5 extra at end, under rock)...")
    for n_extra in range(1, 6):
        k0_ext = K0_VISIBLE + "e" * n_extra
        eg = get_e_groups(k0_ext)
        im = get_inter_group_msg(k0_ext)
        n_e = sum(1 for c in k0_ext if c == 'e')
        clean = 0
        for start in range(97):
            nulls = runlength_mask(eg, im, start)
            mask = check_clean(nulls, 24)
            if mask:
                clean += 1
                all_clean.append((f"append_{n_extra}e", start, sorted(mask)))
        print(f"  +{n_extra} E's: total {n_e} E's, groups={eg}, clean={clean}/97")

    # === TEST 4: Hidden message chars appended ===
    print("\n[4] HIDDEN MESSAGE CHARS APPENDED (1-15 non-E chars)...")
    for n_extra in range(1, 16):
        k0_ext = K0_VISIBLE + "X" * n_extra
        eg = get_e_groups(k0_ext)
        im = get_inter_group_msg(k0_ext)
        clean = 0
        for start in range(97):
            nulls = runlength_mask(eg, im, start)
            mask = check_clean(nulls, 24)
            if mask:
                clean += 1
                all_clean.append((f"append_{n_extra}msg", start, sorted(mask)))
        if clean > 0:
            print(f"  +{n_extra} msg chars: clean={clean}/97")

    # === TEST 5: Mixed hidden suffix (E's and non-E's) ===
    print("\n[5] BRUTE-FORCE HIDDEN SUFFIX (length 1-6, E/non-E combos)...")
    for suffix_len in range(1, 7):
        clean_count = 0
        for bits in product([0, 1], repeat=suffix_len):
            suffix = "".join("e" if b else "X" for b in bits)
            k0_ext = K0_VISIBLE + suffix
            eg = get_e_groups(k0_ext)
            im = get_inter_group_msg(k0_ext)
            n_e = sum(eg)
            for start in range(97):
                nulls = runlength_mask(eg, im, start)
                mask = check_clean(nulls, 24)
                if mask:
                    clean_count += 1
                    if clean_count <= 50:
                        all_clean.append((f"suffix_{suffix}", start, sorted(mask)))
        print(f"  len={suffix_len}: {2**suffix_len} suffixes × 97 offsets, clean={clean_count}")

    # === TEST 6: Hidden PREFIX (before visible text) ===
    print("\n[6] BRUTE-FORCE HIDDEN PREFIX (length 1-6, E/non-E combos)...")
    for prefix_len in range(1, 7):
        clean_count = 0
        for bits in product([0, 1], repeat=prefix_len):
            prefix = "".join("e" if b else "X" for b in bits)
            k0_ext = prefix + K0_VISIBLE
            eg = get_e_groups(k0_ext)
            im = get_inter_group_msg(k0_ext)
            for start in range(97):
                nulls = runlength_mask(eg, im, start)
                mask = check_clean(nulls, 24)
                if mask:
                    clean_count += 1
                    if clean_count <= 50:
                        all_clean.append((f"prefix_{prefix}", start, sorted(mask)))
        print(f"  len={prefix_len}: {2**prefix_len} prefixes × 97 offsets, clean={clean_count}")

    # === TEST 7: WHA prefix + hidden suffix combos ===
    print("\n[7] WHA PREFIX + HIDDEN SUFFIX (length 1-4)...")
    k0_wha_base = K0_VISIBLE.replace("TISYOURPOSITION", "WHATISYOURPOSITION")
    for suffix_len in range(1, 5):
        clean_count = 0
        for bits in product([0, 1], repeat=suffix_len):
            suffix = "".join("e" if b else "X" for b in bits)
            k0_ext = k0_wha_base + suffix
            eg = get_e_groups(k0_ext)
            im = get_inter_group_msg(k0_ext)
            for start in range(97):
                nulls = runlength_mask(eg, im, start)
                mask = check_clean(nulls, 24)
                if mask:
                    clean_count += 1
                    if clean_count <= 50:
                        all_clean.append((f"wha+suffix_{suffix}", start, sorted(mask)))
        print(f"  len={suffix_len}: {2**suffix_len} combos × 97 offsets, clean={clean_count}")

    # === SCORE ALL CLEAN MASKS ===
    print(f"\n{'=' * 70}")
    print(f"TOTAL CLEAN MASKS: {len(all_clean)}")
    print(f"{'=' * 70}")

    if not all_clean:
        print("No clean masks found.")
        return

    # Deduplicate masks
    seen = set()
    unique_masks = []
    for variant, start, mask in all_clean:
        key = tuple(mask)
        if key not in seen:
            seen.add(key)
            unique_masks.append((variant, start, mask))

    print(f"Unique masks: {len(unique_masks)}")
    print(f"\nScoring top {min(len(unique_masks), 100)} unique masks through cipher pipeline...")
    print("-" * 70)

    scored = []
    for i, (variant, start, mask) in enumerate(unique_masks[:100]):
        best_score, best_desc, best_pt = score_mask(mask)
        scored.append((best_score, variant, start, mask, best_desc, best_pt))
        if best_score >= 8:
            print(f"  ** {best_score}/24 — {variant} start={start} — {best_desc}")
            print(f"     Mask: {mask}")
            print(f"     PT: {best_pt}...")

    scored.sort(key=lambda x: -x[0])

    print(f"\n{'=' * 70}")
    print("TOP 15 RESULTS:")
    print("-" * 70)
    for s, variant, start, mask, desc, pt in scored[:15]:
        w_nulls = len(set(mask) & {20, 36, 48, 58, 74})
        cons_nulls = len(set(mask) & {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})
        print(f"  {s:2d}/24 [{variant} start={start}] {desc}")
        print(f"      Mask: {mask}")
        print(f"      W-nulls: {w_nulls}/5  Consensus: {cons_nulls}/17")
    print("=" * 70)

    best = scored[0]
    if best[0] >= 10:
        print(f"\n*** ABOVE NOISE ({best[0]}/24) — INVESTIGATE ***")
    elif best[0] >= 7:
        print(f"\nSlightly above noise floor ({best[0]}/24). Marginal.")
    else:
        print(f"\nBest = {best[0]}/24. Noise floor. K0 run-length mask not viable with tested ciphers.")


if __name__ == "__main__":
    main()
