#!/usr/bin/env python3
"""
Cipher: quagmire_multi
Family: archive_evidence
Status: exhausted
Keyspace: ~18000 configs (8 tableau alphas x 10 keys x 3 variants x 2 orientations x 2 CTs x 5 trans options)
Last run:
Best score:
"""
"""E-AAA-TABLEAU-STRUCT-06: Archive-informed structural tableau variant sweep.

SOURCE: Archives of American Art, Jim Sanborn papers (2026-03-27).
  - IMG_1340: "★ Definition of ABSCISSA" — chart column-addressing term
  - IMG_1340: "Bottom chart reading" + "4, 8, 10, 26 = Col"
  - IMG_1569: Beaufort cipher in Sanborn's cipher list
  - IMG_1568: "3 words most" — possibly 3 keywords for different structural roles
  - IMG_1340: "ATBA[SH]" on same page

STRUCTURAL NOVELTY (what has NOT been tested before):
  - Keyword-mixed tableau alphabets using ABSCISSA, PALIMPSEST, ECLIPSE, NORMANDY
  - These change the CT-to-index mapping, producing different key values than AZ or KA
  - Bean constraints derived under AZ/KA do not automatically apply
  - Combined with reversed-row orientation ("bottom chart seeding")
  - Prior tests used only AZ or KA as tableau alphabets

ARCHITECTURE:
  Phase A: Bean constraint check — which (tableau_alpha, variant) combos survive?
  Phase B: Periodic consistency on surviving combos
  Phase C: Full decryption with scoring on CT73 and CT97+transposition
  Phase D: Optional Atbash pre/post layer on best structural variants

CAMPAIGN TYPE: Structural-first (tableau parameters), keyword-second.
"""
import sys, os, time, itertools
from collections import Counter

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, BEAN_EQ, CONSENSUS_NULL_POSITIONS,
    ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
)
from kryptos.kernel.alphabet import keyword_mixed_alphabet
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free

t0 = time.time()

# ── Alphabets ─────────────────────────────────────────────────────────────

AZ = ALPH
KA = KRYPTOS_ALPHABET

# Archive-sourced tableau-construction keywords
TABLEAU_KEYWORDS = ['ABSCISSA', 'PALIMPSEST', 'ECLIPSE', 'NORMANDY']

# Build keyword-mixed alphabets for tableau construction
TABLEAU_ALPHABETS = {}
TABLEAU_ALPHABETS['AZ'] = AZ
TABLEAU_ALPHABETS['KA'] = KA
for kw in TABLEAU_KEYWORDS:
    seq_az = keyword_mixed_alphabet(kw, AZ)
    seq_ka = keyword_mixed_alphabet(kw, KA)
    TABLEAU_ALPHABETS[f'{kw}(AZ)'] = seq_az
    TABLEAU_ALPHABETS[f'{kw}(KA)'] = seq_ka

# Deduplicate by sequence
seen_seqs = {}
for name, seq in list(TABLEAU_ALPHABETS.items()):
    if seq in seen_seqs:
        del TABLEAU_ALPHABETS[name]
    else:
        seen_seqs[seq] = name

print(f"Tableau alphabets: {len(TABLEAU_ALPHABETS)}")
for name, seq in TABLEAU_ALPHABETS.items():
    print(f"  {name:20s}: {seq}")

# ── Period keywords (used as repeating key, separate from tableau) ────────

PERIOD_KEYWORDS = [
    'KRYPTOS', 'ABSCISSA', 'PALIMPSEST', 'ECLIPSE', 'NORMANDY',
    'KUBARK', 'SHADOW', 'COMPASS', 'ENIGMA', 'SANBORN',
]

# ── CT forms ──────────────────────────────────────────────────────────────

CT97 = CT
CT73 = ''.join(c for i, c in enumerate(CT97) if i not in CONSENSUS_NULL_POSITIONS)

CRIB_POS = sorted(CRIB_DICT.keys())

# ── Cipher operations on arbitrary alphabets ──────────────────────────────

def make_idx(alpha):
    return {ch: i for i, ch in enumerate(alpha)}

def key_recover(ct_ch, pt_ch, alpha, variant):
    """Recover key value at one position given tableau alphabet."""
    idx = make_idx(alpha)
    c = idx[ct_ch]
    p = idx[pt_ch]
    if variant == 'vig':
        return (c - p) % MOD
    elif variant == 'beau':
        return (c + p) % MOD
    else:  # vbeau
        return (p - c) % MOD

def decrypt_char(ct_ch, key_val, alpha, variant):
    """Decrypt one character given key value and tableau alphabet."""
    idx = make_idx(alpha)
    c = idx[ct_ch]
    if variant == 'vig':
        p = (c - key_val) % MOD
    elif variant == 'beau':
        p = (key_val - c) % MOD
    else:  # vbeau
        p = (c + key_val) % MOD
    return alpha[p]

def decrypt_periodic(ct_text, period_key, alpha, variant, reverse_rows=False):
    """Decrypt with periodic key using given tableau alphabet.
    If reverse_rows: key letter k maps to shift (25 - alpha_idx[k]) instead of alpha_idx[k].
    """
    idx = make_idx(alpha)
    klen = len(period_key)
    result = []
    for i, c in enumerate(ct_text):
        k_char = period_key[i % klen]
        if reverse_rows:
            k_val = (MOD - 1 - idx[k_char]) % MOD
        else:
            k_val = idx[k_char]
        result.append(decrypt_char(c, k_val, alpha, variant))
    return ''.join(result)

def columnar_decipher(ct, width):
    """Undo columnar transposition."""
    n = len(ct)
    nrows = (n + width - 1) // width
    full_cols = n % width or width
    grid = [''] * width
    pos = 0
    for col in range(width):
        col_len = nrows if col < full_cols else nrows - 1
        grid[col] = ct[pos:pos + col_len]
        pos += col_len
    result = []
    for row in range(nrows):
        for col in range(width):
            if row < len(grid[col]):
                result.append(grid[col][row])
    return ''.join(result)

def atbash(text):
    return ''.join(ALPH[25 - ALPH_IDX[c]] for c in text)

# ═══════════════════════════════════════════════════════════════════════════
# PHASE A: Bean constraint analysis per (tableau_alpha, variant)
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PHASE A: Bean constraint analysis (which tableau alphabets survive?)")
print("=" * 80)

VARIANTS = ['vig', 'beau', 'vbeau']

bean_results = {}  # (alpha_name, variant) -> (eq_pass, n_ineq, n_eq)

for alpha_name, alpha in TABLEAU_ALPHABETS.items():
    for var in VARIANTS:
        # Recover key values at all crib positions
        key_vals = {}
        for pos in CRIB_POS:
            key_vals[pos] = key_recover(CT[pos], CRIB_DICT[pos], alpha, var)

        # Bean equality: k[27] == k[65]
        eq_pass = key_vals[27] == key_vals[65]

        # Count inequalities (pairs where key values differ)
        all_pairs = list(itertools.combinations(CRIB_POS, 2))
        n_ineq = sum(1 for a, b in all_pairs if key_vals[a] != key_vals[b])
        n_eq = 276 - n_ineq

        # Count distinct key values
        n_distinct = len(set(key_vals.values()))

        bean_results[(alpha_name, var)] = (eq_pass, n_ineq, n_eq, n_distinct)

        status = "PASS" if eq_pass else "FAIL"
        print(f"  {alpha_name:20s} {var:6s}: Bean EQ={status}  "
              f"ineq={n_ineq}/276  distinct_keys={n_distinct}/26  "
              f"k27={key_vals[27]} k65={key_vals[65]}")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE B: Periodic consistency on CT97 for Bean-passing combos
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PHASE B: Periodic consistency (periods 1-26) on Bean-passing combos")
print("=" * 80)

def check_periodic_consistency(alpha, var, period, reverse_rows=False):
    """Check if crib-derived key values are consistent with period-P key."""
    idx = make_idx(alpha)
    residues = {}
    for pos in CRIB_POS:
        r = pos % period
        k = key_recover(CT[pos], CRIB_DICT[pos], alpha, var)
        if reverse_rows:
            # Reversed rows change the key recovery — not applicable to raw recovery
            # (reversal affects decryption, not key derivation from cribs)
            pass
        if r not in residues:
            residues[r] = k
        elif residues[r] != k:
            return False, 0
    # Count consistent positions
    return True, len(CRIB_POS)

def count_consistent_positions(alpha, var, period):
    """Count how many crib positions are consistent with best periodic key."""
    residues = {}
    for pos in CRIB_POS:
        r = pos % period
        k = key_recover(CT[pos], CRIB_DICT[pos], alpha, var)
        if r not in residues:
            residues[r] = Counter()
        residues[r][k] += 1
    return sum(c.most_common(1)[0][1] for c in residues.values())

print(f"\n{'Alpha':<20s} {'Var':6s} | Consistent periods (p: score/24)")
print("-" * 80)

periodic_survivors = []

for alpha_name, alpha in TABLEAU_ALPHABETS.items():
    for var in VARIANTS:
        eq_pass = bean_results[(alpha_name, var)][0]
        if not eq_pass:
            continue

        survivors = []
        for p in range(1, 27):
            consistent, _ = check_periodic_consistency(alpha, var, p)
            sc = count_consistent_positions(alpha, var, p)
            if consistent:
                survivors.append((p, sc))

        if survivors:
            # Only report periods where consistency score is meaningful
            # (small periods are more discriminating)
            interesting = [(p, sc) for p, sc in survivors if p <= 13]
            print(f"  {alpha_name:20s} {var:6s}: {len(survivors)} total | "
                  f"small-period: {interesting}")
            for p, sc in survivors:
                if p <= 13:  # Only small periods are meaningful
                    periodic_survivors.append((alpha_name, alpha, var, p, sc))

if not periodic_survivors:
    # ALL eliminated at small periods — this is the expected result for most
    # but report it explicitly
    print("  No fully-consistent small periods found (expected for most combos)")
    print("  Proceeding to Phase C with ALL Bean-passing combos on CT73")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE C: Full decryption sweep
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PHASE C: Full decryption sweep")
print("=" * 80)

best_score = 0
best_result = None
total = 0
hits = []
COL_WIDTHS = [4, 8, 10, 26]  # Archive-derived: "4, 8, 10, 26 = Col"

def test_and_record(pt, ct_label, desc):
    global best_score, best_result, total
    total += 1
    if len(pt) < 10:
        return
    if ct_label in ('CT97',):
        sc = score_candidate(pt)
    else:
        sc = score_candidate_free(pt)

    if sc.crib_score > best_score:
        best_score = sc.crib_score
        best_result = (ct_label, desc, pt, sc)
    if sc.crib_score >= 10:
        hits.append((sc.crib_score, ct_label, desc, pt[:50]))

# Phase C1: Direct periodic decryption on CT73 (all Bean-passing combos)
print("\n--- C1: Periodic decryption on CT73 ---")
for alpha_name, alpha in TABLEAU_ALPHABETS.items():
    for var in VARIANTS:
        eq_pass = bean_results[(alpha_name, var)][0]
        if not eq_pass:
            continue
        for kw in PERIOD_KEYWORDS:
            for rev in [False, True]:
                orient = 'reversed' if rev else 'standard'
                pt = decrypt_periodic(CT73, kw, alpha, var, reverse_rows=rev)
                test_and_record(pt, 'CT73', f'C1_{alpha_name}_{var}_{kw}_{orient}')

print(f"  C1 configs: {total}")

# Phase C2: CT97 + columnar transposition (both peel orders)
print("\n--- C2: CT97 + columnar transposition ---")
c2_start = total
for alpha_name, alpha in TABLEAU_ALPHABETS.items():
    for var in VARIANTS:
        eq_pass = bean_results[(alpha_name, var)][0]
        if not eq_pass:
            continue
        for kw in PERIOD_KEYWORDS:
            for rev in [False, True]:
                orient = 'reversed' if rev else 'standard'
                for w in COL_WIDTHS:
                    # Peel order 1: undo substitution, then undo transposition
                    sub_pt = decrypt_periodic(CT97, kw, alpha, var, reverse_rows=rev)
                    pt1 = columnar_decipher(sub_pt, w)
                    test_and_record(pt1, 'CT97', f'C2a_{alpha_name}_{var}_{kw}_{orient}_col{w}')

                    # Peel order 2: undo transposition, then undo substitution
                    detrans = columnar_decipher(CT97, w)
                    pt2 = decrypt_periodic(detrans, kw, alpha, var, reverse_rows=rev)
                    test_and_record(pt2, 'CT97', f'C2b_{alpha_name}_{var}_{kw}_{orient}_col{w}')

print(f"  C2 configs: {total - c2_start}")

# Phase C3: CT73 + columnar transposition
print("\n--- C3: CT73 + columnar transposition ---")
c3_start = total
for alpha_name, alpha in TABLEAU_ALPHABETS.items():
    for var in VARIANTS:
        eq_pass = bean_results[(alpha_name, var)][0]
        if not eq_pass:
            continue
        for kw in PERIOD_KEYWORDS:
            for rev in [False, True]:
                orient = 'reversed' if rev else 'standard'
                for w in COL_WIDTHS:
                    sub_pt = decrypt_periodic(CT73, kw, alpha, var, reverse_rows=rev)
                    pt1 = columnar_decipher(sub_pt, w)
                    test_and_record(pt1, 'CT73', f'C3a_{alpha_name}_{var}_{kw}_{orient}_col{w}')

                    detrans = columnar_decipher(CT73, w)
                    pt2 = decrypt_periodic(detrans, kw, alpha, var, reverse_rows=rev)
                    test_and_record(pt2, 'CT73', f'C3b_{alpha_name}_{var}_{kw}_{orient}_col{w}')

print(f"  C3 configs: {total - c3_start}")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE D: Atbash pre/post layer on CT73 best structural variants
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PHASE D: Atbash as pre/post layer")
print("=" * 80)

d_start = total
for alpha_name, alpha in TABLEAU_ALPHABETS.items():
    for var in VARIANTS:
        eq_pass = bean_results[(alpha_name, var)][0]
        if not eq_pass:
            continue
        for kw in PERIOD_KEYWORDS:
            for rev in [False, True]:
                orient = 'reversed' if rev else 'standard'

                # Atbash BEFORE decryption (applied to CT)
                ct_atbash = atbash(CT73)
                pt = decrypt_periodic(ct_atbash, kw, alpha, var, reverse_rows=rev)
                test_and_record(pt, 'CT73_atbash_pre', f'D1_{alpha_name}_{var}_{kw}_{orient}')

                # Atbash AFTER decryption (applied to PT)
                raw_pt = decrypt_periodic(CT73, kw, alpha, var, reverse_rows=rev)
                pt = atbash(raw_pt)
                test_and_record(pt, 'CT73_atbash_post', f'D2_{alpha_name}_{var}_{kw}_{orient}')

print(f"  D configs: {total - d_start}")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE E: Quagmire IV — two different keyword-mixed alphabets
# (CT alphabet != PT alphabet, testing "3 words most" hypothesis)
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PHASE E: Quagmire IV (two keyword-mixed alphabets)")
print("=" * 80)

e_start = total
Q4_KEYS = ['KRYPTOS', 'ABSCISSA', 'PALIMPSEST', 'ECLIPSE', 'NORMANDY']

# For Q4: CT alphabet and PT alphabet are DIFFERENT keyword-mixed alphabets
# Period key is a third keyword
for ct_kw in Q4_KEYS:
    ct_alpha = keyword_mixed_alphabet(ct_kw)
    ct_idx = make_idx(ct_alpha)
    for pt_kw in Q4_KEYS:
        if pt_kw == ct_kw:
            continue  # Same keyword = Q3, already tested above
        pt_alpha = keyword_mixed_alphabet(pt_kw)

        for period_kw in Q4_KEYS:
            # Q4 Vigenere decrypt: P = pt_alpha[(ct_idx[c] - ct_idx[k]) % 26]
            klen = len(period_kw)
            pt_chars = []
            for i, c in enumerate(CT73):
                k = period_kw[i % klen]
                c_pos = ct_idx[c]
                k_pos = ct_idx[k]
                p_pos = (c_pos - k_pos) % MOD
                pt_chars.append(pt_alpha[p_pos])
            pt = ''.join(pt_chars)
            test_and_record(pt, 'CT73', f'E_Q4vig_ct{ct_kw}_pt{pt_kw}_k{period_kw}')

            # Q4 Beaufort decrypt: P = pt_alpha[(ct_idx[k] - ct_idx[c]) % 26]
            pt_chars = []
            for i, c in enumerate(CT73):
                k = period_kw[i % klen]
                c_pos = ct_idx[c]
                k_pos = ct_idx[k]
                p_pos = (k_pos - c_pos) % MOD
                pt_chars.append(pt_alpha[p_pos])
            pt = ''.join(pt_chars)
            test_and_record(pt, 'CT73', f'E_Q4beau_ct{ct_kw}_pt{pt_kw}_k{period_kw}')

print(f"  E configs: {total - e_start}")

# ═══════════════════════════════════════════════════════════════════════════
# RESULTS
# ═══════════════════════════════════════════════════════════════════════════

elapsed = time.time() - t0

print("\n" + "=" * 80)
print("E-AAA-TABLEAU-STRUCT-06: RESULTS")
print("=" * 80)
print(f"Total configurations tested: {total}")
print(f"Elapsed: {elapsed:.1f}s")
print(f"Best score: {best_score}/24")

if best_result:
    ct_label, desc, pt, sc = best_result
    print(f"\nBest result:")
    print(f"  CT form: {ct_label}")
    print(f"  Method: {desc}")
    print(f"  PT: {pt[:70]}...")
    print(f"  Score: {sc}")

if hits:
    print(f"\nHits (score >= 10):")
    for h in sorted(hits, reverse=True):
        print(f"  score={h[0]} {h[1]} method={h[2]} pt={h[3]}")
else:
    print(f"\nNo hits >= 10 (all noise)")

# Phase A summary
print(f"\n--- Bean constraint summary ---")
n_pass = sum(1 for v in bean_results.values() if v[0])
n_fail = len(bean_results) - n_pass
print(f"  Bean EQ pass: {n_pass}/{len(bean_results)}")
print(f"  Bean EQ fail: {n_fail}/{len(bean_results)}")

# Structural findings
print(f"\n--- Structural findings ---")
for (alpha_name, var), (eq_pass, n_ineq, n_eq, n_distinct) in sorted(bean_results.items()):
    if eq_pass and n_distinct < 20:
        print(f"  NOTABLE: {alpha_name} {var}: only {n_distinct} distinct key values "
              f"({n_eq} equalities) — lower entropy keystream")

print(f"\n{'='*80}")
print(f"Campaign complete. {total} configs in {elapsed:.1f}s.")
print(f"{'='*80}")
