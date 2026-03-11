#!/usr/bin/env python3
"""
Cipher: autokey
Family: encoding
Status: active
Keyspace: 156 (6 variants × 26 keys) + dictionary primers
Last run: 2026-03-11
Best score: TBD

Attack #3: Autokey exhaustive search on raw 97-char K4 CT.
Critical gap: Autokey was never systematically tested despite being
explicitly "OPEN" in elimination analysis. Only 26 priming keys per variant.

Variants:
  - Vigenere Autokey:  zi = xi-1, decrypt: xi = (yi - zi) mod 26
  - Beaufort Autokey:  zi = xi-1, decrypt: xi = (zi - yi) mod 26  
  - Var.Beaufort AK:   zi = xi-1, decrypt: xi = (yi + zi) mod 26
  Each with AZ and KA alphabets.

Also tests multi-letter primers from dictionary.
"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN

# ── Quadgram scoring ─────────────────────────────────────────────────────
with open(os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json')) as f:
    QG = json.load(f)
FLOOR = min(QG.values()) - 1

def qg_score(text):
    text = text.upper()
    if len(text) < 4: return FLOOR
    s = sum(QG.get(text[i:i+4], FLOOR) for i in range(len(text)-3))
    return s / (len(text) - 3)

# ── Free crib search ─────────────────────────────────────────────────────
CRIBS = ['EASTNORTHEAST', 'BERLINCLOCK', 'NORTHEAST', 'BERLIN', 'CLOCK',
         'NORTH', 'EAST', 'LAYER', 'BURIED', 'UNDERGRUUND']

def crib_score(text):
    text = text.upper()
    hits = 0
    for crib in CRIBS[:2]:  # primary cribs only
        if crib in text:
            hits += len(crib)
    return hits

# ── Alphabets ─────────────────────────────────────────────────────────────
AZ = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
KA = 'KRYPTOSABCDEFGHIJLMNQUVWXZ'

def make_idx(alpha):
    return {c: i for i, c in enumerate(alpha)}

# ── Autokey decryption ────────────────────────────────────────────────────
def autokey_decrypt(ct, primer, variant, alpha):
    """
    primer: list of ints (priming key values)
    variant: 'vig', 'beau', 'varbeau'
    alpha: alphabet string
    """
    idx = make_idx(alpha)
    m = len(primer)
    n = len(ct)
    ct_nums = [idx[c] for c in ct]
    pt = []
    z = list(primer)  # keystream starts with primer
    
    for i in range(n):
        yi = ct_nums[i]
        zi = z[i] if i < len(z) else z[-1]  # shouldn't happen
        
        if variant == 'vig':
            xi = (yi - zi) % 26
        elif variant == 'beau':
            xi = (zi - yi) % 26
        elif variant == 'varbeau':
            xi = (yi + zi) % 26
        
        pt.append(xi)
        z.append(xi)  # autokey: next keystream = current plaintext
    
    return ''.join(alpha[x] for x in pt)

# ── Phase 1: Single-letter primers (26 × 6 = 156 configs) ────────────────
print("=" * 70)
print("PHASE 1: Single-letter Autokey primers (156 configs)")
print("=" * 70)

results = []
for alpha_name, alpha in [('AZ', AZ), ('KA', KA)]:
    for variant in ['vig', 'beau', 'varbeau']:
        for k in range(26):
            pt = autokey_decrypt(CT, [k], variant, alpha)
            qs = qg_score(pt)
            cs = crib_score(pt)
            results.append((qs, cs, k, variant, alpha_name, pt))

results.sort(reverse=True)
print(f"\nTop 15 by quadgram score:")
for qs, cs, k, var, alph, pt in results[:15]:
    letter = AZ[k] if alph == 'AZ' else KA[k]
    print(f"  {qs:7.3f}  crib={cs:2d}  K={k:2d}({letter}) {var:8s} {alph}  {pt[:50]}...")

# Check for any crib hits
crib_hits = [(qs, cs, k, var, alph, pt) for qs, cs, k, var, alph, pt in results if cs > 0]
if crib_hits:
    print(f"\n*** CRIB HITS FOUND: {len(crib_hits)} ***")
    for qs, cs, k, var, alph, pt in crib_hits:
        print(f"  crib={cs}  K={k} {var} {alph}  {pt}")
else:
    print(f"\nNo crib hits in single-letter autokey on raw CT.")

# ── Phase 2: Dictionary word primers ──────────────────────────────────────
print("\n" + "=" * 70)
print("PHASE 2: Dictionary-word Autokey primers (top keywords)")
print("=" * 70)

# Thematic keywords + top candidates
KEYWORDS = [
    'KRYPTOS', 'KOMPASS', 'PALIMPSEST', 'ABSCISSA', 'DEFECTOR',
    'COLOPHON', 'ENIGMA', 'HOROLOGE', 'SHADOW', 'LUCID', 'MEMORY',
    'PRIME', 'MATRIX', 'BINARY', 'MORSE', 'CIPHER', 'SECRET',
    'BERLIN', 'CLOCK', 'NORTHEAST', 'COMPASS', 'LODESTONE',
    'FIVE', 'POINT', 'LAYER', 'MASK', 'GRILLE', 'SHIFT',
    'BURIED', 'INVISIBLE', 'DIGITAL', 'FORCES', 'POSITION',
    'SOS', 'RQ', 'VIRTUALLY', 'SCHEIDT', 'SANBORN',
]

results2 = []
for alpha_name, alpha in [('AZ', AZ), ('KA', KA)]:
    idx = make_idx(alpha)
    for variant in ['vig', 'beau', 'varbeau']:
        for kw in KEYWORDS:
            # Convert keyword to primer values in this alphabet
            try:
                primer = [idx[c] for c in kw]
            except KeyError:
                continue
            pt = autokey_decrypt(CT, primer, variant, alpha)
            qs = qg_score(pt)
            cs = crib_score(pt)
            results2.append((qs, cs, kw, variant, alpha_name, pt))

results2.sort(reverse=True)
print(f"\nTop 15 by quadgram score:")
for qs, cs, kw, var, alph, pt in results2[:15]:
    print(f"  {qs:7.3f}  crib={cs:2d}  KW={kw:15s} {var:8s} {alph}  {pt[:45]}...")

crib_hits2 = [(qs, cs, kw, var, alph, pt) for qs, cs, kw, var, alph, pt in results2 if cs > 0]
if crib_hits2:
    print(f"\n*** CRIB HITS FOUND: {len(crib_hits2)} ***")
    for qs, cs, kw, var, alph, pt in crib_hits2:
        print(f"  crib={cs}  KW={kw} {var} {alph}  {pt}")
else:
    print(f"\nNo crib hits in dictionary autokey on raw CT.")

# ── Phase 3: Extended dictionary (wordlist) ───────────────────────────────
print("\n" + "=" * 70)
print("PHASE 3: Full wordlist Autokey primers (1M+ words, AZ Vig only)")
print("=" * 70)

wordlist_path = os.path.join(os.path.dirname(__file__), '..', '..', 'wordlists', 'english.txt')
best_qs = -999
best_cs = 0
count = 0
results3 = []

az_idx = make_idx(AZ)
with open(wordlist_path) as f:
    for line in f:
        word = line.strip().upper()
        if len(word) < 3 or len(word) > 20:
            continue
        if not all(c in az_idx for c in word):
            continue
        
        primer = [az_idx[c] for c in word]
        
        # Test Vig autokey only (fastest)
        pt = autokey_decrypt(CT, primer, 'vig', AZ)
        qs = qg_score(pt)
        cs = crib_score(pt)
        
        if cs > 0:
            results3.append((qs, cs, word, 'vig', 'AZ', pt))
            print(f"  CRIB HIT! crib={cs} KW={word} {pt[:50]}...")
        
        if qs > best_qs:
            best_qs = qs
            results3.append((qs, cs, word, 'vig', 'AZ', pt))
        
        count += 1
        if count % 100000 == 0:
            print(f"  ...tested {count} words, best qg={best_qs:.3f}")

# Also test Beaufort and VarBeau with top words
print(f"\nTested {count} words (Vig AZ). Best quadgram: {best_qs:.3f}")

results3.sort(reverse=True)
print(f"\nTop 10 by quadgram score:")
for qs, cs, kw, var, alph, pt in results3[:10]:
    print(f"  {qs:7.3f}  crib={cs:2d}  KW={kw:15s} {var:8s} {alph}  {pt[:45]}...")

# Final summary
total_crib = len(crib_hits) + len(crib_hits2) + len([r for r in results3 if r[1] > 0])
print(f"\n{'='*70}")
print(f"TOTAL CRIB HITS: {total_crib}")
print(f"{'='*70}")
