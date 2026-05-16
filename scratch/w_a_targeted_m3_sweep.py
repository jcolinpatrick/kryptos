#!/usr/bin/env python3
"""
W-A targeted M3 sweep: 5-position null mask {20, 36, 48, 58, 74} (the W's).
Test periodic Vig/Beau/VarBeau on the 92-char W-removed string at periods 13-36.

Pre-registered criteria:
  SIGNAL:       crib_score == 24 AND ngram_per_quad > -4.0 AND MC p < 0.01
  BREAKTHROUGH: above AND ngram_per_quad > -3.5
  NOISE/INTERESTING: anything else
"""
import os, sys, json, random
from itertools import product
_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    parent = os.path.dirname(_ROOT)
    if parent == _ROOT: sys.exit("repo root not found")
    _ROOT = parent
sys.path.insert(0, os.path.join(_ROOT, 'src'))
from kryptos.kernel.constants import CT, CRIB_DICT

W_POS = {20, 36, 48, 58, 74}

# Build 92-char string + remapped cribs
remap = {}
new_ct = []
new_pos = 0
for orig in range(97):
    if orig in W_POS: continue
    remap[orig] = new_pos
    new_ct.append(CT[orig])
    new_pos += 1
CT92 = ''.join(new_ct)
CRIB92 = {remap[p]: CRIB_DICT[p] for p in CRIB_DICT}
CRIB_POSITIONS_92 = sorted(CRIB92.keys())

# Quadgrams
QUAD_PATH = os.path.join(_ROOT, 'data', 'english_quadgrams.json')
with open(QUAD_PATH) as f:
    QUADGRAMS = json.load(f)
LOG_FLOOR = -10.0

def ngram_per_quad(pt):
    if len(pt) < 4: return 0.0
    total = sum(QUADGRAMS.get(pt[i:i+4], LOG_FLOOR) for i in range(len(pt)-3))
    return total / (len(pt) - 3)

def derive_k(c, p, variant):
    cc, pp = ord(c)-65, ord(p)-65
    if variant == 'vig': return (cc - pp) % 26
    if variant == 'beau': return (cc + pp) % 26
    if variant == 'varbeau': return (pp - cc) % 26

def apply_k(c, k, variant):
    cc = ord(c)-65
    if variant == 'vig': p = (cc - k) % 26
    if variant == 'beau': p = (k - cc) % 26
    if variant == 'varbeau': p = (cc + k) % 26
    return chr(p + 65)

def crib_consistency(variant, p):
    """Return (consistent, constraints_dict) where constraints_dict maps residue -> k."""
    constraints = {}
    for pos in CRIB_POSITIONS_92:
        r = pos % p
        k = derive_k(CT92[pos], CRIB92[pos], variant)
        if r in constraints:
            if constraints[r] != k:
                return False, None
        constraints[r] = k
    return True, constraints

def decrypt_with_key(variant, p, key_dict):
    return ''.join(apply_k(CT92[i], key_dict[i % p], variant) for i in range(len(CT92)))

# === Sweep ===
print("="*72)
print(" W-A TARGETED M3 SWEEP")
print(" Null mask: {20, 36, 48, 58, 74}; CT92 length 92")
print(" Cribs at remapped positions:", CRIB_POSITIONS_92)
print("="*72)

results = []   # (variant, p, n_unconstrained, ngram, pt, key)

for variant in ['vig', 'beau', 'varbeau']:
    print(f"\n--- variant: {variant} ---")
    for p in range(13, 37):
        ok, constraints = crib_consistency(variant, p)
        if not ok:
            print(f"  p={p:2d}: INCONSISTENT")
            continue
        n_constrained = len(constraints)
        unconstrained = [r for r in range(p) if r not in constraints]

        if len(unconstrained) == 0:
            # Fully determined key; one decryption to score
            pt = decrypt_with_key(variant, p, constraints)
            ng = ngram_per_quad(pt)
            results.append((variant, p, 0, ng, pt, dict(constraints)))
            print(f"  p={p:2d}: CONSISTENT, fully determined, ngram/quad = {ng:.3f}")
        elif len(unconstrained) <= 3:
            # Brute force up to 26^3 = 17,576
            best_local = None
            for combo in product(range(26), repeat=len(unconstrained)):
                full = dict(constraints)
                for r, k in zip(unconstrained, combo):
                    full[r] = k
                pt = decrypt_with_key(variant, p, full)
                ng = ngram_per_quad(pt)
                if best_local is None or ng > best_local[3]:
                    best_local = (variant, p, len(unconstrained), ng, pt, full)
            results.append(best_local)
            print(f"  p={p:2d}: CONSISTENT, {len(unconstrained)} unconstrained, "
                  f"best ngram/quad = {best_local[3]:.3f} (over {26**len(unconstrained)} keys)")
        else:
            # Too many unconstrained; report consistency only
            print(f"  p={p:2d}: CONSISTENT, {len(unconstrained)} unconstrained -- skip brute force ({26**len(unconstrained)} keys)")

# === Rank ===
results.sort(key=lambda x: -x[3])  # best ngram first
print(f"\n{'='*72}")
print(" RANKING by ngram/quad (higher = more English-like)")
print("="*72)
print(f" {'rank':4} {'variant':10} {'p':4} {'unconstr':9} {'ngram/quad':12} {'pt':70}")
for i, r in enumerate(results[:15]):
    var, p, nu, ng, pt, _ = r
    print(f" {i+1:<4} {var:10} {p:<4} {nu:<9} {ng:<12.3f} {pt}")

# === Monte Carlo null ===
print(f"\n{'='*72}")
print(" Monte Carlo null: 1000 random 92-char strings, what's the typical best ngram?")
print("="*72)
rng = random.Random(42)
mc_scores = []
for _ in range(1000):
    s = ''.join(rng.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(92))
    mc_scores.append(ngram_per_quad(s))
mc_scores.sort()
mean = sum(mc_scores) / len(mc_scores)
print(f" Random-92 ngram/quad: mean={mean:.3f}, best={mc_scores[-1]:.3f}, p99={mc_scores[990]:.3f}, p99.9={mc_scores[999]:.3f}")

# Compare best result to MC null
if results:
    best_observed = results[0][3]
    n_above = sum(1 for s in mc_scores if s >= best_observed)
    p_value = n_above / len(mc_scores) if n_above > 0 else 1.0/(len(mc_scores)+1)
    print(f" Best observed: {best_observed:.3f}  -> empirical p = {p_value:.4f} ({n_above}/{len(mc_scores)} random scored higher)")

# === Verdict ===
print(f"\n{'='*72}")
print(" PRE-REGISTERED VERDICT")
print("="*72)
SIGNAL_NGRAM = -4.0
BREAKTHROUGH_NGRAM = -3.5
SIGNAL_P = 0.01

if not results:
    print(" No (variant, p) admitted consistency. W-A model EMPTY.")
else:
    best = results[0]
    var, p, nu, ng, pt, _ = best
    n_above = sum(1 for s in mc_scores if s >= ng)
    p_value = max(n_above / len(mc_scores), 1.0/(len(mc_scores)+1))

    sig_ngram_pass = ng > SIGNAL_NGRAM
    sig_p_pass = p_value < SIGNAL_P
    bt_ngram_pass = ng > BREAKTHROUGH_NGRAM

    print(f" Best: {var} p={p}, ngram/quad={ng:.3f}, MC p={p_value:.4f}")
    print(f"   ngram > -4.0 (SIGNAL):       {'PASS' if sig_ngram_pass else 'FAIL'}")
    print(f"   ngram > -3.5 (BREAKTHROUGH): {'PASS' if bt_ngram_pass else 'FAIL'}")
    print(f"   p < 0.01:                    {'PASS' if sig_p_pass else 'FAIL'}")

    if sig_ngram_pass and sig_p_pass and bt_ngram_pass:
        verdict = "BREAKTHROUGH"
    elif sig_ngram_pass and sig_p_pass:
        verdict = "SIGNAL"
    else:
        verdict = "NOISE / INTERESTING (no signal under preregistered criteria)"
    print(f"\n VERDICT: {verdict}")
    print(f" PT: {pt}")
